CREATE TABLE actions (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, id uuid NOT NULL,
 workload_id uuid NOT NULL, request jsonb NOT NULL,
 status text NOT NULL CHECK (status IN ('received','denied','succeeded')),
 reason text, PRIMARY KEY (tenant_id,environment_id,id)
);
CREATE TABLE submission_keys (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, workload_id uuid NOT NULL,
 key text NOT NULL, digest bytea NOT NULL, action_id uuid NOT NULL,
 PRIMARY KEY (tenant_id,environment_id,workload_id,key),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES actions(tenant_id,environment_id,id)
);
CREATE TABLE audit_events (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 sequence bigint NOT NULL, event_type text NOT NULL,
 PRIMARY KEY(tenant_id,environment_id,action_id,sequence),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES actions(tenant_id,environment_id,id)
);
CREATE TABLE fake_effects (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,environment_id,action_id),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES actions(tenant_id,environment_id,id)
);
-- Private worker queue. API can insert jobs but cannot read global dispatch state.
CREATE TABLE outbox_jobs (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 done boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,environment_id,action_id),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES actions(tenant_id,environment_id,id)
);
DO $$
DECLARE t text;
BEGIN
 FOREACH t IN ARRAY ARRAY['actions','submission_keys','audit_events','fake_effects'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id = nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id = nullif(current_setting(''apl.environment_id'',true),'''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id = nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
-- Fixed SQL and search_path; owner must be the migration role, never a runtime role.
CREATE FUNCTION claim_next_job() RETURNS TABLE(tenant_id uuid,environment_id uuid,action_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
 SELECT q.tenant_id,q.environment_id,q.action_id FROM public.outbox_jobs q
 WHERE NOT q.done ORDER BY q.action_id FOR UPDATE SKIP LOCKED LIMIT 1
$$;
REVOKE ALL ON FUNCTION claim_next_job() FROM PUBLIC;
CREATE FUNCTION complete_job(t uuid,e uuid,a uuid) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
 UPDATE public.outbox_jobs SET done=true WHERE tenant_id=t AND environment_id=e AND action_id=a
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e=nullif(current_setting('apl.environment_id',true),'')::uuid
$$;
REVOKE ALL ON FUNCTION complete_job(uuid,uuid,uuid) FROM PUBLIC;
-- Queue is global dispatch infrastructure; enforce tenant-scoped enqueue explicitly.
CREATE FUNCTION guard_job_tenant() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
 IF NEW.tenant_id IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR NEW.environment_id IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'queue tenant context mismatch' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_job_tenant BEFORE INSERT ON outbox_jobs FOR EACH ROW EXECUTE FUNCTION guard_job_tenant();
