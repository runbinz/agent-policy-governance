ALTER TABLE tenants ADD COLUMN paused boolean NOT NULL DEFAULT false;
ALTER TABLE workloads ADD COLUMN paused boolean NOT NULL DEFAULT false;

CREATE TABLE tenant_dispatch_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
CREATE TABLE workload_dispatch_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,workload_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,workload_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,workload_id) REFERENCES workloads
);
CREATE TABLE dispatch_scope_audit (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,workload_id uuid,
 sequence bigint GENERATED ALWAYS AS IDENTITY,paused boolean NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,environment_id,sequence),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,workload_id) REFERENCES workloads
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['tenant_dispatch_grants','workload_dispatch_grants','dispatch_scope_audit'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE TRIGGER tenant_dispatch_grants_change AFTER INSERT OR UPDATE OR DELETE ON tenant_dispatch_grants
FOR EACH ROW EXECUTE FUNCTION audit_identity_change();
CREATE TRIGGER workload_dispatch_grants_change AFTER INSERT OR UPDATE OR DELETE ON workload_dispatch_grants
FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

-- Explicit operator grants only; no connection or review grant implies these controls.
-- The update locks the same scope row held by authorize_scope during dispatch.
CREATE FUNCTION admin_set_tenant_dispatch_paused(t uuid,e uuid,r uuid,pause boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'tenant dispatch administration denied' USING ERRCODE='AP403';
 END IF;
 PERFORM 1 FROM public.tenant_dispatch_grants g JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.environments en USING(tenant_id,environment_id)
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id)=(t,e,r) AND g.enabled AND rv.enabled AND en.enabled
 FOR SHARE OF g,rv,en;
 IF NOT FOUND THEN RAISE EXCEPTION 'tenant dispatch administration denied' USING ERRCODE='AP403'; END IF;
 UPDATE public.tenants tn SET paused=pause WHERE tn.tenant_id=t AND tn.paused IS DISTINCT FROM pause;
 IF FOUND THEN
  INSERT INTO public.dispatch_scope_audit(tenant_id,environment_id,reviewer_id,paused) VALUES(t,e,r,pause);
 END IF;
END $$;

CREATE FUNCTION admin_set_workload_dispatch_paused(t uuid,e uuid,r uuid,w uuid,pause boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'workload dispatch administration denied' USING ERRCODE='AP403';
 END IF;
 PERFORM 1 FROM public.workload_dispatch_grants g JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.environments en USING(tenant_id,environment_id)
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.workload_id)=(t,e,r,w) AND g.enabled AND rv.enabled AND en.enabled
 FOR SHARE OF g,rv,en;
 IF NOT FOUND THEN RAISE EXCEPTION 'workload dispatch administration denied' USING ERRCODE='AP403'; END IF;
 UPDATE public.workloads wl SET paused=pause
 WHERE (wl.tenant_id,wl.environment_id,wl.workload_id)=(t,e,w) AND wl.paused IS DISTINCT FROM pause;
 IF FOUND THEN
  INSERT INTO public.dispatch_scope_audit(tenant_id,environment_id,reviewer_id,workload_id,paused) VALUES(t,e,r,w,pause);
 END IF;
END $$;
REVOKE ALL ON FUNCTION admin_set_tenant_dispatch_paused(uuid,uuid,uuid,boolean),
 admin_set_workload_dispatch_paused(uuid,uuid,uuid,uuid,boolean) FROM PUBLIC;
