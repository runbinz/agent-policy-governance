ALTER TABLE actions DROP CONSTRAINT actions_status_check;
ALTER TABLE actions ADD CONSTRAINT actions_status_check CHECK(status IN (
 'received','denied','succeeded','pending_approval','ready','rejected','expired','cancelled','dispatching','failed_confirmed'
));

CREATE TABLE external_dispatches (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 connection_id uuid NOT NULL, provider_namespace text NOT NULL CHECK(provider_namespace ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 provider_key text NOT NULL CHECK(provider_key='apl-refund-v1-'||action_id::text),
 policy_version bigint NOT NULL, approval_generation bigint,
 snapshot jsonb NOT NULL,
 available_at_ms bigint NOT NULL CHECK(available_at_ms>=0),
 observations integer NOT NULL DEFAULT 0 CHECK(observations BETWEEN 0 AND 8),
 abandoned_at_ms bigint CHECK(abandoned_at_ms>=0),
 lease_expires_ms bigint GENERATED ALWAYS AS ((snapshot#>>'{lease,expires_at}')::bigint) STORED,
 closed boolean GENERATED ALWAYS AS (
   abandoned_at_ms IS NOT NULL OR jsonb_typeof(snapshot->'state')='object'
 ) STORED NOT NULL,
 CHECK((snapshot->>'action_id')::uuid IS NOT DISTINCT FROM action_id),
 CHECK((snapshot#>>'{request,connection_id}')::uuid IS NOT DISTINCT FROM connection_id),
 CHECK(jsonb_typeof(snapshot->'state') IN ('string','object')),
 CHECK(abandoned_at_ms IS NULL OR (snapshot->'state'='"authorized"'::jsonb AND snapshot->'first_send_at'='null'::jsonb)),
 PRIMARY KEY(tenant_id,environment_id,action_id),
 UNIQUE(provider_namespace,provider_key),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES actions,
 FOREIGN KEY(tenant_id,environment_id,connection_id,policy_version) REFERENCES policy_versions,
 FOREIGN KEY(tenant_id,environment_id,action_id,approval_generation) REFERENCES approvals
);
-- Private global routing metadata contains no provider request or evidence.
CREATE TABLE external_dispatch_queue (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,action_id uuid NOT NULL,
 provider_namespace text NOT NULL,available_at_ms bigint NOT NULL,lease_expires_ms bigint,closed boolean NOT NULL,
 PRIMARY KEY(tenant_id,environment_id,action_id),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES external_dispatches
);
CREATE INDEX external_dispatch_ready ON external_dispatch_queue(provider_namespace,available_at_ms,action_id) WHERE NOT closed;
CREATE FUNCTION sync_external_dispatch_queue() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 INSERT INTO public.external_dispatch_queue VALUES(NEW.tenant_id,NEW.environment_id,NEW.action_id,NEW.provider_namespace,
   NEW.available_at_ms,NEW.lease_expires_ms,NEW.closed OR NEW.snapshot->'state'='"manual_review"'::jsonb)
 ON CONFLICT(tenant_id,environment_id,action_id) DO UPDATE SET
   available_at_ms=excluded.available_at_ms,lease_expires_ms=excluded.lease_expires_ms,closed=excluded.closed;
 RETURN NULL;
END $$;
CREATE TRIGGER sync_external_dispatch_queue AFTER INSERT OR UPDATE ON external_dispatches FOR EACH ROW EXECUTE FUNCTION sync_external_dispatch_queue();

CREATE TABLE external_attempts (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0), marked_at_ms bigint NOT NULL CHECK(marked_at_ms>=0),
 PRIMARY KEY(tenant_id,environment_id,action_id,generation),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES external_dispatches
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['external_dispatches','external_attempts'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;

CREATE FUNCTION guard_external_dispatch() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.closed OR NEW.snapshot->'request' IS DISTINCT FROM OLD.snapshot->'request'
  OR (OLD.snapshot->>'first_send_at' IS NOT NULL AND NEW.snapshot->'first_send_at' IS DISTINCT FROM OLD.snapshot->'first_send_at')
  OR (OLD.snapshot->>'first_send_at' IS NOT NULL AND NEW.snapshot->'retry_until' IS DISTINCT FROM OLD.snapshot->'retry_until') THEN
  RAISE EXCEPTION 'external dispatch history is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_external_dispatch BEFORE UPDATE ON external_dispatches FOR EACH ROW EXECUTE FUNCTION guard_external_dispatch();

-- Private namespace-aware picker. It returns only scoped identifiers and holds
-- the queue row through the transaction that stores the new fence.
CREATE FUNCTION claim_external_dispatch(ns text) RETURNS TABLE(tenant_id uuid,environment_id uuid,action_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT d.tenant_id,d.environment_id,d.action_id FROM public.external_dispatch_queue d
 WHERE d.provider_namespace=ns AND NOT d.closed
 AND d.available_at_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 AND (d.lease_expires_ms IS NULL OR d.lease_expires_ms<=floor(extract(epoch FROM clock_timestamp())*1000)::bigint)
 ORDER BY d.available_at_ms,d.action_id FOR UPDATE SKIP LOCKED LIMIT 1
$$;

CREATE FUNCTION lock_external_dispatch(t uuid,e uuid,a uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT coalesce((SELECT true FROM public.external_dispatch_queue q
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a)
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e=nullif(current_setting('apl.environment_id',true),'')::uuid FOR UPDATE),false)
$$;

CREATE FUNCTION external_hold_matches(t uuid,e uuid,a uuid,c uuid,w uuid,amount bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT coalesce((SELECT true FROM public.budget_reservations r
 WHERE (r.tenant_id,r.environment_id,r.action_id,r.connection_id,r.workload_id,r.amount_minor)=(t,e,a,c,w,amount)
 AND r.state='held' AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e=nullif(current_setting('apl.environment_id',true),'')::uuid FOR SHARE),false)
$$;
REVOKE ALL ON FUNCTION claim_external_dispatch(text),lock_external_dispatch(uuid,uuid,uuid),external_hold_matches(uuid,uuid,uuid,uuid,uuid,bigint) FROM PUBLIC;
