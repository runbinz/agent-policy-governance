-- Runtime roles use narrow functions; route ownership is an administrative operation.
CREATE TABLE provider_routes (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, connection_id uuid NOT NULL,
 provider_namespace text NOT NULL UNIQUE CHECK(provider_namespace ~ '^[A-Za-z0-9_.:-]{1,128}$'),
 PRIMARY KEY(tenant_id,environment_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE FUNCTION guard_provider_route() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'provider routing is immutable'; END IF;
 -- Serialize switching a connection with both fake and external authorization.
 PERFORM 1 FROM public.connections c WHERE (c.tenant_id,c.environment_id,c.connection_id)=
  (NEW.tenant_id,NEW.environment_id,NEW.connection_id) FOR UPDATE;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_provider_route BEFORE INSERT OR UPDATE OR DELETE ON provider_routes
 FOR EACH ROW EXECUTE FUNCTION guard_provider_route();
CREATE TRIGGER audit_provider_route AFTER INSERT ON provider_routes
 FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

ALTER TABLE outbox_jobs ADD COLUMN connection_id uuid;
UPDATE outbox_jobs q SET connection_id=(a.request->>'connection_id')::uuid FROM actions a
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(a.tenant_id,a.environment_id,a.id);
ALTER TABLE outbox_jobs ALTER COLUMN connection_id SET NOT NULL;
CREATE FUNCTION bind_outbox_connection() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 SELECT (a.request->>'connection_id')::uuid INTO NEW.connection_id FROM public.actions a
 WHERE (a.tenant_id,a.environment_id,a.id)=(NEW.tenant_id,NEW.environment_id,NEW.action_id);
 RETURN NEW;
END $$;
CREATE TRIGGER bind_outbox_connection BEFORE INSERT ON outbox_jobs
 FOR EACH ROW EXECUTE FUNCTION bind_outbox_connection();
CREATE INDEX external_candidate_ready ON outbox_jobs(tenant_id,environment_id,connection_id,available_at,action_id) WHERE NOT done;

CREATE OR REPLACE FUNCTION claim_next_job() RETURNS TABLE(tenant_id uuid,environment_id uuid,action_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT q.tenant_id,q.environment_id,q.action_id FROM public.outbox_jobs q
 WHERE NOT q.done AND q.available_at<=clock_timestamp() AND NOT EXISTS (
  SELECT 1 FROM public.provider_routes r WHERE (r.tenant_id,r.environment_id,r.connection_id)=
   (q.tenant_id,q.environment_id,q.connection_id))
 ORDER BY q.available_at,q.action_id FOR UPDATE OF q SKIP LOCKED LIMIT 1
$$;
CREATE FUNCTION external_candidate(ns text) RETURNS TABLE(tenant_id uuid,environment_id uuid,action_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT q.tenant_id,q.environment_id,q.action_id FROM public.outbox_jobs q JOIN public.provider_routes r
 USING(tenant_id,environment_id,connection_id)
 WHERE r.provider_namespace=ns AND NOT q.done AND q.available_at<=clock_timestamp()
 ORDER BY q.available_at,q.action_id LIMIT 1
$$;
CREATE FUNCTION provider_route(t uuid,e uuid,c uuid) RETURNS text
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT r.provider_namespace FROM public.provider_routes r
 WHERE (r.tenant_id,r.environment_id,r.connection_id)=(t,e,c)
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e=nullif(current_setting('apl.environment_id',true),'')::uuid
$$;
-- Manual review closes the polling queue, but not the dispatch itself.
CREATE UNIQUE INDEX external_one_open_payment
 ON external_dispatches(provider_namespace,(snapshot#>>'{request,payment_id}')) WHERE NOT closed;
REVOKE ALL ON FUNCTION external_candidate(text),provider_route(uuid,uuid,uuid) FROM PUBLIC;

CREATE FUNCTION external_payment_changed_since(t uuid,e uuid,ns text,payment text,observed_ms bigint) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(
  SELECT 1 FROM public.external_dispatches d JOIN public.budget_ledger_events l
  USING(tenant_id,environment_id,action_id)
  WHERE (d.tenant_id,d.environment_id,d.provider_namespace)=(t,e,ns)
   AND d.snapshot#>>'{request,payment_id}'=payment AND l.sequence=2
   AND l.recorded_at>=to_timestamp(observed_ms::double precision/1000))
 WHERE t=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e=nullif(current_setting('apl.environment_id',true),'')::uuid
$$;
REVOKE ALL ON FUNCTION external_payment_changed_since(uuid,uuid,text,text,bigint) FROM PUBLIC;
