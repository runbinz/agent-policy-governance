CREATE TABLE reconciliation_grants (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, reviewer_id uuid NOT NULL,
 connection_id uuid NOT NULL, enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TRIGGER audit_reconciliation_grant AFTER INSERT OR UPDATE OR DELETE ON reconciliation_grants
 FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

CREATE TABLE external_reconciliation_requests (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 reviewer_id uuid NOT NULL, requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES external_dispatches,
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);

CREATE FUNCTION request_external_reconciliation(t uuid,e uuid,a uuid,r uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE state jsonb; authorized_connection uuid; is_closed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN 'hidden'; END IF;

 -- Use the same queue-first lock order as claim and observation.
 SELECT q.closed INTO is_closed FROM public.external_dispatch_queue q
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'hidden'; END IF;
 SELECT d.connection_id,d.snapshot->'state' INTO authorized_connection,state FROM public.external_dispatches d
 WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a);
 PERFORM 1 FROM public.reconciliation_grants g
 JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.environments en USING(tenant_id,environment_id)
 JOIN public.tenants tn USING(tenant_id)
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=(t,e,r,authorized_connection)
 AND g.enabled AND rv.enabled AND en.enabled AND tn.enabled FOR SHARE OF g,rv,en,tn;
 IF NOT FOUND THEN RETURN 'hidden'; END IF;
 IF state IS DISTINCT FROM '"manual_review"'::jsonb THEN RETURN 'not_manual'; END IF;
 IF NOT is_closed THEN RETURN 'queued'; END IF;

 INSERT INTO public.external_reconciliation_requests(tenant_id,environment_id,action_id,reviewer_id) VALUES(t,e,a,r);
 INSERT INTO public.audit_events(tenant_id,environment_id,action_id,sequence,event_type)
 SELECT t,e,a,coalesce(max(sequence),0)+1,'dispatch.reconciliation_requested'
 FROM public.audit_events WHERE (tenant_id,environment_id,action_id)=(t,e,a);
 UPDATE public.external_dispatch_queue q SET closed=false,
  available_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a);
 RETURN 'queued';
END $$;
REVOKE ALL ON FUNCTION request_external_reconciliation(uuid,uuid,uuid,uuid) FROM PUBLIC;
