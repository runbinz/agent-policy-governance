ALTER TABLE workload_grants ADD COLUMN cancel_action boolean NOT NULL DEFAULT false;
ALTER TABLE connections ADD COLUMN paused boolean NOT NULL DEFAULT false;

CREATE OR REPLACE FUNCTION authorize_scope(t uuid,e uuid,w uuid,c uuid,permission text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT (tn.enabled AND en.enabled AND wl.enabled AND cn.enabled AND gr.enabled AND CASE permission WHEN 'submit_refund' THEN gr.submit_refund WHEN 'read_action' THEN gr.read_action WHEN 'read_events' THEN gr.read_events WHEN 'cancel_action' THEN gr.cancel_action ELSE false END)
 INTO allowed FROM public.tenants tn JOIN public.environments en USING(tenant_id)
 JOIN public.workloads wl USING(tenant_id,environment_id)
 JOIN public.workload_grants gr USING(tenant_id,environment_id,workload_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 WHERE tn.tenant_id=t AND en.environment_id=e AND wl.workload_id=w AND cn.connection_id=c
 FOR SHARE OF tn,en,wl,gr,cn;
 RETURN coalesce(allowed,false);
END $$;

-- Administrative mutation only. The same connection row is locked FOR SHARE
-- by authorize_scope for the full worker transaction. The existing connections
-- trigger records the pause change and session_user in identity_audit.
CREATE FUNCTION set_connection_paused(t uuid,e uuid,c uuid,pause boolean) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 UPDATE public.connections cn SET paused=pause
 WHERE (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c) AND cn.paused IS DISTINCT FROM pause;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION set_connection_paused(uuid,uuid,uuid,boolean) FROM PUBLIC;

-- Caller must hold the queue row (same lock ordering as worker and reviewer).
-- The API role cannot arbitrarily change action status or mark a refund successful.
CREATE FUNCTION transition_cancel(t uuid,e uuid,a uuid,w uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF NOT public.lock_approval_job(t,e,a) OR NOT public.authorize_scope(t,e,w,c,'cancel_action') THEN RETURN false; END IF;
 UPDATE public.actions SET status='cancelled',reason='ACTION_CANCELLED'
 WHERE (tenant_id,environment_id,id,workload_id)=(t,e,a,w)
 AND request->>'connection_id'=c::text AND status IN ('received','pending_approval','ready');
 IF NOT FOUND THEN RETURN false; END IF;
 INSERT INTO public.audit_events(tenant_id,environment_id,action_id,sequence,event_type)
 SELECT t,e,a,coalesce(max(sequence),0)+1,'action.cancelled'
 FROM public.audit_events WHERE (tenant_id,environment_id,action_id)=(t,e,a);
 PERFORM public.complete_job(t,e,a);
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION transition_cancel(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;

CREATE TABLE action_policy_decisions (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,action_id uuid NOT NULL,audit_sequence bigint NOT NULL,
 connection_id uuid NOT NULL,policy_version bigint,outcome text NOT NULL CHECK(outcome IN ('allow','deny','require_approval','expired','approved','rejected')),
 reason text NOT NULL, evaluated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,environment_id,action_id,audit_sequence),
 FOREIGN KEY(tenant_id,environment_id,action_id,audit_sequence) REFERENCES audit_events(tenant_id,environment_id,action_id,sequence),
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections,
 FOREIGN KEY(tenant_id,environment_id,connection_id,policy_version) REFERENCES policy_versions
);
ALTER TABLE action_policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_policy_decisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON action_policy_decisions
 USING (tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);

-- Use one database timestamp at the write boundary and report an expired
-- update as zero changed rows (the API maps this to a stale decision).
CREATE OR REPLACE FUNCTION guard_approval_decision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.decision IS NOT NULL OR NEW.decision IS NULL THEN
  RAISE EXCEPTION 'approval decision is immutable';
 END IF;
 NEW.decided_at=clock_timestamp();
 IF NEW.expires_at<=NEW.decided_at THEN RETURN NULL; END IF;
 RETURN NEW;
END $$;
