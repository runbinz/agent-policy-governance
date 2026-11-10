-- Preserve unknown legacy ages: add columns first, then defaults for new records.
ALTER TABLE approvals ADD COLUMN created_at timestamptz;
ALTER TABLE approvals ALTER COLUMN created_at SET DEFAULT clock_timestamp();
ALTER TABLE external_dispatches ADD COLUMN state_changed_at timestamptz;
ALTER TABLE external_dispatches ALTER COLUMN state_changed_at SET DEFAULT clock_timestamp();
CREATE FUNCTION timestamp_dispatch_state() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF NEW.snapshot->'state' IS DISTINCT FROM OLD.snapshot->'state' THEN NEW.state_changed_at=clock_timestamp();
 ELSE NEW.state_changed_at=OLD.state_changed_at; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER timestamp_dispatch_state BEFORE UPDATE ON external_dispatches FOR EACH ROW EXECUTE FUNCTION timestamp_dispatch_state();
REVOKE ALL ON FUNCTION timestamp_dispatch_state() FROM PUBLIC;
CREATE TABLE operations_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,connection_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
ALTER TABLE operations_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE operations_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON operations_grants USING (tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);
CREATE TRIGGER operations_grant_change AFTER INSERT OR UPDATE OR DELETE ON operations_grants FOR EACH ROW EXECUTE FUNCTION audit_identity_change();
CREATE FUNCTION authorize_operations(t uuid,e uuid,r uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT tn.enabled AND en.enabled AND rv.enabled AND cn.enabled AND gr.enabled INTO allowed
 FROM public.operations_grants gr JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id)
 WHERE (gr.tenant_id,gr.environment_id,gr.reviewer_id,gr.connection_id)=(t,e,r,c)
 FOR SHARE OF tn,en,rv,cn,gr;
 RETURN coalesce(allowed,false);
END $$;
CREATE FUNCTION read_operations(t uuid,e uuid,r uuid,c uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF NOT public.authorize_operations(t,e,r,c) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 WITH moment AS (SELECT statement_timestamp() AS now),
 pending AS (
 SELECT q.created_at FROM public.approvals q JOIN public.actions a ON (a.tenant_id,a.environment_id,a.id)=(q.tenant_id,q.environment_id,q.action_id)
 JOIN public.policy_bindings pb ON (pb.tenant_id,pb.environment_id,pb.connection_id,pb.version)=(q.tenant_id,q.environment_id,q.connection_id,q.policy_version)
 WHERE (q.tenant_id,q.environment_id,q.connection_id)=(t,e,c) AND a.status='pending_approval' AND q.decision IS NULL AND q.expires_at>(SELECT now FROM moment)
 AND NOT EXISTS(SELECT FROM public.approvals newer WHERE (newer.tenant_id,newer.environment_id,newer.action_id)=(t,e,q.action_id) AND newer.generation>q.generation)),
 unresolved AS (SELECT d.snapshot->>'state' AS state,d.state_changed_at FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.connection_id)=(t,e,c) AND NOT d.closed AND d.snapshot->>'state' IN ('unknown','pending','manual_review')),
 ready AS (SELECT j.available_at FROM public.outbox_jobs j JOIN public.actions a ON (a.tenant_id,a.environment_id,a.id)=(j.tenant_id,j.environment_id,j.action_id) WHERE (j.tenant_id,j.environment_id)=(t,e) AND a.request->>'connection_id'=c::text AND a.status IN ('received','ready') AND NOT j.done AND j.available_at<=(SELECT now FROM moment)),
 budget AS (SELECT coalesce(sum(amount_minor) FILTER(WHERE state='held'),0)::bigint held,
 coalesce(sum(amount_minor) FILTER(WHERE state='settled' AND utc_day=((SELECT now FROM moment) AT TIME ZONE 'UTC')::date),0)::bigint committed,
 coalesce(sum(amount_minor) FILTER(WHERE state IN ('held','settled') AND utc_day=((SELECT now FROM moment) AT TIME ZONE 'UTC')::date),0)::bigint used
 FROM public.budget_reservations WHERE (tenant_id,environment_id,connection_id)=(t,e,c))
 SELECT jsonb_build_object(
 'connection_id',c,'sampled_at_unix',floor(extract(epoch FROM m.now))::bigint,
 'tenant_paused',tn.paused,'connection_paused',cn.paused,
 'workloads_paused',(SELECT count(*) FROM public.workloads w JOIN public.workload_grants g USING(tenant_id,environment_id,workload_id) WHERE (g.tenant_id,g.environment_id,g.connection_id)=(t,e,c) AND g.enabled AND w.enabled AND w.paused),
 'pending_approvals',(SELECT count(*) FROM pending),
 'oldest_approval_age_seconds',(SELECT CASE WHEN min(created_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(created_at))))::bigint END FROM pending),
 'held_minor',b.held,'committed_today_minor',b.committed,'daily_used_minor',b.used,
 'daily_limit_minor',lim.daily_limit_minor,'exposure_limit_minor',lim.exposure_limit_minor,
 'unknown_outcomes',(SELECT count(*) FROM unresolved WHERE state='unknown'),
 'pending_provider',(SELECT count(*) FROM unresolved WHERE state='pending'),
 'manual_review',(SELECT count(*) FROM unresolved WHERE state='manual_review'),
 'oldest_unresolved_age_seconds',(SELECT CASE WHEN min(state_changed_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(state_changed_at))))::bigint END FROM unresolved),
 'ready_jobs',(SELECT count(*) FROM ready),
 'oldest_ready_lag_seconds',(SELECT CASE WHEN min(available_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(available_at))))::bigint END FROM ready),
 'failed_notifications',(SELECT count(*) FROM public.notification_jobs WHERE (tenant_id,environment_id,connection_id)=(t,e,c) AND status='failed'),
 'queued_notifications',(SELECT count(*) FROM public.notification_jobs WHERE (tenant_id,environment_id,connection_id)=(t,e,c) AND status IN ('queued','processing')),
 'failed_exports',(SELECT count(*) FROM public.evidence_exports WHERE (tenant_id,environment_id,connection_id)=(t,e,c) AND status='failed'),
 'unknown_age_records',(SELECT count(*) FROM pending WHERE created_at IS NULL)+(SELECT count(*) FROM unresolved WHERE state_changed_at IS NULL))
 INTO result FROM moment m CROSS JOIN budget b JOIN public.tenants tn ON tn.tenant_id=t
 JOIN public.connections cn ON (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c)
 LEFT JOIN public.budget_connections lim ON (lim.tenant_id,lim.environment_id,lim.connection_id)=(t,e,c);
 RETURN result;
END $$;
REVOKE ALL ON operations_grants FROM PUBLIC;
REVOKE ALL ON FUNCTION authorize_operations(uuid,uuid,uuid,uuid),read_operations(uuid,uuid,uuid,uuid) FROM PUBLIC;
