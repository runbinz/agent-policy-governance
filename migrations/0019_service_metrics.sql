-- Private aggregate only; no tenant identifiers or unbounded labels escape.
CREATE FUNCTION read_service_metrics() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
 WITH moment AS (SELECT statement_timestamp() AS now),
 pending AS (
 SELECT q.created_at FROM public.approvals q JOIN public.actions a ON (a.tenant_id,a.environment_id,a.id)=(q.tenant_id,q.environment_id,q.action_id)
 JOIN public.policy_bindings pb ON (pb.tenant_id,pb.environment_id,pb.connection_id,pb.version)=(q.tenant_id,q.environment_id,q.connection_id,q.policy_version)
 WHERE a.status='pending_approval' AND q.decision IS NULL AND q.expires_at>(SELECT now FROM moment)
 AND NOT EXISTS(SELECT FROM public.approvals newer WHERE (newer.tenant_id,newer.environment_id,newer.action_id)=(q.tenant_id,q.environment_id,q.action_id) AND newer.generation>q.generation)),
 unresolved AS (SELECT d.snapshot->>'state' AS state,d.state_changed_at FROM public.external_dispatches d WHERE NOT d.closed AND d.snapshot->>'state' IN ('unknown','pending','manual_review')),
 ready AS (SELECT j.available_at FROM public.outbox_jobs j JOIN public.actions a ON (a.tenant_id,a.environment_id,a.id)=(j.tenant_id,j.environment_id,j.action_id) WHERE a.status IN ('received','ready') AND NOT j.done AND j.available_at<=(SELECT now FROM moment)),
 decisions AS (SELECT outcome,reason,count(*)::bigint n FROM (SELECT CASE WHEN outcome IN ('allow','require_approval','deny') THEN outcome ELSE 'other' END outcome,CASE WHEN reason IN ('POLICY_AUTO_ALLOW','APPROVAL_REQUIRED','APPROVAL_SATISFIED','POLICY_HARD_LIMIT','INVALID_POLICY','INVALID_REQUEST','NO_ACTIVE_POLICY','AUTHORIZATION_REVOKED','APPROVAL_EXPIRED','BUDGET_DAILY_EXCEEDED','BUDGET_EXPOSURE_EXCEEDED','BUDGET_NOT_CONFIGURED','PROVIDER_CHARGE_INELIGIBLE','OTHER') THEN reason ELSE 'OTHER' END reason FROM public.action_policy_decisions) bounded GROUP BY outcome,reason),
 budget AS (SELECT coalesce(sum(amount_minor) FILTER(WHERE state='held'),0)::bigint held,
 coalesce(sum(amount_minor) FILTER(WHERE state='settled' AND utc_day=((SELECT now FROM moment) AT TIME ZONE 'UTC')::date),0)::bigint committed,
 coalesce(sum(amount_minor) FILTER(WHERE state IN ('held','settled') AND utc_day=((SELECT now FROM moment) AT TIME ZONE 'UTC')::date),0)::bigint used
 FROM public.budget_reservations)
 SELECT jsonb_build_object(
 'sampled_at_unix',floor(extract(epoch FROM m.now))::bigint,
 'pending_approvals',(SELECT count(*) FROM pending),
 'oldest_approval_age_seconds',(SELECT CASE WHEN min(created_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(created_at))))::bigint END FROM pending),
 'held_minor',b.held,'committed_today_minor',b.committed,
 'unknown_outcomes',(SELECT count(*) FROM unresolved WHERE state='unknown'),
 'pending_provider',(SELECT count(*) FROM unresolved WHERE state='pending'),
 'manual_review',(SELECT count(*) FROM unresolved WHERE state='manual_review'),
 'oldest_unresolved_age_seconds',(SELECT CASE WHEN min(state_changed_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(state_changed_at))))::bigint END FROM unresolved),
 'ready_jobs',(SELECT count(*) FROM ready),
 'oldest_ready_lag_seconds',(SELECT CASE WHEN min(available_at) IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM m.now-min(available_at))))::bigint END FROM ready),
 'failed_notifications',(SELECT count(*) FROM public.notification_jobs WHERE status='failed'),
 'unknown_age_records',(SELECT count(*) FROM pending WHERE created_at IS NULL)+(SELECT count(*) FROM unresolved WHERE state_changed_at IS NULL),
 'decisions',(SELECT coalesce(jsonb_agg(jsonb_build_object('outcome',outcome,'reason',reason,'count',n) ORDER BY outcome,reason),'[]'::jsonb) FROM decisions))
 FROM moment m CROSS JOIN budget b;
$$;
REVOKE ALL ON FUNCTION read_service_metrics() FROM PUBLIC;
