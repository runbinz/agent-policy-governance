-- Existing audit rows remain historically undated.
ALTER TABLE audit_events ADD COLUMN recorded_at timestamptz;
ALTER TABLE audit_events ALTER COLUMN recorded_at SET DEFAULT statement_timestamp();
CREATE TABLE action_detail_grants (LIKE operations_grants INCLUDING ALL);
ALTER TABLE action_detail_grants ADD FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers;
ALTER TABLE action_detail_grants ADD FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections;
ALTER TABLE action_detail_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE action_detail_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON action_detail_grants USING (tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);
CREATE TRIGGER action_detail_grant_change AFTER INSERT OR UPDATE OR DELETE ON action_detail_grants FOR EACH ROW EXECUTE FUNCTION audit_identity_change();
CREATE FUNCTION authorize_action_detail(t uuid,e uuid,r uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT tn.enabled AND en.enabled AND rv.enabled AND cn.enabled AND gr.enabled INTO allowed
 FROM public.action_detail_grants gr JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id)
 WHERE (gr.tenant_id,gr.environment_id,gr.reviewer_id,gr.connection_id)=(t,e,r,c)
 FOR SHARE OF tn,en,rv,cn,gr;
 RETURN coalesce(allowed,false);
END $$;
CREATE FUNCTION action_detail_time(moment timestamptz) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT to_char(moment AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"') $$;
CREATE FUNCTION action_detail_reason(reason text) RETURNS text LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT CASE WHEN reason IN ('POLICY_AUTO_ALLOW','APPROVAL_REQUIRED','APPROVAL_SATISFIED','POLICY_HARD_LIMIT','INVALID_POLICY','INVALID_REQUEST','NO_ACTIVE_POLICY','AUTHORIZATION_REVOKED','APPROVAL_EXPIRED','BUDGET_DAILY_EXCEEDED','BUDGET_EXPOSURE_EXCEEDED','BUDGET_NOT_CONFIGURED','PROVIDER_CHARGE_INELIGIBLE','PROVIDER_CONFIRMED_NON_EXECUTION') THEN reason ELSE 'OTHER' END $$;
CREATE FUNCTION read_action_detail(t uuid,e uuid,r uuid,c uuid,a uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF NOT public.authorize_action_detail(t,e,r,c) OR NOT EXISTS(SELECT FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) AND x.request->>'connection_id'=c::text AND public.evidence_action_visible(t,e,a)) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 SELECT jsonb_build_object('schema_version',1,'observed_at',public.action_detail_time(statement_timestamp()),'id',x.id,'workload_id',x.workload_id,'connection_id',c,'status',x.status,'created_at',public.action_detail_time(x.created_at),'terminal_at',public.action_detail_time(x.terminal_at),
 'immutable_request',jsonb_build_object('type',x.request->'type','resource',jsonb_build_object('payment_id',x.request#>'{resource,payment_id}'),'parameters',jsonb_build_object('amount_minor',x.request#>'{parameters,amount_minor}','currency',x.request#>'{parameters,currency}')),
 'policy',jsonb_build_object('latest',(SELECT jsonb_build_object('audit_sequence',q.audit_sequence,'policy_version',q.policy_version,'outcome',q.outcome,'reason_code',public.action_detail_reason(q.reason)) FROM public.action_policy_decisions q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) ORDER BY q.audit_sequence DESC LIMIT 1)),
 'approval',(SELECT jsonb_build_object('generation',q.generation,'policy_version',q.policy_version,'action_digest',q.action_digest,'queued_at',public.action_detail_time(q.created_at),'expires_at',public.action_detail_time(q.expires_at),'reviewer_id',q.reviewer_id,'decision',q.decision,'decided_at',public.action_detail_time(q.decided_at)) FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) ORDER BY q.generation DESC LIMIT 1),
 'decision_eligibility',jsonb_build_object('can_decide',x.status='pending_approval' AND public.authorize_reviewer(t,e,r,c) AND coalesce((SELECT q.decision IS NULL AND q.expires_at>statement_timestamp() AND EXISTS(SELECT FROM public.policy_bindings b WHERE (b.tenant_id,b.environment_id,b.connection_id,b.version)=(t,e,c,q.policy_version)) FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) ORDER BY generation DESC LIMIT 1),false),'reason_code',CASE WHEN x.status<>'pending_approval' THEN 'APPROVAL_NOT_AVAILABLE' WHEN NOT public.authorize_reviewer(t,e,r,c) THEN 'NO_AUTHORITY' ELSE coalesce((SELECT CASE WHEN q.decision IS NOT NULL THEN 'APPROVAL_NOT_AVAILABLE' WHEN q.expires_at<=statement_timestamp() THEN 'APPROVAL_EXPIRED' WHEN NOT EXISTS(SELECT FROM public.policy_bindings b WHERE (b.tenant_id,b.environment_id,b.connection_id,b.version)=(t,e,c,q.policy_version)) THEN 'POLICY_CHANGED' ELSE 'ELIGIBLE' END FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) ORDER BY q.generation DESC LIMIT 1),'APPROVAL_NOT_AVAILABLE') END),
 'budget',(SELECT jsonb_build_object('state',b.state,'amount_minor',b.amount_minor,'currency','USD','utc_day',b.utc_day::text,'reserved_at',(SELECT public.action_detail_time(l.recorded_at) FROM public.budget_ledger_events l WHERE (l.tenant_id,l.environment_id,l.action_id,l.sequence)=(t,e,a,1)),'settled_or_released_at',(SELECT public.action_detail_time(l.recorded_at) FROM public.budget_ledger_events l WHERE (l.tenant_id,l.environment_id,l.action_id,l.sequence)=(t,e,a,2))) FROM public.budget_reservations b WHERE (b.tenant_id,b.environment_id,b.action_id)=(t,e,a)),
 '_dispatch',(SELECT jsonb_build_object('snapshot',d.snapshot,'state_changed_at',public.action_detail_time(d.state_changed_at),'abandoned_at',public.action_detail_time(to_timestamp(d.abandoned_at_ms::double precision/1000))) FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a)),
 '_fixture',EXISTS(SELECT FROM public.fake_effects f WHERE (f.tenant_id,f.environment_id,f.action_id)=(t,e,a))) INTO result FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a);
 RETURN result;
END $$;
CREATE FUNCTION read_action_history(t uuid,e uuid,r uuid,c uuid,a uuid,k text,after_key bigint,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF k NOT IN ('audit','policy','approval','budget','attempt') OR k IS NULL OR after_key<0 OR after_key IS NULL OR page_limit NOT BETWEEN 1 AND 100 OR page_limit IS NULL THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 IF NOT public.authorize_action_detail(t,e,r,c) OR NOT EXISTS(SELECT FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) AND x.request->>'connection_id'=c::text AND public.evidence_action_visible(t,e,a)) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 IF k='audit' THEN SELECT coalesce(jsonb_agg(item ORDER BY ordering),'[]'::jsonb) INTO result FROM (SELECT jsonb_build_object('kind','audit','sequence',q.sequence,'event_type',CASE WHEN q.event_type IN ('action.received','action.denied','action.succeeded','action.pending_approval','action.ready','action.rejected','action.expired','action.cancelled','action.dispatching','action.failed_confirmed','approval.requested','approval.approved','approval.rejected','dispatch.authorized','dispatch.send_marked','dispatch.succeeded','dispatch.failed_confirmed','dispatch.pending','dispatch.unknown','dispatch.manual_review','dispatch.abandoned_unsent','dispatch.reconciliation_requested') THEN q.event_type ELSE 'OTHER' END,'recorded_at',public.action_detail_time(q.recorded_at)) item,q.sequence ordering FROM public.audit_events q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND q.sequence>after_key ORDER BY q.sequence LIMIT page_limit+1) bounded; END IF;
 IF k='policy' THEN SELECT coalesce(jsonb_agg(item ORDER BY ordering),'[]'::jsonb) INTO result FROM (SELECT jsonb_build_object('audit_sequence',q.audit_sequence,'policy_version',q.policy_version,'outcome',q.outcome,'reason_code',public.action_detail_reason(q.reason)) || jsonb_build_object('kind','policy','evaluated_at',public.action_detail_time(q.evaluated_at)) item,q.audit_sequence ordering FROM public.action_policy_decisions q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND q.audit_sequence>after_key ORDER BY q.audit_sequence LIMIT page_limit+1) bounded; END IF;
 IF k='approval' THEN SELECT coalesce(jsonb_agg(item ORDER BY ordering),'[]'::jsonb) INTO result FROM (SELECT jsonb_build_object('generation',q.generation,'policy_version',q.policy_version,'action_digest',q.action_digest,'queued_at',public.action_detail_time(q.created_at),'expires_at',public.action_detail_time(q.expires_at),'reviewer_id',q.reviewer_id,'decision',q.decision,'decided_at',public.action_detail_time(q.decided_at)) || jsonb_build_object('kind','approval') item,q.generation ordering FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND q.generation>after_key ORDER BY q.generation LIMIT page_limit+1) bounded; END IF;
 IF k='budget' THEN SELECT coalesce(jsonb_agg(item ORDER BY ordering),'[]'::jsonb) INTO result FROM (SELECT jsonb_build_object('kind','budget','sequence',q.sequence,'event_kind',q.event_kind,'recorded_at',public.action_detail_time(q.recorded_at)) item,q.sequence ordering FROM public.budget_ledger_events q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND q.sequence>after_key ORDER BY q.sequence LIMIT page_limit+1) bounded; END IF;
 IF k='attempt' THEN SELECT coalesce(jsonb_agg(item ORDER BY ordering),'[]'::jsonb) INTO result FROM (SELECT jsonb_build_object('kind','attempt','generation',q.generation,'recorded_at',public.action_detail_time(to_timestamp(q.marked_at_ms::double precision/1000))) item,q.generation ordering FROM public.external_attempts q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND q.generation>after_key ORDER BY q.generation LIMIT page_limit+1) bounded; END IF;
 RETURN result; END $$;
REVOKE ALL ON action_detail_grants FROM PUBLIC;
REVOKE ALL ON FUNCTION authorize_action_detail(uuid,uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION read_action_detail(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION read_action_history(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION action_detail_time(timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION action_detail_reason(text) FROM PUBLIC;
