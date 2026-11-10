-- Recovery reads have independent authority and retain identity locks until commit.
CREATE FUNCTION authorize_reconciliation(t uuid,e uuid,r uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT tn.enabled AND en.enabled AND rv.enabled AND cn.enabled AND gr.enabled INTO allowed
 FROM public.reconciliation_grants gr JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id)
 WHERE (gr.tenant_id,gr.environment_id,gr.reviewer_id,gr.connection_id)=(t,e,r,c)
 FOR SHARE OF tn,en,rv,cn,gr;
 RETURN coalesce(allowed,false);
END $$;
CREATE FUNCTION read_operations_items(t uuid,e uuid,r uuid,c uuid,k text,after_key uuid,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF NOT public.authorize_operations(t,e,r,c) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 IF k IS NULL OR k NOT IN ('dispatches','ready_jobs') OR page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 WITH bounded AS MATERIALIZED (
 SELECT a.id,a.workload_id,a.status,d.snapshot,d.connection_id dispatch_connection,d.closed,d.abandoned_at_ms,d.state_changed_at,
 CASE WHEN k='ready_jobs' THEN j.available_at END due,
 b.state hold_state,coalesce(CASE WHEN b.state='held' THEN b.amount_minor ELSE 0 END,0) held_minor,
 public.authorize_reconciliation(t,e,r,c) reconciliation_allowed,
 q.closed queue_closed
 FROM public.actions a
 LEFT JOIN public.external_dispatches d ON (d.tenant_id,d.environment_id,d.action_id)=(a.tenant_id,a.environment_id,a.id)
 LEFT JOIN public.external_dispatch_queue q ON (q.tenant_id,q.environment_id,q.action_id)=(a.tenant_id,a.environment_id,a.id)
 LEFT JOIN public.outbox_jobs j ON (j.tenant_id,j.environment_id,j.action_id)=(a.tenant_id,a.environment_id,a.id)
 LEFT JOIN public.budget_reservations b ON (b.tenant_id,b.environment_id,b.action_id)=(a.tenant_id,a.environment_id,a.id)
 WHERE (a.tenant_id,a.environment_id)=(t,e) AND a.request->>'connection_id'=c::text
 AND (after_key IS NULL OR a.id>after_key) AND public.evidence_action_visible(t,e,a.id)
 AND ((k='dispatches' AND NOT d.closed AND d.abandoned_at_ms IS NULL)
 OR (k='ready_jobs' AND a.status IN ('received','ready') AND NOT j.done AND j.available_at<=statement_timestamp()))
 ORDER BY a.id LIMIT page_limit+1
 ) SELECT coalesce(jsonb_agg(jsonb_build_object('action_id',id,'workload_id',workload_id,'action_status',status,
 'queue_due_at',public.action_detail_time(due),'queue_lag_seconds',CASE WHEN due IS NULL THEN NULL ELSE greatest(0,floor(extract(epoch FROM statement_timestamp()-due)))::bigint END,
 'state_changed_at',public.action_detail_time(state_changed_at),'hold_state',hold_state,'held_minor',held_minor,
 '_snapshot',snapshot,'_connection',dispatch_connection,'_closed',closed,'_abandoned',abandoned_at_ms,
 '_reconciliation_allowed',reconciliation_allowed,'_queue_closed',queue_closed,
 '_now_ms',floor(extract(epoch FROM statement_timestamp())*1000)::bigint) ORDER BY id),'[]'::jsonb) INTO result FROM bounded;
 RETURN result;
END $$;
CREATE FUNCTION read_reconciliation_state(t uuid,e uuid,r uuid,a uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE c uuid; result jsonb;
BEGIN
 SELECT (x.request->>'connection_id')::uuid INTO c FROM public.actions x
 WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) AND public.evidence_action_visible(t,e,a);
 IF c IS NULL OR NOT public.authorize_reconciliation(t,e,r,c) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 SELECT jsonb_build_object('action_id',a,'connection_id',c,'action_status',x.status,
 '_snapshot',d.snapshot,'_connection',d.connection_id,'_closed',d.closed,'_abandoned',d.abandoned_at_ms,
 '_queue_closed',q.closed,'_now_ms',floor(extract(epoch FROM statement_timestamp())*1000)::bigint)
 INTO result FROM public.actions x LEFT JOIN public.external_dispatches d ON (d.tenant_id,d.environment_id,d.action_id)=(x.tenant_id,x.environment_id,x.id)
 LEFT JOIN public.external_dispatch_queue q ON (q.tenant_id,q.environment_id,q.action_id)=(x.tenant_id,x.environment_id,x.id)
 WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a);
 RETURN result;
END $$;
CREATE OR REPLACE FUNCTION request_external_reconciliation(t uuid,e uuid,a uuid,r uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE state jsonb; c uuid; is_closed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN 'hidden'; END IF;
 SELECT q.closed INTO is_closed FROM public.external_dispatch_queue q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'hidden'; END IF;
 SELECT d.connection_id,d.snapshot->'state' INTO c,state FROM public.external_dispatches d JOIN public.actions x ON (x.tenant_id,x.environment_id,x.id)=(d.tenant_id,d.environment_id,d.action_id)
 WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a) AND x.request->>'connection_id'=d.connection_id::text AND public.evidence_action_visible(t,e,a);
 IF c IS NULL OR NOT public.authorize_reconciliation(t,e,r,c) THEN RETURN 'hidden'; END IF;
 IF state IS DISTINCT FROM '"manual_review"'::jsonb THEN RETURN 'not_manual'; END IF;
 IF NOT is_closed THEN RETURN 'queued'; END IF;
 INSERT INTO public.external_reconciliation_requests(tenant_id,environment_id,action_id,reviewer_id) VALUES(t,e,a,r);
 INSERT INTO public.audit_events(tenant_id,environment_id,action_id,sequence,event_type) SELECT t,e,a,coalesce(max(sequence),0)+1,'dispatch.reconciliation_requested' FROM public.audit_events WHERE (tenant_id,environment_id,action_id)=(t,e,a);
 UPDATE public.external_dispatch_queue SET closed=false,available_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint WHERE (tenant_id,environment_id,action_id)=(t,e,a);
 RETURN 'queued';
END $$;
REVOKE ALL ON FUNCTION authorize_reconciliation(uuid,uuid,uuid,uuid),read_operations_items(uuid,uuid,uuid,uuid,text,uuid,bigint),read_reconciliation_state(uuid,uuid,uuid,uuid) FROM PUBLIC;
