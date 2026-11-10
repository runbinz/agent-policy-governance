-- UUID keyset pagination only: action UUIDs do not imply creation-time ordering.
CREATE INDEX evidence_actions_connection_id ON actions
 (tenant_id,environment_id,(request->>'connection_id'),id);
CREATE INDEX evidence_actions_connection_status_id ON actions
 (tenant_id,environment_id,(request->>'connection_id'),status,id);

CREATE FUNCTION search_action_evidence(t uuid,e uuid,r uuid,c uuid,
 selected_status text,selected_workload uuid,selected_action uuid,
 minimum_minor bigint,maximum_minor bigint,after_id uuid,page_limit bigint)
RETURNS TABLE(id uuid,workload_id uuid,connection_id uuid,status text,reason text,
 amount_minor bigint,currency text,policy_version bigint,budget_state text,budget_amount_minor bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF page_limit NOT BETWEEN 1 AND 100 OR page_limit IS NULL
 OR minimum_minor NOT BETWEEN 0 AND 50000 OR maximum_minor NOT BETWEEN 0 AND 50000
 OR minimum_minor>maximum_minor
 OR (selected_status IS NOT NULL AND selected_status NOT IN (
 'received','denied','succeeded','pending_approval','ready','rejected','expired','cancelled','dispatching','failed_confirmed')) THEN
  RAISE EXCEPTION 'invalid evidence filter' USING ERRCODE='AP400';
 END IF;
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN
  RAISE EXCEPTION 'evidence not found' USING ERRCODE='AP404';
 END IF;
 RETURN QUERY SELECT a.id,a.workload_id,c,a.status,a.reason,
 (a.request#>>'{parameters,amount_minor}')::bigint,a.request#>>'{parameters,currency}',
 p.policy_version,b.state,b.amount_minor
 FROM public.actions a
 LEFT JOIN LATERAL (
  SELECT v.policy_version FROM public.action_policy_decisions v
  WHERE (v.tenant_id,v.environment_id,v.action_id)=(a.tenant_id,a.environment_id,a.id)
  ORDER BY v.audit_sequence DESC LIMIT 1
 ) p ON true
 LEFT JOIN public.budget_reservations b ON (b.tenant_id,b.environment_id,b.action_id)=(a.tenant_id,a.environment_id,a.id)
 WHERE (a.tenant_id,a.environment_id)=(t,e) AND a.request->>'connection_id'=c::text
 AND (selected_status IS NULL OR a.status=selected_status)
 AND (selected_workload IS NULL OR a.workload_id=selected_workload)
 AND (selected_action IS NULL OR a.id=selected_action)
 AND (minimum_minor IS NULL OR (a.request#>>'{parameters,amount_minor}')::bigint>=minimum_minor)
 AND (maximum_minor IS NULL OR (a.request#>>'{parameters,amount_minor}')::bigint<=maximum_minor)
 AND (after_id IS NULL OR a.id>after_id)
 ORDER BY a.id LIMIT page_limit+1;
 -- The authorizer keeps grant/reviewer/scope locks for this entire transaction.
 -- Rechecking also fails closed if future authorizer implementations change.
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN
  RAISE EXCEPTION 'evidence not found' USING ERRCODE='AP404';
 END IF;
END $$;
REVOKE ALL ON FUNCTION search_action_evidence(uuid,uuid,uuid,uuid,text,uuid,uuid,bigint,bigint,uuid,bigint) FROM PUBLIC;
