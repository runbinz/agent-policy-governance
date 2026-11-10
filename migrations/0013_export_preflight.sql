-- Bound history cardinality and estimated JSON memory before any jsonb_agg.
-- Streaming UNION ALL + LIMIT avoids materializing an unbounded history set.
-- Six bytes per exported text byte covers JSON escaping; fixed overhead includes
-- keys, UUIDs, numbers and per-row JSONB structure. Conservative limits reject
-- the whole export, never silently truncate evidence.
CREATE FUNCTION preflight_evidence_export(t uuid,e uuid,export_id uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE ids uuid[]; estimated bigint:=4096; seen integer:=0; item record;
BEGIN
 SELECT x.action_ids INTO ids FROM public.evidence_exports x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,export_id);
 IF NOT FOUND THEN RAISE EXCEPTION 'export not found' USING ERRCODE='AP404'; END IF;
 FOR item IN
  SELECT cost FROM (
   SELECT 512::bigint+6*(coalesce(octet_length(a.status),0)::bigint+coalesce(octet_length(a.reason),0)
    +coalesce(octet_length(a.request->>'type'),0)+coalesce(octet_length(a.request#>>'{parameters,currency}'),0))
    +coalesce(pg_column_size(a.id),0) AS cost
    FROM public.actions a WHERE (a.tenant_id,a.environment_id)=(t,e) AND a.id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*coalesce(octet_length(v.event_type),0)::bigint+coalesce(pg_column_size(v.sequence),0)
    FROM public.audit_events v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*(coalesce(octet_length(v.outcome),0)::bigint+coalesce(octet_length(v.reason),0))+coalesce(pg_column_size(v.policy_version),0)
    FROM public.action_policy_decisions v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*coalesce(octet_length(v.decision),0)::bigint+coalesce(pg_column_size(v.reviewer_id),0)
    FROM public.approvals v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*coalesce(octet_length((v.snapshot->'state')::text),0)::bigint
    FROM public.external_dispatches v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+coalesce(pg_column_size(v.generation),0)+coalesce(pg_column_size(v.marked_at_ms),0)
    FROM public.external_attempts v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*coalesce(octet_length(v.state),0)::bigint+coalesce(pg_column_size(v.amount_minor),0)
    FROM public.budget_reservations v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
   UNION ALL
   SELECT 512::bigint+6*coalesce(octet_length(v.event_kind),0)::bigint+coalesce(pg_column_size(v.recorded_at),0)
    FROM public.budget_ledger_events v WHERE (v.tenant_id,v.environment_id)=(t,e) AND v.action_id=ANY(ids)
  ) costs LIMIT 20001
 LOOP
  seen:=seen+1;
  estimated:=estimated+item.cost;
  IF seen>20000 OR estimated>20971520 THEN
   RAISE EXCEPTION 'export_too_large' USING ERRCODE='AP413',HINT='export_preflight_limit';
  END IF;
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION preflight_evidence_export(uuid,uuid,uuid) FROM PUBLIC;

CREATE OR REPLACE FUNCTION snapshot_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,g bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM public.lock_evidence_export(t,e,r,c,export_id,g);
 PERFORM public.preflight_evidence_export(t,e,export_id);
 SELECT jsonb_build_object('schema_version',1,'export_id',export_id,'tenant_id',t,'environment_id',e,'connection_id',c,
 'generated_at',to_char(clock_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'actions',coalesce(jsonb_agg(jsonb_build_object(
  'id',a.id,'status',a.status,'reason',a.reason,'action_type',a.request->>'type',
  'amount_minor',(a.request#>>'{parameters,amount_minor}')::bigint,'currency',a.request#>>'{parameters,currency}',
  'audit',coalesce((SELECT jsonb_agg(jsonb_build_object('sequence',v.sequence,'event_type',v.event_type) ORDER BY v.sequence)
    FROM public.audit_events v WHERE (v.tenant_id,v.environment_id,v.action_id)=(t,e,a.id)),'[]'::jsonb),
  'policy_decisions',coalesce((SELECT jsonb_agg(jsonb_build_object('sequence',p.audit_sequence,'version',p.policy_version,'outcome',p.outcome,'reason',p.reason) ORDER BY p.audit_sequence)
    FROM public.action_policy_decisions p WHERE (p.tenant_id,p.environment_id,p.action_id)=(t,e,a.id)),'[]'::jsonb),
  'approvals',coalesce((SELECT jsonb_agg(jsonb_build_object('generation',q.generation,'policy_version',q.policy_version,'reviewer_id',q.reviewer_id,'decision',q.decision) ORDER BY q.generation)
    FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a.id)),'[]'::jsonb),
  'execution',(SELECT jsonb_build_object('state',d.snapshot->'state','first_send_at',d.snapshot->'first_send_at','retry_until',d.snapshot->'retry_until',
    'attempts',coalesce((SELECT jsonb_agg(jsonb_build_object('generation',v.generation,'marked_at_ms',v.marked_at_ms) ORDER BY v.generation)
      FROM public.external_attempts v WHERE (v.tenant_id,v.environment_id,v.action_id)=(t,e,a.id)),'[]'::jsonb))
    FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a.id)),
  'budget',(SELECT jsonb_build_object('state',b.state,'amount_minor',b.amount_minor,'utc_day',b.utc_day,
    'events',coalesce((SELECT jsonb_agg(jsonb_build_object('sequence',v.sequence,'event_kind',v.event_kind,'recorded_at',v.recorded_at) ORDER BY v.sequence)
      FROM public.budget_ledger_events v WHERE (v.tenant_id,v.environment_id,v.action_id)=(t,e,a.id)),'[]'::jsonb))
    FROM public.budget_reservations b WHERE (b.tenant_id,b.environment_id,b.action_id)=(t,e,a.id))
 ) ORDER BY a.id),'[]'::jsonb)) INTO result
 FROM public.evidence_exports x JOIN public.actions a ON a.id=ANY(x.action_ids) AND (a.tenant_id,a.environment_id)=(x.tenant_id,x.environment_id)
 WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,export_id) AND a.request->>'connection_id'=c::text;
 IF octet_length(result::text)>20971520 THEN RAISE EXCEPTION 'export_too_large' USING ERRCODE='AP413'; END IF;
 PERFORM public.lock_evidence_export(t,e,r,c,export_id,g);
 RETURN result;
END $$;
