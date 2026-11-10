CREATE TABLE evidence_export_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,connection_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TABLE evidence_exports (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,id uuid NOT NULL,connection_id uuid NOT NULL,requester_id uuid NOT NULL,
 action_ids uuid[] NOT NULL CHECK(cardinality(action_ids) BETWEEN 1 AND 1000),
 status text NOT NULL CHECK(status IN ('queued','processing','ready','failed')),expires_at timestamptz NOT NULL,
 error_code text,ready_generation bigint,
 PRIMARY KEY(tenant_id,environment_id,id),
 FOREIGN KEY(tenant_id,environment_id,requester_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections,
 CHECK((status='ready')=(ready_generation IS NOT NULL))
);
CREATE TABLE evidence_export_audit (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,export_id uuid NOT NULL,requester_id uuid NOT NULL,
 sequence bigint GENERATED ALWAYS AS IDENTITY,event_type text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,environment_id,export_id,sequence),
 FOREIGN KEY(tenant_id,environment_id,export_id) REFERENCES evidence_exports
);
-- Private cross-tenant routing metadata; it contains no evidence or object keys.
CREATE TABLE evidence_export_jobs (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,environment_id uuid NOT NULL,connection_id uuid NOT NULL,requester_id uuid NOT NULL,
 generation bigint NOT NULL DEFAULT 0,attempts integer NOT NULL DEFAULT 0,lease_until timestamptz,
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),expires_at timestamptz NOT NULL,done boolean NOT NULL DEFAULT false,
 FOREIGN KEY(tenant_id,environment_id,id) REFERENCES evidence_exports
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['evidence_export_grants','evidence_exports','evidence_export_audit'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE TRIGGER export_grants_change AFTER INSERT OR UPDATE OR DELETE ON evidence_export_grants
FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

CREATE FUNCTION evidence_export_allowed(t uuid,e uuid,r uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT g.enabled AND rv.enabled AND en.enabled AND tn.enabled INTO allowed
 FROM public.evidence_export_grants g JOIN public.reviewers rv
 ON (rv.tenant_id,rv.environment_id,rv.reviewer_id)=(g.tenant_id,g.environment_id,g.reviewer_id)
 JOIN public.environments en ON (en.tenant_id,en.environment_id)=(g.tenant_id,g.environment_id)
 JOIN public.tenants tn ON tn.tenant_id=g.tenant_id
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=(t,e,r,c)
 FOR SHARE OF g,rv,en,tn;
 RETURN coalesce(allowed,false);
END $$;
CREATE FUNCTION evidence_export_event(t uuid,e uuid,id uuid,r uuid,event text) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,public AS $$
 INSERT INTO public.evidence_export_audit(tenant_id,environment_id,export_id,requester_id,event_type) VALUES(t,e,id,r,event)
$$;
CREATE FUNCTION request_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,ids uuid[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE found_count integer;
BEGIN
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN RAISE EXCEPTION 'export not found' USING ERRCODE='AP404'; END IF;
 IF cardinality(ids) NOT BETWEEN 1 AND 1000 OR ids IS NULL OR
   cardinality(ids)<>(SELECT count(DISTINCT x) FROM unnest(ids) x) THEN
  RAISE EXCEPTION 'invalid export selection' USING ERRCODE='AP400';
 END IF;
 SELECT count(*) INTO found_count FROM public.actions a
 WHERE (a.tenant_id,a.environment_id)=(t,e) AND a.id=ANY(ids) AND a.request->>'connection_id'=c::text;
 IF found_count<>cardinality(ids) THEN RAISE EXCEPTION 'export not found' USING ERRCODE='AP404'; END IF;
 INSERT INTO public.evidence_exports VALUES(t,e,export_id,c,r,ids,'queued',clock_timestamp()+interval '1 hour',NULL,NULL);
 INSERT INTO public.evidence_export_jobs(id,tenant_id,environment_id,connection_id,requester_id,expires_at)
 SELECT export_id,t,e,c,r,x.expires_at FROM public.evidence_exports x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,export_id);
 PERFORM public.evidence_export_event(t,e,export_id,r,'export.requested');
END $$;
CREATE FUNCTION read_evidence_export(t uuid,e uuid,r uuid,export_id uuid,download boolean)
RETURNS TABLE(id uuid,connection_id uuid,status text,expires_at text,error_code text,generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE item public.evidence_exports%ROWTYPE;
BEGIN
 SELECT * INTO item FROM public.evidence_exports x WHERE (x.tenant_id,x.environment_id,x.id,x.requester_id)=(t,e,export_id,r);
 IF NOT FOUND OR item.expires_at<=clock_timestamp() OR NOT public.evidence_export_allowed(t,e,r,item.connection_id) THEN
  RAISE EXCEPTION 'export not found' USING ERRCODE='AP404';
 END IF;
 IF item.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'export not found' USING ERRCODE='AP404'; END IF;
 IF download AND item.status<>'ready' THEN RAISE EXCEPTION 'export not ready' USING ERRCODE='AP409'; END IF;
 RETURN QUERY SELECT item.id,item.connection_id,item.status,
 to_char(item.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),item.error_code,item.ready_generation;
END $$;
CREATE FUNCTION record_evidence_download(t uuid,e uuid,r uuid,export_id uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM * FROM public.read_evidence_export(t,e,r,export_id,true);
 PERFORM public.evidence_export_event(t,e,export_id,r,'export.downloaded');
END $$;
CREATE FUNCTION claim_evidence_export()
RETURNS TABLE(id uuid,tenant_id uuid,environment_id uuid,connection_id uuid,requester_id uuid,generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE job public.evidence_export_jobs%ROWTYPE;
BEGIN
 FOR i IN 1..20 LOOP
  SELECT * INTO job FROM public.evidence_export_jobs q
  WHERE NOT q.done AND q.available_at<=clock_timestamp() AND q.expires_at>clock_timestamp()
  AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp())
  ORDER BY q.available_at,q.id FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM set_config('apl.tenant_id',job.tenant_id::text,true),set_config('apl.environment_id',job.environment_id::text,true);
  IF job.attempts>=3 OR NOT public.evidence_export_allowed(job.tenant_id,job.environment_id,job.requester_id,job.connection_id) THEN
   UPDATE public.evidence_export_jobs q SET done=true WHERE q.id=job.id;
   UPDATE public.evidence_exports x SET status='failed',error_code='export_failed'
    WHERE (x.tenant_id,x.environment_id,x.id)=(job.tenant_id,job.environment_id,job.id);
   PERFORM public.evidence_export_event(job.tenant_id,job.environment_id,job.id,job.requester_id,'export.failed');
   CONTINUE;
  END IF;
  UPDATE public.evidence_export_jobs q SET generation=q.generation+1,attempts=q.attempts+1,
   lease_until=clock_timestamp()+interval '60 seconds' WHERE q.id=job.id RETURNING * INTO job;
  UPDATE public.evidence_exports x SET status='processing',error_code=NULL
   WHERE (x.tenant_id,x.environment_id,x.id)=(job.tenant_id,job.environment_id,job.id);
  PERFORM public.evidence_export_event(job.tenant_id,job.environment_id,job.id,job.requester_id,'export.processing');
  RETURN QUERY SELECT job.id,job.tenant_id,job.environment_id,job.connection_id,job.requester_id,job.generation;
  RETURN;
 END LOOP;
END $$;
CREATE FUNCTION lock_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,g bigint) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE job public.evidence_export_jobs%ROWTYPE;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'stale export lease' USING ERRCODE='AP409';
 END IF;
 SELECT * INTO job FROM public.evidence_export_jobs q WHERE q.id=export_id FOR UPDATE;
 IF NOT FOUND OR (job.tenant_id,job.environment_id,job.requester_id,job.connection_id,job.generation) IS DISTINCT FROM (t,e,r,c,g)
 OR job.done OR job.lease_until IS NULL OR job.lease_until<=clock_timestamp() OR job.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'stale export lease' USING ERRCODE='AP409';
 END IF;
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN RAISE EXCEPTION 'export not found' USING ERRCODE='AP404'; END IF;
 -- Grant/reviewer locks can wait. Recheck the wall clock at the end of every
 -- authorization boundary so a stale lease cannot publish a ready object.
 IF job.lease_until<=clock_timestamp() OR job.expires_at<=clock_timestamp() THEN
  RAISE EXCEPTION 'stale export lease' USING ERRCODE='AP409';
 END IF;
END $$;
CREATE FUNCTION snapshot_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,g bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE result jsonb;
BEGIN
 PERFORM public.lock_evidence_export(t,e,r,c,export_id,g);
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
CREATE FUNCTION finish_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,g bigint,target text,code text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE attempts integer;
BEGIN
 PERFORM public.lock_evidence_export(t,e,r,c,export_id,g);
 IF target NOT IN ('ready','failed','retry') OR target IS NULL OR
  (target='failed' AND (code IS NULL OR code NOT IN ('export_too_large','snapshot_failed','object_write_failed'))) THEN
  RAISE EXCEPTION 'invalid export transition' USING ERRCODE='AP400';
 END IF;
 SELECT q.attempts INTO attempts FROM public.evidence_export_jobs q WHERE q.id=export_id;
 IF target='retry' AND attempts>=3 THEN target:='failed';code:='export_failed'; END IF;
 UPDATE public.evidence_export_jobs q SET done=target<>'retry',lease_until=NULL,available_at=clock_timestamp()+interval '5 seconds' WHERE q.id=export_id;
 UPDATE public.evidence_exports x SET status=CASE WHEN target='retry' THEN 'queued' ELSE target END,
 error_code=CASE WHEN target='failed' THEN code ELSE NULL END,ready_generation=CASE WHEN target='ready' THEN g ELSE NULL END
 WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,export_id);
 PERFORM public.evidence_export_event(t,e,export_id,r,'export.'||CASE WHEN target='retry' THEN 'queued' ELSE target END);
END $$;
REVOKE ALL ON FUNCTION evidence_export_allowed(uuid,uuid,uuid,uuid),evidence_export_event(uuid,uuid,uuid,uuid,text),
 request_evidence_export(uuid,uuid,uuid,uuid,uuid,uuid[]),read_evidence_export(uuid,uuid,uuid,uuid,boolean),
 record_evidence_download(uuid,uuid,uuid,uuid),claim_evidence_export(),
 lock_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint),snapshot_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint),
 finish_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint,text,text) FROM PUBLIC;
