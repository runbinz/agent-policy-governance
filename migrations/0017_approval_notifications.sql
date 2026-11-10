CREATE TABLE notification_routes (
 id uuid PRIMARY KEY,tenant_id uuid NOT NULL,environment_id uuid NOT NULL,connection_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('fake','slack')),enabled boolean NOT NULL DEFAULT true,
 team_id text,channel_id text,
 CHECK((kind='fake' AND team_id IS NULL AND channel_id IS NULL) OR
       (kind='slack' AND team_id ~ '^T[A-Z0-9]{8,63}$' AND channel_id ~ '^[CG][A-Z0-9]{8,63}$' AND team_id IS NOT NULL AND channel_id IS NOT NULL)),
 UNIQUE(tenant_id,environment_id,connection_id,id),
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE UNIQUE INDEX notification_enabled_route ON notification_routes(tenant_id,environment_id,connection_id) WHERE enabled;
CREATE FUNCTION guard_notification_route() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' OR (to_jsonb(NEW)-'enabled') IS DISTINCT FROM (to_jsonb(OLD)-'enabled') THEN
  RAISE EXCEPTION 'notification recipient is immutable; disable and create a route';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_notification_route BEFORE UPDATE OR DELETE ON notification_routes FOR EACH ROW EXECUTE FUNCTION guard_notification_route();
CREATE TRIGGER audit_notification_route AFTER INSERT OR UPDATE ON notification_routes FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

-- Private routing metadata and receipts. No request, digest, payment, customer,
-- provider key or message text is stored in these tables.
CREATE TABLE notification_jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),tenant_id uuid NOT NULL,environment_id uuid NOT NULL,
 connection_id uuid NOT NULL,action_id uuid NOT NULL,approval_generation bigint NOT NULL,expires_at timestamptz NOT NULL,
 route_id uuid,generation bigint NOT NULL DEFAULT 0,attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','processing','delivered','failed','skipped')),
 available_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,
 UNIQUE(tenant_id,environment_id,action_id,approval_generation),
 FOREIGN KEY(tenant_id,environment_id,action_id,approval_generation) REFERENCES approvals,
 FOREIGN KEY(tenant_id,environment_id,connection_id,route_id) REFERENCES notification_routes(tenant_id,environment_id,connection_id,id)
);
CREATE FUNCTION guard_notification_job_route() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.route_id IS NOT NULL AND NEW.route_id IS DISTINCT FROM OLD.route_id THEN
  RAISE EXCEPTION 'notification job recipient is immutable';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_notification_job_route BEFORE UPDATE ON notification_jobs FOR EACH ROW EXECUTE FUNCTION guard_notification_job_route();
CREATE TABLE notification_channels (
 team_id text NOT NULL,channel_id text NOT NULL,job_id uuid REFERENCES notification_jobs,
 generation bigint,lease_until timestamptz,next_send_at timestamptz NOT NULL DEFAULT '-infinity',
 PRIMARY KEY(team_id,channel_id)
);
CREATE TABLE notification_receipts (
 job_id uuid PRIMARY KEY REFERENCES notification_jobs,route_id uuid NOT NULL REFERENCES notification_routes,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE notification_audit (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,job_id uuid NOT NULL REFERENCES notification_jobs,
 event_type text NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION enqueue_approval_notification() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE queued uuid;
BEGIN
 INSERT INTO public.notification_jobs(tenant_id,environment_id,connection_id,action_id,approval_generation,expires_at)
 VALUES(NEW.tenant_id,NEW.environment_id,NEW.connection_id,NEW.action_id,NEW.generation,NEW.expires_at)
 ON CONFLICT(tenant_id,environment_id,action_id,approval_generation) DO NOTHING RETURNING id INTO queued;
 IF queued IS NOT NULL THEN INSERT INTO public.notification_audit(job_id,event_type) VALUES(queued,'notification.queued'); END IF;
 RETURN NULL;
END $$;
CREATE TRIGGER enqueue_approval_notification AFTER INSERT ON approvals FOR EACH ROW EXECUTE FUNCTION enqueue_approval_notification();
WITH queued AS (
 INSERT INTO notification_jobs(tenant_id,environment_id,connection_id,action_id,approval_generation,expires_at)
 SELECT q.tenant_id,q.environment_id,q.connection_id,q.action_id,q.generation,q.expires_at FROM approvals q JOIN actions a
 ON (a.tenant_id,a.environment_id,a.id)=(q.tenant_id,q.environment_id,q.action_id)
 WHERE a.status='pending_approval' AND q.decision IS NULL AND q.expires_at>clock_timestamp()
 AND q.generation=(SELECT max(p.generation) FROM approvals p WHERE (p.tenant_id,p.environment_id,p.action_id)=(q.tenant_id,q.environment_id,q.action_id))
 RETURNING id
) INSERT INTO notification_audit(job_id,event_type) SELECT id,'notification.queued' FROM queued;

CREATE FUNCTION notification_current(job public.notification_jobs) RETURNS boolean LANGUAGE sql SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(
  SELECT FROM public.approvals q JOIN public.actions a ON (a.tenant_id,a.environment_id,a.id)=(q.tenant_id,q.environment_id,q.action_id)
  JOIN public.policy_bindings pb ON (pb.tenant_id,pb.environment_id,pb.connection_id,pb.version)=(q.tenant_id,q.environment_id,q.connection_id,q.policy_version)
  JOIN public.tenants tn ON tn.tenant_id=a.tenant_id
  JOIN public.environments en ON (en.tenant_id,en.environment_id)=(a.tenant_id,a.environment_id)
  JOIN public.connections cn ON (cn.tenant_id,cn.environment_id,cn.connection_id)=(q.tenant_id,q.environment_id,q.connection_id)
  JOIN public.workloads w ON (w.tenant_id,w.environment_id,w.workload_id)=(a.tenant_id,a.environment_id,a.workload_id)
  JOIN public.workload_grants g ON (g.tenant_id,g.environment_id,g.workload_id,g.connection_id)=(a.tenant_id,a.environment_id,a.workload_id,q.connection_id)
  WHERE (q.tenant_id,q.environment_id,q.connection_id,q.action_id,q.generation)=(job.tenant_id,job.environment_id,job.connection_id,job.action_id,job.approval_generation)
  AND q.decision IS NULL AND q.expires_at>clock_timestamp() AND a.status='pending_approval'
  AND tn.enabled AND en.enabled AND cn.enabled AND w.enabled AND g.enabled AND g.submit_refund
  AND q.generation=(SELECT max(p.generation) FROM public.approvals p WHERE (p.tenant_id,p.environment_id,p.action_id)=(q.tenant_id,q.environment_id,q.action_id))
 )
$$;

CREATE FUNCTION release_notification_channel(route public.notification_routes,job public.notification_jobs,cooldown bigint) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,public AS $$
 UPDATE public.notification_channels c SET job_id=NULL,generation=NULL,lease_until=NULL,
 next_send_at=greatest(c.next_send_at,clock_timestamp()+cooldown*interval '1 second')
 WHERE route.kind='slack' AND (c.team_id,c.channel_id,c.job_id,c.generation)=(route.team_id,route.channel_id,job.id,job.generation)
$$;
CREATE FUNCTION claim_notification(selected_route uuid,selected_kind text)
RETURNS TABLE(id uuid,tenant_id uuid,environment_id uuid,connection_id uuid,action_id uuid,route_id uuid,approval_generation bigint,generation bigint,kind text,team_id text,channel_id text,expires_at_unix bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE route public.notification_routes%ROWTYPE;channel public.notification_channels%ROWTYPE;job public.notification_jobs%ROWTYPE;
BEGIN
 SELECT * INTO route FROM public.notification_routes r WHERE r.id=selected_route FOR UPDATE;
 IF NOT FOUND OR NOT route.enabled OR route.kind<>selected_kind THEN RETURN; END IF;
 PERFORM set_config('apl.tenant_id',route.tenant_id::text,true),set_config('apl.environment_id',route.environment_id::text,true);
 IF route.kind='slack' THEN
  INSERT INTO public.notification_channels(team_id,channel_id) VALUES(route.team_id,route.channel_id) ON CONFLICT DO NOTHING;
  SELECT * INTO channel FROM public.notification_channels c WHERE (c.team_id,c.channel_id)=(route.team_id,route.channel_id) FOR UPDATE;
  IF channel.next_send_at>clock_timestamp() OR channel.lease_until>clock_timestamp() THEN RETURN; END IF;
 END IF;
 FOR i IN 1..20 LOOP
  SELECT * INTO job FROM public.notification_jobs q
  WHERE (q.tenant_id,q.environment_id,q.connection_id)=(route.tenant_id,route.environment_id,route.connection_id)
  AND (q.route_id IS NULL OR q.route_id=route.id)
  AND q.status IN ('queued','processing') AND q.available_at<=clock_timestamp()
  AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp())
  ORDER BY q.available_at,q.id FOR UPDATE SKIP LOCKED LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  IF job.attempts>=8 OR NOT public.notification_current(job) THEN
   UPDATE public.notification_jobs q SET status=CASE WHEN job.attempts>=8 THEN 'failed' ELSE 'skipped' END,lease_until=NULL WHERE q.id=job.id;
   INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,CASE WHEN job.attempts>=8 THEN 'notification.failed' ELSE 'notification.skipped' END);
   CONTINUE;
  END IF;
  UPDATE public.notification_jobs q SET route_id=route.id,generation=q.generation+1,attempts=q.attempts+1,
   status='processing',lease_until=clock_timestamp()+interval '60 seconds' WHERE q.id=job.id RETURNING * INTO job;
  IF route.kind='slack' THEN UPDATE public.notification_channels c SET job_id=job.id,generation=job.generation,lease_until=job.lease_until
   WHERE (c.team_id,c.channel_id)=(route.team_id,route.channel_id); END IF;
  INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,'notification.claimed');
  RETURN QUERY SELECT job.id,job.tenant_id,job.environment_id,job.connection_id,job.action_id,route.id,
    job.approval_generation,job.generation,route.kind,route.team_id,route.channel_id,floor(extract(epoch FROM job.expires_at))::bigint;
  RETURN;
 END LOOP;
END $$;

CREATE FUNCTION lock_notification_lease(lease jsonb) RETURNS public.notification_jobs
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE route public.notification_routes%ROWTYPE;channel public.notification_channels%ROWTYPE;job public.notification_jobs%ROWTYPE;
BEGIN
 SELECT * INTO route FROM public.notification_routes r WHERE r.id=(lease->>'route_id')::uuid FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
 IF route.kind='slack' THEN
  SELECT * INTO channel FROM public.notification_channels c WHERE (c.team_id,c.channel_id)=(route.team_id,route.channel_id) FOR UPDATE;
 END IF;
 SELECT * INTO job FROM public.notification_jobs q WHERE q.id=(lease->>'id')::uuid FOR UPDATE;
 IF NOT FOUND OR job.status<>'processing' OR job.lease_until IS NULL OR job.lease_until<=clock_timestamp()
 OR (job.tenant_id,job.environment_id,job.connection_id,job.action_id,job.route_id,job.approval_generation,job.generation) IS DISTINCT FROM
 ((lease->>'tenant_id')::uuid,(lease->>'environment_id')::uuid,(lease->>'connection_id')::uuid,(lease->>'action_id')::uuid,
  (lease->>'route_id')::uuid,(lease->>'approval_generation')::bigint,(lease->>'generation')::bigint)
 OR (route.kind,route.team_id,route.channel_id) IS DISTINCT FROM (lease->>'kind',lease->>'team_id',lease->>'channel_id')
 OR floor(extract(epoch FROM job.expires_at))::bigint IS DISTINCT FROM (lease->>'expires_at_unix')::bigint
 OR (route.kind='slack' AND ((channel.job_id,channel.generation) IS DISTINCT FROM (job.id,job.generation) OR channel.lease_until IS NULL OR channel.lease_until<=clock_timestamp())) THEN
  RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409';
 END IF;
 PERFORM set_config('apl.tenant_id',job.tenant_id::text,true),set_config('apl.environment_id',job.environment_id::text,true);
 RETURN job;
END $$;
CREATE FUNCTION notification_preflight(lease jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE job public.notification_jobs%ROWTYPE;route public.notification_routes%ROWTYPE;
BEGIN
 job:=public.lock_notification_lease(lease);
 SELECT * INTO route FROM public.notification_routes r WHERE r.id=job.route_id;
 IF NOT route.enabled OR NOT public.notification_current(job) THEN
  UPDATE public.notification_jobs q SET status='skipped',lease_until=NULL WHERE q.id=job.id AND q.lease_until>clock_timestamp();
  IF NOT FOUND THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
  PERFORM public.release_notification_channel(route,job,1);
  INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,'notification.skipped');
  RETURN false;
 END IF;
 IF job.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
 RETURN true;
END $$;
CREATE FUNCTION record_fake_notification(lease jsonb) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE job public.notification_jobs%ROWTYPE;
BEGIN
 IF lease->>'kind'<>'fake' THEN RAISE EXCEPTION 'fake route required' USING ERRCODE='AP400'; END IF;
 IF NOT public.notification_preflight(lease) THEN RETURN false; END IF;
 SELECT * INTO job FROM public.notification_jobs q WHERE q.id=(lease->>'id')::uuid;
 INSERT INTO public.notification_receipts(job_id,route_id) VALUES(job.id,job.route_id) ON CONFLICT DO NOTHING;
 IF FOUND THEN INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,'notification.fake_recorded'); END IF;
 IF job.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
 RETURN true;
END $$;
CREATE FUNCTION finish_notification(lease jsonb,outcome text,retry_after_seconds bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE job public.notification_jobs%ROWTYPE;route public.notification_routes%ROWTYPE;delay bigint;target text;
BEGIN
 job:=public.lock_notification_lease(lease);
 SELECT * INTO route FROM public.notification_routes r WHERE r.id=job.route_id;
 IF outcome NOT IN ('delivered','retry','failed') OR outcome IS NULL OR retry_after_seconds NOT BETWEEN 0 AND 86400 OR retry_after_seconds IS NULL THEN
  RAISE EXCEPTION 'invalid notification outcome' USING ERRCODE='AP400';
 END IF;
 target:=CASE WHEN outcome='retry' AND NOT route.enabled THEN 'skipped' WHEN outcome='retry' AND job.attempts>=8 THEN 'failed' WHEN outcome='retry' THEN 'queued' ELSE outcome END;
 delay:=least(86400,greatest(retry_after_seconds,CASE WHEN outcome='retry' THEN least(3600,(2^job.attempts)::bigint)+floor(random()*3)::bigint ELSE 1 END));
 UPDATE public.notification_jobs q SET status=target,lease_until=NULL,available_at=clock_timestamp()+delay*interval '1 second'
 WHERE q.id=job.id AND q.lease_until>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
 PERFORM public.release_notification_channel(route,job,delay);
 INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,'notification.'||CASE WHEN target='queued' THEN 'retry' ELSE target END);
 IF job.lease_until<=clock_timestamp() THEN RAISE EXCEPTION 'stale notification lease' USING ERRCODE='AP409'; END IF;
END $$;
-- Called in its own transaction before a target route is claimed. At most
-- one route/channel is locked, so route replacement cannot create cross-route
-- lock cycles. Unassigned jobs can use the replacement; assigned jobs never do.
CREATE FUNCTION cleanup_obsolete_notification_jobs() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE route public.notification_routes%ROWTYPE;job public.notification_jobs%ROWTYPE;
BEGIN
 SELECT * INTO route FROM public.notification_routes r WHERE NOT r.enabled
 AND EXISTS(SELECT FROM public.notification_jobs q WHERE q.route_id=r.id AND q.status IN ('queued','processing')
    AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp()))
 ORDER BY r.id FOR UPDATE SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 IF route.kind='slack' THEN
  PERFORM 1 FROM public.notification_channels c WHERE (c.team_id,c.channel_id)=(route.team_id,route.channel_id) FOR UPDATE;
 END IF;
 FOR job IN SELECT * FROM public.notification_jobs q WHERE q.route_id=route.id AND q.status IN ('queued','processing')
 AND (q.lease_until IS NULL OR q.lease_until<=clock_timestamp()) ORDER BY q.id FOR UPDATE SKIP LOCKED LIMIT 20 LOOP
  UPDATE public.notification_jobs q SET status='skipped',lease_until=NULL WHERE q.id=job.id;
  PERFORM public.release_notification_channel(route,job,1);
  INSERT INTO public.notification_audit(job_id,event_type) VALUES(job.id,'notification.skipped');
 END LOOP;
END $$;
REVOKE ALL ON FUNCTION cleanup_obsolete_notification_jobs() FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_notification_route(),guard_notification_job_route(),enqueue_approval_notification(),notification_current(public.notification_jobs),
 release_notification_channel(public.notification_routes,public.notification_jobs,bigint),claim_notification(uuid,text),
 lock_notification_lease(jsonb),notification_preflight(jsonb),record_fake_notification(jsonb),finish_notification(jsonb,text,bigint) FROM PUBLIC;
