-- No evidence, requester identity, connection identifiers, or object keys are
-- copied into this private routing table. Sweeps never permanently finish:
-- a suspended pre-expiry writer can resume after an earlier deletion batch.
CREATE TABLE evidence_export_cleanup_jobs (
 id uuid PRIMARY KEY REFERENCES evidence_export_jobs(id),
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation>=0),
 lease_until timestamptz,available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 first_cleanup_at timestamptz,
 FOREIGN KEY(tenant_id,environment_id,id) REFERENCES evidence_exports
);
INSERT INTO evidence_export_cleanup_jobs(id,tenant_id,environment_id)
 SELECT id,tenant_id,environment_id FROM evidence_export_jobs;
CREATE FUNCTION queue_evidence_export_cleanup() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 INSERT INTO public.evidence_export_cleanup_jobs(id,tenant_id,environment_id)
 VALUES(NEW.id,NEW.tenant_id,NEW.environment_id);
 RETURN NULL;
END $$;
CREATE TRIGGER queue_evidence_export_cleanup AFTER INSERT ON evidence_export_jobs
 FOR EACH ROW EXECUTE FUNCTION queue_evidence_export_cleanup();

CREATE FUNCTION claim_evidence_export_cleanup()
RETURNS TABLE(id uuid,tenant_id uuid,environment_id uuid,generation bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE job public.evidence_export_cleanup_jobs%ROWTYPE;
BEGIN
 SELECT c.* INTO job FROM public.evidence_export_cleanup_jobs c JOIN public.evidence_export_jobs e USING(id)
 WHERE e.expires_at+interval '5 minutes'<=clock_timestamp()
 AND (e.lease_until IS NULL OR e.lease_until<=clock_timestamp())
 AND c.available_at<=clock_timestamp() AND (c.lease_until IS NULL OR c.lease_until<=clock_timestamp())
 ORDER BY c.available_at,c.id FOR UPDATE OF c SKIP LOCKED LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 UPDATE public.evidence_export_cleanup_jobs c SET generation=c.generation+1,lease_until=clock_timestamp()+interval '60 seconds'
 WHERE c.id=job.id RETURNING * INTO job;
 RETURN QUERY SELECT job.id,job.tenant_id,job.environment_id,job.generation;
END $$;

CREATE FUNCTION finish_evidence_export_cleanup(t uuid,e uuid,export_id uuid,g bigint,complete boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE cleanup public.evidence_export_cleanup_jobs%ROWTYPE; job public.evidence_export_jobs%ROWTYPE;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'stale cleanup lease' USING ERRCODE='AP409';
 END IF;
 SELECT * INTO cleanup FROM public.evidence_export_cleanup_jobs c WHERE c.id=export_id FOR UPDATE;
 IF NOT FOUND OR (cleanup.tenant_id,cleanup.environment_id,cleanup.generation) IS DISTINCT FROM (t,e,g)
 OR cleanup.lease_until IS NULL OR cleanup.lease_until<=clock_timestamp() OR complete IS NULL THEN
  RAISE EXCEPTION 'stale cleanup lease' USING ERRCODE='AP409';
 END IF;
 SELECT * INTO job FROM public.evidence_export_jobs q WHERE q.id=export_id FOR SHARE;
 IF NOT FOUND OR job.expires_at+interval '5 minutes'>clock_timestamp()
 OR (job.lease_until IS NOT NULL AND job.lease_until>clock_timestamp()) OR cleanup.lease_until<=clock_timestamp() THEN
  RAISE EXCEPTION 'stale cleanup lease' USING ERRCODE='AP409';
 END IF;
 IF complete AND cleanup.first_cleanup_at IS NULL THEN
  PERFORM public.evidence_export_event(t,e,export_id,job.requester_id,'export.artifacts_deleted');
 END IF;
 UPDATE public.evidence_export_cleanup_jobs c SET
 first_cleanup_at=CASE WHEN complete THEN coalesce(c.first_cleanup_at,clock_timestamp()) ELSE c.first_cleanup_at END,
 lease_until=NULL,available_at=clock_timestamp()+CASE WHEN complete THEN interval '1 hour' ELSE interval '5 seconds' END
 WHERE c.id=export_id AND c.lease_until>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'stale cleanup lease' USING ERRCODE='AP409'; END IF;
END $$;
REVOKE ALL ON FUNCTION queue_evidence_export_cleanup(),claim_evidence_export_cleanup(),
 finish_evidence_export_cleanup(uuid,uuid,uuid,bigint,boolean) FROM PUBLIC;
