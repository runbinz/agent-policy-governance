-- Keep the frozen business aggregate as an owner-only helper. Both STABLE
-- functions observe the same calling statement snapshot and timestamp.
ALTER FUNCTION read_service_metrics() RENAME TO read_service_metrics_base;
REVOKE ALL ON FUNCTION read_service_metrics_base() FROM PUBLIC;
DO $$ DECLARE runtime_role text; BEGIN
 FOREACH runtime_role IN ARRAY ARRAY['apl_api','apl_worker'] LOOP
  IF EXISTS(SELECT FROM pg_roles WHERE rolname=runtime_role) THEN
   EXECUTE format('REVOKE ALL ON FUNCTION read_service_metrics_base() FROM %I',runtime_role);
  END IF;
 END LOOP;
END $$;
CREATE FUNCTION read_service_metrics() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
 WITH moment AS (SELECT floor(extract(epoch FROM statement_timestamp())*1000)::bigint AS now_ms),
 ready AS (
  SELECT q.available_at_ms,q.lease_expires_ms FROM public.external_dispatch_queue q CROSS JOIN moment m
  WHERE NOT q.closed AND q.available_at_ms<=m.now_ms
   AND (q.lease_expires_ms IS NULL OR q.lease_expires_ms<=m.now_ms)
 )
 SELECT public.read_service_metrics_base() || jsonb_build_object(
  'stale_dispatch_leases',(SELECT count(*) FROM ready WHERE lease_expires_ms IS NOT NULL),
  'ready_external_dispatches',(SELECT count(*) FROM ready),
  'oldest_external_ready_lag_seconds',(SELECT CASE WHEN min(available_at_ms) IS NULL THEN NULL ELSE greatest(0,floor((m.now_ms-min(available_at_ms))::numeric/1000))::bigint END FROM ready)
 ) FROM moment m;
$$;
REVOKE ALL ON FUNCTION read_service_metrics() FROM PUBLIC;
