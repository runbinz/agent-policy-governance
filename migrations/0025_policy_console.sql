-- Fixed browser projection; existing policy administration authority is reused.
CREATE FUNCTION read_policy_page(t uuid,e uuid,r uuid,c uuid,after_version bigint,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 100
 OR (after_version IS NOT NULL AND after_version NOT BETWEEN 1 AND 9007199254740991) THEN
  RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400';
 END IF;
 BEGIN
  PERFORM public.lock_connection_admin(t,e,r,c,'simulate',false);
 EXCEPTION WHEN SQLSTATE 'AP403' THEN
  RAISE EXCEPTION 'resource not found' USING ERRCODE='AP404';
 END;
 IF NOT EXISTS(SELECT FROM public.connections cn WHERE (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c) AND cn.enabled) THEN
  RAISE EXCEPTION 'resource not found' USING ERRCODE='AP404';
 END IF;
 -- Connection SHARE also excludes publication when no binding yet exists.
 PERFORM 1 FROM public.policy_bindings b WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c) FOR SHARE;
 WITH candidates AS MATERIALIZED (
  SELECT p.version,p.auto_limit_minor,p.hard_limit_minor,p.approval_ttl_seconds
  FROM public.policy_versions p WHERE (p.tenant_id,p.environment_id,p.connection_id)=(t,e,c)
  AND (after_version IS NULL OR p.version>after_version) ORDER BY p.version LIMIT page_limit+1
 ), page AS (SELECT * FROM candidates ORDER BY version LIMIT page_limit), active AS (
  SELECT p.version,p.auto_limit_minor,p.hard_limit_minor,p.approval_ttl_seconds
  FROM public.policy_bindings b JOIN public.policy_versions p USING(tenant_id,environment_id,connection_id,version)
  WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c)
 )
 SELECT jsonb_build_object('connection_id',c,'active_policy',(SELECT to_jsonb(a) FROM active a),
  'versions',coalesce((SELECT jsonb_agg(to_jsonb(p) ORDER BY p.version) FROM page p),'[]'::jsonb),
  'next_after',CASE WHEN (SELECT count(*) FROM candidates)>page_limit THEN (SELECT max(version) FROM page) ELSE NULL END,
  'can_edit',g.edit_policy,'can_publish',g.publish_policy) INTO result
 FROM public.connection_admin_grants g WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=(t,e,r,c);
 IF octet_length(result::text)>131072 OR EXISTS (
  SELECT FROM jsonb_array_elements((result->'versions') || CASE WHEN result->'active_policy'='null'::jsonb THEN '[]'::jsonb ELSE jsonb_build_array(result->'active_policy') END) p
  WHERE (p->>'version')::bigint NOT BETWEEN 1 AND 9007199254740991
 ) THEN RAISE EXCEPTION 'data unavailable' USING ERRCODE='AP500'; END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION read_policy_page(uuid,uuid,uuid,uuid,bigint,bigint) FROM PUBLIC;
