CREATE TABLE connection_admin_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,connection_id uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT true,edit_policy boolean NOT NULL DEFAULT false,
 publish_policy boolean NOT NULL DEFAULT false,control_dispatch boolean NOT NULL DEFAULT false,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TABLE connection_admin_audit (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,connection_id uuid NOT NULL,
 sequence bigint GENERATED ALWAYS AS IDENTITY,
 reviewer_id uuid NOT NULL,operation text NOT NULL CHECK(operation IN ('policy.drafted','policy.published','dispatch.paused','dispatch.resumed')),
 details jsonb NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,environment_id,connection_id,sequence),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['connection_admin_grants','connection_admin_audit'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;
CREATE TRIGGER admin_grants_change AFTER INSERT OR UPDATE OR DELETE ON connection_admin_grants
FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

-- A narrow helper only callable by the definer. Lock the same connection row
-- that dispatch holds FOR SHARE before validating or changing administration state.
CREATE FUNCTION lock_connection_admin(t uuid,e uuid,r uuid,c uuid,permission text,exclusive boolean) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'connection administration denied' USING ERRCODE='AP403';
 END IF;
 -- Reject unauthorized callers before taking the exclusive connection lock.
 PERFORM 1 FROM public.connection_admin_grants g
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=(t,e,r,c) AND g.enabled
 AND CASE permission WHEN 'edit' THEN g.edit_policy WHEN 'simulate' THEN g.edit_policy OR g.publish_policy
   WHEN 'publish' THEN g.publish_policy WHEN 'control' THEN g.control_dispatch ELSE false END;
 IF NOT FOUND THEN RAISE EXCEPTION 'connection administration denied' USING ERRCODE='AP403'; END IF;
 IF exclusive THEN
  PERFORM 1 FROM public.connections cn WHERE (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c) FOR UPDATE;
 ELSE
  PERFORM 1 FROM public.connections cn WHERE (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c) FOR SHARE;
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'connection administration denied' USING ERRCODE='AP403'; END IF;
 SELECT (rv.enabled AND g.enabled AND en.enabled AND tn.enabled AND CASE permission
    WHEN 'edit' THEN g.edit_policy WHEN 'simulate' THEN g.edit_policy OR g.publish_policy
    WHEN 'publish' THEN g.publish_policy WHEN 'control' THEN g.control_dispatch ELSE false END)
 INTO allowed FROM public.connection_admin_grants g
 JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id)
 JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id)
 WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=(t,e,r,c)
 FOR SHARE OF g,rv,en,tn;
 IF NOT coalesce(allowed,false) THEN RAISE EXCEPTION 'connection administration denied' USING ERRCODE='AP403'; END IF;
END $$;

CREATE FUNCTION admin_create_policy_draft(t uuid,e uuid,r uuid,c uuid,v bigint,auto_limit bigint,hard_limit bigint,ttl bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM public.lock_connection_admin(t,e,r,c,'edit',false);
 INSERT INTO public.policy_versions(tenant_id,environment_id,connection_id,version,auto_limit_minor,hard_limit_minor,approval_ttl_seconds)
 VALUES(t,e,c,v,auto_limit,hard_limit,ttl) ON CONFLICT DO NOTHING;
 IF NOT FOUND THEN RAISE EXCEPTION 'policy version already exists' USING ERRCODE='AP409'; END IF;
 INSERT INTO public.connection_admin_audit(tenant_id,environment_id,connection_id,reviewer_id,operation,details)
 VALUES(t,e,c,r,'policy.drafted',jsonb_build_object('version',v,'auto_limit_minor',auto_limit,'hard_limit_minor',hard_limit,'approval_ttl_seconds',ttl));
END $$;

CREATE FUNCTION admin_simulation_policies(t uuid,e uuid,r uuid,c uuid,v bigint)
RETURNS TABLE(is_active boolean,version bigint,auto_limit_minor bigint,hard_limit_minor bigint,approval_ttl_seconds bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM public.lock_connection_admin(t,e,r,c,'simulate',false);
 RETURN QUERY SELECT false,p.version,p.auto_limit_minor,p.hard_limit_minor,p.approval_ttl_seconds
 FROM public.policy_versions p WHERE (p.tenant_id,p.environment_id,p.connection_id,p.version)=(t,e,c,v);
 IF NOT FOUND THEN RAISE EXCEPTION 'policy version not found' USING ERRCODE='AP404'; END IF;
 RETURN QUERY SELECT true,p.version,p.auto_limit_minor,p.hard_limit_minor,p.approval_ttl_seconds
 FROM public.policy_bindings b JOIN public.policy_versions p USING(tenant_id,environment_id,connection_id,version)
 WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c) FOR SHARE OF b;
END $$;

CREATE FUNCTION admin_publish_policy(t uuid,e uuid,r uuid,c uuid,v bigint,expected bigint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE current_version bigint;
BEGIN
 PERFORM public.lock_connection_admin(t,e,r,c,'publish',true);
 SELECT b.version INTO current_version FROM public.policy_bindings b
 WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c) FOR UPDATE;
 current_version:=coalesce(current_version,0);
 IF current_version<>expected OR v<=current_version THEN RAISE EXCEPTION 'policy binding version conflict' USING ERRCODE='AP409'; END IF;
 PERFORM 1 FROM public.policy_versions p WHERE (p.tenant_id,p.environment_id,p.connection_id,p.version)=(t,e,c,v);
 IF NOT FOUND THEN RAISE EXCEPTION 'policy version not found' USING ERRCODE='AP404'; END IF;
 IF current_version=0 THEN
  INSERT INTO public.policy_bindings(tenant_id,environment_id,connection_id,version) VALUES(t,e,c,v)
  ON CONFLICT DO NOTHING;
 ELSE
  UPDATE public.policy_bindings b SET version=v WHERE (b.tenant_id,b.environment_id,b.connection_id,b.version)=(t,e,c,current_version);
 END IF;
 IF NOT FOUND THEN RAISE EXCEPTION 'policy binding version conflict' USING ERRCODE='AP409'; END IF;
 INSERT INTO public.connection_admin_audit(tenant_id,environment_id,connection_id,reviewer_id,operation,details)
 VALUES(t,e,c,r,'policy.published',jsonb_build_object('version',v,'previous_version',current_version));
END $$;

CREATE FUNCTION admin_set_dispatch_paused(t uuid,e uuid,r uuid,c uuid,pause boolean) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 PERFORM public.lock_connection_admin(t,e,r,c,'control',true);
 UPDATE public.connections cn SET paused=pause
 WHERE (cn.tenant_id,cn.environment_id,cn.connection_id)=(t,e,c) AND cn.paused IS DISTINCT FROM pause;
 IF FOUND THEN
  INSERT INTO public.connection_admin_audit(tenant_id,environment_id,connection_id,reviewer_id,operation,details)
  VALUES(t,e,c,r,CASE WHEN pause THEN 'dispatch.paused' ELSE 'dispatch.resumed' END,jsonb_build_object('paused',pause));
 END IF;
END $$;

REVOKE ALL ON FUNCTION lock_connection_admin(uuid,uuid,uuid,uuid,text,boolean),
 admin_create_policy_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint),
 admin_simulation_policies(uuid,uuid,uuid,uuid,bigint),
 admin_publish_policy(uuid,uuid,uuid,uuid,bigint,bigint),
 admin_set_dispatch_paused(uuid,uuid,uuid,uuid,boolean) FROM PUBLIC;
