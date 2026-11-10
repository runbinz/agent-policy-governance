-- Revisioned operator reads and writes; dedicated control grants remain independent.
ALTER TABLE tenants ADD COLUMN control_revision bigint NOT NULL DEFAULT 1
 CHECK(control_revision BETWEEN 1 AND 9007199254740991);
CREATE FUNCTION bump_control_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.control_revision>=9007199254740991 THEN RAISE EXCEPTION 'revision exhausted' USING ERRCODE='AP409'; END IF;
 NEW.control_revision=OLD.control_revision+1;
 RETURN NEW;
END $$;
CREATE TRIGGER bump_control_revision BEFORE UPDATE ON tenants FOR EACH ROW EXECUTE FUNCTION bump_control_revision();

-- Closed mapping and target locks; never expose this helper to runtime roles.
CREATE FUNCTION lock_dispatch_control(t uuid,e uuid,r uuid,k text,target uuid) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE tab text; idcol text; revisioncol text; granttab text; targetclause text; permission text; allowed boolean; result jsonb;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
 RAISE EXCEPTION 'control denied' USING ERRCODE='AP403'; END IF;
 CASE k
 WHEN 'tenant' THEN
  IF target IS NOT NULL THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
  tab='tenants'; idcol='tenant_id'; revisioncol='control_revision'; granttab='tenant_dispatch_grants'; targetclause='';permission='true';
 WHEN 'connection' THEN tab='connections';idcol='connection_id';revisioncol='admin_revision';granttab='connection_admin_grants';targetclause=' AND g.connection_id=$4';permission='g.control_dispatch';
 WHEN 'workload' THEN tab='workloads';idcol='workload_id';revisioncol='admin_revision';granttab='workload_dispatch_grants';targetclause=' AND g.workload_id=$4';permission='true';
 ELSE RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END CASE;
 IF k<>'tenant' AND target IS NULL THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 -- Refuse unauthorized identities before contending on a target. Recheck and lock
 -- authority after the target lock, matching the existing connection setter.
 EXECUTE format('SELECT EXISTS(SELECT FROM public.%I g JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id) JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id) WHERE (g.tenant_id,g.environment_id,g.reviewer_id)=($1,$2,$3) AND g.enabled AND rv.enabled AND en.enabled AND tn.enabled AND %s%s)',granttab,permission,targetclause)
 INTO allowed USING t,e,r,target;
 IF NOT allowed THEN RAISE EXCEPTION 'control denied' USING ERRCODE='AP403'; END IF;
 EXECUTE format('SELECT jsonb_build_object(''kind'',$4,''target_id'',x.%I,''tenant_id'',$1,''environment_id'',$2,''enabled'',x.enabled,''paused'',x.paused,''revision'',x.%I) FROM public.%I x WHERE x.tenant_id=$1%s AND x.%I=$3 FOR UPDATE OF x',idcol,revisioncol,tab,CASE WHEN k='tenant' THEN '' ELSE ' AND x.environment_id=$2' END,idcol)
 INTO result USING t,e,coalesce(target,t),k;
 IF result IS NULL THEN RAISE EXCEPTION 'control denied' USING ERRCODE='AP403'; END IF;
 EXECUTE format('SELECT true FROM public.%I g JOIN public.reviewers rv USING(tenant_id,environment_id,reviewer_id) JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id) WHERE (g.tenant_id,g.environment_id,g.reviewer_id)=($1,$2,$3) AND g.enabled AND rv.enabled AND en.enabled AND tn.enabled AND %s%s FOR SHARE OF g,rv,en,tn',granttab,permission,targetclause)
 INTO allowed USING t,e,r,target;
 IF NOT coalesce(allowed,false) THEN RAISE EXCEPTION 'control denied' USING ERRCODE='AP403'; END IF;
 RETURN result;
END $$;
CREATE FUNCTION read_dispatch_control_state(t uuid,e uuid,r uuid,k text,target uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
BEGIN RETURN public.lock_dispatch_control(t,e,r,k,target); END $$;
CREATE FUNCTION set_dispatch_control_state(t uuid,e uuid,r uuid,k text,target uuid,expected bigint,pause boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE state jsonb;
BEGIN
 state=public.lock_dispatch_control(t,e,r,k,target);
 IF expected IS NULL OR expected NOT BETWEEN 1 AND 9007199254740991 OR pause IS NULL THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 IF (state->>'revision')::bigint<>expected THEN RAISE EXCEPTION 'revision conflict' USING ERRCODE='AP409'; END IF;
 IF (state->>'paused')::boolean=pause THEN RETURN state; END IF;
 CASE k
 WHEN 'tenant' THEN PERFORM public.admin_set_tenant_dispatch_paused(t,e,r,pause);
 WHEN 'connection' THEN PERFORM public.admin_set_dispatch_paused(t,e,r,target,pause);
 WHEN 'workload' THEN PERFORM public.admin_set_workload_dispatch_paused(t,e,r,target,pause);
 END CASE;
 RETURN public.lock_dispatch_control(t,e,r,k,target);
END $$;
REVOKE ALL ON FUNCTION bump_control_revision(),lock_dispatch_control(uuid,uuid,uuid,text,uuid),read_dispatch_control_state(uuid,uuid,uuid,text,uuid),set_dispatch_control_state(uuid,uuid,uuid,text,uuid,bigint,boolean) FROM PUBLIC;
