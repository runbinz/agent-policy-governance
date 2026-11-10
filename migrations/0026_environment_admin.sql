-- Dedicated, default-deny environment administration. No dispatch or financial side effects.
CREATE TABLE environment_admin_grants (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, reviewer_id uuid NOT NULL,
 enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
CREATE TABLE environment_admin_audit (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, reviewer_id uuid NOT NULL,
 operation text NOT NULL CHECK(operation IN ('entity.enabled','entity.disabled','grant.revoked')),
 kind text NOT NULL CHECK(kind IN ('connections','workloads','reviewers','workload','approval','reconciliation','policy_admin','evidence_export','operations','action_detail','tenant_dispatch','workload_dispatch','environment_admin')),
 connection_id uuid, workload_id uuid, target_reviewer_id uuid,
 expected_revision bigint NOT NULL CHECK(expected_revision BETWEEN 1 AND 9007199254740990),
 new_revision bigint NOT NULL CHECK(new_revision=expected_revision+1),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['environment_admin_grants','environment_admin_audit'] LOOP
 EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',tab);
 EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',tab);
 EXECUTE format($policy$CREATE POLICY tenant_scope ON %I USING(tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid)$policy$,tab);
 END LOOP;
END $$;
CREATE FUNCTION bump_admin_revision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.admin_revision>=9007199254740991 THEN RAISE EXCEPTION 'revision exhausted' USING ERRCODE='AP409'; END IF;
 NEW.admin_revision=OLD.admin_revision+1;
 RETURN NEW;
END $$;
DO $$ DECLARE tab text; BEGIN
 FOREACH tab IN ARRAY ARRAY['connections','workloads','reviewers','workload_grants','reviewer_grants','reconciliation_grants','connection_admin_grants','evidence_export_grants','operations_grants','action_detail_grants','tenant_dispatch_grants','workload_dispatch_grants','environment_admin_grants'] LOOP
 EXECUTE format('ALTER TABLE %I ADD COLUMN admin_revision bigint NOT NULL DEFAULT 1 CHECK(admin_revision BETWEEN 1 AND 9007199254740991)',tab);
 EXECUTE format('CREATE TRIGGER bump_admin_revision BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION bump_admin_revision()',tab);
 END LOOP;
END $$;
CREATE TRIGGER environment_admin_grants_change AFTER INSERT OR UPDATE OR DELETE ON environment_admin_grants FOR EACH ROW EXECUTE FUNCTION audit_identity_change();
CREATE FUNCTION guard_environment_admin_audit() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'administration audit is immutable'; END $$;
CREATE TRIGGER immutable_environment_admin_audit BEFORE UPDATE OR DELETE ON environment_admin_audit FOR EACH ROW EXECUTE FUNCTION guard_environment_admin_audit();

CREATE FUNCTION lock_environment_admin(t uuid,e uuid,r uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
 RAISE EXCEPTION 'resource not found' USING ERRCODE='AP404'; END IF;
 PERFORM 1 FROM public.tenants tn JOIN public.environments en USING(tenant_id)
 JOIN public.reviewers rv USING(tenant_id,environment_id)
 JOIN public.environment_admin_grants gr USING(tenant_id,environment_id,reviewer_id)
 WHERE (gr.tenant_id,gr.environment_id,gr.reviewer_id)=(t,e,r)
 AND tn.enabled AND en.enabled AND rv.enabled AND gr.enabled FOR SHARE OF tn,en,rv,gr;
 IF NOT FOUND THEN RAISE EXCEPTION 'resource not found' USING ERRCODE='AP404'; END IF;
END $$;

-- All dynamic SQL identifiers and permission fragments come from this closed mapping.
-- This helper has no runtime execute grant.
CREATE FUNCTION environment_grant_spec(k text) RETURNS TABLE(tab text,has_c boolean,has_w boolean,has_r boolean,flags text[])
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 RETURN QUERY SELECT s.table_name,s.c,s.w,s.r,s.permissions FROM (VALUES
 ('workload','workload_grants',true,true,false,ARRAY['submit_refund','read_action','read_events','cancel_action']),
 ('approval','reviewer_grants',true,false,true,ARRAY['approve']),
 ('reconciliation','reconciliation_grants',true,false,true,ARRAY['reconcile']),
 ('policy_admin','connection_admin_grants',true,false,true,ARRAY['edit_policy','publish_policy','control_dispatch']),
 ('evidence_export','evidence_export_grants',true,false,true,ARRAY['export_evidence']),
 ('operations','operations_grants',true,false,true,ARRAY['read_operations']),
 ('action_detail','action_detail_grants',true,false,true,ARRAY['read_action_detail']),
 ('tenant_dispatch','tenant_dispatch_grants',false,false,true,ARRAY['control_tenant_dispatch']),
 ('workload_dispatch','workload_dispatch_grants',false,true,true,ARRAY['control_workload_dispatch']),
 ('environment_admin','environment_admin_grants',false,false,true,ARRAY['administer_environment'])
 ) s(kind,table_name,c,w,r,permissions) WHERE s.kind=k;
 IF NOT FOUND THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
END $$;

CREATE FUNCTION read_admin_entities(t uuid,e uuid,r uuid,k text,after_id uuid,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE tab text; idcol text; extras text; result jsonb;
BEGIN
 PERFORM public.lock_environment_admin(t,e,r);
 IF page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 CASE k
 WHEN 'connections' THEN tab='connections'; idcol='connection_id'; extras=$q$,
 'paused',x.paused,'can_control',EXISTS(SELECT FROM public.connection_admin_grants g WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.connection_id)=($1,$2,$3,x.connection_id) AND g.enabled AND g.control_dispatch),
 'mode',CASE WHEN NOT EXISTS(SELECT FROM public.provider_routes p WHERE (p.tenant_id,p.environment_id,p.connection_id)=(x.tenant_id,x.environment_id,x.connection_id)) THEN 'local_fake' WHEN EXISTS(SELECT FROM public.provider_routes p WHERE (p.tenant_id,p.environment_id,p.connection_id)=(x.tenant_id,x.environment_id,x.connection_id) AND p.provider_namespace LIKE 'stripe-test:%') THEN 'stripe_sandbox' ELSE 'external_configured' END,
 'credential_health','unobserved','last_payment_verified_at',(SELECT public.action_detail_time(max(p.recorded_at)) FROM public.payment_attestations p WHERE (p.tenant_id,p.environment_id,p.connection_id)=(x.tenant_id,x.environment_id,x.connection_id))$q$;
 WHEN 'workloads' THEN tab='workloads'; idcol='workload_id'; extras=$q$,'paused',x.paused,'can_control',EXISTS(SELECT FROM public.workload_dispatch_grants g WHERE (g.tenant_id,g.environment_id,g.reviewer_id,g.workload_id)=($1,$2,$3,x.workload_id) AND g.enabled)$q$;
 WHEN 'reviewers' THEN tab='reviewers'; idcol='reviewer_id'; extras='';
 ELSE RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END CASE;
 EXECUTE format($q$
 WITH candidates AS MATERIALIZED(SELECT x.* FROM public.%I x WHERE (x.tenant_id,x.environment_id)=($1,$2) AND ($4 IS NULL OR x.%I>$4) ORDER BY x.%I LIMIT $5+1),
 page AS MATERIALIZED(SELECT * FROM candidates ORDER BY %I LIMIT $5)
 SELECT jsonb_build_object('tenant_id',$1,'environment_id',$2,'kind',$6,
 'items',coalesce((SELECT jsonb_agg(jsonb_build_object('kind',$6,'id',x.%I,'enabled',x.enabled,'admin_revision',x.admin_revision %s) ORDER BY x.%I) FROM page x),'[]'::jsonb),
 'next_after',CASE WHEN (SELECT count(*) FROM candidates)>$5 THEN (SELECT x.%I FROM page x ORDER BY x.%I DESC LIMIT 1) ELSE NULL END,
 'tenant_paused',(SELECT tn.paused FROM public.tenants tn WHERE tn.tenant_id=$1),
 'can_control_tenant',EXISTS(SELECT FROM public.tenant_dispatch_grants g WHERE (g.tenant_id,g.environment_id,g.reviewer_id)=($1,$2,$3) AND g.enabled))
 $q$,tab,idcol,idcol,idcol,idcol,extras,idcol,idcol,idcol)
 INTO result USING t,e,r,after_id,page_limit,k;
 IF octet_length(result::text)>131072 THEN RAISE EXCEPTION 'data unavailable' USING ERRCODE='AP500'; END IF;
 RETURN result;
END $$;

CREATE FUNCTION read_admin_grants(t uuid,e uuid,r uuid,k text,after_cursor text,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE spec record; prefix text; cursor_key text; expr text; perms text; flag text; result jsonb; part text;
BEGIN
 PERFORM public.lock_environment_admin(t,e,r);
 SELECT * INTO spec FROM public.environment_grant_spec(k);
 IF page_limit IS NULL OR page_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 prefix=t::text||'/'||e::text||'/'||k||'/';
 IF after_cursor IS NOT NULL THEN
  IF left(after_cursor,length(prefix))<>prefix THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
  cursor_key=substr(after_cursor,length(prefix)+1);
  IF cursor_key !~ '^[0-9a-f-]{36}:[0-9a-f-]{36}:[0-9a-f-]{36}$' THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
  BEGIN
   FOREACH part IN ARRAY string_to_array(cursor_key,':') LOOP IF (part::uuid)::text<>part THEN RAISE EXCEPTION 'invalid cursor'; END IF; END LOOP;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END;
  IF (NOT spec.has_r AND split_part(cursor_key,':',1)<>'00000000-0000-0000-0000-000000000000') OR (NOT spec.has_w AND split_part(cursor_key,':',2)<>'00000000-0000-0000-0000-000000000000') OR (NOT spec.has_c AND split_part(cursor_key,':',3)<>'00000000-0000-0000-0000-000000000000') THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 END IF;
 expr=CASE WHEN spec.has_r THEN 'x.reviewer_id::text' ELSE quote_literal('00000000-0000-0000-0000-000000000000') END||'||'':''||'||CASE WHEN spec.has_w THEN 'x.workload_id::text' ELSE quote_literal('00000000-0000-0000-0000-000000000000') END||'||'':''||'||CASE WHEN spec.has_c THEN 'x.connection_id::text' ELSE quote_literal('00000000-0000-0000-0000-000000000000') END;
 perms='ARRAY[]::text[]';
 FOREACH flag IN ARRAY spec.flags LOOP
  perms=perms||'||CASE WHEN '||CASE WHEN k IN ('workload','policy_admin') THEN format('x.%I',flag) ELSE 'true' END||' THEN ARRAY['||quote_literal(flag)||'] ELSE ARRAY[]::text[] END';
 END LOOP;
 EXECUTE format($q$
 WITH candidates AS MATERIALIZED(SELECT x.*,%s AS row_key FROM public.%I x WHERE (x.tenant_id,x.environment_id)=($1,$2) AND ($3 IS NULL OR (%s) COLLATE "C">$3 COLLATE "C") ORDER BY (%s) COLLATE "C" LIMIT $4+1),
 page AS MATERIALIZED(SELECT * FROM candidates ORDER BY row_key COLLATE "C" LIMIT $4)
 SELECT jsonb_build_object('tenant_id',$1,'environment_id',$2,'kind',$5,'items',coalesce((SELECT jsonb_agg(jsonb_build_object('connection_id',%s,'workload_id',%s,'reviewer_id',%s,'enabled',x.enabled,'admin_revision',x.admin_revision,'permissions',%s) ORDER BY row_key COLLATE "C") FROM page x),'[]'::jsonb),
 'next_after',CASE WHEN (SELECT count(*) FROM candidates)>$4 THEN $6||(SELECT row_key FROM page ORDER BY row_key COLLATE "C" DESC LIMIT 1) ELSE NULL END)
 $q$,expr,spec.tab,expr,expr,CASE WHEN spec.has_c THEN 'x.connection_id' ELSE 'NULL::uuid' END,CASE WHEN spec.has_w THEN 'x.workload_id' ELSE 'NULL::uuid' END,CASE WHEN spec.has_r THEN 'x.reviewer_id' ELSE 'NULL::uuid' END,perms)
 INTO result USING t,e,cursor_key,page_limit,k,prefix;
 IF octet_length(result::text)>131072 THEN RAISE EXCEPTION 'data unavailable' USING ERRCODE='AP500'; END IF;
 RETURN result;
END $$;

CREATE FUNCTION admin_set_entity_enabled(t uuid,e uuid,r uuid,k text,target uuid,expected bigint,new_enabled boolean) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE tab text; idcol text; revision bigint;
BEGIN
 PERFORM public.lock_environment_admin(t,e,r);
 IF expected IS NULL OR expected NOT BETWEEN 1 AND 9007199254740990 OR target IS NULL OR new_enabled IS NULL THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 CASE k WHEN 'connections' THEN tab='connections';idcol='connection_id'; WHEN 'workloads' THEN tab='workloads';idcol='workload_id'; WHEN 'reviewers' THEN tab='reviewers';idcol='reviewer_id'; ELSE RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END CASE;
 IF k='reviewers' AND target=r AND NOT new_enabled THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 EXECUTE format('UPDATE public.%I SET enabled=$5 WHERE tenant_id=$1 AND environment_id=$2 AND %I=$3 AND admin_revision=$4 RETURNING admin_revision',tab,idcol) INTO revision USING t,e,target,expected,new_enabled;
 IF revision IS NULL THEN RAISE EXCEPTION 'revision conflict' USING ERRCODE='AP409'; END IF;
 INSERT INTO public.environment_admin_audit(tenant_id,environment_id,reviewer_id,operation,kind,connection_id,workload_id,target_reviewer_id,expected_revision,new_revision)
 VALUES(t,e,r,CASE WHEN new_enabled THEN 'entity.enabled' ELSE 'entity.disabled' END,k,CASE WHEN k='connections' THEN target END,CASE WHEN k='workloads' THEN target END,CASE WHEN k='reviewers' THEN target END,expected,revision);
 RETURN revision;
END $$;
CREATE FUNCTION admin_revoke_grant(t uuid,e uuid,r uuid,k text,c uuid,w uuid,target_r uuid,expected bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE spec record; clause text; revision bigint;
BEGIN
 PERFORM public.lock_environment_admin(t,e,r);
 SELECT * INTO spec FROM public.environment_grant_spec(k);
 IF expected IS NULL OR expected NOT BETWEEN 1 AND 9007199254740990 OR spec.has_c<>(c IS NOT NULL) OR spec.has_w<>(w IS NOT NULL) OR spec.has_r<>(target_r IS NOT NULL) THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 IF k='environment_admin' AND target_r=r THEN RAISE EXCEPTION 'invalid request' USING ERRCODE='AP400'; END IF;
 clause=CASE WHEN spec.has_c THEN ' AND connection_id=$3' ELSE '' END||CASE WHEN spec.has_w THEN ' AND workload_id=$4' ELSE '' END||CASE WHEN spec.has_r THEN ' AND reviewer_id=$5' ELSE '' END;
 EXECUTE format('UPDATE public.%I SET enabled=false WHERE tenant_id=$1 AND environment_id=$2%s AND admin_revision=$6 RETURNING admin_revision',spec.tab,clause) INTO revision USING t,e,c,w,target_r,expected;
 IF revision IS NULL THEN RAISE EXCEPTION 'revision conflict' USING ERRCODE='AP409'; END IF;
 INSERT INTO public.environment_admin_audit(tenant_id,environment_id,reviewer_id,operation,kind,connection_id,workload_id,target_reviewer_id,expected_revision,new_revision)
 VALUES(t,e,r,'grant.revoked',k,c,w,target_r,expected,revision);
 RETURN revision;
END $$;
REVOKE ALL ON environment_admin_grants,environment_admin_audit FROM PUBLIC;
REVOKE ALL ON FUNCTION bump_admin_revision(),guard_environment_admin_audit(),lock_environment_admin(uuid,uuid,uuid),environment_grant_spec(text),read_admin_entities(uuid,uuid,uuid,text,uuid,bigint),read_admin_grants(uuid,uuid,uuid,text,text,bigint),admin_set_entity_enabled(uuid,uuid,uuid,text,uuid,bigint,boolean),admin_revoke_grant(uuid,uuid,uuid,text,uuid,uuid,uuid,bigint) FROM PUBLIC;
