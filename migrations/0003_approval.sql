ALTER TABLE actions DROP CONSTRAINT actions_status_check;
ALTER TABLE actions ADD CONSTRAINT actions_status_check CHECK(status IN ('received','denied','succeeded','pending_approval','ready','rejected','expired','cancelled'));
ALTER TABLE outbox_jobs ADD COLUMN available_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE INDEX outbox_available_idx ON outbox_jobs(available_at,action_id) WHERE NOT done;
CREATE OR REPLACE FUNCTION claim_next_job() RETURNS TABLE(tenant_id uuid,environment_id uuid,action_id uuid)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT q.tenant_id,q.environment_id,q.action_id FROM public.outbox_jobs q
 WHERE NOT q.done AND q.available_at <= clock_timestamp()
 ORDER BY q.available_at,q.action_id FOR UPDATE SKIP LOCKED LIMIT 1
$$;

CREATE TABLE policy_versions (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, connection_id uuid NOT NULL, version bigint NOT NULL CHECK(version>0),
 auto_limit_minor bigint NOT NULL CHECK(auto_limit_minor>=0), hard_limit_minor bigint NOT NULL CHECK(hard_limit_minor>=0 AND hard_limit_minor<=50000 AND hard_limit_minor>=auto_limit_minor),
 approval_ttl_seconds bigint NOT NULL CHECK(approval_ttl_seconds BETWEEN 1 AND 86400),
 PRIMARY KEY(tenant_id,environment_id,connection_id,version),
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TABLE policy_bindings (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, connection_id uuid NOT NULL, version bigint NOT NULL,
 PRIMARY KEY(tenant_id,environment_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,connection_id,version) REFERENCES policy_versions
);
CREATE FUNCTION guard_policy_publication() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_TABLE_NAME='policy_versions' OR TG_OP='DELETE' THEN RAISE EXCEPTION 'immutable policy history'; END IF;
 IF (NEW.tenant_id,NEW.environment_id,NEW.connection_id) IS DISTINCT FROM (OLD.tenant_id,OLD.environment_id,OLD.connection_id) OR NEW.version<=OLD.version THEN
   RAISE EXCEPTION 'publish a higher version for the same scope';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER immutable_policy_versions BEFORE UPDATE OR DELETE ON policy_versions FOR EACH ROW EXECUTE FUNCTION guard_policy_publication();
CREATE TRIGGER monotonic_policy_binding BEFORE UPDATE OR DELETE ON policy_bindings FOR EACH ROW EXECUTE FUNCTION guard_policy_publication();
CREATE TABLE reviewers (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id), FOREIGN KEY(tenant_id,environment_id) REFERENCES environments
);
CREATE TABLE reviewer_grants (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,connection_id uuid NOT NULL,enabled boolean NOT NULL DEFAULT true,
 PRIMARY KEY(tenant_id,environment_id,reviewer_id,connection_id),
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TABLE reviewer_registry (
 issuer text NOT NULL,subject text NOT NULL,tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,
 PRIMARY KEY(issuer,subject), FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
CREATE TABLE approvals (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,action_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 connection_id uuid NOT NULL,policy_version bigint NOT NULL,action_digest text NOT NULL CHECK(action_digest ~ '^[0-9a-f]{64}$'),
 expires_at timestamptz NOT NULL, reviewer_id uuid, decision text CHECK(decision IN ('approve','reject')), decided_at timestamptz,
 CHECK ((reviewer_id IS NULL AND decision IS NULL AND decided_at IS NULL) OR (reviewer_id IS NOT NULL AND decision IS NOT NULL AND decided_at IS NOT NULL)),
 PRIMARY KEY(tenant_id,environment_id,action_id,generation),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES actions,
 FOREIGN KEY(tenant_id,environment_id,connection_id,policy_version) REFERENCES policy_versions,
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['policy_versions','policy_bindings','reviewers','reviewer_grants','approvals'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
 FOREACH t IN ARRAY ARRAY['policy_versions','policy_bindings','reviewers','reviewer_grants','reviewer_registry'] LOOP
  EXECUTE format('CREATE TRIGGER approval_admin_change AFTER INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION audit_identity_change()',t);
 END LOOP;
END $$;
CREATE FUNCTION lookup_reviewer(i text,s text) RETURNS TABLE(tenant_id uuid,environment_id uuid,reviewer_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE ident public.reviewer_registry%ROWTYPE;
BEGIN
 SELECT * INTO ident FROM public.reviewer_registry r WHERE r.issuer=i AND r.subject=s;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM set_config('apl.tenant_id',ident.tenant_id::text,true),set_config('apl.environment_id',ident.environment_id::text,true);
 RETURN QUERY SELECT r.tenant_id,r.environment_id,r.reviewer_id FROM public.reviewers r
 WHERE (r.tenant_id,r.environment_id,r.reviewer_id)=(ident.tenant_id,ident.environment_id,ident.reviewer_id) AND r.enabled;
END $$;
CREATE FUNCTION authorize_reviewer(t uuid,e uuid,r uuid,c uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE allowed boolean;
BEGIN
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 SELECT (rv.enabled AND gr.enabled AND cn.enabled AND en.enabled AND tn.enabled) INTO allowed
 FROM public.reviewers rv JOIN public.reviewer_grants gr USING(tenant_id,environment_id,reviewer_id)
 JOIN public.connections cn USING(tenant_id,environment_id,connection_id)
 JOIN public.environments en USING(tenant_id,environment_id) JOIN public.tenants tn USING(tenant_id)
 WHERE (rv.tenant_id,rv.environment_id,rv.reviewer_id,gr.connection_id)=(t,e,r,c) FOR SHARE OF rv,gr,cn,en,tn;
 RETURN coalesce(allowed,false);
END $$;
CREATE FUNCTION active_policy(t uuid,e uuid,c uuid) RETURNS TABLE(version bigint,auto_limit_minor bigint,hard_limit_minor bigint,approval_ttl_seconds bigint)
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT v.version,v.auto_limit_minor,v.hard_limit_minor,v.approval_ttl_seconds
 FROM public.policy_bindings b JOIN public.policy_versions v USING(tenant_id,environment_id,connection_id,version)
 WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c)
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid AND e=nullif(current_setting('apl.environment_id',true),'')::uuid FOR SHARE OF b
$$;
CREATE FUNCTION lock_approval_job(t uuid,e uuid,a uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT coalesce((SELECT true FROM public.outbox_jobs q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a)
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid AND e=nullif(current_setting('apl.environment_id',true),'')::uuid FOR UPDATE),false)
$$;
CREATE FUNCTION schedule_approval_job(t uuid,e uuid,a uuid,delay_seconds bigint) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 UPDATE public.outbox_jobs q SET available_at=clock_timestamp()+greatest(delay_seconds,0)*interval '1 second'
 WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND NOT q.done
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid AND e=nullif(current_setting('apl.environment_id',true),'')::uuid
$$;
REVOKE ALL ON FUNCTION lookup_reviewer(text,text),authorize_reviewer(uuid,uuid,uuid,uuid),active_policy(uuid,uuid,uuid),lock_approval_job(uuid,uuid,uuid),schedule_approval_job(uuid,uuid,uuid,bigint) FROM PUBLIC;
CREATE FUNCTION transition_review(t uuid,e uuid,a uuid,target text) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF target NOT IN ('ready','rejected') OR t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN RETURN false; END IF;
 UPDATE public.actions SET status=target,reason=CASE WHEN target='rejected' THEN 'REVIEW_REJECTED' ELSE NULL END
 WHERE (tenant_id,environment_id,id)=(t,e,a) AND status='pending_approval';
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION transition_review(uuid,uuid,uuid,text) FROM PUBLIC;
CREATE FUNCTION guard_approval_decision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF OLD.decision IS NOT NULL OR NEW.decision IS NULL OR NEW.expires_at <= clock_timestamp() THEN
  RAISE EXCEPTION 'approval is already decided or expired';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER one_approval_decision BEFORE UPDATE ON approvals FOR EACH ROW EXECUTE FUNCTION guard_approval_decision();
