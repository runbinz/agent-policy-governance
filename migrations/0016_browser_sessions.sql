-- Private bearer-credential hashes; never grant runtime table access.
CREATE TABLE browser_login_flows (
 state_hash bytea PRIMARY KEY CHECK(octet_length(state_hash)=32),
 binding_hash bytea NOT NULL CHECK(octet_length(binding_hash)=32),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '5 minutes'
);
CREATE INDEX browser_login_expiry ON browser_login_flows(expires_at);
CREATE TABLE browser_sessions (
 session_hash bytea PRIMARY KEY CHECK(octet_length(session_hash)=32),
 csrf_hash bytea NOT NULL CHECK(octet_length(csrf_hash)=32),
 id uuid UNIQUE NOT NULL,issuer text NOT NULL,subject text NOT NULL,
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '1 hour',
 revoked_at timestamptz,
 FOREIGN KEY(tenant_id,environment_id,reviewer_id) REFERENCES reviewers
);
CREATE INDEX browser_session_expiry ON browser_sessions(expires_at);
CREATE TABLE browser_session_audit (
 tenant_id uuid NOT NULL,environment_id uuid NOT NULL,reviewer_id uuid NOT NULL,
 session_id uuid NOT NULL,event_type text NOT NULL CHECK(event_type IN ('session.created','session.revoked')),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE browser_session_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE browser_session_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON browser_session_audit USING (
 tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND
 environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);

CREATE FUNCTION start_browser_login(s bytea,b bytea) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF octet_length(s) IS DISTINCT FROM 32 OR octet_length(b) IS DISTINCT FROM 32 THEN
  RAISE EXCEPTION 'invalid login flow' USING ERRCODE='AP400';
 END IF;
 -- Serialize admission so concurrent replicas cannot exceed the active cap.
 PERFORM pg_advisory_xact_lock(712845993::bigint);
 DELETE FROM public.browser_login_flows WHERE state_hash IN
  (SELECT state_hash FROM public.browser_login_flows WHERE expires_at<=clock_timestamp() LIMIT 1000);
 DELETE FROM public.browser_sessions WHERE session_hash IN
  (SELECT session_hash FROM public.browser_sessions WHERE expires_at<clock_timestamp()-interval '1 day' LIMIT 1000);
 IF (SELECT count(*) FROM public.browser_login_flows WHERE expires_at>clock_timestamp())>=10000 THEN
  RAISE EXCEPTION 'login capacity exhausted' USING ERRCODE='AP429';
 END IF;
 INSERT INTO public.browser_login_flows(state_hash,binding_hash) VALUES(s,b);
END $$;

CREATE FUNCTION consume_browser_login(s bytea,b bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 DELETE FROM public.browser_login_flows WHERE state_hash=s AND binding_hash=b AND expires_at>clock_timestamp();
 RETURN FOUND;
END $$;

CREATE FUNCTION create_browser_session(s bytea,csrf bytea,session_id uuid,iss text,sub text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE mapping public.reviewer_registry%ROWTYPE; allowed boolean;
BEGIN
 IF octet_length(s) IS DISTINCT FROM 32 OR octet_length(csrf) IS DISTINCT FROM 32
 OR session_id IS NULL OR iss IS NULL OR sub IS NULL THEN
  RAISE EXCEPTION 'invalid browser session' USING ERRCODE='AP400';
 END IF;
 SELECT * INTO mapping FROM public.reviewer_registry q WHERE q.issuer=iss AND q.subject=sub FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'unauthorized' USING ERRCODE='AP401'; END IF;
 PERFORM set_config('apl.tenant_id',mapping.tenant_id::text,true);
 PERFORM set_config('apl.environment_id',mapping.environment_id::text,true);
 SELECT rv.enabled AND en.enabled AND tn.enabled INTO allowed
 FROM public.reviewers rv JOIN public.environments en USING(tenant_id,environment_id)
 JOIN public.tenants tn USING(tenant_id)
 WHERE (rv.tenant_id,rv.environment_id,rv.reviewer_id)=(mapping.tenant_id,mapping.environment_id,mapping.reviewer_id)
 FOR SHARE OF rv,en,tn;
 IF NOT coalesce(allowed,false) THEN RAISE EXCEPTION 'unauthorized' USING ERRCODE='AP401'; END IF;
 INSERT INTO public.browser_sessions(session_hash,csrf_hash,id,issuer,subject,tenant_id,environment_id,reviewer_id)
 VALUES(s,csrf,session_id,iss,sub,mapping.tenant_id,mapping.environment_id,mapping.reviewer_id);
 INSERT INTO public.browser_session_audit VALUES(mapping.tenant_id,mapping.environment_id,mapping.reviewer_id,session_id,'session.created',clock_timestamp());
END $$;

CREATE FUNCTION read_browser_session(s bytea)
RETURNS TABLE(issuer text,subject text,expires_at_unix bigint,csrf_hash bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE session public.browser_sessions%ROWTYPE; allowed boolean;
BEGIN
 SELECT * INTO session FROM public.browser_sessions q WHERE q.session_hash=s FOR SHARE;
 IF NOT FOUND OR session.revoked_at IS NOT NULL OR session.expires_at<=clock_timestamp() THEN RETURN; END IF;
 PERFORM set_config('apl.tenant_id',session.tenant_id::text,true);
 PERFORM set_config('apl.environment_id',session.environment_id::text,true);
 SELECT rv.enabled AND en.enabled AND tn.enabled INTO allowed FROM public.reviewer_registry q
 JOIN public.reviewers rv ON (rv.tenant_id,rv.environment_id,rv.reviewer_id)=(q.tenant_id,q.environment_id,q.reviewer_id)
 JOIN public.environments en ON (en.tenant_id,en.environment_id)=(rv.tenant_id,rv.environment_id)
 JOIN public.tenants tn ON tn.tenant_id=rv.tenant_id
 WHERE (q.issuer,q.subject,q.tenant_id,q.environment_id,q.reviewer_id)=
 (session.issuer,session.subject,session.tenant_id,session.environment_id,session.reviewer_id)
 FOR SHARE OF q,rv,en,tn;
 IF NOT coalesce(allowed,false) OR session.expires_at<=clock_timestamp() THEN RETURN; END IF;
 RETURN QUERY SELECT session.issuer,session.subject,floor(extract(epoch FROM session.expires_at))::bigint,session.csrf_hash;
END $$;

CREATE FUNCTION revoke_browser_session(s bytea,csrf bytea) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE session public.browser_sessions%ROWTYPE;
BEGIN
 UPDATE public.browser_sessions q SET revoked_at=clock_timestamp()
 WHERE q.session_hash=s AND q.csrf_hash=csrf AND q.revoked_at IS NULL AND q.expires_at>clock_timestamp()
 RETURNING * INTO session;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM set_config('apl.tenant_id',session.tenant_id::text,true);
 PERFORM set_config('apl.environment_id',session.environment_id::text,true);
 INSERT INTO public.browser_session_audit VALUES(session.tenant_id,session.environment_id,session.reviewer_id,session.id,'session.revoked',clock_timestamp());
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION start_browser_login(bytea,bytea),consume_browser_login(bytea,bytea),
 create_browser_session(bytea,bytea,uuid,text,text),read_browser_session(bytea),revoke_browser_session(bytea,bytea) FROM PUBLIC;
