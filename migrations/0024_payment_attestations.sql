-- Retained minimal authenticated payment observations; no customer or raw provider data.
CREATE TABLE payment_attestations (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL, id uuid NOT NULL,
 workload_id uuid NOT NULL, connection_id uuid NOT NULL, provider_namespace text NOT NULL,
 schema_version integer NOT NULL DEFAULT 1 CHECK(schema_version=1),
 payment_id text NOT NULL CHECK(length(payment_id) BETWEEN 1 AND 255),
 requested_minor bigint NOT NULL CHECK(requested_minor BETWEEN 1 AND 50000), currency text NOT NULL CHECK(currency='USD'),
 charge_amount_minor bigint NOT NULL CHECK(charge_amount_minor BETWEEN 1 AND 9007199254740991),
 captured_minor bigint NOT NULL CHECK(captured_minor BETWEEN 1 AND charge_amount_minor),
 refunded_minor bigint NOT NULL CHECK(refunded_minor BETWEEN 0 AND captured_minor),
 captured boolean NOT NULL CHECK(captured), paid boolean NOT NULL CHECK(paid), disputed boolean NOT NULL CHECK(NOT disputed),
 status text NOT NULL CHECK(status='succeeded'), method text NOT NULL CHECK(method='card'),
 direct_charge boolean NOT NULL CHECK(direct_charge), eligible boolean NOT NULL DEFAULT true CHECK(eligible),
 observed_at_ms bigint NOT NULL CHECK(observed_at_ms>=0), fresh_until_ms bigint NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(), facts_digest text NOT NULL CHECK(facts_digest ~ '^[a-f0-9]{64}$'),
 CHECK(captured_minor-refunded_minor>=requested_minor),
 CHECK(fresh_until_ms>observed_at_ms AND fresh_until_ms-observed_at_ms<=30000),
 PRIMARY KEY(tenant_id,environment_id,action_id,id),
 FOREIGN KEY(tenant_id,environment_id,action_id) REFERENCES actions,
 FOREIGN KEY(tenant_id,environment_id,connection_id) REFERENCES connections
);
ALTER TABLE payment_attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE payment_attestations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON payment_attestations USING(tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);
CREATE FUNCTION guard_payment_attestation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'payment attestations are immutable'; END $$;
CREATE TRIGGER guard_payment_attestation BEFORE UPDATE OR DELETE ON payment_attestations FOR EACH ROW EXECUTE FUNCTION guard_payment_attestation();
ALTER TABLE approvals ADD COLUMN payment_attestation_id uuid;
ALTER TABLE approvals ADD FOREIGN KEY(tenant_id,environment_id,action_id,payment_attestation_id) REFERENCES payment_attestations;
ALTER TABLE external_dispatches ADD COLUMN payment_attestation_id uuid;
ALTER TABLE external_dispatches ADD FOREIGN KEY(tenant_id,environment_id,action_id,payment_attestation_id) REFERENCES payment_attestations;
CREATE OR REPLACE FUNCTION guard_approval_decision() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF (to_jsonb(NEW)-ARRAY['reviewer_id','decision','decided_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['reviewer_id','decision','decided_at']) OR OLD.decision IS NOT NULL OR NEW.decision IS NULL THEN
 RAISE EXCEPTION 'approval generation is immutable'; END IF;
 NEW.decided_at=clock_timestamp();
 IF NEW.expires_at<=NEW.decided_at THEN RETURN NULL; END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION guard_dispatch_attestation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF (NEW.tenant_id,NEW.environment_id,NEW.action_id,NEW.connection_id,NEW.provider_namespace,NEW.provider_key,NEW.policy_version,NEW.approval_generation,NEW.payment_attestation_id) IS DISTINCT FROM
 (OLD.tenant_id,OLD.environment_id,OLD.action_id,OLD.connection_id,OLD.provider_namespace,OLD.provider_key,OLD.policy_version,OLD.approval_generation,OLD.payment_attestation_id) THEN RAISE EXCEPTION 'dispatch binding is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_dispatch_attestation BEFORE UPDATE ON external_dispatches FOR EACH ROW EXECUTE FUNCTION guard_dispatch_attestation();
-- Scoped read for API decision validation, deliberately excludes observation freshness.
CREATE FUNCTION payment_review_attested(t uuid,e uuid,a uuid,g bigint) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT FROM public.approvals q JOIN public.payment_attestations p ON (p.tenant_id,p.environment_id,p.action_id,p.id)=(q.tenant_id,q.environment_id,q.action_id,q.payment_attestation_id)
 JOIN public.actions x ON (x.tenant_id,x.environment_id,x.id)=(p.tenant_id,p.environment_id,p.action_id)
 JOIN public.provider_routes r ON (r.tenant_id,r.environment_id,r.connection_id,r.provider_namespace)=(p.tenant_id,p.environment_id,p.connection_id,p.provider_namespace)
 WHERE (q.tenant_id,q.environment_id,q.action_id,q.generation)=(t,e,a,g) AND p.workload_id=x.workload_id AND p.connection_id=(x.request->>'connection_id')::uuid
 AND p.payment_id=x.request#>>'{resource,payment_id}' AND p.requested_minor=(x.request#>>'{parameters,amount_minor}')::bigint AND p.currency=x.request#>>'{parameters,currency}'
 AND p.observed_at_ms<=floor(extract(epoch FROM p.recorded_at)*1000)::bigint
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid AND e=nullif(current_setting('apl.environment_id',true),'')::uuid)
$$;
REVOKE ALL ON payment_attestations FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_payment_attestation(),guard_dispatch_attestation(),payment_review_attested(uuid,uuid,uuid,bigint) FROM PUBLIC;
CREATE FUNCTION read_action_payment_attestation(t uuid,e uuid,r uuid,c uuid,a uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 IF NOT public.authorize_action_detail(t,e,r,c) OR NOT EXISTS(SELECT FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) AND x.request->>'connection_id'=c::text AND public.evidence_action_visible(t,e,a)) THEN RAISE EXCEPTION 'not found' USING ERRCODE='AP404'; END IF;
 WITH binding AS (
 SELECT q.payment_attestation_id id,'approval'::text source,q.generation approval_generation FROM public.approvals q WHERE (q.tenant_id,q.environment_id,q.action_id)=(t,e,a) AND (NOT EXISTS(SELECT FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a)) OR EXISTS(SELECT FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) AND x.status IN ('pending_approval','ready'))) ORDER BY generation DESC LIMIT 1
 ), chosen AS (
 SELECT * FROM binding UNION ALL SELECT d.payment_attestation_id,'dispatch',d.approval_generation FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a) AND NOT EXISTS(SELECT FROM binding)
 )
 SELECT jsonb_build_object('id',p.id,'source',b.source,'approval_generation',b.approval_generation,'observation',jsonb_build_object('schema_version',p.schema_version,'request',jsonb_build_object('connection_id',p.connection_id,'payment_id',p.payment_id,'amount_minor',p.requested_minor,'currency','usd','observed_at',p.observed_at_ms,'fresh_until',p.fresh_until_ms),'facts',jsonb_build_object('charge_amount_minor',p.charge_amount_minor,'captured_minor',p.captured_minor,'refunded_minor',p.refunded_minor,'paid',p.paid,'captured',p.captured,'disputed',p.disputed,'direct_charge',p.direct_charge,'status',p.status,'method',p.method))) INTO result
 FROM chosen b JOIN public.payment_attestations p ON (p.tenant_id,p.environment_id,p.action_id,p.id)=(t,e,a,b.id)
 JOIN public.actions x ON (x.tenant_id,x.environment_id,x.id)=(t,e,a)
 WHERE p.workload_id=x.workload_id AND p.connection_id=c AND p.payment_id=x.request#>>'{resource,payment_id}' AND p.requested_minor=(x.request#>>'{parameters,amount_minor}')::bigint AND p.currency=x.request#>>'{parameters,currency}';
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION read_action_payment_attestation(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
CREATE FUNCTION payment_attestation_required(t uuid,e uuid,c uuid) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT EXISTS(SELECT FROM public.provider_routes WHERE (tenant_id,environment_id,connection_id)=(t,e,c))
 AND t=nullif(current_setting('apl.tenant_id',true),'')::uuid AND e=nullif(current_setting('apl.environment_id',true),'')::uuid
$$;
REVOKE ALL ON FUNCTION payment_attestation_required(uuid,uuid,uuid) FROM PUBLIC;
ALTER FUNCTION read_action_detail(uuid,uuid,uuid,uuid,uuid) RENAME TO read_action_detail_v23;
REVOKE ALL ON FUNCTION read_action_detail_v23(uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
DO $$ DECLARE runtime_role text; BEGIN FOREACH runtime_role IN ARRAY ARRAY['apl_api','apl_worker'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=runtime_role) THEN EXECUTE format('REVOKE ALL ON FUNCTION read_action_detail_v23(uuid,uuid,uuid,uuid,uuid) FROM %I',runtime_role); END IF; END LOOP; END $$;
CREATE FUNCTION read_action_detail(t uuid,e uuid,r uuid,c uuid,a uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb; linked uuid; attested boolean;
BEGIN
 result=public.read_action_detail_v23(t,e,r,c,a);
 IF result->'approval'<>'null'::jsonb THEN
 SELECT payment_attestation_id INTO linked FROM public.approvals WHERE (tenant_id,environment_id,action_id)=(t,e,a) ORDER BY generation DESC LIMIT 1;
 result=jsonb_set(result,'{approval,payment_attestation_id}',coalesce(to_jsonb(linked),'null'::jsonb));
 IF public.payment_attestation_required(t,e,c) THEN
 attested=public.payment_review_attested(t,e,a,(result#>>'{approval,generation}')::bigint);
 IF NOT attested THEN result=jsonb_set(result,'{decision_eligibility,can_decide}','false'::jsonb); result=jsonb_set(result,'{decision_eligibility,reason_code}','"PAYMENT_EVIDENCE_UNAVAILABLE"'::jsonb); END IF;
 END IF;
 END IF;
 RETURN result;
END $$;
ALTER FUNCTION read_action_history(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) RENAME TO read_action_history_v23;
REVOKE ALL ON FUNCTION read_action_history_v23(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM PUBLIC;
DO $$ DECLARE runtime_role text; BEGIN FOREACH runtime_role IN ARRAY ARRAY['apl_api','apl_worker'] LOOP IF EXISTS(SELECT FROM pg_roles WHERE rolname=runtime_role) THEN EXECUTE format('REVOKE ALL ON FUNCTION read_action_history_v23(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM %I',runtime_role); END IF; END LOOP; END $$;
CREATE FUNCTION read_action_history(t uuid,e uuid,r uuid,c uuid,a uuid,k text,after_key bigint,page_limit bigint) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public SET statement_timeout='5s' AS $$
DECLARE result jsonb;
BEGIN
 result=public.read_action_history_v23(t,e,r,c,a,k,after_key,page_limit);
 IF k='approval' THEN
 SELECT coalesce(jsonb_agg(item || jsonb_build_object('payment_attestation_id',q.payment_attestation_id) ORDER BY ordering),'[]'::jsonb) INTO result
 FROM jsonb_array_elements(result) WITH ORDINALITY AS j(item,ordering) LEFT JOIN public.approvals q ON (q.tenant_id,q.environment_id,q.action_id,q.generation)=(t,e,a,(item->>'generation')::bigint);
 ELSIF k='audit' THEN
 SELECT coalesce(jsonb_agg(CASE WHEN q.event_type='payment.attested' THEN jsonb_set(item,'{event_type}','"payment.attested"'::jsonb) ELSE item END ORDER BY ordering),'[]'::jsonb) INTO result
 FROM jsonb_array_elements(result) WITH ORDINALITY AS j(item,ordering) LEFT JOIN public.audit_events q ON (q.tenant_id,q.environment_id,q.action_id,q.sequence)=(t,e,a,(item->>'sequence')::bigint);
 END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION read_action_detail(uuid,uuid,uuid,uuid,uuid),read_action_history(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM PUBLIC;
