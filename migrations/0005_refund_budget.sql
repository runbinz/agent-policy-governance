-- USD minor units. One required connection row serializes admission and configuration
-- for all scopes under that connection; derived totals need no separate counters.
CREATE TABLE budget_connections (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, connection_id uuid NOT NULL,
 daily_limit_minor bigint NOT NULL CHECK (daily_limit_minor >= 0),
 exposure_limit_minor bigint NOT NULL CHECK (exposure_limit_minor >= 0),
 PRIMARY KEY (tenant_id,environment_id,connection_id),
 FOREIGN KEY (tenant_id,environment_id,connection_id) REFERENCES connections
);
CREATE TABLE budget_scope_limits (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, connection_id uuid NOT NULL,
 scope_kind text NOT NULL CHECK (scope_kind IN ('workload','customer')),
 scope_ref text NOT NULL CHECK (btrim(scope_ref) <> '' AND octet_length(scope_ref) <= 255),
 workload_id uuid GENERATED ALWAYS AS (CASE WHEN scope_kind='workload' THEN scope_ref::uuid END) STORED,
 CHECK (scope_kind <> 'workload' OR scope_ref = workload_id::text),
 daily_limit_minor bigint NOT NULL CHECK (daily_limit_minor >= 0),
 exposure_limit_minor bigint NOT NULL CHECK (exposure_limit_minor >= 0),
 PRIMARY KEY (tenant_id,environment_id,connection_id,scope_kind,scope_ref),
 FOREIGN KEY (tenant_id,environment_id,connection_id) REFERENCES budget_connections,
 FOREIGN KEY (tenant_id,environment_id,workload_id) REFERENCES workloads
);
CREATE TABLE budget_reservations (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 connection_id uuid NOT NULL, workload_id uuid NOT NULL,
 customer_ref text CHECK (btrim(customer_ref) <> '' AND octet_length(customer_ref) <= 255),
 amount_minor bigint NOT NULL CHECK (amount_minor BETWEEN 1 AND 50000),
 utc_day date NOT NULL, state text NOT NULL CHECK (state IN ('held','settled','released')),
 PRIMARY KEY (tenant_id,environment_id,action_id),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES actions,
 FOREIGN KEY (tenant_id,environment_id,connection_id) REFERENCES budget_connections,
 FOREIGN KEY (tenant_id,environment_id,workload_id) REFERENCES workloads
);
CREATE INDEX budget_reservations_daily ON budget_reservations (tenant_id,environment_id,connection_id,utc_day) WHERE state <> 'released';
CREATE INDEX budget_reservations_held ON budget_reservations (tenant_id,environment_id,connection_id) WHERE state = 'held';
CREATE TABLE budget_ledger_events (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL, action_id uuid NOT NULL,
 sequence smallint NOT NULL,
 event_kind text NOT NULL,
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 applied_limits jsonb,
 CHECK ((sequence=1 AND event_kind='reserved' AND applied_limits IS NOT NULL)
     OR (sequence=2 AND event_kind IN ('settled','released') AND applied_limits IS NULL)),
 PRIMARY KEY (tenant_id,environment_id,action_id,sequence),
 FOREIGN KEY (tenant_id,environment_id,action_id) REFERENCES budget_reservations
);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['budget_connections','budget_scope_limits','budget_reservations','budget_ledger_events'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY tenant_scope ON %I USING (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid) WITH CHECK (tenant_id=nullif(current_setting(''apl.tenant_id'',true),'''')::uuid AND environment_id=nullif(current_setting(''apl.environment_id'',true),'''')::uuid)',t);
 END LOOP;
END $$;

CREATE FUNCTION guard_budget_scope_change() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE scope public.budget_scope_limits%ROWTYPE;
BEGIN
 IF TG_OP = 'UPDATE' AND (NEW.tenant_id,NEW.environment_id,NEW.connection_id,NEW.scope_kind,NEW.scope_ref) IS DISTINCT FROM
     (OLD.tenant_id,OLD.environment_id,OLD.connection_id,OLD.scope_kind,OLD.scope_ref) THEN
  RAISE EXCEPTION 'budget scope identity is immutable';
 END IF;
 IF TG_OP='DELETE' THEN scope:=OLD; ELSE scope:=NEW; END IF;
 PERFORM 1 FROM public.budget_connections b WHERE (b.tenant_id,b.environment_id,b.connection_id)=(scope.tenant_id,scope.environment_id,scope.connection_id) FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'connection budget required'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_budget_scope_change BEFORE INSERT OR UPDATE OR DELETE ON budget_scope_limits FOR EACH ROW EXECUTE FUNCTION guard_budget_scope_change();
CREATE TRIGGER audit_budget_connections AFTER INSERT OR UPDATE OR DELETE ON budget_connections FOR EACH ROW EXECUTE FUNCTION audit_identity_change();
CREATE TRIGGER audit_budget_scopes AFTER INSERT OR UPDATE OR DELETE ON budget_scope_limits FOR EACH ROW EXECUTE FUNCTION audit_identity_change();

CREATE FUNCTION guard_budget_reservation_change() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.state<>'held' OR NEW.state NOT IN ('settled','released') OR
    (to_jsonb(NEW)-'state') IS DISTINCT FROM (to_jsonb(OLD)-'state') THEN
  RAISE EXCEPTION 'invalid budget reservation mutation';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER guard_budget_reservation_change BEFORE UPDATE OR DELETE ON budget_reservations FOR EACH ROW EXECUTE FUNCTION guard_budget_reservation_change();
CREATE FUNCTION reject_budget_ledger_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN RAISE EXCEPTION 'budget ledger events are immutable'; END $$;
CREATE TRIGGER reject_budget_ledger_mutation BEFORE UPDATE OR DELETE OR TRUNCATE ON budget_ledger_events FOR EACH STATEMENT EXECUTE FUNCTION reject_budget_ledger_mutation();

CREATE FUNCTION reserve_refund_budget(t uuid,e uuid,a uuid,c uuid,customer text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE
 action public.actions%ROWTYPE;
 cfg public.budget_connections%ROWTYPE;
 previous public.budget_reservations%ROWTYPE;
 limits record;
 minor bigint;
 dispatch_day date;
 daily_used numeric;
 exposure_used numeric;
 applied jsonb:='[]'::jsonb;
BEGIN
 IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'budget operations require READ COMMITTED'; END IF;
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'budget tenant context mismatch' USING ERRCODE='42501';
 END IF;
 SELECT * INTO action FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) FOR UPDATE;
 IF NOT FOUND OR action.request->>'type' IS DISTINCT FROM 'refund.create'
  OR action.request->>'connection_id' IS DISTINCT FROM c::text
  OR action.request #>> '{parameters,currency}' IS DISTINCT FROM 'USD'
  OR (customer IS NOT NULL AND (btrim(customer)='' OR octet_length(customer)>255)) THEN RETURN 'invalid_action'; END IF;
 minor:=(action.request #>> '{parameters,amount_minor}')::bigint;
 IF minor IS NULL OR minor NOT BETWEEN 1 AND 50000 THEN RETURN 'invalid_action'; END IF;
 SELECT * INTO cfg FROM public.budget_connections b WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,c) FOR UPDATE;
 IF NOT FOUND THEN RETURN 'not_configured'; END IF;
 SELECT * INTO previous FROM public.budget_reservations r WHERE (r.tenant_id,r.environment_id,r.action_id)=(t,e,a);
 IF FOUND THEN
  IF (previous.connection_id,previous.workload_id,previous.customer_ref,previous.amount_minor) IS DISTINCT FROM (c,action.workload_id,customer,minor) THEN RETURN 'conflict'; END IF;
  RETURN CASE WHEN previous.state='held' THEN 'already_held' ELSE previous.state END;
 END IF;
 IF action.status NOT IN ('received','ready') THEN RETURN 'invalid_action'; END IF;
 dispatch_day:=(clock_timestamp() AT TIME ZONE 'UTC')::date;
 FOR limits IN
  SELECT 'connection'::text AS kind,''::text AS ref,cfg.daily_limit_minor AS daily,cfg.exposure_limit_minor AS exposure
  UNION ALL
  SELECT l.scope_kind,l.scope_ref,l.daily_limit_minor,l.exposure_limit_minor FROM public.budget_scope_limits l
   WHERE (l.tenant_id,l.environment_id,l.connection_id)=(t,e,c) AND (l.workload_id=action.workload_id OR (l.scope_kind='customer' AND l.scope_ref=customer))
  ORDER BY 1,2
 LOOP
  SELECT COALESCE(sum(r.amount_minor) FILTER (WHERE r.utc_day=dispatch_day),0),
         COALESCE(sum(r.amount_minor) FILTER (WHERE r.state='held'),0)
  INTO daily_used,exposure_used FROM public.budget_reservations r
  WHERE (r.tenant_id,r.environment_id,r.connection_id)=(t,e,c) AND r.state<>'released'
    AND (r.utc_day=dispatch_day OR r.state='held')
    AND CASE limits.kind WHEN 'workload' THEN r.workload_id=action.workload_id WHEN 'customer' THEN r.customer_ref=customer ELSE true END;
  IF daily_used+minor > limits.daily THEN RETURN 'daily_exceeded'; END IF;
  IF exposure_used+minor > limits.exposure THEN RETURN 'exposure_exceeded'; END IF;
  applied:=applied||jsonb_build_array(jsonb_build_object('kind',limits.kind,'ref',limits.ref,'daily_limit_minor',limits.daily,'exposure_limit_minor',limits.exposure));
 END LOOP;
 INSERT INTO public.budget_reservations VALUES(t,e,a,c,action.workload_id,customer,minor,dispatch_day,'held');
 INSERT INTO public.budget_ledger_events (tenant_id,environment_id,action_id,sequence,event_kind,applied_limits) VALUES(t,e,a,1,'reserved',applied);
 RETURN 'new_hold';
END $$;

CREATE FUNCTION finalize_refund_budget(t uuid,e uuid,a uuid,outcome text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
DECLARE reservation public.budget_reservations%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation') <> 'read committed' THEN RAISE EXCEPTION 'budget operations require READ COMMITTED'; END IF;
 IF t IS DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid OR e IS DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid THEN
  RAISE EXCEPTION 'budget tenant context mismatch' USING ERRCODE='42501';
 END IF;
 IF outcome NOT IN ('settled','released') OR outcome IS NULL THEN RAISE EXCEPTION 'unsupported terminal budget outcome'; END IF;
 PERFORM 1 FROM public.actions x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a) FOR UPDATE;
 SELECT * INTO reservation FROM public.budget_reservations r WHERE (r.tenant_id,r.environment_id,r.action_id)=(t,e,a);
 IF NOT FOUND THEN RETURN 'missing'; END IF;
 PERFORM 1 FROM public.budget_connections b WHERE (b.tenant_id,b.environment_id,b.connection_id)=(t,e,reservation.connection_id) FOR UPDATE;
 IF reservation.state=outcome THEN RETURN outcome; END IF;
 IF reservation.state<>'held' THEN RETURN 'conflict'; END IF;
 UPDATE public.budget_reservations r SET state=outcome WHERE (r.tenant_id,r.environment_id,r.action_id)=(t,e,a);
 INSERT INTO public.budget_ledger_events (tenant_id,environment_id,action_id,sequence,event_kind) VALUES(t,e,a,2,outcome);
 RETURN outcome;
END $$;
REVOKE ALL ON FUNCTION reserve_refund_budget(uuid,uuid,uuid,uuid,text), finalize_refund_budget(uuid,uuid,uuid,text) FROM PUBLIC;
