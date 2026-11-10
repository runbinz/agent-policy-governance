-- Visibility retention only. No execution, accounting, audit or key records are deleted.
CREATE TABLE evidence_retention_settings (
 tenant_id uuid NOT NULL, environment_id uuid NOT NULL,
 searchable_days integer NOT NULL DEFAULT 90 CHECK(searchable_days BETWEEN 1 AND 36500),
 PRIMARY KEY(tenant_id,environment_id),
 FOREIGN KEY(tenant_id,environment_id) REFERENCES environments
);
ALTER TABLE evidence_retention_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_retention_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON evidence_retention_settings USING (
 tenant_id=nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND environment_id=nullif(current_setting('apl.environment_id',true),'')::uuid);
-- Unknown legacy timestamps remain unknown. Observation is a conservative grace,
-- never an assertion about historical creation/termination.
ALTER TABLE actions ADD COLUMN created_at timestamptz;
ALTER TABLE actions ADD COLUMN terminal_at timestamptz;
ALTER TABLE actions ADD COLUMN retention_observed_at timestamptz NOT NULL DEFAULT statement_timestamp();
ALTER TABLE actions ALTER COLUMN created_at SET DEFAULT statement_timestamp();
CREATE FUNCTION maintain_action_retention_times() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  NEW.created_at=statement_timestamp();
  NEW.retention_observed_at=statement_timestamp();
  NEW.terminal_at=CASE WHEN NEW.status IN ('denied','rejected','expired','cancelled','failed_confirmed','succeeded') THEN statement_timestamp() ELSE NULL END;
 ELSE
  NEW.created_at=OLD.created_at;
  NEW.retention_observed_at=OLD.retention_observed_at;
  NEW.terminal_at=OLD.terminal_at;
  IF NEW.status IS DISTINCT FROM OLD.status THEN
   NEW.terminal_at=CASE WHEN NEW.status IN ('denied','rejected','expired','cancelled','failed_confirmed','succeeded') THEN statement_timestamp() ELSE NULL END;
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER maintain_action_retention_times BEFORE INSERT OR UPDATE ON actions
 FOR EACH ROW EXECUTE FUNCTION maintain_action_retention_times();
REVOKE ALL ON FUNCTION maintain_action_retention_times() FROM PUBLIC;
CREATE INDEX actions_retention_terminal ON actions(tenant_id,environment_id,terminal_at);

-- Exact boundary: terminal age >= configured days is hidden. One statement's
-- timestamp is shared by search, request validation and export preflight.
CREATE FUNCTION evidence_action_visible(t uuid,e uuid,a uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
 SELECT t IS NOT DISTINCT FROM nullif(current_setting('apl.tenant_id',true),'')::uuid
 AND e IS NOT DISTINCT FROM nullif(current_setting('apl.environment_id',true),'')::uuid
 AND coalesce((SELECT
  x.status NOT IN ('denied','rejected','expired','cancelled','failed_confirmed','succeeded')
  OR EXISTS(SELECT FROM public.external_dispatches d WHERE (d.tenant_id,d.environment_id,d.action_id)=(t,e,a) AND NOT d.closed)
  OR EXISTS(SELECT FROM public.budget_reservations b WHERE (b.tenant_id,b.environment_id,b.action_id)=(t,e,a) AND b.state='held')
  OR coalesce(x.terminal_at,x.retention_observed_at) IS NULL
  OR coalesce(x.terminal_at,x.retention_observed_at)>statement_timestamp()-make_interval(days=>coalesce(s.searchable_days,90))
 FROM public.actions x LEFT JOIN public.evidence_retention_settings s USING(tenant_id,environment_id)
 WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,a)),false)
$$;
REVOKE ALL ON FUNCTION evidence_action_visible(uuid,uuid,uuid) FROM PUBLIC;
CREATE OR REPLACE FUNCTION search_action_evidence(t uuid,e uuid,r uuid,c uuid,
 selected_status text,selected_workload uuid,selected_action uuid,
 minimum_minor bigint,maximum_minor bigint,after_id uuid,page_limit bigint)
RETURNS TABLE(id uuid,workload_id uuid,connection_id uuid,status text,reason text,
 amount_minor bigint,currency text,policy_version bigint,budget_state text,budget_amount_minor bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 IF page_limit NOT BETWEEN 1 AND 100 OR page_limit IS NULL
 OR minimum_minor NOT BETWEEN 0 AND 50000 OR maximum_minor NOT BETWEEN 0 AND 50000
 OR minimum_minor>maximum_minor
 OR (selected_status IS NOT NULL AND selected_status NOT IN (
 'received','denied','succeeded','pending_approval','ready','rejected','expired','cancelled','dispatching','failed_confirmed')) THEN
  RAISE EXCEPTION 'invalid evidence filter' USING ERRCODE='AP400';
 END IF;
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN
  RAISE EXCEPTION 'evidence not found' USING ERRCODE='AP404';
 END IF;
 RETURN QUERY SELECT a.id,a.workload_id,c,a.status,a.reason,
 (a.request#>>'{parameters,amount_minor}')::bigint,a.request#>>'{parameters,currency}',
 p.policy_version,b.state,b.amount_minor
 FROM public.actions a
 LEFT JOIN LATERAL (
  SELECT v.policy_version FROM public.action_policy_decisions v
  WHERE (v.tenant_id,v.environment_id,v.action_id)=(a.tenant_id,a.environment_id,a.id)
  ORDER BY v.audit_sequence DESC LIMIT 1
 ) p ON true
 LEFT JOIN public.budget_reservations b ON (b.tenant_id,b.environment_id,b.action_id)=(a.tenant_id,a.environment_id,a.id)
 WHERE (a.tenant_id,a.environment_id)=(t,e) AND a.request->>'connection_id'=c::text
 AND public.evidence_action_visible(t,e,a.id)
 AND (selected_status IS NULL OR a.status=selected_status)
 AND (selected_workload IS NULL OR a.workload_id=selected_workload)
 AND (selected_action IS NULL OR a.id=selected_action)
 AND (minimum_minor IS NULL OR (a.request#>>'{parameters,amount_minor}')::bigint>=minimum_minor)
 AND (maximum_minor IS NULL OR (a.request#>>'{parameters,amount_minor}')::bigint<=maximum_minor)
 AND (after_id IS NULL OR a.id>after_id)
 ORDER BY a.id LIMIT page_limit+1;
 -- The authorizer keeps grant/reviewer/scope locks for this entire transaction.
 -- Rechecking also fails closed if future authorizer implementations change.
 IF NOT public.evidence_export_allowed(t,e,r,c) THEN
  RAISE EXCEPTION 'evidence not found' USING ERRCODE='AP404';
 END IF;
END $$;
REVOKE ALL ON FUNCTION search_action_evidence(uuid,uuid,uuid,uuid,text,uuid,uuid,bigint,bigint,uuid,bigint) FROM PUBLIC;

ALTER FUNCTION request_evidence_export(uuid,uuid,uuid,uuid,uuid,uuid[]) RENAME TO request_evidence_export_retention_base;
REVOKE ALL ON FUNCTION request_evidence_export_retention_base(uuid,uuid,uuid,uuid,uuid,uuid[]) FROM PUBLIC;
-- Renaming retains existing grants; remove runtime access to the bypass path.
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='apl_api') THEN
  REVOKE ALL ON FUNCTION request_evidence_export_retention_base(uuid,uuid,uuid,uuid,uuid,uuid[]) FROM apl_api;
 END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='apl_worker') THEN
  REVOKE ALL ON FUNCTION request_evidence_export_retention_base(uuid,uuid,uuid,uuid,uuid,uuid[]) FROM apl_worker;
 END IF;
END $$;
CREATE FUNCTION request_evidence_export(t uuid,e uuid,r uuid,c uuid,export_id uuid,ids uuid[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public AS $$
BEGIN
 -- Base performs authorization and selection validation first; any visibility
 -- failure rolls its writes back with the same transaction.
 PERFORM public.request_evidence_export_retention_base(t,e,r,c,export_id,ids);
 IF EXISTS(SELECT FROM unnest(ids) id WHERE NOT public.evidence_action_visible(t,e,id)) THEN
  RAISE EXCEPTION 'export not found' USING ERRCODE='AP404';
 END IF;
END $$;
REVOKE ALL ON FUNCTION request_evidence_export(uuid,uuid,uuid,uuid,uuid,uuid[]) FROM PUBLIC;
ALTER FUNCTION preflight_evidence_export(uuid,uuid,uuid) RENAME TO preflight_evidence_export_retention_base;
REVOKE ALL ON FUNCTION preflight_evidence_export_retention_base(uuid,uuid,uuid) FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='apl_api') THEN
  REVOKE ALL ON FUNCTION preflight_evidence_export_retention_base(uuid,uuid,uuid) FROM apl_api;
 END IF;
 IF EXISTS(SELECT FROM pg_roles WHERE rolname='apl_worker') THEN
  REVOKE ALL ON FUNCTION preflight_evidence_export_retention_base(uuid,uuid,uuid) FROM apl_worker;
 END IF;
END $$;
CREATE FUNCTION preflight_evidence_export(t uuid,e uuid,export_id uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,public AS $$
DECLARE ids uuid[];
BEGIN
 SELECT x.action_ids INTO ids FROM public.evidence_exports x WHERE (x.tenant_id,x.environment_id,x.id)=(t,e,export_id);
 IF NOT FOUND OR EXISTS(SELECT FROM unnest(ids) id WHERE NOT public.evidence_action_visible(t,e,id)) THEN
  RAISE EXCEPTION 'export not found' USING ERRCODE='AP404';
 END IF;
 PERFORM public.preflight_evidence_export_retention_base(t,e,export_id);
END $$;
REVOKE ALL ON FUNCTION preflight_evidence_export(uuid,uuid,uuid) FROM PUBLIC;
-- Existing sessions may have cached the former preflight function OID before
-- its rename. Recreate the unchanged caller to invalidate its PL/pgSQL plans.
DO $$ BEGIN
 EXECUTE pg_get_functiondef('public.snapshot_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint)'::regprocedure);
END $$;
