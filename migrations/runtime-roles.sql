-- Apply once as a privileged local administrator AFTER migrations.
-- NOLOGIN group roles: grant membership to separate API/worker LOGIN credentials.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='apl_api') THEN CREATE ROLE apl_api NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='apl_worker') THEN CREATE ROLE apl_worker NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
END $$;
GRANT USAGE ON SCHEMA public TO apl_api,apl_worker;
GRANT SELECT,INSERT ON actions,submission_keys,audit_events TO apl_api;
GRANT INSERT ON outbox_jobs TO apl_api;
GRANT SELECT,UPDATE ON actions TO apl_worker;
GRANT SELECT,INSERT ON audit_events,fake_effects TO apl_worker;
GRANT EXECUTE ON FUNCTION claim_next_job(),complete_job(uuid,uuid,uuid) TO apl_worker;
GRANT SELECT ON tenants,environments,workloads,connections,workload_grants TO apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION authorize_scope(uuid,uuid,uuid,uuid,text) TO apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION lookup_identity(text,text) TO apl_api;
GRANT SELECT ON reviewers,reviewer_grants,policy_bindings,approvals TO apl_api;
GRANT UPDATE(reviewer_id,decision,decided_at) ON approvals TO apl_api;
GRANT SELECT,INSERT ON approvals TO apl_worker;
GRANT EXECUTE ON FUNCTION lookup_reviewer(text,text),lock_approval_job(uuid,uuid,uuid),transition_review(uuid,uuid,uuid,text) TO apl_api;
GRANT EXECUTE ON FUNCTION authorize_reviewer(uuid,uuid,uuid,uuid),active_policy(uuid,uuid,uuid),schedule_approval_job(uuid,uuid,uuid,bigint) TO apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION transition_cancel(uuid,uuid,uuid,uuid,uuid) TO apl_api;
GRANT INSERT ON action_policy_decisions TO apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION reserve_refund_budget(uuid,uuid,uuid,uuid,text), finalize_refund_budget(uuid,uuid,uuid,text) TO apl_worker;
GRANT SELECT,INSERT ON external_dispatches TO apl_worker;
GRANT UPDATE(snapshot,available_at_ms,abandoned_at_ms,observations) ON external_dispatches TO apl_worker;
GRANT SELECT,INSERT ON external_attempts TO apl_worker;
GRANT EXECUTE ON FUNCTION lock_approval_job(uuid,uuid,uuid),claim_external_dispatch(text),lock_external_dispatch(uuid,uuid,uuid),external_hold_matches(uuid,uuid,uuid,uuid,uuid,bigint) TO apl_worker;
GRANT EXECUTE ON FUNCTION external_candidate(text),provider_route(uuid,uuid,uuid) TO apl_worker;
GRANT EXECUTE ON FUNCTION external_payment_changed_since(uuid,uuid,text,text,bigint) TO apl_worker;
GRANT EXECUTE ON FUNCTION ingest_stripe_wake(text,text,text,text,text,text) TO apl_api;
GRANT EXECUTE ON FUNCTION request_external_reconciliation(uuid,uuid,uuid,uuid) TO apl_api;
GRANT EXECUTE ON FUNCTION admin_create_policy_draft(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint),
 admin_simulation_policies(uuid,uuid,uuid,uuid,bigint),admin_publish_policy(uuid,uuid,uuid,uuid,bigint,bigint),
 admin_set_dispatch_paused(uuid,uuid,uuid,uuid,boolean) TO apl_api;
GRANT EXECUTE ON FUNCTION admin_set_tenant_dispatch_paused(uuid,uuid,uuid,boolean),
 admin_set_workload_dispatch_paused(uuid,uuid,uuid,uuid,boolean) TO apl_api;
GRANT EXECUTE ON FUNCTION request_evidence_export(uuid,uuid,uuid,uuid,uuid,uuid[]),
 read_evidence_export(uuid,uuid,uuid,uuid,boolean),record_evidence_download(uuid,uuid,uuid,uuid) TO apl_api;
GRANT EXECUTE ON FUNCTION claim_evidence_export(),snapshot_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint),
 finish_evidence_export(uuid,uuid,uuid,uuid,uuid,bigint,text,text) TO apl_worker;
GRANT EXECUTE ON FUNCTION claim_evidence_export_cleanup(),
 finish_evidence_export_cleanup(uuid,uuid,uuid,bigint,boolean) TO apl_worker;
GRANT EXECUTE ON FUNCTION search_action_evidence(uuid,uuid,uuid,uuid,text,uuid,uuid,bigint,bigint,uuid,bigint) TO apl_api;
GRANT EXECUTE ON FUNCTION start_browser_login(bytea,bytea),consume_browser_login(bytea,bytea),
 create_browser_session(bytea,bytea,uuid,text,text),read_browser_session(bytea),revoke_browser_session(bytea,bytea) TO apl_api;
GRANT EXECUTE ON FUNCTION cleanup_obsolete_notification_jobs(),claim_notification(uuid,text),notification_preflight(jsonb),
 record_fake_notification(jsonb),finish_notification(jsonb,text,bigint) TO apl_worker;

GRANT EXECUTE ON FUNCTION authorize_operations(uuid,uuid,uuid,uuid),read_operations(uuid,uuid,uuid,uuid) TO apl_api;
GRANT EXECUTE ON FUNCTION authorize_reconciliation(uuid,uuid,uuid,uuid),read_operations_items(uuid,uuid,uuid,uuid,text,uuid,bigint),read_reconciliation_state(uuid,uuid,uuid,uuid) TO apl_api;

REVOKE ALL ON FUNCTION read_service_metrics_base() FROM apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION read_service_metrics() TO apl_api,apl_worker;
-- Retention wrappers are the only runtime entry points; never grant bypass bases.
REVOKE ALL ON FUNCTION request_evidence_export_retention_base(uuid,uuid,uuid,uuid,uuid,uuid[]),
 preflight_evidence_export_retention_base(uuid,uuid,uuid),evidence_action_visible(uuid,uuid,uuid)
 FROM apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION authorize_action_detail(uuid,uuid,uuid,uuid),
 read_action_detail(uuid,uuid,uuid,uuid,uuid),read_action_history(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint)
 TO apl_api;
GRANT SELECT,INSERT ON payment_attestations TO apl_worker;
GRANT EXECUTE ON FUNCTION read_action_payment_attestation(uuid,uuid,uuid,uuid,uuid) TO apl_api;
GRANT EXECUTE ON FUNCTION payment_review_attested(uuid,uuid,uuid,bigint) TO apl_api,apl_worker;
GRANT EXECUTE ON FUNCTION payment_attestation_required(uuid,uuid,uuid) TO apl_api;
GRANT EXECUTE ON FUNCTION read_policy_page(uuid,uuid,uuid,uuid,bigint,bigint) TO apl_api;
GRANT EXECUTE ON FUNCTION read_dispatch_control_state(uuid,uuid,uuid,text,uuid),
 set_dispatch_control_state(uuid,uuid,uuid,text,uuid,bigint,boolean) TO apl_api;
GRANT EXECUTE ON FUNCTION read_admin_entities(uuid,uuid,uuid,text,uuid,bigint),
 read_admin_grants(uuid,uuid,uuid,text,text,bigint),
 admin_set_entity_enabled(uuid,uuid,uuid,text,uuid,bigint,boolean),
 admin_revoke_grant(uuid,uuid,uuid,text,uuid,uuid,uuid,bigint) TO apl_api;
REVOKE ALL ON FUNCTION read_action_detail_v23(uuid,uuid,uuid,uuid,uuid),
 read_action_history_v23(uuid,uuid,uuid,uuid,uuid,text,bigint,bigint) FROM apl_api,apl_worker;
