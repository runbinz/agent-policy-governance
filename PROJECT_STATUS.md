# Data Governance — current status
Updated: November 9, 2026

## Scope and specification
- Root: `/Users/runbinzhou/Documents/ChatGPT/Data Governance`; coordinator chat `01a1271c-c387-7de3-9bad-898740ca5836`.
- Read `AGENTS.md`; implementation spec: `agent-policy-layer-software-plan.md`; business context: comprehensive plan.
- Rust/Axum/Tokio/Serde/SQLx/PostgreSQL; React/TypeScript/Vite with generated OpenAPI types.
- Full verification history: `docs/verification-history.md`. Read only relevant entries, not the whole archive.
- Other known project chat: `01a12382-1eec-71d3-b5d9-6e357b8f3fe1`; verify exact project membership before inspecting contents. No standalone chat messaging authorized.

## Implemented and locally verified
- Scoped workload/reviewer identity, managed JWKS refresh, policy versions/simulation/publication, exact approvals, cancellation and multi-scope pause controls.
- Atomic budgets, durable fenced dispatch, trusted Stripe sandbox routing, webhook inbox and reconciliation/manual-review holds.
- Managed OIDC browser sessions/CSRF, stateless authenticated MCP, reviewer console.
- Redacted evidence search/encrypted exports/expiry cleanup and durable minimal approval notifications with fake/Slack transports.
- Migrations through 0027 frozen; use forward migrations. All source currently untracked; do not overwrite other work.

## Latest evidence
- Full shared gate: 153 tests passed, formatting and Clippy on Rust 1.90; .local/control-final-gate.log.
- Revisioned dispatch controls verified in API/browser for tenant, connection and workload, including stale resume rejection; generated-client check/build and secret scan passed. Public pause/resume now requires expected_revision.
- Fresh console API generation/check/build and isolated administration browser revision/enable/revoke/access-loss checks passed. Earlier masked API-check failure is corrected in verification history.
- Retained facts, exact generation/dispatch linkage, stale review, fresh dispatch/rollback and legacy-send/reconciliation tests passed. Recovery test now owns its database.
- Required metrics/13 alert rules and authenticated live worker scrape passed locally; `.local/required-metrics-gate.log`.
- Searchable visibility retention passed runtime-role, boundary/export/replay and same-connection migration tests plus independent static review. No physical deletion.
- Dependency upgrades fixed active TLS/XML/Tokio advisories; gate passed with two explicit disabled SQLx backend exceptions. See docs/DEPENDENCY_SECURITY.md. Remote CI not run.
- Restore rehearsal preserved exposure/execution, paused tenants, invalidated browser sessions and disabled routes; `.local/notification-restore-gate.log`.
- PostgreSQL synthetic verification: 127.0.0.1:55433, admin apl_admin, active DB apl_operations_final_gate. Use separate disposable agent databases.
- Gate: `TEST_DATABASE_URL=postgresql://apl_admin@127.0.0.1:55433/apl_operations_final_gate bash scripts/verify.sh`.

## Active ownership and next work
- Control agents finished; migration0027 and independent control console integrated and verified.
- Next: docs/contracts/operations-recovery-v1.md. recovery_store owns migration0028 and persistence operations_recovery module/tests; recovery_ui owns new RecoveryPanel.tsx and ReconciliationPanel.tsx. Coordinator owns shared declarations/grants/API/OpenAPI/client/integration. No nested agents.
- Administration inventory/enable/revocation shipped locally. Provisioning/grant creation and measured credential health remain mandatory; full administration is incomplete.
- Policy editor/diff/simulation/publication and secret checks passed locally; remote CI/production acceptance remain open.

## Remaining scope (not completed)
- Administration provisioning/grant creation, measured credential health, operations recovery detail/reconciliation UI and assigned-authority filtering. Actual alert delivery and production metrics-owner configuration remain deployment work.
- Load/fault/application-security and cross-target/history secret checks; physical metadata expiry/durable archive and retention administration; production configuration/deployment/secrets and staged rollout. Repeat dependency gate when dependencies change.
- Real managed issuer/HTTPS browser, remote MCP client, Stripe sandbox, Slack, S3/cloud backup acceptance require external accounts/access. Local mocks do not prove production readiness.
- Goal stays active until specification requirements are verified; never equate compilation or a partial gate with execution safety.

## Efficient execution
Follow `docs/AGENT_WORKFLOW.md`: focused reads, fresh bounded agent contexts, targeted checks then one final integration gate, compact output/handoffs. Update this file with current ownership/results; archive historical detail instead of growing it.
