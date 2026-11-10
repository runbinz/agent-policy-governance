# Reviewer action detail — proposal for coordinator review

Status: implemented under ADR0013, extended by payment-attestation-v1.md/ADR0014 with locally verified retained authoritative payment facts. Real-account acceptance remains open.
Sources: domain Action/Approval, dispatch VerifiedRefundRequest/DispatchSnapshot, migrations0001–0022,
existing approval/evidence/operations authorizers and apps/console/openapi.yaml.

## Read boundary

- Add GET /v1/reviewer/actions/{id}?connection_id={uuid}; separate reviewer route, never widen workload GET /v1/actions/{id} or /events.
- Add GET /v1/reviewer/actions/{id}/history?connection_id={uuid}&kind={audit|policy|approval|budget|attempt}&after={cursor}&limit={1..100}; default50.
- Authorization: new explicit per-connection action_detail_grants, default deny; existing reviewer/evidence/operations grants confer no implicit detail access.
- New locked authorizer follows authorize_operations/evidence_export_allowed: exact authenticated tenant/environment, enabled tenant/environment/reviewer/connection/grant; FOR SHARE locks through transaction, scoped RLS, revoke PUBLIC execute, runtime EXECUTE only.
- Resolve reviewer from authenticated issuer/subject or managed browser session, never request identity/scope fields. Require action's stored connection to equal authorized connection.
- Reauthenticate before response as current evidence routes do; GET is read-only, Cache-Control: no-store. Bearer workload/MCP credentials never accepted here.
- Decisions remain POST /v1/approvals/{id}/decision with independent authorize_reviewer, generation and backend-checked digest. Detail grant never grants approve/reject.

## Detail response (fixed projection; no generic JSON passthrough)

- schema_version:1, observed_at: database response observation UTC RFC3339, id, workload_id, connection_id, status; nullable created_at/terminal_at from0022.
- immutable_request:{type,resource:{payment_id},parameters:{amount_minor,currency}} projected from actions.request; amounts integer minor units, identifiers escaped text.
- Omit metadata entirely in v1. Existing metadata is untrusted display data, never authoritative customer/payment/policy facts.
- policy:{latest:{audit_sequence,policy_version,outcome,reason_code}|null}; project action_policy_decisions, not today's policy binding. More records through history.
- reason_code uses centralized allowlist (existing bounded service-metrics reason codes are starting inventory); unknown stored strings map OTHER, never echo arbitrary reasons/errors.
- approval:{generation,policy_version,action_digest,queued_at,expires_at,reviewer_id,decision,decided_at}|null from highest generation in approvals.
- decision_eligibility:{can_decide,reason_code}; recompute current latest-generation/pending/unexpired/current-policy/authorize_reviewer predicate; advisory only, POST rechecks all invariants.
- authoritative_payment:{availability:verified_context|unavailable,context:null|{payment_id,connection_id,amount_minor,currency,observed_at,fresh_until}}.
- Context comes only from validated stored external_dispatches.snapshot.request (VerifiedRefundRequest), clearly labelled connector-verified refund context at the recorded time; it is not a live payment balance.
- No dispatch row means unavailable, including pre-dispatch pending approvals. Invalid stored context fails closed, never falls back to request/metadata.
- Current schema does NOT retain captured/refunded balance, payment status/method or connector verification facts for pending approvals. Those required richer payment facts need separate persisted authoritative evidence (see decisions below).
- budget:null|{state:held|settled|released,amount_minor,currency:USD,utc_day,reserved_at,settled_or_released_at}; from budget_reservations + ledger recorded_at.
- This is the action's exposure: held remains exposed even on unknown/manual_review; settled is committed, released contributes zero. Null means no recorded reservation, not zero verified available budget.
- Exclude customer_ref/applied_limits scope refs and other-action totals; connection aggregate exposure remains independently authorized operations screen.
- execution:null|{state,first_send_at,retry_until,state_changed_at,abandoned_at}; validated external snapshot state mapped to enum, plus durable timestamp columns. Epoch milliseconds converted checked to UTC RFC3339.
- provider_outcome:{status:not_recorded|unresolved|confirmed_success|confirmed_non_execution,source:none|external_dispatch|local_fixture}.
- Only validated terminal external DispatchState supplies confirmed provider outcomes. Authorized/in_flight/pending/unknown/manual_review are unresolved; abandoned unsent is not provider-confirmed non-execution.
- Local fake_effects success is explicitly local_fixture, never provider success. Contradictory action/dispatch state is unavailable/inconsistent safe error, never synthesize confirmation from actions.status alone.
- Never serialize ProviderKey, provider_namespace, EvidenceRef strings, raw snapshot, webhook body, object keys, leases, tokens, secret configuration, support transcripts or arbitrary provider errors.

## History, timestamps and payload limits

- Response {items,next_cursor}; each kind has its own stable ascending key: audit.sequence, policy.audit_sequence, approval.generation, budget.sequence, attempt.generation.
- Cursor is versioned, strictly parsed, bound to action/connection/kind; validate positive bounded integers. It grants no authority. Query limit+1, never load unbounded history before truncation.
- Audit items:{sequence,event_type,recorded_at}; policy:{audit_sequence,policy_version,outcome,reason_code,evaluated_at}; unknown event types map safe OTHER.
- Approval items use the detail approval shape; budget:{sequence,event_kind,recorded_at}; attempt:{generation,recorded_at} from external_attempts.marked_at_ms (send marker, not proof of HTTP call or provider receipt).
- Add nullable audit_events.recorded_at with DB default for NEW rows only; old audit rows stay null, no backfill with migration time. Policy history already has evaluated_at; project that existing authoritative evaluation timestamp.
- Existing approvals.created_at and external_dispatches.state_changed_at are nullable for legacy rows. Approval decided_at/expiry and ledger timestamps are already stored; never infer historic transitions from expiry, UUID order or current state.
- Console keeps audit sequence order, shows timestamp unknown where null, and separates history kinds; do not invent a single chronological total ordering or correlate unlinked rows by matching time.
- Detail contains only one latest policy/approval and one reservation/execution; history pages cap100 items. Enforce serialized response ceiling128KiB and statement timeout5s; reject oversize with safe RESULT_TOO_LARGE, never silently truncate immutable parameters.
- Validate stored string bounds/enums in projection, including payment_id<=255 UTF-8 bytes and digest64hex. Unexpected corrupt data returns safe DATA_UNAVAILABLE without raw values.

## Errors and retention

- Invalid UUID/kind/limit/cursor:400 INVALID_REQUEST. Missing/invalid reviewer identity:401 AUTHENTICATION_REQUIRED. Unknown action, wrong scope/connection, disabled/revoked grant, retention-hidden:identical404 NOT_FOUND.
- Unexpected projection/database failure:500 safe SERVER_ERROR or DATA_UNAVAILABLE; no SQL/body leakage. No403/410 that distinguishes hidden records. Decision POST retains existing conflict/expiry behavior.
- Both detail and every history page apply the same scoped searchable-retention predicate introduced by0022 in the authorized transaction; no direct-ID/history bypass. No physical deletion or changed idempotency lifetime.
- Active/unresolved/held rows remain visible per retention contract. A page crossing retention cutoff returns404; console clears stale sensitive detail and explains unavailable/access changed without asserting deletion.
- Existing materialized exports keep their separate expiry and grant rules; detail access grants no export permission. Response observation time is not a historical event time.

## Console and implementation tasks

1. Persistence/security owner: new forward migration0023 (confirm next free number), detail grant + audited changes/authorizer/read functions, nullable audit timestamp column/default; migrations/runtime-roles.sql minimal grants. No edits to frozen migrations.
2. Backend owner: crates/domain/src/lib.rs typed response/page enums; new crates/persistence/src/action_detail.rs + module registration; new crates/api/src/action_detail.rs + router wiring in lib.rs; reuse reviewer session authentication and safe errors.
3. Coordinator: apps/console/openapi.yaml complete nullable schemas, generated src/api.generated.ts and src/api.ts methods; do not hand-edit generated types.
4. Console owner: new apps/console/src/ActionDetail.tsx; App.tsx queue/evidence links route through selected connection; style.css scoped styles. Cancel stale fetches, handle loading/404/conflict; keyboard-accessible paged history and explicit amount confirmation before existing decision POST.
5. Evidence remains read-only; refresh detail/queue after decisions; decision buttons require current eligibility and selected exact generation/digest, no inferred assignments.

## Acceptance and remaining evidence work

- ADR0013 selects the dedicated detail grant, default deny. No implicit existing-grant OR authorization.
- Decide authoritative payment evidence persistence BEFORE claiming §12 complete: minimal immutable connector attestation at policy/approval evaluation with observation/expiry and required captured/refunded/eligibility facts; historical rows remain unavailable. Existing VerifiedRefundRequest alone cannot satisfy richer payment context.
- ADR0013 permits exact payment resource and deciding reviewer UUID under the dedicated grant, excluding customer identity/evidence references.
- Targeted tests: new crates/persistence/tests/action_detail.rs on owned PostgreSQL DB with actual runtime roles: cross-scope/connection, grant revocation/disable, independent decision authority, secret sentinels, invalid snapshot, exact nullable timestamps, keyset boundaries, history>100, oversize and retention cutoff/held/unresolved exceptions.
- API tests in new module: reviewer/session vs workload/MCP auth, malformed filters, indistinguishable404, no-store and safe500. Synthetic browser checks: queue/evidence navigation, unknown timestamps/payment, XSS escaping, paging, stale selection/races, monetary confirmation and existing decision conflict refresh.
- Commands once implemented: cargo fmt --all -- --check; cargo clippy --workspace --all-targets -- -D warnings; TEST_DATABASE_URL=<owned-db> cargo test -p apl-persistence --test action_detail -- --ignored; cargo test -p apl-api; npm --prefix apps/console run api:check; npm --prefix apps/console run build; coordinator scripts/verify.sh integration gate.


## Implementation interfaces and ownership
- Domain DTOs live in crates/domain/src/action_detail.rs, exported as pub mod action_detail by coordinator. Use typed serde responses, no unbounded Value on the public wire.
- Persistence methods: Store::action_detail(&Reviewer, connection_id:Uuid, action_id:Uuid)->Result<ActionDetail>; Store::action_history(&Reviewer, connection_id:Uuid, action_id:Uuid, kind:HistoryKind, after:Option<&str>, limit:usize)->Result<ActionHistoryPage>. Domain types imported from apl_domain::action_detail.
- HistoryKind wire values audit/policy/approval/budget/attempt; items carry a kind discriminator. Cursor strictly bound to action/connection/kind. Invalid filters return StoreError::Invalid and safe400; hidden/auth failures StoreError::NotFound; corrupt stored data safe500 (Serialization/Database), never Invalid.
- Use existing lowercase API error conventions: invalid_request, unauthorized, not_found, internal_error. Oversize responses may use result_too_large500; no raw diagnostics.
- Backend agent owns new domain module, migration0023, new persistence action_detail.rs and tests/action_detail.rs only. Coordinator owns module declarations, runtime-role grants, API integration, OpenAPI/generated client and shared configuration.
- Before starting API/UI work, backend agent publishes exact DTO names/fields and SQL function signatures; then freeze the shared wire contract. No hand-edited generated types.
