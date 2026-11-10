# Operations v1 interface

GET `/v1/operations?connection_id=<uuid>` requires a separate enabled `operations_grants` row for reviewer/connection, not approval or control authority. Resolve tenant/environment from identity. Read-only, no-store/nosniff, generic errors, final authentication recheck after I/O. Unknown query fields rejected. No raw request/payment/customer/provider key/routing or metadata fields.

`persistence::operations::OperationsSnapshot` (Serialize/Deserialize), all fields required:
- connection_id:Uuid; sampled_at_unix:i64.
- tenant_paused, connection_paused:bool; workloads_paused:i64 (only workloads granted this connection).
- pending_approvals:i64; oldest_approval_age_seconds:Option<i64>.
- held_minor, committed_today_minor, daily_used_minor:i64; daily_limit_minor, exposure_limit_minor:Option<i64>.
- unknown_outcomes, pending_provider, manual_review:i64; oldest_unresolved_age_seconds:Option<i64>.
- ready_jobs:i64; oldest_ready_lag_seconds:Option<i64>.
- failed_notifications, queued_notifications, failed_exports, unknown_age_records:i64.

`Store::operations_snapshot(&Reviewer, connection_id:Uuid)->Result<OperationsSnapshot>` uses one consistent snapshot, explicit current grant and tenant/environment enabled checks, narrow API-only function(s), 5s statement timeout and final authorization recheck. Unauthorized/foreign connection hidden404. Aggregate budgets from authoritative reservations: held all days; committed/daily used for current UTC day. Ready lag is clock minus existing outbox available_at, ready jobs only. Pending approvals must be latest, unexpired, undecided and match active policy. Provider states are snapshot strings unknown/pending/manual_review; exclude terminal/abandoned. State-age means time since entering current unresolved state.

Migration0018 adds nullable approvals.created_at and external_dispatches.state_changed_at WITHOUT legacy backfill, then defaults for new rows; a snapshot state-change trigger timestamps later transitions only. Legacy unknown ages remain null and contribute unknown_age_records. Do not invent historical timestamps. No actions table column changes needed. Tests cover isolation/revocation, totals, ages, unknown history and no mutations/direct role access.

API router: `operations::router(store, workload_auth, reviewer_auth)->Router`; coordinator wires startup. Console uses existing ReviewerCredential/sessionSignal; new OperationsPanel connection input, explicit refresh, status/error/empty feedback and snapshot cards. Scope change/token clearing aborts stale requests. No automatic control mutations in this initial read-only view.

Telemetry crate is independent: bounded route-template/method/status-class HTTP counters and latency histogram, server-generated trace UUID response header and structured completion logs. Never label/log raw URI, query, bearer/cookie, body, user/tenant/action IDs. `/metrics` requires its own configured bearer secret; disabled unless configured; scrape route excluded from its own metrics. Coordinator wires startup and sanitized persistence error classification. Further worker/provider/business metrics remain required by plan and must not be claimed delivered by HTTP counters alone.
