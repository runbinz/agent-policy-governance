# Implementation backlog and agent execution plan

## Working protocol

Read `AGENTS.md`, `PROJECT_STATUS.md`, and relevant software-plan sections first. The coordinator defines contracts before assigning parallel work. Each assignment states its objective, owned files, dependencies, acceptance criteria, and checks. Subagents do not delegate further. Only the coordinator edits shared manifests, lockfiles, and status during parallel work. Reviewer tasks are read-only unless explicitly assigned fixes.

For each milestone, implement the smallest complete slice, review its permission and failure boundaries, and run `TEST_DATABASE_URL=… bash scripts/verify.sh` against a dedicated disposable PostgreSQL database. Fix failures and rerun the affected checks, then run the shared gate before handoff. Record what passed, what remains, and any genuine external prerequisite in `PROJECT_STATUS.md`. Continue with the next unblocked slice. Local or sandbox verification does not satisfy live deployment or provider acceptance criteria.

## F1 — local durable fake-provider slice (complete)

Deliver a Cargo workspace, strict refund request types, pure policy, two local workload identities, tenant-scoped submission/status/events, transactional idempotency, audit trail, PostgreSQL queue, fake-provider worker, and reproducible local demo.

Acceptance:
- Invalid/unauthenticated requests fail; caller cannot choose tenant or connection grants.
- Same key and request return one action under concurrency; changed request conflicts.
- Tenant B cannot read tenant A's action or events; database runtime roles enforce isolation.
- A committed action survives process/store restart and reaches a durable fake result once.
- Unsupported approval-required actions fail closed.
- Formatting, Clippy, unit, database, and HTTP integration checks pass.

This milestone deliberately uses local bearer-token fixtures and a database-backed fake provider. Its atomic fake execution is not the real external-provider dispatch protocol.

## F2 — authentication and authorization (workload foundation delivered)

Delivered: RS256 signatures using trusted static JWKS, issuer/audience/expiry/not-before validation, registered identity mappings, persisted scoped grants/revocation, enabled connection checks, role separation, and database-backed JWT/isolation tests. API operations and fake dispatch recheck authorization under locks. Identity changes are audited.

Managed discovery, bounded key refresh/rotation, and fail-closed readiness are implemented and verified with a mock issuer. Outstanding operational work: connect a real managed issuer and finish operator provisioning workflows. Production deployment startup belongs to F5; current API remains loopback-only. Human login and reviewer roles precede F3 approvals. See ADR 0002 for limits.

## F3 — approval and policy lifecycle

The constrained policy console now loads authorized immutable versions, shows active/draft differences, simulates static fixtures and confirms expected-version publication. Locally verified; see current status for evidence and remaining administration scope.

Delivered and verified locally: immutable versioned policies with guarded SQL publication, exact-action digest binding, distinct reviewer JWT or development credentials, expiry/revocation checks, cancellation, audited connection pause, durable policy decision evidence, and the local reviewer console. Connection-scoped policy administration and independently granted tenant, workload, and connection pause/resume APIs are implemented. Managed OIDC code flow, shared opaque sessions, secure cookie/CSRF checks and console login/logout are implemented and verified with mocks and PostgreSQL; real issuer/HTTPS deployment acceptance remains open.

## F4 — money and external execution safety

Delivered and verified locally: atomic budgets, durable external dispatch, trusted account routing, per-payment serialization, opt-in Stripe sandbox adapter, signed webhook inbox, and grant-checked manual review reconciliation. Tests use PostgreSQL and loopback provider mocks. Real sandbox verification remains outstanding.

## F5 — integration and operational readiness

Delivered locally: signed MCP transport and workload authorization, generated OpenAPI console client, verified provider webhook inbox, operations runbook, an isolated PostgreSQL dump/restore rehearsal, scoped asynchronous encrypted evidence exports with search/selection/cleanup, and durable minimal approval notifications with fake and Slack transports. Export hardening and regressions pass after independent review. Scoped operations snapshots/console and protected bounded HTTP telemetry are implemented; legacy unknown ages remain explicit. Worker/provider/business metrics and tested alert rules are now implemented, as are connection/currency/amount/recorded-age approval filters. Searchable-retention visibility and dependency-advisory remediation passed local integration verification. Outstanding: assigned-authority model, action detail and administrative screens, physical metadata expiry/durable archival evidence and retention administration; actual alert delivery; real remote MCP and managed-issuer/Stripe/Slack/S3 acceptance; load, secret and application security testing; deployment/secrets integration and staged production restore/rollout.

Each milestone must update shared status with checks actually run and unresolved limitations before the next milestone begins.
