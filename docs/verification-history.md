# Verification history

## Status archived November 8, 2026

# Data Governance — shared project status

Updated: November 7, 2026

## Source of truth

- `agent-policy-layer-software-plan.md`: implementation specification; version 1.1 selects Rust backend.
- `agent-policy-layer-comprehensive-plan.md`: business and product context.
- `AGENTS.md`: project scope and cross-chat working agreements.
- `README.md`: project index linking all plans and setup instructions.
- `docs/IMPLEMENTATION.md`: milestones and agent execution protocol.
- `docs/LOCAL_DEVELOPMENT.md`: reproducible setup and demo.

## Current state

F1/F2, local F3 approval/controls, and F4 durable dispatch and budget enforcement are verified. The optional Stripe sandbox worker has trusted connection routing and per-payment serialization. The signed webhook inbox deduplicates events and wakes matching dispatches. A separately granted operator can request a read-only provider check for manual review. Connection policy administration and pause/resume are scoped and audited. Managed issuer discovery and key refresh are integrated and mock-tested. Tenant/workload stops and stateless remote MCP are implemented and locally verified. A real Stripe sandbox account and issuer, remote MCP client acceptance and production deployment remain outstanding. Managed browser login/session/CSRF integration is implemented and mock-tested; actual issuer and HTTPS browser acceptance remain outstanding. Tenant-scoped evidence search and export selection are locally verified. Export console and bounded ciphertext cleanup are locally verified. Scoped encrypted exports and review hardening pass the local verification gate. Durable approval notifications, fake receipts and bounded Slack transport are locally verified; real Slack acceptance remains outstanding.
Selected backend: Rust + Axum + Tokio + Serde + SQLx + PostgreSQL.
Selected console: React + TypeScript + Vite, using generated OpenAPI client.
Compiler checks are part of the AI development loop; database concurrency and failure tests remain required.

## Known project chats

| Chat ID | Title | Role |
|---|---|---|
| `01a12382-1eec-71d3-b5d9-6e357b8f3fe1` | Review this | Original review and plan creation |
| `01a1271c-c387-7de3-9bad-898740ca5836` | Find software plan file | Stack decision and coordination setup |

Only reference conversation contents after verifying project membership or exact project working directory. This chat is the implementation coordinator, authorized to use bounded subagents.

## Active work and ownership

No active file ownership. Approval notifications completed: persistence agent migration 0017/private queue/leases/channel cooldown; domain agent minimal fake/Slack adapter; coordinator worker integration, queue selection, cross-crate tests and restore defaults. API agent independently reviewed design and code; recipient-sticking and active-policy suppression findings fixed and re-reviewed. Migrations through 0017 frozen. Agents idle. No real Slack messages sent.

Completed November 5:
- Domain agent: versioned policy evaluation, local reviewer console, dispatch and recovery state contracts, and independent expiry review.
- Persistence agent: approval persistence, cancellation, pause, policy evidence, and fake-worker ledger integration.
- API agent: reviewer endpoints and signed JWT regression coverage, budget ledger, and checked-in OpenAPI/console types.
- Coordinator: migrations and Cargo integration, policy publication script, cancel route, shared verification and demo gates, CI, fixtures, and documentation.

Migrations 0003–0017 have been applied; use forward migrations for changes. The continuous implementation goal is active.

Completed F2:
- Identity agent: `crates/identity/`; RS256 verifier, test fixtures, claim/key tests; independent authorization review.
- Persistence agent: new identity migration, restricted runtime permissions, grant rechecks/locking, identity audit, local seed, database regressions.
- API agent: explicit local/JWT modes, persisted resolution, startup and signed-JWT HTTP tests; independent identity review.
- Coordinator: integration, dependency lockfile, setup/docs/CI, database migrations and complete verification.

Independent review found cross-connection read access for identities sharing a workload. Fixed by checking the action's stored connection as well as tenant/environment/workload, with status/event regression tests.

Completed F1 work:
- Coordinator: workspace/lockfile/toolchain, integration, project index, backlog, Docker setup/demo, CI workflow, verification.
- Domain subagent: typed validation and policy; independent read-only review.
- Persistence subagent: PostgreSQL isolation/idempotency/audit/jobs and recovery/concurrency tests.
- API subagent: local authentication, HTTP endpoints, worker executable, boundary tests.

Review's missing submission status link was fixed with `status_url` and `Location`. Requested permission/concurrency/partial-write rollback tests were added and passed.

## Next implementation step

Next: operational metrics/dashboard, then remaining administrative screens, load/security tests, metadata retention and deployment hardening. Real managed issuer/HTTPS deployment, remote MCP, Stripe sandbox, Slack and cloud storage acceptance still require external accounts/clients after implementation.

## Last verification

November 7, 2026, approval notification checkpoint:
- Full shared gate passed: 110 tests across default and explicit PostgreSQL runs, formatting and Clippy. Covers atomic enqueue/rollback/dedup, bounded claims/restart/stale fences, active-policy and scope suppression, sticky recipients, disabled-route cleanup, shared channel cooldown/Retry-After and fake receipt idempotence. Worker integration proves notice delivery leaves approval pending with no effect/reservation, and cancellation after preflight suppresses the fake receipt.
- Notification transport uses loopback mocks only: verified token workspace, fixed API host, redacted plain facts plus authenticated structural link, size/time bounds, no redirects/automatic HTTP retries, transient/permanent outcomes. No real Slack calls or messages. Delivery remains at least once; a late suspended sender can duplicate outside database fencing.
- Independent review findings fixed before migration freeze and re-reviewed with no new actionable finding. `--queue notifications`/`exports` exclude dispatch/provider initialization; default combined worker remains available locally.
- Updated synthetic restore rehearsal passed into `apl_notification_restore_gate`: preserved execution/exposure, paused all tenants, invalidated browser sessions/login flows and disabled notification routes before runtime grants. Recipient setup must be reverified before enabling notification egress.

November 7, 2026, managed browser integration checkpoint:
- Full shared gate passed: 102 tests across default and explicit PostgreSQL runs, formatting and Clippy. Signed login uses one API/database pool to start and a second to complete; binding mismatch, HEAD callback, replay, expired state, disabled reviewers, mixed credentials, missing/wrong CSRF and cookie-as-workload are rejected. Positive cookie/CSRF approval follows the existing digest/policy/budget/fake-worker path, rejects replay and records one synthetic effect.
- Console contract check/build passed. A loopback presentation fixture verified restored session view, error/retry, CSRF-bearing logout without Authorization, and managed POST login form without token entry. This fixture does not test real OIDC or Secure cookies. No real issuer or external provider was contacted.
- Bounded independent security review reported no actionable bypass. Real issuer registration, upstream SSO behavior, actual HTTPS/proxy cookie handling and deployment remain staging checks.
- Synthetic dump/restore rehearsal passed into `apl_browser_restore_gate`: preserved execution/exposure records, paused every tenant, cleared login transactions and revoked restored browser sessions with the expected audit count before runtime grants. No provider egress.

November 7, 2026, browser login foundations checkpoint:
- Full shared gate passed: 99 tests across default and explicit PostgreSQL runs, formatting and Clippy. Shared callback consumption is single-use across two pools; wrong browser binding, replay, expiry, revoked/disabled mappings, wrong logout CSRF, duplicate logout and direct runtime table access are rejected.
- ID-token tests enforce sole client audience, nonce, authorized party, recent numeric issuance and managed-cache freshness. Mock code exchanges verify S256 fields, exact redirect/client, bounded JSON, no automatic retry/redirect and generic provider errors. Provider tokens are discarded.
- No browser login routes or sessions are enabled in API startup yet. Cookie/CSRF/console integration and mock end-to-end tests remain required before claiming managed login works. No real issuer was contacted.

November 7, 2026, evidence search checkpoint:
- Full shared gate passed: 92 tests across default and explicit PostgreSQL runs, formatting and Clippy. Tests cover bound filters, UUID keyset pagination, explicit auditor grants/revocation, same-tenant cross-connection and cross-tenant isolation, allowlisted output and signed HTTP behavior.
- Console API drift check and production build passed. Browser verified redacted results, one-row pages, selection across pages, export form prefill, filter-change selection clearing, hidden foreign connection and reviewer token clearing. Local synthetic data only.
- The cleanup end-to-end test now drives earlier due jobs before asserting its own artifact deletion, allowing repeated gates on a reused disposable database. Search ordering is UUID-based and makes no chronology claim.

November 7, 2026, export console and cleanup checkpoint:
- Full shared gate passed: 89 tests across default and explicit PostgreSQL runs, formatting and Clippy. Includes scoped bounded cleanup, retry/restart fencing, grace period, hourly late-write sweeps and audit-once semantics. Coordinator end-to-end test deletes after grant revocation and removes a simulated late write on a later sweep.
- Console API drift check and production build passed. In-app browser verified request → queued → ready → download, generic revoked-access error, and token clearing. Local synthetic fixtures only; no cloud calls or provider writes.
- Independent cleanup review reported no actionable findings. Artifact deletion does not erase S3 versions or backups; cloud lifecycle/IAM and retention remain deployment acceptance items.

November 7, 2026, final export backend checkpoint:
- Full shared gate passed on fresh `apl_exports_final_gate`: 84 tests across default and explicit PostgreSQL runs, formatting and Clippy. Includes expired JWT during final download audit wait, pre-aggregation history/size rejection, requester/grant isolation, generation fences, encrypted artifacts, and retired startup keys.
- Added Cargo migration-directory tracking to persistence and ledger so incremental builds embed new migrations. Migrations through 0013 applied.
- Console contract/build passed before the new export UI work began. S3 and external issuer/provider acceptance remain unverified.

November 7, 2026, initial export integration:
- Shared gate passed: 81 tests across default and explicit PostgreSQL runs, including scoped encrypted export/download/revocation. Console API contract check and build passed.
- Storage tests cover ciphertext-only files, tampering, scope/generation binding and retained keys. S3 configuration was built without cloud calls.
- Independent review found final token-expiry and pre-aggregation size-bound issues; both fixes pass targeted checks. Retained-key startup tests pass. The final shared gate later passed on fresh apl_exports_final_gate after fixing Cargo migration-directory tracking; the earlier incremental binary embedded only migrations through 0012.

November 7, 2026, MCP and multi-scope controls checkpoint:
- Full shared gate passed: 60 non-database tests and eight PostgreSQL tests. MCP and REST use one scoped idempotency map; valid registered workloads are rate limited, and foreign workloads cannot read/cancel actions.
- Console contract check/build passed. MCP transport was verified with signed fixtures and in-process HTTP; a real remote client and authorization server were not connected.
- Local synthetic dump/restore rehearsal preserved action/audit/dispatch/attempt/ledger counts, held exposure, and migration version, and set every restored tenant paused before runtime grants. No provider egress occurred. This does not validate deployed backup retention or production RPO/RTO.

November 6, 2026, administration and managed identity checkpoint:
- Shared gate passed: 51 non-database tests and seven PostgreSQL tests, including concurrent publication, grant revocation, read-only simulation, and operator audit records.
- Local mock issuer tests cover atomic rotation, dual-audience rejection, URL and issuer mismatch, and stale-cache fail-closed behavior. No real issuer was contacted.
- OpenAPI contract regeneration, drift check, and console build passed.

November 6, 2026, sandbox and reconciliation checkpoint:
- Shared gate passed on PostgreSQL 14: 44 non-database tests and six PostgreSQL suites. Covers fake worker exclusion, held-payment serialization, stale Charge context, signed webhook deduplication, and grant-checked manual review reconciliation that cannot send again.
- Console OpenAPI regeneration, contract drift check, and build passed. Stripe HTTP tests used loopback mocks only.

November 5, 2026, external dispatch checkpoint:
- Full `scripts/verify.sh` passed against isolated PostgreSQL 14 database `apl_external_gate`: 33 non-database tests and five PostgreSQL suites, including restart, stale lease, unknown hold, manual review, and worker cancellation after provider acceptance. Replacement worker reconciled the existing effect with one send and one settlement.
- `npm --prefix apps/console run api:check` and `npm --prefix apps/console run build` passed with the new action statuses.
- No live provider calls occurred. The fixture test cancels an async worker after acceptance and starts a replacement worker with a fresh database pool; it does not claim to test a real Stripe outage or a deployment restart.

November 5, 2026, F3 and F4 local checkpoint:
- `TEST_DATABASE_URL=… bash scripts/verify.sh`: passed against isolated PostgreSQL 14 on loopback port 55433; 30 non-database tests and three PostgreSQL suites passed. These include cancellation vs. worker, pause ordering, concurrent budget admission, UTC rollover, and approval expiry while waiting for a budget lock.
- `npm ci`, `npm run api:check`, and `npm run build` in `apps/console`: passed. The Vite proxy forwarded the complete HTTP demo to the Rust API, including exact approval, replay rejection, and cancellation with budget checks active.
- `scripts/publish-policy.sql` published a new version and correctly rolled back a stale expected-version attempt.
- Independent review found an expiry race returning an incorrect 500 instead of a stale-decision conflict. Migration 0004 fixes the write boundary; the gate passed with the fix.
- Docker was unavailable during this checkpoint. The isolated local PostgreSQL cluster under `.local/verify-pg.r2Datf` contains only synthetic verification data. Remote CI has not run.

October 10, 2026, F2 baseline:
- Rust 1.90.0 installed; dependency versions pinned in Cargo.lock.
- `cargo check --workspace`: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed.
- `cargo test --locked --workspace`: 16 tests passed (domain, HTTP boundary, startup, and JWT/key validation); two database tests intentionally ignored in default suite.
- Dedicated PostgreSQL 17 persistence test explicitly run with `--ignored`: passed (idempotency, nonowner RLS, permissions, concurrency, rollback/restart, revocation locking, cross-connection isolation, identity audit).
- Signed-JWT HTTP/PostgreSQL test explicitly run with `--ignored`: passed (valid signature/admission, tamper/expired/wrong issuer/audience/unknown subject, ignored tenant claims, cross-tenant access, revoked dispatch with no effect).
- `python3 scripts/demo.py`: passed with separate API/worker database logins.
- `git diff --check`: passed. CI workflow added; remote CI has not run.

Docker PostgreSQL runs on loopback port 55432, data in ignored `.local/postgres`. API (127.0.0.1:8080, local auth mode) and fake worker were restarted with F2 code. Development fixtures only; no real refunds were issued. JWT mode is verified with test keys, but no real issuer account has been connected.

## Handoff format

For each active task, record: chat ID, objective, owned files, state, checks actually run, remaining work, and blockers. Remove obsolete claims when work finishes.

## November 9, 2026 — required operational metrics
- Shared gate `.local/required-metrics-gate.log`: 128 tests passed, formatting and Clippy, including actual runtime-role database integration.
- Migrations0019–0021 provide global consistent bounded aggregates; row_security=off fails closed for an insufficient function owner. Runtime API/worker remain non-bypass.
- Typed bounded worker/provider counters, internal processing timing excluding provider I/O, 10s collector deadline, stale-sample reporting and loopback authenticated worker metrics.
- Official promtool3.5.0 checks passed13 rules and15 scenarios/123 assertions; `.local/metrics-alerts-check.log`. No actual alert delivery configured.
- Live synthetic worker on separate apl_exports_ui DB: unauthenticated401, authenticated200, business collector up, notification idle ticks, route ID absent; stopped owned worker afterward. No external provider writes.
- Production metrics owner still needs explicit global-row privileges; local administrator ownership is not production deployment proof.

## November9,2026 — approval queue filter increment
- Nullable authoritative queued_at exposed from existing approvals.created_at; legacy null remains unknown. Runtime-role isolated DB test covers exact timestamp, tenant/environment isolation, revoked grants, expired/decided/nonpending/currentpolicy exclusion.
- Composed currency/connection/inclusive minor-unit amount/minimum recorded-age filters; safe integer/range validation and reset. No assignment model fabricated.
- `.local/approval-filters-gate.log`:129 tests, formatting andClippy passed. Console generated API check/build passed; pure boundary assertions passed.
- Local synthetic browser checks: missingcurrency/reversedrange validation, exact1000boundary combinedwith30minuteage shows1of3, active0minuteage excludesunknown, empty/reset, exactconfirmation and409refresh/focus recovery. Submitted generation2 and original64character digest unchanged; noactualrefund. Testservers stopped.

## November 9, 2026 — searchable retention and dependency remediation
- `.local/retention-security-final-gate.log`: 131 tests passed, formatting and Clippy on Rust 1.90 after dependency upgrades. Migration0022 frozen after integration.
- Retention runtime-role tests: exact cutoff, per-scope/default settings, unknown legacy grace, active/open external/held exposure exceptions, selected-ID and export bypass prevention, queued snapshot expiry, existing download TTL, unchanged replay/no extra enqueue and timestamp protection. Same-connection pre0022 upgrade exercises cached preflight invalidation.
- Independent static review found no actionable retention authorization/export/replay/lock-order issue. Physical deletion, durable archive, backup retention and configuration API remain open.
- Active advisory fixes: Tokio1.53.3, rustls0.23.46, rustls-webpki0.103.16, webpki-roots1.0.10, object_store0.14.2/quick-xml0.41.0. ObjectStoreExt imports are the only application/test source adaptation. Evidence17 tests passed separately.
- `.local/dependency-policy-check.log`: advisory gate passed; npm0 advisories, Rust0 warnings, two explicit disabled-backend lockfile exceptions (RSA/MySQL and SQLite). Four policy boundary assertions passed, including fail on enabling an affected backend and fail on unknown findings. New CI step added but remote CI not run.
- Native certificate verifier behavior changed with object_store upgrade; real S3/trust acceptance remains required. No actual provider calls or deployment performed.

## November 9, 2026 — reviewer detail and secret scanner
- Full .local/detail-final-gate.log: 137 Rust tests, formatting and Clippy passed. Migration0023 frozen. Console API generation check/build passed.
- Dedicated detail grant, typed redacted detail and five paged history kinds; immutable request, policy/approval, action exposure, validated external context/outcome, honest legacy timestamps. Workload read endpoints unchanged.
- Actual runtime-role tests cover scope/grant independence, disabled tenant/environment/reviewer/connection, terminal success/nonexecution/contradictions, unknown-label redaction, corrupt context, bound pagination, retention/held exceptions and revocation blocking until reader commit. Independent static review found no actionable issue.
- Real loopback API/browser against owned apl_detail_ui_20261109: submission and fake worker produced pending approval; default-deny detail404 while queue visible; explicit grant enabled detail/history200 and policy navigation; revoke+refresh cleared sensitive view; queue confirmation remained available and token clearing removed the view. No monetary decision submitted. Owned API/Vite processes stopped.
- Nullable active terminal/undecided timestamps display Not terminal/Not decided; historical unknowns stay explicit. Recorded connector context is not a live balance; full payment facts remain pending ADR0014.
- Gitleaks8.30.1 working-tree scan and synthetic GitHub-token detection/redaction/cleanup self-test passed; .local/detail-secret-check.log. Minimal documented fixture exceptions; source and untracked files scanned. CI step added, remote CI/Docker path/history scan not run.
- ADR0014 accepts retained preapproval facts design, immutable generation linkage, material-change review rotation and fresh equivalent dispatch recheck. Observation age alone must not impose a 30-second human decision window. Implementation remains next.

## November 9, 2026 — retained payment facts
- Verification correction: the earlier reviewer-detail entry incorrectly recorded API-check success. An OpenAPI formatting error was masked by a later successful command; the console built against stale generated types. Fixed schema nesting, regenerated types, and independently confirmed generation/check/build with set -e. Current .local/attestation-openapi-final-check.log and attestation-console-final-build.log pass.
- Final .local/attestation-final-gate.log: 143 Rust tests, formatting and all-target Clippy passed after integration, legacy-send fix and isolation repair. Migration0024 frozen.
- Typed validated observations retain authenticated Stripe charge facts with original read-start freshness. Immutable scoped attestations bind approval generations and fresh dispatch facts; original action digest preserved. Same material facts avoid repeated snapshots; changed facts rotate review without extending its original deadline. Observation age alone does not impose a 30-second human review window.
- Runtime-role lifecycle covers scope/FK/immutability/API write denial, forged metadata exclusion, stale/future/mismatched observations, route/authority changes, decision race, material-change generation/expiry, validated public projections, and atomic rollback when a demonstrably blocked budget wait consumes freshness. Dedicated .local/attestation-lock-test.log passed.
- Legacy unsent records without retained evidence cannot create a send marker; only provably unsent holds can be abandoned/released. Marked unknown records preserve key, held exposure and reconciliation. Regression passed in lifecycle and shared gate.
- Persistence recovery test now uses its own UUID child database because repeated shared gates exposed old paused jobs in global queue claims. Existing assertions/worker protocol preserved; .local/attestation-isolation-regression.log passed.
- API/browser on owned apl_attestation_ui_20261109 with explicitly seeded synthetic trusted historical facts: captured30000/refunded1000/remaining29000 USD minor units, stale-but-reviewable state and exact generation link; hostile-looking identifier rendered twice as text with zero image elements, private metadata absent. This UI fixture does not prove authenticated provider acquisition; separate connector mock tests cover acquisition. No provider writes or monetary decision submitted. Owned API/Vite stopped.
- Connector targeted suite:22 tests passed plus targeted Clippy; no new dependencies. Gitleaks self-test and current working-tree scan pass. Real Stripe/account acceptance and remote CI remain open.

## November 9, 2026 — policy administration console
- .local/policy-final-gate.log:145 Rust tests, formatting and Clippy passed. Migration0025 frozen. Fresh API generation/check, console build and secret negative-control/working-tree scan passed.
- Narrow policy page read uses existing edit-or-publish authority, explicit enabled-connection check, transaction-held locks, independently returned active definition, bounded pagination and exact safe JSON versions. No direct policy table grants.
- Runtime-role tests cover scope/disabled/revoked and independent edit/publish permissions, active outside page, pagination, read/publication locks, stale publication precondition and unrepresentable versions. API tests verify workload rejection before filter errors and generic/no-store responses.
- Console creates immutable versions, validates constrained numbers, shows saved-vs-active differences, simulates bounded synthetic fixtures and confirms captured expected-version publication. Uncertain publication clears loaded state without auto-retry. Existing monetary approvals remain independent.
- Real loopback API/browser on owned apl_policy_ui_20261109: invalid auto>hard disabled saving; version2 saved; simulation500/1500/50000 produced allow/require_approval/deny under stricter draft; explicit modal showed exact values+expected1; publication acknowledged and active2 refreshed. Concurrent publication to3 rejected confirmation for4 captured at2, refreshed3 and cleared selection. Scope change/sign-out and denied scope cleared data. Only synthetic metadata writes; no provider/refund calls.
- Owned API/Vite processes stopped. External issuer/production/remote CI acceptance remains open.

## November 9, 2026 — environment administration foundation
- .local/environment-final-gate.log:150 Rust tests, formatting and Clippy passed. Migration0026 frozen. Fresh API generation/check/build and secret self-test/working-tree scan passed.
- Dedicated default-deny environment administration, redacted scoped entity/grant pages, safe revisions, fixed grant-kind/permission mappings, audited enable/disable and revocation. Existing operator/approval/policy permissions remain independent. Credential health is honestly unobserved; a past payment timestamp is not credential health.
- Actual runtime-role tests cover all10 grant kinds including cancel_action, key/cursor validation, scope/default-deny/disabled authority, revisions/audit immutability, target/authority locks, self-protection, mutual administrator revocation ordering, and preservation of unknown/manual-review holds. .local/environment-admin-tests.log (3 tests); API role-first validation tests passed2.
- Isolated real API/browser apl_environment_ui_20261109: approval grant alone yielded admin404; explicit bootstrap enabled inventory; confirmation captured exact tenant/environment/target/revision; competing update1→2 rejected stale disable, refreshed2 and discarded dialog; confirmed disable→3 and enable worked. Workload revocation disabled configured permissions and subsequent submission was denied401 by identity lookup. Privileged authority revocation+refresh cleared inventory; sign-out cleared view.
- Only synthetic metadata changed, no provider writes or refund actions. Owned API/Vite processes stopped. Focused UI harness covers paging, cancellation, stale responses, conflict/unknown outcomes and empty-state credential replacement.
- Remaining mandatory administration work: provisioning/grant creation, measured credential health and independently authorized pause UI. Next control-console contract requires revision-bound public pause/resume rather than stale UI toggles; no claim full administration/production readiness.

## November 9, 2026 — revisioned dispatch controls
- .local/control-final-gate.log:153 Rust tests, formatting and Clippy passed. Migration0027 frozen. Fresh generated API check/build and secret negative-control/working-tree scan passed.
- Dedicated independent control grants protect reads and mutations for all three scopes. Public pause/resume intentionally requires expected_revision and returns ControlState200; stale409, exact no-op preserves revision/audit, uncertain holds and original keys unchanged.
- Runtime-role tests cover scope, permissions, concurrency, audit and locks; API tests cover role-first malformed/mixed/missing/unsafe revision inputs. Targeted JWT integration passed serially; parallel execution against shared grants caused catalog contention and was corrected.
- Isolated actual API/browser apl_control_ui_20261109 verified operations-independent control access, tenant-wide warning, cancel/Escape, three-scope pause/resume, stale resume after intervening resume/pause, explicit reload, administration prefill without automatic write, revocation clearing and sign-out. No provider writes. Owned API/Vite stopped.
- Next implementation contract: operations-recovery-v1.md. Provisioning, measured health, assigned authority, retention/archive, security/load and production acceptance remain open.
