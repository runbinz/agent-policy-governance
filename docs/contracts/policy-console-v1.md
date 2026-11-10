# Policy administration console

Status: implemented and locally verified; see PROJECT_STATUS and verification history. Software-plan section12 requires constrained editing, validation, diff, simulation and explicit publication.

## Existing authority and writes

- Reuse connection_admin_grants edit_policy/publish_policy. Existing lock_connection_admin permission simulate already allows either policy role with enabled tenant/environment/reviewer/connection/grant and transaction-held locks. Approval, detail, evidence and operations grants confer no policy authority.
- Existing POST /v1/policies/drafts creates immutable versions; POST /v1/policies/{version}/simulate compares a selected version with the active version; POST /v1/policies/{version}/publish uses connection_id + expected_version. Keep these authority and concurrency checks.
- Simulation is static policy evaluation only: no provider reads/writes, budget holds or action execution. The UI must not describe a simulated allow as guaranteed execution eligibility.

## Read API needed

- GET /v1/policies?connection_id=<uuid>&after=<positive-version>&limit=<1..100>, default50. Reviewer-only, unknown/duplicate filters rejected generically after authentication. Use no-store/nosniff and reauthenticate after I/O.
- PolicyPage: connection_id, active_policy:PolicyVersion|null, versions:PolicyVersion[], next_after:i64|null, can_edit:bool, can_publish:bool. Definitions immutable. Active policy is separately returned even when absent from this page. Flags are advisory; every write rechecks current authority.
- New forward migration0025 supplies a narrow authorized read function. Invoke existing simulate/read authority, lock active binding consistently, filter versions before LIMIT+1, no direct API table grants or metadata passthrough. Nonexistent/unauthorized scopes use existing generic hidden-resource error conventions.
- Browser-facing numeric versions must be positive safe JSON integers; reject an unrepresentable stored version safely rather than round it. Existing nonbrowser int64 write contracts need not be narrowed. Console input and expected_version remain exact.
- Bound result size and statement duration. Cursor bound is positive version within the selected authenticated connection; it grants no authority. Each page and active value come from one consistent read statement under transaction-held authorization.

## Console behavior

- Policy tab accepts a connection ID until the forthcoming connection inventory can supply a chooser. Paginate all versions, show current active values, select an immutable saved draft/version and show field-by-field differences.
- Constrained fields: version, auto_limit_minor, hard_limit_minor, approval_ttl_seconds, using existing backend validation/ranges. Explain minor-unit amounts and that budgets are separate controls. No free-form policy code.
- Edit-only users can create and simulate; publish-only users can inspect, simulate and publish existing versions. Disabled buttons convey missing capability without granting it.
- Save creates a new immutable version. Form edits invalidate saved selection/simulation confirmation. Never mutate an existing version or silently overwrite on conflict.
- Build bounded simulation fixtures for the selected connection, compare old/new outcomes and reasons. Explicitly label fabricated fixture payment IDs; simulation never verifies a payment.
- Publication requires explicit confirmation showing saved version, exact changed fields and captured expected active version. Backend expected_version remains authoritative. Conflict refreshes active state; ambiguous network failure is an unconfirmed outcome, not an automatic retry or success claim.
- Abort stale requests on connection/session/selection changes. Clear scoped data on authorization loss. Keep monetary approval flows independent.

## Verification and ownership

- Before edits record bounded ownership in PROJECT_STATUS. Coordinator owns shared declarations, OpenAPI/generated client and integration. Do not overlap existing admin handler/function ownership.
- Runtime-role tests: scope/role isolation, disabled/revoked grants, edit/publish independence, active read and pagination, oversized/nonrepresentable versions, concurrent publication precondition. Existing policy/dispatch lock-order tests must remain passing.
- API tests: workload/session separation, validation/redaction/no-store; console generated contract check/build and browser create/diff/simulate/confirm/conflict/cancellation checks.
- Targeted checks first, then one stable workspace gate. No real provider calls or external deployment needed for this slice.
