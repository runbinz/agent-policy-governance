# Operations recovery rows and reconciliation UI

Status: next implementation contract; migration0028 next free. Complete software-plan section12's unresolved outcomes, stale jobs and reconciliation controls. Existing aggregate snapshots and dispatch controls stay in place.

## Scoped recovery rows

- GET /v1/operations/items?connection_id=<uuid>&kind=dispatches|ready_jobs&after=<cursor>&limit=<1..100>, default50. Existing operations_grants authorize reads; no implicit detail, reconciliation, administration or control permission.
- Page: connection_id,kind,items,next_cursor. Cursor canonical and bound to authenticated tenant/environment/connection/kind and complete ordered action UUID; it grants no authority. Query limit+1 before projection; no arbitrary total-page cap.
- Dispatch rows follow the existing operations/metrics unresolved definition: not closed and not abandoned. Include authorized, in-flight, pending, unknown and manual-review states with clear distinctions; never imply unknown means failed or free exposure.
- Ready-job rows follow the existing ready outbox definition with current due time. Label lag as current due-time lag, not total human waiting time. Paused scopes may legitimately retain work.
- Fixed row fields: action_id,workload_id,action_status,dispatch_state(nullable),queue_due_at(nullable),queue_lag_seconds(nullable),state_changed_at(nullable),lease_expired(nullable bool),hold_state(nullable),held_minor,can_reconcile. No payment/customer IDs, requests/metadata, provider namespace/key, evidence references, leases/fences, routes or errors.
- Validate any private snapshot used to derive fields using shared dispatch invariants, exact action/connection binding and consistent parent state. Invalid/corrupt data fails closed; never fabricate a confirmed provider outcome from action status alone. Unknown historical timestamps remain null.
- can_reconcile is advisory, independently derived from enabled reconciliation permission and current manual-review state; the mutation always rechecks. All rows apply current scoped searchable visibility. Active/unresolved/held exceptions remain as designed.

## Reconciliation preview and request

- Add GET /v1/actions/{id}/reconcile under the existing reconciliation grant, independent of operations/detail read. Return minimal ReconciliationState: action_id,connection_id,dispatch_state(nullable),can_request,reason_code. It allows a permitted operator to exercise the grant without needing unrelated read permissions.
- Authorize exact identity-derived scope, enabled identities/connection/grant and retain appropriate locks. GET never changes a queue, appends a mutation audit, calls a provider or releases exposure. Generic hidden-resource errors reveal no cross-scope existence.
- Keep existing POST /v1/actions/{id}/reconcile scheduling semantics: only a current eligible manual-review record, independent permission rechecked under locks, original action/provider key retained. It schedules evidence collection; it is not an unconditional refund retry.
- The confirmation captures the previewed action and connection, explains evidence collection and possible existing execution, and sends only on explicit confirmation. Backend state guards remain authoritative; stale state conflicts and refreshes preview.
- Unknown HTTP outcomes clear preview and require an explicit refresh, never automatic retry. Provider observations may later settle/release only under existing verified-outcome rules; requesting reconciliation itself does neither.

## UI and verification

- Extend Operations with bounded recovery rows, due lag/state/lease/held exposure, paging and links to independently authorized detail. A row may initiate a reconciliation preview, never write directly.
- A reusable reconciliation panel with explicit action ID remains accessible to reconciliation-only operators even without operations/detail read. Keep the existing independently authorized dispatch-control panel. Scope/session changes abort requests, suppress late data and clear captured confirmations.
- Private SQL helpers default-deny and expose only fixed projections; statements5s/application10s, no-store/nosniff, strict role-first validation and final identity checks. Safe enums/reasons/numeric bounds; no raw provider text.
- Actual runtime-role tests on isolated DB: scope/default deny and independent permissions, all dispatch states, abandoned/closed exclusion, due-job definition, bound pagination/cursors, retained/legacy ages, redaction/corrupt snapshot, revocation/locks, GET no mutation, manual-only request conflict, unchanged stable key and uncertain holds. Preserve dispatch/recovery/restore regressions.
- API role/session/CSRF/no-store validation; generated contract/build; browser rows/paging, preview/confirm/stale conflict/access loss and cancellation; then stable shared gate.
- Record ownership before edits. Full goal still includes provisioning/grant creation, measured credential health, assigned authority, retention/archive, load/security and production acceptance.
