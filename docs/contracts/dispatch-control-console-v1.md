# Dispatch control console and revision checks

Status: implemented and locally verified, migration0027 frozen. See current status/history for evidence. Real-account/production acceptance remains open.

## Authority and reads

- Controls require existing connection_admin_grants.control_dispatch, workload_dispatch_grants or tenant_dispatch_grants, according to scope. Environment administration, policy, approval and operations-read permissions confer no implicit control authority.
- GET /v1/controls/state?kind=tenant|connection|workload&id=<uuid>. id required for connection/workload and forbidden for tenant; tenant identity derives from authentication. Strict unknown/duplicate validation, reviewer-only, no-store/nosniff, bounded statement/application deadlines and final identity check.
- ControlState: kind,target_id,tenant_id,environment_id,enabled,paused,revision. Read only the authorized target. Tenant-wide control remains explicitly across all environments of the authenticated tenant. No listing of unauthorized targets.
- Implement a shared private locked authorizer for control reads and writes, using the existing control grant and scope lock semantics. GET may lock rows but never changes state, records a mutation audit, schedules work or calls a provider.

## Revision protocol

- Connections/workloads reuse admin_revision from0026, which also invalidates confirmation after enable/disable changes. Add a positive safe integer control_revision to tenants, with guarded increments on actual updates; preserve existing defaults and identity auditing.
- Existing public POST /v1/controls/pause and /resume now require expected_revision in each strictly validated connection/workload/tenant body shape. This is an intentional prelaunch contract evolution: update OpenAPI/client/tests/docs together. Missing or unrepresentable expectations fail safely; no public unversioned bypass.
- Under existing operator authority and target locks, compare current revision before changing paused state. Stale expectation conflicts and rolls back all effects/audits. No-op against the exact current revision is safe and need not increment or append a fictitious change.
- New Store/versioned SQL helpers may call existing trusted internal setters while retaining locks; existing internal Store methods can remain for regression/administrative use. Public HTTP handlers must always use the versioned path.
- Return the authoritative ControlState after an acknowledged change. Retain existing audit events/actor information atomically. Never release uncertain holds, cancel possible provider effects, reset provider keys or grant new privileges.

## Console

- A reusable DispatchControlPanel works without environment-admin or operations-read permission. Place it in Operations, with a scope picker and explicit target UUID for connection/workload. It first loads authorized state, then captures kind/id/scope/revision/paused for a confirmation.
- Also make it reachable from authorized connection/workload rows in Administration without coupling the two permissions. Pass an explicit target; loading a target never performs a write.
- Confirm target and tenant-wide consequences. Pause/resume is not cancellation or proof of non-execution. Stale confirmation refreshes and discards the captured action. Unknown write outcome clears state and requires refresh, never auto-retry.
- Abort stale session/target/unmount requests, clear scoped data on access loss, preserve keyboard confirmation/cancellation. No provider credentials or external requests are part of this slice.

## Required evidence

- Runtime-role isolated DB: independent grants/default deny/cross-scope, disabled/revoked identities, exact/no-op/stale revisions for all3 scopes, concurrent pause/resume, permission/target lock ordering, audit integrity, GET has no state change, uncertain exposure unchanged. Existing dispatch/restore regressions stay passing.
- API tests include role-first validation, required expected_revision, no public unversioned mutation, generic errors/no-store and browser CSRF/session paths. Generated contract/build and real local browser pause/resume/stale conflict/access-loss checks, then stable shared gate.
- Record ownership before edits. Coordinator owns shared configuration/OpenAPI/integration; no frozen migration edits. Full goal still includes provisioning/grant creation, measured credential health, operations recovery lists/reconciliation UI and assigned-reviewer work.
