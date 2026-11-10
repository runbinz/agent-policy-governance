# Environment administration foundation

Status: foundation implemented and locally verified. Full software-plan section12 connection/workload administration remains the objective; registration/grant creation, credential verification reporting and completed pause UI remain required subsequent work, not silently excluded deliverables.

## Authority and schema

- Forward migration0026. New environment_admin_grants(tenant_id,environment_id,reviewer_id,enabled) defaults deny through absence. Privileged bootstrap only; no implicit approval, policy, export or operations permission grants administration authority.
- Locked authorizer checks exact authenticated scope and enabled tenant/environment/reviewer/admin grant, retaining SHARE locks through each transaction. API receives only narrow function EXECUTE privileges; no direct identity/grant UPDATE or unrestricted SELECT.
- Add positive safe-JSON admin_revision default1 to connections, workloads, reviewers and the grant tables below. BEFORE UPDATE increments OLD+1, ignoring attempted caller revision injection; existing writers continue to work. No changes to frozen migrations, immutable provider routing or monetary records.
- Audit enable/disable/revocation with acting reviewer ID, exact scoped target, expected/new revisions and operation, atomically. New audit table is append-only to runtime roles; exclude secrets and arbitrary text.
- Self-disable of the acting reviewer and self-revocation of the acting environment-admin grant are rejected. Authorized changes retain authority locks, so concurrent administrator revocations cannot both commit after removing each other's authority. Test this ordering; do not assume it from compilation.

## Inventory contracts

- GET /v1/admin/entities?kind=connections|workloads|reviewers&after=<uuid>&limit=<1..100>, default50. Strict unknown/duplicate validation after reviewer authentication. Scope always derives from identity.
- AdminEntityPage: tenant_id,environment_id,kind,items,next_after (nullable UUID),tenant_paused,can_control_tenant. Entity items have kind discriminator and id,enabled,admin_revision.
- Connection adds paused,can_control,mode=local_fake|stripe_sandbox|external_configured,credential_health=unobserved,last_payment_verified_at nullable recorded timestamp. Never return provider namespace/account/key/secret reference. Mode derives from immutable configured route; no route means local_fake. A past payment verification is not current credential health.
- Workload adds paused,can_control. Reviewer contains only scoped UUID/enabled/revision; external subject mappings and registration are separate follow-up interfaces.
- Control flags come from existing independently enabled dispatch-control grants, not environment-admin authority. Tenant pause remains explicitly tenant-wide; workload/connection controls remain their existing scopes.
- GET /v1/admin/grants?kind=<GrantKind>&after=<bound-cursor>&limit=<1..100>. AdminGrantPage: kind,items,next_after. Row: connection_id/workload_id/reviewer_id (nullable as appropriate),enabled,admin_revision,permissions (closed enum array of configured true flags, effective only when enabled).
- GrantKind: workload,approval,reconciliation,policy_admin,evidence_export,operations,action_detail,tenant_dispatch,workload_dispatch,environment_admin. Use existing tables/flags. Cursor canonical and bound to authenticated tenant/environment/kind and complete ordered row key; limit before materializing JSON. No global page cap.
- Both reads use one consistent projected page, bounded128KiB/5s statements and10s application deadline, no-store/nosniff, final identity check after I/O. Hidden/unauthorized scopes use identical generic404; corrupt/unrepresentable stored projections safe500.

## Mutations

- POST /v1/admin/entities/{kind}/{id}/enabled with {expected_revision,enabled}. kind uses the same three entity kinds. Exact scoped row and revision checked; updates serialize with existing authorization locks. Returns {revision}. Missing/stale target yields generic conflict; no cross-scope existence disclosure.
- POST /v1/admin/grants/revoke with {kind,connection_id?,workload_id?,reviewer_id?,expected_revision}. Validate exact required/forbidden key fields per kind. Set enabled=false without deleting rows or erasing configured flags. Returns {revision}; stale/missing target conflicts.
- SQL targets are a closed server-owned mapping, never caller-supplied table/column names. Validate in Rust and SQL. Revisions are positive safe integers. Mutations recheck authority under locks and audit in the same transaction.
- Revocation/disable prevents newly authorized sends according to existing ordering; it neither cancels an already possible provider effect nor releases uncertain holds. No provider writes, new executions, credential disclosure, implicit control grants, or physical deletion.

## Console and follow-ups

- New Administration tab shows paged scoped entities/grants with enable state/revisions, mode, honest unobserved credential status and independently authorized control capabilities. Explicit confirmation names target and consequence before disable/revoke; conflict refreshes and discards captured confirmation. Ambiguous writes require refresh, no automatic retry.
- Abort stale session/scope/filter requests and clear data on access loss. Shared client generated from OpenAPI. Existing policy/approval/evidence operations stay independent.
- Follow-up required before declaring full administration complete: actor/identity provisioning and audited grant creation/change; worker-reported credential verification/freshness; connection/workload/tenant pause UI using existing control endpoints; operational recovery views and assigned-reviewer model.
- Tests: actual runtime-role isolated database, scope/disabled components, default deny and permission independence, all grant kinds/key validation, safe projections/cursors/limits, revision conflicts, self-protection/concurrent revocations, held-read versus revoke/disable ordering, audit immutability, no uncertain hold release, existing dispatch/restore regressions. API role/session/no-store validation, generated client/build and browser confirmation/conflict/cancellation checks, then full shared gate.

## Ownership

Before source edits assign bounded files in PROJECT_STATUS. Coordinator owns shared declarations/grants, API/OpenAPI/client and integration. Migration0026 is next free after frozen0025. No source ownership assigned by this design document.
