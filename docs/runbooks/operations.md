# Refund gateway operations

These procedures assume the operator has a registered human identity and the appropriate grants. Production network access, metrics/alerts, and backup retention must be configured and verified before a live rollout. Never attach secrets, full provider payloads, customer data, or access tokens to incident records.

## Emergency stop and controlled resume

1. First read `GET /v1/controls/state?kind=connection&id=<uuid>` (or workload; tenant omits id). Use the returned revision in `POST /v1/controls/pause` with exactly one target: `{"connection_id":"…","expected_revision":1}`, `{"workload_id":"…","expected_revision":1}`, or `{"tenant":true,"expected_revision":1}`. Replace example1 with the actual revision. Stale revisions conflict and require a fresh read; public writes without a revision are rejected. The tenant comes from the operator identity. Each scope requires its own grant; an approval grant is insufficient.
2. Verify HTTP 200 and the returned paused state and revision. A state change appends an attributed control audit row; an exact no-op preserves revision and creates no new mutation audit. A pause blocks new dispatch while effective. A network write already sent, or one crossing the final local preflight boundary, may still complete. Keep reconciliation available for existing attempts.
3. Before resume, inspect pending approvals, open provider attempts, and budget holds. Resolve the incident and verify provider state for ambiguous results. Read current authorized state and confirm its exact revision before `POST /v1/controls/resume`; on an unknown HTTP outcome, refresh state rather than automatically retry. Resume only the intended scope; other active pauses still block dispatch.

## Credential exposure or suspected cross-tenant access

Pause the affected scope and disable exposed workload/administrator grants. Revoke and rotate the relevant identity-provider key or Stripe credential using the provider's own controls; application pause is not credential revocation. Preserve action IDs, affected scopes, time bounds, and redacted audit rows in a restricted incident record. Compare provider-side attempts with local send markers and ledger holds. For suspected isolation failure, stop ingress and isolate the affected environment until the scope and permissions are verified. Do not resume on the strength of a single successful request.

## Provider outage and growing unknown queue

Pause new dispatch if failure rates rise or remote state cannot be verified. Distinguish blocked or unsent requests from requests with a send marker. Monitor pending, unknown, and manual-review dispatches with their oldest ages and held amounts; pending and unknown are exposure, not failures. Leave the bounded reconciliation worker enabled if the provider permits reads. A signed webhook can wake a matching lookup but cannot settle a refund.

Use Operations recovery rows for unresolved dispatches or currently due jobs. Paging uses scope-bound cursors; current due-time lag does not measure total human waiting time. Operations read permission does not imply reconciliation or action-detail access.

Once a dispatch enters manual review, an operator with its connection's reconciliation grant can preview `GET /v1/actions/{id}/reconcile` and explicitly confirm `POST /v1/actions/{id}/reconcile`. This requests a provider read, not a new refund. A conflict requires a fresh preview; an unknown HTTP outcome requires explicit refresh rather than automatic retry. If the result remains inconclusive, retain the hold, record the incident, and seek provider evidence. A timeout, expired lease, missing search result, or successful local restore is not proof of non-execution.

## Ledger mismatch

Pause the affected connection. Compare the immutable action, authorization, send attempts, verified terminal evidence, budget reservation, and ledger events. A held reservation must not be edited away to free capacity. If evidence and accounting disagree, preserve the database rows and escalate for a reviewed correction or recovery procedure. Verify both provider and database state before resuming.

## Backup restore

1. Restore into an isolated environment with no provider egress, API ingress, or running workers. Keep the original backup and source intact.
2. Verify the restored migration versions, least-privilege runtime grants, and integrity of action, approval, dispatch, and ledger records. Pause all restored tenants before connecting any worker. Disable restored notification routes, clear restored browser login transactions and revoke restored browser sessions with audit records before reopening API ingress; a backup can otherwise revive a previously revoked application session. Reapply secret references through the deployment process, never from a dump.
3. Reconcile the provider's refund history against the restore point, especially operations whose local dispatch record may have been lost. A restored database can omit a completed refund even if all local constraints hold. Maintain the pause until the recovered evidence and budget exposure are reviewed.
4. Record observed restore point and elapsed recovery time. The plan's targets are provisional until measured against the deployed backup system. Reconcile restored memberships/grants against current identity administration and independent revocation evidence before opening API ingress; restored grants alone do not prove current authority. Open ingress and resume narrowly only after reconciliation and approval of the recovery evidence.

For the local rehearsal, create an empty disposable target and run:

```sh
APL_RESTORE_REHEARSAL=1 \
  APL_RESTORE_SOURCE_URL='quiescent-synthetic-database-url' \
  APL_RESTORE_TARGET_URL='empty-isolated-target-database-url' \
  bash scripts/verify-restore.sh
```

Use a compatible `pg_dump` and `pg_restore`. The rehearsal compares action, audit, dispatch, attempt and ledger counts, held exposure, and migration version. It pauses every restored tenant, invalidates browser sessions and login flows, disables notification routes, verifies the revocation audit count, and reapplies restricted runtime grants. It does not perform a provider reconciliation or qualify a production backup policy.

## Rollback

Pause affected dispatch before rolling back workers or API. Confirm the older binary supports the applied schema and existing dispatch snapshots. Do not downgrade a migration that stores newer attempts or holds. Prefer a forward corrective migration when compatibility is uncertain. Recheck worker readiness and provider outcomes before controlled resume. Use the shared verification gate and a staged environment before a live rollback rehearsal.

## Browser session or flow-key exposure

Restrict ingress and pause affected execution scopes as needed. Disable the affected reviewer/membership for immediate per-request denial; role removal is independent of identity-provider cookies. Revoke affected application sessions through controlled database administration, preserving one `session.revoked` audit event for each newly revoked session. Clear pending login transactions if the shared flow key is exposed. Rotate `APL_BROWSER_FLOW_KEY` on every API replica together and restart/drain old replicas before reopening login; mixed keys make sessions inconsistent. Provision the new secret through the secret manager and verify login, logout, revocation and role isolation in staging. Do not put cookie values, hashes, client secrets or CSRF tokens in incident notes. Application logout does not terminate the provider's SSO session.

## Notification delivery failure or wrong recipient

Keep the authenticated approval queue available. Do not approve, cancel, extend expiry or release reservations merely to fix a notification. For a recipient incident, disable the affected notification route and revoke/rotate its bot credential if exposed. Pending unassigned jobs may use a replacement route; already assigned jobs remain fixed and disabled-route cleanup skips their queued/expired work. A post that crossed preflight can still complete or duplicate after a suspended worker resumes; database fencing cannot recall a Slack message. Preserve job/action IDs and redacted event names, not tokens or message bodies.

Inspect notification status/attempt counts and the configured workspace/channel through controlled administration. Rate limits and temporary failures retry at most eight claims with cooldown; permanent/exhausted failures leave review in the web queue. Verify access, provider health and approval currentness before creating any new notification attempt through a reviewed procedure. Restores leave all notification routes disabled; verify recipient membership, credential workspace and console origin before enabling routes and starting notification workers. Runtime worker roles cannot edit destinations or audit rows directly.
