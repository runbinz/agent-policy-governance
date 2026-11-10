#!/usr/bin/env bash
# Only for a quiescent, synthetic source and an empty disposable target.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${APL_RESTORE_SOURCE_URL:?Use a quiescent synthetic source database}"
: "${APL_RESTORE_TARGET_URL:?Use a separately created empty disposable database}"
if [[ "${APL_RESTORE_REHEARSAL:-}" != "1" ]]; then
  echo "Set APL_RESTORE_REHEARSAL=1 for isolated synthetic databases only." >&2
  exit 2
fi
source_psql() { psql -X -qAt -v ON_ERROR_STOP=1 "$APL_RESTORE_SOURCE_URL" "$@"; }
target_psql() { psql -X -qAt -v ON_ERROR_STOP=1 "$APL_RESTORE_TARGET_URL" "$@"; }
if [[ "$(target_psql -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")" != 0 ]]; then
  echo "Target must have an empty public schema; refusing restore." >&2
  exit 2
fi
snapshot=$(mktemp)
trap 'rm -f -- "$snapshot"' EXIT
signature=$(cat <<'SQL'
SELECT
 (SELECT count(*) FROM actions),
 (SELECT count(*) FROM audit_events),
 (SELECT count(*) FROM external_dispatches),
 (SELECT count(*) FROM external_attempts),
 (SELECT count(*) FROM budget_ledger_events),
 (SELECT coalesce(sum(amount_minor),0) FROM budget_reservations WHERE state='held'),
 (SELECT max(version) FROM _sqlx_migrations WHERE success)
SQL
)
before=$(source_psql -c "$signature")
pg_dump --format=custom --file="$snapshot" --dbname="$APL_RESTORE_SOURCE_URL"
pg_restore --single-transaction --exit-on-error --no-owner --no-privileges \
  --dbname="$APL_RESTORE_TARGET_URL" "$snapshot"
[[ "$(target_psql -c "$signature")" == "$before" ]] || { echo "Restore evidence or exposure totals differ" >&2; exit 1; }
auth_audits=$(source_psql -c 'SELECT count(*) FROM browser_session_audit')
auth_unrevoked=$(source_psql -c 'SELECT count(*) FROM browser_sessions WHERE revoked_at IS NULL')
[[ "$(target_psql -c 'SELECT count(*) FROM browser_session_audit')" == "$auth_audits" ]]
# No processes or egress may be connected to the target. Set the durable pause
# before granting runtime access. This affects only the isolated target.
target_psql -c 'UPDATE tenants SET paused=true WHERE NOT paused'
target_psql <<'SQL'
BEGIN;
DELETE FROM browser_login_flows;
UPDATE notification_routes SET enabled=false WHERE enabled;
WITH revoked AS (
 UPDATE browser_sessions SET revoked_at=clock_timestamp() WHERE revoked_at IS NULL
 RETURNING tenant_id,environment_id,reviewer_id,id
)
INSERT INTO browser_session_audit(tenant_id,environment_id,reviewer_id,session_id,event_type)
 SELECT tenant_id,environment_id,reviewer_id,id,'session.revoked' FROM revoked;
COMMIT;
SQL
target_psql -f migrations/runtime-roles.sql >/dev/null
[[ "$(target_psql -c 'SELECT count(*) FROM tenants WHERE NOT paused')" == 0 ]]
[[ "$(target_psql -c 'SELECT count(*) FROM browser_sessions WHERE revoked_at IS NULL')" == 0 ]]
[[ "$(target_psql -c 'SELECT count(*) FROM browser_login_flows')" == 0 ]]
[[ "$(target_psql -c 'SELECT count(*) FROM notification_routes WHERE enabled')" == 0 ]]
[[ "$(target_psql -c 'SELECT count(*) FROM browser_session_audit')" == "$((auth_audits + auth_unrevoked))" ]]
[[ "$(target_psql -c "SELECT has_table_privilege('apl_api','external_dispatches','SELECT')")" == f ]]
echo "PASS: restored action, audit, dispatch, attempt, ledger and held exposure totals; all restored tenants paused; browser sessions/login flows invalidated; notification routes disabled."
