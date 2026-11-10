#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Run on a seeded, isolated development database, without another worker on that database.
: "${APL_DEMO_API_DATABASE_URL:?Set the demo API database URL}"
: "${APL_DEMO_WORKER_DATABASE_URL:?Set the demo worker database URL}"
export APL_LOCAL_DEV=true APL_AUTH_MODE=local
export APL_DEV_TOKEN_A=local-tenant-a-token-at-least-32-bytes
export APL_DEV_TOKEN_B=local-tenant-b-token-at-least-32-bytes
export APL_DEV_REVIEWER_TOKEN=local-reviewer-token-at-least-32-bytes
export APL_BIND_ADDR="127.0.0.1:${APL_DEMO_PORT:-18080}"
export APL_DEMO_BASE_URL="${APL_DEMO_BASE_URL:-http://$APL_BIND_ADDR}"

cargo build --locked -p apl-api -p apl-worker
logs=$(mktemp -d)
api_pid= worker_pid=
cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    cat "$logs/api.log" "$logs/worker.log" 2>/dev/null || true
  fi
  for pid in "$api_pid" "$worker_pid"; do
    if [[ -n $pid ]]; then
      kill -TERM "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT
DATABASE_URL="$APL_DEMO_API_DATABASE_URL" target/debug/apl-api >"$logs/api.log" 2>&1 &
api_pid=$!
DATABASE_URL="$APL_DEMO_WORKER_DATABASE_URL" target/debug/apl-worker >"$logs/worker.log" 2>&1 &
worker_pid=$!

for ((attempt=0; attempt<50; attempt++)); do
  kill -0 "$api_pid" "$worker_pid"
  if curl --fail --silent --max-time 1 "http://$APL_BIND_ADDR/health/ready" >/dev/null; then
    python3 scripts/demo.py
    exit
  fi
  sleep 0.2
done
echo 'Demo API did not become ready' >&2
exit 1
