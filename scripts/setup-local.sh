#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose up -d --wait
APL_LOCAL_DEV=true DATABASE_URL=postgres://apl_admin:local_admin_only@127.0.0.1:55432/apl_dev cargo run -p apl-api -- --migrate
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U apl_admin -d apl_dev < migrations/runtime-roles.sql
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U apl_admin -d apl_dev < scripts/local-logins.sql
docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U apl_admin -d apl_dev < scripts/seed-local.sql
