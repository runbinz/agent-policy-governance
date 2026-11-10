#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../observability"
if [[ -n "${PROMTOOL:-}" ]]; then
  "$PROMTOOL" check rules alerts.yml
  "$PROMTOOL" test rules alerts.test.yml
elif command -v promtool >/dev/null 2>&1; then
  promtool check rules alerts.yml
  promtool test rules alerts.test.yml
else
  for operation in check test; do
    file=alerts.yml
    [[ "$operation" != test ]] || file=alerts.test.yml
    docker run --rm --entrypoint /bin/promtool -v "$PWD:/rules:ro" -w /rules \
      prom/prometheus:v3.5.0 "$operation" rules "$file"
  done
fi
