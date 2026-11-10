#!/usr/bin/env bash
# Scan the entire working tree, including untracked source. Reports are redacted.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
version=8.30.1
tool_dir="$root/.local/tools/gitleaks/$version"
report_dir="$root/.local/secret-scan"
mkdir -p "$tool_dir" "$report_dir"
chmod 700 "$report_dir"
umask 077

if [[ "${GITLEAKS_USE_DOCKER:-0}" == 1 ]]; then
  command -v docker >/dev/null || { echo 'Docker is required for GITLEAKS_USE_DOCKER=1' >&2; exit 2; }
  scanner=(docker run --rm --user "$(id -u):$(id -g)" -v "$root:/repo" -w /repo "ghcr.io/gitleaks/gitleaks:v$version")
else
  if [[ ! -x "$tool_dir/gitleaks" ]]; then
    case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) echo 'Unsupported OS; use Docker mode' >&2; exit 2 ;; esac
    case "$(uname -m)" in arm64|aarch64) arch=arm64 ;; x86_64|amd64) arch=x64 ;; *) echo 'Unsupported architecture; use Docker mode' >&2; exit 2 ;; esac
    asset="gitleaks_${version}_${os}_${arch}.tar.gz"
    release="https://github.com/gitleaks/gitleaks/releases/download/v$version"
    curl --fail --silent --show-error --location "$release/gitleaks_${version}_checksums.txt" -o "$tool_dir/checksums.txt"
    curl --fail --silent --show-error --location "$release/$asset" -o "$tool_dir/$asset"
    expected=$(awk -v asset="$asset" '$2 == asset {print $1}' "$tool_dir/checksums.txt")
    [[ ${#expected} == 64 ]] || { echo 'Missing release checksum' >&2; exit 2; }
    if command -v sha256sum >/dev/null; then
      actual=$(sha256sum "$tool_dir/$asset" | awk '{print $1}')
    else
      actual=$(shasum -a 256 "$tool_dir/$asset" | awk '{print $1}')
    fi
    [[ "$actual" == "$expected" ]] || { echo 'Gitleaks checksum mismatch' >&2; exit 2; }
    tar -xzf "$tool_dir/$asset" -C "$tool_dir" gitleaks
    chmod 700 "$tool_dir/gitleaks"
  fi
  [[ $("$tool_dir/gitleaks" version) == "$version" ]] || { echo 'Unexpected Gitleaks version' >&2; exit 2; }
  scanner=("$tool_dir/gitleaks")
fi
scan() {
  "${scanner[@]}" dir . --config .gitleaks.toml --redact=100 --no-banner --no-color \
    --ignore-gitleaks-allow --gitleaks-ignore-path .local/secret-scan/no-ignore-file \
    --report-format json --report-path ".local/secret-scan/$1.json" \
    >"$report_dir/$1.log" 2>&1
}
if [[ "${1:-}" == --self-test ]]; then
  # The synthetic token is assembled so this script itself contains no token.
  control=$(mktemp "$root/docs/secret-scan-control.XXXXXX")
  trap 'rm -f "$control"' EXIT
  token="ghp_$(printf 'AbCdEf0123456789%.0s' {1..2})AbCdEf01"
  printf 'github_token = "%s"\n' "$token" > "$control"
  result=0
  scan negative-control || result=$?
  rm -f "$control"
  trap - EXIT
  [[ $result == 1 ]] || { echo 'Negative control did not fail as expected' >&2; exit 2; }
  grep -q 'github-pat' "$report_dir/negative-control.json"
  grep -q 'REDACTED' "$report_dir/negative-control.json"
  if grep -Fq "$token" "$report_dir/negative-control.json" "$report_dir/negative-control.log"; then
    echo 'Negative control redaction failed' >&2; exit 2
  fi
  echo 'Negative control detected; report and log redaction verified.'
elif [[ $# != 0 ]]; then
  echo 'Usage: bash scripts/verify-secrets.sh [--self-test]' >&2; exit 2
fi
if scan working-tree; then
  echo "Gitleaks $version: working-tree scan passed. Redacted reports: .local/secret-scan/"
else
  result=$?
  echo "Gitleaks failed (exit $result). Inspect redacted .local/secret-scan/working-tree.json and .log" >&2
  exit "$result"
fi
