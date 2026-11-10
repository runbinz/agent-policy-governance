# Secret scanning

Run from the checkout:

```sh
bash scripts/verify-secrets.sh
# Also verify detection, failure status, redaction and cleanup:
bash scripts/verify-secrets.sh --self-test
```

The gate uses [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), extending its bundled default rules. It scans the current working tree, including untracked files. This matters while the initial repository contents remain untracked. The gate does not scan Git history. Run a separate history review before importing existing history or releasing a repository that has contained secrets.

The script downloads the matching official macOS/Linux arm64/x64 release archive into `.local/tools/gitleaks/8.30.1/`, verifies SHA256 against the release's official checksum manifest, and extracts only the executable. It does not install a system binary. HTTPS and the publisher's release/checksum assets are the installation trust boundary; the manifest is not an independent signature. A cached executable must report the exact pinned version. Delete its version directory to reinstall and repeat archive verification.

CI needs outbound HTTPS to GitHub release assets, Bash, curl, tar and either sha256sum or shasum. Run the self-test command as a required CI step after checkout. An optional Docker engine path uses the version-pinned official image:

```sh
GITLEAKS_USE_DOCKER=1 bash scripts/verify-secrets.sh --self-test
```

This uses `ghcr.io/gitleaks/gitleaks:v8.30.1` with the checkout mounted at `/repo`; the Docker fallback has not been executed locally. Its release tag is version-pinned, not digest-pinned. Use an organization-approved immutable digest if required by deployment policy. Updating Gitleaks requires changing the script's version and reviewing configuration exceptions against the new default rules.

Reports and scanner logs are written only to ignored `.local/secret-scan/`, with full scanner redaction enabled and restrictive report-directory permissions. Findings cause exit 1; setup failures and negative-control failures also stop the gate. The script prints only a compact outcome and report locations. Review redacted findings locally; do not upload raw source or credentials to diagnostics systems.

`.gitleaks.toml` excludes generated `.local`, `.git`, `target`, `node_modules`, `__pycache__`, and console `dist` output. Actual source, plans, tests and other working files remain included, including `.env` if present. There is no baseline. The gate disables inline `gitleaks:allow` comments and supplies an absent ignore-file location rather than accepting repository `.gitleaksignore` suppression. No file-size cap is configured. Standard Gitleaks detector behavior still applies; nested archives are not traversed and symlinks are not followed.

Two rule-specific exceptions require both an exact path and a constrained match:

- The public RSA private-key fixture at `crates/identity/tests/fixtures/test-only-private.pem`, used by the JWT tests and documented in the adjacent README. Its exception requires the existing key prefix and PEM structure. It is test material and must never become an operational key. Other secrets in that file remain subject to all other rules.
- The exact status phrase about credential expiry and revocation in `docs/IMPLEMENTATION.md`, which the generic API-key detector interprets as a credential assignment. Other matches in that document remain scanned.

The self-test creates a temporary synthetic recognizable GitHub token under the scanned `docs/` directory, requires scanner exit 1 and a GitHub PAT finding, checks that both the JSON report and scanner log omit the token, removes the temporary file, then requires the clean working-tree scan to pass. The synthetic token is not submitted to GitHub or any provider.

Local verification on November 9, 2026: `bash -n scripts/verify-secrets.sh` and `bash scripts/verify-secrets.sh --self-test` passed using the checksum-verified macOS arm64 release. The final working-tree report contained no findings. Remote CI and the Docker fallback were not executed.

This detector gate does not validate credentials against external services, prove the absence of secrets, or establish application execution safety. Provider credential acceptance and sensitive-field runtime reviews remain separate verification work.
