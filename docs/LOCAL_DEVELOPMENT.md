# Local development

Prerequisites: Rust (pinned toolchain is installed automatically by rustup), Docker Compose, and Python 3 for the HTTP demo.
Run all commands from the Data Governance folder. PostgreSQL listens on loopback port 55432, and data lives in ignored `.local/postgres`.

## Setup

```sh
bash scripts/setup-local.sh
```

This starts PostgreSQL 17, applies migrations as the administrator, and creates separate non-superuser API/worker logins. Passwords below are public local fixtures. Never use them for a deployment. Do not run the application using the administrator URL.

## Run API

```sh
export APL_LOCAL_DEV=true
export APL_AUTH_MODE=local
export APL_DEV_TOKEN_A=local-tenant-a-token-at-least-32-bytes
export APL_DEV_TOKEN_B=local-tenant-b-token-at-least-32-bytes
export APL_DEV_REVIEWER_TOKEN=local-reviewer-token-at-least-32-bytes
export DATABASE_URL=postgres://apl_api_login:local_api_only@127.0.0.1:55432/apl_dev
cargo run -p apl-api
```

## Run worker in another terminal

```sh
APL_LOCAL_DEV=true DATABASE_URL=postgres://apl_worker_login:local_worker_only@127.0.0.1:55432/apl_dev cargo run -p apl-worker
```

The API binds to 127.0.0.1:8080. In local mode only explicit fixture tokens are accepted. They resolve through seeded database identity mappings; tenant, environment, workload, and connection grants are checked in PostgreSQL on each operation and again during dispatch. Running setup again does not reenable revoked fixture records.

## JWT workload mode

Provide an operator-approved public JWKS file from your issuer, and register its exact issuer/subject in `identity_registry` with administrator credentials. The registration references an existing workload grant. Do not use the committed test signing key for a deployment.

```sh
export APL_AUTH_MODE=jwt
export APL_JWT_ISSUER=https://your-workload-issuer.example
export APL_JWT_AUDIENCE=your-agent-policy-api
export APL_JWKS_FILE=/absolute/path/to/public-jwks.json
export DATABASE_URL=postgres://apl_api_login:local_api_only@127.0.0.1:55432/apl_dev
cargo run -p apl-api
```

JWT mode accepts RS256 signatures with registered key IDs, exact issuer/audience, unexpired tokens, and valid optional not-before claims. Unknown identities fail authentication; tenant claims do not establish authority. The public key file is read at startup, so key rotation requires updating it and restarting the API. Token-supplied key URLs are ignored. Network JWKS discovery/refresh and managed-provider onboarding are not implemented. Both API modes remain loopback-bound. To accept reviewer JWTs, configure a distinct `APL_REVIEWER_JWT_AUDIENCE` and register reviewer identities and connection grants separately. Tokens accepted by both verifiers are rejected. Browser login through a managed identity provider and production deployment are later work.

Workloads, tenants, environments, connections, and grants can be disabled by a database administrator. Runtime roles cannot edit them. Permission flags separately control submission, status reads, and event reads. Revocation blocks new operations and queued fake execution; an already committed effect cannot be recalled. Identity configuration changes are recorded in `identity_audit`.

## Demonstration

With the API and worker running:

```sh
python3 scripts/demo.py
```

The demo checks authentication, submission, duplicate replay, changed-body conflict, connection authorization, cross-tenant access, durable success and audit history, and exact-action approval with replay protection. It never calls a payment provider.

To review refunds in the browser, run `npm ci` then `npm run dev` from `apps/console`. Open [the local reviewer console](http://127.0.0.1:5173) and enter the configured local reviewer token. The token clears on reload. The default seeded policy requires approval above 5,000 cents and hard-denies amounts above 50,000 cents; a missing policy denies execution.

For managed signing keys, keep JWT mode and set `APL_MANAGED_JWKS=true` instead of `APL_JWKS_FILE`. The API loads discovery from the configured HTTPS issuer, checks the returned issuer for exact equality, and fetches its same-origin JWKS. If keys are hosted on another origin, explicitly pin the exact HTTPS URL with `APL_MANAGED_JWKS_URL`. Startup requires a valid initial fetch. Refresh runs every minute; a failed refresh preserves the last good set for at most ten minutes, after which managed verification and readiness fail closed. JWT input does not trigger network fetches. This supports workload and reviewer bearer verification; browser login remains separate.

## Policy administration and dispatch controls

`scripts/publish-policy.sql` publishes an immutable policy as a database administrator. Pass `tenant_id`, `environment_id`, `connection_id`, `version`, `expected_version`, `auto_limit_minor`, `hard_limit_minor`, and `approval_ttl_seconds` as `psql -v` arguments with `-v ON_ERROR_STOP=1`. An expected version of `0` requires an unbound connection. A stale expected version rolls back the new version as well as the binding change. For routine API administration, use a registered reviewer identity with a separate `connection_admin_grants` row. Grant `edit_policy`, `publish_policy`, and `control_dispatch` independently. `POST /v1/policies/drafts` creates immutable versions; `POST /v1/policies/{version}/simulate` compares the draft and active policy on up to 25 synthetic refund requests without submission or reservation; `POST /v1/policies/{version}/publish` uses an expected active version. Read `GET /v1/controls/state?kind=connection&id=<uuid>` (or workload; tenant omits id), then use `POST /v1/controls/pause` or `/resume` with the returned `expected_revision` and exactly one target: `{"connection_id":"…","expected_revision":1}`, `{"workload_id":"…","expected_revision":1}`, or `{"tenant":true,"expected_revision":1}`. Replace the example revision with the current read value; stale revisions return409. Successful writes return authoritative JSON control state, including exact no-ops. The console provides the same read/confirmation flow. Tenant-wide and workload stops require explicit `tenant_dispatch_grants` or `workload_dispatch_grants`; connection grants do not imply broader authority. Other active scopes still block dispatch after a single scope is resumed. Connection changes record the authenticated operator in `connection_admin_audit`; tenant/workload controls use `dispatch_scope_audit`. Approval grants do not grant any of these capabilities.

The workload can cancel its own queued actions at `POST /v1/actions/{id}/cancel` when it has the separate `cancel_action` grant. Already terminal actions return `409`. New local fixtures have this grant; upgrades intentionally leave existing grants unchanged. Database administrators can call `set_connection_paused(tenant_id, environment_id, connection_id, true)` to park execution and pass `false` to resume. Pauses are audited, and workers recheck them before a fake effect. No application runtime role can invoke the pause function.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

For the same verification gate as CI, set `TEST_DATABASE_URL` to a disposable database and run `bash scripts/verify.sh`. The script also runs the database integration tests serially. CI separately type-checks and builds the console.

The PostgreSQL integration test is explicitly ignored by the default suite. Run it against a dedicated test database as the local administrator:

```sh
docker compose exec -T postgres psql -U apl_admin -d postgres -c 'CREATE DATABASE apl_test'
TEST_DATABASE_URL=postgres://apl_admin:local_admin_only@127.0.0.1:55432/apl_test cargo test -p apl-persistence --test postgres -- --ignored
TEST_DATABASE_URL=postgres://apl_admin:local_admin_only@127.0.0.1:55432/apl_test cargo test -p apl-api --test jwt_postgres -- --ignored
```

Create `apl_test` once. The test applies migrations, then uses actual nonowner runtime roles for application queries. Random IDs allow repeated execution. Tests use admin access solely for setup and verification.

## Scope

The default worker atomically simulates provider effects and budget settlement in PostgreSQL. Each connection must have a budget; the local fixtures seed daily and outstanding caps of 1,000,000 cents. Missing or exhausted caps deny execution. Optional sandbox execution and MCP are described below. Managed-provider onboarding remains open; managed browser session configuration is described below. Malformed requests fail before admission.

## Stripe sandbox worker

The default worker uses the database simulation. A separate, opt-in worker can use Stripe sandbox; do not reuse a live Stripe account key or a connection with test and live traffic mixed. Provision a dedicated connection with workload grants, an active policy, and a budget. As an administrator, bind its tenant/environment/connection to `stripe-test:<acct_id>` in `provider_routes`. The binding and account namespace are immutable and unique; provision a new connection for a different account. The fake worker skips bound connections.

Set `APL_WORKER_MODE=stripe-sandbox`, `APL_LOCAL_DEV=true`, `APL_STRIPE_CONNECTION_ID`, and `APL_STRIPE_ACCOUNT_ID`. Supply `APL_STRIPE_SANDBOX_KEY` from your local secret environment and `DATABASE_URL` for the worker role. Run `cargo run --locked -p apl-worker`; `--once` drives one queue operation. Startup verifies the account using the test credential. A successful sandbox run needs an actual captured USD card Charge in that account and a refund intent using its `ch_` ID. Only that narrow refund path is supported.

The adapter has passed loopback mock tests. No real Stripe sandbox account has been connected or tested. For a direct sandbox webhook, configure the API with the matching `APL_STRIPE_ACCOUNT_ID` and `APL_STRIPE_WEBHOOK_SECRET`. The endpoint is `POST /v1/webhooks/stripe-sandbox`. Signed, matching deliveries wake reconciliation; provider reads establish terminal outcomes. After automatic reconciliation reaches manual review, an operator with a separate `reconciliation_grants` row can call `POST /v1/actions/{id}/reconcile` using their reviewer credential. This queues a provider read and leaves the hold in place until terminal evidence is verified.

Stop services with `docker compose stop`. Do not delete `.local/postgres` unless intentionally discarding local database data.

## MCP Streamable HTTP

Enable managed JWT verification and set `APL_MCP_RESOURCE_URL` to the public, canonical HTTPS URL ending in `/mcp`. Keep the upstream API bound to loopback and configure the HTTPS reverse proxy to preserve the public Host (or HTTP/2 authority). Configure allowed browser origins as a comma-separated `APL_MCP_ALLOWED_ORIGINS` value; requests without an Origin can use the machine-to-machine transport. The endpoint is disabled by default and cannot use fixture or static-key startup mode.

Configure the authorization server to issue tokens with the **sole** audience equal to the MCP resource URL and scope `apl:refunds`. The resource metadata endpoint is `/.well-known/oauth-protected-resource/mcp`. Register the issuer/subject as a workload and grant the required connection permissions as for REST. A valid token without the MCP scope is rejected even if the workload is registered.

The endpoint implements stateless MCP revision `2025-11-25`. Send JSON POST requests with `Accept: application/json, text/event-stream` and supply `MCP-Protocol-Version: 2025-11-25` after initialization. The tools are `submit_refund` (client-supplied idempotency key and refund request), `get_action`, and `cancel_action` (action ID). No reviewer or administrative tools are exposed. REST and MCP submissions share the same workload idempotency records. No OAuth client has been registered against a real issuer for deployment acceptance.

## Evidence exports

Configure the API and worker with the same `APL_EVIDENCE_BACKEND`, `APL_EVIDENCE_KEY_ID`, and `APL_EVIDENCE_KEY` (standard base64 encoding of a randomly generated 32-byte secret). Local mode requires `APL_EVIDENCE_BACKEND=local`, `APL_LOCAL_DEV=true`, and an existing absolute `APL_EVIDENCE_LOCAL_DIR`. Deployment mode uses `APL_EVIDENCE_BACKEND=s3`, `APL_EVIDENCE_BUCKET`, `APL_EVIDENCE_REGION`, and AWS credentials. Keep encryption keys in secret configuration. Unconfigured storage leaves export endpoints disabled.

Provision a separate enabled `evidence_export_grants` row for the reviewer and connection. `POST /v1/exports` accepts `{ "connection_id": "<uuid>", "action_ids": ["<uuid>"] }` and returns 202. Poll `GET /v1/exports/{id}`; download ready JSON from `GET /v1/exports/{id}/download`. Run the worker to build queued exports. Only the requesting reviewer can retrieve the export, and revocation takes effect on subsequent downloads. The console Evidence tab supports requesting exports, tracking an export ID, and authenticated JSON downloads. Token clearing aborts pending work.

Exports expire after one hour and are capped at 1,000 actions, 20,000 total action/history rows, and 20 MiB; a conservative preflight can reject a selection below the exact byte limit. Storage failure retries are bounded; clients should inspect status rather than assume readiness. Expiry immediately denies downloads. With storage configured, the worker starts ciphertext cleanup after a five-minute grace period and the writer lease has elapsed. It deletes at most 1,000 objects per batch, retries partial/failed batches, and re-sweeps hourly to catch delayed writers. Configure and verify S3 lifecycle rules and separate versioned-object/backup retention before deployment. For key rotation, supply the old immutable key IDs and base64 keys through `APL_EVIDENCE_READ_KEYS` (JSON object, at most 15 entries and 4096 bytes) on both API and worker. Preserve retired keys until dependent artifacts and backups expire. No real S3 bucket has been exercised.

## Evidence search

`GET /v1/evidence?connection_id=<uuid>` returns redacted action summaries to a reviewer with the same explicit connection evidence grant. Optional filters are `status`, `workload_id`, `action_id`, `min_amount_minor`, and `max_amount_minor` (0–50,000). Use `limit` (1–100, default 50) and exclusive `after` UUID cursors for pagination; `next_after: null` means exhausted. Ordering is by UUID, not creation time. Search is available when reviewer authentication is configured even if artifact storage is disabled.

The console Evidence tab supports filters, bounded pages and selection across pages, then copies selected IDs and their connection into the export form for review. Changing filters clears search results and selection. No payment references, request metadata or provider credentials are searched or returned. Search is a current-state view; the later export is a separate authorized snapshot. See ADR 0008 for consistency and redaction semantics.

## Managed browser login

Managed browser login requires `APL_AUTH_MODE=jwt`, `APL_MANAGED_JWKS=true`, a trusted `APL_JWT_ISSUER`, and a workload audience as above. Set `APL_BROWSER_ORIGIN` to the exact public HTTPS origin without a trailing slash, `APL_BROWSER_CLIENT_ID` to a dedicated OIDC client ID, and `APL_BROWSER_FLOW_KEY` to standard base64 encoding of a random 32-byte secret from your secret manager. Keep that key identical across API replicas. The browser client ID must differ from workload, reviewer bearer and MCP audiences. Optional `APL_BROWSER_CLIENT_SECRET` selects `client_secret_post`; without it the registration must allow public PKCE (`none`). Never give browser login secrets to workers or frontend build settings.

Register the exact redirect `<APL_BROWSER_ORIGIN>/auth/callback`, authorization code flow, S256 PKCE and RS256 ID tokens. Discovery must advertise the selected client authentication method and those protocol capabilities. Authorization and token endpoints must share the configured issuer origin. Map the verified issuer/subject into `reviewer_registry` and provision explicit role/connection grants; login does not enroll users or assign roles. `APL_REVIEWER_JWT_AUDIENCE` is optional when browser login supplies the human identity. It remains available for separately authorized bearer API clients.

Serve the console and API under this one HTTPS origin. The reverse proxy must preserve the canonical public Host when forwarding `/auth/` and `/v1/` to the loopback API and preserve Set-Cookie/redirect headers; ignore untrusted forwarded-host values. Keep the upstream API private. Browser login has no HTTP development bypass. The console discovers `/auth/config`, performs POST navigation to `/auth/login`, and keeps only the CSRF value/expiry in memory; Secure HttpOnly session cookies are managed by the browser. GET `/auth/session` bootstraps CSRF. Cookie-authenticated mutations require the exact configured Origin and `X-CSRF-Token`; mixed cookie/bearer credentials are rejected.

Sessions expire after one hour and logout revokes shared state. Already-authorized requests may finish; logout does not recall approvals or provider calls. It ends the application session, not the provider's SSO session. Coordinate flow-key rotation across all replicas and invalidate existing sessions/login flows before reopening ingress. Disabled reviewers or removed identity mappings are denied on the next request; identity-provider deprovisioning must also update local membership or wait for session expiry. A real issuer registration, actual HTTPS cookie behavior and deployment are still staging acceptance items.

For presentation-only console checks, stop the API and run `python3 scripts/console-auth-fixture.py --mode managed-in` on loopback 8080, then start Vite on 5173. The fixture shows a synthetic session, checks the console's CSRF-bearing logout and returns to the managed sign-in screen. It does not test OIDC, secure cookies, grants, or authentication. Modes `managed-out` and `development` support the other screens. No money operations or provider calls are implemented in this fixture.

## Approval notifications

Notification delivery is disabled unless explicitly configured. As a privileged administrator, create a `notification_routes` row with a new route UUID and an existing tenant/environment/connection. Use `kind='fake'` with null team/channel for local verification, or `kind='slack'` with a reviewed Slack team ID (`T…`) and channel ID (`C…` or `G…`). IDs must be 9–64 uppercase alphanumeric characters. Only one route per connection can be enabled; recipient fields are immutable. To replace a recipient, disable the old route and insert a new one. Never take a destination from action metadata or an agent request.

For a network-free local worker, set `APL_LOCAL_DEV=true`, `APL_NOTIFICATION_MODE=fake`, `APL_NOTIFICATION_ROUTE_ID=<route-uuid>`, `APL_CONSOLE_ORIGIN=http://127.0.0.1:5173`, and the worker-role `DATABASE_URL`. Run `cargo run --locked -p apl-worker -- --queue notifications`; `--once` performs one queue iteration. The fake sink records `notification_receipts`, while the approval stays pending. It does not approve or execute the refund.

The opt-in Slack adapter uses `APL_NOTIFICATION_MODE=slack`, the same explicit route UUID, a canonical HTTPS `APL_CONSOLE_ORIGIN`, `APL_SLACK_TEAM_ID`, and a bot credential in `APL_SLACK_BOT_TOKEN`. Provision a bot with `chat:write` in the intended channel and verify that channel's audience; broader public-channel/custom-identity scopes are unnecessary. The worker verifies the token's workspace before posting to the database route's channel. Credentials stay out of the database, messages and logs. Current worker startup still requires the development opt-in; enabling the adapter is not evidence of production readiness. Initial real acceptance needs a dedicated test workspace, reviewed channel and explicit operator configuration. No live Slack call has been made during implementation.

One job is queued transactionally for each approval generation. Claims use 60-second fenced leases and at most eight attempts, including crashed claims. Posts are preceded by current approval/policy/scope checks. Jobs assigned on their first claim remain bound to that route; disabling a route skips its queued/expired work through bounded cleanup. In-flight authorized deliveries can still finish. Unassigned jobs can use a replacement route. Transient errors retry with bounded backoff and shared per-channel cooldown honoring Retry-After; permanent or exhausted errors stop only the notice. The web queue remains usable. Delivery can duplicate or arrive stale after a timeout/suspended worker and never grants authority.

Use separate `--queue dispatch`, `--queue notifications`, and `--queue exports` processes when isolating workloads; the default `--queue all` preserves the local combined-worker behavior. Dedicated notification/export processes do not initialize the refund provider. A notification process handles one explicit route, so provision additional workers for additional routes. Monitor `notification_jobs` and `notification_audit` through controlled administrative access until the operations dashboard is available. See ADR 0010 and the notification crate README for transport limits and disclosure boundaries.

## Operational visibility

Provision an independent enabled `operations_grants` row for a reviewer and connection. `GET /v1/operations?connection_id=<uuid>` returns scoped pause state, current approval/provider counts and ages, reservation-derived USD minor-unit totals, ready-queue lag and failed notification/export counts. The console Operations tab has an explicit connection and refresh action; it does not pause, reconcile or alter funds. Legacy records with unknown age remain unknown, with a visible count. Provider age means time in the current unresolved state. Other human role grants do not imply this read permission.

Set a dedicated `APL_METRICS_TOKEN` (at least 32 visible random ASCII characters) to enable private `GET /metrics`. It must differ from development credentials. Scrape with its bearer value from private management ingress; keep this endpoint off the public proxy. Metrics are per API process and contain only bounded route-template/method/status-class HTTP counters and latency histograms. Response `X-Request-ID` is generated by the server; supplied IDs are ignored. Persistence logs emit error classes rather than raw SQL diagnostics. Worker/provider and business-event metrics are still follow-up work; these HTTP metrics do not establish the plan's latency or availability targets.
