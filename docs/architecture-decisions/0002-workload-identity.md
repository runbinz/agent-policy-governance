# ADR 0002: Verified workload identity and persisted grants

Status: implemented and verified for development, October 10, 2026.

Workload requests carry either explicitly enabled local fixture credentials or an RS256 JWT. Verified issuer and subject resolve to a registered workload in PostgreSQL. Tenant, environment, workload, and connection authority come from that registration, not token tenant claims or request headers. One identity maps to one connection in this first implementation; multi-connection grants require extending the principal model deliberately.

JWT mode uses an operator-provisioned public JWKS file, exact issuer/audience validation, signature checking, expiry, optional not-before checking, and explicit algorithm/key restrictions. Token-supplied key URLs are never fetched. Key rotation is performed by provisioning the new JWKS and restarting the API; multiple valid keys may overlap. Managed mode optionally discovers the configured HTTPS issuer, checks exact issuer equality, and refreshes an atomic signing-key cache. Same-origin JWKS is the default; a different URL requires an exact configured pin. Failed refreshes do not replace valid keys, and the stale cutoff fails closed. Unknown keys never trigger a request. The configured JWKS must satisfy the existing strict RS256 public-key policy. Real issuer onboarding and browser login remain outstanding. [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)

Local fixture mode continues to require an explicit development flag, explicit tokens, and loopback binding. JWT mode also remains loopback-bound for this development release. The fake worker still requires local development mode. Supporting JWT verification does not make this a production-ready deployment.

Runtime API and worker credentials can read necessary identity/grant records but cannot provision or change them. A restricted database function resolves identity before tenant context is established. All subsequent action operations set transaction-local tenant context and recheck current persisted permissions. Worker dispatch rechecks workload, connection, and submission authority under locks; disabling them serializes with fake execution. Grants distinguish submission, status, and event visibility.

Provisioning and revocation are administrator SQL operations for now. Database audit triggers record identity/configuration changes without logging tokens or credentials. Human login, membership roles, delegation, admin APIs, and the reviewer console are outside this milestone.
