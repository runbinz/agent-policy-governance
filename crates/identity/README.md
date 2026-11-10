# Workload JWT verification

Use `JwtVerifier` for an operator-provisioned static public JWKS, or
`ManagedIssuer` for explicit discovery and rotation. Both enforce RS256,
required issuer, audience, subject and expiry claims, a trusted key ID, and
strict RSA key checks.
The configured provider JWKS must contain only usable RS256 RSA signing keys;
a mixed or malformed set is rejected as a whole.

For managed mode, configure one exact HTTPS issuer and the distinct API
audiences. `ManagedIssuer::refresh()` obtains discovery and signing keys.
Run a successful refresh before serving authenticated requests, then schedule
refreshes comfortably inside the configured stale interval. Monitor failures
and cache freshness. Each successful refresh atomically replaces all keys;
a failed refresh preserves the previous keys only until their original stale
cutoff. There is no fallback after the cutoff. A token with more than one
configured audience is rejected for all configured audiences.

The cache derives discovery from the configured issuer, requires an exact
metadata issuer match, and only fetches same-origin HTTPS keys unless the
operator pins an exact alternate HTTPS JWKS URL. Redirects, proxy environment
settings, token-provided URLs and unknown key IDs never initiate extra
requests. Requests and document sizes are bounded. A successful key rotation
immediately removes keys absent from the new set; providers should publish
overlapping signing keys for continuity.

MCP uses `verify_for_resource` to require a sole exact resource audience and
the required case-sensitive OAuth scope. A valid token missing that scope
returns `InsufficientScope`; a malformed scope claim is an invalid token.
Ordinary `verify` retains its existing REST behavior and ignores scope.

This crate does not implement browser sessions, managed login, token
acquisition, or identity registration. See the
[OpenID Connect Discovery specification](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig).
