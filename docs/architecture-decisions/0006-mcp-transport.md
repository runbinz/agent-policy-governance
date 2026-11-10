# ADR 0006: Remote MCP compatibility target

Status: implemented and tested locally against signed JWT and PostgreSQL fixtures. No remote MCP client or authorization server has been connected.

Target the protocol revision in the software plan, 2025-11-25. Implement a stateless Streamable HTTP endpoint at an operator-configured canonical resource URL. Use JSON responses for requests, HTTP 202 for accepted notifications, and HTTP 405 for the optional standalone GET stream. Validate Origin against an explicit allowlist when present, preserve protocol-version negotiation, and bound request bodies. Do not advertise server notifications, resources, or prompts until implemented. [Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

Expose only refund submission, status, and cancellation. Give each tool a strict input schema and pass it to the same Store methods as the HTTP action API. Require a client-supplied idempotency key for refund submission. A workload's identity and grants are resolved in PostgreSQL; tool arguments cannot set tenant, environment, or actor. Do not expose reviewer or operator operations as tools.

For remote deployments, publish OAuth protected resource metadata and include its canonical URL in the authentication challenge. The resource must be a trusted configuration value, never derived from an incoming Host header. Pin the token audience to the MCP resource and verify the configured issuer using the managed signing-key cache. Do not accept reviewer tokens or pass a bearer token onward to Stripe. Document the identity provider's preregistered client and resource-indicator support before claiming compatibility with a real remote client. [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)

Tool invocations have a per-process rate limit of 60 per registered workload per minute. Add a shared ingress limit for multi-instance deployments; the local guard does not replace perimeter throttling.
