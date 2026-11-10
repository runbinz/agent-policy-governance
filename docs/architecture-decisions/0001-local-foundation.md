# ADR 0001: Rust local foundation

Status: accepted for first development slice, October 10, 2026.

Use Rust 1.90, Axum 0.8, Tokio, Serde, SQLx 0.8, and PostgreSQL. Cargo.lock pins resolved dependency versions. Begin with domain, persistence, API, and worker crates; add crates when concrete interfaces justify them.

Local development explicitly enables synthetic bearer-token identities and binds the API to loopback. Production identity and live provider execution are absent. There are no default accepted tokens. Runtime API and worker database roles are separate from migration ownership.

The fake provider stores one effect per action in PostgreSQL. Worker decision, fake effect, action status, audit, and job completion commit together. This makes local recovery deterministic but does not model atomicity across PostgreSQL and Stripe. External dispatch requires separate durable attempts, budget reservations, stable provider keys, and reconciliation before live writes are enabled.

Policy allows only valid USD refunds up to 5,000 cents automatically. Higher valid amounts are denied with APPROVAL_NOT_IMPLEMENTED. The fake policy and connection fixtures must be replaced by persisted versioned policy/configuration before production.

MCP and Stripe version compatibility spikes are deferred until their adapters are built. Neither is a prerequisite for this fake-provider foundation; no current compatibility claim is made.
