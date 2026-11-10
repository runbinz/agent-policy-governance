# Reviewer action detail authorization and evidence
Date: 2026-11-09. Status: accepted; implementation starting.

Reviewer detail uses separate reviewer-only routes and a dedicated per-connection action_detail_grants permission, denied by default. Review, export, operations and detail authority remain independent. Local fixture provisioning is explicit; production grant administration remains part of the administrative interface work.

The dedicated grant permits exact payment resource identifiers and deciding reviewer UUIDs needed to interpret the action. Customer identifiers, arbitrary metadata, raw connector evidence, provider keys, routes, secrets and unrelated actions are excluded. All projections are bounded, escaped by the console, and subject to searchable retention and transaction-held authorization.

Historical records cannot supply facts never persisted. The detail implementation must show recorded connector context and unavailable facts honestly, without treating a refund request as a captured/refunded balance. Completing the required detail feature also requires a subsequent immutable connector-attestation path before approval, with observation/freshness and captured/refunded/eligibility facts. That work remains in scope; the initial read surface is not completion of section12.

Workload routes retain their existing authority. Detail cannot approve or execute; decisions still independently bind generation and digest and recheck current reviewer authority.
