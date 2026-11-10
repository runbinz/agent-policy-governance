# Retained payment facts and review freshness
Date: 2026-11-09. Status: implemented and locally verified; real-account acceptance remains open.

The routed worker already verifies the charge before creating an approval. Retain minimal immutable facts from that authenticated read atomically with each review generation, and retain the fresh observation used for dispatch. Do not add provider reads to GET requests.

An approval generation binds one immutable observation through a scoped foreign key. Keep the existing canonical action digest and all exact approval fields/checks. Material facts include trusted route identity, payment/request identity, captured/refunded amounts, and eligibility facts; observation timestamps are excluded from the material digest.

A human reviews a recorded observation within the existing approval deadline. Expiring the 30-second dispatch freshness window alone does not rotate a generation or prohibit a decision: that would make normal human review impractical. Show observation age/staleness explicitly. A material change observed by the worker requires a new review generation while preserving the original review deadline for context-only replacement. Legacy routed approvals without an attestation require reevaluation before approval/dispatch. Fake actions never claim verified payment facts.

Dispatch always requires a fresh validated observation with material facts equal to the approved generation, plus existing current policy, reviewer authority, controls, payment serialization and atomic budget checks. Changed facts return to review before new holds/send. Indeterminate in-flight executions keep their original keys, holds and reconciliation rules; observation expiry must never create another execution opportunity.

Private trusted route identity binds the existing provider namespace and configured account/connection, checked against the locked current route. Do not store secret credentials or invent a route version. Credential rotation for the same account does not itself change material payment facts; account/namespace changes do.

Use provider-neutral validated observation values in the shared dispatch/application contract; the production Stripe adapter supplies them only after its authenticated charge verification. Structural type validation does not prove network provenance. HTTP/MCP accept no observations, worker-only insertion and exact server-side route/request checks enforce the runtime boundary. Tests must cover attempted untrusted metadata substitution and all public input surfaces.

Migration0024, typed connector facts, transactional persistence/generation handling, detail projections and failure tests are implemented. The 143-test shared gate, actual runtime-role lifecycle/upgrade tests and synthetic browser projection checks passed. Constructor/mocked connector/seeded UI evidence does not prove real-account acceptance. Dedicated detail-read and approval permissions stay independent.
