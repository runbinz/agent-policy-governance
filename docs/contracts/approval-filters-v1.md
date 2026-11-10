# Approval queue filters, first increment

Expose `queued_at: string | null` on Approval from approvals.created_at (UTC RFC3339). Legacy null remains unknown. Timestamp is generation-specific, never inferred from expiry. Additive required nullable OpenAPI property; preserve generation/digest, authorization/current-policy predicate, expiry behavior.

Console filters current authorized queue by connection, currency, inclusive amount range in integer minor units (explicit label), and minimum age in whole minutes since queued_at. Null age excluded only when minimum age active; show unknown age honestly. Reject invalid/negative/unsafe integer/reversed ranges visibly; never silently interpret decimals. Currency required when amount filter active to avoid cross-currency comparisons. Filters compose, reset, and do not mutate approval input. UI updates age clock while mounted.

Assigned-authority filtering remains a separate increment: existing model authorizes by connection grant and has no assignment concept. Do not invent an assignment from reviewer ID or expiry. Document this remaining gap.

Ownership: approval_fields agent domain Approval + persistence approvals.rs + dedicated approval_queue test only. queue_ui agent App.tsx + new approvalFilters.ts + queue-specific styles only. Coordinator OpenAPI/generated client/api.ts/shared docs and checks. No migration needed (created_at exists from0018).
