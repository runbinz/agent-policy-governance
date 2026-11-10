# Preapproval payment attestation — bounded follow-up proposal

Status: implemented and locally verified under ADR0014. Implements retained preapproval facts identified by ADR0013; real-account acceptance remains open.
No provider writes, new workflow, or live-provider GET detail reads are part of this slice.

## Actual ordering and gap

- `Store::submit` stores immutable request/idempotency/outbox in `received`; submission does not evaluate Stripe.
- Routed jobs: worker `next_external_candidate` → Stripe `verify_charge` outside transaction → `prepare_verified_external` → `approvals::process` under job/action/control/policy locks.
- `process` evaluates active policy, creates/parks `pending_approval`, or dispatches an allowed/approved action. Pending jobs are scheduled again by `park` (up to five seconds); their next routed evaluation reads Stripe again.
- Policy changes are observed on this reevaluation and decision/dispatch checks; changed policy/digest makes a new generation when review is still required. Policy auto-allow can dispatch without review; hard deny still wins.
- Stripe already verifies exact account/charge, sandbox USD, paid/captured/succeeded/undisputed direct card and remaining amount before approval. Its `Charge` facts are discarded; only `VerifiedRefundRequest` plus private customer scope survive until dispatch. Existing dispatch snapshot is insufficient for captured/refunded/status facts.
- `StripeError::Charge` currently denies a candidate; transport/unverified failures defer it. Preserve that distinction; never invent facts from an error.

## Trusted typed observation

- Define provider-neutral validated VerifiedPaymentObservation values in the shared dispatch/application contract with private fields and bounded getters. Production Stripe supplies them after authenticated read_charge and eligibility validation. No HTTP/MCP observation input. Constructor checks structural consistency, not network provenance (ADR0014).
- Fields: schema_version=1, connection_id, payment_id, currency=USD, amount_minor (requested refund), charge_amount_minor, captured_minor, refunded_minor, captured, paid, disputed, status=succeeded, method=card, direct_charge=true, eligible=true, observed_at_ms, fresh_until_ms. Checked integer arithmetic and existing ID bounds; remaining_minor is computed by checked subtraction.
- Keep customer_ref separate and private for ledger scope; no customer identity, provider response/body, evidence reference, route secrets or payment instrument details in public projection.
- `verify_charge` returns `VerifiedChargeContext { request: VerifiedRefundRequest, observation: VerifiedPaymentObservation, customer_ref }`; observation and request must share exact connection/payment/amount/currency/times.
- Use candidate DB observation time conservatively as read-start lower bound; fresh_until = start + existing 30_000ms, never response-completion + TTL. Transaction checks DB now after lock waits and rejects future/stale/impossible intervals. Time spent reading consumes freshness.
- Trusted route/account binding is checked again under existing authorization locks. Persist the existing private provider namespace/account identity to invalidate route replacement; no invented route version (ADR0014). Never expose it through detail.
- Trust boundary is the authenticated worker/connector, not cryptographic proof against a compromised worker or database administrator. Runtime API/MCP roles cannot insert observations; constructor privacy alone is insufficient.

## Forward schema and exact binding

- Migration0024_payment_attestations.sql is reserved after frozen0023. Never edit frozen migrations.
- Add immutable `payment_attestations` keyed `(tenant_id,environment_id,action_id,id)` with typed bounded columns above, private route identity, DB recorded_at, and canonical server-computed `facts_digest`.
- `facts_digest` covers schema/domain tag, tenant/environment/action/workload/connection/payment, requested amount/currency, private route identity and ALL material payment facts; exclude observation timestamps/id/recorded_at so identical refreshed facts compare equal.
- Add nullable `approvals.payment_attestation_id` with composite FK including tenant/environment/action. Extend immutable-approval guard to prohibit changing this link, original scope, policy version and action digest; only existing decision fields may change once.
- Keep existing `apl.refund.approval.v1` action_digest and backend recomputation unchanged. Generation's immutable FK binds extra context; no client-supplied observation can replace it. Detail identifies the linked attestation, never “latest observation” as approved facts.
- Add nullable `external_dispatches.payment_attestation_id` for the exact fresh dispatch observation; preserve immutable snapshot/request/key and existing generation link. Dispatch evidence may differ in observation time, never material facts from approved generation.
- Forced scoped RLS, composite FKs, worker-only INSERT, no runtime UPDATE/DELETE, no PUBLIC function execution. API reads only through dedicated detail authorizer/retention projection; raw new table grants are not a reviewer authorization substitute.
- No backfill. Legacy approvals/context remain unavailable; routed legacy approvals cannot approve/send until reevaluation creates a fresh generation with trusted evidence. Existing in-flight legacy dispatches keep reconciliation/retry contract; do not retrofit observations or reset keys/holds.
- Legacy authorized records with no send marker and no retained evidence cannot start a provider call. Existing worker abandonment releases only these provably unsent holds. Already marked legacy sends retain their reconciliation/key/uncertain-exposure contract.

## Transaction changes and freshness

- Extend `ExternalInput`/`prepare_verified_external` with the typed observation. Validate exact action/request/route and freshness before policy evaluation; persist observation in the SAME transaction as new approval or dispatch authorization, with audit event `payment.attested`.
- Avoid unbounded five-second snapshots: do not persist identical observations for a parked current generation; persist only new generation/dispatch facts (and a changed-context generation). Fetching remains outside locks.
- New approval INSERT requires a fresh eligible observation and immutable FK. This precedes visibility of `pending_approval`/notification. Auto-allow still requires and stores a fresh dispatch observation.
- An undecided generation retains its original observation for its existing approval lifetime. Freshness expiry alone does not rotate it. Changed material facts require a new generation with fresh observation even when policy/action_digest stay equal; the replaced generation cannot be decided. Use existing generation replacement and audited scheduling.
- Decision POST and detail eligibility require linked matching valid recorded evidence and the original approval deadline for routed actions. Observation staleness alone does not prohibit human review (ADR0014); dispatch still requires fresh equivalent facts. GET reports age/staleness without scheduling work or reading Stripe.
- Preserve approval expiry: if original approval TTL expires, existing `expire_approval` behavior wins. Context refresh must not extend approval lifetime indefinitely: replacement for context alone retains the original review deadline; policy-change generation follows existing policy TTL behavior.
- After a human decision, worker refreshes normally before dispatch. Same material facts may use a NEW timestamped dispatch observation without changing approval generation/digest; approval's historical evidence may now be stale, but fresh equal facts validate it for dispatch.
- Changed eligible facts after approval return `ready`→`pending_approval` with new generation/FK and existing approval deadline; no hold/send is authorized. Ineligible charge retains current terminal denial path. Temporary read/freshness failure retains pre-dispatch state and retries safely.
- Preserve exact generation/digest/current policy/reviewer authority/stops/expiry checks, payment advisory lock, open-dispatch exclusion, `external_payment_changed_since`, atomic budget holds and stable dispatch idempotency. Recheck freshness after budget/control locks at authorize boundary; stale rollback reserves nothing.
- `send_authorized` verifies dispatch evidence identity and material equivalence for approval-required NEW authorization. Durable retries/reconciliation use original snapshot/key and outcome rules, never reauthorize a new refund or release uncertain exposure due to observation expiry.
- Provider final read-before-create remains an existing defense; external actors can change charge between read and refund. Observation is timestamped evidence, not a provider atomic precondition or guarantee of current balance.

## Read DTO and compatibility

- Extend `apl_domain::action_detail::AuthoritativePayment` with `availability: verified_payment|verified_context|unavailable`, a typed nullable `payment` projection, and existing legacy `context` projection. Do not silently reinterpret existing verified_context as full payment evidence.
- `PaymentAttestationView`: attestation_id, schema_version, source=approval|dispatch, approval_generation (nullable), payment_id, connection_id, requested_minor, charge_amount_minor, captured_minor, refunded_minor, remaining_minor, currency, status, captured, paid, disputed, method, direct_charge, eligible_at_observation, observed_at, fresh_until, freshness=fresh|stale; no “eligible now” assertion.
- Pending/ready approval detail uses EXACT generation FK; auto-allow execution uses dispatch FK. Historical approval pages may expose only attestation_id, with bounded authorized lookup deferred if necessary. Unknown/corrupt evidence fails closed; never fall back to metadata/request values as verified facts.
- Fake/local jobs keep their existing workflow and show unavailable full payment data, with local_fixture outcomes. Agent metadata, fake-effect rows and legacy VerifiedRefundRequest snapshots cannot populate `verified_payment`. No caller flag can opt into trusted evidence.
- OpenAPI/generated client/console label observation time, staleness and recorded eligibility. Missing/invalid evidence or expired/replaced generations prevent routed approval; staleness alone does not. Refresh after conflicts. POST remains authoritative.

## Implementation ownership and acceptance

- Connector owner: `crates/stripe-sandbox/src/lib.rs`, `src/tests.rs` (typed facts, validation/error distinctions); no provider writes added.
- Persistence owner: new migration0024, new `crates/persistence/src/payment_attestation.rs`, `src/approvals.rs`, `src/external.rs`, focused `tests/payment_attestation.rs`; lock/order changes reviewed by coordinator.
- Coordinator: persistence lib/module/signature wiring, `migrations/runtime-roles.sql`, worker main integration, domain detail DTO, API/detail eligibility, `apps/console/openapi.yaml`, generated client and detail UI; update ADR0013 only on acceptance. Coordinate current detail-backend ownership before edits.
- Connector tests: exact charge/account/mode/currency, captured/refunded arithmetic, method/status/directness, malformed/missing facts, mismatch and timeout consume freshness; error paths never emit attestation.
- Real runtime-role PostgreSQL tests: atomic evidence+approval/audit, scoped FK/RLS, API insert/update denial, immutable link, fake/legacy/metadata forgery, stale/future context, generation/digest/policy/route changes, authority revocation, approve/reject race and review deadline preservation.
- Dispatch tests: identical refresh preserves exact approval; changed facts require new review before holds/send; ineligibility denies; transient reads defer; lock-wait expiry rolls back hold; stale pre-settlement observation rejected; no duplicate key/new send after unknown outcome; legacy in-flight reconciliation unchanged.
- Read/API/browser tests: pending facts available before review; stale historical facts labelled; no network calls during GET, retention/detail grant boundaries, no secrets/customer/raw body, malformed stored context fails closed, replaced-generation click conflicts and refreshes safely.
- Verified locally: connector unit tests; isolated runtime-role lifecycle/projection/legacy-send tests; console generation/check/build and synthetic browser facts/XSS checks; formatting, Clippy and 143-test shared integration gate. See PROJECT_STATUS and verification-history for logs and limits.

## Frozen implementation interfaces

- Shared dispatch module payment_observation exposes PaymentFacts (charge_amount_minor/captured_minor/refunded_minor:u64; paid/captured/disputed/direct_charge:bool; status/method:String) and VerifiedPaymentObservation with private fields. Constructor new(request:VerifiedRefundRequest,facts:PaymentFacts)->Result<Self,DispatchError>; getters request()->&VerifiedRefundRequest and facts()->&PaymentFacts. Clone/Debug/Eq/Serialize and validated TryFrom-backed Deserialize for trusted database round-trips, never HTTP input.
- Constructor accepts only paid/captured/undisputed succeeded direct card, checked captured<=charge/refunded<=captured/remaining>=requested; money facts <=9007199254740991 for exact public JSON integers, freshness interval <=30000ms, RFC3339-representable epoch milliseconds. Structural consistency is not network provenance.
- StripeAdapter::verify_charge_context(payment_id,amount_minor,observed_at,fresh_until)->Result<VerifiedChargeContext,StripeError>, whose public fields are request, observation, customer_ref. Preserve old verify_charge by delegating to this method and discarding observation for compatibility of read-only connector callers; production worker MUST use new method.
- Store::prepare_verified_external gains observation:VerifiedPaymentObservation immediately after request. No production preparation path may bypass attestation. Coordinator updates existing callers/tests and owns lib.rs signature/body wiring based on persistence agent instructions.
- Connector agent owns dispatch/src/payment_observation.rs, stripe-sandbox/src/lib.rs and src/tests.rs only; coordinator declares/reexports module. Persistence agent owns migration0024, persistence/src/payment_attestation.rs, approvals.rs, external.rs and tests/payment_attestation.rs only. Coordinator owns shared declarations/grants/signatures, worker wiring, domain/read DTO/OpenAPI/console and existing regression-test call sites.
