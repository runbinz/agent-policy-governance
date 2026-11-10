# External refund dispatch contracts

This crate is pure Rust state and adapter interfaces. It neither connects to
PostgreSQL nor calls a provider. Use an authoritative database clock for
`Timestamp` values (Unix milliseconds). Persist the resulting snapshot under a
row lock or guarded compare-and-set. In-memory transitions alone grant no
permission to send a refund.

1. Fetch and verify the provider's payment context outside the database
   transaction. Build an immutable `VerifiedRefundRequest` using the exact
   provider payment, connection, USD amount, and freshness window. Within the
   authorization transaction, lock and recheck the action, control and policy
   rows, and budgets, then commit `Dispatch::authorize` with the request, action
   ID, provider key, budget hold, and outbox/audit. The action ID must uniquely
   identify the logical request in the provider account. Freeze the connection's
   provider account/endpoint and credential namespace for retries; the same
   key in a different account does not provide deduplication.
2. Restore the persisted snapshot and claim a monotonic lease under the lock.
   Persist and commit the generation and exclusive expiry before acting. A
   persisted lease cannot be reused across unrelated actions. Use the same
   generation and an unexpired lease for all subsequent guarded updates. Run
   one provider operation at a time under each lease; do not apply an old
   response after starting a newer operation under that lease. Webhooks should
   enqueue reconciliation rather than bypass the lease.
3. Follow `next_step`. For a send, persist `begin_send` and the attempt before
   network I/O. No network write occurs in a database transaction. Recheck the
   live lease and send deadline as close to network I/O as practical, and bound
   provider request time. Fences protect local state, not an external call
   already in transit.
4. A crash before the marker means the first send is still possible with fresh
   context. A crash after it leaves an in-flight request, even if the process
   died before sending a byte. Reconcile first. Only an unknown outcome can
   allow replay; use the same payload and key and only if both the persisted and
   current verified connector safety windows remain open and context is fresh.
   Include clock uncertainty and network time in the provider safety margin.
   Never treat a transport error, missing lookup result, or an expired lease as
   proof of non-execution.
5. Commit `observe`, its evidence, state, audit, and ledger effect atomically.
   Confirmed success settles; verified non-execution releases. Pending and
   unknown keep the hold. A known pending refund cannot become replayable merely
   because lookup becomes inconclusive. Terminal states cannot change or emit
   another budget effect. If a result arrives after a lease expires, discard
   the stale local update and reconcile under a new lease.
6. A stale, never-sent request returns `HoldUnsent`. The integrator must
   cancel it or perform a fresh authorization with authoritative context, under
   the same logical action and hold discipline, before any send. Unknown or
   in-flight requests never use that path. Escalate repeated unresolved
   reconciliation to manual review; only verified provider evidence may
   resolve it.

On restore, deserialize the stored JSON into `DispatchSnapshot` and call
`Dispatch::restore`. Use the persisted immutable request and compare the derived key
to the key committed at dispatch authorization. Reject any mismatch. Persist
attempts separately; the snapshot tracks only the first possible send and its
absolute replay cutoff. The adapter and persistence layer must separately
authenticate webhook/evidence sources and deduplicate or re-fetch observations.

For local tests, `fixture::FixtureProvider` implements the same provider trait
without networking. Its clones share one simulated provider, so tests can
replace a worker without losing effects. Select success, accepted-then-timeout,
pending, or verified non-execution for unseen keys. Use `complete_pending` to
advance pending results. To interrupt a worker after provider acceptance,
pause responses, await the execution count, then cancel that worker. The
provider effect remains visible to reconciliation. This fixture is in-memory;
it does not model provider durability across a fixture process restart.
