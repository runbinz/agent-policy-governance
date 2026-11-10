# ADR 0003: Policy and approval dispatch boundary

Development milestone; provider execution remains simulated.

Policy versions are scoped to one tenant, environment, and connection. An administrator inserts an immutable version and publishes it by advancing the connection's active binding in the same transaction. Advancing to a new version invalidates older approval generations. Restoring a previous rule set means publishing its settings as a higher version. Until the policy administration API is implemented, the database administrator is the publisher. Missing policy denies execution.

Workload and reviewer identities are resolved separately. Local reviewers use a separate fixture credential. For JWT, reviewers have a distinct audience and a separate mapping and connection grant; tokens valid for both audiences are rejected. Browser session login through a managed identity provider remains future work.

A review decision presents the generation and digest returned by the review queue. The digest binds the immutable action and active policy version. Decisions are conditional on the current approval, policy, reviewer grant, and expiry. Replays and stale requests conflict. The worker checks the binding and current reviewer authority again before committing a simulated effect.

PostgreSQL is authoritative for queue timing and expiry. Pending requests remain durable while parked. The worker, reviewer, and any future cancellation operation must serialize on the same job/action locks, then check applicable authorization and policy rows before changing state. The audit record and state change commit together. For an external provider, a later milestone will commit durable dispatch authorization and budget reservations before making a network call.
