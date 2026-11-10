# ADR 0008: Redacted evidence search

Auditors search one explicit connection at a time using the same current connection-scoped evidence grant required for exports. Approval authority alone does not grant evidence access. The API resolves tenant/environment from reviewer identity and rechecks authentication after database I/O. Results and errors disable caching. Search is available without object storage; export generation still requires configured storage.

Search supports action UUID, workload UUID, status, and minimum/maximum amount in minor units. Each page returns at most 100 allowlisted summaries: IDs, action state/reason, amount/currency, policy version, and budget state/amount. No raw request, metadata, payment/customer reference, provider account, or idempotency key is returned or searched. The database uses bound parameters and a bounded query timeout; unauthorized connections are hidden as not found.

Pagination orders UUIDs ascending and returns an exclusive `next_after` cursor. This is stable keyset ordering, not chronology. Each page reflects current state: status changes can affect later pages, and concurrent inserts before the cursor require a new search. Search is not an export snapshot. Export requests independently reauthorize every selected action and later build a bounded repeatable-read snapshot.

The console clears search selection when its scope or filters change and aborts pending work when the reviewer clears their token. Selecting actions prefills the existing explicit export request; selection does not itself create an export or authorize any refund.
