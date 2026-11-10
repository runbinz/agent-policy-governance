# Searchable retention and reserved submission keys

Date: 2026-11-09. Status: implemented first visibility increment; locally verified by the 131-test shared gate and independent static review.

The initial metadata window is90 days after terminal completion, configurable per tenant/environment. Active work, unresolved external outcomes and held budget remain visible without age expiry because reconciliation and financial control depend on them. This is searchable visibility, not physical deletion or a durable evidence archive.

Database-maintained creation and terminal timestamps cover new activity. Existing unknown ages stay unknown; a separate migration observation grants legacy terminal records a conservative retention grace window. Never infer event times from identifiers or approval expiry.

Use one scoped visibility rule for evidence search, explicit selections, export requests and export snapshot generation. A queued export that becomes ineligible fails closed. Already generated encrypted downloads retain their existing one-hour lifetime and fenced cleanup.

Submission keys remain reserved indefinitely in this release. Matching scoped-key replay returns the original action; a changed request conflicts. Retention never creates another execution opportunity. Keep action anchors, audit, policy/approval evidence, provider retry records, webhook deduplication, reservations and ledger. A future physical archive must introduce an atomic scoped tombstone/replay contract before removing full records.

This increment does not complete longer-lived archival storage, backup retention, physical metadata expiry, or the administrative retention configuration interface. Those remain release work.

Migration 0022 recreates the existing snapshot caller after introducing its preflight wrapper so previously cached function plans enforce the retention predicate. A same-connection upgrade test covers this boundary. Internal bypass bases and helper are not runtime entry points.
