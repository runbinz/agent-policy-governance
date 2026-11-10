# Policy console and read authority
Date: 2026-11-09. Status: locally verified by the 145-test shared gate, console checks and isolated browser publication/conflict checks.

The console reads policies through a narrow reviewer endpoint authorized by the existing edit-policy or publish-policy grants. These roles already share simulation authority; approval, evidence and operations permissions grant no policy access. Read locking follows the existing connection administration protocol, with an explicit enabled-connection check.

Return separately identified active policy and bounded immutable version pages, with advisory edit/publish capabilities. Browser-facing versions must be exact safe integers; fail closed on unrepresentable stored values. The editor creates new versions and never mutates saved definitions. Publication confirms exact saved values and the captured expected active version; server preconditions and permissions remain authoritative. Simulations evaluate static policy fixtures, not payment eligibility or available budgets.

Existing write contracts remain unchanged. Console request cancellation prevents stale scope/session data from being displayed; an interrupted publication is an unknown outcome requiring an authorized refresh, never an automatic retry.
