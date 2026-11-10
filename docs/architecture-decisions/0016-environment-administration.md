# Environment administration authority
Date: 2026-11-09. Status: foundation locally verified by the 150-test shared gate, console checks and isolated API/browser mutation/conflict tests.

Introduce a dedicated environment-admin grant, default deny, for scoped inventory, enable/disable and grant revocation. Existing review, policy, evidence and operations permissions do not imply administrative authority. Dispatch controls retain their separate grants.

Use safe integer revisions and transaction-held authority/target locks to reject stale changes. Audit actor, exact scope/target and revisions atomically. Reject acting-reviewer self-disable and acting-admin self-revocation; test concurrent revocation ordering rather than assuming last-administrator safety. Never release uncertain financial holds as an administrative side effect.

Inventory exposes fixed scoped identifiers, configured permissions and route mode without provider accounts, namespaces or credentials. Credential verification is unobserved until worker reporting supplies measured evidence. Past payment verification timestamps do not establish current credential health.

This foundation does not complete provisioning, grant creation, measured health, pause UI or the full administration release requirement; those remain in the software-plan objective.
