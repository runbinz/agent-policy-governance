# Revisioned operator controls
Date: 2026-11-09. Status: locally verified by the 153-test shared gate and isolated three-scope browser checks, including stale resume after an intervening resume/pause cycle.

Expose target state only under its existing dedicated control grant. Environment-admin and operations-read grants do not imply pause/resume authority. Reads never schedule or mutate work.

Public pause/resume requests must include the revision shown by the authorized read. Compare under authority and target locks before changing state; stale confirmation conflicts. This is an intentional prelaunch HTTP contract change, with existing internal setters retained for trusted code/regressions. Use connection/workload admin revisions and a guarded tenant control revision. Exact no-op requests may acknowledge without fictitious audit or increment.

Confirmation names scope, target and expected revision, including the tenant-wide effect. Unknown HTTP outcomes require state refresh. Pausing does not prove non-execution, cancel possible provider effects or release uncertain holds. Operator UI remains reachable without unrelated administrative read permissions.
