# Independently authorized recovery projections
Date: 2026-11-09. Status: implementation and verification in progress.

Operations recovery pages project only fixed redacted fields from unresolved dispatches or currently due outbox jobs. Canonical cursors bind tenant, environment, connection and kind; they confer no authority. Shared dispatch restoration validates private snapshots and their action/connection/parent bindings before projecting provider state. Historical missing times remain unknown.

A separate reconciliation preview uses the existing reconciliation grant, independent of operations and detail grants. GET never schedules work. Explicit POST requests evidence collection with existing queue locks and stable provider keys; uncertain exposure remains held. Corrupt data must roll back any attempted scheduling and audit within the transaction. Browser confirmations capture exact action/connection; conflicts discard confirmations and refresh, while unknown outcomes require explicit refresh without retry.

This completes a local operations workflow slice only. External-provider acceptance, production access, provisioning, measured credential health and the remaining software-plan requirements stay open.
