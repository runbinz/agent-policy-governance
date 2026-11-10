# Data Governance — project home

Open this file in Codex for an index of the project. These are ordinary files in the Data Governance folder; they do not appear as separate chats.

## Plans and agent instructions

- [Software implementation plan](agent-policy-layer-software-plan.md): Rust architecture, contracts, safety requirements, and roadmap.
- [Comprehensive plan](agent-policy-layer-comprehensive-plan.md): product and business context.
- [Agent instructions](AGENTS.md): project boundaries, delegation, ownership, and verification rules.
- [Shared project status](PROJECT_STATUS.md): current work and handoffs between chats.
- [Implementation backlog](docs/IMPLEMENTATION.md): concrete milestones and acceptance criteria.
- [Architecture decisions](docs/architecture-decisions/0001-local-foundation.md): current scope and limitations.
- [Workload identity decision](docs/architecture-decisions/0002-workload-identity.md): JWT verification, persisted grants, and operational limitations.
- [Approval boundary](docs/architecture-decisions/0003-policy-approval-boundary.md): immutable policies and exact-action review.
- [Budget and dispatch recovery](docs/architecture-decisions/0004-budget-and-external-dispatch.md): budget holds and the external dispatch boundary.
- [Operations runbook](docs/runbooks/operations.md): stop, incident response, reconciliation, and restore.
- [Reviewer console](apps/console/README.md): local queue and decision interface.
- [Local development](docs/LOCAL_DEVELOPMENT.md): setup, test, and demonstration commands.

## Current implementation

Rust workspace with Axum API, durable workers, shared domain/persistence, authenticated identity, fenced dispatch and budget ledger, Stripe sandbox connector/webhooks, evidence storage, notifications and telemetry. PostgreSQL enforces scoped access and durable execution state.

The React reviewer console supports managed browser sessions, exact approval decisions, independently authorized action detail/history, evidence search/exports and scoped operations. REST and MCP share workload authorization. Workers support local fake execution and Stripe sandbox execution; these are not a live-payment production connector.

Local verification includes recovery/isolation tests, bounded operational metrics and alert rules. See [shared status](PROJECT_STATUS.md) for current checks and remaining administrative screens, retention, load/security validation and deployment work. Real-account acceptance and production readiness remain unproven.

## Agent workflow

This project's coordinator assigns bounded tasks with explicit file ownership. Implementation agents return code and verification evidence; the coordinator integrates and checks the complete slice. Project decisions and status live in the files above so other in-scope chats can pick them up.
