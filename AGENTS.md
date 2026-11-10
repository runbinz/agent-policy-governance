# Data Governance project instructions

## Scope and shared context

- This project's root is `/Users/runbinzhou/Documents/ChatGPT/Data Governance`.
- Keep project source, plans, decisions, and handoff notes in this root. Do not read or change unrelated project files or chats. Toolchain, dependency, skill, and official documentation access remains permitted when necessary for this project.
- Before project work, read `PROJECT_STATUS.md` and the relevant sections of `agent-policy-layer-software-plan.md`.
- For cross-chat context, read only chats verified to belong to this Data Governance project or whose working directory is this exact root. A chat title alone is insufficient. If a listing includes other projects, do not inspect their conversation contents.
- Chats have separate conversational context. Persist decisions and handoffs in project files; do not assume another chat automatically knows them.
- Read-only reference to in-scope chats is permitted. Sending messages to another standalone chat requires explicit user authorization. The user has authorized this coordinator to delegate bounded implementation tasks to subagents. Do not create standalone chats unless requested.

## Coordination

- Follow `docs/AGENT_WORKFLOW.md` for focused context, bounded output and targeted-then-integration verification. Keep current status compact and archive completed evidence; retain the full software-plan scope and required safety checks.

- Use one user-designated coordinator chat for roadmap decisions and integration. Other chats handle bounded tasks with explicit file ownership.
- This chat (`01a1271c-c387-7de3-9bad-898740ca5836`) is the implementation coordinator. Use at most three simultaneous subagents and one level of delegation initially. Subagents must not spawn further agents.
- Give each task an objective, owned files, shared interfaces, acceptance criteria, and verification commands. The coordinator owns integration and shared configuration. Review agents report findings without changing implementation unless assigned.
- Before editing, check the current files and working tree for other chats' changes. Do not overwrite or revert others' work.
- Record task ownership and intended files in `PROJECT_STATUS.md` before implementation. If ownership overlaps, resolve it before editing those files.
- At handoff, update status with changed files, checks actually run, remaining work, and blockers. Keep it concise and factual. Re-read the status file before updating it to preserve concurrent changes.
- The software plan is the implementation specification. The comprehensive plan supplies business context. Record architectural changes in `docs/architecture-decisions/` when implementation begins.

## Implementation baseline

- Backend: Rust, Axum, Tokio, Serde, SQLx, PostgreSQL; shared domain/application crates for API, worker, and MCP.
- Console: React, TypeScript, Vite; generated API client from backend OpenAPI contracts.
- Follow the software plan's isolation, approval, budget, idempotency, and reconciliation invariants.
- Rust compiler checks complement behavioral tests. Never claim compilation proves execution safety.
- Once a Cargo workspace exists, run formatting, Clippy, and relevant tests for Rust changes. Report unavailable checks accurately.
