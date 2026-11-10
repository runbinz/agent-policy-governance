# Efficient implementation loop

- Keep the entire software-plan objective. Optimize duplicated context and work, not verification coverage or product scope.
- Use PROJECT_STATUS.md for current state only; archive completed detail in verification-history.md. Do not repeatedly read history, full plans, generated clients or complete logs.
- Search symbols with rg, then read the relevant ranges. Save long command output under .local and return the exit status, summary and failure excerpt.
- Prefer apply_patch for multiline source/document edits; avoid nesting long shell heredocs inside JavaScript template strings with Markdown backticks. Keep installer/advisory/build directory searches narrowly scoped.
- For new bounded work, prefer a fresh subagent with fork_turns=none, a self-contained objective, owned files, contract path and acceptance commands. Do not inherit the full coordinator history. Use at most three simultaneous agents and no nested delegation.
- Delegate independent substantial work or security review. Handle small edits directly. Resolve contracts before parallel edits and keep shared files coordinator-owned.
- Agents run targeted checks for their changes. Coordinator reviews results, runs targeted integration/failure checks, then one full integration gate after the slice stabilizes. Repeat broad checks only for changed code, failures or unresolved concerns.
- Sequential shell checks must use set -e or individually inspect every exit status. A later successful build must not mask API generation/check failures. Inspect each check's terminal result and summary before recording it as passed.
- Database tests must coexist with the shared ignored-test gate. Global aggregate/age assertions require an owned isolated database or baseline-aware checks; do not leave synthetic ready jobs for other worker tests to consume.
- Await real process/agent handles; avoid frequent unchanged polling. Batch independent reads and report compact results. Communicate meaningful progress at least once per minute while working.
- Handoffs: changed files, actual checks/results, unresolved issues, next dependency. Do not repeat prior conversation, paste full source or claim unrun checks.
- Re-read current ownership before status edits. Preserve decisions and evidence in files so later fresh contexts can continue safely.
