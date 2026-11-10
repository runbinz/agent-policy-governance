# Runtime Policy and Approval Layer for AI Agents

Comprehensive startup and execution plan · October 9, 2026 · Version 1.0

## 1. Executive decision

Build a runtime authorization and execution service for customer-support agents issuing refunds. Start with one refund provider, one support workflow, and one approval channel. Expand only after proving that customers will pay to put the service in their production execution path.

**Initial promise:** Let support agents issue refunds within company policy, route exceptions to authorized reviewers, and produce a traceable record of each attempt and its outcome.

The broader opportunity is an independent control layer for agent actions across systems. The initial product must earn that position through reliable execution of one consequential workflow.

This document proposes a strategy; it does not establish market demand. All pricing, staffing costs, conversion gates, and performance targets below are planning assumptions. Validate them with customers and benchmarks. Weeks are relative to project kickoff; calendar dates are intentionally not committed.

### Twelve-month objectives

- Establish one repeatable customer profile and purchasing process.
- Reach 3–5 paying production customers by month 6, subject to the stage gates below.
- Demonstrate correct enforcement, attributable approvals, and recoverable execution under failure.
- Make the first production integration repeatable within five customer engineering days.
- Determine whether the business can grow through a standard product rather than bespoke integration services.

### Decisions to make now

| Decision | Proposed default | Evidence that would change it |
|---|---|---|
| Initial workflow | Support refunds | Interviews reveal stronger paid demand for another narrowly specified action |
| First provider | Stripe, provisionally | At least two qualified partners share another provider |
| Approval experience | Web review screen with Slack notifications | Partners require a different existing approval channel |
| Integration | Typed execution API plus a thin MCP adapter | Partners consistently use a different integration surface |
| Deployment | Hosted, one region, isolated tenant credentials | Qualified buyers reject it and fund a repeatable private deployment |
| Commercial model | Platform fee plus included executed-action volume | Buyers demonstrate another metric better matches value |
| Open source | Adapter, schemas, examples first | A documented distribution strategy justifies opening the enforcement core |

## 2. Customer, buyer, and problem

### Initial customer profile

Target software or online-service businesses that already operate support automation, have meaningful refund volume, and want their agents to execute actions. The best early customers have an engineering owner, documented refund rules, a supported payment provider, and a support leader accountable for resolution cost and customer experience.

Use 1,000+ refund-related requests per month as a prospecting hypothesis, not a qualification requirement. A lower-volume workflow may still have substantial value if approvals consume significant time or block a funded deployment.

Avoid initial engagements requiring healthcare-specific deployments, multiple payment systems, general desktop agents, unrestricted shell access, or an organization-wide identity replacement.

### Buying group

| Role | Responsibility | Evidence needed |
|---|---|---|
| Support operations leader | Workflow sponsor and potential budget owner | Current handling cost, approval backlog, automation target |
| Platform or agent engineering lead | Integration owner and technical champion | Execution path, credential ownership, deployment constraints |
| Security lead | Security evaluation and approval | Threat model, isolation, auditability, incident procedures |
| Finance or payments owner | Refund authority and reconciliation | Limits, eligible transactions, provider records, exception ownership |
| Procurement/privacy reviewers | Contract and data review where applicable | Security package, data handling terms, subprocessors |

Do not assume the security reviewer owns the budget. Identify the economic buyer and approval process in every opportunity.

### Job to be done

“When we allow an agent to refund a customer, ensure it acts only on the right transaction, within delegated limits, with the required human authorization, and with an outcome our operations team can reconcile.”

The alternatives to investigate are human review of every refund, application code with hardcoded rules, existing approval software, an authorization engine combined with an internal worker, and vendor-native controls. Ask customers to demonstrate these alternatives before claiming a gap.

## 3. Discovery and validation: weeks 1–4

### Research plan

Complete 20–25 interviews across approximately 10–15 organizations. Interview multiple roles at selected organizations rather than treating every interview as an independent buying signal. Include engineering, support operations, security, and payments owners.

Recruit through founders’ networks, agent implementation teams, support automation communities, and targeted outbound. Lead with a request to understand a recent deployment or refund workflow. Avoid pitching a universal security platform before hearing the problem.

### Interview questions

1. Walk through the last refund your agent attempted or was prevented from issuing.
2. Where was it stopped, who intervened, and how long did resolution take?
3. Which production system holds the authoritative transaction and eligibility data?
4. What can the agent do with its current credentials? Can it call the provider directly?
5. Which rules change often, and who is authorized to change them?
6. What failures have occurred, and what did recovery require?
7. What are monthly volume, handling time, approval rate, and existing engineering costs?
8. Why would you buy this instead of adding rules and approvals to your current application?
9. Who can fund a pilot, and what security and procurement steps precede it?
10. Will you provide a technical owner, sandbox access, anonymized examples, and written purchasing criteria?

Record observed facts separately from interpretations. “We care about trust” is weak evidence. A blocked funded rollout, named owner, integration commitment, and paid pilot are stronger evidence.

### Required discovery outputs

- Workflow map covering agents, humans, credentials, tools, and authoritative records.
- Baseline metrics and a customer-specific value estimate.
- List of policy examples, exceptions, and recovery scenarios.
- Purchasing map, objections, competing alternatives, and estimated integration effort.
- One-page product pitch and a clickable approval-flow mockup.
- A signed or explicitly agreed pilot scope for each committed partner.

### Gate A: proceed, narrow, or stop

Proceed when at least three organizations share the same substantive problem, two commit engineering time and sandbox access, and at least one accepts a paid pilot with measurable success criteria. These are proposed gates, not market benchmarks.

If interest exists but nobody commits resources, continue discovery rather than building the full platform. If integrations vary too much, narrow the customer profile. If native controls solve the problem adequately and buyers see no independent value, reconsider the wedge.

## 4. Positioning and competitive strategy

Authorization and agent security are existing categories. Cerbos describes an agent integration that evaluates identity, tool names, parameters, and context. Invariant publishes work on agent security and policy enforcement. These sources establish adjacent approaches; they do not establish either vendor’s complete current feature set. [Cerbos integration](https://www.cerbos.dev/blog/fine-grained-authorization-for-ai-agents-with-cerbos-and-aperture-by-tailscale), [Invariant research](https://invariantlabs.ai/blog/icml2024-agents-formal-security)

**Positioning hypothesis:** Customers will pay for a complete controlled execution workflow: policy decision, approval, budget reservation, provider execution, reconciliation, and evidence. Generic allow/deny alone is unlikely to establish sufficient differentiation.

| Alternative | What to test in discovery | Proposed reason to choose this product |
|---|---|---|
| Internal implementation | Build cost and maintenance burden | A supported workflow with tested failure recovery |
| General authorization engine | Whether decisions alone solve the need | Approval and execution lifecycle integrated with the provider |
| Gateway or security platform | Existing interception and governance coverage | Action-specific semantics and operational ownership |
| Provider-native controls | Coverage of the entire workflow | Consistent policy across agent, reviewer, and downstream action |
| Human review for every action | Cost, delay, error rate | Policy-bounded automation with exceptions routed to people |

Maintain a living competitive matrix based on demos, public documentation, and customer evaluations. Track deployment, identity, approvals, cumulative budgets, idempotency, reconciliation, evidence export, pricing, and integration effort. Mark unknowns explicitly.

Potential defensibility comes from reliable adapters, operational trust, distribution relationships, reusable workflow policies, and the cost of replacing a functioning control process. Do not assume a cross-customer data moat. Policy data can be sensitive and may not transfer between organizations; any learning across customers needs explicit contractual permission and an appropriate privacy design.

## 5. MVP scope

### Included

- One refund connector and a small set of read operations needed to validate eligibility.
- Authenticated workload identity, tenant isolation, and attribution to the initiating user where applicable.
- Provider credentials held by the execution service and inaccessible to the agent.
- Typed API for submit, inspect status, cancel before dispatch, and retrieve evidence.
- MCP adapter exposing the same constrained operations and permissions.
- Versioned deterministic rules with allow, deny, and require-approval outcomes.
- Per-action and cumulative monetary limits; rate limits as separate controls.
- Web approval queue, Slack notification, expiry, denial, and cancellation.
- Durable execution state, idempotency, and provider reconciliation.
- Searchable action history, structured exports, emergency stop, and operational alerts.

### Deferred

- Arbitrary HTTP forwarding, shell execution, browser automation, and arbitrary MCP servers.
- General prompt-injection detection or claims of complete prevention.
- Autonomous policy changes, model routing, and a standalone identity platform.
- Multiple refund providers, currencies requiring conversion, and complex multi-step compensation.
- Broad compliance certification claims, multi-region active-active operation, and customized on-premises deployments.

Basic secure reviewer authentication is required from the start. Integrate enterprise SSO during a pilot if required to validate reviewer identity and revocation; do not defer an essential control merely to preserve a pricing tier.

## 6. Architecture and enforcement boundary

```text
Agent / client
    | authenticated typed request
    v
Execution gateway ----> authoritative transaction context
    |
    +----> deterministic policy evaluator + versioned policy
    |
    +----> transactional state and monetary reservation ledger
    |
    +----> approval queue ----> authenticated reviewer
    |
    v
Constrained execution worker ----> refund provider
    ^                                  |
    |                                  v
    +-------- reconciliation / verified provider events

Every transition --> durable audit records --> customer evidence export
Admin console --> policy publishing, identities, credential rotation, stop controls
```

### Trust model

Treat model output, tool arguments, support-ticket text, and agent-provided identity claims as untrusted. Bind tenant and workload identity to verified authentication. Fetch refund eligibility and amounts from authoritative systems, not an agent’s explanation.

The service protects configured execution paths. It cannot guarantee control over credentials or tools outside its boundary. Before enabling a production agent, revoke its direct refund credentials, restrict provider permissions, and verify that alternate tools cannot invoke the same write path. Where relevant, enforce network egress restrictions and provider-side access constraints.

The provider remains authoritative for payment state. The customer remains responsible for policy intent and the approved human operating process. Human manual refunds require reconciliation or a separate allocation of budget; otherwise the gateway can enforce only its own spending, not an organization-wide cap.

MCP is an integration surface, not proof of complete mediation. Implement audience validation and distinct downstream credentials; MCP guidance forbids token passthrough and documents proxy-specific risks. Pin and test the supported protocol and SDK versions. [MCP security guidance](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)

### Implementation defaults

Use a modular service rather than early microservices. Choose a backend language the founding team can operate confidently. Use a relational database for action state, reservations, and a transactional outbox; use a managed secrets store and encrypted object storage for exports. A queue may schedule work but is not the authority for whether an action may execute.

Keep policy evaluation deterministic and independent of an LLM. Evaluate an existing policy engine against a small typed rule implementation during a short prototype. Choose based on policy expressiveness, explainability, versioning, latency, and maintenance—not on building a novel policy language.

## 7. Policy semantics and execution lifecycle

### Minimum policy inputs

Authenticated tenant and agent; delegated user if present; action type; provider account; transaction identifier; amount in integer minor units; currency; authoritative refundable balance; customer or account identifier; policy version; current budget usage; resource state and freshness; approval requirements.

Hard prohibitions take precedence over approvals. Missing or unverifiable required context blocks the protected action. An approval never grants additional provider scope or overrides a hard limit.

### Illustrative policy, to validate with partners

| Condition | Result |
|---|---|
| Agent disabled, wrong tenant/account, or unsupported operation | Deny |
| Refund exceeds remaining refundable amount | Deny |
| Refund redirects value outside the original payment route | Deny |
| Currency unsupported or required context unavailable | Block with a retryable or terminal reason as appropriate |
| Amount at most $50 and eligible under all other rules | Allow automatically |
| Amount above $50 and at most $500 | Require authorized support manager |
| Amount above $500 | Deny in MVP; route to existing manual process |
| Proposed action exceeds the configured cumulative cap | Block regardless of approval |

Thresholds are examples, not recommended refund policies. Specify time zone, rolling versus calendar windows, currency, scope, and reset behavior for every budget. Aggregate by customer/order as needed to prevent splitting one refund into smaller requests.

### Lifecycle

`received → validated → denied | pending_approval | ready`

`pending_approval → ready | rejected | expired | cancelled`

`ready → executing → succeeded | failed_confirmed | outcome_unknown`

`outcome_unknown → succeeded | failed_confirmed | manual_reconciliation`

Every transition is persisted and guarded against duplicate workers and stale updates. Provider acknowledgement of a pending refund is not final success; maintain a pending execution status until the provider confirms its outcome.

1. Authenticate and validate a strict request schema; reject unsupported fields and destinations.
2. Resolve the caller’s idempotency key within its tenant and workload scope. Repeated identical requests return the same action; changed parameters with the same key fail.
3. Fetch authoritative context and evaluate the currently published policy.
4. If approval is required, store an immutable action description and expiry. Do not reserve money indefinitely while waiting for a reviewer.
5. At dispatch, recheck identity, approval, current policy, resource state, and expiry. If a policy change affects the approval requirements, obtain a new approval. Tightened policy always takes effect before dispatch.
6. Atomically reserve available budget and transition to execution. Approval does not guarantee budget availability when execution starts.
7. Invoke the provider with a stable provider idempotency key derived from the action. Preserve the mapping across worker restarts and retries.
8. Commit spend on confirmed success; release reservations on confirmed non-execution. Keep reservations for uncertain outcomes and reconcile before retrying or releasing.

Use provider-supported preconditions and authoritative refundable-balance constraints where available. Serialize gateway actions for the same resource, but recognize that local locking cannot prevent external manual writes. Recheck provider state and document remaining races in the connector contract.

Do not promise universal exactly-once execution. Stripe documents idempotency behavior, including parameter comparison and key-retention behavior; implement and test the connector against those details. After the provider’s safe retry window, reconcile rather than blindly resend. [Stripe idempotency documentation](https://docs.stripe.com/api/idempotent_requests)

## 8. Approval experience

The reviewer sees the requesting agent and initiating user, original transaction, proposed amount and currency, current refundable balance, policy reason, cumulative exposure, and expiry. Render ticket excerpts as untrusted text; they cannot supply authoritative identity, eligibility, or instructions to the reviewer interface.

Bind approval to an immutable digest covering tenant, workload, action, destination/provider account, transaction, amount, currency, and relevant policy context. Changing execution parameters creates a new action. Persist the reviewer’s identity and authority at approval time and revalidate authority before dispatch.

Use Slack for notification and navigation to an authenticated approval screen in the MVP. An email or Slack link is not itself authorization. If interactive Slack approval is later added, verify signatures and replay protections, then separately verify tenant membership and approval authority. [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/)

Support deny reasons, expiration, escalation to a configured backup reviewer, and cancellation before dispatch. Never silently auto-approve on timeout. Concurrent approvals, deny/approve races, and duplicate callbacks must resolve through one authoritative state transition.

For the pilot, set a configurable approval lifetime, provisionally 30 minutes. Measure whether it fits operations. Display expired or already-executed actions clearly, and prevent link previews or GET requests from changing state.

## 9. Security, privacy, and evidence

### Required controls before production

- Tenant-scoped authorization on every request, database operation, queue job, export, and approval.
- Short-lived workload credentials where practical; rotation and revocation procedures.
- Minimal provider scopes, managed secret storage, encryption in transit and at rest.
- Distinct permissions for policy administrators, reviewers, operators, and read-only auditors.
- Reviewed policy changes, version history, simulation against recorded fixtures, and controlled publication.
- Strict provider destination allowlists; no arbitrary network proxy capability.
- Credential and sensitive-field redaction in logs, errors, notifications, and exports.
- Dependency and secret scanning, external security review of the production boundary, and documented incident handling.

### Audit record

Store action and correlation IDs, authenticated principals, normalized non-secret request fields, policy version and decision reasons, context provenance and timestamp, approval events, budget reservations, execution attempts, provider IDs, final outcome, and reconciliation events. Record denied requests as well as successful actions.

Use append-only application events and access-controlled storage, with independently retained exports or signed checkpoints where warranted. A hash chain alone does not establish trustworthy evidence if one administrator can rewrite both data and anchors. Log access, export, policy changes, and privileged operations.

Default to structured metadata rather than full prompts or ticket bodies. Agree retention before pilot launch; a provisional starting point is 90 days of searchable metadata with configurable archival. Define deletion, export, backup retention, residency, and incident-notification terms with each customer.

Provide an evidence package explaining control operation and limitations. Do not label exports “SOC 2 compliant” or “HIPAA compliant.” Any formal assurance or regulated deployment is a separate workstream with qualified reviewers and explicit scope. This plan makes no legal or certification determination.

## 10. Reliability and recovery

| Failure | Required behavior |
|---|---|
| Policy evaluation or required context unavailable | Block protected write; return an explicit reason |
| Approval service unavailable | Keep action pending; no implicit approval |
| Audit/state persistence unavailable | Do not dispatch a new protected write |
| External export service unavailable | Continue only if the local durable audit/outbox remains healthy |
| Provider times out after dispatch | Mark outcome unknown, retain reservation, reconcile |
| Worker crashes | Recover persisted state using stable idempotency keys and leases |
| Budget database unavailable | Block new monetary commitments |
| Credential revoked | Stop affected execution and alert the customer |
| Emergency stop activated | Prevent new dispatch; reconcile already-sent actions |

The pilot uses fail-closed behavior for protected writes. A documented manual process can preserve business continuity, but it uses separately authorized human credentials and records its actions for reconciliation.

Proposed engineering targets: less than 100 ms p95 gateway processing overhead excluding external API calls and human waiting; 99.9% monthly availability for the submit/status service after hardening; no loss of acknowledged action state within the defined single-region deployment failure model. Establish disaster-recovery targets separately—provisionally RPO at most 5 minutes and RTO at most 4 hours—and validate restore procedures before contractual commitments.

For disaster recovery, suspend affected execution until restored state is reconciled with provider records. Backup recovery must not result in replaying already-completed refunds. Publish benchmark workload, region, concurrency, and exclusions whenever reporting latency or availability.

## 11. Verification and production readiness

Test security invariants and failure recovery, not just happy-path examples.

| Test family | Required scenarios | Acceptance condition |
|---|---|---|
| Identity/isolation | Forged tenant, disabled agent, wrong reviewer, cross-tenant export | No unauthorized decision, disclosure, or execution |
| Policy | Boundary amounts, missing context, policy updates, split requests | Expected deterministic outcome and explainable reason |
| Concurrency | Simultaneous requests at cap, same-order partial refunds | No overcommit in gateway-controlled budgets |
| Approval | Changed amount, expired approval, replay, role revocation | No execution under invalid authorization |
| Execution | Duplicate delivery, timeout after success, worker restart | No duplicate refund in supported provider scenarios |
| Reconciliation | Delayed/duplicate events, manual provider changes | Correct final state and ledger adjustment |
| Bypass | Direct API, alternate tool, leaked agent environment | Agent cannot reach protected write using available credentials |
| Operations | Lost dependency, stop control, backup restoration | Safe blocked state and demonstrated recovery |

Use property-based tests for ledger and state-machine invariants, provider sandbox integration tests, and deliberate fault injection around dispatch and response persistence. Verify incoming provider events and treat duplicate or out-of-order delivery as normal.

Production gate: all supported critical scenarios pass, no unresolved critical/high security findings affecting the deployment, named incident owners, tested rotation and stop procedures, completed recovery drill, and written customer acceptance of the enforcement boundary. Passing tests establishes evidence within tested conditions, not a universal safety guarantee.

## 12. Design-partner program

Start with two partners in sandbox; cap concurrent early production pilots at three until support effort is understood. Recruit additional partners after the connector and onboarding process stabilize.

### Pilot structure: six to eight weeks

1. **Baseline and mapping:** Document workflow, current metrics, credential paths, and authorized rules.
2. **Sandbox:** Exercise policy fixtures, reviewer setup, and provider failure cases.
3. **Shadow evaluation:** Compare recommendations with human decisions; no control claim while the agent retains bypass paths.
4. **Restricted production:** Remove direct agent write access, enable low limits and narrow cohorts, and run daily reconciliation.
5. **Controlled expansion:** Increase limits only after joint review of outcomes and operational burden.
6. **Commercial review:** Compare agreed baseline with results and decide conversion or termination.

The pilot agreement specifies scope, fees, responsibilities, data handling, production limits, incident contacts, success criteria, conversion pricing, and offboarding. Case-study permission is separate and optional. Do not trade unlimited custom engineering for a logo.

### Success scorecard

| Metric | Proposed threshold | Measurement |
|---|---|---|
| Integration effort | At most five customer engineering days after prerequisites | Logged customer hours |
| Review workload | At least 30% reduction for policy-eligible cases | Baseline-adjusted manual-review rate |
| Control correctness | All agreed must-block cases blocked | Pre-production suite and production review |
| Unexplained outcomes | No aged unknown outcome beyond the agreed provider-specific window | Reconciliation queue |
| Approval handling | Meets customer-defined staffed-hours SLA | Median and p95 queue time |
| Customer value | Buyer validates measurable benefit | Written pilot review |
| Conversion | At least two of first three completed pilots pay to continue | Signed recurring agreement |

Adjust thresholds before a pilot starts, not afterward to declare success. Report denominators and sample sizes; low production volume cannot establish rare-failure rates.

## 13. Go-to-market and pricing experiments

Lead with a workflow-specific pitch: “Let your support agent complete approved refunds while your team controls limits and exceptions.” Demonstrate a permitted refund, an escalated refund, a denied refund, and a timeout recovered without duplication.

Build a founder-led prospect list of approximately 40 qualified accounts during discovery. Prioritize those with active agent deployment projects. Seek introductions through implementation consultancies and support automation vendors after early pilots demonstrate repeatability.

### Proposed pricing tests in USD

| Offer | Starting hypothesis | Boundary |
|---|---|---|
| Paid pilot | $3,000–$10,000 for six to eight weeks | One workflow/provider; fixed onboarding scope |
| Production | $1,500–$5,000 per month | Platform fee, included volume, agreed support |
| Additional usage | Test after measuring volume and unit costs | Transparent successful executed-action meter |
| Enterprise requirements | Quote after discovery | Additional environments, deployment or support commitments |

These are experiments, not researched market prices. Test willingness to pay against customer value and alternatives. Do not bill each retry, callback, or denial as a separate business action. Rate-limit abusive requests independently of commercial usage. Avoid per-agent pricing initially because agent identities can proliferate without corresponding value.

Illustrative value calculation: 5,000 monthly cases × 3 minutes saved ÷ 60 × $40 loaded hourly cost = $10,000 monthly handling capacity released. At a $2,500 subscription, that is a 4× gross capacity-to-fee ratio before integration and operating costs. It is not guaranteed cash savings; validate whether capacity is actually redeployed. Keep speculative avoided-loss estimates separate.

Track delivery cost by customer: infrastructure, event storage, vendor fees, onboarding, incident response, and support hours. Target a credible path above 70% gross margin for the standardized hosted product; do not hide ongoing integration work outside cost reporting.

## 14. Team, budget, and delivery roadmap

Assume a three-person initial team: a product/commercial founder, a backend/security engineer, and a full-stack/integration engineer. Add fractional security review and design/operations assistance where necessary. If the founder is also the lead engineer, reduce parallel commitments or extend the schedule.

Illustrative monthly cash plan: $45,000–$75,000 in loaded people costs, $2,000–$6,000 in infrastructure/tooling, and $3,000–$10,000 in specialist support and business expenses. With 20% contingency, plan roughly $60,000–$109,000 per month, or $360,000–$655,000 for six months before revenue. Geography, compensation, insurance, and procurement requirements may materially change this estimate. Update it with actual quotes and available runway before hiring.

| Period | Product/engineering work | Commercial work | Exit gate |
|---|---|---|---|
| Weeks 1–2 | Workflow and threat maps; sandbox feasibility | First 10 interviews; buyer mapping | Repeated problem and plausible integration |
| Weeks 3–4 | Approval mockup; connector spike; policy examples | Complete discovery; negotiate pilot | Gate A: committed partners and paid demand |
| Weeks 5–6 | Identity, secrets, typed API, action state, policy decisions | Baseline pilot metrics and security review | Authenticated sandbox execution |
| Weeks 7–8 | Approval binding, reservations, idempotency | Reviewer usability sessions | Core correctness and concurrency tests pass |
| Weeks 9–10 | Reconciliation, evidence export, alerts, stop controls | Complete deployment and support agreements | Failure drills pass |
| Weeks 11–12 | External review, restore drill, restricted production preparation | Launch first limited pilot if ready | Production readiness gate |
| Months 4–6 | Stabilize first connector and onboarding | Run and convert pilots; recruit next partners | 3–5 paid production customers as target; repeatability evidence |
| Months 7–9 | Add one adjacent action or connector if justified | Test channel/referral motion | Multiple customers request and fund the same expansion |
| Months 10–12 | Scale isolation, operations, enterprise features as needed | Validate renewals and expansion | Retained customers and sustainable delivery economics |

Security-critical work and stage gates take precedence over the calendar. Do not launch protected production writes merely because month three has arrived.

### Weekly operating cadence

- Product/commercial owner reviews pipeline, objections, conversion, and customer value.
- Engineering owner reviews correctness, unknown outcomes, availability, and vulnerabilities.
- Integration owner reviews onboarding effort, reviewer experience, and support burden.
- Team records decisions, evidence, changed assumptions, and the next experiment.

## 15. Expansion and open-source strategy

Expand in this order only when customer evidence supports it: additional refund rules; adjacent support actions such as credits or subscription changes; a second provider; then more general policy and evidence management.

An additional action requires a connector contract defining authoritative context, reversible and irreversible effects, idempotency support, approval semantics, and reconciliation. Reuse the execution framework, but do not assume refund semantics apply to every tool.

Publish the client SDK, MCP adapter, sample policies, local simulator, and documented schemas once stable. Retain one clearly supported hosted deployment path. Decide whether to open the core after testing whether self-hosting creates qualified adoption and whether the team can maintain secure release and upgrade processes. Obtain license review before making distribution commitments.

Policy recommendations can later run in review-only mode, backed by evidence and human approval. Anomaly detection is a separate product hypothesis. Broader prompt-injection defense should not become a prerequisite for selling deterministic action controls.

## 16. Risk register and stop conditions

| Risk | Early signal | Response | Owner |
|---|---|---|---|
| Weak demand | Praise without integration or payment | Narrow or change workflow before further build | Commercial |
| Easy substitution | Buyer can meet needs with native controls | Test complete execution value; avoid feature race | Product |
| Bypass | Agent still holds provider write access | Block production activation until boundary verified | Security/engineering |
| Duplicate or uncertain execution | Repeated unknown outcomes or retry ambiguity | Freeze affected connector and reconcile | Engineering |
| Approval fatigue | High escalation rate and slow reviewer response | Improve policy scope and reviewer routing | Product |
| Integration services trap | Each customer needs a separate implementation | Restrict supported stack and charge scoped services | Commercial/integration |
| Security incident | Suspected key exposure or cross-tenant access | Revoke, stop affected paths, preserve evidence, respond under agreed process | Security |
| Economic mismatch | Support cost overwhelms subscription value | Standardize, reprice, or decline unsuitable customers | Commercial |
| Premature expansion | New connectors requested by only one prospect | Require repeated paid demand before roadmap commitment | Product |

At day 30, revisit the wedge if no qualified partner will commit resources. At day 90, revisit feasibility if correct constrained execution is still not demonstrable. At month 6, reconsider the standalone business if paid conversions are weak, onboarding remains bespoke, or customers obtain equivalent value more easily elsewhere. A missed gate triggers a documented review; it does not automatically justify more feature work.

## 17. First ten working days

| Day | Deliverable | Owner |
|---|---|---|
| 1 | Assumption register, refund workflow sketch, qualification rubric | Product/commercial |
| 2 | Prospect list and interview outreach draft | Commercial |
| 3–4 | First five interviews; buyer and credential maps | Commercial + engineering |
| 5 | Discovery synthesis; top competing alternatives | Product |
| 6 | Prototype showing allow, approval, deny, and unknown outcome | Engineering/integration |
| 7 | Provider sandbox spike and initial connector limitations | Engineering |
| 8 | Pilot proposal, success scorecard, and price hypothesis | Commercial |
| 9 | Partner technical sessions and threat-boundary review | Engineering |
| 10 | Written decision: retain wedge, narrow it, or change it | Team |

The immediate outcome is a testable purchase proposition and a credible enforcement design. Start the production build only after the discovery gate supplies evidence to support it.

## 18. Source notes and open questions

Primary documentation was consulted for protocol security, provider retry behavior, Slack verification, and adjacent product positioning. This is a scoped landscape check, not an exhaustive market study. Technical specifications should be rechecked when implementing and version-pinned in the repository.

- [MCP security best practices](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices): proxy trust boundaries and credential handling.
- [Stripe idempotent requests](https://docs.stripe.com/api/idempotent_requests): connector retry requirements.
- [Slack request verification](https://docs.slack.dev/authentication/verifying-requests-from-slack/): authenticity checks for future interactive callbacks.
- [Cerbos agent authorization integration](https://www.cerbos.dev/blog/fine-grained-authorization-for-ai-agents-with-cerbos-and-aperture-by-tailscale): adjacent authorization approach.
- [Invariant agent security research](https://invariantlabs.ai/blog/icml2024-agents-formal-security): adjacent policy-enforcement research.

Questions to resolve through discovery: Who signs the contract? Which provider do the first two partners share? How much manual work can actually disappear? Can the customer remove every agent-controlled refund credential? What global spending limits must include manual activity? Which residency and authentication requirements are mandatory? What reliability commitments can the initial team support economically?
