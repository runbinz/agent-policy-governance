# Provisional Prometheus alerts

These rules implement the bounded metrics contract in `docs/contracts/metrics-v1.md` and software-plan section 13. Thresholds are engineering examples pending load tests and operating history; they are not availability commitments. They only evaluate alerts. There is no Alertmanager routing, external delivery, or automatic execution-control change here. Never release funds, retry an ambiguous charge, or clear a hold from an alert.

Load `observability/alerts.yml` through Prometheus `rule_files` for a single deployment/database environment. Do not combine unrelated environments under these global aggregations. Keep metrics endpoints protected with their configured token and use explicit loopback worker listeners. Supply separate scrape targets for API and worker processes. Prometheus adds scrape metadata; rule output intentionally removes it and exposes only alert name and fixed severity for global rules. The configured-target health rule retains infrastructure job and instance labels; these identify services, never business entities.

| Alert | Provisional condition | Sustained for |
| --- | --- | --- |
| Business collector down | Any reported collector down, or all collector series absent | 2 minutes |
| Business snapshot stale | Latest global sample older than 120 seconds, or timestamp absent | 2 minutes |
| Unresolved backlog age | Unknown/manual-review backlog exists and oldest unresolved age >15 minutes | 5 minutes |
| Approval backlog age | Pending approvals exist and oldest age >1 hour | 5 minutes |
| Ready queue lag | Ready jobs exist and oldest lag >2 minutes | 5 minutes |
| Notification failures | Retained terminal failure count >0 | 5 minutes |
| Stale dispatch leases | Expired dispatch lease count >0 (active leases are excluded) | 2 minutes |
| External-ready queue lag | Available external dispatches exist and oldest lag >5 minutes | 5 minutes |
| Configured target down | `up{job=~"apl-api|apl-worker"} == 0`, evaluated per scrape target | 2 minutes |
| Unknown age records | Retained unknown-age count >0 | 5 minutes |
| Provider/reconcile indeterminate fraction | Unknown + timeout >10% with ≥20 calls in a rolling 5-minute window, combined for context + execute; separately for reconcile | 5 minutes |
| Internal dispatch p95 | Histogram p95 >100 ms with ≥20 internal dispatch observations per 5 minutes | 5 minutes |

Global database snapshots are duplicated across replicas: gauges use `max`, never `sum`. Collector health uses `min` so one failed collector remains visible even if another is healthy. Process counters/histograms aggregate across processes with `increase`/`rate`, preserving reset handling. Decision counts are retained-row gauges, not counters, and are not used as rates. No tenant, action, customer, channel, namespace, key, URI value, or raw error labels are introduced.

Unknown ages are omitted by the collector rather than represented as zero. The unknown-age alert catches this blind spot; fresh valid ages alone do not prove all records are covered. Business alerts may continue from retained snapshots after collection fails; the collector and staleness alerts identify that loss of freshness. Missing workload series and zero traffic do not trigger rate/latency/backlog alerts; missing business collector data intentionally does trigger health alerts. The configured-target rule detects failed scrapes separately from global snapshot freshness, so a failed worker target remains visible while an API replica is healthy. Keep the scrape job names `apl-api` and `apl-worker`. A removed or never-configured target has no `up` series and cannot be identified by this rule; maintain deployment-specific expected-target inventory monitoring separately. Global aggregate rules cannot identify one vanished target while other replicas remain healthy.

A confirmed provider business failure or verified ineligible charge is excluded from the indeterminate numerator. Unknown/timeout outcomes need reconciliation and evidence review. Notification failures count retained terminal failures and can remain elevated until the durable state changes; they are not a monotonic notification error rate. The internal dispatch histogram excludes provider network time and human waiting.

Validate with a pinned official Prometheus `promtool` binary (CI owns the version):

```sh
promtool check rules observability/alerts.yml
(cd observability && promtool test rules alerts.test.yml)
```

Synthetic tests cover absent/healthy collectors, zero traffic, sustained firing, duplicate global gauges, and minimum provider volume, context lookup ambiguity, verified context ineligibility, stale versus active leases, external-ready lag thresholds and duplicate snapshots, failed worker scrapes alongside healthy APIs, and absent/removed target inventory limits. See the official [rule test format](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/) and [alerting rule semantics](https://prometheus.io/docs/prometheus/latest/configuration/alerting_rules/). These fixtures verify rule behavior, not production instrumentation, delivery, capacity, or execution safety.
