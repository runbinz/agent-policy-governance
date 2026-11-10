use super::{Metrics, Observation, BUCKETS};
use std::{collections::BTreeMap, fmt::Write, time::Duration};

macro_rules! labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name { fn label(self) -> &'static str { match self { $(Self::$variant => $label),+ } } }
    };
}
labels!(WorkerQueue { Dispatch => "dispatch", Notifications => "notifications", Exports => "exports", ExportCleanup => "export_cleanup" });
labels!(TickResult { Worked => "worked", Idle => "idle", Error => "error" });
labels!(ProviderOperation { Context => "context", Execute => "execute", Reconcile => "reconcile" });
labels!(ProviderResult { Succeeded => "succeeded", FailedConfirmed => "failed_confirmed", Pending => "pending", Unknown => "unknown", Timeout => "timeout", Ineligible => "ineligible" });

#[derive(Clone, Debug, Default)]
pub struct DecisionCount {
    pub outcome: String,
    pub reason: String,
    pub count: i64,
}

/// Global retained-row gauges. Unknown ages must be represented as `None`.
#[derive(Clone, Debug, Default)]
pub struct BusinessSnapshot {
    pub sampled_at_unix: i64,
    pub held_minor: i64,
    pub committed_today_minor: i64,
    pub pending_approvals: i64,
    pub oldest_approval_age_seconds: Option<i64>,
    pub unknown_outcomes: i64,
    pub pending_provider: i64,
    pub manual_review: i64,
    pub oldest_unresolved_age_seconds: Option<i64>,
    pub stale_dispatch_leases: i64,
    pub ready_external_dispatches: i64,
    pub oldest_external_ready_lag_seconds: Option<i64>,
    pub ready_jobs: i64,
    pub oldest_ready_lag_seconds: Option<i64>,
    pub failed_notifications: i64,
    pub unknown_age_records: i64,
    pub decisions: Vec<DecisionCount>,
}

const REASONS: [&str; 14] = [
    "POLICY_AUTO_ALLOW",
    "APPROVAL_REQUIRED",
    "APPROVAL_SATISFIED",
    "POLICY_HARD_LIMIT",
    "INVALID_POLICY",
    "INVALID_REQUEST",
    "NO_ACTIVE_POLICY",
    "AUTHORIZATION_REVOKED",
    "APPROVAL_EXPIRED",
    "BUDGET_DAILY_EXCEEDED",
    "BUDGET_EXPOSURE_EXCEEDED",
    "BUDGET_NOT_CONFIGURED",
    "PROVIDER_CHARGE_INELIGIBLE",
    "OTHER",
];

#[derive(Default)]
pub(super) struct Runtime {
    workers: BTreeMap<(&'static str, &'static str), Observation>,
    providers: BTreeMap<(&'static str, &'static str), Observation>,
    dispatch: Observation,
    snapshot: Option<BusinessSnapshot>,
    decisions: BTreeMap<(&'static str, &'static str), i64>,
    up: bool,
}

impl Observation {
    fn observe(&mut self, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        self.count = self.count.saturating_add(1);
        self.sum = (self.sum + seconds).min(f64::MAX);
        for (i, bound) in BUCKETS.iter().enumerate() {
            if seconds <= *bound {
                self.buckets[i] = self.buckets[i].saturating_add(1);
            }
        }
    }
    fn histogram(&self, out: &mut String, name: &str, labels: &str) {
        let separator = if labels.is_empty() { "" } else { "," };
        for (bound, count) in BUCKETS.iter().zip(self.buckets) {
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels}{separator}le=\"{bound}\"}} {count}"
            );
        }
        let _ = writeln!(
            out,
            "{name}_bucket{{{labels}{separator}le=\"+Inf\"}} {}",
            self.count
        );
        let suffix = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{labels}}}")
        };
        let _ = writeln!(
            out,
            "{name}_count{suffix} {}\n{name}_sum{suffix} {}",
            self.count, self.sum
        );
    }
}

impl Metrics {
    pub fn record_worker_tick(&self, queue: WorkerQueue, result: TickResult, elapsed: Duration) {
        self.data
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .runtime
            .workers
            .entry((queue.label(), result.label()))
            .or_default()
            .observe(elapsed);
    }
    pub fn record_provider_call(
        &self,
        operation: ProviderOperation,
        result: ProviderResult,
        elapsed: Duration,
    ) {
        self.data
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .runtime
            .providers
            .entry((operation.label(), result.label()))
            .or_default()
            .observe(elapsed);
    }
    /// Measures internal work only; callers must exclude provider and human waiting.
    pub fn record_internal_dispatch(&self, elapsed: Duration) {
        self.data
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .runtime
            .dispatch
            .observe(elapsed);
    }
    pub fn set_business(&self, mut snapshot: BusinessSnapshot) {
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let runtime = &mut data.runtime;
        runtime.decisions.clear();
        // Canonical static labels limit retained cardinality to 4 × 14, regardless of input size.
        for decision in snapshot.decisions.drain(..) {
            let outcome = match decision.outcome.as_str() {
                "allow" => "allow",
                "require_approval" => "require_approval",
                "deny" => "deny",
                _ => "other",
            };
            let reason = REASONS
                .iter()
                .copied()
                .find(|reason| *reason == decision.reason)
                .unwrap_or("OTHER");
            let count = runtime.decisions.entry((outcome, reason)).or_default();
            *count = count.saturating_add(decision.count.max(0));
        }
        // Do not retain the allocation (or any untrusted label strings) from the caller.
        snapshot.decisions = Vec::new();
        runtime.snapshot = Some(snapshot);
        runtime.up = true;
    }
    pub fn business_failed(&self) {
        self.data
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .runtime
            .up = false;
    }
}

impl Runtime {
    pub(super) fn render(&self, out: &mut String) {
        for (name, series, first, second) in [
            ("apl_worker", &self.workers, "queue", "result"),
            ("apl_provider", &self.providers, "operation", "outcome"),
        ] {
            let counter = if name == "apl_worker" {
                "ticks"
            } else {
                "calls"
            };
            let duration = if name == "apl_worker" { "tick" } else { "call" };
            let _ = writeln!(out, "# TYPE {name}_{counter}_total counter\n# TYPE {name}_{duration}_duration_seconds histogram");
            for ((a, b), observation) in series {
                let labels = format!("{first}=\"{a}\",{second}=\"{b}\"");
                let _ = writeln!(
                    out,
                    "{name}_{counter}_total{{{labels}}} {}",
                    observation.count
                );
                observation.histogram(out, &format!("{name}_{duration}_duration_seconds"), &labels);
            }
        }
        out.push_str("# TYPE apl_internal_dispatch_duration_seconds histogram\n");
        self.dispatch
            .histogram(out, "apl_internal_dispatch_duration_seconds", "");
        gauge(out, "apl_business_collector_up", i64::from(self.up));
        if let Some(s) = &self.snapshot {
            for (name, value) in [
                ("apl_business_sample_timestamp_seconds", s.sampled_at_unix),
                ("apl_budget_held_minor", s.held_minor),
                ("apl_budget_committed_today_minor", s.committed_today_minor),
                ("apl_pending_approvals", s.pending_approvals),
                ("apl_unknown_outcomes", s.unknown_outcomes),
                ("apl_pending_provider", s.pending_provider),
                ("apl_manual_review", s.manual_review),
                ("apl_ready_jobs", s.ready_jobs),
                ("apl_stale_dispatch_leases", s.stale_dispatch_leases),
                ("apl_ready_external_dispatches", s.ready_external_dispatches),
                ("apl_notification_failures", s.failed_notifications),
                ("apl_unknown_age_records", s.unknown_age_records),
            ] {
                gauge(out, name, value);
            }
            for (name, value) in [
                (
                    "apl_oldest_approval_age_seconds",
                    s.oldest_approval_age_seconds,
                ),
                (
                    "apl_oldest_unresolved_age_seconds",
                    s.oldest_unresolved_age_seconds,
                ),
                ("apl_oldest_ready_lag_seconds", s.oldest_ready_lag_seconds),
                (
                    "apl_oldest_external_ready_lag_seconds",
                    s.oldest_external_ready_lag_seconds,
                ),
            ] {
                if let Some(value) = value {
                    gauge(out, name, value);
                }
            }
        }
        out.push_str("# TYPE apl_policy_decisions gauge\n");
        for ((outcome, reason), count) in &self.decisions {
            let _ = writeln!(
                out,
                "apl_policy_decisions{{outcome=\"{outcome}\",reason=\"{reason}\"}} {count}"
            );
        }
    }
}
fn gauge(out: &mut String, name: &str, value: i64) {
    let _ = writeln!(out, "# TYPE {name} gauge\n{name} {}", value.max(0));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn metrics() -> std::sync::Arc<Metrics> {
        Metrics::new("0123456789abcdef0123456789abcdef").unwrap()
    }

    #[test]
    fn typed_counters_histograms_and_all_provider_outcomes() {
        let m = metrics();
        m.record_worker_tick(
            WorkerQueue::Dispatch,
            TickResult::Worked,
            Duration::from_millis(3),
        );
        m.record_worker_tick(
            WorkerQueue::Dispatch,
            TickResult::Worked,
            Duration::from_millis(20),
        );
        for queue in [
            WorkerQueue::Notifications,
            WorkerQueue::Exports,
            WorkerQueue::ExportCleanup,
        ] {
            for result in [TickResult::Worked, TickResult::Idle, TickResult::Error] {
                m.record_worker_tick(queue, result, Duration::ZERO);
            }
        }
        for op in [ProviderOperation::Execute, ProviderOperation::Reconcile] {
            for result in [
                ProviderResult::Succeeded,
                ProviderResult::FailedConfirmed,
                ProviderResult::Pending,
                ProviderResult::Unknown,
                ProviderResult::Timeout,
            ] {
                m.record_provider_call(op, result, Duration::from_millis(5));
            }
        }
        m.record_internal_dispatch(Duration::MAX);
        let text = m.render();
        assert!(text.contains("apl_worker_ticks_total{queue=\"dispatch\",result=\"worked\"} 2"));
        assert!(text.contains("apl_worker_tick_duration_seconds_bucket{queue=\"dispatch\",result=\"worked\",le=\"0.005\"} 1"));
        assert!(text.contains("apl_worker_tick_duration_seconds_bucket{queue=\"dispatch\",result=\"worked\",le=\"0.025\"} 2"));
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("apl_provider_calls_total{"))
                .count(),
            10
        );
        assert!(text
            .contains("apl_provider_calls_total{operation=\"reconcile\",outcome=\"timeout\"} 1"));
        let data = m.data.lock().unwrap();
        assert!(data.runtime.dispatch.sum.is_finite());
        assert!((data.runtime.workers[&("dispatch", "worked")].sum - 0.023).abs() < 1e-10);
    }

    #[test]
    fn context_verification_has_distinct_bounded_outcomes() {
        let m = metrics();
        for result in [
            ProviderResult::Succeeded,
            ProviderResult::Ineligible,
            ProviderResult::Unknown,
        ] {
            m.record_provider_call(
                ProviderOperation::Context,
                result,
                Duration::from_millis(10),
            );
        }
        let text = m.render();
        for outcome in ["succeeded", "ineligible", "unknown"] {
            assert!(text.contains(&format!(
                "apl_provider_calls_total{{operation=\"context\",outcome=\"{outcome}\"}} 1"
            )));
            assert!(text.contains(&format!("apl_provider_call_duration_seconds_count{{operation=\"context\",outcome=\"{outcome}\"}} 1")));
        }
        assert!(!text.contains("operation=\"execute\""));
        assert!(!text.contains("operation=\"reconcile\""));
    }

    #[test]
    fn business_failure_retains_last_snapshot_and_unknown_ages_are_absent() {
        let m = metrics();
        assert!(m.render().contains("apl_business_collector_up 0"));
        assert!(!m
            .render()
            .contains("apl_business_sample_timestamp_seconds "));
        m.business_failed();
        m.set_business(BusinessSnapshot {
            sampled_at_unix: 100,
            held_minor: 25,
            oldest_approval_age_seconds: Some(9),
            unknown_age_records: 2,
            decisions: vec![DecisionCount {
                outcome: "allow".into(),
                reason: "POLICY_AUTO_ALLOW".into(),
                count: 4,
            }],
            ..Default::default()
        });
        let healthy = m.render();
        assert!(healthy.contains("apl_business_collector_up 1"));
        assert!(healthy.contains("apl_oldest_approval_age_seconds 9"));
        assert!(!healthy.contains("apl_oldest_unresolved_age_seconds"));
        assert!(!healthy.contains("apl_oldest_ready_lag_seconds"));
        m.business_failed();
        assert_eq!(
            healthy.replace("apl_business_collector_up 1", "apl_business_collector_up 0"),
            m.render()
        );
        m.set_business(BusinessSnapshot::default());
        assert!(!m.render().contains("apl_oldest_approval_age_seconds"));
        assert!(!m.render().contains("outcome=\"allow\""));
    }

    #[test]
    fn external_dispatch_backlog_gauges_preserve_unknown_and_failed_samples() {
        let m = metrics();
        m.set_business(BusinessSnapshot {
            stale_dispatch_leases: 2,
            ready_external_dispatches: 3,
            oldest_external_ready_lag_seconds: Some(60),
            ..Default::default()
        });
        let healthy = m.render();
        assert!(healthy.contains("apl_stale_dispatch_leases 2"));
        assert!(healthy.contains("apl_ready_external_dispatches 3"));
        assert!(healthy.contains("apl_oldest_external_ready_lag_seconds 60"));
        m.business_failed();
        assert_eq!(
            healthy.replace("apl_business_collector_up 1", "apl_business_collector_up 0"),
            m.render()
        );
        m.set_business(BusinessSnapshot {
            stale_dispatch_leases: -1,
            ready_external_dispatches: -2,
            ..Default::default()
        });
        let unknown = m.render();
        assert!(unknown.contains("apl_stale_dispatch_leases 0"));
        assert!(unknown.contains("apl_ready_external_dispatches 0"));
        assert!(!unknown.contains("apl_oldest_external_ready_lag_seconds"));
    }

    #[test]
    fn malformed_values_and_injected_labels_are_bounded() {
        let m = metrics();
        let mut decisions = Vec::new();
        for i in 0..10000 {
            decisions.push(DecisionCount {
                outcome: format!("private-{i}\"\nINJECT"),
                reason: format!("secret-{i}"),
                count: i64::MAX,
            });
        }
        decisions.push(DecisionCount {
            outcome: "allow".into(),
            reason: "POLICY_AUTO_ALLOW".into(),
            count: -99,
        });
        m.set_business(BusinessSnapshot {
            sampled_at_unix: -1,
            held_minor: -2,
            oldest_ready_lag_seconds: Some(-3),
            decisions,
            ..Default::default()
        });
        let text = m.render();
        assert!(!text.contains("private-"));
        assert!(!text.contains("secret-"));
        assert!(!text.contains("INJECT"));
        assert!(text.contains(
            "apl_policy_decisions{outcome=\"other\",reason=\"OTHER\"} 9223372036854775807"
        ));
        assert!(
            text.contains("apl_policy_decisions{outcome=\"allow\",reason=\"POLICY_AUTO_ALLOW\"} 0")
        );
        assert!(text.contains("apl_budget_held_minor 0"));
        assert!(text.contains("apl_oldest_ready_lag_seconds 0"));
        let data = m.data.lock().unwrap();
        assert_eq!(data.runtime.decisions.len(), 2);
        assert_eq!(
            data.runtime.snapshot.as_ref().unwrap().decisions.capacity(),
            0
        );
    }
}
