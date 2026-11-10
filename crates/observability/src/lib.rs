//! Private background collector; no database call is performed by a scrape.
use apl_persistence::Store;
use apl_telemetry::{BusinessSnapshot, DecisionCount, Metrics};
use std::{sync::Arc, time::Duration};

pub async fn collect(store: &Store, metrics: &Metrics) {
    match tokio::time::timeout(Duration::from_secs(10), store.service_metrics()).await {
        Ok(Ok(s)) => metrics.set_business(BusinessSnapshot {
            sampled_at_unix: s.sampled_at_unix,
            held_minor: s.held_minor,
            committed_today_minor: s.committed_today_minor,
            pending_approvals: s.pending_approvals,
            oldest_approval_age_seconds: s.oldest_approval_age_seconds,
            unknown_outcomes: s.unknown_outcomes,
            pending_provider: s.pending_provider,
            manual_review: s.manual_review,
            oldest_unresolved_age_seconds: s.oldest_unresolved_age_seconds,
            ready_jobs: s.ready_jobs,
            oldest_ready_lag_seconds: s.oldest_ready_lag_seconds,
            failed_notifications: s.failed_notifications,
            unknown_age_records: s.unknown_age_records,
            stale_dispatch_leases: s.stale_dispatch_leases,
            ready_external_dispatches: s.ready_external_dispatches,
            oldest_external_ready_lag_seconds: s.oldest_external_ready_lag_seconds,
            decisions: s
                .decisions
                .into_iter()
                .map(|d| DecisionCount {
                    outcome: d.outcome,
                    reason: d.reason,
                    count: d.count,
                })
                .collect(),
        }),
        _ => metrics.business_failed(),
    }
}
pub fn start(store: Store, metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        loop {
            collect(&store, &metrics).await;
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}
