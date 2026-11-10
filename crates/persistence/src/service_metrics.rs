//! Private process collector snapshot; never expose through a tenant API.
use crate::{Result, Store};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionCount {
    pub outcome: String,
    pub reason: String,
    pub count: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceMetrics {
    pub sampled_at_unix: i64,
    pub held_minor: i64,
    pub committed_today_minor: i64,
    pub pending_approvals: i64,
    pub oldest_approval_age_seconds: Option<i64>,
    pub unknown_outcomes: i64,
    pub pending_provider: i64,
    pub manual_review: i64,
    pub oldest_unresolved_age_seconds: Option<i64>,
    pub ready_jobs: i64,
    pub stale_dispatch_leases: i64,
    pub ready_external_dispatches: i64,
    pub oldest_external_ready_lag_seconds: Option<i64>,
    pub oldest_ready_lag_seconds: Option<i64>,
    pub failed_notifications: i64,
    pub unknown_age_records: i64,
    pub decisions: Vec<DecisionCount>,
}

impl Store {
    pub async fn service_metrics(&self) -> Result<ServiceMetrics> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        let value: serde_json::Value = sqlx::query_scalar("SELECT read_service_metrics()")
            .fetch_one(&mut *tx)
            .await?;
        let snapshot = serde_json::from_value(value)?;
        tx.commit().await?;
        Ok(snapshot)
    }
}
