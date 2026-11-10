//! Redacted connection operations, independently authorized from review/control.
use crate::{Result, Store, StoreError};
use apl_domain::Reviewer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OperationsSnapshot {
    pub connection_id: Uuid,
    pub sampled_at_unix: i64,
    pub tenant_paused: bool,
    pub connection_paused: bool,
    pub workloads_paused: i64,
    pub pending_approvals: i64,
    pub oldest_approval_age_seconds: Option<i64>,
    pub held_minor: i64,
    pub committed_today_minor: i64,
    pub daily_used_minor: i64,
    pub daily_limit_minor: Option<i64>,
    pub exposure_limit_minor: Option<i64>,
    pub unknown_outcomes: i64,
    pub pending_provider: i64,
    pub manual_review: i64,
    pub oldest_unresolved_age_seconds: Option<i64>,
    pub ready_jobs: i64,
    pub oldest_ready_lag_seconds: Option<i64>,
    pub failed_notifications: i64,
    pub queued_notifications: i64,
    pub failed_exports: i64,
    pub unknown_age_records: i64,
}
impl Store {
    pub async fn operations_snapshot(
        &self,
        reviewer: &Reviewer,
        connection_id: Uuid,
    ) -> Result<OperationsSnapshot> {
        let mut tx = self.pool.begin().await.map_err(redact)?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await
            .map_err(redact)?;
        sqlx::query(
            "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
        )
        .bind(reviewer.tenant_id.to_string())
        .bind(reviewer.environment_id.to_string())
        .execute(&mut *tx)
        .await
        .map_err(redact)?;
        let value: serde_json::Value = sqlx::query_scalar("SELECT read_operations($1,$2,$3,$4)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(redact)?;
        let allowed: bool = sqlx::query_scalar("SELECT authorize_operations($1,$2,$3,$4)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(redact)?;
        if !allowed {
            return Err(StoreError::NotFound);
        }
        let snapshot = serde_json::from_value(value)?;
        tx.commit().await.map_err(redact)?;
        Ok(snapshot)
    }
}
fn redact(error: sqlx::Error) -> StoreError {
    if error.as_database_error().and_then(|e| e.code()).as_deref() == Some("AP404") {
        StoreError::NotFound
    } else {
        StoreError::Database(error)
    }
}
