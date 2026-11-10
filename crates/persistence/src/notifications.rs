//! Fenced notification delivery. Transactions end before any network request.
use crate::{Result, Store, StoreError};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NotificationLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub connection_id: Uuid,
    pub action_id: Uuid,
    pub route_id: Uuid,
    pub approval_generation: i64,
    pub generation: i64,
    pub kind: String,
    pub team_id: Option<String>,
    pub channel_id: Option<String>,
    pub expires_at_unix: i64,
}

impl Store {
    pub async fn claim_notification(
        &self,
        route_id: Uuid,
        kind: &str,
    ) -> Result<Option<NotificationLease>> {
        if !["fake", "slack"].contains(&kind) {
            return Err(StoreError::Invalid("invalid notification kind".into()));
        }
        let mut tx = self.notification_tx().await?;
        // Commit obsolete-route cleanup before acquiring a different route.
        sqlx::query("SELECT cleanup_obsolete_notification_jobs()")
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await?;
        let mut tx = self.notification_tx().await?;
        let row = sqlx::query("SELECT * FROM claim_notification($1,$2)")
            .bind(route_id)
            .bind(kind)
            .fetch_optional(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await?;
        Ok(row.map(|r| NotificationLease {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            environment_id: r.get("environment_id"),
            connection_id: r.get("connection_id"),
            action_id: r.get("action_id"),
            route_id: r.get("route_id"),
            approval_generation: r.get("approval_generation"),
            generation: r.get("generation"),
            kind: r.get("kind"),
            team_id: r.get("team_id"),
            channel_id: r.get("channel_id"),
            expires_at_unix: r.get("expires_at_unix"),
        }))
    }
    pub async fn notification_preflight(&self, lease: &NotificationLease) -> Result<bool> {
        let mut tx = self.notification_tx().await?;
        let result = sqlx::query_scalar("SELECT notification_preflight($1)")
            .bind(serde_json::to_value(lease)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn record_fake_notification(&self, lease: &NotificationLease) -> Result<bool> {
        let mut tx = self.notification_tx().await?;
        let result = sqlx::query_scalar("SELECT record_fake_notification($1)")
            .bind(serde_json::to_value(lease)?)
            .fetch_one(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn finish_notification(
        &self,
        lease: &NotificationLease,
        outcome: &str,
        retry_after_seconds: i64,
    ) -> Result<()> {
        if !["delivered", "retry", "failed"].contains(&outcome)
            || !(0..=86400).contains(&retry_after_seconds)
        {
            return Err(StoreError::Invalid("invalid notification outcome".into()));
        }
        let mut tx = self.notification_tx().await?;
        sqlx::query("SELECT finish_notification($1,$2,$3)")
            .bind(serde_json::to_value(lease)?)
            .bind(outcome)
            .bind(retry_after_seconds)
            .execute(&mut *tx)
            .await
            .map_err(error)?;
        tx.commit().await?;
        Ok(())
    }

    async fn notification_tx(&self) -> Result<Transaction<'static, Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }
}
fn error(e: sqlx::Error) -> StoreError {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP409") => StoreError::Conflict,
        Some("AP400") => StoreError::Invalid("invalid notification operation".into()),
        _ => StoreError::Database(e),
    }
}
