//! Scoped asynchronous evidence exports. Object encryption and I/O are separate.
use crate::{context, Result, Store, StoreError};
use apl_domain::Reviewer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use std::collections::HashSet;
use uuid::Uuid;

pub const MAX_EXPORT_BYTES: usize = 20 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportInfo {
    pub id: Uuid,
    pub connection_id: Uuid,
    pub status: String,
    pub expires_at: String,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub connection_id: Uuid,
    pub requester_id: Uuid,
    pub generation: i64,
}

impl Store {
    pub async fn request_export(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        action_ids: &[Uuid],
    ) -> Result<ExportInfo> {
        if action_ids.is_empty()
            || action_ids.len() > 1000
            || action_ids.iter().collect::<HashSet<_>>().len() != action_ids.len()
        {
            return Err(StoreError::Invalid(
                "select 1 to 1000 unique action IDs".into(),
            ));
        }
        let id = Uuid::new_v4();
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT request_evidence_export($1,$2,$3,$4,$5,$6)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection)
            .bind(id)
            .bind(action_ids)
            .execute(&mut *tx)
            .await
            .map_err(export_error)?;
        let row = read(&mut tx, reviewer, id, false).await?;
        let info = info(&row);
        tx.commit().await?;
        Ok(info)
    }

    pub async fn export_info(&self, reviewer: &Reviewer, id: Uuid) -> Result<ExportInfo> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let row = read(&mut tx, reviewer, id, false).await?;
        let result = info(&row);
        tx.commit().await?;
        Ok(result)
    }

    pub async fn download_export_lease(
        &self,
        reviewer: &Reviewer,
        id: Uuid,
    ) -> Result<ExportLease> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let row = read(&mut tx, reviewer, id, true).await?;
        let result = ExportLease {
            id,
            tenant_id: reviewer.tenant_id,
            environment_id: reviewer.environment_id,
            connection_id: row.get("connection_id"),
            requester_id: reviewer.reviewer_id,
            generation: row.get("generation"),
        };
        tx.commit().await?;
        Ok(result)
    }

    pub async fn record_export_download(&self, reviewer: &Reviewer, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT record_evidence_download($1,$2,$3,$4)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(export_error)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn claim_export(&self) -> Result<Option<ExportLease>> {
        let row = sqlx::query("SELECT * FROM claim_evidence_export()")
            .fetch_optional(&self.pool)
            .await
            .map_err(export_error)?;
        Ok(row.map(|r| ExportLease {
            id: r.get("id"),
            tenant_id: r.get("tenant_id"),
            environment_id: r.get("environment_id"),
            connection_id: r.get("connection_id"),
            requester_id: r.get("requester_id"),
            generation: r.get("generation"),
        }))
    }

    /// Capture a consistent read-only evidence view. Runtime code cannot choose
    /// columns; SQL constructs a fixed redacted schema and enforces a byte limit.
    pub async fn export_snapshot(&self, lease: &ExportLease) -> Result<Value> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            .execute(&mut *tx)
            .await?;
        sqlx::query("SET LOCAL statement_timeout='15s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, lease.tenant_id, lease.environment_id).await?;
        let snapshot: Value =
            sqlx::query_scalar("SELECT snapshot_evidence_export($1,$2,$3,$4,$5,$6)")
                .bind(lease.tenant_id)
                .bind(lease.environment_id)
                .bind(lease.requester_id)
                .bind(lease.connection_id)
                .bind(lease.id)
                .bind(lease.generation)
                .fetch_one(&mut *tx)
                .await
                .map_err(export_error)?;
        if serde_json::to_vec(&snapshot)?.len() > MAX_EXPORT_BYTES {
            return Err(StoreError::Invalid("export_too_large".into()));
        }
        tx.commit().await?;
        Ok(snapshot)
    }

    /// Call only after the encrypted object for this exact generation is durable.
    pub async fn complete_export(&self, lease: &ExportLease) -> Result<()> {
        self.finish_export(lease, "ready", None).await
    }

    pub async fn fail_export(&self, lease: &ExportLease, error_code: &str) -> Result<()> {
        if !["export_too_large", "snapshot_failed", "object_write_failed"].contains(&error_code) {
            return Err(StoreError::Invalid("invalid export failure code".into()));
        }
        self.finish_export(lease, "failed", Some(error_code)).await
    }

    pub async fn retry_export(&self, lease: &ExportLease) -> Result<()> {
        self.finish_export(lease, "retry", None).await
    }

    async fn finish_export(
        &self,
        lease: &ExportLease,
        status: &str,
        code: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, lease.tenant_id, lease.environment_id).await?;
        sqlx::query("SELECT finish_evidence_export($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(lease.tenant_id)
            .bind(lease.environment_id)
            .bind(lease.requester_id)
            .bind(lease.connection_id)
            .bind(lease.id)
            .bind(lease.generation)
            .bind(status)
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(export_error)?;
        tx.commit().await?;
        Ok(())
    }
}

async fn read(
    tx: &mut Transaction<'_, Postgres>,
    r: &Reviewer,
    id: Uuid,
    download: bool,
) -> Result<PgRow> {
    sqlx::query("SELECT * FROM read_evidence_export($1,$2,$3,$4,$5)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .bind(id)
        .bind(download)
        .fetch_one(&mut **tx)
        .await
        .map_err(export_error)
}
fn info(row: &PgRow) -> ExportInfo {
    ExportInfo {
        id: row.get("id"),
        connection_id: row.get("connection_id"),
        status: row.get("status"),
        expires_at: row.get("expires_at"),
        error_code: row.get("error_code"),
    }
}
fn export_error(error: sqlx::Error) -> StoreError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP404") => StoreError::NotFound,
        Some("AP409") => StoreError::Conflict,
        Some("AP400") => StoreError::Invalid("invalid export request".into()),
        Some("AP413") => StoreError::Invalid("export_too_large".into()),
        _ => StoreError::Database(error),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportCleanupLease {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub generation: i64,
}

impl Store {
    /// Expired export artifacts are swept repeatedly, including after an earlier
    /// successful cleanup, to catch delayed writers from expired generations.
    pub async fn claim_export_cleanup(&self) -> Result<Option<ExportCleanupLease>> {
        let row = sqlx::query("SELECT * FROM claim_evidence_export_cleanup()")
            .fetch_optional(&self.pool)
            .await
            .map_err(export_error)?;
        Ok(row.map(|row| ExportCleanupLease {
            id: row.get("id"),
            tenant_id: row.get("tenant_id"),
            environment_id: row.get("environment_id"),
            generation: row.get("generation"),
        }))
    }

    /// Complete means this bounded object-deletion batch exhausted its current
    /// listing. It schedules another sweep in one hour; false retries in five seconds.
    pub async fn finish_export_cleanup(
        &self,
        lease: &ExportCleanupLease,
        complete: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, lease.tenant_id, lease.environment_id).await?;
        sqlx::query("SELECT finish_evidence_export_cleanup($1,$2,$3,$4,$5)")
            .bind(lease.tenant_id)
            .bind(lease.environment_id)
            .bind(lease.id)
            .bind(lease.generation)
            .bind(complete)
            .execute(&mut *tx)
            .await
            .map_err(export_error)?;
        tx.commit().await?;
        Ok(())
    }
}
