use crate::{context, Result, Store, StoreError};
use apl_domain::{PolicyVersion, Reviewer};
use sqlx::{postgres::PgRow, Row};
use uuid::Uuid;

impl Store {
    pub async fn create_policy_draft(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        policy: &PolicyVersion,
    ) -> Result<()> {
        policy
            .validate()
            .map_err(|error| StoreError::Invalid(error.to_string()))?;
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT admin_create_policy_draft($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection)
            .bind(policy.version)
            .bind(policy.auto_limit_minor)
            .bind(policy.hard_limit_minor)
            .bind(policy.approval_ttl_seconds)
            .execute(&mut *tx)
            .await
            .map_err(admin_error)?;
        tx.commit().await?;
        Ok(())
    }

    /// Read the active policy and proposed version under the same scope lock.
    pub async fn simulation_policies(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        version: i64,
    ) -> Result<(Option<PolicyVersion>, PolicyVersion)> {
        validate_version(version)?;
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let rows = sqlx::query("SELECT * FROM admin_simulation_policies($1,$2,$3,$4,$5)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection)
            .bind(version)
            .fetch_all(&mut *tx)
            .await
            .map_err(admin_error)?;
        let (active, proposed): (Vec<_>, Vec<_>) = rows
            .into_iter()
            .partition(|row| row.get::<bool, _>("is_active"));
        let draft = proposed
            .first()
            .map(policy_from_row)
            .ok_or(StoreError::NotFound)?;
        let active = active.first().map(policy_from_row);
        tx.commit().await?;
        Ok((active, draft))
    }

    /// Compare and replace the active binding. A zero expectation requires
    /// that there has never been an active policy for this connection.
    pub async fn publish_policy(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        version: i64,
        expected_version: i64,
    ) -> Result<()> {
        validate_version(version)?;
        if expected_version < 0 {
            return Err(StoreError::Invalid(
                "expected version cannot be negative".into(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT admin_publish_policy($1,$2,$3,$4,$5,$6)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection)
            .bind(version)
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(admin_error)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_dispatch_paused(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        paused: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT admin_set_dispatch_paused($1,$2,$3,$4,$5)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(connection)
            .bind(paused)
            .execute(&mut *tx)
            .await
            .map_err(admin_error)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_tenant_dispatch_paused(
        &self,
        reviewer: &Reviewer,
        paused: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT admin_set_tenant_dispatch_paused($1,$2,$3,$4)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(paused)
            .execute(&mut *tx)
            .await
            .map_err(admin_error)?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_workload_dispatch_paused(
        &self,
        reviewer: &Reviewer,
        workload: Uuid,
        paused: bool,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SELECT admin_set_workload_dispatch_paused($1,$2,$3,$4,$5)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(workload)
            .bind(paused)
            .execute(&mut *tx)
            .await
            .map_err(admin_error)?;
        tx.commit().await?;
        Ok(())
    }
}

fn validate_version(version: i64) -> Result<()> {
    if version < 1 {
        return Err(StoreError::Invalid(
            "policy version must be positive".into(),
        ));
    }
    Ok(())
}

fn policy_from_row(row: &PgRow) -> PolicyVersion {
    PolicyVersion {
        version: row.get("version"),
        auto_limit_minor: row.get("auto_limit_minor"),
        hard_limit_minor: row.get("hard_limit_minor"),
        approval_ttl_seconds: row.get("approval_ttl_seconds"),
    }
}

fn admin_error(error: sqlx::Error) -> StoreError {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("AP403") => StoreError::Forbidden,
        Some("AP404") => StoreError::NotFound,
        Some("AP409") => StoreError::Conflict,
        _ => StoreError::Database(error),
    }
}
