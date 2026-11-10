//! Bounded immutable policy pages using the policy administrator read boundary.
use crate::{context, Result, Store, StoreError};
use apl_domain::{PolicyVersion, Reviewer};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPage {
    pub connection_id: Uuid,
    pub active_policy: Option<PolicyVersion>,
    pub versions: Vec<PolicyVersion>,
    pub next_after: Option<i64>,
    pub can_edit: bool,
    pub can_publish: bool,
}

fn unavailable() -> StoreError {
    StoreError::Serialization(serde::de::Error::custom("data unavailable"))
}

impl Store {
    pub async fn policy_page(
        &self,
        reviewer: &Reviewer,
        connection: Uuid,
        after: Option<i64>,
        limit: usize,
    ) -> Result<PolicyPage> {
        if !(1..=100).contains(&limit)
            || after.is_some_and(|v| !(1..=MAX_SAFE_INTEGER).contains(&v))
        {
            return Err(StoreError::Invalid("invalid request".into()));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let value: serde_json::Value =
            sqlx::query_scalar("SELECT read_policy_page($1,$2,$3,$4,$5,$6)")
                .bind(reviewer.tenant_id)
                .bind(reviewer.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(connection)
                .bind(after)
                .bind(limit as i64)
                .fetch_one(&mut *tx)
                .await
                .map_err(|error| {
                    match error.as_database_error().and_then(|e| e.code()).as_deref() {
                        Some("AP404" | "AP403") => StoreError::NotFound,
                        Some("AP400") => StoreError::Invalid("invalid request".into()),
                        Some("AP500") => unavailable(),
                        _ => StoreError::Database(error),
                    }
                })?;
        if serde_json::to_vec(&value)?.len() > 128 * 1024 {
            return Err(unavailable());
        }
        let page: PolicyPage = serde_json::from_value(value).map_err(|_| unavailable())?;
        if page.connection_id != connection
            || page.versions.len() > limit
            || (!page.can_edit && !page.can_publish)
            || page
                .versions
                .windows(2)
                .any(|p| p[0].version >= p[1].version)
            || page
                .versions
                .iter()
                .any(|p| after.is_some_and(|a| p.version <= a))
            || page
                .next_after
                .is_some_and(|a| page.versions.last().map(|p| p.version) != Some(a))
        {
            return Err(unavailable());
        }
        for policy in page.versions.iter().chain(page.active_policy.iter()) {
            if policy.version > MAX_SAFE_INTEGER || policy.validate().is_err() {
                return Err(unavailable());
            }
        }
        tx.commit().await?;
        Ok(page)
    }
}
