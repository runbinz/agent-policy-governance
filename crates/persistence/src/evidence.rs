//! Redacted, scoped evidence search with bounded UUID keyset pagination.
use crate::{context, Result, Store, StoreError};
use apl_domain::{ActionStatus, Reviewer};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFilter {
    pub connection_id: Uuid,
    pub status: Option<String>,
    pub workload_id: Option<Uuid>,
    pub action_id: Option<Uuid>,
    pub min_amount_minor: Option<i64>,
    pub max_amount_minor: Option<i64>,
    pub after: Option<Uuid>,
    pub limit: Option<i64>,
}

impl EvidenceFilter {
    pub fn validate(&self) -> Result<()> {
        if self
            .status
            .as_ref()
            .is_some_and(|status| status.parse::<ActionStatus>().is_err())
        {
            return Err(StoreError::Invalid("unsupported action status".into()));
        }
        if self
            .min_amount_minor
            .is_some_and(|value| !(0..=50_000).contains(&value))
            || self
                .max_amount_minor
                .is_some_and(|value| !(0..=50_000).contains(&value))
            || matches!((self.min_amount_minor,self.max_amount_minor),(Some(min),Some(max)) if min>max)
        {
            return Err(StoreError::Invalid(
                "amount bounds must satisfy 0 <= min <= max <= 50000".into(),
            ));
        }
        if !(1..=100).contains(&self.limit.unwrap_or(50)) {
            return Err(StoreError::Invalid(
                "limit must be between 1 and 100".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAction {
    pub id: Uuid,
    pub workload_id: Uuid,
    pub connection_id: Uuid,
    pub status: String,
    pub reason: Option<String>,
    pub amount_minor: i64,
    pub currency: String,
    pub policy_version: Option<i64>,
    pub budget_state: Option<String>,
    pub budget_amount_minor: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidencePage {
    pub items: Vec<EvidenceAction>,
    pub next_after: Option<Uuid>,
}

impl Store {
    pub async fn search_evidence(
        &self,
        reviewer: &Reviewer,
        filter: &EvidenceFilter,
    ) -> Result<EvidencePage> {
        filter.validate()?;
        let limit = filter.limit.unwrap_or(50) as usize;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let rows =
            sqlx::query("SELECT * FROM search_action_evidence($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
                .bind(reviewer.tenant_id)
                .bind(reviewer.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(filter.connection_id)
                .bind(&filter.status)
                .bind(filter.workload_id)
                .bind(filter.action_id)
                .bind(filter.min_amount_minor)
                .bind(filter.max_amount_minor)
                .bind(filter.after)
                .bind(limit as i64)
                .fetch_all(&mut *tx)
                .await
                .map_err(search_error)?;
        let has_more = rows.len() > limit;
        let items: Vec<EvidenceAction> = rows
            .into_iter()
            .take(limit)
            .map(|row| EvidenceAction {
                id: row.get("id"),
                workload_id: row.get("workload_id"),
                connection_id: row.get("connection_id"),
                status: row.get("status"),
                reason: row.get("reason"),
                amount_minor: row.get("amount_minor"),
                currency: row.get("currency"),
                policy_version: row.get("policy_version"),
                budget_state: row.get("budget_state"),
                budget_amount_minor: row.get("budget_amount_minor"),
            })
            .collect();
        let next_after = has_more.then(|| items.last().expect("validated positive page size").id);
        tx.commit().await?;
        Ok(EvidencePage { items, next_after })
    }
}

fn search_error(error: sqlx::Error) -> StoreError {
    match error
        .as_database_error()
        .and_then(|error| error.code())
        .as_deref()
    {
        Some("AP404") => StoreError::NotFound,
        Some("AP400") => StoreError::Invalid("invalid evidence filter".into()),
        _ => StoreError::Database(error),
    }
}
