//! Independent, revisioned operator control projections.
use crate::{context, Result, Store, StoreError};
use apl_domain::Reviewer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlKind {
    Tenant,
    Connection,
    Workload,
}
impl ControlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Connection => "connection",
            Self::Workload => "workload",
        }
    }
}
impl std::str::FromStr for ControlKind {
    type Err = StoreError;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "tenant" => Ok(Self::Tenant),
            "connection" => Ok(Self::Connection),
            "workload" => Ok(Self::Workload),
            _ => Err(invalid()),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlState {
    pub kind: ControlKind,
    pub target_id: Uuid,
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub enabled: bool,
    pub paused: bool,
    pub revision: i64,
}
fn invalid() -> StoreError {
    StoreError::Invalid("invalid control request".into())
}
fn map_error(error: sqlx::Error) -> StoreError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP400") => invalid(),
        Some("AP403") => StoreError::Forbidden,
        Some("AP409") => StoreError::Conflict,
        _ => StoreError::Database(error),
    }
}
impl Store {
    pub async fn control_state(
        &self,
        reviewer: &Reviewer,
        kind: ControlKind,
        target: Option<Uuid>,
    ) -> Result<ControlState> {
        self.control_state_query(reviewer, kind, target, None).await
    }
    pub async fn set_control_state(
        &self,
        reviewer: &Reviewer,
        kind: ControlKind,
        target: Option<Uuid>,
        expected: i64,
        paused: bool,
    ) -> Result<ControlState> {
        if !(1..=9_007_199_254_740_991).contains(&expected) {
            return Err(invalid());
        }
        self.control_state_query(reviewer, kind, target, Some((expected, paused)))
            .await
    }
    async fn control_state_query(
        &self,
        reviewer: &Reviewer,
        kind: ControlKind,
        target: Option<Uuid>,
        mutation: Option<(i64, bool)>,
    ) -> Result<ControlState> {
        if (kind == ControlKind::Tenant) != target.is_none() {
            return Err(invalid());
        }
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        let sql = if mutation.is_some() {
            "SELECT set_dispatch_control_state($1,$2,$3,$4,$5,$6,$7)"
        } else {
            "SELECT read_dispatch_control_state($1,$2,$3,$4,$5)"
        };
        let mut query = sqlx::query_scalar::<_, serde_json::Value>(sql)
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(kind.as_str())
            .bind(target);
        if let Some((expected, paused)) = mutation {
            query = query.bind(expected).bind(paused);
        }
        let value = query.fetch_one(&mut *tx).await.map_err(map_error)?;
        let corrupt =
            || StoreError::Serialization(serde::de::Error::custom("control data unavailable"));
        let state: ControlState = serde_json::from_value(value).map_err(|_| corrupt())?;
        if state.kind != kind
            || state.target_id != target.unwrap_or(reviewer.tenant_id)
            || state.tenant_id != reviewer.tenant_id
            || state.environment_id != reviewer.environment_id
            || !(1..=9_007_199_254_740_991).contains(&state.revision)
            || mutation.is_some_and(|(_, paused)| state.paused != paused)
        {
            return Err(corrupt());
        }
        tx.commit().await?;
        Ok(state)
    }
}
