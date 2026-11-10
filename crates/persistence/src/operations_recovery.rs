//! Bounded recovery projections; private dispatch state is validated before disclosure.
use crate::{context, Result, Store, StoreError};
use apl_dispatch::{Dispatch, DispatchSnapshot, DispatchState};
use apl_domain::{ActionStatus, Reviewer};
use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    Dispatches,
    ReadyJobs,
}
impl RecoveryKind {
    fn name(self) -> &'static str {
        match self {
            Self::Dispatches => "dispatches",
            Self::ReadyJobs => "ready_jobs",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryItem {
    pub action_id: Uuid,
    pub workload_id: Uuid,
    pub action_status: String,
    pub dispatch_state: Option<String>,
    pub queue_due_at: Option<String>,
    pub queue_lag_seconds: Option<i64>,
    pub state_changed_at: Option<String>,
    pub lease_expired: Option<bool>,
    pub hold_state: Option<String>,
    pub held_minor: i64,
    pub can_reconcile: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPage {
    pub connection_id: Uuid,
    pub kind: RecoveryKind,
    pub items: Vec<RecoveryItem>,
    pub next_cursor: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReconciliationState {
    pub action_id: Uuid,
    pub connection_id: Uuid,
    pub dispatch_state: Option<String>,
    pub can_request: bool,
    pub reason_code: String,
}
#[derive(Deserialize)]
struct PrivateDispatch {
    #[serde(rename = "_snapshot")]
    snapshot: Option<DispatchSnapshot>,
    #[serde(rename = "_connection")]
    connection: Option<Uuid>,
    #[serde(rename = "_closed")]
    closed: Option<bool>,
    #[serde(rename = "_abandoned")]
    abandoned: Option<i64>,
    #[serde(rename = "_queue_closed")]
    queue_closed: Option<bool>,
    #[serde(rename = "_now_ms")]
    now_ms: u64,
}
fn corrupt() -> StoreError {
    StoreError::Serialization(serde::de::Error::custom("data unavailable"))
}
fn database(e: sqlx::Error) -> StoreError {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP404") => StoreError::NotFound,
        Some("AP400") => StoreError::Invalid("invalid request".into()),
        _ => StoreError::Database(e),
    }
}
fn valid_time(value: &Option<String>) -> bool {
    value.as_ref().is_none_or(|s| {
        s.len() == 27
            && s.bytes().enumerate().all(|(i, b)| match i {
                4 | 7 => b == b'-',
                10 => b == b'T',
                13 | 16 => b == b':',
                19 => b == b'.',
                26 => b == b'Z',
                _ => b.is_ascii_digit(),
            })
            && &s[..4] != "0000"
    })
}
fn cursor(r: &Reviewer, c: Uuid, k: RecoveryKind, a: Uuid) -> String {
    format!(
        "v1:{}:{}:{c}:{}:{a}",
        r.tenant_id,
        r.environment_id,
        k.name()
    )
}
fn parse_cursor(r: &Reviewer, c: Uuid, k: RecoveryKind, v: Option<&str>) -> Result<Option<Uuid>> {
    let Some(v) = v else { return Ok(None) };
    let invalid = || StoreError::Invalid("invalid cursor".into());
    if v.len() > 200 {
        return Err(invalid());
    }
    let a = v
        .rsplit(':')
        .next()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(invalid)?;
    if cursor(r, c, k, a) != v {
        return Err(invalid());
    }
    Ok(Some(a))
}
// Parent status alone is never evidence of a provider outcome.
fn validated(
    v: &serde_json::Value,
    c: Uuid,
    a: Uuid,
) -> Result<(Option<String>, Option<bool>, bool)> {
    let p: PrivateDispatch = serde_json::from_value(v.clone()).map_err(|_| corrupt())?;
    let status: ActionStatus =
        serde_json::from_value(v["action_status"].clone()).map_err(|_| corrupt())?;
    let Some(s) = p.snapshot else {
        if p.connection.is_some()
            || p.closed.is_some()
            || p.queue_closed.is_some()
            || p.abandoned.is_some()
        {
            return Err(corrupt());
        }
        return Ok((None, None, false));
    };
    Dispatch::restore(s.clone()).map_err(|_| corrupt())?;
    if s.action_id != a
        || s.request.connection_id() != c
        || p.connection != Some(c)
        || p.closed.is_none()
        || p.queue_closed.is_none()
    {
        return Err(corrupt());
    }
    let name = match s.state {
        DispatchState::Authorized => "authorized",
        DispatchState::InFlight => "in_flight",
        DispatchState::Pending => "pending",
        DispatchState::Unknown => "unknown",
        DispatchState::ManualReview => "manual_review",
        DispatchState::Succeeded(_) => "succeeded",
        DispatchState::FailedConfirmed(_) => "failed_confirmed",
    };
    let consistent = if p.abandoned.is_some() {
        name == "authorized"
            && s.first_send_at.is_none()
            && status == ActionStatus::Denied
            && p.closed == Some(true)
    } else {
        match name {
            "succeeded" => status == ActionStatus::Succeeded && p.closed == Some(true),
            "failed_confirmed" => status == ActionStatus::FailedConfirmed && p.closed == Some(true),
            _ => status == ActionStatus::Dispatching && p.closed == Some(false),
        }
    };
    if !consistent {
        return Err(corrupt());
    }
    let eligible = name == "manual_review" && p.queue_closed == Some(true) && p.abandoned.is_none();
    Ok((
        Some(name.into()),
        s.lease.map(|l| l.expires_at <= p.now_ms),
        eligible,
    ))
}
async fn begin(store: &Store, r: &Reviewer) -> Result<Transaction<'static, Postgres>> {
    let mut tx = store.pool.begin().await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    context(&mut tx, r.tenant_id, r.environment_id).await?;
    Ok(tx)
}
async fn authorize(
    tx: &mut Transaction<'_, Postgres>,
    r: &Reviewer,
    c: Uuid,
    function: &str,
) -> Result<()> {
    let allowed: bool = sqlx::query_scalar(&format!("SELECT {function}($1,$2,$3,$4)"))
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .bind(c)
        .fetch_one(&mut **tx)
        .await
        .map_err(database)?;
    if !allowed {
        return Err(StoreError::NotFound);
    }
    Ok(())
}
/// Validate the private record before committing a queue-first reconciliation request.
/// Caller retains the queue lock and rolls back the transaction on any error.
pub(crate) async fn validate_reconciliation_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    r: &Reviewer,
    a: Uuid,
) -> Result<()> {
    let v: serde_json::Value = sqlx::query_scalar("SELECT read_reconciliation_state($1,$2,$3,$4)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .bind(a)
        .fetch_one(&mut **tx)
        .await
        .map_err(database)?;
    let c: Uuid = serde_json::from_value(v["connection_id"].clone()).map_err(|_| corrupt())?;
    if v["action_id"] != serde_json::to_value(a)? {
        return Err(corrupt());
    }
    let (state, _, _) = validated(&v, c, a)?;
    if state.as_deref() != Some("manual_review") {
        return Err(StoreError::Conflict);
    }
    authorize(tx, r, c, "authorize_reconciliation").await
}
impl Store {
    pub async fn operations_items(
        &self,
        r: &Reviewer,
        c: Uuid,
        kind: RecoveryKind,
        after: Option<&str>,
        limit: u32,
    ) -> Result<RecoveryPage> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::Invalid("invalid limit".into()));
        }
        let key = parse_cursor(r, c, kind, after)?;
        let mut tx = begin(self, r).await?;
        let rows: serde_json::Value =
            sqlx::query_scalar("SELECT read_operations_items($1,$2,$3,$4,$5,$6,$7)")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(r.reviewer_id)
                .bind(c)
                .bind(kind.name())
                .bind(key)
                .bind(i64::from(limit))
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        let rows = rows.as_array().ok_or_else(corrupt)?;
        if rows.len() > limit as usize + 1 {
            return Err(corrupt());
        }
        let more = rows.len() > limit as usize;
        let mut items = Vec::new();
        for v in rows.iter().take(limit as usize) {
            let a: Uuid = serde_json::from_value(v["action_id"].clone()).map_err(|_| corrupt())?;
            let (dispatch_state, lease_expired, eligible) = validated(v, c, a)?;
            let mut public = v.as_object().ok_or_else(corrupt)?.clone();
            let authority = public
                .remove("_reconciliation_allowed")
                .and_then(|v| v.as_bool())
                .ok_or_else(corrupt)?;
            public.retain(|k, _| !k.starts_with('_'));
            public.insert(
                "dispatch_state".into(),
                serde_json::to_value(dispatch_state)?,
            );
            public.insert("lease_expired".into(), serde_json::to_value(lease_expired)?);
            public.insert("can_reconcile".into(), (authority && eligible).into());
            let item: RecoveryItem =
                serde_json::from_value(public.into()).map_err(|_| corrupt())?;
            if !valid_time(&item.queue_due_at)
                || !valid_time(&item.state_changed_at)
                || !(0..=9_007_199_254_740_991).contains(&item.held_minor)
                || item
                    .queue_lag_seconds
                    .is_some_and(|n| !(0..=9_007_199_254_740_991).contains(&n))
                || item
                    .hold_state
                    .as_deref()
                    .is_some_and(|s| !matches!(s, "held" | "settled" | "released"))
                || (item.hold_state.as_deref() != Some("held") && item.held_minor != 0)
            {
                return Err(corrupt());
            }
            items.push(item);
        }
        authorize(&mut tx, r, c, "authorize_operations").await?;
        let next_cursor = if more {
            Some(cursor(
                r,
                c,
                kind,
                items.last().ok_or_else(corrupt)?.action_id,
            ))
        } else {
            None
        };
        tx.commit().await?;
        Ok(RecoveryPage {
            connection_id: c,
            kind,
            items,
            next_cursor,
        })
    }
    pub async fn reconciliation_state(&self, r: &Reviewer, a: Uuid) -> Result<ReconciliationState> {
        let mut tx = begin(self, r).await?;
        let v: serde_json::Value =
            sqlx::query_scalar("SELECT read_reconciliation_state($1,$2,$3,$4)")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(r.reviewer_id)
                .bind(a)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        let c: Uuid = serde_json::from_value(v["connection_id"].clone()).map_err(|_| corrupt())?;
        if v["action_id"] != serde_json::to_value(a)? {
            return Err(corrupt());
        }
        let (dispatch_state, _, can_request) = validated(&v, c, a)?;
        let reason_code = if can_request {
            "ELIGIBLE"
        } else if dispatch_state.is_none() {
            "NO_DISPATCH"
        } else if dispatch_state.as_deref() == Some("manual_review") {
            "ALREADY_QUEUED"
        } else {
            "NOT_MANUAL_REVIEW"
        }
        .into();
        authorize(&mut tx, r, c, "authorize_reconciliation").await?;
        tx.commit().await?;
        Ok(ReconciliationState {
            action_id: a,
            connection_id: c,
            dispatch_state,
            can_request,
            reason_code,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursors_bind_complete_scope() {
        let r = Reviewer {
            tenant_id: Uuid::new_v4(),
            environment_id: Uuid::new_v4(),
            reviewer_id: Uuid::new_v4(),
        };
        let c = Uuid::new_v4();
        let a = Uuid::new_v4();
        let v = cursor(&r, c, RecoveryKind::Dispatches, a);
        assert_eq!(
            parse_cursor(&r, c, RecoveryKind::Dispatches, Some(&v)).unwrap(),
            Some(a)
        );
        assert!(parse_cursor(&r, c, RecoveryKind::ReadyJobs, Some(&v)).is_err());
        assert!(parse_cursor(&r, Uuid::new_v4(), RecoveryKind::Dispatches, Some(&v)).is_err());
        let foreign = Reviewer {
            tenant_id: Uuid::new_v4(),
            ..r.clone()
        };
        assert!(parse_cursor(&foreign, c, RecoveryKind::Dispatches, Some(&v)).is_err());
        assert!(parse_cursor(&r, c, RecoveryKind::Dispatches, Some(&v.to_uppercase())).is_err());
    }
}
