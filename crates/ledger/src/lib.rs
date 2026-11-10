//! Transactional USD budget accounting. See the crate README for dispatch ordering.
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetAction {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub action_id: Uuid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reservation {
    NewHold,
    AlreadyHeld,
    Settled,
    Released,
    NotConfigured,
    DailyExceeded,
    ExposureExceeded,
    InvalidAction,
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfirmedOutcome {
    Success,
    NonExecution,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Finalization {
    Settled,
    Released,
    Missing,
    Conflict,
}

#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("budget database returned an unrecognized result")]
    UnknownResult,
}

/// Reserves against all applicable configured limits. The amount and workload
/// are read from the locked action; only verified provider facts may supply
/// `customer_ref`. A held result alone does not authorize an external write.
pub async fn reserve(
    tx: &mut Transaction<'_, Postgres>,
    action: BudgetAction,
    connection_id: Uuid,
    customer_ref: Option<&str>,
) -> Result<Reservation, LedgerError> {
    let status: String = sqlx::query_scalar("SELECT public.reserve_refund_budget($1,$2,$3,$4,$5)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .bind(connection_id)
        .bind(customer_ref)
        .fetch_one(&mut **tx)
        .await?;
    match status.as_str() {
        "new_hold" => Ok(Reservation::NewHold),
        "already_held" => Ok(Reservation::AlreadyHeld),
        "settled" => Ok(Reservation::Settled),
        "released" => Ok(Reservation::Released),
        "not_configured" => Ok(Reservation::NotConfigured),
        "daily_exceeded" => Ok(Reservation::DailyExceeded),
        "exposure_exceeded" => Ok(Reservation::ExposureExceeded),
        "invalid_action" => Ok(Reservation::InvalidAction),
        "conflict" => Ok(Reservation::Conflict),
        _ => Err(LedgerError::UnknownResult),
    }
}

/// Finalizes an existing hold using confirmed provider evidence. Pending and
/// unknown outcomes must never call this function; they keep the hold active.
pub async fn finalize(
    tx: &mut Transaction<'_, Postgres>,
    action: BudgetAction,
    outcome: ConfirmedOutcome,
) -> Result<Finalization, LedgerError> {
    let outcome = match outcome {
        ConfirmedOutcome::Success => "settled",
        ConfirmedOutcome::NonExecution => "released",
    };
    let status: String = sqlx::query_scalar("SELECT public.finalize_refund_budget($1,$2,$3,$4)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .bind(outcome)
        .fetch_one(&mut **tx)
        .await?;
    match status.as_str() {
        "settled" => Ok(Finalization::Settled),
        "released" => Ok(Finalization::Released),
        "missing" => Ok(Finalization::Missing),
        "conflict" => Ok(Finalization::Conflict),
        _ => Err(LedgerError::UnknownResult),
    }
}
