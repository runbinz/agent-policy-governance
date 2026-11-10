//! Dedicated detail authority and fixed, bounded reviewer projections.
use crate::{context, Result, Store, StoreError};
use apl_dispatch::{Dispatch, DispatchSnapshot, DispatchState, VerifiedPaymentObservation};
use apl_domain::{action_detail::*, ActionStatus, Reviewer};
use serde::Serialize;
use serde_json::Value;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;
fn corrupt() -> StoreError {
    StoreError::Serialization(serde::de::Error::custom("data unavailable"))
}
fn bounded<T: Serialize>(v: &T) -> Result<()> {
    if serde_json::to_vec(v)?.len() > 128 * 1024 {
        return Err(corrupt());
    }
    Ok(())
}
fn database(e: sqlx::Error) -> StoreError {
    match e.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP404") => StoreError::NotFound,
        Some("AP400") => StoreError::Invalid("invalid request".into()),
        _ => StoreError::Database(e),
    }
}
fn kind_name(k: &HistoryKind) -> &'static str {
    match k {
        HistoryKind::Audit => "audit",
        HistoryKind::Policy => "policy",
        HistoryKind::Approval => "approval",
        HistoryKind::Budget => "budget",
        HistoryKind::Attempt => "attempt",
    }
}
fn cursor(c: Uuid, a: Uuid, k: &HistoryKind, key: i64) -> String {
    format!("v1:{c}:{a}:{}:{key}", kind_name(k))
}
fn parse_cursor(value: Option<&str>, c: Uuid, a: Uuid, k: &HistoryKind) -> Result<i64> {
    let Some(v) = value else { return Ok(0) };
    if v.len() > 160 {
        return Err(StoreError::Invalid("invalid cursor".into()));
    }
    let key = v
        .rsplit(':')
        .next()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|n| *n > 0)
        .ok_or_else(|| StoreError::Invalid("invalid cursor".into()))?;
    if cursor(c, a, k, key) != v {
        return Err(StoreError::Invalid("invalid cursor".into()));
    }
    Ok(key)
}
async fn timestamp(tx: &mut Transaction<'_, Postgres>, ms: Option<u64>) -> Result<Option<String>> {
    let Some(ms) = ms else { return Ok(None) }; // Restrict to RFC3339's four-digit year range and exact integer milliseconds.
    if ms > 253_402_300_799_999 {
        return Err(corrupt());
    }
    Ok(sqlx::query_scalar("SELECT to_char(to_timestamp($1::double precision/1000) AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"')").bind(ms as i64).fetch_one(&mut **tx).await?)
}
fn validate_approval(q: &Approval) -> Result<()> {
    if q.generation <= 0
        || q.policy_version <= 0
        || q.action_digest.len() != 64
        || !q
            .action_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(corrupt());
    }
    Ok(())
}
impl Store {
    pub async fn action_detail(&self, r: &Reviewer, c: Uuid, a: Uuid) -> Result<ActionDetail> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, r.tenant_id, r.environment_id).await?;
        let mut v: Value = sqlx::query_scalar("SELECT read_action_detail($1,$2,$3,$4,$5)")
            .bind(r.tenant_id)
            .bind(r.environment_id)
            .bind(r.reviewer_id)
            .bind(c)
            .bind(a)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
        let stored = v
            .as_object_mut()
            .ok_or_else(corrupt)?
            .remove("_dispatch")
            .ok_or_else(corrupt)?;
        let fixture = v
            .as_object_mut()
            .ok_or_else(corrupt)?
            .remove("_fixture")
            .and_then(|v| v.as_bool())
            .ok_or_else(corrupt)?;
        let mut payment = AuthoritativePayment {
            availability: PaymentAvailability::Unavailable,
            context: None,
            payment: None,
        };
        let mut execution = None;
        let mut outcome = ProviderOutcome {
            status: ProviderStatus::NotRecorded,
            source: ProviderSource::None,
        };
        if !stored.is_null() {
            let snapshot: DispatchSnapshot = serde_json::from_value(stored["snapshot"].clone())?;
            Dispatch::restore(snapshot.clone()).map_err(|_| corrupt())?;
            if snapshot.action_id != a || snapshot.request.connection_id() != c {
                return Err(corrupt());
            }
            let status: ActionStatus = serde_json::from_value(v["status"].clone())?;
            let (state, provider) = match snapshot.state {
                DispatchState::Authorized => {
                    (ExecutionState::Authorized, ProviderStatus::Unresolved)
                }
                DispatchState::InFlight => (ExecutionState::InFlight, ProviderStatus::Unresolved),
                DispatchState::Pending => (ExecutionState::Pending, ProviderStatus::Unresolved),
                DispatchState::Unknown => (ExecutionState::Unknown, ProviderStatus::Unresolved),
                DispatchState::ManualReview => {
                    (ExecutionState::ManualReview, ProviderStatus::Unresolved)
                }
                DispatchState::Succeeded(_) => {
                    if status != ActionStatus::Succeeded {
                        return Err(corrupt());
                    }
                    (ExecutionState::Succeeded, ProviderStatus::ConfirmedSuccess)
                }
                DispatchState::FailedConfirmed(_) => {
                    if status != ActionStatus::FailedConfirmed {
                        return Err(corrupt());
                    }
                    (
                        ExecutionState::FailedConfirmed,
                        ProviderStatus::ConfirmedNonExecution,
                    )
                }
            };
            if matches!(
                status,
                ActionStatus::Succeeded | ActionStatus::FailedConfirmed
            ) && !matches!(
                provider,
                ProviderStatus::ConfirmedSuccess | ProviderStatus::ConfirmedNonExecution
            ) {
                return Err(corrupt());
            }
            let observed = timestamp(&mut tx, Some(snapshot.request.observed_at()))
                .await?
                .ok_or_else(corrupt)?;
            let fresh = timestamp(&mut tx, Some(snapshot.request.fresh_until()))
                .await?
                .ok_or_else(corrupt)?;
            payment = AuthoritativePayment {
                availability: PaymentAvailability::VerifiedContext,
                context: Some(PaymentContext {
                    payment_id: snapshot.request.payment_id().into(),
                    connection_id: c,
                    amount_minor: snapshot.request.amount_minor(),
                    currency: "USD".into(),
                    observed_at: observed,
                    fresh_until: fresh,
                }),
                payment: None,
            };
            execution = Some(Execution {
                state,
                first_send_at: timestamp(&mut tx, snapshot.first_send_at).await?,
                retry_until: timestamp(&mut tx, snapshot.retry_until).await?,
                state_changed_at: serde_json::from_value(stored["state_changed_at"].clone())?,
                abandoned_at: serde_json::from_value(stored["abandoned_at"].clone())?,
            });
            outcome = ProviderOutcome {
                status: provider,
                source: ProviderSource::ExternalDispatch,
            };
        } else if fixture {
            if v["status"] != "succeeded" {
                return Err(corrupt());
            }
            outcome = ProviderOutcome {
                status: ProviderStatus::ConfirmedSuccess,
                source: ProviderSource::LocalFixture,
            };
        }
        let attestation: Option<Value> =
            sqlx::query_scalar("SELECT read_action_payment_attestation($1,$2,$3,$4,$5)")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(r.reviewer_id)
                .bind(c)
                .bind(a)
                .fetch_one(&mut *tx)
                .await
                .map_err(database)?;
        if let Some(record) = attestation {
            let observation: VerifiedPaymentObservation =
                serde_json::from_value(record["observation"].clone())?;
            let request = observation.request();
            if request.connection_id() != c
                || v["immutable_request"]["resource"]["payment_id"] != request.payment_id()
                || v["immutable_request"]["parameters"]["amount_minor"] != request.amount_minor()
            {
                return Err(corrupt());
            }
            let now = crate::external::database_now(&mut tx).await?;
            let facts = observation.facts();
            let id: Uuid = serde_json::from_value(record["id"].clone())?;
            let source: PaymentEvidenceSource = serde_json::from_value(record["source"].clone())?;
            let generation: Option<i64> =
                serde_json::from_value(record["approval_generation"].clone())?;
            if id.is_nil()
                || matches!(source, PaymentEvidenceSource::Approval)
                    && generation.is_none_or(|g| g <= 0)
            {
                return Err(corrupt());
            }
            payment.payment = Some(PaymentAttestationView {
                attestation_id: id,
                schema_version: observation.schema_version(),
                source,
                approval_generation: generation,
                payment_id: request.payment_id().into(),
                connection_id: c,
                requested_minor: request.amount_minor(),
                charge_amount_minor: facts.charge_amount_minor,
                captured_minor: facts.captured_minor,
                refunded_minor: facts.refunded_minor,
                remaining_minor: observation.remaining_minor(),
                currency: "USD".into(),
                status: facts.status.clone(),
                captured: facts.captured,
                paid: facts.paid,
                disputed: facts.disputed,
                method: facts.method.clone(),
                direct_charge: facts.direct_charge,
                eligible_at_observation: true,
                observed_at: timestamp(&mut tx, Some(request.observed_at()))
                    .await?
                    .ok_or_else(corrupt)?,
                fresh_until: timestamp(&mut tx, Some(request.fresh_until()))
                    .await?
                    .ok_or_else(corrupt)?,
                freshness: if request.is_fresh(now) {
                    PaymentFreshness::Fresh
                } else {
                    PaymentFreshness::Stale
                },
            });
            payment.availability = PaymentAvailability::VerifiedPayment;
        }
        v["authoritative_payment"] = serde_json::to_value(payment)?;
        v["execution"] = serde_json::to_value(execution)?;
        v["provider_outcome"] = serde_json::to_value(outcome)?;
        let detail: ActionDetail = serde_json::from_value(v)?;
        if let Some(payment) = &detail.authoritative_payment.payment {
            match payment.source {
                PaymentEvidenceSource::Approval => {
                    let approval = detail.approval.as_ref().ok_or_else(corrupt)?;
                    if approval.payment_attestation_id != Some(payment.attestation_id)
                        || Some(approval.generation) != payment.approval_generation
                    {
                        return Err(corrupt());
                    }
                }
                PaymentEvidenceSource::Dispatch if detail.execution.is_none() => {
                    return Err(corrupt())
                }
                PaymentEvidenceSource::Dispatch => {}
            }
        } else if detail
            .approval
            .as_ref()
            .is_some_and(|q| q.payment_attestation_id.is_some())
        {
            return Err(corrupt());
        }
        let req = &detail.immutable_request;
        if req.action_type != "refund.create"
            || req.resource.payment_id.trim().is_empty()
            || req.resource.payment_id.len() > 255
            || req.parameters.currency != "USD"
            || !(1..=50000).contains(&req.parameters.amount_minor)
        {
            return Err(corrupt());
        }
        if let Some(q) = &detail.approval {
            validate_approval(q)?
        }
        if let Some(p) = &detail.authoritative_payment.context {
            if p.payment_id != req.resource.payment_id
                || i64::from(p.amount_minor) != req.parameters.amount_minor
            {
                return Err(corrupt());
            }
        }
        bounded(&detail)?;
        tx.commit().await?;
        Ok(detail)
    }
    pub async fn action_history(
        &self,
        r: &Reviewer,
        c: Uuid,
        a: Uuid,
        k: HistoryKind,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ActionHistoryPage> {
        if !(1..=100).contains(&limit) {
            return Err(StoreError::Invalid("invalid limit".into()));
        }
        let key = parse_cursor(after, c, a, &k)?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, r.tenant_id, r.environment_id).await?;
        let v: Value = sqlx::query_scalar("SELECT read_action_history($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(r.tenant_id)
            .bind(r.environment_id)
            .bind(r.reviewer_id)
            .bind(c)
            .bind(a)
            .bind(kind_name(&k))
            .bind(key)
            .bind(limit as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(database)?;
        let mut items: Vec<HistoryItem> = serde_json::from_value(v)?;
        for item in &items {
            if item.key() <= key {
                return Err(corrupt());
            }
            if let HistoryItem::Approval { record } = item {
                validate_approval(record)?
            }
        }
        let more = items.len() > limit;
        items.truncate(limit);
        let next_cursor = if more {
            Some(cursor(c, a, &k, items.last().ok_or_else(corrupt)?.key()))
        } else {
            None
        };
        let page = ActionHistoryPage { items, next_cursor };
        bounded(&page)?;
        tx.commit().await?;
        Ok(page)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_size_is_bounded() {
        assert!(bounded(&"x".repeat(128 * 1024)).is_err());
        assert!(bounded(&"small").is_ok());
    }
    #[test]
    fn cursors_bind_all_dimensions() {
        let c = Uuid::new_v4();
        let a = Uuid::new_v4();
        let v = cursor(c, a, &HistoryKind::Audit, 7);
        assert_eq!(
            parse_cursor(Some(&v), c, a, &HistoryKind::Audit).unwrap(),
            7
        );
        assert!(parse_cursor(Some(&v), c, a, &HistoryKind::Policy).is_err());
        assert!(parse_cursor(Some(&v), c, Uuid::new_v4(), &HistoryKind::Audit).is_err());
        assert!(parse_cursor(Some("v1:0"), c, a, &HistoryKind::Audit).is_err());
    }
}
