//! Immutable, exact action-bound payment evidence. Timestamps are not material facts.
use crate::{
    external::{database_now, ExternalAction},
    Result, StoreError,
};
use apl_dispatch::{VerifiedPaymentObservation, VerifiedRefundRequest};
use apl_domain::RefundRequest;
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;
type Tx<'a> = Transaction<'a, Postgres>;

pub(super) async fn validate(
    tx: &mut Tx<'_>,
    observation: &VerifiedPaymentObservation,
    request: &VerifiedRefundRequest,
) -> Result<()> {
    let now = database_now(tx).await?;
    if observation.request() != request || request.observed_at() > now || !request.is_fresh(now) {
        return Err(StoreError::Invalid(
            "payment observation is mismatched or stale".into(),
        ));
    }
    Ok(())
}
pub(super) async fn digest(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    namespace: &str,
    observation: &VerifiedPaymentObservation,
) -> Result<String> {
    let row = sqlx::query(
        "SELECT workload_id,request FROM actions WHERE (tenant_id,environment_id,id)=($1,$2,$3)",
    )
    .bind(action.tenant_id)
    .bind(action.environment_id)
    .bind(action.action_id)
    .fetch_one(&mut **tx)
    .await?;
    let stored: RefundRequest = serde_json::from_value(row.get("request"))?;
    let r = observation.request();
    let route: Option<String> = sqlx::query_scalar("SELECT provider_route($1,$2,$3)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(stored.connection_id)
        .fetch_one(&mut **tx)
        .await?;
    if route.as_deref() != Some(namespace)
        || stored.connection_id != r.connection_id()
        || stored.resource.payment_id != r.payment_id()
        || stored.parameters.amount_minor != i64::from(r.amount_minor())
        || stored.parameters.currency != "USD"
    {
        return Err(StoreError::Invalid(
            "payment observation binding mismatch".into(),
        ));
    }
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&(
            "apl.payment.attestation.v1",
            action.tenant_id,
            action.environment_id,
            action.action_id,
            row.get::<Uuid, _>("workload_id"),
            r.connection_id(),
            r.payment_id(),
            r.amount_minor(),
            "USD",
            namespace,
            observation.facts()
        ))?)
    ))
}
pub(super) async fn matches(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    id: Option<Uuid>,
    digest: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT FROM payment_attestations WHERE (tenant_id,environment_id,action_id)=($1,$2,$3) AND id=$4 AND facts_digest=$5)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).bind(id).bind(digest).fetch_one(&mut **tx).await?)
}
pub(super) async fn insert(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    namespace: &str,
    observation: &VerifiedPaymentObservation,
) -> Result<Uuid> {
    validate(tx, observation, observation.request()).await?;
    let digest = digest(tx, action, namespace, observation).await?;
    let id = Uuid::new_v4();
    let r = observation.request();
    let f = observation.facts();
    sqlx::query("INSERT INTO payment_attestations(tenant_id,environment_id,action_id,id,workload_id,connection_id,provider_namespace,payment_id,requested_minor,currency,charge_amount_minor,captured_minor,refunded_minor,captured,paid,disputed,status,method,direct_charge,observed_at_ms,fresh_until_ms,facts_digest) SELECT $1,$2,$3,$4,workload_id,$5,$6,$7,$8,'USD',$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20 FROM actions WHERE (tenant_id,environment_id,id)=($1,$2,$3)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).bind(id).bind(r.connection_id()).bind(namespace).bind(r.payment_id()).bind(i64::from(r.amount_minor()))
        .bind(f.charge_amount_minor as i64).bind(f.captured_minor as i64).bind(f.refunded_minor as i64).bind(f.captured).bind(f.paid).bind(f.disputed).bind(&f.status).bind(&f.method).bind(f.direct_charge).bind(r.observed_at() as i64).bind(r.fresh_until() as i64).bind(digest).execute(&mut **tx).await?;
    sqlx::query("INSERT INTO audit_events SELECT $1,$2,$3,coalesce(max(sequence),0)+1,'payment.attested' FROM audit_events WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).execute(&mut **tx).await?;
    Ok(id)
}
