//! Durable provider-neutral handoff. No provider calls occur inside a database transaction.
use crate::{authorized, context, Result, Store, StoreError};
use apl_dispatch::{
    BudgetEffect, Dispatch, DispatchError, DispatchState, Lease, NextStep, ProviderOutcome,
    ReplaySafety, VerifiedRefundRequest,
};
use apl_domain::{
    evaluate_version, PolicyVersion, Principal, RefundRequest, Reviewer, VersionDecision,
};
use apl_ledger::{BudgetAction, ConfirmedOutcome, Finalization};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;

type Tx<'a> = Transaction<'a, Postgres>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExternalAction {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub action_id: Uuid,
}

#[derive(Debug)]
pub struct ExternalCandidate {
    pub action: ExternalAction,
    pub request: RefundRequest,
    pub observed_at: u64,
}
impl From<ExternalAction> for BudgetAction {
    fn from(action: ExternalAction) -> Self {
        Self {
            tenant_id: action.tenant_id,
            environment_id: action.environment_id,
            action_id: action.action_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ExternalClaim {
    pub action: ExternalAction,
    pub provider_namespace: String,
    pub lease: Lease,
    pub dispatch: Dispatch,
    pub next_step: NextStep,
}

pub async fn database_now(tx: &mut Tx<'_>) -> Result<u64> {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    u64::try_from(now).map_err(|_| DispatchError::InvalidSnapshot.into())
}

/// Stage an external refund in the same transaction as the initial budget hold.
/// The caller must roll back on error. No provider I/O is authorized here.
pub(super) async fn prepare(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    provider_namespace: &str,
    request: VerifiedRefundRequest,
    observation: apl_dispatch::VerifiedPaymentObservation,
    policy_version: i64,
    approval_generation: Option<i64>,
) -> Result<()> {
    validate_namespace(provider_namespace)?;
    context(tx, action.tenant_id, action.environment_id).await?;
    let job_locked: bool = sqlx::query_scalar("SELECT lock_approval_job($1,$2,$3)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .fetch_one(&mut **tx)
        .await?;
    if !job_locked {
        return Err(StoreError::NotFound);
    }
    let row = action_row(tx, action).await?;
    if !matches!(row.get::<&str, _>("status"), "received" | "ready") {
        return Err(DispatchError::SendForbidden.into());
    }
    crate::payment_attestation::validate(tx, &observation, &request).await?;
    let evidence =
        crate::payment_attestation::insert(tx, action, provider_namespace, &observation).await?;
    let auth = Authorization {
        payment_attestation_id: Some(evidence),
        request: &request,
        policy_version,
        approval_generation,
    };
    if !send_authorized(tx, action, &row, &auth).await? {
        return Err(DispatchError::SendForbidden.into());
    }
    let now = database_now(tx).await?;
    let dispatch = Dispatch::authorize(action.action_id, request, now)?;
    sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,
        provider_key,policy_version,approval_generation,snapshot,available_at_ms,payment_attestation_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id)
        .bind(dispatch.snapshot().request.connection_id()).bind(provider_namespace).bind(dispatch.provider_key().as_str())
        .bind(policy_version).bind(approval_generation).bind(serde_json::to_value(dispatch.snapshot())?).bind(as_bigint(now)?).bind(evidence)
        .execute(&mut **tx).await?;
    set_status(tx, action, "dispatching", None).await?;
    audit(tx, action, "dispatch.authorized").await?;
    sqlx::query("SELECT complete_job($1,$2,$3)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

impl Store {
    pub async fn request_external_reconciliation(
        &self,
        operator: &Reviewer,
        id: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, operator.tenant_id, operator.environment_id).await?;
        let result: String =
            sqlx::query_scalar("SELECT request_external_reconciliation($1,$2,$3,$4)")
                .bind(operator.tenant_id)
                .bind(operator.environment_id)
                .bind(id)
                .bind(operator.reviewer_id)
                .fetch_one(&mut *tx)
                .await?;
        match result.as_str() {
            "queued" => {
                // Queue lock is retained by the SQL request. Validate the exact
                // stored dispatch before committing either scheduling or audit.
                crate::operations_recovery::validate_reconciliation_in_tx(&mut tx, operator, id)
                    .await?;
                tx.commit().await.map_err(Into::into)
            }
            "hidden" => Err(StoreError::NotFound),
            "not_manual" => Err(StoreError::Conflict),
            _ => Err(StoreError::Invalid("invalid reconciliation result".into())),
        }
    }
    /// Used only after the API authenticates the raw Stripe webhook body.
    pub async fn ingest_stripe_wake(
        &self,
        namespace: &str,
        event_id: &str,
        event_type: &str,
        refund_id: &str,
        charge_id: &str,
        correlation: Option<&str>,
    ) -> Result<bool> {
        Ok(
            sqlx::query_scalar("SELECT ingest_stripe_wake($1,$2,$3,$4,$5,$6)")
                .bind(namespace)
                .bind(event_id)
                .bind(event_type)
                .bind(refund_id)
                .bind(charge_id)
                .bind(correlation)
                .fetch_one(&self.pool)
                .await?,
        )
    }
    pub async fn next_external_candidate(
        &self,
        namespace: &str,
    ) -> Result<Option<ExternalCandidate>> {
        validate_namespace(namespace)?;
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query("SELECT * FROM external_candidate($1)")
            .bind(namespace)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            tx.commit().await?;
            return Ok(None);
        };
        let action = ExternalAction {
            tenant_id: row.get("tenant_id"),
            environment_id: row.get("environment_id"),
            action_id: row.get("action_id"),
        };
        context(&mut tx, action.tenant_id, action.environment_id).await?;
        let row = sqlx::query(
            "SELECT request FROM actions WHERE (tenant_id,environment_id,id)=($1,$2,$3)",
        )
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .fetch_one(&mut *tx)
        .await?;
        let request = serde_json::from_value(row.get("request"))?;
        let observed_at = database_now(&mut tx).await?;
        tx.commit().await?;
        Ok(Some(ExternalCandidate {
            action,
            request,
            observed_at,
        }))
    }

    pub async fn defer_external_candidate(
        &self,
        candidate: &ExternalCandidate,
        namespace: &str,
    ) -> Result<()> {
        self.finish_candidate_check(candidate, namespace, false)
            .await
    }

    pub async fn reject_external_candidate(
        &self,
        candidate: &ExternalCandidate,
        namespace: &str,
    ) -> Result<()> {
        self.finish_candidate_check(candidate, namespace, true)
            .await
    }

    async fn finish_candidate_check(
        &self,
        candidate: &ExternalCandidate,
        namespace: &str,
        reject: bool,
    ) -> Result<()> {
        let action = candidate.action;
        let mut tx = self.pool.begin().await?;
        context(&mut tx, action.tenant_id, action.environment_id).await?;
        let route: Option<String> = sqlx::query_scalar("SELECT provider_route($1,$2,$3)")
            .bind(action.tenant_id)
            .bind(action.environment_id)
            .bind(candidate.request.connection_id)
            .fetch_one(&mut *tx)
            .await?;
        if route.as_deref() != Some(namespace) {
            return Err(StoreError::Forbidden);
        }
        let locked: bool = sqlx::query_scalar("SELECT lock_approval_job($1,$2,$3)")
            .bind(action.tenant_id)
            .bind(action.environment_id)
            .bind(action.action_id)
            .fetch_one(&mut *tx)
            .await?;
        if !locked {
            return Err(StoreError::NotFound);
        }
        if reject {
            crate::approvals::reject_external_candidate(
                &mut tx,
                action.tenant_id,
                action.environment_id,
                action.action_id,
            )
            .await?;
        } else {
            sqlx::query("SELECT schedule_approval_job($1,$2,$3,5)")
                .bind(action.tenant_id)
                .bind(action.environment_id)
                .bind(action.action_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn claim_external(
        &self,
        provider_namespace: &str,
        duration_ms: u64,
        replay: ReplaySafety,
    ) -> Result<Option<ExternalClaim>> {
        validate_namespace(provider_namespace)?;
        if !(1..=300_000).contains(&duration_ms) {
            return Err(DispatchError::InvalidLease.into());
        }
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query("SELECT * FROM claim_external_dispatch($1)")
            .bind(provider_namespace)
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let action = ExternalAction {
            tenant_id: row.get("tenant_id"),
            environment_id: row.get("environment_id"),
            action_id: row.get("action_id"),
        };
        context(&mut tx, action.tenant_id, action.environment_id).await?;
        let row = dispatch_row(&mut tx, action).await?;
        let mut dispatch = restore(&row, action)?;
        let now = database_now(&mut tx).await?;
        let lease = dispatch.claim(now, duration_ms)?;
        let next_step = dispatch.next_step(lease, now, replay)?;
        save(&mut tx, action, &dispatch, now).await?;
        tx.commit().await?;
        Ok(Some(ExternalClaim {
            action,
            provider_namespace: provider_namespace.into(),
            lease,
            dispatch,
            next_step,
        }))
    }

    /// Commit the attempt before returning. A crash after this call always
    /// leaves a possible send; the next worker must reconcile first.
    pub async fn begin_external_send(
        &self,
        claim: &ExternalClaim,
        replay: ReplaySafety,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = lock_claim(&mut tx, claim).await?;
        let mut dispatch = restore(&row, claim.action)?;
        let action = action_row(&mut tx, claim.action).await?;
        let auth = Authorization {
            payment_attestation_id: row.get("payment_attestation_id"),
            request: &dispatch.snapshot().request,
            policy_version: row.get("policy_version"),
            approval_generation: row.get("approval_generation"),
        };
        // A pre-attestation authorization may be recovered, but must not start
        // a new provider call without retained evidence. The worker can abandon
        // this provably unsent record; marked sends still reconcile normally.
        if dispatch.snapshot().first_send_at.is_none() && auth.payment_attestation_id.is_none() {
            return Err(DispatchError::SendForbidden.into());
        }
        if action.get::<&str, _>("status") != "dispatching"
            || !send_authorized(&mut tx, claim.action, &action, &auth).await?
        {
            return Err(DispatchError::SendForbidden.into());
        }
        let now = database_now(&mut tx).await?;
        dispatch.begin_send(claim.lease, now, replay)?;
        sqlx::query("INSERT INTO external_attempts(tenant_id,environment_id,action_id,generation,marked_at_ms) VALUES($1,$2,$3,$4,$5)")
            .bind(claim.action.tenant_id).bind(claim.action.environment_id).bind(claim.action.action_id)
            .bind(as_bigint(claim.lease.generation)?).bind(as_bigint(now)?).execute(&mut *tx).await?;
        save(&mut tx, claim.action, &dispatch, now).await?;
        audit(&mut tx, claim.action, "dispatch.send_marked").await?;
        tx.commit().await?;
        Ok(())
    }

    /// Last local check before a caller starts provider I/O. No database
    /// check can fence a socket; once marked, a skipped send is reconciled.
    pub async fn external_send_still_current(&self, claim: &ExternalClaim) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let row = match lock_claim(&mut tx, claim).await {
            Ok(row) => row,
            Err(StoreError::Dispatch(DispatchError::StaleLease)) => return Ok(false),
            Err(error) => return Err(error),
        };
        let dispatch = restore(&row, claim.action)?;
        let attempted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT FROM external_attempts
            WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4))",
        )
        .bind(claim.action.tenant_id)
        .bind(claim.action.environment_id)
        .bind(claim.action.action_id)
        .bind(as_bigint(claim.lease.generation)?)
        .fetch_one(&mut *tx)
        .await?;
        if !attempted || dispatch.snapshot().state != DispatchState::InFlight {
            tx.commit().await?;
            return Ok(false);
        }
        let action = action_row(&mut tx, claim.action).await?;
        let auth = Authorization {
            payment_attestation_id: row.get("payment_attestation_id"),
            request: &dispatch.snapshot().request,
            policy_version: row.get("policy_version"),
            approval_generation: row.get("approval_generation"),
        };
        let authorized = action.get::<&str, _>("status") == "dispatching"
            && send_authorized(&mut tx, claim.action, &action, &auth).await?;
        let now = database_now(&mut tx).await?;
        let valid =
            authorized && now < claim.lease.expires_at && dispatch.snapshot().request.is_fresh(now);
        tx.commit().await?;
        Ok(valid)
    }

    /// Verified observations can settle or release exposure. Unknown and
    /// pending observations deliberately leave the ledger hold untouched.
    pub async fn observe_external(
        &self,
        claim: &ExternalClaim,
        outcome: ProviderOutcome,
    ) -> Result<DispatchState> {
        let mut tx = self.pool.begin().await?;
        let row = lock_claim(&mut tx, claim).await?;
        let mut dispatch = restore(&row, claim.action)?;
        let now = database_now(&mut tx).await?;
        let effect = dispatch.observe(claim.lease, now, outcome)?;
        let mut observations: i32 = row.get("observations");
        if effect == BudgetEffect::KeepHold
            && dispatch.snapshot().state != DispatchState::ManualReview
        {
            observations += 1;
            if observations >= 8 {
                dispatch.require_manual_review(claim.lease, now)?;
            }
            sqlx::query("UPDATE external_dispatches SET observations=$4 WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
                .bind(claim.action.tenant_id).bind(claim.action.environment_id).bind(claim.action.action_id)
                .bind(observations).execute(&mut *tx).await?;
        }
        let state = dispatch.snapshot().state.clone();
        let delay_ms = (1000_u64 << observations.saturating_sub(1).max(0)).min(60_000);
        let (delay, event) = match &state {
            DispatchState::Succeeded(_) => {
                finalize(
                    &mut tx,
                    claim.action,
                    ConfirmedOutcome::Success,
                    Finalization::Settled,
                )
                .await?;
                set_status(&mut tx, claim.action, "succeeded", None).await?;
                (0, "dispatch.succeeded")
            }
            DispatchState::FailedConfirmed(_) => {
                finalize(
                    &mut tx,
                    claim.action,
                    ConfirmedOutcome::NonExecution,
                    Finalization::Released,
                )
                .await?;
                set_status(
                    &mut tx,
                    claim.action,
                    "failed_confirmed",
                    Some("PROVIDER_CONFIRMED_NON_EXECUTION"),
                )
                .await?;
                (0, "dispatch.failed_confirmed")
            }
            DispatchState::Pending => (delay_ms, "dispatch.pending"),
            DispatchState::Unknown => (delay_ms, "dispatch.unknown"),
            DispatchState::ManualReview => (30_000, "dispatch.manual_review"),
            _ => return Err(DispatchError::InvalidSnapshot.into()),
        };
        debug_assert_eq!(state.is_terminal(), effect != BudgetEffect::KeepHold);
        save(&mut tx, claim.action, &dispatch, now.saturating_add(delay)).await?;
        audit(&mut tx, claim.action, event).await?;
        tx.commit().await?;
        Ok(state)
    }

    /// Close an authorized attempt that provably has no send marker. Once
    /// a marker exists, only verified provider evidence can release the hold.
    pub async fn abandon_external_unsent(&self, claim: &ExternalClaim) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let row = lock_claim(&mut tx, claim).await?;
        let dispatch = restore(&row, claim.action)?;
        let now = database_now(&mut tx).await?;
        if dispatch.snapshot().lease != Some(claim.lease) || now >= claim.lease.expires_at {
            return Err(DispatchError::StaleLease.into());
        }
        if dispatch.snapshot().state != DispatchState::Authorized
            || dispatch.snapshot().first_send_at.is_some()
        {
            return Err(DispatchError::SendForbidden.into());
        }
        finalize(
            &mut tx,
            claim.action,
            ConfirmedOutcome::NonExecution,
            Finalization::Released,
        )
        .await?;
        sqlx::query("UPDATE external_dispatches SET abandoned_at_ms=$4 WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
            .bind(claim.action.tenant_id).bind(claim.action.environment_id).bind(claim.action.action_id)
            .bind(as_bigint(now)?).execute(&mut *tx).await?;
        set_status(
            &mut tx,
            claim.action,
            "denied",
            Some("EXTERNAL_UNSENT_ABANDONED"),
        )
        .await?;
        audit(&mut tx, claim.action, "dispatch.abandoned_unsent").await?;
        tx.commit().await?;
        Ok(())
    }
}

struct Authorization<'a> {
    payment_attestation_id: Option<Uuid>,
    request: &'a VerifiedRefundRequest,
    policy_version: i64,
    approval_generation: Option<i64>,
}

async fn send_authorized(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    row: &PgRow,
    auth: &Authorization<'_>,
) -> Result<bool> {
    let request: RefundRequest = serde_json::from_value(row.get("request"))?;
    let connection = request.connection_id;
    if connection != auth.request.connection_id()
        || request.resource.payment_id != auth.request.payment_id()
        || request.parameters.amount_minor != i64::from(auth.request.amount_minor())
        || request.parameters.currency != "USD"
    {
        return Ok(false);
    }
    let principal = Principal {
        tenant_id: action.tenant_id,
        environment_id: action.environment_id,
        workload_id: row.get("workload_id"),
        connection_id: connection,
    };
    if !authorized(tx, &principal, "submit_refund").await? {
        return Ok(false);
    }
    if crate::dispatch_scope_paused(tx, &principal).await? {
        return Ok(false);
    }
    let Some(row) = sqlx::query("SELECT * FROM active_policy($1,$2,$3)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(connection)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(false);
    };
    let policy = PolicyVersion {
        version: row.get("version"),
        auto_limit_minor: row.get("auto_limit_minor"),
        hard_limit_minor: row.get("hard_limit_minor"),
        approval_ttl_seconds: row.get("approval_ttl_seconds"),
    };
    if policy.version != auth.policy_version {
        return Ok(false);
    }
    match (
        evaluate_version(&request, &policy),
        auth.approval_generation,
    ) {
        (VersionDecision::Allow, None) => {}
        (VersionDecision::RequireApproval, Some(generation)) => {
            let digest = format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&(
                    "apl.refund.approval.v1",
                    action.action_id,
                    action.tenant_id,
                    action.environment_id,
                    principal.workload_id,
                    connection,
                    policy.version,
                    &request,
                ))?)
            );
            let Some(reviewer):Option<Uuid>=sqlx::query_scalar(
                "SELECT reviewer_id FROM approvals q WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)
                 AND (connection_id,policy_version,action_digest)=($5,$6,$7) AND decision='approve'
                 AND expires_at>clock_timestamp()
                 AND generation=(SELECT max(p.generation) FROM approvals p WHERE (p.tenant_id,p.environment_id,p.action_id)=($1,$2,$3))")
                .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).bind(generation)
                .bind(connection).bind(policy.version).bind(digest).fetch_optional(&mut **tx).await?
            else {return Ok(false);};
            let allowed: bool = sqlx::query_scalar("SELECT authorize_reviewer($1,$2,$3,$4)")
                .bind(action.tenant_id)
                .bind(action.environment_id)
                .bind(reviewer)
                .bind(connection)
                .fetch_one(&mut **tx)
                .await?;
            if !allowed {
                return Ok(false);
            }
        }
        _ => return Ok(false),
    }
    if let Some(evidence) = auth.payment_attestation_id {
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT FROM payment_attestations p WHERE (p.tenant_id,p.environment_id,p.action_id,p.id)=($1,$2,$3,$4) AND p.connection_id=$5 AND p.payment_id=$6 AND p.requested_minor=$7 AND p.observed_at_ms=$8 AND p.fresh_until_ms=$9 AND p.provider_namespace=provider_route($1,$2,$5) AND ($10::bigint IS NULL OR EXISTS(SELECT FROM approvals q JOIN payment_attestations v ON (v.tenant_id,v.environment_id,v.action_id,v.id)=(q.tenant_id,q.environment_id,q.action_id,q.payment_attestation_id) WHERE (q.tenant_id,q.environment_id,q.action_id,q.generation)=($1,$2,$3,$10) AND v.facts_digest=p.facts_digest)))")
            .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).bind(evidence).bind(connection).bind(auth.request.payment_id()).bind(i64::from(auth.request.amount_minor())).bind(as_bigint(auth.request.observed_at())?).bind(as_bigint(auth.request.fresh_until())?).bind(auth.approval_generation).fetch_one(&mut **tx).await?;
        if !valid {
            return Ok(false);
        }
    }
    let held: bool = sqlx::query_scalar("SELECT external_hold_matches($1,$2,$3,$4,$5,$6)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .bind(connection)
        .bind(principal.workload_id)
        .bind(request.parameters.amount_minor)
        .fetch_one(&mut **tx)
        .await?;
    if !held {
        return Ok(false);
    }
    if auth.payment_attestation_id.is_some() && !auth.request.is_fresh(database_now(tx).await?) {
        return Ok(false);
    }
    // Recheck the review clock after all potentially contended locks.
    if let Some(generation) = auth.approval_generation {
        return Ok(sqlx::query_scalar(
            "SELECT expires_at>clock_timestamp() FROM approvals
          WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)",
        )
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .bind(generation)
        .fetch_one(&mut **tx)
        .await?);
    }
    Ok(true)
}

async fn lock_claim(tx: &mut Tx<'_>, claim: &ExternalClaim) -> Result<PgRow> {
    let action = claim.action;
    context(tx, action.tenant_id, action.environment_id).await?;
    let locked: bool = sqlx::query_scalar("SELECT lock_external_dispatch($1,$2,$3)")
        .bind(action.tenant_id)
        .bind(action.environment_id)
        .bind(action.action_id)
        .fetch_one(&mut **tx)
        .await?;
    if !locked {
        return Err(DispatchError::StaleLease.into());
    }
    let row = dispatch_row(tx, action).await?;
    if row.get::<bool, _>("closed")
        || row.get::<&str, _>("provider_namespace") != claim.provider_namespace
    {
        return Err(DispatchError::StaleLease.into());
    }
    let dispatch = restore(&row, action)?;
    if dispatch.snapshot().lease != Some(claim.lease)
        || database_now(tx).await? >= claim.lease.expires_at
    {
        return Err(DispatchError::StaleLease.into());
    }
    Ok(row)
}
async fn action_row(tx: &mut Tx<'_>, action: ExternalAction) -> Result<PgRow> {
    sqlx::query("SELECT status,workload_id,request FROM actions WHERE (tenant_id,environment_id,id)=($1,$2,$3)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).fetch_optional(&mut **tx)
        .await?.ok_or(StoreError::NotFound)
}
async fn dispatch_row(tx: &mut Tx<'_>, action: ExternalAction) -> Result<PgRow> {
    sqlx::query(
        "SELECT snapshot,provider_key,provider_namespace,policy_version,approval_generation,payment_attestation_id,closed,observations
        FROM external_dispatches WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)",
    )
    .bind(action.tenant_id)
    .bind(action.environment_id)
    .bind(action.action_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(StoreError::NotFound)
}
fn restore(row: &PgRow, action: ExternalAction) -> Result<Dispatch> {
    let dispatch = Dispatch::restore(serde_json::from_value(row.get("snapshot"))?)?;
    if dispatch.snapshot().action_id != action.action_id
        || dispatch.provider_key().as_str() != row.get::<&str, _>("provider_key")
    {
        return Err(DispatchError::InvalidSnapshot.into());
    }
    Ok(dispatch)
}
async fn save(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    dispatch: &Dispatch,
    available_at: u64,
) -> Result<()> {
    sqlx::query("UPDATE external_dispatches SET snapshot=$4,available_at_ms=$5 WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id)
        .bind(serde_json::to_value(dispatch.snapshot())?).bind(as_bigint(available_at)?).execute(&mut **tx).await?;
    Ok(())
}
async fn set_status(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    status: &str,
    reason: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE actions SET status=$4,reason=$5 WHERE (tenant_id,environment_id,id)=($1,$2,$3)",
    )
    .bind(action.tenant_id)
    .bind(action.environment_id)
    .bind(action.action_id)
    .bind(status)
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
async fn audit(tx: &mut Tx<'_>, action: ExternalAction, event: &str) -> Result<()> {
    sqlx::query("INSERT INTO audit_events(tenant_id,environment_id,action_id,sequence,event_type)
        SELECT $1,$2,$3,coalesce(max(sequence),0)+1,$4 FROM audit_events WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
        .bind(action.tenant_id).bind(action.environment_id).bind(action.action_id).bind(event)
        .execute(&mut **tx).await?;
    Ok(())
}
async fn finalize(
    tx: &mut Tx<'_>,
    action: ExternalAction,
    outcome: ConfirmedOutcome,
    expected: Finalization,
) -> Result<()> {
    if apl_ledger::finalize(tx, action.into(), outcome).await? != expected {
        return Err(StoreError::BudgetState);
    }
    Ok(())
}
fn as_bigint(n: u64) -> Result<i64> {
    i64::try_from(n).map_err(|_| DispatchError::InvalidLease.into())
}
fn validate_namespace(ns: &str) -> Result<()> {
    if ns.is_empty()
        || ns.len() > 128
        || !ns
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
    {
        return Err(StoreError::Invalid("invalid provider namespace".into()));
    }
    Ok(())
}
