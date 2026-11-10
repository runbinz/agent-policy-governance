use super::{authorized, context, fetch_action, Result, Store, StoreError};
use apl_domain::{
    evaluate_version, Action, ActionStatus, Approval, ApprovalDecision, ApprovalInput,
    PolicyVersion, Principal, RefundRequest, Reviewer, VersionDecision,
};
use apl_ledger::{BudgetAction, ConfirmedOutcome, Finalization, Reservation};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;

type Tx<'a> = Transaction<'a, Postgres>;

pub(super) struct ExternalInput<'a> {
    pub provider_namespace: &'a str,
    pub request: apl_dispatch::VerifiedRefundRequest,
    pub observation: apl_dispatch::VerifiedPaymentObservation,
    pub customer_ref: Option<&'a str>,
}

#[derive(Clone, Copy)]
struct Job {
    t: Uuid,
    e: Uuid,
    id: Uuid,
}

pub(super) async fn reject_external_candidate(
    tx: &mut Tx<'_>,
    t: Uuid,
    e: Uuid,
    id: Uuid,
) -> Result<()> {
    let job = Job { t, e, id };
    let row = action_row(tx, job).await?;
    if matches!(
        row.get::<&str, _>("status"),
        "received" | "pending_approval" | "ready"
    ) {
        terminal(
            tx,
            job,
            ActionStatus::Denied,
            Some("PROVIDER_CHARGE_INELIGIBLE"),
        )
        .await?;
    }
    Ok(())
}

impl Store {
    pub async fn cancel(&self, principal: &Principal, id: Uuid) -> Result<Action> {
        let job = Job {
            t: principal.tenant_id,
            e: principal.environment_id,
            id,
        };
        let mut tx = self.pool.begin().await?;
        context(&mut tx, job.t, job.e).await?;
        if !lock_job(&mut tx, job).await? {
            return Err(StoreError::NotFound);
        }
        if !authorized(&mut tx, principal, "cancel_action").await? {
            return Err(StoreError::Forbidden);
        }
        let mut action = fetch_action(&mut tx, principal, id)
            .await?
            .ok_or(StoreError::NotFound)?;
        let changed: bool = sqlx::query_scalar("SELECT transition_cancel($1,$2,$3,$4,$5)")
            .bind(job.t)
            .bind(job.e)
            .bind(id)
            .bind(principal.workload_id)
            .bind(principal.connection_id)
            .fetch_one(&mut *tx)
            .await?;
        if !changed {
            return Err(StoreError::Conflict);
        }
        tx.commit().await?;
        action.status = ActionStatus::Cancelled;
        action.reason = Some("ACTION_CANCELLED".into());
        Ok(action)
    }

    pub async fn resolve_reviewer(&self, issuer: &str, subject: &str) -> Result<Option<Reviewer>> {
        let row = sqlx::query("SELECT * FROM lookup_reviewer($1,$2)")
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| Reviewer {
            tenant_id: r.get("tenant_id"),
            environment_id: r.get("environment_id"),
            reviewer_id: r.get("reviewer_id"),
        }))
    }

    pub async fn list_approvals(&self, reviewer: &Reviewer) -> Result<Vec<Approval>> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let rows = sqlx::query(
            "SELECT a.id, a.request, q.connection_id,q.generation,q.policy_version,q.action_digest,              to_char(q.created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS queued_at,              to_char(q.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS expires_at              FROM approvals q JOIN actions a ON (a.tenant_id,a.environment_id,a.id)=(q.tenant_id,q.environment_id,q.action_id)              JOIN policy_bindings b ON (b.tenant_id,b.environment_id,b.connection_id,b.version)=(q.tenant_id,q.environment_id,q.connection_id,q.policy_version)              WHERE q.tenant_id=$1 AND q.environment_id=$2 AND a.status='pending_approval'              AND q.generation=(SELECT max(z.generation) FROM approvals z WHERE (z.tenant_id,z.environment_id,z.action_id)=(q.tenant_id,q.environment_id,q.action_id)) AND q.decision IS NULL AND q.expires_at>clock_timestamp()              AND authorize_reviewer($1,$2,$3,q.connection_id) ORDER BY q.expires_at,a.id",
        ).bind(reviewer.tenant_id).bind(reviewer.environment_id).bind(reviewer.reviewer_id).fetch_all(&mut *tx).await?;
        let approvals = rows
            .into_iter()
            .map(|r| {
                Ok(Approval {
                    action_id: r.get("id"),
                    connection_id: r.get("connection_id"),
                    generation: r.get("generation"),
                    policy_version: r.get("policy_version"),
                    action_digest: r.get("action_digest"),
                    queued_at: r.get("queued_at"),
                    expires_at: r.get("expires_at"),
                    request: serde_json::from_value(r.get("request"))?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        tx.commit().await?;
        Ok(approvals)
    }

    pub async fn decide_approval(
        &self,
        reviewer: &Reviewer,
        id: Uuid,
        input: &ApprovalInput,
    ) -> Result<Action> {
        let job = Job {
            t: reviewer.tenant_id,
            e: reviewer.environment_id,
            id,
        };
        let mut tx = self.pool.begin().await?;
        context(&mut tx, job.t, job.e).await?;
        if !lock_job(&mut tx, job).await? {
            return Err(StoreError::NotFound);
        }
        let row = action_row(&mut tx, job).await?;
        let request: RefundRequest = serde_json::from_value(row.get("request"))?;
        if !reviewer_allowed(&mut tx, job, reviewer.reviewer_id, request.connection_id).await? {
            return Err(StoreError::NotFound);
        }
        if row.get::<&str, _>("status") != "pending_approval" {
            return Err(StoreError::Conflict);
        }
        let Some(policy) = policy(&mut tx, job, request.connection_id).await? else {
            return Err(StoreError::Conflict);
        };
        let principal = Principal {
            tenant_id: job.t,
            environment_id: job.e,
            workload_id: row.get("workload_id"),
            connection_id: request.connection_id,
        };
        let digest = approval_digest(job.id, &principal, &request, &policy)?;
        let Some(review) = latest(&mut tx, job).await? else {
            return Err(StoreError::Conflict);
        };
        let routed: bool = sqlx::query_scalar("SELECT payment_attestation_required($1,$2,$3)")
            .bind(job.t)
            .bind(job.e)
            .bind(request.connection_id)
            .fetch_one(&mut *tx)
            .await?;
        if routed
            && !sqlx::query_scalar::<_, bool>("SELECT payment_review_attested($1,$2,$3,$4)")
                .bind(job.t)
                .bind(job.e)
                .bind(job.id)
                .bind(input.generation)
                .fetch_one(&mut *tx)
                .await?
        {
            return Err(StoreError::Conflict);
        }
        if !review_matches(&review, &policy, request.connection_id, &digest)
            || review.get::<i64, _>("generation") != input.generation
            || digest != input.action_digest
            || review.get::<Option<String>, _>("decision").is_some()
            || evaluate_version(&request, &policy) != VersionDecision::RequireApproval
        {
            return Err(StoreError::Conflict);
        }
        let wrote = sqlx::query("UPDATE approvals SET reviewer_id=$5,decision=$6,decided_at=clock_timestamp()             WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4) AND decision IS NULL AND expires_at>clock_timestamp()")
            .bind(job.t).bind(job.e).bind(job.id).bind(input.generation).bind(reviewer.reviewer_id)
            .bind(input.decision.as_str()).execute(&mut *tx).await?.rows_affected();
        if wrote != 1 {
            return Err(StoreError::Conflict);
        }
        let (status, reason, event) = match input.decision {
            ApprovalDecision::Approve => (ActionStatus::Ready, None, "approval.approved"),
            ApprovalDecision::Reject => (
                ActionStatus::Rejected,
                Some("REVIEW_REJECTED"),
                "approval.rejected",
            ),
        };
        let changed: bool = sqlx::query_scalar("SELECT transition_review($1,$2,$3,$4)")
            .bind(job.t)
            .bind(job.e)
            .bind(job.id)
            .bind(status.as_str())
            .fetch_one(&mut *tx)
            .await?;
        if !changed {
            return Err(StoreError::Conflict);
        }
        event_append(&mut tx, job, event).await?;
        let (outcome, audit_reason) = match input.decision {
            ApprovalDecision::Approve => ("approved", "REVIEW_APPROVED"),
            ApprovalDecision::Reject => ("rejected", "REVIEW_REJECTED"),
        };
        record_policy(
            &mut tx,
            job,
            request.connection_id,
            Some(policy.version),
            outcome,
            audit_reason,
        )
        .await?;
        schedule(&mut tx, job, 0).await?;
        tx.commit().await?;
        Ok(Action {
            id,
            status,
            request,
            reason: reason.map(str::to_owned),
        })
    }
}

pub(super) async fn process(
    tx: &mut Tx<'_>,
    t: Uuid,
    e: Uuid,
    id: Uuid,
    external: Option<ExternalInput<'_>>,
) -> Result<()> {
    let job = Job { t, e, id };
    let row = action_row(tx, job).await?;
    let state: ActionStatus = row
        .get::<&str, _>("status")
        .parse()
        .map_err(|_| StoreError::Invalid("unknown stored state".into()))?;
    if !matches!(
        state,
        ActionStatus::Received | ActionStatus::PendingApproval | ActionStatus::Ready
    ) {
        return complete(tx, job).await;
    }
    let request: RefundRequest = serde_json::from_value(row.get("request"))?;
    if external.as_ref().is_some_and(|input| {
        input.request.connection_id() != request.connection_id
            || input.request.payment_id() != request.resource.payment_id
            || i64::from(input.request.amount_minor()) != request.parameters.amount_minor
            || request.parameters.currency != "USD"
    }) {
        return Err(StoreError::Invalid(
            "verified provider facts do not match the action".into(),
        ));
    }
    if let Some(input) = &external {
        crate::payment_attestation::validate(tx, &input.observation, &input.request).await?;
    }
    let principal = Principal {
        tenant_id: t,
        environment_id: e,
        workload_id: row.get("workload_id"),
        connection_id: request.connection_id,
    };
    if !authorized(tx, &principal, "submit_refund").await? {
        return terminal(tx, job, ActionStatus::Denied, Some("AUTHORIZATION_REVOKED")).await;
    }
    let connection = request.connection_id;
    let route: Option<String> = sqlx::query_scalar("SELECT provider_route($1,$2,$3)")
        .bind(t)
        .bind(e)
        .bind(connection)
        .fetch_one(&mut **tx)
        .await?;
    match (&external, route.as_deref()) {
        (Some(input), Some(route)) if input.provider_namespace == route => {}
        (Some(_), _) => return Err(StoreError::Forbidden),
        (None, Some(_)) => return Ok(()),
        (None, None) => {}
    }
    let Some(policy) = policy(tx, job, connection).await? else {
        terminal(tx, job, ActionStatus::Denied, Some("NO_ACTIVE_POLICY")).await?;
        return record_policy(tx, job, connection, None, "deny", "NO_ACTIVE_POLICY").await;
    };
    let evaluation = evaluate_version(&request, &policy);
    if let VersionDecision::Deny(reason) = evaluation {
        terminal(tx, job, ActionStatus::Denied, Some(reason)).await?;
        return record_policy(tx, job, connection, Some(policy.version), "deny", reason).await;
    }
    if evaluation == VersionDecision::Allow {
        if crate::dispatch_scope_paused(tx, &principal).await? {
            return schedule(tx, job, 5).await;
        }
        if state == ActionStatus::PendingApproval {
            // A newly active policy can allow an old pending action.
            set_state(tx, job, ActionStatus::Ready, None).await?;
        }
        return dispatch(tx, job, connection, policy.version, None, external).await;
    }
    let digest = approval_digest(id, &principal, &request, &policy)?;
    let current = latest(tx, job).await?;
    let action = super::external::ExternalAction {
        tenant_id: t,
        environment_id: e,
        action_id: id,
    };
    let facts_digest = if let Some(input) = &external {
        Some(
            crate::payment_attestation::digest(
                tx,
                action,
                input.provider_namespace,
                &input.observation,
            )
            .await?,
        )
    } else {
        None
    };
    let mut preserve_deadline = false;
    if let Some(review) = &current {
        if review_matches(review, &policy, request.connection_id, &digest) {
            preserve_deadline = true;
            let still_valid: bool = sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)")
                .bind(t).bind(e).bind(id).bind(review.get::<i64,_>("generation")).fetch_one(&mut **tx).await?;
            if !still_valid {
                return expire_approval(tx, job, connection, policy.version).await;
            }
            let facts_match = match &facts_digest {
                Some(d) => {
                    crate::payment_attestation::matches(
                        tx,
                        action,
                        review.get("payment_attestation_id"),
                        d,
                    )
                    .await?
                }
                None => true,
            };
            if facts_match
                && review.get::<Option<String>, _>("decision").as_deref() == Some("approve")
            {
                if let Some(reviewer) = review.get::<Option<Uuid>, _>("reviewer_id") {
                    if reviewer_allowed(tx, job, reviewer, request.connection_id).await? {
                        // Check time after waiting for reviewer locks, at the fake effect boundary.
                        let still_valid: bool = sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)")
                            .bind(t).bind(e).bind(id).bind(review.get::<i64,_>("generation")).fetch_one(&mut **tx).await?;
                        if still_valid {
                            if crate::dispatch_scope_paused(tx, &principal).await? {
                                return park(tx, job, review.get("generation")).await;
                            }
                            return dispatch(
                                tx,
                                job,
                                connection,
                                policy.version,
                                Some(review.get("generation")),
                                external,
                            )
                            .await;
                        }
                        return expire_approval(tx, job, connection, policy.version).await;
                    }
                }
                // Revoked reviewer authority requires a fresh approval.
            } else if facts_match && review.get::<Option<String>, _>("decision").is_none() {
                return park(tx, job, review.get("generation")).await;
            }
        }
    }
    let generation = current
        .as_ref()
        .map_or(1, |r| r.get::<i64, _>("generation") + 1);
    let evidence = if let Some(input) = &external {
        Some(
            crate::payment_attestation::insert(
                tx,
                action,
                input.provider_namespace,
                &input.observation,
            )
            .await?,
        )
    } else {
        None
    };
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,payment_attestation_id)         VALUES($1,$2,$3,$4,$5,$6,$7,CASE WHEN $10 THEN (SELECT expires_at FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4-1)) ELSE clock_timestamp()+$8*interval '1 second' END,$9)")
        .bind(t).bind(e).bind(id).bind(generation).bind(request.connection_id).bind(policy.version)
        .bind(digest).bind(policy.approval_ttl_seconds).bind(evidence).bind(preserve_deadline).execute(&mut **tx).await?;
    set_state(tx, job, ActionStatus::PendingApproval, None).await?;
    event_append(tx, job, "approval.requested").await?;
    record_policy(
        tx,
        job,
        connection,
        Some(policy.version),
        "require_approval",
        "APPROVAL_REQUIRED",
    )
    .await?;
    park(tx, job, generation).await
}

async fn lock_job(tx: &mut Tx<'_>, job: Job) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT lock_approval_job($1,$2,$3)")
        .bind(job.t)
        .bind(job.e)
        .bind(job.id)
        .fetch_one(&mut **tx)
        .await?)
}
async fn expire_approval(tx: &mut Tx<'_>, job: Job, connection: Uuid, version: i64) -> Result<()> {
    terminal(tx, job, ActionStatus::Expired, Some("APPROVAL_EXPIRED")).await?;
    record_policy(
        tx,
        job,
        connection,
        Some(version),
        "expired",
        "APPROVAL_EXPIRED",
    )
    .await
}
async fn record_policy(
    tx: &mut Tx<'_>,
    job: Job,
    connection: Uuid,
    version: Option<i64>,
    outcome: &str,
    reason: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO action_policy_decisions(tenant_id,environment_id,action_id,audit_sequence,connection_id,policy_version,outcome,reason)
        SELECT $1,$2,$3,max(sequence),$4,$5,$6,$7 FROM audit_events
        WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
        .bind(job.t).bind(job.e).bind(job.id).bind(connection).bind(version).bind(outcome).bind(reason)
        .execute(&mut **tx).await?;
    Ok(())
}

async fn action_row(tx: &mut Tx<'_>, job: Job) -> Result<PgRow> {
    // The caller holds the private outbox row before reading or updating this action.
    sqlx::query("SELECT request,workload_id,status FROM actions WHERE (tenant_id,environment_id,id)=($1,$2,$3)")
        .bind(job.t).bind(job.e).bind(job.id).fetch_optional(&mut **tx).await?.ok_or(StoreError::NotFound)
}
async fn reviewer_allowed(
    tx: &mut Tx<'_>,
    job: Job,
    reviewer: Uuid,
    connection: Uuid,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT authorize_reviewer($1,$2,$3,$4)")
        .bind(job.t)
        .bind(job.e)
        .bind(reviewer)
        .bind(connection)
        .fetch_one(&mut **tx)
        .await?)
}
async fn policy(tx: &mut Tx<'_>, job: Job, connection: Uuid) -> Result<Option<PolicyVersion>> {
    let row = sqlx::query("SELECT * FROM active_policy($1,$2,$3)")
        .bind(job.t)
        .bind(job.e)
        .bind(connection)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(|r| PolicyVersion {
        version: r.get("version"),
        auto_limit_minor: r.get("auto_limit_minor"),
        hard_limit_minor: r.get("hard_limit_minor"),
        approval_ttl_seconds: r.get("approval_ttl_seconds"),
    }))
}
fn approval_digest(
    id: Uuid,
    p: &Principal,
    r: &RefundRequest,
    policy: &PolicyVersion,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        "apl.refund.approval.v1",
        id,
        p.tenant_id,
        p.environment_id,
        p.workload_id,
        p.connection_id,
        policy.version,
        r,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
async fn latest(tx: &mut Tx<'_>, job: Job) -> Result<Option<PgRow>> {
    Ok(sqlx::query("SELECT generation,connection_id,policy_version,action_digest,decision,reviewer_id,payment_attestation_id FROM approvals         WHERE (tenant_id,environment_id,action_id)=($1,$2,$3) ORDER BY generation DESC LIMIT 1")
        .bind(job.t).bind(job.e).bind(job.id).fetch_optional(&mut **tx).await?)
}
fn review_matches(row: &PgRow, policy: &PolicyVersion, connection: Uuid, digest: &str) -> bool {
    row.get::<i64, _>("policy_version") == policy.version
        && row.get::<Uuid, _>("connection_id") == connection
        && row.get::<String, _>("action_digest") == digest
}
async fn event_append(tx: &mut Tx<'_>, job: Job, event: &str) -> Result<()> {
    sqlx::query("INSERT INTO audit_events SELECT $1,$2,$3,coalesce(max(sequence),0)+1,$4         FROM audit_events WHERE (tenant_id,environment_id,action_id)=($1,$2,$3)")
        .bind(job.t).bind(job.e).bind(job.id).bind(event).execute(&mut **tx).await?;
    Ok(())
}
async fn schedule(tx: &mut Tx<'_>, job: Job, delay: i64) -> Result<()> {
    sqlx::query("SELECT schedule_approval_job($1,$2,$3,$4)")
        .bind(job.t)
        .bind(job.e)
        .bind(job.id)
        .bind(delay)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn park(tx: &mut Tx<'_>, job: Job, generation: i64) -> Result<()> {
    let seconds:i64=sqlx::query_scalar("SELECT least(5,greatest(1,ceil(extract(epoch FROM expires_at-clock_timestamp()))))::bigint         FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)")
        .bind(job.t).bind(job.e).bind(job.id).bind(generation).fetch_one(&mut **tx).await?;
    schedule(tx, job, seconds).await
}
async fn complete(tx: &mut Tx<'_>, job: Job) -> Result<()> {
    sqlx::query("SELECT complete_job($1,$2,$3)")
        .bind(job.t)
        .bind(job.e)
        .bind(job.id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
async fn set_state(
    tx: &mut Tx<'_>,
    job: Job,
    status: ActionStatus,
    reason: Option<&str>,
) -> Result<()> {
    sqlx::query(
        "UPDATE actions SET status=$4,reason=$5 WHERE (tenant_id,environment_id,id)=($1,$2,$3)",
    )
    .bind(job.t)
    .bind(job.e)
    .bind(job.id)
    .bind(status.as_str())
    .bind(reason)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
async fn terminal(
    tx: &mut Tx<'_>,
    job: Job,
    status: ActionStatus,
    reason: Option<&str>,
) -> Result<()> {
    set_state(tx, job, status, reason).await?;
    event_append(tx, job, &format!("action.{}", status.as_str())).await?;
    complete(tx, job).await
}
async fn dispatch(
    tx: &mut Tx<'_>,
    job: Job,
    connection: Uuid,
    version: i64,
    generation: Option<i64>,
    external: Option<ExternalInput<'_>>,
) -> Result<()> {
    let action = BudgetAction {
        tenant_id: job.t,
        environment_id: job.e,
        action_id: job.id,
    };
    // The synthetic provider has no verified customer identity. Do not use caller
    // metadata as a customer fact. Only a new hold can authorize this fake effect.
    let customer = external.as_ref().and_then(|input| input.customer_ref);
    if let Some(input) = &external {
        let payment = input.request.payment_id();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(serde_json::to_string(&(input.provider_namespace, payment))?)
            .execute(&mut **tx)
            .await?;
        let busy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM external_dispatches WHERE provider_namespace=$1 AND snapshot#>>'{request,payment_id}'=$2 AND NOT closed)")
            .bind(input.provider_namespace).bind(payment).fetch_one(&mut **tx).await?;
        let observed_ms = i64::try_from(input.request.observed_at()).map_err(|_| {
            StoreError::Invalid("provider observation timestamp out of range".into())
        })?;
        let changed: bool =
            sqlx::query_scalar("SELECT external_payment_changed_since($1,$2,$3,$4,$5)")
                .bind(job.t)
                .bind(job.e)
                .bind(input.provider_namespace)
                .bind(payment)
                .bind(observed_ms)
                .fetch_one(&mut **tx)
                .await?;
        if busy || changed {
            return schedule(tx, job, 5).await;
        }
    }
    let held = apl_ledger::reserve(tx, action, connection, customer).await?;
    let denied = match held {
        Reservation::NewHold => None,
        Reservation::NotConfigured => Some("BUDGET_NOT_CONFIGURED"),
        Reservation::DailyExceeded => Some("BUDGET_DAILY_EXCEEDED"),
        Reservation::ExposureExceeded => Some("BUDGET_EXPOSURE_EXCEEDED"),
        _ => return Err(StoreError::BudgetState),
    };
    if let Some(reason) = denied {
        if let Some(generation) = generation {
            let unexpired:bool=sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)")
                .bind(job.t).bind(job.e).bind(job.id).bind(generation).fetch_one(&mut **tx).await?;
            if !unexpired {
                return expire_approval(tx, job, connection, version).await;
            }
        }
        terminal(tx, job, ActionStatus::Denied, Some(reason)).await?;
        return record_policy(tx, job, connection, Some(version), "deny", reason).await;
    }

    if let Some(input) = external {
        if let Some(generation) = generation {
            let unexpired: bool = sqlx::query_scalar("SELECT expires_at>clock_timestamp() FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)")
                .bind(job.t).bind(job.e).bind(job.id).bind(generation).fetch_one(&mut **tx).await?;
            if !unexpired {
                if apl_ledger::finalize(tx, action, ConfirmedOutcome::NonExecution).await?
                    != Finalization::Released
                {
                    return Err(StoreError::BudgetState);
                }
                return expire_approval(tx, job, connection, version).await;
            }
        }
        super::external::prepare(
            tx,
            super::external::ExternalAction {
                tenant_id: job.t,
                environment_id: job.e,
                action_id: job.id,
            },
            input.provider_namespace,
            input.request,
            input.observation,
            version,
            generation,
        )
        .await?;
        let reason = if generation.is_some() {
            "APPROVAL_SATISFIED"
        } else {
            "POLICY_AUTO_ALLOW"
        };
        return record_policy(tx, job, connection, Some(version), "allow", reason).await;
    }

    // Budget locking may have taken long enough for the approval to expire.
    // Check again in the effect statement itself. The fake effect is a database
    // row, so its write and accounting settle together; no external call occurs.
    let effects=sqlx::query("INSERT INTO fake_effects(tenant_id,environment_id,action_id)
        SELECT $1,$2,$3 WHERE $4::bigint IS NULL OR EXISTS (
            SELECT 1 FROM approvals WHERE (tenant_id,environment_id,action_id,generation)=($1,$2,$3,$4)
              AND decision='approve' AND expires_at>clock_timestamp())")
        .bind(job.t).bind(job.e).bind(job.id).bind(generation)
        .execute(&mut **tx).await?.rows_affected();
    if effects == 0 {
        if generation.is_none()
            || apl_ledger::finalize(tx, action, ConfirmedOutcome::NonExecution).await?
                != Finalization::Released
        {
            return Err(StoreError::BudgetState);
        }
        return expire_approval(tx, job, connection, version).await;
    }
    if effects != 1
        || apl_ledger::finalize(tx, action, ConfirmedOutcome::Success).await?
            != Finalization::Settled
    {
        return Err(StoreError::BudgetState);
    }
    terminal(tx, job, ActionStatus::Succeeded, None).await?;
    let reason = if generation.is_some() {
        "APPROVAL_SATISFIED"
    } else {
        "POLICY_AUTO_ALLOW"
    };
    record_policy(tx, job, connection, Some(version), "allow", reason).await
}
