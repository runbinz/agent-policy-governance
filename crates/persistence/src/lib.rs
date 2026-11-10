pub mod action_detail;
mod admin;
mod approvals;
pub mod browser;
pub mod dispatch_controls;
pub mod environment_admin;
pub mod evidence;
pub mod exports;
pub mod external;
pub mod notifications;
pub mod operations;
pub mod operations_recovery;
mod payment_attestation;
pub mod policy_console;
pub mod service_metrics;

use apl_domain::{Action, ActionStatus, AuditEvent, Principal, RefundRequest};
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("idempotency key already used with different request")]
    Conflict,
    #[error("action not found")]
    NotFound,
    #[error("connection not authorized")]
    Forbidden,
    #[error("{0}")]
    Invalid(String),
    #[error("budget state inconsistent with an unexecuted action")]
    BudgetState,
    #[error(transparent)]
    Ledger(#[from] apl_ledger::LedgerError),
    #[error(transparent)]
    Dispatch(#[from] apl_dispatch::DispatchError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error(transparent)]
    Migration(#[from] sqlx::migrate::MigrateError),
}
impl StoreError {
    /// Bounded safe diagnostics. Display/Debug can contain database details or
    /// untrusted validation text and must not be emitted to production logs.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::NotFound => "not_found",
            Self::Forbidden => "forbidden",
            Self::Invalid(_) => "invalid",
            Self::BudgetState => "budget_state",
            Self::Ledger(_) => "ledger",
            Self::Dispatch(_) => "dispatch",
            Self::Database(_) => "database",
            Self::Serialization(_) => "serialization",
            Self::Migration(_) => "migration",
        }
    }
}
pub type Result<T> = std::result::Result<T, StoreError>;
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}
impl Store {
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
    pub fn connect_lazy(url: &str) -> Result<Self> {
        Ok(Self {
            pool: PgPoolOptions::new().max_connections(10).connect_lazy(url)?,
        })
    }
    pub async fn resolve_identity(&self, issuer: &str, subject: &str) -> Result<Option<Principal>> {
        let row = sqlx::query("SELECT * FROM lookup_identity($1,$2)")
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|row| Principal {
            tenant_id: row.get("tenant_id"),
            environment_id: row.get("environment_id"),
            workload_id: row.get("workload_id"),
            connection_id: row.get("connection_id"),
        }))
    }
    pub async fn health(&self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
    pub async fn connect(url: &str) -> Result<Self> {
        Ok(Self {
            pool: PgPoolOptions::new()
                .max_connections(10)
                .connect(url)
                .await?,
        })
    }
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        Ok(())
    }
    pub async fn submit(
        &self,
        p: &Principal,
        key: &str,
        request: &RefundRequest,
    ) -> Result<Action> {
        if request.connection_id != p.connection_id {
            return Err(StoreError::Forbidden);
        }
        request
            .validate()
            .map_err(|e| StoreError::Invalid(e.to_string()))?;
        if key.is_empty() || key.len() > 200 {
            return Err(StoreError::Invalid(
                "idempotency key must contain 1–200 bytes".into(),
            ));
        }
        // Typed structures and ordered metadata give stable serialization independent of input JSON ordering.
        let value = serde_json::to_value(request)?;
        let digest = Sha256::digest(serde_json::to_vec(&value)?).to_vec();
        let mut tx = self.pool.begin().await?;
        context(&mut tx, p.tenant_id, p.environment_id).await?;
        if !authorized(&mut tx, p, "submit_refund").await? {
            return Err(StoreError::Forbidden);
        }
        // Serialize only submissions sharing this scoped key. Hash collisions merely serialize unrelated work.
        let lock_key = format!(
            "{}:{}:{}:{}",
            p.tenant_id, p.environment_id, p.workload_id, key
        );
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(lock_key)
            .execute(&mut *tx)
            .await?;
        if let Some(row) = sqlx::query("SELECT digest,action_id FROM submission_keys WHERE tenant_id=$1 AND environment_id=$2 AND workload_id=$3 AND key=$4")
            .bind(p.tenant_id).bind(p.environment_id).bind(p.workload_id).bind(key).fetch_optional(&mut *tx).await? {
            if row.get::<Vec<u8>,_>("digest") != digest { return Err(StoreError::Conflict); }
            let id = row.get("action_id");
            let action = fetch_action(&mut tx,p,id).await?.ok_or_else(||StoreError::Invalid("missing idempotent action".into()))?;
            tx.commit().await?;
            return Ok(action);
        }
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status) VALUES($1,$2,$3,$4,$5,'received')")
            .bind(p.tenant_id).bind(p.environment_id).bind(id).bind(p.workload_id).bind(value).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO submission_keys VALUES($1,$2,$3,$4,$5,$6)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(p.workload_id)
            .bind(key)
            .bind(digest)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO audit_events VALUES($1,$2,$3,1,'action.received')")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO outbox_jobs(tenant_id,environment_id,action_id) VALUES($1,$2,$3)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(Action {
            id,
            status: ActionStatus::Received,
            request: request.clone(),
            reason: None,
        })
    }
    pub async fn get(&self, p: &Principal, id: Uuid) -> Result<Option<Action>> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, p.tenant_id, p.environment_id).await?;
        if !authorized(&mut tx, p, "read_action").await? {
            return Err(StoreError::Forbidden);
        }
        let result = fetch_action(&mut tx, p, id).await?;
        tx.commit().await?;
        Ok(result)
    }
    pub async fn events(&self, p: &Principal, id: Uuid) -> Result<Option<Vec<AuditEvent>>> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, p.tenant_id, p.environment_id).await?;
        if !authorized(&mut tx, p, "read_events").await? {
            return Err(StoreError::Forbidden);
        }
        if fetch_action(&mut tx, p, id).await?.is_none() {
            return Ok(None);
        }
        let rows=sqlx::query("SELECT sequence,event_type FROM audit_events WHERE tenant_id=$1 AND environment_id=$2 AND action_id=$3 ORDER BY sequence").bind(p.tenant_id).bind(p.environment_id).bind(id).fetch_all(&mut *tx).await?;
        let events = rows
            .into_iter()
            .map(|r| AuditEvent {
                sequence: r.get("sequence"),
                event_type: r.get("event_type"),
            })
            .collect();
        tx.commit().await?;
        Ok(Some(events))
    }
    /// Fake provider ONLY: effect and local state commit together. This is not an external-call protocol.
    pub async fn process_one(&self) -> Result<bool> {
        let mut tx = self.pool.begin().await?;
        let Some(job) = sqlx::query("SELECT * FROM claim_next_job()")
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.commit().await?;
            return Ok(false);
        };
        let t: Uuid = job.get("tenant_id");
        let e: Uuid = job.get("environment_id");
        let id: Uuid = job.get("action_id");
        context(&mut tx, t, e).await?;
        approvals::process(&mut tx, t, e, id, None).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// A trusted worker supplies facts read from a provider before opening this transaction.
    /// No provider I/O is performed while evaluating or holding database locks.
    pub async fn prepare_verified_external(
        &self,
        action: external::ExternalAction,
        provider_namespace: &str,
        request: apl_dispatch::VerifiedRefundRequest,
        observation: apl_dispatch::VerifiedPaymentObservation,
        customer_ref: Option<&str>,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        context(&mut tx, action.tenant_id, action.environment_id).await?;
        let exists: bool = sqlx::query_scalar("SELECT lock_approval_job($1,$2,$3)")
            .bind(action.tenant_id)
            .bind(action.environment_id)
            .bind(action.action_id)
            .fetch_one(&mut *tx)
            .await?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        approvals::process(
            &mut tx,
            action.tenant_id,
            action.environment_id,
            action.action_id,
            Some(approvals::ExternalInput {
                provider_namespace,
                request,
                observation,
                customer_ref,
            }),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}
async fn context(tx: &mut Transaction<'_, Postgres>, t: Uuid, e: Uuid) -> Result<()> {
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(t.to_string())
    .bind(e.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}
async fn fetch_action(
    tx: &mut Transaction<'_, Postgres>,
    p: &Principal,
    id: Uuid,
) -> Result<Option<Action>> {
    let row=sqlx::query("SELECT id,status,request,reason FROM actions WHERE tenant_id=$1 AND environment_id=$2 AND workload_id=$3 AND id=$4 AND request->>'connection_id'=$5")
        .bind(p.tenant_id).bind(p.environment_id).bind(p.workload_id).bind(id).bind(p.connection_id.to_string()).fetch_optional(&mut **tx).await?;
    row.map(|r| {
        Ok(Action {
            id: r.get("id"),
            status: r
                .get::<&str, _>("status")
                .parse()
                .map_err(|_| StoreError::Invalid("unknown stored state".into()))?,
            request: serde_json::from_value(r.get("request"))?,
            reason: r.get("reason"),
        })
    })
    .transpose()
}

async fn authorized(
    tx: &mut Transaction<'_, Postgres>,
    p: &Principal,
    permission: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT authorize_scope($1,$2,$3,$4,$5)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .bind(permission)
        .fetch_one(&mut **tx)
        .await?)
}

/// Call only after authorize_scope has locked the tenant, workload and connection.
async fn dispatch_scope_paused(tx: &mut Transaction<'_, Postgres>, p: &Principal) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT t.paused OR w.paused OR c.paused
        FROM tenants t JOIN workloads w USING(tenant_id)
        JOIN connections c USING(tenant_id,environment_id)
        WHERE (w.tenant_id,w.environment_id,w.workload_id,c.connection_id)=($1,$2,$3,$4)",
    )
    .bind(p.tenant_id)
    .bind(p.environment_id)
    .bind(p.workload_id)
    .bind(p.connection_id)
    .fetch_one(&mut **tx)
    .await?)
}
