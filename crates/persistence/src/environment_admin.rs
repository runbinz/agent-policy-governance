//! Scoped administration projections and optimistic, audited mutations.
use crate::{context, Result, Store, StoreError};
use apl_domain::Reviewer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_ADMIN_REVISION: i64 = 9_007_199_254_740_991;

macro_rules! kinds {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $wire),+ } }
        }
        impl std::str::FromStr for $name {
            type Err = StoreError;
            fn from_str(value: &str) -> Result<Self> {
                match value { $($wire => Ok(Self::$variant),)+ _ => Err(invalid()) }
            }
        }
    }
}
kinds!(EntityKind { Connections => "connections", Workloads => "workloads", Reviewers => "reviewers" });
kinds!(GrantKind {
    Workload => "workload", Approval => "approval", Reconciliation => "reconciliation",
    PolicyAdmin => "policy_admin", EvidenceExport => "evidence_export", Operations => "operations",
    ActionDetail => "action_detail", TenantDispatch => "tenant_dispatch",
    WorkloadDispatch => "workload_dispatch", EnvironmentAdmin => "environment_admin"
});
kinds!(ConnectionMode { LocalFake => "local_fake", StripeSandbox => "stripe_sandbox", ExternalConfigured => "external_configured" });
kinds!(CredentialHealth { Unobserved => "unobserved" });
kinds!(GrantPermission {
    SubmitRefund => "submit_refund", ReadAction => "read_action", ReadEvents => "read_events", CancelAction => "cancel_action",
    Approve => "approve", Reconcile => "reconcile", EditPolicy => "edit_policy", PublishPolicy => "publish_policy",
    ControlDispatch => "control_dispatch", ExportEvidence => "export_evidence", ReadOperations => "read_operations",
    ReadActionDetail => "read_action_detail", ControlTenantDispatch => "control_tenant_dispatch",
    ControlWorkloadDispatch => "control_workload_dispatch", AdministerEnvironment => "administer_environment"
});

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdminEntity {
    Connections {
        id: Uuid,
        enabled: bool,
        admin_revision: i64,
        paused: bool,
        can_control: bool,
        mode: ConnectionMode,
        credential_health: CredentialHealth,
        last_payment_verified_at: Option<String>,
    },
    Workloads {
        id: Uuid,
        enabled: bool,
        admin_revision: i64,
        paused: bool,
        can_control: bool,
    },
    Reviewers {
        id: Uuid,
        enabled: bool,
        admin_revision: i64,
    },
}
impl AdminEntity {
    pub fn id(&self) -> Uuid {
        match self {
            Self::Connections { id, .. }
            | Self::Workloads { id, .. }
            | Self::Reviewers { id, .. } => *id,
        }
    }
    pub fn revision(&self) -> i64 {
        match self {
            Self::Connections { admin_revision, .. }
            | Self::Workloads { admin_revision, .. }
            | Self::Reviewers { admin_revision, .. } => *admin_revision,
        }
    }
    pub fn kind(&self) -> EntityKind {
        match self {
            Self::Connections { .. } => EntityKind::Connections,
            Self::Workloads { .. } => EntityKind::Workloads,
            Self::Reviewers { .. } => EntityKind::Reviewers,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminEntityPage {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub kind: EntityKind,
    pub items: Vec<AdminEntity>,
    pub next_after: Option<Uuid>,
    pub tenant_paused: bool,
    pub can_control_tenant: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminGrant {
    pub connection_id: Option<Uuid>,
    pub workload_id: Option<Uuid>,
    pub reviewer_id: Option<Uuid>,
    pub enabled: bool,
    pub admin_revision: i64,
    pub permissions: Vec<GrantPermission>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminGrantPage {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub kind: GrantKind,
    pub items: Vec<AdminGrant>,
    pub next_after: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeInput {
    pub kind: GrantKind,
    pub connection_id: Option<Uuid>,
    pub workload_id: Option<Uuid>,
    pub reviewer_id: Option<Uuid>,
    pub expected_revision: i64,
}
impl RevokeInput {
    pub fn validate(&self) -> Result<()> {
        if !safe_revision(self.expected_revision)
            || self.expected_revision == MAX_ADMIN_REVISION
            || shape(self.kind)
                != (
                    self.connection_id.is_some(),
                    self.workload_id.is_some(),
                    self.reviewer_id.is_some(),
                )
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionResult {
    pub revision: i64,
}
fn shape(kind: GrantKind) -> (bool, bool, bool) {
    match kind {
        GrantKind::Workload => (true, true, false),
        GrantKind::TenantDispatch | GrantKind::EnvironmentAdmin => (false, false, true),
        GrantKind::WorkloadDispatch => (false, true, true),
        _ => (true, false, true),
    }
}
fn safe_revision(n: i64) -> bool {
    (1..=MAX_ADMIN_REVISION).contains(&n)
}
fn invalid() -> StoreError {
    StoreError::Invalid("invalid request".into())
}
fn unavailable() -> StoreError {
    StoreError::Serialization(serde::de::Error::custom("data unavailable"))
}
fn map_error(error: sqlx::Error) -> StoreError {
    match error.as_database_error().and_then(|e| e.code()).as_deref() {
        Some("AP403" | "AP404") => StoreError::NotFound,
        Some("AP400") => invalid(),
        Some("AP409" | "40P01" | "40001") => StoreError::Conflict,
        Some("AP500") => unavailable(),
        _ => StoreError::Database(error),
    }
}
fn projected<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> Result<T> {
    if serde_json::to_vec(&value)?.len() > 128 * 1024 {
        return Err(unavailable());
    }
    serde_json::from_value(value).map_err(|_| unavailable())
}
fn cursor_key(row: &AdminGrant) -> String {
    format!(
        "{}:{}:{}",
        row.reviewer_id.unwrap_or(Uuid::nil()),
        row.workload_id.unwrap_or(Uuid::nil()),
        row.connection_id.unwrap_or(Uuid::nil())
    )
}
fn cursor_prefix(reviewer: &Reviewer, kind: GrantKind) -> String {
    format!(
        "{}/{}/{}/",
        reviewer.tenant_id,
        reviewer.environment_id,
        kind.as_str()
    )
}
fn validate_cursor(reviewer: &Reviewer, kind: GrantKind, cursor: &str) -> Result<String> {
    let key = cursor
        .strip_prefix(&cursor_prefix(reviewer, kind))
        .ok_or_else(invalid)?;
    let keys: Vec<_> = key.split(':').collect();
    if keys.len() != 3 {
        return Err(invalid());
    }
    for part in &keys {
        if Uuid::parse_str(part).map_err(|_| invalid())?.to_string() != *part {
            return Err(invalid());
        }
    }
    let (c, w, r) = shape(kind);
    for (present, part) in [(r, keys[0]), (w, keys[1]), (c, keys[2])] {
        if !present && part != Uuid::nil().to_string() {
            return Err(invalid());
        }
    }
    Ok(key.to_owned())
}
impl Store {
    pub async fn admin_entities(
        &self,
        reviewer: &Reviewer,
        kind: EntityKind,
        after: Option<Uuid>,
        limit: usize,
    ) -> Result<AdminEntityPage> {
        if !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let value = sqlx::query_scalar("SELECT read_admin_entities($1,$2,$3,$4,$5,$6)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(kind.as_str())
            .bind(after)
            .bind(limit as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_error)?;
        let page: AdminEntityPage = projected(value)?;
        if page.tenant_id != reviewer.tenant_id
            || page.environment_id != reviewer.environment_id
            || page.kind != kind
            || page.items.len() > limit
            || page.items.iter().any(|x| {
                x.kind() != kind
                    || !safe_revision(x.revision())
                    || after.is_some_and(|a| x.id() <= a)
            })
            || page.items.windows(2).any(|w| w[0].id() >= w[1].id())
            || page
                .next_after
                .is_some_and(|a| page.items.last().map(AdminEntity::id) != Some(a))
        {
            return Err(unavailable());
        }
        tx.commit().await?;
        Ok(page)
    }
    pub async fn admin_grants(
        &self,
        reviewer: &Reviewer,
        kind: GrantKind,
        after: Option<&str>,
        limit: usize,
    ) -> Result<AdminGrantPage> {
        if !(1..=100).contains(&limit) {
            return Err(invalid());
        }
        let after_key = after
            .map(|s| validate_cursor(reviewer, kind, s))
            .transpose()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let value = sqlx::query_scalar("SELECT read_admin_grants($1,$2,$3,$4,$5,$6)")
            .bind(reviewer.tenant_id)
            .bind(reviewer.environment_id)
            .bind(reviewer.reviewer_id)
            .bind(kind.as_str())
            .bind(after)
            .bind(limit as i64)
            .fetch_one(&mut *tx)
            .await
            .map_err(map_error)?;
        let page: AdminGrantPage = projected(value)?;
        if page.tenant_id != reviewer.tenant_id
            || page.environment_id != reviewer.environment_id
            || page.kind != kind
            || page.items.len() > limit
            || page.items.iter().any(|row| {
                !safe_revision(row.admin_revision)
                    || shape(kind)
                        != (
                            row.connection_id.is_some(),
                            row.workload_id.is_some(),
                            row.reviewer_id.is_some(),
                        )
                    || after_key.as_ref().is_some_and(|a| cursor_key(row) <= *a)
            })
            || page
                .items
                .windows(2)
                .any(|w| cursor_key(&w[0]) >= cursor_key(&w[1]))
        {
            return Err(unavailable());
        }
        if let Some(next) = &page.next_after {
            validate_cursor(reviewer, kind, next).map_err(|_| unavailable())?;
            if page
                .items
                .last()
                .map(|row| format!("{}{}", cursor_prefix(reviewer, kind), cursor_key(row)))
                .as_ref()
                != Some(next)
            {
                return Err(unavailable());
            }
        }
        tx.commit().await?;
        Ok(page)
    }
    pub async fn admin_set_enabled(
        &self,
        reviewer: &Reviewer,
        kind: EntityKind,
        id: Uuid,
        expected: i64,
        enabled: bool,
    ) -> Result<RevisionResult> {
        if !safe_revision(expected)
            || expected == MAX_ADMIN_REVISION
            || (kind == EntityKind::Reviewers && id == reviewer.reviewer_id && !enabled)
        {
            return Err(invalid());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT admin_set_entity_enabled($1,$2,$3,$4,$5,$6,$7)")
                .bind(reviewer.tenant_id)
                .bind(reviewer.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(kind.as_str())
                .bind(id)
                .bind(expected)
                .bind(enabled)
                .fetch_one(&mut *tx)
                .await
                .map_err(map_error)?;
        if revision != expected + 1 {
            return Err(unavailable());
        }
        tx.commit().await?;
        Ok(RevisionResult { revision })
    }
    pub async fn admin_revoke(
        &self,
        reviewer: &Reviewer,
        input: &RevokeInput,
    ) -> Result<RevisionResult> {
        input.validate()?;
        if input.kind == GrantKind::EnvironmentAdmin
            && input.reviewer_id == Some(reviewer.reviewer_id)
        {
            return Err(invalid());
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("SET LOCAL statement_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        context(&mut tx, reviewer.tenant_id, reviewer.environment_id).await?;
        let revision: i64 =
            sqlx::query_scalar("SELECT admin_revoke_grant($1,$2,$3,$4,$5,$6,$7,$8)")
                .bind(reviewer.tenant_id)
                .bind(reviewer.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(input.kind.as_str())
                .bind(input.connection_id)
                .bind(input.workload_id)
                .bind(input.reviewer_id)
                .bind(input.expected_revision)
                .fetch_one(&mut *tx)
                .await
                .map_err(map_error)?;
        if revision != input.expected_revision + 1 {
            return Err(unavailable());
        }
        tx.commit().await?;
        Ok(RevisionResult { revision })
    }
}
