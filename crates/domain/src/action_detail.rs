//! Bounded reviewer-only projections; timestamps are recorded UTC RFC3339 strings.
use crate::{ActionStatus, Parameters, Resource};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
macro_rules! wire_enum { ($name:ident {$($v:ident),*}) => { #[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)] #[serde(rename_all="snake_case")] pub enum $name {$($v),*} }; }
wire_enum!(HistoryKind {
    Audit,
    Policy,
    Approval,
    Budget,
    Attempt
});
wire_enum!(PolicyOutcome {
    Allow,
    Deny,
    RequireApproval,
    Expired,
    Approved,
    Rejected
});
wire_enum!(Decision { Approve, Reject });
wire_enum!(BudgetState {
    Held,
    Settled,
    Released
});
wire_enum!(ExecutionState {
    Authorized,
    InFlight,
    Pending,
    Unknown,
    ManualReview,
    Succeeded,
    FailedConfirmed
});
wire_enum!(PaymentAvailability {
    VerifiedPayment,
    VerifiedContext,
    Unavailable
});
wire_enum!(ProviderStatus {
    NotRecorded,
    Unresolved,
    ConfirmedSuccess,
    ConfirmedNonExecution
});
wire_enum!(ProviderSource {
    None,
    ExternalDispatch,
    LocalFixture
});
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImmutableRequest {
    #[serde(rename = "type")]
    pub action_type: String,
    pub resource: Resource,
    pub parameters: Parameters,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRecord {
    pub audit_sequence: i64,
    pub policy_version: Option<i64>,
    pub outcome: PolicyOutcome,
    pub reason_code: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub latest: Option<PolicyRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Approval {
    pub generation: i64,
    pub policy_version: i64,
    pub action_digest: String,
    pub queued_at: Option<String>,
    pub expires_at: String,
    pub reviewer_id: Option<Uuid>,
    pub decision: Option<Decision>,
    pub decided_at: Option<String>,
    pub payment_attestation_id: Option<Uuid>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionEligibility {
    pub can_decide: bool,
    pub reason_code: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentContext {
    pub payment_id: String,
    pub connection_id: Uuid,
    pub amount_minor: u32,
    pub currency: String,
    pub observed_at: String,
    pub fresh_until: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthoritativePayment {
    pub availability: PaymentAvailability,
    pub context: Option<PaymentContext>,
    pub payment: Option<PaymentAttestationView>,
}
wire_enum!(PaymentEvidenceSource { Approval, Dispatch });
wire_enum!(PaymentFreshness { Fresh, Stale });
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentAttestationView {
    pub attestation_id: Uuid,
    pub schema_version: u8,
    pub source: PaymentEvidenceSource,
    pub approval_generation: Option<i64>,
    pub payment_id: String,
    pub connection_id: Uuid,
    pub requested_minor: u32,
    pub charge_amount_minor: u64,
    pub captured_minor: u64,
    pub refunded_minor: u64,
    pub remaining_minor: u64,
    pub currency: String,
    pub status: String,
    pub captured: bool,
    pub paid: bool,
    pub disputed: bool,
    pub method: String,
    pub direct_charge: bool,
    pub eligible_at_observation: bool,
    pub observed_at: String,
    pub fresh_until: String,
    pub freshness: PaymentFreshness,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub state: BudgetState,
    pub amount_minor: i64,
    pub currency: String,
    pub utc_day: String,
    pub reserved_at: Option<String>,
    pub settled_or_released_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    pub state: ExecutionState,
    pub first_send_at: Option<String>,
    pub retry_until: Option<String>,
    pub state_changed_at: Option<String>,
    pub abandoned_at: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderOutcome {
    pub status: ProviderStatus,
    pub source: ProviderSource,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionDetail {
    pub schema_version: u8,
    pub observed_at: String,
    pub id: Uuid,
    pub workload_id: Uuid,
    pub connection_id: Uuid,
    pub status: ActionStatus,
    pub created_at: Option<String>,
    pub terminal_at: Option<String>,
    pub immutable_request: ImmutableRequest,
    pub policy: Policy,
    pub approval: Option<Approval>,
    pub decision_eligibility: DecisionEligibility,
    pub authoritative_payment: AuthoritativePayment,
    pub budget: Option<Budget>,
    pub execution: Option<Execution>,
    pub provider_outcome: ProviderOutcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HistoryItem {
    Audit {
        sequence: i64,
        event_type: String,
        recorded_at: Option<String>,
    },
    Policy {
        #[serde(flatten)]
        record: PolicyRecord,
        evaluated_at: String,
    },
    Approval {
        #[serde(flatten)]
        record: Approval,
    },
    Budget {
        sequence: i64,
        event_kind: String,
        recorded_at: String,
    },
    Attempt {
        generation: i64,
        recorded_at: String,
    },
}
impl HistoryItem {
    pub fn key(&self) -> i64 {
        match self {
            Self::Audit { sequence, .. } | Self::Budget { sequence, .. } => *sequence,
            Self::Policy { record, .. } => record.audit_sequence,
            Self::Approval { record } => record.generation,
            Self::Attempt { generation, .. } => *generation,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActionHistoryPage {
    pub items: Vec<HistoryItem>,
    pub next_cursor: Option<String>,
}
