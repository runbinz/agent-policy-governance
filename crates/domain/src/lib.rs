//! HTTP- and database-independent contracts for the local refund slice.
pub mod action_detail;

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub workload_id: Uuid,
    pub connection_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefundRequest {
    #[serde(rename = "type")]
    pub action_type: String,
    pub connection_id: Uuid,
    pub resource: Resource,
    pub parameters: Parameters,
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub payment_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub amount_minor: i64,
    pub currency: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct ValidationError(pub &'static str);

impl RefundRequest {
    /// Limits are measured in UTF-8 bytes. Values remain untrusted display data.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.action_type != "refund.create" {
            return Err(ValidationError("unsupported action type"));
        }
        if self.parameters.currency != "USD" {
            return Err(ValidationError("currency must be USD"));
        }
        if !(1..=50_000).contains(&self.parameters.amount_minor) {
            return Err(ValidationError("amount_minor must be between 1 and 50000"));
        }
        if self.resource.payment_id.trim().is_empty() || self.resource.payment_id.len() > 255 {
            return Err(ValidationError("payment_id must contain 1 to 255 bytes"));
        }
        if self.metadata.len() > 20
            || self.metadata.iter().any(|(key, value)| {
                key.trim().is_empty()
                    || key.len() > 64
                    || value.trim().is_empty()
                    || value.len() > 500
            })
        {
            return Err(ValidationError("metadata permits 20 entries with nonempty keys up to 64 bytes and values up to 500 bytes"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Received,
    Denied,
    PendingApproval,
    Ready,
    Rejected,
    Expired,
    Cancelled,
    Dispatching,
    FailedConfirmed,
    Succeeded,
}

impl ActionStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "received",
            Self::Denied => "denied",
            Self::PendingApproval => "pending_approval",
            Self::Ready => "ready",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Dispatching => "dispatching",
            Self::FailedConfirmed => "failed_confirmed",
            Self::Succeeded => "succeeded",
        }
    }
}

impl FromStr for ActionStatus {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "received" => Ok(Self::Received),
            "denied" => Ok(Self::Denied),
            "pending_approval" => Ok(Self::PendingApproval),
            "ready" => Ok(Self::Ready),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            "dispatching" => Ok(Self::Dispatching),
            "failed_confirmed" => Ok(Self::FailedConfirmed),
            "succeeded" => Ok(Self::Succeeded),
            _ => Err(ValidationError("unknown action status")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub id: Uuid,
    pub status: ActionStatus,
    pub request: RefundRequest,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: i64,
    pub event_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyVersion {
    pub version: i64,
    pub auto_limit_minor: i64,
    pub hard_limit_minor: i64,
    pub approval_ttl_seconds: i64,
}

impl PolicyVersion {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version < 1 {
            return Err(ValidationError("policy version must be positive"));
        }
        if !(0..=50_000).contains(&self.hard_limit_minor)
            || !(0..=self.hard_limit_minor).contains(&self.auto_limit_minor)
        {
            return Err(ValidationError(
                "policy thresholds must satisfy 0 <= auto <= hard <= 50000",
            ));
        }
        if !(1..=86_400).contains(&self.approval_ttl_seconds) {
            return Err(ValidationError(
                "approval TTL must be between 1 and 86400 seconds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionDecision {
    Allow,
    RequireApproval,
    Deny(&'static str),
}

pub fn evaluate_version(request: &RefundRequest, policy: &PolicyVersion) -> VersionDecision {
    if request.validate().is_err() {
        return VersionDecision::Deny("INVALID_REQUEST");
    }
    if policy.validate().is_err() {
        return VersionDecision::Deny("INVALID_POLICY");
    }
    let amount = request.parameters.amount_minor;
    if amount > policy.hard_limit_minor {
        VersionDecision::Deny("POLICY_HARD_LIMIT")
    } else if amount > policy.auto_limit_minor {
        VersionDecision::RequireApproval
    } else {
        VersionDecision::Allow
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewer {
    pub tenant_id: Uuid,
    pub environment_id: Uuid,
    pub reviewer_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub action_id: Uuid,
    pub connection_id: Uuid,
    pub generation: i64,
    pub policy_version: i64,
    pub action_digest: String,
    pub queued_at: Option<String>,
    pub expires_at: String,
    pub request: RefundRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}

impl ApprovalDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalInput {
    pub generation: i64,
    pub action_digest: String,
    pub decision: ApprovalDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(&'static str),
}

pub fn evaluate(request: &RefundRequest) -> PolicyDecision {
    if request.validate().is_err() {
        return PolicyDecision::Deny("INVALID_REQUEST");
    }
    if request.parameters.amount_minor <= 5_000 {
        PolicyDecision::Allow
    } else {
        PolicyDecision::Deny("APPROVAL_NOT_IMPLEMENTED")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn payload() -> Value {
        json!({"type":"refund.create", "connection_id":Uuid::nil(),
            "resource":{"payment_id":"pay_123"},
            "parameters":{"amount_minor":2500,"currency":"USD"}})
    }

    fn request() -> RefundRequest {
        serde_json::from_value(payload()).expect("valid test fixture")
    }

    #[test]
    fn amount_and_policy_boundaries() {
        let mut request = request();
        for amount in [1, 5_000] {
            request.parameters.amount_minor = amount;
            assert_eq!(request.validate(), Ok(()));
            assert_eq!(evaluate(&request), PolicyDecision::Allow);
        }
        for amount in [5_001, 50_000] {
            request.parameters.amount_minor = amount;
            assert_eq!(request.validate(), Ok(()));
            assert_eq!(
                evaluate(&request),
                PolicyDecision::Deny("APPROVAL_NOT_IMPLEMENTED")
            );
        }
        for amount in [i64::MIN, -1, 0, 50_001, i64::MAX] {
            request.parameters.amount_minor = amount;
            assert!(request.validate().is_err());
            assert_eq!(evaluate(&request), PolicyDecision::Deny("INVALID_REQUEST"));
        }
    }

    #[test]
    fn rejects_unknown_fields_at_every_request_level() {
        for path in [None, Some("resource"), Some("parameters")] {
            let mut value = payload();
            let target = match path {
                Some(key) => &mut value[key],
                None => &mut value,
            };
            target["unexpected"] = json!(true);
            assert!(serde_json::from_value::<RefundRequest>(value).is_err());
        }
    }

    #[test]
    fn validates_action_currency_payment_and_metadata() {
        let mut invalid = request();
        invalid.action_type = "refund.delete".into();
        assert!(invalid.validate().is_err());
        let mut invalid = request();
        invalid.parameters.currency = "usd".into();
        assert!(invalid.validate().is_err());
        for payment in [" ".into(), "x".repeat(256)] {
            let mut invalid = request();
            invalid.resource.payment_id = payment;
            assert!(invalid.validate().is_err());
        }
        for (key, value) in [
            (" ".into(), "ok".into()),
            ("x".repeat(65), "ok".into()),
            ("ok".into(), " ".into()),
            ("ok".into(), "x".repeat(501)),
        ] {
            let mut invalid = request();
            invalid.metadata.insert(key, value);
            assert!(invalid.validate().is_err());
        }
        let mut request = request();
        request.resource.payment_id = "x".repeat(255);
        for index in 0..20 {
            request
                .metadata
                .insert(format!("{index:064}"), "x".repeat(500));
        }
        assert_eq!(request.validate(), Ok(()));
        request.metadata.insert("overflow".into(), "value".into());
        assert!(request.validate().is_err());
    }

    #[test]
    fn status_round_trips_and_rejects_unknown_state() {
        for status in [
            ActionStatus::Received,
            ActionStatus::Denied,
            ActionStatus::PendingApproval,
            ActionStatus::Ready,
            ActionStatus::Rejected,
            ActionStatus::Expired,
            ActionStatus::Cancelled,
            ActionStatus::Dispatching,
            ActionStatus::FailedConfirmed,
            ActionStatus::Succeeded,
        ] {
            assert_eq!(status.as_str().parse(), Ok(status));
            assert_eq!(
                serde_json::to_value(status).expect("serialize status"),
                json!(status.as_str())
            );
        }
        assert!("executing".parse::<ActionStatus>().is_err());
    }

    #[test]
    fn version_policy_checks_inclusive_thresholds_and_denies_invalid_inputs() {
        let mut request = request();
        let mut policy = PolicyVersion {
            version: 1,
            auto_limit_minor: 5_000,
            hard_limit_minor: 10_000,
            approval_ttl_seconds: 600,
        };
        for (amount, expected) in [
            (5_000, VersionDecision::Allow),
            (5_001, VersionDecision::RequireApproval),
            (10_000, VersionDecision::RequireApproval),
            (10_001, VersionDecision::Deny("POLICY_HARD_LIMIT")),
            (0, VersionDecision::Deny("INVALID_REQUEST")),
        ] {
            request.parameters.amount_minor = amount;
            assert_eq!(evaluate_version(&request, &policy), expected);
        }
        request.parameters.amount_minor = 1;
        policy.auto_limit_minor = 0;
        assert_eq!(
            evaluate_version(&request, &policy),
            VersionDecision::RequireApproval
        );
        policy.hard_limit_minor = 0;
        assert_eq!(
            evaluate_version(&request, &policy),
            VersionDecision::Deny("POLICY_HARD_LIMIT")
        );
        policy.approval_ttl_seconds = 0;
        assert_eq!(
            evaluate_version(&request, &policy),
            VersionDecision::Deny("INVALID_POLICY")
        );
    }

    #[test]
    fn rejects_invalid_policy_versions_thresholds_and_ttl() {
        let policy = PolicyVersion {
            version: 1,
            auto_limit_minor: 50_000,
            hard_limit_minor: 50_000,
            approval_ttl_seconds: 86_400,
        };
        assert!(policy.validate().is_ok());
        for invalid in [
            PolicyVersion {
                version: 0,
                ..policy
            },
            PolicyVersion {
                auto_limit_minor: -1,
                ..policy
            },
            PolicyVersion {
                hard_limit_minor: -1,
                ..policy
            },
            PolicyVersion {
                hard_limit_minor: 49_999,
                ..policy
            },
            PolicyVersion {
                hard_limit_minor: 50_001,
                ..policy
            },
            PolicyVersion {
                approval_ttl_seconds: 0,
                ..policy
            },
            PolicyVersion {
                approval_ttl_seconds: 86_401,
                ..policy
            },
        ] {
            assert!(invalid.validate().is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn approval_input_uses_strict_decision_contract() {
        let mut value = json!({"generation":1,"action_digest":"digest","decision":"approve"});
        let input: ApprovalInput = serde_json::from_value(value.clone()).expect("approval input");
        assert_eq!(input.decision, ApprovalDecision::Approve);
        value["decision"] = json!("reject");
        let input: ApprovalInput = serde_json::from_value(value.clone()).expect("rejection input");
        assert_eq!(input.decision, ApprovalDecision::Reject);
        value["reviewer_id"] = json!(Uuid::nil());
        assert!(serde_json::from_value::<ApprovalInput>(value).is_err());
    }
}
