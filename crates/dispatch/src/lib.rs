//! Provider-neutral dispatch and recovery rules. Storage and network I/O are separate.

pub mod fixture;
pub mod payment_observation;
pub use payment_observation::{PaymentFacts, VerifiedPaymentObservation};

use serde::{Deserialize, Serialize};
use std::future::Future;
use uuid::Uuid;

/// Unix time in milliseconds from the authoritative dispatch clock.
pub type Timestamp = u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Currency {
    Usd,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StoredRefundRequest")]
pub struct VerifiedRefundRequest {
    connection_id: Uuid,
    payment_id: String,
    amount_minor: u32,
    currency: Currency,
    observed_at: Timestamp,
    fresh_until: Timestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRefundRequest {
    connection_id: Uuid,
    payment_id: String,
    amount_minor: u32,
    currency: Currency,
    observed_at: Timestamp,
    fresh_until: Timestamp,
}

impl TryFrom<StoredRefundRequest> for VerifiedRefundRequest {
    type Error = DispatchError;

    fn try_from(value: StoredRefundRequest) -> Result<Self, Self::Error> {
        Self::new(
            value.connection_id,
            value.payment_id,
            value.amount_minor,
            value.currency,
            value.observed_at,
            value.fresh_until,
        )
    }
}

impl VerifiedRefundRequest {
    /// Called only after the connector verifies the payment and refund context.
    pub fn new(
        connection_id: Uuid,
        payment_id: String,
        amount_minor: u32,
        currency: Currency,
        observed_at: Timestamp,
        fresh_until: Timestamp,
    ) -> Result<Self, DispatchError> {
        if connection_id.is_nil()
            || payment_id.trim().is_empty()
            || payment_id.len() > 255
            || !(1..=50_000).contains(&amount_minor)
            || observed_at >= fresh_until
        {
            return Err(DispatchError::InvalidRequest);
        }
        Ok(Self {
            connection_id,
            payment_id,
            amount_minor,
            currency,
            observed_at,
            fresh_until,
        })
    }

    pub fn connection_id(&self) -> Uuid {
        self.connection_id
    }
    pub fn payment_id(&self) -> &str {
        &self.payment_id
    }
    pub fn amount_minor(&self) -> u32 {
        self.amount_minor
    }
    pub fn currency(&self) -> Currency {
        self.currency
    }
    pub fn observed_at(&self) -> Timestamp {
        self.observed_at
    }
    pub fn fresh_until(&self) -> Timestamp {
        self.fresh_until
    }
    pub fn is_fresh(&self, now: Timestamp) -> bool {
        (self.observed_at..self.fresh_until).contains(&now)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderKey(String);

impl ProviderKey {
    /// One stable key per logical action, never per attempt or lease.
    fn for_action(action_id: Uuid) -> Self {
        Self(format!("apl-refund-v1-{action_id}"))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct EvidenceRef(String);

impl EvidenceRef {
    /// A reference to persisted, verified provider evidence. Transport failures
    /// and an inconclusive lookup cannot be used as this reference.
    pub fn new(reference: String) -> Result<Self, DispatchError> {
        if reference.trim().is_empty() || reference.len() > 255 {
            return Err(DispatchError::InvalidEvidence);
        }
        Ok(Self(reference))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for EvidenceRef {
    type Error = DispatchError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderOutcome {
    ConfirmedSuccess(EvidenceRef),
    /// Authenticated terminal evidence for this exact keyed operation. An
    /// absent refund or expired worker lease cannot prove non-execution: an
    /// earlier sender may still be paused before its network call.
    ConfirmedNonExecution(EvidenceRef),
    Pending,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplaySafety {
    /// This is the default when the provider's contract is unverified.
    ReconcileOnly,
    /// Verified provider retention minus the adapter's safety margin, including
    /// time for network transit and clock uncertainty. Zero disallows replay.
    SameKeyWithin { safe_duration_ms: u64 },
}

impl ReplaySafety {
    fn deadline(self, first_send_at: Timestamp) -> Option<Timestamp> {
        match self {
            Self::SameKeyWithin { safe_duration_ms } if safe_duration_ms != 0 => {
                first_send_at.checked_add(safe_duration_ms)
            }
            _ => None,
        }
    }
}

/// Use a generic adapter bound (no heap allocation for the future is required).
/// Implementations map timeout and ambiguous transport/provider results to Unknown.
pub trait RefundProvider: Send + Sync {
    fn replay_safety(&self) -> ReplaySafety;
    fn execute<'a>(
        &'a self,
        request: &'a VerifiedRefundRequest,
        key: &'a ProviderKey,
    ) -> impl Future<Output = ProviderOutcome> + Send + 'a;
    fn reconcile<'a>(
        &'a self,
        request: &'a VerifiedRefundRequest,
        key: &'a ProviderKey,
    ) -> impl Future<Output = ProviderOutcome> + Send + 'a;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchState {
    Authorized,
    InFlight,
    Pending,
    Unknown,
    ManualReview,
    Succeeded(EvidenceRef),
    FailedConfirmed(EvidenceRef),
}

impl DispatchState {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Succeeded(_) | Self::FailedConfirmed(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub action_id: Uuid,
    pub generation: u64,
    pub expires_at: Timestamp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NextStep {
    SendInitial,
    ReplaySameKey,
    Reconcile,
    /// No send marker exists, but the authorized context is stale. Never send
    /// this request without a new authorization and authoritative context.
    HoldUnsent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetEffect {
    KeepHold,
    Settle,
    Release,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DispatchError {
    #[error("invalid verified refund request")]
    InvalidRequest,
    #[error("invalid provider evidence reference")]
    InvalidEvidence,
    #[error("verified refund context is stale")]
    StaleContext,
    #[error("stored dispatch state is invalid")]
    InvalidSnapshot,
    #[error("dispatch is already terminal")]
    Terminal,
    #[error("dispatch has an active lease")]
    LeaseBusy,
    #[error("dispatch lease is stale or expired")]
    StaleLease,
    #[error("invalid lease duration or generation")]
    InvalidLease,
    #[error("provider send is not authorized in this state")]
    SendForbidden,
    #[error("provider outcome is not valid in this state")]
    OutcomeForbidden,
}

/// Values needed to restore a dispatch from durable storage. Use one consistent
/// version of the row and its attempt fields; updates must be transactional.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchSnapshot {
    pub action_id: Uuid,
    pub request: VerifiedRefundRequest,
    pub state: DispatchState,
    pub lease: Option<Lease>,
    pub first_send_at: Option<Timestamp>,
    pub retry_until: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dispatch {
    row: DispatchSnapshot,
    key: ProviderKey,
}

impl Dispatch {
    /// Commit this initial record with the immutable request, hold, audit, and
    /// outbox. No provider call is authorized until begin_send is committed.
    pub fn authorize(
        action_id: Uuid,
        request: VerifiedRefundRequest,
        now: Timestamp,
    ) -> Result<Self, DispatchError> {
        if !request.is_fresh(now) {
            return Err(DispatchError::StaleContext);
        }
        Self::restore(DispatchSnapshot {
            action_id,
            request,
            state: DispatchState::Authorized,
            lease: None,
            first_send_at: None,
            retry_until: None,
        })
    }

    pub fn restore(row: DispatchSnapshot) -> Result<Self, DispatchError> {
        let sent = row.first_send_at.is_some();
        if row.action_id.is_nil()
            || sent == matches!(row.state, DispatchState::Authorized)
            || (sent && row.lease.is_none())
            || row.lease.is_some_and(|lease| {
                lease.action_id != row.action_id
                    || lease.generation == 0
                    || lease.expires_at == 0
                    || row
                        .first_send_at
                        .is_some_and(|first| first >= lease.expires_at)
            })
            || row
                .first_send_at
                .is_some_and(|first| !row.request.is_fresh(first))
            || row
                .retry_until
                .is_some_and(|end| row.first_send_at.is_none_or(|first| first >= end))
        {
            return Err(DispatchError::InvalidSnapshot);
        }
        Ok(Self {
            key: ProviderKey::for_action(row.action_id),
            row,
        })
    }

    pub fn snapshot(&self) -> &DispatchSnapshot {
        &self.row
    }
    pub fn provider_key(&self) -> &ProviderKey {
        &self.key
    }

    /// Persist the new fence under a row lock before performing any work.
    pub fn claim(&mut self, now: Timestamp, duration_ms: u64) -> Result<Lease, DispatchError> {
        if self.row.state.is_terminal() {
            return Err(DispatchError::Terminal);
        }
        if self.row.lease.is_some_and(|lease| now < lease.expires_at) {
            return Err(DispatchError::LeaseBusy);
        }
        let generation = self
            .row
            .lease
            .map_or(0, |lease| lease.generation)
            .checked_add(1)
            .ok_or(DispatchError::InvalidLease)?;
        let expires_at = now
            .checked_add(duration_ms)
            .filter(|&end| end > now)
            .ok_or(DispatchError::InvalidLease)?;
        let lease = Lease {
            action_id: self.row.action_id,
            generation,
            expires_at,
        };
        self.row.lease = Some(lease);
        Ok(lease)
    }

    fn check_lease(&self, lease: Lease, now: Timestamp) -> Result<(), DispatchError> {
        if self.row.lease != Some(lease) || now >= lease.expires_at {
            return Err(DispatchError::StaleLease);
        }
        Ok(())
    }

    pub fn next_step(
        &self,
        lease: Lease,
        now: Timestamp,
        replay: ReplaySafety,
    ) -> Result<NextStep, DispatchError> {
        if self.row.state.is_terminal() {
            return Err(DispatchError::Terminal);
        }
        self.check_lease(lease, now)?;
        let fresh = self.row.request.is_fresh(now);
        let retry_safe = self.row.first_send_at.is_some_and(|first| {
            now >= first
                && self.row.retry_until.is_some_and(|until| now < until)
                && replay.deadline(first).is_some_and(|until| now < until)
        });
        Ok(match self.row.state {
            DispatchState::Authorized if fresh => NextStep::SendInitial,
            DispatchState::Authorized => NextStep::HoldUnsent,
            DispatchState::Unknown if fresh && retry_safe => NextStep::ReplaySameKey,
            // An inherited InFlight marker always starts with reconciliation.
            // Pending and manual-review actions likewise never replay.
            _ => NextStep::Reconcile,
        })
    }

    /// Persist this transition and its attempt record BEFORE issuing the write.
    /// If the process crashes after commit, InFlight conservatively means that
    /// the request may have reached the provider, even if no bytes were sent.
    pub fn begin_send(
        &mut self,
        lease: Lease,
        now: Timestamp,
        replay: ReplaySafety,
    ) -> Result<(), DispatchError> {
        match self.next_step(lease, now, replay)? {
            NextStep::SendInitial => {
                self.row.first_send_at = Some(now);
                self.row.retry_until = replay.deadline(now);
            }
            NextStep::ReplaySameKey => {}
            _ => return Err(DispatchError::SendForbidden),
        }
        self.row.state = DispatchState::InFlight;
        Ok(())
    }

    /// Apply a verified execution/reconciliation result under the active fence.
    /// Commit the budget effect, terminal state, evidence, and audit together.
    pub fn observe(
        &mut self,
        lease: Lease,
        now: Timestamp,
        outcome: ProviderOutcome,
    ) -> Result<BudgetEffect, DispatchError> {
        if self.row.state.is_terminal() {
            return Err(DispatchError::Terminal);
        }
        self.check_lease(lease, now)?;
        if self.row.state == DispatchState::Authorized {
            return Err(DispatchError::OutcomeForbidden);
        }
        let (state, budget) = match outcome {
            ProviderOutcome::ConfirmedSuccess(reference) => {
                (DispatchState::Succeeded(reference), BudgetEffect::Settle)
            }
            ProviderOutcome::ConfirmedNonExecution(reference) => (
                DispatchState::FailedConfirmed(reference),
                BudgetEffect::Release,
            ),
            // Once the provider has acknowledged a pending refund, an inconclusive
            // follow-up must not downgrade it to a replayable unknown state.
            ProviderOutcome::Pending | ProviderOutcome::Unknown
                if self.row.state == DispatchState::ManualReview =>
            {
                (DispatchState::ManualReview, BudgetEffect::KeepHold)
            }
            ProviderOutcome::Pending => (DispatchState::Pending, BudgetEffect::KeepHold),
            ProviderOutcome::Unknown if self.row.state == DispatchState::Pending => {
                (DispatchState::Pending, BudgetEffect::KeepHold)
            }
            ProviderOutcome::Unknown => (DispatchState::Unknown, BudgetEffect::KeepHold),
        };
        self.row.state = state;
        Ok(budget)
    }

    /// Stops automated sends when the reconciliation budget is exhausted.
    /// Verified outcomes can still be applied under a current lease.
    pub fn require_manual_review(
        &mut self,
        lease: Lease,
        now: Timestamp,
    ) -> Result<(), DispatchError> {
        if self.row.state.is_terminal() {
            return Err(DispatchError::Terminal);
        }
        self.check_lease(lease, now)?;
        if self.row.state == DispatchState::Authorized {
            return Err(DispatchError::OutcomeForbidden);
        }
        self.row.state = DispatchState::ManualReview;
        Ok(())
    }
}
