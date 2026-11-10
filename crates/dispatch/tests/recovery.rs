use apl_dispatch::{
    BudgetEffect, Currency, Dispatch, DispatchError, DispatchState, EvidenceRef, NextStep,
    ProviderOutcome, ReplaySafety, VerifiedRefundRequest,
};
use uuid::Uuid;

const SAFE: ReplaySafety = ReplaySafety::SameKeyWithin {
    safe_duration_ms: 60,
};

fn request() -> VerifiedRefundRequest {
    VerifiedRefundRequest::new(
        Uuid::from_u128(1),
        "pay_test".into(),
        2500,
        Currency::Usd,
        100,
        200,
    )
    .unwrap()
}

fn authorize() -> Dispatch {
    Dispatch::authorize(Uuid::from_u128(2), request(), 100).unwrap()
}

fn evidence() -> EvidenceRef {
    EvidenceRef::new("evidence-1".into()).unwrap()
}

#[test]
fn crash_before_marker_permits_first_send_with_same_immutable_request_and_key() {
    let mut dispatch = authorize();
    let old = dispatch.claim(100, 10).unwrap();
    let key = dispatch.provider_key().clone();
    assert_eq!(dispatch.claim(109, 20), Err(DispatchError::LeaseBusy));
    let mut restored = Dispatch::restore(dispatch.snapshot().clone()).unwrap();
    let next = restored.claim(110, 20).unwrap();
    assert_eq!(next.generation, old.generation + 1);
    assert_eq!(restored.provider_key(), &key);
    assert_eq!(restored.snapshot().request, request());
    assert_eq!(
        restored.next_step(next, 110, SAFE),
        Ok(NextStep::SendInitial)
    );
    assert_eq!(
        restored.begin_send(old, 110, SAFE),
        Err(DispatchError::StaleLease)
    );
}

#[test]
fn crash_after_marker_requires_reconciliation_and_fences_old_worker() {
    let mut dispatch = authorize();
    let old = dispatch.claim(100, 10).unwrap();
    dispatch.begin_send(old, 100, SAFE).unwrap();
    assert_eq!(
        dispatch.begin_send(old, 101, SAFE),
        Err(DispatchError::SendForbidden)
    );
    let key = dispatch.provider_key().clone();
    let mut restored = Dispatch::restore(dispatch.snapshot().clone()).unwrap();
    let current = restored.claim(110, 20).unwrap();
    assert_eq!(
        restored.next_step(current, 110, SAFE),
        Ok(NextStep::Reconcile)
    );
    assert_eq!(
        restored.observe(old, 110, ProviderOutcome::ConfirmedSuccess(evidence())),
        Err(DispatchError::StaleLease)
    );
    assert_eq!(
        restored.observe(current, 112, ProviderOutcome::Unknown),
        Ok(BudgetEffect::KeepHold)
    );
    assert_eq!(
        restored.next_step(current, 112, ReplaySafety::ReconcileOnly),
        Ok(NextStep::Reconcile)
    );
    assert_eq!(
        restored.next_step(current, 112, SAFE),
        Ok(NextStep::ReplaySameKey)
    );
    restored.begin_send(current, 113, SAFE).unwrap();
    assert_eq!(restored.provider_key(), &key);
    assert_eq!(restored.snapshot().first_send_at, Some(100));
    assert_eq!(restored.snapshot().retry_until, Some(160));
}

#[test]
fn replay_never_extends_retention_and_stops_at_the_exclusive_boundary() {
    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 200).unwrap();
    dispatch.begin_send(lease, 100, SAFE).unwrap();
    dispatch
        .observe(lease, 102, ProviderOutcome::Unknown)
        .unwrap();
    let longer = ReplaySafety::SameKeyWithin {
        safe_duration_ms: 120,
    };
    let shorter = ReplaySafety::SameKeyWithin {
        safe_duration_ms: 20,
    };
    assert_eq!(
        dispatch.next_step(lease, 119, shorter),
        Ok(NextStep::ReplaySameKey)
    );
    assert_eq!(
        dispatch.next_step(lease, 120, shorter),
        Ok(NextStep::Reconcile)
    );
    assert_eq!(
        dispatch.next_step(lease, 159, longer),
        Ok(NextStep::ReplaySameKey)
    );
    assert_eq!(
        dispatch.begin_send(lease, 160, longer),
        Err(DispatchError::SendForbidden)
    );
    assert_eq!(dispatch.snapshot().state, DispatchState::Unknown);

    let mut without = authorize();
    let lease = without.claim(100, 200).unwrap();
    without
        .begin_send(lease, 100, ReplaySafety::ReconcileOnly)
        .unwrap();
    without
        .observe(lease, 102, ProviderOutcome::Unknown)
        .unwrap();
    assert_eq!(without.next_step(lease, 103, SAFE), Ok(NextStep::Reconcile));
}

#[test]
fn expired_context_or_lease_forbids_sending() {
    assert_eq!(
        Dispatch::authorize(Uuid::from_u128(2), request(), 99),
        Err(DispatchError::StaleContext)
    );
    assert_eq!(
        Dispatch::authorize(Uuid::from_u128(2), request(), 200),
        Err(DispatchError::StaleContext)
    );
    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 110).unwrap();
    assert_eq!(
        dispatch.next_step(lease, 200, SAFE),
        Ok(NextStep::HoldUnsent)
    );
    assert_eq!(
        dispatch.begin_send(lease, 200, SAFE),
        Err(DispatchError::SendForbidden)
    );
    assert_eq!(
        dispatch.next_step(lease, 210, SAFE),
        Err(DispatchError::StaleLease)
    );

    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 150).unwrap();
    let long = ReplaySafety::SameKeyWithin {
        safe_duration_ms: 120,
    };
    dispatch.begin_send(lease, 100, long).unwrap();
    dispatch
        .observe(lease, 110, ProviderOutcome::Unknown)
        .unwrap();
    assert_eq!(
        dispatch.next_step(lease, 199, long),
        Ok(NextStep::ReplaySameKey)
    );
    assert_eq!(
        dispatch.next_step(lease, 200, long),
        Ok(NextStep::Reconcile)
    );
}

#[test]
fn pending_and_manual_review_remain_non_replayable_after_unknown_observations() {
    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 80).unwrap();
    dispatch.begin_send(lease, 100, SAFE).unwrap();
    assert_eq!(
        dispatch.observe(lease, 101, ProviderOutcome::Pending),
        Ok(BudgetEffect::KeepHold)
    );
    assert_eq!(
        dispatch.observe(lease, 102, ProviderOutcome::Unknown),
        Ok(BudgetEffect::KeepHold)
    );
    assert_eq!(dispatch.snapshot().state, DispatchState::Pending);
    assert_eq!(
        dispatch.next_step(lease, 103, SAFE),
        Ok(NextStep::Reconcile)
    );
    dispatch.require_manual_review(lease, 104).unwrap();
    assert_eq!(
        dispatch.observe(lease, 105, ProviderOutcome::Unknown),
        Ok(BudgetEffect::KeepHold)
    );
    assert_eq!(dispatch.snapshot().state, DispatchState::ManualReview);
    assert_eq!(
        dispatch.begin_send(lease, 106, SAFE),
        Err(DispatchError::SendForbidden)
    );
    assert_eq!(
        dispatch.observe(lease, 107, ProviderOutcome::ConfirmedSuccess(evidence())),
        Ok(BudgetEffect::Settle)
    );
}

#[test]
fn confirmed_terminal_outcome_cannot_be_replaced_or_emit_another_budget_effect() {
    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 10).unwrap();
    assert_eq!(
        dispatch.observe(
            lease,
            100,
            ProviderOutcome::ConfirmedNonExecution(evidence())
        ),
        Err(DispatchError::OutcomeForbidden)
    );
    dispatch.begin_send(lease, 100, SAFE).unwrap();
    assert_eq!(
        dispatch.observe(
            lease,
            101,
            ProviderOutcome::ConfirmedNonExecution(evidence())
        ),
        Ok(BudgetEffect::Release)
    );
    assert_eq!(
        dispatch.observe(
            lease,
            102,
            ProviderOutcome::ConfirmedNonExecution(evidence())
        ),
        Err(DispatchError::Terminal)
    );
    assert_eq!(
        dispatch.observe(lease, 102, ProviderOutcome::ConfirmedSuccess(evidence())),
        Err(DispatchError::Terminal)
    );
    assert_eq!(dispatch.claim(111, 10), Err(DispatchError::Terminal));
    assert_eq!(
        dispatch.snapshot().state,
        DispatchState::FailedConfirmed(evidence())
    );
}

#[test]
fn inconsistent_persisted_attempt_is_rejected() {
    let dispatch = authorize();
    let mut row = dispatch.snapshot().clone();
    row.state = DispatchState::InFlight;
    assert_eq!(Dispatch::restore(row), Err(DispatchError::InvalidSnapshot));
    let mut row = dispatch.snapshot().clone();
    row.retry_until = Some(110);
    assert_eq!(Dispatch::restore(row), Err(DispatchError::InvalidSnapshot));
}

#[test]
fn persisted_json_round_trips_and_invalid_nested_values_are_rejected() {
    let mut dispatch = authorize();
    let lease = dispatch.claim(100, 80).unwrap();
    dispatch.begin_send(lease, 100, SAFE).unwrap();
    let json = serde_json::to_value(dispatch.snapshot()).unwrap();
    let restored = Dispatch::restore(serde_json::from_value(json.clone()).unwrap()).unwrap();
    assert_eq!(restored, dispatch);

    for (field, value) in [
        ("amount_minor", serde_json::json!(0)),
        ("payment_id", serde_json::json!(" ")),
        ("fresh_until", serde_json::json!(99)),
        ("currency", serde_json::json!("eur")),
    ] {
        let mut bad = json.clone();
        bad["request"][field] = value;
        assert!(serde_json::from_value::<apl_dispatch::DispatchSnapshot>(bad).is_err());
    }
    let mut bad = json.clone();
    bad["state"] = serde_json::json!({ "succeeded": "" });
    assert!(serde_json::from_value::<apl_dispatch::DispatchSnapshot>(bad).is_err());

    let mut bad = json;
    bad["lease"]["generation"] = serde_json::json!(0);
    assert_eq!(
        Dispatch::restore(serde_json::from_value(bad).unwrap()),
        Err(DispatchError::InvalidSnapshot)
    );
}

#[test]
fn lease_cannot_be_used_on_another_action_at_the_same_generation() {
    let mut one = authorize();
    let mut other = Dispatch::authorize(Uuid::from_u128(3), request(), 100).unwrap();
    let one_lease = one.claim(100, 10).unwrap();
    let other_lease = other.claim(100, 10).unwrap();
    assert_eq!(one_lease.generation, other_lease.generation);
    assert_eq!(
        other.begin_send(one_lease, 100, SAFE),
        Err(DispatchError::StaleLease)
    );
}
