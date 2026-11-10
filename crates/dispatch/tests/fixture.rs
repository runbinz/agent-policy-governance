use apl_dispatch::{
    fixture::{FixtureProvider, FixtureScenario},
    Currency, Dispatch, ProviderOutcome, RefundProvider, VerifiedRefundRequest,
};
use uuid::Uuid;

fn action(id: u128, amount: u32) -> Dispatch {
    let request = VerifiedRefundRequest::new(
        Uuid::from_u128(1),
        "pay_fixture".into(),
        amount,
        Currency::Usd,
        100,
        200,
    )
    .unwrap();
    Dispatch::authorize(Uuid::from_u128(id), request, 100).unwrap()
}

#[tokio::test]
async fn accepted_timeout_can_reconcile_or_replay_without_a_second_effect() {
    let provider = FixtureProvider::new(FixtureScenario::AcceptedThenTimeout);
    let action = action(2, 1_500);
    let req = &action.snapshot().request;
    let key = action.provider_key();
    assert_eq!(provider.execute(req, key).await, ProviderOutcome::Unknown);
    let outcome = provider.reconcile(req, key).await;
    assert!(matches!(outcome, ProviderOutcome::ConfirmedSuccess(_)));
    assert_eq!(provider.execute(req, key).await, outcome);
    assert_eq!(provider.effect_count(), 1);
    assert_eq!(provider.execute_count(), 2);
    assert_eq!(provider.reconcile_count(), 1);
}

#[tokio::test]
async fn abandoned_response_keeps_provider_effect_for_another_worker() {
    let provider = FixtureProvider::new(FixtureScenario::Success);
    provider.pause_responses();
    let sender = provider.clone();
    let action = action(2, 1_500);
    let attempt = action.clone();
    let task = tokio::spawn(async move {
        sender
            .execute(&attempt.snapshot().request, attempt.provider_key())
            .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        provider.wait_for_execute_count(1),
    )
    .await
    .unwrap();
    assert_eq!(provider.effect_count(), 1);
    assert!(!task.is_finished());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(matches!(
        provider
            .reconcile(&action.snapshot().request, action.provider_key())
            .await,
        ProviderOutcome::ConfirmedSuccess(_)
    ));
    provider.resume_responses();
}

#[tokio::test]
async fn pending_and_non_execution_evidence_stay_bound_to_immutable_payload() {
    let provider = FixtureProvider::new(FixtureScenario::Pending);
    let pending = action(2, 1_500);
    let different = action(2, 2_000);
    let denied = action(3, 1_500);
    assert_eq!(
        provider
            .execute(&pending.snapshot().request, pending.provider_key())
            .await,
        ProviderOutcome::Pending
    );
    assert_eq!(
        provider
            .reconcile(&pending.snapshot().request, pending.provider_key())
            .await,
        ProviderOutcome::Pending
    );
    assert_eq!(
        provider
            .execute(&different.snapshot().request, different.provider_key())
            .await,
        ProviderOutcome::Unknown
    );
    assert_eq!(provider.complete_pending(), 1);
    assert_eq!(provider.complete_pending(), 0);
    assert!(matches!(
        provider
            .reconcile(&pending.snapshot().request, pending.provider_key())
            .await,
        ProviderOutcome::ConfirmedSuccess(_)
    ));

    provider.set_scenario(FixtureScenario::ConfirmedNonExecution);
    let outcome = provider
        .execute(&denied.snapshot().request, denied.provider_key())
        .await;
    assert!(matches!(outcome, ProviderOutcome::ConfirmedNonExecution(_)));
    assert_eq!(
        provider
            .reconcile(&denied.snapshot().request, denied.provider_key())
            .await,
        outcome
    );
    assert_eq!(provider.effect_count(), 1);
}
