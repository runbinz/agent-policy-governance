use apl_dispatch::{
    DispatchError, DispatchState, NextStep, ProviderOutcome, RefundProvider, ReplaySafety,
};
use apl_persistence::{Store, StoreError};
use std::time::Duration;

/// Notification delivery is outside the approval transaction and grants no
/// execution authority. Unknown delivery may be retried and can duplicate.
pub async fn tick_notification(
    store: &Store,
    notifier: &apl_notifications::Notifier,
) -> Result<bool, StoreError> {
    use apl_notifications::{DeliveryOutcome, NotificationMessage};
    let Some(lease) = store
        .claim_notification(notifier.route_id(), notifier.kind())
        .await?
    else {
        return Ok(false);
    };
    if !store.notification_preflight(&lease).await? {
        return Ok(true);
    }
    let message = NotificationMessage {
        id: lease.id,
        action_id: lease.action_id,
        approval_generation: lease.approval_generation,
    };
    match notifier
        .deliver(
            &message,
            lease.team_id.as_deref(),
            lease.channel_id.as_deref(),
        )
        .await
    {
        DeliveryOutcome::Delivered => {
            if lease.kind == "fake" && !store.record_fake_notification(&lease).await? {
                return Ok(true);
            }
            store.finish_notification(&lease, "delivered", 0).await?;
        }
        DeliveryOutcome::RetryAfter(seconds) => {
            store
                .finish_notification(&lease, "retry", seconds.clamp(1, 86400) as i64)
                .await?;
        }
        DeliveryOutcome::PermanentFailure => {
            store.finish_notification(&lease, "failed", 0).await?;
        }
    }
    Ok(true)
}

/// Sweep one expired export scope, retrying partial or failed storage cleanup.
/// Repeated database scheduling also removes late writes from suspended workers.
pub async fn tick_export_cleanup(
    store: &Store,
    artifacts: &apl_evidence::EvidenceStore,
) -> Result<bool, StoreError> {
    let Some(lease) = store.claim_export_cleanup().await? else {
        return Ok(false);
    };
    let complete = artifacts
        .delete_export(lease.tenant_id, lease.environment_id, lease.id)
        .await
        .unwrap_or(false);
    store.finish_export_cleanup(&lease, complete).await?;
    Ok(true)
}

/// Build and encrypt one durable export. Storage failures leave a retryable job;
/// readiness is committed only after the generation-specific artifact exists.
pub async fn tick_export(
    store: &Store,
    artifacts: &apl_evidence::EvidenceStore,
) -> Result<bool, StoreError> {
    let Some(lease) = store.claim_export().await? else {
        return Ok(false);
    };
    let snapshot = match store.export_snapshot(&lease).await {
        Ok(value) => value,
        Err(error) => {
            let code = match error {
                StoreError::Invalid(ref message) if message == "export_too_large" => {
                    "export_too_large"
                }
                _ => "snapshot_failed",
            };
            store.fail_export(&lease, code).await?;
            return Ok(true);
        }
    };
    let bytes = serde_json::to_vec(&snapshot)?;
    if bytes.len() > apl_evidence::MAX_PLAINTEXT_BYTES {
        store.fail_export(&lease, "export_too_large").await?;
        return Ok(true);
    }
    let scope = apl_evidence::ExportScope {
        tenant_id: lease.tenant_id,
        environment_id: lease.environment_id,
        export_id: lease.id,
        generation: lease.generation,
    };
    if artifacts.put(scope, &bytes).await.is_err() {
        store.retry_export(&lease).await?;
        return Ok(true);
    }
    store.complete_export(&lease).await?;
    Ok(true)
}

#[derive(Debug, Eq, PartialEq)]
pub enum ExternalTick {
    Idle,
    Deferred,
    AbandonedUnsent,
    Observed(DispatchState),
}

/// Drive one operation for a trusted, server-configured provider namespace.
/// The transport timeout does not prove that a remote refund did not happen.
/// Keep replay disabled until a connector's specific safety contract is integrated.
pub async fn tick_external(
    store: &Store,
    namespace: &str,
    provider: &impl RefundProvider,
    lease_ms: u64,
    operation_timeout: Duration,
) -> Result<ExternalTick, StoreError> {
    tick_external_with_metrics(
        store,
        namespace,
        provider,
        lease_ms,
        operation_timeout,
        None,
    )
    .await
}

pub async fn tick_external_with_metrics(
    store: &Store,
    namespace: &str,
    provider: &impl RefundProvider,
    lease_ms: u64,
    operation_timeout: Duration,
    metrics: Option<&apl_telemetry::Metrics>,
) -> Result<ExternalTick, StoreError> {
    let mut internal = InternalDispatchTimer::new(metrics);
    if operation_timeout.is_zero() || operation_timeout.as_millis() >= u128::from(lease_ms) {
        return Err(StoreError::Invalid(
            "provider timeout must be shorter than the dispatch lease".into(),
        ));
    }
    let Some(claim) = store
        .claim_external(namespace, lease_ms, ReplaySafety::ReconcileOnly)
        .await?
    else {
        return Ok(ExternalTick::Idle);
    };
    internal.activate();
    let request = &claim.dispatch.snapshot().request;
    let key = claim.dispatch.provider_key();
    let outcome = match claim.next_step {
        NextStep::HoldUnsent => {
            store.abandon_external_unsent(&claim).await?;
            return Ok(ExternalTick::AbandonedUnsent);
        }
        NextStep::SendInitial => {
            match store
                .begin_external_send(&claim, ReplaySafety::ReconcileOnly)
                .await
            {
                Err(StoreError::Dispatch(DispatchError::SendForbidden)) => {
                    store.abandon_external_unsent(&claim).await?;
                    return Ok(ExternalTick::AbandonedUnsent);
                }
                result => result?,
            }
            // begin_external_send commits the marker and attempt before this call.
            if !store.external_send_still_current(&claim).await? {
                // The marker already exists; recovery must reconcile, not release.
                return Ok(ExternalTick::Deferred);
            }
            internal.pause();
            let outcome = provider_call(
                apl_telemetry::ProviderOperation::Execute,
                operation_timeout,
                provider.execute(request, key),
                metrics,
            )
            .await;
            internal.resume();
            outcome
        }
        NextStep::Reconcile => {
            internal.pause();
            let outcome = provider_call(
                apl_telemetry::ProviderOperation::Reconcile,
                operation_timeout,
                provider.reconcile(request, key),
                metrics,
            )
            .await;
            internal.resume();
            outcome
        }
        NextStep::ReplaySameKey => return Err(DispatchError::SendForbidden.into()),
    };
    Ok(ExternalTick::Observed(
        store.observe_external(&claim, outcome).await?,
    ))
}

async fn provider_call(
    operation: apl_telemetry::ProviderOperation,
    timeout: Duration,
    call: impl std::future::Future<Output = ProviderOutcome>,
    metrics: Option<&apl_telemetry::Metrics>,
) -> ProviderOutcome {
    use apl_telemetry::ProviderResult;
    let start = std::time::Instant::now();
    let (outcome, result) = match tokio::time::timeout(timeout, call).await {
        Ok(outcome) => {
            let result = match &outcome {
                ProviderOutcome::ConfirmedSuccess(_) => ProviderResult::Succeeded,
                ProviderOutcome::ConfirmedNonExecution(_) => ProviderResult::FailedConfirmed,
                ProviderOutcome::Pending => ProviderResult::Pending,
                ProviderOutcome::Unknown => ProviderResult::Unknown,
            };
            (outcome, result)
        }
        Err(_) => (ProviderOutcome::Unknown, ProviderResult::Timeout),
    };
    if let Some(metrics) = metrics {
        metrics.record_provider_call(operation, result, start.elapsed());
    }
    outcome
}

pub struct InternalDispatchTimer<'a> {
    metrics: Option<&'a apl_telemetry::Metrics>,
    start: Option<std::time::Instant>,
    elapsed: Duration,
    active: bool,
}
impl<'a> InternalDispatchTimer<'a> {
    pub fn new(metrics: Option<&'a apl_telemetry::Metrics>) -> Self {
        Self {
            metrics,
            start: Some(std::time::Instant::now()),
            elapsed: Duration::ZERO,
            active: false,
        }
    }
    pub fn activate(&mut self) {
        self.active = true;
    }
    pub fn pause(&mut self) {
        if let Some(start) = self.start.take() {
            self.elapsed += start.elapsed();
        }
    }
    pub fn resume(&mut self) {
        self.start = Some(std::time::Instant::now());
    }
}
impl Drop for InternalDispatchTimer<'_> {
    fn drop(&mut self) {
        self.pause();
        if self.active {
            if let Some(metrics) = self.metrics {
                metrics.record_internal_dispatch(self.elapsed);
            }
        }
    }
}

#[cfg(test)]
mod metrics_tests {
    use super::*;
    use apl_telemetry::{Metrics, ProviderOperation};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
        Router,
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn provider_timeout_and_internal_pause_are_measured_without_authority_changes() {
        let token = "synthetic-provider-metrics-secret-at-least-32-bytes";
        let metrics = Metrics::new(token).unwrap();
        assert_eq!(
            provider_call(
                ProviderOperation::Execute,
                Duration::from_secs(1),
                async { ProviderOutcome::Pending },
                Some(&metrics)
            )
            .await,
            ProviderOutcome::Pending
        );
        assert_eq!(
            provider_call(
                ProviderOperation::Reconcile,
                Duration::from_millis(1),
                std::future::pending(),
                Some(&metrics)
            )
            .await,
            ProviderOutcome::Unknown
        );
        let mut internal = InternalDispatchTimer::new(Some(&metrics));
        internal.activate();
        internal.pause();
        let elapsed = internal.elapsed;
        tokio::time::sleep(Duration::from_millis(2)).await;
        assert_eq!(internal.elapsed, elapsed);
        internal.resume();
        drop(internal);
        let response = metrics
            .instrument(Router::new())
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            body.contains("apl_provider_calls_total{operation=\"execute\",outcome=\"pending\"} 1")
        );
        assert!(body
            .contains("apl_provider_calls_total{operation=\"reconcile\",outcome=\"timeout\"} 1"));
        assert!(body.contains("apl_internal_dispatch_duration_seconds_count 1"));
        assert!(!body.contains(token));
    }
}
