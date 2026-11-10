use apl_persistence::Store;
use apl_stripe_sandbox::{StripeError, StripeSandbox};
use apl_telemetry::{Metrics, ProviderOperation, ProviderResult, TickResult, WorkerQueue};
use apl_worker::{
    tick_export, tick_export_cleanup, tick_external_with_metrics, tick_notification, ExternalTick,
    InternalDispatchTimer,
};
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use uuid::Uuid;
use zeroize::Zeroizing;

enum Mode {
    Fake,
    StripeSandbox {
        provider: Box<StripeSandbox>,
        namespace: String,
        connection: Uuid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Queue {
    All,
    Dispatch,
    Notifications,
    Exports,
}
impl Queue {
    fn dispatch(self) -> bool {
        matches!(self, Self::All | Self::Dispatch)
    }
    fn notifications(self) -> bool {
        matches!(self, Self::All | Self::Notifications)
    }
    fn exports(self) -> bool {
        matches!(self, Self::All | Self::Exports)
    }
}
fn arguments(args: &[String]) -> Result<(bool, Queue), &'static str> {
    let usage = "usage: apl-worker [--once] [--queue all|dispatch|notifications|exports]";
    let mut once = false;
    let mut queue = None;
    let mut args = args.iter();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--once" if !once => once = true,
            "--queue" if queue.is_none() => {
                queue = Some(match args.next().map(String::as_str) {
                    Some("all") => Queue::All,
                    Some("dispatch") => Queue::Dispatch,
                    Some("notifications") => Queue::Notifications,
                    Some("exports") => Queue::Exports,
                    _ => return Err(usage),
                })
            }
            _ => return Err(usage),
        }
    }
    Ok((once, queue.unwrap_or(Queue::All)))
}

impl Mode {
    async fn from_environment() -> Result<Self, Box<dyn std::error::Error>> {
        match env::var("APL_WORKER_MODE").as_deref() {
            Err(env::VarError::NotPresent) | Ok("fake") => Ok(Self::Fake),
            Ok("stripe-sandbox") => {
                let connection = env::var("APL_STRIPE_CONNECTION_ID")?.parse()?;
                let account = env::var("APL_STRIPE_ACCOUNT_ID")?;
                let provider = StripeSandbox::new(
                    required_env("APL_STRIPE_SANDBOX_KEY")?,
                    connection,
                    account.clone(),
                )
                .await?;
                Ok(Self::StripeSandbox {
                    provider: Box::new(provider),
                    namespace: format!("stripe-test:{account}"),
                    connection,
                })
            }
            _ => Err("APL_WORKER_MODE must be fake or stripe-sandbox".into()),
        }
    }

    async fn tick(
        &self,
        store: &Store,
        metrics: Option<&Metrics>,
    ) -> apl_persistence::Result<bool> {
        let Self::StripeSandbox {
            provider,
            namespace,
            connection,
        } = self
        else {
            let start = Instant::now();
            let result = store.process_one().await;
            if matches!(result, Ok(true)) {
                if let Some(metrics) = metrics {
                    metrics.record_internal_dispatch(start.elapsed());
                }
            }
            return result;
        };
        if tick_external_with_metrics(
            store,
            namespace,
            provider.as_ref(),
            30_000,
            Duration::from_secs(22),
            metrics,
        )
        .await?
            != ExternalTick::Idle
        {
            return Ok(true);
        }
        let mut internal = InternalDispatchTimer::new(metrics);
        let Some(candidate) = store.next_external_candidate(namespace).await? else {
            return Ok(false);
        };
        internal.activate();
        if candidate.request.connection_id != *connection {
            return Err(apl_persistence::StoreError::Forbidden);
        }
        let amount = u32::try_from(candidate.request.parameters.amount_minor)
            .map_err(|_| apl_persistence::StoreError::Invalid("invalid sandbox amount".into()))?;
        internal.pause();
        let context_start = Instant::now();
        let verified = provider
            .verify_charge_context(
                &candidate.request.resource.payment_id,
                amount,
                candidate.observed_at,
                candidate.observed_at + 30_000,
            )
            .await;
        internal.resume();
        if let Some(metrics) = metrics {
            metrics.record_provider_call(
                ProviderOperation::Context,
                match &verified {
                    Ok(_) => ProviderResult::Succeeded,
                    Err(StripeError::Charge) => ProviderResult::Ineligible,
                    Err(_) => ProviderResult::Unknown,
                },
                context_start.elapsed(),
            );
        }
        match verified {
            Ok(context) => {
                store
                    .prepare_verified_external(
                        candidate.action,
                        namespace,
                        context.request,
                        context.observation,
                        context.customer_ref.as_deref(),
                    )
                    .await?
            }
            Err(StripeError::Charge) => {
                store
                    .reject_external_candidate(&candidate, namespace)
                    .await?
            }
            Err(_) => {
                store
                    .defer_external_candidate(&candidate, namespace)
                    .await?
            }
        }
        Ok(true)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    if env::var("APL_LOCAL_DEV").as_deref() != Ok("true") {
        return Err("worker requires APL_LOCAL_DEV=true".into());
    }
    let args: Vec<_> = env::args().skip(1).collect();
    let (once, queue) = arguments(&args)?;
    let metrics_config = metrics_config()?;
    let metrics = metrics_config.as_ref().map(|(m, _)| m.clone());
    let store = Store::connect(&required_env("DATABASE_URL")?)
        .await
        .map_err(|_| "worker database unavailable")?;
    let artifacts = if queue.exports() {
        apl_evidence::EvidenceStore::from_env()?
    } else {
        None
    };
    let notifier = if queue.notifications() {
        apl_notifications::Notifier::from_env()?
    } else {
        None
    };
    let mode = if queue.dispatch() {
        Some(Mode::from_environment().await?)
    } else {
        None
    };
    if queue == Queue::Exports && artifacts.is_none() {
        return Err("exports queue requires evidence storage".into());
    }
    if queue == Queue::Notifications && notifier.is_none() {
        return Err("notifications queue requires APL_NOTIFICATION_MODE".into());
    }
    if let Some((metrics, bind)) = metrics_config {
        let listener = tokio::net::TcpListener::bind(bind).await?;
        let router = metrics.instrument(axum::Router::new());
        apl_observability::start(store.clone(), metrics);
        tokio::spawn(async move {
            if axum::serve(listener, router).await.is_err() {
                tracing::error!("worker metrics listener failed");
            }
        });
    }
    if once {
        if let Some(artifacts) = &artifacts {
            measured(
                metrics.as_deref(),
                WorkerQueue::ExportCleanup,
                tick_export_cleanup(&store, artifacts),
            )
            .await
            .map_err(|error| format!("worker iteration failed ({})", error.class()))?;
            measured(
                metrics.as_deref(),
                WorkerQueue::Exports,
                tick_export(&store, artifacts),
            )
            .await
            .map_err(|error| format!("worker iteration failed ({})", error.class()))?;
        }
        if let Some(mode) = &mode {
            measured(
                metrics.as_deref(),
                WorkerQueue::Dispatch,
                mode.tick(&store, metrics.as_deref()),
            )
            .await
            .map_err(|error| format!("worker iteration failed ({})", error.class()))?;
        }
        if let Some(notifier) = &notifier {
            measured(
                metrics.as_deref(),
                WorkerQueue::Notifications,
                tick_notification(&store, notifier),
            )
            .await
            .map_err(|error| format!("worker iteration failed ({})", error.class()))?;
        }
        return Ok(());
    }
    loop {
        tokio::select! {
            result = async {
                if let Some(artifacts) = &artifacts {
                    measured(metrics.as_deref(),WorkerQueue::ExportCleanup,tick_export_cleanup(&store,artifacts)).await?;
                    measured(metrics.as_deref(),WorkerQueue::Exports,tick_export(&store,artifacts)).await?;
                }
                let mut work=false;
                if let Some(mode)=&mode {work|=measured(metrics.as_deref(),WorkerQueue::Dispatch,mode.tick(&store,metrics.as_deref())).await?;}
                if let Some(notifier)=&notifier {work|=measured(metrics.as_deref(),WorkerQueue::Notifications,tick_notification(&store,notifier)).await?;}
                Ok::<bool,apl_persistence::StoreError>(work)
            } => {
                match result {
                    Ok(true) => {},
                    Ok(false) => tokio::time::sleep(Duration::from_millis(250)).await,
                    Err(error) => { tracing::error!(error_class=error.class(), "worker iteration failed"); tokio::time::sleep(Duration::from_secs(1)).await; }
                }
            }
            result = tokio::signal::ctrl_c() => {
                result?;
                break;
            }
        }
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required and must be valid Unicode").into())
}

async fn measured(
    metrics: Option<&Metrics>,
    queue: WorkerQueue,
    work: impl std::future::Future<Output = apl_persistence::Result<bool>>,
) -> apl_persistence::Result<bool> {
    let start = Instant::now();
    let result = work.await;
    if let Some(metrics) = metrics {
        metrics.record_worker_tick(
            queue,
            match result {
                Ok(true) => TickResult::Worked,
                Ok(false) => TickResult::Idle,
                Err(_) => TickResult::Error,
            },
            start.elapsed(),
        );
    }
    result
}
type MetricsConfig = Option<(Arc<Metrics>, SocketAddr)>;

fn metrics_config() -> Result<MetricsConfig, Box<dyn std::error::Error>> {
    fn value(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match env::var(name) {
            Ok(v) => Ok(Some(v)),
            Err(env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(format!("{name} must be valid Unicode").into()),
        }
    }
    let token = value("APL_METRICS_TOKEN")?.map(Zeroizing::new);
    let bind = value("APL_WORKER_METRICS_BIND")?;
    let (token, bind) = match (token, bind) {
        (None, None) => return Ok(None),
        (Some(t), Some(b)) => (t, b),
        _ => {
            return Err(
                "worker metrics require both APL_METRICS_TOKEN and APL_WORKER_METRICS_BIND".into(),
            )
        }
    };
    for name in ["APL_SLACK_BOT_TOKEN", "APL_STRIPE_SANDBOX_KEY"] {
        if value(name)?.as_deref() == Some(token.as_str()) {
            return Err("metrics token must be separate from provider credentials".into());
        }
    }
    let address: SocketAddr = bind.parse().map_err(|_| "invalid worker metrics bind")?;
    if !address.ip().is_loopback() {
        return Err("worker metrics must bind to loopback".into());
    }
    let metrics = Metrics::new(&token).map_err(|_| "invalid worker metrics token")?;
    Ok(Some((metrics, address)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    #[test]
    fn queue_selection_is_explicit_and_rejects_ambiguous_flags() {
        assert_eq!(arguments(&[]).unwrap(), (false, Queue::All));
        let (once, queue) = arguments(&args(&["--queue", "notifications", "--once"])).unwrap();
        assert!(once && queue.notifications() && !queue.dispatch() && !queue.exports());
        let (_, queue) = arguments(&args(&["--queue", "dispatch"])).unwrap();
        assert!(queue.dispatch() && !queue.notifications() && !queue.exports());
        for values in [
            vec!["--once", "--once"],
            vec!["--queue"],
            vec!["--queue", "unknown"],
            vec!["--queue", "all", "--queue", "dispatch"],
        ] {
            assert!(arguments(&args(&values)).is_err());
        }
    }
}
