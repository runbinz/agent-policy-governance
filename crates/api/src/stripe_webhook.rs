use apl_persistence::Store;
use apl_stripe_webhook::{AccountPolicy, WebhookVerifier, MAX_BODY_BYTES};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
struct Endpoint {
    store: Store,
    namespace: String,
    verifier: Arc<WebhookVerifier>,
}

pub fn router(store: Store, account: &str, secret: &str) -> Result<Router, &'static str> {
    if !account.strip_prefix("acct_").is_some_and(|id| {
        !id.is_empty() && id.len() <= 100 && id.bytes().all(|byte| byte.is_ascii_alphanumeric())
    }) {
        return Err("invalid sandbox webhook account");
    }
    let verifier = WebhookVerifier::new(secret, AccountPolicy::Direct)
        .map_err(|_| "invalid sandbox webhook secret")?;
    Ok(Router::new()
        .route("/v1/webhooks/stripe-sandbox", post(receive))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(Endpoint {
            store,
            namespace: format!("stripe-test:{account}"),
            verifier: Arc::new(verifier),
        }))
}

async fn receive(State(endpoint): State<Endpoint>, headers: HeaderMap, body: Bytes) -> StatusCode {
    let mut signatures = headers.get_all("stripe-signature").iter();
    let Some(signature) = signatures.next().and_then(|value| value.to_str().ok()) else {
        return StatusCode::BAD_REQUEST;
    };
    if signatures.next().is_some() {
        return StatusCode::BAD_REQUEST;
    }
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return StatusCode::SERVICE_UNAVAILABLE;
    };
    let Ok(event) = endpoint.verifier.verify(&body, signature, now.as_secs()) else {
        return StatusCode::BAD_REQUEST;
    };
    let Some(refund) = event.refund else {
        return StatusCode::NO_CONTENT;
    };
    match endpoint
        .store
        .ingest_stripe_wake(
            &endpoint.namespace,
            &event.event_id,
            &event.event_type,
            &refund.refund_id,
            &refund.charge_id,
            refund.correlation.as_deref(),
        )
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}
