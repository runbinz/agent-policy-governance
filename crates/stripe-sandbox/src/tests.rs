use super::*;
use apl_dispatch::Dispatch;
use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Router,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

const KEY: &str = "sk_test_fixture";
const ACCOUNT: &str = "acct_example";
const CHARGE: &str = "ch_example";

#[derive(Clone)]
struct Step {
    method: Method,
    path: &'static str,
    status: StatusCode,
    body: Value,
    redirect: bool,
    refund_key: Option<String>,
    delay: Duration,
}
fn step(method: Method, path: &'static str, body: Value) -> Step {
    Step {
        method,
        path,
        status: StatusCode::OK,
        body,
        redirect: false,
        refund_key: None,
        delay: Duration::ZERO,
    }
}
fn account() -> Step {
    step(
        Method::GET,
        "/v1/account",
        json!({"object":"account","id":ACCOUNT}),
    )
}
fn charge_json() -> Value {
    json!({"id":CHARGE,"object":"charge","livemode":false,"currency":"usd","amount":5000,"amount_captured":5000,
        "amount_refunded":1000,"captured":true,"paid":true,"disputed":false,"status":"succeeded",
        "payment_method_details":{"type":"card"},"customer":"cus_example","on_behalf_of":null,
        "transfer":null,"transfer_data":null,"source_transfer":null})
}
fn charge() -> Step {
    step(Method::GET, "/v1/charges/ch_example", charge_json())
}
fn refund(key: &ProviderKey, status: &str, id: &str) -> Value {
    json!({"id":id,"object":"refund","charge":CHARGE,"amount":2500,"currency":"usd",
        "metadata":{"apl_refund_key":key.as_str()},"status":status})
}
fn list(path: &'static str, items: Vec<Value>, more: bool) -> Step {
    step(
        Method::GET,
        path,
        json!({"object":"list","data":items,"has_more":more}),
    )
}
fn execute(key: &ProviderKey, body: Value) -> Step {
    let mut s = step(Method::POST, "/v1/refunds", body);
    s.refund_key = Some(key.as_str().into());
    s
}

struct Mock {
    addr: String,
    steps: Arc<Mutex<VecDeque<Step>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Mock {
    async fn start(steps: Vec<Step>) -> Self {
        let steps = Arc::new(Mutex::new(VecDeque::from(steps)));
        let app = Router::new().fallback(handle).with_state(steps.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { addr, steps, task }
    }
    async fn adapter(&self, connection: Uuid) -> StripeSandbox {
        StripeSandbox::connect(KEY.into(), connection, ACCOUNT.into(), &self.addr)
            .await
            .unwrap()
    }
    fn complete(&self) {
        assert!(self.steps.lock().unwrap().is_empty(), "missing mock calls");
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    State(steps): State<Arc<Mutex<VecDeque<Step>>>>,
    request: Request<Body>,
) -> Response {
    let expected = steps
        .lock()
        .unwrap()
        .front()
        .cloned()
        .expect("unexpected Stripe call");
    assert_eq!(request.method().as_str(), expected.method.as_str());
    assert_eq!(
        request.uri().path_and_query().unwrap().as_str(),
        expected.path
    );
    assert_eq!(request.headers()["authorization"], format!("Bearer {KEY}"));
    assert_eq!(request.headers()["stripe-version"], STRIPE_VERSION);
    assert!(!request.headers().contains_key("stripe-account"));
    if let Some(key) = expected.refund_key {
        assert_eq!(request.headers()["idempotency-key"], key);
        assert_eq!(
            request.headers()["content-type"],
            "application/x-www-form-urlencoded"
        );
        let data = to_bytes(request.into_body(), 4096).await.unwrap();
        let text = std::str::from_utf8(&data).unwrap();
        assert_eq!(
            text,
            format!("charge={CHARGE}&amount=2500&metadata%5Bapl_refund_key%5D={key}")
        );
    }
    steps.lock().unwrap().pop_front();
    tokio::time::sleep(expected.delay).await;
    let mut response = (expected.status, axum::Json(expected.body)).into_response();
    if expected.redirect {
        response
            .headers_mut()
            .insert("location", "/unexpected".parse().unwrap());
    }
    response
}
fn request(connection: Uuid) -> Dispatch {
    let verified =
        VerifiedRefundRequest::new(connection, CHARGE.into(), 2500, Currency::Usd, 100, 200)
            .unwrap();
    Dispatch::authorize(Uuid::new_v4(), verified, 110).unwrap()
}

#[tokio::test]
async fn verifies_sandbox_account_charge_and_exact_refund_request() {
    let connection = Uuid::new_v4();
    let dispatch = request(connection);
    let key = dispatch.provider_key();
    let mock = Mock::start(vec![
        account(),
        charge(),
        charge(),
        execute(key, refund(key, "succeeded", "re_exact")),
    ])
    .await;
    let adapter = mock.adapter(connection).await;
    let (verified, customer) = adapter.verify_charge(CHARGE, 2500, 100, 200).await.unwrap();
    assert_eq!(verified, dispatch.snapshot().request);
    assert_eq!(customer.as_deref(), Some("cus_example"));
    assert_eq!(adapter.replay_safety(), ReplaySafety::ReconcileOnly);
    assert_eq!(
        adapter.execute(&verified, key).await,
        ProviderOutcome::ConfirmedSuccess(
            EvidenceRef::new("stripe:acct_example:re_exact".into()).unwrap()
        )
    );
    mock.complete();
}

#[tokio::test]
async fn rejects_live_secrets_wrong_account_and_unsafe_charges() {
    let connection = Uuid::new_v4();
    let mut wrong = account();
    wrong.body["id"] = json!("acct_other");
    let mock = Mock::start(vec![wrong]).await;
    assert!(matches!(
        StripeSandbox::connect(
            "sk_live_fixture".into(),
            connection,
            ACCOUNT.into(),
            &mock.addr
        )
        .await,
        Err(StripeError::Configuration)
    ));
    assert!(matches!(
        StripeSandbox::connect(KEY.into(), connection, ACCOUNT.into(), &mock.addr).await,
        Err(StripeError::Account)
    ));
    mock.complete();
    let mut steps = vec![account()];
    for (field, value) in [
        ("livemode", json!(true)),
        ("disputed", json!(true)),
        ("captured", json!(false)),
        ("amount_refunded", json!(4000)),
        ("currency", json!("eur")),
        ("transfer_data", json!({"destination":"acct_other"})),
    ] {
        let mut charge = charge();
        charge.body[field] = value;
        steps.push(charge);
    }
    let mut missing = charge();
    missing.body.as_object_mut().unwrap().remove("customer");
    steps.push(missing);
    let mock = Mock::start(steps).await;
    let adapter = mock.adapter(connection).await;
    assert!(adapter
        .verify_charge("ch_escape/other", 2500, 100, 200)
        .await
        .is_err());
    for _ in 0..7 {
        assert!(adapter.verify_charge(CHARGE, 2500, 100, 200).await.is_err());
    }
    mock.complete();
}

#[tokio::test]
async fn reconciliation_requires_one_exact_match_across_all_pages() {
    const LIST: &str = "/v1/refunds?charge=ch_example&limit=10";
    const NEXT: &str = "/v1/refunds?charge=ch_example&limit=10&starting_after=re_first";
    let connection = Uuid::new_v4();
    let dispatch = request(connection);
    let key = dispatch.provider_key();
    let pending = refund(key, "requires_action", "re_first");
    let duplicate = refund(key, "succeeded", "re_other");
    let failed = refund(key, "failed", "re_failed");
    let mock = Mock::start(vec![
        account(),
        charge(),
        list(LIST, vec![pending.clone()], true),
        list(NEXT, vec![duplicate], false),
        charge(),
        list(LIST, vec![], false),
        charge(),
        list(LIST, vec![pending], false),
        charge(),
        list(LIST, vec![failed], false),
    ])
    .await;
    let adapter = mock.adapter(connection).await;
    let request = &dispatch.snapshot().request;
    assert_eq!(
        adapter.reconcile(request, key).await,
        ProviderOutcome::Unknown
    );
    assert_eq!(
        adapter.reconcile(request, key).await,
        ProviderOutcome::Unknown
    );
    assert_eq!(
        adapter.reconcile(request, key).await,
        ProviderOutcome::Pending
    );
    assert!(matches!(
        adapter.reconcile(request, key).await,
        ProviderOutcome::ConfirmedNonExecution(_)
    ));
    mock.complete();
}

#[tokio::test]
async fn errors_and_incorrect_success_responses_never_release_or_retry() {
    let connection = Uuid::new_v4();
    let dispatch = request(connection);
    let key = dispatch.provider_key();
    let mut redirect = execute(key, json!({}));
    redirect.status = StatusCode::TEMPORARY_REDIRECT;
    redirect.redirect = true;
    let mut unavailable = execute(key, json!({"error":"unavailable"}));
    unavailable.status = StatusCode::SERVICE_UNAVAILABLE;
    let mut steps = vec![account(), charge(), redirect, charge(), unavailable];
    for (field, value) in [
        ("livemode", json!(true)),
        ("amount", json!(5000)),
        ("charge", json!("ch_other")),
        ("currency", json!("eur")),
        ("metadata", json!({})),
        ("status", json!("new_state")),
    ] {
        let mut wrong = refund(key, "succeeded", "re_wrong");
        wrong[field] = value;
        steps.push(charge());
        steps.push(execute(key, wrong));
    }
    let mut oversize = refund(key, "succeeded", "re_wrong");
    oversize["ignored"] = json!("x".repeat(RESPONSE_LIMIT));
    steps.push(charge());
    steps.push(execute(key, oversize));
    let mock = Mock::start(steps).await;
    let adapter = mock.adapter(connection).await;
    for _ in 0..9 {
        assert_eq!(
            adapter.execute(&dispatch.snapshot().request, key).await,
            ProviderOutcome::Unknown
        );
    }
    mock.complete();
}

#[tokio::test]
async fn partial_reconciliation_scan_does_not_confirm_even_an_exact_match() {
    let connection = Uuid::new_v4();
    let dispatch = request(connection);
    let key = dispatch.provider_key();
    let mut steps = vec![account(), charge()];
    for (index, path) in [
        "/v1/refunds?charge=ch_example&limit=10",
        "/v1/refunds?charge=ch_example&limit=10&starting_after=re_page0",
        "/v1/refunds?charge=ch_example&limit=10&starting_after=re_page1",
        "/v1/refunds?charge=ch_example&limit=10&starting_after=re_page2",
        "/v1/refunds?charge=ch_example&limit=10&starting_after=re_page3",
    ]
    .into_iter()
    .enumerate()
    {
        let mut item = refund(key, "succeeded", &format!("re_page{index}"));
        if index != 0 {
            item["metadata"] = json!({});
        }
        steps.push(list(path, vec![item], true));
    }
    let mock = Mock::start(steps).await;
    let adapter = mock.adapter(connection).await;
    assert_eq!(
        adapter.reconcile(&dispatch.snapshot().request, key).await,
        ProviderOutcome::Unknown
    );
    let wrong_connection = request(Uuid::new_v4());
    assert_eq!(
        adapter
            .execute(&wrong_connection.snapshot().request, key)
            .await,
        ProviderOutcome::Unknown
    );
    mock.complete();
}

#[tokio::test]
async fn retained_observation_uses_read_start_and_private_customer_scope() {
    let connection = Uuid::new_v4();
    let mut slow = charge();
    slow.delay = Duration::from_millis(40);
    let mock = Mock::start(vec![account(), slow]).await;
    let adapter = mock.adapter(connection).await;
    let started = std::time::Instant::now();
    let context = adapter
        .verify_charge_context(CHARGE, 2500, 100, 120)
        .await
        .unwrap();
    assert!(started.elapsed() >= Duration::from_millis(40));
    assert_eq!(context.observation.request(), &context.request);
    assert_eq!(context.request.observed_at(), 100);
    assert_eq!(context.request.fresh_until(), 120);
    assert!(!context.request.is_fresh(140));
    assert_eq!(context.observation.facts().refunded_minor, 1000);
    assert_eq!(context.customer_ref.as_deref(), Some("cus_example"));
    let json = serde_json::to_string(&context.observation).unwrap();
    assert!(!json.contains("cus_example"));
    mock.complete();
}

#[tokio::test]
async fn invalid_authenticated_charge_facts_never_emit_observations() {
    let cases = [
        ("id", json!("ch_other"), false),
        ("object", json!("payment_intent"), false),
        ("livemode", json!(true), true),
        ("currency", json!("eur"), true),
        ("payment_method_details", json!({"type":"bank"}), true),
        ("payment_method_details", json!(null), true),
        ("paid", json!(false), true),
        ("captured", json!(false), true),
        ("disputed", json!(true), true),
        ("status", json!("pending"), true),
        ("amount_captured", json!(5001), true),
        ("amount_refunded", json!(5001), true),
        ("amount_refunded", json!(2501), true),
        ("amount", json!(9_007_199_254_740_992u64), true),
        ("on_behalf_of", json!("acct_other"), true),
        ("transfer", json!("tr_other"), true),
        ("transfer_data", json!({"destination":"acct_other"}), true),
        ("source_transfer", json!("tr_other"), true),
        ("customer", json!("cus_invalid/slash"), false),
        ("customer", json!({"id":"cus_expanded"}), false),
        ("amount_captured", json!(-1), false),
    ];
    let mut steps = vec![account()];
    for (field, value, _) in &cases {
        let mut next = charge();
        next.body[*field] = value.clone();
        steps.push(next);
    }
    for field in ["customer", "paid", "amount_refunded"] {
        let mut next = charge();
        next.body.as_object_mut().unwrap().remove(field);
        steps.push(next);
    }
    let mut unavailable = charge();
    unavailable.status = StatusCode::SERVICE_UNAVAILABLE;
    steps.push(unavailable);
    let mock = Mock::start(steps).await;
    let adapter = mock.adapter(Uuid::new_v4()).await;
    for (field, _, charge_error) in cases {
        let result = adapter.verify_charge_context(CHARGE, 2500, 100, 200).await;
        assert!(
            if charge_error {
                matches!(result, Err(StripeError::Charge))
            } else {
                matches!(result, Err(StripeError::Unverified))
            },
            "{field}"
        );
    }
    for _ in 0..4 {
        assert!(matches!(
            adapter.verify_charge_context(CHARGE, 2500, 100, 200).await,
            Err(StripeError::Unverified)
        ));
    }
    mock.complete();
}

#[tokio::test]
async fn timed_out_charge_read_cannot_emit_an_observation() {
    let mut slow = charge();
    slow.delay = Duration::from_millis(100);
    let mock = Mock::start(vec![account(), slow]).await;
    let mut adapter = mock.adapter(Uuid::new_v4()).await;
    adapter.client = Client::builder()
        .timeout(Duration::from_millis(10))
        .no_proxy()
        .build()
        .unwrap();
    assert!(matches!(
        adapter.verify_charge_context(CHARGE, 2500, 100, 200).await,
        Err(StripeError::Unverified)
    ));
    mock.complete();
}
