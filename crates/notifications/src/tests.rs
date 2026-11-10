use super::*;
use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::{HeaderMap, Method, Response},
    routing::post,
    Router,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
};
use tokio::{net::TcpListener, task::JoinHandle};

const TEAM: &str = "T12345678";
const CHANNEL: &str = "C12345678";
const TOKEN: &str = "xoxb-fixture-only";

fn message() -> NotificationMessage {
    NotificationMessage {
        id: Uuid::from_u128(1),
        action_id: Uuid::from_u128(2),
        approval_generation: 3,
    }
}

fn config(values: &[(&str, &str)]) -> Result<Option<Notifier>, NotificationError> {
    let values: BTreeMap<_, _> = values.iter().copied().collect();
    Notifier::from_lookup(|key| Ok(values.get(key).map(|value| (*value).to_owned())))
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
    retry: Option<String>,
    delay: Duration,
}
impl Reply {
    fn json(value: Value) -> Self {
        Self {
            status: 200,
            body: value.to_string(),
            retry: None,
            delay: Duration::ZERO,
        }
    }
}
type Captured = (String, Method, HeaderMap, Value);
#[derive(Clone)]
struct MockState {
    auth: Reply,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    captured: Arc<Mutex<Vec<Captured>>>,
}

struct Mock {
    state: MockState,
    origin: Url,
    task: JoinHandle<()>,
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Mock {
    async fn start(auth: Reply, replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            Url::parse(&format!("http://{}/api/", listener.local_addr().unwrap())).unwrap();
        let state = MockState {
            auth,
            replies: Arc::new(Mutex::new(replies.into())),
            captured: Arc::new(Mutex::new(Vec::new())),
        };
        let router = Router::new()
            .route(
                "/api/{method}",
                post(
                    |State(state): State<MockState>,
                     Path(path): Path<String>,
                     method: Method,
                     headers: HeaderMap,
                     body: Bytes| async move {
                        state.captured.lock().unwrap().push((
                            path.clone(),
                            method,
                            headers,
                            serde_json::from_slice(&body).unwrap(),
                        ));
                        let reply = if path == "auth.test" {
                            state.auth.clone()
                        } else {
                            state.replies.lock().unwrap().pop_front().unwrap()
                        };
                        if !reply.delay.is_zero() {
                            tokio::time::sleep(reply.delay).await;
                        }
                        let mut response = Response::builder().status(reply.status);
                        if let Some(retry) = reply.retry {
                            response = response.header("retry-after", retry);
                        }
                        if reply.status == 302 {
                            response = response.header("location", "/api/chat.postMessage");
                        }
                        response.body(Body::from(reply.body)).unwrap()
                    },
                ),
            )
            .with_state(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Self {
            state,
            origin,
            task,
        }
    }

    fn notifier(&self) -> Notifier {
        Notifier {
            route_id: Uuid::from_u128(10),
            console_url: "https://console.example/".into(),
            transport: Transport::Slack(Arc::new(Slack {
                client: client().unwrap(),
                token: Zeroizing::new(TOKEN.into()),
                team_id: TEAM.into(),
                origin: self.origin.clone(),
            })),
        }
    }

    fn calls(&self) -> usize {
        self.state.captured.lock().unwrap().len()
    }
}
fn auth() -> Reply {
    Reply::json(json!({"ok":true,"team_id":TEAM}))
}
fn delivered() -> Reply {
    Reply::json(json!({"ok":true,"channel":CHANNEL,"ts":"1234.5678"}))
}

#[tokio::test]
async fn verifies_team_before_posting_minimal_plain_text_to_exact_channel() {
    let mock = Mock::start(auth(), vec![delivered()]).await;
    let notifier = mock.notifier();
    assert_eq!(
        notifier
            .deliver(&message(), Some(TEAM), Some(CHANNEL))
            .await,
        DeliveryOutcome::Delivered
    );
    let captured = mock.state.captured.lock().unwrap();
    assert_eq!(captured.len(), 2);
    assert_eq!(captured[0].0, "auth.test");
    assert_eq!(captured[1].0, "chat.postMessage");
    for (_, method, headers, body) in captured.iter() {
        assert_eq!(*method, Method::POST);
        assert_eq!(headers["authorization"], format!("Bearer {TOKEN}"));
        assert!(!body.to_string().contains(TOKEN));
    }
    let body = &captured[1].3;
    assert_eq!(body["channel"], CHANNEL);
    assert_eq!(body["client_msg_id"], message().id.to_string());
    assert_eq!(body["mrkdwn"], false);
    assert_eq!(body["parse"], "none");
    assert_eq!(body["unfurl_links"], false);
    assert_eq!(body["unfurl_media"], false);
    assert_eq!(body["text"],format!("Approval requested. Action {}. Approval generation 3. Open the authenticated reviewer queue: https://console.example/",message().action_id));
    assert_eq!(
        body["blocks"],
        json!([{
            "type":"rich_text",
            "elements":[{
                "type":"rich_text_section",
                "elements":[
                    {"type":"text","text":format!("Approval requested. Action {}. Approval generation 3. ",message().action_id)},
                    {"type":"link","url":"https://console.example/","text":"Open reviewer queue"}
                ]
            }]
        }])
    );
    assert!(!body.to_string().contains("action_id"));
    assert!(!body.to_string().contains("button"));
    assert!(!body["blocks"].to_string().contains("mrkdwn"));
    assert_eq!(body.as_object().unwrap().len(), 8);
}

#[tokio::test]
async fn rejects_route_or_token_team_mismatch_and_invalid_channels_without_posts() {
    let mock = Mock::start(
        Reply::json(json!({"ok":true,"team_id":"T99999999"})),
        vec![],
    )
    .await;
    let notifier = mock.notifier();
    assert_eq!(
        notifier
            .deliver(&message(), Some("T99999999"), Some(CHANNEL))
            .await,
        DeliveryOutcome::PermanentFailure
    );
    assert_eq!(
        notifier
            .deliver(&message(), Some(TEAM), Some("@channel"))
            .await,
        DeliveryOutcome::PermanentFailure
    );
    assert_eq!(mock.calls(), 0);
    assert_eq!(
        notifier
            .deliver(&message(), Some(TEAM), Some(CHANNEL))
            .await,
        DeliveryOutcome::PermanentFailure
    );
    assert_eq!(mock.calls(), 1);
}

#[tokio::test]
async fn classifies_rate_limits_failures_and_malformed_receipts_without_hidden_retries() {
    let cases = [
        (
            Reply {
                status: 429,
                retry: Some("120".into()),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(120),
        ),
        (
            Reply {
                status: 429,
                retry: Some("999999".into()),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(86400),
        ),
        (
            Reply {
                status: 429,
                retry: Some("0".into()),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(1),
        ),
        (
            Reply {
                status: 429,
                retry: Some("bad".into()),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply {
                status: 503,
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply {
                status: 403,
                ..delivered()
            },
            DeliveryOutcome::PermanentFailure,
        ),
        (
            Reply {
                body: "not JSON".into(),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply {
                body: "x".repeat(MAX_RESPONSE_BYTES + 1),
                ..delivered()
            },
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply::json(json!({"ok":false,"error":"not_in_channel"})),
            DeliveryOutcome::PermanentFailure,
        ),
        (
            Reply::json(json!({"ok":false,"error":"invalid_auth"})),
            DeliveryOutcome::PermanentFailure,
        ),
        (
            Reply::json(json!({"ok":false,"error":"internal_error"})),
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply::json(json!({"ok":true,"channel":"C99999999","ts":"1234.56"})),
            DeliveryOutcome::RetryAfter(30),
        ),
        (
            Reply::json(json!({"ok":true,"channel":CHANNEL,"ts":""})),
            DeliveryOutcome::RetryAfter(30),
        ),
    ];
    for (reply, expected) in cases {
        let mock = Mock::start(auth(), vec![reply]).await;
        assert_eq!(
            mock.notifier()
                .deliver(&message(), Some(TEAM), Some(CHANNEL))
                .await,
            expected
        );
        assert_eq!(mock.calls(), 2);
    }
    for reply in [
        Reply {
            status: 302,
            ..auth()
        },
        Reply {
            status: 500,
            ..auth()
        },
        Reply::json(json!({"ok":false,"error":"token_revoked"})),
    ] {
        let mock = Mock::start(reply, vec![]).await;
        let result = mock
            .notifier()
            .deliver(&message(), Some(TEAM), Some(CHANNEL))
            .await;
        assert!(result != DeliveryOutcome::Delivered);
        assert_eq!(mock.calls(), 1);
    }
}

#[tokio::test]
async fn total_delivery_timeout_is_bounded_and_fake_never_uses_network() {
    let mock = Mock::start(
        Reply {
            delay: Duration::from_secs(6),
            ..auth()
        },
        vec![],
    )
    .await;
    assert_eq!(
        mock.notifier()
            .deliver(&message(), Some(TEAM), Some(CHANNEL))
            .await,
        DeliveryOutcome::RetryAfter(30)
    );
    assert_eq!(mock.calls(), 1);
    let fake = Notifier::fake(Uuid::from_u128(10), "http://127.0.0.1:5173").unwrap();
    assert_eq!(fake.kind(), "fake");
    assert_eq!(fake.route_id(), Uuid::from_u128(10));
    assert_eq!(
        fake.deliver(&message(), None, None).await,
        DeliveryOutcome::Delivered
    );
}

#[test]
fn startup_configuration_is_explicit_and_secret_errors_are_generic() {
    assert!(config(&[]).unwrap().is_none());
    for name in [
        "APL_NOTIFICATION_ROUTE_ID",
        "APL_CONSOLE_ORIGIN",
        "APL_SLACK_TEAM_ID",
        "APL_SLACK_BOT_TOKEN",
    ] {
        assert!(config(&[(name, "stray")]).is_err());
    }
    let route = Uuid::from_u128(1).to_string();
    let fake = [
        ("APL_NOTIFICATION_MODE", "fake"),
        ("APL_NOTIFICATION_ROUTE_ID", route.as_str()),
        ("APL_CONSOLE_ORIGIN", "http://127.0.0.1:5173"),
        ("APL_LOCAL_DEV", "true"),
    ];
    assert_eq!(config(&fake).unwrap().unwrap().kind(), "fake");
    let slack = [
        ("APL_NOTIFICATION_MODE", "slack"),
        ("APL_NOTIFICATION_ROUTE_ID", route.as_str()),
        ("APL_CONSOLE_ORIGIN", "https://console.example"),
        ("APL_SLACK_TEAM_ID", TEAM),
        ("APL_SLACK_BOT_TOKEN", TOKEN),
    ];
    assert_eq!(config(&slack).unwrap().unwrap().kind(), "slack");
    for (key, value) in [
        ("APL_NOTIFICATION_MODE", "unknown"),
        ("APL_NOTIFICATION_ROUTE_ID", "bad"),
        ("APL_CONSOLE_ORIGIN", "http://console.example"),
        ("APL_CONSOLE_ORIGIN", "https://console.example/path"),
        ("APL_CONSOLE_ORIGIN", "https://console.example/?q=1"),
        ("APL_CONSOLE_ORIGIN", "https://user@console.example"),
        ("APL_SLACK_TEAM_ID", "Tbad"),
        ("APL_SLACK_BOT_TOKEN", "xoxp-private"),
        ("APL_SLACK_BOT_TOKEN", "xoxb- bad"),
    ] {
        let mut invalid = slack;
        invalid[slack.iter().position(|(name, _)| *name == key).unwrap()] = (key, value);
        assert!(config(&invalid).is_err());
    }
    assert!(Notifier::from_lookup(|_| Err(NotificationError::InvalidConfiguration)).is_err());
    assert_eq!(
        NotificationError::InvalidConfiguration.to_string(),
        "invalid notification configuration"
    );
}
