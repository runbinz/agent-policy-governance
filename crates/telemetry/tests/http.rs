use apl_telemetry::Metrics;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    routing::get,
    Router,
};
use tower::ServiceExt;
use uuid::Uuid;
const TOKEN: &str = "0123456789abcdef0123456789abcdef";
fn app() -> Router {
    Metrics::new(TOKEN)
        .unwrap()
        .instrument(Router::new().route("/items/{id}", get(|| async { "ok" })))
}
async fn scrape(app: Router) -> String {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    String::from_utf8(
        to_bytes(response.into_body(), 1_000_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
#[tokio::test]
async fn protected_scrape_rejects_ambiguity() {
    for headers in [
        vec![],
        vec!["Bearer bad".to_owned()],
        vec![format!("Bearer {TOKEN}"), format!("Bearer {TOKEN}")],
        vec![format!("Bearer {TOKEN}, Bearer {TOKEN}")],
        vec![format!("Bearer {TOKEN} ")],
    ] {
        let mut request = Request::builder().uri("/metrics");
        for value in headers {
            request = request.header("authorization", value);
        }
        let response = app()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert!(!scrape(app()).await.contains("route="));
    for token in [
        "",
        "short",
        "0123456789abcdef0123456789abc def",
        "0123456789abcdef0123456789abcdef\n",
    ] {
        assert!(Metrics::new(token).is_err());
    }
}
#[tokio::test]
async fn templates_histogram_and_redaction() {
    let app = app();
    for _ in 0..3 {
        let id = Uuid::new_v4();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/items/{id}?token=INJECTED_SECRET"))
                    .header("authorization", "Bearer INJECTED_SECRET")
                    .header("x-request-id", "INJECTED_SECRET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let trace = response.headers()["x-request-id"].to_str().unwrap();
        assert_eq!(Uuid::parse_str(trace).unwrap().get_version_num(), 4);
    }
    let text = scrape(app.clone()).await;
    assert!(!text.contains("INJECTED_SECRET"));
    assert!(!text.contains(TOKEN));
    assert!(text.contains(
        "apl_http_requests_total{route=\"/items/{id}\",method=\"GET\",status_class=\"2xx\"} 3"
    ));
    assert!(text.contains("le=\"+Inf\"} 3"));
    assert!(text.contains("apl_http_request_duration_seconds_count{route=\"/items/{id}\",method=\"GET\",status_class=\"2xx\"} 3"));
    assert_eq!(text, scrape(app).await);
}
#[tokio::test]
async fn unmatched_paths_and_custom_methods_are_bounded() {
    let app = app();
    let mut traces = std::collections::HashSet::new();
    for i in 0..100 {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/private-{i}?secret={i}"))
                    .method(format!("CUSTOM{i}").as_str())
                    .header("x-request-id", Uuid::nil().to_string())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(traces.insert(
            response.headers()["x-request-id"]
                .to_str()
                .unwrap()
                .to_owned()
        ));
    }
    let text = scrape(app).await;
    assert_eq!(
        text.lines()
            .filter(|l| l.starts_with("apl_http_requests_total{"))
            .count(),
        1
    );
    assert!(text.contains(
        "route=\"__unmatched_or_overflow__\",method=\"OTHER\",status_class=\"4xx\"} 100"
    ));
    assert!(!text.contains("private-"));
}
