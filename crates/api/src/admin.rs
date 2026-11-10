//! Reviewer-authenticated policy and dispatch control endpoints.
use super::{invalid_json, resolve_reviewer, ApiError, AppState};
use apl_domain::{evaluate_version, PolicyVersion, RefundRequest, VersionDecision};
use apl_persistence::dispatch_controls::{ControlKind, ControlState};
use apl_persistence::StoreError;
use axum::{
    extract::{
        rejection::{JsonRejection, QueryRejection},
        Path, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(super) fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/policies", get(policy_page))
        .route("/v1/policies/drafts", post(create_draft))
        .route("/v1/policies/{version}/simulate", post(simulate))
        .route("/v1/policies/{version}/publish", post(publish))
        .route("/v1/controls/pause", post(pause))
        .route("/v1/controls/resume", post(resume))
        .route("/v1/controls/state", get(control_state))
        .layer(middleware::from_fn(no_cache))
}

async fn no_cache(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyQuery {
    connection_id: Uuid,
    after: Option<i64>,
    limit: Option<usize>,
}
async fn policy_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<PolicyQuery>, QueryRejection>,
) -> Result<Json<apl_persistence::policy_console::PolicyPage>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Query(query) = query.map_err(|_| invalid())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit)
        || query
            .after
            .is_some_and(|v| !(1..=9_007_199_254_740_991).contains(&v))
    {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let page = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state
            .store
            .policy_page(&reviewer, query.connection_id, query.after, limit),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(page))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftInput {
    connection_id: Uuid,
    version: i64,
    auto_limit_minor: i64,
    hard_limit_minor: i64,
    approval_ttl_seconds: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SimulationInput {
    connection_id: Uuid,
    requests: Vec<RefundRequest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishInput {
    connection_id: Uuid,
    expected_version: i64,
}

#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum ControlInput {
    Connection {
        connection_id: Uuid,
        expected_revision: i64,
    },
    Workload {
        workload_id: Uuid,
        expected_revision: i64,
    },
    Tenant {
        tenant: bool,
        expected_revision: i64,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlQuery {
    kind: ControlKind,
    id: Option<Uuid>,
}
async fn control_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ControlQuery>, QueryRejection>,
) -> Result<Json<ControlState>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Query(query) = query.map_err(|_| invalid())?;
    if matches!(query.kind, ControlKind::Tenant) != query.id.is_none() {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.store.control_state(&reviewer, query.kind, query.id),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(result))
}

#[derive(Serialize)]
struct Simulation {
    active_version: Option<i64>,
    draft_version: i64,
    results: Vec<SimulationComparison>,
}

#[derive(Serialize)]
struct SimulationComparison {
    old: Outcome,
    new: Outcome,
}

#[derive(Serialize)]
struct Outcome {
    outcome: &'static str,
    reason: &'static str,
}

impl Outcome {
    fn for_policy(request: &RefundRequest, policy: Option<&PolicyVersion>) -> Self {
        let decision = policy.map_or(VersionDecision::Deny("NO_ACTIVE_POLICY"), |policy| {
            evaluate_version(request, policy)
        });
        let (outcome, reason) = match decision {
            VersionDecision::Allow => ("allow", "POLICY_AUTO_ALLOW"),
            VersionDecision::RequireApproval => ("require_approval", "APPROVAL_REQUIRED"),
            VersionDecision::Deny(reason) => ("deny", reason),
        };
        Self { outcome, reason }
    }
}

fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}

fn parse_version(value: &str) -> Result<i64, ApiError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|v| *v > 0)
        .ok_or_else(invalid)
}

fn map_admin_error(error: StoreError, conflict: &'static str) -> ApiError {
    match error {
        StoreError::Conflict => ApiError(StatusCode::CONFLICT, conflict),
        other => other.into(),
    }
}

async fn create_draft(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<DraftInput>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Json(input) = body.map_err(invalid_json)?;
    let policy = PolicyVersion {
        version: input.version,
        auto_limit_minor: input.auto_limit_minor,
        hard_limit_minor: input.hard_limit_minor,
        approval_ttl_seconds: input.approval_ttl_seconds,
    };
    policy.validate().map_err(|_| invalid())?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    state
        .store
        .create_policy_draft(&reviewer, input.connection_id, &policy)
        .await
        .map_err(|error| map_admin_error(error, "policy_conflict"))?;
    Ok(StatusCode::CREATED)
}

async fn simulate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(version): Path<String>,
    body: Result<Json<SimulationInput>, JsonRejection>,
) -> Result<Json<Simulation>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let version = parse_version(&version)?;
    let Json(input) = body.map_err(invalid_json)?;
    if !(1..=25).contains(&input.requests.len())
        || input.requests.iter().any(|request| {
            request.connection_id != input.connection_id || request.validate().is_err()
        })
    {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let (active, draft) = state
        .store
        .simulation_policies(&reviewer, input.connection_id, version)
        .await
        .map_err(|error| map_admin_error(error, "policy_conflict"))?;
    let results = input
        .requests
        .iter()
        .map(|request| SimulationComparison {
            old: Outcome::for_policy(request, active.as_ref()),
            new: Outcome::for_policy(request, Some(&draft)),
        })
        .collect();
    Ok(Json(Simulation {
        active_version: active.map(|policy| policy.version),
        draft_version: draft.version,
        results,
    }))
}

async fn publish(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(version): Path<String>,
    body: Result<Json<PublishInput>, JsonRejection>,
) -> Result<StatusCode, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let version = parse_version(&version)?;
    let Json(input) = body.map_err(invalid_json)?;
    if input.expected_version < 0 {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    state
        .store
        .publish_policy(
            &reviewer,
            input.connection_id,
            version,
            input.expected_version,
        )
        .await
        .map_err(|error| map_admin_error(error, "policy_conflict"))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn pause(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<ControlInput>, JsonRejection>,
) -> Result<Json<ControlState>, ApiError> {
    set_paused(state, headers, body, true).await
}
async fn resume(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<ControlInput>, JsonRejection>,
) -> Result<Json<ControlState>, ApiError> {
    set_paused(state, headers, body, false).await
}
async fn set_paused(
    state: AppState,
    headers: HeaderMap,
    body: Result<Json<ControlInput>, JsonRejection>,
    paused: bool,
) -> Result<Json<ControlState>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Json(input) = body.map_err(invalid_json)?;
    let (kind, id, expected) = match input {
        ControlInput::Connection {
            connection_id,
            expected_revision,
        } => (
            ControlKind::Connection,
            Some(connection_id),
            expected_revision,
        ),
        ControlInput::Workload {
            workload_id,
            expected_revision,
        } => (ControlKind::Workload, Some(workload_id), expected_revision),
        ControlInput::Tenant {
            tenant: true,
            expected_revision,
        } => (ControlKind::Tenant, None, expected_revision),
        ControlInput::Tenant { tenant: false, .. } => return Err(invalid()),
    };
    if !(1..=9_007_199_254_740_991).contains(&expected) {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state
            .store
            .set_control_state(&reviewer, kind, id, expected, paused),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))?
    .map_err(|error| map_admin_error(error, "control_conflict"))?;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use crate::{
        router_with_reviewers, Authenticator, LocalReviewerToken, ReviewerAuthenticator,
        TokenRegistry,
    };
    use apl_persistence::Store;
    use axum::{body::Body, http::Request};
    use serde_json::{json, Value};
    use std::time::Duration;
    use tower::ServiceExt;

    use super::*;

    const WORKLOAD: &str = "workload-a-test-token-0123456789abcdef";
    const REVIEWER: &str = "reviewer-a-test-token-0123456789abcdef";
    const CONNECTION: &str = "00000000-0000-0000-0000-000000000301";

    #[tokio::test]
    async fn control_mutations_require_exact_revision_payloads() {
        for path in ["/v1/controls/pause", "/v1/controls/resume"] {
            for input in [
                json!({"connection_id":CONNECTION}),
                json!({"workload_id":CONNECTION}),
                json!({"tenant":true}),
                json!({"tenant":true,"expected_revision":0}),
                json!({"tenant":true,"expected_revision":9007199254740992i64}),
                json!({"tenant":true,"connection_id":CONNECTION,"expected_revision":1}),
            ] {
                assert_eq!(post(path, REVIEWER, input).await, StatusCode::BAD_REQUEST);
            }
        }
    }
    #[tokio::test]
    async fn control_reads_validate_scope_without_leaking_request_details() {
        for token in [WORKLOAD, REVIEWER] {
            for query in [
                "kind=unknown".to_string(),
                "kind=connection".into(),
                format!("kind=tenant&id={CONNECTION}"),
                "kind=tenant&kind=workload".into(),
                "kind=tenant&tenant_id=private".into(),
            ] {
                let workloads = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
                let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workloads).unwrap();
                let app = router_with_reviewers(
                    Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
                    Authenticator::Local(workloads),
                    Some(ReviewerAuthenticator::Local(reviewer)),
                );
                let request = Request::get(format!("/v1/controls/state?{query}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap();
                let response = tokio::time::timeout(Duration::from_secs(2), app.oneshot(request))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if token == WORKLOAD {
                        StatusCode::UNAUTHORIZED
                    } else {
                        StatusCode::BAD_REQUEST
                    }
                );
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "private, no-store"
                );
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap(),
                    json!({"error":{"code":if token==WORKLOAD{"unauthorized"}else{"invalid_request"}}})
                );
            }
        }
    }

    #[tokio::test]
    async fn policy_read_authentication_validation_and_cache_boundary() {
        let bad = [
            "connection_id=private-value".to_string(),
            format!("connection_id={CONNECTION}&tenant_id=private"),
            format!("connection_id={CONNECTION}&connection_id={CONNECTION}"),
            format!("connection_id={CONNECTION}&limit=101"),
            format!("connection_id={CONNECTION}&after=0"),
            format!("connection_id={CONNECTION}&after=9007199254740992"),
        ];
        for token in [WORKLOAD, REVIEWER] {
            for query in &bad {
                let workloads = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
                let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workloads).unwrap();
                let app = router_with_reviewers(
                    Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
                    Authenticator::Local(workloads),
                    Some(ReviewerAuthenticator::Local(reviewer)),
                );
                let request = Request::get(format!("/v1/policies?{query}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap();
                let response = tokio::time::timeout(Duration::from_secs(2), app.oneshot(request))
                    .await
                    .unwrap()
                    .unwrap();
                let expected = if token == WORKLOAD {
                    StatusCode::UNAUTHORIZED
                } else {
                    StatusCode::BAD_REQUEST
                };
                assert_eq!(response.status(), expected);
                assert_eq!(
                    response.headers()[header::CACHE_CONTROL],
                    "private, no-store"
                );
                assert_eq!(
                    response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                    "nosniff"
                );
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .unwrap();
                assert_eq!(
                    serde_json::from_slice::<Value>(&body).unwrap(),
                    json!({"error":{"code":if token==WORKLOAD {"unauthorized"} else {"invalid_request"}}})
                );
            }
        }
    }

    async fn post(path: &str, token: &str, input: Value) -> StatusCode {
        let workloads = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
        let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workloads).unwrap();
        let router = router_with_reviewers(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            Authenticator::Local(workloads),
            Some(ReviewerAuthenticator::Local(reviewer)),
        );
        let request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), router.oneshot(request))
            .await
            .expect("invalid admin request should not resolve database grants")
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn workload_credentials_cannot_reach_any_admin_handler() {
        for path in [
            "/v1/policies/drafts",
            "/v1/policies/1/simulate",
            "/v1/policies/1/publish",
            "/v1/controls/pause",
            "/v1/controls/resume",
        ] {
            assert_eq!(
                post(path, WORKLOAD, json!({})).await,
                StatusCode::UNAUTHORIZED,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_admin_input_is_rejected_before_database_resolution() {
        let refund = json!({"type":"refund.create","connection_id":CONNECTION,"resource":{"payment_id":"ch_example"},"parameters":{"amount_minor":2500,"currency":"USD"}});
        let mut cross_connection = refund.clone();
        cross_connection["connection_id"] = json!(Uuid::nil());
        for (path, body) in [
            (
                "/v1/policies/drafts",
                json!({"connection_id":CONNECTION,"version":2,"auto_limit_minor":5001,"hard_limit_minor":5000,"approval_ttl_seconds":60}),
            ),
            (
                "/v1/policies/1/simulate",
                json!({"connection_id":CONNECTION,"requests":vec![refund;26]}),
            ),
            (
                "/v1/policies/1/simulate",
                json!({"connection_id":CONNECTION,"requests":[cross_connection]}),
            ),
            (
                "/v1/policies/1/publish",
                json!({"connection_id":CONNECTION,"expected_version":-1}),
            ),
            (
                "/v1/controls/pause",
                json!({"connection_id":CONNECTION,"paused":false}),
            ),
            ("/v1/controls/pause", json!({"tenant":false})),
            (
                "/v1/controls/pause",
                json!({"tenant":true,"connection_id":CONNECTION}),
            ),
        ] {
            assert_eq!(
                post(path, REVIEWER, body).await,
                StatusCode::BAD_REQUEST,
                "{path}"
            );
        }
    }
}
