//! HTTP boundary with verified identities resolved through persisted grants.
pub mod action_detail;
mod admin;
pub mod browser;
pub mod environment_admin;
pub mod evidence;
pub mod exports;
pub mod mcp;
pub mod operations;
pub mod stripe_webhook;

use apl_domain::{ApprovalInput, Principal, RefundRequest, Reviewer};
use apl_identity::{JwtVerifier, ManagedJwtVerifier, VerifiedIdentity};
use apl_persistence::{Store, StoreError};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Clone)]
pub struct TokenRegistry {
    token_a: String,
    token_b: String,
}
impl TokenRegistry {
    pub fn new(token_a: String, token_b: String) -> Result<Self, String> {
        if token_a.len() < 32
            || token_b.len() < 32
            || token_a == token_b
            || token_a.chars().any(char::is_whitespace)
            || token_b.chars().any(char::is_whitespace)
        {
            return Err(
                "development tokens must be distinct, at least 32 bytes, and contain no whitespace"
                    .into(),
            );
        }
        Ok(Self { token_a, token_b })
    }
    fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedIdentity, ApiError> {
        self.verify(bearer(headers)?)
    }
    fn verify(&self, token: &str) -> Result<VerifiedIdentity, ApiError> {
        let n = if token == self.token_a {
            1
        } else if token == self.token_b {
            2
        } else {
            return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
        };
        Ok(VerifiedIdentity {
            issuer: "urn:apl:local".into(),
            subject: if n == 1 { "tenant-a" } else { "tenant-b" }.into(),
        })
    }
}
fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    if headers.get_all("authorization").iter().count() != 1 {
        return Err(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
}
#[derive(Clone)]
pub enum Authenticator {
    Local(TokenRegistry),
    Jwt(JwtVerifier),
    Managed(ManagedJwtVerifier),
}
impl Authenticator {
    fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedIdentity, ApiError> {
        match self {
            Self::Local(tokens) => tokens.authenticate(headers),
            Self::Jwt(verifier) => verifier
                .verify(bearer(headers)?)
                .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "unauthorized")),
            Self::Managed(verifier) => verifier
                .verify(bearer(headers)?)
                .map_err(|_| unauthorized()),
        }
    }
}
#[derive(Clone)]
pub enum ReviewerAuthenticator {
    Local(LocalReviewerToken),
    Jwt(std::sync::Arc<JwtVerifier>),
    Managed(ManagedJwtVerifier),
    Browser {
        bearer: Option<Box<ReviewerAuthenticator>>,
        sessions: std::sync::Arc<browser::BrowserAuth>,
    },
}

#[derive(Clone)]
pub struct LocalReviewerToken(String);

impl LocalReviewerToken {
    pub fn new(token: String, workloads: &TokenRegistry) -> Result<Self, &'static str> {
        if token.len() < 32
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
            || workloads.verify(&token).is_ok()
        {
            return Err("reviewer token must be distinct from workload tokens and contain at least 32 visible ASCII bytes");
        }
        Ok(Self(token))
    }
}

impl ReviewerAuthenticator {
    fn authenticate_bearer(&self, headers: &HeaderMap) -> Result<VerifiedIdentity, ApiError> {
        if let Self::Browser { bearer, .. } = self {
            return bearer
                .as_ref()
                .ok_or_else(unauthorized)?
                .authenticate_bearer(headers);
        }
        let token = bearer(headers)?;
        match self {
            Self::Local(config) if config.0 == token => Ok(VerifiedIdentity {
                issuer: "urn:apl:local".into(),
                subject: "reviewer-a".into(),
            }),
            Self::Jwt(verifier) => verifier.verify(token).map_err(|_| unauthorized()),
            Self::Managed(verifier) => verifier.verify(token).map_err(|_| unauthorized()),
            Self::Local(_) => Err(unauthorized()),
            Self::Browser { .. } => unreachable!(),
        }
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedIdentity, ApiError> {
        if let Self::Browser { sessions, .. } = self {
            if browser::session_cookie(headers)?.is_some() {
                if headers.contains_key("authorization") {
                    return Err(unauthorized());
                }
                return sessions.authenticate(headers).await;
            }
        }
        self.authenticate_bearer(headers)
    }
}

fn unauthorized() -> ApiError {
    ApiError(StatusCode::UNAUTHORIZED, "unauthorized")
}

#[derive(Clone)]
struct AppState {
    store: Store,
    auth: Authenticator,
    reviewer_auth: Option<ReviewerAuthenticator>,
}

impl AppState {
    fn authenticate_workload(&self, headers: &HeaderMap) -> Result<VerifiedIdentity, ApiError> {
        let identity = self.auth.authenticate(headers)?;
        if self
            .reviewer_auth
            .as_ref()
            .is_some_and(|auth| auth.authenticate_bearer(headers).is_ok())
        {
            return Err(unauthorized());
        }
        Ok(identity)
    }

    async fn authenticate_reviewer(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedIdentity, ApiError> {
        let identity = self
            .reviewer_auth
            .as_ref()
            .ok_or_else(unauthorized)?
            .authenticate(headers)
            .await?;
        if self.auth.authenticate(headers).is_ok() {
            return Err(unauthorized());
        }
        Ok(identity)
    }
}

pub fn router(store: Store, tokens: TokenRegistry) -> Router {
    router_with_auth(store, Authenticator::Local(tokens))
}
pub fn router_with_auth(store: Store, auth: Authenticator) -> Router {
    router_with_reviewers(store, auth, None)
}

pub fn router_with_reviewers(
    store: Store,
    auth: Authenticator,
    reviewer_auth: Option<ReviewerAuthenticator>,
) -> Router {
    Router::new()
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"ok"})) }),
        )
        .route("/health/ready", get(ready))
        .route("/v1/actions", post(submit))
        .route("/v1/actions/{id}", get(action))
        .route("/v1/actions/{id}/events", get(events))
        .route("/v1/actions/{id}/cancel", post(cancel))
        .route(
            "/v1/actions/{id}/reconcile",
            get(reconciliation_state)
                .post(reconcile)
                .layer(axum::middleware::from_fn(reconciliation_no_cache)),
        )
        .route("/v1/approvals", get(approvals))
        .route("/v1/approvals/{id}/decision", post(decide))
        .merge(admin::routes())
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(AppState {
            store,
            auth,
            reviewer_auth,
        })
}
#[derive(Debug)]
struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":{"code":self.1}}))).into_response()
    }
}
impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        match value {
            StoreError::Conflict => Self(StatusCode::CONFLICT, "idempotency_conflict"),
            StoreError::Forbidden | StoreError::NotFound => {
                Self(StatusCode::NOT_FOUND, "not_found")
            }
            StoreError::Invalid(_) => Self(StatusCode::BAD_REQUEST, "invalid_request"),
            other => {
                tracing::error!(error_class = other.class(), "persistence operation failed");
                Self(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
            }
        }
    }
}
async fn ready(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    if matches!(&state.auth, Authenticator::Managed(verifier) if !verifier.is_fresh()) {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"));
    }
    state
        .store
        .health()
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))?;
    Ok(Json(json!({"status":"ready"})))
}
async fn submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<RefundRequest>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_workload(&headers)?;
    if headers.get_all("idempotency-key").iter().count() != 1 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_idempotency_key"));
    }
    let key = headers
        .get("idempotency-key")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty() && v.len() <= 128 && v.bytes().all(|b| b.is_ascii_graphic()))
        .ok_or(ApiError(StatusCode::BAD_REQUEST, "invalid_idempotency_key"))?;
    let Json(request) = body.map_err(invalid_json)?;
    request
        .validate()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let principal = resolve(&state, identity).await?;
    let result = state.store.submit(&principal, key, &request).await?;
    tracing::info!(action_id=%result.id, status=result.status.as_str(), "action admitted");
    let status_url = format!("/v1/actions/{}", result.id);
    let mut body = serde_json::to_value(&result)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?;
    body["status_url"] = json!(status_url);
    Ok((StatusCode::ACCEPTED, [("location", status_url)], Json(body)))
}
async fn action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_workload(&headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let principal = resolve(&state, identity).await?;
    let action = state
        .store
        .get(&principal, id)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    Ok(Json(action))
}
async fn events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_workload(&headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let principal = resolve(&state, identity).await?;
    let events = state
        .store
        .events(&principal, id)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    Ok(Json(events))
}

async fn cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_workload(&headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let principal = resolve(&state, identity).await?;
    let cancelled = state
        .store
        .cancel(&principal, id)
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError(StatusCode::CONFLICT, "action_not_cancellable"),
            other => ApiError::from(other),
        })?;
    Ok(Json(cancelled))
}

async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let operator = resolve_reviewer(&state, identity).await?;
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.store.request_external_reconciliation(&operator, id),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))?
    .map_err(|error| match error {
        StoreError::Conflict => ApiError(StatusCode::CONFLICT, "action_not_in_manual_review"),
        other => other.into(),
    })?;
    state.authenticate_reviewer(&headers).await?;
    Ok(StatusCode::ACCEPTED)
}

async fn reconciliation_no_cache(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response
}

async fn reconciliation_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<apl_persistence::operations_recovery::ReconciliationState>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let snapshot = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.store.reconciliation_state(&reviewer, id),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(snapshot))
}

async fn approvals(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let queue = state.store.list_approvals(&reviewer).await?;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(queue))
}

async fn decide(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<ApprovalInput>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))?;
    let Json(input) = body.map_err(invalid_json)?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let action = state
        .store
        .decide_approval(&reviewer, id, &input)
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError(StatusCode::CONFLICT, "approval_conflict"),
            other => other.into(),
        })?;
    Ok(Json(action))
}

async fn resolve_reviewer(
    state: &AppState,
    identity: VerifiedIdentity,
) -> Result<Reviewer, ApiError> {
    state
        .store
        .resolve_reviewer(&identity.issuer, &identity.subject)
        .await?
        .ok_or_else(unauthorized)
}

fn invalid_json(error: JsonRejection) -> ApiError {
    ApiError(
        if error.status() == StatusCode::PAYLOAD_TOO_LARGE {
            StatusCode::PAYLOAD_TOO_LARGE
        } else {
            StatusCode::BAD_REQUEST
        },
        "invalid_request",
    )
}

async fn resolve(state: &AppState, identity: VerifiedIdentity) -> Result<Principal, ApiError> {
    state
        .store
        .resolve_identity(&identity.issuer, &identity.subject)
        .await?
        .ok_or(ApiError(StatusCode::UNAUTHORIZED, "unauthorized"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tokens_are_explicit_distinct_and_scoped() {
        assert!(TokenRegistry::new("short".into(), "short".into()).is_err());
        let tokens = TokenRegistry::new("a".repeat(32), "b".repeat(32)).unwrap();
        assert!(tokens.authenticate(&HeaderMap::new()).is_err());
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            format!("Bearer {}", "a".repeat(32)).parse().unwrap(),
        );
        assert_eq!(
            tokens.authenticate(&headers).unwrap(),
            VerifiedIdentity {
                issuer: "urn:apl:local".into(),
                subject: "tenant-a".into()
            }
        );
        headers.insert("authorization", "Bearer unknown".parse().unwrap());
        assert!(tokens.authenticate(&headers).is_err());
    }
    fn app() -> Router {
        router(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            TokenRegistry::new("a".repeat(32), "b".repeat(32)).unwrap(),
        )
    }
    #[tokio::test]
    async fn reconciliation_reads_and_writes_reject_wrong_role_without_leaking_path() {
        use axum::{
            body::{to_bytes, Body},
            http::Request,
        };
        use tower::ServiceExt;
        for method in ["GET", "POST"] {
            let response = app()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v1/actions/private-invalid-id/reconcile")
                        .header("authorization", format!("Bearer {}", "a".repeat(32)))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()[axum::http::header::CACHE_CONTROL],
                "private, no-store"
            );
            assert_eq!(
                response.headers()[axum::http::header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"error":{"code":"unauthorized"}})
            );
        }
    }

    #[tokio::test]
    async fn health_is_public_and_actions_require_known_tokens() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let health = app()
            .oneshot(
                Request::builder()
                    .uri("/health/live")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);
        for token in [None, Some("Bearer unknown")] {
            let mut builder =
                Request::builder().uri("/v1/actions/00000000-0000-0000-0000-000000000001");
            if let Some(token) = token {
                builder = builder.header("authorization", token);
            }
            let response = app()
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }
    #[tokio::test]
    async fn unknown_fields_and_missing_keys_rejected_before_database() {
        use axum::{body::Body, http::Request};
        use tower::ServiceExt;
        let payload = serde_json::json!({"type":"refund.create","connection_id":"00000000-0000-0000-0000-000000000301","resource":{"payment_id":"pay_1"},"parameters":{"amount_minor":2500,"currency":"USD"},"tenant_id":"injected"});
        for key in [None, Some("request-1")] {
            let mut builder = Request::builder()
                .method("POST")
                .uri("/v1/actions")
                .header("authorization", format!("Bearer {}", "a".repeat(32)))
                .header("content-type", "application/json");
            if let Some(key) = key {
                builder = builder.header("idempotency-key", key);
            }
            let response = app()
                .oneshot(builder.body(Body::from(payload.to_string())).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }
}
