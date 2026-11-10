//! Independent environment administration, without exposing identity tables.
use super::{
    invalid_json, resolve_reviewer, ApiError, AppState, Authenticator, ReviewerAuthenticator,
};
use apl_persistence::{environment_admin::*, Store};
use axum::{
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        Path, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::time::Duration;
use uuid::Uuid;
const MAX_REVISION: i64 = 9_007_199_254_740_991;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntityQuery {
    kind: EntityKind,
    after: Option<Uuid>,
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantQuery {
    kind: GrantKind,
    after: Option<String>,
    limit: Option<usize>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnabledInput {
    expected_revision: i64,
    enabled: bool,
}
pub fn router(store: Store, auth: Authenticator, reviewer_auth: ReviewerAuthenticator) -> Router {
    Router::new()
        .route("/v1/admin/entities", get(entities))
        .route("/v1/admin/grants", get(grants))
        .route("/v1/admin/entities/{kind}/{id}/enabled", post(set_enabled))
        .route("/v1/admin/grants/revoke", post(revoke))
        .layer(middleware::from_fn(no_cache))
        .with_state(AppState {
            store,
            auth,
            reviewer_auth: Some(reviewer_auth),
        })
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
fn invalid() -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, "invalid_request")
}
fn deadline() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
}
fn mutation_error(error: apl_persistence::StoreError) -> ApiError {
    match error {
        apl_persistence::StoreError::Conflict => ApiError(StatusCode::CONFLICT, "admin_conflict"),
        other => ApiError::from(other),
    }
}
fn limit(value: Option<usize>) -> Result<usize, ApiError> {
    let n = value.unwrap_or(50);
    if (1..=100).contains(&n) {
        Ok(n)
    } else {
        Err(invalid())
    }
}
async fn entities(
    State(s): State<AppState>,
    h: HeaderMap,
    q: Result<Query<EntityQuery>, QueryRejection>,
) -> Result<Json<AdminEntityPage>, ApiError> {
    let identity = s.authenticate_reviewer(&h).await?;
    let Query(q) = q.map_err(|_| invalid())?;
    let n = limit(q.limit)?;
    let r = resolve_reviewer(&s, identity).await?;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        s.store.admin_entities(&r, q.kind, q.after, n),
    )
    .await
    .map_err(|_| deadline())??;
    s.authenticate_reviewer(&h).await?;
    Ok(Json(result))
}
async fn grants(
    State(s): State<AppState>,
    h: HeaderMap,
    q: Result<Query<GrantQuery>, QueryRejection>,
) -> Result<Json<AdminGrantPage>, ApiError> {
    let identity = s.authenticate_reviewer(&h).await?;
    let Query(q) = q.map_err(|_| invalid())?;
    let n = limit(q.limit)?;
    if q.after.as_ref().is_some_and(|v| v.len() > 1024) {
        return Err(invalid());
    }
    let r = resolve_reviewer(&s, identity).await?;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        s.store.admin_grants(&r, q.kind, q.after.as_deref(), n),
    )
    .await
    .map_err(|_| deadline())??;
    s.authenticate_reviewer(&h).await?;
    Ok(Json(result))
}
async fn set_enabled(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<(EntityKind, Uuid)>, PathRejection>,
    body: Result<Json<EnabledInput>, JsonRejection>,
) -> Result<Json<RevisionResult>, ApiError> {
    let identity = s.authenticate_reviewer(&h).await?;
    let Path((kind, id)) = path.map_err(|_| invalid())?;
    let Json(body) = body.map_err(invalid_json)?;
    if !(1..MAX_REVISION).contains(&body.expected_revision) {
        return Err(invalid());
    }
    let r = resolve_reviewer(&s, identity).await?;
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        s.store
            .admin_set_enabled(&r, kind, id, body.expected_revision, body.enabled),
    )
    .await
    .map_err(|_| deadline())?
    .map_err(mutation_error)?;
    s.authenticate_reviewer(&h).await?;
    Ok(Json(result))
}
async fn revoke(
    State(s): State<AppState>,
    h: HeaderMap,
    body: Result<Json<RevokeInput>, JsonRejection>,
) -> Result<Json<RevisionResult>, ApiError> {
    let identity = s.authenticate_reviewer(&h).await?;
    let Json(body) = body.map_err(invalid_json)?;
    body.validate().map_err(|_| invalid())?;
    let r = resolve_reviewer(&s, identity).await?;
    let result = tokio::time::timeout(Duration::from_secs(10), s.store.admin_revoke(&r, &body))
        .await
        .map_err(|_| deadline())?
        .map_err(mutation_error)?;
    s.authenticate_reviewer(&h).await?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalReviewerToken, TokenRegistry};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use serde_json::{json, Value};
    use tower::ServiceExt;
    const WORKLOAD: &str = "workload-environment-test-0123456789abcdef";
    const REVIEWER: &str = "reviewer-environment-test-0123456789abcdef";
    async fn request(method: &str, path: &str, token: &str, body: Value) -> Response {
        let workloads = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
        let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workloads).unwrap();
        let app = router(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            Authenticator::Local(workloads),
            ReviewerAuthenticator::Local(reviewer),
        );
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), app.oneshot(req))
            .await
            .expect("rejected input must not access database")
            .unwrap()
    }
    #[tokio::test]
    async fn role_rejection_precedes_query_path_and_body_details() {
        for (method, path, body) in [
            (
                "GET",
                "/v1/admin/entities?kind=private&tenant_id=private",
                json!(null),
            ),
            ("GET", "/v1/admin/grants?kind=unknown", json!(null)),
            (
                "POST",
                "/v1/admin/entities/private/%FF/enabled",
                json!({"secret":"must-not-echo"}),
            ),
            (
                "POST",
                "/v1/admin/grants/revoke",
                json!({"kind":"unknown","secret":"must-not-echo"}),
            ),
        ] {
            let reply = request(method, path, WORKLOAD, body).await;
            assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
            assert_eq!(reply.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error":{"code":"unauthorized"}})
            );
        }
    }
    #[tokio::test]
    async fn malformed_inventory_and_mutation_inputs_are_generic() {
        for (method, path, body) in [
            ("GET", "/v1/admin/entities?kind=unknown", json!(null)),
            (
                "GET",
                "/v1/admin/entities?kind=connections&limit=101",
                json!(null),
            ),
            (
                "GET",
                "/v1/admin/entities?kind=connections&kind=workloads",
                json!(null),
            ),
            (
                "GET",
                "/v1/admin/grants?kind=workload&tenant_id=private",
                json!(null),
            ),
            (
                "POST",
                "/v1/admin/entities/workloads/00000000-0000-0000-0000-000000000201/enabled",
                json!({"enabled":false,"expected_revision":0}),
            ),
            (
                "POST",
                "/v1/admin/grants/revoke",
                json!({"kind":"workload","expected_revision":1}),
            ),
            (
                "POST",
                "/v1/admin/grants/revoke",
                json!({"kind":"approval","expected_revision":1,"reviewer_id":"00000000-0000-0000-0000-000000000401","connection_id":"00000000-0000-0000-0000-000000000301","injected":"private"}),
            ),
        ] {
            let reply = request(method, path, REVIEWER, body).await;
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(&body).unwrap(),
                json!({"error":{"code":"invalid_request"}})
            );
        }
    }
}
