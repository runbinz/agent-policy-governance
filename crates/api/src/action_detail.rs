//! Independently authorized reviewer detail; workload routes retain their authority.
use super::{resolve_reviewer, ApiError, AppState, Authenticator, ReviewerAuthenticator};
use apl_domain::action_detail::{ActionDetail, ActionHistoryPage, HistoryKind};
use apl_persistence::Store;
use axum::{
    extract::{
        rejection::{PathRejection, QueryRejection},
        Path, Query, Request, State,
    },
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DetailQuery {
    connection_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryQuery {
    connection_id: Uuid,
    kind: HistoryKind,
    after: Option<String>,
    limit: Option<usize>,
}

pub fn router(
    store: Store,
    workload_auth: Authenticator,
    reviewer_auth: ReviewerAuthenticator,
) -> Router {
    Router::new()
        .route("/v1/reviewer/actions/{id}", get(detail))
        .route("/v1/reviewer/actions/{id}/history", get(history))
        .layer(middleware::from_fn(no_cache))
        .with_state(AppState {
            store,
            auth: workload_auth,
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
fn bounded<T: Serialize>(value: T) -> Result<Json<T>, ApiError> {
    let bytes = serde_json::to_vec(&value)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"))?;
    if bytes.len() > 128 * 1024 {
        return Err(ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "result_too_large",
        ));
    }
    Ok(Json(value))
}

async fn detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<DetailQuery>, QueryRejection>,
) -> Result<Json<ActionDetail>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Path(raw_id) = path.map_err(|_| invalid())?;
    let id = Uuid::parse_str(&raw_id).map_err(|_| invalid())?;
    let Query(query) = query.map_err(|_| invalid())?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let value = tokio::time::timeout(
        Duration::from_secs(10),
        state
            .store
            .action_detail(&reviewer, query.connection_id, id),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    bounded(value)
}

async fn history(
    State(state): State<AppState>,
    headers: HeaderMap,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<HistoryQuery>, QueryRejection>,
) -> Result<Json<ActionHistoryPage>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Path(raw_id) = path.map_err(|_| invalid())?;
    let id = Uuid::parse_str(&raw_id).map_err(|_| invalid())?;
    let Query(query) = query.map_err(|_| invalid())?;
    let limit = query.limit.unwrap_or(50);
    if !(1..=100).contains(&limit) || query.after.as_ref().is_some_and(|v| v.len() > 1024) {
        return Err(invalid());
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let value = tokio::time::timeout(
        Duration::from_secs(10),
        state.store.action_history(
            &reviewer,
            query.connection_id,
            id,
            query.kind,
            query.after.as_deref(),
            limit,
        ),
    )
    .await
    .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    bounded(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalReviewerToken, TokenRegistry};
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    const WORKLOAD: &str = "workload-detail-test-token-0123456789abcdef";
    const REVIEWER: &str = "reviewer-detail-test-token-0123456789abcdef";
    const CONNECTION: &str = "00000000-0000-0000-0000-000000000301";
    const ACTION: &str = "00000000-0000-0000-0000-000000000401";

    fn app() -> Router {
        let workload = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
        let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workload).unwrap();
        router(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            Authenticator::Local(workload),
            ReviewerAuthenticator::Local(reviewer),
        )
    }
    async fn response(method: &str, uri: &str, token: &str) -> Response {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), app().oneshot(request))
            .await
            .expect("rejected request must not access database")
            .unwrap()
    }
    #[tokio::test]
    async fn workload_rejection_precedes_private_filter_and_path_validation() {
        for path in [
            format!("/v1/reviewer/actions/{ACTION}?connection_id={CONNECTION}"),
            "/v1/reviewer/actions/%FF?connection_id=private-filter".into(),
            format!("/v1/reviewer/actions/{ACTION}/history?kind=private-kind"),
        ] {
            let reply = response("GET", &path, WORKLOAD).await;
            assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
            assert_eq!(reply.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error":{"code":"unauthorized"}})
            );
        }
    }
    #[tokio::test]
    async fn malformed_filters_are_generic_and_mutations_unsupported() {
        let base = format!("/v1/reviewer/actions/{ACTION}");
        for path in [
            format!("{base}?connection_id=private-filter"),
            format!("{base}?connection_id={CONNECTION}&tenant_id=private-value"),
            format!("{base}?connection_id={CONNECTION}&connection_id={CONNECTION}"),
            format!("{base}/history?connection_id={CONNECTION}&kind=unknown"),
            format!("{base}/history?connection_id={CONNECTION}&kind=audit&limit=0"),
            format!("{base}/history?connection_id={CONNECTION}&kind=audit&limit=101"),
            format!(
                "{base}/history?connection_id={CONNECTION}&kind=audit&after={}",
                "a".repeat(1025)
            ),
            format!("/v1/reviewer/actions/%FF?connection_id={CONNECTION}"),
        ] {
            let reply = response("GET", &path, REVIEWER).await;
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({"error":{"code":"invalid_request"}})
            );
        }
        let reply = response(
            "POST",
            &format!("{base}?connection_id={CONNECTION}"),
            REVIEWER,
        )
        .await;
        assert_eq!(reply.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
    }
    #[test]
    fn response_limit_is_bytes_and_never_truncates() {
        assert!(bounded("a".repeat(128 * 1024 - 2)).is_ok());
        let error = bounded("é".repeat(64 * 1024)).unwrap_err();
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.1, "result_too_large");
    }
}
