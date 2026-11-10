//! Read-only connection-scoped operational snapshots.
use super::{resolve_reviewer, ApiError, AppState, Authenticator, ReviewerAuthenticator};
use apl_persistence::{
    operations::OperationsSnapshot,
    operations_recovery::{RecoveryKind, RecoveryPage},
    Store,
};
use axum::{
    extract::{rejection::QueryRejection, Query, Request, State},
    http::{header, HeaderMap, HeaderValue},
    middleware::{self, Next},
    response::Response,
    routing::get,
    Json, Router,
};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationsQuery {
    connection_id: uuid::Uuid,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemsQuery {
    connection_id: uuid::Uuid,
    kind: RecoveryKind,
    after: Option<String>,
    limit: Option<u32>,
}

/// This read-only endpoint is independent of artifact storage configuration.
pub fn router(
    store: Store,
    workload_auth: Authenticator,
    reviewer_auth: ReviewerAuthenticator,
) -> Router {
    Router::new()
        .route("/v1/operations", get(snapshot))
        .route("/v1/operations/items", get(items))
        .layer(middleware::from_fn(no_cache))
        .with_state(AppState {
            store,
            auth: workload_auth,
            reviewer_auth: Some(reviewer_auth),
        })
}

async fn items(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<ItemsQuery>, QueryRejection>,
) -> Result<Json<RecoveryPage>, ApiError> {
    let identity = state.authenticate_reviewer(&headers).await?;
    let Query(filter) =
        query.map_err(|_| ApiError(axum::http::StatusCode::BAD_REQUEST, "invalid_request"))?;
    let limit = filter.limit.unwrap_or(50);
    if !(1..=100).contains(&limit)
        || filter
            .after
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 1024)
    {
        return Err(ApiError(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_request",
        ));
    }
    let reviewer = resolve_reviewer(&state, identity).await?;
    let page = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.store.operations_items(
            &reviewer,
            filter.connection_id,
            filter.kind,
            filter.after.as_deref(),
            limit,
        ),
    )
    .await
    .map_err(|_| ApiError(axum::http::StatusCode::SERVICE_UNAVAILABLE, "unavailable"))??;
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(page))
}

async fn no_cache(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn snapshot(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<OperationsQuery>, QueryRejection>,
) -> Result<Json<OperationsSnapshot>, ApiError> {
    // Role verification precedes validation details; typed query rejection must
    // not echo raw query strings or the framework's detailed parse errors.
    let identity = state.authenticate_reviewer(&headers).await?;
    let Query(filter) =
        query.map_err(|_| ApiError(axum::http::StatusCode::BAD_REQUEST, "invalid_request"))?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let page = state
        .store
        .operations_snapshot(&reviewer, filter.connection_id)
        .await?;
    // Database authorization may wait. Token expiry and managed-cache freshness
    // and browser session validity are checked again after snapshot I/O.
    state.authenticate_reviewer(&headers).await?;
    Ok(Json(page))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalReviewerToken, TokenRegistry};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use std::time::Duration;
    use tower::ServiceExt;

    const WORKLOAD: &str = "workload-a-test-token-0123456789abcdef";
    const REVIEWER: &str = "reviewer-a-test-token-0123456789abcdef";
    const CONNECTION: &str = "00000000-0000-0000-0000-000000000301";

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
            .expect("invalid operations request must not access the database")
            .unwrap()
    }

    #[tokio::test]
    async fn workload_cannot_query_operations_and_post_is_not_supported() {
        let uri = format!("/v1/operations?connection_id={CONNECTION}");
        let reply = response("GET", &uri, WORKLOAD).await;
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
        assert_eq!(reply.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let reply = response("POST", &uri, REVIEWER).await;
        assert_eq!(reply.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
    }

    #[tokio::test]
    async fn role_check_precedes_query_errors() {
        for token in [WORKLOAD, "unknown-token"] {
            let reply = response(
                "GET",
                "/v1/operations?connection_id=private-value&tenant_id=secret",
                token,
            )
            .await;
            assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"error":{"code":"unauthorized"}})
            );
        }
    }

    #[tokio::test]
    async fn recovery_filters_are_role_first_bounded_and_redacted() {
        let prefix = format!("/v1/operations/items?connection_id={CONNECTION}");
        for query in [
            "kind=dispatches&limit=0",
            "kind=ready_jobs&limit=101",
            "kind=invalid",
            "kind=dispatches&kind=ready_jobs",
            "kind=dispatches&tenant_id=private",
            "kind=dispatches&after=",
            "kind=dispatches&limit=-1",
        ] {
            let uri = format!("{prefix}&{query}");
            for (token, status) in [
                (WORKLOAD, StatusCode::UNAUTHORIZED),
                (REVIEWER, StatusCode::BAD_REQUEST),
            ] {
                let reply = response("GET", &uri, token).await;
                assert_eq!(reply.status(), status, "{query}");
                assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
                assert_eq!(reply.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
                let body = to_bytes(reply.into_body(), 1024).await.unwrap();
                let code = if status == StatusCode::UNAUTHORIZED {
                    "unauthorized"
                } else {
                    "invalid_request"
                };
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    json!({"error":{"code":code}})
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_unknown_and_duplicate_filters_return_generic_errors() {
        for query in [
            "connection_id=not-a-uuid".into(),
            format!("connection_id={CONNECTION}&tenant_id=sensitive-injected-value"),
            format!("connection_id={CONNECTION}&connection_id={CONNECTION}"),
            format!("connection_id={CONNECTION}&workload_id=bad"),
            format!("connection_id={CONNECTION}&status=unknown-status"),
            format!("connection_id={CONNECTION}&after=bad"),
            format!("connection_id={CONNECTION}&limit=101"),
            format!("connection_id={CONNECTION}&min_amount_minor=100&max_amount_minor=99"),
            String::new(),
        ] {
            let reply = response("GET", &format!("/v1/operations?{query}"), REVIEWER).await;
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{query}");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"error":{"code":"invalid_request"}})
            );
        }
    }
}
