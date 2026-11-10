//! Redacted, connection-scoped evidence search for explicitly granted reviewers.
use super::{resolve_reviewer, ApiError, AppState, Authenticator, ReviewerAuthenticator};
use apl_persistence::{
    evidence::{EvidenceFilter, EvidencePage},
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

/// This read-only endpoint is independent of artifact storage configuration.
pub fn router(
    store: Store,
    workload_auth: Authenticator,
    reviewer_auth: ReviewerAuthenticator,
) -> Router {
    Router::new()
        .route("/v1/evidence", get(search))
        .layer(middleware::from_fn(no_cache))
        .with_state(AppState {
            store,
            auth: workload_auth,
            reviewer_auth: Some(reviewer_auth),
        })
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

async fn search(
    State(state): State<AppState>,
    headers: HeaderMap,
    query: Result<Query<EvidenceFilter>, QueryRejection>,
) -> Result<Json<EvidencePage>, ApiError> {
    // Role verification precedes validation details; typed query rejection must
    // not echo raw query strings or the framework's detailed parse errors.
    let identity = state.authenticate_reviewer(&headers).await?;
    let Query(filter) =
        query.map_err(|_| ApiError(axum::http::StatusCode::BAD_REQUEST, "invalid_request"))?;
    filter.validate()?;
    let reviewer = resolve_reviewer(&state, identity).await?;
    let page = state.store.search_evidence(&reviewer, &filter).await?;
    // Database authorization may wait. Token expiry and managed-cache freshness
    // are checked again synchronously after all awaited I/O.
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
            .expect("invalid evidence search must not access the database")
            .unwrap()
    }

    #[tokio::test]
    async fn workload_cannot_query_evidence_and_post_is_not_supported() {
        let uri = format!("/v1/evidence?connection_id={CONNECTION}");
        let reply = response("GET", &uri, WORKLOAD).await;
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
        assert_eq!(reply.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let reply = response("POST", &uri, REVIEWER).await;
        assert_eq!(reply.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(reply.headers()[header::CACHE_CONTROL], "private, no-store");
    }

    #[tokio::test]
    async fn malformed_unknown_and_out_of_range_filters_return_generic_errors() {
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
            let reply = response("GET", &format!("/v1/evidence?{query}"), REVIEWER).await;
            assert_eq!(reply.status(), StatusCode::BAD_REQUEST, "{query}");
            let body = to_bytes(reply.into_body(), 1024).await.unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"error":{"code":"invalid_request"}})
            );
        }
    }
}
