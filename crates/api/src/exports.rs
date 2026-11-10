//! Scoped asynchronous evidence export API. GET never generates an artifact.
use super::{invalid_json, unauthorized, ApiError, AppState, Authenticator, ReviewerAuthenticator};
use apl_domain::Reviewer;
use apl_evidence::{EvidenceStore, ExportScope, MAX_PLAINTEXT_BYTES};
use apl_persistence::{exports::ExportInfo, Store, StoreError};
use axum::{
    extract::{rejection::JsonRejection, DefaultBodyLimit, Path, Request, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc};
use uuid::Uuid;

#[derive(Clone)]
struct ExportState {
    access: AppState,
    artifacts: Arc<EvidenceStore>,
}

/// Merge only when the encrypted evidence store is configured.
pub fn router(
    store: Store,
    artifacts: Arc<EvidenceStore>,
    workload_auth: Authenticator,
    reviewer_auth: ReviewerAuthenticator,
) -> Router {
    Router::new()
        .route("/v1/exports", post(request_export))
        .route("/v1/exports/{id}", get(export_info))
        .route("/v1/exports/{id}/download", get(download))
        // One thousand UUIDs require approximately 39 KiB in the JSON request.
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn(no_cache))
        .with_state(ExportState {
            access: AppState {
                store,
                auth: workload_auth,
                reviewer_auth: Some(reviewer_auth),
            },
            artifacts,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportInput {
    connection_id: Uuid,
    action_ids: Vec<Uuid>,
}

impl ExportInput {
    fn validate(&self) -> Result<(), ApiError> {
        if !(1..=1000).contains(&self.action_ids.len())
            || self
                .action_ids
                .iter()
                .copied()
                .collect::<HashSet<_>>()
                .len()
                != self.action_ids.len()
        {
            return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_request"));
        }
        Ok(())
    }
}

async fn reviewer(state: &ExportState, headers: &HeaderMap) -> Result<Reviewer, ApiError> {
    let identity = state.access.authenticate_reviewer(headers).await?;
    state
        .access
        .store
        .resolve_reviewer(&identity.issuer, &identity.subject)
        .await?
        .ok_or_else(unauthorized)
}

fn export_error(error: StoreError) -> ApiError {
    match error {
        StoreError::Conflict => ApiError(StatusCode::CONFLICT, "export_not_ready"),
        other => other.into(),
    }
}

fn export_id(value: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(value).map_err(|_| ApiError(StatusCode::NOT_FOUND, "not_found"))
}

async fn request_export(
    State(state): State<ExportState>,
    headers: HeaderMap,
    body: Result<Json<ExportInput>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    // Verify the role before reporting request validation errors, and resolve
    // database identity only once the bounded body is known to be valid.
    state.access.authenticate_reviewer(&headers).await?;
    let Json(input) = body.map_err(invalid_json)?;
    input.validate()?;
    let reviewer = reviewer(&state, &headers).await?;
    let export = state
        .access
        .store
        .request_export(&reviewer, input.connection_id, &input.action_ids)
        .await
        .map_err(export_error)?;
    Ok((StatusCode::ACCEPTED, Json(export)))
}

async fn export_info(
    State(state): State<ExportState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ExportInfo>, ApiError> {
    state.access.authenticate_reviewer(&headers).await?;
    let id = export_id(&id)?;
    let reviewer = reviewer(&state, &headers).await?;
    Ok(Json(
        state
            .access
            .store
            .export_info(&reviewer, id)
            .await
            .map_err(export_error)?,
    ))
}

async fn download(
    State(state): State<ExportState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    state.access.authenticate_reviewer(&headers).await?;
    let id = export_id(&id)?;
    let initial_reviewer = reviewer(&state, &headers).await?;
    let lease = state
        .access
        .store
        .download_export_lease(&initial_reviewer, id)
        .await
        .map_err(export_error)?;
    let bytes = state
        .artifacts
        .get(ExportScope {
            tenant_id: lease.tenant_id,
            environment_id: lease.environment_id,
            export_id: lease.id,
            generation: lease.generation,
        })
        .await
        .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "export_unavailable"))?;
    if bytes.len() > MAX_PLAINTEXT_BYTES {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "export_unavailable",
        ));
    }
    // Artifact I/O may take long enough for the token, mapping, grant, or export
    // lifetime to change. Recheck all of them before returning decrypted bytes.
    let fresh_reviewer = reviewer(&state, &headers).await?;
    let fresh_lease = state
        .access
        .store
        .download_export_lease(&fresh_reviewer, id)
        .await
        .map_err(export_error)?;
    if fresh_lease.id != lease.id
        || fresh_lease.tenant_id != lease.tenant_id
        || fresh_lease.environment_id != lease.environment_id
        || fresh_lease.connection_id != lease.connection_id
        || fresh_lease.requester_id != lease.requester_id
        || fresh_lease.generation != lease.generation
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "not_found"));
    }
    state
        .access
        .store
        .record_export_download(&fresh_reviewer, id)
        .await
        .map_err(export_error)?;
    // The final database transaction can itself wait on authorization/audit locks.
    // Recheck token expiry and managed key freshness after all awaited I/O.
    state.access.authenticate_reviewer(&headers).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/json"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"evidence-export.json\"",
            ),
        ],
        bytes,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LocalReviewerToken, TokenRegistry};
    use axum::{body::Body, http::Request};
    use serde_json::json;
    use std::{path::PathBuf, time::Duration};
    use tower::ServiceExt;

    const WORKLOAD: &str = "workload-a-test-token-0123456789abcdef";
    const REVIEWER: &str = "reviewer-a-test-token-0123456789abcdef";

    struct TestApp {
        router: Router,
        path: PathBuf,
    }
    impl TestApp {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("apl-api-export-{}", Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            let artifacts = EvidenceStore::local(&path, "test-key-v1", [7; 32]).unwrap();
            let workload = TokenRegistry::new(WORKLOAD.into(), "w".repeat(32)).unwrap();
            let reviewer = LocalReviewerToken::new(REVIEWER.into(), &workload).unwrap();
            let router = router(
                Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
                Arc::new(artifacts),
                Authenticator::Local(workload),
                ReviewerAuthenticator::Local(reviewer),
            );
            Self { router, path }
        }
        async fn request(&self, request: Request<Body>) -> Response {
            tokio::time::timeout(Duration::from_secs(2), self.router.clone().oneshot(request))
                .await
                .expect("invalid export request should not consult the database")
                .unwrap()
        }
    }
    impl Drop for TestApp {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
        }
    }

    #[tokio::test]
    async fn all_export_routes_reject_workload_credentials_and_disable_caching() {
        let app = TestApp::new();
        for (method, path) in [
            ("POST", "/v1/exports"),
            ("GET", "/v1/exports/00000000-0000-0000-0000-000000000001"),
            (
                "GET",
                "/v1/exports/00000000-0000-0000-0000-000000000001/download",
            ),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {WORKLOAD}"))
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let response = app.request(request).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "private, no-store"
            );
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
        }
    }

    #[tokio::test]
    async fn strict_export_input_is_bounded_before_database_resolution() {
        let app = TestApp::new();
        let connection = Uuid::new_v4();
        let action = Uuid::new_v4();
        for body in [
            json!({"connection_id":connection,"action_ids":[]}),
            json!({"connection_id":connection,"action_ids":[action,action]}),
            json!({"connection_id":connection,"action_ids":(0..1001).map(|_|Uuid::new_v4()).collect::<Vec<_>>()}),
            json!({"connection_id":connection,"action_ids":[action],"tenant_id":"injected"}),
        ] {
            let request = Request::post("/v1/exports")
                .header("authorization", format!("Bearer {REVIEWER}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            assert_eq!(app.request(request).await.status(), StatusCode::BAD_REQUEST);
        }
        let request = Request::post("/v1/exports")
            .header("authorization", format!("Bearer {REVIEWER}"))
            .header("content-type", "application/json")
            .body(Body::from(" ".repeat(64 * 1024 + 1)))
            .unwrap();
        assert_eq!(
            app.request(request).await.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }
}
