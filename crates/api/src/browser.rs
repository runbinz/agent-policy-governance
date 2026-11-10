//! Same-origin managed login, opaque shared sessions and browser CSRF boundary.
use crate::{unauthorized, ApiError};
use apl_identity::{
    browser::{credential_hash, new_secret, pkce_challenge, BrowserOidc, BrowserSecrets},
    VerifiedIdentity,
};
use apl_persistence::{browser::BrowserSession, Store, StoreError};
use axum::{
    extract::{rejection::QueryRejection, Query, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use url::Url;
use zeroize::Zeroizing;

const SESSION: &str = "__Host-apl_session";
const BINDING: &str = "__Host-apl_login";

pub struct BrowserAuth {
    store: Store,
    provider: Provider,
    secrets: BrowserSecrets,
    origin: String,
    authority: String,
}
#[derive(Clone)]
enum Provider {
    Oidc(BrowserOidc),
    #[cfg(test)]
    Fixture(Arc<test_support::FixtureProvider>),
}
impl Provider {
    fn issuer(&self) -> &str {
        match self {
            Self::Oidc(p) => p.issuer(),
            #[cfg(test)]
            Self::Fixture(p) => &p.issuer,
        }
    }
    fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> Result<String, ApiError> {
        match self {
            Self::Oidc(p) => p
                .authorization_url(state, nonce, challenge)
                .map_err(|_| unauthorized()),
            #[cfg(test)]
            Self::Fixture(p) => p.authorization_url(state, nonce, challenge),
        }
    }
    async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, ApiError> {
        match self {
            Self::Oidc(p) => p
                .exchange_code(code, verifier, nonce)
                .await
                .map_err(|_| unauthorized()),
            #[cfg(test)]
            Self::Fixture(p) => p.exchange(code, verifier, nonce),
        }
    }
}

impl BrowserAuth {
    pub fn validate_origin(origin: &str) -> Result<(), &'static str> {
        canonical_origin(origin).map(|_| ())
    }
    pub fn new(
        store: Store,
        provider: BrowserOidc,
        origin: &str,
        key: [u8; 32],
    ) -> Result<Arc<Self>, &'static str> {
        let (origin, authority) = canonical_origin(origin)?;
        if provider.redirect_uri() != format!("{origin}/auth/callback") {
            return Err("browser callback must match public origin");
        }
        Ok(Arc::new(Self {
            store,
            provider: Provider::Oidc(provider),
            secrets: BrowserSecrets::new(key),
            origin,
            authority,
        }))
    }
    /// Wrap the complete API, including separately merged reviewer routes.
    /// This prevents new cookie-authenticated mutations from omitting CSRF.
    pub fn protect(self: &Arc<Self>, router: Router) -> Router {
        router
            .merge(
                Router::new()
                    .route(
                        "/auth/config",
                        get(|| async {
                            Json(json!({"managed_login":true,"development_tokens":false}))
                        }),
                    )
                    .route("/auth/login", post(start_login))
                    .route("/auth/callback", get(callback))
                    .route("/auth/session", get(session_info))
                    .route("/auth/logout", post(logout))
                    .with_state(self.clone()),
            )
            .layer(middleware::from_fn_with_state(self.clone(), boundary))
    }
    fn host(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        if headers.get_all(header::HOST).iter().count() != 1
            || headers.get(header::HOST).and_then(|h| h.to_str().ok())
                != Some(self.authority.as_str())
        {
            return Err(forbidden());
        }
        Ok(())
    }
    fn origin(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        self.host(headers)?;
        if headers.get_all(header::ORIGIN).iter().count() != 1
            || headers.get(header::ORIGIN).and_then(|h| h.to_str().ok())
                != Some(self.origin.as_str())
            || headers
                .get("sec-fetch-site")
                .is_some_and(|h| h != "same-origin")
        {
            return Err(forbidden());
        }
        Ok(())
    }
    async fn session(
        &self,
        headers: &HeaderMap,
    ) -> Result<(BrowserSession, Zeroizing<String>), ApiError> {
        self.host(headers)?;
        if headers.contains_key(header::AUTHORIZATION) {
            return Err(unauthorized());
        }
        let token = Zeroizing::new(session_cookie(headers)?.ok_or_else(unauthorized)?);
        credential(&token)?;
        let session = self
            .store
            .read_browser_session(&credential_hash(&token))
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unauthorized)?;
        // A key rotation fails closed for prior sessions. Store expiry is
        // checked again after all awaited database work.
        let csrf = self.secrets.csrf(&token).map_err(|_| unauthorized())?;
        if session.expires_at_unix <= now()?
            || !bool::from(session.csrf_hash.as_slice().ct_eq(&credential_hash(&csrf)))
        {
            return Err(unauthorized());
        }
        Ok((session, token))
    }
    pub(crate) async fn authenticate(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedIdentity, ApiError> {
        let (session, _) = self.session(headers).await?;
        Ok(VerifiedIdentity {
            issuer: session.issuer,
            subject: session.subject,
        })
    }
    async fn csrf(&self, headers: &HeaderMap) -> Result<(), ApiError> {
        self.origin(headers)?;
        let (session, _) = self.session(headers).await?;
        let csrf = single_header(headers, "x-csrf-token").ok_or_else(forbidden)?;
        credential(csrf).map_err(|_| forbidden())?;
        if !bool::from(session.csrf_hash.as_slice().ct_eq(&credential_hash(csrf))) {
            return Err(forbidden());
        }
        Ok(())
    }
}

pub fn disabled_router(development_tokens: bool) -> Router {
    Router::new().route(
        "/auth/config",
        get(move || async move {
            Json(json!({"managed_login":false,"development_tokens":development_tokens}))
        }),
    )
}

async fn boundary(State(auth): State<Arc<BrowserAuth>>, request: Request, next: Next) -> Response {
    let headers = request.headers().clone();
    let auth_path = request.uri().path().starts_with("/auth/");
    let login_path = request.uri().path() == "/auth/login";
    let callback_wrong_method =
        request.uri().path() == "/auth/callback" && request.method() != Method::GET;
    let mutation = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    let check = async {
        if callback_wrong_method {
            return Err(ApiError(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
            ));
        }
        if auth_path {
            auth.host(&headers)?;
        }
        if session_cookie(&headers)?.is_some() {
            if headers.contains_key(header::AUTHORIZATION) {
                return Err(unauthorized());
            }
            auth.host(&headers)?;
            if mutation && !login_path {
                auth.csrf(&headers).await?;
            }
        }
        Ok::<(), ApiError>(())
    }
    .await;
    let mut response = match check {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    };
    let headers = response.headers_mut();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

async fn start_login(
    State(auth): State<Arc<BrowserAuth>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    auth.origin(&headers)?;
    let state = new_secret().map_err(|_| unavailable())?;
    let binding = new_secret().map_err(|_| unavailable())?;
    let verifier = auth.secrets.verifier(&state).map_err(|_| unavailable())?;
    let nonce = auth.secrets.nonce(&state).map_err(|_| unavailable())?;
    let challenge = pkce_challenge(&verifier).map_err(|_| unavailable())?;
    let location = auth
        .provider
        .authorization_url(&state, &nonce, &challenge)?;
    auth.store
        .start_browser_login(&credential_hash(&state), &credential_hash(&binding))
        .await
        .map_err(login_store_error)?;
    let mut response = Redirect::to(&location).into_response();
    cookie(&mut response, BINDING, &binding, 300)?;
    Ok(response)
}

#[derive(Deserialize)]
struct Callback {
    state: String,
    code: Option<String>,
    error: Option<String>,
    iss: Option<String>,
}
async fn callback(
    State(auth): State<Arc<BrowserAuth>>,
    headers: HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Response {
    let result = finish_callback(&auth, &headers, query).await;
    let mut response = match result {
        Ok(response) => response,
        Err(error) => error.into_response(),
    };
    // A failed callback never retains a stale browser binding.
    let _ = cookie(&mut response, BINDING, "", 0);
    response
}
async fn finish_callback(
    auth: &BrowserAuth,
    headers: &HeaderMap,
    query: Result<Query<Callback>, QueryRejection>,
) -> Result<Response, ApiError> {
    auth.host(headers)?;
    let Query(query) = query.map_err(|_| unauthorized())?;
    credential(&query.state)?;
    let binding = Zeroizing::new(read_cookie(headers, BINDING)?.ok_or_else(unauthorized)?);
    credential(&binding)?;
    if query
        .iss
        .as_ref()
        .is_some_and(|s| s != auth.provider.issuer())
    {
        return Err(unauthorized());
    }
    if !auth
        .store
        .consume_browser_login(&credential_hash(&query.state), &credential_hash(&binding))
        .await
        .map_err(|_| unavailable())?
    {
        return Err(unauthorized());
    }
    if query.error.is_some() {
        return Err(unauthorized());
    }
    let code = Zeroizing::new(query.code.ok_or_else(unauthorized)?);
    let verifier = auth
        .secrets
        .verifier(&query.state)
        .map_err(|_| unauthorized())?;
    let nonce = auth
        .secrets
        .nonce(&query.state)
        .map_err(|_| unauthorized())?;
    let identity = auth.provider.exchange(&code, &verifier, &nonce).await?;
    let session = new_secret().map_err(|_| unavailable())?;
    let csrf = auth.secrets.csrf(&session).map_err(|_| unavailable())?;
    auth.store
        .create_browser_session(
            &credential_hash(&session),
            &credential_hash(&csrf),
            &identity.issuer,
            &identity.subject,
        )
        .await
        .map_err(login_store_error)?;
    // Replace, rather than retain, the previous browser's session on re-login.
    if let Some(old) = session_cookie(headers)? {
        if let Ok(old_csrf) = auth.secrets.csrf(&old) {
            auth.store
                .revoke_browser_session(&credential_hash(&old), &credential_hash(&old_csrf))
                .await
                .map_err(|_| unavailable())?;
        }
    }
    let mut response = Redirect::to("/").into_response();
    cookie(&mut response, SESSION, &session, 3600)?;
    Ok(response)
}
async fn session_info(State(auth): State<Arc<BrowserAuth>>, headers: HeaderMap) -> Response {
    match auth.session(&headers).await {
        Ok((session, token)) => {
            let csrf = auth
                .secrets
                .csrf(&token)
                .expect("validated session credential");
            Json(json!({"authenticated":true,"csrf_token":csrf.as_str(),"expires_at":session.expires_at_unix})).into_response()
        }
        Err(error) => {
            let clear = error.0 == StatusCode::UNAUTHORIZED;
            let mut response = error.into_response();
            if clear {
                let _ = cookie(&mut response, SESSION, "", 0);
            }
            response
        }
    }
}
async fn logout(
    State(auth): State<Arc<BrowserAuth>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    // Check here as well as in the outer boundary: this handler never depends
    // on a caller remembering to apply a layer to its mutation.
    auth.csrf(&headers).await?;
    let token = Zeroizing::new(session_cookie(&headers)?.ok_or_else(unauthorized)?);
    let csrf = single_header(&headers, "x-csrf-token").ok_or_else(forbidden)?;
    if !auth
        .store
        .revoke_browser_session(&credential_hash(&token), &credential_hash(csrf))
        .await
        .map_err(|_| unavailable())?
    {
        return Err(unauthorized());
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    cookie(&mut response, SESSION, "", 0)?;
    cookie(&mut response, BINDING, "", 0)?;
    Ok(response)
}

pub(crate) fn session_cookie(headers: &HeaderMap) -> Result<Option<String>, ApiError> {
    read_cookie(headers, SESSION)
}
fn read_cookie(headers: &HeaderMap, name: &str) -> Result<Option<String>, ApiError> {
    let mut found = None;
    let mut bytes = 0;
    for header in headers.get_all(header::COOKIE) {
        bytes += header.len();
        if bytes > 8192 {
            return Err(unauthorized());
        }
        let header = header.to_str().map_err(|_| unauthorized())?;
        for pair in header.split(';') {
            if let Some((key, value)) = pair.trim().split_once('=') {
                if key == name {
                    if found.is_some() {
                        return Err(unauthorized());
                    }
                    found = Some(value.to_owned());
                }
            }
        }
    }
    Ok(found)
}
fn cookie(response: &mut Response, name: &str, value: &str, seconds: u32) -> Result<(), ApiError> {
    let value =
        format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}");
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).map_err(|_| unavailable())?,
    );
    Ok(())
}
fn credential(value: &str) -> Result<(), ApiError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(unauthorized());
    }
    Ok(())
}
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    if headers.get_all(name).iter().count() != 1 {
        return None;
    }
    headers.get(name)?.to_str().ok()
}
fn canonical_origin(value: &str) -> Result<(String, String), &'static str> {
    let invalid =
        "browser public origin must be canonical HTTPS without credentials, query or path";
    let url = Url::parse(value).map_err(|_| invalid)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.origin().ascii_serialization() != value
    {
        return Err(invalid);
    }
    Ok((
        value.into(),
        url[url::Position::BeforeHost..url::Position::AfterPort].into(),
    ))
}
fn now() -> Result<i64, ApiError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unauthorized())?
        .as_secs() as i64)
}
fn forbidden() -> ApiError {
    ApiError(StatusCode::FORBIDDEN, "invalid_csrf_or_origin")
}
fn unavailable() -> ApiError {
    ApiError(StatusCode::SERVICE_UNAVAILABLE, "login_unavailable")
}
fn login_store_error(error: StoreError) -> ApiError {
    match &error {
        StoreError::Database(e)
            if e.as_database_error().and_then(|e| e.code()).as_deref() == Some("AP401") =>
        {
            unauthorized()
        }
        StoreError::Database(e)
            if e.as_database_error().and_then(|e| e.code()).as_deref() == Some("AP429") =>
        {
            ApiError(StatusCode::TOO_MANY_REQUESTS, "login_capacity")
        }
        _ => unavailable(),
    }
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::{router_with_reviewers, Authenticator, ReviewerAuthenticator, TokenRegistry};
    use apl_identity::JwtVerifier;
    use axum::body::{to_bytes, Body};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use sqlx::{postgres::PgPoolOptions, PgPool};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    const ORIGIN: &str = "https://console.example.test";
    const HOST: &str = "console.example.test";
    pub(super) struct FixtureProvider {
        pub issuer: String,
        subject: String,
        expected: Mutex<Option<(String, String)>>,
        exchanges: AtomicUsize,
    }
    impl FixtureProvider {
        pub fn authorization_url(
            &self,
            state: &str,
            nonce: &str,
            challenge: &str,
        ) -> Result<String, ApiError> {
            *self.expected.lock().unwrap() = Some((challenge.into(), nonce.into()));
            let mut url = Url::parse(&format!("{}/authorize", self.issuer)).unwrap();
            url.query_pairs_mut().extend_pairs([
                ("state", state),
                ("nonce", nonce),
                ("code_challenge", challenge),
            ]);
            Ok(url.into())
        }
        pub fn exchange(
            &self,
            code: &str,
            verifier: &str,
            nonce: &str,
        ) -> Result<VerifiedIdentity, ApiError> {
            self.exchanges.fetch_add(1, Ordering::SeqCst);
            let expected = self
                .expected
                .lock()
                .unwrap()
                .clone()
                .ok_or_else(unauthorized)?;
            if code != "synthetic-code"
                || pkce_challenge(verifier).map_err(|_| unauthorized())? != expected.0
                || nonce != expected.1
            {
                return Err(unauthorized());
            }
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("test-1".into());
            let now = now().unwrap();
            let token=encode(&header,&json!({"iss":self.issuer,"sub":self.subject,"aud":"browser-client","iat":now,"exp":now+300,"nonce":expected.1}),
                &EncodingKey::from_rsa_pem(include_bytes!("../../identity/tests/fixtures/test-only-private.pem")).unwrap()).unwrap();
            JwtVerifier::from_jwks(
                &self.issuer,
                "browser-client",
                include_str!("../../identity/tests/fixtures/jwks.json"),
            )
            .unwrap()
            .verify_id_token(&token, "browser-client", nonce)
            .map_err(|_| unauthorized())
        }
    }

    fn fixture(
        store: Store,
        subject: String,
        provider: Option<Arc<FixtureProvider>>,
    ) -> Arc<BrowserAuth> {
        Arc::new(BrowserAuth {
            store,
            provider: Provider::Fixture(provider.unwrap_or_else(|| {
                Arc::new(FixtureProvider {
                    issuer: "https://identity.example.test".into(),
                    subject,
                    expected: Mutex::new(None),
                    exchanges: AtomicUsize::new(0),
                })
            })),
            secrets: BrowserSecrets::new([7; 32]),
            origin: ORIGIN.into(),
            authority: HOST.into(),
        })
    }
    fn app(auth: Arc<BrowserAuth>, artifacts: Option<Arc<apl_evidence::EvidenceStore>>) -> Router {
        let workload =
            Authenticator::Local(TokenRegistry::new("a".repeat(32), "b".repeat(32)).unwrap());
        let reviewer = ReviewerAuthenticator::Browser {
            bearer: None,
            sessions: auth.clone(),
        };
        let mut router =
            router_with_reviewers(auth.store.clone(), workload.clone(), Some(reviewer.clone()));
        if let Some(artifacts) = artifacts {
            router = router.merge(crate::exports::router(
                auth.store.clone(),
                artifacts,
                workload,
                reviewer,
            ));
        }
        auth.protect(router)
    }
    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<serde_json::Value>,
    ) -> Response {
        let mut request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::HOST, HOST);
        for (key, value) in headers {
            request = request.header(*key, *value);
        }
        let body = if let Some(body) = body {
            request = request.header(header::CONTENT_TYPE, "application/json");
            Body::from(body.to_string())
        } else {
            Body::empty()
        };
        app.clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
    }
    async fn json_body(response: Response) -> serde_json::Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 65536).await.unwrap()).unwrap()
    }
    fn returned_cookie(response: &Response, name: &str) -> String {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .find_map(|value| {
                let value = value.to_str().unwrap();
                value.starts_with(&format!("{name}=")).then(|| {
                    assert!(value.contains("; Secure; HttpOnly; SameSite=Lax;"));
                    assert!(value.contains("; Path=/;"));
                    assert!(!value.contains("Domain="));
                    value.split(';').next().unwrap().to_string()
                })
            })
            .unwrap()
    }
    async fn login(app: &Router) -> (String, String) {
        let response = call(app, "POST", "/auth/login", &[("origin", ORIGIN)], None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        let binding = returned_cookie(&response, BINDING);
        let location = Url::parse(response.headers()[header::LOCATION].to_str().unwrap()).unwrap();
        let state = location
            .query_pairs()
            .find(|(k, _)| k == "state")
            .unwrap()
            .1
            .into_owned();
        (state, binding)
    }

    #[tokio::test]
    async fn browser_boundary_rejects_cross_origin_and_ambiguous_credentials_without_db() {
        let auth = fixture(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            "fixture".into(),
            None,
        );
        let app = app(auth, None);
        assert_eq!(
            call(&app, "GET", "/auth/login", &[], None).await.status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        for headers in [
            vec![],
            vec![("origin", "https://evil.example.test")],
            vec![("origin", ORIGIN), ("host", "evil.example.test")],
        ] {
            assert_eq!(
                call(&app, "POST", "/auth/login", &headers, None)
                    .await
                    .status(),
                StatusCode::FORBIDDEN
            );
        }
        let cookie = format!("{SESSION}={}", "s".repeat(43));
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/exports",
                &[("cookie", &cookie), ("origin", "https://evil.example.test")],
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app,
                "GET",
                "/v1/approvals",
                &[("cookie", &cookie), ("authorization", "Bearer a")],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let duplicate = format!("{cookie}; {cookie}");
        assert_eq!(
            call(
                &app,
                "GET",
                "/auth/session",
                &[("cookie", &duplicate)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let config = call(&app, "GET", "/auth/config", &[], None).await;
        assert_eq!(config.headers()[header::CACHE_CONTROL], "private, no-store");
        assert_eq!(
            json_body(config).await,
            json!({"managed_login":true,"development_tokens":false})
        );
        for value in [
            "http://console.example.test",
            "https://console.example.test/",
            "https://console.example.test/path",
            "https://user@console.example.test",
        ] {
            assert!(canonical_origin(value).is_err());
        }
    }

    #[tokio::test]
    #[ignore = "requires dedicated TEST_DATABASE_URL with database administration"]
    async fn signed_browser_flow_shared_replicas_csrf_revocation_and_logout() {
        let url = std::env::var("TEST_DATABASE_URL").unwrap();
        let admin = PgPool::connect(&url).await.unwrap();
        Store::from_pool(admin.clone()).migrate().await.unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
            .execute(&admin)
            .await
            .unwrap();
        let t = Uuid::new_v4();
        let e = Uuid::new_v4();
        let r = Uuid::new_v4();
        let subject = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO tenants(tenant_id) VALUES($1)")
            .bind(t)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO environments(tenant_id,environment_id) VALUES($1,$2)")
            .bind(t)
            .bind(e)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
            .bind(t)
            .bind(e)
            .bind(r)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO reviewer_registry VALUES('https://identity.example.test',$1,$2,$3,$4)",
        )
        .bind(&subject)
        .bind(t)
        .bind(e)
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
        async fn store(url: &str) -> Store {
            Store::from_pool(
                PgPoolOptions::new()
                    .after_connect(|c, _| {
                        Box::pin(async move {
                            sqlx::query("SET ROLE apl_api").execute(c).await?;
                            Ok(())
                        })
                    })
                    .connect(url)
                    .await
                    .unwrap(),
            )
        }
        let api = store(&url).await;
        let auth = fixture(api.clone(), subject.clone(), None);
        let Provider::Fixture(provider) = &auth.provider else {
            unreachable!()
        };
        let provider = provider.clone();
        let second = fixture(store(&url).await, subject, Some(provider.clone()));
        let root = std::env::temp_dir().join(format!("apl-browser-{}", Uuid::new_v4()));
        std::fs::create_dir(&root).unwrap();
        let artifacts =
            Arc::new(apl_evidence::EvidenceStore::local(&root, "test-key", [7; 32]).unwrap());
        let app_a = app(auth, Some(artifacts.clone()));
        let app_b = app(second, Some(artifacts));
        let (state, binding) = login(&app_a).await;
        let callback = format!("/auth/callback?state={state}&code=synthetic-code");
        assert_eq!(
            call(&app_b, "HEAD", &callback, &[("cookie", &binding)], None)
                .await
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let wrong = format!("{BINDING}={}", "x".repeat(43));
        assert_eq!(
            call(&app_b, "GET", &callback, &[("cookie", &wrong)], None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(provider.exchanges.load(Ordering::SeqCst), 0);
        let response = call(&app_b, "GET", &callback, &[("cookie", &binding)], None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers()[header::LOCATION], "/");
        let session = returned_cookie(&response, SESSION);
        assert!(returned_cookie(&response, BINDING).ends_with('='));
        assert_eq!(
            call(&app_a, "GET", &callback, &[("cookie", &binding)], None)
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
        let info = json_body(
            call(
                &app_a,
                "GET",
                "/auth/session",
                &[("cookie", &session)],
                None,
            )
            .await,
        )
        .await;
        assert_eq!(info["authenticated"], true);
        let csrf = info["csrf_token"].as_str().unwrap();
        assert!(!info.to_string().contains(&session));
        // Positive monetary workflow still uses the exact existing approval,
        // digest and worker path. This is only the atomic fake provider.
        let c = Uuid::new_v4();
        let w = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)",
        )
        .bind(t)
        .bind(e)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
        sqlx::query("INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES($1,$2,$3)")
            .bind(t)
            .bind(e)
            .bind(w)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id,enabled,submit_refund,read_action,read_events,cancel_action) VALUES($1,$2,$3,$4,true,true,true,true,true)").bind(t).bind(e).bind(w).bind(c).execute(&admin).await.unwrap();
        sqlx::query("INSERT INTO reviewer_grants VALUES($1,$2,$3,$4,true)")
            .bind(t)
            .bind(e)
            .bind(r)
            .bind(c)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO policy_versions(tenant_id,environment_id,connection_id,version,auto_limit_minor,hard_limit_minor,approval_ttl_seconds) VALUES($1,$2,$3,1,5000,50000,300)").bind(t).bind(e).bind(c).execute(&admin).await.unwrap();
        sqlx::query("INSERT INTO policy_bindings VALUES($1,$2,$3,1)")
            .bind(t)
            .bind(e)
            .bind(c)
            .execute(&admin)
            .await
            .unwrap();
        sqlx::query("INSERT INTO budget_connections(tenant_id,environment_id,connection_id,daily_limit_minor,exposure_limit_minor) VALUES($1,$2,$3,100000,100000)").bind(t).bind(e).bind(c).execute(&admin).await.unwrap();
        let principal = apl_domain::Principal {
            tenant_id: t,
            environment_id: e,
            workload_id: w,
            connection_id: c,
        };
        let request:apl_domain::RefundRequest=serde_json::from_value(json!({"type":"refund.create","connection_id":c,"resource":{"payment_id":"synthetic_browser_payment"},"parameters":{"amount_minor":6000,"currency":"USD"},"metadata":{}})).unwrap();
        let action = api
            .submit(&principal, &Uuid::new_v4().to_string(), &request)
            .await
            .unwrap();
        let worker = Store::from_pool(
            PgPoolOptions::new()
                .after_connect(|c, _| {
                    Box::pin(async move {
                        sqlx::query("SET ROLE apl_worker").execute(c).await?;
                        Ok(())
                    })
                })
                .connect(&url)
                .await
                .unwrap(),
        );
        for _ in 0..200 {
            if api
                .get(&principal, action.id)
                .await
                .unwrap()
                .unwrap()
                .status
                == apl_domain::ActionStatus::PendingApproval
            {
                break;
            }
            assert!(worker.process_one().await.unwrap());
        }
        let queue = json_body(
            call(
                &app_a,
                "GET",
                "/v1/approvals",
                &[("cookie", &session)],
                None,
            )
            .await,
        )
        .await;
        let item = queue
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["action_id"] == action.id.to_string())
            .unwrap();
        let decision = json!({"generation":item["generation"],"action_digest":item["action_digest"],"decision":"approve"});
        let path = format!("/v1/approvals/{}/decision", action.id);
        assert_eq!(
            call(
                &app_a,
                "POST",
                &path,
                &[("cookie", &session), ("origin", ORIGIN)],
                Some(decision.clone())
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let approved = call(
            &app_b,
            "POST",
            &path,
            &[
                ("cookie", &session),
                ("origin", ORIGIN),
                ("x-csrf-token", csrf),
            ],
            Some(decision.clone()),
        )
        .await;
        assert_eq!(approved.status(), StatusCode::OK);
        assert_eq!(json_body(approved).await["status"], "ready");
        assert_eq!(
            call(
                &app_a,
                "POST",
                &path,
                &[
                    ("cookie", &session),
                    ("origin", ORIGIN),
                    ("x-csrf-token", csrf)
                ],
                Some(decision)
            )
            .await
            .status(),
            StatusCode::CONFLICT
        );
        for _ in 0..200 {
            if api
                .get(&principal, action.id)
                .await
                .unwrap()
                .unwrap()
                .status
                == apl_domain::ActionStatus::Succeeded
            {
                break;
            }
            assert!(worker.process_one().await.unwrap());
        }
        let effects: i64 =
            sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
                .bind(action.id)
                .fetch_one(&admin)
                .await
                .unwrap();
        assert_eq!(effects, 1);
        assert_eq!(
            call(
                &app_b,
                "GET",
                "/v1/approvals",
                &[("cookie", &session)],
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            call(
                &app_a,
                "POST",
                "/v1/exports",
                &[("cookie", &session), ("origin", ORIGIN)],
                Some(json!({}))
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let body = json!({"connection_id":Uuid::new_v4(),"action_ids":[Uuid::new_v4()]});
        assert_eq!(
            call(
                &app_b,
                "POST",
                "/v1/exports",
                &[
                    ("cookie", &session),
                    ("origin", ORIGIN),
                    ("x-csrf-token", csrf)
                ],
                Some(body)
            )
            .await
            .status(),
            StatusCode::NOT_FOUND,
            "session does not grant export authority"
        );
        assert_eq!(
            call(
                &app_b,
                "POST",
                "/v1/actions",
                &[
                    ("cookie", &session),
                    ("origin", ORIGIN),
                    ("x-csrf-token", csrf)
                ],
                Some(json!({}))
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED,
            "human session is not workload identity"
        );
        sqlx::query("UPDATE reviewers SET enabled=false WHERE reviewer_id=$1")
            .bind(r)
            .execute(&admin)
            .await
            .unwrap();
        assert_eq!(
            call(
                &app_b,
                "GET",
                "/v1/approvals",
                &[("cookie", &session)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        sqlx::query("UPDATE reviewers SET enabled=true WHERE reviewer_id=$1")
            .bind(r)
            .execute(&admin)
            .await
            .unwrap();
        assert_eq!(
            call(
                &app_b,
                "POST",
                "/auth/logout",
                &[
                    ("cookie", &session),
                    ("origin", ORIGIN),
                    ("x-csrf-token", &"x".repeat(43))
                ],
                None
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(
                &app_a,
                "GET",
                "/auth/session",
                &[("cookie", &session)],
                None
            )
            .await
            .status(),
            StatusCode::OK
        );
        let response = call(
            &app_b,
            "POST",
            "/auth/logout",
            &[
                ("cookie", &session),
                ("origin", ORIGIN),
                ("x-csrf-token", csrf),
            ],
            None,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(returned_cookie(&response, SESSION).ends_with('='));
        assert_eq!(
            call(
                &app_a,
                "GET",
                "/auth/session",
                &[("cookie", &session)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM browser_session_audit WHERE reviewer_id=$1")
                .bind(r)
                .fetch_one(&admin)
                .await
                .unwrap();
        assert_eq!(count, 2);
        let (state, binding) = login(&app_a).await;
        sqlx::query("UPDATE browser_login_flows SET expires_at=clock_timestamp()-interval '1 second' WHERE state_hash=$1").bind(credential_hash(&state).as_slice()).execute(&admin).await.unwrap();
        assert_eq!(
            call(
                &app_b,
                "GET",
                &format!("/auth/callback?state={state}&code=synthetic-code"),
                &[("cookie", &binding)],
                None
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(provider.exchanges.load(Ordering::SeqCst), 1);
        std::fs::remove_dir_all(root).unwrap();
    }
}
