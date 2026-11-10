//! Explicitly refreshed OIDC signing-key cache. Token processing never fetches.

use crate::{IdentityError, JwtVerifier, VerifiedIdentity};
use reqwest::{redirect, Client, StatusCode, Url};
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const MAX_URL_BYTES: usize = 2048;
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 256 * 1024;
const MAX_AUDIENCES: usize = 8;
const MAX_STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ManagedIdentityError {
    #[error("invalid managed issuer configuration")]
    InvalidConfiguration,
    #[error("managed issuer refresh is already in progress")]
    RefreshInProgress,
    #[error("managed issuer could not be fetched")]
    FetchFailed,
    #[error("managed issuer document is invalid or exceeds its size limit")]
    InvalidDocument,
    #[error("managed issuer metadata did not match the trusted configuration")]
    IssuerMismatch,
    #[error("managed issuer signing-key URL is not allowed")]
    JwksUrlRejected,
    #[error("managed issuer cache is unavailable")]
    CacheUnavailable,
}

#[derive(Clone)]
pub struct ManagedIssuer {
    inner: Arc<Inner>,
}

#[derive(Clone)]
pub struct ManagedJwtVerifier {
    issuer: ManagedIssuer,
    audience: String,
}

struct Inner {
    issuer: String,
    issuer_url: Url,
    discovery_url: Url,
    pinned_jwks_url: Option<String>,
    audiences: BTreeSet<String>,
    stale_after: Duration,
    http: Client,
    refresh: Mutex<()>,
    cache: RwLock<Option<Cache>>,
    // Only a private unit-test constructor can enable loopback HTTP.
    allow_loopback_http: bool,
}

struct Cache {
    refreshed_at: Instant,
    verifiers: BTreeMap<String, JwtVerifier>,
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    jwks_uri: String,
}

impl ManagedIssuer {
    /// Creates an empty, fail-closed cache. Call refresh before accepting traffic.
    /// If pinned_jwks_url is supplied, discovery must return that exact URL.
    pub fn new(
        issuer: &str,
        audiences: &[&str],
        pinned_jwks_url: Option<&str>,
        stale_after: Duration,
    ) -> Result<Self, ManagedIdentityError> {
        Self::build(issuer, audiences, pinned_jwks_url, stale_after, false)
    }

    fn build(
        issuer: &str,
        audiences: &[&str],
        pinned_jwks_url: Option<&str>,
        stale_after: Duration,
        allow_loopback_http: bool,
    ) -> Result<Self, ManagedIdentityError> {
        let invalid = ManagedIdentityError::InvalidConfiguration;
        let issuer_url = trusted_url(issuer, allow_loopback_http).ok_or(invalid)?;
        if issuer_url.query().is_some()
            || audiences.is_empty()
            || audiences.len() > MAX_AUDIENCES
            || stale_after.is_zero()
            || stale_after > MAX_STALE_AFTER
            || audiences
                .iter()
                .any(|value| value.trim().is_empty() || value.trim() != *value || value.len() > 256)
        {
            return Err(invalid);
        }
        let distinct: BTreeSet<String> = audiences.iter().map(|value| (*value).into()).collect();
        if distinct.len() != audiences.len() {
            return Err(invalid);
        }
        if pinned_jwks_url.is_some_and(|pin| trusted_url(pin, allow_loopback_http).is_none()) {
            return Err(invalid);
        }
        let discovery_url = Url::parse(&format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        ))
        .map_err(|_| invalid)?;
        let http = Client::builder()
            .redirect(redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(HTTP_TIMEOUT)
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|_| invalid)?;
        Ok(Self {
            inner: Arc::new(Inner {
                issuer: issuer.to_owned(),
                issuer_url,
                discovery_url,
                pinned_jwks_url: pinned_jwks_url.map(str::to_owned),
                audiences: distinct,
                stale_after,
                http,
                refresh: Mutex::new(()),
                cache: RwLock::new(None),
                allow_loopback_http,
            }),
        })
    }

    /// Refresh from operator-configured discovery. Invalid refreshes leave the
    /// previous key set and its original freshness cutoff untouched.
    pub async fn refresh(&self) -> Result<(), ManagedIdentityError> {
        let inner = &self.inner;
        let _gate = inner
            .refresh
            .try_lock()
            .map_err(|_| ManagedIdentityError::RefreshInProgress)?;
        let discovery = fetch(
            &inner.http,
            inner.discovery_url.clone(),
            MAX_DISCOVERY_BYTES,
        )
        .await?;
        let discovery: Discovery = serde_json::from_slice(&discovery)
            .map_err(|_| ManagedIdentityError::InvalidDocument)?;
        if discovery.issuer != inner.issuer {
            return Err(ManagedIdentityError::IssuerMismatch);
        }
        let jwks_url = trusted_url(&discovery.jwks_uri, inner.allow_loopback_http)
            .ok_or(ManagedIdentityError::JwksUrlRejected)?;
        let allowed = match &inner.pinned_jwks_url {
            Some(pin) => &discovery.jwks_uri == pin,
            None => jwks_url.origin() == inner.issuer_url.origin(),
        };
        if !allowed {
            return Err(ManagedIdentityError::JwksUrlRejected);
        }
        let keys = fetch(&inner.http, jwks_url, MAX_JWKS_BYTES).await?;
        let keys = std::str::from_utf8(&keys).map_err(|_| ManagedIdentityError::InvalidDocument)?;
        let verifiers = inner
            .audiences
            .iter()
            .map(|audience| {
                JwtVerifier::from_jwks(&inner.issuer, audience, keys)
                    .map(|verifier| (audience.clone(), verifier))
                    .map_err(|_| ManagedIdentityError::InvalidDocument)
            })
            .collect::<Result<_, _>>()?;
        let mut slot = inner
            .cache
            .write()
            .map_err(|_| ManagedIdentityError::CacheUnavailable)?;
        *slot = Some(Cache {
            refreshed_at: Instant::now(),
            verifiers,
        });
        Ok(())
    }

    pub fn verifier(&self, audience: &str) -> Result<ManagedJwtVerifier, ManagedIdentityError> {
        if !self.inner.audiences.contains(audience) {
            return Err(ManagedIdentityError::InvalidConfiguration);
        }
        Ok(ManagedJwtVerifier {
            issuer: self.clone(),
            audience: audience.to_owned(),
        })
    }

    pub fn is_fresh(&self) -> bool {
        self.with_fresh_cache(|_| ()).is_some()
    }

    fn with_fresh_cache<T>(&self, f: impl FnOnce(&Cache) -> T) -> Option<T> {
        let slot = self.inner.cache.read().ok()?;
        let cache = slot.as_ref()?;
        if cache.refreshed_at.elapsed() >= self.inner.stale_after {
            return None;
        }
        Some(f(cache))
    }
}

impl ManagedJwtVerifier {
    pub fn issuer(&self) -> &str {
        &self.issuer.inner.issuer
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn verify_id_token(
        &self,
        token: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.issuer
            .with_fresh_cache(|cache| {
                cache
                    .verifiers
                    .get(&self.audience)
                    .ok_or(IdentityError::InvalidToken)?
                    .verify_id_token(token, &self.audience, expected_nonce)
            })
            .ok_or(IdentityError::InvalidToken)?
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, None, None)
    }

    pub fn verify_with_scope(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, None, Some(required_scope))
    }

    pub fn verify_for_resource(
        &self,
        token: &str,
        resource: &str,
        required_scope: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, Some(resource), Some(required_scope))
    }

    fn verify_restricted(
        &self,
        token: &str,
        resource: Option<&str>,
        required_scope: Option<&str>,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.issuer
            .with_fresh_cache(|cache| {
                cache
                    .verifiers
                    .get(&self.audience)
                    .ok_or(IdentityError::InvalidToken)?
                    .verify_restricted(
                        token,
                        |value| value != self.audience && cache.verifiers.contains_key(value),
                        resource,
                        required_scope,
                    )
            })
            .ok_or(IdentityError::InvalidToken)?
    }

    pub fn is_fresh(&self) -> bool {
        self.issuer.is_fresh()
    }
}

fn trusted_url(value: &str, allow_loopback_http: bool) -> Option<Url> {
    if value.len() > MAX_URL_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        return None;
    }
    let url = Url::parse(value).ok()?;
    let loopback_http =
        allow_loopback_http && url.scheme() == "http" && url.host_str() == Some("127.0.0.1");
    if !(url.scheme() == "https" || loopback_http)
        || url.host().is_none()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || value.contains('\\')
    {
        return None;
    }
    Some(url)
}

async fn fetch(http: &Client, url: Url, limit: usize) -> Result<Vec<u8>, ManagedIdentityError> {
    let mut response = http
        .get(url)
        .header(
            reqwest::header::ACCEPT,
            "application/json, application/jwk-set+json",
        )
        .send()
        .await
        .map_err(|_| ManagedIdentityError::FetchFailed)?;
    if response.status() != StatusCode::OK {
        return Err(ManagedIdentityError::FetchFailed);
    }
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ManagedIdentityError::InvalidDocument);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| ManagedIdentityError::FetchFailed)?
    {
        if chunk.len() > limit - bytes.len() {
            return Err(ManagedIdentityError::InvalidDocument);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::State,
        http::{header, Response},
        routing::get,
        Router,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex as SyncMutex,
    };
    use tokio::{net::TcpListener, task::JoinHandle};

    const KEYS: &str = include_str!("../tests/fixtures/jwks.json");
    const PRIVATE: &[u8] = include_bytes!("../tests/fixtures/test-only-private.pem");
    const STALE_AFTER: Duration = Duration::from_secs(60);

    #[derive(Clone)]
    struct MockState {
        discovery: Arc<SyncMutex<String>>,
        keys: Arc<SyncMutex<String>>,
        key_requests: Arc<AtomicUsize>,
    }

    struct Mock {
        issuer: String,
        jwks_url: String,
        state: MockState,
        task: JoinHandle<()>,
    }

    impl Drop for Mock {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Mock {
        async fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let issuer = format!("{origin}/tenant");
            let jwks_url = format!("{origin}/jwks");
            let state = MockState {
                discovery: Arc::new(SyncMutex::new(
                    json!({"issuer":issuer,"jwks_uri":jwks_url}).to_string(),
                )),
                keys: Arc::new(SyncMutex::new(KEYS.to_owned())),
                key_requests: Arc::new(AtomicUsize::new(0)),
            };
            let routes = Router::new()
                .route(
                    "/tenant/.well-known/openid-configuration",
                    get(|State(state): State<MockState>| async move {
                        state.discovery.lock().unwrap().clone()
                    }),
                )
                .route(
                    "/jwks",
                    get(|State(state): State<MockState>| async move {
                        state.key_requests.fetch_add(1, Ordering::SeqCst);
                        state.keys.lock().unwrap().clone()
                    }),
                )
                .route(
                    "/redirect",
                    get(|| async {
                        Response::builder()
                            .status(302)
                            .header(header::LOCATION, "/jwks")
                            .body(Body::empty())
                            .unwrap()
                    }),
                )
                .with_state(state.clone());
            let task = tokio::spawn(async move {
                axum::serve(listener, routes).await.unwrap();
            });
            Self {
                issuer,
                jwks_url,
                state,
                task,
            }
        }

        fn discover(&self, issuer: &str, jwks: &str) {
            *self.state.discovery.lock().unwrap() =
                json!({"issuer":issuer,"jwks_uri":jwks}).to_string();
        }

        fn managed(&self, pin: Option<&str>) -> ManagedIssuer {
            ManagedIssuer::build(
                &self.issuer,
                &["workload", "reviewer"],
                pin,
                STALE_AFTER,
                true,
            )
            .unwrap()
        }

        fn token(&self, kid: &str, audience: Value) -> String {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some(kid.into());
            header.jku = Some(format!("{}/untrusted", self.issuer));
            let exp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 120;
            encode(
                &header,
                &json!({"iss":self.issuer,"sub":"fixture","aud":audience,"exp":exp}),
                &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
            )
            .unwrap()
        }
    }

    #[test]
    fn public_configuration_requires_https_and_distinct_audiences() {
        for url in [
            "http://127.0.0.1:80",
            "https://user@issuer.example",
            "https://issuer.example/?q=1",
            "https://issuer.example/#fragment",
        ] {
            assert!(ManagedIssuer::new(url, &["api"], None, STALE_AFTER).is_err());
        }
        assert!(
            ManagedIssuer::new("https://issuer.example", &["api", "api"], None, STALE_AFTER)
                .is_err()
        );
        assert!(ManagedIssuer::new(
            "https://issuer.example",
            &["api"],
            Some("http://keys.example"),
            STALE_AFTER
        )
        .is_err());
        assert!(ManagedIssuer::new(
            "https://issuer.example",
            &["api"],
            Some("https://keys.example/jwks"),
            STALE_AFTER
        )
        .is_ok());
    }

    #[tokio::test]
    async fn rotation_atomically_replaces_keys_for_every_audience_without_token_fetches() {
        let mock = Mock::start().await;
        let issuer = mock.managed(None);
        let workload = issuer.verifier("workload").unwrap();
        let reviewer = issuer.verifier("reviewer").unwrap();
        let token = mock.token("test-1", json!("workload"));
        assert!(!workload.is_fresh());
        assert!(workload.verify(&token).is_err());

        issuer.refresh().await.unwrap();
        assert!(workload.is_fresh());
        assert_eq!(workload.verify(&token).unwrap().subject, "fixture");
        assert!(reviewer.verify(&token).is_err());
        let reviewer_token = mock.token("test-1", json!(["unrelated", "reviewer"]));
        assert!(reviewer.verify(&reviewer_token).is_ok());
        let both = mock.token("test-1", json!(["workload", "reviewer"]));
        assert!(workload.verify(&both).is_err());
        assert!(reviewer.verify(&both).is_err());
        assert!(workload
            .verify(&mock.token("attacker-selected", json!("workload")))
            .is_err());
        assert_eq!(mock.state.key_requests.load(Ordering::SeqCst), 1);

        *mock.state.keys.lock().unwrap() = KEYS.replace("test-1", "test-2");
        issuer.refresh().await.unwrap();
        assert!(workload.verify(&token).is_err());
        assert!(reviewer.verify(&reviewer_token).is_err());
        assert!(workload
            .verify(&mock.token("test-2", json!("workload")))
            .is_ok());
        assert!(reviewer
            .verify(&mock.token("test-2", json!("reviewer")))
            .is_ok());
    }

    #[tokio::test]
    async fn scoped_verification_preserves_atomic_audience_checks() {
        let mock = Mock::start().await;
        let issuer = mock.managed(None);
        let workload = issuer.verifier("workload").unwrap();
        issuer.refresh().await.unwrap();
        let token = |audience: Value, scope: &str| {
            let mut header = Header::new(Algorithm::RS256);
            header.kid = Some("test-1".into());
            let exp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 120;
            encode(
                &header,
                &json!({"iss":mock.issuer,"sub":"fixture","aud":audience,
                "exp":exp,"scope":scope}),
                &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
            )
            .unwrap()
        };
        let exact = token(json!(["workload"]), "refunds");
        assert!(workload
            .verify_for_resource(&exact, "workload", "refunds")
            .is_ok());
        assert_eq!(
            workload.verify_for_resource(&exact, "workload", "other"),
            Err(IdentityError::InsufficientScope)
        );
        let dual = token(json!(["workload", "reviewer"]), "refunds");
        assert_eq!(
            workload.verify_with_scope(&dual, "refunds"),
            Err(IdentityError::InvalidToken)
        );
        let unrelated = token(json!(["workload", "other"]), "refunds");
        assert!(workload.verify_with_scope(&unrelated, "refunds").is_ok());
        assert_eq!(
            workload.verify_for_resource(&unrelated, "workload", "refunds"),
            Err(IdentityError::InvalidToken)
        );
    }

    #[tokio::test]
    async fn managed_id_tokens_require_fresh_cache_and_bound_nonce() {
        let mock = Mock::start().await;
        let issuer = mock.managed(None);
        let verifier = issuer.verifier("reviewer").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let nonce = "n".repeat(43);
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-1".into());
        let token = encode(&header,&json!({"iss":mock.issuer,"sub":"human","aud":"reviewer","iat":now,"exp":now+120,"nonce":nonce}),
            &EncodingKey::from_rsa_pem(PRIVATE).unwrap()).unwrap();
        assert!(verifier.verify_id_token(&token, &nonce).is_err());
        issuer.refresh().await.unwrap();
        assert!(verifier.verify_id_token(&token, &nonce).is_ok());
        assert!(verifier.verify_id_token(&token, &"x".repeat(43)).is_err());
        issuer
            .inner
            .cache
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .refreshed_at = Instant::now().checked_sub(STALE_AFTER).unwrap();
        assert!(verifier.verify_id_token(&token, &nonce).is_err());
    }

    #[tokio::test]
    async fn failed_refresh_keeps_last_known_good_without_extending_freshness() {
        let mock = Mock::start().await;
        let issuer = mock.managed(None);
        let verifier = issuer.verifier("workload").unwrap();
        let token = mock.token("test-1", json!("workload"));
        issuer.refresh().await.unwrap();
        let first_refresh = issuer
            .inner
            .cache
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .refreshed_at;

        *mock.state.keys.lock().unwrap() = "x".repeat(MAX_JWKS_BYTES + 1);
        assert_eq!(
            issuer.refresh().await,
            Err(ManagedIdentityError::InvalidDocument)
        );
        *mock.state.keys.lock().unwrap() = r#"{"keys":[]}"#.into();
        assert_eq!(
            issuer.refresh().await,
            Err(ManagedIdentityError::InvalidDocument)
        );
        assert_eq!(
            issuer
                .inner
                .cache
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .refreshed_at,
            first_refresh
        );
        assert!(verifier.verify(&token).is_ok());

        issuer
            .inner
            .cache
            .write()
            .unwrap()
            .as_mut()
            .unwrap()
            .refreshed_at = Instant::now().checked_sub(STALE_AFTER).unwrap();
        assert!(!verifier.is_fresh());
        assert!(verifier.verify(&token).is_err());
        *mock.state.keys.lock().unwrap() = KEYS.into();
        issuer.refresh().await.unwrap();
        assert!(verifier.verify(&token).is_ok());
    }

    #[tokio::test]
    async fn rejects_issuer_mismatch_unpinned_origin_and_redirect_without_fetching_keys() {
        let mock = Mock::start().await;
        let other = Mock::start().await;
        let issuer = mock.managed(None);
        mock.discover("https://wrong.example", &mock.jwks_url);
        assert_eq!(
            issuer.refresh().await,
            Err(ManagedIdentityError::IssuerMismatch)
        );

        mock.discover(&mock.issuer, &other.jwks_url);
        assert_eq!(
            issuer.refresh().await,
            Err(ManagedIdentityError::JwksUrlRejected)
        );
        assert_eq!(other.state.key_requests.load(Ordering::SeqCst), 0);

        let pinned = mock.managed(Some(&other.jwks_url));
        pinned.refresh().await.unwrap();
        assert_eq!(other.state.key_requests.load(Ordering::SeqCst), 1);
        mock.discover(&mock.issuer, &mock.jwks_url);
        assert_eq!(
            pinned.refresh().await,
            Err(ManagedIdentityError::JwksUrlRejected)
        );

        let redirect = mock.jwks_url.replace("/jwks", "/redirect");
        mock.discover(&mock.issuer, &redirect);
        assert_eq!(
            issuer.refresh().await,
            Err(ManagedIdentityError::FetchFailed)
        );
        assert_eq!(mock.state.key_requests.load(Ordering::SeqCst), 0);
    }
}
