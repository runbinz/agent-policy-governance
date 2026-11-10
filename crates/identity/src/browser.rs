//! OIDC code flow primitives. No provider token or client secret is exposed in errors.
use crate::{IdentityError, ManagedJwtVerifier, VerifiedIdentity};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::{redirect, Client, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BrowserLoginError {
    #[error("invalid browser login configuration")]
    InvalidConfiguration,
    #[error("browser login is unavailable")]
    Unavailable,
    #[error("browser login was not accepted")]
    Rejected,
}

/// Shared replica secret derives independent PKCE, nonce and CSRF values. Only
/// hashes of state/binding are needed in the database; no PKCE secret is stored.
pub struct BrowserSecrets(Zeroizing<[u8; 32]>);
impl BrowserSecrets {
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }
    fn derive(&self, label: &[u8], value: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.0.as_ref()).expect("fixed HMAC key size");
        mac.update(label);
        mac.update(value.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
    pub fn verifier(&self, state: &str) -> Result<Zeroizing<String>, BrowserLoginError> {
        secret(state)?;
        Ok(Zeroizing::new(self.derive(b"apl-browser-pkce-v1\0", state)))
    }
    pub fn nonce(&self, state: &str) -> Result<String, BrowserLoginError> {
        secret(state)?;
        Ok(self.derive(b"apl-browser-nonce-v1\0", state))
    }
    pub fn csrf(&self, session: &str) -> Result<Zeroizing<String>, BrowserLoginError> {
        secret(session)?;
        Ok(Zeroizing::new(
            self.derive(b"apl-browser-csrf-v1\0", session),
        ))
    }
}
pub fn new_secret() -> Result<Zeroizing<String>, BrowserLoginError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| BrowserLoginError::Unavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}
pub fn credential_hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}
pub fn pkce_challenge(verifier: &str) -> Result<String, BrowserLoginError> {
    if !(43..=128).contains(&verifier.len())
        || !verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
    {
        return Err(BrowserLoginError::Rejected);
    }
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())))
}
fn secret(value: &str) -> Result<(), BrowserLoginError> {
    if value.len() != 43
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(BrowserLoginError::Rejected);
    }
    Ok(())
}

#[derive(Clone)]
pub struct BrowserOidc(Arc<OidcInner>);
struct OidcInner {
    issuer: String,
    client: Client,
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    redirect_uri: String,
    authorization: Url,
    token: Url,
    verifier: IdVerifier,
}
enum IdVerifier {
    Managed(ManagedJwtVerifier),
    #[cfg(test)]
    Fixture(Box<crate::JwtVerifier>),
}
impl IdVerifier {
    fn verify(
        &self,
        token: &str,
        client_id: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        match self {
            Self::Managed(verifier) if verifier.audience() == client_id => {
                verifier.verify_id_token(token, nonce)
            }
            Self::Managed(_) => Err(IdentityError::InvalidToken),
            #[cfg(test)]
            Self::Fixture(verifier) => verifier.verify_id_token(token, client_id, nonce),
        }
    }
}
#[derive(Deserialize)]
struct Metadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    code_challenge_methods_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
}
#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

impl BrowserOidc {
    /// A dedicated managed verifier must use this exact issuer and client ID.
    /// Public PKCE clients and client_secret_post are supported; implicit flow,
    /// refresh tokens, userinfo and provider access tokens are not used.
    pub async fn discover(
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        client_secret: Option<Zeroizing<String>>,
        verifier: ManagedJwtVerifier,
    ) -> Result<Self, BrowserLoginError> {
        if verifier.issuer() != issuer || verifier.audience() != client_id {
            return Err(BrowserLoginError::InvalidConfiguration);
        }
        Self::build(
            issuer,
            client_id,
            redirect_uri,
            client_secret,
            IdVerifier::Managed(verifier),
            false,
        )
        .await
    }
    async fn build(
        issuer: &str,
        client_id: &str,
        redirect_uri: &str,
        client_secret: Option<Zeroizing<String>>,
        verifier: IdVerifier,
        test_http: bool,
    ) -> Result<Self, BrowserLoginError> {
        let bad = BrowserLoginError::InvalidConfiguration;
        let issuer_url = endpoint(issuer, test_http).ok_or(bad)?;
        let redirect = endpoint(redirect_uri, test_http).ok_or(bad)?;
        if redirect.path() != "/auth/callback"
            || client_id.is_empty()
            || client_id.len() > 256
            || client_id
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || client_secret.as_ref().is_some_and(|s| {
                s.is_empty() || s.len() > 4096 || s.bytes().any(|b| b.is_ascii_control())
            })
        {
            return Err(bad);
        }
        let client = Client::builder()
            .redirect(redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| bad)?;
        let discovery = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let response = client
            .get(discovery)
            .send()
            .await
            .map_err(|_| BrowserLoginError::Unavailable)?;
        let bytes = bounded_json(response).await?;
        let metadata: Metadata = serde_json::from_slice(&bytes).map_err(|_| bad)?;
        let authorization = endpoint(&metadata.authorization_endpoint, test_http).ok_or(bad)?;
        let token = endpoint(&metadata.token_endpoint, test_http).ok_or(bad)?;
        let method = if client_secret.is_some() {
            "client_secret_post"
        } else {
            "none"
        };
        if metadata.issuer != issuer
            || authorization.origin() != issuer_url.origin()
            || token.origin() != issuer_url.origin()
            || !metadata
                .response_types_supported
                .iter()
                .any(|s| s == "code")
            || !metadata
                .code_challenge_methods_supported
                .iter()
                .any(|s| s == "S256")
            || !metadata
                .token_endpoint_auth_methods_supported
                .iter()
                .any(|s| s == method)
            || !metadata
                .id_token_signing_alg_values_supported
                .iter()
                .any(|s| s == "RS256")
        {
            return Err(bad);
        }
        Ok(Self(Arc::new(OidcInner {
            issuer: issuer.into(),
            client,
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization,
            token,
            verifier,
        })))
    }
    pub fn authorization_url(
        &self,
        state: &str,
        nonce: &str,
        challenge: &str,
    ) -> Result<String, BrowserLoginError> {
        for value in [state, nonce, challenge] {
            secret(value)?;
        }
        let mut url = self.0.authorization.clone();
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("scope", "openid"),
            ("client_id", self.0.client_id.as_str()),
            ("redirect_uri", self.0.redirect_uri.as_str()),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", challenge),
            ("code_challenge_method", "S256"),
        ]);
        Ok(url.into())
    }
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }
    pub fn redirect_uri(&self) -> &str {
        &self.0.redirect_uri
    }
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, BrowserLoginError> {
        if code.is_empty() || code.len() > 4096 || code.bytes().any(|b| b.is_ascii_control()) {
            return Err(BrowserLoginError::Rejected);
        }
        secret(verifier)?;
        secret(nonce)?;
        let mut parameters = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", self.0.redirect_uri.as_str()),
            ("client_id", self.0.client_id.as_str()),
            ("code_verifier", verifier),
        ];
        if let Some(value) = &self.0.client_secret {
            parameters.push(("client_secret", value.as_str()));
        }
        let response = self
            .0
            .client
            .post(self.0.token.clone())
            .form(&parameters)
            .send()
            .await
            .map_err(|_| BrowserLoginError::Unavailable)?;
        let bytes = bounded_json(response).await?;
        let response: TokenResponse =
            serde_json::from_slice(&bytes).map_err(|_| BrowserLoginError::Rejected)?;
        let token = Zeroizing::new(response.id_token);
        self.0
            .verifier
            .verify(&token, &self.0.client_id, nonce)
            .map_err(|_| BrowserLoginError::Rejected)
    }
}

fn endpoint(value: &str, test_http: bool) -> Option<Url> {
    if value.len() > 2048
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.host_str().is_none()
        || (url.scheme() != "https"
            && !(test_http && url.scheme() == "http" && url.host_str() == Some("127.0.0.1")))
    {
        return None;
    }
    Some(url)
}
async fn bounded_json(
    mut response: reqwest::Response,
) -> Result<Zeroizing<Vec<u8>>, BrowserLoginError> {
    if !response.status().is_success()
        || response.content_length().is_some_and(|n| n > 65536)
        || response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|s| s.to_str().ok())
            .is_none_or(|s| {
                s.split(';')
                    .next()
                    .is_none_or(|s| s.trim() != "application/json")
            })
    {
        return Err(BrowserLoginError::Rejected);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BrowserLoginError::Unavailable)?
    {
        if bytes.len() + chunk.len() > 65536 {
            return Err(BrowserLoginError::Rejected);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::Form,
        http::{header, StatusCode},
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use std::{
        collections::HashMap,
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    const CLIENT: &str = "browser-client";
    const NONCE: &str = "nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn";
    type Requests = Arc<Mutex<Vec<HashMap<String, String>>>>;
    fn metadata(issuer: &str) -> Value {
        json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),
            "response_types_supported":["code"],"code_challenge_methods_supported":["S256"],
            "token_endpoint_auth_methods_supported":["none","client_secret_post"],"id_token_signing_alg_values_supported":["RS256"]})
    }
    fn id_token(issuer: &str, nonce: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-1".into());
        encode(&header,&json!({"iss":issuer,"sub":"human-1","aud":CLIENT,"exp":now+300,"iat":now,"nonce":nonce}),
            &EncodingKey::from_rsa_pem(include_bytes!("../tests/fixtures/test-only-private.pem")).unwrap()).unwrap()
    }
    async fn mock(
        change: impl FnOnce(&mut Value),
        mode: &str,
        secret: Option<String>,
    ) -> (
        Result<BrowserOidc, BrowserLoginError>,
        Requests,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let mut document = metadata(&issuer);
        change(&mut document);
        let nonce = if mode == "wrong-nonce" {
            "x".repeat(43)
        } else {
            NONCE.into()
        };
        let token = id_token(&issuer, &nonce);
        let requests: Requests = Arc::new(Mutex::new(Vec::new()));
        let capture = requests.clone();
        let mode = mode.to_string();
        let app=Router::new()
            .route("/.well-known/openid-configuration",get(move || {let value=document.clone();async move {Json(value)}}))
            .route("/token",post(move |Form(parameters):Form<HashMap<String,String>>| {
                let capture=capture.clone(); let mode=mode.clone();let token=token.clone();
                async move {
                    capture.lock().unwrap().push(parameters);
                    match mode.as_str() {
                        "redirect" => (StatusCode::TEMPORARY_REDIRECT,[(header::LOCATION,"http://127.0.0.1:1/forbidden")]).into_response(),
                        "oversize" => ([(header::CONTENT_TYPE,"application/json")],"x".repeat(65537)).into_response(),
                        "sensitive-error" => (StatusCode::BAD_REQUEST,Json(json!({"error":"secret-provider-detail"}))).into_response(),
                        _=>Json(json!({"id_token":token,"access_token":"discarded-provider-token","token_type":"Bearer"})).into_response(),
                    }
                }
            }));
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let verifier = crate::JwtVerifier::from_jwks(
            &issuer,
            CLIENT,
            include_str!("../tests/fixtures/jwks.json"),
        )
        .unwrap();
        let client = BrowserOidc::build(
            &issuer,
            CLIENT,
            "http://127.0.0.1:9999/auth/callback",
            secret.map(Zeroizing::new),
            IdVerifier::Fixture(Box::new(verifier)),
            true,
        )
        .await;
        (client, requests, task)
    }

    #[test]
    fn random_secrets_domain_separation_and_pkce_vector() {
        let one = new_secret().unwrap();
        let two = new_secret().unwrap();
        assert_ne!(*one, *two);
        assert_eq!(one.len(), 43);
        let secrets = BrowserSecrets::new([7; 32]);
        let verifier = secrets.verifier(&one).unwrap();
        let nonce = secrets.nonce(&one).unwrap();
        let csrf = secrets.csrf(&one).unwrap();
        assert_ne!(*verifier, nonce);
        assert_ne!(*verifier, *csrf);
        assert_ne!(nonce, *csrf);
        assert_eq!(*verifier, *secrets.verifier(&one).unwrap());
        assert_ne!(
            *verifier,
            *BrowserSecrets::new([8; 32]).verifier(&one).unwrap()
        );
        assert!(secrets.verifier("bad").is_err());
        assert_eq!(
            pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        assert!(pkce_challenge(&"!".repeat(43)).is_err());
        for value in [
            "http://identity.example.test",
            "https://user:password@example.test",
            "https://example.test/a?x=y",
            "https://example.test/#x",
        ] {
            assert!(endpoint(value, false).is_none());
        }
    }

    #[tokio::test]
    async fn code_exchange_is_exact_and_drops_provider_tokens() {
        let (client, requests, task) =
            mock(|_| {}, "good", Some("synthetic-client-secret".into())).await;
        let client = client.unwrap();
        let state = "s".repeat(43);
        let verifier = "v".repeat(43);
        let url = Url::parse(
            &client
                .authorization_url(&state, NONCE, &pkce_challenge(&verifier).unwrap())
                .unwrap(),
        )
        .unwrap();
        let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("response_type").unwrap(), "code");
        assert_eq!(query.get("scope").unwrap(), "openid");
        assert_eq!(query.get("state").unwrap(), &state);
        assert_eq!(query.get("nonce").unwrap(), NONCE);
        assert_eq!(query.get("code_challenge_method").unwrap(), "S256");
        assert!(!query.contains_key("client_secret"));
        let identity = client
            .exchange_code("synthetic-code", &verifier, NONCE)
            .await
            .unwrap();
        assert_eq!(identity.subject, "human-1");
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].get("code_verifier").unwrap(), &verifier);
        assert_eq!(requests[0].get("grant_type").unwrap(), "authorization_code");
        assert_eq!(requests[0].get("client_id").unwrap(), CLIENT);
        assert_eq!(
            requests[0].get("redirect_uri").unwrap(),
            "http://127.0.0.1:9999/auth/callback"
        );
        assert_eq!(
            requests[0].get("client_secret").unwrap(),
            "synthetic-client-secret"
        );
        task.abort();
    }

    #[tokio::test]
    async fn issuer_endpoint_and_protocol_metadata_fail_closed() {
        for (field, value) in [
            ("issuer", json!("https://other.example.test")),
            (
                "authorization_endpoint",
                json!("https://other.example.test/authorize"),
            ),
            ("token_endpoint", json!("http://127.0.0.1:1/token")),
            ("code_challenge_methods_supported", json!(["plain"])),
            (
                "token_endpoint_auth_methods_supported",
                json!(["client_secret_basic"]),
            ),
            ("response_types_supported", json!(["token"])),
            ("id_token_signing_alg_values_supported", json!(["HS256"])),
        ] {
            let (client, requests, task) = mock(|doc| doc[field] = value, "good", None).await;
            assert!(
                matches!(client, Err(BrowserLoginError::InvalidConfiguration)),
                "{field}"
            );
            assert!(requests.lock().unwrap().is_empty());
            task.abort();
        }
    }

    #[tokio::test]
    async fn nonce_redirect_size_and_provider_errors_never_establish_identity() {
        for mode in ["wrong-nonce", "redirect", "oversize", "sensitive-error"] {
            let (client, requests, task) = mock(|_| {}, mode, None).await;
            let error = client
                .unwrap()
                .exchange_code("synthetic-code", &"v".repeat(43), NONCE)
                .await
                .unwrap_err();
            assert_eq!(error, BrowserLoginError::Rejected, "{mode}");
            assert!(!error.to_string().contains("secret-provider-detail"));
            assert_eq!(
                requests.lock().unwrap().len(),
                1,
                "no automatic retry or redirect"
            );
            task.abort();
        }
    }
}
