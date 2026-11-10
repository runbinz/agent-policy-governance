//! Verification against operator-provisioned or managed issuer public keys.
//! No token-supplied URL or key material is fetched or trusted.
pub mod browser;
mod managed;

pub use managed::{ManagedIdentityError, ManagedIssuer, ManagedJwtVerifier};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::collections::BTreeMap;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid identity verifier configuration")]
    InvalidConfiguration,
    #[error("invalid access token")]
    InvalidToken,
    #[error("access token lacks the required scope")]
    InsufficientScope,
}

#[derive(Clone)]
pub struct JwtVerifier {
    keys: BTreeMap<String, DecodingKey>,
    validation: Validation,
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<serde_json::Value>,
}

#[derive(Deserialize)]
struct PublicKey {
    kty: String,
    kid: String,
    n: String,
    e: String,
    alg: Option<String>,
    #[serde(rename = "use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    // Deserialize these to numeric types as well as validating them in the JWT library.
    exp: u64,
    #[serde(rename = "nbf")]
    _nbf: Option<u64>,
    #[serde(rename = "aud")]
    _aud: Audience,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl JwtVerifier {
    /// OIDC code-flow ID token: sole client audience, one-use nonce and recent
    /// issuance. This is separate from access-token/resource verification.
    pub fn verify_id_token(
        &self,
        token: &str,
        client_id: &str,
        expected_nonce: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        let invalid = IdentityError::InvalidToken;
        if !(32..=128).contains(&expected_nonce.len()) {
            return Err(invalid);
        }
        let identity = self.verify_restricted(token, |_| false, Some(client_id), None)?;
        if identity.subject.len() > 255 || !identity.subject.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(invalid);
        }
        let encoded = token.split('.').nth(1).ok_or(invalid)?;
        let payload = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid)?;
        let claims: IdTokenClaims = serde_json::from_slice(&payload).map_err(|_| invalid)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid)?
            .as_secs();
        if !bool::from(claims.nonce.as_bytes().ct_eq(expected_nonce.as_bytes()))
            || claims.iat > now.saturating_add(30)
            || now.saturating_sub(claims.iat) > 300
            || claims.iat >= claims.exp
            || claims
                .azp
                .is_some_and(|azp| azp.as_str() != Some(client_id))
        {
            return Err(invalid);
        }
        Ok(identity)
    }

    /// Rejects the entire set on an unusable key, avoiding silent configuration drift.
    pub fn from_jwks(issuer: &str, audience: &str, jwks_json: &str) -> Result<Self, IdentityError> {
        let invalid = IdentityError::InvalidConfiguration;
        if issuer.trim().is_empty() || audience.trim().is_empty() {
            return Err(invalid);
        }
        let jwks: Jwks = serde_json::from_str(jwks_json).map_err(|_| invalid)?;
        if jwks.keys.is_empty() {
            return Err(invalid);
        }
        let mut keys = BTreeMap::new();
        for value in jwks.keys {
            if ["d", "p", "q", "dp", "dq", "qi", "oth"]
                .iter()
                .any(|field| value.get(field).is_some())
            {
                return Err(invalid);
            }
            let key: PublicKey = serde_json::from_value(value).map_err(|_| invalid)?;
            if key.kty != "RSA"
                || key.kid.trim().is_empty()
                || key.alg.as_deref().is_some_and(|alg| alg != "RS256")
                || key.usage.as_deref().is_some_and(|usage| usage != "sig")
                || key.key_ops.as_ref().is_some_and(|ops| {
                    ops.len() != 1 || ops.first().map(String::as_str) != Some("verify")
                })
                || keys.contains_key(&key.kid)
            {
                return Err(invalid);
            }
            let modulus = URL_SAFE_NO_PAD.decode(&key.n).map_err(|_| invalid)?;
            let exponent = URL_SAFE_NO_PAD.decode(&key.e).map_err(|_| invalid)?;
            // RFC 7518 Base64urlUInt is unsigned big-endian, without leading zero octets.
            let first = modulus.first().copied().ok_or(invalid)?;
            let bits = modulus.len() * 8 - first.leading_zeros() as usize;
            if first == 0
                || bits < 2048
                || exponent.is_empty()
                || exponent[0] == 0
                || exponent.last().is_none_or(|last| last & 1 == 0)
                || (exponent.len() == 1 && exponent[0] < 3)
            {
                return Err(invalid);
            }
            let decoding = DecodingKey::from_rsa_components(&key.n, &key.e).map_err(|_| invalid)?;
            keys.insert(key.kid, decoding);
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_required_spec_claims(&["iss", "sub", "aud", "exp"]);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        Ok(Self { keys, validation })
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, |_| false, None, None)
    }

    pub fn verify_with_scope(
        &self,
        token: &str,
        required_scope: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, |_| false, None, Some(required_scope))
    }

    /// Requires both the configured audience and the sole exact resource audience.
    pub fn verify_for_resource(
        &self,
        token: &str,
        resource: &str,
        required_scope: &str,
    ) -> Result<VerifiedIdentity, IdentityError> {
        self.verify_restricted(token, |_| false, Some(resource), Some(required_scope))
    }

    fn verify_restricted(
        &self,
        token: &str,
        excluded: impl Fn(&str) -> bool,
        resource: Option<&str>,
        required_scope: Option<&str>,
    ) -> Result<VerifiedIdentity, IdentityError> {
        let invalid = IdentityError::InvalidToken;
        if token.is_empty() || token.len() > 16 * 1024 {
            return Err(invalid);
        }
        let header = decode_header(token).map_err(|_| invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(invalid);
        }
        // Unsupported critical extensions must never be silently accepted.
        let encoded = token.split('.').next().ok_or(invalid)?;
        let raw = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid)?;
        let raw: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| invalid)?;
        if raw.get("crit").is_some() || raw.get("b64").is_some() {
            return Err(invalid);
        }
        let kid = header.kid.as_deref().ok_or(invalid)?;
        let key = self.keys.get(kid).ok_or(invalid)?;
        let claims = decode::<Claims>(token, key, &self.validation)
            .map_err(|_| invalid)?
            .claims;
        if claims.sub.trim().is_empty() {
            return Err(invalid);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| invalid)?
            .as_secs();
        if claims.exp <= now {
            return Err(invalid);
        }
        let audience = match &claims._aud {
            Audience::Single(value) => std::slice::from_ref(value),
            Audience::Multiple(values) => values.as_slice(),
        };
        if audience.is_empty()
            || (audience.len() == 1 && audience[0].is_empty())
            || audience.iter().any(|value| excluded(value))
            || resource
                .is_some_and(|resource| audience.len() != 1 || audience[0].as_str() != resource)
        {
            return Err(invalid);
        }
        if let Some(scope) = required_scope {
            verify_scope(token, scope)?;
        }
        Ok(VerifiedIdentity {
            issuer: claims.iss,
            subject: claims.sub,
        })
    }
}

#[derive(Deserialize)]
struct IdTokenClaims {
    nonce: String,
    iat: u64,
    exp: u64,
    #[serde(default, deserialize_with = "present_scope")]
    azp: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ScopeClaim {
    // Distinguish an absent optional claim from a present malformed null.
    #[serde(default, deserialize_with = "present_scope")]
    scope: Option<serde_json::Value>,
}

fn present_scope<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<serde_json::Value>, D::Error> {
    serde_json::Value::deserialize(deserializer).map(Some)
}

fn verify_scope(token: &str, required: &str) -> Result<(), IdentityError> {
    if !scope_token(required) {
        return Err(IdentityError::InvalidConfiguration);
    }
    let invalid = IdentityError::InvalidToken;
    // Only called after signature, issuer, audience and time checks passed.
    let encoded = token.split('.').nth(1).ok_or(invalid)?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| invalid)?;
    let claim: ScopeClaim = serde_json::from_slice(&decoded).map_err(|_| invalid)?;
    let claim = claim.scope.ok_or(IdentityError::InsufficientScope)?;
    let scope = claim.as_str().ok_or(invalid)?;
    let mut found = false;
    for value in scope.split(' ') {
        if !scope_token(value) {
            return Err(invalid);
        }
        found |= value == required;
    }
    if found {
        Ok(())
    } else {
        Err(IdentityError::InsufficientScope)
    }
}

fn scope_token(value: &str) -> bool {
    // RFC 6749 section 3.3: case-sensitive, printable ASCII except quote and backslash.
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
}
