use apl_identity::{IdentityError, JwtVerifier};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const JWKS: &str = include_str!("fixtures/jwks.json");
const PRIVATE: &[u8] = include_bytes!("fixtures/test-only-private.pem");
const ISSUER: &str = "https://identity.example.test";
const AUDIENCE: &str = "apl-api";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn claims() -> Value {
    json!({"iss":ISSUER,"sub":"workload-1","aud":AUDIENCE,"exp":now()+300})
}
fn token(claims: &Value, kid: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.into());
    encode(
        &header,
        claims,
        &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
    )
    .unwrap()
}
fn verifier() -> JwtVerifier {
    JwtVerifier::from_jwks(ISSUER, AUDIENCE, JWKS).unwrap()
}

#[test]
fn oidc_id_token_binds_nonce_client_authorized_party_and_recent_issuance() {
    let nonce = "n".repeat(43);
    let valid = json!({"iss":ISSUER,"sub":"human-1","aud":AUDIENCE,"exp":now()+300,"iat":now(),"nonce":nonce,"azp":AUDIENCE});
    assert!(verifier()
        .verify_id_token(&token(&valid, "test-1"), AUDIENCE, &nonce)
        .is_ok());
    for (field, value) in [
        ("nonce", json!("x".repeat(43))),
        ("nonce", json!(null)),
        ("iat", json!(now() - 301)),
        ("iat", json!(now() + 60)),
        ("iat", json!("123")),
        ("azp", json!("other-client")),
        ("azp", json!(null)),
        ("aud", json!([AUDIENCE, "other-client"])),
        ("aud", json!("other-client")),
    ] {
        let mut claims = valid.clone();
        claims[field] = value;
        assert!(
            verifier()
                .verify_id_token(&token(&claims, "test-1"), AUDIENCE, &nonce)
                .is_err(),
            "{field}"
        );
    }
    for field in ["nonce", "iat"] {
        let mut claims = valid.clone();
        claims.as_object_mut().unwrap().remove(field);
        assert!(verifier()
            .verify_id_token(&token(&claims, "test-1"), AUDIENCE, &nonce)
            .is_err());
    }
    assert!(
        verifier()
            .verify_id_token(&token(&claims(), "test-1"), AUDIENCE, &nonce)
            .is_err(),
        "access token is not an ID token"
    );
    assert!(verifier()
        .verify_id_token(&token(&valid, "test-1"), "other-client", &nonce)
        .is_err());
}

#[test]
fn valid_identity_and_array_audience() {
    let verifier = verifier();
    let identity = verifier.verify(&token(&claims(), "test-1")).unwrap();
    assert_eq!(identity.issuer, ISSUER);
    assert_eq!(identity.subject, "workload-1");
    let mut claims = claims();
    claims["aud"] = json!(["other", AUDIENCE]);
    assert!(verifier.verify(&token(&claims, "test-1")).is_ok());
}

#[test]
fn rejects_invalid_claims_and_missing_required_claims() {
    let verifier = verifier();
    for (field, value) in [
        ("iss", json!("https://wrong.example.test")),
        ("aud", json!("wrong-audience")),
        ("sub", json!(" ")),
        ("exp", json!(now() - 1)),
        ("exp", json!(now())),
        ("exp", json!("9999999999")),
        ("nbf", json!(now() + 300)),
    ] {
        let mut claims = claims();
        claims[field] = value;
        assert_eq!(
            verifier.verify(&token(&claims, "test-1")),
            Err(IdentityError::InvalidToken),
            "{field}"
        );
    }
    for field in ["iss", "sub", "aud", "exp"] {
        let mut claims = claims();
        claims.as_object_mut().unwrap().remove(field);
        assert!(
            verifier.verify(&token(&claims, "test-1")).is_err(),
            "{field}"
        );
    }
}

#[test]
fn rejects_algorithm_confusion_tampering_and_unknown_keys() {
    let verifier = verifier();
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some("test-1".into());
    let hs = encode(
        &header,
        &claims(),
        &EncodingKey::from_secret(b"fake-secret"),
    )
    .unwrap();
    assert!(verifier.verify(&hs).is_err());
    assert!(verifier.verify(&token(&claims(), "unknown")).is_err());
    let valid = token(&claims(), "test-1");
    let mut parts: Vec<_> = valid.split('.').map(str::to_owned).collect();
    let mut modified = claims();
    modified["sub"] = json!("attacker");
    parts[1] = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&modified).unwrap());
    assert!(verifier.verify(&parts.join(".")).is_err());
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"test-1"}"#),
        parts[1]
    );
    assert!(verifier.verify(&none).is_err());
    assert!(verifier.verify(&"x".repeat(16 * 1024 + 1)).is_err());
    let missing_kid = encode(
        &Header::new(Algorithm::RS256),
        &claims(),
        &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
    )
    .unwrap();
    assert!(verifier.verify(&missing_kid).is_err());
}

#[test]
fn key_rotation_and_jku_never_override_local_keys() {
    let mut jwks: Value = serde_json::from_str(JWKS).unwrap();
    let mut rotated = jwks["keys"][0].clone();
    rotated["kid"] = json!("test-2");
    jwks["keys"].as_array_mut().unwrap().push(rotated);
    let verifier = JwtVerifier::from_jwks(ISSUER, AUDIENCE, &jwks.to_string()).unwrap();
    for kid in ["test-1", "test-2"] {
        assert!(verifier.verify(&token(&claims(), kid)).is_ok());
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-1".into());
    header.jku = Some("http://127.0.0.1:1/attacker-jwks".into());
    let signed = encode(
        &header,
        &claims(),
        &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
    )
    .unwrap();
    assert!(verifier.verify(&signed).is_ok());
    header.kid = Some("remote-only".into());
    let signed = encode(
        &header,
        &claims(),
        &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
    )
    .unwrap();
    assert!(verifier.verify(&signed).is_err());
}

#[test]
fn rejects_unsafe_or_ambiguous_key_configuration() {
    for (field, value) in [
        ("kid", json!("")),
        ("kty", json!("EC")),
        ("alg", json!("HS256")),
        ("use", json!("enc")),
        ("key_ops", json!(["sign"])),
        ("key_ops", json!(["verify", "sign"])),
        ("n", json!(URL_SAFE_NO_PAD.encode([255_u8; 128]))),
        ("n", json!("!")),
        ("e", json!("AA")),
        ("d", json!("private")),
    ] {
        let mut jwks: Value = serde_json::from_str(JWKS).unwrap();
        jwks["keys"][0][field] = value;
        assert!(
            JwtVerifier::from_jwks(ISSUER, AUDIENCE, &jwks.to_string()).is_err(),
            "{field}"
        );
    }
    let mut duplicate: Value = serde_json::from_str(JWKS).unwrap();
    let key = duplicate["keys"][0].clone();
    duplicate["keys"].as_array_mut().unwrap().push(key);
    assert!(JwtVerifier::from_jwks(ISSUER, AUDIENCE, &duplicate.to_string()).is_err());
    assert!(JwtVerifier::from_jwks(ISSUER, AUDIENCE, r#"{"keys":[]}"#).is_err());
    assert!(JwtVerifier::from_jwks("", AUDIENCE, JWKS).is_err());
}

#[test]
fn resource_requires_sole_exact_audience_and_an_exact_valid_scope() {
    const SCOPE: &str = "apl:refunds";
    let verifier = verifier();
    let mut claims = claims();
    let check =
        |claims: &Value| verifier.verify_for_resource(&token(claims, "test-1"), AUDIENCE, SCOPE);
    assert_eq!(check(&claims), Err(IdentityError::InsufficientScope));
    for scope in ["apl:refunds.extra", "APL:refunds", "prefix-apl:refunds"] {
        claims["scope"] = json!(scope);
        assert_eq!(check(&claims), Err(IdentityError::InsufficientScope));
    }
    for scope in [
        json!(null),
        json!([]),
        json!(5),
        json!(""),
        json!(" apl:refunds"),
        json!("apl:refunds  other"),
        json!("apl:refunds\tother"),
        json!("apl:refunds other\\"),
    ] {
        claims["scope"] = scope;
        assert_eq!(check(&claims), Err(IdentityError::InvalidToken));
        assert!(verifier.verify(&token(&claims, "test-1")).is_ok());
    }
    claims["scope"] = json!("other apl:refunds another");
    assert!(check(&claims).is_ok());
    assert!(verifier
        .verify_with_scope(&token(&claims, "test-1"), SCOPE)
        .is_ok());
    claims["aud"] = json!([AUDIENCE]);
    assert!(check(&claims).is_ok());
    for audience in [
        json!([AUDIENCE, "other"]),
        json!([AUDIENCE, AUDIENCE]),
        json!("other"),
    ] {
        claims["aud"] = audience;
        assert_eq!(check(&claims), Err(IdentityError::InvalidToken));
    }
    claims["aud"] = json!(AUDIENCE);
    assert_eq!(
        verifier.verify_for_resource(&token(&claims, "test-1"), "other", SCOPE),
        Err(IdentityError::InvalidToken)
    );
    claims["iss"] = json!("wrong");
    claims.as_object_mut().unwrap().remove("scope");
    assert_eq!(check(&claims), Err(IdentityError::InvalidToken));
}
