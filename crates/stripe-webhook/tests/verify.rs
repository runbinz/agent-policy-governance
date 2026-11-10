use apl_stripe_webhook::{
    AccountPolicy, RefundWake, WebhookError, WebhookVerifier, MAX_BODY_BYTES,
    MAX_SIGNATURE_HEADER_BYTES,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const SECRET: &str = "whsec_fixture_only";
const NOW: u64 = 1_800_000_000;
const BODY: &[u8] = br#"{
  "id":"evt_example", "type":"refund.updated", "object":"event", "livemode":false,
  "data":{"object":{"id":"re_example","object":"refund","charge":"ch_example",
  "metadata":{"apl_refund_key":"apl-refund-v1-example"},"status":"succeeded"}}
}"#;

fn signature(secret: &str, body: &[u8], time: u64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{time}.").as_bytes());
    mac.update(body);
    format!("{:x}", mac.finalize().into_bytes())
}

fn header(secret: &str, body: &[u8], time: u64) -> String {
    format!("t={time},v1={}", signature(secret, body, time))
}

fn direct() -> WebhookVerifier {
    WebhookVerifier::new(SECRET, AccountPolicy::Direct).unwrap()
}

#[test]
fn extracts_only_a_refund_wake_hint_from_the_exact_signed_body() {
    let headers = header(SECRET, BODY, NOW);
    let result = direct().verify(BODY, &headers, NOW).unwrap();
    assert_eq!(result.event_id, "evt_example");
    assert_eq!(result.event_type, "refund.updated");
    assert_eq!(result.account, None);
    assert_eq!(
        result.refund,
        Some(RefundWake {
            refund_id: "re_example".into(),
            charge_id: "ch_example".into(),
            correlation: Some("apl-refund-v1-example".into()),
        })
    );
    let mut mutated = BODY.to_vec();
    mutated.push(b' ');
    assert_eq!(
        direct().verify(&mutated, &headers, NOW),
        Err(WebhookError::InvalidSignature)
    );
}

#[test]
fn accepts_any_matching_v1_during_rotation_but_never_v0() {
    let old = signature("whsec_old", BODY, NOW);
    let new = signature(SECRET, BODY, NOW);
    for values in [format!("v1={old},v1={new}"), format!("v1={new},v1={old}")] {
        assert!(direct()
            .verify(BODY, &format!("t={NOW},v0={old},{values}"), NOW)
            .is_ok());
    }
    assert_eq!(
        direct().verify(BODY, &format!("t={NOW},v1={old},v0={new}"), NOW),
        Err(WebhookError::InvalidSignature)
    );
}

#[test]
fn enforces_inclusive_clock_skew_in_both_directions() {
    let verifier = direct();
    for timestamp in [NOW - 300, NOW + 300] {
        assert!(verifier
            .verify(BODY, &header(SECRET, BODY, timestamp), NOW)
            .is_ok());
    }
    for timestamp in [NOW - 301, NOW + 301, u64::MAX] {
        assert_eq!(
            verifier.verify(BODY, &header(SECRET, BODY, timestamp), NOW),
            Err(WebhookError::StaleTimestamp)
        );
    }
}

#[test]
fn rejects_ambiguous_malformed_and_unbounded_inputs() {
    let sig = signature(SECRET, BODY, NOW);
    for invalid in [
        String::new(),
        format!("t={NOW},t={NOW},v1={sig}"),
        format!("t=+{NOW},v1={sig}"),
        format!("t=18446744073709551616,v1={sig}"),
        format!("t={NOW},v0={sig}"),
        format!("t={NOW},v1=nope"),
        format!("t={NOW},v1={}", "z".repeat(64)),
        format!("t={NOW}{}", format!(",v1={sig}").repeat(9)),
        format!("t={NOW},v1={sig}{}", ",v0=z".repeat(31)),
        format!("t={NOW},v1={sig},v0=\n"),
        "x".repeat(MAX_SIGNATURE_HEADER_BYTES + 1),
    ] {
        assert_eq!(
            direct().verify(BODY, &invalid, NOW),
            Err(WebhookError::InvalidHeader)
        );
    }
    assert_eq!(
        direct().verify(
            &vec![0; MAX_BODY_BYTES + 1],
            &header(SECRET, BODY, NOW),
            NOW
        ),
        Err(WebhookError::BodyTooLarge)
    );
}

#[test]
fn enforces_endpoint_scope_and_sandbox_mode() {
    let raw = |change: &str| {
        String::from_utf8(BODY.to_vec())
            .unwrap()
            .replace(r#""livemode":false"#, change)
    };
    let connected = raw(r#""livemode":false,"account":"acct_example""#);
    let other = raw(r#""livemode":false,"account":"acct_other""#);
    let organization = raw(r#""livemode":false,"context":"org_example""#);
    let live = raw(r#""livemode":true"#);
    let connected_verifier =
        WebhookVerifier::new(SECRET, AccountPolicy::Connected("acct_example".into())).unwrap();
    let verify = |verifier: &WebhookVerifier, body: &[u8]| {
        verifier.verify(body, &header(SECRET, body, NOW), NOW)
    };
    assert!(verify(&connected_verifier, connected.as_bytes()).is_ok());
    assert_eq!(
        verify(&connected_verifier, other.as_bytes()),
        Err(WebhookError::AccountMismatch)
    );
    assert_eq!(
        verify(&connected_verifier, BODY),
        Err(WebhookError::AccountMismatch)
    );
    assert_eq!(
        verify(&direct(), connected.as_bytes()),
        Err(WebhookError::AccountMismatch)
    );
    assert_eq!(
        verify(&direct(), organization.as_bytes()),
        Err(WebhookError::AccountMismatch)
    );
    assert_eq!(
        verify(&direct(), live.as_bytes()),
        Err(WebhookError::LiveEvent)
    );
}

#[test]
fn authenticates_unrelated_events_but_rejects_malformed_refund_snapshots() {
    let text = std::str::from_utf8(BODY).unwrap();
    let verify =
        |body: &str| direct().verify(body.as_bytes(), &header(SECRET, body.as_bytes(), NOW), NOW);
    for input in [
        text.replace("refund.updated", "charge.refunded"),
        text.replace(r#""charge":"ch_example""#, r#""charge":null"#),
    ] {
        assert_eq!(verify(&input).unwrap().refund, None);
    }
    for input in [
        text.replace(
            r#""livemode":false"#,
            r#""livemode":false,"livemode":false"#,
        ),
        text.replace(r#""object":"refund""#, r#""object":"charge""#),
        text.replace(r#""charge":"ch_example""#, r#""charge":"pi_example""#),
        "not JSON".into(),
    ] {
        assert_eq!(verify(&input), Err(WebhookError::InvalidEvent));
    }
    let input = text.replace(
        r#""charge":"ch_example""#,
        r#""charge":{"id":"ch_expanded"}"#,
    );
    assert_eq!(
        verify(&input).unwrap().refund.unwrap().charge_id,
        "ch_expanded"
    );
}
