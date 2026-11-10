//! Authenticate Stripe sandbox snapshot events for reconciliation wake-up only.

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::value::RawValue;
use sha2::Sha256;
use subtle::{Choice, ConstantTimeEq};

pub const MAX_BODY_BYTES: usize = 256 * 1024;
pub const MAX_SIGNATURE_HEADER_BYTES: usize = 4096;
pub const MAX_TIMESTAMP_SKEW_SECONDS: u64 = 300;
const MAX_V1_SIGNATURES: usize = 8;
const MAX_HEADER_FIELDS: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccountPolicy {
    Direct,
    Connected(String),
}

/// Only authenticated Stripe event metadata. A refund snapshot is a wake hint,
/// not terminal provider evidence, even if the payload reports success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEvent {
    pub event_id: String,
    pub event_type: String,
    pub account: Option<String>,
    pub refund: Option<RefundWake>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefundWake {
    pub refund_id: String,
    pub charge_id: String,
    /// An untrusted lookup hint. Match the persisted provider namespace,
    /// immutable charge and key before waking an existing dispatch.
    pub correlation: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WebhookError {
    #[error("invalid webhook verifier configuration")]
    InvalidConfiguration,
    #[error("webhook body is too large")]
    BodyTooLarge,
    #[error("invalid webhook signature header")]
    InvalidHeader,
    #[error("webhook signature did not match")]
    InvalidSignature,
    #[error("webhook signature timestamp is outside the allowed window")]
    StaleTimestamp,
    #[error("invalid webhook event")]
    InvalidEvent,
    #[error("live webhook events are not supported")]
    LiveEvent,
    #[error("webhook account is outside the configured endpoint scope")]
    AccountMismatch,
}

#[derive(Clone)]
pub struct WebhookVerifier {
    mac: Hmac<Sha256>,
    account: AccountPolicy,
}

impl WebhookVerifier {
    pub fn new(endpoint_secret: &str, account: AccountPolicy) -> Result<Self, WebhookError> {
        if !endpoint_secret.starts_with("whsec_")
            || endpoint_secret.len() <= "whsec_".len()
            || endpoint_secret.len() > 256
            || !endpoint_secret.bytes().all(|byte| byte.is_ascii_graphic())
            || matches!(&account, AccountPolicy::Connected(id) if !provider_id(id, "acct_"))
        {
            return Err(WebhookError::InvalidConfiguration);
        }
        let mac = Hmac::new_from_slice(endpoint_secret.as_bytes())
            .map_err(|_| WebhookError::InvalidConfiguration)?;
        Ok(Self { mac, account })
    }

    /// The timestamp is trusted caller time in Unix seconds; the header's t
    /// value is signed, and is checked in both directions.
    pub fn verify(
        &self,
        raw_body: &[u8],
        signature_header: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedEvent, WebhookError> {
        if raw_body.len() > MAX_BODY_BYTES {
            return Err(WebhookError::BodyTooLarge);
        }
        let header = parse_header(signature_header)?;
        let mut mac = self.mac.clone();
        mac.update(header.timestamp_text.as_bytes());
        mac.update(b".");
        mac.update(raw_body);
        let expected = mac.finalize().into_bytes();
        let matched = header
            .signatures
            .iter()
            .fold(Choice::from(0), |matched, candidate| {
                matched | expected.as_slice().ct_eq(candidate.as_slice())
            });
        if !bool::from(matched) {
            return Err(WebhookError::InvalidSignature);
        }
        if now_unix_seconds.abs_diff(header.timestamp) > MAX_TIMESTAMP_SKEW_SECONDS {
            return Err(WebhookError::StaleTimestamp);
        }

        let event: Event =
            serde_json::from_slice(raw_body).map_err(|_| WebhookError::InvalidEvent)?;
        if event.livemode {
            return Err(WebhookError::LiveEvent);
        }
        // Organization-scoped events require a separate trusted context policy.
        if event.context.is_some()
            || !match (&self.account, &event.account) {
                (AccountPolicy::Direct, None) => true,
                (AccountPolicy::Connected(expected), Some(actual)) => expected == actual,
                _ => false,
            }
        {
            return Err(WebhookError::AccountMismatch);
        }
        if event.object != "event"
            || !provider_id(&event.id, "evt_")
            || event.kind.is_empty()
            || event.kind.len() > 128
            || !event
                .kind
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._".contains(&byte))
            || !event.data.object.get().starts_with('{')
        {
            return Err(WebhookError::InvalidEvent);
        }
        let refund = match event.kind.as_str() {
            "refund.created" | "refund.updated" | "refund.failed" | "charge.refund.updated" => {
                refund_hint(event.data.object.get())?
            }
            _ => None,
        };
        Ok(VerifiedEvent {
            event_id: event.id,
            event_type: event.kind,
            account: event.account,
            refund,
        })
    }
}

struct SignatureHeader<'a> {
    timestamp: u64,
    timestamp_text: &'a str,
    signatures: Vec<[u8; 32]>,
}

fn parse_header(input: &str) -> Result<SignatureHeader<'_>, WebhookError> {
    let invalid = WebhookError::InvalidHeader;
    if input.len() > MAX_SIGNATURE_HEADER_BYTES
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t'))
    {
        return Err(invalid);
    }
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for (index, part) in input.split(',').enumerate() {
        if index >= MAX_HEADER_FIELDS {
            return Err(invalid);
        }
        let (scheme, value) = part.trim().split_once('=').ok_or(invalid)?;
        if scheme.is_empty() || value.is_empty() {
            return Err(invalid);
        }
        match scheme {
            "t" => {
                if timestamp.is_some() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(invalid);
                }
                timestamp = Some((value.parse().map_err(|_| invalid)?, value));
            }
            "v1" => {
                if signatures.len() == MAX_V1_SIGNATURES {
                    return Err(invalid);
                }
                signatures.push(decode_signature(value).ok_or(invalid)?);
            }
            _ => {}
        }
    }
    let (timestamp, timestamp_text) = timestamp.ok_or(invalid)?;
    if signatures.is_empty() {
        return Err(invalid);
    }
    Ok(SignatureHeader {
        timestamp,
        timestamp_text,
        signatures,
    })
}

fn decode_signature(value: &str) -> Option<[u8; 32]> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut result = [0_u8; 32];
    for (out, pair) in result.iter_mut().zip(bytes.chunks_exact(2)) {
        *out = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Some(result)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn provider_id(value: &str, prefix: &str) -> bool {
    value.len() <= 255
        && value.strip_prefix(prefix).is_some_and(|tail| {
            !tail.is_empty()
                && tail
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

#[derive(Deserialize)]
struct Event<'a> {
    id: String,
    object: String,
    #[serde(rename = "type")]
    kind: String,
    account: Option<String>,
    context: Option<String>,
    livemode: bool,
    #[serde(borrow)]
    data: EventData<'a>,
}

#[derive(Deserialize)]
struct EventData<'a> {
    #[serde(borrow)]
    object: &'a RawValue,
}

#[derive(Deserialize)]
struct Refund {
    id: String,
    object: String,
    charge: Option<Charge>,
    metadata: Option<Metadata>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Charge {
    Id(String),
    Expanded { id: String },
}

#[derive(Deserialize)]
struct Metadata {
    apl_refund_key: Option<String>,
}

fn refund_hint(raw: &str) -> Result<Option<RefundWake>, WebhookError> {
    let refund: Refund = serde_json::from_str(raw).map_err(|_| WebhookError::InvalidEvent)?;
    if refund.object != "refund" || !provider_id(&refund.id, "re_") {
        return Err(WebhookError::InvalidEvent);
    }
    let charge_id = match refund.charge {
        Some(Charge::Id(id) | Charge::Expanded { id }) if provider_id(&id, "ch_") => id,
        // Stripe's charge is nullable. It cannot wake our charge-based connector.
        None => return Ok(None),
        _ => return Err(WebhookError::InvalidEvent),
    };
    let correlation = refund
        .metadata
        .and_then(|metadata| metadata.apl_refund_key)
        .filter(|key| {
            key.len() <= 255 && !key.is_empty() && key.bytes().all(|byte| byte.is_ascii_graphic())
        });
    Ok(Some(RefundWake {
        refund_id: refund.id,
        charge_id,
        correlation,
    }))
}
