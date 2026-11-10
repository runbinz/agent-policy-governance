//! Narrow Stripe sandbox adapter. Live secrets, account switching, and replay are excluded.
use apl_dispatch::{
    Currency, EvidenceRef, PaymentFacts, ProviderKey, ProviderOutcome, RefundProvider,
    ReplaySafety, VerifiedPaymentObservation, VerifiedRefundRequest,
};
use reqwest::{header::HeaderValue, Client, Method, RequestBuilder, Url};
use serde::{de::DeserializeOwned, Deserialize, Deserializer};
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

const STRIPE_BASE: &str = "https://api.stripe.com";
const STRIPE_VERSION: &str = "2026-10-28.endive";
const RESPONSE_LIMIT: usize = 256 * 1024;
const PAGE_SIZE: usize = 10;
const MAX_PAGES: usize = 5;
const CORRELATION: &str = "apl_refund_key";

#[derive(Debug, thiserror::Error)]
pub enum StripeError {
    #[error("invalid Stripe sandbox configuration")]
    Configuration,
    #[error("Stripe sandbox account could not be verified")]
    Account,
    #[error("unsupported Stripe sandbox charge or refund amount")]
    Charge,
    #[error("Stripe sandbox request could not be verified")]
    Unverified,
}

#[derive(Clone)]
pub struct StripeSandbox {
    client: Client,
    base: Url,
    authorization: HeaderValue,
    connection_id: Uuid,
    account_id: String,
}

/// Authenticated connector result. Customer scope is private ledger context and
/// must never be included in the public payment projection.
pub struct VerifiedChargeContext {
    pub request: VerifiedRefundRequest,
    pub observation: VerifiedPaymentObservation,
    pub customer_ref: Option<String>,
}

impl StripeSandbox {
    /// Verifies the account that owns the configured test-mode credential.
    pub async fn new(
        key: String,
        connection_id: Uuid,
        expected_account_id: String,
    ) -> Result<Self, StripeError> {
        Self::connect(key, connection_id, expected_account_id, STRIPE_BASE).await
    }

    async fn connect(
        key: String,
        connection_id: Uuid,
        account_id: String,
        base: &str,
    ) -> Result<Self, StripeError> {
        if connection_id.is_nil()
            || !valid_id(&account_id, "acct_")
            || !["sk_test_", "rk_test_"].iter().any(|prefix| {
                key.len() <= 512
                    && key.strip_prefix(prefix).is_some_and(|suffix| {
                        !suffix.is_empty()
                            && suffix.bytes().all(|byte| byte.is_ascii_alphanumeric())
                    })
            })
        {
            return Err(StripeError::Configuration);
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {key}"))
            .map_err(|_| StripeError::Configuration)?;
        authorization.set_sensitive(true);
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(4))
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .no_proxy()
            .build()
            .map_err(|_| StripeError::Configuration)?;
        let adapter = Self {
            client,
            base: Url::parse(base).map_err(|_| StripeError::Configuration)?,
            authorization,
            connection_id,
            account_id,
        };
        let account: Account = read(adapter.request(Method::GET, "/v1/account")?)
            .await
            .map_err(|_| StripeError::Account)?;
        if account.object != "account" || account.id != adapter.account_id {
            return Err(StripeError::Account);
        }
        Ok(adapter)
    }

    /// Reads authoritative payment and customer facts for the exact charge.
    pub async fn verify_charge(
        &self,
        payment_id: &str,
        amount_minor: u32,
        observed_at: u64,
        fresh_until: u64,
    ) -> Result<(VerifiedRefundRequest, Option<String>), StripeError> {
        let context = self
            .verify_charge_context(payment_id, amount_minor, observed_at, fresh_until)
            .await?;
        Ok((context.request, context.customer_ref))
    }

    /// Retains facts from the authenticated read, using the supplied read-start
    /// bounds unchanged so time spent on the network consumes freshness.
    pub async fn verify_charge_context(
        &self,
        payment_id: &str,
        amount_minor: u32,
        observed_at: u64,
        fresh_until: u64,
    ) -> Result<VerifiedChargeContext, StripeError> {
        let request = VerifiedRefundRequest::new(
            self.connection_id,
            payment_id.to_owned(),
            amount_minor,
            Currency::Usd,
            observed_at,
            fresh_until,
        )
        .map_err(|_| StripeError::Charge)?;
        let charge = self.read_charge(payment_id).await?;
        if !charge.eligible(amount_minor) {
            return Err(StripeError::Charge);
        }
        let observation = VerifiedPaymentObservation::new(
            request.clone(),
            PaymentFacts {
                charge_amount_minor: charge.amount,
                captured_minor: charge.amount_captured,
                refunded_minor: charge.amount_refunded,
                paid: charge.paid,
                captured: charge.captured,
                disputed: charge.disputed,
                direct_charge: true,
                status: charge.status,
                method: charge
                    .payment_method_details
                    .ok_or(StripeError::Charge)?
                    .kind,
            },
        )
        .map_err(|_| StripeError::Charge)?;
        Ok(VerifiedChargeContext {
            request,
            observation,
            customer_ref: charge.customer,
        })
    }

    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder, StripeError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| StripeError::Configuration)?;
        Ok(self
            .client
            .request(method, url)
            .header("Authorization", self.authorization.clone())
            .header("Stripe-Version", STRIPE_VERSION))
    }

    async fn read_charge(&self, payment_id: &str) -> Result<Charge, StripeError> {
        if !valid_id(payment_id, "ch_") {
            return Err(StripeError::Charge);
        }
        let charge: Charge =
            read(self.request(Method::GET, &format!("/v1/charges/{payment_id}"))?).await?;
        if charge.object != "charge"
            || charge.id != payment_id
            || charge
                .customer
                .as_ref()
                .is_some_and(|id| !valid_id(id, "cus_"))
        {
            return Err(StripeError::Unverified);
        }
        if charge.livemode || charge.currency != "usd" {
            return Err(StripeError::Charge);
        }
        Ok(charge)
    }

    async fn create_refund(
        &self,
        request: &VerifiedRefundRequest,
        key: &ProviderKey,
    ) -> Result<ProviderOutcome, StripeError> {
        if request.connection_id() != self.connection_id
            || !self
                .read_charge(request.payment_id())
                .await?
                .eligible(request.amount_minor())
        {
            return Err(StripeError::Charge);
        }
        let amount = request.amount_minor().to_string();
        let refund: Refund = read(
            self.request(Method::POST, "/v1/refunds")?
                .header("Idempotency-Key", key.as_str())
                .form(&[
                    ("charge", request.payment_id()),
                    ("amount", &amount),
                    ("metadata[apl_refund_key]", key.as_str()),
                ]),
        )
        .await?;
        self.correlate(&refund, request, key)
    }

    async fn list_refunds(
        &self,
        request: &VerifiedRefundRequest,
        key: &ProviderKey,
    ) -> Result<ProviderOutcome, StripeError> {
        if request.connection_id() != self.connection_id {
            return Err(StripeError::Charge);
        }
        // Refund objects do not publish livemode. Establish it from the exact charge
        // under the same account before trusting any refund from that account.
        self.read_charge(request.payment_id()).await?;
        let mut cursor: Option<String> = None;
        let mut matched = None;
        for _ in 0..MAX_PAGES {
            let mut query = self
                .request(Method::GET, "/v1/refunds")?
                .query(&[("charge", request.payment_id()), ("limit", "10")]);
            if let Some(cursor) = &cursor {
                query = query.query(&[("starting_after", cursor)]);
            }
            let page: RefundPage = read(query).await?;
            if page.object != "list" || page.data.len() > PAGE_SIZE {
                return Err(StripeError::Unverified);
            }
            for refund in &page.data {
                if refund
                    .metadata
                    .get(CORRELATION)
                    .is_some_and(|value| value == key.as_str())
                {
                    if matched.is_some() {
                        return Err(StripeError::Unverified);
                    }
                    matched = Some(self.correlate(refund, request, key)?);
                }
            }
            if !page.has_more {
                return Ok(matched.unwrap_or(ProviderOutcome::Unknown));
            }
            let next = &page.data.last().ok_or(StripeError::Unverified)?.id;
            if !valid_id(next, "re_") || cursor.as_ref() == Some(next) {
                return Err(StripeError::Unverified);
            }
            cursor = Some(next.clone());
        }
        // A partial scan cannot rule out a second correlated refund.
        Ok(ProviderOutcome::Unknown)
    }

    fn correlate(
        &self,
        refund: &Refund,
        request: &VerifiedRefundRequest,
        key: &ProviderKey,
    ) -> Result<ProviderOutcome, StripeError> {
        if refund.object != "refund"
            || !valid_id(&refund.id, "re_")
            || refund.livemode == Some(true)
            || refund.charge.as_deref() != Some(request.payment_id())
            || refund.currency != "usd"
            || refund.amount != request.amount_minor()
            || refund.metadata.get(CORRELATION).map(String::as_str) != Some(key.as_str())
        {
            return Err(StripeError::Unverified);
        }
        let evidence = || {
            EvidenceRef::new(format!("stripe:{}:{}", self.account_id, refund.id))
                .map_err(|_| StripeError::Unverified)
        };
        Ok(match refund.status.as_deref() {
            Some("succeeded") => ProviderOutcome::ConfirmedSuccess(evidence()?),
            Some("failed" | "canceled") => ProviderOutcome::ConfirmedNonExecution(evidence()?),
            Some("pending" | "requires_action") => ProviderOutcome::Pending,
            _ => ProviderOutcome::Unknown,
        })
    }
}

impl RefundProvider for StripeSandbox {
    fn replay_safety(&self) -> ReplaySafety {
        ReplaySafety::ReconcileOnly
    }
    async fn execute(&self, request: &VerifiedRefundRequest, key: &ProviderKey) -> ProviderOutcome {
        self.create_refund(request, key)
            .await
            .unwrap_or(ProviderOutcome::Unknown)
    }
    async fn reconcile(
        &self,
        request: &VerifiedRefundRequest,
        key: &ProviderKey,
    ) -> ProviderOutcome {
        self.list_refunds(request, key)
            .await
            .unwrap_or(ProviderOutcome::Unknown)
    }
}

fn valid_id(value: &str, prefix: &str) -> bool {
    value.len() <= 96
        && value.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_alphanumeric())
        })
}

async fn read<T: DeserializeOwned>(request: RequestBuilder) -> Result<T, StripeError> {
    let mut response = request.send().await.map_err(|_| StripeError::Unverified)?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|n| n > RESPONSE_LIMIT as u64)
    {
        return Err(StripeError::Unverified);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| StripeError::Unverified)?
    {
        if chunk.len() > RESPONSE_LIMIT - bytes.len() {
            return Err(StripeError::Unverified);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| StripeError::Unverified)
}

#[derive(Deserialize)]
struct Account {
    id: String,
    object: String,
}

#[derive(Deserialize)]
struct Charge {
    id: String,
    object: String,
    livemode: bool,
    currency: String,
    amount: u64,
    amount_captured: u64,
    amount_refunded: u64,
    captured: bool,
    paid: bool,
    disputed: bool,
    status: String,
    payment_method_details: Option<PaymentMethod>,
    #[serde(deserialize_with = "required_customer")]
    customer: Option<String>,
    on_behalf_of: Option<String>,
    transfer: Option<String>,
    transfer_data: Option<serde_json::Value>,
    source_transfer: Option<String>,
}
fn required_customer<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::deserialize(deserializer)
}
impl Charge {
    fn eligible(&self, amount: u32) -> bool {
        self.captured
            && self.paid
            && !self.disputed
            && self.status == "succeeded"
            && self.amount_captured <= self.amount
            && self
                .payment_method_details
                .as_ref()
                .is_some_and(|details| details.kind == "card")
            && self
                .amount_captured
                .checked_sub(self.amount_refunded)
                .is_some_and(|remaining| remaining >= u64::from(amount))
            && self.on_behalf_of.is_none()
            && self.transfer.is_none()
            && self.transfer_data.is_none()
            && self.source_transfer.is_none()
    }
}
#[derive(Deserialize)]
struct PaymentMethod {
    #[serde(rename = "type")]
    kind: String,
}
#[derive(Deserialize)]
struct Refund {
    id: String,
    object: String,
    livemode: Option<bool>,
    charge: Option<String>,
    currency: String,
    amount: u32,
    metadata: BTreeMap<String, String>,
    status: Option<String>,
}
#[derive(Deserialize)]
struct RefundPage {
    object: String,
    data: Vec<Refund>,
    has_more: bool,
}

#[cfg(test)]
mod tests;
