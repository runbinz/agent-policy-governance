//! Structurally validated payment facts. Network provenance belongs to the connector.
use crate::{DispatchError, VerifiedRefundRequest};
use serde::{Deserialize, Serialize};

const MAX_JSON_INTEGER: u64 = 9_007_199_254_740_991;
// Last millisecond of RFC3339's four-digit year 9999.
const MAX_RFC3339_MS: u64 = 253_402_300_799_999;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentFacts {
    pub charge_amount_minor: u64,
    pub captured_minor: u64,
    pub refunded_minor: u64,
    pub paid: bool,
    pub captured: bool,
    pub disputed: bool,
    pub direct_charge: bool,
    pub status: String,
    pub method: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "StoredObservation")]
pub struct VerifiedPaymentObservation {
    schema_version: u8,
    request: VerifiedRefundRequest,
    facts: PaymentFacts,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredObservation {
    schema_version: u8,
    request: VerifiedRefundRequest,
    facts: PaymentFacts,
}

impl TryFrom<StoredObservation> for VerifiedPaymentObservation {
    type Error = DispatchError;
    fn try_from(value: StoredObservation) -> Result<Self, Self::Error> {
        if value.schema_version != 1 {
            return Err(DispatchError::InvalidRequest);
        }
        Self::new(value.request, value.facts)
    }
}

impl VerifiedPaymentObservation {
    /// Validates consistency only; callers must establish authenticated provenance.
    pub fn new(request: VerifiedRefundRequest, facts: PaymentFacts) -> Result<Self, DispatchError> {
        let interval = request.fresh_until().checked_sub(request.observed_at());
        if !interval.is_some_and(|ms| (1..=30_000).contains(&ms))
            || request.fresh_until() > MAX_RFC3339_MS
            || facts.charge_amount_minor > MAX_JSON_INTEGER
            || facts.captured_minor > facts.charge_amount_minor
            || facts
                .captured_minor
                .checked_sub(facts.refunded_minor)
                .is_none_or(|remaining| remaining < u64::from(request.amount_minor()))
            || !facts.paid
            || !facts.captured
            || facts.disputed
            || !facts.direct_charge
            || facts.status != "succeeded"
            || facts.method != "card"
        {
            return Err(DispatchError::InvalidRequest);
        }
        Ok(Self {
            schema_version: 1,
            request,
            facts,
        })
    }
    pub fn schema_version(&self) -> u8 {
        self.schema_version
    }
    pub fn request(&self) -> &VerifiedRefundRequest {
        &self.request
    }
    pub fn facts(&self) -> &PaymentFacts {
        &self.facts
    }
    pub fn remaining_minor(&self) -> u64 {
        // The constructor and deserializer checked this subtraction.
        self.facts.captured_minor - self.facts.refunded_minor
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Currency;
    use serde_json::json;
    use uuid::Uuid;

    fn request(start: u64, end: u64) -> VerifiedRefundRequest {
        VerifiedRefundRequest::new(
            Uuid::new_v4(),
            "ch_example".into(),
            2500,
            Currency::Usd,
            start,
            end,
        )
        .unwrap()
    }
    fn facts() -> PaymentFacts {
        PaymentFacts {
            charge_amount_minor: 5000,
            captured_minor: 5000,
            refunded_minor: 1000,
            paid: true,
            captured: true,
            disputed: false,
            direct_charge: true,
            status: "succeeded".into(),
            method: "card".into(),
        }
    }
    #[test]
    fn validates_roundtrip_and_exact_request_times() {
        let request = request(100, 30_100);
        let observation = VerifiedPaymentObservation::new(request.clone(), facts()).unwrap();
        assert_eq!(observation.request(), &request);
        assert_eq!(observation.remaining_minor(), 4000);
        assert!(!observation.request().is_fresh(30_100));
        let value = serde_json::to_value(&observation).unwrap();
        assert_eq!(
            serde_json::from_value::<VerifiedPaymentObservation>(value.clone()).unwrap(),
            observation
        );
        for (path, invalid) in [("schema_version", json!(2)), ("extra", json!(true))] {
            let mut bad = value.clone();
            bad[path] = invalid;
            assert!(serde_json::from_value::<VerifiedPaymentObservation>(bad).is_err());
        }
        for (field, invalid) in [
            ("charge_amount_minor", json!(MAX_JSON_INTEGER + 1)),
            ("captured_minor", json!(5001)),
            ("refunded_minor", json!(5001)),
            ("paid", json!(false)),
            ("captured", json!(false)),
            ("disputed", json!(true)),
            ("direct_charge", json!(false)),
            ("status", json!("pending")),
            ("method", json!("bank")),
        ] {
            let mut bad = value.clone();
            bad["facts"][field] = invalid;
            assert!(
                serde_json::from_value::<VerifiedPaymentObservation>(bad).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn rejects_impossible_money_and_time_bounds() {
        for (start, end) in [
            (0, 30_001),
            (MAX_RFC3339_MS, MAX_RFC3339_MS + 1),
            (u64::MAX - 1, u64::MAX),
        ] {
            assert!(VerifiedPaymentObservation::new(request(start, end), facts()).is_err());
        }
        let mut invalid = facts();
        invalid.refunded_minor = 2501;
        assert!(VerifiedPaymentObservation::new(request(1, 2), invalid).is_err());
        let mut boundary = facts();
        boundary.charge_amount_minor = MAX_JSON_INTEGER;
        boundary.captured_minor = MAX_JSON_INTEGER;
        boundary.refunded_minor = MAX_JSON_INTEGER - 2500;
        assert!(VerifiedPaymentObservation::new(
            request(MAX_RFC3339_MS - 1, MAX_RFC3339_MS),
            boundary
        )
        .is_ok());
    }
}
