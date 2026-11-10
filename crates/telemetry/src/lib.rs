//! Bounded process-local telemetry and validated global business snapshots.
mod runtime;
use axum::{
    extract::{MatchedPath, Request, State},
    http::{header, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
pub use runtime::{
    BusinessSnapshot, DecisionCount, ProviderOperation, ProviderResult, TickResult, WorkerQueue,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::Instant,
};
use subtle::ConstantTimeEq;
use tracing::Instrument;
use uuid::Uuid;

const BUCKETS: [f64; 11] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0,
];
const MAX_ROUTES: usize = 128;
const FALLBACK: &str = "__unmatched_or_overflow__";

#[derive(thiserror::Error, Debug)]
pub enum TelemetryError {
    #[error("metrics bearer token must contain at least 32 visible ASCII characters")]
    InvalidToken,
}

/// Deliberately does not implement Debug: its authentication digest is secret material.
pub struct Metrics {
    token_digest: [u8; 32],
    data: Mutex<Data>,
}
#[derive(Default)]
struct Data {
    routes: BTreeSet<String>,
    series: BTreeMap<(String, &'static str, u16), Observation>,
    runtime: runtime::Runtime,
}
#[derive(Default)]
struct Observation {
    count: u64,
    sum: f64,
    buckets: [u64; 11],
}

impl Metrics {
    pub fn new(scrape_token: &str) -> Result<Arc<Self>, TelemetryError> {
        if scrape_token.len() < 32 || !scrape_token.bytes().all(|b| (33..=126).contains(&b)) {
            return Err(TelemetryError::InvalidToken);
        }
        Ok(Arc::new(Self {
            token_digest: Sha256::digest(scrape_token.as_bytes()).into(),
            data: Mutex::new(Data::default()),
        }))
    }

    /// Apply after composing application routes. This installs a protected scrape route.
    pub fn instrument(self: &Arc<Self>, router: Router) -> Router {
        router
            .route("/metrics", get(scrape).with_state(self.clone()))
            .layer(middleware::from_fn_with_state(self.clone(), observe))
    }

    fn record(&self, route: &str, method: &'static str, status: u16, elapsed: f64) {
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let route = if data.routes.contains(route) {
            route
        } else if route != FALLBACK && data.routes.len() < MAX_ROUTES {
            data.routes.insert(route.to_owned());
            route
        } else {
            FALLBACK
        };
        let observation = data
            .series
            .entry((route.to_owned(), method, status))
            .or_default();
        observation.count = observation.count.saturating_add(1);
        observation.sum += elapsed;
        for (i, bound) in BUCKETS.iter().enumerate() {
            if elapsed <= *bound {
                observation.buckets[i] = observation.buckets[i].saturating_add(1);
            }
        }
    }

    fn render(&self) -> String {
        use std::fmt::Write;
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::from("# HELP apl_http_requests_total Completed HTTP requests.\n# TYPE apl_http_requests_total counter\n# HELP apl_http_request_duration_seconds HTTP request duration.\n# TYPE apl_http_request_duration_seconds histogram\n");
        for ((route, method, status), observation) in &data.series {
            let route = route
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let labels =
                format!("route=\"{route}\",method=\"{method}\",status_class=\"{status}xx\"");
            let _ = writeln!(
                out,
                "apl_http_requests_total{{{labels}}} {}",
                observation.count
            );
            for (bound, count) in BUCKETS.iter().zip(observation.buckets) {
                let _ = writeln!(
                    out,
                    "apl_http_request_duration_seconds_bucket{{{labels},le=\"{bound}\"}} {count}"
                );
            }
            let _ = writeln!(
                out,
                "apl_http_request_duration_seconds_bucket{{{labels},le=\"+Inf\"}} {}",
                observation.count
            );
            let _ = writeln!(
                out,
                "apl_http_request_duration_seconds_count{{{labels}}} {}",
                observation.count
            );
            let _ = writeln!(
                out,
                "apl_http_request_duration_seconds_sum{{{labels}}} {}",
                observation.sum
            );
        }
        data.runtime.render(&mut out);
        out
    }
}

async fn scrape(State(metrics): State<Arc<Metrics>>, request: Request) -> Response {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let token = values
        .next()
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let valid = token
        .filter(|t| !t.is_empty() && t.bytes().all(|b| (33..=126).contains(&b)))
        .map(|t| {
            bool::from(
                metrics
                    .token_digest
                    .ct_eq(&Sha256::digest(t.as_bytes())[..]),
            )
        })
        .unwrap_or(false);
    if !valid || values.next().is_some() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics.render(),
    )
        .into_response()
}

fn method_label(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::DELETE => "DELETE",
        Method::OPTIONS => "OPTIONS",
        Method::CONNECT => "CONNECT",
        Method::TRACE => "TRACE",
        _ => "OTHER",
    }
}

async fn observe(State(metrics): State<Arc<Metrics>>, request: Request, next: Next) -> Response {
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned())
        .unwrap_or_else(|| FALLBACK.to_owned());
    let method = method_label(request.method());
    let trace = Uuid::new_v4().to_string();
    let span = tracing::info_span!("http_request", trace_id = %trace);
    let start = Instant::now();
    let mut response = next.run(request).instrument(span).await;
    let elapsed = start.elapsed().as_secs_f64();
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&trace).expect("UUID is a valid header"),
    );
    if route != "/metrics" {
        metrics.record(
            &route,
            method,
            (response.status().as_u16() / 100).clamp(1, 5),
            elapsed,
        );
        tracing::info!(route = %route, method, status = response.status().as_u16(), duration_seconds = elapsed, trace_id = %trace, "HTTP request completed");
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cumulative_buckets_and_route_cap() {
        let metrics = Metrics::new("0123456789abcdef0123456789abcdef").unwrap();
        metrics.record("/known", "GET", 2, 0.003);
        metrics.record("/known", "GET", 2, 0.02);
        {
            let data = metrics.data.lock().unwrap();
            let observation = data.series.get(&("/known".to_owned(), "GET", 2)).unwrap();
            assert_eq!(observation.count, 2);
            assert_eq!(observation.buckets, [0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2]);
            assert!((observation.sum - 0.023).abs() < 1e-10);
        }
        for i in 0..1000 {
            metrics.record(&format!("/route/{i}"), "GET", 2, 0.0);
        }
        let data = metrics.data.lock().unwrap();
        assert_eq!(data.routes.len(), MAX_ROUTES);
        assert_eq!(data.series.len(), MAX_ROUTES + 1);
        assert_eq!(
            data.series
                .get(&(FALLBACK.to_owned(), "GET", 2))
                .unwrap()
                .count,
            873
        );
    }
}
