//! Stateless, JSON-only Streamable HTTP MCP resource for workload refunds.
use super::bearer;
use apl_domain::{Action, RefundRequest};
use apl_identity::{IdentityError, JwtVerifier, ManagedJwtVerifier, VerifiedIdentity};
use apl_persistence::{Store, StoreError};
use axum::{
    body::Bytes,
    extract::{rejection::BytesRejection, DefaultBodyLimit, Request, State},
    http::{header, uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{
    de::{self, DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer,
};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const PROTOCOL_VERSION: &str = "2025-11-25";
pub const REQUIRED_SCOPE: &str = "apl:refunds";
const METADATA_PATH: &str = "/.well-known/oauth-protected-resource/mcp";
const BODY_LIMIT: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("invalid MCP HTTPS resource, issuer, or allowed origin")]
pub struct McpConfigError;

#[derive(Clone)]
pub struct McpConfig {
    resource: String,
    issuer: String,
    authority: Authority,
    origins: BTreeSet<String>,
    challenge: HeaderValue,
    scope_challenge: HeaderValue,
}

impl McpConfig {
    pub fn new(
        resource: &str,
        issuer: &str,
        allowed_origins: &[String],
    ) -> Result<Self, McpConfigError> {
        let uri = trusted_https(resource)?;
        if uri.path() != "/mcp" {
            return Err(McpConfigError);
        }
        trusted_https(issuer)?;
        let authority = uri.authority().cloned().ok_or(McpConfigError)?;
        let mut origins = BTreeSet::new();
        for origin in allowed_origins {
            let origin_uri = trusted_https(origin)?;
            let origin_authority = origin_uri.authority().ok_or(McpConfigError)?;
            if origin != &format!("https://{origin_authority}") {
                return Err(McpConfigError);
            }
            origins.insert(origin.clone());
        }
        let fields = format!(
            "resource_metadata=\"https://{authority}{METADATA_PATH}\", scope=\"{REQUIRED_SCOPE}\""
        );
        let challenge =
            HeaderValue::from_str(&format!("Bearer {fields}")).map_err(|_| McpConfigError)?;
        let scope_challenge =
            HeaderValue::from_str(&format!("Bearer error=\"insufficient_scope\", {fields}"))
                .map_err(|_| McpConfigError)?;
        Ok(Self {
            resource: resource.into(),
            issuer: issuer.into(),
            authority,
            origins,
            challenge,
            scope_challenge,
        })
    }
}

fn trusted_https(value: &str) -> Result<Uri, McpConfigError> {
    if value.len() > 2048
        || !value.starts_with("https://")
        || value.contains(['#', '"', '\\'])
        || !value.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(McpConfigError);
    }
    let uri = value.parse::<Uri>().map_err(|_| McpConfigError)?;
    let authority = uri.authority().ok_or(McpConfigError)?;
    if uri.scheme_str() != Some("https")
        || uri.query().is_some()
        || authority.as_str().contains('@')
        || authority.host().is_empty()
        || authority.host().contains('%')
    {
        return Err(McpConfigError);
    }
    Ok(uri)
}

#[derive(Clone)]
pub enum McpVerifier {
    Managed(ManagedJwtVerifier),
    /// Explicit injection for signed integration fixtures; startup uses managed discovery.
    Static(Box<JwtVerifier>),
}

impl McpVerifier {
    fn verify(&self, token: &str, resource: &str) -> Result<VerifiedIdentity, IdentityError> {
        match self {
            Self::Managed(verifier) => {
                verifier.verify_for_resource(token, resource, REQUIRED_SCOPE)
            }
            Self::Static(verifier) => verifier.verify_for_resource(token, resource, REQUIRED_SCOPE),
        }
    }
}

#[derive(Clone)]
struct McpState {
    store: Store,
    verifier: McpVerifier,
    config: McpConfig,
    tool_limit: Arc<Mutex<ToolWindow>>,
}

// No protocol sessions or affinity: this is a bounded abuse guard per process.
// A multi-instance deployment should also enforce rate limits at the ingress.
const TOOL_WINDOW: Duration = Duration::from_secs(60);
const TOOL_LIMIT: u16 = 60;
const WORKLOAD_LIMIT: usize = 4096;

struct ToolWindow {
    started: Instant,
    counts: HashMap<(Uuid, Uuid, Uuid), u16>,
}
impl ToolWindow {
    fn new(started: Instant) -> Self {
        Self {
            started,
            counts: HashMap::new(),
        }
    }
    fn admit(&mut self, workload: (Uuid, Uuid, Uuid), now: Instant) -> Result<(), u64> {
        if now.duration_since(self.started) >= TOOL_WINDOW {
            self.started = now;
            self.counts.clear();
        }
        let retry = || {
            TOOL_WINDOW
                .saturating_sub(now.duration_since(self.started))
                .as_secs()
                .max(1)
        };
        if let Some(count) = self.counts.get_mut(&workload) {
            if *count >= TOOL_LIMIT {
                return Err(retry());
            }
            *count += 1;
        } else {
            if self.counts.len() >= WORKLOAD_LIMIT {
                return Err(retry());
            }
            self.counts.insert(workload, 1);
        }
        Ok(())
    }
}

pub fn router(store: Store, verifier: McpVerifier, config: McpConfig) -> Router {
    Router::new()
        .route("/mcp", post(rpc).options(preflight))
        .route(METADATA_PATH, get(metadata).options(preflight))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(middleware::from_fn_with_state(
            config.clone(),
            guard_transport,
        ))
        .with_state(McpState {
            store,
            verifier,
            config,
            tool_limit: Arc::new(Mutex::new(ToolWindow::new(Instant::now()))),
        })
}

async fn guard_transport(
    State(config): State<McpConfig>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().query().is_some() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let headers = request.headers();
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = hosts.next();
    let uri_authority = request.uri().authority();
    let matches = |authority: &str| authority.eq_ignore_ascii_case(config.authority.as_str());
    if (host.is_none() && uri_authority.is_none())
        || hosts.next().is_some()
        || host.is_some_and(|host| !host.to_str().is_ok_and(matches))
        || uri_authority.is_some_and(|authority| !matches(authority.as_str()))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut origins = headers.get_all(header::ORIGIN).iter();
    let origin = origins.next();
    if origins.next().is_some()
        || origin.is_some_and(|origin| {
            !origin
                .to_str()
                .is_ok_and(|origin| config.origins.contains(origin))
        })
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let origin = origin.cloned();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.append(header::VARY, HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type, MCP-Protocol-Version"),
        );
        headers.insert(
            header::ACCESS_CONTROL_EXPOSE_HEADERS,
            HeaderValue::from_static("WWW-Authenticate"),
        );
    }
    response
}

async fn preflight() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn metadata(State(state): State<McpState>) -> Json<Value> {
    Json(
        json!({"resource":state.config.resource,"authorization_servers":[state.config.issuer],
        "scopes_supported":[REQUIRED_SCOPE],"bearer_methods_supported":["header"]}),
    )
}

fn challenge(config: &McpConfig, insufficient_scope: bool) -> Response {
    let (status, challenge) = if insufficient_scope {
        (StatusCode::FORBIDDEN, &config.scope_challenge)
    } else {
        (StatusCode::UNAUTHORIZED, &config.challenge)
    };
    (status, [(header::WWW_AUTHENTICATE, challenge.clone())]).into_response()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    jsonrpc: String,
    method: String,
    #[serde(default, deserialize_with = "present")]
    id: Option<Value>,
    #[serde(default, deserialize_with = "present")]
    params: Option<Value>,
}
fn present<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Value>, D::Error> {
    UniqueJson::deserialize(d).map(|value| Some(value.0))
}

// JSON object keys cannot be repeated. Parse parameters before converting them
// to typed tool arguments so repeated keys cannot silently replace input.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = UniqueJson;
            fn expecting(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                fmt.write_str("JSON without duplicate object keys")
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(value.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(UniqueJson(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, UniqueJson(value))) = map.next_entry()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate object key"));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Initialize {
    protocol_version: String,
    capabilities: Map<String, Value>,
    client_info: ClientInfo,
    #[serde(default, rename = "_meta")]
    _meta: Option<Map<String, Value>>,
}
#[derive(Deserialize)]
struct ClientInfo {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyParams {
    #[serde(default, rename = "_meta")]
    _meta: Option<Map<String, Value>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    #[serde(default)]
    arguments: Map<String, Value>,
    #[serde(default, rename = "_meta")]
    _meta: Option<Map<String, Value>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Submit {
    idempotency_key: String,
    request: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionId {
    action_id: Uuid,
}

async fn rpc(
    State(state): State<McpState>,
    headers: HeaderMap,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let token = match bearer(&headers) {
        Ok(token) => token,
        Err(_) => return challenge(&state.config, false),
    };
    let identity = match state.verifier.verify(token, &state.config.resource) {
        Ok(identity)
            if identity.issuer == state.config.issuer && identity.subject.len() <= 1024 =>
        {
            identity
        }
        Err(IdentityError::InsufficientScope) => return challenge(&state.config, true),
        _ => return challenge(&state.config, false),
    };
    if !accepts(&headers, "application/json") || !accepts(&headers, "text/event-stream") {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    let mut content_types = headers.get_all(header::CONTENT_TYPE).iter();
    if !content_types
        .next()
        .and_then(|header| header.to_str().ok())
        .and_then(|content| content.split(';').next())
        .is_some_and(|content| content.trim().eq_ignore_ascii_case("application/json"))
        || content_types.next().is_some()
    {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    let body = match body {
        Ok(body) => body,
        Err(error) => return error.into_response(),
    };
    if body
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'[')
    {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            Value::Null,
            -32600,
            "Batch requests are unsupported",
        );
    }
    let message = match serde_json::from_slice::<Envelope>(&body) {
        Ok(message)
            if message.jsonrpc == "2.0"
                && !message.method.is_empty()
                && message.id.as_ref().is_none_or(valid_id)
                && message.params.as_ref().is_none_or(Value::is_object) =>
        {
            message
        }
        Err(error) if error.is_syntax() || error.is_eof() => {
            return rpc_error(StatusCode::BAD_REQUEST, Value::Null, -32700, "Parse error")
        }
        _ => {
            return rpc_error(
                StatusCode::BAD_REQUEST,
                Value::Null,
                -32600,
                "Invalid request",
            )
        }
    };
    let mut versions = headers.get_all("mcp-protocol-version").iter();
    let version = versions.next();
    if versions.next().is_some()
        || match version {
            Some(version) => version != PROTOCOL_VERSION,
            None => message.method != "initialize",
        }
    {
        return rpc_error(
            StatusCode::BAD_REQUEST,
            message.id.unwrap_or(Value::Null),
            -32600,
            "Unsupported MCP protocol version",
        );
    }
    let Some(id) = message.id else {
        // Notifications never dispatch tools or mutate actions.
        return if message.method.starts_with("notifications/") {
            StatusCode::ACCEPTED.into_response()
        } else {
            StatusCode::BAD_REQUEST.into_response()
        };
    };
    let params = message.params;
    match message.method.as_str() {
        "initialize" => {
            let Some(params) = parse::<Initialize>(params) else {
                return invalid_params(id);
            };
            if params.protocol_version.trim().is_empty()
                || params.client_info.name.trim().is_empty()
                || params.client_info.version.trim().is_empty()
            {
                return invalid_params(id);
            }
            let _capabilities = params.capabilities;
            rpc_result(
                id,
                json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{"tools":{}},
                "serverInfo":{"name":"agent-policy-layer","version":env!("CARGO_PKG_VERSION")}}),
            )
        }
        "ping" | "tools/list" => {
            if params.is_some() && parse::<EmptyParams>(params).is_none() {
                return invalid_params(id);
            }
            let result = if message.method == "ping" {
                json!({})
            } else {
                tools()
            };
            rpc_result(id, result)
        }
        "tools/call" => {
            let Some(call) = parse::<Call>(params) else {
                return invalid_params(id);
            };
            call_tool(&state, id, identity, call).await
        }
        _ => rpc_error(StatusCode::OK, id, -32601, "Method not found"),
    }
}

fn accepts(headers: &HeaderMap, media: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|entry| {
            let mut parts = entry.split(';');
            parts
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case(media))
                && parts
                    .filter_map(|part| part.trim().split_once('='))
                    .filter(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
                    .all(|(_, value)| {
                        value
                            .trim()
                            .parse::<f32>()
                            .is_ok_and(|q| q > 0.0 && q <= 1.0)
                    })
        })
}
fn valid_id(id: &Value) -> bool {
    id.is_string() || id.is_i64() || id.is_u64()
}
fn parse<T: DeserializeOwned>(value: Option<Value>) -> Option<T> {
    serde_json::from_value(value?).ok()
}
fn rpc_result(id: Value, result: Value) -> Response {
    Json(json!({"jsonrpc":"2.0","id":id,"result":result})).into_response()
}
fn rpc_error(status: StatusCode, id: Value, code: i32, message: &'static str) -> Response {
    (
        status,
        Json(json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})),
    )
        .into_response()
}
fn invalid_params(id: Value) -> Response {
    rpc_error(StatusCode::OK, id, -32602, "Invalid params")
}

async fn call_tool(
    state: &McpState,
    id: Value,
    identity: VerifiedIdentity,
    call: Call,
) -> Response {
    enum Operation {
        Submit(String, Box<RefundRequest>),
        Get(Uuid),
        Cancel(Uuid),
    }
    let args = Some(Value::Object(call.arguments));
    let operation = match call.name.as_str() {
        "submit_refund" => {
            let Some(input) = parse::<Submit>(args) else {
                return tool_error(id, "invalid_request");
            };
            if !valid_key(&input.idempotency_key)
                || !input.request.is_object()
                || !input.request["resource"].is_object()
                || !input.request["parameters"].is_object()
            {
                return tool_error(id, "invalid_request");
            }
            let Some(request) = parse::<RefundRequest>(Some(input.request)) else {
                return tool_error(id, "invalid_request");
            };
            if request.validate().is_err() {
                return tool_error(id, "invalid_request");
            }
            Operation::Submit(input.idempotency_key, Box::new(request))
        }
        "get_action" | "cancel_action" => match parse::<ActionId>(args) {
            Some(input) if call.name == "get_action" => Operation::Get(input.action_id),
            Some(input) => Operation::Cancel(input.action_id),
            None => return tool_error(id, "invalid_request"),
        },
        _ => return rpc_error(StatusCode::OK, id, -32602, "Unknown tool"),
    };
    let principal = match state
        .store
        .resolve_identity(&identity.issuer, &identity.subject)
        .await
    {
        Ok(Some(principal)) => principal,
        Ok(None) => return challenge(&state.config, false),
        Err(error) => return store_failure(id, error, "conflict"),
    };
    let workload = (
        principal.tenant_id,
        principal.environment_id,
        principal.workload_id,
    );
    let admission = state
        .tool_limit
        .lock()
        .ok()
        .map(|mut window| window.admit(workload, Instant::now()));
    match admission {
        Some(Ok(())) => {}
        Some(Err(seconds)) => {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                [(header::RETRY_AFTER, seconds.to_string())],
            )
                .into_response()
        }
        None => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    }
    let (result, submitted, conflict) = match operation {
        Operation::Submit(key, request) => (
            state.store.submit(&principal, &key, &request).await,
            true,
            "idempotency_conflict",
        ),
        Operation::Get(action_id) => (
            state
                .store
                .get(&principal, action_id)
                .await
                .and_then(|action| action.ok_or(StoreError::NotFound)),
            false,
            "conflict",
        ),
        Operation::Cancel(action_id) => (
            state.store.cancel(&principal, action_id).await,
            false,
            "action_not_cancellable",
        ),
    };
    match result {
        Ok(action) => action_result(id, action, submitted),
        Err(error) => store_failure(id, error, conflict),
    }
}
fn valid_key(key: &str) -> bool {
    !key.is_empty() && key.len() <= 128 && key.bytes().all(|byte| byte.is_ascii_graphic())
}
fn action_result(id: Value, action: Action, submitted: bool) -> Response {
    // Avoid echoing free-text action metadata into an agent's tool context.
    let mut data = json!({"id":action.id,"status":action.status,"reason":action.reason});
    if submitted {
        data["status_url"] = json!(format!("/v1/actions/{}", action.id));
    }
    tool_result(id, data, false)
}
fn store_failure(id: Value, error: StoreError, conflict: &'static str) -> Response {
    let code = match error {
        StoreError::Conflict => conflict,
        StoreError::NotFound | StoreError::Forbidden => "not_found",
        StoreError::Invalid(_) => "invalid_request",
        error => {
            tracing::error!(%error,"MCP workload operation failed");
            "internal_error"
        }
    };
    tool_error(id, code)
}
fn tool_error(id: Value, code: &'static str) -> Response {
    tool_result(id, json!({"error":{"code":code}}), true)
}
fn tool_result(id: Value, data: Value, error: bool) -> Response {
    rpc_result(
        id,
        json!({"content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":error}),
    )
}

fn tools() -> Value {
    let action_input = json!({"type":"object","additionalProperties":false,"required":["action_id"],
        "properties":{"action_id":{"type":"string","format":"uuid"}}});
    json!({"tools":[
        {"name":"submit_refund","description":"Submit a USD refund for policy evaluation; acceptance does not authorize execution.",
            "inputSchema":{"type":"object","additionalProperties":false,"required":["idempotency_key","request"],"properties":{
                "idempotency_key":{"type":"string","minLength":1,"maxLength":128,"pattern":"^[!-~]+$"},
                "request":{"type":"object","additionalProperties":false,"required":["type","connection_id","resource","parameters"],"properties":{
                    "type":{"type":"string","const":"refund.create"},"connection_id":{"type":"string","format":"uuid"},
                    "resource":{"type":"object","additionalProperties":false,"required":["payment_id"],"properties":{"payment_id":{"type":"string","minLength":1,"maxLength":255}}},
                    "parameters":{"type":"object","additionalProperties":false,"required":["amount_minor","currency"],"properties":{"amount_minor":{"type":"integer","minimum":1,"maximum":50000},"currency":{"type":"string","const":"USD"}}},
                    "metadata":{"type":"object","maxProperties":20,"propertyNames":{"minLength":1,"maxLength":64},"additionalProperties":{"type":"string","minLength":1,"maxLength":500}}
                }}
            }}},
        {"name":"get_action","description":"Get the current state of an action in the workload scope.","inputSchema":action_input,"annotations":{"readOnlyHint":true}},
        {"name":"cancel_action","description":"Cancel a workload action before dispatch authorization.","inputSchema":action_input}
    ]})
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use tower::ServiceExt;

    const HOST: &str = "mcp.example.test";
    const RESOURCE: &str = "https://mcp.example.test/mcp";
    const ISSUER: &str = "https://identity.example.test";
    const ORIGIN: &str = "https://client.example.test";

    fn app() -> Router {
        let jwks = include_str!("../../identity/tests/fixtures/jwks.json");
        router(
            Store::connect_lazy("postgres://localhost/apl_unused").unwrap(),
            McpVerifier::Static(Box::new(
                JwtVerifier::from_jwks(ISSUER, RESOURCE, jwks).unwrap(),
            )),
            McpConfig::new(RESOURCE, ISSUER, &[ORIGIN.into()]).unwrap(),
        )
    }
    fn signed(audience: Value, scope: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-1".into());
        let key = EncodingKey::from_rsa_pem(include_bytes!(
            "../../identity/tests/fixtures/test-only-private.pem"
        ))
        .unwrap();
        encode(
            &header,
            &json!({"iss":ISSUER,"sub":"fixture","aud":audience,"scope":scope,"exp":now+300}),
            &key,
        )
        .unwrap()
    }
    fn post_request(payload: impl Into<Body>, token: &str, version: Option<&str>) -> Request {
        let mut request = Request::post("/mcp")
            .header(header::HOST, HOST)
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        if let Some(version) = version {
            request = request.header("mcp-protocol-version", version);
        }
        request.body(payload.into()).unwrap()
    }
    async fn response_json(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), BODY_LIMIT).await.unwrap()).unwrap()
    }

    #[test]
    fn canonical_resource_and_origins_are_strict() {
        for value in [
            "http://mcp.example.test/mcp",
            "https://mcp.example.test/mcp/",
            "https://mcp.example.test/mcp?q=1",
            "https://me@mcp.example.test/mcp",
        ] {
            assert!(McpConfig::new(value, ISSUER, &[]).is_err(), "{value}");
        }
        assert!(
            McpConfig::new(RESOURCE, ISSUER, &["https://client.example.test/".into()]).is_err()
        );
    }

    #[tokio::test]
    async fn guards_canonical_host_origin_and_publishes_metadata() {
        for (host, origin) in [
            ("bad.example.test", ORIGIN),
            (HOST, "https://attacker.example.test"),
        ] {
            let request = Request::get("/mcp")
                .header(header::HOST, host)
                .header(header::ORIGIN, origin)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                app().oneshot(request).await.unwrap().status(),
                StatusCode::FORBIDDEN
            );
        }
        let request = Request::get("/mcp")
            .header(header::HOST, HOST)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app().oneshot(request).await.unwrap().status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        let request = Request::get(METADATA_PATH)
            .header(header::HOST, HOST)
            .header(header::ORIGIN, ORIGIN)
            .body(Body::empty())
            .unwrap();
        let response = app().oneshot(request).await.unwrap();
        assert_eq!(
            response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            ORIGIN
        );
        assert_eq!(
            response_json(response).await,
            json!({"resource":RESOURCE,"authorization_servers":[ISSUER],"scopes_supported":[REQUIRED_SCOPE],"bearer_methods_supported":["header"]})
        );
    }

    #[tokio::test]
    async fn authentication_challenges_invalid_audience_and_insufficient_scope() {
        let ping = r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#;
        for (token, status) in [
            ("invalid".into(), StatusCode::UNAUTHORIZED),
            (
                signed(json!([RESOURCE, "another-service"]), REQUIRED_SCOPE),
                StatusCode::UNAUTHORIZED,
            ),
            (signed(json!(RESOURCE), "other"), StatusCode::FORBIDDEN),
        ] {
            let response = app()
                .oneshot(post_request(ping, &token, Some(PROTOCOL_VERSION)))
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            let header = response.headers()[header::WWW_AUTHENTICATE]
                .to_str()
                .unwrap();
            assert!(header
                .contains("https://mcp.example.test/.well-known/oauth-protected-resource/mcp"));
            assert_eq!(
                header.contains("insufficient_scope"),
                status == StatusCode::FORBIDDEN
            );
        }
    }

    #[tokio::test]
    async fn lifecycle_lists_only_workload_tools_and_never_executes_notifications() {
        let app = app();
        let token = signed(json!(RESOURCE), REQUIRED_SCOPE);
        let init = json!({"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}});
        let response = app
            .clone()
            .oneshot(post_request(init.to_string(), &token, None))
            .await
            .unwrap();
        assert!(!response.headers().contains_key("mcp-session-id"));
        let response = response_json(response).await;
        assert_eq!(response["id"], "init");
        assert_eq!(response["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(response["result"]["capabilities"], json!({"tools":{}}));
        let notification = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let response = app
            .clone()
            .oneshot(post_request(notification, &token, Some(PROTOCOL_VERSION)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .unwrap()
            .is_empty());
        let list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let response = app
            .clone()
            .oneshot(post_request(list, &token, Some(PROTOCOL_VERSION)))
            .await
            .unwrap();
        let response = response_json(response).await;
        let names: Vec<_> = response["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["submit_refund", "get_action", "cancel_action"]);
        for version in [None, Some("2025-06-18")] {
            assert_eq!(
                app.clone()
                    .oneshot(post_request(list, &token, version))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let call = r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"cancel_action","arguments":{"action_id":"00000000-0000-0000-0000-000000000001"}}}"#;
        assert_eq!(
            app.oneshot(post_request(call, &token, Some(PROTOCOL_VERSION)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn rejects_batches_duplicate_fields_and_injected_authority_before_database() {
        let app = app();
        let token = signed(json!(RESOURCE), REQUIRED_SCOPE);
        for payload in [
            r#"["2.0","ping",1,{}]"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_action","arguments":{"action_id":"first","action_id":"second"}}}"#,
        ] {
            assert_eq!(
                app.clone()
                    .oneshot(post_request(payload, &token, Some(PROTOCOL_VERSION)))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        let payload = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_action","arguments":{"action_id":"00000000-0000-0000-0000-000000000001","tenant_id":"injected"}}}"#;
        let response = app
            .clone()
            .oneshot(post_request(payload, &token, Some(PROTOCOL_VERSION)))
            .await
            .unwrap();
        assert_eq!(response_json(response).await["result"]["isError"], true);
        let response = app
            .oneshot(post_request(
                " ".repeat(BODY_LIMIT + 1),
                &token,
                Some(PROTOCOL_VERSION),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
    #[test]
    fn rate_limit_is_per_registered_workload_and_recovers_at_window_boundary() {
        let now = Instant::now();
        let mut window = ToolWindow::new(now);
        let workload = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for _ in 0..TOOL_LIMIT {
            assert!(window.admit(workload, now).is_ok());
        }
        assert_eq!(window.admit(workload, now), Err(60));
        assert!(window
            .admit((workload.0, Uuid::new_v4(), workload.2), now)
            .is_ok());
        assert!(window.admit(workload, now + TOOL_WINDOW).is_ok());
    }
}
