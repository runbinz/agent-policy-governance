//! Minimal approval notices. Delivery is at least once; never approves an action.

use reqwest::{Client, StatusCode, Url};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_SECONDS: u64 = 30;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotificationMessage {
    pub id: Uuid,
    pub action_id: Uuid,
    pub approval_generation: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Delivered,
    RetryAfter(u64),
    PermanentFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NotificationError {
    #[error("invalid notification configuration")]
    InvalidConfiguration,
}

#[derive(Clone)]
pub struct Notifier {
    route_id: Uuid,
    console_url: String,
    transport: Transport,
}

#[derive(Clone)]
enum Transport {
    Fake,
    Slack(Arc<Slack>),
}

struct Slack {
    client: Client,
    token: Zeroizing<String>,
    team_id: String,
    origin: Url,
}

impl Notifier {
    /// Explicit local no-network sink for tests; environment mode still requires local-dev opt-in.
    pub fn fake(route_id: Uuid, console_origin: &str) -> Result<Self, NotificationError> {
        if route_id.is_nil() {
            return Err(NotificationError::InvalidConfiguration);
        }
        Ok(Self {
            route_id,
            console_url: self::console_origin(console_origin, true)?,
            transport: Transport::Fake,
        })
    }

    pub fn from_env() -> Result<Option<Self>, NotificationError> {
        Self::from_lookup(|name| match std::env::var(name) {
            Ok(value) => Ok(Some(value)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(_) => Err(NotificationError::InvalidConfiguration),
        })
    }

    fn from_lookup(
        lookup: impl Fn(&str) -> Result<Option<String>, NotificationError>,
    ) -> Result<Option<Self>, NotificationError> {
        let invalid = NotificationError::InvalidConfiguration;
        let mode = lookup("APL_NOTIFICATION_MODE")?;
        let route = lookup("APL_NOTIFICATION_ROUTE_ID")?;
        let console = lookup("APL_CONSOLE_ORIGIN")?;
        let team = lookup("APL_SLACK_TEAM_ID")?;
        let token = lookup("APL_SLACK_BOT_TOKEN")?.map(Zeroizing::new);
        let Some(mode) = mode else {
            if route.is_some() || console.is_some() || team.is_some() || token.is_some() {
                return Err(invalid);
            }
            return Ok(None);
        };
        let route_id = Uuid::parse_str(&route.ok_or(invalid)?).map_err(|_| invalid)?;
        if route_id.is_nil() {
            return Err(invalid);
        }
        let fake = mode == "fake";
        let console_url = console_origin(&console.ok_or(invalid)?, fake)?;
        let transport = match mode.as_str() {
            "fake" if team.is_none() && token.is_none() => {
                if lookup("APL_LOCAL_DEV")?.as_deref() != Some("true") {
                    return Err(invalid);
                }
                Transport::Fake
            }
            "slack" => {
                let team_id = team.ok_or(invalid)?;
                let token = token.ok_or(invalid)?;
                if !slack_id(&team_id, b"T")
                    || !token.starts_with("xoxb-")
                    || !(6..=512).contains(&token.len())
                    || !token.bytes().all(|byte| byte.is_ascii_graphic())
                {
                    return Err(invalid);
                }
                Transport::Slack(Arc::new(Slack {
                    client: client()?,
                    token,
                    team_id,
                    origin: Url::parse("https://slack.com/api/").map_err(|_| invalid)?,
                }))
            }
            _ => return Err(invalid),
        };
        Ok(Some(Self {
            route_id,
            console_url,
            transport,
        }))
    }

    pub fn route_id(&self) -> Uuid {
        self.route_id
    }
    pub fn kind(&self) -> &str {
        match &self.transport {
            Transport::Fake => "fake",
            Transport::Slack(_) => "slack",
        }
    }

    /// team_id/channel_id must come from the immutable, trusted database route.
    pub async fn deliver(
        &self,
        message: &NotificationMessage,
        team_id: Option<&str>,
        channel_id: Option<&str>,
    ) -> DeliveryOutcome {
        if message.id.is_nil() || message.action_id.is_nil() || message.approval_generation <= 0 {
            return DeliveryOutcome::PermanentFailure;
        }
        let Transport::Slack(slack) = &self.transport else {
            return DeliveryOutcome::Delivered;
        };
        let (Some(team), Some(channel)) = (team_id, channel_id) else {
            return DeliveryOutcome::PermanentFailure;
        };
        if team != slack.team_id || !slack_id(team, b"T") || !slack_id(channel, b"CG") {
            return DeliveryOutcome::PermanentFailure;
        }
        tokio::time::timeout(TIMEOUT, self.deliver_slack(slack, message, channel))
            .await
            .unwrap_or(DeliveryOutcome::RetryAfter(RETRY_SECONDS))
    }

    async fn deliver_slack(
        &self,
        slack: &Slack,
        message: &NotificationMessage,
        channel: &str,
    ) -> DeliveryOutcome {
        let auth = match slack.post("auth.test", &serde_json::json!({})).await {
            Ok(response) => response,
            Err(outcome) => return outcome,
        };
        if auth.team_id.as_deref() != Some(&slack.team_id) {
            return DeliveryOutcome::PermanentFailure;
        }
        let text = format!(
            "Approval requested. Action {}. Approval generation {}. Open the authenticated reviewer queue: {}",
            message.action_id, message.approval_generation, self.console_url
        );
        let response = match slack
            .post(
                "chat.postMessage",
                &serde_json::json!({
                    "channel":channel, "text":text, "client_msg_id":message.id,
                    "unfurl_links":false, "unfurl_media":false, "mrkdwn":false, "parse":"none",
                    "blocks":[{
                        "type":"rich_text",
                        "elements":[{
                            "type":"rich_text_section",
                            "elements":[
                                {"type":"text","text":format!(
                                    "Approval requested. Action {}. Approval generation {}. ",
                                    message.action_id, message.approval_generation
                                )},
                                {"type":"link","url":self.console_url,"text":"Open reviewer queue"}
                            ]
                        }]
                    }],
                }),
            )
            .await
        {
            Ok(response) => response,
            Err(outcome) => return outcome,
        };
        if response.channel.as_deref() != Some(channel)
            || !response.ts.as_ref().is_some_and(|ts| {
                !ts.is_empty()
                    && ts.len() <= 64
                    && ts.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.')
                    && ts.bytes().any(|byte| byte.is_ascii_digit())
            })
        {
            return DeliveryOutcome::RetryAfter(RETRY_SECONDS);
        }
        DeliveryOutcome::Delivered
    }
}

impl Slack {
    async fn post(
        &self,
        method: &str,
        body: &serde_json::Value,
    ) -> Result<SlackResponse, DeliveryOutcome> {
        let retry = DeliveryOutcome::RetryAfter(RETRY_SECONDS);
        let url = self
            .origin
            .join(method)
            .map_err(|_| DeliveryOutcome::PermanentFailure)?;
        let mut response = self
            .client
            .post(url)
            .bearer_auth(self.token.as_str())
            .json(body)
            .send()
            .await
            .map_err(|_| retry)?;
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            let wait = response
                .headers()
                .get("retry-after")
                .and_then(|value| value.to_str().ok())
                .filter(|value| {
                    value.len() <= 20 && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<u64>().ok())
                .map(|seconds| seconds.clamp(1, 86_400))
                .unwrap_or(RETRY_SECONDS);
            return Err(DeliveryOutcome::RetryAfter(wait));
        }
        if response.status().is_server_error() {
            return Err(retry);
        }
        if !response.status().is_success() {
            return Err(DeliveryOutcome::PermanentFailure);
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(retry);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| retry)? {
            if chunk.len() > MAX_RESPONSE_BYTES - bytes.len() {
                return Err(retry);
            }
            bytes.extend_from_slice(&chunk);
        }
        let parsed: SlackResponse = serde_json::from_slice(&bytes).map_err(|_| retry)?;
        if !parsed.ok {
            return Err(match parsed.error.as_deref() {
                Some(
                    "ratelimited"
                    | "rate_limited"
                    | "internal_error"
                    | "fatal_error"
                    | "service_unavailable"
                    | "request_timeout",
                ) => retry,
                _ => DeliveryOutcome::PermanentFailure,
            });
        }
        Ok(parsed)
    }
}

#[derive(Deserialize)]
struct SlackResponse {
    ok: bool,
    error: Option<String>,
    team_id: Option<String>,
    channel: Option<String>,
    ts: Option<String>,
}

fn client() -> Result<Client, NotificationError> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .timeout(TIMEOUT)
        .connect_timeout(TIMEOUT)
        .build()
        .map_err(|_| NotificationError::InvalidConfiguration)
}

fn slack_id(value: &str, prefixes: &[u8]) -> bool {
    (9..=64).contains(&value.len())
        && prefixes.contains(&value.as_bytes()[0])
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

fn console_origin(value: &str, fake: bool) -> Result<String, NotificationError> {
    let invalid = NotificationError::InvalidConfiguration;
    if value.len() > 2048
        || value.contains('\\')
        || value.bytes().any(|byte| !byte.is_ascii_graphic())
    {
        return Err(invalid);
    }
    let url = Url::parse(value).map_err(|_| invalid)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if !(url.scheme() == "https" || fake && url.scheme() == "http" && loopback)
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid);
    }
    let canonical = url.origin().ascii_serialization();
    if value != canonical && value != format!("{canonical}/") {
        return Err(invalid);
    }
    Ok(format!("{canonical}/"))
}

#[cfg(test)]
mod tests;
