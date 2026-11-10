use apl_api::{
    mcp::{self, McpConfig, McpVerifier},
    router_with_reviewers, Authenticator, LocalReviewerToken, ReviewerAuthenticator, TokenRegistry,
};
use apl_identity::{browser::BrowserOidc, JwtVerifier, ManagedIssuer};
use apl_persistence::Store;
use base64::Engine;
use std::{env, net::SocketAddr, time::Duration};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().init();
    let addr: SocketAddr = env::var("APL_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()?;
    if !addr.ip().is_loopback() {
        return Err(
            "API must bind to a loopback address until production deployment is implemented".into(),
        );
    }
    let args: Vec<_> = env::args().skip(1).collect();
    if args == ["--migrate"] {
        if env::var("APL_LOCAL_DEV").as_deref() != Ok("true") {
            return Err("local migrations require APL_LOCAL_DEV=true".into());
        }
        let store =
            Store::connect(&optional_env("DATABASE_URL")?.ok_or("DATABASE_URL is required")?)
                .await
                .map_err(|_| "database unavailable")?;
        store.migrate().await?;
        return Ok(());
    }
    if !args.is_empty() {
        return Err("usage: apl-api [--migrate]".into());
    }
    let mode = env::var("APL_AUTH_MODE")?;
    let metrics_token = optional_env("APL_METRICS_TOKEN")?.map(Zeroizing::new);
    if let Some(token) = &metrics_token {
        for name in [
            "APL_DEV_TOKEN_A",
            "APL_DEV_TOKEN_B",
            "APL_DEV_REVIEWER_TOKEN",
        ] {
            if optional_env(name)?.as_deref() == Some(token.as_str()) {
                return Err("metrics token must be distinct from development credentials".into());
            }
        }
    }
    let metrics = metrics_token
        .as_ref()
        .map(|token| {
            apl_telemetry::Metrics::new(token).map_err(|_| {
                "metrics bearer token must contain at least 32 visible ASCII characters"
            })
        })
        .transpose()?;
    drop(metrics_token);
    let managed = match optional_env("APL_MANAGED_JWKS")?.as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err("APL_MANAGED_JWKS must be true or false".into()),
    };
    let pinned_jwks = optional_env("APL_MANAGED_JWKS_URL")?;
    let mcp_resource = optional_env("APL_MCP_RESOURCE_URL")?;
    let mcp_origins = optional_env("APL_MCP_ALLOWED_ORIGINS")?;
    let browser_origin = optional_env("APL_BROWSER_ORIGIN")?;
    let browser_client = optional_env("APL_BROWSER_CLIENT_ID")?;
    let browser_secret = optional_env("APL_BROWSER_CLIENT_SECRET")?.map(Zeroizing::new);
    let browser_key = optional_env("APL_BROWSER_FLOW_KEY")?.map(Zeroizing::new);
    let browser_configured = browser_origin.is_some()
        || browser_client.is_some()
        || browser_secret.is_some()
        || browser_key.is_some();
    if browser_configured
        && (mode != "jwt"
            || !managed
            || browser_origin.is_none()
            || browser_client.is_none()
            || browser_key.is_none())
    {
        return Err("browser login requires managed JWT mode, APL_BROWSER_ORIGIN, APL_BROWSER_CLIENT_ID and APL_BROWSER_FLOW_KEY".into());
    }
    if let Some(origin) = &browser_origin {
        apl_api::browser::BrowserAuth::validate_origin(origin)?;
    }
    let browser_key = browser_key
        .map(|value| -> Result<Zeroizing<[u8; 32]>, &'static str> {
            let bytes = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(value.as_bytes())
                    .map_err(|_| {
                        "browser flow key must be standard base64 encoding of 32 random bytes"
                    })?,
            );
            Ok(Zeroizing::new(
                bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| "browser flow key must encode 32 bytes")?,
            ))
        })
        .transpose()?;
    let mut browser_provider = None;
    if (mcp_resource.is_some() && !managed) || (mcp_origins.is_some() && mcp_resource.is_none()) {
        return Err("MCP requires APL_MCP_RESOURCE_URL and managed JWT authentication".into());
    }
    let mut mcp_endpoint = None;
    if (managed && mode != "jwt") || (!managed && pinned_jwks.is_some()) {
        return Err(
            "managed JWKS settings require JWT authentication and APL_MANAGED_JWKS=true".into(),
        );
    }
    let (auth, reviewer_auth) = match mode.as_str() {
        "local" => {
            if env::var("APL_LOCAL_DEV").as_deref() != Ok("true") {
                return Err("local fixture authentication requires APL_LOCAL_DEV=true".into());
            }
            if optional_env("APL_REVIEWER_JWT_AUDIENCE")?.is_some() {
                return Err("reviewer JWT audience requires JWT authentication mode".into());
            }
            let workloads =
                TokenRegistry::new(env::var("APL_DEV_TOKEN_A")?, env::var("APL_DEV_TOKEN_B")?)?;
            let reviewer = optional_env("APL_DEV_REVIEWER_TOKEN")?
                .map(|token| {
                    LocalReviewerToken::new(token, &workloads).map(ReviewerAuthenticator::Local)
                })
                .transpose()?;
            (Authenticator::Local(workloads), reviewer)
        }
        "jwt" => {
            if optional_env("APL_DEV_REVIEWER_TOKEN")?.is_some() {
                return Err("development reviewer token requires local authentication mode".into());
            }
            let issuer = env::var("APL_JWT_ISSUER")?;
            if !issuer.starts_with("https://") || issuer.len() <= 8 {
                return Err("APL_JWT_ISSUER must be an HTTPS issuer".into());
            }
            let audience = env::var("APL_JWT_AUDIENCE")?;
            if audience.trim().is_empty() {
                return Err("APL_JWT_AUDIENCE must not be empty".into());
            }
            let reviewer_audience = optional_env("APL_REVIEWER_JWT_AUDIENCE")?;
            if reviewer_audience
                .as_ref()
                .is_some_and(|value| value.trim().is_empty() || value == &audience)
            {
                return Err(
                    "APL_REVIEWER_JWT_AUDIENCE must be nonempty and distinct from APL_JWT_AUDIENCE"
                        .into(),
                );
            }
            if browser_client.as_ref().is_some_and(|client| {
                client == &audience
                    || reviewer_audience.as_ref() == Some(client)
                    || mcp_resource.as_ref() == Some(client)
            }) {
                return Err(
                    "browser client ID must be distinct from workload, reviewer and MCP audiences"
                        .into(),
                );
            }
            if managed {
                if optional_env("APL_JWKS_FILE")?.is_some() {
                    return Err("configure either managed JWKS or APL_JWKS_FILE".into());
                }
                let audiences: Vec<&str> = std::iter::once(audience.as_str())
                    .chain(reviewer_audience.as_deref())
                    .chain(mcp_resource.as_deref())
                    .chain(browser_client.as_deref())
                    .collect();
                let mcp_config = mcp_resource
                    .as_deref()
                    .map(|resource| {
                        let origins: Vec<String> = mcp_origins
                            .as_deref()
                            .unwrap_or("")
                            .split(',')
                            .map(str::trim)
                            .filter(|origin| !origin.is_empty())
                            .map(str::to_owned)
                            .collect();
                        McpConfig::new(resource, &issuer, &origins)
                    })
                    .transpose()?;
                let cache = ManagedIssuer::new(
                    &issuer,
                    &audiences,
                    pinned_jwks.as_deref(),
                    Duration::from_secs(600),
                )?;
                cache.refresh().await?;
                if let (Some(client), Some(origin)) =
                    (browser_client.as_deref(), browser_origin.as_deref())
                {
                    browser_provider = Some(
                        BrowserOidc::discover(
                            &issuer,
                            client,
                            &format!("{origin}/auth/callback"),
                            browser_secret,
                            cache.verifier(client)?,
                        )
                        .await?,
                    );
                }
                if let (Some(resource), Some(config)) = (mcp_resource.as_deref(), mcp_config) {
                    mcp_endpoint = Some((McpVerifier::Managed(cache.verifier(resource)?), config));
                }
                let auth = Authenticator::Managed(cache.verifier(&audience)?);
                let reviewer = reviewer_audience
                    .as_deref()
                    .map(|aud| cache.verifier(aud).map(ReviewerAuthenticator::Managed))
                    .transpose()?;
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        if cache.refresh().await.is_err() {
                            tracing::warn!("managed signing key refresh failed");
                        }
                    }
                });
                (auth, reviewer)
            } else {
                let jwks = std::fs::read_to_string(env::var("APL_JWKS_FILE")?)?;
                let reviewer = reviewer_audience
                    .map(|aud| {
                        JwtVerifier::from_jwks(&issuer, &aud, &jwks)
                            .map(|verifier| ReviewerAuthenticator::Jwt(verifier.into()))
                    })
                    .transpose()?;
                (
                    Authenticator::Jwt(JwtVerifier::from_jwks(&issuer, &audience, &jwks)?),
                    reviewer,
                )
            }
        }
        _ => return Err("APL_AUTH_MODE must be local or jwt".into()),
    };
    let store = Store::connect(&optional_env("DATABASE_URL")?.ok_or("DATABASE_URL is required")?)
        .await
        .map_err(|_| "database unavailable")?;
    if let Some(metrics) = &metrics {
        apl_observability::start(store.clone(), metrics.clone());
    }
    let browser = browser_provider
        .map(|provider| {
            apl_api::browser::BrowserAuth::new(
                store.clone(),
                provider,
                browser_origin.as_deref().expect("validated browser origin"),
                **browser_key.as_ref().expect("validated browser key"),
            )
        })
        .transpose()?;
    let reviewer_auth = if let Some(sessions) = &browser {
        Some(ReviewerAuthenticator::Browser {
            bearer: reviewer_auth.map(Box::new),
            sessions: sessions.clone(),
        })
    } else {
        reviewer_auth
    };
    let artifacts = apl_evidence::EvidenceStore::from_env()?;
    let mut router = router_with_reviewers(store.clone(), auth.clone(), reviewer_auth.clone());
    if let Some(reviewer) = reviewer_auth.clone() {
        router = router.merge(apl_api::environment_admin::router(
            store.clone(),
            auth.clone(),
            reviewer.clone(),
        ));
        router = router.merge(apl_api::action_detail::router(
            store.clone(),
            auth.clone(),
            reviewer.clone(),
        ));
        router = router.merge(apl_api::operations::router(
            store.clone(),
            auth.clone(),
            reviewer.clone(),
        ));
        router = router.merge(apl_api::evidence::router(
            store.clone(),
            auth.clone(),
            reviewer,
        ));
    }
    if let Some(artifacts) = artifacts {
        let reviewer = reviewer_auth.ok_or("evidence exports require reviewer authentication")?;
        router = router.merge(apl_api::exports::router(
            store.clone(),
            artifacts.into(),
            auth,
            reviewer,
        ));
    }
    if let Some((verifier, config)) = mcp_endpoint {
        router = router.merge(mcp::router(store.clone(), verifier, config));
    }
    if let Some(secret) = optional_env("APL_STRIPE_WEBHOOK_SECRET")? {
        router = router.merge(apl_api::stripe_webhook::router(
            store,
            &env::var("APL_STRIPE_ACCOUNT_ID")?,
            &secret,
        )?);
    }
    router = if let Some(browser) = browser {
        browser.protect(router)
    } else {
        router.merge(apl_api::browser::disabled_router(mode == "local"))
    };
    if let Some(metrics) = metrics {
        router = metrics.instrument(router);
    }
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "API listening");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(%error, "shutdown signal failed");
            }
        })
        .await?;
    Ok(())
}

fn optional_env(name: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(_) => Err(format!("{name} must be valid Unicode").into()),
    }
}
