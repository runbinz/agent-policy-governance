use std::process::Command;

#[test]
fn metrics_secret_requires_valid_separate_credential() {
    fails(
        &[("APL_AUTH_MODE", "local"), ("APL_METRICS_TOKEN", "short")],
        "metrics bearer token must contain",
    );
    fails(
        &[
            ("APL_AUTH_MODE", "local"),
            ("APL_METRICS_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("APL_DEV_TOKEN_A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ],
        "metrics token must be distinct",
    );
}

#[test]
fn browser_login_requires_complete_managed_configuration_before_database_access() {
    fails(
        &[
            ("APL_AUTH_MODE", "local"),
            ("APL_BROWSER_ORIGIN", "https://console.example.test"),
        ],
        "browser login requires managed JWT mode",
    );
    let common = [
        ("APL_AUTH_MODE", "jwt"),
        ("APL_MANAGED_JWKS", "true"),
        ("APL_JWT_ISSUER", "https://identity.example.test"),
        ("APL_JWT_AUDIENCE", "workload"),
        ("APL_BROWSER_CLIENT_ID", "browser-client"),
        (
            "APL_BROWSER_FLOW_KEY",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        ),
    ];
    let mut values = common.to_vec();
    values.push(("APL_BROWSER_ORIGIN", "http://console.example.test"));
    fails(&values, "canonical HTTPS");
    let mut values = common.to_vec();
    values.push(("APL_BROWSER_ORIGIN", "https://console.example.test"));
    values[4] = ("APL_BROWSER_CLIENT_ID", "workload");
    fails(&values, "browser client ID must be distinct");
    let mut values = common.to_vec();
    values.push(("APL_BROWSER_ORIGIN", "https://console.example.test"));
    values[5] = ("APL_BROWSER_FLOW_KEY", "sensitive-invalid-key-marker");
    fails(&values, "browser flow key must be standard base64");
    let output = Command::new(env!("CARGO_BIN_EXE_apl-api"))
        .env_clear()
        .envs(values.iter().copied())
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sensitive-invalid-key-marker"));
}

fn fails(envs: &[(&str, &str)], expected: &str) {
    let output = Command::new(env!("CARGO_BIN_EXE_apl-api"))
        .env_clear()
        .envs(envs.iter().copied())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(expected), "unexpected failure: {stderr}");
}

#[test]
fn startup_rejects_unknown_auth_mode_without_database_access() {
    fails(
        &[("APL_AUTH_MODE", "automatic")],
        "APL_AUTH_MODE must be local or jwt",
    );
}

#[test]
fn local_mode_requires_explicit_development_opt_in() {
    fails(
        &[("APL_AUTH_MODE", "local")],
        "local fixture authentication requires APL_LOCAL_DEV=true",
    );
}

#[test]
fn public_binding_is_rejected() {
    fails(
        &[("APL_BIND_ADDR", "0.0.0.0:8080"), ("APL_AUTH_MODE", "jwt")],
        "loopback",
    );
}

#[test]
fn jwt_requires_https_issuer_and_nonempty_audience() {
    fails(
        &[
            ("APL_AUTH_MODE", "jwt"),
            ("APL_JWT_ISSUER", "http://issuer.example"),
        ],
        "HTTPS issuer",
    );
    fails(
        &[
            ("APL_AUTH_MODE", "jwt"),
            ("APL_JWT_ISSUER", "https://issuer.example"),
            ("APL_JWT_AUDIENCE", " "),
        ],
        "must not be empty",
    );
}

#[test]
fn local_reviewer_token_cannot_equal_a_workload_token() {
    fails(
        &[
            ("APL_AUTH_MODE", "local"),
            ("APL_LOCAL_DEV", "true"),
            ("APL_DEV_TOKEN_A", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ("APL_DEV_TOKEN_B", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            ("APL_DEV_REVIEWER_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        ],
        "reviewer token must be distinct",
    );
}

#[test]
fn reviewer_jwt_audience_cannot_equal_workload_audience() {
    fails(
        &[
            ("APL_AUTH_MODE", "jwt"),
            ("APL_JWT_ISSUER", "https://issuer.example"),
            ("APL_JWT_AUDIENCE", "apl-api"),
            ("APL_REVIEWER_JWT_AUDIENCE", "apl-api"),
        ],
        "must be nonempty and distinct from APL_JWT_AUDIENCE",
    );
}

#[test]
fn managed_key_fetch_requires_explicit_unambiguous_configuration() {
    fails(
        &[("APL_AUTH_MODE", "local"), ("APL_MANAGED_JWKS", "true")],
        "managed JWKS settings require JWT authentication",
    );
    fails(
        &[
            ("APL_AUTH_MODE", "jwt"),
            ("APL_JWT_ISSUER", "https://issuer.example"),
            ("APL_JWT_AUDIENCE", "apl-api"),
            ("APL_MANAGED_JWKS", "true"),
            ("APL_JWKS_FILE", "unused.json"),
        ],
        "configure either managed JWKS or APL_JWKS_FILE",
    );
}

#[test]
fn mcp_requires_managed_verification_before_startup() {
    fails(
        &[
            ("APL_AUTH_MODE", "jwt"),
            (
                "APL_MCP_RESOURCE_URL",
                "https://governance.example.test/mcp",
            ),
        ],
        "MCP requires APL_MCP_RESOURCE_URL and managed JWT authentication",
    );
}
