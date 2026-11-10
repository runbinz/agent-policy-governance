use std::process::Command;

#[test]
fn metrics_requires_explicit_private_bind_and_separate_secret() {
    let token = "synthetic-worker-metrics-secret-at-least-32-bytes";
    for (extra, expected) in [
        (vec![("APL_METRICS_TOKEN", token)], "require both"),
        (
            vec![("APL_WORKER_METRICS_BIND", "127.0.0.1:9091")],
            "require both",
        ),
        (
            vec![
                ("APL_METRICS_TOKEN", token),
                ("APL_WORKER_METRICS_BIND", "0.0.0.0:9091"),
            ],
            "loopback",
        ),
        (
            vec![
                ("APL_METRICS_TOKEN", "short"),
                ("APL_WORKER_METRICS_BIND", "127.0.0.1:9091"),
            ],
            "invalid worker metrics token",
        ),
        (
            vec![
                ("APL_METRICS_TOKEN", token),
                ("APL_SLACK_BOT_TOKEN", token),
                ("APL_WORKER_METRICS_BIND", "127.0.0.1:9091"),
            ],
            "separate from provider",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_apl-worker"))
            .env_clear()
            .env("APL_LOCAL_DEV", "true")
            .envs(extra)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains(token));
    }
}
