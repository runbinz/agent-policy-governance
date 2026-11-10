use apl_observability::collect;
use apl_persistence::Store;
use apl_telemetry::Metrics;
use axum::{
    body::{to_bytes, Body},
    http::Request,
    Router,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
const TOKEN: &str = "synthetic-collector-scrape-secret-at-least-32-bytes";

async fn scrape(metrics: &std::sync::Arc<Metrics>) -> String {
    let response = metrics
        .instrument(Router::new())
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    String::from_utf8(
        to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with database administration"]
async fn collector_uses_private_snapshot_and_preserves_last_data_on_failure() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api = Store::from_pool(
        PgPoolOptions::new()
            .after_connect(|c, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE apl_api").execute(c).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap(),
    );
    let metrics = Metrics::new(TOKEN).unwrap();
    collect(&api, &metrics).await;
    let before = scrape(&metrics).await;
    assert!(before.contains("apl_business_collector_up 1"));
    let held = before
        .lines()
        .find(|line| line.starts_with("apl_budget_held_minor "))
        .unwrap()
        .to_owned();
    sqlx::query("REVOKE EXECUTE ON FUNCTION read_service_metrics() FROM apl_api")
        .execute(&admin)
        .await
        .unwrap();
    collect(&api, &metrics).await;
    sqlx::query("GRANT EXECUTE ON FUNCTION read_service_metrics() TO apl_api")
        .execute(&admin)
        .await
        .unwrap();
    let failed = scrape(&metrics).await;
    assert!(failed.contains("apl_business_collector_up 0"));
    assert!(failed.contains(&held));
}
