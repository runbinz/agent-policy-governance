use apl_persistence::Store;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL test database"]
async fn signed_webhooks_are_deduplicated_and_invalid_bodies_are_not_stored() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let (t, e, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let account = format!("acct_{}", c.simple());
    let namespace = format!("stripe-test:{account}");
    sqlx::query("INSERT INTO tenants(tenant_id) VALUES($1)")
        .bind(t)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments(tenant_id,environment_id) VALUES($1,$2)")
        .bind(t)
        .bind(e)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)")
        .bind(t)
        .bind(e)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO provider_routes VALUES($1,$2,$3,$4)")
        .bind(t)
        .bind(e)
        .bind(c)
        .bind(&namespace)
        .execute(&admin)
        .await
        .unwrap();
    let api = PgPoolOptions::new()
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_api").execute(conn).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let secret = "whsec_syntheticSignatureOnly";
    let router = apl_api::stripe_webhook::router(Store::from_pool(api), &account, secret).unwrap();
    let body = serde_json::json!({"id":"evt_WebhookFixture","object":"event","livemode":false,
        "type":"refund.updated","data":{"object":{"id":"re_WebhookFixture","object":"refund",
        "charge":"ch_WebhookFixture","metadata":{}}}})
    .to_string();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let signature: String = mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for (payload, status) in [
        (format!("{body} "), StatusCode::BAD_REQUEST),
        (body.clone(), StatusCode::NO_CONTENT),
        (body, StatusCode::NO_CONTENT),
    ] {
        let request = Request::post("/v1/webhooks/stripe-sandbox")
            .header("stripe-signature", format!("t={timestamp},v1={signature}"))
            .body(Body::from(payload))
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            status
        );
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM stripe_webhook_inbox WHERE provider_namespace=$1")
            .bind(namespace)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(count, 1);
}
