use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

async fn runtime(url: &str, worker: bool) -> PgPool {
    PgPoolOptions::new()
        .after_connect(move |c, _| {
            Box::pin(async move {
                sqlx::query(if worker {
                    "SET ROLE apl_worker"
                } else {
                    "SET ROLE apl_api"
                })
                .execute(c)
                .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with database administration"]
async fn shared_browser_state_sessions_revocation_and_permissions() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = runtime(&url, false).await;
    let api = Store::from_pool(api_pool.clone());
    let replica = Store::from_pool(runtime(&url, false).await);
    let state = *Uuid::new_v4().as_bytes();
    let state = [state, state].concat();
    let binding = [2u8; 32];
    api.start_browser_login(&state, &binding).await.unwrap();
    assert!(!replica
        .consume_browser_login(&state, &[9; 32])
        .await
        .unwrap());
    let (first, second) = tokio::join!(
        api.consume_browser_login(&state, &binding),
        replica.consume_browser_login(&state, &binding)
    );
    assert_ne!(
        first.unwrap(),
        second.unwrap(),
        "one callback may consume shared state"
    );
    assert!(!api.consume_browser_login(&state, &binding).await.unwrap());
    api.start_browser_login(&state, &binding).await.unwrap();
    sqlx::query("UPDATE browser_login_flows SET expires_at=clock_timestamp()-interval '1 second' WHERE state_hash=$1").bind(&state).execute(&admin).await.unwrap();
    assert!(!replica
        .consume_browser_login(&state, &binding)
        .await
        .unwrap());

    let t = Uuid::new_v4();
    let e = Uuid::new_v4();
    let r = Uuid::new_v4();
    let subject = Uuid::new_v4().to_string();
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
    sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
        .bind(t)
        .bind(e)
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_registry VALUES('urn:browser:test',$1,$2,$3,$4)")
        .bind(&subject)
        .bind(t)
        .bind(e)
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    let hash = [*r.as_bytes(), *r.as_bytes()].concat();
    let csrf = [4u8; 32];
    api.create_browser_session(&hash, &csrf, "urn:browser:test", &subject)
        .await
        .unwrap();
    let session = replica.read_browser_session(&hash).await.unwrap().unwrap();
    assert_eq!(session.subject, subject);
    assert_eq!(session.issuer, "urn:browser:test");
    assert_eq!(session.csrf_hash, csrf);
    assert!(replica
        .read_browser_session(&[8; 32])
        .await
        .unwrap()
        .is_none());
    sqlx::query("UPDATE reviewers SET enabled=false WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    assert!(replica.read_browser_session(&hash).await.unwrap().is_none());
    sqlx::query("UPDATE reviewers SET enabled=true WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reviewer_registry WHERE subject=$1")
        .bind(&subject)
        .execute(&admin)
        .await
        .unwrap();
    assert!(replica.read_browser_session(&hash).await.unwrap().is_none());
    sqlx::query("INSERT INTO reviewer_registry VALUES('urn:browser:test',$1,$2,$3,$4)")
        .bind(&subject)
        .bind(t)
        .bind(e)
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    assert!(!replica
        .revoke_browser_session(&hash, &[9; 32])
        .await
        .unwrap());
    assert!(api.revoke_browser_session(&hash, &csrf).await.unwrap());
    assert!(!replica.revoke_browser_session(&hash, &csrf).await.unwrap());
    assert!(replica.read_browser_session(&hash).await.unwrap().is_none());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM browser_session_audit WHERE reviewer_id=$1")
            .bind(r)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(count, 2, "one creation and one logout audit");
    let second_hash = [*Uuid::new_v4().as_bytes(), *Uuid::new_v4().as_bytes()].concat();
    api.create_browser_session(&second_hash, &csrf, "urn:browser:test", &subject)
        .await
        .unwrap();
    sqlx::query("UPDATE browser_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE session_hash=$1").bind(&second_hash).execute(&admin).await.unwrap();
    assert!(replica
        .read_browser_session(&second_hash)
        .await
        .unwrap()
        .is_none());
    assert!(api
        .create_browser_session(&[7; 32], &csrf, "urn:browser:test", "unknown")
        .await
        .is_err());
    assert!(matches!(
        api.read_browser_session(&[1; 31]).await,
        Err(StoreError::Invalid(_))
    ));
    for table in [
        "browser_login_flows",
        "browser_sessions",
        "browser_session_audit",
    ] {
        let error = sqlx::query(&format!("SELECT * FROM {table}"))
            .execute(&api_pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    let worker = Store::from_pool(runtime(&url, true).await);
    let error = worker.read_browser_session(&hash).await.err().unwrap();
    assert!(
        matches!(error,StoreError::Database(e) if e.as_database_error().unwrap().code().as_deref()==Some("42501"))
    );
}
