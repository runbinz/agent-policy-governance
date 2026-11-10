use apl_domain::{RefundRequest, Reviewer};
use apl_persistence::Store;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL admin with disposable database creation privileges"]
async fn queue_timestamp_and_runtime_authorization_predicates() {
    let parent = std::env::var("TEST_DATABASE_URL").unwrap();
    let control = PgPool::connect(&parent).await.unwrap();
    let name = format!("apl_queue_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&control)
        .await
        .unwrap();
    let mut url = url::Url::parse(&parent).unwrap();
    url.set_path(&format!("/{name}"));
    let admin = PgPool::connect(url.as_str()).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let runtime = PgPoolOptions::new()
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_api").execute(c).await?;
                Ok(())
            })
        })
        .connect(url.as_str())
        .await
        .unwrap();
    let unsafe_role: bool = sqlx::query_scalar("SELECT rolsuper OR rolbypassrls OR EXISTS(SELECT FROM pg_class WHERE relname='actions' AND relowner=pg_roles.oid) FROM pg_roles WHERE rolname=current_user")
        .fetch_one(&runtime).await.unwrap();
    assert!(!unsafe_role);
    let store = Store::from_pool(runtime.clone());
    let t = Uuid::new_v4();
    let e = Uuid::new_v4();
    let r = Uuid::new_v4();
    let mut expected = Vec::new();
    // Include foreign tenant and same-tenant foreign environment fixtures.
    for (tenant, environment, visible) in [
        (t, e, true),
        (t, Uuid::new_v4(), false),
        (Uuid::new_v4(), Uuid::new_v4(), false),
    ] {
        let c = Uuid::new_v4();
        let w = Uuid::new_v4();
        sqlx::raw_sql(&format!(r#"
            INSERT INTO tenants(tenant_id) VALUES('{tenant}') ON CONFLICT DO NOTHING;
            INSERT INTO environments(tenant_id,environment_id) VALUES('{tenant}','{environment}');
            INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES('{tenant}','{environment}','{w}');
            INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{tenant}','{environment}','{c}');
            INSERT INTO reviewers VALUES('{tenant}','{environment}','{r}',true);
            INSERT INTO reviewer_grants VALUES('{tenant}','{environment}','{r}','{c}',true);
            INSERT INTO policy_versions VALUES('{tenant}','{environment}','{c}',1,5000,50000,1800);
            INSERT INTO policy_bindings VALUES('{tenant}','{environment}','{c}',1);
        "#)).execute(&admin).await.unwrap();
        for (known, expired, decided) in [
            (false, false, false),
            (true, false, false),
            (true, true, false),
            (true, false, true),
        ] {
            let id = Uuid::new_v4();
            let request: RefundRequest = serde_json::from_value(serde_json::json!({
                "type":"refund.create", "connection_id":c,
                "resource":{"payment_id":"fake_payment"},
                "parameters":{"amount_minor":2500,"currency":"USD"}
            }))
            .unwrap();
            sqlx::query("INSERT INTO actions VALUES($1,$2,$3,$4,$5,'pending_approval',NULL)")
                .bind(tenant)
                .bind(environment)
                .bind(id)
                .bind(w)
                .bind(serde_json::to_value(&request).unwrap())
                .execute(&admin)
                .await
                .unwrap();
            sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,created_at,decision,reviewer_id,decided_at) VALUES($1,$2,$3,7,$4,1,repeat('a',64),clock_timestamp()+CASE WHEN $6 THEN interval '-1 second' ELSE interval '1 hour' END,CASE WHEN $5 THEN '2026-01-02T03:04:05.123456Z'::timestamptz ELSE NULL END,CASE WHEN $7 THEN 'reject' ELSE NULL END,CASE WHEN $7 THEN $8::uuid ELSE NULL END,CASE WHEN $7 THEN clock_timestamp() ELSE NULL END)")
                .bind(tenant).bind(environment).bind(id).bind(c).bind(known).bind(expired).bind(decided).bind(r)
                .execute(&admin).await.unwrap();
            if visible && !expired && !decided {
                expected.push((id, known, request));
            }
        }
    }
    let reviewer = Reviewer {
        tenant_id: t,
        environment_id: e,
        reviewer_id: r,
    };
    let queue = store.list_approvals(&reviewer).await.unwrap();
    assert_eq!(queue.len(), 2);
    for (id, known, request) in &expected {
        let item = queue.iter().find(|q| q.action_id == *id).unwrap();
        assert_eq!(
            item.queued_at.as_deref(),
            known.then_some("2026-01-02T03:04:05.123456Z")
        );
        assert_eq!(
            (
                &item.request,
                item.generation,
                item.policy_version,
                item.action_digest.as_str()
            ),
            (
                request,
                7,
                1,
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
        );
        let json = serde_json::to_value(item).unwrap();
        assert!(json.get("queued_at").is_some());
        assert_eq!(json["queued_at"].is_null(), !known);
    }
    // Every existing security/eligibility predicate still filters the timestamp DTO.
    for (change, restore) in [
        (
            "UPDATE reviewer_grants SET enabled=false",
            "UPDATE reviewer_grants SET enabled=true",
        ),
        (
            "UPDATE actions SET status='ready'",
            "UPDATE actions SET status='pending_approval'",
        ),
    ] {
        sqlx::query(change).execute(&admin).await.unwrap();
        assert!(
            store.list_approvals(&reviewer).await.unwrap().is_empty(),
            "{change}"
        );
        sqlx::query(restore).execute(&admin).await.unwrap();
        assert_eq!(store.list_approvals(&reviewer).await.unwrap().len(), 2);
    }
    sqlx::query("INSERT INTO policy_versions SELECT tenant_id,environment_id,connection_id,2,5000,50000,1800 FROM policy_bindings")
        .execute(&admin).await.unwrap();
    sqlx::query("UPDATE policy_bindings SET version=2")
        .execute(&admin)
        .await
        .unwrap();
    assert!(store.list_approvals(&reviewer).await.unwrap().is_empty());
    runtime.close().await;
    admin.close().await;
    sqlx::query(&format!("DROP DATABASE {name}"))
        .execute(&control)
        .await
        .unwrap();
    control.close().await;
}
