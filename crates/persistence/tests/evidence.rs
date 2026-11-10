use apl_domain::Reviewer;
use apl_persistence::{evidence::EvidenceFilter, Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

fn filter(connection_id: Uuid) -> EvidenceFilter {
    EvidenceFilter {
        connection_id,
        status: None,
        workload_id: None,
        action_id: None,
        min_amount_minor: None,
        max_amount_minor: None,
        after: None,
        limit: None,
    }
}
async fn fixture(pool: &PgPool) -> (Reviewer, Uuid, Uuid) {
    let r = Reviewer {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        reviewer_id: Uuid::new_v4(),
    };
    let c = Uuid::new_v4();
    let w = Uuid::new_v4();
    sqlx::query("INSERT INTO tenants(tenant_id) VALUES($1)")
        .bind(r.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments(tenant_id,environment_id) VALUES($1,$2)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(c)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES($1,$2,$3)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(w)
        .execute(pool)
        .await
        .unwrap();
    (r, c, w)
}
async fn action(pool: &PgPool, r: &Reviewer, c: Uuid, w: Uuid, amount: i64, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actions VALUES($1,$2,$3,$4,$5,$6,NULL)")
        .bind(r.tenant_id).bind(r.environment_id).bind(id).bind(w)
        .bind(serde_json::json!({"type":"refund.create","connection_id":c,"resource":{"payment_id":"secret_payment_identifier"},
            "parameters":{"amount_minor":amount,"currency":"USD"},"metadata":{"private":"secret_metadata"}}))
        .bind(status).execute(pool).await.unwrap();
    id
}
#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with database administration"]
async fn evidence_keyset_filters_scope_redaction_and_revocation() {
    let url = std::env::var("TEST_DATABASE_URL").expect("dedicated PostgreSQL database required");
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = PgPoolOptions::new()
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_api").execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let api = Store::from_pool(api_pool.clone());
    let (r, c, w) = fixture(&admin).await;
    let (other, other_c, other_w) = fixture(&admin).await;
    let foreign = action(&admin, &other, other_c, other_w, 100, "received").await;
    let mut expected = Vec::new();
    for n in 1..=5 {
        expected.push(
            action(
                &admin,
                &r,
                c,
                w,
                n * 100,
                if n % 2 == 0 { "succeeded" } else { "received" },
            )
            .await,
        );
    }
    expected.sort();
    let mut query = filter(c);
    assert!(matches!(
        api.search_evidence(&r, &query).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO evidence_export_grants VALUES($1,$2,$3,$4,true)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
    let audit_before: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_audit")
        .fetch_one(&admin)
        .await
        .unwrap();
    query.limit = Some(2);
    let mut seen = Vec::new();
    loop {
        let page = api.search_evidence(&r, &query).await.unwrap();
        assert!(page.items.len() <= 2);
        for row in page.items {
            assert_eq!(row.connection_id, c);
            assert_eq!(row.workload_id, w);
            assert_eq!(row.currency, "USD");
            assert_eq!(row.policy_version, None);
            assert_eq!(row.budget_state, None);
            let json = serde_json::to_string(&row).unwrap();
            for forbidden in [
                "payment_id",
                "secret_payment_identifier",
                "metadata",
                "secret_metadata",
                "customer_ref",
                "provider_key",
            ] {
                assert!(!json.contains(forbidden));
            }
            seen.push(row.id);
        }
        if page.next_after.is_none() {
            break;
        }
        query.after = page.next_after;
    }
    assert_eq!(seen, expected);
    assert!(api.search_evidence(&r, &query).await.unwrap().items.len() <= 2);
    query = filter(c);
    query.status = Some("succeeded".into());
    query.min_amount_minor = Some(200);
    query.max_amount_minor = Some(400);
    let rows = api.search_evidence(&r, &query).await.unwrap().items;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|row| matches!(row.amount_minor, 200 | 400)));
    query = filter(c);
    query.action_id = Some(expected[2]);
    assert_eq!(
        api.search_evidence(&r, &query).await.unwrap().items.len(),
        1
    );
    query.action_id = Some(foreign);
    assert!(api
        .search_evidence(&r, &query)
        .await
        .unwrap()
        .items
        .is_empty());
    query = filter(c);
    query.workload_id = Some(other_w);
    assert!(api
        .search_evidence(&r, &query)
        .await
        .unwrap()
        .items
        .is_empty());
    query = filter(other_c);
    assert!(matches!(
        api.search_evidence(&r, &query).await,
        Err(StoreError::NotFound)
    ));
    query = filter(c);
    assert!(matches!(
        api.search_evidence(&other, &query).await,
        Err(StoreError::NotFound)
    ));

    // A second connection in the same tenant/environment is still excluded.
    let second_c = Uuid::new_v4();
    sqlx::query("INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(second_c)
        .execute(&admin)
        .await
        .unwrap();
    let cross_connection = action(&admin, &r, second_c, w, 250, "received").await;
    query = filter(c);
    query.action_id = Some(cross_connection);
    assert!(api
        .search_evidence(&r, &query)
        .await
        .unwrap()
        .items
        .is_empty());
    let audit_after: i64 = sqlx::query_scalar("SELECT count(*) FROM identity_audit")
        .fetch_one(&admin)
        .await
        .unwrap();
    // The only extra audit is the explicitly created second connection.
    assert_eq!(audit_after, audit_before + 1);

    for invalid in [
        serde_json::json!({"connection_id":c,"status":"bogus"}),
        serde_json::json!({"connection_id":c,"min_amount_minor":-1}),
        serde_json::json!({"connection_id":c,"max_amount_minor":50001}),
        serde_json::json!({"connection_id":c,"min_amount_minor":2,"max_amount_minor":1}),
        serde_json::json!({"connection_id":c,"limit":0}),
        serde_json::json!({"connection_id":c,"limit":101}),
    ] {
        let invalid: EvidenceFilter = serde_json::from_value(invalid).unwrap();
        assert!(matches!(
            api.search_evidence(&r, &invalid).await,
            Err(StoreError::Invalid(_))
        ));
    }
    assert!(serde_json::from_value::<EvidenceFilter>(
        serde_json::json!({"connection_id":c,"unexpected":true})
    )
    .is_err());
    query = filter(c);
    let mut revoke = admin.begin().await.unwrap();
    sqlx::query("UPDATE evidence_export_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(r.reviewer_id)
        .execute(&mut *revoke)
        .await
        .unwrap();
    let (result, ()) = tokio::join!(api.search_evidence(&r, &query), async {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        revoke.commit().await.unwrap();
    });
    assert!(matches!(result, Err(StoreError::NotFound)));
    for table in [
        "evidence_export_grants",
        "budget_reservations",
        "action_policy_decisions",
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
}
