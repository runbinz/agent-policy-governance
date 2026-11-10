use apl_domain::Reviewer;
use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires owned disposable TEST_DATABASE_URL admin"]
async fn policy_page_runtime_authority_pagination_and_publication() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let (t, e, c, r) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    sqlx::raw_sql(&format!(r#"INSERT INTO tenants(tenant_id) VALUES('{t}');
      INSERT INTO environments VALUES('{t}','{e}',true);
      INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{t}','{e}','{c}');
      INSERT INTO reviewers VALUES('{t}','{e}','{r}',true);
      INSERT INTO reviewer_grants VALUES('{t}','{e}','{r}','{c}',true);
      INSERT INTO policy_versions SELECT '{t}','{e}','{c}',n,100,50000,1800 FROM generate_series(1,5) n;
      INSERT INTO policy_bindings VALUES('{t}','{e}','{c}',1);"#)).execute(&admin).await.unwrap();
    let api = PgPoolOptions::new()
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_api").execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = Store::from_pool(api.clone());
    let reviewer = Reviewer {
        tenant_id: t,
        environment_id: e,
        reviewer_id: r,
    };
    let empty = Uuid::new_v4();
    sqlx::query("INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)")
        .bind(t)
        .bind(e)
        .bind(empty)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO connection_admin_grants VALUES($1,$2,$3,$4,true,true,false,false)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(empty)
        .execute(&admin)
        .await
        .unwrap();
    let page = store
        .policy_page(&reviewer, empty, None, 100)
        .await
        .unwrap();
    assert!(page.active_policy.is_none() && page.versions.is_empty() && page.next_after.is_none());
    assert!(matches!(
        store.policy_page(&reviewer, c, None, 2).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO connection_admin_grants VALUES($1,$2,$3,$4,true,true,false,false)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
    let page = store.policy_page(&reviewer, c, None, 2).await.unwrap();
    assert!(page.can_edit && !page.can_publish);
    assert!(matches!(
        store.publish_policy(&reviewer, c, 2, 1).await,
        Err(StoreError::Forbidden)
    ));
    assert_eq!(
        page.versions.iter().map(|p| p.version).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert_eq!(page.next_after, Some(2));
    let page = store
        .policy_page(&reviewer, c, page.next_after, 2)
        .await
        .unwrap();
    assert_eq!(page.active_policy.unwrap().version, 1);
    assert_eq!(
        page.versions.iter().map(|p| p.version).collect::<Vec<_>>(),
        vec![3, 4]
    );
    let page = store
        .policy_page(&reviewer, c, page.next_after, 2)
        .await
        .unwrap();
    assert_eq!(page.versions[0].version, 5);
    assert!(page.next_after.is_none());
    for (after, limit) in [
        (Some(0), 2),
        (Some(9_007_199_254_740_992), 2),
        (None, 0),
        (None, 101),
    ] {
        assert!(matches!(
            store.policy_page(&reviewer, c, after, limit).await,
            Err(StoreError::Invalid(_))
        ));
    }
    assert!(matches!(
        store
            .policy_page(
                &Reviewer {
                    environment_id: Uuid::new_v4(),
                    ..reviewer.clone()
                },
                c,
                None,
                2
            )
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store
            .policy_page(
                &Reviewer {
                    tenant_id: Uuid::new_v4(),
                    ..reviewer.clone()
                },
                c,
                None,
                2
            )
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.policy_page(&reviewer, Uuid::new_v4(), None, 2).await,
        Err(StoreError::NotFound)
    ));
    for (table, column, id) in [
        ("tenants", "tenant_id", t),
        ("environments", "environment_id", e),
        ("connections", "connection_id", c),
        ("reviewers", "reviewer_id", r),
        ("connection_admin_grants", "reviewer_id", r),
    ] {
        let q = format!("UPDATE {table} SET enabled=$1 WHERE {column}=$2");
        sqlx::query(&q)
            .bind(false)
            .bind(id)
            .execute(&admin)
            .await
            .unwrap();
        assert!(
            matches!(
                store.policy_page(&reviewer, c, None, 2).await,
                Err(StoreError::NotFound)
            ),
            "{table}"
        );
        sqlx::query(&q)
            .bind(true)
            .bind(id)
            .execute(&admin)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE connection_admin_grants SET edit_policy=false,publish_policy=false,control_dispatch=true WHERE reviewer_id=$1").bind(r).execute(&admin).await.unwrap();
    assert!(matches!(
        store.policy_page(&reviewer, c, None, 2).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("UPDATE connection_admin_grants SET publish_policy=true WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    let page = store.policy_page(&reviewer, c, None, 2).await.unwrap();
    assert!(!page.can_edit && page.can_publish);
    assert!(matches!(
        store
            .create_policy_draft(
                &reviewer,
                c,
                &apl_domain::PolicyVersion {
                    version: 6,
                    auto_limit_minor: 100,
                    hard_limit_minor: 50000,
                    approval_ttl_seconds: 1800,
                },
            )
            .await,
        Err(StoreError::Forbidden)
    ));
    // A read snapshot serializes with publication, preserving exact expected-version semantics.
    let mut reader = api.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(t.to_string())
    .bind(e.to_string())
    .execute(&mut *reader)
    .await
    .unwrap();
    let _: serde_json::Value = sqlx::query_scalar("SELECT read_policy_page($1,$2,$3,$4,NULL,2)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    let mut writer = admin.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='150ms'")
        .execute(&mut *writer)
        .await
        .unwrap();
    let error = sqlx::query("UPDATE policy_bindings SET version=2 WHERE connection_id=$1")
        .bind(c)
        .execute(&mut *writer)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("55P03")
    );
    writer.rollback().await.unwrap();
    reader.commit().await.unwrap();
    store.publish_policy(&reviewer, c, 2, 1).await.unwrap();
    assert!(matches!(
        store.publish_policy(&reviewer, c, 3, 1).await,
        Err(StoreError::Conflict)
    ));
    assert_eq!(
        store
            .policy_page(&reviewer, c, None, 1)
            .await
            .unwrap()
            .active_policy
            .unwrap()
            .version,
        2
    );
    // Safe numeric boundary is exact; unsafe returned and active values fail closed.
    sqlx::query("INSERT INTO policy_versions VALUES($1,$2,$3,9007199254740991,100,50000,1800),($1,$2,$3,9007199254740992,100,50000,1800)").bind(t).bind(e).bind(c).execute(&admin).await.unwrap();
    assert!(store.policy_page(&reviewer, c, Some(5), 1).await.is_ok());
    assert!(matches!(
        store
            .policy_page(&reviewer, c, Some(9_007_199_254_740_991), 1)
            .await,
        Err(StoreError::Serialization(_))
    ));
    store
        .publish_policy(&reviewer, c, 9_007_199_254_740_992, 2)
        .await
        .unwrap();
    assert!(matches!(
        store.policy_page(&reviewer, c, None, 1).await,
        Err(StoreError::Serialization(_))
    ));
    let public:bool=sqlx::query_scalar("SELECT has_function_privilege('public','read_policy_page(uuid,uuid,uuid,uuid,bigint,bigint)','EXECUTE')").fetch_one(&admin).await.unwrap();
    assert!(!public);
    assert!(sqlx::query("SELECT * FROM policy_versions")
        .fetch_all(&api)
        .await
        .is_err());
    api.close().await;
    admin.close().await;
}
