use apl_domain::Reviewer;
use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL admin"]
async fn operations_scopes_totals_ages_and_runtime_permissions() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let (t, e, c, w, r, a, b, d) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    sqlx::raw_sql(&format!(r#"
      SELECT set_config('apl.tenant_id','{t}',false),set_config('apl.environment_id','{e}',false);
      INSERT INTO tenants(tenant_id,paused) VALUES('{t}',true);
      INSERT INTO environments VALUES('{t}','{e}',true);
      INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{t}','{e}','{c}');
      INSERT INTO workloads(tenant_id,environment_id,workload_id,paused) VALUES('{t}','{e}','{w}',true);
      INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id) VALUES('{t}','{e}','{w}','{c}');
      INSERT INTO reviewers VALUES('{t}','{e}','{r}',true);
      INSERT INTO reviewer_grants VALUES('{t}','{e}','{r}','{c}',true);
      INSERT INTO policy_versions VALUES('{t}','{e}','{c}',1,5000,50000,1800);
      INSERT INTO policy_bindings VALUES('{t}','{e}','{c}',1);
      INSERT INTO budget_connections VALUES('{t}','{e}','{c}',10000,20000);
      INSERT INTO actions VALUES('{t}','{e}','{a}','{w}','{{"connection_id":"{c}","private":"secret"}}','pending_approval',NULL),
      ('{t}','{e}','{b}','{w}','{{"connection_id":"{c}"}}','ready',NULL),
      ('{t}','{e}','{d}','{w}','{{"connection_id":"{c}"}}','dispatching',NULL);
      INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,created_at)
      VALUES('{t}','{e}','{a}',1,'{c}',1,repeat('0',64),clock_timestamp()+interval '1 hour',NULL);
      INSERT INTO outbox_jobs(tenant_id,environment_id,action_id,available_at) VALUES('{t}','{e}','{b}',clock_timestamp()-interval '2 minutes');
      INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state)
      VALUES('{t}','{e}','{a}','{c}','{w}',100,(clock_timestamp() AT TIME ZONE 'UTC')::date-1,'held'),
      ('{t}','{e}','{b}','{c}','{w}',200,(clock_timestamp() AT TIME ZONE 'UTC')::date,'settled'),
      ('{t}','{e}','{d}','{c}','{w}',300,(clock_timestamp() AT TIME ZONE 'UTC')::date,'held');
      INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms,state_changed_at)
      VALUES('{t}','{e}','{d}','{c}','fake','apl-refund-v1-{d}',1,'{{"action_id":"{d}","request":{{"connection_id":"{c}"}},"state":"unknown"}}',0,NULL);
    "#)).execute(&admin).await.unwrap();
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
    // Approval authority alone does not grant operations.
    assert!(matches!(
        store.operations_snapshot(&reviewer, c).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO operations_grants VALUES($1,$2,$3,$4,true)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
    let snap = store.operations_snapshot(&reviewer, c).await.unwrap();
    assert_eq!(
        (
            snap.held_minor,
            snap.committed_today_minor,
            snap.daily_used_minor
        ),
        (400, 200, 500)
    );
    assert_eq!(
        (
            snap.pending_approvals,
            snap.unknown_outcomes,
            snap.unknown_age_records
        ),
        (1, 1, 2)
    );
    assert_eq!(snap.oldest_approval_age_seconds, None);
    assert_eq!(snap.oldest_unresolved_age_seconds, None);
    assert_eq!(snap.ready_jobs, 1);
    assert!(snap.oldest_ready_lag_seconds.unwrap() >= 120);
    assert!(snap.tenant_paused);
    assert_eq!(snap.workloads_paused, 1);
    assert!(!serde_json::to_string(&snap).unwrap().contains("secret"));
    assert_eq!(snap.queued_notifications, 1);
    assert_eq!(snap.failed_notifications, 0);
    assert_eq!(snap.daily_limit_minor, Some(10000));
    assert_eq!(snap.exposure_limit_minor, Some(20000));
    sqlx::query("UPDATE notification_jobs SET status='failed' WHERE action_id=$1")
        .bind(a)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO evidence_exports(tenant_id,environment_id,id,connection_id,requester_id,action_ids,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,'failed',clock_timestamp()+interval '1 hour')")
        .bind(t).bind(e).bind(Uuid::new_v4()).bind(c).bind(r).bind(vec![a]).execute(&admin).await.unwrap();
    let counted = store.operations_snapshot(&reviewer, c).await.unwrap();
    assert_eq!(
        (
            counted.queued_notifications,
            counted.failed_notifications,
            counted.failed_exports
        ),
        (0, 1, 1)
    );
    // State entry timestamps change on state transition, not observations.
    sqlx::query("UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{state}','\"pending\"') WHERE action_id=$1").bind(d).execute(&admin).await.unwrap();
    let snap = store.operations_snapshot(&reviewer, c).await.unwrap();
    assert_eq!(
        (
            snap.unknown_outcomes,
            snap.pending_provider,
            snap.unknown_age_records
        ),
        (0, 1, 1)
    );
    assert!(snap.oldest_unresolved_age_seconds.unwrap() <= 2);
    sqlx::query("UPDATE external_dispatches SET observations=observations+1 WHERE action_id=$1")
        .bind(d)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        store.operations_snapshot(&reviewer, Uuid::new_v4()).await,
        Err(StoreError::NotFound)
    ));
    let foreign = Reviewer {
        tenant_id: Uuid::new_v4(),
        ..reviewer.clone()
    };
    assert!(matches!(
        store.operations_snapshot(&foreign, c).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,created_at) VALUES($1,$2,$3,2,$4,1,repeat('0',64),clock_timestamp()+interval '1 hour',clock_timestamp()-interval '5 minutes')")
        .bind(t).bind(e).bind(a).bind(c).execute(&admin).await.unwrap();
    let latest = store.operations_snapshot(&reviewer, c).await.unwrap();
    assert_eq!(
        (latest.pending_approvals, latest.unknown_age_records),
        (1, 0)
    );
    assert!(latest.oldest_approval_age_seconds.unwrap() >= 300);
    sqlx::query("UPDATE environments SET enabled=false WHERE tenant_id=$1 AND environment_id=$2")
        .bind(t)
        .bind(e)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        store.operations_snapshot(&reviewer, c).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("UPDATE environments SET enabled=true WHERE tenant_id=$1 AND environment_id=$2")
        .bind(t)
        .bind(e)
        .execute(&admin)
        .await
        .unwrap();
    for table in [
        "operations_grants",
        "budget_reservations",
        "external_dispatches",
        "notification_jobs",
        "evidence_exports",
    ] {
        assert!(sqlx::query(&format!("SELECT * FROM {table}"))
            .execute(&api)
            .await
            .is_err());
    }
    for role in ["apl_api", "apl_worker"] {
        let permissions:(bool,bool,bool)=sqlx::query_as("SELECT has_table_privilege($1,'operations_grants','SELECT'),has_table_privilege($1,'operations_grants','UPDATE'),has_function_privilege($1,'read_operations(uuid,uuid,uuid,uuid)','EXECUTE')").bind(role).fetch_one(&admin).await.unwrap();
        assert_eq!(permissions, (false, false, role == "apl_api"));
    }
    sqlx::query("UPDATE operations_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        store.operations_snapshot(&reviewer, c).await,
        Err(StoreError::NotFound)
    ));
    // Snapshot fixtures deliberately model states directly. Do not leave their
    // synthetic ready job for unrelated global worker tests to execute.
    sqlx::query("UPDATE outbox_jobs SET done=true WHERE tenant_id=$1 AND environment_id=$2")
        .bind(t)
        .bind(e)
        .execute(&admin)
        .await
        .unwrap();
    api.close().await;
    admin.close().await;
}
