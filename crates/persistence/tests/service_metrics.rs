use apl_persistence::Store;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL admin with disposable database creation privileges"]
async fn global_metrics_totals_labels_and_permissions() {
    // Global totals/oldest ages cannot share arbitrary fixtures from other
    // workspace tests. Own one isolated database and remove only that database.
    let parent_url = std::env::var("TEST_DATABASE_URL").unwrap();
    let control = PgPool::connect(&parent_url).await.unwrap();
    let name = format!("apl_metrics_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&control)
        .await
        .unwrap();
    let mut parsed = url::Url::parse(&parent_url).unwrap();
    parsed.set_path(&format!("/{name}"));
    let url = parsed.to_string();
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

    for role in ["apl_api", "apl_worker"] {
        let can_create: bool =
            sqlx::query_scalar("SELECT has_schema_privilege($1,'public','CREATE')")
                .bind(role)
                .fetch_one(&admin)
                .await
                .unwrap();
        assert!(!can_create);
        let role_name = role.to_string();
        let pool = PgPoolOptions::new()
            .after_connect(move |c, _| {
                let command = format!("SET ROLE {role_name}");
                Box::pin(async move {
                    sqlx::query(&command).execute(c).await?;
                    Ok(())
                })
            })
            .connect(&url)
            .await
            .unwrap();
        let snap = Store::from_pool(pool.clone())
            .service_metrics()
            .await
            .unwrap();
        assert_eq!(
            (
                snap.held_minor,
                snap.committed_today_minor,
                snap.pending_approvals
            ),
            (400, 200, 1)
        );
        assert_eq!(
            (
                snap.unknown_outcomes,
                snap.pending_provider,
                snap.manual_review,
                snap.unknown_age_records
            ),
            (1, 0, 0, 2)
        );
        assert_eq!(snap.oldest_approval_age_seconds, None);
        assert_eq!(snap.oldest_unresolved_age_seconds, None);
        assert_eq!(snap.ready_jobs, 1);
        assert!(snap.oldest_ready_lag_seconds.unwrap() >= 120);
        assert!(!serde_json::to_string(&snap).unwrap().contains("secret"));
        // Runtime SELECT is still scoped by RLS and cannot read global rows.
        assert!(sqlx::query("SELECT * FROM budget_reservations")
            .execute(&pool)
            .await
            .is_err());
        let visible: i64 = sqlx::query_scalar("SELECT count(*) FROM actions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(visible, 0);
        pool.close().await;
    }
    let store = Store::from_pool(admin.clone());
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,created_at) VALUES($1,$2,$3,2,$4,1,repeat('0',64),clock_timestamp()+interval '1 hour',clock_timestamp()-interval '5 minutes')").bind(t).bind(e).bind(a).bind(c).execute(&admin).await.unwrap();
    let snap = store.service_metrics().await.unwrap();
    assert_eq!((snap.pending_approvals, snap.unknown_age_records), (1, 1));
    assert!(snap.oldest_approval_age_seconds.unwrap() >= 300);
    sqlx::query("UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{state}','\"pending\"') WHERE action_id=$1").bind(d).execute(&admin).await.unwrap();
    let snap = store.service_metrics().await.unwrap();
    assert_eq!(
        (
            snap.unknown_outcomes,
            snap.pending_provider,
            snap.unknown_age_records
        ),
        (0, 1, 0)
    );
    sqlx::query("UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{state}','\"manual_review\"') WHERE action_id=$1").bind(d).execute(&admin).await.unwrap();
    assert_eq!(store.service_metrics().await.unwrap().manual_review, 1);
    sqlx::query("UPDATE notification_jobs SET status='failed' WHERE action_id=$1")
        .bind(a)
        .execute(&admin)
        .await
        .unwrap();
    assert_eq!(
        store.service_metrics().await.unwrap().failed_notifications,
        2
    );
    // Newest expired generation suppresses an older otherwise-pending approval.
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at) VALUES($1,$2,$3,3,$4,1,repeat('0',64),clock_timestamp()-interval '1 second')").bind(t).bind(e).bind(a).bind(c).execute(&admin).await.unwrap();
    assert_eq!(store.service_metrics().await.unwrap().pending_approvals, 0);
    for n in 1..=100 {
        sqlx::query("INSERT INTO audit_events(tenant_id,environment_id,action_id,sequence,event_type) VALUES($1,$2,$3,$4,'{}')").bind(t).bind(e).bind(a).bind(n as i64).execute(&admin).await.unwrap();
        sqlx::query("INSERT INTO action_policy_decisions(tenant_id,environment_id,action_id,audit_sequence,connection_id,outcome,reason) VALUES($1,$2,$3,$4,$5,'approved',$6)").bind(t).bind(e).bind(a).bind(n as i64).bind(c).bind(format!("secret-{n}\n{{label=bad}}")).execute(&admin).await.unwrap();
    }
    let snap = store.service_metrics().await.unwrap();
    assert_eq!(snap.decisions.len(), 1);
    assert_eq!(
        (
            &*snap.decisions[0].outcome,
            &*snap.decisions[0].reason,
            snap.decisions[0].count
        ),
        ("other", "OTHER", 100)
    );
    let permission:(bool,Vec<String>)=sqlx::query_as("SELECT has_function_privilege('public','read_service_metrics()','EXECUTE'),proconfig FROM pg_proc WHERE oid='read_service_metrics()'::regprocedure").fetch_one(&admin).await.unwrap();
    assert!(!permission.0);
    assert!(permission.1.iter().any(|v| v == "statement_timeout=5s"));
    // An active binding mismatch excludes pending approvals even when latest/unexpired.
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at) VALUES($1,$2,$3,4,$4,1,repeat('0',64),clock_timestamp()+interval '1 hour')").bind(t).bind(e).bind(a).bind(c).execute(&admin).await.unwrap();
    assert_eq!(store.service_metrics().await.unwrap().pending_approvals, 1);
    sqlx::query("INSERT INTO policy_versions SELECT tenant_id,environment_id,connection_id,2,5000,50000,1800 FROM policy_bindings WHERE tenant_id=$1").bind(t).execute(&admin).await.unwrap();
    sqlx::query("UPDATE policy_bindings SET version=2 WHERE tenant_id=$1")
        .bind(t)
        .execute(&admin)
        .await
        .unwrap();
    assert_eq!(store.service_metrics().await.unwrap().pending_approvals, 0);
    let c2 = Uuid::new_v4();
    let a2 = Uuid::new_v4();
    sqlx::query("INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)")
        .bind(t)
        .bind(e)
        .bind(c2)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO actions VALUES($1,$2,$3,$4,'{}','ready',NULL)")
        .bind(t)
        .bind(e)
        .bind(a2)
        .bind(w)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO budget_connections VALUES($1,$2,$3,10000,20000)")
        .bind(t)
        .bind(e)
        .bind(c2)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state) VALUES($1,$2,$3,$4,$5,700,(clock_timestamp() AT TIME ZONE 'UTC')::date,'held')").bind(t).bind(e).bind(a2).bind(c2).bind(w).execute(&admin).await.unwrap();
    assert_eq!(store.service_metrics().await.unwrap().held_minor, 1100);
    sqlx::query("INSERT INTO audit_events VALUES($1,$2,$3,101,'decision')")
        .bind(t)
        .bind(e)
        .bind(a)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO action_policy_decisions(tenant_id,environment_id,action_id,audit_sequence,connection_id,outcome,reason) VALUES($1,$2,$3,101,$4,'allow','POLICY_AUTO_ALLOW')").bind(t).bind(e).bind(a).bind(c).execute(&admin).await.unwrap();
    let snap = store.service_metrics().await.unwrap();
    assert_eq!(snap.decisions.len(), 2);
    assert!(snap
        .decisions
        .iter()
        .any(|d| d.outcome == "allow" && d.reason == "POLICY_AUTO_ALLOW" && d.count == 1));
    // Manual-review rows are closed in the private queue and never ready.
    let empty = store.service_metrics().await.unwrap();
    assert_eq!(
        (empty.ready_external_dispatches, empty.stale_dispatch_leases),
        (0, 0)
    );
    assert_eq!(empty.oldest_external_ready_lag_seconds, None);
    let now_ms: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM statement_timestamp())*1000)::bigint")
            .fetch_one(&admin)
            .await
            .unwrap();
    // Use actual dispatch rows so the queue trigger and generated lease/closed
    // columns participate. Expired in_flight leases survive a process crash.
    for (state, offset, lease, expected_ready, expected_stale) in [
        (
            serde_json::json!("in_flight"),
            -120_000,
            Some(now_ms - 1),
            1,
            1,
        ),
        (serde_json::json!("unknown"), -60_000, None, 2, 1),
        (serde_json::json!("pending"), 120_000, None, 2, 1),
        (
            serde_json::json!("in_flight"),
            -300_000,
            Some(now_ms + 120_000),
            2,
            1,
        ),
        (serde_json::json!({"succeeded":{}}), -600_000, None, 2, 1),
        (serde_json::json!("manual_review"), -600_000, None, 2, 1),
        (
            serde_json::json!("in_flight"),
            120_000,
            Some(now_ms - 1),
            2,
            1,
        ),
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO actions VALUES($1,$2,$3,$4,'{}','dispatching',NULL)")
            .bind(t)
            .bind(e)
            .bind(id)
            .bind(w)
            .execute(&admin)
            .await
            .unwrap();
        let snapshot = serde_json::json!({"action_id":id,"request":{"connection_id":c},"state":state,"lease":{"expires_at":lease}});
        sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms) VALUES($1,$2,$3,$4,'fake',$5,1,$6,$7)").bind(t).bind(e).bind(id).bind(c).bind(format!("apl-refund-v1-{id}")).bind(snapshot).bind(now_ms+offset).execute(&admin).await.unwrap();
        let snap = store.service_metrics().await.unwrap();
        assert_eq!(
            (snap.ready_external_dispatches, snap.stale_dispatch_leases),
            (expected_ready, expected_stale)
        );
        assert!((120..125).contains(&snap.oldest_external_ready_lag_seconds.unwrap()));
    }
    for role in ["apl_api", "apl_worker"] {
        let rights:(bool,bool,bool)=sqlx::query_as("SELECT has_function_privilege($1,'read_service_metrics()','EXECUTE'),has_function_privilege($1,'read_service_metrics_base()','EXECUTE'),has_table_privilege($1,'external_dispatch_queue','SELECT')").bind(role).fetch_one(&admin).await.unwrap();
        assert_eq!(rights, (true, false, false));
    }
    for function in ["read_service_metrics()", "read_service_metrics_base()"] {
        let config: Vec<String> =
            sqlx::query_scalar("SELECT proconfig FROM pg_proc WHERE oid=$1::regprocedure")
                .bind(function)
                .fetch_one(&admin)
                .await
                .unwrap();
        assert!(config.iter().any(|v| v == "row_security=off"));
        assert!(config.iter().any(|v| v == "statement_timeout=5s"));
    }
    for role in ["apl_api", "apl_worker"] {
        let bypass: bool =
            sqlx::query_scalar("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=$1")
                .bind(role)
                .fetch_one(&admin)
                .await
                .unwrap();
        assert!(!bypass);
    }
    // Transactional role/owner changes are rolled back even after the expected
    // failed statement. Only this test's private child database is affected.
    let restricted_owner = format!("apl_metrics_owner_{}", Uuid::new_v4().simple());
    let original_owner:String=sqlx::query_scalar("SELECT pg_get_userbyid(proowner)::text FROM pg_proc WHERE oid='read_service_metrics_base()'::regprocedure").fetch_one(&admin).await.unwrap();
    let mut tx = admin.begin().await.unwrap();
    sqlx::query(&format!(
        "CREATE ROLE {restricted_owner} NOLOGIN NOSUPERUSER NOBYPASSRLS"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT USAGE ON SCHEMA public TO {restricted_owner}"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO {restricted_owner}"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(&format!(
        "ALTER FUNCTION read_service_metrics_base() OWNER TO {restricted_owner}"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    let error = sqlx::query_scalar::<_, serde_json::Value>("SELECT read_service_metrics()")
        .fetch_one(&mut *tx)
        .await
        .unwrap_err();
    tx.rollback().await.unwrap();
    let restored_owner:String=sqlx::query_scalar("SELECT pg_get_userbyid(proowner)::text FROM pg_proc WHERE oid='read_service_metrics_base()'::regprocedure").fetch_one(&admin).await.unwrap();
    assert_eq!(restored_owner, original_owner);
    let role_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_roles WHERE rolname=$1)")
            .bind(restricted_owner)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(!role_exists);
    let database_error = error.as_database_error().unwrap();
    assert_eq!(database_error.code().as_deref(), Some("42501"));
    assert!(database_error.message().contains("row-level security"));
    assert_eq!(store.service_metrics().await.unwrap().held_minor, 1100);
    admin.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&control)
        .await
        .unwrap();
    control.close().await;
}
