use apl_domain::{Principal, RefundRequest, Reviewer};
use apl_persistence::{evidence::EvidenceFilter, Store, StoreError};
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
async fn fixture(admin: &PgPool) -> (Principal, Reviewer) {
    let p = Principal {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        workload_id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
    };
    let reviewer = Reviewer {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        reviewer_id: Uuid::new_v4(),
    };
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("INSERT INTO tenants(tenant_id) VALUES($1)")
        .bind(p.tenant_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments(tenant_id,environment_id) VALUES($1,$2)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES($1,$2,$3)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    for sql in [
        "INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)",
        "INSERT INTO policy_versions VALUES($1,$2,$3,1,5000,50000,1800)",
        "INSERT INTO policy_bindings VALUES($1,$2,$3,1)",
        "INSERT INTO budget_connections VALUES($1,$2,$3,100000,100000)",
    ] {
        sqlx::query(sql)
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(p.connection_id)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id,submit_refund,read_action,read_events) VALUES($1,$2,$3,$4,true,true,true)")
        .bind(p.tenant_id).bind(p.environment_id).bind(p.workload_id).bind(p.connection_id).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer.reviewer_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    (p, reviewer)
}
async fn grant(admin: &PgPool, r: &Reviewer, c: Uuid, enabled: bool) {
    sqlx::query("INSERT INTO evidence_export_grants VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant_id,environment_id,reviewer_id,connection_id) DO UPDATE SET enabled=excluded.enabled")
        .bind(r.tenant_id).bind(r.environment_id).bind(r.reviewer_id).bind(c).bind(enabled).execute(admin).await.unwrap();
}

fn filter(c: Uuid, id: Option<Uuid>) -> EvidenceFilter {
    EvidenceFilter {
        connection_id: c,
        status: None,
        workload_id: None,
        action_id: id,
        min_amount_minor: None,
        max_amount_minor: None,
        after: None,
        limit: None,
    }
}
async fn age(admin: &PgPool, id: Uuid, terminal: bool, days: i32) {
    // Isolated owner-only fixture mutation; DDL and restoration are transactional.
    let mut tx = admin.begin().await.unwrap();
    sqlx::query("ALTER TABLE actions DISABLE TRIGGER maintain_action_retention_times")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE actions SET created_at=NULL,terminal_at=CASE WHEN $2 THEN statement_timestamp()-make_interval(days=>$3) ELSE NULL END,retention_observed_at=statement_timestamp()-make_interval(days=>$3) WHERE id=$1")
  .bind(id).bind(terminal).bind(days).execute(&mut *tx).await.unwrap();
    sqlx::query("ALTER TABLE actions ENABLE TRIGGER maintain_action_retention_times")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}
#[tokio::test]
#[ignore = "requires owned disposable TEST_DATABASE_URL with database admin"]
async fn retention_visibility_exports_and_indefinite_replay() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = runtime(&url, false).await;
    let worker_pool = runtime(&url, true).await;
    let api = Store::from_pool(api_pool.clone());
    let worker = Store::from_pool(worker_pool);
    let (p, r) = fixture(&admin).await;
    grant(&admin, &r, p.connection_id, true).await;
    let (other, other_r) = fixture(&admin).await;
    grant(&admin, &other_r, other.connection_id, true).await;
    let request:RefundRequest=serde_json::from_value(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,"resource":{"payment_id":"test_payment"},"parameters":{"amount_minor":100,"currency":"USD"},"metadata":{}})).unwrap();
    let old = api.submit(&p, "reserved-forever", &request).await.unwrap();
    let active = api.submit(&p, "active", &request).await.unwrap();
    let grace = api.submit(&p, "legacy-grace", &request).await.unwrap();
    let legacy = api.submit(&p, "legacy-old", &request).await.unwrap();
    let held = api.submit(&p, "held", &request).await.unwrap();
    let unresolved = api.submit(&p, "unresolved", &request).await.unwrap();
    for id in [old.id, grace.id, legacy.id, held.id, unresolved.id] {
        sqlx::query("UPDATE actions SET status='succeeded' WHERE id=$1")
            .bind(id)
            .execute(&admin)
            .await
            .unwrap();
    }
    age(&admin, old.id, true, 91).await;
    age(&admin, active.id, true, 200).await;
    age(&admin, grace.id, false, 89).await;
    age(&admin, legacy.id, false, 91).await;
    age(&admin, held.id, true, 200).await;
    age(&admin, unresolved.id, true, 200).await;
    sqlx::query("INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state) VALUES($1,$2,$3,$4,$5,100,current_date,'held')")
  .bind(p.tenant_id).bind(p.environment_id).bind(held.id).bind(p.connection_id).bind(p.workload_id).execute(&admin).await.unwrap();
    sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms) VALUES($1,$2,$3,$4,'retention-test','apl-refund-v1-'||$3::text,1,$5,0)")
  .bind(p.tenant_id).bind(p.environment_id).bind(unresolved.id).bind(p.connection_id)
  .bind(serde_json::json!({"action_id":unresolved.id,"request":{"connection_id":p.connection_id},"state":"manual_review","first_send_at":1,"retry_until":2}))
  .execute(&admin).await.unwrap();
    let ids: Vec<_> = api
        .search_evidence(&r, &filter(p.connection_id, None))
        .await
        .unwrap()
        .items
        .into_iter()
        .map(|x| x.id)
        .collect();
    assert_eq!(ids.len(), 4);
    for id in [active.id, grace.id, held.id, unresolved.id] {
        assert!(ids.contains(&id));
    }
    for id in [old.id, legacy.id] {
        assert!(api
            .search_evidence(&r, &filter(p.connection_id, Some(id)))
            .await
            .unwrap()
            .items
            .is_empty());
        assert!(matches!(
            api.request_export(&r, p.connection_id, &[id]).await,
            Err(StoreError::NotFound)
        ));
    }
    assert!(api
        .search_evidence(&other_r, &filter(other.connection_id, Some(active.id)))
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(matches!(
        api.request_export(&other_r, other.connection_id, &[active.id])
            .await,
        Err(StoreError::NotFound)
    ));
    // A single simple-query message shares statement_timestamp throughout.
    // Test exact inclusive cutoff and its adjacent microseconds under API role.
    for (offset, expected) in [(0, 0), (1, 1), (-1, 0)] {
        let sql = format!(
            r#"BEGIN;
          ALTER TABLE actions DISABLE TRIGGER maintain_action_retention_times;
          UPDATE actions SET terminal_at=statement_timestamp()-interval '90 days'+{offset}*interval '1 microsecond' WHERE id='{id}';
          ALTER TABLE actions ENABLE TRIGGER maintain_action_retention_times;
          SELECT set_config('apl.tenant_id','{tenant}',true),set_config('apl.environment_id','{environment}',true);
          SET LOCAL ROLE apl_api;
          DO $assert$ DECLARE n bigint; BEGIN
            SELECT count(*) INTO n FROM search_action_evidence('{tenant}','{environment}','{reviewer}','{connection}',NULL,NULL,'{id}',NULL,NULL,NULL,50);
            IF n<>{expected} THEN RAISE EXCEPTION 'cutoff assertion: %',n; END IF;
          END $assert$;
          COMMIT;"#,
            id = old.id,
            tenant = p.tenant_id,
            environment = p.environment_id,
            reviewer = r.reviewer_id,
            connection = p.connection_id
        );
        sqlx::raw_sql(&sql).execute(&admin).await.unwrap();
    }
    age(&admin, old.id, true, 91).await;
    // Runtime attempts cannot rewrite timestamps or manufacture a new grace.
    let mut tx = api_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    assert!(
        sqlx::query("UPDATE evidence_retention_settings SET searchable_days=1")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    // Config is scoped and runtime cannot modify it. Widening makes old terminal
    // metadata searchable again without resurrecting an execution.
    assert!(
        sqlx::query("INSERT INTO evidence_retention_settings VALUES($1,$2,365)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .execute(&api_pool)
            .await
            .is_err()
    );
    assert!(
        sqlx::query("INSERT INTO evidence_retention_settings VALUES($1,$2,0)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .execute(&admin)
            .await
            .is_err()
    );
    sqlx::query("INSERT INTO evidence_retention_settings VALUES($1,$2,365)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .execute(&admin)
        .await
        .unwrap();
    assert_eq!(
        api.search_evidence(&r, &filter(p.connection_id, Some(old.id)))
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    sqlx::query("UPDATE evidence_retention_settings SET searchable_days=90 WHERE tenant_id=$1 AND environment_id=$2").bind(p.tenant_id).bind(p.environment_id).execute(&admin).await.unwrap();
    // Legacy timestamps remain unknown, with explicit observation grace.
    let unknown:bool=sqlx::query_scalar("SELECT created_at IS NULL AND terminal_at IS NULL AND retention_observed_at IS NOT NULL FROM actions WHERE id=$1").bind(grace.id).fetch_one(&admin).await.unwrap();
    assert!(unknown);
    // A queued snapshot crossing the metadata boundary fails safely, while a
    // previously materialized export retains its own one-hour download lifetime.
    let ready = api
        .request_export(&r, p.connection_id, &[grace.id])
        .await
        .unwrap();
    let lease = worker.claim_export().await.unwrap().unwrap();
    assert_eq!(lease.id, ready.id);
    worker.export_snapshot(&lease).await.unwrap();
    worker.complete_export(&lease).await.unwrap();
    let queued = api
        .request_export(&r, p.connection_id, &[grace.id])
        .await
        .unwrap();
    let lease = worker.claim_export().await.unwrap().unwrap();
    assert_eq!(lease.id, queued.id);
    age(&admin, grace.id, false, 91).await;
    assert!(matches!(
        worker.export_snapshot(&lease).await,
        Err(StoreError::NotFound)
    ));
    worker.fail_export(&lease, "snapshot_failed").await.unwrap();
    assert_eq!(
        api.export_info(&r, queued.id).await.unwrap().status,
        "failed"
    );
    assert!(api.download_export_lease(&r, ready.id).await.is_ok());
    // Replay remains available beyond searchable retention and never enqueues.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_jobs WHERE action_id=$1")
        .bind(old.id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(
        api.submit(&p, "reserved-forever", &request)
            .await
            .unwrap()
            .id,
        old.id
    );
    let mut changed = request.clone();
    changed.parameters.amount_minor = 101;
    assert!(matches!(
        api.submit(&p, "reserved-forever", &changed).await,
        Err(StoreError::Conflict)
    ));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM outbox_jobs WHERE action_id=$1")
        .bind(old.id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(before, after);
    let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action_id=$1")
        .bind(old.id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(retained, 1);
    for name in [
        "request_evidence_export_retention_base(uuid,uuid,uuid,uuid,uuid,uuid[])",
        "preflight_evidence_export_retention_base(uuid,uuid,uuid)",
        "evidence_action_visible(uuid,uuid,uuid)",
    ] {
        for role in ["apl_api", "apl_worker"] {
            let allowed: bool =
                sqlx::query_scalar("SELECT has_function_privilege($1,$2,'EXECUTE')")
                    .bind(role)
                    .bind(name)
                    .fetch_one(&admin)
                    .await
                    .unwrap();
            assert!(!allowed, "{role} bypass {name}");
        }
    }
}

#[tokio::test]
#[ignore = "requires owned disposable TEST_DATABASE_URL with database admin"]
async fn retention_upgrade_keeps_unknown_legacy_times_and_guards_new_times() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    let database = format!("apl_retention_upgrade_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    let mut scoped_url = url::Url::parse(&url).unwrap();
    scoped_url.set_path(&database);
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(scoped_url.as_str())
        .await
        .unwrap();
    let mut previous = sqlx::migrate!("../../migrations");
    previous.migrations = std::borrow::Cow::Owned(
        previous
            .iter()
            .filter(|m| m.version < 22)
            .cloned()
            .collect(),
    );
    previous.run(&pool).await.unwrap();
    let (p, r) = fixture(&pool).await;
    grant(&pool, &r, p.connection_id, true).await;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status) VALUES($1,$2,$3,$4,$5,'succeeded')")
        .bind(p.tenant_id).bind(p.environment_id).bind(id).bind(p.workload_id)
        .bind(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,"parameters":{"amount_minor":100,"currency":"USD"}}))
        .execute(&pool).await.unwrap();
    // Warm the old preflight plan on this same physical connection before
    // migration; renaming a function alone must not leave a cached bypass.
    let before_upgrade = Store::from_pool(pool.clone());
    before_upgrade
        .request_export(&r, p.connection_id, &[id])
        .await
        .unwrap();
    let old_lease = before_upgrade.claim_export().await.unwrap().unwrap();
    before_upgrade.export_snapshot(&old_lease).await.unwrap();
    Store::from_pool(pool.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let unknown: bool = sqlx::query_scalar("SELECT created_at IS NULL AND terminal_at IS NULL AND retention_observed_at<=statement_timestamp() FROM actions WHERE id=$1")
        .bind(id).fetch_one(&pool).await.unwrap();
    assert!(unknown);
    let api_pool = runtime(scoped_url.as_str(), false).await;
    let worker_pool = runtime(scoped_url.as_str(), true).await;
    let api = Store::from_pool(api_pool.clone());
    assert_eq!(
        api.search_evidence(&r, &filter(p.connection_id, Some(id)))
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    let mut tx = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    let preserved: bool = sqlx::query_scalar("UPDATE actions SET created_at=statement_timestamp(),terminal_at=statement_timestamp(),retention_observed_at='2000-01-01' WHERE id=$1 RETURNING created_at IS NULL AND terminal_at IS NULL AND retention_observed_at>'2000-01-01'")
        .bind(id).fetch_one(&mut *tx).await.unwrap();
    assert!(preserved);
    sqlx::query("UPDATE actions SET status='received' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let stamped:bool=sqlx::query_scalar("UPDATE actions SET status='succeeded' WHERE id=$1 RETURNING created_at IS NULL AND terminal_at=statement_timestamp()")
        .bind(id).fetch_one(&mut *tx).await.unwrap();
    assert!(stamped);
    tx.commit().await.unwrap();
    age(&pool, id, false, 91).await;
    assert!(matches!(
        before_upgrade.export_snapshot(&old_lease).await,
        Err(StoreError::NotFound)
    ));
    assert!(api
        .search_evidence(&r, &filter(p.connection_id, Some(id)))
        .await
        .unwrap()
        .items
        .is_empty());
    let request:RefundRequest=serde_json::from_value(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,"resource":{"payment_id":"test_payment"},"parameters":{"amount_minor":100,"currency":"USD"},"metadata":{}})).unwrap();
    let new = api.submit(&p, "timestamp-new", &request).await.unwrap();
    let known:bool=sqlx::query_scalar("SELECT created_at IS NOT NULL AND terminal_at IS NULL AND retention_observed_at=created_at FROM actions WHERE id=$1").bind(new.id).fetch_one(&pool).await.unwrap();
    assert!(known);
    api_pool.close().await;
    worker_pool.close().await;
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
}
