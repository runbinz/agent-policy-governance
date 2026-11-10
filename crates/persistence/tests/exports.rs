use apl_domain::{Principal, RefundRequest, Reviewer};
use apl_persistence::{exports::ExportLease, Store, StoreError};
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
async fn expire_lease(admin: &PgPool, lease: &ExportLease) {
    sqlx::query("UPDATE evidence_export_jobs SET lease_until=clock_timestamp()-interval '1 second',available_at=clock_timestamp() WHERE id=$1")
        .bind(lease.id).execute(admin).await.unwrap();
}
#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL and database admin"]
async fn exports_scope_redaction_fences_and_expiry() {
    let url =
        std::env::var("TEST_DATABASE_URL").expect("dedicated PostgreSQL test database required");
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = runtime(&url, false).await;
    let worker_pool = runtime(&url, true).await;
    let api = Store::from_pool(api_pool.clone());
    let worker = Store::from_pool(worker_pool.clone());
    let (p, r) = fixture(&admin).await;
    let (other, other_r) = fixture(&admin).await;
    let request:RefundRequest=serde_json::from_value(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,
        "resource":{"payment_id":"secret_payment_identifier"},"parameters":{"amount_minor":2500,"currency":"USD"},
        "metadata":{"private":"secret_metadata_value"}})).unwrap();
    let action = api.submit(&p, "export-action", &request).await.unwrap();
    while worker.process_one().await.unwrap() {}
    assert!(matches!(
        api.request_export(&r, p.connection_id, &[action.id]).await,
        Err(StoreError::NotFound)
    ));
    grant(&admin, &r, p.connection_id, true).await;
    for ids in [vec![], vec![action.id, action.id]] {
        assert!(matches!(
            api.request_export(&r, p.connection_id, &ids).await,
            Err(StoreError::Invalid(_))
        ));
    }
    assert!(matches!(
        api.request_export(&r, p.connection_id, &[Uuid::new_v4()])
            .await,
        Err(StoreError::NotFound)
    ));
    grant(&admin, &other_r, other.connection_id, true).await;
    assert!(matches!(
        api.request_export(&other_r, other.connection_id, &[action.id])
            .await,
        Err(StoreError::NotFound)
    ));
    let export = api
        .request_export(&r, p.connection_id, &[action.id])
        .await
        .unwrap();
    assert_eq!(export.status, "queued");
    assert!(matches!(
        api.export_info(&other_r, export.id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        api.download_export_lease(&r, export.id).await,
        Err(StoreError::Conflict)
    ));
    let (a, b) = tokio::join!(worker.claim_export(), worker.claim_export());
    let a = a.unwrap();
    let b = b.unwrap();
    assert_ne!(a.is_some(), b.is_some());
    let first = a.or(b).unwrap();
    assert_eq!(first.id, export.id);
    let snapshot = worker.export_snapshot(&first).await.unwrap();
    assert_eq!(snapshot["export_id"], export.id.to_string());
    assert_eq!(snapshot["actions"][0]["budget"]["state"], "settled");
    let text = serde_json::to_string(&snapshot).unwrap();
    for secret in [
        "secret_payment_identifier",
        "secret_metadata_value",
        "payment_id",
        "metadata",
        "provider_key",
        "customer_ref",
    ] {
        assert!(!text.contains(secret), "redaction leaked {secret}");
    }
    // Authorization lock contention must not extend the wall-clock lease.
    let mut grant_lock = admin.begin().await.unwrap();
    sqlx::query("UPDATE evidence_export_grants SET enabled=true WHERE reviewer_id=$1")
        .bind(r.reviewer_id)
        .execute(&mut *grant_lock)
        .await
        .unwrap();
    sqlx::query("UPDATE evidence_export_jobs SET lease_until=clock_timestamp()+interval '200 milliseconds' WHERE id=$1")
        .bind(first.id).execute(&admin).await.unwrap();
    let (completion, ()) = tokio::join!(worker.complete_export(&first), async {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        grant_lock.rollback().await.unwrap();
    });
    assert!(matches!(completion, Err(StoreError::Conflict)));
    // A restarted worker fences both snapshot reads and stale object completions.
    expire_lease(&admin, &first).await;
    let second = worker.claim_export().await.unwrap().unwrap();
    assert_eq!(second.generation, first.generation + 1);
    assert!(matches!(
        worker.export_snapshot(&first).await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        worker.complete_export(&first).await,
        Err(StoreError::Conflict)
    ));
    worker.complete_export(&second).await.unwrap();
    assert_eq!(
        api.export_info(&r, export.id).await.unwrap().status,
        "ready"
    );
    assert_eq!(
        api.download_export_lease(&r, export.id).await.unwrap(),
        second
    );
    api.record_export_download(&r, export.id).await.unwrap();
    assert!(matches!(
        worker.retry_export(&second).await,
        Err(StoreError::Conflict)
    ));
    grant(&admin, &r, p.connection_id, false).await;
    assert!(matches!(
        api.export_info(&r, export.id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        api.download_export_lease(&r, export.id).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        api.record_export_download(&r, export.id).await,
        Err(StoreError::NotFound)
    ));
    grant(&admin, &r, p.connection_id, true).await;
    sqlx::query(
        "UPDATE evidence_exports SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",
    )
    .bind(export.id)
    .execute(&admin)
    .await
    .unwrap();
    assert!(matches!(
        api.download_export_lease(&r, export.id).await,
        Err(StoreError::NotFound)
    ));

    let retry = api
        .request_export(&r, p.connection_id, &[action.id])
        .await
        .unwrap();
    for attempt in 1..=3 {
        sqlx::query("UPDATE evidence_export_jobs SET available_at=clock_timestamp() WHERE id=$1")
            .bind(retry.id)
            .execute(&admin)
            .await
            .unwrap();
        let lease = worker.claim_export().await.unwrap().unwrap();
        assert_eq!(lease.generation, attempt);
        worker.retry_export(&lease).await.unwrap();
        assert!(matches!(
            worker.complete_export(&lease).await,
            Err(StoreError::Conflict)
        ));
    }
    assert_eq!(
        api.export_info(&r, retry.id).await.unwrap().status,
        "failed"
    );

    let large = api
        .request_export(&r, p.connection_id, &[action.id])
        .await
        .unwrap();
    let lease = worker.claim_export().await.unwrap().unwrap();
    assert_eq!(lease.id, large.id);
    sqlx::query("INSERT INTO audit_events(tenant_id,environment_id,action_id,sequence,event_type) SELECT $1,$2,$3,n+100,repeat('x',22000) FROM generate_series(1,1000) n")
        .bind(p.tenant_id).bind(p.environment_id).bind(action.id).execute(&admin).await.unwrap();
    assert!(
        matches!(worker.export_snapshot(&lease).await,Err(StoreError::Invalid(message)) if message=="export_too_large")
    );
    let mut direct = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(lease.tenant_id.to_string())
    .bind(lease.environment_id.to_string())
    .execute(&mut *direct)
    .await
    .unwrap();
    let early = sqlx::query("SELECT snapshot_evidence_export($1,$2,$3,$4,$5,$6)")
        .bind(lease.tenant_id)
        .bind(lease.environment_id)
        .bind(lease.requester_id)
        .bind(lease.connection_id)
        .bind(lease.id)
        .bind(lease.generation)
        .execute(&mut *direct)
        .await
        .unwrap_err();
    let database = early
        .as_database_error()
        .unwrap()
        .downcast_ref::<sqlx::postgres::PgDatabaseError>();
    assert_eq!(database.code(), "AP413");
    assert_eq!(
        database.hint(),
        Some("export_preflight_limit"),
        "byte limit must reject before JSON aggregation"
    );
    direct.rollback().await.unwrap();
    worker
        .fail_export(&lease, "export_too_large")
        .await
        .unwrap();
    assert_eq!(
        api.export_info(&r, large.id)
            .await
            .unwrap()
            .error_code
            .as_deref(),
        Some("export_too_large")
    );
    // This history fits the final byte cap but exceeds the lower operational
    // row cap, proving rejection occurs before the original JSON aggregate.
    let many_action = api.submit(&p, "many-small-events", &request).await.unwrap();
    while worker.process_one().await.unwrap() {}
    sqlx::query("INSERT INTO audit_events(tenant_id,environment_id,action_id,sequence,event_type) SELECT $1,$2,$3,n+100,'small' FROM generate_series(1,20001) n")
        .bind(p.tenant_id).bind(p.environment_id).bind(many_action.id).execute(&admin).await.unwrap();
    let many = api
        .request_export(&r, p.connection_id, &[many_action.id])
        .await
        .unwrap();
    let many_lease = worker.claim_export().await.unwrap().unwrap();
    assert_eq!(many_lease.id, many.id);
    assert!(
        matches!(worker.export_snapshot(&many_lease).await,Err(StoreError::Invalid(message)) if message=="export_too_large")
    );
    worker
        .fail_export(&many_lease, "export_too_large")
        .await
        .unwrap();
    let audits: Vec<String> = sqlx::query_scalar(
        "SELECT event_type FROM evidence_export_audit WHERE export_id=$1 ORDER BY sequence",
    )
    .bind(export.id)
    .fetch_all(&admin)
    .await
    .unwrap();
    assert_eq!(
        audits,
        [
            "export.requested",
            "export.processing",
            "export.processing",
            "export.ready",
            "export.downloaded"
        ]
    );
    // Cleanup is not authorized until expiry plus grace AND the old object
    // writer lease has elapsed. It keeps sweeping after an exhausted batch.
    let cleanup_info = api
        .request_export(&r, p.connection_id, &[action.id])
        .await
        .unwrap();
    sqlx::query("UPDATE evidence_export_jobs SET expires_at=clock_timestamp()-interval '4 minutes' WHERE id=$1")
        .bind(cleanup_info.id).execute(&admin).await.unwrap();
    assert!(worker.claim_export_cleanup().await.unwrap().is_none());
    sqlx::query("UPDATE evidence_export_jobs SET expires_at=clock_timestamp()-interval '6 minutes',lease_until=clock_timestamp()+interval '10 seconds' WHERE id=$1")
        .bind(cleanup_info.id).execute(&admin).await.unwrap();
    assert!(worker.claim_export_cleanup().await.unwrap().is_none());
    sqlx::query("UPDATE evidence_export_jobs SET lease_until=NULL WHERE id=$1")
        .bind(cleanup_info.id)
        .execute(&admin)
        .await
        .unwrap();
    // Even revocation must not prevent deletion of expired artifacts.
    grant(&admin, &r, p.connection_id, false).await;
    let (one, two) = tokio::join!(worker.claim_export_cleanup(), worker.claim_export_cleanup());
    let one = one.unwrap();
    let two = two.unwrap();
    assert_ne!(one.is_some(), two.is_some());
    let first_cleanup = one.or(two).unwrap();
    assert_eq!(first_cleanup.id, cleanup_info.id);
    let mut forged = first_cleanup.clone();
    forged.environment_id = Uuid::new_v4();
    assert!(matches!(
        worker.finish_export_cleanup(&forged, true).await,
        Err(StoreError::Conflict)
    ));
    sqlx::query("UPDATE evidence_export_cleanup_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(cleanup_info.id).execute(&admin).await.unwrap();
    let second_cleanup = worker.claim_export_cleanup().await.unwrap().unwrap();
    assert_eq!(second_cleanup.generation, first_cleanup.generation + 1);
    assert!(matches!(
        worker.finish_export_cleanup(&first_cleanup, true).await,
        Err(StoreError::Conflict)
    ));
    worker
        .finish_export_cleanup(&second_cleanup, false)
        .await
        .unwrap();
    assert!(matches!(
        worker.finish_export_cleanup(&second_cleanup, true).await,
        Err(StoreError::Conflict)
    ));
    assert!(worker.claim_export_cleanup().await.unwrap().is_none());
    let retry_seconds:f64=sqlx::query_scalar("SELECT extract(epoch FROM available_at-clock_timestamp())::double precision FROM evidence_export_cleanup_jobs WHERE id=$1")
        .bind(cleanup_info.id).fetch_one(&admin).await.unwrap();
    assert!(retry_seconds > 3.0 && retry_seconds <= 5.0);
    sqlx::query(
        "UPDATE evidence_export_cleanup_jobs SET available_at=clock_timestamp() WHERE id=$1",
    )
    .bind(cleanup_info.id)
    .execute(&admin)
    .await
    .unwrap();
    let third_cleanup = worker.claim_export_cleanup().await.unwrap().unwrap();
    worker
        .finish_export_cleanup(&third_cleanup, true)
        .await
        .unwrap();
    assert!(worker.claim_export_cleanup().await.unwrap().is_none());
    let sweep_seconds:f64=sqlx::query_scalar("SELECT extract(epoch FROM available_at-clock_timestamp())::double precision FROM evidence_export_cleanup_jobs WHERE id=$1")
        .bind(cleanup_info.id).fetch_one(&admin).await.unwrap();
    assert!(sweep_seconds > 3590.0 && sweep_seconds <= 3600.0);
    // Simulate one-hour later and a late suspended writer's artifact.
    sqlx::query(
        "UPDATE evidence_export_cleanup_jobs SET available_at=clock_timestamp() WHERE id=$1",
    )
    .bind(cleanup_info.id)
    .execute(&admin)
    .await
    .unwrap();
    let resweep = worker.claim_export_cleanup().await.unwrap().unwrap();
    assert!(resweep.generation > third_cleanup.generation);
    worker.finish_export_cleanup(&resweep, true).await.unwrap();
    let cleanup_events:i64=sqlx::query_scalar("SELECT count(*) FROM evidence_export_audit WHERE export_id=$1 AND event_type='export.artifacts_deleted'")
        .bind(cleanup_info.id).fetch_one(&admin).await.unwrap();
    assert_eq!(cleanup_events, 1);
    let denied = sqlx::query("SELECT * FROM claim_evidence_export_cleanup()")
        .execute(&api_pool)
        .await
        .unwrap_err();
    assert_eq!(
        denied.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
    for pool in [&api_pool, &worker_pool] {
        for sql in [
            "SELECT * FROM evidence_exports",
            "UPDATE evidence_export_grants SET enabled=true",
            "DELETE FROM evidence_export_audit",
            "SELECT * FROM evidence_export_jobs",
            "SELECT * FROM evidence_export_cleanup_jobs",
        ] {
            let error = sqlx::query(sql).execute(pool).await.unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("42501")
            );
        }
    }
}
