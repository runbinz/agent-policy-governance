use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

#[derive(Clone, Copy)]
struct Scope {
    t: Uuid,
    e: Uuid,
    c: Uuid,
    w: Uuid,
}
async fn fixture(pool: &PgPool) -> Scope {
    let s = Scope {
        t: Uuid::new_v4(),
        e: Uuid::new_v4(),
        c: Uuid::new_v4(),
        w: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO tenants(tenant_id) VALUES($1)")
        .bind(s.t)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments(tenant_id,environment_id) VALUES($1,$2)")
        .bind(s.t)
        .bind(s.e)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES($1,$2,$3)")
        .bind(s.t)
        .bind(s.e)
        .bind(s.w)
        .execute(pool)
        .await
        .unwrap();
    for sql in [
        "INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES($1,$2,$3)",
        "INSERT INTO policy_versions VALUES($1,$2,$3,1,5000,50000,1800)",
        "INSERT INTO policy_bindings VALUES($1,$2,$3,1)",
    ] {
        sqlx::query(sql)
            .bind(s.t)
            .bind(s.e)
            .bind(s.c)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id,submit_refund) VALUES($1,$2,$3,$4,true)")
  .bind(s.t).bind(s.e).bind(s.w).bind(s.c).execute(pool).await.unwrap();
    s
}
async fn pending(pool: &PgPool, s: Scope) -> (Uuid, Uuid) {
    let a = Uuid::new_v4();
    sqlx::query("INSERT INTO actions VALUES($1,$2,$3,$4,$5,'pending_approval',NULL)")
  .bind(s.t).bind(s.e).bind(a).bind(s.w).bind(serde_json::json!({"type":"refund.create","connection_id":s.c,"resource":{"payment_id":"redacted"},"parameters":{"currency":"USD","amount_minor":6000}}))
  .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at) VALUES($1,$2,$3,1,$4,1,repeat('0',64),clock_timestamp()+interval '1 hour')")
  .bind(s.t).bind(s.e).bind(a).bind(s.c).execute(pool).await.unwrap();
    let job = sqlx::query_scalar("SELECT id FROM notification_jobs WHERE action_id=$1")
        .bind(a)
        .fetch_one(pool)
        .await
        .unwrap();
    (a, job)
}
async fn route(pool: &PgPool, s: Scope, kind: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO notification_routes(id,tenant_id,environment_id,connection_id,kind,team_id,channel_id) VALUES($1,$2,$3,$4,$5,$6,$7)")
  .bind(id).bind(s.t).bind(s.e).bind(s.c).bind(kind).bind((kind=="slack").then_some("T12345678")).bind((kind=="slack").then_some("C12345678"))
  .execute(pool).await.unwrap();
    id
}
async fn expire(pool: &PgPool, job: Uuid) {
    sqlx::query("UPDATE notification_jobs SET lease_until=clock_timestamp()-interval '1 second',available_at=clock_timestamp() WHERE id=$1").bind(job).execute(pool).await.unwrap();
    sqlx::query("UPDATE notification_channels SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=$1").bind(job).execute(pool).await.unwrap();
}
#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL admin"]
async fn durable_notifications_scopes_leases_suppression_and_cooldown() {
    let url = std::env::var("TEST_DATABASE_URL").expect("dedicated PostgreSQL required");
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let worker_pool = PgPoolOptions::new()
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_worker").execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let worker = Store::from_pool(worker_pool.clone());
    let s = fixture(&admin).await;
    let (action, job) = pending(&admin, s).await;
    // The enqueue and audit must roll back with their approval.
    let mut rolled = admin.begin().await.unwrap();
    sqlx::query("INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at) VALUES($1,$2,$3,2,$4,1,repeat('1',64),clock_timestamp()+interval '1 hour')")
  .bind(s.t).bind(s.e).bind(action).bind(s.c).execute(&mut *rolled).await.unwrap();
    rolled.rollback().await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_jobs WHERE action_id=$1")
            .bind(action)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(count, 1);
    let fake = route(&admin, s, "fake").await;
    assert!(worker
        .claim_notification(fake, "slack")
        .await
        .unwrap()
        .is_none());
    let (one, two) = tokio::join!(
        worker.claim_notification(fake, "fake"),
        worker.claim_notification(fake, "fake")
    );
    let one = one.unwrap();
    let two = two.unwrap();
    assert_ne!(one.is_some(), two.is_some());
    let lease = one.or(two).unwrap();
    assert_eq!(lease.id, job);
    assert_eq!(lease.action_id, action);
    assert!(worker.notification_preflight(&lease).await.unwrap());
    assert!(worker.record_fake_notification(&lease).await.unwrap());
    assert!(worker.record_fake_notification(&lease).await.unwrap());
    let receipts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM notification_receipts WHERE job_id=$1")
            .bind(job)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(receipts, 1);
    // A real post may finish after a decision or route change; completion records fact.
    sqlx::query("UPDATE actions SET status='ready' WHERE id=$1")
        .bind(action)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("UPDATE notification_routes SET enabled=false WHERE id=$1")
        .bind(fake)
        .execute(&admin)
        .await
        .unwrap();
    worker
        .finish_notification(&lease, "delivered", 0)
        .await
        .unwrap();
    assert!(matches!(
        worker.finish_notification(&lease, "delivered", 0).await,
        Err(StoreError::Conflict)
    ));
    sqlx::query("UPDATE notification_routes SET enabled=true WHERE id=$1")
        .bind(fake)
        .execute(&admin)
        .await
        .unwrap();
    let (_, suppressed) = pending(&admin, s).await;
    let lease = worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lease.id, suppressed);
    sqlx::query("UPDATE workload_grants SET enabled=false WHERE workload_id=$1")
        .bind(s.w)
        .execute(&admin)
        .await
        .unwrap();
    assert!(!worker.notification_preflight(&lease).await.unwrap());
    sqlx::query("UPDATE workload_grants SET enabled=true WHERE workload_id=$1")
        .bind(s.w)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        worker.record_fake_notification(&lease).await,
        Err(StoreError::Conflict)
    ));
    let (_, crashes) = pending(&admin, s).await;
    let old = worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .unwrap();
    expire(&admin, crashes).await;
    let next = worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(next.generation, old.generation + 1);
    assert!(matches!(
        worker.notification_preflight(&old).await,
        Err(StoreError::Conflict)
    ));
    for expected in 2..=8 {
        let current = if expected == 2 {
            next.clone()
        } else {
            worker
                .claim_notification(fake, "fake")
                .await
                .unwrap()
                .unwrap()
        };
        assert_eq!(current.generation, expected);
        expire(&admin, crashes).await;
    }
    assert!(worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .is_none());
    let status: String = sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
        .bind(crashes)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(status, "failed");

    let a = fixture(&admin).await;
    let b = fixture(&admin).await;
    let (_, ja) = pending(&admin, a).await;
    let (_, jb) = pending(&admin, b).await;
    let ra = route(&admin, a, "slack").await;
    let rb = route(&admin, b, "slack").await;
    let stale = worker
        .claim_notification(ra, "slack")
        .await
        .unwrap()
        .unwrap();
    assert!(worker
        .claim_notification(rb, "slack")
        .await
        .unwrap()
        .is_none());
    expire(&admin, ja).await;
    let owner = worker
        .claim_notification(rb, "slack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.id, jb);
    assert!(matches!(
        worker.finish_notification(&stale, "delivered", 0).await,
        Err(StoreError::Conflict)
    ));
    assert!(worker.notification_preflight(&owner).await.unwrap());
    worker
        .finish_notification(&owner, "retry", 30)
        .await
        .unwrap();
    assert!(worker
        .claim_notification(ra, "slack")
        .await
        .unwrap()
        .is_none());
    let wait:f64=sqlx::query_scalar("SELECT extract(epoch FROM next_send_at-clock_timestamp())::double precision FROM notification_channels WHERE team_id='T12345678' AND channel_id='C12345678'").fetch_one(&admin).await.unwrap();
    assert!(wait > 28.0 && wait <= 30.0);
    sqlx::query("UPDATE notification_channels SET next_send_at=clock_timestamp()")
        .execute(&admin)
        .await
        .unwrap();
    let current = worker
        .claim_notification(ra, "slack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(current.id, ja);
    let mut forged = current.clone();
    forged.tenant_id = b.t;
    assert!(matches!(
        worker.notification_preflight(&forged).await,
        Err(StoreError::Conflict)
    ));
    worker
        .finish_notification(&current, "failed", 0)
        .await
        .unwrap();
    assert!(worker
        .claim_notification(rb, "slack")
        .await
        .unwrap()
        .is_none());

    // An already-assigned retry cannot move to a replacement recipient.
    let (_, sticky) = pending(&admin, s).await;
    let assigned = worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(assigned.id, sticky);
    worker
        .finish_notification(&assigned, "retry", 0)
        .await
        .unwrap();
    let (_, active_crash) = pending(&admin, s).await;
    let active_lease = worker
        .claim_notification(fake, "fake")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(active_lease.id, active_crash);
    let (_, unassigned) = pending(&admin, s).await;
    sqlx::query("UPDATE notification_routes SET enabled=false WHERE id=$1")
        .bind(fake)
        .execute(&admin)
        .await
        .unwrap();
    let replacement = route(&admin, s, "slack").await;
    sqlx::query("UPDATE notification_channels SET next_send_at=clock_timestamp()")
        .execute(&admin)
        .await
        .unwrap();
    let replacement_claim = worker
        .claim_notification(replacement, "slack")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replacement_claim.id, unassigned);
    let sticky_status: String =
        sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
            .bind(sticky)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(sticky_status, "skipped");
    let active_status: String =
        sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
            .bind(active_crash)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(active_status, "processing");
    expire(&admin, active_crash).await;
    assert!(worker
        .claim_notification(replacement, "slack")
        .await
        .unwrap()
        .is_none());
    let active_status: String =
        sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
            .bind(active_crash)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(active_status, "skipped");

    sqlx::query("UPDATE notification_routes SET enabled=false WHERE id=$1")
        .bind(replacement)
        .execute(&admin)
        .await
        .unwrap();
    worker
        .finish_notification(&replacement_claim, "retry", 0)
        .await
        .unwrap();
    let unassigned_status: String =
        sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
            .bind(unassigned)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(unassigned_status, "skipped");

    let obsolete_scope = fixture(&admin).await;
    let (_, obsolete) = pending(&admin, obsolete_scope).await;
    let obsolete_route = route(&admin, obsolete_scope, "fake").await;
    sqlx::query("INSERT INTO policy_versions VALUES($1,$2,$3,2,5000,50000,1800)")
        .bind(obsolete_scope.t)
        .bind(obsolete_scope.e)
        .bind(obsolete_scope.c)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("UPDATE policy_bindings SET version=2 WHERE connection_id=$1")
        .bind(obsolete_scope.c)
        .execute(&admin)
        .await
        .unwrap();
    assert!(worker
        .claim_notification(obsolete_route, "fake")
        .await
        .unwrap()
        .is_none());
    let obsolete_status: String =
        sqlx::query_scalar("SELECT status FROM notification_jobs WHERE id=$1")
            .bind(obsolete)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(obsolete_status, "skipped");
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
    for pool in [&api_pool, &worker_pool] {
        for table in [
            "notification_routes",
            "notification_jobs",
            "notification_channels",
            "notification_receipts",
            "notification_audit",
        ] {
            let error = sqlx::query(&format!("SELECT * FROM {table}"))
                .execute(pool)
                .await
                .unwrap_err();
            assert_eq!(
                error.as_database_error().unwrap().code().as_deref(),
                Some("42501")
            );
        }
    }
    let error = sqlx::query("SELECT * FROM claim_notification($1,'fake')")
        .bind(fake)
        .execute(&api_pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
}
