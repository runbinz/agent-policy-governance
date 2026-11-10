//! Uses an owned child database so global queue claims cannot consume other tests' jobs.
//! TEST_DATABASE_URL=postgres://... cargo test -p apl-persistence --test postgres -- --ignored
use apl_domain::{
    ActionStatus, ApprovalDecision, ApprovalInput, Principal, RefundRequest, Reviewer,
};
use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;

async fn runtime_pool(url: &str, worker: bool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(6)
        .after_connect(move |connection, _| {
            Box::pin(async move {
                sqlx::query(if worker {
                    "SET ROLE apl_worker"
                } else {
                    "SET ROLE apl_api"
                })
                .execute(connection)
                .await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .expect("runtime pool")
}
fn principal() -> Principal {
    Principal {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        workload_id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
    }
}
fn request(p: &Principal) -> RefundRequest {
    serde_json::from_value(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,"resource":{"payment_id":"fake_payment"},"parameters":{"amount_minor":2500,"currency":"USD"}})).unwrap()
}

async fn publish(pool: &PgPool, p: &Principal, version: i64, auto: i64, hard: i64, ttl: i64) {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO policy_versions VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .bind(version)
        .bind(auto)
        .bind(hard)
        .bind(ttl)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO policy_bindings VALUES($1,$2,$3,$4) ON CONFLICT(tenant_id,environment_id,connection_id) DO UPDATE SET version=excluded.version")
        .bind(p.tenant_id).bind(p.environment_id).bind(p.connection_id).bind(version).execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

async fn configure_budget(pool: &PgPool, p: &Principal, daily: i64, exposure: i64) {
    sqlx::query("INSERT INTO budget_connections VALUES($1,$2,$3,$4,$5)
        ON CONFLICT(tenant_id,environment_id,connection_id)
        DO UPDATE SET daily_limit_minor=excluded.daily_limit_minor,exposure_limit_minor=excluded.exposure_limit_minor")
        .bind(p.tenant_id).bind(p.environment_id).bind(p.connection_id).bind(daily).bind(exposure)
        .execute(pool).await.unwrap();
}

async fn seed(pool: &PgPool, p: &Principal, subject: &str) {
    sqlx::query("INSERT INTO tenants VALUES($1,true) ON CONFLICT DO NOTHING")
        .bind(p.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments VALUES($1,$2,true) ON CONFLICT DO NOTHING")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workloads VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO connections VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workload_grants VALUES($1,$2,$3,$4,true,true,true,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO identity_registry VALUES('urn:apl:test',$1,$2,$3,$4,$5)")
        .bind(subject)
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .execute(pool)
        .await
        .unwrap();
    publish(pool, p, 1, 5000, 50000, 1800).await;
    configure_budget(pool, p, 1_000_000, 1_000_000).await;
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL admin with database and role creation privileges"]
async fn isolation_concurrency_and_restart() {
    let parent = std::env::var("TEST_DATABASE_URL")
        .expect("set TEST_DATABASE_URL to a dedicated PostgreSQL database; do not use production");
    let control = PgPool::connect(&parent).await.unwrap();
    let database = format!("apl_isolation_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&control)
        .await
        .unwrap();
    let mut child = url::Url::parse(&parent).unwrap();
    child.set_path(&database);
    let url = child.to_string();
    let admin = Store::connect(&url).await.unwrap();
    admin.migrate().await.unwrap();
    let admin_pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin_pool)
        .await
        .unwrap();
    let api_pool = runtime_pool(&url, false).await;
    let worker_pool = runtime_pool(&url, true).await;
    let unsafe_role:bool=sqlx::query_scalar("SELECT rolsuper OR rolbypassrls OR EXISTS(SELECT FROM pg_class WHERE relname='actions' AND relowner=pg_roles.oid) FROM pg_roles WHERE rolname=current_user").fetch_one(&api_pool).await.unwrap();
    assert!(
        !unsafe_role,
        "tests must execute under nonowner nonbypass runtime role"
    );
    let api = Store::from_pool(api_pool.clone());
    let worker = Store::from_pool(worker_pool.clone());
    let p = principal();
    seed(&admin_pool, &p, &p.workload_id.to_string()).await;
    let mut second_connection = p.clone();
    second_connection.connection_id = Uuid::new_v4();
    sqlx::query("INSERT INTO connections VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(second_connection.connection_id)
        .execute(&admin_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workload_grants VALUES($1,$2,$3,$4,true,true,true,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(second_connection.connection_id)
        .execute(&admin_pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO identity_registry VALUES('urn:apl:test',$1,$2,$3,$4,$5)")
        .bind(format!("second-{}", p.workload_id))
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(second_connection.connection_id)
        .execute(&admin_pool)
        .await
        .unwrap();
    publish(&admin_pool, &second_connection, 1, 5000, 50000, 1800).await;
    configure_budget(&admin_pool, &second_connection, 1_000_000, 1_000_000).await;
    let second_action = api
        .submit(
            &second_connection,
            "second-connection",
            &request(&second_connection),
        )
        .await
        .unwrap();
    assert!(api.get(&p, second_action.id).await.unwrap().is_none());
    assert!(api.events(&p, second_action.id).await.unwrap().is_none());
    assert!(api
        .get(&second_connection, second_action.id)
        .await
        .unwrap()
        .is_some());
    let r = request(&p);
    let (first, second) = tokio::join!(
        api.submit(&p, "same-key", &r),
        api.submit(&p, "same-key", &r)
    );
    let first = first.unwrap();
    assert_eq!(first.id, second.unwrap().id);
    let mut changed = r.clone();
    changed.parameters.amount_minor += 1;
    assert!(matches!(
        api.submit(&p, "same-key", &changed).await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        api.get(&principal(), first.id).await,
        Err(StoreError::Forbidden)
    ));
    assert!(matches!(
        api.events(&principal(), first.id).await,
        Err(StoreError::Forbidden)
    ));
    let mut other_env = p.clone();
    other_env.environment_id = Uuid::new_v4();
    assert!(matches!(
        api.get(&other_env, first.id).await,
        Err(StoreError::Forbidden)
    ));
    let mut other_workload = p.clone();
    other_workload.workload_id = Uuid::new_v4();
    assert!(matches!(
        api.get(&other_workload, first.id).await,
        Err(StoreError::Forbidden)
    ));
    let other = principal();
    seed(&admin_pool, &other, &other.workload_id.to_string()).await;
    assert!(api.get(&other, first.id).await.unwrap().is_none());
    assert!(api.events(&other, first.id).await.unwrap().is_none());
    let other_action = api
        .submit(&other, "same-key", &request(&other))
        .await
        .unwrap();
    assert_ne!(
        first.id, other_action.id,
        "same keys in separate tenants must be independent"
    );
    assert_eq!(
        api.submit(&other, "same-key", &request(&other))
            .await
            .unwrap()
            .id,
        other_action.id
    );
    for statement in [
        "SELECT * FROM claim_next_job()",
        "SELECT complete_job('00000000-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000000')",
        "SELECT * FROM outbox_jobs",
        "SELECT * FROM fake_effects",
        "UPDATE audit_events SET event_type='forged'",
        "UPDATE workloads SET enabled=false",
        "UPDATE workload_grants SET submit_refund=true",
        "SELECT * FROM identity_registry",
        "INSERT INTO identity_audit(actor,table_name,operation) VALUES('fake','fake','UPDATE')",
    ] {
        let error = sqlx::query(statement).execute(&api_pool).await.unwrap_err();
        assert_eq!(error.as_database_error().unwrap().code().as_deref(), Some("42501"), "API role should lack privilege for {statement}");
    }
    let invalid_grant = sqlx::query("INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id) VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id).bind(p.environment_id).bind(p.workload_id).bind(other.connection_id)
        .execute(&admin_pool).await.unwrap_err();
    assert_eq!(
        invalid_grant.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let mut cross_reference = api_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *cross_reference)
    .await
    .unwrap();
    let error = sqlx::query("INSERT INTO submission_keys VALUES($1,$2,$3,'cross-reference',$4,$5)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(vec![0_u8])
        .bind(other_action.id)
        .execute(&mut *cross_reference)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    cross_reference.rollback().await.unwrap();
    // No context must yield no rows even without explicit tenant predicates.
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM actions")
        .fetch_one(&api_pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    // An interrupted worker transaction releases the claim, retaining pending work.
    let mut interrupted = worker_pool.begin().await.unwrap();
    let claimed = sqlx::query("SELECT * FROM claim_next_job()")
        .fetch_one(&mut *interrupted)
        .await
        .unwrap();
    let claimed_tenant: Uuid = claimed.get("tenant_id");
    let claimed_environment: Uuid = claimed.get("environment_id");
    let claimed_action: Uuid = claimed.get("action_id");
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(claimed_tenant.to_string())
    .bind(claimed_environment.to_string())
    .execute(&mut *interrupted)
    .await
    .unwrap();
    sqlx::query("INSERT INTO fake_effects VALUES($1,$2,$3)")
        .bind(claimed_tenant)
        .bind(claimed_environment)
        .bind(claimed_action)
        .execute(&mut *interrupted)
        .await
        .unwrap();
    interrupted.rollback().await.unwrap();
    let rolled_back_effects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
            .bind(claimed_action)
            .fetch_one(&admin_pool)
            .await
            .unwrap();
    assert_eq!(
        rolled_back_effects, 0,
        "interrupted fake effect must roll back"
    );
    drop(worker);
    let restarted = Store::from_pool(worker_pool.clone());
    while restarted.process_one().await.unwrap() {}
    assert_eq!(
        api.get(&p, first.id).await.unwrap().unwrap().status,
        ActionStatus::Succeeded
    );
    assert_eq!(api.events(&p, first.id).await.unwrap().unwrap().len(), 2);
    assert!(!restarted.process_one().await.unwrap());
    let effects: i64 = sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
        .bind(first.id)
        .fetch_one(&admin_pool)
        .await
        .unwrap();
    assert_eq!(effects, 1);
    publish(&admin_pool, &p, 2, 5000, 5000, 1800).await;
    let mut denied = r.clone();
    denied.parameters.amount_minor = 5001;
    let denied = api.submit(&p, "deny", &denied).await.unwrap();
    while restarted.process_one().await.unwrap() {}
    assert_eq!(
        api.get(&p, denied.id).await.unwrap().unwrap().status,
        ActionStatus::Denied
    );
    let effects: i64 = sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
        .bind(denied.id)
        .fetch_one(&admin_pool)
        .await
        .unwrap();
    assert_eq!(effects, 0);

    let mut concurrent_actions = Vec::new();
    for index in 0..12 {
        concurrent_actions.push(
            api.submit(&p, &format!("worker-race-{index}"), &r)
                .await
                .unwrap()
                .id,
        );
    }
    let second_worker = Store::from_pool(worker_pool.clone());
    let drain_one = async {
        let mut processed = 0;
        while restarted.process_one().await.unwrap() {
            processed += 1;
        }
        processed
    };
    let drain_two = async {
        let mut processed = 0;
        while second_worker.process_one().await.unwrap() {
            processed += 1;
        }
        processed
    };
    let (one, two) = tokio::join!(drain_one, drain_two);
    assert_eq!(one + two, concurrent_actions.len());
    for id in concurrent_actions {
        assert_eq!(
            api.get(&p, id).await.unwrap().unwrap().status,
            ActionStatus::Succeeded
        );
        assert_eq!(api.events(&p, id).await.unwrap().unwrap().len(), 2);
        let effects: i64 =
            sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
                .bind(id)
                .fetch_one(&admin_pool)
                .await
                .unwrap();
        assert_eq!(effects, 1);
    }
    let recovered_effects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
            .bind(claimed_action)
            .fetch_one(&admin_pool)
            .await
            .unwrap();
    assert_eq!(recovered_effects, 1);
    assert!(api
        .resolve_identity("urn:apl:test", "unknown")
        .await
        .unwrap()
        .is_none());
    let subject = p.workload_id.to_string();
    assert_eq!(
        api.resolve_identity("urn:apl:test", &subject)
            .await
            .unwrap(),
        Some(p.clone())
    );
    let mut active_authorization = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *active_authorization)
    .await
    .unwrap();
    let allowed: bool = sqlx::query_scalar("SELECT authorize_scope($1,$2,$3,$4,'submit_refund')")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .fetch_one(&mut *active_authorization)
        .await
        .unwrap();
    assert!(allowed);
    let mut revocation = admin_pool.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *revocation)
        .await
        .unwrap();
    let blocked = sqlx::query("UPDATE workload_grants SET enabled=false WHERE workload_id=$1")
        .bind(p.workload_id)
        .execute(&mut *revocation)
        .await
        .unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03"),
        "revocation must serialize with active authorization"
    );
    revocation.rollback().await.unwrap();
    active_authorization.rollback().await.unwrap();
    let revoked = api.submit(&p, "revoke-before-dispatch", &r).await.unwrap();
    sqlx::query("UPDATE workload_grants SET submit_refund=false WHERE workload_id=$1")
        .bind(p.workload_id)
        .execute(&admin_pool)
        .await
        .unwrap();
    assert!(matches!(
        api.submit(&p, "cannot-submit", &r).await,
        Err(StoreError::Forbidden)
    ));
    assert!(
        api.get(&p, revoked.id).await.unwrap().is_some(),
        "read grant is independent of submit"
    );
    while restarted.process_one().await.unwrap() {}
    let outcome = api.get(&p, revoked.id).await.unwrap().unwrap();
    assert_eq!(outcome.status, ActionStatus::Denied);
    assert_eq!(outcome.reason.as_deref(), Some("AUTHORIZATION_REVOKED"));
    let effects: i64 = sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
        .bind(revoked.id)
        .fetch_one(&admin_pool)
        .await
        .unwrap();
    assert_eq!(effects, 0);
    sqlx::query("UPDATE workload_grants SET submit_refund=true,read_action=false,read_events=false WHERE workload_id=$1").bind(p.workload_id).execute(&admin_pool).await.unwrap();
    assert!(api.submit(&p, "submit-without-read", &r).await.is_ok());
    assert!(matches!(
        api.get(&p, first.id).await,
        Err(StoreError::Forbidden)
    ));
    assert!(matches!(
        api.events(&p, first.id).await,
        Err(StoreError::Forbidden)
    ));
    for table in ["workloads", "connections", "workload_grants"] {
        let column = if table == "connections" {
            "connection_id"
        } else {
            "workload_id"
        };
        let id = if table == "connections" {
            p.connection_id
        } else {
            p.workload_id
        };
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=false WHERE {column}=$1"
        ))
        .bind(id)
        .execute(&admin_pool)
        .await
        .unwrap();
        assert!(api
            .resolve_identity("urn:apl:test", &subject)
            .await
            .unwrap()
            .is_none());
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=true WHERE {column}=$1"
        ))
        .bind(id)
        .execute(&admin_pool)
        .await
        .unwrap();
    }
    let audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM identity_audit WHERE new_record->>'workload_id'=$1",
    )
    .bind(p.workload_id.to_string())
    .fetch_one(&admin_pool)
    .await
    .unwrap();
    assert!(audits >= 8);
    while restarted.process_one().await.unwrap() {}
    approval_regressions(&admin_pool, &api, &restarted).await;
    control_regressions(&admin_pool, &api_pool, &worker_pool, &api, &restarted).await;
    budget_dispatch_regressions(&admin_pool, &api, &restarted).await;
    scope_pause_regressions(&admin_pool, &api_pool, &worker_pool, &api, &restarted).await;
    api_pool.close().await;
    worker_pool.close().await;
    admin_pool.close().await;
    drop(admin);
    sqlx::query(&format!("DROP DATABASE {database} WITH (FORCE)"))
        .execute(&control)
        .await
        .unwrap();
    control.close().await;
}

async fn seed_reviewer(pool: &PgPool, p: &Principal) -> Reviewer {
    let reviewer = Reviewer {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        reviewer_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer.reviewer_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_grants VALUES($1,$2,$3,$4,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer.reviewer_id)
        .bind(p.connection_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_registry VALUES('urn:apl:test-review',$1,$2,$3,$4)")
        .bind(reviewer.reviewer_id.to_string())
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer.reviewer_id)
        .execute(pool)
        .await
        .unwrap();
    reviewer
}
async fn drain(worker: &Store) {
    while worker.process_one().await.unwrap() {}
}
async fn effect_count(admin: &PgPool, id: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
        .bind(id)
        .fetch_one(admin)
        .await
        .unwrap()
}
async fn input_for(api: &Store, reviewer: &Reviewer, id: Uuid) -> ApprovalInput {
    let entry = api
        .list_approvals(reviewer)
        .await
        .unwrap()
        .into_iter()
        .find(|q| q.action_id == id)
        .unwrap();
    ApprovalInput {
        generation: entry.generation,
        action_digest: entry.action_digest,
        decision: ApprovalDecision::Approve,
    }
}
async fn approval_regressions(admin: &PgPool, api: &Store, worker: &Store) {
    let p = principal();
    seed(admin, &p, &p.workload_id.to_string()).await;
    let reviewer = seed_reviewer(admin, &p).await;
    assert_eq!(
        api.resolve_reviewer("urn:apl:test-review", &reviewer.reviewer_id.to_string())
            .await
            .unwrap(),
        Some(reviewer.clone())
    );
    let other = principal();
    seed(admin, &other, &other.workload_id.to_string()).await;
    let other_reviewer = seed_reviewer(admin, &other).await;
    let mut other_connection = p.clone();
    other_connection.connection_id = Uuid::new_v4();
    sqlx::query("INSERT INTO connections VALUES($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(other_connection.connection_id)
        .execute(admin)
        .await
        .unwrap();
    let wrong_connection = seed_reviewer(admin, &other_connection).await;

    let mut r = request(&p);
    r.parameters.amount_minor = 5001;
    let action = api.submit(&p, "approval-race", &r).await.unwrap();
    drain(worker).await;
    assert_eq!(
        api.get(&p, action.id).await.unwrap().unwrap().status,
        ActionStatus::PendingApproval
    );
    assert_eq!(effect_count(admin, action.id).await, 0);
    let approve = input_for(api, &reviewer, action.id).await;
    assert!(api
        .list_approvals(&other_reviewer)
        .await
        .unwrap()
        .is_empty());
    assert!(api
        .list_approvals(&wrong_connection)
        .await
        .unwrap()
        .is_empty());
    for outsider in [&other_reviewer, &wrong_connection] {
        assert!(matches!(
            api.decide_approval(outsider, action.id, &approve).await,
            Err(StoreError::NotFound)
        ));
    }
    let mut wrong = approve.clone();
    wrong.action_digest = "0".repeat(64);
    assert!(matches!(
        api.decide_approval(&reviewer, action.id, &wrong).await,
        Err(StoreError::Conflict)
    ));
    wrong = approve.clone();
    wrong.generation += 1;
    assert!(matches!(
        api.decide_approval(&reviewer, action.id, &wrong).await,
        Err(StoreError::Conflict)
    ));
    let reject = ApprovalInput {
        decision: ApprovalDecision::Reject,
        ..approve.clone()
    };
    let (a, b) = tokio::join!(
        api.decide_approval(&reviewer, action.id, &approve),
        api.decide_approval(&reviewer, action.id, &reject)
    );
    assert!(matches!(
        (&a, &b),
        (Ok(_), Err(StoreError::Conflict)) | (Err(StoreError::Conflict), Ok(_))
    ));
    drain(worker).await;
    let expected = if a.is_ok() {
        ActionStatus::Succeeded
    } else {
        ActionStatus::Rejected
    };
    assert_eq!(
        api.get(&p, action.id).await.unwrap().unwrap().status,
        expected
    );
    assert_eq!(effect_count(admin, action.id).await, i64::from(a.is_ok()));
    assert!(matches!(
        api.decide_approval(&reviewer, action.id, &approve).await,
        Err(StoreError::Conflict)
    ));

    let action = api.submit(&p, "policy-change", &r).await.unwrap();
    drain(worker).await;
    let stale = input_for(api, &reviewer, action.id).await;
    api.decide_approval(&reviewer, action.id, &stale)
        .await
        .unwrap();
    publish(admin, &p, 2, 4000, 50000, 1800).await;
    drain(worker).await;
    assert_eq!(effect_count(admin, action.id).await, 0);
    let fresh = input_for(api, &reviewer, action.id).await;
    assert_eq!(fresh.generation, stale.generation + 1);
    assert_ne!(fresh.action_digest, stale.action_digest);
    assert!(matches!(
        api.decide_approval(&reviewer, action.id, &stale).await,
        Err(StoreError::Conflict)
    ));
    api.decide_approval(&reviewer, action.id, &fresh)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, action.id).await, 1);

    let action = api.submit(&p, "reviewer-revocation", &r).await.unwrap();
    drain(worker).await;
    let approve = input_for(api, &reviewer, action.id).await;
    api.decide_approval(&reviewer, action.id, &approve)
        .await
        .unwrap();
    sqlx::query("UPDATE reviewer_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(reviewer.reviewer_id)
        .execute(admin)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, action.id).await, 0);
    assert_eq!(
        api.get(&p, action.id).await.unwrap().unwrap().status,
        ActionStatus::PendingApproval
    );
    sqlx::query("UPDATE reviewer_grants SET enabled=true WHERE reviewer_id=$1")
        .bind(reviewer.reviewer_id)
        .execute(admin)
        .await
        .unwrap();
    let fresh = input_for(api, &reviewer, action.id).await;
    assert_eq!(fresh.generation, approve.generation + 1);
    api.decide_approval(
        &reviewer,
        action.id,
        &ApprovalInput {
            decision: ApprovalDecision::Reject,
            ..fresh
        },
    )
    .await
    .unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, action.id).await, 0);

    publish(admin, &p, 3, 4000, 50000, 1).await;
    let action = api.submit(&p, "expiry", &r).await.unwrap();
    drain(worker).await;
    let approve = input_for(api, &reviewer, action.id).await;
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    assert!(matches!(
        api.decide_approval(&reviewer, action.id, &approve).await,
        Err(StoreError::Conflict)
    ));
    drain(worker).await;
    assert_eq!(
        api.get(&p, action.id).await.unwrap().unwrap().status,
        ActionStatus::Expired
    );
    assert_eq!(effect_count(admin, action.id).await, 0);
}

async fn control_regressions(
    admin: &PgPool,
    api_pool: &PgPool,
    worker_pool: &PgPool,
    api: &Store,
    worker: &Store,
) {
    let p = principal();
    seed(admin, &p, &p.workload_id.to_string()).await;
    let r = request(&p);
    let action = api.submit(&p, "cancel", &r).await.unwrap();
    assert!(matches!(
        api.cancel(&p, action.id).await,
        Err(StoreError::Forbidden)
    ));
    sqlx::query("UPDATE workload_grants SET cancel_action=true WHERE workload_id=$1")
        .bind(p.workload_id)
        .execute(admin)
        .await
        .unwrap();
    assert!(matches!(
        api.cancel(&p, Uuid::new_v4()).await,
        Err(StoreError::NotFound)
    ));
    let cancelled = api.cancel(&p, action.id).await.unwrap();
    assert_eq!(cancelled.status, ActionStatus::Cancelled);
    assert!(matches!(
        api.cancel(&p, action.id).await,
        Err(StoreError::Conflict)
    ));
    drain(worker).await;
    assert_eq!(effect_count(admin, action.id).await, 0);
    assert_eq!(
        api.events(&p, action.id)
            .await
            .unwrap()
            .unwrap()
            .last()
            .unwrap()
            .event_type,
        "action.cancelled"
    );

    let reviewer = seed_reviewer(admin, &p).await;
    let mut review_request = r.clone();
    review_request.parameters.amount_minor = 5001;
    let reviewed = api
        .submit(&p, "cancel-approved", &review_request)
        .await
        .unwrap();
    drain(worker).await;
    let input = input_for(api, &reviewer, reviewed.id).await;
    assert_eq!(
        api.decide_approval(&reviewer, reviewed.id, &input)
            .await
            .unwrap()
            .status,
        ActionStatus::Ready
    );
    assert_eq!(
        api.cancel(&p, reviewed.id).await.unwrap().status,
        ActionStatus::Cancelled
    );
    drain(worker).await;
    assert_eq!(effect_count(admin, reviewed.id).await, 0);
    let history:Vec<(Option<i64>,String,String)>=sqlx::query_as("SELECT policy_version,outcome,reason FROM action_policy_decisions WHERE action_id=$1 ORDER BY audit_sequence")
        .bind(reviewed.id).fetch_all(admin).await.unwrap();
    assert_eq!(
        history,
        vec![
            (
                Some(1),
                "require_approval".into(),
                "APPROVAL_REQUIRED".into()
            ),
            (Some(1), "approved".into(), "REVIEW_APPROVED".into())
        ]
    );

    let race = api.submit(&p, "cancel-race", &r).await.unwrap();
    let (cancel, processed) = tokio::join!(api.cancel(&p, race.id), worker.process_one());
    processed.unwrap();
    let final_action = api.get(&p, race.id).await.unwrap().unwrap();
    if cancel.is_ok() {
        assert_eq!(final_action.status, ActionStatus::Cancelled);
        assert_eq!(effect_count(admin, race.id).await, 0);
    } else {
        assert!(matches!(cancel, Err(StoreError::Conflict)));
        assert_eq!(final_action.status, ActionStatus::Succeeded);
        assert_eq!(effect_count(admin, race.id).await, 1);
    }

    let mut locked = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *locked)
    .await
    .unwrap();
    let allowed: bool = sqlx::query_scalar("SELECT authorize_scope($1,$2,$3,$4,'submit_refund')")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .fetch_one(&mut *locked)
        .await
        .unwrap();
    assert!(allowed);
    let mut admin_tx = admin.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *admin_tx)
        .await
        .unwrap();
    let blocked = sqlx::query("SELECT set_connection_paused($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .execute(&mut *admin_tx)
        .await
        .unwrap_err();
    assert_eq!(
        blocked.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    admin_tx.rollback().await.unwrap();
    locked.rollback().await.unwrap();

    let paused: bool = sqlx::query_scalar("SELECT set_connection_paused($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .fetch_one(admin)
        .await
        .unwrap();
    assert!(paused);
    let blocked = api.submit(&p, "paused", &r).await.unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, blocked.id).await, 0);
    assert_eq!(
        api.get(&p, blocked.id).await.unwrap().unwrap().status,
        ActionStatus::Received
    );
    let resuming: bool = sqlx::query_scalar("SELECT set_connection_paused($1,$2,$3,false)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .fetch_one(admin)
        .await
        .unwrap();
    assert!(resuming);
    // Advance this job's test clock without sleeping through the polling delay.
    sqlx::query("UPDATE outbox_jobs SET available_at=clock_timestamp() WHERE action_id=$1")
        .bind(blocked.id)
        .execute(admin)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, blocked.id).await, 1);
    assert!(matches!(
        api.cancel(&p, blocked.id).await,
        Err(StoreError::Conflict)
    ));
    let history: (Option<i64>, String, String) = sqlx::query_as(
        "SELECT policy_version,outcome,reason FROM action_policy_decisions WHERE action_id=$1",
    )
    .bind(blocked.id)
    .fetch_one(admin)
    .await
    .unwrap();
    assert_eq!(
        history,
        (Some(1), "allow".into(), "POLICY_AUTO_ALLOW".into())
    );
    let pause_count:i64=sqlx::query_scalar("SELECT count(*) FROM identity_audit WHERE table_name='connections' AND operation='UPDATE' AND new_record->>'connection_id'=$1 AND new_record->>'paused' IS DISTINCT FROM old_record->>'paused'")
        .bind(p.connection_id.to_string()).fetch_one(admin).await.unwrap();
    assert_eq!(pause_count, 2);
    for pool in [api_pool, worker_pool] {
        for statement in [
            "UPDATE action_policy_decisions SET reason='forged'",
            "DELETE FROM action_policy_decisions",
            "UPDATE audit_events SET event_type='forged'",
            "SELECT set_connection_paused('00000000-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000000',true)",
        ] {
            let error=sqlx::query(statement).execute(pool).await.unwrap_err();
            assert_eq!(error.as_database_error().unwrap().code().as_deref(),Some("42501"));
        }
    }
}

async fn budget_dispatch_regressions(admin: &PgPool, api: &Store, worker: &Store) {
    let p = principal();
    seed(admin, &p, &p.workload_id.to_string()).await;
    let r = request(&p);
    sqlx::query("DELETE FROM budget_connections WHERE connection_id=$1")
        .bind(p.connection_id)
        .execute(admin)
        .await
        .unwrap();
    for (key, config, reason) in [
        ("missing", None, "BUDGET_NOT_CONFIGURED"),
        ("daily", Some((0, 10_000)), "BUDGET_DAILY_EXCEEDED"),
        ("exposure", Some((10_000, 0)), "BUDGET_EXPOSURE_EXCEEDED"),
    ] {
        if let Some((daily, exposure)) = config {
            configure_budget(admin, &p, daily, exposure).await;
        }
        let id = api.submit(&p, key, &r).await.unwrap().id;
        drain(worker).await;
        let action = api.get(&p, id).await.unwrap().unwrap();
        assert_eq!(action.status, ActionStatus::Denied);
        assert_eq!(action.reason.as_deref(), Some(reason));
        assert_eq!(effect_count(admin, id).await, 0);
        let reservations: i64 =
            sqlx::query_scalar("SELECT count(*) FROM budget_reservations WHERE action_id=$1")
                .bind(id)
                .fetch_one(admin)
                .await
                .unwrap();
        assert_eq!(reservations, 0);
    }
    configure_budget(admin, &p, 30_000, 30_000).await;
    let mut approval_request = r.clone();
    approval_request.parameters.amount_minor = 5001;
    let pending = api
        .submit(&p, "old-policy", &approval_request)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(
        api.get(&p, pending.id).await.unwrap().unwrap().status,
        ActionStatus::PendingApproval
    );
    publish(admin, &p, 2, 10000, 50000, 1800).await;
    sqlx::query("UPDATE outbox_jobs SET available_at=clock_timestamp() WHERE action_id=$1")
        .bind(pending.id)
        .execute(admin)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(
        api.get(&p, pending.id).await.unwrap().unwrap().status,
        ActionStatus::Succeeded
    );
    assert_eq!(effect_count(admin, pending.id).await, 1);
    assert_eq!(
        api.submit(&p, "old-policy", &approval_request)
            .await
            .unwrap()
            .id,
        pending.id
    );
    drain(worker).await;
    let state: (String, i64) =
        sqlx::query_as("SELECT state,amount_minor FROM budget_reservations WHERE action_id=$1")
            .bind(pending.id)
            .fetch_one(admin)
            .await
            .unwrap();
    assert_eq!(state, ("settled".into(), 5001));
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_kind FROM budget_ledger_events WHERE action_id=$1 ORDER BY sequence",
    )
    .bind(pending.id)
    .fetch_all(admin)
    .await
    .unwrap();
    assert_eq!(events, vec!["reserved", "settled"]);
    assert_eq!(effect_count(admin, pending.id).await, 1);

    publish(admin, &p, 3, 4000, 50000, 3).await;
    let reviewer = seed_reviewer(admin, &p).await;
    let approved = api
        .submit(&p, "expires-while-waiting-budget", &approval_request)
        .await
        .unwrap();
    drain(worker).await;
    let input = input_for(api, &reviewer, approved.id).await;
    api.decide_approval(&reviewer, approved.id, &input)
        .await
        .unwrap();
    let mut blocker = admin.begin().await.unwrap();
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT connection_id FROM budget_connections WHERE connection_id=$1 FOR UPDATE")
        .bind(p.connection_id)
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    let (processed, ()) = tokio::join!(worker.process_one(), async {
        tokio::time::timeout(std::time::Duration::from_secs(2),async {
            loop {
                let blocked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))")
                    .bind(pid).fetch_one(admin).await.unwrap();
                if blocked { break; }
                tokio::time::sleep(std::time::Duration::from_millis(15)).await;
            }
        }).await.expect("worker must reach the budget lock before approval expires");
        tokio::time::sleep(std::time::Duration::from_millis(3100)).await;
        blocker.rollback().await.unwrap();
    });
    assert!(processed.unwrap());
    assert_eq!(
        api.get(&p, approved.id).await.unwrap().unwrap().status,
        ActionStatus::Expired
    );
    assert_eq!(effect_count(admin, approved.id).await, 0);
    let events: Vec<String> = sqlx::query_scalar(
        "SELECT event_kind FROM budget_ledger_events WHERE action_id=$1 ORDER BY sequence",
    )
    .bind(approved.id)
    .fetch_all(admin)
    .await
    .unwrap();
    assert_eq!(events, vec!["reserved", "released"]);
}

async fn scope_pause_regressions(
    admin: &PgPool,
    api_pool: &PgPool,
    worker_pool: &PgPool,
    api: &Store,
    worker: &Store,
) {
    let p = principal();
    let neighbor = Principal {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        ..principal()
    };
    let other_env = Principal {
        tenant_id: p.tenant_id,
        ..principal()
    };
    let outsider = principal();
    for scope in [&p, &neighbor, &other_env, &outsider] {
        seed(admin, scope, &scope.workload_id.to_string()).await;
    }
    let operator = seed_reviewer(admin, &p).await;
    let outsider_reviewer = seed_reviewer(admin, &outsider).await;
    sqlx::query("INSERT INTO connection_admin_grants(tenant_id,environment_id,reviewer_id,connection_id,control_dispatch) VALUES($1,$2,$3,$4,true)")
        .bind(p.tenant_id).bind(p.environment_id).bind(operator.reviewer_id).bind(p.connection_id).execute(admin).await.unwrap();
    assert!(matches!(
        api.set_tenant_dispatch_paused(&operator, true).await,
        Err(StoreError::Forbidden)
    ));
    assert!(matches!(
        api.set_workload_dispatch_paused(&operator, p.workload_id, true)
            .await,
        Err(StoreError::Forbidden)
    ));
    sqlx::query("INSERT INTO workload_dispatch_grants(tenant_id,environment_id,reviewer_id,workload_id) VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id).bind(p.environment_id).bind(operator.reviewer_id).bind(p.workload_id).execute(admin).await.unwrap();
    assert!(matches!(
        api.set_workload_dispatch_paused(&operator, other_env.workload_id, true)
            .await,
        Err(StoreError::Forbidden)
    ));
    assert!(matches!(
        api.set_workload_dispatch_paused(&operator, neighbor.workload_id, true)
            .await,
        Err(StoreError::Forbidden)
    ));
    assert!(matches!(
        api.set_workload_dispatch_paused(&outsider_reviewer, p.workload_id, true)
            .await,
        Err(StoreError::Forbidden)
    ));
    sqlx::query(
        "INSERT INTO tenant_dispatch_grants(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)",
    )
    .bind(p.tenant_id)
    .bind(p.environment_id)
    .bind(operator.reviewer_id)
    .execute(admin)
    .await
    .unwrap();

    // Existing workload/tenant FOR SHARE locks must serialize both control writes.
    let mut worker_tx = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *worker_tx)
    .await
    .unwrap();
    let authorized: bool =
        sqlx::query_scalar("SELECT authorize_scope($1,$2,$3,$4,'submit_refund')")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(p.workload_id)
            .bind(p.connection_id)
            .fetch_one(&mut *worker_tx)
            .await
            .unwrap();
    assert!(authorized);
    for statement in [
        "SELECT admin_set_tenant_dispatch_paused($1,$2,$3,true)",
        "SELECT admin_set_workload_dispatch_paused($1,$2,$3,$4,true)",
    ] {
        let mut control = api_pool.begin().await.unwrap();
        sqlx::query("SET LOCAL lock_timeout='100ms'")
            .execute(&mut *control)
            .await
            .unwrap();
        sqlx::query(
            "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
        )
        .bind(p.tenant_id.to_string())
        .bind(p.environment_id.to_string())
        .execute(&mut *control)
        .await
        .unwrap();
        let query = sqlx::query(statement)
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(operator.reviewer_id);
        let query = if statement.contains("workload") {
            query.bind(p.workload_id)
        } else {
            query
        };
        let err = query.execute(&mut *control).await.unwrap_err();
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        control.rollback().await.unwrap();
    }
    worker_tx.rollback().await.unwrap();

    api.set_workload_dispatch_paused(&operator, p.workload_id, true)
        .await
        .unwrap();
    api.set_workload_dispatch_paused(&operator, p.workload_id, true)
        .await
        .unwrap();
    let main = api
        .submit(&p, "workload-paused", &request(&p))
        .await
        .unwrap()
        .id;
    let near = api
        .submit(&neighbor, "neighbor-unpaused", &request(&neighbor))
        .await
        .unwrap()
        .id;
    drain(worker).await;
    assert_eq!(effect_count(admin, main).await, 0);
    assert_eq!(effect_count(admin, near).await, 1);

    api.set_tenant_dispatch_paused(&operator, true)
        .await
        .unwrap();
    api.set_workload_dispatch_paused(&operator, p.workload_id, false)
        .await
        .unwrap();
    let remote = api
        .submit(&other_env, "other-env-paused", &request(&other_env))
        .await
        .unwrap()
        .id;
    let unrelated = api
        .submit(&outsider, "other-tenant-unpaused", &request(&outsider))
        .await
        .unwrap()
        .id;
    drain(worker).await;
    assert_eq!(effect_count(admin, main).await, 0);
    assert_eq!(effect_count(admin, remote).await, 0);
    assert_eq!(effect_count(admin, unrelated).await, 1);

    api.set_tenant_dispatch_paused(&operator, false)
        .await
        .unwrap();
    sqlx::query("UPDATE outbox_jobs SET available_at=clock_timestamp() WHERE action_id IN ($1,$2)")
        .bind(main)
        .bind(remote)
        .execute(admin)
        .await
        .unwrap();
    drain(worker).await;
    assert_eq!(effect_count(admin, main).await, 1);
    assert_eq!(effect_count(admin, remote).await, 1);
    let events:Vec<(Option<Uuid>,bool)>=sqlx::query_as("SELECT workload_id,paused FROM dispatch_scope_audit WHERE reviewer_id=$1 ORDER BY sequence")
        .bind(operator.reviewer_id).fetch_all(admin).await.unwrap();
    assert_eq!(
        events,
        vec![
            (Some(p.workload_id), true),
            (None, true),
            (Some(p.workload_id), false),
            (None, false)
        ]
    );
    let forbidden = sqlx::query("UPDATE dispatch_scope_audit SET paused=false")
        .execute(api_pool)
        .await
        .unwrap_err();
    assert_eq!(
        forbidden.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
}
