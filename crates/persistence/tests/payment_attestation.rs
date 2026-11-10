//! Isolated PostgreSQL runtime-role attestation lifecycle and boundary checks.
use apl_dispatch::{
    Currency, NextStep, PaymentFacts, ProviderOutcome, ReplaySafety, VerifiedPaymentObservation,
    VerifiedRefundRequest,
};
use apl_domain::{ApprovalDecision, ApprovalInput, Principal, RefundRequest, Reviewer};
use apl_persistence::{external::ExternalAction, Store};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use uuid::Uuid;
async fn role_pool(url: &str, role: &'static str) -> PgPool {
    PgPoolOptions::new()
        .after_connect(move |conn, _| {
            Box::pin(async move {
                sqlx::query(role).execute(conn).await?;
                Ok(())
            })
        })
        .connect(url)
        .await
        .unwrap()
}

async fn fixture(pool: &PgPool) -> Principal {
    let p = Principal {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        workload_id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
    };
    let mut tx = pool.begin().await.unwrap();
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
    sqlx::query("INSERT INTO workload_grants(tenant_id,environment_id,workload_id,connection_id,submit_refund,read_action,read_events,cancel_action)
        VALUES($1,$2,$3,$4,true,true,true,true)").bind(p.tenant_id).bind(p.environment_id).bind(p.workload_id).bind(p.connection_id)
        .execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    p
}

async fn observation(
    admin: &PgPool,
    p: &Principal,
    refunded: u64,
    age: i64,
) -> VerifiedPaymentObservation {
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint")
            .fetch_one(admin)
            .await
            .unwrap();
    VerifiedPaymentObservation::new(
        VerifiedRefundRequest::new(
            p.connection_id,
            "ch_Attested".into(),
            7500,
            Currency::Usd,
            (now - age) as u64,
            (now - age + 30000) as u64,
        )
        .unwrap(),
        PaymentFacts {
            charge_amount_minor: 30000,
            captured_minor: 30000,
            refunded_minor: refunded,
            paid: true,
            captured: true,
            disputed: false,
            direct_charge: true,
            status: "succeeded".into(),
            method: "card".into(),
        },
    )
    .unwrap()
}
async fn prepare(
    worker: &Store,
    action: ExternalAction,
    ns: &str,
    o: VerifiedPaymentObservation,
) -> Result<(), apl_persistence::StoreError> {
    worker
        .prepare_verified_external(action, ns, o.request().clone(), o, None)
        .await
}
#[tokio::test]
#[ignore = "requires PostgreSQL database creation and runtime roles"]
async fn immutable_atomic_generations_and_fresh_dispatch() {
    let parent = std::env::var("TEST_DATABASE_URL").unwrap();
    let owner = PgPool::connect(&parent).await.unwrap();
    let db = format!("apl_attestation_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {db}"))
        .execute(&owner)
        .await
        .unwrap();
    let mut url = url::Url::parse(&parent).unwrap();
    url.set_path(&db);
    let admin = PgPool::connect(url.as_str()).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = role_pool(url.as_str(), "SET ROLE apl_api").await;
    let worker_pool = role_pool(url.as_str(), "SET ROLE apl_worker").await;
    let api = Store::from_pool(api_pool.clone());
    let worker = Store::from_pool(worker_pool.clone());
    let p = fixture(&admin).await;
    let ns = format!("stripe-test:acct_{}", Uuid::new_v4().simple());
    sqlx::query("INSERT INTO provider_routes VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .bind(&ns)
        .execute(&admin)
        .await
        .unwrap();
    let r:RefundRequest=serde_json::from_value(serde_json::json!({"type":"refund.create","connection_id":p.connection_id,"resource":{"payment_id":"ch_Attested"},"parameters":{"amount_minor":7500,"currency":"USD"},"metadata":{"paid":"true","customer":"forged"}})).unwrap();
    let submitted = api.submit(&p, "attestation", &r).await.unwrap();
    let action = ExternalAction {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        action_id: submitted.id,
    };
    // Future/stale and binding mismatch roll back all state and observations.
    for age in [-1000, 31000] {
        assert!(
            prepare(&worker, action, &ns, observation(&admin, &p, 0, age).await)
                .await
                .is_err()
        );
    }
    assert!(prepare(
        &worker,
        action,
        "stripe-test:acct_wrong",
        observation(&admin, &p, 0, 0).await
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM payment_attestations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    prepare(&worker, action, &ns, observation(&admin, &p, 0, 0).await)
        .await
        .unwrap();
    let first=sqlx::query("SELECT generation,payment_attestation_id,expires_at::text deadline FROM approvals WHERE action_id=$1").bind(action.action_id).fetch_one(&admin).await.unwrap();
    let original: Uuid = first.get("payment_attestation_id");
    let deadline: String = first.get("deadline");
    for _ in 0..3 {
        prepare(&worker, action, &ns, observation(&admin, &p, 0, 0).await)
            .await
            .unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM payment_attestations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        1
    );
    // All public roles lack insert/update; worker also cannot rewrite recorded facts.
    for pool in [&api_pool, &worker_pool] {
        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
        )
        .bind(p.tenant_id.to_string())
        .bind(p.environment_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        assert!(sqlx::query("UPDATE payment_attestations SET paid=false")
            .execute(&mut *tx)
            .await
            .is_err());
    }
    assert!(
        sqlx::query("INSERT INTO payment_attestations DEFAULT VALUES")
            .execute(&api_pool)
            .await
            .is_err()
    );
    assert!(sqlx::query("SELECT * FROM payment_attestations")
        .fetch_all(&api_pool)
        .await
        .is_err());
    let mut wrong = worker_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4().to_string())
    .execute(&mut *wrong)
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM payment_attestations")
            .fetch_one(&mut *wrong)
            .await
            .unwrap(),
        0
    );
    wrong.rollback().await.unwrap();
    let reviewer = Reviewer {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        reviewer_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO reviewers(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer.reviewer_id)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_grants(tenant_id,environment_id,reviewer_id,connection_id) VALUES($1,$2,$3,$4)").bind(p.tenant_id).bind(p.environment_id).bind(reviewer.reviewer_id).bind(p.connection_id).execute(&admin).await.unwrap();
    sqlx::query("INSERT INTO action_detail_grants(tenant_id,environment_id,reviewer_id,connection_id) VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id).bind(p.environment_id).bind(reviewer.reviewer_id).bind(p.connection_id).execute(&admin).await.unwrap();
    let mut view = api_pool.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(p.tenant_id.to_string())
    .bind(p.environment_id.to_string())
    .execute(&mut *view)
    .await
    .unwrap();
    for name in ["read_action_detail", "read_action_payment_attestation"] {
        let value: serde_json::Value =
            sqlx::query_scalar(&format!("SELECT {name}($1,$2,$3,$4,$5)"))
                .bind(p.tenant_id)
                .bind(p.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(p.connection_id)
                .bind(action.action_id)
                .fetch_one(&mut *view)
                .await
                .unwrap();
        let text = value.to_string();
        assert!(!text.contains(&ns));
        assert!(!text.contains("forged"));
        assert!(!text.contains("provider_namespace"));
        if name == "read_action_detail" {
            assert_eq!(
                value["approval"]["payment_attestation_id"],
                original.to_string()
            );
        } else {
            let _: VerifiedPaymentObservation =
                serde_json::from_value(value["observation"].clone()).unwrap();
        }
    }
    for kind in ["audit", "approval"] {
        let history: serde_json::Value =
            sqlx::query_scalar("SELECT read_action_history($1,$2,$3,$4,$5,$6,0,100)")
                .bind(p.tenant_id)
                .bind(p.environment_id)
                .bind(reviewer.reviewer_id)
                .bind(p.connection_id)
                .bind(action.action_id)
                .bind(kind)
                .fetch_one(&mut *view)
                .await
                .unwrap();
        assert!(history.to_string().contains(if kind == "audit" {
            "payment.attested"
        } else {
            "payment_attestation_id"
        }));
    }
    view.commit().await.unwrap();
    let detail = api
        .action_detail(&reviewer, p.connection_id, action.action_id)
        .await
        .unwrap();
    let projected = detail.authoritative_payment.payment.as_ref().unwrap();
    assert_eq!(projected.attestation_id, original);
    assert_eq!(projected.approval_generation, Some(1));
    assert_eq!(projected.captured_minor, 30000);
    assert_eq!(projected.refunded_minor, 0);
    assert_eq!(projected.remaining_minor, 30000);
    assert_eq!(
        detail.approval.as_ref().unwrap().payment_attestation_id,
        Some(original)
    );
    let safe = serde_json::to_string(&detail).unwrap();
    assert!(!safe.contains(&ns));
    assert!(!safe.contains("forged"));
    assert!(!safe.contains("customer"));
    // An administrative fixture route replacement invalidates recorded review evidence.
    let queue = api.list_approvals(&reviewer).await.unwrap();
    let route_input = ApprovalInput {
        generation: queue[0].generation,
        action_digest: queue[0].action_digest.clone(),
        decision: ApprovalDecision::Approve,
    };
    for replacement in [format!("{ns}_replacement"), ns.clone()] {
        let mut mutation = admin.begin().await.unwrap();
        sqlx::query("ALTER TABLE provider_routes DISABLE TRIGGER guard_provider_route")
            .execute(&mut *mutation)
            .await
            .unwrap();
        sqlx::query("UPDATE provider_routes SET provider_namespace=$1")
            .bind(&replacement)
            .execute(&mut *mutation)
            .await
            .unwrap();
        sqlx::query("ALTER TABLE provider_routes ENABLE TRIGGER guard_provider_route")
            .execute(&mut *mutation)
            .await
            .unwrap();
        mutation.commit().await.unwrap();
        if replacement != ns {
            assert!(api
                .decide_approval(&reviewer, action.action_id, &route_input)
                .await
                .is_err());
        }
    }
    // Material change rotates and retains exact deadline. Old click conflicts.
    let queue = api.list_approvals(&reviewer).await.unwrap();
    let old = ApprovalInput {
        generation: queue[0].generation,
        action_digest: queue[0].action_digest.clone(),
        decision: ApprovalDecision::Approve,
    };
    prepare(
        &worker,
        action,
        &ns,
        observation(&admin, &p, 100, 28000).await,
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    assert!(api
        .decide_approval(&reviewer, action.action_id, &old)
        .await
        .is_err());
    let next=sqlx::query("SELECT payment_attestation_id,expires_at::text deadline FROM approvals WHERE action_id=$1 ORDER BY generation DESC LIMIT 1").bind(action.action_id).fetch_one(&admin).await.unwrap();
    assert_ne!(next.get::<Uuid, _>("payment_attestation_id"), original);
    assert_eq!(next.get::<String, _>("deadline"), deadline);
    let queue = api.list_approvals(&reviewer).await.unwrap();
    let input = ApprovalInput {
        generation: queue[0].generation,
        action_digest: queue[0].action_digest.clone(),
        decision: ApprovalDecision::Approve,
    };
    let (one, two) = tokio::join!(
        api.decide_approval(&reviewer, action.action_id, &input),
        api.decide_approval(&reviewer, action.action_id, &input)
    );
    assert_ne!(
        one.is_ok(),
        two.is_ok(),
        "exactly one stale-observation review decision commits"
    );
    // Reviewer revocation cannot send against historical approval.
    sqlx::query("UPDATE reviewer_grants SET enabled=false")
        .execute(&admin)
        .await
        .unwrap();
    prepare(&worker, action, &ns, observation(&admin, &p, 100, 0).await)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM budget_reservations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    sqlx::query("UPDATE reviewer_grants SET enabled=true")
        .execute(&admin)
        .await
        .unwrap();
    // Changed facts after approval return to review without reserving exposure.
    prepare(&worker, action, &ns, observation(&admin, &p, 200, 0).await)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM budget_reservations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    let queue = api.list_approvals(&reviewer).await.unwrap();
    let input = ApprovalInput {
        generation: queue[0].generation,
        action_digest: queue[0].action_digest.clone(),
        decision: ApprovalDecision::Approve,
    };
    api.decide_approval(&reviewer, action.action_id, &input)
        .await
        .unwrap();
    // A budget lock consumes observation freshness and the whole authorization rolls back.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM payment_attestations")
        .fetch_one(&admin)
        .await
        .unwrap();
    let mut lock = admin.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM budget_connections FOR UPDATE")
        .execute(&mut *lock)
        .await
        .unwrap();
    let o = observation(&admin, &p, 200, 28000).await;
    let w = worker.clone();
    let n = ns.clone();
    let blocked = tokio::spawn(async move { prepare(&w, action, &n, o).await });
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%reserve_refund_budget%')")
                .fetch_one(&admin).await.unwrap();
            if waiting { break; }
            assert!(!blocked.is_finished(), "preparation must reach the held budget lock");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("worker must demonstrably wait for the budget lock");
    tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
    lock.commit().await.unwrap();
    assert!(blocked.await.unwrap().is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM payment_attestations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM budget_reservations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM budget_ledger_events")
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    prepare(&worker, action, &ns, observation(&admin, &p, 200, 0).await)
        .await
        .unwrap();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM external_dispatches d JOIN payment_attestations p ON (d.tenant_id,d.environment_id,d.action_id,d.payment_attestation_id)=(p.tenant_id,p.environment_id,p.action_id,p.id)").fetch_one(&admin).await.unwrap();
    assert_eq!(count, 1);
    assert!(sqlx::query(
        "UPDATE approvals SET payment_attestation_id=NULL WHERE action_id=$1 AND generation=1"
    )
    .bind(action.action_id)
    .execute(&admin)
    .await
    .is_err());
    assert!(
        sqlx::query("UPDATE external_dispatches SET payment_attestation_id=NULL")
            .execute(&admin)
            .await
            .is_err()
    );
    // Reconciliation after an unknown outcome keeps original key and exposure.
    let claim = worker
        .claim_external(&ns, 1000, ReplaySafety::ReconcileOnly)
        .await
        .unwrap()
        .unwrap();
    let key = claim.dispatch.provider_key().as_str().to_owned();
    worker
        .begin_external_send(&claim, ReplaySafety::ReconcileOnly)
        .await
        .unwrap();
    worker
        .observe_external(&claim, ProviderOutcome::Unknown)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM budget_reservations")
            .fetch_one(&admin)
            .await
            .unwrap(),
        "held"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT provider_key FROM external_dispatches")
            .fetch_one(&admin)
            .await
            .unwrap(),
        key
    );
    // A changed context cannot extend an expired original review deadline.
    sqlx::query("INSERT INTO policy_versions VALUES($1,$2,$3,2,5000,50000,1)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .execute(&admin)
        .await
        .unwrap();
    sqlx::query("UPDATE policy_bindings SET version=2")
        .execute(&admin)
        .await
        .unwrap();
    let expiring = api.submit(&p, "expires", &r).await.unwrap();
    let expires_action = ExternalAction {
        action_id: expiring.id,
        ..action
    };
    prepare(
        &worker,
        expires_action,
        &ns,
        observation(&admin, &p, 200, 0).await,
    )
    .await
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    prepare(
        &worker,
        expires_action,
        &ns,
        observation(&admin, &p, 300, 0).await,
    )
    .await
    .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT status FROM actions WHERE id=$1")
            .bind(expiring.id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        "expired"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM approvals WHERE action_id=$1")
            .bind(expiring.id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        1
    );
    // Emulate a pre0024 in-flight dispatch: no attestation FK must not disturb
    // its original key, unknown hold or reconciliation path.
    let mut legacy = admin.begin().await.unwrap();
    sqlx::query("ALTER TABLE external_dispatches DISABLE TRIGGER guard_dispatch_attestation")
        .execute(&mut *legacy)
        .await
        .unwrap();
    sqlx::query("UPDATE external_dispatches SET payment_attestation_id=NULL WHERE action_id=$1")
        .bind(action.action_id)
        .execute(&mut *legacy)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE external_dispatches ENABLE TRIGGER guard_dispatch_attestation")
        .execute(&mut *legacy)
        .await
        .unwrap();
    legacy.commit().await.unwrap();
    let retry = worker
        .claim_external(&ns, 1000, ReplaySafety::ReconcileOnly)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retry.next_step, NextStep::Reconcile);
    assert_eq!(retry.dispatch.provider_key().as_str(), key);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM external_attempts")
            .fetch_one(&admin)
            .await
            .unwrap(),
        1
    );
    sqlx::query("UPDATE external_dispatches SET available_at_ms=floor(extract(epoch FROM clock_timestamp())*1000)::bigint+60000 WHERE action_id=$1").bind(action.action_id).execute(&admin).await.unwrap();
    // A legacy authorization with no send marker must fail before a provider
    // attempt. Only this provably unsent hold can be released by abandonment.
    let mut unsent_request = r.clone();
    unsent_request.resource.payment_id = "ch_LegacyUnsent".into();
    unsent_request.parameters.amount_minor = 2500;
    let unsent = api
        .submit(&p, "legacy-unsent", &unsent_request)
        .await
        .unwrap();
    let unsent_action = ExternalAction {
        action_id: unsent.id,
        ..action
    };
    let base = observation(&admin, &p, 0, 0).await;
    let verified = VerifiedRefundRequest::new(
        p.connection_id,
        unsent_request.resource.payment_id.clone(),
        2500,
        Currency::Usd,
        base.request().observed_at(),
        base.request().fresh_until(),
    )
    .unwrap();
    let observed = VerifiedPaymentObservation::new(verified.clone(), base.facts().clone()).unwrap();
    worker
        .prepare_verified_external(unsent_action, &ns, verified, observed, None)
        .await
        .unwrap();
    let mut legacy = admin.begin().await.unwrap();
    sqlx::query("ALTER TABLE external_dispatches DISABLE TRIGGER guard_dispatch_attestation")
        .execute(&mut *legacy)
        .await
        .unwrap();
    sqlx::query("UPDATE external_dispatches SET payment_attestation_id=NULL WHERE action_id=$1")
        .bind(unsent.id)
        .execute(&mut *legacy)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE external_dispatches ENABLE TRIGGER guard_dispatch_attestation")
        .execute(&mut *legacy)
        .await
        .unwrap();
    legacy.commit().await.unwrap();
    let claim = worker
        .claim_external(&ns, 10000, ReplaySafety::ReconcileOnly)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(claim.action.action_id, unsent.id);
    assert!(matches!(
        worker
            .begin_external_send(&claim, ReplaySafety::ReconcileOnly)
            .await,
        Err(apl_persistence::StoreError::Dispatch(
            apl_dispatch::DispatchError::SendForbidden
        ))
    ));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM external_attempts WHERE action_id=$1")
            .bind(unsent.id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        0
    );
    worker.abandon_external_unsent(&claim).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM budget_reservations WHERE action_id=$1")
            .bind(unsent.id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        "released"
    );
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM budget_reservations WHERE action_id=$1")
            .bind(action.action_id)
            .fetch_one(&admin)
            .await
            .unwrap(),
        "held"
    );
    api_pool.close().await;
    worker_pool.close().await;
    admin.close().await;
    sqlx::query(&format!("DROP DATABASE {db}"))
        .execute(&owner)
        .await
        .unwrap();
}
