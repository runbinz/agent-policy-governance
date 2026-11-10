//! Provider-neutral dispatch recovery against PostgreSQL; no external calls.
use apl_dispatch::{
    Currency, DispatchError, DispatchState, EvidenceRef, NextStep, PaymentFacts, ProviderOutcome,
    ReplaySafety, VerifiedPaymentObservation, VerifiedRefundRequest,
};
use apl_domain::{ActionStatus, Principal, RefundRequest, Reviewer};
use apl_persistence::{
    external::{database_now, ExternalAction},
    Store, StoreError,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;
use uuid::Uuid;

fn observation(request: &VerifiedRefundRequest) -> VerifiedPaymentObservation {
    VerifiedPaymentObservation::new(
        request.clone(),
        PaymentFacts {
            charge_amount_minor: 100_000,
            captured_minor: 100_000,
            refunded_minor: 0,
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

async fn stage(
    admin: &PgPool,
    api: &Store,
    worker: &Store,
    p: &Principal,
    namespace: &str,
    key: &str,
) -> ExternalAction {
    let request:RefundRequest=serde_json::from_value(serde_json::json!({
        "type":"refund.create","connection_id":p.connection_id,"resource":{"payment_id":"ch_VerifiedFixture"},
        "parameters":{"amount_minor":2500,"currency":"USD"}
    })).unwrap();
    let submitted = api.submit(p, key, &request).await.unwrap();
    let scope = ExternalAction {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        action_id: submitted.id,
    };
    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    let mut tx = admin.begin().await.unwrap();
    let now = database_now(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let verified = VerifiedRefundRequest::new(
        p.connection_id,
        request.resource.payment_id,
        2500,
        Currency::Usd,
        now,
        now + 30_000,
    )
    .unwrap();
    worker
        .prepare_verified_external(
            scope,
            namespace,
            verified.clone(),
            observation(&verified),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        api.get(p, scope.action_id).await.unwrap().unwrap().status,
        ActionStatus::Dispatching
    );
    scope
}

async fn reservation(pool: &PgPool, action: ExternalAction) -> String {
    sqlx::query_scalar("SELECT state FROM budget_reservations WHERE action_id=$1")
        .bind(action.action_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with PostgreSQL role creation privileges"]
async fn external_dispatch_restart_fence_and_exposure() {
    let url = std::env::var("TEST_DATABASE_URL").expect("use a dedicated PostgreSQL test database");
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let api_pool = role_pool(&url, "SET ROLE apl_api").await;
    let api = Store::from_pool(api_pool.clone());
    let worker_pool = role_pool(&url, "SET ROLE apl_worker").await;
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
    let replay = ReplaySafety::ReconcileOnly;
    let action = stage(&admin, &api, &worker, &p, &ns, "crash").await;
    assert_eq!(reservation(&admin, action).await, "held");
    let request = api
        .get(&p, action.action_id)
        .await
        .unwrap()
        .unwrap()
        .request;
    let blocked = api.submit(&p, "same-payment", &request).await.unwrap();
    assert!(worker
        .next_external_candidate("other-namespace")
        .await
        .unwrap()
        .is_none());
    while worker.process_one().await.unwrap() {}
    let candidate = worker.next_external_candidate(&ns).await.unwrap().unwrap();
    assert_eq!(candidate.action.action_id, blocked.id);
    let verified = VerifiedRefundRequest::new(
        p.connection_id,
        request.resource.payment_id,
        2500,
        Currency::Usd,
        candidate.observed_at,
        candidate.observed_at + 30_000,
    )
    .unwrap();
    assert!(matches!(
        worker
            .prepare_verified_external(
                candidate.action,
                "other-namespace",
                verified.clone(),
                observation(&verified),
                None
            )
            .await,
        Err(StoreError::Forbidden)
    ));
    worker
        .prepare_verified_external(
            candidate.action,
            &ns,
            verified.clone(),
            observation(&verified),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        api.get(&p, blocked.id).await.unwrap().unwrap().status,
        ActionStatus::Received
    );
    let holds: i64 =
        sqlx::query_scalar("SELECT count(*) FROM budget_reservations WHERE action_id=$1")
            .bind(blocked.id)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(holds, 0);
    assert!(matches!(
        api.cancel(&p, action.action_id).await,
        Err(StoreError::Conflict)
    ));
    assert!(worker
        .claim_external("other-namespace", 1000, replay)
        .await
        .unwrap()
        .is_none());

    let (left, right) = tokio::join!(
        worker.claim_external(&ns, 500, replay),
        worker.claim_external(&ns, 500, replay)
    );
    let left = left.unwrap();
    let right = right.unwrap();
    assert_ne!(left.is_some(), right.is_some());
    let first = left.or(right).unwrap();
    assert_eq!(first.action, action);
    assert_eq!(first.next_step, NextStep::SendInitial);
    assert!(!worker.external_send_still_current(&first).await.unwrap());
    worker.begin_external_send(&first, replay).await.unwrap();
    assert!(worker.external_send_still_current(&first).await.unwrap());
    sqlx::query("UPDATE tenants SET paused=true WHERE tenant_id=$1")
        .bind(p.tenant_id)
        .execute(&admin)
        .await
        .unwrap();
    assert!(!worker.external_send_still_current(&first).await.unwrap());
    assert_eq!(reservation(&admin, action).await, "held");
    sqlx::query("UPDATE tenants SET paused=false WHERE tenant_id=$1")
        .bind(p.tenant_id)
        .execute(&admin)
        .await
        .unwrap();

    assert!(matches!(
        worker.abandon_external_unsent(&first).await,
        Err(StoreError::Dispatch(DispatchError::SendForbidden))
    ));
    let attempts: i64 =
        sqlx::query_scalar("SELECT count(*) FROM external_attempts WHERE action_id=$1")
            .bind(action.action_id)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert_eq!(attempts, 1);
    let key = first.dispatch.provider_key().as_str().to_owned();
    // Crash after the committed send marker but before recording any outcome.
    drop(worker);
    tokio::time::sleep(Duration::from_millis(520)).await;
    let restarted = Store::from_pool(worker_pool.clone());
    assert!(!restarted.external_send_still_current(&first).await.unwrap());
    let recovery = restarted
        .claim_external(&ns, 5000, replay)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(recovery.next_step, NextStep::Reconcile);
    assert_eq!(recovery.dispatch.provider_key().as_str(), key);
    assert!(recovery.lease.generation > first.lease.generation);
    assert!(!restarted
        .external_send_still_current(&recovery)
        .await
        .unwrap());
    assert!(matches!(
        restarted
            .observe_external(&first, ProviderOutcome::Unknown)
            .await,
        Err(StoreError::Dispatch(DispatchError::StaleLease))
    ));
    assert_eq!(
        restarted
            .observe_external(&recovery, ProviderOutcome::Unknown)
            .await
            .unwrap(),
        DispatchState::Unknown
    );
    let stale_evidence = EvidenceRef::new("fixture:old-fence".into()).unwrap();
    assert!(matches!(
        restarted
            .observe_external(&first, ProviderOutcome::ConfirmedSuccess(stale_evidence))
            .await,
        Err(StoreError::Dispatch(DispatchError::StaleLease))
    ));
    assert_eq!(reservation(&admin, action).await, "held");
    assert_eq!(
        api.get(&p, action.action_id).await.unwrap().unwrap().status,
        ActionStatus::Dispatching
    );
    sqlx::query(
        "UPDATE external_dispatch_queue SET available_at_ms=10000000000000 WHERE action_id=$1",
    )
    .bind(action.action_id)
    .execute(&admin)
    .await
    .unwrap();
    let key = recovery.dispatch.provider_key().as_str();
    assert!(api
        .ingest_stripe_wake(
            &ns,
            "evt_WrongCharge",
            "refund.updated",
            "re_Test",
            "ch_Other",
            Some(key)
        )
        .await
        .unwrap());
    let ready_at = || {
        sqlx::query_scalar::<_, i64>(
            "SELECT available_at_ms FROM external_dispatch_queue WHERE action_id=$1",
        )
        .bind(action.action_id)
        .fetch_one(&admin)
    };
    assert_eq!(ready_at().await.unwrap(), 10_000_000_000_000);
    assert!(api
        .ingest_stripe_wake(
            &ns,
            "evt_RightCharge",
            "refund.updated",
            "re_Test",
            "ch_VerifiedFixture",
            Some(key)
        )
        .await
        .unwrap());
    assert!(!api
        .ingest_stripe_wake(
            &ns,
            "evt_RightCharge",
            "refund.updated",
            "re_Test",
            "ch_VerifiedFixture",
            Some(key)
        )
        .await
        .unwrap());
    assert!(ready_at().await.unwrap() < 10_000_000_000_000);
    assert_eq!(reservation(&admin, action).await, "held");
    assert!(restarted
        .claim_external(&ns, 5000, replay)
        .await
        .unwrap()
        .is_none());
    let evidence = EvidenceRef::new("fixture:verified-provider-refund".into()).unwrap();
    assert_eq!(
        restarted
            .observe_external(
                &recovery,
                ProviderOutcome::ConfirmedSuccess(evidence.clone())
            )
            .await
            .unwrap(),
        DispatchState::Succeeded(evidence)
    );
    assert_eq!(reservation(&admin, action).await, "settled");
    // A Charge read made before settlement cannot authorize the next refund.
    restarted
        .prepare_verified_external(
            candidate.action,
            &ns,
            verified.clone(),
            observation(&verified),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        api.get(&p, blocked.id).await.unwrap().unwrap().status,
        ActionStatus::Received
    );
    api.cancel(&p, blocked.id).await.unwrap();
    assert_eq!(
        api.get(&p, action.action_id).await.unwrap().unwrap().status,
        ActionStatus::Succeeded
    );
    assert!(restarted
        .claim_external(&ns, 5000, replay)
        .await
        .unwrap()
        .is_none());
    let audit = api.events(&p, action.action_id).await.unwrap().unwrap();
    assert_eq!(
        audit
            .iter()
            .map(|e| e.event_type.as_str())
            .collect::<Vec<_>>(),
        [
            "action.received",
            "payment.attested",
            "dispatch.authorized",
            "dispatch.send_marked",
            "dispatch.unknown",
            "dispatch.succeeded"
        ]
    );

    let unsent = stage(&admin, &api, &restarted, &p, &ns, "unsent").await;
    let claim = restarted
        .claim_external(&ns, 5000, replay)
        .await
        .unwrap()
        .unwrap();
    let paused: bool = sqlx::query_scalar("SELECT set_connection_paused($1,$2,$3,true)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(paused);
    assert!(matches!(
        restarted.begin_external_send(&claim, replay).await,
        Err(StoreError::Dispatch(DispatchError::SendForbidden))
    ));
    restarted.abandon_external_unsent(&claim).await.unwrap();
    assert_eq!(reservation(&admin, unsent).await, "released");
    assert_eq!(
        api.get(&p, unsent.action_id).await.unwrap().unwrap().status,
        ActionStatus::Denied
    );

    let resumed: bool = sqlx::query_scalar("SELECT set_connection_paused($1,$2,$3,false)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.connection_id)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert!(resumed);
    let inconclusive = stage(&admin, &api, &restarted, &p, &ns, "manual-review").await;
    let claim = restarted
        .claim_external(&ns, 1500, replay)
        .await
        .unwrap()
        .unwrap();
    restarted.begin_external_send(&claim, replay).await.unwrap();
    for count in 1..=8 {
        let observed = restarted
            .observe_external(&claim, ProviderOutcome::Unknown)
            .await
            .unwrap();
        assert_eq!(
            observed,
            if count == 8 {
                DispatchState::ManualReview
            } else {
                DispatchState::Unknown
            }
        );
    }
    let automated_closed: bool =
        sqlx::query_scalar("SELECT closed FROM external_dispatch_queue WHERE action_id=$1")
            .bind(inconclusive.action_id)
            .fetch_one(&admin)
            .await
            .unwrap();
    assert!(automated_closed);
    assert_eq!(reservation(&admin, inconclusive).await, "held");

    let operator = Reviewer {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        reviewer_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO reviewers(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)")
        .bind(operator.tenant_id)
        .bind(operator.environment_id)
        .bind(operator.reviewer_id)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        api.request_external_reconciliation(&operator, inconclusive.action_id)
            .await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO reconciliation_grants(tenant_id,environment_id,reviewer_id,connection_id) VALUES($1,$2,$3,$4)")
        .bind(operator.tenant_id).bind(operator.environment_id).bind(operator.reviewer_id).bind(p.connection_id).execute(&admin).await.unwrap();
    assert!(matches!(
        api.request_external_reconciliation(&operator, action.action_id)
            .await,
        Err(StoreError::Conflict)
    ));
    let (first, duplicate) = tokio::join!(
        api.request_external_reconciliation(&operator, inconclusive.action_id),
        api.request_external_reconciliation(&operator, inconclusive.action_id)
    );
    first.unwrap();
    duplicate.unwrap();
    let requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM external_reconciliation_requests WHERE action_id=$1",
    )
    .bind(inconclusive.action_id)
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(requests, 1);
    tokio::time::sleep(Duration::from_millis(1520)).await;
    let manual = restarted
        .claim_external(&ns, 5000, replay)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(manual.next_step, NextStep::Reconcile);
    assert!(matches!(
        restarted.begin_external_send(&manual, replay).await,
        Err(StoreError::Dispatch(DispatchError::SendForbidden))
    ));
    assert_eq!(reservation(&admin, inconclusive).await, "held");
    let evidence = EvidenceRef::new("fixture:manual-confirmed".into()).unwrap();
    assert_eq!(
        restarted
            .observe_external(&manual, ProviderOutcome::ConfirmedSuccess(evidence.clone()))
            .await
            .unwrap(),
        DispatchState::Succeeded(evidence)
    );
    assert_eq!(reservation(&admin, inconclusive).await, "settled");

    for sql in [
        "SELECT * FROM external_dispatches",
        "SELECT * FROM external_dispatch_queue",
        "SELECT * FROM external_attempts",
        "SELECT * FROM claim_external_dispatch('test')",
    ] {
        let e = sqlx::query(sql).execute(&api_pool).await.unwrap_err();
        assert_eq!(
            e.as_database_error().unwrap().code().as_deref(),
            Some("42501")
        );
    }
    let error = sqlx::query("SELECT * FROM external_dispatch_queue")
        .execute(&worker_pool)
        .await
        .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("42501")
    );
}
