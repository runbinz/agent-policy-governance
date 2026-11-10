use apl_dispatch::{
    fixture::{FixtureProvider, FixtureScenario},
    Currency, DispatchState, PaymentFacts, VerifiedPaymentObservation, VerifiedRefundRequest,
};
use apl_domain::{ActionStatus, RefundRequest};
use apl_persistence::{external::ExternalAction, Store};
use apl_worker::{tick_external, ExternalTick};
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

#[tokio::test]
#[ignore = "requires a dedicated PostgreSQL test database"]
async fn crash_after_provider_acceptance_reconciles_without_second_send() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = Store::connect(&url).await.unwrap();
    admin.migrate().await.unwrap();
    let db = PgPool::connect(&url).await.unwrap();
    for script in [
        include_str!("../../../migrations/runtime-roles.sql"),
        include_str!("../../../scripts/seed-local.sql"),
    ] {
        sqlx::raw_sql(script).execute(&db).await.unwrap();
    }
    let api = Store::from_pool(role_pool(&url, "SET ROLE apl_api").await);
    let worker = Store::from_pool(role_pool(&url, "SET ROLE apl_worker").await);
    let principal = api
        .resolve_identity("urn:apl:local", "tenant-a")
        .await
        .unwrap()
        .unwrap();
    let request: RefundRequest = serde_json::from_value(serde_json::json!({
        "type": "refund.create", "connection_id": principal.connection_id,
        "resource": {"payment_id": "fixture_payment"},
        "parameters": {"currency": "USD", "amount_minor": 2500}
    }))
    .unwrap();
    let action = api
        .submit(&principal, &Uuid::new_v4().to_string(), &request)
        .await
        .unwrap();
    let external = ExternalAction {
        tenant_id: principal.tenant_id,
        environment_id: principal.environment_id,
        action_id: action.id,
    };
    let namespace = "fixture-worker-recovery".to_owned();
    sqlx::query("INSERT INTO provider_routes VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING")
        .bind(principal.tenant_id)
        .bind(principal.environment_id)
        .bind(principal.connection_id)
        .bind(&namespace)
        .execute(&db)
        .await
        .unwrap();
    let now: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint")
            .fetch_one(&db)
            .await
            .unwrap();
    let now = u64::try_from(now).unwrap();
    let verified = VerifiedRefundRequest::new(
        principal.connection_id,
        request.resource.payment_id.clone(),
        2500,
        Currency::Usd,
        now,
        now + 30_000,
    )
    .unwrap();
    let wrong = VerifiedRefundRequest::new(
        principal.connection_id,
        request.resource.payment_id,
        2501,
        Currency::Usd,
        now,
        now + 30_000,
    )
    .unwrap();
    assert!(worker
        .prepare_verified_external(
            external,
            &namespace,
            wrong.clone(),
            observation(&wrong),
            None
        )
        .await
        .is_err());
    worker
        .prepare_verified_external(
            external,
            &namespace,
            verified.clone(),
            observation(&verified),
            None,
        )
        .await
        .unwrap();
    assert_eq!(
        api.get(&principal, action.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ActionStatus::Dispatching
    );
    let fixture = FixtureProvider::new(FixtureScenario::Success);
    fixture.pause_responses();
    let worker_task = worker.clone();
    let fixture_task = fixture.clone();
    let namespace_task = namespace.clone();
    let job = tokio::spawn(async move {
        tick_external(
            &worker_task,
            &namespace_task,
            &fixture_task,
            1500,
            Duration::from_millis(1200),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(4), fixture.wait_for_execute_count(1))
        .await
        .expect("provider was never reached");
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert_eq!(fixture.effect_count(), 1);
    let held: String =
        sqlx::query_scalar("SELECT state FROM budget_reservations WHERE action_id=$1")
            .bind(action.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(held, "held");
    fixture.resume_responses();
    let restarted = Store::from_pool(role_pool(&url, "SET ROLE apl_worker").await);
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let tick = tick_external(
                &restarted,
                &namespace,
                &fixture,
                1500,
                Duration::from_millis(1200),
            )
            .await
            .unwrap();
            if tick != ExternalTick::Idle {
                break tick;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(
        result,
        ExternalTick::Observed(DispatchState::Succeeded(_))
    ));
    assert_eq!(fixture.execute_count(), 1);
    assert_eq!(fixture.reconcile_count(), 1);
    assert_eq!(
        api.get(&principal, action.id)
            .await
            .unwrap()
            .unwrap()
            .status,
        ActionStatus::Succeeded
    );
    let settled: String =
        sqlx::query_scalar("SELECT state FROM budget_reservations WHERE action_id=$1")
            .bind(action.id)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(settled, "settled");
}
