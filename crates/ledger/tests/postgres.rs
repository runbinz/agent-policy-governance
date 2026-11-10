//! Run with a dedicated PostgreSQL admin TEST_DATABASE_URL and --ignored.
use apl_ledger::{reserve, BudgetAction, Reservation};
use sqlx::{PgPool, Postgres, Transaction};
use std::time::Duration;
use uuid::Uuid;

async fn scoped(pool: &PgPool, action: BudgetAction) -> Transaction<'_, Postgres> {
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL ROLE apl_worker")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(action.tenant_id.to_string())
    .bind(action.environment_id.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    tx
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with admin role creation privileges"]
async fn budget_contract_and_concurrent_admission() {
    let url = std::env::var("TEST_DATABASE_URL").expect("use a dedicated PostgreSQL test database");
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::raw_sql(include_str!("../sql/check-budget.sql"))
        .execute(&pool)
        .await
        .unwrap();

    let first = BudgetAction {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        action_id: Uuid::new_v4(),
    };
    let second = BudgetAction {
        action_id: Uuid::new_v4(),
        ..first
    };
    let connection = Uuid::new_v4();
    let workload = Uuid::new_v4();
    let mut seed = pool.begin().await.unwrap();
    sqlx::query("INSERT INTO tenants VALUES($1,true)")
        .bind(first.tenant_id)
        .execute(&mut *seed)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments VALUES($1,$2,true)")
        .bind(first.tenant_id)
        .bind(first.environment_id)
        .execute(&mut *seed)
        .await
        .unwrap();
    sqlx::query("INSERT INTO workloads VALUES($1,$2,$3,true)")
        .bind(first.tenant_id)
        .bind(first.environment_id)
        .bind(workload)
        .execute(&mut *seed)
        .await
        .unwrap();
    sqlx::query("INSERT INTO connections VALUES($1,$2,$3,true)")
        .bind(first.tenant_id)
        .bind(first.environment_id)
        .bind(connection)
        .execute(&mut *seed)
        .await
        .unwrap();
    sqlx::query("INSERT INTO budget_connections VALUES($1,$2,$3,1500,1500)")
        .bind(first.tenant_id)
        .bind(first.environment_id)
        .bind(connection)
        .execute(&mut *seed)
        .await
        .unwrap();
    for id in [first.action_id, second.action_id] {
        sqlx::query("INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status) VALUES ($1,$2,$3,$4,jsonb_build_object('type','refund.create','connection_id',$5::uuid,'parameters',jsonb_build_object('currency','USD','amount_minor',1500)),'received')")
            .bind(first.tenant_id).bind(first.environment_id).bind(id).bind(workload).bind(connection)
            .execute(&mut *seed).await.unwrap();
    }
    seed.commit().await.unwrap();

    let mut winner = scoped(&pool, first).await;
    assert_eq!(
        reserve(&mut winner, first, connection, None).await.unwrap(),
        Reservation::NewHold
    );
    let mut loser = scoped(&pool, second).await;
    let attempt = reserve(&mut loser, second, connection, None);
    tokio::pin!(attempt);
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut attempt)
            .await
            .is_err(),
        "contender should wait for the same connection lock"
    );
    winner.commit().await.unwrap();
    assert!(matches!(
        attempt.await.unwrap(),
        Reservation::DailyExceeded | Reservation::ExposureExceeded
    ));
}
