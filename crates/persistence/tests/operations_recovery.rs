use apl_dispatch::{Currency, Dispatch, DispatchState, Lease, VerifiedRefundRequest};
use apl_domain::Reviewer;
use apl_persistence::{operations_recovery::*, Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;
struct Fixture {
    control: PgPool,
    name: String,
    admin: PgPool,
    api: PgPool,
    r: Reviewer,
    c: Uuid,
    w: Uuid,
}
impl Fixture {
    async fn new() -> Self {
        let parent = std::env::var("TEST_DATABASE_URL").unwrap();
        let control = PgPool::connect(&parent).await.unwrap();
        let name = format!("apl_recovery_rows_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&control)
            .await
            .unwrap();
        let mut url = url::Url::parse(&parent).unwrap();
        url.set_path(&format!("/{name}"));
        let admin = PgPool::connect(url.as_str()).await.unwrap();
        Store::from_pool(admin.clone()).migrate().await.unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
            .execute(&admin)
            .await
            .unwrap();
        let api = PgPoolOptions::new()
            .after_connect(|c, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE apl_api").execute(c).await?;
                    Ok(())
                })
            })
            .connect(url.as_str())
            .await
            .unwrap();
        let (t, e, r, c, w) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        sqlx::raw_sql(&format!(
            r#"
   INSERT INTO tenants(tenant_id) VALUES('{t}');INSERT INTO environments VALUES('{t}','{e}',true);
   INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{t}','{e}','{c}');
   INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES('{t}','{e}','{w}');
   INSERT INTO reviewers VALUES('{t}','{e}','{r}',true);
   INSERT INTO policy_versions VALUES('{t}','{e}','{c}',1,5000,50000,1800);
   INSERT INTO budget_connections VALUES('{t}','{e}','{c}',100000,100000);
  "#
        ))
        .execute(&admin)
        .await
        .unwrap();
        Self {
            control,
            name,
            admin,
            api,
            r: Reviewer {
                tenant_id: t,
                environment_id: e,
                reviewer_id: r,
            },
            c,
            w,
        }
    }
    fn store(&self) -> Store {
        Store::from_pool(self.api.clone())
    }
    async fn grant(&self, table: &str) {
        sqlx::query(&format!(
            "INSERT INTO {table} VALUES($1,$2,$3,$4,true) ON CONFLICT DO NOTHING"
        ))
        .bind(self.r.tenant_id)
        .bind(self.r.environment_id)
        .bind(self.r.reviewer_id)
        .bind(self.c)
        .execute(&self.admin)
        .await
        .unwrap();
    }
    async fn action(&self, status: &str) -> Uuid {
        let a = Uuid::new_v4();
        sqlx::query("INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status,created_at) VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()-interval '200 days')")
   .bind(self.r.tenant_id).bind(self.r.environment_id).bind(a).bind(self.w).bind(serde_json::json!({"connection_id":self.c,"private":"secret-payment"})).bind(status).execute(&self.admin).await.unwrap();
        a
    }
    async fn dispatch(&self, state: DispatchState) -> Uuid {
        let status = match state {
            DispatchState::Succeeded(_) => "succeeded",
            DispatchState::FailedConfirmed(_) => "failed_confirmed",
            _ => "dispatching",
        };
        let a = self.action(status).await;
        let request = VerifiedRefundRequest::new(
            self.c,
            format!("private-payment-{a}"),
            123,
            Currency::Usd,
            1000,
            2000,
        )
        .unwrap();
        let mut snapshot = Dispatch::authorize(a, request, 1001)
            .unwrap()
            .snapshot()
            .clone();
        if state != DispatchState::Authorized {
            snapshot.first_send_at = Some(1002);
            snapshot.retry_until = Some(2000);
            snapshot.lease = Some(Lease {
                action_id: a,
                generation: 1,
                expires_at: 2001,
            });
        }
        snapshot.state = state;
        Dispatch::restore(snapshot.clone()).unwrap();
        sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms,state_changed_at) VALUES($1,$2,$3,$4,'private-provider',$5,1,$6,0,NULL)")
   .bind(self.r.tenant_id).bind(self.r.environment_id).bind(a).bind(self.c).bind(format!("apl-refund-v1-{a}")).bind(serde_json::to_value(snapshot).unwrap()).execute(&self.admin).await.unwrap();
        sqlx::query("INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state) VALUES($1,$2,$3,$4,$5,123,CURRENT_DATE,'held')")
   .bind(self.r.tenant_id).bind(self.r.environment_id).bind(a).bind(self.c).bind(self.w).execute(&self.admin).await.unwrap();
        a
    }
    async fn cleanup(self) {
        self.api.close().await;
        self.admin.close().await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.control)
            .await
            .unwrap();
        self.control.close().await;
    }
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL admin"]
async fn recovery_runtime_scope_paging_validation_and_independent_preview() {
    let f = Fixture::new().await;
    let store = f.store();
    let manual = f.dispatch(DispatchState::ManualReview).await;
    let unknown = f.dispatch(DispatchState::Unknown).await;
    let pending = f.dispatch(DispatchState::Pending).await;
    let inflight = f.dispatch(DispatchState::InFlight).await;
    let authorized = f.dispatch(DispatchState::Authorized).await;
    assert!(matches!(
        store
            .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.reconciliation_state(&f.r, manual).await,
        Err(StoreError::NotFound)
    ));
    f.grant("operations_grants").await;
    let page = store
        .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 5);
    for item in &page.items {
        assert!(!item.can_reconcile);
        assert_eq!(item.held_minor, 123);
        assert_eq!(item.hold_state.as_deref(), Some("held"));
        assert_eq!(item.state_changed_at, None);
    }
    assert!(matches!(
        store.reconciliation_state(&f.r, manual).await,
        Err(StoreError::NotFound)
    ));
    f.grant("reconciliation_grants").await;
    let before:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM external_reconciliation_requests),(SELECT count(*) FROM audit_events),(SELECT sum(amount_minor)::bigint FROM budget_reservations WHERE state='held')").fetch_one(&f.admin).await.unwrap();
    let state = store.reconciliation_state(&f.r, manual).await.unwrap();
    assert!(state.can_request);
    assert_eq!(state.reason_code, "ELIGIBLE");
    let no_dispatch = f.action("ready").await;
    assert_eq!(
        store
            .reconciliation_state(&f.r, no_dispatch)
            .await
            .unwrap()
            .reason_code,
        "NO_DISPATCH"
    );
    let page = store
        .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 100)
        .await
        .unwrap();
    assert!(
        page.items
            .iter()
            .find(|i| i.action_id == manual)
            .unwrap()
            .can_reconcile
    );
    let raw = serde_json::to_string(&page).unwrap();
    for secret in [
        "private-payment",
        "private-provider",
        "snapshot",
        "provider_key",
        "lease_expires",
        "secret-payment",
    ] {
        assert!(!raw.contains(secret));
    }
    let mut seen = Vec::new();
    let mut cursor = None;
    loop {
        let p = store
            .operations_items(&f.r, f.c, RecoveryKind::Dispatches, cursor.as_deref(), 2)
            .await
            .unwrap();
        seen.extend(p.items.iter().map(|i| i.action_id));
        cursor = p.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    let mut expected = vec![manual, unknown, pending, inflight, authorized];
    expected.sort();
    assert_eq!(seen, expected);
    let first = store
        .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 1)
        .await
        .unwrap();
    assert!(matches!(
        store
            .operations_items(
                &f.r,
                f.c,
                RecoveryKind::ReadyJobs,
                first.next_cursor.as_deref(),
                1
            )
            .await,
        Err(StoreError::Invalid(_))
    ));
    for limit in [0, 101] {
        assert!(matches!(
            store
                .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, limit)
                .await,
            Err(StoreError::Invalid(_))
        ));
    }
    let foreign = Reviewer {
        environment_id: Uuid::new_v4(),
        ..f.r.clone()
    };
    assert!(matches!(
        store.reconciliation_state(&foreign, manual).await,
        Err(StoreError::NotFound)
    ));
    // Reads do not schedule, audit, settle or release exposure.
    let after:(i64,i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM external_reconciliation_requests),(SELECT count(*) FROM audit_events),(SELECT sum(amount_minor)::bigint FROM budget_reservations WHERE state='held')").fetch_one(&f.admin).await.unwrap();
    assert_eq!(before, after);
    // A reconciliation-only operator needs no operations or detail permission.
    sqlx::query("UPDATE operations_grants SET enabled=false")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(
        store
            .reconciliation_state(&f.r, manual)
            .await
            .unwrap()
            .can_request
    );
    assert!(matches!(
        store
            .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    // Revocation waits for authority locks retained by the read transaction.
    let mut lock = f.api.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(f.r.tenant_id.to_string())
    .bind(f.r.environment_id.to_string())
    .execute(&mut *lock)
    .await
    .unwrap();
    let _: serde_json::Value = sqlx::query_scalar("SELECT read_reconciliation_state($1,$2,$3,$4)")
        .bind(f.r.tenant_id)
        .bind(f.r.environment_id)
        .bind(f.r.reviewer_id)
        .bind(manual)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let mut revoke = f.admin.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='50ms'")
        .execute(&mut *revoke)
        .await
        .unwrap();
    assert!(
        sqlx::query("UPDATE reconciliation_grants SET enabled=false")
            .execute(&mut *revoke)
            .await
            .is_err()
    );
    revoke.rollback().await.unwrap();
    lock.rollback().await.unwrap();
    let key: String =
        sqlx::query_scalar("SELECT provider_key FROM external_dispatches WHERE action_id=$1")
            .bind(manual)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(matches!(
        store.request_external_reconciliation(&f.r, unknown).await,
        Err(StoreError::Conflict)
    ));
    store
        .request_external_reconciliation(&f.r, manual)
        .await
        .unwrap();
    assert_eq!(
        store
            .reconciliation_state(&f.r, manual)
            .await
            .unwrap()
            .reason_code,
        "ALREADY_QUEUED"
    );
    let unchanged:(String,i64)=sqlx::query_as("SELECT d.provider_key,b.amount_minor FROM external_dispatches d JOIN budget_reservations b USING(tenant_id,environment_id,action_id) WHERE d.action_id=$1 AND b.state='held'").bind(manual).fetch_one(&f.admin).await.unwrap();
    assert_eq!(unchanged, (key, 123));
    sqlx::query("UPDATE connections SET enabled=false")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(matches!(
        store.reconciliation_state(&f.r, manual).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store.request_external_reconciliation(&f.r, manual).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("UPDATE connections SET enabled=true")
        .execute(&f.admin)
        .await
        .unwrap();
    // Model storage corruption using the fixture administrator, beyond normal writes.
    sqlx::query("ALTER TABLE external_dispatches DISABLE TRIGGER guard_external_dispatch")
        .execute(&f.admin)
        .await
        .unwrap();
    // Invalid private snapshots and inconsistent parent states fail closed.
    sqlx::query("UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{first_send_at}','null') WHERE action_id=$1").bind(unknown).execute(&f.admin).await.unwrap();
    assert!(store.reconciliation_state(&f.r, unknown).await.is_err());
    sqlx::query("UPDATE actions SET status='succeeded' WHERE id=$1")
        .bind(pending)
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(store.reconciliation_state(&f.r, pending).await.is_err());
    for role in ["apl_api", "apl_worker"] {
        let allowed:bool=sqlx::query_scalar("SELECT has_function_privilege($1,'read_reconciliation_state(uuid,uuid,uuid,uuid)','EXECUTE')").bind(role).fetch_one(&f.admin).await.unwrap();
        assert_eq!(allowed, role == "apl_api");
    }
    let corrupt_manual = f.dispatch(DispatchState::ManualReview).await;
    sqlx::query("UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{first_send_at}','null') WHERE action_id=$1").bind(corrupt_manual).execute(&f.admin).await.unwrap();
    assert!(store
        .request_external_reconciliation(&f.r, corrupt_manual)
        .await
        .is_err());
    let queued: bool =
        sqlx::query_scalar("SELECT closed FROM external_dispatch_queue WHERE action_id=$1")
            .bind(corrupt_manual)
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert!(queued);
    let requests: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM external_reconciliation_requests WHERE action_id=$1",
    )
    .bind(corrupt_manual)
    .fetch_one(&f.admin)
    .await
    .unwrap();
    assert_eq!(requests, 0);
    let inconsistent_manual = f.dispatch(DispatchState::ManualReview).await;
    sqlx::query("UPDATE actions SET status='succeeded' WHERE id=$1")
        .bind(inconsistent_manual)
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(store
        .request_external_reconciliation(&f.r, inconsistent_manual)
        .await
        .is_err());
    let unchanged: (bool,i64)=sqlx::query_as("SELECT q.closed,(SELECT count(*) FROM external_reconciliation_requests r WHERE r.action_id=q.action_id) FROM external_dispatch_queue q WHERE q.action_id=$1").bind(inconsistent_manual).fetch_one(&f.admin).await.unwrap();
    assert_eq!(unchanged, (true, 0));
    f.cleanup().await;
}
#[tokio::test]
#[ignore = "requires disposable TEST_DATABASE_URL admin"]
async fn recovery_ready_definition_closed_exclusion_and_retention() {
    let f = Fixture::new().await;
    f.grant("operations_grants").await;
    f.grant("reconciliation_grants").await;
    let store = f.store();
    let terminal = f
        .dispatch(DispatchState::Succeeded(
            apl_dispatch::EvidenceRef::new("private-success".into()).unwrap(),
        ))
        .await;
    let failed = f
        .dispatch(DispatchState::FailedConfirmed(
            apl_dispatch::EvidenceRef::new("private-failed".into()).unwrap(),
        ))
        .await;
    let abandoned = f.dispatch(DispatchState::Authorized).await;
    sqlx::query("UPDATE external_dispatches SET abandoned_at_ms=2000 WHERE action_id=$1")
        .bind(abandoned)
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE actions SET status='denied' WHERE id=$1")
        .bind(abandoned)
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(store
        .operations_items(&f.r, f.c, RecoveryKind::Dispatches, None, 50)
        .await
        .unwrap()
        .items
        .is_empty());
    for a in [terminal, failed, abandoned] {
        assert!(
            !store
                .reconciliation_state(&f.r, a)
                .await
                .unwrap()
                .can_request
        );
    }
    let ready = f.action("ready").await;
    let received = f.action("received").await;
    let future = f.action("ready").await;
    let done = f.action("ready").await;
    let wrong_status = f.action("pending_approval").await;
    let mut jobs = f.admin.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(f.r.tenant_id.to_string())
    .bind(f.r.environment_id.to_string())
    .execute(&mut *jobs)
    .await
    .unwrap();
    for (a, delta, finished) in [
        (ready, -120, false),
        (received, -10, false),
        (future, 120, false),
        (done, -30, true),
        (wrong_status, -30, false),
    ] {
        sqlx::query("INSERT INTO outbox_jobs(tenant_id,environment_id,action_id,available_at,done) VALUES($1,$2,$3,clock_timestamp()+make_interval(secs=>$4),$5)")
   .bind(f.r.tenant_id).bind(f.r.environment_id).bind(a).bind(delta as f64).bind(finished).execute(&mut *jobs).await.unwrap();
    }
    jobs.commit().await.unwrap();
    sqlx::query("UPDATE tenants SET paused=true")
        .execute(&f.admin)
        .await
        .unwrap();
    let rows = store
        .operations_items(&f.r, f.c, RecoveryKind::ReadyJobs, None, 50)
        .await
        .unwrap()
        .items;
    assert_eq!(rows.len(), 2);
    let due = rows.iter().find(|i| i.action_id == ready).unwrap();
    assert!(due.queue_lag_seconds.unwrap() >= 120);
    assert!(due.queue_lag_seconds.unwrap() < 180);
    assert_eq!(due.dispatch_state, None);
    assert_eq!(due.lease_expired, None);
    assert!(due.queue_due_at.as_deref().unwrap().ends_with('Z'));
    // Age records using the fixture administrator; production writes preserve timestamps.
    sqlx::query("ALTER TABLE actions DISABLE TRIGGER maintain_action_retention_times")
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("UPDATE actions SET created_at=clock_timestamp()-interval '200 days' WHERE id=$1")
        .bind(ready)
        .execute(&f.admin)
        .await
        .unwrap();
    // Old active actions remain visible; old terminal actions with a held exposure remain visible.
    sqlx::query("UPDATE actions SET terminal_at=clock_timestamp()-interval '200 days' WHERE id=$1")
        .bind(terminal)
        .execute(&f.admin)
        .await
        .unwrap();
    sqlx::query("ALTER TABLE actions ENABLE TRIGGER maintain_action_retention_times")
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(store
        .operations_items(&f.r, f.c, RecoveryKind::ReadyJobs, None, 50)
        .await
        .unwrap()
        .items
        .iter()
        .any(|i| i.action_id == ready));
    assert!(store.reconciliation_state(&f.r, terminal).await.is_ok());
    // Once the hold is settled, aged terminal evidence is hidden by current retention.
    sqlx::query("UPDATE budget_reservations SET state='settled' WHERE action_id=$1")
        .bind(terminal)
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(matches!(
        store.reconciliation_state(&f.r, terminal).await,
        Err(StoreError::NotFound)
    ));
    let fake_terminal = f.action("succeeded").await;
    assert_eq!(
        store
            .reconciliation_state(&f.r, fake_terminal)
            .await
            .unwrap()
            .reason_code,
        "NO_DISPATCH"
    );
    // Neither worker nor PUBLIC can use the new read functions.
    for signature in [
        "read_operations_items(uuid,uuid,uuid,uuid,text,uuid,bigint)",
        "read_reconciliation_state(uuid,uuid,uuid,uuid)",
    ] {
        let denied: bool =
            sqlx::query_scalar("SELECT has_function_privilege('apl_worker',$1,'EXECUTE')")
                .bind(signature)
                .fetch_one(&f.admin)
                .await
                .unwrap();
        assert!(!denied);
    }
    f.cleanup().await;
}
