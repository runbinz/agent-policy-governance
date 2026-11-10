use apl_domain::Reviewer;
use apl_persistence::{dispatch_controls::*, Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;
struct Fixture {
    control: PgPool,
    name: String,
    admin: PgPool,
    runtime: PgPool,
    reviewer: Reviewer,
    other: Uuid,
    connection: Uuid,
    workload: Uuid,
}
impl Fixture {
    async fn new() -> Self {
        let parent = std::env::var("TEST_DATABASE_URL").unwrap();
        let control = PgPool::connect(&parent).await.unwrap();
        let name = format!("apl_controls_{}", Uuid::new_v4().simple());
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
        let runtime = PgPoolOptions::new()
            .after_connect(|c, _| {
                Box::pin(async move {
                    sqlx::query("SET ROLE apl_api").execute(c).await?;
                    Ok(())
                })
            })
            .connect(url.as_str())
            .await
            .unwrap();
        let (t, e, r, other, c, w) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        // Deliberately retain legacy INSERT VALUES arity after trailing revision columns.
        sqlx::raw_sql(&format!(r#"
            INSERT INTO tenants(tenant_id) VALUES('{t}');
            INSERT INTO environments VALUES('{t}','{e}',true);
            INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{t}','{e}','{c}');
            INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES('{t}','{e}','{w}');
            INSERT INTO reviewers VALUES('{t}','{e}','{r}',true),('{t}','{e}','{other}',true);
            INSERT INTO workload_grants VALUES('{t}','{e}','{w}','{c}',true,true,true,true,true);
            INSERT INTO reviewer_grants VALUES('{t}','{e}','{other}','{c}',true);
            INSERT INTO reconciliation_grants VALUES('{t}','{e}','{other}','{c}',true);
            INSERT INTO connection_admin_grants VALUES('{t}','{e}','{other}','{c}',true,true,true,true);
            INSERT INTO evidence_export_grants VALUES('{t}','{e}','{other}','{c}',true);
            INSERT INTO operations_grants VALUES('{t}','{e}','{other}','{c}',true);
            INSERT INTO action_detail_grants VALUES('{t}','{e}','{other}','{c}',true);
            INSERT INTO tenant_dispatch_grants VALUES('{t}','{e}','{other}',true);
            INSERT INTO workload_dispatch_grants VALUES('{t}','{e}','{other}','{w}',true);
        "#)).execute(&admin).await.unwrap();
        // Retain both uncertain and manual-review financial exposure throughout administration.
        for state in ["unknown", "manual_review"] {
            let action = Uuid::new_v4();
            sqlx::raw_sql(&format!(r#"
                INSERT INTO policy_versions VALUES('{t}','{e}','{c}',1,100,50000,1800) ON CONFLICT DO NOTHING;
                INSERT INTO budget_connections VALUES('{t}','{e}','{c}',10000,10000) ON CONFLICT DO NOTHING;
                INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status)
                VALUES('{t}','{e}','{action}','{w}','{{"connection_id":"{c}"}}','dispatching');
                INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state)
                VALUES('{t}','{e}','{action}','{c}','{w}',100,CURRENT_DATE,'held');
                INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms)
                VALUES('{t}','{e}','{action}','{c}','environment-test','apl-refund-v1-{action}',1,
                '{{"action_id":"{action}","request":{{"connection_id":"{c}"}},"state":"{state}"}}',0);
            "#)).execute(&admin).await.unwrap();
        }
        Self {
            control,
            name,
            admin,
            runtime,
            reviewer: Reviewer {
                tenant_id: t,
                environment_id: e,
                reviewer_id: r,
            },
            other,
            connection: c,
            workload: w,
        }
    }
    fn store(&self) -> Store {
        Store::from_pool(self.runtime.clone())
    }
    async fn grant(&self) {
        sqlx::query("INSERT INTO environment_admin_grants VALUES($1,$2,$3,true),($1,$2,$4,true)")
            .bind(self.reviewer.tenant_id)
            .bind(self.reviewer.environment_id)
            .bind(self.reviewer.reviewer_id)
            .bind(self.other)
            .execute(&self.admin)
            .await
            .unwrap();
    }
    async fn scoped_tx(&self) -> sqlx::Transaction<'static, sqlx::Postgres> {
        let mut tx = self.runtime.begin().await.unwrap();
        sqlx::query(
            "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
        )
        .bind(self.reviewer.tenant_id.to_string())
        .bind(self.reviewer.environment_id.to_string())
        .execute(&mut *tx)
        .await
        .unwrap();
        tx
    }
    async fn close(self) {
        self.runtime.close().await;
        self.admin.close().await;
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&self.control)
            .await
            .unwrap();
        self.control.close().await;
    }
}

#[tokio::test]
#[ignore = "requires isolated PostgreSQL runtime-role database"]
async fn independent_revisioned_controls() {
    let f = Fixture::new().await;
    let s = f.store();
    let scopes = [
        (ControlKind::Tenant, None),
        (ControlKind::Connection, Some(f.connection)),
        (ControlKind::Workload, Some(f.workload)),
    ];
    for (kind, target) in scopes {
        assert!(matches!(
            s.control_state(&f.reviewer, kind, target).await,
            Err(StoreError::Forbidden)
        ));
    }
    // Unrelated administration grants confer no control authority.
    f.grant().await;
    assert!(matches!(
        s.control_state(&f.reviewer, ControlKind::Tenant, None)
            .await,
        Err(StoreError::Forbidden)
    ));
    let t = f.reviewer.tenant_id;
    let e = f.reviewer.environment_id;
    let r = f.reviewer.reviewer_id;
    sqlx::raw_sql(&format!("INSERT INTO tenant_dispatch_grants VALUES('{t}','{e}','{r}',true); INSERT INTO workload_dispatch_grants VALUES('{t}','{e}','{r}','{}',true); INSERT INTO connection_admin_grants VALUES('{t}','{e}','{r}','{}',true,false,false,true)",f.workload,f.connection)).execute(&f.admin).await.unwrap();
    let audit_before:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM dispatch_scope_audit)+(SELECT count(*) FROM connection_admin_audit)").fetch_one(&f.admin).await.unwrap();
    for (kind, target) in scopes {
        let before = s.control_state(&f.reviewer, kind, target).await.unwrap();
        assert!(!before.paused);
        assert_eq!(
            before,
            s.set_control_state(&f.reviewer, kind, target, before.revision, false)
                .await
                .unwrap()
        );
        assert_eq!(
            before,
            s.control_state(&f.reviewer, kind, target).await.unwrap()
        );
        let paused = s
            .set_control_state(&f.reviewer, kind, target, before.revision, true)
            .await
            .unwrap();
        assert!(paused.paused);
        assert_eq!(paused.revision, before.revision + 1);
        assert!(matches!(
            s.set_control_state(&f.reviewer, kind, target, before.revision, false)
                .await,
            Err(StoreError::Conflict)
        ));
        let (a, b) = tokio::join!(
            s.set_control_state(&f.reviewer, kind, target, paused.revision, false),
            s.set_control_state(&f.reviewer, kind, target, paused.revision, false)
        );
        assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
        assert!(matches!(
            if a.is_err() { a } else { b },
            Err(StoreError::Conflict)
        ));
        let current = s.control_state(&f.reviewer, kind, target).await.unwrap();
        assert!(!current.paused);
        // Disabled and revoked identities fail independently of target state.
        sqlx::query("UPDATE reviewers SET enabled=false WHERE reviewer_id=$1")
            .bind(r)
            .execute(&f.admin)
            .await
            .unwrap();
        assert!(matches!(
            s.control_state(&f.reviewer, kind, target).await,
            Err(StoreError::Forbidden)
        ));
        sqlx::query("UPDATE reviewers SET enabled=true WHERE reviewer_id=$1")
            .bind(r)
            .execute(&f.admin)
            .await
            .unwrap();
        let mut wrong = f.reviewer.clone();
        wrong.environment_id = Uuid::new_v4();
        assert!(matches!(
            s.control_state(&wrong, kind, target).await,
            Err(StoreError::Forbidden)
        ));
    }
    // Authorized reads serialize on targets; unauthorized reads reject before
    // target contention. Reads also retain grant locks through commit.
    for (kind, target, table, idcol, id) in [
        (ControlKind::Tenant, None, "tenants", "tenant_id", t),
        (
            ControlKind::Connection,
            Some(f.connection),
            "connections",
            "connection_id",
            f.connection,
        ),
        (
            ControlKind::Workload,
            Some(f.workload),
            "workloads",
            "workload_id",
            f.workload,
        ),
    ] {
        let mut held = f.admin.begin().await.unwrap();
        sqlx::query(&format!(
            "SELECT 1 FROM {table} WHERE {idcol}=$1 FOR UPDATE"
        ))
        .bind(id)
        .execute(&mut *held)
        .await
        .unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            s.control_state(&f.reviewer, kind, target)
        )
        .await
        .is_err());
        let mut denied = f.reviewer.clone();
        denied.reviewer_id = Uuid::new_v4();
        assert!(matches!(
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                s.control_state(&denied, kind, target)
            )
            .await
            .unwrap(),
            Err(StoreError::Forbidden)
        ));
        held.rollback().await.unwrap();
        let mut read = f.scoped_tx().await;
        sqlx::query("SELECT read_dispatch_control_state($1,$2,$3,$4,$5)")
            .bind(t)
            .bind(e)
            .bind(r)
            .bind(kind.as_str())
            .bind(target)
            .execute(&mut *read)
            .await
            .unwrap();
        let grant = match kind {
            ControlKind::Tenant => "tenant_dispatch_grants",
            ControlKind::Connection => "connection_admin_grants",
            ControlKind::Workload => "workload_dispatch_grants",
        };
        let mut changing = f.admin.begin().await.unwrap();
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            sqlx::query(&format!(
                "UPDATE {grant} SET enabled=false WHERE reviewer_id=$1"
            ))
            .bind(r)
            .execute(&mut *changing)
        )
        .await
        .is_err());
        read.rollback().await.unwrap();
        changing.rollback().await.unwrap();
    }
    for table in ["dispatch_scope_audit", "connection_admin_audit"] {
        let mut tx = f.scoped_tx().await;
        assert!(
            sqlx::query(&format!("UPDATE {table} SET reviewer_id=reviewer_id"))
                .execute(&mut *tx)
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        let mut tx = f.scoped_tx().await;
        assert!(sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await
            .is_err());
        tx.rollback().await.unwrap();
    }
    let audit_after:i64=sqlx::query_scalar("SELECT (SELECT count(*) FROM dispatch_scope_audit)+(SELECT count(*) FROM connection_admin_audit)").fetch_one(&f.admin).await.unwrap();
    assert_eq!(audit_after - audit_before, 6);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM budget_reservations WHERE state='held'")
            .fetch_one(&f.admin)
            .await
            .unwrap(),
        2
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM external_dispatches WHERE snapshot->>'state' IN ('unknown','manual_review')").fetch_one(&f.admin).await.unwrap(),2);
    // Runtime cannot call the private authorizer or directly update audits.
    let mut tx = f.scoped_tx().await;
    assert!(
        sqlx::query("SELECT lock_dispatch_control($1,$2,$3,'tenant',NULL)")
            .bind(t)
            .bind(e)
            .bind(r)
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    for table in ["tenants", "environments"] {
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=false WHERE tenant_id=$1"
        ))
        .bind(t)
        .execute(&f.admin)
        .await
        .unwrap();
        for (kind, target) in scopes {
            assert!(matches!(
                s.control_state(&f.reviewer, kind, target).await,
                Err(StoreError::Forbidden)
            ));
        }
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=true WHERE tenant_id=$1"
        ))
        .bind(t)
        .execute(&f.admin)
        .await
        .unwrap();
    }
    // A dedicated grant confers no authority on either other control scope.
    for (kind, target, table) in [
        (ControlKind::Tenant, None, "tenant_dispatch_grants"),
        (
            ControlKind::Connection,
            Some(f.connection),
            "connection_admin_grants",
        ),
        (
            ControlKind::Workload,
            Some(f.workload),
            "workload_dispatch_grants",
        ),
    ] {
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=false WHERE reviewer_id=$1"
        ))
        .bind(r)
        .execute(&f.admin)
        .await
        .unwrap();
        assert!(matches!(
            s.control_state(&f.reviewer, kind, target).await,
            Err(StoreError::Forbidden)
        ));
        for (other, other_target) in scopes {
            if other != kind {
                assert!(s
                    .control_state(&f.reviewer, other, other_target)
                    .await
                    .is_ok());
            }
        }
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=true WHERE reviewer_id=$1"
        ))
        .bind(r)
        .execute(&f.admin)
        .await
        .unwrap();
    }
    for table in [
        "tenant_dispatch_grants",
        "connection_admin_grants",
        "workload_dispatch_grants",
    ] {
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=false WHERE reviewer_id=$1"
        ))
        .bind(r)
        .execute(&f.admin)
        .await
        .unwrap();
    }
    for (kind, target) in scopes {
        assert!(matches!(
            s.control_state(&f.reviewer, kind, target).await,
            Err(StoreError::Forbidden)
        ));
    }
    f.close().await;
}
