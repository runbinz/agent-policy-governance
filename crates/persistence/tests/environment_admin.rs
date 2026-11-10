use apl_domain::Reviewer;
use apl_persistence::{environment_admin::*, Store, StoreError};
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
        let name = format!("apl_env_admin_{}", Uuid::new_v4().simple());
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
const KINDS: [GrantKind; 10] = [
    GrantKind::Workload,
    GrantKind::Approval,
    GrantKind::Reconciliation,
    GrantKind::PolicyAdmin,
    GrantKind::EvidenceExport,
    GrantKind::Operations,
    GrantKind::ActionDetail,
    GrantKind::TenantDispatch,
    GrantKind::WorkloadDispatch,
    GrantKind::EnvironmentAdmin,
];

#[tokio::test]
#[ignore = "requires isolated disposable TEST_DATABASE_URL admin"]
async fn environment_admin_scopes_pages_revisions_and_audit() {
    let f = Fixture::new().await;
    let store = f.store();
    let r = &f.reviewer;
    assert!(matches!(
        store
            .admin_entities(r, EntityKind::Connections, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    // All other authority grants remain independent of administration.
    let other = Reviewer {
        reviewer_id: f.other,
        ..r.clone()
    };
    assert!(matches!(
        store
            .admin_grants(&other, GrantKind::Approval, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    f.grant().await;
    let page = store
        .admin_entities(r, EntityKind::Connections, None, 1)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert!(!page.can_control_tenant);
    assert!(matches!(
        &page.items[0],
        AdminEntity::Connections {
            mode: ConnectionMode::LocalFake,
            credential_health: CredentialHealth::Unobserved,
            last_payment_verified_at: None,
            can_control: false,
            ..
        }
    ));
    let json = serde_json::to_string(&page).unwrap();
    assert!(
        !json.contains("provider_namespace")
            && !json.contains("secret")
            && !json.contains("account")
    );
    // Same tenant, foreign environment and foreign tenant neither list nor mutate.
    for (t, e) in [
        (r.tenant_id, Uuid::new_v4()),
        (Uuid::new_v4(), Uuid::new_v4()),
    ] {
        let foreign = Reviewer {
            tenant_id: t,
            environment_id: e,
            reviewer_id: r.reviewer_id,
        };
        assert!(matches!(
            store
                .admin_entities(&foreign, EntityKind::Reviewers, None, 50)
                .await,
            Err(StoreError::NotFound)
        ));
    }
    for (table, idcol, id) in [
        ("tenants", "tenant_id", r.tenant_id),
        ("environments", "environment_id", r.environment_id),
        ("reviewers", "reviewer_id", r.reviewer_id),
        ("environment_admin_grants", "reviewer_id", r.reviewer_id),
    ] {
        sqlx::query(&format!(
            "UPDATE {table} SET enabled=false WHERE {idcol}=$1"
        ))
        .bind(id)
        .execute(&f.admin)
        .await
        .unwrap();
        assert!(
            matches!(
                store.admin_grants(r, GrantKind::Approval, None, 50).await,
                Err(StoreError::NotFound)
            ),
            "disabled {table}"
        );
        sqlx::query(&format!("UPDATE {table} SET enabled=true WHERE {idcol}=$1"))
            .bind(id)
            .execute(&f.admin)
            .await
            .unwrap();
    }
    // An independently authorized foreign environment remains a disjoint inventory.
    let foreign_e = Uuid::new_v4();
    let foreign_c = Uuid::new_v4();
    sqlx::raw_sql(&format!(r#"
        INSERT INTO environments VALUES('{}','{foreign_e}',true);
        INSERT INTO reviewers VALUES('{}','{foreign_e}','{}',true);
        INSERT INTO environment_admin_grants VALUES('{}','{foreign_e}','{}',true);
        INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{}','{foreign_e}','{foreign_c}');
    "#,r.tenant_id,r.tenant_id,r.reviewer_id,r.tenant_id,r.reviewer_id,r.tenant_id)).execute(&f.admin).await.unwrap();
    let foreign = Reviewer {
        environment_id: foreign_e,
        ..r.clone()
    };
    let foreign_page = store
        .admin_entities(&foreign, EntityKind::Connections, None, 100)
        .await
        .unwrap();
    assert_eq!(
        foreign_page
            .items
            .iter()
            .map(AdminEntity::id)
            .collect::<Vec<_>>(),
        vec![foreign_c]
    );
    assert!(matches!(
        store
            .admin_set_enabled(&foreign, EntityKind::Connections, f.connection, 1, false)
            .await,
        Err(StoreError::Conflict)
    ));
    // Only separate dispatch grants enable controls.
    let other_page = store
        .admin_entities(&other, EntityKind::Connections, None, 50)
        .await
        .unwrap();
    assert!(other_page.can_control_tenant);
    assert!(matches!(
        &other_page.items[0],
        AdminEntity::Connections {
            can_control: true,
            ..
        }
    ));
    // Immutable configured routing determines honest mode; private identifier never projected.
    sqlx::query("INSERT INTO provider_routes VALUES($1,$2,$3,$4)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(f.connection)
        .bind(format!("stripe-test:acct_{}", Uuid::new_v4().simple()))
        .execute(&f.admin)
        .await
        .unwrap();
    assert!(matches!(
        &store
            .admin_entities(r, EntityKind::Connections, None, 50)
            .await
            .unwrap()
            .items[0],
        AdminEntity::Connections {
            mode: ConnectionMode::StripeSandbox,
            ..
        }
    ));
    // Traversal reaches every row and cursor is tied to exact scope and kind.
    let reviewers = store
        .admin_entities(r, EntityKind::Reviewers, None, 1)
        .await
        .unwrap();
    let after = reviewers.next_after.unwrap();
    let next = store
        .admin_entities(r, EntityKind::Reviewers, Some(after), 1)
        .await
        .unwrap();
    assert_eq!(next.items.len(), 1);
    assert!(next.next_after.is_none());
    assert!(matches!(
        store
            .admin_entities(r, EntityKind::Connections, None, 0)
            .await,
        Err(StoreError::Invalid(_))
    ));
    let grants = store
        .admin_grants(r, GrantKind::EnvironmentAdmin, None, 1)
        .await
        .unwrap();
    let cursor = grants.next_after.unwrap();
    assert_eq!(
        store
            .admin_grants(r, GrantKind::EnvironmentAdmin, Some(&cursor), 1)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    assert!(matches!(
        store
            .admin_grants(r, GrantKind::Approval, Some(&cursor), 1)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store
            .admin_grants(
                r,
                GrantKind::EnvironmentAdmin,
                Some(&(cursor.clone() + "x")),
                1
            )
            .await,
        Err(StoreError::Invalid(_))
    ));
    // Caller revision injection is ignored; changes from legacy writers advance revision.
    sqlx::query("UPDATE connections SET admin_revision=999 WHERE connection_id=$1")
        .bind(f.connection)
        .execute(&f.admin)
        .await
        .unwrap();
    let rev = store
        .admin_entities(r, EntityKind::Connections, None, 50)
        .await
        .unwrap()
        .items[0]
        .revision();
    assert_eq!(rev, 2);
    assert_eq!(
        store
            .admin_set_enabled(r, EntityKind::Connections, f.connection, rev, false)
            .await
            .unwrap()
            .revision,
        3
    );
    assert!(matches!(
        store
            .admin_set_enabled(r, EntityKind::Connections, f.connection, rev, true)
            .await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store
            .admin_set_enabled(r, EntityKind::Connections, Uuid::new_v4(), 1, false)
            .await,
        Err(StoreError::Conflict)
    ));
    assert!(matches!(
        store
            .admin_set_enabled(r, EntityKind::Reviewers, r.reviewer_id, 1, false)
            .await,
        Err(StoreError::Invalid(_))
    ));
    for kind in KINDS {
        let row = store
            .admin_grants(r, kind, None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|row| row.reviewer_id != Some(r.reviewer_id))
            .unwrap();
        assert!(!row.permissions.is_empty());
        if kind == GrantKind::Workload {
            assert!(row.permissions.contains(&GrantPermission::CancelAction));
        }
        let input = RevokeInput {
            kind,
            connection_id: row.connection_id,
            workload_id: row.workload_id,
            reviewer_id: row.reviewer_id,
            expected_revision: row.admin_revision,
        };
        let mut bad = input.clone();
        bad.workload_id = if bad.workload_id.is_some() {
            None
        } else {
            Some(f.workload)
        };
        assert!(matches!(
            store.admin_revoke(r, &bad).await,
            Err(StoreError::Invalid(_))
        ));
        // SQL independently enforces forbidden/required keys.
        let mut tx = f.scoped_tx().await;
        let error = sqlx::query("SELECT admin_revoke_grant($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(r.tenant_id)
            .bind(r.environment_id)
            .bind(r.reviewer_id)
            .bind(kind.as_str())
            .bind(bad.connection_id)
            .bind(bad.workload_id)
            .bind(bad.reviewer_id)
            .bind(bad.expected_revision)
            .execute(&mut *tx)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("AP400")
        );
        tx.rollback().await.unwrap();
        assert_eq!(
            store.admin_revoke(r, &input).await.unwrap().revision,
            row.admin_revision + 1
        );
        assert!(matches!(
            store.admin_revoke(r, &input).await,
            Err(StoreError::Conflict)
        ));
        let updated = store
            .admin_grants(r, kind, None, 100)
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|x| {
                x.connection_id == row.connection_id
                    && x.workload_id == row.workload_id
                    && x.reviewer_id == row.reviewer_id
            })
            .unwrap();
        assert!(!updated.enabled);
        assert_eq!(updated.permissions, row.permissions);
    }
    let input = RevokeInput {
        kind: GrantKind::EnvironmentAdmin,
        connection_id: None,
        workload_id: None,
        reviewer_id: Some(r.reviewer_id),
        expected_revision: 3,
    };
    assert!(matches!(
        store.admin_revoke(r, &input).await,
        Err(StoreError::Invalid(_))
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM environment_admin_audit")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(count, 11);
    let valid: bool=sqlx::query_scalar("SELECT bool_and(reviewer_id=$1 AND tenant_id=$2 AND environment_id=$3 AND new_revision=expected_revision+1) FROM environment_admin_audit").bind(r.reviewer_id).bind(r.tenant_id).bind(r.environment_id).fetch_one(&f.admin).await.unwrap();
    assert!(valid);
    for sql in [
        "UPDATE environment_admin_audit SET kind='workload'",
        "DELETE FROM environment_admin_audit",
        "SELECT * FROM environment_admin_grants",
        "UPDATE connections SET enabled=true",
        "UPDATE reviewer_grants SET enabled=true",
        "SELECT environment_grant_spec('approval')",
    ] {
        let mut tx = f.scoped_tx().await;
        assert!(
            sqlx::query(sql).execute(&mut *tx).await.is_err(),
            "raw denied: {sql}"
        );
        tx.rollback().await.unwrap();
    }
    assert!(sqlx::query("DELETE FROM environment_admin_audit")
        .execute(&f.admin)
        .await
        .is_err());
    let held: i64 =
        sqlx::query_scalar("SELECT count(*) FROM budget_reservations WHERE state='held'")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    let uncertain: i64 = sqlx::query_scalar("SELECT count(*) FROM external_dispatches WHERE snapshot->>'state' IN ('unknown','manual_review')").fetch_one(&f.admin).await.unwrap();
    assert_eq!((held, uncertain), (2, 2));
    f.close().await;
}

#[tokio::test]
#[ignore = "requires isolated disposable TEST_DATABASE_URL admin"]
async fn environment_admin_held_authority_and_target_locks() {
    let f = Fixture::new().await;
    f.grant().await;
    let r = &f.reviewer;
    // A read holds authority until transaction completion, even after its statement returns.
    let mut held = f.scoped_tx().await;
    sqlx::query("SELECT read_admin_entities($1,$2,$3,'connections',NULL,50)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(r.reviewer_id)
        .execute(&mut *held)
        .await
        .unwrap();
    let mut revoke = f.scoped_tx().await;
    sqlx::query("SET LOCAL lock_timeout='100ms'")
        .execute(&mut *revoke)
        .await
        .unwrap();
    let err = sqlx::query("SELECT admin_revoke_grant($1,$2,$3,'environment_admin',NULL,NULL,$4,1)")
        .bind(r.tenant_id)
        .bind(r.environment_id)
        .bind(f.other)
        .bind(r.reviewer_id)
        .execute(&mut *revoke)
        .await
        .unwrap_err();
    assert_eq!(
        err.as_database_error().unwrap().code().as_deref(),
        Some("55P03")
    );
    revoke.rollback().await.unwrap();
    held.commit().await.unwrap();
    // Existing workload authorization SHARE locks serialize entity disable and grant revocation.
    for entity in [true, false] {
        let mut held = f.scoped_tx().await;
        let authorized: bool =
            sqlx::query_scalar("SELECT authorize_scope($1,$2,$3,$4,'submit_refund')")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(f.workload)
                .bind(f.connection)
                .fetch_one(&mut *held)
                .await
                .unwrap();
        assert!(authorized);
        let mut mutation = f.scoped_tx().await;
        sqlx::query("SET LOCAL lock_timeout='100ms'")
            .execute(&mut *mutation)
            .await
            .unwrap();
        let err = if entity {
            sqlx::query("SELECT admin_set_entity_enabled($1,$2,$3,'connections',$4,1,false)")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(r.reviewer_id)
                .bind(f.connection)
                .execute(&mut *mutation)
                .await
                .unwrap_err()
        } else {
            sqlx::query("SELECT admin_revoke_grant($1,$2,$3,'workload',$4,$5,NULL,1)")
                .bind(r.tenant_id)
                .bind(r.environment_id)
                .bind(r.reviewer_id)
                .bind(f.connection)
                .bind(f.workload)
                .execute(&mut *mutation)
                .await
                .unwrap_err()
        };
        assert_eq!(
            err.as_database_error().unwrap().code().as_deref(),
            Some("55P03")
        );
        mutation.rollback().await.unwrap();
        held.commit().await.unwrap();
    }
    // Both administrators capture authority first, then attempt mutual revocation.
    // PostgreSQL must abort one transaction; both cannot commit from stale authority.
    let mut a = f.scoped_tx().await;
    let mut b = f.scoped_tx().await;
    for (tx, actor) in [(&mut a, r.reviewer_id), (&mut b, f.other)] {
        sqlx::query("SELECT read_admin_grants($1,$2,$3,'environment_admin',NULL,50)")
            .bind(r.tenant_id)
            .bind(r.environment_id)
            .bind(actor)
            .execute(&mut **tx)
            .await
            .unwrap();
    }
    let t = r.tenant_id;
    let e = r.environment_id;
    let actor = r.reviewer_id;
    let other = f.other;
    let one = tokio::spawn(async move {
        let result =
            sqlx::query("SELECT admin_revoke_grant($1,$2,$3,'environment_admin',NULL,NULL,$4,1)")
                .bind(t)
                .bind(e)
                .bind(actor)
                .bind(other)
                .execute(&mut *a)
                .await;
        if result.is_ok() {
            a.commit().await.unwrap();
            true
        } else {
            a.rollback().await.unwrap();
            false
        }
    });
    let two = tokio::spawn(async move {
        let result =
            sqlx::query("SELECT admin_revoke_grant($1,$2,$3,'environment_admin',NULL,NULL,$4,1)")
                .bind(t)
                .bind(e)
                .bind(other)
                .bind(actor)
                .execute(&mut *b)
                .await;
        if result.is_ok() {
            b.commit().await.unwrap();
            true
        } else {
            b.rollback().await.unwrap();
            false
        }
    });
    let (one, two) = tokio::join!(one, two);
    assert_ne!(one.unwrap(), two.unwrap());
    let enabled: i64 =
        sqlx::query_scalar("SELECT count(*) FROM environment_admin_grants WHERE enabled")
            .fetch_one(&f.admin)
            .await
            .unwrap();
    assert_eq!(enabled, 1);
    let audit: i64 = sqlx::query_scalar("SELECT count(*) FROM environment_admin_audit")
        .fetch_one(&f.admin)
        .await
        .unwrap();
    assert_eq!(audit, 1);
    f.close().await;
}

#[test]
fn environment_admin_closed_input_shapes_and_safe_revisions() {
    for kind in KINDS {
        assert_eq!(kind.as_str().parse::<GrantKind>().unwrap(), kind);
        let (c, w, r) = match kind {
            GrantKind::Workload => (true, true, false),
            GrantKind::TenantDispatch | GrantKind::EnvironmentAdmin => (false, false, true),
            GrantKind::WorkloadDispatch => (false, true, true),
            _ => (true, false, true),
        };
        let mut input = RevokeInput {
            kind,
            connection_id: c.then(Uuid::new_v4),
            workload_id: w.then(Uuid::new_v4),
            reviewer_id: r.then(Uuid::new_v4),
            expected_revision: 1,
        };
        assert!(input.validate().is_ok());
        for revision in [0, -1, MAX_ADMIN_REVISION, MAX_ADMIN_REVISION + 1] {
            input.expected_revision = revision;
            assert!(input.validate().is_err());
        }
    }
    assert!("workload_grants; DELETE FROM actions"
        .parse::<GrantKind>()
        .is_err());
    assert!(serde_json::from_str::<RevokeInput>(r#"{"kind":"tenant_dispatch","reviewer_id":"00000000-0000-0000-0000-000000000001","expected_revision":1,"secret":"x"}"#).is_err());
}
