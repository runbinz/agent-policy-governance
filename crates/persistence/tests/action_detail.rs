use apl_domain::{action_detail::HistoryKind, Reviewer};
use apl_persistence::{Store, StoreError};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;
#[tokio::test]
#[ignore = "requires owned disposable TEST_DATABASE_URL admin"]
async fn detail_authority_redaction_history_and_retention() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = PgPool::connect(&url).await.unwrap();
    Store::from_pool(admin.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&admin)
        .await
        .unwrap();
    let (t, e, c, w, r, a) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    sqlx::raw_sql(&format!(r#"SELECT set_config('apl.tenant_id','{t}',false),set_config('apl.environment_id','{e}',false);
 INSERT INTO tenants(tenant_id) VALUES('{t}');INSERT INTO environments VALUES('{t}','{e}',true);INSERT INTO connections(tenant_id,environment_id,connection_id) VALUES('{t}','{e}','{c}');INSERT INTO workloads(tenant_id,environment_id,workload_id) VALUES('{t}','{e}','{w}');INSERT INTO reviewers VALUES('{t}','{e}','{r}',true);
 INSERT INTO reviewer_grants VALUES('{t}','{e}','{r}','{c}',true);
 INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status) VALUES('{t}','{e}','{a}','{w}','{{"type":"refund.create","connection_id":"{c}","resource":{{"payment_id":"pay_<script>"}},"parameters":{{"amount_minor":123,"currency":"USD"}},"metadata":{{"private":"SECRET_SENTINEL"}}}}','received');
 INSERT INTO audit_events(tenant_id,environment_id,action_id,sequence,event_type,recorded_at) SELECT '{t}','{e}','{a}',n,CASE n WHEN 2 THEN 'approval.requested' WHEN 3 THEN 'dispatch.send_marked' WHEN 4 THEN 'dispatch.reconciliation_requested' ELSE 'SECRET_SENTINEL' END,CASE WHEN n=1 THEN NULL ELSE clock_timestamp() END FROM generate_series(1,105) n;
 "#)).execute(&admin).await.unwrap();
    let api = PgPoolOptions::new()
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET ROLE apl_api").execute(c).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .unwrap();
    let store = Store::from_pool(api.clone());
    let reviewer = Reviewer {
        tenant_id: t,
        environment_id: e,
        reviewer_id: r,
    };
    assert!(matches!(
        store.action_detail(&reviewer, c, a).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("INSERT INTO action_detail_grants VALUES($1,$2,$3,$4,true)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .execute(&admin)
        .await
        .unwrap();
    let detail = store.action_detail(&reviewer, c, a).await.unwrap();
    let serialized = serde_json::to_string(&detail).unwrap();
    assert!(!serialized.contains("SECRET_SENTINEL"));
    assert!(!detail.decision_eligibility.can_decide);
    assert!(detail.authoritative_payment.context.is_none());
    assert!(detail.execution.is_none());
    let page = store
        .action_history(&reviewer, c, a, HistoryKind::Audit, None, 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 100);
    let serialized = serde_json::to_string(&page).unwrap();
    assert!(!serialized.contains("SECRET_SENTINEL"));
    assert!(serialized.contains("\"recorded_at\":null"));
    assert!(serialized.contains("approval.requested"));
    assert!(serialized.contains("dispatch.send_marked"));
    assert!(serialized.contains("dispatch.reconciliation_requested"));
    assert!(serialized.contains("OTHER"));
    let next = page.next_cursor.unwrap();
    let page = store
        .action_history(&reviewer, c, a, HistoryKind::Audit, Some(&next), 100)
        .await
        .unwrap();
    assert_eq!(page.items.len(), 5);
    assert!(page.next_cursor.is_none());
    assert!(matches!(
        store
            .action_history(&reviewer, c, a, HistoryKind::Policy, Some(&next), 50)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.action_detail(&reviewer, Uuid::new_v4(), a).await,
        Err(StoreError::NotFound)
    ));
    let wrong = Reviewer {
        environment_id: Uuid::new_v4(),
        ..reviewer.clone()
    };
    assert!(matches!(
        store.action_detail(&wrong, c, a).await,
        Err(StoreError::NotFound)
    ));
    // An old terminal record is hidden identically on both direct and history reads.
    sqlx::raw_sql(&format!(
        r#"UPDATE actions SET status='denied' WHERE id='{a}';
    ALTER TABLE actions DISABLE TRIGGER maintain_action_retention_times;
    UPDATE actions SET terminal_at=clock_timestamp()-interval '91 days' WHERE id='{a}';
    ALTER TABLE actions ENABLE TRIGGER maintain_action_retention_times;"#
    ))
    .execute(&admin)
    .await
    .unwrap();
    assert!(matches!(
        store.action_detail(&reviewer, c, a).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store
            .action_history(&reviewer, c, a, HistoryKind::Audit, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    // Held exposure preserves visibility even beyond the searchable horizon.
    sqlx::raw_sql(&format!(r#"INSERT INTO budget_connections VALUES('{t}','{e}','{c}',10000,10000);
    INSERT INTO budget_reservations(tenant_id,environment_id,action_id,connection_id,workload_id,amount_minor,utc_day,state) VALUES('{t}','{e}','{a}','{c}','{w}',123,current_date,'held');
    INSERT INTO budget_ledger_events VALUES('{t}','{e}','{a}',1,'reserved',clock_timestamp(),'{{}}');
    "#)).execute(&admin).await.unwrap();
    assert!(store
        .action_detail(&reviewer, c, a)
        .await
        .unwrap()
        .budget
        .is_some());
    assert_eq!(
        store
            .action_history(&reviewer, c, a, HistoryKind::Budget, None, 50)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    // Restore an active status, then exercise a validated connector projection.
    sqlx::raw_sql(&format!(
        r#"UPDATE actions SET status='ready' WHERE id='{a}';
    INSERT INTO policy_versions VALUES('{t}','{e}','{c}',1,5000,50000,1800);
    INSERT INTO policy_bindings VALUES('{t}','{e}','{c}',1);
    "#
    ))
    .execute(&admin)
    .await
    .unwrap();
    let verified = apl_dispatch::VerifiedRefundRequest::new(
        c,
        "pay_<script>".into(),
        123,
        apl_dispatch::Currency::Usd,
        1000,
        2000,
    )
    .unwrap();
    let dispatch = apl_dispatch::Dispatch::authorize(a, verified, 1001).unwrap();
    sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms,state_changed_at) VALUES($1,$2,$3,$4,$7,$5,1,$6,0,NULL)").bind(t).bind(e).bind(a).bind(c).bind(format!("apl-refund-v1-{a}")).bind(serde_json::to_value(dispatch.snapshot()).unwrap()).bind(format!("SECRET_NAMESPACE_{a}")).execute(&admin).await.unwrap();
    let detail = store.action_detail(&reviewer, c, a).await.unwrap();
    assert_eq!(
        detail.authoritative_payment.context.unwrap().observed_at,
        "1970-01-01T00:00:01.000Z"
    );
    assert!(detail.execution.unwrap().state_changed_at.is_none());
    let text = serde_json::to_string(&store.action_detail(&reviewer, c, a).await.unwrap()).unwrap();
    assert!(!text.contains("SECRET_NAMESPACE"));
    assert!(!text.contains("apl-refund-v1"));
    assert!(!text.contains("snapshot"));
    // Detail authority does not confer review authority; eligibility uses the independent grant.
    sqlx::raw_sql(&format!(r#"UPDATE actions SET status='pending_approval' WHERE id='{a}';
    INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at,created_at) VALUES('{t}','{e}','{a}',1,'{c}',1,repeat('0',64),clock_timestamp()+interval '1 hour',NULL);
    UPDATE reviewer_grants SET enabled=false WHERE reviewer_id='{r}';"#)).execute(&admin).await.unwrap();
    let detail = store.action_detail(&reviewer, c, a).await.unwrap();
    assert!(!detail.decision_eligibility.can_decide);
    assert_eq!(detail.decision_eligibility.reason_code, "NO_AUTHORITY");
    assert!(detail.approval.unwrap().queued_at.is_none());
    assert_eq!(
        store
            .action_history(&reviewer, c, a, HistoryKind::Approval, None, 50)
            .await
            .unwrap()
            .items
            .len(),
        1
    );
    let mut tx = api.begin().await.unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(t.to_string())
    .bind(e.to_string())
    .execute(&mut *tx)
    .await
    .unwrap();
    let allowed: bool = sqlx::query_scalar("SELECT authorize_reviewer($1,$2,$3,$4)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(!allowed);
    tx.rollback().await.unwrap();
    sqlx::query("UPDATE reviewer_grants SET enabled=true WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    let eligible = store
        .action_detail(&reviewer, c, a)
        .await
        .unwrap()
        .decision_eligibility;
    assert!(eligible.can_decide);
    assert_eq!(eligible.reason_code, "ELIGIBLE");
    sqlx::raw_sql(&format!(r#"INSERT INTO policy_versions VALUES('{t}','{e}','{c}',2,5000,50000,1800);UPDATE policy_bindings SET version=2 WHERE connection_id='{c}';"#)).execute(&admin).await.unwrap();
    let changed = store
        .action_detail(&reviewer, c, a)
        .await
        .unwrap()
        .decision_eligibility;
    assert!(!changed.can_decide);
    assert_eq!(changed.reason_code, "POLICY_CHANGED");
    sqlx::raw_sql(&format!(r#"INSERT INTO approvals(tenant_id,environment_id,action_id,generation,connection_id,policy_version,action_digest,expires_at) VALUES('{t}','{e}','{a}',2,'{c}',2,repeat('0',64),clock_timestamp()-interval '1 second');"#)).execute(&admin).await.unwrap();
    let expired = store
        .action_detail(&reviewer, c, a)
        .await
        .unwrap()
        .decision_eligibility;
    assert!(!expired.can_decide);
    assert_eq!(expired.reason_code, "APPROVAL_EXPIRED");
    // Every disabled identity/scope component independently closes the read boundary.
    for (table, column, id) in [
        ("tenants", "tenant_id", t),
        ("environments", "environment_id", e),
        ("reviewers", "reviewer_id", r),
        ("connections", "connection_id", c),
    ] {
        let statement = format!("UPDATE {table} SET enabled=$1 WHERE {column}=$2");
        sqlx::query(&statement)
            .bind(false)
            .bind(id)
            .execute(&admin)
            .await
            .unwrap();
        assert!(
            matches!(
                store.action_detail(&reviewer, c, a).await,
                Err(StoreError::NotFound)
            ),
            "disabled {table}"
        );
        assert!(
            matches!(
                store
                    .action_history(&reviewer, c, a, HistoryKind::Audit, None, 50)
                    .await,
                Err(StoreError::NotFound)
            ),
            "disabled {table} history"
        );
        sqlx::query(&statement)
            .bind(true)
            .bind(id)
            .execute(&admin)
            .await
            .unwrap();
    }
    // The authorized read retains SHARE locks until its runtime transaction ends.
    let mut reader = api.begin().await.unwrap();
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *reader)
        .await
        .unwrap();
    sqlx::query(
        "SELECT set_config('apl.tenant_id',$1,true),set_config('apl.environment_id',$2,true)",
    )
    .bind(t.to_string())
    .bind(e.to_string())
    .execute(&mut *reader)
    .await
    .unwrap();
    let _: serde_json::Value = sqlx::query_scalar("SELECT read_action_detail($1,$2,$3,$4,$5)")
        .bind(t)
        .bind(e)
        .bind(r)
        .bind(c)
        .bind(a)
        .fetch_one(&mut *reader)
        .await
        .unwrap();
    let mut revoker = admin.begin().await.unwrap();
    sqlx::query("SET LOCAL lock_timeout='150ms'")
        .execute(&mut *revoker)
        .await
        .unwrap();
    sqlx::query("SET LOCAL statement_timeout='2s'")
        .execute(&mut *revoker)
        .await
        .unwrap();
    let blocked = sqlx::query("UPDATE action_detail_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(r)
        .execute(&mut *revoker)
        .await
        .unwrap_err();
    assert_eq!(
        blocked
            .as_database_error()
            .and_then(|e| e.code())
            .as_deref(),
        Some("55P03")
    );
    revoker.rollback().await.unwrap();
    reader.commit().await.unwrap();
    sqlx::query("UPDATE action_detail_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        store.action_detail(&reviewer, c, a).await,
        Err(StoreError::NotFound)
    ));
    sqlx::query("UPDATE action_detail_grants SET enabled=true WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    // Valid terminal provider outcomes are projected only when the stored action agrees.
    for (terminal_status, success) in [("succeeded", true), ("failed_confirmed", false)] {
        let terminal_id = Uuid::new_v4();
        sqlx::query("INSERT INTO actions(tenant_id,environment_id,id,workload_id,request,status) SELECT tenant_id,environment_id,$1,workload_id,request,$2 FROM actions WHERE id=$3").bind(terminal_id).bind(terminal_status).bind(a).execute(&admin).await.unwrap();
        let request = apl_dispatch::VerifiedRefundRequest::new(
            c,
            "pay_<script>".into(),
            123,
            apl_dispatch::Currency::Usd,
            1000,
            2000,
        )
        .unwrap();
        let mut terminal = apl_dispatch::Dispatch::authorize(terminal_id, request, 1001).unwrap();
        let lease = terminal.claim(1002, 100).unwrap();
        terminal
            .begin_send(lease, 1003, apl_dispatch::ReplaySafety::ReconcileOnly)
            .unwrap();
        let evidence = apl_dispatch::EvidenceRef::new("SECRET_TERMINAL_EVIDENCE".into()).unwrap();
        let outcome = if success {
            apl_dispatch::ProviderOutcome::ConfirmedSuccess(evidence)
        } else {
            apl_dispatch::ProviderOutcome::ConfirmedNonExecution(evidence)
        };
        terminal.observe(lease, 1004, outcome).unwrap();
        sqlx::query("INSERT INTO external_dispatches(tenant_id,environment_id,action_id,connection_id,provider_namespace,provider_key,policy_version,snapshot,available_at_ms) VALUES($1,$2,$3,$4,$5,$6,1,$7,0)").bind(t).bind(e).bind(terminal_id).bind(c).bind(format!("terminal_{terminal_id}")).bind(format!("apl-refund-v1-{terminal_id}")).bind(serde_json::to_value(terminal.snapshot()).unwrap()).execute(&admin).await.unwrap();
        let detail = store
            .action_detail(&reviewer, c, terminal_id)
            .await
            .unwrap();
        assert_eq!(
            detail.provider_outcome.source,
            apl_domain::action_detail::ProviderSource::ExternalDispatch
        );
        assert_eq!(
            detail.provider_outcome.status,
            if success {
                apl_domain::action_detail::ProviderStatus::ConfirmedSuccess
            } else {
                apl_domain::action_detail::ProviderStatus::ConfirmedNonExecution
            }
        );
        assert!(!serde_json::to_string(&detail)
            .unwrap()
            .contains("SECRET_TERMINAL_EVIDENCE"));
        // A terminal dispatch cannot certify the opposite action outcome.
        sqlx::query("UPDATE actions SET status=$1 WHERE id=$2")
            .bind(if success {
                "failed_confirmed"
            } else {
                "succeeded"
            })
            .bind(terminal_id)
            .execute(&admin)
            .await
            .unwrap();
        assert!(matches!(
            store.action_detail(&reviewer, c, terminal_id).await,
            Err(StoreError::Serialization(_))
        ));
    }
    // Corrupt persisted context fails closed, rather than substituting request data.
    sqlx::raw_sql(&format!(r#"ALTER TABLE external_dispatches DISABLE TRIGGER guard_external_dispatch;
    UPDATE external_dispatches SET snapshot=jsonb_set(snapshot,'{{request,amount_minor}}','0') WHERE action_id='{a}';
    ALTER TABLE external_dispatches ENABLE TRIGGER guard_external_dispatch;"#)).execute(&admin).await.unwrap();
    assert!(matches!(
        store.action_detail(&reviewer, c, a).await,
        Err(StoreError::Serialization(_))
    ));
    sqlx::query("UPDATE action_detail_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(r)
        .execute(&admin)
        .await
        .unwrap();
    assert!(matches!(
        store.action_detail(&reviewer, c, a).await,
        Err(StoreError::NotFound)
    ));
    assert!(matches!(
        store
            .action_history(&reviewer, c, a, HistoryKind::Audit, None, 50)
            .await,
        Err(StoreError::NotFound)
    ));
    // The helper is not public and neither grants review nor export authority.
    let granted:bool=sqlx::query_scalar("SELECT has_function_privilege('public','read_action_detail(uuid,uuid,uuid,uuid,uuid)','EXECUTE')").fetch_one(&admin).await.unwrap();
    assert!(!granted);
    api.close().await;
    admin.close().await;
}
