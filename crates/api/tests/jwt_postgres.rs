//! Dedicated test DB only; executes HTTP with restricted runtime database roles.
use apl_api::{router_with_reviewers, Authenticator, ReviewerAuthenticator};
use apl_domain::Principal;
use apl_identity::JwtVerifier;
use apl_persistence::Store;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde_json::{json, Value};
use sqlx::{postgres::PgPoolOptions, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

const ISSUER: &str = "https://identity.example.test";
fn token(subject: &str, overrides: Value) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = json!({"iss":ISSUER,"sub":subject,"aud":"apl-api","exp":now+300});
    for (k, v) in overrides.as_object().unwrap() {
        claims[k] = v.clone();
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-1".into());
    encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(include_bytes!(
            "../../identity/tests/fixtures/test-only-private.pem"
        ))
        .unwrap(),
    )
    .unwrap()
}
async fn control_input(app: &Router, token: &str, mut target: Value) -> Value {
    let path = if let Some(id) = target.get("connection_id") {
        format!(
            "/v1/controls/state?kind=connection&id={}",
            id.as_str().unwrap()
        )
    } else if let Some(id) = target.get("workload_id") {
        format!(
            "/v1/controls/state?kind=workload&id={}",
            id.as_str().unwrap()
        )
    } else {
        "/v1/controls/state?kind=tenant".into()
    };
    let (status, state) = call(app, "GET", &path, token, None).await;
    assert_eq!(status, StatusCode::OK);
    target["expected_revision"] = state["revision"].clone();
    target
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {token}"));
    let body = match body {
        Some(value) => {
            request = request
                .header("content-type", "application/json")
                .header("idempotency-key", Uuid::new_v4().to_string());
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
    (
        status,
        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        },
    )
}
async fn runtime_pool(url: &str, worker: bool) -> PgPool {
    PgPoolOptions::new()
        .max_connections(4)
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
        .unwrap()
}
async fn seed(pool: &PgPool, subject: &str) -> Principal {
    let p = Principal {
        tenant_id: Uuid::new_v4(),
        environment_id: Uuid::new_v4(),
        workload_id: Uuid::new_v4(),
        connection_id: Uuid::new_v4(),
    };
    sqlx::query("INSERT INTO tenants VALUES($1,true)")
        .bind(p.tenant_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO environments VALUES($1,$2,true)")
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
    sqlx::query("INSERT INTO budget_connections VALUES($1,$2,$3,1000000,1000000)")
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
    sqlx::query("INSERT INTO identity_registry VALUES($1,$2,$3,$4,$5,$6)")
        .bind(ISSUER)
        .bind(subject)
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(p.workload_id)
        .bind(p.connection_id)
        .execute(pool)
        .await
        .unwrap();
    p
}
#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with admin role creation privileges"]
async fn jwt_identity_http_isolation_and_revocation() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let admin = Store::connect(&url).await.unwrap();
    admin.migrate().await.unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let sub_a = Uuid::new_v4().to_string();
    let sub_b = Uuid::new_v4().to_string();
    let a = seed(&pool, &sub_a).await;
    let b = seed(&pool, &sub_b).await;
    let api = Store::from_pool(runtime_pool(&url, false).await);
    let worker = Store::from_pool(runtime_pool(&url, true).await);
    let verifier = JwtVerifier::from_jwks(
        ISSUER,
        "apl-api",
        include_str!("../../identity/tests/fixtures/jwks.json"),
    )
    .unwrap();
    let review_verifier = JwtVerifier::from_jwks(
        ISSUER,
        "apl-reviewer",
        include_str!("../../identity/tests/fixtures/jwks.json"),
    )
    .unwrap();
    let app = router_with_reviewers(
        api,
        Authenticator::Jwt(verifier),
        Some(ReviewerAuthenticator::Jwt(review_verifier.into())),
    );
    let payload = json!({"type":"refund.create","connection_id":a.connection_id,"resource":{"payment_id":"fake_jwt_payment"},"parameters":{"amount_minor":2500,"currency":"USD"}});
    let valid_a = token(
        &sub_a,
        json!({"tenant_id":b.tenant_id,"environment_id":b.environment_id}),
    );
    let (status, submitted) = call(&app, "POST", "/v1/actions", &valid_a, Some(payload)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = Uuid::parse_str(submitted["id"].as_str().unwrap()).unwrap();
    let path = format!("/v1/actions/{id}");
    assert_eq!(
        call(&app, "GET", &path, &valid_a, None).await.0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "GET", &path, &token(&sub_b, json!({})), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let actual_tenant: Uuid = sqlx::query_scalar("SELECT tenant_id FROM actions WHERE id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actual_tenant, a.tenant_id);
    for bad in [
        token(&sub_a, json!({"iss":"https://wrong.example.test"})),
        token(&sub_a, json!({"aud":"wrong"})),
        token(&sub_a, json!({"exp":1})),
        token("unmapped-subject", json!({})),
    ] {
        assert_eq!(
            call(&app, "GET", &path, &bad, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let mut tampered = valid_a.as_bytes().to_vec();
    let signature_start = valid_a.rfind('.').unwrap() + 1;
    tampered[signature_start] = if tampered[signature_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    assert_eq!(
        call(
            &app,
            "GET",
            &path,
            &String::from_utf8(tampered).unwrap(),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("UPDATE workloads SET enabled=false WHERE workload_id=$1")
        .bind(a.workload_id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(&app, "GET", &path, &valid_a, None).await.0,
        StatusCode::UNAUTHORIZED
    );
    // Drain earlier test jobs too; locate this action by its terminal state.
    for _ in 0..100 {
        let status: String = sqlx::query_scalar("SELECT status FROM actions WHERE id=$1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
        if status != "received" {
            break;
        }
        assert!(worker.process_one().await.unwrap());
    }
    let reason: String = sqlx::query_scalar("SELECT reason FROM actions WHERE id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reason, "AUTHORIZATION_REVOKED");
    let effects: i64 = sqlx::query_scalar("SELECT count(*) FROM fake_effects WHERE action_id=$1")
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(effects, 0);
    sqlx::query("UPDATE workloads SET enabled=true WHERE workload_id=$1")
        .bind(a.workload_id)
        .execute(&pool)
        .await
        .unwrap();
    let (status, result) = call(&app, "GET", &path, &valid_a, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(result["status"], "denied");
    exercise_approvals(&pool, &worker, &app, &a, &b, &sub_a, &sub_b).await;
}

async fn exercise_approvals(
    pool: &PgPool,
    worker: &Store,
    app: &Router,
    a: &Principal,
    b: &Principal,
    sub_a: &str,
    sub_b: &str,
) {
    // Intentionally map the same subjects to both registries. Only the designated
    // token audience may access each HTTP role, independent of database mapping.
    for (p, subject) in [(a, sub_a), (b, sub_b)] {
        let reviewer = Uuid::new_v4();
        sqlx::query("INSERT INTO reviewers VALUES($1,$2,$3,true)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(reviewer)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO reviewer_grants VALUES($1,$2,$3,$4,true)")
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(reviewer)
            .bind(p.connection_id)
            .execute(pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO reviewer_registry VALUES($1,$2,$3,$4,$5)")
            .bind(ISSUER)
            .bind(subject)
            .bind(p.tenant_id)
            .bind(p.environment_id)
            .bind(reviewer)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO policy_versions VALUES($1,$2,$3,1,1000,5000,600)")
        .bind(a.tenant_id)
        .bind(a.environment_id)
        .bind(a.connection_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO policy_bindings VALUES($1,$2,$3,1)")
        .bind(a.tenant_id)
        .bind(a.environment_id)
        .bind(a.connection_id)
        .execute(pool)
        .await
        .unwrap();
    let payload = json!({"type":"refund.create","connection_id":a.connection_id,"resource":{"payment_id":"fake_approval_payment"},"parameters":{"amount_minor":2500,"currency":"USD"}});
    let workload = token(sub_a, json!({}));
    let reviewer_a = token(sub_a, json!({"aud":"apl-reviewer"}));
    let reviewer_b = token(sub_b, json!({"aud":"apl-reviewer"}));
    let dual_audience = token(sub_a, json!({"aud":["apl-api","apl-reviewer"]}));
    for bad in [&reviewer_a, &dual_audience] {
        assert_eq!(
            call(app, "POST", "/v1/actions", bad, Some(payload.clone()))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    for bad in [&workload, &dual_audience] {
        assert_eq!(
            call(app, "GET", "/v1/approvals", bad, None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (code, submitted) = call(app, "POST", "/v1/actions", &workload, Some(payload)).await;
    assert_eq!(code, StatusCode::ACCEPTED);
    let id = submitted["id"].as_str().unwrap();
    let path = format!("/v1/actions/{id}");
    for _ in 0..100 {
        if call(app, "GET", &path, &workload, None).await.1["status"] != "received" {
            break;
        }
        assert!(worker.process_one().await.unwrap());
    }
    let (code, queue_a) = call(app, "GET", "/v1/approvals", &reviewer_a, None).await;
    assert_eq!(code, StatusCode::OK);
    let item = queue_a
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["action_id"] == id)
        .expect("pending approval in reviewer queue");
    let (code, queue_b) = call(app, "GET", "/v1/approvals", &reviewer_b, None).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(queue_b, json!([]));
    let decision = json!({"generation":item["generation"],"action_digest":item["action_digest"],"decision":"approve"});
    let endpoint = format!("/v1/approvals/{id}/decision");
    assert_eq!(
        call(app, "POST", &endpoint, &reviewer_b, Some(decision.clone()))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let mut invalid = decision.clone();
    invalid["reviewer_id"] = json!(Uuid::new_v4());
    assert_eq!(
        call(app, "POST", &endpoint, &reviewer_a, Some(invalid))
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    let mut stale = decision.clone();
    stale["generation"] = json!(item["generation"].as_i64().unwrap() + 1);
    assert_eq!(
        call(app, "POST", &endpoint, &reviewer_a, Some(stale)).await,
        (
            StatusCode::CONFLICT,
            json!({"error":{"code":"approval_conflict"}})
        )
    );
    let (code, action) = call(app, "POST", &endpoint, &reviewer_a, Some(decision.clone())).await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(action["status"], "ready");
    assert_eq!(
        call(app, "POST", &endpoint, &reviewer_a, Some(decision))
            .await
            .0,
        StatusCode::CONFLICT
    );
    for _ in 0..100 {
        if call(app, "GET", &path, &workload, None).await.1["status"] != "ready" {
            break;
        }
        assert!(worker.process_one().await.unwrap());
    }
    assert_eq!(
        call(app, "GET", &path, &workload, None).await.1["status"],
        "succeeded"
    );
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with admin role creation privileges"]
async fn policy_admin_grants_and_concurrent_publication() {
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    Store::from_pool(pool.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let subject = Uuid::new_v4().to_string();
    let scope = seed(&pool, &subject).await;
    let other = seed(&pool, &Uuid::new_v4().to_string()).await;
    let reviewer = Uuid::new_v4();
    sqlx::query("INSERT INTO reviewers(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)")
        .bind(scope.tenant_id)
        .bind(scope.environment_id)
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_registry VALUES($1,$2,$3,$4,$5)")
        .bind(ISSUER)
        .bind(&subject)
        .bind(scope.tenant_id)
        .bind(scope.environment_id)
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    let jwks = include_str!("../../identity/tests/fixtures/jwks.json");
    let app = router_with_reviewers(
        Store::from_pool(runtime_pool(&url, false).await),
        Authenticator::Jwt(JwtVerifier::from_jwks(ISSUER, "apl-api", jwks).unwrap()),
        Some(ReviewerAuthenticator::Jwt(
            JwtVerifier::from_jwks(ISSUER, "apl-reviewer", jwks)
                .unwrap()
                .into(),
        )),
    );
    let review_token = token(&subject, json!({"aud":"apl-reviewer"}));
    let workload_token = token(&subject, json!({}));
    let draft = |connection_id, version| json!({"connection_id":connection_id,"version":version,"auto_limit_minor":4000,"hard_limit_minor":10000,"approval_ttl_seconds":600});
    let scoped = json!({"connection_id":scope.connection_id,"expected_revision":1});
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/policies/drafts",
            &workload_token,
            Some(draft(scope.connection_id, 1))
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/policies/drafts",
            &review_token,
            Some(draft(scope.connection_id, 1))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("INSERT INTO connection_admin_grants(tenant_id,environment_id,reviewer_id,connection_id,edit_policy) VALUES($1,$2,$3,$4,true)")
        .bind(scope.tenant_id).bind(scope.environment_id).bind(reviewer).bind(scope.connection_id).execute(&pool).await.unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/policies/drafts",
            &review_token,
            Some(draft(other.connection_id, 1))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    for version in [1, 2] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/policies/drafts",
                &review_token,
                Some(draft(scope.connection_id, version))
            )
            .await
            .0,
            StatusCode::CREATED
        );
    }
    let action = json!({"type":"refund.create","connection_id":scope.connection_id,"resource":{"payment_id":"fake_policy"},"parameters":{"amount_minor":2500,"currency":"USD"}});
    let (status, simulation) = call(
        &app,
        "POST",
        "/v1/policies/1/simulate",
        &review_token,
        Some(json!({"connection_id":scope.connection_id,"requests":[action]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(simulation["active_version"].is_null());
    assert_eq!(
        simulation["results"][0]["old"]["reason"],
        "NO_ACTIVE_POLICY"
    );
    assert_eq!(simulation["results"][0]["new"]["outcome"], "allow");
    let actions: i64 = sqlx::query_scalar("SELECT count(*) FROM actions WHERE tenant_id=$1")
        .bind(scope.tenant_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actions, 0, "simulation must not submit actions");
    let publish = json!({"connection_id":scope.connection_id,"expected_version":0});
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/policies/1/publish",
            &review_token,
            Some(publish.clone())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/controls/pause",
            &review_token,
            Some(scoped.clone())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE connection_admin_grants SET publish_policy=true,control_dispatch=true WHERE reviewer_id=$1")
        .bind(reviewer).execute(&pool).await.unwrap();
    let (first, second) = tokio::join!(
        call(
            &app,
            "POST",
            "/v1/policies/1/publish",
            &review_token,
            Some(publish.clone())
        ),
        call(
            &app,
            "POST",
            "/v1/policies/2/publish",
            &review_token,
            Some(publish)
        )
    );
    assert!(
        matches!(
            (first.0, second.0),
            (StatusCode::NO_CONTENT, StatusCode::CONFLICT)
                | (StatusCode::CONFLICT, StatusCode::NO_CONTENT)
        ),
        "{first:?} {second:?}"
    );
    for (path, paused) in [("/v1/controls/pause", true), ("/v1/controls/resume", false)] {
        assert_eq!(
            call(
                &app,
                "POST",
                path,
                &review_token,
                Some(control_input(&app, &review_token, scoped.clone()).await)
            )
            .await
            .0,
            StatusCode::OK
        );
        let actual:bool=sqlx::query_scalar("SELECT paused FROM connections WHERE (tenant_id,environment_id,connection_id)=($1,$2,$3)")
            .bind(scope.tenant_id).bind(scope.environment_id).bind(scope.connection_id).fetch_one(&pool).await.unwrap();
        assert_eq!(actual, paused);
    }
    let workload = json!({"workload_id":scope.workload_id,"expected_revision":1});
    let tenant = json!({"tenant":true,"expected_revision":1});
    for target in [workload.clone(), tenant.clone()] {
        assert_eq!(
            call(
                &app,
                "POST",
                "/v1/controls/pause",
                &review_token,
                Some(target)
            )
            .await
            .0,
            StatusCode::NOT_FOUND
        );
    }
    sqlx::query("INSERT INTO workload_dispatch_grants(tenant_id,environment_id,reviewer_id,workload_id) VALUES($1,$2,$3,$4)")
        .bind(scope.tenant_id).bind(scope.environment_id).bind(reviewer).bind(scope.workload_id).execute(&pool).await.unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/controls/pause",
            &review_token,
            Some(tenant.clone())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/controls/pause",
            &review_token,
            Some(json!({"workload_id":other.workload_id,"expected_revision":1}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query(
        "INSERT INTO tenant_dispatch_grants(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)",
    )
    .bind(scope.tenant_id)
    .bind(scope.environment_id)
    .bind(reviewer)
    .execute(&pool)
    .await
    .unwrap();
    for target in [workload, tenant] {
        for path in ["/v1/controls/pause", "/v1/controls/resume"] {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    path,
                    &review_token,
                    Some(control_input(&app, &review_token, target.clone()).await)
                )
                .await
                .0,
                StatusCode::OK
            );
        }
    }
    let scope_audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM dispatch_scope_audit WHERE reviewer_id=$1")
            .bind(reviewer)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(scope_audit, 4);
    let audit: Vec<String> = sqlx::query_scalar(
        "SELECT operation FROM connection_admin_audit WHERE reviewer_id=$1 ORDER BY sequence",
    )
    .bind(reviewer)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        audit,
        [
            "policy.drafted",
            "policy.drafted",
            "policy.published",
            "dispatch.paused",
            "dispatch.resumed"
        ]
    );
    sqlx::query("UPDATE connection_admin_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/controls/pause",
            &review_token,
            Some(scoped)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with admin role creation privileges"]
async fn mcp_uses_same_refund_grants_and_idempotency_as_rest() {
    use apl_api::mcp::{self, McpConfig, McpVerifier};
    const RESOURCE: &str = "https://governance.example.test/mcp";
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    Store::from_pool(pool.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let subject = Uuid::new_v4().to_string();
    let foreign_subject = Uuid::new_v4().to_string();
    let scope = seed(&pool, &subject).await;
    let foreign = seed(&pool, &foreign_subject).await;
    sqlx::query("UPDATE workload_grants SET cancel_action=true WHERE workload_id=$1")
        .bind(scope.workload_id)
        .execute(&pool)
        .await
        .unwrap();
    let store = Store::from_pool(runtime_pool(&url, false).await);
    let jwks = include_str!("../../identity/tests/fixtures/jwks.json");
    let app = mcp::router(
        store.clone(),
        McpVerifier::Static(Box::new(
            JwtVerifier::from_jwks(ISSUER, RESOURCE, jwks).unwrap(),
        )),
        McpConfig::new(RESOURCE, ISSUER, &[]).unwrap(),
    );
    let rest = apl_api::router_with_auth(
        store,
        Authenticator::Jwt(JwtVerifier::from_jwks(ISSUER, "apl-api", jwks).unwrap()),
    );
    let mcp_token = token(&subject, json!({"aud":RESOURCE,"scope":"apl:refunds"}));
    let foreign_token = token(
        &foreign_subject,
        json!({"aud":RESOURCE,"scope":"apl:refunds"}),
    );
    let send = |credential: String, body: Value| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::post("/mcp")
                        .header("host", "governance.example.test")
                        .header("accept", "application/json, text/event-stream")
                        .header("content-type", "application/json")
                        .header("mcp-protocol-version", "2025-11-25")
                        .header("authorization", format!("Bearer {credential}"))
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let json = serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null);
            (status, json)
        }
    };
    let call_tool = |name: &str, arguments: Value| json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}});
    let list = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
    assert_eq!(
        send(token(&subject, json!({})), list.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        send(token(&subject, json!({"aud":RESOURCE})), list.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let (status, tool_list) = send(mcp_token.clone(), list).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tool_list["result"]["tools"].as_array().unwrap().len(), 3);

    let key = Uuid::new_v4().to_string();
    let request = json!({"type":"refund.create","connection_id":scope.connection_id,"resource":{"payment_id":"fake_mcp_payment"},"parameters":{"amount_minor":2500,"currency":"USD"}});
    let submit = call_tool(
        "submit_refund",
        json!({"idempotency_key":key,"request":request}),
    );
    let (status, created) = send(mcp_token.clone(), submit.clone()).await;
    assert_eq!(status, StatusCode::OK);
    let id = created["result"]["structuredContent"]["id"]
        .as_str()
        .expect("MCP action ID");
    assert_eq!(
        send(mcp_token.clone(), submit).await.1["result"]["structuredContent"]["id"],
        id
    );
    let rest_request = Request::post("/v1/actions")
        .header(
            "authorization",
            format!("Bearer {}", token(&subject, json!({}))),
        )
        .header("content-type", "application/json")
        .header("idempotency-key", &key)
        .body(Body::from(request.to_string()))
        .unwrap();
    let rest_response = rest.oneshot(rest_request).await.unwrap();
    assert_eq!(rest_response.status(), StatusCode::ACCEPTED);
    let rest_body: Value = serde_json::from_slice(
        &to_bytes(rest_response.into_body(), 64 * 1024)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(rest_body["id"], id);
    let read = call_tool("get_action", json!({"action_id":id}));
    assert_eq!(
        send(mcp_token.clone(), read.clone()).await.1["result"]["structuredContent"]["id"],
        id
    );
    assert_eq!(
        send(foreign_token.clone(), read).await.1["result"]["isError"],
        true
    );
    let foreign_request = json!({"type":"refund.create","connection_id":foreign.connection_id,"resource":{"payment_id":"fake_foreign"},"parameters":{"amount_minor":2500,"currency":"USD"}});
    assert_eq!(
        send(
            mcp_token.clone(),
            call_tool(
                "submit_refund",
                json!({"idempotency_key":"foreign","request":foreign_request})
            )
        )
        .await
        .1["result"]["isError"],
        true
    );
    let cancel = call_tool("cancel_action", json!({"action_id":id}));
    assert_eq!(
        send(foreign_token, cancel.clone()).await.1["result"]["isError"],
        true
    );
    assert_eq!(
        send(mcp_token.clone(), cancel).await.1["result"]["structuredContent"]["status"],
        "cancelled"
    );
    let read = call_tool("get_action", json!({"action_id":id}));
    let mut throttled = false;
    for _ in 0..60 {
        if send(mcp_token.clone(), read.clone()).await.0 == StatusCode::TOO_MANY_REQUESTS {
            throttled = true;
            break;
        }
    }
    assert!(throttled, "valid calls must hit the per-workload bound");
}

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL with admin role creation privileges"]
async fn encrypted_exports_are_scoped_redacted_and_revocable() {
    use apl_evidence::EvidenceStore;
    let url = std::env::var("TEST_DATABASE_URL").unwrap();
    let pool = PgPool::connect(&url).await.unwrap();
    Store::from_pool(pool.clone()).migrate().await.unwrap();
    sqlx::raw_sql(include_str!("../../../migrations/runtime-roles.sql"))
        .execute(&pool)
        .await
        .unwrap();
    let subject = Uuid::new_v4().to_string();
    let p = seed(&pool, &subject).await;
    let other = seed(&pool, &Uuid::new_v4().to_string()).await;
    let reviewer = Uuid::new_v4();
    sqlx::query("INSERT INTO reviewers(tenant_id,environment_id,reviewer_id) VALUES($1,$2,$3)")
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO reviewer_registry VALUES($1,$2,$3,$4,$5)")
        .bind(ISSUER)
        .bind(&subject)
        .bind(p.tenant_id)
        .bind(p.environment_id)
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    let api = Store::from_pool(runtime_pool(&url, false).await);
    let worker = Store::from_pool(runtime_pool(&url, true).await);
    let request: apl_domain::RefundRequest = serde_json::from_value(json!({"type":"refund.create","connection_id":p.connection_id,
        "resource":{"payment_id":"sensitive_payment_marker"},"parameters":{"amount_minor":2500,"currency":"USD"},
        "metadata":{"transcript":"sensitive_metadata_marker"}})).unwrap();
    let action = api
        .submit(&p, &Uuid::new_v4().to_string(), &request)
        .await
        .unwrap();
    let root = std::env::temp_dir().join(format!("apl-export-{}", Uuid::new_v4()));
    std::fs::create_dir(&root).unwrap();
    let artifacts = std::sync::Arc::new(EvidenceStore::local(&root, "test-key", [7; 32]).unwrap());
    let jwks = include_str!("../../identity/tests/fixtures/jwks.json");
    let app = apl_api::exports::router(
        api.clone(),
        artifacts.clone(),
        Authenticator::Jwt(JwtVerifier::from_jwks(ISSUER, "apl-api", jwks).unwrap()),
        ReviewerAuthenticator::Jwt(
            JwtVerifier::from_jwks(ISSUER, "apl-reviewer", jwks)
                .unwrap()
                .into(),
        ),
    );
    let app = app.merge(apl_api::evidence::router(
        api.clone(),
        Authenticator::Jwt(JwtVerifier::from_jwks(ISSUER, "apl-api", jwks).unwrap()),
        ReviewerAuthenticator::Jwt(
            JwtVerifier::from_jwks(ISSUER, "apl-reviewer", jwks)
                .unwrap()
                .into(),
        ),
    ));
    let app = app.merge(apl_api::operations::router(
        api.clone(),
        Authenticator::Jwt(JwtVerifier::from_jwks(ISSUER, "apl-api", jwks).unwrap()),
        ReviewerAuthenticator::Jwt(
            JwtVerifier::from_jwks(ISSUER, "apl-reviewer", jwks)
                .unwrap()
                .into(),
        ),
    ));
    let reviewer_token = token(&subject, json!({"aud":"apl-reviewer"}));
    let body = json!({"connection_id":p.connection_id,"action_ids":[action.id]});
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/exports",
            &token(&subject, json!({})),
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/exports",
            &reviewer_token,
            Some(body.clone())
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let search_path = format!("/v1/evidence?connection_id={}&limit=1", p.connection_id);
    assert_eq!(
        call(&app, "GET", &search_path, &reviewer_token, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", &search_path, &token(&subject, json!({})), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("INSERT INTO evidence_export_grants(tenant_id,environment_id,reviewer_id,connection_id) VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id).bind(p.environment_id).bind(reviewer).bind(p.connection_id).execute(&pool).await.unwrap();
    assert_eq!(
        call(
            &app,
            "POST",
            "/v1/exports",
            &reviewer_token,
            Some(json!({"connection_id":other.connection_id,"action_ids":[action.id]}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (status, page) = call(&app, "GET", &search_path, &reviewer_token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page["items"][0]["id"], action.id.to_string());
    assert!(page["next_after"].is_null());
    assert!(!page.to_string().contains("sensitive_payment_marker"));
    assert!(!page.to_string().contains("sensitive_metadata_marker"));
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/evidence?connection_id={}", other.connection_id),
            &reviewer_token,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let (_, empty) = call(
        &app,
        "GET",
        &format!("{search_path}&workload_id={}", other.workload_id),
        &reviewer_token,
        None,
    )
    .await;
    assert_eq!(empty["items"], json!([]));
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("{search_path}&status=invalid"),
            &reviewer_token,
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let ops_path = format!("/v1/operations?connection_id={}", p.connection_id);
    assert_eq!(
        call(&app, "GET", &ops_path, &reviewer_token, None).await.0,
        StatusCode::NOT_FOUND,
        "evidence grant is not operations authority"
    );
    sqlx::query("INSERT INTO operations_grants(tenant_id,environment_id,reviewer_id,connection_id) VALUES($1,$2,$3,$4)")
        .bind(p.tenant_id).bind(p.environment_id).bind(reviewer).bind(p.connection_id).execute(&pool).await.unwrap();
    let (status, snapshot) = call(&app, "GET", &ops_path, &reviewer_token, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["connection_id"], p.connection_id.to_string());
    assert_eq!(snapshot["held_minor"], 0);
    assert!(!snapshot.to_string().contains("sensitive_payment_marker"));
    let items_path = format!(
        "/v1/operations/items?connection_id={}&kind=dispatches",
        p.connection_id
    );
    let (items_status, page) = call(&app, "GET", &items_path, &reviewer_token, None).await;
    assert_eq!(items_status, StatusCode::OK);
    assert_eq!(page["connection_id"], p.connection_id.to_string());
    assert_eq!(page["kind"], "dispatches");
    assert!(!page.to_string().contains("sensitive_payment_marker"));
    let preview_path = format!("/v1/actions/{}/reconcile", action.id);
    assert_eq!(
        call(&app, "GET", &preview_path, &reviewer_token, None)
            .await
            .0,
        StatusCode::NOT_FOUND,
        "operations and evidence grants do not imply reconciliation preview authority"
    );
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/operations?connection_id={}", other.connection_id),
            &reviewer_token,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    sqlx::query("UPDATE operations_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(&app, "GET", &ops_path, &reviewer_token, None).await.0,
        StatusCode::NOT_FOUND
    );
    let (status, info) = call(&app, "POST", "/v1/exports", &reviewer_token, Some(body)).await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let id = info["id"].as_str().unwrap();
    assert_ne!(
        call(
            &app,
            "GET",
            &format!("/v1/exports/{id}/download"),
            &reviewer_token,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(apl_worker::tick_export(&worker, artifacts.as_ref())
        .await
        .unwrap());
    let (status, info) = call(
        &app,
        "GET",
        &format!("/v1/exports/{id}"),
        &reviewer_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(info["status"], "ready");
    let (status, data) = call(
        &app,
        "GET",
        &format!("/v1/exports/{id}/download"),
        &reviewer_token,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let text = data.to_string();
    assert!(text.contains(&action.id.to_string()));
    assert!(!text.contains("sensitive_payment_marker"));
    assert!(!text.contains("sensitive_metadata_marker"));
    download_expiry_during_final_audit(&pool, &app, &subject, id).await;
    sqlx::query("UPDATE evidence_export_grants SET enabled=false WHERE reviewer_id=$1")
        .bind(reviewer)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        call(
            &app,
            "GET",
            &format!("/v1/exports/{id}/download"),
            &reviewer_token,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&app, "GET", &search_path, &reviewer_token, None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    // Expiry cleanup operates after auditor revocation and re-sweeps late writes.
    let export_id = Uuid::parse_str(id).unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT ready_generation FROM evidence_exports WHERE id=$1")
            .bind(export_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let scope = apl_evidence::ExportScope {
        tenant_id: p.tenant_id,
        environment_id: p.environment_id,
        export_id,
        generation,
    };
    assert!(artifacts.get(scope).await.is_ok());
    sqlx::query("UPDATE evidence_exports SET expires_at=clock_timestamp()-interval '10 minutes' WHERE id=$1")
        .bind(export_id).execute(&pool).await.unwrap();
    sqlx::query("UPDATE evidence_export_jobs SET expires_at=clock_timestamp()-interval '10 minutes' WHERE id=$1")
        .bind(export_id).execute(&pool).await.unwrap();
    // A reused disposable database can have earlier due sweeps. Drive the
    // global queue rather than assume this export is its next job.
    let cleanup_jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_export_cleanup_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    for _ in 0..=cleanup_jobs {
        if artifacts.get(scope).await.is_err() {
            break;
        }
        assert!(apl_worker::tick_export_cleanup(&worker, artifacts.as_ref())
            .await
            .unwrap());
    }
    assert!(artifacts.get(scope).await.is_err());
    artifacts
        .put(scope, b"synthetic late stale-worker artifact")
        .await
        .unwrap();
    sqlx::query(
        "UPDATE evidence_export_cleanup_jobs SET available_at=clock_timestamp() WHERE id=$1",
    )
    .bind(export_id)
    .execute(&pool)
    .await
    .unwrap();
    // A reused disposable database can have earlier due sweeps. Drive the
    // global queue rather than assume this export is its next job.
    let cleanup_jobs: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_export_cleanup_jobs")
        .fetch_one(&pool)
        .await
        .unwrap();
    for _ in 0..=cleanup_jobs {
        if artifacts.get(scope).await.is_err() {
            break;
        }
        assert!(apl_worker::tick_export_cleanup(&worker, artifacts.as_ref())
            .await
            .unwrap());
    }
    assert!(artifacts.get(scope).await.is_err());
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM evidence_export_audit WHERE export_id=$1 AND event_type='export.artifacts_deleted'")
        .bind(export_id).fetch_one(&pool).await.unwrap();
    assert_eq!(audits, 1);
    std::fs::remove_dir_all(root).unwrap();
}

/// The final authorization/audit transaction may wait even after artifact I/O
/// and the second identity check have completed. A valid token must not become
/// an expired-token download while that transaction is blocked.
async fn download_expiry_during_final_audit(
    pool: &PgPool,
    app: &Router,
    subject: &str,
    export_id: &str,
) {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let export_id = Uuid::parse_str(export_id).unwrap();
    let suffix = Uuid::new_v4().simple().to_string();
    let trigger = format!("test_export_wait_{suffix}");
    let function = format!("test_export_wait_fn_{suffix}");
    let lock_key = Uuid::new_v4().as_u128() as i64;
    // The trigger is scoped to one random export, and never runs in normal code.
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION public.{function}() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock({lock_key}::bigint); RETURN NEW; END $$; \
         CREATE TRIGGER {trigger} BEFORE INSERT ON evidence_export_audit FOR EACH ROW \
         WHEN (NEW.export_id='{export_id}'::uuid AND NEW.event_type='export.downloaded') EXECUTE FUNCTION public.{function}();"
    )).execute(pool).await.unwrap();
    let mut blocker = pool.begin().await.unwrap();
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .unwrap();
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut *blocker)
        .await
        .unwrap();
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 5;
    let short_token = token(subject, json!({"aud":"apl-reviewer","exp":expires_at}));
    let app = app.clone();
    let mut download = tokio::spawn(async move {
        call(
            &app,
            "GET",
            &format!("/v1/exports/{export_id}/download"),
            &short_token,
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND wait_event_type='Lock')"
            ).bind(blocker_pid).fetch_one(pool).await.unwrap();
            if waiting { break; }
            assert!(!download.is_finished(),"download never reached the final database wait");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("final download audit transaction did not wait");
    let deadline = UNIX_EPOCH + Duration::from_secs(expires_at);
    if let Ok(remaining) = deadline.duration_since(SystemTime::now()) {
        tokio::time::sleep(remaining + Duration::from_millis(25)).await;
    }
    assert!(
        !download.is_finished(),
        "audit barrier must remain blocked until expiry"
    );
    blocker.commit().await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), &mut download)
        .await
        .unwrap()
        .unwrap();
    sqlx::raw_sql(&format!(
        "DROP TRIGGER {trigger} ON evidence_export_audit; DROP FUNCTION public.{function}();"
    ))
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        response,
        (
            StatusCode::UNAUTHORIZED,
            json!({"error":{"code":"unauthorized"}})
        ),
        "an expired reviewer token must not receive decrypted export data after a database wait"
    );
}
