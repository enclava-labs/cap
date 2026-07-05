//! Integration tests for API routes using testcontainers.

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use enclava_api::{
    auth::jwt::issue_session_token,
    state::{AppState, CapManagementMode, InternalAuthConfig},
    test_router,
};
use enclava_common::{
    descriptor::{
        Capabilities, DeploymentDescriptor, EnvVar, OciRuntimeSpec, Port, Resources,
        SecurityContext, Sidecars, SignerIdentity,
    },
    image::ImageRef,
};
use enclava_engine::{manifest::network_policy::generate_network_policy, types::AttestationConfig};
use rand::rngs::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

async fn setup_test_db() -> PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("failed to connect to test db");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations failed");

    pool
}

async fn setup_test_state_with_mode(management_mode: CapManagementMode) -> (AppState, PgPool) {
    let pool = setup_test_db().await;
    let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
    let hmac_key = Arc::new([0u8; 32]); // Test HMAC key
    unsafe {
        std::env::set_var(
            "API_KEY_HMAC_PEPPER",
            "cap-test-api-key-hmac-pepper-with-at-least-32-bytes",
        );
    }

    let state = AppState {
        db: pool.clone(),
        management_mode,
        signing_key,
        hmac_key,
        api_url: "http://localhost:3000".to_string(),
        dashboard_url: Some("https://console.example.test".to_string()),
        platform_domain: "enclava.dev".to_string(),
        tee_domain_suffix: "tee.enclava.dev".to_string(),
        http_client: reqwest::Client::new(),
        registry_client: enclava_api::clients::RegistryClient::new(
            enclava_api::clients::ClientConfig::from_env(),
            enclava_api::clients::AllowList::from_env_or_default(None),
        )
        .unwrap(),
        trustee_http_client: reqwest::Client::new(),
        tee_http_client: reqwest::Client::new(),
        attestation: Some(AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/attestation-proxy@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/caddy-ingress@sha256:2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
            trustee_policy_read_available: false,
            workload_artifacts_url: None,
            tls_certificate_broker_url: None,
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
        }),
        dns: None,
        acme: None,
        kbs_policy: None,
        trustee_attestation_verify_url: None,
        trustee_attestation_verify_bearer_token: None,
        signing_service: None,
        require_customer_signed_policy_artifact: false,
        deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(1)),
        internal_auth: Some(InternalAuthConfig::from_plaintext_tokens(
            &["cap-internal-current", "cap-internal-next"],
            &["spiffe://paas.example.test/enclava-paas"],
        )),
    };

    (state, pool)
}

async fn setup_test_state() -> (AppState, PgPool) {
    setup_test_state_with_mode(CapManagementMode::Standalone).await
}

async fn setup_paas_managed_test_state() -> (AppState, PgPool) {
    setup_test_state_with_mode(CapManagementMode::PaasManaged).await
}

fn add_internal_headers(
    request: axum_test::TestRequest,
    idempotency_key: &str,
) -> axum_test::TestRequest {
    request
        .add_header("authorization", "Bearer cap-internal-current")
        .add_header(
            "x-enclava-internal-client-san",
            "spiffe://paas.example.test/enclava-paas",
        )
        .add_header("idempotency-key", idempotency_key)
}

fn add_internal_actor_headers(
    request: axum_test::TestRequest,
    idempotency_key: &str,
    paas_user_id: &str,
) -> axum_test::TestRequest {
    add_internal_headers(request, idempotency_key)
        .add_header("x-enclava-paas-user-id", paas_user_id)
}

async fn signup_owner(server: &axum_test::TestServer, prefix: &str) -> (String, Uuid) {
    let suffix = Uuid::new_v4().simple().to_string();
    let signup = server
        .post("/auth/signup")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({
            "provider": "email",
            "email": format!("{prefix}-{suffix}@example.test"),
            "password": "correct horse battery staple",
            "display_name": format!("{prefix} Owner"),
        }))
        .await;
    signup.assert_status(StatusCode::CREATED);
    let auth: Value = signup.json();
    let session_token = auth["token"].as_str().expect("session token").to_string();
    let org_id = Uuid::parse_str(auth["org_id"].as_str().expect("org id")).expect("uuid org id");
    (session_token, org_id)
}

fn generic_deployment_body(
    external_id: &str,
    app_name: &str,
    provider: &str,
    repository: &str,
    image: &str,
    subject: &str,
    issuer: &str,
) -> Value {
    serde_json::json!({
        "external_id": external_id,
        "app": {
            "name": app_name,
            "create_if_missing": true,
            "unlock_mode": "auto"
        },
        "source": {
            "provider": provider,
            "repository": repository
        },
        "workload": {
            "image": image,
            "container_name": "app"
        },
        "signing": {
            "subject": subject,
            "issuer": issuer
        }
    })
}

async fn persisted_app_source(pool: &PgPool, org_id: Uuid, app_name: &str) -> (String, String) {
    sqlx::query_as::<_, (String, String)>(
        "SELECT source_provider, source_repository
           FROM apps
          WHERE org_id = $1 AND name = $2",
    )
    .bind(org_id)
    .bind(app_name)
    .fetch_one(pool)
    .await
    .expect("persisted app source")
}

async fn persisted_app_egress(pool: &PgPool, org_id: Uuid, app_name: &str) -> Value {
    sqlx::query_scalar::<_, Value>(
        "SELECT egress_allowlist
           FROM apps
          WHERE org_id = $1 AND name = $2",
    )
    .bind(org_id)
    .bind(app_name)
    .fetch_one(pool)
    .await
    .expect("persisted app egress allowlist")
}

async fn bootstrap_paas_internal_org(
    server: &axum_test::TestServer,
    suffix: &str,
    paas_org_id: &str,
    paas_user_id: &str,
    org_name: &str,
) {
    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("hosted-org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "Hosted Deploy Org",
        "status": "active",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("hosted-member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "Hosted Deploy User",
        "role": "owner",
        "active": true,
        "version": 1,
    }))
    .await
    .assert_status_ok();

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("hosted-entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 1,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await
    .assert_status_ok();
}

fn github_signer_subject() -> &'static str {
    "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main"
}

fn github_signer_issuer() -> &'static str {
    "https://token.actions.githubusercontent.com"
}

fn device_code_hash(code: &str) -> Vec<u8> {
    Sha256::digest(code.as_bytes()).to_vec()
}

#[tokio::test]
async fn health_endpoint_returns_ok() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);

    let server = axum_test::TestServer::builder().http_transport().build(app);

    let response = server
        .get("/health")
        .add_header("x-forwarded-for", "127.0.0.1")
        .await;

    response.assert_status_ok();
    response.assert_text("ok");
}

#[tokio::test]
async fn device_login_approval_issues_cli_session_and_users_me_works() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let (session_token, org_id) = signup_owner(&server, "device-login").await;

    let start = server
        .post("/auth/device/start")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({}))
        .await;
    start.assert_status_ok();
    let start_body: Value = start.json();
    let device_code = start_body["device_code"].as_str().expect("device_code");
    let user_code = start_body["user_code"].as_str().expect("user_code");
    assert!(
        start_body["verification_uri"]
            .as_str()
            .unwrap()
            .contains("/cli/login")
    );

    let pending = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": device_code }))
        .await;
    pending.assert_status_ok();
    let pending_body: Value = pending.json();
    assert_eq!(pending_body["status"], "pending");

    let slow_down = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": device_code }))
        .await;
    slow_down.assert_status_ok();
    let slow_down_body: Value = slow_down.json();
    assert_eq!(slow_down_body["status"], "slow_down");

    let approve = server
        .post("/auth/device/approve")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "user_code": user_code,
            "org_id": org_id,
        }))
        .await;
    approve.assert_status_ok();
    let approve_body: Value = approve.json();
    assert_eq!(approve_body["status"], "approved");
    assert_eq!(approve_body["org_id"], org_id.to_string());

    let approved = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": device_code }))
        .await;
    approved.assert_status_ok();
    let approved_body: Value = approved.json();
    assert_eq!(approved_body["status"], "approved");
    let cli_token = approved_body["auth"]["token"]
        .as_str()
        .expect("approved poll returns session token");

    let me = server
        .get("/users/me")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(cli_token)
        .await;
    me.assert_status_ok();
    let me_body: Value = me.json();
    assert_eq!(me_body["active_org"]["id"], org_id.to_string());
    assert_eq!(me_body["active_org"]["entitlement_class"], "core");
    assert_eq!(me_body["active_org"]["deploy_allowed"], true);
    assert_eq!(me_body["active_org"]["deploy_block_reason"], Value::Null);
    assert_eq!(me_body["orgs"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn device_login_approved_code_is_single_use_and_still_expires() {
    let (state, pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let (session_token, org_id) = signup_owner(&server, "device-login-reuse").await;

    let start = server
        .post("/auth/device/start")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({}))
        .await;
    start.assert_status_ok();
    let start_body: Value = start.json();
    let device_code = start_body["device_code"].as_str().expect("device_code");
    let user_code = start_body["user_code"].as_str().expect("user_code");

    let approve = server
        .post("/auth/device/approve")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "user_code": user_code,
            "org_id": org_id,
        }))
        .await;
    approve.assert_status_ok();

    let first_poll = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": device_code }))
        .await;
    first_poll.assert_status_ok();
    let first_body: Value = first_poll.json();
    assert_eq!(first_body["status"], "approved");
    assert!(first_body["auth"]["token"].is_string());

    let second_poll = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": device_code }))
        .await;
    second_poll.assert_status_ok();
    let second_body: Value = second_poll.json();
    assert_eq!(second_body["status"], "expired");
    assert_eq!(second_body["auth"], Value::Null);

    let expired_start = server
        .post("/auth/device/start")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({}))
        .await;
    expired_start.assert_status_ok();
    let expired_start_body: Value = expired_start.json();
    let expired_device_code = expired_start_body["device_code"]
        .as_str()
        .expect("expired device_code");
    let expired_user_code = expired_start_body["user_code"]
        .as_str()
        .expect("expired user_code");

    let approve_expired = server
        .post("/auth/device/approve")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "user_code": expired_user_code,
            "org_id": org_id,
        }))
        .await;
    approve_expired.assert_status_ok();

    sqlx::query("UPDATE device_login_sessions SET expires_at = $1 WHERE device_code_hash = $2")
        .bind(Utc::now() - Duration::minutes(1))
        .bind(device_code_hash(expired_device_code))
        .execute(&pool)
        .await
        .expect("expire approved device code");

    let expired_poll = server
        .post("/auth/device/poll")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({ "device_code": expired_device_code }))
        .await;
    expired_poll.assert_status_ok();
    let expired_body: Value = expired_poll.json();
    assert_eq!(expired_body["status"], "expired");
    assert_eq!(expired_body["auth"], Value::Null);
}

#[tokio::test]
async fn paas_internal_org_member_and_entitlement_sync_are_idempotent() {
    let (state, pool) = setup_paas_managed_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("paas-{}", &suffix[..16]);

    let missing_san = server
        .put(&format!("/internal/paas/orgs/{paas_org_id}"))
        .add_header("authorization", "Bearer cap-internal-current")
        .add_header("idempotency-key", format!("org-missing-san-{suffix}"))
        .json(&serde_json::json!({
            "name": org_name,
            "display_name": "PaaS Managed",
            "status": "active",
        }))
        .await;
    missing_san.assert_status(StatusCode::UNAUTHORIZED);

    let create_org = add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "PaaS Managed",
        "status": "active",
    }))
    .await;
    create_org.assert_status(StatusCode::CREATED);
    let created_body: Value = create_org.json();
    let cap_org_id =
        Uuid::parse_str(created_body["cap_org_id"].as_str().expect("cap org id")).unwrap();
    assert_eq!(created_body["paas_org_id"], paas_org_id);

    let replay = add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "PaaS Managed",
        "status": "active",
    }))
    .await;
    replay.assert_status(StatusCode::CREATED);
    let replay_body: Value = replay.json();
    assert_eq!(replay_body["cap_org_id"], cap_org_id.to_string());

    let mismatch = add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": format!("paas-different-{}", &suffix[..8]),
        "display_name": "PaaS Managed",
        "status": "active",
    }))
    .await;
    mismatch.assert_status(StatusCode::CONFLICT);
    let mismatch_body: Value = mismatch.json();
    assert_eq!(mismatch_body["error"], "idempotency_key_reused");

    let sync_member = add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "PaaS User",
        "role": "owner",
        "active": true,
        "version": 7,
    }))
    .await;
    sync_member.assert_status_ok();
    let member_body: Value = sync_member.json();
    let cap_user_id =
        Uuid::parse_str(member_body["cap_user_id"].as_str().expect("cap user id")).unwrap();
    assert_eq!(member_body["role"], "owner");

    let sync_entitlement = add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 3,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await;
    sync_entitlement.assert_status_ok();

    let management: (String, String) =
        sqlx::query_as("SELECT mode, status FROM organization_management WHERE org_id = $1")
            .bind(cap_org_id)
            .fetch_one(&pool)
            .await
            .expect("organization management row");
    assert_eq!(
        management,
        ("paas_managed".to_string(), "active".to_string())
    );

    let member: (String, Option<chrono::DateTime<Utc>>) = sqlx::query_as(
        "SELECT role::text, removed_at FROM memberships WHERE org_id = $1 AND user_id = $2",
    )
    .bind(cap_org_id)
    .bind(cap_user_id)
    .fetch_one(&pool)
    .await
    .expect("synced membership");
    assert_eq!(member.0, "owner");
    assert_eq!(member.1, None);

    let entitlement: (i64, bool, Value) = sqlx::query_as(
        "SELECT version, deploy_allowed, limits FROM organization_entitlements WHERE org_id = $1",
    )
    .bind(cap_org_id)
    .fetch_one(&pool)
    .await
    .expect("synced entitlement");
    assert_eq!(entitlement.0, 3);
    assert!(entitlement.1);
    assert_eq!(entitlement.2["max_apps"], 2);
}

#[tokio::test]
async fn standalone_cap_does_not_mount_paas_internal_routes() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);

    let response = add_internal_headers(
        server.put("/internal/paas/orgs/standalone-route-check"),
        "standalone-route-check",
    )
    .json(&serde_json::json!({
        "name": "standalone-route-check",
        "display_name": "Standalone Route Check",
        "status": "active",
    }))
    .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn paas_managed_orgs_fail_closed_and_block_public_writes() {
    let (state, pool) = setup_paas_managed_test_state().await;
    let hmac_key = state.hmac_key.clone();
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("guard-{}", &suffix[..16]);

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("guard-org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "Guarded Org",
        "status": "active",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("guard-member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "Guarded User",
        "role": "owner",
        "active": true,
        "version": 1,
    }))
    .await
    .assert_status_ok();

    let cap_user_id: Uuid = sqlx::query_scalar(
        "SELECT cap_id FROM paas_external_mappings WHERE resource_type = 'user' AND paas_external_id = $1",
    )
    .bind(&paas_user_id)
    .fetch_one(&pool)
    .await
    .expect("cap user mapping");
    let session_token = issue_session_token(&hmac_key, cap_user_id).expect("session token");

    let missing_entitlement = server
        .get("/users/me")
        .add_header("x-forwarded-for", "127.0.0.1")
        .add_header("x-enclava-org", &org_name)
        .authorization_bearer(&session_token)
        .await;
    missing_entitlement.assert_status_ok();
    let missing_body: Value = missing_entitlement.json();
    assert_eq!(missing_body["active_org"]["deploy_allowed"], false);
    assert_eq!(
        missing_body["active_org"]["deploy_block_reason"],
        "paas_managed_entitlement_missing"
    );

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("guard-entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 1,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await
    .assert_status_ok();

    let entitled = server
        .get("/users/me")
        .add_header("x-forwarded-for", "127.0.0.1")
        .add_header("x-enclava-org", &org_name)
        .authorization_bearer(&session_token)
        .await;
    entitled.assert_status_ok();
    let entitled_body: Value = entitled.json();
    assert_eq!(entitled_body["active_org"]["deploy_allowed"], true);
    assert_eq!(
        entitled_body["active_org"]["deploy_block_reason"],
        Value::Null
    );

    let public_create = server
        .post("/apps")
        .add_header("x-forwarded-for", "127.0.0.1")
        .add_header("x-enclava-org", &org_name)
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "name": format!("blocked-{}", &suffix[..8]),
            "unlock_mode": "auto",
        }))
        .await;
    public_create.assert_status(StatusCode::FORBIDDEN);
    let public_body: Value = public_create.json();
    assert_eq!(public_body["error"], "paas_managed_instance");
}

#[tokio::test]
async fn paas_internal_domain_challenge_does_not_reenter_public_write_guard() {
    let (state, _pool) = setup_paas_managed_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("domain-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);
    let domain = format!("dashboard-{}.example.com", &suffix[..12]);

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("domain-org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "Domain Bridge Org",
        "status": "active",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("domain-member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "Domain Bridge User",
        "role": "owner",
        "active": true,
        "version": 1,
    }))
    .await
    .assert_status_ok();

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("domain-entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 1,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await
    .assert_status_ok();

    add_internal_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/apps")),
        &format!("domain-app-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": app_name,
        "unlock_mode": "auto",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let challenge = add_internal_actor_headers(
        server.post(&format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains"
        )),
        &format!("domain-challenge-{suffix}"),
        &paas_user_id,
    )
    .json(&serde_json::json!({ "domain": domain }))
    .await;
    challenge.assert_status_ok();
    let challenge_body: Value = challenge.json();
    assert_eq!(challenge_body["domain"], domain);
    assert!(
        challenge_body["txt_record_value"]
            .as_str()
            .is_some_and(|value| value.starts_with("enclava-domain-verification="))
    );
}

#[tokio::test]
async fn paas_internal_config_sync_bypasses_public_paas_managed_write_guard() {
    let (state, pool) = setup_paas_managed_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("cfg-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("config-org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "Config Sync Org",
        "status": "active",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("config-member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "Config Sync User",
        "role": "owner",
        "active": true,
        "version": 1,
    }))
    .await
    .assert_status_ok();

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("config-entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 1,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await
    .assert_status_ok();

    let create_app = add_internal_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/apps")),
        &format!("config-app-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": app_name,
        "unlock_mode": "auto",
    }))
    .await;
    create_app.assert_status(StatusCode::CREATED);
    let create_app_body: Value = create_app.json();
    let cap_app_id =
        Uuid::parse_str(create_app_body["cap_app_id"].as_str().expect("cap app id")).unwrap();

    let sync = add_internal_actor_headers(
        server.post(&format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/sync"
        )),
        &format!("config-sync-{suffix}"),
        &paas_user_id,
    )
    .json(&serde_json::json!({
        "key_name": "SMOKE_SECRET",
    }))
    .await;
    sync.assert_status_ok();
    let sync_body: Value = sync.json();
    assert_eq!(sync_body["status"], "synced");

    let key: String = sqlx::query_scalar("SELECT key_name FROM config_metadata WHERE app_id = $1")
        .bind(cap_app_id)
        .fetch_one(&pool)
        .await
        .expect("config metadata row");
    assert_eq!(key, "SMOKE_SECRET");

    let delete = add_internal_actor_headers(
        server.delete(&format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/SMOKE_SECRET/meta"
        )),
        &format!("config-delete-{suffix}"),
        &paas_user_id,
    )
    .json(&serde_json::json!({}))
    .await;
    delete.assert_status(StatusCode::NO_CONTENT);

    let remaining: Option<String> =
        sqlx::query_scalar("SELECT key_name FROM config_metadata WHERE app_id = $1")
            .bind(cap_app_id)
            .fetch_optional(&pool)
            .await
            .expect("config metadata lookup after delete");
    assert_eq!(remaining, None);
}

#[tokio::test]
async fn paas_internal_create_app_persists_cli_signer_identity() {
    let (state, pool) = setup_paas_managed_test_state().await;
    let attestation = state.attestation.clone().expect("test attestation config");
    let api_signing_pubkey = enclava_api::auth::jwt::public_key_base64(&state.signing_key);
    let api_url = state.api_url.clone();
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("pins-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);

    bootstrap_paas_internal_org(&server, &suffix, &paas_org_id, &paas_user_id, &org_name).await;

    let create = add_internal_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/apps")),
        &format!("hosted-app-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": app_name,
        "unlock_mode": "password",
        "bootstrap_pubkey_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "signer_identity_subject": github_signer_subject(),
        "signer_identity_issuer": github_signer_issuer(),
        "egress_allowlist": [
            { "host": "relay.enclava.me", "ports": [20000] },
            { "host": "rekor.sigstore.dev" }
        ],
    }))
    .await;
    create.assert_status(StatusCode::CREATED);
    let create_body: Value = create.json();

    let pinned: (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Value,
    ) = sqlx::query_as(
        "SELECT namespace,
                  instance_id,
                  service_account,
                  bootstrap_owner_pubkey_hash,
                  tenant_instance_identity_hash,
                  signer_identity_subject,
                  signer_identity_issuer,
                  egress_allowlist
           FROM apps
          WHERE name = $1",
    )
    .bind(&app_name)
    .fetch_one(&pool)
    .await
    .expect("app signer pins");
    assert_eq!(pinned.5.as_deref(), Some(github_signer_subject()));
    assert_eq!(pinned.6.as_deref(), Some(github_signer_issuer()));
    assert_eq!(create_body["namespace"], pinned.0);
    assert_eq!(create_body["instance_id"], pinned.1);
    assert_eq!(create_body["service_account"], pinned.2);
    assert_eq!(create_body["bootstrap_owner_pubkey_hash"], pinned.3);
    assert_eq!(create_body["tenant_instance_identity_hash"], pinned.4);
    assert_eq!(
        pinned.7,
        serde_json::json!([
            { "host": "relay.enclava.me", "ports": [20000] },
            { "host": "rekor.sigstore.dev", "ports": [443] }
        ])
    );

    let cap_app_id =
        Uuid::parse_str(create_body["cap_app_id"].as_str().expect("cap app id")).unwrap();
    sqlx::query(
        "INSERT INTO app_containers (id, app_id, name, image_ref, image_digest, port, is_primary)
         VALUES ($1, $2, 'web', $3, $4, 8080, true)",
    )
    .bind(Uuid::new_v4())
    .bind(cap_app_id)
    .bind("ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .execute(&pool)
    .await
    .expect("insert test app container");
    let persisted_app: enclava_api::models::App =
        sqlx::query_as("SELECT * FROM apps WHERE id = $1")
            .bind(cap_app_id)
            .fetch_one(&pool)
            .await
            .expect("persisted app");
    let app_spec = enclava_api::deploy::build_confidential_app(
        &pool,
        &persisted_app,
        &attestation,
        &api_signing_pubkey,
        &api_url,
    )
    .await
    .expect("confidential app spec");
    let network_policy = generate_network_policy(&app_spec);
    let egress = network_policy["spec"]["egress"]
        .as_array()
        .expect("egress array");
    let relay_rule = egress
        .iter()
        .find(|rule| rule["toFQDNs"][0]["matchName"].as_str() == Some("relay.enclava.me"))
        .expect("relay egress rule");
    assert_eq!(relay_rule["toPorts"][0]["ports"][0]["port"], "20000");
}

#[tokio::test]
async fn paas_internal_deploy_reuses_signed_deploy_gate() {
    let (mut state, pool) = setup_paas_managed_test_state().await;
    state.require_customer_signed_policy_artifact = true;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("deploy-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);

    bootstrap_paas_internal_org(&server, &suffix, &paas_org_id, &paas_user_id, &org_name).await;

    add_internal_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/apps")),
        &format!("hosted-deploy-app-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": app_name,
        "unlock_mode": "password",
        "bootstrap_pubkey_hash": "1111111111111111111111111111111111111111111111111111111111111111",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    sqlx::query(
        "UPDATE apps
            SET signer_identity_subject = $1,
                signer_identity_issuer = $2,
                signer_identity_set_at = now()
          WHERE name = $3",
    )
    .bind(github_signer_subject())
    .bind(github_signer_issuer())
    .bind(&app_name)
    .execute(&pool)
    .await
    .expect("set signer pins");

    let response = add_internal_actor_headers(
        server.post(&format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/deploy"
        )),
        &format!("hosted-deploy-{suffix}"),
        &paas_user_id,
    )
    .json(&serde_json::json!({
        "image": "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    }))
    .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("signed policy deployments require"),
        "unexpected response body: {body}"
    );
}

#[tokio::test]
async fn paas_internal_agent_policy_route_reaches_cap_policy_broker() {
    let (state, pool) = setup_paas_managed_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("policy-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);

    bootstrap_paas_internal_org(&server, &suffix, &paas_org_id, &paas_user_id, &org_name).await;

    add_internal_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/apps")),
        &format!("hosted-policy-app-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": app_name,
        "unlock_mode": "password",
        "bootstrap_pubkey_hash": "1111111111111111111111111111111111111111111111111111111111111111",
        "signer_identity_subject": github_signer_subject(),
        "signer_identity_issuer": github_signer_issuer(),
    }))
    .await
    .assert_status(StatusCode::CREATED);

    let (
        cap_org_id,
        org_slug,
        cap_app_id,
        domain,
        tee_domain,
        namespace,
        service_account,
        identity_hash_hex,
    ): (
        Uuid,
        String,
        Uuid,
        String,
        Option<String>,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT o.id,
                o.cust_slug,
                a.id,
                a.domain,
                a.tee_domain,
                a.namespace,
                a.service_account,
                a.tenant_instance_identity_hash
           FROM apps a
           JOIN organizations o ON o.id = a.org_id
          WHERE a.name = $1",
    )
    .bind(&app_name)
    .fetch_one(&pool)
    .await
    .expect("app descriptor inputs");
    let identity_hash: [u8; 32] = hex::decode(identity_hash_hex)
        .expect("decode identity hash")
        .try_into()
        .expect("identity hash length");
    let descriptor = DeploymentDescriptor {
        schema_version: "v1".to_string(),
        org_id: cap_org_id,
        org_slug,
        app_id: cap_app_id,
        app_name: app_name.clone(),
        deploy_id: Uuid::new_v4(),
        created_at: Utc::now(),
        nonce: [7; 32],
        app_domain: domain,
        tee_domain: tee_domain.expect("tee domain"),
        custom_domains: vec![],
        namespace,
        service_account,
        identity_hash,
        image_ref: "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        signer_identity: SignerIdentity {
            subject: github_signer_subject().to_string(),
            issuer: github_signer_issuer().to_string(),
        },
        oci_runtime_spec: OciRuntimeSpec {
            command: vec![],
            args: vec!["/usr/local/bin/app".to_string()],
            env: vec![EnvVar {
                name: "RUST_LOG".to_string(),
                value: "info".to_string(),
            }],
            ports: vec![Port {
                container_port: 8000,
                protocol: "TCP".to_string(),
            }],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        },
        sidecars: Sidecars {
            attestation_proxy_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            caddy_digest:
                "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
        },
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        expected_firmware_measurement: [3; 32],
        expected_runtime_class: "kata-qemu-snp".to_string(),
        kbs_resource_path: format!("default/{app_name}-owner"),
        unlock_mode: "password".to_string(),
        policy_template_id: "enclava-kbs-policy-v1".to_string(),
        policy_template_sha256: [4; 32],
        platform_release_version: "cap-test".to_string(),
        expected_agent_policy_hash: [5; 32],
        expected_cc_init_data_hash: [6; 32],
        expected_kbs_policy_hash: [7; 32],
    };

    let response = add_internal_actor_headers(
        server.post(&format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/agent-policy"
        )),
        &format!("hosted-agent-policy-{suffix}"),
        &paas_user_id,
    )
    .json(&serde_json::json!({ "descriptor": descriptor }))
    .await;

    response.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let body: Value = response.json();
    assert_eq!(body["error"], "platform signing service is not configured");
}

#[tokio::test]
async fn paas_internal_generic_deployment_uses_synced_entitlement_and_signer_preconditions() {
    let (mut state, pool) = setup_paas_managed_test_state().await;
    state.require_customer_signed_policy_artifact = true;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    let org_name = format!("generic-{}", &suffix[..16]);
    let app_name = format!("app-{}", &suffix[..12]);
    let external_id = format!("deploy-{suffix}");

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}")),
        &format!("generic-org-create-{suffix}"),
    )
    .json(&serde_json::json!({
        "name": org_name,
        "display_name": "Generic Deploy Org",
        "status": "active",
    }))
    .await
    .assert_status(StatusCode::CREATED);

    add_internal_headers(
        server.put(&format!(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        )),
        &format!("generic-member-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "display_name": "Generic Deploy User",
        "role": "owner",
        "active": true,
        "version": 1,
    }))
    .await
    .assert_status_ok();

    add_internal_headers(
        server.put(&format!("/internal/paas/orgs/{paas_org_id}/entitlements")),
        &format!("generic-entitlement-sync-{suffix}"),
    )
    .json(&serde_json::json!({
        "version": 1,
        "deploy_allowed": true,
        "block_reason": null,
        "limits": {
            "name": "starter",
            "max_apps": 2,
            "max_cpu": "2",
            "max_memory": "4Gi",
            "max_storage": "20Gi"
        }
    }))
    .await
    .assert_status_ok();

    let mut deploy_body = generic_deployment_body(
        &external_id,
        &app_name,
        "github",
        "acme/confidential-app",
        "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    );
    deploy_body["app"]["egress_allowlist"] = serde_json::json!([
        { "host": "relay.enclava.me", "ports": [20000] }
    ]);

    let response = add_internal_actor_headers(
        server.post(&format!("/internal/paas/orgs/{paas_org_id}/deployments")),
        &format!("generic-deploy-{suffix}"),
        &paas_user_id,
    )
    .json(&deploy_body)
    .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("signed policy deployments require"),
        "unexpected response body: {body}"
    );

    let cap_org_id: Uuid = sqlx::query_scalar(
        "SELECT cap_id FROM paas_external_mappings WHERE resource_type = 'organization' AND paas_external_id = $1",
    )
    .bind(&paas_org_id)
    .fetch_one(&pool)
    .await
    .expect("cap org mapping");
    assert_eq!(
        persisted_app_source(&pool, cap_org_id, &app_name).await,
        ("github".to_string(), "acme/confidential-app".to_string())
    );
    assert_eq!(
        persisted_app_egress(&pool, cap_org_id, &app_name).await,
        serde_json::json!([{ "host": "relay.enclava.me", "ports": [20000] }])
    );
}

#[tokio::test]
async fn app_logs_fail_closed_until_encrypted_streaming_exists() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let app_name = format!("logs-{}", &suffix[..12]);
    let (session_token, _org_id) = signup_owner(&server, "logs-unavailable").await;

    let create = server
        .post("/apps")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "name": app_name,
            "unlock_mode": "auto",
            "signer_identity_subject": "repo:enclava/logs:ref:refs/heads/main",
            "signer_identity_issuer": "https://token.actions.githubusercontent.com"
        }))
        .await;
    create.assert_status(StatusCode::CREATED);

    let logs = server
        .get(&format!("/apps/{app_name}/logs"))
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .await;
    logs.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(logs.headers()["cache-control"], "no-store");
    let body: Value = logs.json();
    assert_eq!(body["error"], "encrypted_logs_required");
    assert_eq!(body["code"], "encrypted_logs_required");
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("encrypted log streaming is required")
    );
    assert_eq!(body["status"], "creating");
}

#[tokio::test]
async fn custom_domain_verified_challenge_cannot_replay_after_expiry() {
    let (state, pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let app_name = format!("domain-{}", &suffix[..12]);
    let domain = format!("stale-{}.example.com", &suffix[..12]);
    let (session_token, _org_id) = signup_owner(&server, "domain-replay").await;

    let create = server
        .post("/apps")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&serde_json::json!({
            "name": app_name,
            "unlock_mode": "auto",
        }))
        .await;
    create.assert_status(StatusCode::CREATED);
    let create_body: Value = create.json();
    let app_id = Uuid::parse_str(create_body["id"].as_str().expect("app id")).unwrap();

    sqlx::query(
        "INSERT INTO custom_domain_challenges (
             id, app_id, domain, challenge_token, expires_at, verified_at
         )
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(Uuid::new_v4())
    .bind(app_id)
    .bind(&domain)
    .bind("historically-valid-token")
    .bind(Utc::now() - Duration::hours(1))
    .bind(Utc::now() - Duration::hours(2))
    .execute(&pool)
    .await
    .expect("insert stale verified domain challenge");

    let verify = server
        .post(&format!("/apps/{app_name}/domains/{domain}/verify"))
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .await;
    verify.assert_status(StatusCode::CONFLICT);
    let body: Value = verify.json();
    assert_eq!(body["error"], "challenge has expired");

    let custom_domain: Option<String> =
        sqlx::query_scalar("SELECT custom_domain FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("load app custom domain");
    assert_eq!(custom_domain, None);

    let tracked_dns: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM dns_records WHERE app_id = $1 AND hostname = $2")
            .bind(app_id)
            .bind(&domain)
            .fetch_optional(&pool)
            .await
            .expect("load tracked custom DNS row");
    assert_eq!(tracked_dns, None);
}

#[tokio::test]
async fn generic_github_deployment_validates_and_reaches_strict_deploy_gate() {
    let (mut state, pool) = setup_test_state().await;
    state.require_customer_signed_policy_artifact = true;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let app_name = format!("github-{}", &suffix[..12]);
    let external_id = format!("deploy-{suffix}");
    let (session_token, org_id) = signup_owner(&server, "generic-github").await;

    let response = server
        .post("/deployments")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&generic_deployment_body(
            &external_id,
            &app_name,
            "github",
            "acme/confidential-app",
            "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        ))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("signed policy deployments require"),
        "unexpected response body: {body}"
    );
    assert_eq!(
        persisted_app_source(&pool, org_id, &app_name).await,
        ("github".to_string(), "acme/confidential-app".to_string())
    );
}

#[tokio::test]
async fn generic_gitlab_deployment_validates_and_reaches_strict_deploy_gate() {
    let (mut state, pool) = setup_test_state().await;
    state.require_customer_signed_policy_artifact = true;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let app_name = format!("gitlab-{}", &suffix[..12]);
    let external_id = format!("deploy-{suffix}");
    let (session_token, org_id) = signup_owner(&server, "generic-gitlab").await;

    let response = server
        .post("/deployments")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&generic_deployment_body(
            &external_id,
            &app_name,
            "gitlab",
            "acme/platform/confidential-app",
            "registry.gitlab.com/acme/platform/confidential-app/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://gitlab.com/acme/platform/confidential-app/-/blob/main/.gitlab-ci.yml@refs/heads/main",
            "https://gitlab.com",
        ))
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("signed policy deployments require"),
        "unexpected response body: {body}"
    );
    assert_eq!(
        persisted_app_source(&pool, org_id, &app_name).await,
        (
            "gitlab".to_string(),
            "acme/platform/confidential-app".to_string()
        )
    );
}

#[tokio::test]
async fn generic_deployment_external_id_is_idempotent_and_conflict_checked() {
    let (state, pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();
    let app_name = format!("idem-{}", &suffix[..12]);
    let external_id = format!("deploy-{suffix}");
    let (session_token, org_id) = signup_owner(&server, "generic-idem").await;
    let app_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let image = "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let subject =
        "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main";
    let issuer = "https://token.actions.githubusercontent.com";

    sqlx::query(
        "INSERT INTO apps (
            id, org_id, name, namespace, instance_id, tenant_id, service_account,
            bootstrap_owner_pubkey_hash, tenant_instance_identity_hash, unlock_mode,
            domain, tee_domain, signer_identity_subject, signer_identity_issuer,
            signer_identity_set_at, source_provider, source_repository
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'auto'::unlock_enum, $10, $11, $12, $13, now(), $14, $15)",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(&app_name)
    .bind(format!("cap-{app_name}"))
    .bind(format!("tenant-{}", &suffix[..12]))
    .bind("test")
    .bind(format!("cap-{app_name}-sa"))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("{app_name}.enclava.dev"))
    .bind(format!("{app_name}.tee.enclava.dev"))
    .bind(subject)
    .bind(issuer)
    .bind("github")
    .bind("acme/confidential-app")
    .execute(&pool)
    .await
    .expect("insert idempotency app");

    sqlx::query(
        "INSERT INTO deployments (
            id, org_id, app_id, trigger, status, spec_snapshot, image_digest,
            cosign_verified, external_id, source_provider, source_repository
         )
         VALUES ($1, $2, $3, 'api'::trigger_enum, 'pending'::deploy_status_enum, $4, $5, true, $6, $7, $8)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(app_id)
    .bind(serde_json::json!({
        "app_name": app_name,
        "namespace": format!("cap-{app_name}"),
        "instance_id": format!("tenant-{}", &suffix[..12]),
        "image": image,
        "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "container_name": "app",
        "resources": null,
        "external_id": external_id,
        "source_provider": "github",
        "source_repository": "acme/confidential-app",
    }))
    .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind(&external_id)
    .bind("github")
    .bind("acme/confidential-app")
    .execute(&pool)
    .await
    .expect("insert idempotency deployment");

    let retry = server
        .post("/deployments")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&generic_deployment_body(
            &external_id,
            &app_name,
            "github",
            "acme/confidential-app",
            image,
            subject,
            issuer,
        ))
        .await;
    retry.assert_status_ok();
    let retry_body: Value = retry.json();
    let expected_deployment_id = deployment_id.to_string();
    assert_eq!(
        retry_body["deployment_id"].as_str(),
        Some(expected_deployment_id.as_str())
    );

    let conflict = server
        .post("/deployments")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(&session_token)
        .json(&generic_deployment_body(
            &external_id,
            "different-app",
            "github",
            "acme/confidential-app",
            image,
            subject,
            issuer,
        ))
        .await;
    conflict.assert_status(StatusCode::CONFLICT);
    let conflict_body: Value = conflict.json();
    assert_eq!(
        conflict_body["error"].as_str(),
        Some("external_id already exists with different app.name")
    );
}

#[tokio::test]
async fn api_key_creation_cannot_escalate_scopes_end_to_end() {
    let (state, _pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();

    let signup = server
        .post("/auth/signup")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({
            "provider": "email",
            "email": format!("api-key-owner-{suffix}@example.test"),
            "password": "correct horse battery staple",
            "display_name": format!("Owner {suffix}"),
        }))
        .await;
    signup.assert_status(StatusCode::CREATED);
    let auth: Value = signup.json();
    let session_token = auth["token"].as_str().expect("session token");

    let limited_key = server
        .post("/auth/api-keys")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(session_token)
        .json(&serde_json::json!({
            "name": "read-admin",
            "scopes": ["org:admin", "apps:read"],
        }))
        .await;
    limited_key.assert_status(StatusCode::CREATED);
    let limited_key_body: Value = limited_key.json();
    let raw_limited_key = limited_key_body["raw_key"].as_str().expect("raw API key");

    let escalation = server
        .post("/auth/api-keys")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(raw_limited_key)
        .json(&serde_json::json!({
            "name": "write-key",
            "scopes": ["apps:write"],
        }))
        .await;
    escalation.assert_status(StatusCode::FORBIDDEN);

    let same_scope = server
        .post("/auth/api-keys")
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(raw_limited_key)
        .json(&serde_json::json!({
            "name": "read-child",
            "scopes": ["apps:read"],
        }))
        .await;
    same_scope.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn signer_rotation_token_rotates_signer_end_to_end() {
    let (state, pool) = setup_test_state().await;
    let app = test_router(state);
    let server = axum_test::TestServer::builder().http_transport().build(app);
    let suffix = Uuid::new_v4().simple().to_string();

    let signup = server
        .post("/auth/signup")
        .add_header("x-forwarded-for", "127.0.0.1")
        .json(&serde_json::json!({
            "provider": "email",
            "email": format!("signer-owner-{suffix}@example.test"),
            "password": "correct horse battery staple",
            "display_name": format!("Signer {suffix}"),
        }))
        .await;
    signup.assert_status(StatusCode::CREATED);
    let auth: Value = signup.json();
    let session_token = auth["token"].as_str().expect("session token");
    let org_id = Uuid::parse_str(auth["org_id"].as_str().expect("org id")).expect("uuid org id");

    let app_id = Uuid::new_v4();
    let app_name = format!("signer-{suffix}");
    let previous_subject = format!("repo:enclava/{suffix}:ref:refs/heads/main");
    let previous_issuer = "https://token.actions.githubusercontent.com";
    sqlx::query(
        "INSERT INTO apps (
            id, org_id, name, namespace, instance_id, tenant_id, service_account,
            bootstrap_owner_pubkey_hash, tenant_instance_identity_hash, unlock_mode,
            domain, tee_domain, signer_identity_subject, signer_identity_issuer, signer_identity_set_at
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::unlock_enum, $11, $12, $13, $14, now())",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(&app_name)
    .bind(format!("cap-test-{suffix}"))
    .bind(format!("tenant-{suffix}"))
    .bind(format!("tenant-{suffix}"))
    .bind(format!("sa-{suffix}"))
    .bind("bootstrap-hash")
    .bind("identity-hash")
    .bind("password")
    .bind(format!("{app_name}.enclava.dev"))
    .bind(format!("{app_name}.tee.enclava.dev"))
    .bind(&previous_subject)
    .bind(previous_issuer)
    .execute(&pool)
    .await
    .expect("insert signer app");

    let new_subject = format!("repo:enclava/{suffix}:ref:refs/heads/release");
    let issued = server
        .post(&format!("/apps/{app_name}/signer/rotation-token"))
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(session_token)
        .json(&serde_json::json!({
            "subject": new_subject,
            "issuer": previous_issuer,
        }))
        .await;
    issued.assert_status_ok();
    let issued_body: Value = issued.json();
    let confirmation_token = issued_body["token"]
        .as_str()
        .expect("signer rotation token");

    let invalid_rotation = server
        .patch(&format!("/apps/{app_name}/signer"))
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(session_token)
        .json(&serde_json::json!({
            "subject": new_subject,
            "issuer": previous_issuer,
            "email_confirmation_token": "tok-123",
        }))
        .await;
    invalid_rotation.assert_status(StatusCode::FORBIDDEN);

    let rotation = server
        .patch(&format!("/apps/{app_name}/signer"))
        .add_header("x-forwarded-for", "127.0.0.1")
        .authorization_bearer(session_token)
        .json(&serde_json::json!({
            "subject": new_subject,
            "issuer": previous_issuer,
            "email_confirmation_token": confirmation_token,
        }))
        .await;
    rotation.assert_status_ok();
    let rotated: Value = rotation.json();
    assert_eq!(
        rotated["signer_identity_subject"].as_str(),
        Some(new_subject.as_str())
    );
    assert_eq!(
        rotated["signer_identity_issuer"].as_str(),
        Some(previous_issuer)
    );
}
