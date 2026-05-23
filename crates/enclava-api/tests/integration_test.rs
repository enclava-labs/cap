//! Integration tests for API routes using testcontainers.

use axum::http::StatusCode;
use ed25519_dalek::SigningKey;
use enclava_api::{state::AppState, test_router};
use enclava_common::image::ImageRef;
use enclava_engine::types::AttestationConfig;
use rand::rngs::OsRng;
use serde_json::Value;
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

async fn setup_test_state() -> (AppState, PgPool) {
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
        signing_key,
        hmac_key,
        api_url: "http://localhost:3000".to_string(),
        btcpay_url: "http://localhost:23001".to_string(),
        btcpay_api_key: "test-key".to_string(),
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
        btcpay_webhook_secret: "test-secret".to_string(),
        attestation: Some(AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/attestation-proxy@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-ai/caddy-ingress@sha256:2222222222222222222222222222222222222222222222222222222222222222",
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
    };

    (state, pool)
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
    assert_eq!(me_body["orgs"].as_array().unwrap().len(), 1);
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
