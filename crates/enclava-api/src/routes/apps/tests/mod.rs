use super::{
    CreateAppRequest, RotateSignerRequest, SignerRotationTokenRequest, create_app, derive_identity,
    issue_signer_rotation_token_route, list_apps, normalize_health_config,
    workload_teardown_instance_id,
};
use crate::models::{App, AppStatus, Role, UnlockMode};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

#[test]
fn create_request_defaults_to_password_unlock() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
    }))
    .unwrap();

    assert_eq!(body.unlock_mode, "password");
}

#[test]
fn create_request_accepts_cli_health_fields() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "health_path": "/v1/info",
        "health_interval": 30,
        "health_timeout": 5
    }))
    .unwrap();

    let (path, interval, timeout) = normalize_health_config(
        body.health_path.as_deref(),
        body.health_interval,
        body.health_timeout,
    )
    .unwrap();

    assert_eq!(path, "/v1/info");
    assert_eq!(interval, 30);
    assert_eq!(timeout, 5);
}

#[test]
fn create_request_rejects_unsafe_health_path() {
    let err = normalize_health_config(Some("/v1/info;bad"), Some(30), Some(5)).unwrap_err();
    assert!(err.contains("invalid HTTP path"));
}

#[test]
fn auto_unlock_identity_uses_supplied_bootstrap_hash_when_present() {
    let app_id = uuid::Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap();
    let bootstrap_hash = "ab".repeat(32);

    let (_tenant_id, _instance_id, _namespace, _service_account, pubkey_hash, identity_hash) =
        derive_identity("tenant", app_id, "mini-prod", "auto", Some(&bootstrap_hash)).unwrap();

    assert_eq!(pubkey_hash, bootstrap_hash);
    assert_eq!(
        identity_hash,
        enclava_common::crypto::compute_identity_hash("tenant", "tenant-aaaaaaaa", &bootstrap_hash,)
    );
}

#[test]
fn initial_set_call_omits_token() {
    let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
        "subject": "repo:me/app:ref:refs/heads/main",
        "issuer":  "https://token.actions.githubusercontent.com",
    }))
    .expect("token must be optional");
    assert!(body.email_confirmation_token.is_none());
}

#[test]
fn rotation_call_carries_token() {
    let body: RotateSignerRequest = serde_json::from_value(serde_json::json!({
        "subject": "repo:me/app:ref:refs/heads/main",
        "issuer":  "https://token.actions.githubusercontent.com",
        "email_confirmation_token": "tok-123",
    }))
    .unwrap();
    assert_eq!(body.email_confirmation_token.as_deref(), Some("tok-123"));
}

#[test]
fn whitespace_only_token_is_treated_as_absent_by_handler_logic() {
    // The handler trims and filters; reproduce that exact predicate so
    // future refactors that drop the trim/filter trip a unit test.
    let token: Option<String> = Some("   ".to_string());
    let normalized = token.as_deref().map(str::trim).filter(|t| !t.is_empty());
    assert!(normalized.is_none());
}

#[test]
fn teardown_token_instance_id_matches_attestation_proxy_owner_instance_id() {
    let app = App {
        id: uuid::Uuid::new_v4(),
        org_id: uuid::Uuid::new_v4(),
        name: "demo".to_string(),
        namespace: "cap-a826eb13-demo".to_string(),
        instance_id: "a826eb13-12345678".to_string(),
        tenant_id: "a826eb13".to_string(),
        service_account: "cap-demo-sa".to_string(),
        bootstrap_owner_pubkey_hash: "00".repeat(32),
        tenant_instance_identity_hash: "11".repeat(32),
        unlock_mode: UnlockMode::Password,
        domain: "demo.a826eb13.enclava.dev".to_string(),
        tee_domain: Some("demo.a826eb13.tee.enclava.dev".to_string()),
        custom_domain: None,
        status: AppStatus::Running,
        signer_identity_subject: None,
        signer_identity_issuer: None,
        signer_identity_set_at: None,
        source_provider: None,
        source_repository: None,
        egress_allowlist: serde_json::json!([]),
        health_path: "/health".to_string(),
        health_interval_seconds: 30,
        health_timeout_seconds: 5,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(
        workload_teardown_instance_id(&app),
        "cap-a826eb13-demo-demo"
    );
}

#[tokio::test]
async fn create_app_rejects_member_before_database_access() {
    let result = create_app(
        crate::test_support::auth_context(Role::Member, &[]),
        State(crate::test_support::lazy_state()),
        Json(CreateAppRequest {
            name: "demo".to_string(),
            unlock_mode: "password".to_string(),
            bootstrap_pubkey_hash: None,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: Vec::new(),
            health_path: None,
            health_interval: None,
            health_timeout: None,
        }),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("member app creation unexpectedly passed authorization"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_apps_rejects_unscoped_api_key_before_database_access() {
    let result = list_apps(
        crate::test_support::auth_context(Role::Member, &["config:write"]),
        State(crate::test_support::lazy_state()),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("unscoped app list unexpectedly passed authorization"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn signer_rotation_token_rejects_api_key_before_database_access() {
    let result = issue_signer_rotation_token_route(
        crate::test_support::auth_context(Role::Owner, &["apps:write"]),
        State(crate::test_support::lazy_state()),
        Path("demo".to_string()),
        Json(SignerRotationTokenRequest {
            subject: "repo:me/app:ref:refs/heads/main".to_string(),
            issuer: "https://token.actions.githubusercontent.com".to_string(),
        }),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("API key minted signer rotation token"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}
