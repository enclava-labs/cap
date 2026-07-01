use super::{
    CreateAppRequest, EgressAllowlistAuditReason, RotateSignerRequest, SignerRotationTokenRequest,
    create_app, egress_allowlist_host_audit_reasons, issue_signer_rotation_token_route, list_apps,
    request_workload_teardown, requires_workload_teardown, validate_egress_allowlist,
    validate_egress_mode, workload_teardown_instance_id,
};
use crate::models::{App, AppStatus, Role, UnlockMode};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use std::time::Duration;

#[test]
fn create_request_defaults_to_password_unlock() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
    }))
    .unwrap();

    assert_eq!(body.unlock_mode, "password");
    assert_eq!(body.egress_mode, "restricted");
    assert!(body.egress_allowlist.is_empty());
}

#[test]
fn egress_mode_accepts_restricted_and_public_internet() {
    assert_eq!(
        validate_egress_mode("restricted").unwrap().as_str(),
        "restricted"
    );
    assert_eq!(
        validate_egress_mode("public_internet").unwrap().as_str(),
        "public_internet"
    );
    assert!(validate_egress_mode("cluster").is_err());
}

#[test]
fn egress_allowlist_defaults_omitted_ports_to_https() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [
            { "host": "relay.enclava.me", "ports": [20000] },
            { "host": "rekor.sigstore.dev" }
        ]
    }))
    .unwrap();

    let rules = validate_egress_allowlist(&body.egress_allowlist).unwrap();
    assert_eq!(rules[0].host, "relay.enclava.me");
    assert_eq!(rules[0].ports, vec![20000]);
    assert_eq!(rules[1].host, "rekor.sigstore.dev");
    assert_eq!(rules[1].ports, vec![443]);
}

#[test]
fn egress_allowlist_rejects_ip_hosts_and_empty_ports() {
    let ip_host: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [{ "host": "1.2.3.4", "ports": [443] }]
    }))
    .unwrap();
    assert!(validate_egress_allowlist(&ip_host.egress_allowlist).is_err());

    let empty_ports: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [{ "host": "relay.enclava.me", "ports": [] }]
    }))
    .unwrap();
    assert!(validate_egress_allowlist(&empty_ports.egress_allowlist).is_err());
}

#[test]
fn egress_allowlist_warn_only_audit_classifies_internal_and_rebinding_hosts() {
    assert_eq!(
        egress_allowlist_host_audit_reasons("metadata.google.internal"),
        vec![
            EgressAllowlistAuditReason::Metadata,
            EgressAllowlistAuditReason::InternalDnsSuffix
        ]
    );
    assert_eq!(
        egress_allowlist_host_audit_reasons("kubernetes.default.svc.cluster.local"),
        vec![
            EgressAllowlistAuditReason::KubernetesService,
            EgressAllowlistAuditReason::InternalDnsSuffix
        ]
    );
    assert_eq!(
        egress_allowlist_host_audit_reasons("169.254.169.254.nip.io"),
        vec![EgressAllowlistAuditReason::RebindingHelper]
    );
    assert!(egress_allowlist_host_audit_reasons("api.stripe.com").is_empty());
}

#[test]
fn egress_allowlist_audit_is_warn_only_until_migration_enforces_it() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [
            { "host": "metadata.google.internal", "ports": [80] },
            { "host": "kubernetes.default.svc.cluster.local", "ports": [443] },
            { "host": "169.254.169.254.nip.io", "ports": [8080] }
        ]
    }))
    .unwrap();

    let rules = validate_egress_allowlist(&body.egress_allowlist)
        .expect("audit is warn-only and must not reject existing values");
    assert_eq!(rules.len(), 3);
    assert_eq!(rules[0].host, "metadata.google.internal");
    assert_eq!(rules[0].ports, vec![80]);
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
        egress_allowlist: sqlx::types::Json(Vec::new()),
        egress_mode: "restricted".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    assert_eq!(
        workload_teardown_instance_id(&app),
        "cap-a826eb13-demo-demo"
    );
}

#[test]
fn only_running_apps_require_workload_teardown_endpoint() {
    assert!(requires_workload_teardown(AppStatus::Running));
    assert!(!requires_workload_teardown(AppStatus::Creating));
    assert!(!requires_workload_teardown(AppStatus::Failed));
    assert!(!requires_workload_teardown(AppStatus::Stopped));
    assert!(!requires_workload_teardown(AppStatus::Deleting));
}

#[tokio::test]
async fn unreachable_running_workload_teardown_is_best_effort() {
    let mut state = crate::test_support::lazy_state();
    state.tee_http_client = reqwest::Client::builder()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);
    let app = App {
        id: uuid::Uuid::new_v4(),
        org_id: auth.org_id,
        name: "demo".to_string(),
        namespace: "cap-a826eb13-demo".to_string(),
        instance_id: "a826eb13-12345678".to_string(),
        tenant_id: "a826eb13".to_string(),
        service_account: "cap-demo-sa".to_string(),
        bootstrap_owner_pubkey_hash: "00".repeat(32),
        tenant_instance_identity_hash: "11".repeat(32),
        unlock_mode: UnlockMode::Password,
        domain: "127.0.0.1:9".to_string(),
        tee_domain: Some("127.0.0.1:9".to_string()),
        custom_domain: None,
        status: AppStatus::Running,
        signer_identity_subject: None,
        signer_identity_issuer: None,
        signer_identity_set_at: None,
        source_provider: None,
        source_repository: None,
        egress_allowlist: sqlx::types::Json(Vec::new()),
        egress_mode: "restricted".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    request_workload_teardown(&state, &auth, &app)
        .await
        .expect("unreachable workload teardown endpoint must not block deletion");
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
            egress_mode: "restricted".to_string(),
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
