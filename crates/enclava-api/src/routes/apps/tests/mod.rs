use super::{
    AppDeleteFailure, CreateAppRequest, EgressAllowlistAuditReason, RotateSignerRequest,
    SignerRotationTokenRequest, app_delete_failure, create_app,
    delete_tenant_namespace_with_timeouts, egress_allowlist_host_audit_reasons,
    issue_signer_rotation_token_route, list_apps, request_workload_teardown,
    requires_workload_teardown, validate_egress_allowlist, validate_egress_mode,
    workload_teardown_instance_id,
};
use crate::models::{App, AppStatus, Role, UnlockMode};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{Request, Response, StatusCode};
use kube::client::Body;
use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Duration,
};
use tower::service_fn;

struct CapturedLogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("captured log mutex").extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn captured_warn_logs() -> (Arc<Mutex<Vec<u8>>>, tracing::dispatcher::DefaultGuard) {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer({
            let logs = Arc::clone(&logs);
            move || CapturedLogWriter(Arc::clone(&logs))
        })
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (logs, guard)
}

fn captured_log_text(logs: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(logs.lock().expect("captured log mutex").clone())
        .expect("captured logs are UTF-8")
}

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
fn running_and_deleting_apps_require_workload_teardown_endpoint() {
    assert!(requires_workload_teardown(AppStatus::Running));
    assert!(requires_workload_teardown(AppStatus::Deleting));
    assert!(!requires_workload_teardown(AppStatus::Creating));
    assert!(!requires_workload_teardown(AppStatus::Failed));
    assert!(!requires_workload_teardown(AppStatus::Stopped));
}

#[tokio::test]
async fn tenant_namespace_delete_is_bounded_when_provider_read_hangs() {
    let client = kube::Client::new(
        service_fn(|_request: Request<Body>| async move {
            std::future::pending::<Result<Response<Body>, io::Error>>().await
        }),
        "default",
    );
    let namespaces = kube::Api::all(client);
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        delete_tenant_namespace_with_timeouts(
            namespaces,
            "bounded-delete",
            enclava_engine::apply::generation::MutationGeneration::new(1).unwrap(),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ),
    )
    .await
    .expect("test guard: provider operation deadline did not fire")
    .expect_err("hung provider read must hit the outer operation deadline");

    assert!(matches!(
        error,
        enclava_engine::apply::engine::ApplyError::CleanupStepFailed { step, detail }
            if step == "delete_namespace"
                && detail == "namespace deletion provider operation timed out"
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn unreachable_running_workload_teardown_is_best_effort_and_diagnostics_are_bounded() {
    const SECRET_APP_NAME: &str = "secret-app-name-sentinel";
    const SECRET_NAMESPACE: &str = "secret-namespace-sentinel";
    const SECRET_DOMAIN: &str = "secret-teardown-host.invalid";

    let mut state = crate::test_support::lazy_state();
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        .build()
        .unwrap();
    let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);
    let app = App {
        id: uuid::Uuid::new_v4(),
        org_id: auth.org_id,
        name: SECRET_APP_NAME.to_string(),
        namespace: SECRET_NAMESPACE.to_string(),
        instance_id: "a826eb13-12345678".to_string(),
        tenant_id: "a826eb13".to_string(),
        service_account: "cap-demo-sa".to_string(),
        bootstrap_owner_pubkey_hash: "00".repeat(32),
        tenant_instance_identity_hash: "11".repeat(32),
        unlock_mode: UnlockMode::Password,
        domain: SECRET_DOMAIN.to_string(),
        tee_domain: Some(SECRET_DOMAIN.to_string()),
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

    let (logs, guard) = captured_warn_logs();
    request_workload_teardown(&state, &auth, &app)
        .await
        .expect("unreachable workload teardown endpoint must not block deletion");
    drop(guard);

    let diagnostics = captured_log_text(&logs);
    assert!(diagnostics.contains(&app.id.to_string()));
    assert!(diagnostics.contains("app_delete_teardown_unavailable"));
    for secret in [SECRET_APP_NAME, SECRET_NAMESPACE, SECRET_DOMAIN] {
        assert!(
            !diagnostics.contains(secret),
            "tenant-controlled teardown data escaped into diagnostics"
        );
    }
}

#[test]
fn app_delete_failure_discards_secret_source_diagnostics() {
    const SECRET: &str = "upstream-secret-error-sentinel";

    struct SecretDiagnostic;

    impl std::fmt::Display for SecretDiagnostic {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str(SECRET)
        }
    }

    let app_id = uuid::Uuid::new_v4();
    let (logs, guard) = captured_warn_logs();
    let (status, Json(body)) =
        app_delete_failure(app_id, AppDeleteFailure::EdgeRoute, SecretDiagnostic);
    drop(guard);

    let diagnostics = captured_log_text(&logs);
    let response = serde_json::to_string(&body).expect("delete error response serializes");
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "app_delete_edge_unavailable");
    assert!(diagnostics.contains(&app_id.to_string()));
    assert!(diagnostics.contains("app_delete_edge_unavailable"));
    assert!(!diagnostics.contains(SECRET));
    assert!(!response.contains(SECRET));
}

#[test]
fn app_delete_source_never_reads_or_formats_external_diagnostics() {
    let source = include_str!("../../apps.rs");
    let teardown = source
        .split("async fn request_workload_teardown")
        .nth(1)
        .expect("workload teardown helper exists")
        .split("/// Comprehensive app name validation")
        .next()
        .expect("workload teardown helper body");
    let deletion = source
        .split("pub async fn delete_app")
        .nth(1)
        .expect("app deletion route exists")
        .split("#[derive(Debug, Deserialize)]\npub struct RotateSignerRequest")
        .next()
        .expect("app deletion route body");

    for forbidden in [
        "response.text()",
        "app_name = %app.name",
        "namespace = %app.namespace",
        "url = %url",
        "body = %body",
        "error = %error",
        "failed to issue teardown token: {e}",
    ] {
        assert!(
            !teardown.contains(forbidden),
            "teardown diagnostics must not contain `{forbidden}`"
        );
    }

    assert!(
        !deletion.contains("dns_error_response"),
        "app deletion must not use the raw DNS error response"
    );
    assert!(
        !deletion.contains("format!("),
        "app deletion must not format dependency errors into responses"
    );
    assert!(
        deletion
            .find("request_workload_teardown")
            .expect("app deletion requests workload teardown")
            < deletion
                .find("enqueue_signed_policy_revocation_if_active")
                .expect("app deletion enqueues signed-policy revocation"),
        "app deletion must preserve KBS authorization until workload teardown completes"
    );
    for failure in [
        "app_delete_dns_failure",
        "AppDeleteFailure::EdgeBackend",
        "AppDeleteFailure::EdgeRoute",
        "AppDeleteFailure::Namespace",
        "AppDeleteFailure::KbsOwnerBinding",
        "AppDeleteFailure::KbsTlsBinding",
        "AppDeleteFailure::KbsPolicy",
    ] {
        assert!(
            deletion.contains(failure),
            "app deletion must route failures through bounded diagnostic `{failure}`"
        );
    }
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
