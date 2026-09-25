use super::{
    AppDeleteFailure, CreateAppRequest, EgressAllowlistAuditReason, RotateSignerRequest,
    SignerRotationTokenRequest, WorkloadTeardownDecision, app_delete_failure, create_app,
    delete_tenant_namespace_with_timeouts, derive_identity, egress_allowlist_host_audit_reasons,
    issue_signer_rotation_token_route, list_apps, post_workload_teardown,
    request_workload_teardown, requires_workload_teardown, rotate_signer,
    validate_egress_allowlist, validate_egress_mode, workload_teardown_http_failure,
    workload_teardown_instance_id,
};
use crate::auth::jwt::SignerRotationTokenInput;
use crate::auth::middleware::AuthContext;
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

fn teardown_test_app(auth: &AuthContext, status: AppStatus, domain: &str) -> App {
    App {
        id: uuid::Uuid::new_v4(),
        org_id: auth.org_id,
        name: "secret-app-name-sentinel".to_string(),
        namespace: "secret-namespace-sentinel".to_string(),
        instance_id: "a826eb13-12345678".to_string(),
        tenant_id: "a826eb13".to_string(),
        service_account: "cap-demo-sa".to_string(),
        bootstrap_owner_pubkey_hash: "00".repeat(32),
        tenant_instance_identity_hash: "11".repeat(32),
        unlock_mode: UnlockMode::Password,
        domain: domain.to_string(),
        tee_domain: Some(domain.to_string()),
        custom_domain: None,
        status,
        signer_identity_subject: None,
        signer_identity_issuer: None,
        signer_identity_set_at: None,
        source_provider: None,
        source_repository: None,
        egress_allowlist: sqlx::types::Json(Vec::new()),
        egress_mode: "restricted".to_string(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn unreachable_tee_state() -> crate::state::AppState {
    let mut state = crate::test_support::lazy_state();
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        // The per-request teardown timeout overrides the client timeout, so
        // bound the connect/DNS phase explicitly against resolver stalls.
        .connect_timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    state
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
fn egress_allowlist_rejects_internal_and_rebinding_hosts() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [
            { "host": "metadata.google.internal", "ports": [80] },
            { "host": "kubernetes.default.svc.cluster.local", "ports": [443] },
            { "host": "169.254.169.254.nip.io", "ports": [8080] }
        ]
    }))
    .unwrap();

    let err = validate_egress_allowlist(&body.egress_allowlist)
        .expect_err("internal/rebinding hosts must be rejected");
    assert!(err.contains("metadata.google.internal"));
    assert!(err.contains("metadata"));
}

#[test]
fn egress_allowlist_internal_hosts_still_validate_public_hosts() {
    let body: CreateAppRequest = serde_json::from_value(serde_json::json!({
        "name": "demo",
        "egress_allowlist": [
            { "host": "api.stripe.com", "ports": [443] },
            { "host": "objects.githubusercontent.com" }
        ]
    }))
    .unwrap();

    let rules = validate_egress_allowlist(&body.egress_allowlist).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(rules[0].host, "api.stripe.com");
    assert_eq!(rules[0].ports, vec![443]);
    assert_eq!(rules[1].ports, vec![443]);
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
fn running_apps_require_workload_teardown_endpoint() {
    assert!(requires_workload_teardown(AppStatus::Running));
    assert!(!requires_workload_teardown(AppStatus::Deleting));
    assert!(!requires_workload_teardown(AppStatus::Creating));
    assert!(!requires_workload_teardown(AppStatus::Failed));
    assert!(!requires_workload_teardown(AppStatus::Stopped));
}

#[tokio::test]
async fn tenant_namespace_delete_succeeds_when_already_absent() {
    // Both the initial GET and a raced DELETE can report absence. Neither
    // permits another GET (which could fail after teardown already succeeded).
    for absent_on_delete in [false, true] {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = calls.clone();
        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let call = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    assert_eq!(request.uri().path(), "/api/v1/namespaces/absent-delete");
                    let (status, body) = if absent_on_delete && call == 0 {
                        assert_eq!(request.method(), "GET");
                        (
                            StatusCode::OK,
                            serde_json::json!({
                                "apiVersion": "v1", "kind": "Namespace",
                                "metadata": {"name": "absent-delete", "uid": "old", "resourceVersion": "1"}
                            }),
                        )
                    } else {
                        assert_eq!(call, usize::from(absent_on_delete));
                        assert_eq!(
                            request.method().as_str(),
                            if absent_on_delete { "DELETE" } else { "GET" }
                        );
                        (
                            StatusCode::NOT_FOUND,
                            serde_json::json!({
                                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                "reason": "NotFound", "message": "absent", "code": 404
                            }),
                        )
                    };
                    Ok::<_, io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(body.to_string().into_bytes()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        delete_tenant_namespace_with_timeouts(
            kube::Api::all(client),
            "absent-delete",
            enclava_engine::apply::generation::MutationGeneration::new(1).unwrap(),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .await
        .expect("confirmed absence converges immediately");
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1 + usize::from(absent_on_delete)
        );
    }
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
async fn unreachable_running_workload_teardown_blocks_deletion_and_diagnostics_are_bounded() {
    const SECRET_APP_NAME: &str = "secret-app-name-sentinel";
    const SECRET_NAMESPACE: &str = "secret-namespace-sentinel";
    const SECRET_DOMAIN: &str = "secret-teardown-host.invalid";

    let mut state = crate::test_support::lazy_state();
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_millis(200))
        // The per-request teardown timeout overrides the client timeout, so
        // bound the connect/DNS phase explicitly against resolver stalls.
        .connect_timeout(Duration::from_millis(500))
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
    let (status, Json(body)) = request_workload_teardown(
        &state,
        &auth,
        &app,
        WorkloadTeardownDecision {
            required: true,
            completed: false,
        },
    )
    .await
    .expect_err("unreachable workload teardown endpoint must block deletion");
    drop(guard);

    let diagnostics = captured_log_text(&logs);
    let response = serde_json::to_string(&body).expect("delete error response serializes");
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body["error"], "app_delete_teardown_unavailable");
    assert!(diagnostics.contains(&app.id.to_string()));
    assert!(diagnostics.contains("app_delete_teardown_unavailable"));
    assert!(
        diagnostics.contains("category="),
        "transport failures must log a coarse category"
    );
    for secret in [SECRET_APP_NAME, SECRET_NAMESPACE, SECRET_DOMAIN] {
        assert!(
            !diagnostics.contains(secret),
            "tenant-controlled teardown data escaped into diagnostics"
        );
        assert!(
            !response.contains(secret),
            "tenant-controlled teardown data escaped into the delete error response"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn failed_and_creating_apps_skip_unreachable_workload_teardown() {
    let state = unreachable_tee_state();
    let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);

    for status in [AppStatus::Creating, AppStatus::Failed, AppStatus::Stopped] {
        let app = teardown_test_app(&auth, status, "secret-teardown-host.invalid");
        let (logs, guard) = captured_warn_logs();
        request_workload_teardown(
            &state,
            &auth,
            &app,
            WorkloadTeardownDecision {
                required: requires_workload_teardown(status),
                completed: false,
            },
        )
        .await
        .unwrap_or_else(|_| panic!("{status:?} app delete must not require TEE teardown"));
        drop(guard);
        let diagnostics = captured_log_text(&logs);
        assert!(
            !diagnostics.contains("app_delete_teardown_unavailable"),
            "{status:?} app delete contacted an unreachable TEE"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn completed_workload_teardown_skips_unreachable_retry() {
    let state = unreachable_tee_state();
    let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);
    let app = teardown_test_app(&auth, AppStatus::Deleting, "secret-teardown-host.invalid");

    let (logs, guard) = captured_warn_logs();
    request_workload_teardown(
        &state,
        &auth,
        &app,
        WorkloadTeardownDecision {
            required: true,
            completed: true,
        },
    )
    .await
    .expect("retry after successful teardown must proceed while the TEE is gone");
    drop(guard);

    let diagnostics = captured_log_text(&logs);
    assert!(!diagnostics.contains("app_delete_teardown_unavailable"));
}

#[test]
fn locked_running_workload_teardown_blocks_deletion_and_diagnostics_are_bounded() {
    const SECRET: &str = "upstream-locked-body-sentinel";
    let app_id = uuid::Uuid::new_v4();
    let (logs, guard) = captured_warn_logs();
    let (status, Json(body)) = workload_teardown_http_failure(app_id, StatusCode::LOCKED);
    drop(guard);

    let diagnostics = captured_log_text(&logs);
    let response = serde_json::to_string(&body).expect("delete error response serializes");
    assert_eq!(status, StatusCode::LOCKED);
    assert_eq!(body["error"], "app_delete_teardown_locked");
    assert!(diagnostics.contains(&app_id.to_string()));
    assert!(diagnostics.contains("app_delete_teardown_locked"));
    assert!(!diagnostics.contains(SECRET));
    assert!(!response.contains(SECRET));
}

#[tokio::test]
async fn locked_running_workload_teardown_http_status_fails_destroy() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = axum::Router::new().route(
        "/.well-known/confidential/teardown",
        axum::routing::post(|| async { StatusCode::LOCKED }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });

    let mut state = crate::test_support::lazy_state();
    state.tee_http_client = reqwest::Client::builder().no_proxy().build().unwrap();
    let auth = crate::test_support::auth_context(Role::Admin, &["apps:write"]);
    let app = teardown_test_app(&auth, AppStatus::Running, "secret-teardown-host.invalid");
    let url = format!("http://{address}/.well-known/confidential/teardown");

    let (logs, guard) = captured_warn_logs();
    let (status, Json(body)) = post_workload_teardown(&state, &app, "teardown-token", &url)
        .await
        .expect_err("locked password-mode TEE must block destroy");
    drop(guard);
    task.abort();

    let diagnostics = captured_log_text(&logs);
    assert_eq!(status, StatusCode::LOCKED);
    assert_eq!(body["error"], "app_delete_teardown_locked");
    assert!(diagnostics.contains(&app.id.to_string()));
    assert!(!diagnostics.contains("secret-app-name-sentinel"));
    assert!(!diagnostics.contains("secret-namespace-sentinel"));
    assert!(!diagnostics.contains("secret-teardown-host.invalid"));
    assert!(!diagnostics.contains(&url));
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
    assert!(
        deletion
            .contains("WHEN status = 'deleting'::app_status_enum THEN workload_teardown_required"),
        "app deletion must persist the pre-delete teardown decision across retries"
    );
    assert!(
        deletion.contains("requires_workload_teardown(phase_app.status)"),
        "app deletion must decide teardown from the status before the deleting transition"
    );
    assert!(
        !deletion.contains("requires_workload_teardown(deleting_app.status)"),
        "app deletion must not re-derive teardown from the post-transition Deleting status"
    );
    assert!(
        teardown.contains("workload_teardown_completed_at"),
        "successful teardown must persist a durable completion marker"
    );
    assert!(
        teardown.contains("app_delete_teardown_already_completed"),
        "retries must skip TEE teardown after the completion marker is set"
    );
    assert!(
        teardown.contains("AppDeleteFailure::TeardownLocked"),
        "a locked TEE must fail destroy through a stable teardown error code"
    );
    assert!(
        teardown.contains("Duration::from_secs(60)"),
        "the teardown client timeout must out-wait the proxy's two 20 s KBS deletes"
    );
    let migration = include_str!("../../../../migrations/0048_app_workload_teardown_state.sql");
    assert!(
        !migration.to_lowercase().contains("update apps"),
        "0048 must not backfill: the delete route records the requirement at delete time, and any backfill would only be read by a new replica retrying an old-replica delete whose workload may already be gone (mixed-rollout wedge)"
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

#[test]
fn derive_identity_rejects_oversized_generated_namespace() {
    let error = derive_identity(
        &"o".repeat(40),
        uuid::Uuid::nil(),
        &"a".repeat(20),
        "password",
        Some(&"00".repeat(32)),
    )
    .unwrap_err();

    assert!(error.contains("namespace longer than 63 characters"));
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

#[tokio::test]
async fn signer_rotation_token_is_single_use_and_withdraws_rotated_out_artifacts() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect signer rotation regression database");
    crate::db::pool::run_migrations(&pool)
        .await
        .expect("migrate signer rotation regression database");

    let org_id = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    let app_id = uuid::Uuid::new_v4();
    let suffix = app_id.simple().to_string();
    sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(format!("signer-rotation-{suffix}"))
        .bind(&suffix[..8])
        .execute(&pool)
        .await
        .expect("insert signer rotation organization");
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'rotation owner')")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert signer rotation user");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, created_at, removed_at)
         VALUES ($1, $2, 'owner', now(), NULL)
         ON CONFLICT DO NOTHING",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("insert signer rotation membership");
    sqlx::query(
        "INSERT INTO apps (
             id, org_id, name, namespace, instance_id, tenant_id,
             service_account, bootstrap_owner_pubkey_hash,
             tenant_instance_identity_hash, domain, status,
             signer_identity_subject, signer_identity_issuer
         ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
             'running'::app_status_enum, $11, $12
         )",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(format!("app-{}", &suffix[..12]))
    .bind(format!("cap-{}", &suffix[..12]))
    .bind(format!("instance-{suffix}"))
    .bind(&suffix[..8])
    .bind(format!("cap-{}-sa", &suffix[..12]))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("{}.example.test", &suffix[..12]))
    .bind("https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main")
    .bind("https://token.actions.githubusercontent.com")
    .execute(&pool)
    .await
    .expect("insert signer rotation app");

    // A retained artifact signed under the previous identity.
    let deploy_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
         VALUES ($1, $2, $3, 'healthy'::deploy_status_enum, '{}'::jsonb)",
    )
    .bind(deploy_id)
    .bind(org_id)
    .bind(app_id)
    .execute(&pool)
    .await
    .expect("insert signer rotation deployment");
    let descriptor_core_hash: Vec<u8> = (0..32)
        .map(|i| (app_id.as_bytes()[i % 16] as u16 + i as u16) as u8)
        .collect();
    let artifact_json = serde_json::json!({
        "signer_identity": {
            "subject": "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com",
        }
    });
    sqlx::query(
        "INSERT INTO workload_artifacts (
             descriptor_core_hash, app_id, deploy_id, descriptor_payload,
             descriptor_signature, descriptor_signing_key_id,
             org_keyring_payload, org_keyring_signature, signed_policy_artifact
         ) VALUES ($1, $2, $3, $4, $5, 'test-key', '{}'::jsonb, $6, '{}'::jsonb)",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .bind(deploy_id)
    .bind(&artifact_json)
    .bind(vec![1u8; 64])
    .bind(vec![2u8; 64])
    .execute(&pool)
    .await
    .expect("insert rotated-out workload artifact");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let hmac_key = [7u8; 32];
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: "signer-rotation-test".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: crate::auth::middleware::ManagementOrigin::Public,
    };
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://token.actions.githubusercontent.com";

    let desired_before: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read desired generation before any rotation");

    let token = crate::auth::jwt::issue_signer_rotation_token(
        &hmac_key,
        &SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_subject.to_string(),
            previous_issuer: previous_issuer.to_string(),
            new_subject: new_subject.to_string(),
            new_issuer: new_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue signer rotation token");

    let app_name = sqlx::query_scalar::<_, String>("SELECT name FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("load app name");

    let Json(rotated) = rotate_signer(
        clone_auth(&auth),
        State(state.clone()),
        Path(app_name.clone()),
        Json(RotateSignerRequest {
            subject: new_subject.to_string(),
            issuer: new_issuer.to_string(),
            email_confirmation_token: Some(token.clone()),
        }),
    )
    .await
    .expect("first rotation succeeds");
    assert_eq!(
        rotated.signer_identity_subject.as_deref(),
        Some(new_subject)
    );

    // The rotated-out artifact is withdrawn from KBS policy.
    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawn_signer_artifacts
          WHERE descriptor_core_hash = $1 AND app_id = $2",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count withdrawn artifacts");
    assert_eq!(
        withdrawn, 1,
        "rotation must withdraw the old-signer artifact"
    );
    // And a signed-policy generation was enqueued durably: every rotation
    // must advance the generation.
    let desired: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read desired generation after rotation");
    assert!(
        desired > desired_before,
        "rotation must enqueue policy reconciliation"
    );
    // The consumed jti ledger row is committed with the rotation.
    let jti_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count consumed jti rows");
    assert_eq!(jti_rows, 1, "rotation must record the consumed jti");

    // Rotate back to the previous identity so the original token's claims
    // (previous=old, new=new) match again, then replay it: it must be
    // rejected because its jti was consumed.
    let rotate_back_token = crate::auth::jwt::issue_signer_rotation_token(
        &hmac_key,
        &SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: new_subject.to_string(),
            previous_issuer: new_issuer.to_string(),
            new_subject: previous_subject.to_string(),
            new_issuer: previous_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue rotate-back token");
    let desired_mid: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read desired generation before rotate-back");
    let Json(_) = rotate_signer(
        clone_auth(&auth),
        State(state.clone()),
        Path(app_name.clone()),
        Json(RotateSignerRequest {
            subject: previous_subject.to_string(),
            issuer: previous_issuer.to_string(),
            email_confirmation_token: Some(rotate_back_token),
        }),
    )
    .await
    .expect("rotate back succeeds");
    let desired_after: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read desired generation after rotate-back");
    assert!(
        desired_after > desired_mid,
        "rotating an already-withdrawn artifact must still bump the generation"
    );

    let replay = rotate_signer(
        clone_auth(&auth),
        State(state.clone()),
        Path(app_name.clone()),
        Json(RotateSignerRequest {
            subject: new_subject.to_string(),
            issuer: new_issuer.to_string(),
            email_confirmation_token: Some(token),
        }),
    )
    .await;
    let err = match replay {
        Ok(_) => panic!("consumed signer rotation token was replayable"),
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::FORBIDDEN);
    // The rejected replay must not have committed any part of the rotation.
    let replayed_subject: Option<String> =
        sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("load app subject after rejected replay");
    assert_eq!(
        replayed_subject.as_deref(),
        Some(previous_subject),
        "rejected replay must roll back the signer update"
    );

    sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete signer rotation audit rows");
    sqlx::query("DELETE FROM consumed_signer_rotation_tokens WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete signer rotation consumed tokens");
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete signer rotation fixture");
}

#[tokio::test]
async fn signer_rotation_never_flips_an_unsigned_install_into_signed_mode() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect unsigned rotation regression database");
    crate::db::pool::run_migrations(&pool)
        .await
        .expect("migrate unsigned rotation regression database");

    let org_id = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    let app_id = uuid::Uuid::new_v4();
    let suffix = app_id.simple().to_string();
    sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(format!("unsigned-rotation-{suffix}"))
        .bind(&suffix[..8])
        .execute(&pool)
        .await
        .expect("insert unsigned rotation organization");
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'unsigned owner')")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert unsigned rotation user");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, created_at, removed_at)
         VALUES ($1, $2, 'owner', now(), NULL)",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("insert unsigned rotation membership");
    sqlx::query(
        "INSERT INTO apps (
             id, org_id, name, namespace, instance_id, tenant_id,
             service_account, bootstrap_owner_pubkey_hash,
             tenant_instance_identity_hash, domain, status,
             signer_identity_subject, signer_identity_issuer
         ) VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
             'running'::app_status_enum, $11, $12
         )",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(format!("app-{}", &suffix[..12]))
    .bind(format!("cap-{}", &suffix[..12]))
    .bind(format!("instance-{suffix}"))
    .bind(&suffix[..8])
    .bind(format!("cap-{}-sa", &suffix[..12]))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("{}.example.test", &suffix[..12]))
    .bind("https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main")
    .bind("https://token.actions.githubusercontent.com")
    .execute(&pool)
    .await
    .expect("insert unsigned rotation app");

    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";

    // A legacy binding row so rotation must carry the new identity into it.
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
             app_id, binding_key, repository, tag, namespace, service_account,
             tenant_instance_identity_hash, signer_identity_subject,
             signer_identity_issuer
         ) VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5, $6, $7)
         ON CONFLICT (app_id) DO NOTHING",
    )
    .bind(app_id)
    .bind(format!("tls-{}", &suffix[..12]))
    .bind(format!("cap-{}", &suffix[..12]))
    .bind(format!("cap-{}-sa", &suffix[..12]))
    .bind("22".repeat(32))
    .bind(previous_subject)
    .bind(previous_issuer)
    .execute(&pool)
    .await
    .expect("insert legacy tls binding");

    // Pin the install to the unsigned-only state: desired_generation = 0.
    // The singleton is process-wide shared state, so snapshot it and restore
    // it in cleanup instead of leaving the wipe behind.
    type ReconciliationSingleton = (
        i64,
        i64,
        i64,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        Option<String>,
    );
    let singleton_before: ReconciliationSingleton = sqlx::query_as(
        "SELECT desired_generation, configmap_generation, applied_generation,
                configmap_policy_sha256, applied_policy_sha256,
                configmap_resource_version
           FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("snapshot reconciliation singleton");
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 0,
                configmap_generation = 0,
                applied_generation = 0,
                configmap_policy_sha256 = NULL,
                applied_policy_sha256 = NULL,
                configmap_resource_version = NULL
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("reset reconciliation state to unsigned");
    // The helper bumps when ANY workload_artifacts row exists (table-wide,
    // not per-app). Skip this regression when a shared database carries
    // leftover fixtures from other tests.
    let total_artifacts: i64 = sqlx::query_scalar("SELECT count(*) FROM workload_artifacts")
        .fetch_one(&pool)
        .await
        .expect("count workload artifacts");
    if total_artifacts != 0 {
        // Restore before skipping so the singleton wipe is not left behind.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = $1,
                    configmap_generation = $2,
                    applied_generation = $3,
                    configmap_policy_sha256 = $4,
                    applied_policy_sha256 = $5,
                    configmap_resource_version = $6
              WHERE singleton",
        )
        .bind(singleton_before.0)
        .bind(singleton_before.1)
        .bind(singleton_before.2)
        .bind(&singleton_before.3)
        .bind(&singleton_before.4)
        .bind(&singleton_before.5)
        .execute(&pool)
        .await
        .expect("restore reconciliation singleton before skipping");
        eprintln!("skipping: shared database has {total_artifacts} workload artifacts");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete skipped unsigned rotation fixture");
        return;
    }

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let hmac_key = [7u8; 32];
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: "unsigned-rotation-test".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: crate::auth::middleware::ManagementOrigin::Public,
    };
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";

    let token = crate::auth::jwt::issue_signer_rotation_token(
        &hmac_key,
        &SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_subject.to_string(),
            previous_issuer: previous_issuer.to_string(),
            new_subject: new_subject.to_string(),
            new_issuer: new_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue unsigned rotation token");

    let app_name = sqlx::query_scalar::<_, String>("SELECT name FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("load unsigned app name");

    let Json(rotated) = rotate_signer(
        clone_auth(&auth),
        State(state.clone()),
        Path(app_name),
        Json(RotateSignerRequest {
            subject: new_subject.to_string(),
            issuer: new_issuer.to_string(),
            email_confirmation_token: Some(token),
        }),
    )
    .await
    .expect("unsigned rotation succeeds");
    assert_eq!(
        rotated.signer_identity_subject.as_deref(),
        Some(new_subject)
    );

    // The legacy binding must carry the new identity into the next Rego
    // render.
    let (binding_subject, binding_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load tls binding identity after rotation");
    assert_eq!(
        binding_subject.as_deref(),
        Some(new_subject),
        "rotation must update the legacy Rego binding signer subject"
    );
    assert_eq!(
        binding_issuer.as_deref(),
        Some(new_issuer),
        "rotation must update the legacy Rego binding signer issuer"
    );

    // The install must still be unsigned: rotation never enters signed mode.
    let desired: i64 = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&pool)
    .await
    .expect("read desired generation after unsigned rotation");
    assert_eq!(
        desired, 0,
        "rotation on an unsigned-only install must not enter signed mode"
    );

    // Restore the shared singleton exactly as it was found (all columns the
    // test wiped, hashes included, so 0041's CHECKs keep holding).
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = $1,
                configmap_generation = $2,
                applied_generation = $3,
                configmap_policy_sha256 = $4,
                applied_policy_sha256 = $5,
                configmap_resource_version = $6
          WHERE singleton",
    )
    .bind(singleton_before.0)
    .bind(singleton_before.1)
    .bind(singleton_before.2)
    .bind(singleton_before.3.clone())
    .bind(singleton_before.4.clone())
    .bind(singleton_before.5.clone())
    .execute(&pool)
    .await
    .expect("restore reconciliation singleton");
    sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete unsigned rotation audit rows");
    sqlx::query("DELETE FROM consumed_signer_rotation_tokens WHERE org_id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete unsigned rotation consumed tokens");
    sqlx::query("DELETE FROM organizations WHERE id = $1")
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("delete unsigned rotation fixture");
}

fn clone_auth(auth: &AuthContext) -> AuthContext {
    AuthContext {
        user_id: auth.user_id,
        org_id: auth.org_id,
        org_name: auth.org_name.clone(),
        role: auth.role,
        api_key: auth.api_key.clone(),
        management_origin: auth.management_origin,
    }
}
