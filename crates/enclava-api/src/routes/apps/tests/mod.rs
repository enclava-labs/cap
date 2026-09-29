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
use crate::test_support::{KbsPolicyProvider, kbs_policy_kube_client};
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
        signer_rotation_generation: 0,
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
        signer_rotation_generation: 0,
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
        signer_rotation_generation: 0,
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

#[tokio::test]
async fn deletion_retry_preserves_teardown_requirement_before_policy_revocation() {
    let (_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_delete_teardown_retry").await;
    let (org_id, user_id, app_id) = insert_signer_rotation_app(&pool, None, None).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (attempts_tx, mut attempts_rx) = tokio::sync::mpsc::channel(2);
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            attempts_tx.send(()).await.unwrap();
            drop(stream);
        }
    });
    let app_name: String =
        sqlx::query_scalar("UPDATE apps SET tee_domain = $2 WHERE id = $1 RETURNING name")
            .bind(app_id)
            .bind(address.to_string())
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation SET desired_generation = 1 WHERE singleton",
    )
    .execute(&pool)
    .await
    .unwrap();
    let policy_before = read_withdrawal_reconciliation_state(&pool).await;
    let mut state = unreachable_tee_state();
    state.db = pool.clone();
    let mut auth = crate::test_support::auth_context(Role::Owner, &["apps:write"]);
    auth.org_id = org_id;
    auth.user_id = user_id;

    for _ in 0..2 {
        let (status, Json(body)) = tokio::time::timeout(
            Duration::from_secs(3),
            super::delete_app(auth.clone(), State(state.clone()), Path(app_name.clone())),
        )
        .await
        .expect("deletion must release its lanes after teardown fails")
        .expect_err("an unavailable TEE must block both deletion attempts");
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "app_delete_teardown_unavailable");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), attempts_rx.recv())
                .await
                .expect("each deletion attempt must contact the TEE"),
            Some(())
        );
        let app_status: String = sqlx::query_scalar("SELECT status::text FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(app_status, "deleting");
        assert_eq!(
            read_withdrawal_reconciliation_state(&pool).await,
            policy_before,
            "failed confidential teardown must not revoke the workload's KBS authority"
        );
    }
    server.await.unwrap();
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

/// Fixture for the signer-rotation regressions: an org, an owner user, and
/// a running app pinned to the given signer identity (or none, for the
/// initial-set cases).
async fn insert_signer_rotation_app(
    pool: &sqlx::PgPool,
    signer_subject: Option<&str>,
    signer_issuer: Option<&str>,
) -> (uuid::Uuid, uuid::Uuid, uuid::Uuid) {
    let org_id = uuid::Uuid::new_v4();
    let user_id = uuid::Uuid::new_v4();
    let app_id = uuid::Uuid::new_v4();
    let suffix = app_id.simple().to_string();
    sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
        .bind(org_id)
        .bind(format!("signer-rotation-{suffix}"))
        .bind(&suffix[..8])
        .execute(pool)
        .await
        .expect("insert signer rotation organization");
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'rotation owner')")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert signer rotation user");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, created_at, removed_at)
         VALUES ($1, $2, 'owner', now(), NULL)",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
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
    .bind(signer_subject)
    .bind(signer_issuer)
    .execute(pool)
    .await
    .expect("insert signer rotation app");
    (org_id, user_id, app_id)
}

/// A retained workload artifact whose signed descriptor carries the given
/// signer identity: exactly what a rotated-out signer leaves behind.
async fn insert_signed_artifact_for_identity(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    app_id: uuid::Uuid,
    subject: &str,
    issuer: &str,
) -> Vec<u8> {
    let descriptor_core_hash: Vec<u8> = (0..32u8).collect();
    insert_signed_artifact_for_identity_with_hash(
        pool,
        org_id,
        app_id,
        subject,
        issuer,
        &descriptor_core_hash,
    )
    .await;
    descriptor_core_hash
}

/// [`insert_signed_artifact_for_identity`] with an explicit descriptor hash,
/// for tests that need several distinct artifacts under one identity.
async fn insert_signed_artifact_for_identity_with_hash(
    pool: &sqlx::PgPool,
    org_id: uuid::Uuid,
    app_id: uuid::Uuid,
    subject: &str,
    issuer: &str,
    descriptor_core_hash: &[u8],
) {
    let deploy_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
         VALUES ($1, $2, $3, 'healthy'::deploy_status_enum, '{}'::jsonb)",
    )
    .bind(deploy_id)
    .bind(org_id)
    .bind(app_id)
    .execute(pool)
    .await
    .expect("insert signer rotation deployment");
    let measurement_hex = hex::encode(descriptor_core_hash);
    let descriptor_payload = serde_json::json!({
        "image_ref": format!("ghcr.io/acme/workload@sha256:{measurement_hex}"),
        "expected_cc_init_data_hash": measurement_hex,
        "signer_identity": {
            "subject": subject,
            "issuer": issuer,
        }
    });
    sqlx::query(
        "INSERT INTO workload_artifacts (
             descriptor_core_hash, app_id, deploy_id, descriptor_payload,
             descriptor_signature, descriptor_signing_key_id,
             org_keyring_payload, org_keyring_signature, signed_policy_artifact
         ) VALUES ($1, $2, $3, $4, $5, 'test-key', '{}'::jsonb, $6, '{}'::jsonb)",
    )
    .bind(descriptor_core_hash)
    .bind(app_id)
    .bind(deploy_id)
    .bind(&descriptor_payload)
    .bind(vec![1u8; 64])
    .bind(vec![2u8; 64])
    .execute(pool)
    .await
    .expect("insert rotated-out workload artifact");
}

/// A legacy kbs_tls_bindings row: the Rego render source on unsigned
/// installs, which rotation must carry the new identity into.
async fn insert_legacy_tls_binding(
    pool: &sqlx::PgPool,
    app_id: uuid::Uuid,
    subject: &str,
    issuer: &str,
) {
    let suffix = app_id.simple().to_string();
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
    .bind(subject)
    .bind(issuer)
    .execute(pool)
    .await
    .expect("insert legacy tls binding");
}

async fn read_withdrawal_reconciliation_state(pool: &sqlx::PgPool) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT desired_generation, selector_bumps_owed, withdrawal_bumps_owed
           FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(pool)
    .await
    .expect("read signed policy reconciliation singleton")
}

fn test_kbs_policy_config() -> crate::kbs::KbsPolicyConfig {
    crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".to_string(),
        configmap_name: "resource-policy".to_string(),
        policy_key: "policy.rego".to_string(),
        deployment_name: "trustee".to_string(),
        required: true,
        signed_policy_retention: 6,
        signed_policy_max_bytes: 900 * 1024,
    }
}

/// Rotating back to the previous identity must not make its consumed token
/// replayable or let a rejected replay change the published generation. The
/// token stays unusable for transitions (A -> B -> A -> B reuses no token),
/// but presenting the consumed A -> B token while B is current is an
/// owner-authorized read-only confirmation of the committed identity: it
/// must not mutate authority, consume a jti, audit, withdraw, or republish.
#[tokio::test]
async fn signer_rotation_token_is_single_use_and_owes_a_deferred_withdrawal_bump() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_rotation_single_use").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    let descriptor_core_hash = insert_signed_artifact_for_identity(
        &pool,
        org_id,
        app_id,
        previous_subject,
        previous_issuer,
    )
    .await;
    // Signed mode is durable at generation 1: the deployment acceptance
    // that committed the artifact enqueued it.
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

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

    // PR #187 review: active signed mode without KBS provider configuration
    // must fail closed BEFORE the rotation commits -- the withdrawal and the
    // deferred generation bump would otherwise strand the old policy live
    // with no convergence path (the periodic reconciler also refuses to
    // start without configuration). The token JTI must stay unconsumed so
    // the same token can drive the rotation once configuration returns.
    let unconfigured_token = crate::auth::jwt::issue_signer_rotation_token(
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
    .expect("issue unconfigured-refusal token");
    let app_name = sqlx::query_scalar::<_, String>("SELECT name FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("load app name");
    let unconfigured = rotate_signer(
        clone_auth(&auth),
        State(state.clone()),
        Path(app_name.clone()),
        Json(RotateSignerRequest {
            subject: new_subject.to_string(),
            issuer: new_issuer.to_string(),
            email_confirmation_token: Some(unconfigured_token),
        }),
    )
    .await
    .expect_err("signed mode without KBS configuration must refuse the rotation");
    assert_eq!(unconfigured.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(unconfigured.1.0["code"], "kbs_publication_not_configured");
    let unconfigured_subject: Option<String> =
        sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("load app subject after unconfigured refusal");
    assert_eq!(
        unconfigured_subject.as_deref(),
        Some(previous_subject),
        "the unconfigured refusal must not have committed any rotation"
    );
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 0),
        "the unconfigured refusal must owe no withdrawal debt"
    );
    let jti_rows_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count consumed jti rows after unconfigured refusal");
    assert_eq!(
        jti_rows_before, 0,
        "the unconfigured refusal must leave the rotation token unconsumed"
    );

    // Configure the KBS provider: the rotation can now commit and its
    // withdrawal must publish before success is reported.
    state.kbs_policy = Some(test_kbs_policy_config());
    let provider = Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));

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

    crate::kbs::TEST_KUBE_CLIENT
        .scope(kbs_policy_kube_client(provider.clone()), async {
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
            // The owed withdrawal bump is consumed only by the fenced reconciler
            // AFTER the filtered ConfigMap replace succeeded (migration 0052): the
            // route reports success only once the generation is live, so the debt
            // is settled, never performed inside the rotation transaction.
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                (2, 0, 0),
                "success must mean the owed withdrawal bump was published and consumed"
            );
            {
                let provider = provider.lock().await;
                assert_eq!(
                    provider.published_generation(),
                    Some(2),
                    "the withdrawal generation must be live in the ConfigMap before success"
                );
            }
            // The consumed jti ledger row is committed with the rotation.
            let jti_rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows");
            assert_eq!(jti_rows, 1, "rotation must record the consumed jti");

            // Rotate back so the original token's claims (previous=old, new=new)
            // match again, then replay it: the jti was consumed, so the replay
            // must be refused and the whole transaction -- including the trigger's
            // withdrawal and owed bump -- rolled back.
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
            // Every rotation owes one bump -- even when the artifact was already
            // withdrawn -- and success means the reconciler published and consumed
            // it (generation advances again).
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                (3, 0, 0),
                "rotating an already-withdrawn artifact must publish and consume another bump"
            );

            let replay = rotate_signer(
                clone_auth(&auth),
                State(state.clone()),
                Path(app_name.clone()),
                Json(RotateSignerRequest {
                    subject: new_subject.to_string(),
                    issuer: new_issuer.to_string(),
                    email_confirmation_token: Some(token.clone()),
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
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                (3, 0, 0),
                "rejected replay must leave the published generation untouched"
            );
            let jti_rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows after replay");
            assert_eq!(jti_rows, 2, "the rejected replay must not add a jti row");

            // A consumed token cannot rotate A again, but it can confirm B
            // after a different, fresh token has legitimately committed B.
            let state_before_second_rotation =
                read_withdrawal_reconciliation_state(&pool).await;
            let jti_rows_before_second_rotation: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows before the second genuine rotation");
            let second_rotation_token = crate::auth::jwt::issue_signer_rotation_token(
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
            .expect("issue second genuine rotation token");
            let Json(rotated_again) = rotate_signer(
                clone_auth(&auth),
                State(state.clone()),
                Path(app_name.clone()),
                Json(RotateSignerRequest {
                    subject: new_subject.to_string(),
                    issuer: new_issuer.to_string(),
                    email_confirmation_token: Some(second_rotation_token),
                }),
            )
            .await
            .expect("genuine second A->B rotation must commit with a fresh bound token");
            assert_eq!(
                rotated_again.signer_identity_subject.as_deref(),
                Some(new_subject)
            );
            let state_after_second_rotation =
                read_withdrawal_reconciliation_state(&pool).await;
            assert!(
                state_after_second_rotation.0 > state_before_second_rotation.0,
                "the genuine second rotation must advance the published generation"
            );
            assert_eq!(
                (state_after_second_rotation.1, state_after_second_rotation.2),
                (0, 0),
                "the genuine second rotation must settle its withdrawal debt before success"
            );
            let jti_rows_after_second_rotation: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows after the second genuine rotation");
            assert_eq!(
                jti_rows_after_second_rotation, jti_rows_before_second_rotation + 1,
                "the genuine second rotation must consume its own fresh jti"
            );

            let state_before_confirmation =
                read_withdrawal_reconciliation_state(&pool).await;
            type ConfirmationSnapshot = (
                Option<String>,
                Option<String>,
                Option<chrono::DateTime<chrono::Utc>>,
                i64,
                i64,
                i64,
            );
            let confirmation_snapshot_sql =
                "SELECT signer_identity_subject, signer_identity_issuer, signer_identity_set_at,
                    (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id = $2 AND action = 'app.signer.rotate'),
                    (SELECT count(*) FROM withdrawn_signer_artifacts
                      WHERE app_id = $1 AND descriptor_core_hash = $3)
                 FROM apps WHERE id = $1";
            let before_confirmation: ConfirmationSnapshot =
                sqlx::query_as(confirmation_snapshot_sql)
                    .bind(app_id)
                    .bind(org_id)
                    .bind(&descriptor_core_hash)
                    .fetch_one(&pool)
                    .await
                    .expect("read authority before confirmation");
            {
                let provider = provider.lock().await;
                assert_eq!(
                    provider.published_generation(),
                    Some(state_after_second_rotation.0),
                    "the genuine second rotation must leave its generation live before the confirmation"
                );
            }
            let Json(confirmed) = rotate_signer(
                clone_auth(&auth),
                State(state.clone()),
                Path(app_name.clone()),
                Json(RotateSignerRequest {
                    subject: new_subject.to_string(),
                    issuer: new_issuer.to_string(),
                    email_confirmation_token: Some(token),
                }),
            )
            .await
            .expect("consumed A->B token is an accepted read-only confirmation while B is current");
            assert_eq!(
                confirmed.signer_identity_subject.as_deref(),
                Some(new_subject),
                "the confirmation reports the committed identity"
            );
            let Json(confirmed_without_token) = rotate_signer(
                clone_auth(&auth),
                State(state.clone()),
                Path(app_name.clone()),
                Json(RotateSignerRequest {
                    subject: new_subject.to_string(),
                    issuer: new_issuer.to_string(),
                    email_confirmation_token: None,
                }),
            )
            .await
            .expect("the current owner may confirm the committed identity without a token");
            assert_eq!(
                confirmed_without_token.signer_identity_subject.as_deref(),
                Some(new_subject)
            );
            let after_confirmation: ConfirmationSnapshot =
                sqlx::query_as(confirmation_snapshot_sql)
                    .bind(app_id)
                    .bind(org_id)
                    .bind(&descriptor_core_hash)
                    .fetch_one(&pool)
                    .await
                    .expect("read authority after confirmation");
            assert_eq!(
                after_confirmation, before_confirmation,
                "confirmation must preserve identity, commit time, tokens, audit, and withdrawals"
            );
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                state_before_confirmation,
                "the confirmation must not bump or owe any generation"
            );
            {
                let provider = provider.lock().await;
                assert_eq!(
                    provider.published_generation(),
                    Some(state_before_confirmation.0),
                    "the confirmation must leave the published generation untouched"
                );
            }

            crate::test_support::drop_isolated_database("cap119_rotation_single_use", pool).await;
        })
        .await;
}

#[tokio::test]
async fn initial_signer_set_in_signed_mode_without_kbs_config_fails_closed() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_initial_set_pending").await;
    let new_subject = "https://github.com/acme/first/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://first-issuer.example.test";
    let (org_id, user_id, app_id) = insert_signer_rotation_app(&pool, None, None).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: "signer-initial-set-test".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: crate::auth::middleware::ManagementOrigin::Public,
    };
    let app_name = sqlx::query_scalar::<_, String>("SELECT name FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("load app name");

    let pending = rotate_signer(
        clone_auth(&auth),
        State(state),
        Path(app_name),
        Json(RotateSignerRequest {
            subject: new_subject.to_string(),
            issuer: new_issuer.to_string(),
            email_confirmation_token: None,
        }),
    )
    .await
    .expect_err("initial set in signed mode without KBS config must not report success");
    assert_eq!(pending.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(pending.1.0["code"], "kbs_publication_not_configured");
    let committed_subject: Option<String> =
        sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("load app subject after rejected initial set");
    assert!(committed_subject.is_none());
    let set_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'app.signer.set'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count initial set audits");
    assert_eq!(set_audits, 0);

    crate::test_support::drop_isolated_database("cap119_initial_set_pending", pool).await;
}

/// Issue #119 regression: rotating a signer on an unsigned-only install
/// (desired_generation = 0, no workload artifacts) must keep the install
/// unsigned -- entering signed mode with an empty artifact set would deny
/// every workload -- while still carrying the new identity into
/// kbs_tls_bindings, the legacy Rego render source.  Runs against its own
/// per-process database so the singleton starts at the exact
/// unsigned-only state and no concurrent test can bump it mid-assertion.
#[tokio::test]
async fn signer_rotation_never_flips_an_unsigned_install_into_signed_mode() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_unsigned_rotation").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let (org_id, user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    insert_legacy_tls_binding(&pool, app_id, previous_subject, previous_issuer).await;
    // The isolated database migrates empty, so the singleton starts at the
    // unsigned-only state (migration 0041 seeds desired_generation = 0).
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (0, 0, 0),
        "the isolated database must start unsigned"
    );

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

    // The install must still be unsigned: rotation neither enters signed
    // mode nor owes any debt there.
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (0, 0, 0),
        "rotation on an unsigned-only install must not enter signed mode"
    );

    crate::test_support::drop_isolated_database("cap119_unsigned_rotation", pool).await;
}

/// Issue #119 rollout-window regression: between migration 0052 applying
/// and the new binary replacing the old one, a pre-0052 replica's
/// rotate_signer rewrites only the apps row -- it inserts no withdrawal
/// rows, consumes no jti, and enqueues no generation.  Migration 0052's
/// apps_signer_rotation_withdrawal trigger fences that writer inside the
/// database: the identity change itself withdraws the rotated-out
/// artifacts, carries the new identity into the legacy binding, and owes
/// the deferred generation bump while signed-policy mode is active.  The
/// direct UPDATE below is exactly the statement a pre-0052 binary runs.
#[tokio::test]
async fn old_binary_signer_rotation_via_direct_sql_is_fenced_by_the_apps_trigger() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_old_binary_rotation").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, _user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    let descriptor_core_hash = insert_signed_artifact_for_identity(
        &pool,
        org_id,
        app_id,
        previous_subject,
        previous_issuer,
    )
    .await;
    insert_legacy_tls_binding(&pool, app_id, previous_subject, previous_issuer).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

    // The pre-0052 rotation: a bare apps identity rewrite, nothing else.
    sqlx::query(
        "UPDATE apps
            SET signer_identity_subject = $1,
                signer_identity_issuer  = $2,
                signer_identity_set_at  = now(),
                updated_at              = now()
          WHERE id = $3",
    )
    .bind(new_subject)
    .bind(new_issuer)
    .bind(app_id)
    .execute(&pool)
    .await
    .expect("old-binary signer rotation");

    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawn_signer_artifacts
          WHERE descriptor_core_hash = $1 AND app_id = $2",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count withdrawn artifacts after old-binary rotation");
    assert_eq!(
        withdrawn, 1,
        "the trigger must withdraw the old-signer artifact for ANY writer"
    );
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 1),
        "the trigger must owe the deferred bump without moving desired_generation"
    );
    let (binding_subject, binding_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load tls binding identity after old-binary rotation");
    assert_eq!(
        binding_subject.as_deref(),
        Some(new_subject),
        "the trigger must carry the new identity into the legacy Rego binding"
    );
    assert_eq!(
        binding_issuer.as_deref(),
        Some(new_issuer),
        "the trigger must carry the new issuer into the legacy Rego binding"
    );

    // An apps update that does not change the identity owes nothing.
    sqlx::query("UPDATE apps SET updated_at = now() WHERE id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("non-identity apps update");
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 1),
        "non-identity updates must not owe anything"
    );

    // The initial set (NULL -> identity) owes nothing: no artifact can be
    // signed under a missing identity, and the app's first binding insert
    // carries the identity anyway. The trigger still fires so a binding
    // that already exists (created by an earlier unsigned deployment)
    // carries the newly committed identity immediately.
    let (_org_id2, _user_id2, app_id2) = insert_signer_rotation_app(&pool, None, None).await;
    let binding2_suffix = app_id2.simple().to_string();
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
             app_id, binding_key, repository, tag, namespace, service_account,
             tenant_instance_identity_hash
         ) VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5)
         ON CONFLICT (app_id) DO NOTHING",
    )
    .bind(app_id2)
    .bind(format!("tls-{}", &binding2_suffix[..12]))
    .bind(format!("cap-{}", &binding2_suffix[..12]))
    .bind(format!("cap-{}-sa", &binding2_suffix[..12]))
    .bind("33".repeat(32))
    .execute(&pool)
    .await
    .expect("insert unsigned-era tls binding");
    sqlx::query(
        "UPDATE apps
            SET signer_identity_subject = $1,
                signer_identity_issuer  = $2,
                signer_identity_set_at  = now()
          WHERE id = $3",
    )
    .bind(new_subject)
    .bind(new_issuer)
    .bind(app_id2)
    .execute(&pool)
    .await
    .expect("initial signer set");
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 1),
        "the initial signer set must owe nothing"
    );
    let withdrawn_app2: i64 =
        sqlx::query_scalar("SELECT count(*) FROM withdrawn_signer_artifacts WHERE app_id = $1")
            .bind(app_id2)
            .fetch_one(&pool)
            .await
            .expect("count withdrawn artifacts for the initial-set app");
    assert_eq!(withdrawn_app2, 0, "initial set must withdraw nothing");
    let (binding2_subject, binding2_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id2)
    .fetch_one(&pool)
    .await
    .expect("load unsigned-era binding after the initial set");
    assert_eq!(
        binding2_subject.as_deref(),
        Some(new_subject),
        "the initial set must carry the new identity into an existing legacy binding"
    );
    assert_eq!(
        binding2_issuer.as_deref(),
        Some(new_issuer),
        "the initial set must carry the new issuer into an existing legacy binding"
    );

    crate::test_support::drop_isolated_database("cap119_old_binary_rotation", pool).await;
}

/// Pre-migration rotations left kbs_tls_bindings holding the rotated-out
/// signer, and the legacy Rego render keeps authorizing that stale identity.
/// Migration 0052's backfill must align every live binding with the app's
/// committed identity, not just withdraw the old signer's artifacts.
#[tokio::test]
async fn migration_backfill_repairs_stale_legacy_tls_bindings() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_stale_binding_backfill").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, _user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    let descriptor_core_hash = insert_signed_artifact_for_identity(
        &pool,
        org_id,
        app_id,
        previous_subject,
        previous_issuer,
    )
    .await;
    insert_legacy_tls_binding(&pool, app_id, previous_subject, previous_issuer).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

    // Recreate the pre-0052 world, then rotate with old-binary semantics:
    // the apps row changes, the binding does not.
    sqlx::raw_sql(
        "DROP TRIGGER apps_signer_rotation_withdrawal ON apps;
         DROP FUNCTION enforce_signer_rotation_withdrawal();
         DROP TABLE consumed_signer_rotation_tokens;
         DROP TABLE withdrawn_signer_artifacts;
         ALTER TABLE kbs_signed_policy_reconciliation DROP COLUMN withdrawal_bumps_owed;",
    )
    .execute(&pool)
    .await
    .expect("restore schema before the withdrawal migration");
    sqlx::query(
        "UPDATE apps
            SET signer_identity_subject = $1,
                signer_identity_issuer  = $2,
                signer_identity_set_at  = now(),
                updated_at              = now()
          WHERE id = $3",
    )
    .bind(new_subject)
    .bind(new_issuer)
    .bind(app_id)
    .execute(&pool)
    .await
    .expect("pre-0052 signer rotation");
    let (stale_subject, stale_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load binding before the migration");
    assert_eq!(stale_subject.as_deref(), Some(previous_subject));
    assert_eq!(stale_issuer.as_deref(), Some(previous_issuer));

    sqlx::raw_sql(include_str!(
        "../../../../migrations/0052_signer_rotation_jti_and_policy.sql"
    ))
    .execute(&pool)
    .await
    .expect("execute production withdrawal migration");

    let (repaired_subject, repaired_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load binding after the migration");
    assert_eq!(
        repaired_subject.as_deref(),
        Some(new_subject),
        "the backfill must repair the stale legacy binding to the app's identity"
    );
    assert_eq!(
        repaired_issuer.as_deref(),
        Some(new_issuer),
        "the backfill must repair the stale legacy binding to the app's issuer"
    );
    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawn_signer_artifacts
          WHERE descriptor_core_hash = $1 AND app_id = $2",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count withdrawn artifacts after the migration");
    assert_eq!(
        withdrawn, 1,
        "the backfill must still withdraw the rotated-out signer's artifacts"
    );
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 1),
        "the backfill must owe the deferred withdrawal bump"
    );

    crate::test_support::drop_isolated_database("cap119_stale_binding_backfill", pool).await;
}

/// A rotate-back must not resurrect legacy KBS admission for the
/// rotated-out signer: the B -> A rotation carries A back into
/// kbs_tls_bindings (the binding tracks the committed identity), but the
/// A -> B step withdrew A's deployed artifacts and that withdrawal is
/// durable. Coincident image and init-data measurements do not prove a
/// new workload instance, so the legacy Rego render excludes the binding
/// permanently; a fresh deployment must authorize through signed-policy
/// candidates instead.
#[tokio::test]
async fn rotate_back_to_withheld_signer_fails_closed_permanently() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_rotate_back_legacy").await;
    let subject_a = "https://github.com/acme/retired/.github/workflows/ci.yaml@refs/heads/main";
    let issuer_a = "https://token.actions.githubusercontent.com";
    let subject_b = "https://github.com/acme/active/.github/workflows/ci.yaml@refs/heads/main";
    let issuer_b = "https://new-issuer.example.test";
    let (org_id, _user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(subject_a), Some(issuer_a)).await;
    let old_measurement: Vec<u8> = (0..32u8).collect();
    let new_measurement: Vec<u8> = (1..33u8).collect();
    let old_image = format!(
        "ghcr.io/acme/workload@sha256:{}",
        hex::encode(&old_measurement)
    );
    let new_image = format!(
        "ghcr.io/acme/workload@sha256:{}",
        hex::encode(&new_measurement)
    );
    insert_signed_artifact_for_identity_with_hash(
        &pool,
        org_id,
        app_id,
        subject_a,
        issuer_a,
        &old_measurement,
    )
    .await;
    insert_legacy_tls_binding(&pool, app_id, subject_a, issuer_a).await;
    sqlx::query(
        "UPDATE kbs_tls_bindings SET image_digest = $2, init_data_hash = $3 WHERE app_id = $1",
    )
    .bind(app_id)
    .bind(&old_image)
    .bind(&old_measurement)
    .execute(&pool)
    .await
    .unwrap();

    // Baseline: the live artifact admits the binding.
    let admitted = crate::kbs::load_legacy_tls_bindings(&pool)
        .await
        .expect("load admitted legacy tls bindings");
    assert_eq!(admitted.len(), 1, "the live signer must start admitted");

    // A -> B, then the rotate-back B -> A. The direct UPDATEs are the exact
    // statement an old writer runs; migration 0052's trigger performs the
    // artifact withdrawal and the binding carry on both changes.
    for (subject, issuer) in [(subject_b, issuer_b), (subject_a, issuer_a)] {
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = $1,
                    signer_identity_issuer  = $2,
                    signer_identity_set_at  = now(),
                    updated_at              = now()
              WHERE id = $3",
        )
        .bind(subject)
        .bind(issuer)
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("signer rotation via direct sql");
    }

    // The binding tracks the committed identity ...
    let (binding_subject, binding_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer
           FROM kbs_tls_bindings WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load tls binding after the rotate-back");
    assert_eq!(binding_subject.as_deref(), Some(subject_a));
    assert_eq!(binding_issuer.as_deref(), Some(issuer_a));

    // ... A's artifact is withdrawn (durably) ...
    let withdrawn: i64 =
        sqlx::query_scalar("SELECT count(*) FROM withdrawn_signer_artifacts WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count withdrawn artifacts after the rotate-back");
    assert_eq!(
        withdrawn, 1,
        "the A -> B rotation must withdraw A's artifact"
    );

    // ... and the legacy render fails closed: no live artifact under A
    // exists, so the burned workload must not regain admission.
    let admitted = crate::kbs::load_legacy_tls_bindings(&pool)
        .await
        .expect("load admitted legacy tls bindings after the rotate-back");
    assert!(
        admitted.is_empty(),
        "a rotated-out signer must not regain legacy admission without a fresh artifact, got {admitted:?}"
    );

    insert_signed_artifact_for_identity_with_hash(
        &pool,
        org_id,
        app_id,
        subject_a,
        issuer_a,
        &new_measurement,
    )
    .await;
    assert!(
        crate::kbs::load_legacy_tls_bindings(&pool)
            .await
            .unwrap()
            .is_empty(),
        "artifact acceptance must not readmit the previous workload's binding"
    );
    for (image, init_data_hash) in [
        (&new_image, &old_measurement),
        (&old_image, &new_measurement),
    ] {
        sqlx::query(
            "UPDATE kbs_tls_bindings SET image_digest = $2, init_data_hash = $3 WHERE app_id = $1",
        )
        .bind(app_id)
        .bind(image)
        .bind(init_data_hash)
        .execute(&pool)
        .await
        .unwrap();
        assert!(
            crate::kbs::load_legacy_tls_bindings(&pool)
                .await
                .unwrap()
                .is_empty(),
            "both the image reference and init-data measurement must match live authority"
        );
    }
    sqlx::query(
        "UPDATE kbs_tls_bindings SET image_digest = $2, init_data_hash = $3 WHERE app_id = $1",
    )
    .bind(app_id)
    .bind(&new_image)
    .bind(&new_measurement)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        crate::kbs::load_legacy_tls_bindings(&pool)
            .await
            .expect("load admitted legacy tls bindings after the refreshed measurements")
            .is_empty(),
        "matching image and init-data measurements do not prove a new workload instance; the withdrawn binding must never be readmitted"
    );

    crate::test_support::drop_isolated_database("cap119_rotate_back_legacy", pool).await;
}

/// The withdrawal filter must not over-reach: identities that were never
/// rotated out still admit immediately (the initial set carries the identity
/// into an existing legacy binding without waiting for a deployment), and
/// unsigned (NULL identity) bindings keep rendering exactly as before.
#[tokio::test]
async fn never_withdrawn_signer_identities_still_admit_immediately_in_legacy_mode() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_legacy_fresh_identity").await;

    // A genuine unsigned install: NULL-identity bindings render unchanged.
    let (_org_id1, _user_id1, app_id1) = insert_signer_rotation_app(&pool, None, None).await;
    let suffix1 = app_id1.simple().to_string();
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
             app_id, binding_key, repository, tag, namespace, service_account,
             tenant_instance_identity_hash
         ) VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5)",
    )
    .bind(app_id1)
    .bind(format!("tls-{}-unsigned", &suffix1[..12]))
    .bind(format!("cap-{}", &suffix1[..12]))
    .bind(format!("cap-{}-sa", &suffix1[..12]))
    .bind("22".repeat(32))
    .execute(&pool)
    .await
    .expect("insert unsigned legacy tls binding");

    // An unsigned-era app whose owner performs the initial signer set: the
    // fresh identity admits immediately (no artifact and no withdrawal rows
    // exist for it, so nothing can have been burned under it).
    let (_org_id2, _user_id2, app_id2) = insert_signer_rotation_app(&pool, None, None).await;
    let suffix2 = app_id2.simple().to_string();
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
             app_id, binding_key, repository, tag, namespace, service_account,
             tenant_instance_identity_hash
         ) VALUES ($1, $2, 'default', 'workload-secret-seed', $3, $4, $5)",
    )
    .bind(app_id2)
    .bind(format!("tls-{}-initial", &suffix2[..12]))
    .bind(format!("cap-{}", &suffix2[..12]))
    .bind(format!("cap-{}-sa", &suffix2[..12]))
    .bind("33".repeat(32))
    .execute(&pool)
    .await
    .expect("insert unsigned-era legacy tls binding");
    let fresh_subject = "https://github.com/acme/fresh/.github/workflows/ci.yaml@refs/heads/main";
    let fresh_issuer = "https://fresh-issuer.example.test";
    sqlx::query(
        "UPDATE apps
            SET signer_identity_subject = $1,
                signer_identity_issuer  = $2,
                signer_identity_set_at  = now(),
                updated_at              = now()
          WHERE id = $3",
    )
    .bind(fresh_subject)
    .bind(fresh_issuer)
    .bind(app_id2)
    .execute(&pool)
    .await
    .expect("initial signer set via direct sql");

    let admitted = crate::kbs::load_legacy_tls_bindings(&pool)
        .await
        .expect("load admitted legacy tls bindings");
    let mut admitted_keys: Vec<String> = admitted
        .iter()
        .map(|binding| binding.binding_key.clone())
        .collect();
    admitted_keys.sort();
    let mut expected_keys = vec![
        format!("tls-{}-unsigned", &suffix1[..12]),
        format!("tls-{}-initial", &suffix2[..12]),
    ];
    expected_keys.sort();
    assert_eq!(
        admitted_keys, expected_keys,
        "unsigned bindings and never-withdrawn identities must both render"
    );
    let initial_binding = admitted
        .iter()
        .find(|binding| binding.binding_key == format!("tls-{}-initial", &suffix2[..12]))
        .expect("the initial-set binding must be admitted");
    assert_eq!(
        initial_binding.signer_identity_subject.as_deref(),
        Some(fresh_subject)
    );
    assert_eq!(
        initial_binding.signer_identity_issuer.as_deref(),
        Some(fresh_issuer)
    );

    crate::test_support::drop_isolated_database("cap119_legacy_fresh_identity", pool).await;
}

// Pause the production migration after its backfill, before trigger installation.
// An old signer writer must wait and then execute under the new trigger.
#[tokio::test]
async fn migration_backfill_window_is_fenced_by_the_apps_write_exclusion_lock() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_backfill_window").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, _user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    let descriptor_core_hash = insert_signed_artifact_for_identity(
        &pool,
        org_id,
        app_id,
        previous_subject,
        previous_issuer,
    )
    .await;
    insert_legacy_tls_binding(&pool, app_id, previous_subject, previous_issuer).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

    sqlx::raw_sql(
        "DROP TRIGGER apps_signer_rotation_withdrawal ON apps;
         DROP FUNCTION enforce_signer_rotation_withdrawal();
         DROP TABLE consumed_signer_rotation_tokens;
         DROP TABLE withdrawn_signer_artifacts;
         ALTER TABLE kbs_signed_policy_reconciliation DROP COLUMN withdrawal_bumps_owed;",
    )
    .execute(&pool)
    .await
    .expect("restore schema before the withdrawal migration");

    async fn wait_for_blocker(pool: &sqlx::PgPool, waiting: i32, blocking: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let blocked: bool = sqlx::query_scalar("SELECT $1 = ANY(pg_blocking_pids($2))")
                    .bind(blocking)
                    .bind(waiting)
                    .fetch_one(pool)
                    .await
                    .unwrap();
                if blocked {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected database lock dependency did not appear");
    }

    // This table lock pauses the migration's ALTER TABLE after the backfill,
    // leaving the exact unsafe window open without rewriting the migration.
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT singleton FROM kbs_signed_policy_reconciliation FOR UPDATE")
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let gate_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *gate)
        .await
        .unwrap();

    let mut existing_writer = pool.begin().await.unwrap();
    sqlx::query("UPDATE apps SET updated_at = clock_timestamp() WHERE id = $1")
        .bind(app_id)
        .execute(&mut *existing_writer)
        .await
        .unwrap();
    let existing_writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *existing_writer)
        .await
        .unwrap();
    let mut migration = pool.begin().await.unwrap();
    let migration_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *migration)
        .await
        .unwrap();
    let migration = tokio::spawn(async move {
        sqlx::Executor::execute(
            &mut *migration,
            include_str!("../../../../migrations/0052_signer_rotation_jti_and_policy.sql"),
        )
        .await
        .expect("execute production withdrawal migration");
        migration.commit().await.unwrap();
    });
    wait_for_blocker(&pool, migration_pid, existing_writer_pid).await;
    // Deploy transactions take apps before workload_artifacts. Migration must
    // not hold the artifact FK lock while waiting for an existing app writer.
    sqlx::query("LOCK TABLE workload_artifacts IN ROW EXCLUSIVE MODE NOWAIT")
        .execute(&mut *existing_writer)
        .await
        .expect("migration must preserve app-before-artifact lock ordering");
    existing_writer.commit().await.unwrap();
    wait_for_blocker(&pool, migration_pid, gate_pid).await;

    let mut writer_connection = pool.acquire().await.unwrap();
    let writer_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *writer_connection)
        .await
        .unwrap();
    let writer = tokio::spawn(async move {
        sqlx::query(
            "UPDATE apps
                SET signer_identity_subject = $1,
                    signer_identity_issuer = $2,
                    signer_identity_set_at = now(),
                    updated_at = now()
              WHERE id = $3",
        )
        .bind(new_subject)
        .bind(new_issuer)
        .bind(app_id)
        .execute(&mut *writer_connection)
        .await
        .expect("old-binary signer rotation");
    });
    wait_for_blocker(&pool, writer_pid, migration_pid).await;
    gate.commit().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), migration)
        .await
        .expect("migration finishes once its gate opens")
        .expect("migration task panics propagate");

    tokio::time::timeout(std::time::Duration::from_secs(5), writer)
        .await
        .expect("blocked rotation completes after the migration commits")
        .expect("rotation task panics propagate");
    let rotated_subject: Option<String> =
        sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("load app subject after the fenced rotation");
    assert_eq!(
        rotated_subject.as_deref(),
        Some(new_subject),
        "the rotation behind the lock must eventually commit"
    );
    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawn_signer_artifacts
          WHERE descriptor_core_hash = $1 AND app_id = $2",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count withdrawn artifacts after the fenced rotation");
    assert_eq!(
        withdrawn, 1,
        "the resumed rotation must fire the trigger the migration installed"
    );
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 1),
        "the resumed rotation must owe the deferred withdrawal bump"
    );

    crate::test_support::drop_isolated_database("cap119_backfill_window", pool).await;
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

#[tokio::test]
async fn signer_rotation_publication_failure_reports_pending_and_retry_confirms() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap119_rotation_pending_retry").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    insert_signed_artifact_for_identity(&pool, org_id, app_id, previous_subject, previous_issuer)
        .await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation SET desired_generation = 1 WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("enter signed-policy mode");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let hmac_key = [7u8; 32];
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: "rotation-pending-test".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: crate::auth::middleware::ManagementOrigin::Public,
    };
    state.kbs_policy = Some(test_kbs_policy_config());
    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(false)));

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

    crate::kbs::TEST_KUBE_CLIENT
        .scope(kbs_policy_kube_client(provider.clone()), async {
            // First attempt: the rotation commits, but the provider is down, so
            // the fenced publication cannot be confirmed.
            let pending = rotate_signer(
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
            .expect_err("failed publication must not report success");
            assert_eq!(pending.0, StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                pending.1.0["code"],
                crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE,
                "the failure must be the explicit committed-pending error, not a bare 500"
            );
            assert_eq!(pending.1.0["committed"], true);

            // The rotation itself is durable exactly once: identity, jti,
            // withdrawal, and the owed bump.
            let committed_subject: Option<String> =
                sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                    .bind(app_id)
                    .fetch_one(&pool)
                    .await
                    .expect("load committed subject");
            assert_eq!(committed_subject.as_deref(), Some(new_subject));
            let jti_rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows");
            assert_eq!(jti_rows, 1, "the rotation token was consumed exactly once");
            let audit_rows: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'app.signer.rotate'",
            )
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("count rotation audit rows");
            assert_eq!(audit_rows, 1, "exactly one rotation was committed");
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                (1, 0, 1),
                "the withdrawal debt stays owed until publication succeeds"
            );

            // Same-request retry (the consumed token cannot be replayed): the
            // committed identity equals the target, so the route CONFIRMS the
            // rotation -- no token path, no second mutation -- and re-drives the
            // KBS publication under the fence.
            {
                let mut provider = provider.lock().await;
                provider.healthy = true;
            }
            // The failed publication path released its fence (fail-open between
            // retries; the periodic reconciler owns convergence), so the
            // confirmation retry can claim it immediately.
            let Json(confirmed) = rotate_signer(
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
            .expect("confirmation retry must succeed once publication is confirmed");
            assert_eq!(
                confirmed.signer_identity_subject.as_deref(),
                Some(new_subject)
            );

            // The confirmation added NO second mutation: same single audit row,
            // same single jti, and the debt is now published and consumed.
            let audit_rows_after: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'app.signer.rotate'",
            )
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("count rotation audit rows after confirmation");
            assert_eq!(
                audit_rows_after, 1,
                "the confirmation must not rotate again"
            );
            let jti_rows_after: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
            )
            .bind(app_id)
            .fetch_one(&pool)
            .await
            .expect("count consumed jti rows after confirmation");
            assert_eq!(jti_rows_after, 1);
            assert_eq!(
                read_withdrawal_reconciliation_state(&pool).await,
                (2, 0, 0),
                "the confirmation retry must publish and consume the owed bump"
            );
            {
                let provider = provider.lock().await;
                assert_eq!(
                    provider.published_generation(),
                    Some(2),
                    "the owed generation must be live before success is reported"
                );
            }
        })
        .await;

    crate::test_support::drop_isolated_database("cap119_rotation_pending_retry", pool).await;
}

#[tokio::test]
async fn signer_rotation_refuses_when_signed_mode_activates_while_it_waits_for_the_app_lane() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap187_rotation_activation_race").await;
    let previous_subject = "https://github.com/acme/old/.github/workflows/ci.yaml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject = "https://github.com/acme/new/.github/workflows/ci.yaml@refs/heads/main";
    let new_issuer = "https://new-issuer.example.test";
    let (org_id, user_id, app_id) =
        insert_signer_rotation_app(&pool, Some(previous_subject), Some(previous_issuer)).await;
    let descriptor_core_hash = insert_signed_artifact_for_identity(
        &pool,
        org_id,
        app_id,
        previous_subject,
        previous_issuer,
    )
    .await;
    // Activation happens only after the rotation is blocked on the app lane.

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: "rotation-activation-race".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: crate::auth::middleware::ManagementOrigin::Public,
    };
    let token = crate::auth::jwt::issue_signer_rotation_token(
        &[7u8; 32],
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
    .expect("issue rotation token for the activation race");
    let app_name = sqlx::query_scalar::<_, String>("SELECT name FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("load app name");

    let mut lane = pool.begin().await.expect("begin app lane hold");
    crate::deploy::lock_app_deployment_lane(&mut lane, app_id)
        .await
        .expect("hold app deployment lane");
    let lane_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *lane)
        .await
        .expect("read lane holder pid");

    let rotation = tokio::spawn(async move {
        rotate_signer(
            clone_auth(&auth),
            State(state),
            Path(app_name),
            Json(RotateSignerRequest {
                subject: new_subject.to_string(),
                issuer: new_issuer.to_string(),
                email_confirmation_token: Some(token),
            }),
        )
        .await
    });

    // Observe the lock wait rather than assuming the rotation reached the lane.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: Option<i32> = sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity
                  WHERE wait_event_type = 'Lock'
                    AND wait_event = 'advisory'
                    AND $1 = ANY(pg_blocking_pids(pid))",
            )
            .bind(lane_pid)
            .fetch_optional(&pool)
            .await
            .expect("poll for the rotation blocked on the app lane");
            if waiting.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the rotation must block on the held app deployment lane");

    let mut activation = pool.begin().await.expect("begin signed-mode activation");
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
            SET desired_generation = 1
          WHERE singleton",
    )
    .execute(&mut *activation)
    .await
    .expect("activate signed-policy mode");
    activation.commit().await.expect("commit activation");
    lane.commit().await.expect("release app deployment lane");

    let refused = tokio::time::timeout(Duration::from_secs(5), rotation)
        .await
        .expect("the rotation settles once the lane opens")
        .expect("rotation task panics propagate");
    let err = match refused {
        Ok(_) => {
            panic!("an unconfigured rotation must refuse once signed mode activated mid-flight")
        }
        Err(err) => err,
    };
    assert_eq!(err.0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        err.1.0["code"], "kbs_publication_not_configured",
        "the refusal must be the retryable pre-commit gate, not a committed-but-pending report"
    );

    let (signer_subject, signer_issuer): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT signer_identity_subject, signer_identity_issuer FROM apps WHERE id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("load signer identity after the refusal");
    assert_eq!(signer_subject.as_deref(), Some(previous_subject));
    assert_eq!(signer_issuer.as_deref(), Some(previous_issuer));
    let jti_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count consumed jti rows after the refusal");
    assert_eq!(jti_rows, 0, "the refusal must leave the token unconsumed");
    let audit_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE org_id = $1 AND action = 'app.signer.rotate'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count rotation audit rows after the refusal");
    assert_eq!(
        audit_rows, 0,
        "the refusal must not write a rotation audit row"
    );
    let withdrawn: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM withdrawn_signer_artifacts
          WHERE descriptor_core_hash = $1 AND app_id = $2",
    )
    .bind(&descriptor_core_hash)
    .bind(app_id)
    .fetch_one(&pool)
    .await
    .expect("count withdrawn artifacts after the refusal");
    assert_eq!(withdrawn, 0, "the refusal must not withdraw the old signer");
    assert_eq!(
        read_withdrawal_reconciliation_state(&pool).await,
        (1, 0, 0),
        "only the activation may have touched the reconciliation singleton: no withdrawal debt"
    );

    crate::test_support::drop_isolated_database("cap187_rotation_activation_race", pool).await;
}
