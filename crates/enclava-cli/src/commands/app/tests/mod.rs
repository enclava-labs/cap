use super::*;
use crate::commands::app::signing::platform_release_from_deployment_context_with_verifier;
use enclava_cli::app_config::{AppSection, ResourcesSection, StorageSection, UnlockSection};
use enclava_cli::platform_release::PlatformReleaseEnvelope;

fn test_release() -> PlatformRelease {
    PlatformRelease {
            schema_version: "v1".to_string(),
            platform_release_version: "test".to_string(),
            signing_service_url: "https://signing.example.test".to_string(),
            signing_service_pubkey_hex: "11".repeat(32),
            policy_template_id: "trustee-resource-policy-v1".to_string(),
            policy_template_sha256: "22".repeat(32),
            policy_template_text: "package policy\n".to_string(),
            attestation_proxy_image:
                "ghcr.io/enclava-labs/attestation-proxy@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            caddy_ingress_image:
                "ghcr.io/enclava-labs/caddy-ingress@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            trustee_kbs_url: "https://kbs.example.test:8080".to_string(),
            trustee_kbs_ca_cert_pem: String::new(),
            tenant_caddy_tls_mode: "internal".to_string(),
            tenant_caddy_acme_ca: "https://acme-staging-v02.api.letsencrypt.org/directory"
                .to_string(),
            expected_firmware_measurement: "00".repeat(32),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            genpolicy_version: "test-genpolicy".to_string(),
            created_at: "2026-05-09T00:00:00Z".to_string(),
        }
}

fn test_app_response() -> AppResponse {
    AppResponse {
        id: "22222222-2222-2222-2222-222222222222".to_string(),
        name: "demo".to_string(),
        namespace: "cap-org-demo".to_string(),
        instance_id: "org-22222222".to_string(),
        service_account: Some("cap-demo-sa".to_string()),
        bootstrap_owner_pubkey_hash: Some("33".repeat(32)),
        tenant_instance_identity_hash: Some("44".repeat(32)),
        domain: "demo.org.enclava.dev".to_string(),
        app_domain: None,
        tee_domain: Some("demo.org.tee.enclava.dev".to_string()),
        custom_domain: None,
        status: "created".to_string(),
        unlock_mode: "password".to_string(),
        signer_identity_subject: Some(
            "https://github.com/acme/demo/.github/workflows/image.yml@refs/heads/main".to_string(),
        ),
        signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        template_slug: None,
        template_version: None,
        template_expected: TemplateExpected::default(),
        created_at: "2026-05-09T00:00:00Z".to_string(),
    }
}

fn test_app_config() -> AppConfig {
    AppConfig {
        app: AppSection {
            name: "demo".to_string(),
            port: 3338,
            command: vec!["/bin/demo".to_string()],
        },
        storage: StorageSection {
            paths: vec!["/data".to_string()],
            size: "1Gi".to_string(),
            tls_size: "1Gi".to_string(),
        },
        unlock: UnlockSection {
            mode: "password".to_string(),
        },
        services: HashMap::new(),
        resources: ResourcesSection {
            cpu: "1".to_string(),
            memory: "1Gi".to_string(),
        },
        health: None,
    }
}

fn test_deployment_context() -> DeploymentContextResponse {
    DeploymentContextResponse {
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        tls_certificate_broker_url: None,
        current_platform_release_id: None,
        platform_release_envelope: None,
    }
}

#[test]
fn deployment_context_platform_release_is_verified_and_selected() {
    let envelope = PlatformReleaseEnvelope {
        payload: test_release(),
        signature: "33".repeat(64),
        signing_pubkey: "44".repeat(32),
    };
    let expected_release_id = envelope.payload.platform_release_version.clone();
    let deployment_context = DeploymentContextResponse {
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        tls_certificate_broker_url: None,
        current_platform_release_id: Some(expected_release_id.clone()),
        platform_release_envelope: Some(envelope),
    };

    let release =
        platform_release_from_deployment_context_with_verifier(&deployment_context, |envelope| {
            Ok::<_, &'static str>(envelope.payload)
        })
        .expect("context release verifies")
        .expect("context release present");

    assert_eq!(release.platform_release_version, expected_release_id);
}

#[test]
fn deployment_context_platform_release_tampering_fails_closed() {
    let envelope = PlatformReleaseEnvelope {
        payload: test_release(),
        signature: "33".repeat(64),
        signing_pubkey: "44".repeat(32),
    };
    let deployment_context = DeploymentContextResponse {
        api_signing_pubkey: "test-api-signing-pubkey".to_string(),
        tls_certificate_broker_url: None,
        current_platform_release_id: Some(envelope.payload.platform_release_version.clone()),
        platform_release_envelope: Some(envelope),
    };

    let err =
        platform_release_from_deployment_context_with_verifier(&deployment_context, |_envelope| {
            Err::<PlatformRelease, _>("bad signature")
        })
        .expect_err("invalid context release must not fall back to bundled release")
        .to_string();

    assert!(
        err.contains("invalid platform_release_envelope"),
        "unexpected error: {err}"
    );
}

#[test]
fn signed_cc_hash_app_uses_local_artifact_urls_like_live_apply() {
    let app = confidential_app_for_cc_hash(
            &test_app_response(),
            &test_app_config(),
            ConfidentialAppForCcHash {
                image: enclava_common::image::ImageRef::parse(
                    "ghcr.io/acme/demo@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                deployment_id: uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555")
                    .unwrap(),
                release: &test_release(),
                workload_artifact_binding: WorkloadArtifactBinding {
                    descriptor_core_hash: [1; 32],
                    descriptor_signing_pubkey: [2; 32],
                    org_keyring_fingerprint: [3; 32],
                },
                generated_agent_policy: GeneratedAgentPolicy {
                    policy_text: "package agent_policy\n".to_string(),
                    policy_sha256: Sha256::digest(b"package agent_policy\n").into(),
                    genpolicy_version_pin: "test-genpolicy".to_string(),
                },
                deployment_context: test_deployment_context(),
                unlock_mode: "password",
                tenant_id: "org".to_string(),
                tenant_instance_identity_hash: [4; 32],
                bootstrap_owner_pubkey_hash: "33".repeat(32),
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                log_encryption: None,
            },
        )
        .unwrap();
    assert_eq!(app.api_signing_pubkey, "test-api-signing-pubkey");

    let cc_toml = cc_init_data::build_toml_with_options(
        &app,
        &cc_init_data::CcInitDataOptions {
            kbs_url: "https://kbs.example.test:8080".to_string(),
            kbs_ca_cert_pem: None,
            runtime_class: cc_init_data::DEFAULT_RUNTIME_CLASS.to_string(),
        },
    );

    assert!(
        cc_toml.contains(
            "workload_artifacts_url = \"file:///etc/enclava-init/workload-artifacts.json\""
        )
    );
    assert!(
        cc_toml.contains("trustee_policy_url = \"file:///etc/enclava-init/trustee-policy.json\"")
    );
}

#[test]
fn signed_cc_hash_app_uses_api_deployment_context_without_env_exports() {
    let mut release = test_release();
    release.tenant_caddy_tls_mode = "dns01-broker".to_string();
    let deployment_context = DeploymentContextResponse {
        api_signing_pubkey: "context-api-signing-pubkey".to_string(),
        tls_certificate_broker_url: Some(
            "http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
                .to_string(),
        ),
        current_platform_release_id: None,
        platform_release_envelope: None,
    };

    let app = confidential_app_for_cc_hash(
            &test_app_response(),
            &test_app_config(),
            ConfidentialAppForCcHash {
                image: enclava_common::image::ImageRef::parse(
                    "ghcr.io/acme/demo@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                deployment_id: uuid::Uuid::parse_str("11111111-2222-3333-4444-555555555555")
                    .unwrap(),
                release: &release,
                workload_artifact_binding: WorkloadArtifactBinding {
                    descriptor_core_hash: [1; 32],
                    descriptor_signing_pubkey: [2; 32],
                    org_keyring_fingerprint: [3; 32],
                },
                generated_agent_policy: GeneratedAgentPolicy {
                    policy_text: "package agent_policy\n".to_string(),
                    policy_sha256: Sha256::digest(b"package agent_policy\n").into(),
                    genpolicy_version_pin: "test-genpolicy".to_string(),
                },
                deployment_context,
                unlock_mode: "password",
                tenant_id: "org".to_string(),
                tenant_instance_identity_hash: [4; 32],
                bootstrap_owner_pubkey_hash: "33".repeat(32),
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                log_encryption: None,
            },
        )
        .unwrap();
    assert_eq!(app.api_signing_pubkey, "context-api-signing-pubkey");

    let cc_toml = cc_init_data::build_toml_with_options(
        &app,
        &cc_init_data::CcInitDataOptions {
            kbs_url: "https://kbs.example.test:8080".to_string(),
            kbs_ca_cert_pem: None,
            runtime_class: cc_init_data::DEFAULT_RUNTIME_CLASS.to_string(),
        },
    );

    assert!(cc_toml.contains(
            "tls_certificate_broker_url = \"http://cap-api.cap.svc.cluster.local/api/v1/workload/tls/dns01-certificate\""
        ));
    assert!(cc_toml.contains("tls_certificate_hostnames = \"[\\\"demo.org.enclava.dev\\\"]\""));
}

#[test]
fn deploy_unlocks_existing_password_storage_before_config_push() {
    assert!(deploy_should_unlock_before_config(true, false, true));
    assert!(!deploy_should_unlock_before_config(true, true, true));
    assert!(deploy_should_unlock_before_config(true, false, false));
    assert!(!deploy_should_unlock_before_config(false, false, true));
}

#[test]
fn deploy_unlocks_existing_password_storage_even_without_config_push() {
    assert!(deploy_should_unlock_before_config(true, false, false));
}

#[test]
fn stable_ssh_endpoint_from_app_requires_debian_ssh_template_metadata() {
    let mut app = test_app_response();
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::NotStableTemplate
    );

    app.template_slug = Some("mini-enclava-go".to_string());
    app.template_expected.stable_ssh_endpoint = Some("6.tcp.eu.ngrok.io:17958".to_string());
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::NotStableTemplate
    );

    app.template_slug = Some("debian-ssh-ngrok".to_string());
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::Ready("6.tcp.eu.ngrok.io:17958".to_string())
    );

    app.template_expected.stable_ssh_endpoint = None;
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::Missing
    );

    app.template_expected.stable_ssh_endpoint = Some("   ".to_string());
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::Missing
    );

    app.template_expected.stable_ssh_endpoint =
        Some(" TCP://6.TCP.EU.NGROK.IO.:00123 ".to_string());
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::Invalid
    );

    app.template_expected.stable_ssh_endpoint = Some("example.com:22".to_string());
    assert_eq!(
        stable_ssh_endpoint_state_from_app(&app),
        StableSshEndpointState::Invalid
    );
}

#[test]
fn deploy_claims_fresh_created_password_app_when_unlock_status_is_unavailable() {
    assert!(deploy_needs_initial_claim(true, None, "creating"));
}

#[test]
fn deploy_preflights_password_input_before_remote_side_effects() {
    let source = include_str!("../../app.rs");
    let deploy_start = source.find("pub async fn deploy").expect("deploy exists");
    let deploy_end = source[deploy_start..]
        .find("// Phase 1: Deploy")
        .expect("phase 1 follows deploy setup")
        + deploy_start;
    let setup = &source[deploy_start..deploy_end];

    let password_input = setup
        .find("StoragePasswordInput::from_file_option")
        .expect("deploy prepares storage password input");
    let preflight = setup
        .find("storage_password.ensure_available_for_password_mode")
        .expect("deploy preflights password input availability");
    let sign = setup
        .find("build_signed_deploy_blobs")
        .expect("deploy signs local blobs before remote deployment");
    let remote_deploy = source[deploy_start..]
        .find("api.deploy")
        .expect("deploy mutates remote app")
        + deploy_start;

    assert!(
        password_input < preflight && preflight < sign && deploy_end < remote_deploy,
        "password-mode deploy must verify password input before signing and before remote mutation"
    );
}

#[test]
fn deploy_accepts_storage_password_file_flag() {
    use clap::Parser as _;

    let cli = crate::commands::Cli::try_parse_from([
        "enclava",
        "deploy",
        "--image",
        "ghcr.io/acme/demo@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "--storage-password-file",
        "/tmp/enclava-password",
    ])
    .expect("deploy should accept storage password file");

    let crate::commands::Command::Deploy(args) = cli.command else {
        panic!("expected deploy command");
    };
    assert_eq!(
        args.storage_password_file.as_deref(),
        Some(std::path::Path::new("/tmp/enclava-password"))
    );
}

#[test]
fn deploy_bootstrap_probe_attests_before_calling_claim_endpoint() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("wait_for_bootstrap_endpoint exists");
    let fn_end = source[fn_start..]
        .find("async fn wait_for_deploy_runtime")
        .expect("wait_for_deploy_runtime follows wait_for_bootstrap_endpoint")
        + fn_start;
    let body = &source[fn_start..fn_end];

    let attest = body
        .find("attest_receipt_key")
        .expect("bootstrap readiness probe must attest the TEE TLS leaf");
    let challenge = body
        .find("bootstrap_challenge")
        .expect("bootstrap readiness probe must query challenge endpoint");
    assert!(
        attest < challenge,
        "deploy must verify attestation/SPKI binding before probing bootstrap challenge"
    );
}

#[test]
fn deploy_bootstrap_probe_uses_short_probe_timeout_client() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("wait_for_bootstrap_endpoint exists");
    let fn_end = source[fn_start..]
        .find("async fn wait_for_deploy_runtime")
        .expect("wait_for_deploy_runtime follows wait_for_bootstrap_endpoint")
        + fn_start;
    let body = &source[fn_start..fn_end];

    assert!(
        body.contains("TeeClient::new_for_ownership_probe_with_resolve_ip"),
        "bootstrap readiness probes must not inherit the long claim/unlock request timeout"
    );
}

#[test]
fn deploy_runtime_wait_falls_back_to_attested_tee_status() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn wait_for_deploy_runtime")
        .expect("wait_for_deploy_runtime exists");
    let fn_end = source[fn_start..]
        .find("async fn ensure_password_storage_unlocked_for_config")
        .expect("ensure_password_storage_unlocked_for_config follows wait_for_deploy_runtime")
        + fn_start;
    let body = &source[fn_start..fn_end];

    let endpoint = body
        .find("get_unlock_endpoint")
        .expect("runtime wait must resolve the direct TEE endpoint");
    let tee = body
        .find("TeeClient::new_for_ownership")
        .expect("runtime wait must use the ownership timeout TEE client");
    let attest = body
        .find("attest_receipt_key")
        .expect("runtime wait must attest the direct TEE status endpoint");
    let status = body
        .find("status_json")
        .expect("runtime wait must read direct TEE status");
    assert!(
        endpoint < tee && tee < attest && attest < status && body.contains("tee_unlock_state"),
        "deploy runtime wait must not depend only on API status when the direct TEE status is available"
    );
    assert!(
        body.contains("observation_is_fresh")
            && body.contains("if observation_is_fresh && target.accepts_api_status")
            && body.contains("pod_phase_is_verified")
            && body.contains(".is_none_or(|observation| observation.state == \"fresh\")")
            && body.contains("observation.state == \"fresh\"")
            && body.contains("status.status != \"failed\""),
        "new observations must be fresh while legacy responses without observation remain compatible"
    );
}

#[test]
fn status_command_falls_back_to_attested_tee_status() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("pub async fn status")
        .expect("status function exists");
    let fn_end = source[fn_start..]
        .find("#[derive(Args)]\npub struct LogsArgs")
        .expect("logs args follow status function")
        + fn_start;
    let body = &source[fn_start..fn_end];

    let api_status = body
        .find("api.get_status")
        .expect("status command must read API status");
    let endpoint = body
        .find("get_unlock_endpoint")
        .expect("status command must resolve the direct TEE endpoint");
    let tee = body
        .find("TeeClient::new_for_ownership")
        .expect("status command must use the ownership timeout TEE client");
    let attest = body
        .find("attest_receipt_key")
        .expect("status command must attest the direct TEE status endpoint");
    let state = body
        .find("tee_unlock_state")
        .expect("status command must interpret the direct TEE state");
    assert!(
        api_status < endpoint && endpoint < tee && tee < attest && attest < state,
        "status must fall back to attested direct TEE state when API live status lacks TEE fields"
    );
}

#[test]
fn status_command_surfaces_stable_ssh_endpoint_with_validating_follow_up() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("pub async fn status")
        .expect("status function exists");
    let fn_end = source[fn_start..]
        .find("#[derive(Args)]\npub struct LogsArgs")
        .expect("logs args follow status function")
        + fn_start;
    let body = &source[fn_start..fn_end];

    assert!(body.contains("Stable SSH endpoint: {endpoint}"));
    assert!(
        body.contains("Validate:  enclava template ssh-command --name {app_name} --wait"),
        "status should show a follow-up command that reads the stored stable SSH endpoint"
    );
    assert!(
        body.contains("\"running\" | \"ready\" | \"healthy\" => status.status.green().to_string()"),
        "status should render hosted healthy status vocabulary consistently"
    );
    assert!(
        body.contains(
            "\"creating\" | \"deploying\" | \"applying\" | \"pending\" => status.status.yellow().to_string()"
        ),
        "status should render hosted pending status vocabulary consistently"
    );
    assert!(
        body.contains("Stable SSH endpoint metadata missing; redeploy the template so PaaS reserves a stable SSH endpoint"),
        "status should make legacy Debian SSH apps without stable SSH endpoint metadata actionable"
    );
    assert!(
        body.contains("Stable SSH endpoint metadata invalid; redeploy the template so PaaS reserves a stable SSH endpoint"),
        "status should make corrupt Debian SSH endpoint metadata actionable"
    );
}

#[test]
fn log_output_sanitizer_removes_terminal_control_sequences() {
    let raw = "ok \u{1b}[31mred\u{1b}[0m \u{1b}]0;title\u{7} done\r";
    let sanitized = super::sanitize_log_output(raw);

    assert_eq!(sanitized, "ok red  done?");
    assert!(!sanitized.contains('\u{1b}'));
}

#[test]
fn logs_command_points_missing_scope_to_explicit_reapproval() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("pub async fn logs")
        .expect("logs function exists");
    let fn_end = source[fn_start..]
        .find("#[derive(Args)]\npub struct RollbackArgs")
        .expect("rollback args follow logs function")
        + fn_start;
    let body = &source[fn_start..fn_end];

    assert!(body.contains("message.contains(\"apps:logs\")"));
    assert!(body.contains("enclava login --approve-logs"));
    assert!(body.contains("sanitize_log_output"));
}

#[test]
fn logs_command_decrypts_encrypted_frames_locally() {
    use enclava_common::log_encryption::{
        LogFrameContext, encrypt_log_frame, generate_log_keypair, validate_public_key,
    };

    let keypair = generate_log_keypair();
    let recipient = validate_public_key(
        "logs-selected",
        &keypair.public_key_base64url,
        &keypair.public_key_sha256,
    )
    .unwrap();
    let context = LogFrameContext {
        org_id: "org-123".to_string(),
        app_name: "secure-app".to_string(),
        deployment_id: "deploy-123".to_string(),
    };
    let frame = encrypt_log_frame(
        &recipient,
        &context,
        1,
        "stderr",
        "app",
        "2026-07-05T00:00:00Z",
        b"tenant secret plaintext",
    )
    .unwrap();
    let line = serde_json::to_string(&frame).unwrap();

    let output = super::decrypted_log_frame_output(&keypair.private_key_base64url, &line).unwrap();

    assert_eq!(
        output,
        "2026-07-05T00:00:00Z app stderr tenant secret plaintext"
    );
    assert!(!line.contains("tenant secret plaintext"));
}

#[test]
fn default_log_private_key_path_sanitizes_components() {
    let paths =
        enclava_cli::config::CliPaths::from_root(std::path::PathBuf::from("/tmp/enclava")).unwrap();

    let path = super::default_log_private_key_path(&paths, "../app/name", "logs/../../key");

    assert_eq!(
        path,
        std::path::PathBuf::from("/tmp/enclava/keys/logs/.._app_name-logs_.._.._key.x25519")
    );
}

#[tokio::test]
async fn generated_log_key_registration_keeps_private_material_local() {
    use base64::Engine as _;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt as _;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let request_body = request.split("\r\n\r\n").nth(1).unwrap();
        let payload: serde_json::Value = serde_json::from_str(request_body).unwrap();
        let public_key = payload["public_key_base64url"].as_str().unwrap();
        let public_key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(public_key)
            .unwrap();
        let body = serde_json::json!({
            "key_id": "shell-logs",
            "algorithm": "x25519-hpke-v1",
            "public_key_base64url": public_key,
            "public_key_sha256": enclava_common::log_encryption::public_key_sha256(&public_key_bytes),
            "label": "Hosted template app shell",
            "status": "active",
            "active_for_app": true,
            "selected_at": "2026-07-14T00:00:00Z",
            "created_at": "2026-07-14T00:00:00Z",
            "revoked_at": null
        })
        .to_string();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        request
    });

    let temp = tempfile::tempdir().unwrap();
    let paths = CliPaths::from_root(temp.path().join("cli")).unwrap();
    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let generated = generate_log_key_for_app(
        &api,
        &paths,
        "shell",
        "shell-logs",
        Some("Hosted template app shell".to_string()),
        None,
        true,
    )
    .await
    .unwrap();
    let private_key = std::fs::read_to_string(&generated.private_key_file).unwrap();
    let request = handle.join().unwrap();

    assert!(request.starts_with("POST /apps/shell/logs/keys "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(request.contains(r#""key_id":"shell-logs""#));
    assert!(request.contains(r#""activate_for_app":true"#));
    assert!(!request.contains(private_key.trim()));
    assert_eq!(
        std::fs::metadata(&generated.private_key_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[tokio::test]
async fn generated_log_key_retry_reuses_matching_registered_key() {
    use enclava_common::log_encryption::generate_log_keypair;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let keypair = generate_log_keypair();
    let response_public_key = keypair.public_key_base64url.clone();
    let response_public_key_sha256 = keypair.public_key_sha256.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = serde_json::json!({
            "app_name": "shell",
            "active_key_id": "shell-logs",
            "keys": [{
                "key_id": "shell-logs",
                "algorithm": "x25519-hpke-v1",
                "public_key_base64url": response_public_key,
                "public_key_sha256": response_public_key_sha256,
                "label": "Hosted template app shell",
                "status": "active",
                "active_for_app": true,
                "selected_at": "2026-07-14T00:00:00Z",
                "created_at": "2026-07-14T00:00:00Z",
                "revoked_at": null
            }]
        })
        .to_string();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let temp = tempfile::tempdir().unwrap();
    let paths = CliPaths::from_root(temp.path().join("cli")).unwrap();
    paths.ensure_dirs().unwrap();
    let private_key_file = temp.path().join("shell-logs.x25519");
    super::write_private_log_key(&private_key_file, &keypair.private_key_base64url).unwrap();
    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));

    let generated = generate_log_key_for_app(
        &api,
        &paths,
        "shell",
        "shell-logs",
        Some("Hosted template app shell".to_string()),
        Some(private_key_file.clone()),
        true,
    )
    .await
    .unwrap();
    let request = handle.join().unwrap();

    assert!(request.starts_with("GET /apps/shell/logs/keys "));
    assert_eq!(generated.key.key_id, "shell-logs");
    assert_eq!(generated.private_key_file, private_key_file);
    assert_eq!(
        std::fs::read_to_string(&private_key_file).unwrap().trim(),
        keypair.private_key_base64url
    );
}

#[tokio::test]
async fn generated_log_key_rejects_mismatched_registration_response() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = serde_json::json!({
            "key_id": "shell-logs",
            "algorithm": "x25519-hpke-v1",
            "public_key_base64url": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "public_key_sha256": "sha256:stale",
            "label": null,
            "status": "active",
            "active_for_app": true,
            "selected_at": "2026-07-15T00:00:00Z",
            "created_at": "2026-07-15T00:00:00Z",
            "revoked_at": null
        })
        .to_string();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .unwrap();
        String::from_utf8_lossy(&buf[..n]).to_string()
    });

    let temp = tempfile::tempdir().unwrap();
    let paths = CliPaths::from_root(temp.path().join("cli")).unwrap();
    let private_key_file = temp.path().join("shell-logs.x25519");
    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));

    let error = match generate_log_key_for_app(
        &api,
        &paths,
        "shell",
        "shell-logs",
        None,
        Some(private_key_file.clone()),
        true,
    )
    .await
    {
        Ok(_) => panic!("mismatched registration response must be rejected"),
        Err(error) => error.to_string(),
    };
    handle.join().unwrap();

    assert!(error.contains("does not match API log key `shell-logs`"));
    assert!(
        private_key_file.exists(),
        "local key remains available for a safe retry"
    );
}

#[tokio::test]
async fn generated_log_key_retry_rejects_loose_private_key_permissions() {
    use enclava_common::log_encryption::generate_log_keypair;
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let paths = CliPaths::from_root(temp.path().join("cli")).unwrap();
    paths.ensure_dirs().unwrap();
    let private_key_file = temp.path().join("shell-logs.x25519");
    let keypair = generate_log_keypair();
    super::write_private_log_key(&private_key_file, &keypair.private_key_base64url).unwrap();
    std::fs::set_permissions(&private_key_file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let api = ApiClient::new("http://127.0.0.1:1", Some("test-token".to_string()));

    let error = match generate_log_key_for_app(
        &api,
        &paths,
        "shell",
        "shell-logs",
        None,
        Some(private_key_file),
        true,
    )
    .await
    {
        Ok(_) => panic!("loosely permissioned private key must be rejected"),
        Err(error) => error.to_string(),
    };

    assert!(error.contains("has insecure permissions 0644"));
    assert!(error.contains("chmod 600"));
}

#[test]
fn attested_locked_state_overrides_only_running_status() {
    assert_eq!(
        status_with_attested_tee_state("running", "locked"),
        "locked"
    );
    assert_eq!(
        status_with_attested_tee_state("creating", "locked"),
        "creating"
    );
    assert_eq!(status_with_attested_tee_state("failed", "locked"), "failed");
}

#[test]
fn password_redeploy_wait_does_not_accept_stale_unlocked_runtime() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn wait_for_deploy_runtime")
        .expect("wait_for_deploy_runtime exists");
    let fn_end = source[fn_start..]
        .find("async fn ensure_password_storage_unlocked_for_config")
        .expect("ensure_password_storage_unlocked_for_config follows wait_for_deploy_runtime")
        + fn_start;
    let body = &source[fn_start..fn_end];

    assert!(
        source.contains("DeployRuntimeTarget::PasswordLocked"),
        "runtime wait must have a password-redeploy mode"
    );
    assert!(
        body.contains("target.accepts_direct_unlocked()"),
        "password redeploy wait must gate direct unlocked status so old pods cannot satisfy the new rollout"
    );
}

#[test]
fn deploy_waits_on_returned_deployment_record() {
    let source = include_str!("../../app.rs");
    let deploy_start = source
        .find("pub async fn deploy")
        .expect("deploy function exists");
    let deploy_end = source[deploy_start..]
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("wait_for_bootstrap_endpoint follows deploy")
        + deploy_start;
    let body = &source[deploy_start..deploy_end];

    let deploy_call = body.find("api.deploy").expect("deploy calls API");
    let apply_wait = body
        .find("wait_for_deployment_apply_start")
        .expect("deploy must wait for the returned deployment to start applying");
    let runtime_wait = body
        .find("wait_for_deploy_runtime")
        .expect("deploy waits for TEE runtime");
    let completion_wait = body
        .find("wait_for_deployment_completion")
        .expect("deploy must wait for the returned deployment to complete");
    assert!(
        deploy_call < apply_wait && apply_wait < runtime_wait && runtime_wait < completion_wait,
        "deploy must not let stale app status from the previous pod satisfy the new deployment"
    );
    assert!(
        body.contains("resp.deployment_id"),
        "deployment waits must be tied to the deployment returned by POST /deploy"
    );
}

#[test]
fn deploy_password_unlock_attests_before_reading_or_unlocking_storage() {
    let source = include_str!("../../app.rs");
    let fn_start = source
        .find("async fn ensure_password_storage_unlocked_for_config")
        .expect("ensure_password_storage_unlocked_for_config exists");
    let fn_end = source[fn_start..]
        .find("fn tee_unlock_state")
        .expect("tee_unlock_state follows ensure_password_storage_unlocked_for_config")
        + fn_start;
    let body = &source[fn_start..fn_end];

    let attest = body
        .find("attest_receipt_key")
        .expect("password unlock helper must attest the TEE TLS leaf");
    let status = body
        .find("status_json")
        .expect("password unlock helper must read TEE status");
    let unlock = body
        .find("tee.unlock")
        .expect("password unlock helper must call unlock");
    assert!(
        attest < status && attest < unlock,
        "deploy must use the attested/SPKI-pinned client for status and password unlock"
    );
}

#[test]
fn deploy_config_push_attests_before_setting_values() {
    let source = include_str!("../../app.rs");
    let phase_start = source
        .find("// Phase 4: Push config if --set was used")
        .expect("config push phase exists");
    let phase_end = source[phase_start..]
        .find("// Phase 4: Health check")
        .expect("health check phase follows config push")
        + phase_start;
    let body = &source[phase_start..phase_end];

    let attest = body
        .find("attest_receipt_key")
        .expect("deploy config push must attest the TEE TLS leaf");
    let set = body
        .find("config_set")
        .expect("deploy config push must set config values");
    assert!(
        attest < set,
        "deploy config delivery must verify attestation/SPKI binding before writing config"
    );
}

#[test]
fn deploy_health_timeout_is_not_reported_as_success() {
    let source = include_str!("../../app.rs");
    let phase_start = source
        .find("// Phase 4: Health check")
        .expect("health check phase exists");
    let phase_end = source[phase_start..]
        .find("println!();")
        .expect("health check phase is followed by deploy summary")
        + phase_start;
    let body = &source[phase_start..phase_end];

    assert!(
        !body.contains("Deployed (health check timed out)"),
        "deploy must fail when the runtime health check times out"
    );
}

#[test]
fn deploy_health_timeout_covers_generated_readiness_delay() {
    let deploy_health_timeout = Duration::from_secs(DEPLOY_HEALTH_TIMEOUT_SECONDS);
    let generated_readiness_delay_with_jitter = Duration::from_secs(240);

    assert!(
        deploy_health_timeout >= generated_readiness_delay_with_jitter,
        "deploy health timeout must cover the 180s generated readiness delay plus rollout jitter"
    );
}

#[test]
fn parse_config_inputs_reads_values_from_files() {
    let temp = tempfile::tempdir().unwrap();
    let secret_path = temp.path().join("spark-api-key");
    std::fs::write(&secret_path, "secret-value\n").unwrap();

    let pairs = parse_config_inputs(
        &["MINT_BACKEND_BOLT11_SAT=SparkWallet".to_string()],
        &[format!("MINT_SPARK_API_KEY={}", secret_path.display())],
    )
    .unwrap();

    assert_eq!(
        pairs,
        vec![
            (
                "MINT_BACKEND_BOLT11_SAT".to_string(),
                "SparkWallet".to_string()
            ),
            ("MINT_SPARK_API_KEY".to_string(), "secret-value".to_string()),
        ]
    );
}

#[test]
fn storage_password_file_trims_newlines_and_rejects_empty() {
    let temp = tempfile::tempdir().unwrap();
    let password_path = temp.path().join("storage-password");
    std::fs::write(&password_path, "secret value\r\n").unwrap();
    assert_eq!(
        read_storage_password_file(&password_path).unwrap(),
        "secret value"
    );

    let empty_path = temp.path().join("empty-password");
    std::fs::write(&empty_path, "\n").unwrap();
    assert!(
        read_storage_password_file(&empty_path)
            .unwrap_err()
            .to_string()
            .contains("is empty")
    );
}
