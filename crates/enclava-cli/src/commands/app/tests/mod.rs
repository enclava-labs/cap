use super::*;
use crate::commands::app::signing::platform_release_from_deployment_context_with_verifier;
use enclava_cli::app_config::{AppSection, ResourcesSection, StorageSection, UnlockSection};
use enclava_cli::platform_release::PlatformReleaseEnvelope;
#[tokio::test]
async fn stalled_pre_claim_org_read_stops_at_the_hold_deadline_without_claiming() {
    use tokio::io::AsyncReadExt;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stalled pre-claim fixture");
    let addr = listener
        .local_addr()
        .expect("stalled pre-claim fixture addr");
    let (connections, mut seen) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let _ = connections.send(());
            tokio::spawn(async move {
                let mut request = [0_u8; 1024];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                std::future::pending::<()>().await;
                drop(stream);
            });
        }
    });
    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let directory = tempfile::tempdir().expect("fixture state directory");
    let paths = CliPaths::from_root(directory.path().to_path_buf()).expect("fixture state root");
    let storage_password = StoragePasswordInput::from_file_option(None)
        .expect("interactive storage password input for the fixture");

    let deadline = Instant::now() + Duration::from_millis(300);
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(2),
        claim_initial_ownership(
            &api,
            &paths,
            "shell",
            DeploymentWait::trusted("deploy-1", None),
            &storage_password,
            MnemonicCapture::Store,
            Some(deadline),
        ),
    )
    .await
    .expect("ownership preparation must respect the hold deadline")
    .expect_err("a stalled pre-claim org read must stop without claiming");

    assert!(
        started.elapsed() >= Duration::from_millis(200),
        "the claim flow must run until the deadline, returned after {:?}",
        started.elapsed()
    );
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the stalled pre-claim read must stop at the hold deadline instead of the 900s request cap, took {:?}",
        started.elapsed()
    );
    tokio::time::timeout(Duration::from_secs(1), seen.recv())
        .await
        .expect("the stalled org lookup must have been recorded")
        .expect("the fixture must stay alive for the assertion");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), seen.recv())
            .await
            .is_err(),
        "no TEE attestation, challenge, or claim connection may follow the stalled pre-claim read"
    );
}

fn test_release() -> PlatformRelease {
    PlatformRelease {
            schema_version: "v1".to_string(),
            platform_release_version: "test".to_string(),
            signing_service_url: "https://signing.example.test".to_string(),
            signing_service_pubkey_hex: "11".repeat(32),
            platform_trustee_policy_pubkey_hex: "33".repeat(32),
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
            luks2_header_seal: "adopt".to_string(),
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
fn create_unlock_mode_validation_rejects_auto_with_workaround() {
    // auto is a post-claim transition (via `auto-unlock enable`), never a first-deploy
    // mode — there is no owner seed to wrap at create time.
    let err = validate_create_unlock_mode("auto").unwrap_err();
    assert!(
        err.contains("auto-unlock enable"),
        "error should name the workaround: {err}",
    );
    assert!(validate_create_unlock_mode("password").is_ok());
}

#[test]
fn optional_app_name_uses_loaded_config() {
    let app_name = optional_app_name_from_config_result(Ok(test_app_config()))
        .expect("valid config")
        .expect("app name");
    assert_eq!(app_name, "demo");
}

#[test]
fn optional_app_name_suppresses_only_missing_enclava_toml() {
    let app_name = optional_app_name_from_config_result(Err(AppConfigError::ReadFile {
        path: "/tmp/project/enclava.toml".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing"),
    }))
    .expect("a genuinely missing enclava.toml enables org scope");
    assert_eq!(app_name, None);

    let current_dir_error = optional_app_name_from_config_result(Err(AppConfigError::ReadFile {
        path: ".".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "cwd unavailable"),
    }))
    .expect_err("current-directory errors must not be hidden");
    assert!(matches!(current_dir_error, AppConfigError::ReadFile { .. }));
}

#[test]
fn optional_app_name_propagates_malformed_and_invalid_config() {
    let parse_error = optional_app_name_from_config_result(AppConfig::parse("["))
        .expect_err("malformed enclava.toml must fail closed");
    assert!(matches!(parse_error, AppConfigError::Parse(_)));

    let validation_error = optional_app_name_from_config_result(Err(AppConfigError::Validation(
        "invalid app config".to_string(),
    )))
    .expect_err("invalid enclava.toml must fail closed");
    assert!(matches!(validation_error, AppConfigError::Validation(_)));
}

#[test]
fn manual_deploy_keyring_always_checks_remote_state() {
    let source = include_str!("../signing.rs");
    let body = source
        .split("pub(crate) async fn ensure_manual_deploy_keyring")
        .nth(1)
        .unwrap()
        .split("fn render_trustee_policy")
        .next()
        .unwrap();
    let local_check = body.find("verify_keyring").unwrap();
    let remote_check = body.find("api.get_org_keyring").unwrap();

    assert!(local_check < remote_check);
    assert!(!body[local_check..remote_check].contains("return Ok"));
}

#[test]
fn manual_deploy_keyring_always_bootstraps_the_signing_service() {
    let source = include_str!("../signing.rs");
    let body = source
        .split("pub(crate) async fn ensure_manual_deploy_keyring")
        .nth(1)
        .unwrap()
        .split("fn render_trustee_policy")
        .next()
        .unwrap();

    assert_eq!(body.matches(".bootstrap_signing_service_owner").count(), 1);
    assert!(
        body.find(".bootstrap_signing_service_owner").unwrap()
            > body.find("match api.get_org_keyring").unwrap()
    );
}

#[test]
fn deployment_requires_explicit_recoverable_setup_and_login_has_no_keyring_side_effect() {
    let signing = include_str!("../signing.rs");
    let auth = include_str!("../../auth.rs");

    assert!(signing.contains("ensure_manual_deploy_keyring(api, paths, true).await?"));
    assert!(signing.contains("enclava key setup --backup-out <offline-backup.json>"));
    assert!(!auth.contains("ensure_manual_deploy_keyring"));
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
                    omit_log_encryption_claim: false,
                    legacy_collapsed_trustee_key: false,
            omit_luks2_header_seal_claim: false,
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
            luks2_header_seal: "adopt".to_string(),
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
                    omit_log_encryption_claim: false,
                    legacy_collapsed_trustee_key: false,
            omit_luks2_header_seal_claim: false,
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
            luks2_header_seal: "adopt".to_string(),
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
fn deploy_gate_follows_live_ownership_outside_creating() {
    // A failed first deploy leaves the app `failed` + unclaimed: the gate
    // must fire on the live ownership state, not on the status alone.
    assert!(deploy_needs_initial_claim(
        true,
        Some("unclaimed"),
        "failed"
    ));
    assert!(!deploy_needs_initial_claim(true, Some("locked"), "failed"));
    assert!(!deploy_needs_initial_claim(true, None, "failed"));
}

#[test]
fn deploy_preflight_gate_fails_closed_on_unresolved_ownership() {
    // The preflight status read is a TEE query: unresolved ownership must
    // gate before submission (the strand this gate exists to prevent), while
    // the post-submit predicate keeps its None fallback (above) so claimed
    // redeploys never loop into the claim wait.
    assert!(deploy_preflight_needs_claim(true, None, "failed"));
    assert!(deploy_preflight_needs_claim(true, None, "creating"));
    assert!(!deploy_preflight_needs_claim(false, None, "failed"));
    assert!(deploy_preflight_needs_claim(
        true,
        Some("unclaimed"),
        "failed"
    ));
    assert!(!deploy_preflight_needs_claim(
        true,
        Some("locked"),
        "failed"
    ));
}

#[test]
fn deploy_preflight_reads_live_ownership_before_the_claim_gate() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
    let deploy_start = source.find("pub async fn deploy").expect("deploy exists");
    let deploy_end = source[deploy_start..]
        .find("// Phase 1: Deploy")
        .expect("phase 1 follows deploy setup")
        + deploy_start;
    let setup = &source[deploy_start..deploy_end];

    let ownership_read = setup
        .find("preflight_ownership = api")
        .expect("deploy reads live ownership before the gate");
    let gate = setup
        .find("ensure_claim_session_now")
        .expect("deploy gates the claim session");
    let gate_decision = setup
        .find("preflight_ownership.as_deref()")
        .expect("the gate decision consumes the prefetched ownership state");
    assert!(
        ownership_read < gate_decision && gate_decision < gate,
        "ownership must be read before the gate decision, and the decision before the session gate"
    );
}

#[test]
fn destroy_failure_hint_covers_lane_conflicts_and_teardown_failures() {
    let busy = destroy_failure_hint(
        Some("app mutation already in progress"),
        "app mutation already in progress (held by: app_delete) (retry after ~30s)",
        "shell",
    )
    .expect("busy 409 gets operator prose");
    assert!(busy.contains("mutation lane"), "got: {busy}");

    let deferred = destroy_failure_hint(Some("idempotency_request_in_progress"), "", "shell")
        .expect("deferred 409 gets operator prose");
    assert!(deferred.contains("idempotency lease"), "got: {deferred}");

    let locked = destroy_failure_hint(Some("app_delete_teardown_locked"), "", "shell")
        .expect("locked teardown gets operator prose");
    assert!(
        locked.contains("enclava unlock --app shell"),
        "got: {locked}"
    );
    // Hosted deferrals carry the locked cause only in-band.
    let locked_in_band = destroy_failure_hint(
        Some("app mutation already in progress"),
        "cause: app_delete_teardown_locked",
        "shell",
    )
    .expect("in-band cause gets operator prose");
    assert!(locked_in_band.contains("enclava unlock --app shell"));

    let unavailable = destroy_failure_hint(Some("app_delete_teardown_unavailable"), "", "shell")
        .expect("failed teardown gets operator prose");
    assert!(
        unavailable.contains("did not complete") && unavailable.contains("retry destroy"),
        "got: {unavailable}"
    );
    let restored = destroy_failure_hint(
        Some("app_delete_teardown_unavailable"),
        "app_delete_teardown_unavailable (app_restored)",
        "shell",
    )
    .expect("restored disposition gets operator prose");
    assert!(
        restored.contains("restored to its previous state"),
        "got: {restored}"
    );
    let kept = destroy_failure_hint(
        Some("app_delete_teardown_unavailable"),
        "app_delete_teardown_unavailable (app_kept_deleting)",
        "shell",
    )
    .expect("kept-deleting disposition gets operator prose");
    assert!(
        kept.contains("remains in the deleting state"),
        "got: {kept}"
    );

    assert!(destroy_failure_hint(Some("other_error"), "", "shell").is_none());
    assert!(destroy_failure_hint(None, "", "shell").is_none());
}

#[test]
fn deploy_preflights_password_input_before_remote_side_effects() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
fn deployment_failure_message_includes_api_error_code_detail() {
    let deployment = DeploymentEntry {
        id: "deploy-123".to_string(),
        status: "failed".to_string(),
        image_digest: None,
        // Bounded classification codes now cross the CAP projection
        // allowlist verbatim (#18): a KBS signed-policy budget rejection
        // surfaces as its own code, not opaque plaintext.
        error_message: Some("signed_policy_budget_exceeded".to_string()),
        template_slug: None,
        template_version: None,
        template_expected: Default::default(),
        created_at: "2026-07-03T15:48:25Z".to_string(),
        completed_at: None,
    };

    assert_eq!(
        template_deployment_failure_message(&deployment, "deploy-123"),
        "deployment deploy-123 failed: signed_policy_budget_exceeded"
    );
}

#[test]
fn deploy_waits_fail_fast_on_terminal_deployment_failure() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");

    for (fn_name, deadline_message, blocking_call, bounded_check) in [
        (
            "async fn wait_for_bootstrap_endpoint",
            "TEE ownership timed out",
            "api.get_unlock_endpoint(app_name)",
            "fail_if_template_deployment_failed(apiapp_namedeployment_idstart+max_wait&muthistory)",
        ),
        (
            "async fn wait_for_deploy_runtime",
            "TEE boot timed out",
            "api.get_status(app_name)",
            "fail_if_template_deployment_failed(apiapp_nameexpected_deployment_idstart+max_wait&muthistory)",
        ),
    ] {
        let fn_start = source
            .find(fn_name)
            .unwrap_or_else(|| panic!("{fn_name} must exist so standalone app deploy waits exist"));
        let body = &source[fn_start..];
        let wait_loop = body.find("loop {").expect("wait loop exists");
        let deadline = body
            .find(deadline_message)
            .unwrap_or_else(|| panic!("{fn_name} must keep its deadline guard"));
        let failure_check = body
            .find("fail_if_template_deployment_failed")
            .unwrap_or_else(|| {
                panic!("{fn_name} must poll for a terminal deployment failure (#18)")
            });
        let blocking = body
            .find(blocking_call)
            .unwrap_or_else(|| panic!("{fn_name} must keep its readiness poll"));
        assert!(
            wait_loop < deadline && deadline < failure_check,
            "{fn_name}: check the wait deadline before polling deployment history (cap#220 review), so an unresponsive API cannot extend the wait past its budget"
        );
        assert!(
            failure_check < blocking,
            "{fn_name}: the terminal-failure check must run inside the wait loop before the (potentially blocking) readiness request, so a manifest-apply rejection (e.g. KBS signed-policy budget) fails fast instead of timing out ~10 minutes later (#18)"
        );
        // Whitespace- and comma-insensitive so rustfmt line wrapping cannot
        // break the wiring check: the failure check must receive the wait's
        // deadline and the shared detached history probe (cap#220 review
        // follow-ups).
        let dense: String = body
            .chars()
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect();
        assert!(
            dense.contains(bounded_check),
            "{fn_name}: the failure check must take its observation from the detached history probe, bounded by the wait's deadline (cap#220 review follow-ups)"
        );
    }

    // The sibling deployment-history lookups (apply-start and health waits)
    // receive the wait's deadline and the same detached probe: they are how
    // deploy state is observed at all, so their requests must outlive any
    // per-attempt budget (a slow-but-valid answer is observed when it lands)
    // while never blocking the loop or outliving the wait (cap#220 review
    // follow-ups).
    let dense_source: String = source
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();
    assert_eq!(
        dense_source
            .matches("find_deployment_entry(apiapp_namedeployment_idstart+max_wait&muthistory)")
            .count(),
        2,
        "wait_for_deployment_apply_start and wait_for_deployment_completion must observe history through the detached probe (cap#220 review follow-ups)"
    );

    // The standalone ownership wait must not swallow non-retryable
    // unlock-endpoint errors until the 900s budget: it fetches the endpoint
    // lazily inside the loop and routes fetch failures through the same
    // retry predicate as the template wait (auth/decode/404 fail fast).
    let fn_start = source
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("standalone ownership wait exists");
    let body = &source[fn_start..];
    assert!(
        body.contains("should_retry_template_bootstrap_endpoint_error"),
        "endpoint fetch errors must go through the template retry predicate, not an unconditional retry"
    );
}

#[test]
fn wait_attempt_budget_is_finite_and_bounded_by_the_wait() {
    // Far deadline: the per-attempt budget is finite (so a stalled attempt is
    // cut and the loop retries) and comfortably long (so slow-but-valid
    // responses are observed).
    let far = std::time::Instant::now() + std::time::Duration::from_secs(600);
    assert_eq!(wait_attempt_budget(far), WAIT_ATTEMPT_BUDGET);
    assert_eq!(WAIT_ATTEMPT_BUDGET, std::time::Duration::from_secs(60));
    // Nearly exhausted wait: only the remaining time may be used.
    let nearly_exhausted = std::time::Instant::now() + std::time::Duration::from_millis(300);
    let budget = wait_attempt_budget(nearly_exhausted);
    assert!(budget > std::time::Duration::ZERO);
    assert!(budget <= std::time::Duration::from_millis(300));
    // Exhausted wait: no request may start at all.
    assert!(wait_attempt_budget(std::time::Instant::now()).is_zero());
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .unwrap_or_else(std::time::Instant::now);
    assert!(wait_attempt_budget(past).is_zero());
}

#[test]
fn success_exit_settles_requests_with_the_per_attempt_budget() {
    // cap#220 review follow-up: the exit gate's wait for pending history
    // requests is bounded by the same finite per-attempt budget as the
    // readiness polls (60s, min'd with the wait's remaining time by
    // wait_attempt_budget), never a separate advisory cap: earlier reviews
    // rejected a short cap because a slow-but-valid failure answer at 16s+
    // is an observation, not a stall. On expiry the request is reconciled
    // with the success instead of failing a ready deployment.
    let source = include_str!("../../app.rs");
    let gate_start = source
        .find("pub(crate) async fn reconcile_success_with_deployment_history")
        .expect("the gate must exist");
    let gate_end = source[gate_start..]
        .find("\nasync fn find_deployment_entry")
        .expect("find_deployment_entry must follow the gate")
        + gate_start;
    let gate = &source[gate_start..gate_end];
    assert!(
        gate.contains("take_settled_within(wait_attempt_budget(wait_deadline)"),
        "the gate must settle its requests within the per-attempt budget (cap#220 review follow-up)"
    );
    assert!(
        gate.contains("history.force_request(api, app_name, wait_deadline)"),
        "the gate must ask for a current observation at the exit (cap#220 review follow-up): a pre-gate non-failure may predate the failure"
    );
    assert!(
        !gate.contains("SUCCESS_RECONCILE_BUDGET") && !gate.contains("success_reconcile_budget"),
        "the gate must not carry a separate advisory budget cap (rejected in earlier reviews)"
    );
}

#[test]
fn wait_loop_requests_use_the_finite_per_attempt_budget() {
    // cap#220 review follow-ups: every synchronous request a wait loop makes
    // -- the readiness polls (unlock endpoint, runtime status, config keys,
    // SSH command) and the direct-TEE probes (attest, challenge) -- is cut
    // at one finite per-attempt budget, bounded by the wait's remaining
    // time. The deployment-history lookups (the terminal-failure check and
    // the apply-start/health state lookups) run on the detached probe
    // instead: their answers are the loops' source of truth, so they must
    // observe slow-but-valid responses (the 70s-history false timeout) while
    // never blocking the loop or outliving the wait (the stalled-history
    // false timeout).
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
    let template_source = include_str!("../../template.rs").replace("\r\n", "\n");
    // Whitespace- and comma-insensitive: rustfmt may wrap call arguments
    // one-per-line (adding a trailing comma) without changing the wiring.
    let dense = |text: &str| -> String {
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect()
    };
    let app = dense(&source);
    let template = dense(&template_source);

    let failure_check = {
        let start = source
            .find("async fn template_deployment_failure(")
            .expect("terminal-failure check exists");
        let end = start
            + source[start..]
                .find("fn template_deployment_failure_message(")
                .expect("failure message helper follows the check");
        &source[start..end]
    };
    assert!(
        dense(failure_check).contains("history.ensure_request(apiapp_namewait_deadline)")
            && dense(failure_check).contains("history.take_landed().await"),
        "the terminal-failure check must take its observation from the detached history probe (cap#220 review follow-ups): a slow answer is observed whenever it lands, and the shared client's 900s request timeout must never consume the wait"
    );
    assert!(
        !failure_check.contains("bounded_wait_attempt") && !failure_check.contains("timeout("),
        "the terminal-failure check must never block on deployment history (cap#220 review follow-up #2): even a 30s template wait must still poll its ready TEE endpoint"
    );

    let state_lookup = {
        let start = source
            .find("async fn find_deployment_entry(")
            .expect("deployment-state lookup exists");
        let end = start
            + source[start..]
                .find("async fn wait_for_deployment_apply_start(")
                .expect("apply-start wait follows the state lookup");
        &source[start..end]
    };
    assert!(
        dense(state_lookup).contains("history.ensure_request(apiapp_namewait_deadline)")
            && dense(state_lookup).contains("history.take_landed().await"),
        "the deployment-state lookup must take its observation from the detached history probe (cap#220 review follow-ups): slow responses stay observable while a stall never blocks the loop"
    );
    assert!(
        !state_lookup.contains("bounded_wait_attempt") && !state_lookup.contains("timeout("),
        "the deployment-state lookup must never block on deployment history (cap#220 review follow-up #2)"
    );

    // Readiness polls are bounded the same way (cap#220 review follow-up):
    // a stalled status/endpoint call must not eat the wait or hide the
    // failure check's observations behind it.
    assert!(
        app.contains("bounded_wait_attempt(start+max_waitapi.get_status(app_name))"),
        "wait_for_deploy_runtime must bound its status poll per attempt (cap#220 review follow-up)"
    );
    assert!(
        app.matches("bounded_wait_attempt(start+max_waitapi.get_unlock_endpoint(app_name))")
            .count()
            >= 2,
        "wait_for_bootstrap_endpoint and the runtime diagnostic chain must bound their endpoint fetches per attempt (cap#220 review follow-up)"
    );
    assert!(
        template.contains(
            "bounded_wait_attempt(wait_deadlinetimings.run(DeployPhase::BootstrapEndpointAcquisitionapi.get_unlock_endpoint(app_name)))"
        ),
        "wait_for_template_bootstrap_endpoint must bound its endpoint fetch per attempt (cap#220 review follow-up)"
    );
    // And the remaining wait-loop requests from the self-check warning:
    // the direct-TEE attest in the runtime wait, plus the managed-config and
    // SSH polls in the hosted template waits.
    assert!(
        app.matches("bounded_wait_attempt(start+max_waittee.attest_receipt_key())")
            .count()
            >= 2,
        "wait_for_deploy_runtime and wait_for_bootstrap_endpoint must bound their direct-TEE attest per attempt (cap#220 review follow-up #2)"
    );
    assert!(
        app.contains("bounded_wait_attempt(start+max_waitattested_tee.bootstrap_challenge())"),
        "wait_for_bootstrap_endpoint must bound its bootstrap challenge per attempt (cap#220 review follow-up #3)"
    );
    assert!(
        template.contains(
            "bounded_wait_attempt(wait_deadlinetimings.run(DeployPhase::BootstrapAttestationtee.attest_receipt_key()))"
        ),
        "wait_for_template_bootstrap_endpoint must bound its attest per attempt (cap#220 review follow-up #3)"
    );
    assert!(
        template.contains(
            "bounded_wait_attempt(wait_deadlinetimings.run(DeployPhase::BootstrapChallengeattested_tee.bootstrap_challenge()))"
        ),
        "wait_for_template_bootstrap_endpoint must bound its bootstrap challenge per attempt (cap#220 review follow-up #3)"
    );
    assert!(
        template.contains("bounded_wait_attempt(deadlineapi.list_config_keys(instance_name))"),
        "wait_for_paas_managed_config_keys must bound its status poll per attempt (cap#220 review follow-up #2)"
    );
    assert!(
        template
            .contains("bounded_wait_attempt(start+timeoutapi.get_template_ssh_command(app_name))"),
        "wait_for_paas_ssh_command must bound its status poll per attempt (cap#220 review follow-up #2)"
    );
}

#[test]
fn managed_config_cut_reads_retry_until_the_wait_deadline() {
    // cap#220 review follow-up: `bounded_wait_attempt`'s `None` covers both
    // a passed wait deadline and a read cut at the 60s per-attempt budget.
    // Only the first is a timeout: a cut read with wait time remaining must
    // retry on the next tick, not fail the whole managed-config wait.
    let template = include_str!("../../template.rs").replace("\r\n", "\n");
    let wait_start = template
        .find("async fn wait_for_paas_managed_config_keys")
        .expect("the managed-config wait must exist");
    let wait_end = template[wait_start..]
        .find("\n/// One poll of this call's managed-config delivery receipt.")
        .expect("the delivery-receipt poll doc must follow the wait")
        + wait_start;
    let wait = &template[wait_start..wait_end];
    assert!(
        wait.contains("None if Instant::now() < deadline =>"),
        "a read cut at the per-attempt budget must retry on the next tick while the wait deadline is open (cap#220 review follow-up)"
    );
    // The retry arm must come before the terminal `None =>` expiry arm so a
    // cut read can never take the deadline-reached error.
    let retry_arm = wait
        .find("None if Instant::now() < deadline =>")
        .expect("the cut-read retry arm must exist");
    let expiry_arm = wait[retry_arm..]
        .find("None =>")
        .expect("the terminal None arm must exist")
        + retry_arm;
    assert!(retry_arm < expiry_arm);
    // The delivery-receipt poll has the same two-faced `None`: a cut read
    // reports pending while the wait is open, so a stalled delivery-status
    // request cannot abort the wait through the poll's Err. It must also run
    // under `bounded_wait_attempt` (the 60s per-attempt budget), not plain
    // `bounded_request` (deadline-only), so one stalled read cannot hold the
    // loop until the client's 900s request timeout.
    let dense = |text: &str| -> String {
        text.chars()
            .filter(|c| !c.is_whitespace() && *c != ',')
            .collect()
    };
    let poll_start = template[wait_end..]
        .find("async fn poll_managed_delivery_status")
        .expect("the delivery-receipt poll must exist")
        + wait_end;
    let poll = &template[poll_start..];
    assert!(
        dense(poll).contains(
            "bounded_wait_attempt(deadlineapi.managed_config_delivery_status(instance_namedelivery_id))"
        ),
        "poll_managed_delivery_status must bound its read per attempt, not only by the deadline (cap#220 review follow-up)"
    );
    assert!(
        poll.contains("None if Instant::now() < deadline =>"),
        "poll_managed_delivery_status must treat a cut read as pending while the wait deadline is open (cap#220 review follow-up)"
    );
}

#[test]
fn deploy_wait_success_exits_reconcile_deployment_state_first() {
    // cap#220 review follow-up: readiness alone must not end a wait that
    // polls deployment history -- a failed deployment would proceed to
    // ownership handling before its history answer lands. Every successful
    // exit of those waits therefore carries exactly one reconciliation with
    // the detached probe (one per `return Ok(`), so a new success exit
    // cannot silently skip it.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
    let template_source = include_str!("../../template.rs").replace("\r\n", "\n");
    let body_between = |text: &str, start: &str, end: &str| -> String {
        let start_index = text
            .find(start)
            .unwrap_or_else(|| panic!("{start} must exist"));
        let end_index = text[start_index..]
            .find(end)
            .unwrap_or_else(|| panic!("{end} must follow {start}"))
            + start_index;
        text[start_index..end_index].to_string()
    };
    for (fn_name, text, start, end) in [
        (
            "wait_for_bootstrap_endpoint",
            source.as_str(),
            "async fn wait_for_bootstrap_endpoint",
            "async fn wait_for_deploy_runtime",
        ),
        (
            "wait_for_deploy_runtime",
            source.as_str(),
            "async fn wait_for_deploy_runtime",
            "fn observation_is_fresh_for_deployment",
        ),
        (
            "wait_for_deployment_apply_start",
            source.as_str(),
            "async fn wait_for_deployment_apply_start",
            "async fn wait_for_deployment_completion",
        ),
        (
            "wait_for_deployment_completion",
            source.as_str(),
            "async fn wait_for_deployment_completion",
            "async fn ensure_password_storage_unlocked_for_config",
        ),
        (
            "wait_for_template_bootstrap_endpoint",
            template_source.as_str(),
            "async fn wait_for_template_bootstrap_endpoint",
            "pub(crate) fn should_retry_template_bootstrap_endpoint_error",
        ),
        (
            "wait_for_paas_managed_config_keys",
            template_source.as_str(),
            "async fn wait_for_paas_managed_config_keys",
            "async fn refresh_template_config_token_with_retry",
        ),
        (
            "wait_for_paas_ssh_command",
            template_source.as_str(),
            "async fn wait_for_paas_ssh_command",
            "async fn latest_deployment_id",
        ),
    ] {
        let body = body_between(text, start, end);
        let exits = body.matches("return Ok(").count();
        let reconciliations = body
            .matches("reconcile_success_with_deployment_history(")
            .count();
        assert!(exits > 0, "{fn_name} must have successful exits to gate");
        assert_eq!(
            exits, reconciliations,
            "{fn_name}: every successful exit must reconcile the pending deployment-state observation first (cap#220 review follow-up); {exits} `return Ok(` vs {reconciliations} reconciliations"
        );
    }
}

#[test]
fn deploy_progress_does_not_redraw_during_interactive_secret_prompts() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
    let deploy_start = source
        .find("pub async fn deploy")
        .expect("deploy function exists");
    let deploy_end = source[deploy_start..]
        .find("async fn wait_for_bootstrap_endpoint")
        .expect("bootstrap helper follows deploy")
        + deploy_start;
    let body = &source[deploy_start..deploy_end];

    assert!(
        !body.contains("enable_steady_tick"),
        "deploy progress must not redraw during password, unlock, or recovery-mnemonic prompts"
    );
}

#[test]
fn deploy_bootstrap_probe_attests_before_calling_claim_endpoint() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
        .find("bounded_status_json")
        .expect("runtime wait must read direct TEE status through the bounded safe path");
    let classify = body
        .find("direct_tee_runtime_outcome")
        .expect("runtime wait must classify terminal diagnostics from the direct status");
    let poll_loop = body.find("loop {").expect("runtime wait must poll");
    assert!(
        poll_loop < endpoint
            && endpoint < tee
            && tee < attest
            && attest < status
            && status < classify
            && body.contains("tee_supplemental_fields_are_consistent"),
        "deploy runtime wait must refresh and attest the direct TEE endpoint while polling"
    );
    assert!(
        body.contains("observation_is_fresh")
            && body.contains("if observation_is_fresh && target.accepts_api_status")
            && body.contains("pod_phase_is_verified")
            && body
                .contains("observation.deployment_id.as_deref() == Some(expected_deployment_id)")
            && body.contains("observation.state == \"fresh\"")
            && body.contains("direct_tee_allowed")
            && body.contains("status.status != \"failed\""),
        "new observations must be fresh and deployment-bound while legacy responses without observation remain compatible"
    );
}

fn deploy_observation(
    state: &str,
    reason: Option<&str>,
    deployment_id: Option<&str>,
    drifted: bool,
) -> AppStatusObservation {
    AppStatusObservation {
        state: state.to_string(),
        reason: reason.map(str::to_string),
        observed_at: None,
        last_reconciliation_attempted_at: None,
        last_successful_reconciled_at: None,
        deployment_id: deployment_id.map(str::to_string),
        status: None,
        drifted,
    }
}

#[test]
fn deploy_runtime_direct_tee_fallback_accepts_matching_partial_observation() {
    let expected_deployment_id = "22222222-2222-2222-2222-222222222222";
    for reason in [
        "tee_unavailable",
        "tee_malformed",
        "tee_evidence_incomplete",
    ] {
        let observation =
            deploy_observation("partial", Some(reason), Some(expected_deployment_id), false);

        assert!(observation_allows_direct_tee_fallback(
            Some(&observation),
            expected_deployment_id
        ));
        assert!(!observation_is_fresh_for_deployment(
            Some(&observation),
            expected_deployment_id
        ));
    }
}

#[test]
fn deploy_runtime_direct_tee_fallback_rejects_pod_gaps_wrong_or_drifted_deployment() {
    let expected_deployment_id = "22222222-2222-2222-2222-222222222222";
    let wrong = deploy_observation(
        "partial",
        Some("tee_unavailable"),
        Some("33333333-3333-3333-3333-333333333333"),
        false,
    );
    let drifted = deploy_observation(
        "partial",
        Some("tee_unavailable"),
        Some(expected_deployment_id),
        true,
    );

    assert!(!observation_allows_direct_tee_fallback(
        Some(&wrong),
        expected_deployment_id
    ));
    assert!(!observation_allows_direct_tee_fallback(
        Some(&drifted),
        expected_deployment_id
    ));

    for reason in [
        None,
        Some("pod_evidence_incomplete"),
        Some("evidence_mismatch"),
        Some("not_observed"),
    ] {
        let observation =
            deploy_observation("partial", reason, Some(expected_deployment_id), false);
        assert!(
            !observation_allows_direct_tee_fallback(Some(&observation), expected_deployment_id),
            "partial observation reason {reason:?} must retain the pod-evidence fence"
        );
    }
}

#[test]
fn deploy_config_retries_only_locked_tee_responses() {
    assert!(should_retry_deploy_config(&TeeError::Tee {
        status: 423,
        message: "init_not_ready".to_string()
    }));
    assert!(!should_retry_deploy_config(&TeeError::Tee {
        status: 401,
        message: "unauthorized".to_string()
    }));
}

#[test]
fn direct_tee_status_prefers_current_unlock_state() {
    let status = serde_json::json!({
        "state": "unlocked",
        "unlock_state": "error",
        "ownership_state": "locked"
    });

    assert_eq!(tee_unlock_state(&status), "error");
}

#[test]
fn direct_tee_status_accepts_matching_or_omitted_supplemental_fields() {
    for status in [
        serde_json::json!({
            "unlock_state": "unlocked",
            "pod_status": "Running",
            "tee_status": "READY",
            "storage_status": "Unlocked"
        }),
        serde_json::json!({
            "state": "locked",
            "tee_status": "ready",
            "storage_status": "locked"
        }),
        serde_json::json!({"state": "unlocked"}),
        serde_json::json!({
            "state": "unlocked",
            "tee_status": null,
            "storage_status": null
        }),
    ] {
        assert!(tee_supplemental_fields_are_consistent(&status), "{status}");
    }
}

#[test]
fn direct_tee_status_rejects_errors_mismatches_and_malformed_fields() {
    for status in [
        serde_json::json!({"state": "unlocked", "tee_status": "error"}),
        serde_json::json!({"state": "unlocked", "storage_status": "error"}),
        serde_json::json!({"state": "locked", "storage_status": "unlocked"}),
        serde_json::json!({"state": "unlocked", "pod_status": "Pending"}),
        serde_json::json!({"state": "unlocked", "pod_status": 1}),
        serde_json::json!({"state": "unlocked", "tee_status": 1}),
        serde_json::json!({"state": "unlocked", "storage_status": ["unlocked"]}),
    ] {
        assert!(!tee_supplemental_fields_are_consistent(&status), "{status}");
    }
}

#[test]
fn status_command_falls_back_to_attested_tee_status() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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

#[cfg(unix)]
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

#[cfg(unix)]
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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
        .find("set_deploy_config")
        .expect("deploy config push must set config values");
    assert!(
        attest < set,
        "deploy config delivery must verify attestation/SPKI binding before writing config"
    );
}

#[test]
fn deploy_health_timeout_is_not_reported_as_success() {
    // CRLF checkouts (Windows autocrlf) must not break source matching.
    let source = include_str!("../../app.rs").replace("\r\n", "\n");
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

#[tokio::test]
async fn list_org_log_keys_hits_org_endpoint() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = serde_json::json!({ "keys": [] }).to_string();
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

    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let list = api.list_org_log_keys().await.unwrap();
    let request = handle.join().unwrap();

    assert!(request.starts_with("GET /log-keys "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert!(list.keys.is_empty());
}

#[tokio::test]
async fn revoke_org_log_key_hits_org_endpoint() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let body = serde_json::json!({
            "key_id": "team-logs",
            "status": "revoked",
            "revoked_at": "2026-07-15T00:00:00Z",
            "cleared_app_selections": 2
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

    let api = ApiClient::new(&format!("http://{addr}"), Some("test-token".to_string()));
    let resp = api.revoke_org_log_key("team-logs").await.unwrap();
    let request = handle.join().unwrap();

    assert!(request.starts_with("DELETE /log-keys/team-logs "));
    assert!(request.contains("authorization: Bearer test-token"));
    assert_eq!(resp.key_id, "team-logs");
    assert_eq!(resp.status, "revoked");
    assert_eq!(resp.cleared_app_selections, Some(2));
}

// --- terminal bootstrap diagnostics -------------------------------------------

mod terminal_diagnostics {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::{Mutex, OnceLock};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const SYNTHETIC_SECRET_MARKER: &str = "SECRET-MARKER-9a41e7";

    // Public synthetic localhost fixture (same key material as the transport
    // test in tee_client/tls.rs); used only for local TLS test servers.
    const SYNTHETIC_LOCALHOST_CERT_B64: &str = "MIIBfzCCASWgAwIBAgIUDvNchz/4kjYNIUZPbhErYcJcQEkwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkwNjE1NTgyM1oYDzIxMjYwODEzMTU1ODIzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASTrTE27CrHezsrQig5SJS3khO5zrEB7SYnpJj05SOwGHPQCBpYHg38VRS9fdnyKI2JdkuAePfnhVJULAcTmrkuo1MwUTAdBgNVHQ4EFgQUW41obMczsiP/amwMRntTfO2u2g0wHwYDVR0jBBgwFoAUW41obMczsiP/amwMRntTfO2u2g0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBFGRlU//+3JyhVqXNcpWw7QR9N9pEoiRVpgFc0Dxg+uwIhAIO8kzgeVzlTSTS7/2jE2EuVXtAxL3Mcbd62YjrqNtaG";
    const SYNTHETIC_LOCALHOST_KEY_B64: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1eONjcC4FaH2HqTDcwYCUym2nm332NQ/GN4WxJafrU+hRANCAASTrTE27CrHezsrQig5SJS3khO5zrEB7SYnpJj05SOwGHPQCBpYHg38VRS9fdnyKI2JdkuAePfnhVJULAcTmrku";

    /// Serves one static JSON body per request path over local TLS, recording
    /// every received request path.
    async fn spawn_local_tls_server(
        requests: std::sync::Arc<Mutex<Vec<String>>>,
        respond: impl Fn(&str) -> (u16, String) + Send + Sync + 'static,
    ) -> SocketAddr {
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(SYNTHETIC_LOCALHOST_CERT_B64)
            .unwrap();
        let key = base64::engine::general_purpose::STANDARD
            .decode(SYNTHETIC_LOCALHOST_KEY_B64)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(certificate)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let path = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                requests.lock().unwrap().push(path.clone());
                let (status, reason, body) = match respond(&path) {
                    (200, body) => (200, "OK", body),
                    (404, body) => (404, "Not Found", body),
                    (423, body) => (423, "Locked", body),
                    (500, body) => (500, "Internal Server Error", body),
                    _ => (404, "Not Found", "{}".to_string()),
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        address
    }

    /// Plain-HTTP stub for `ApiClient::get_unlock_endpoint`.
    async fn spawn_unlock_endpoint_stub(tee_base_url: String) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let body = serde_json::json!({
                    "tee_url": format!("{tee_base_url}/config"),
                    "tee_resolve_ip": "127.0.0.1",
                    "unlock_endpoint": format!("{tee_base_url}/unlock"),
                    "claim_endpoint": format!("{tee_base_url}/bootstrap/claim"),
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        address
    }

    /// Plain-HTTP JSON stub for `ApiClient` GET routes; unmatched paths 404.
    async fn spawn_json_api_stub(
        respond: impl Fn(&str) -> Option<serde_json::Value> + Send + Sync + 'static,
    ) -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let path = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                let (status, body) = match respond(&path) {
                    Some(value) => ("200 OK", value.to_string()),
                    None => ("404 Not Found", "{}".to_string()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        address
    }

    /// Plain-HTTP `/deployments` stub for the detached history probe: each
    /// connection answers after `delay` with `answer_by_connection(nth)`
    /// (1-based connection number).
    async fn spawn_history_stub(
        delay: std::time::Duration,
        answer_by_connection: impl Fn(usize) -> serde_json::Value + Send + Sync + 'static,
    ) -> SocketAddr {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let answer_by_connection = std::sync::Arc::new(answer_by_connection);
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let nth = connections.fetch_add(1, Ordering::SeqCst) + 1;
                let answer_by_connection = answer_by_connection.clone();
                tokio::spawn(async move {
                    let mut sink = [0_u8; 4096];
                    let _ = stream.read(&mut sink).await;
                    tokio::time::sleep(delay).await;
                    let body = answer_by_connection(nth).to_string();
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        address
    }

    /// Plain-HTTP `/deployments` stub that reads requests and never answers,
    /// counting requests seen (`accepted`) and connections the client closed
    /// again (`closed`).
    async fn spawn_stalled_history_stub(
        accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        closed: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) -> SocketAddr {
        use std::sync::atomic::Ordering;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let accepted = accepted.clone();
                let closed = closed.clone();
                tokio::spawn(async move {
                    let mut sink = [0_u8; 4096];
                    let mut seen = false;
                    loop {
                        match stream.read(&mut sink).await {
                            Ok(0) | Err(_) => {
                                closed.fetch_add(1, Ordering::SeqCst);
                                break;
                            }
                            Ok(_) => {
                                if !seen {
                                    seen = true;
                                    accepted.fetch_add(1, Ordering::SeqCst);
                                }
                            }
                        }
                    }
                });
            }
        });
        address
    }

    /// TLS server writing fully caller-controlled response bytes (no framing
    /// assumptions), recording request paths. A `None` response accepts the
    /// TLS handshake, reads the request, and then stalls forever.
    async fn spawn_local_tls_raw_server(
        requests: std::sync::Arc<Mutex<Vec<String>>>,
        respond: impl Fn(&str) -> Option<Vec<u8>> + Send + Sync + 'static,
    ) -> SocketAddr {
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(SYNTHETIC_LOCALHOST_CERT_B64)
            .unwrap();
        let key = base64::engine::general_purpose::STANDARD
            .decode(SYNTHETIC_LOCALHOST_KEY_B64)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(certificate)],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => {
                            request.extend_from_slice(&chunk[..read]);
                            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                let path = String::from_utf8_lossy(&request)
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("/")
                    .to_string();
                requests.lock().unwrap().push(path.clone());
                match respond(&path) {
                    Some(response) => {
                        let _ = stream.write_all(&response).await;
                        let _ = stream.shutdown().await;
                    }
                    None => std::future::pending::<()>().await,
                }
            }
        });
        address
    }

    fn test_expectation(
        deploy_id: &str,
        launch_hash: [u8; 32],
    ) -> crate::commands::app::TrustedDeploymentExpectation {
        crate::commands::app::TrustedDeploymentExpectation {
            deploy_id: deploy_id.to_string(),
            expected_cc_init_data_hash: launch_hash,
            expected_firmware_measurement: enclava_common::descriptor::FirmwareMeasurement::Full(
                [0x11; 48],
            ),
        }
    }

    const OLD_TEE_LAUNCH_HASH: [u8; 32] = [0x07; 32];
    const NEW_EXPECTED_LAUNCH_HASH: [u8; 32] = [0x09; 32];
    /// Measurement carried by test_expectation (FirmwareMeasurement::Full).
    const EXPECTED_FIRMWARE_MEASUREMENT: [u8; 48] = [0x11; 48];
    const WRONG_FIRMWARE_MEASUREMENT: [u8; 48] = [0x22; 48];

    fn deployment_entry_json(id: &str, status: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "status": status,
            "image_digest": null,
            "created_at": "2026-09-09T00:00:00Z",
            "completed_at": null,
        })
    }

    /// Serializes staging-env mutation among these tests. The guard is only
    /// held across synchronous set/build and clear windows, never across an
    /// await; clients read the env at build time, so later clears are inert.
    fn tls_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn local_tee_client(address: SocketAddr) -> TeeClient {
        TeeClient::new_with_resolve_ip(
            &format!("https://localhost:{}", address.port()),
            Some(address.ip()),
        )
    }

    #[test]
    fn terminal_failure_message_prints_only_code_and_validated_deadline() {
        let diagnostic =
            enclava_cli::tee_client::parse_terminal_bootstrap_error(&serde_json::json!({
                "bootstrap_error": {
                    "error": "acme_rate_limited",
                    "terminal": true,
                    "retry_after": "2027-01-01T12:00:00+00:00",
                    "detail": SYNTHETIC_SECRET_MARKER,
                }
            }))
            .unwrap();
        let message = terminal_bootstrap_failure_message("demo", &diagnostic);
        assert_eq!(
            message,
            "terminal bootstrap failure for app demo: acme_rate_limited (retry_after 2027-01-01T12:00:00Z); run `enclava status --app demo` for the latest state"
        );
        assert!(!message.contains(SYNTHETIC_SECRET_MARKER));
    }

    #[test]
    fn terminal_failure_message_without_deadline_prints_only_the_code() {
        let diagnostic = enclava_cli::tee_client::parse_terminal_bootstrap_error(
            &serde_json::json!({
                "bootstrap_error": { "error": "enclava_init_failed", "terminal": true, "retry_after": null }
            }),
        )
        .unwrap();
        assert_eq!(
            terminal_bootstrap_failure_message("demo", &diagnostic),
            "terminal bootstrap failure for app demo: enclava_init_failed; run `enclava status --app demo` for the latest state"
        );
    }

    #[test]
    fn bootstrap_endpoint_decision_never_masks_terminal_with_claimed_state() {
        let terminal = enclava_cli::tee_client::TeeBootstrapStatus {
            claimed: true,
            terminal_bootstrap_error: enclava_cli::tee_client::parse_terminal_bootstrap_error(
                &serde_json::json!({
                    "bootstrap_error": { "error": "acme_rate_limited", "terminal": true, "retry_after": null }
                }),
            ),
        };
        assert!(matches!(
            bootstrap_endpoint_status_decision(&terminal),
            BootstrapEndpointStatusDecision::Terminal
        ));

        let claimed = enclava_cli::tee_client::TeeBootstrapStatus {
            claimed: true,
            terminal_bootstrap_error: None,
        };
        assert!(matches!(
            bootstrap_endpoint_status_decision(&claimed),
            BootstrapEndpointStatusDecision::AlreadyClaimed
        ));

        let waiting = enclava_cli::tee_client::TeeBootstrapStatus {
            claimed: false,
            terminal_bootstrap_error: None,
        };
        assert!(matches!(
            bootstrap_endpoint_status_decision(&waiting),
            BootstrapEndpointStatusDecision::Waiting
        ));
    }

    #[test]
    fn terminal_diagnostic_probe_spacing_keeps_probes_prompt_but_bounded() {
        let mut last = None;
        assert!(
            tee_terminal_diagnostic_probe_due(&mut last),
            "first probe is due"
        );
        assert!(
            !tee_terminal_diagnostic_probe_due(&mut last),
            "immediate re-probe must wait out the spacing interval"
        );
    }

    #[tokio::test]
    async fn unlock_wait_fails_closed_without_verified_launch_identity() {
        // Without a verified launch identity the loop never attributes a
        // terminal diagnostic: it keeps its own state handling (here: the
        // locked arm ends the wait with the unlock error, not a terminal
        // message). The client stands in for the attested channel; the
        // ordering check below proves the predicate gates the read.
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_server(requests, |path| {
            let body = if path.ends_with("/status") {
                serde_json::json!({
                    "unlock_state": "locked",
                    "bootstrap_error": { "error": "acme_rate_limited", "terminal": true, "retry_after": null }
                })
                .to_string()
            } else {
                "{}".to_string()
            };
            (200, body)
        })
        .await;
        let tee = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let api = ApiClient::new("http://127.0.0.1:1", Some("test".to_string()));
        let expectation = test_expectation("expected-1", NEW_EXPECTED_LAUNCH_HASH);
        let error = wait_for_deploy_unlock_completion(
            &api,
            &tee,
            "demo",
            crate::commands::app::DeploymentWait::trusted("expected-1", Some(&expectation)),
        )
        .await
        .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("unlock did not complete"),
            "unexpected error: {message}"
        );
        assert!(!message.contains("terminal bootstrap failure"));
        let _guard = tls_env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[tokio::test]
    async fn unlock_wait_progresses_normally_when_diagnostics_absent_or_stale() {
        for body in [
            // Healthy status: diagnostic absent.
            serde_json::json!({ "unlock_state": "unlocked" }),
            // A stale diagnostic must not preempt a satisfied unlock.
            serde_json::json!({
                "unlock_state": "unlocked",
                "bootstrap_error": { "error": "acme_rate_limited", "terminal": true, "retry_after": null }
            }),
        ] {
            let address =
                spawn_local_tls_server(std::sync::Arc::new(Mutex::new(Vec::new())), move |path| {
                    let body = if path.ends_with("/status") {
                        body.to_string()
                    } else {
                        "{}".to_string()
                    };
                    (200, body)
                })
                .await;
            let tee = {
                let _guard = tls_env_lock();
                unsafe {
                    std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
                }
                local_tee_client(address)
            };
            let api = ApiClient::new("http://127.0.0.1:1", Some("test".to_string()));
            wait_for_deploy_unlock_completion(
                &api,
                &tee,
                "demo",
                crate::commands::app::DeploymentWait::new("expected-1"),
            )
            .await
            .expect("satisfied unlock must permit normal progress");
            let _guard = tls_env_lock();
            unsafe {
                std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            }
        }
    }

    #[tokio::test]
    async fn bounded_status_read_rejects_oversized_terminal_bodies() {
        let oversized = serde_json::json!({
            "unlock_state": "unlocking",
            "bootstrap_error": { "error": "acme_rate_limited", "terminal": true, "retry_after": null },
            "padding": "x".repeat(80 * 1024),
        })
        .to_string();
        let address =
            spawn_local_tls_server(std::sync::Arc::new(Mutex::new(Vec::new())), move |path| {
                let body = if path.ends_with("/status") {
                    oversized.clone()
                } else {
                    "{}".to_string()
                };
                (200, body)
            })
            .await;
        let client = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let error = client.bootstrap_status().await.unwrap_err();
        {
            let _guard = tls_env_lock();
            unsafe {
                std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            }
        }
        assert!(
            error.to_string().contains("bounded read limit"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn unverified_status_response_cannot_authorize_a_terminal_decision() {
        // The TLS server happily reports a terminal bootstrap error on
        // /status, but never answers /attestation: without a verified
        // attestation (SPKI-pinned client from attest_receipt_key), the
        // diagnostic probe must yield None and never stop a wait.
        let tee_requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let tee_address = spawn_local_tls_server(tee_requests, |path| {
            let body = if path.starts_with("/.well-known/confidential/attestation") {
                "{}".to_string()
            } else {
                serde_json::json!({
                    "unlock_state": "locked",
                    "bootstrap_error": { "error": "enclava_init_failed", "terminal": true, "retry_after": null }
                })
                .to_string()
            };
            (200, body)
        })
        .await;
        let api_address =
            spawn_unlock_endpoint_stub(format!("https://localhost:{}", tee_address.port())).await;
        let api = ApiClient::new(&format!("http://{api_address}"), Some("test".to_string()));

        let expectation = test_expectation("expected-1", NEW_EXPECTED_LAUNCH_HASH);
        assert!(
            deployment_bound_terminal_bootstrap_error(
                &api,
                "demo",
                crate::commands::app::DeploymentWait::trusted("expected-1", Some(&expectation)),
                std::time::Instant::now() + std::time::Duration::from_secs(5)
            )
            .await
            .is_none(),
            "an unattested /status response must never authorize a terminal decision"
        );
    }

    #[tokio::test]
    async fn bounded_status_rejects_error_responses_without_reading_bodies() {
        // A non-success /status must be rejected by status code alone: the
        // response body (arbitrary size, arbitrary content) is never read.
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_server(requests, move |path| {
            let body = if path.ends_with("/status") {
                format!(
                    "{{\"leak\": \"{SYNTHETIC_SECRET_MARKER}\", \"padding\": \"{}\"}}",
                    "y".repeat(128 * 1024)
                )
            } else {
                "{}".to_string()
            };
            (500, body)
        })
        .await;
        let client = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let error = client.bounded_status_json().await.unwrap_err();
        {
            let _guard = tls_env_lock();
            unsafe {
                std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            }
        }
        let message = error.to_string();
        assert!(message.contains("500"), "unexpected error: {message}");
        assert!(!message.contains(SYNTHETIC_SECRET_MARKER));
    }

    #[test]
    fn direct_runtime_outcome_prefers_terminal_over_ready_states() {
        // A locked or unlocked TEE carrying a recognized terminal diagnostic
        // must classify as Terminal, never as a direct-fallback success.
        for unlock_state in ["locked", "unlocked", "unlocking"] {
            let status = serde_json::json!({
                "unlock_state": unlock_state,
                "bootstrap_error": { "error": "acme_certificate_issuance_failed", "terminal": true, "retry_after": null }
            });
            assert_eq!(
                direct_tee_runtime_outcome(&status),
                DirectTeeRuntimeOutcome::Terminal(
                    enclava_cli::tee_client::parse_terminal_bootstrap_error(&status).unwrap()
                ),
                "{unlock_state} must not mask a terminal diagnostic"
            );
        }
        assert_eq!(
            direct_tee_runtime_outcome(&serde_json::json!({ "unlock_state": "locked" })),
            DirectTeeRuntimeOutcome::Locked
        );
        assert_eq!(
            direct_tee_runtime_outcome(&serde_json::json!({ "unlock_state": "unlocked" })),
            DirectTeeRuntimeOutcome::Unlocked
        );
        assert_eq!(
            direct_tee_runtime_outcome(&serde_json::json!({ "unlock_state": "unlocking" })),
            DirectTeeRuntimeOutcome::Waiting
        );
        // Unknown diagnostics never classify as terminal.
        assert_eq!(
            direct_tee_runtime_outcome(&serde_json::json!({
                "unlock_state": "locked",
                "bootstrap_error": { "error": "acme_dns_failed", "terminal": true, "retry_after": null }
            })),
            DirectTeeRuntimeOutcome::Locked
        );
    }

    #[tokio::test]
    async fn set_deploy_config_ignores_terminal_diagnostics_without_verified_identity() {
        // The write is refused once (423, terminal diagnostic present on
        // /status) but the client carries no verified launch identity: the
        // probe must not attribute the terminal failure, the retry must
        // proceed, and no /status read may happen through the probe.
        let attempts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_server(requests.clone(), {
            let attempts = attempts.clone();
            move |path| {
                if path.ends_with("/status") {
                    (
                        200,
                        serde_json::json!({
                            "unlock_state": "locked",
                            "bootstrap_error": { "error": "enclava_init_failed", "terminal": true, "retry_after": null }
                        })
                        .to_string(),
                    )
                } else if attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    (423, "{}".to_string())
                } else {
                    (200, "{}".to_string())
                }
            }
        })
        .await;
        let tee = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let api = ApiClient::new("http://127.0.0.1:1", Some("test".to_string()));
        let expectation = test_expectation("expected-1", NEW_EXPECTED_LAUNCH_HASH);
        set_deploy_config(
            &api,
            &tee,
            "demo",
            crate::commands::app::DeploymentWait::trusted("expected-1", Some(&expectation)),
            "K",
            "V",
            "token",
        )
        .await
        .expect("an unverified endpoint must not block config retries");
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.ends_with("/status")),
            "no /status read may happen before the launch-identity predicate passes"
        );
        let _guard = tls_env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[tokio::test]
    async fn set_deploy_config_succeeds_without_diagnostic_probe() {
        // A successful write must not trigger any status probe.
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_server(requests.clone(), |path| {
            let (status, body) = if path.ends_with("/status") {
                (
                    200,
                    serde_json::json!({ "unlock_state": "locked" }).to_string(),
                )
            } else {
                (200, "{}".to_string())
            };
            (status, body)
        })
        .await;
        let tee = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let api = ApiClient::new("http://127.0.0.1:1", Some("test".to_string()));
        set_deploy_config(
            &api,
            &tee,
            "demo",
            crate::commands::app::DeploymentWait::new("expected-1"),
            "K",
            "V",
            "token",
        )
        .await
        .expect("successful config write must not consult diagnostics");
        assert!(
            !requests
                .lock()
                .unwrap()
                .iter()
                .any(|path| path.ends_with("/status")),
            "no /status probe may accompany a successful write"
        );
        {
            let _guard = tls_env_lock();
            unsafe {
                std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            }
        }
    }

    #[tokio::test]
    async fn terminal_probe_reads_no_status_without_verified_launch_identity() {
        // Fail-closed integration: an endpoint reporting a terminal failure is
        // never read through the diagnostic probe unless the client carries a
        // verified launch identity matching the wait's expectation (the pure
        // launch_identity_binding_fixtures cover hash/masurement mismatch).
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_server(requests.clone(), |path| {
            let body = if path.ends_with("/status") {
                serde_json::json!({
                    "unlock_state": "locked",
                    "bootstrap_error": { "error": "acme_rate_limited", "terminal": true, "retry_after": null }
                })
                .to_string()
            } else {
                "{}".to_string()
            };
            (200, body)
        })
        .await;
        let tee = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let api = ApiClient::new("http://127.0.0.1:1", Some("test".to_string()));
        let expectation = test_expectation("new-1", NEW_EXPECTED_LAUNCH_HASH);
        let deployment = crate::commands::app::DeploymentWait::trusted("new-1", Some(&expectation));

        assert!(
            deployment_bound_terminal_bootstrap_error_on_channel(
                &api,
                "demo",
                deployment,
                &tee,
                std::time::Instant::now() + std::time::Duration::from_secs(5),
            )
            .await
            .is_none()
        );
        assert!(
            requests.lock().unwrap().is_empty(),
            "no /status read may happen before the launch-identity predicate passes"
        );
        let _guard = tls_env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[test]
    fn launch_identity_binding_fixtures() {
        use enclava_cli::tee_client::{
            VerifiedSnpLaunchIdentity, launch_identity_binds_deployment,
        };
        use enclava_common::descriptor::FirmwareMeasurement;

        let expected_measurement = FirmwareMeasurement::Full(EXPECTED_FIRMWARE_MEASUREMENT);
        let fully_verified = VerifiedSnpLaunchIdentity {
            host_data: NEW_EXPECTED_LAUNCH_HASH,
            firmware_measurement: EXPECTED_FIRMWARE_MEASUREMENT,
        };

        // Positive: same fully verified client (hash AND measurement match).
        assert!(launch_identity_binds_deployment(
            Some(&fully_verified),
            &NEW_EXPECTED_LAUNCH_HASH,
            &expected_measurement
        ));
        // Old TEE launch hash vs the new deployment's expected hash: no bind.
        assert!(!launch_identity_binds_deployment(
            Some(&VerifiedSnpLaunchIdentity {
                host_data: OLD_TEE_LAUNCH_HASH,
                firmware_measurement: EXPECTED_FIRMWARE_MEASUREMENT,
            }),
            &NEW_EXPECTED_LAUNCH_HASH,
            &expected_measurement
        ));
        // Matching HOST_DATA with a WRONG firmware measurement: HOST_DATA
        // alone is hypervisor-supplied launch input and must never authorize.
        assert!(!launch_identity_binds_deployment(
            Some(&VerifiedSnpLaunchIdentity {
                host_data: NEW_EXPECTED_LAUNCH_HASH,
                firmware_measurement: WRONG_FIRMWARE_MEASUREMENT,
            }),
            &NEW_EXPECTED_LAUNCH_HASH,
            &expected_measurement
        ));
        // Legacy 32-byte measurement expectation still matches its prefix.
        assert!(launch_identity_binds_deployment(
            Some(&VerifiedSnpLaunchIdentity {
                host_data: NEW_EXPECTED_LAUNCH_HASH,
                firmware_measurement: EXPECTED_FIRMWARE_MEASUREMENT,
            }),
            &NEW_EXPECTED_LAUNCH_HASH,
            &FirmwareMeasurement::Legacy(EXPECTED_FIRMWARE_MEASUREMENT[..32].try_into().unwrap())
        ));
        // Missing verified identity (unattested client or development JSON
        // evidence) never binds.
        assert!(!launch_identity_binds_deployment(
            None,
            &NEW_EXPECTED_LAUNCH_HASH,
            &expected_measurement
        ));
    }

    #[tokio::test]
    async fn malformed_nested_attestation_fields_never_leak_content() {
        // Review regression: an otherwise well-shaped attestation response
        // that echoes the requested nonce, domain, and leaf SPKI but carries
        // a malformed receipt_pubkey_sha256 must fail with a fixed message --
        // hex decode errors interpolate the offending response bytes, and
        // this field is parsed before SNP authentication completes.
        use x509_cert::der::{Decode as _, Encode as _};
        let certificate = base64::engine::general_purpose::STANDARD
            .decode(SYNTHETIC_LOCALHOST_CERT_B64)
            .unwrap();
        let spki_der = x509_cert::Certificate::from_der(&certificate)
            .unwrap()
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        use sha2::Digest as _;
        let leaf_spki_sha256 = hex::encode(sha2::Sha256::digest(&spki_der));

        for malformed in [
            // Invalid hex carrying the secret marker.
            format!("{SYNTHETIC_SECRET_MARKER}-ZZ"),
            // Valid hex, wrong length.
            "aa".repeat(31),
        ] {
            let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
            let leaf_spki_sha256 = leaf_spki_sha256.clone();
            let address = spawn_local_tls_raw_server(requests, move |path| {
                // Echo the client's nonce so the response passes the
                // nonce/domain/SPKI equality checks and reaches the
                // receipt-pubkey hex parse.
                let nonce = path
                    .split('?')
                    .nth(1)
                    .and_then(|query| {
                        query.split('&').find_map(|pair| {
                            let (key, value) = pair.split_once('=')?;
                            (key == "nonce").then_some(value.to_string())
                        })
                    })
                    .unwrap_or_default();
                let body = serde_json::json!({
                    "nonce": nonce,
                    "runtime_data_binding": {
                        "domain": "localhost",
                        "leaf_spki_sha256": leaf_spki_sha256,
                        "receipt_pubkey_sha256": malformed.clone(),
                    },
                    "evidence": { "payload_b64": "" },
                });
                let mut response =
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
                        .to_vec();
                response.extend_from_slice(body.to_string().as_bytes());
                Some(response)
            })
            .await;
            let tee = TeeClient::new_with_resolve_ip(
                &format!("https://localhost:{}", address.port()),
                Some(address.ip()),
            );
            let error = match tee.attest_receipt_key().await {
                Ok(_) => panic!("malformed receipt_pubkey_sha256 must be rejected"),
                Err(error) => error.to_string(),
            };
            assert!(
                error.contains("receipt_pubkey_sha256"),
                "unexpected error: {error}"
            );
            assert!(
                error.contains("is not valid hex") || error.contains("must be 32 bytes"),
                "unexpected error: {error}"
            );
            assert!(
                !error.contains(SYNTHETIC_SECRET_MARKER),
                "hex/length errors must never echo response bytes"
            );
            assert!(
                !error.contains("Invalid character"),
                "raw hex decode errors must never surface"
            );
        }
    }

    #[tokio::test]
    async fn malformed_attestation_response_never_leaks_content() {
        // A type-mismatched (malformed) attestation body must produce a fixed
        // error message: serde type errors can interpolate the offending
        // value, and this response is unauthenticated at that point.
        // Answer every request with the malformed body (the TLS leaf fetch
        // sends no HTTP request and simply disconnects; answering all paths
        // keeps the sequential server loop accepting).
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_raw_server(requests, move |_path| {
            let mut response =
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n"
                    .to_vec();
            // A bare JSON string: valid JSON, wrong type for
            // AttestationResponse, and carrying the secret marker.
            response.extend_from_slice(format!("\"{SYNTHETIC_SECRET_MARKER}\"").as_bytes());
            Some(response)
        })
        .await;
        let tee = TeeClient::new_with_resolve_ip(
            &format!("https://localhost:{}", address.port()),
            Some(address.ip()),
        );
        let error = match tee.attest_receipt_key().await {
            Ok(_) => panic!("malformed attestation body must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("attestation body is malformed"),
            "unexpected error: {error}"
        );
        assert!(
            !error.contains(SYNTHETIC_SECRET_MARKER),
            "malformed-response errors must never carry response content"
        );
    }

    #[tokio::test]
    async fn terminal_probe_budget_caps_stalled_cap_lookup() {
        // A CAP lookup that accepts TCP but never responds must not stall the
        // enclosing wait: the whole probe is cut at its budget.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Accept and stall: read nothing, write nothing.
                let mut sink = [0_u8; 1024];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => std::future::pending::<()>().await,
                    }
                }
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));

        let started = std::time::Instant::now();
        assert!(
            terminal_diagnostic_probe_with_budget(
                &api,
                "demo",
                crate::commands::app::DeploymentWait::trusted(
                    "expected-1",
                    Some(&test_expectation("expected-1", NEW_EXPECTED_LAUNCH_HASH)),
                ),
                None,
                std::time::Duration::from_millis(250),
            )
            .await
            .is_none()
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[tokio::test]
    async fn terminal_failure_check_never_blocks_on_stalled_history() {
        // The terminal-failure check's history lookup is a non-blocking
        // pickup from the detached probe (cap#220 review follow-ups): a
        // `/deployments` endpoint that accepts TCP but never responds cannot
        // spend the enclosing wait's budget before the readiness polls behind
        // the check run (the 30s-template-wait scenario), and once the
        // wait's deadline has passed no request is issued at all.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted_by_server = accepted.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                accepted_by_server.fetch_add(1, Ordering::SeqCst);
                // Accept and stall: read nothing, write nothing.
                let mut sink = [0_u8; 1024];
                loop {
                    match stream.read(&mut sink).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => std::future::pending::<()>().await,
                    }
                }
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let mut history = DeploymentHistoryProbe::new();

        // Deadline already passed: no request may be issued at all.
        fail_if_template_deployment_failed(
            &api,
            "demo",
            "deploy-1",
            std::time::Instant::now(),
            &mut history,
        )
        .await
        .expect("an exhausted wait budget must not turn a stalled lookup into an error");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a passed wait deadline must skip the history lookup entirely"
        );

        // Non-blocking: against a stalled endpoint the check returns at
        // once, leaving the wait's whole budget to the readiness polls.
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fail_if_template_deployment_failed(
                &api,
                "demo",
                "deploy-1",
                std::time::Instant::now() + std::time::Duration::from_millis(250),
                &mut history,
            ),
        )
        .await
        .expect("the failure check must return without blocking on the history endpoint");
        outcome.expect("a stalled history lookup must read as no failure observed");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(500),
            "the failure check must not consume the wait's budget on a stalled history endpoint"
        );
    }

    #[tokio::test]
    async fn slow_terminal_failure_is_surfaced_when_it_lands() {
        // Issue #18 fail-fast survives the non-blocking pickup (cap#220
        // review follow-ups): a history answer carrying the terminal
        // failure is observed however long it takes to land -- including
        // slower than any per-attempt budget -- so a manifest-apply rejection
        // still fails fast instead of hiding behind a wait timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut sink = [0_u8; 4096];
                    let _ = stream.read(&mut sink).await;
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    let body = serde_json::json!([{
                        "deployment_id": "deploy-1",
                        "status": "failed",
                        "error_message": "signed_policy_budget_exceeded",
                        "image_digest": null,
                        "created_at": "2026-10-13T00:00:00Z",
                        "completed_at": "2026-10-13T00:01:00Z",
                    }])
                    .to_string();
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let mut history = DeploymentHistoryProbe::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // Nothing has landed yet: no failure observed, and no blocking.
        fail_if_template_deployment_failed(&api, "demo", "deploy-1", deadline, &mut history)
            .await
            .expect("an in-flight lookup must not error");

        // The slow answer lands: the next check surfaces the real rejection.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let error =
            fail_if_template_deployment_failed(&api, "demo", "deploy-1", deadline, &mut history)
                .await
                .expect_err("a landed terminal failure must fail the wait");
        assert!(
            error
                .to_string()
                .contains("deployment deploy-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn state_lookup_observes_slow_history_responses_whenever_they_land() {
        // cap#220 review follow-ups: the apply-start and health waits learn
        // deployment state only through `find_deployment_entry`, so its
        // request must survive past any per-attempt budget. A response that
        // lands after an earlier pickup returned nothing is still observed
        // (the request is detached, not cancelled): the slow-but-valid
        // `healthy` case completes the wait instead of reporting a false
        // timeout.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    // Read the request, then answer slowly (slower than one
                    // pickup interval) but well within the wait.
                    let mut sink = [0_u8; 4096];
                    let _ = stream.read(&mut sink).await;
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    let body = serde_json::json!([{
                        "deployment_id": "deploy-1",
                        "status": "healthy",
                        "image_digest": null,
                        "created_at": "2026-10-13T00:00:00Z",
                        "completed_at": "2026-10-13T00:01:00Z",
                    }])
                    .to_string();
                    let _ = stream
                        .write_all(
                            format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            )
                            .as_bytes(),
                        )
                        .await;
                });
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let mut history = DeploymentHistoryProbe::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // First pickup: the request was just issued, nothing has landed.
        assert!(
            find_deployment_entry(&api, "demo", "deploy-1", deadline, &mut history)
                .await
                .expect("a slow-but-valid history response must not error")
                .is_none(),
            "no observation has landed yet"
        );

        // The request is not cancelled when a pickup returns nothing: the
        // slow answer is observed when it lands.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let entry = find_deployment_entry(&api, "demo", "deploy-1", deadline, &mut history)
            .await
            .expect("a slow-but-valid history response must not error")
            .expect("the state lookup must observe the slow response whenever it lands");
        assert_eq!(entry.id, "deploy-1");
        assert_eq!(entry.status, "healthy");
    }

    #[tokio::test]
    async fn stalled_history_request_is_superseded_and_a_fresh_request_observes_the_recovery() {
        // cap#220 review follow-up #2: one stalled history request must
        // neither consume the wait nor block retries. The probe keeps it in
        // flight but refreshes alongside it once its refresh window passes,
        // so a fresh request observes the recovered endpoint -- exactly the
        // apply-start/health loop behavior.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections_by_server = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let nth = connections_by_server.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let mut sink = [0_u8; 4096];
                    let _ = stream.read(&mut sink).await;
                    if nth == 1 {
                        // First request stalls: accept and never answer.
                        std::future::pending::<()>().await;
                    }
                    // The endpoint has recovered: answer promptly.
                    let body = serde_json::json!([{
                        "deployment_id": "deploy-1",
                        "status": "healthy",
                        "image_digest": null,
                        "created_at": "2026-10-13T00:00:00Z",
                        "completed_at": "2026-10-13T00:01:00Z",
                    }])
                    .to_string();
                    let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .as_bytes(),
                            )
                            .await;
                });
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        // A short refresh window stands in for WAIT_ATTEMPT_BUDGET so the
        // supersession path is exercised without waiting out the real one.
        let mut history =
            DeploymentHistoryProbe::with_refresh_age(std::time::Duration::from_millis(50));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // Pump 1: the stalled request is issued; no observation lands.
        assert!(
            find_deployment_entry(&api, "demo", "deploy-1", deadline, &mut history)
                .await
                .expect("a stalled lookup must not error")
                .is_none(),
            "the stalled attempt must read as no observation"
        );

        // The refresh window passes with the first request still stalled: a
        // fresh request goes out alongside it (the stalled one is kept, not
        // consuming anything) and the recovered endpoint answers.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(
            find_deployment_entry(&api, "demo", "deploy-1", deadline, &mut history)
                .await
                .expect("a stalled lookup must not error")
                .is_none(),
            "the refresh request has just been issued"
        );
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let entry = find_deployment_entry(&api, "demo", "deploy-1", deadline, &mut history)
            .await
            .expect("the retry must not error")
            .expect("the refreshed request must observe the recovered endpoint");
        assert_eq!(entry.id, "deploy-1");
        assert_eq!(entry.status, "healthy");
        assert!(
            connections.load(Ordering::SeqCst) >= 2,
            "the probe must refresh alongside the stalled request instead of waiting it out"
        );
    }

    #[tokio::test]
    async fn success_gate_recovers_when_an_older_request_stalls_and_the_endpoint_recovers() {
        // cap#220 review follow-up: a request issued before the gate stalls,
        // then the history endpoint recovers. The gate consumes its own
        // fresh healthy answers, which keeps the queue below the depth
        // limit, so the stalled request can only be retired by age: without
        // the age bound every later gate stays `Inconclusive` (a pending
        // request blocks the settle) and the ready deployment runs out its
        // whole wait -- the review's reported bug.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let connections = std::sync::Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections_by_server = connections.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let nth = connections_by_server.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    let mut sink = [0_u8; 4096];
                    let _ = stream.read(&mut sink).await;
                    if nth == 1 {
                        // The pre-gate request stalls: accept, never answer.
                        std::future::pending::<()>().await;
                    }
                    // Every later request sees the deployment healthy.
                    let body = serde_json::json!([{
                        "id": "deploy-1",
                        "status": "healthy",
                        "image_digest": null,
                        "created_at": "2026-10-13T00:00:00Z",
                        "completed_at": "2026-10-13T00:01:00Z",
                    }])
                    .to_string();
                    let _ = stream
                            .write_all(
                                format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                )
                                .as_bytes(),
                            )
                            .await;
                });
            }
        });
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        // A short refresh window stands in for WAIT_ATTEMPT_BUDGET so the
        // age bound (refresh_age * HISTORY_MAX_IN_FLIGHT) is exercised
        // without waiting out the real ~3 minutes.
        let refresh_age = std::time::Duration::from_millis(40);
        let mut history = DeploymentHistoryProbe::with_refresh_age(refresh_age);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);

        // Issue the request that stalls (it is the probe's only one, so the
        // depth policy can never retire it).
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        // A gate immediately after: its own fresh request answers healthy,
        // but the stalled one is still inside the age bound, so the settle
        // must expire inconclusive -- the safe side of the gate.
        let settled_budget = std::time::Duration::from_millis(200);
        let entry_at = std::time::Instant::now();
        history.force_request(&api, "demo", deadline);
        let settled = history
            .take_settled_within(settled_budget, |_, _| true)
            .await;
        assert!(
            !settled,
            "a pending request inside the age bound keeps the gate inconclusive"
        );

        // The age bound passes and the next pump retires the stalled request
        // (below the depth limit): the gate then settles on its fresh
        // answer and confirms the ready deployment.
        let age_bound = refresh_age * 3;
        let waited = entry_at + age_bound - std::time::Instant::now();
        if waited > std::time::Duration::ZERO {
            tokio::time::sleep(waited).await;
        }
        history.ensure_request(&api, "demo", deadline); // applies the age bound
        let gate = reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            deadline,
            &mut history,
        )
        .await
        .expect("the gate must not error on a healthy recovered endpoint");
        assert_eq!(
            gate,
            SuccessGate::Confirmed,
            "the retired stalled request must no longer block the gate: the review's ready-deployment timeout"
        );
    }

    #[tokio::test]
    async fn success_exit_surfaces_a_failed_deployment_landing_after_readiness() {
        // cap#220 review follow-up: readiness answered long before history.
        // The exit must consume the failure when its response lands and
        // report the terminal error instead of letting the ready endpoint
        // mask a failed deployment (the review's example: history records
        // `failed`, its response arrives seconds after the ready endpoint).
        let address = spawn_history_stub(std::time::Duration::from_millis(300), |_| {
            serde_json::json!([{
                "id": "deploy-1",
                "status": "failed",
                "error_message": "signed_policy_budget_exceeded",
                "image_digest": null,
                "created_at": "2026-10-13T00:00:00Z",
                "completed_at": "2026-10-13T00:01:00Z",
            }])
        })
        .await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let mut history = DeploymentHistoryProbe::new();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        let started = std::time::Instant::now();
        let error = reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            deadline,
            &mut history,
        )
        .await
        .expect_err("a ready endpoint must not mask a failed deployment");
        assert!(
            error
                .to_string()
                .contains("deployment deploy-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the exit must consume the answer when it lands, not wait out the budget first"
        );
    }

    #[tokio::test]
    async fn success_exit_accepts_a_non_failed_observation() {
        // The reconciliation is not a failure trap: an observation showing
        // the deployment is fine passes the exit -- both when it lands
        // during the pickup and when the exit finds one already landed (the
        // gate still asks for a current observation first and consumes its
        // answer as soon as it lands, without waiting out the budget).
        let address = spawn_history_stub(std::time::Duration::from_millis(100), |_| {
            serde_json::json!([deployment_entry_json("deploy-1", "healthy")])
        })
        .await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        let mut history = DeploymentHistoryProbe::new();
        reconcile_success_with_deployment_history(&api, "demo", "deploy-1", deadline, &mut history)
            .await
            .expect("a non-failed observation must pass the exit gate");

        // An answer has already landed before the exit: drained at once,
        // and the gate's fresh answer is consumed as soon as it lands.
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        let started = std::time::Instant::now();
        reconcile_success_with_deployment_history(&api, "demo", "deploy-1", deadline, &mut history)
            .await
            .expect("a landed non-failed observation must pass the exit gate");
        assert!(
            started.elapsed() < std::time::Duration::from_millis(300),
            "the exit must consume the fresh answer as soon as it lands, not wait out the budget"
        );
    }

    #[tokio::test]
    async fn success_exit_waits_for_the_fresh_request_when_a_stale_answer_already_landed() {
        // cap#220 review self-check: a stale non-failure answer must not
        // authorize success while a newer request is still in flight -- that
        // request supersedes the stale answer and its failure must be
        // observed before the exit. (The scenario: a slow iteration ages the
        // newest lookup past the refresh window; the gate issues a fresh
        // request whose response would show the failure.)
        let address = spawn_history_stub(std::time::Duration::from_millis(100), |nth| match nth {
            1 => serde_json::json!([deployment_entry_json("deploy-1", "applying")]),
            _ => serde_json::json!([{
                "id": "deploy-1",
                "status": "failed",
                "error_message": "signed_policy_budget_exceeded",
                "image_digest": null,
                "created_at": "2026-10-13T00:00:00Z",
                "completed_at": "2026-10-13T00:01:00Z",
            }]),
        })
        .await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // The stale answer lands first ("applying" before the failure).
        let mut history =
            DeploymentHistoryProbe::with_refresh_age(std::time::Duration::from_millis(50));
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        // The gate's refresh issues the fresh request showing the failure
        // and must wait for it instead of letting the stale answer decide.
        let error = reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            deadline,
            &mut history,
        )
        .await
        .expect_err("a stale non-failure must not mask a fresh request showing the failure");
        assert!(
            error
                .to_string()
                .contains("deployment deploy-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn success_exit_reasks_instead_of_authorizing_on_a_young_landed_answer() {
        // cap#220 self-check: a landed non-failure is not a current
        // observation -- the deployment may have failed after that answer
        // was served. Even when the newest answer is younger than the
        // refresh window (the common case: the failure check ran at the top
        // of the loop, then readiness arrived while the answer aged), the
        // exit must ask again and report the fresh answer's failure instead
        // of letting the pre-gate answer authorize success.
        let address = spawn_history_stub(std::time::Duration::from_millis(100), |nth| match nth {
            1 => serde_json::json!([deployment_entry_json("deploy-1", "healthy")]),
            _ => serde_json::json!([{
                "id": "deploy-1",
                "status": "failed",
                "error_message": "signed_policy_budget_exceeded",
                "image_digest": null,
                "created_at": "2026-10-13T00:00:00Z",
                "completed_at": "2026-10-13T00:01:00Z",
            }]),
        })
        .await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        // The pre-gate answer lands and stays well within the refresh
        // window (the default one is a full attempt budget).
        let mut history = DeploymentHistoryProbe::new();
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;

        let error = reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            deadline,
            &mut history,
        )
        .await
        .expect_err(
            "a pre-gate non-failure must not authorize success without a fresh observation",
        );
        assert!(
            error
                .to_string()
                .contains("deployment deploy-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn success_exit_consumes_a_landed_failure_behind_an_earlier_answer() {
        // A failure answer that landed before the exit must be consumed even
        // when an earlier answer landed first: taking only one answer would
        // drop the error unobserved.
        let address = spawn_history_stub(std::time::Duration::from_millis(100), |nth| match nth {
            1 => serde_json::json!([deployment_entry_json("deploy-1", "applying")]),
            _ => serde_json::json!([{
                "id": "deploy-1",
                "status": "failed",
                "error_message": "signed_policy_budget_exceeded",
                "image_digest": null,
                "created_at": "2026-10-13T00:00:00Z",
                "completed_at": "2026-10-13T00:01:00Z",
            }]),
        })
        .await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        // A short refresh window stands in for WAIT_ATTEMPT_BUDGET so two
        // requests land before the exit without waiting out the real one.
        let mut history =
            DeploymentHistoryProbe::with_refresh_age(std::time::Duration::from_millis(50));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        history.ensure_request(&api, "demo", deadline);
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        let error = reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            deadline,
            &mut history,
        )
        .await
        .expect_err("a landed failure must be consumed even behind an earlier answer");
        assert!(
            error
                .to_string()
                .contains("deployment deploy-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn success_exit_reconciles_pending_with_success_and_stays_bounded() {
        // cap#220 review follow-up: a stalled history endpoint must neither
        // block the exit (let alone the whole wait) nor turn readiness into
        // a failure -- the pending request is reconciled with the success
        // once the bounded pickup budget is gone, and a passed deadline
        // issues no request at all.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let closed = std::sync::Arc::new(AtomicUsize::new(0));
        let address = spawn_stalled_history_stub(accepted.clone(), closed.clone()).await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let mut history = DeploymentHistoryProbe::new();

        // Deadline already passed: no request may be issued at all.
        reconcile_success_with_deployment_history(
            &api,
            "demo",
            "deploy-1",
            std::time::Instant::now(),
            &mut history,
        )
        .await
        .expect("an exhausted wait budget must not turn a stalled lookup into an error");
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "a passed wait deadline must skip the history lookup entirely"
        );

        // Live deadline: the exit waits at most its (clamped) budget for the
        // pending answer, then reconciles it with the success.
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            reconcile_success_with_deployment_history(
                &api,
                "demo",
                "deploy-1",
                std::time::Instant::now() + std::time::Duration::from_millis(500),
                &mut history,
            ),
        )
        .await
        .expect("the exit gate must stay within its bounded pickup budget");
        outcome.expect("a stalled history endpoint must not fail a ready deployment");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the exit must be bounded by the reconcile budget, never the stalled endpoint"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the gate must probe once while budget remains"
        );
    }

    #[tokio::test]
    async fn abort_on_drop_handle_cancels_its_task_instead_of_detaching() {
        // cap#220 review follow-up: a dropped JoinHandle DETACHES its task.
        // The wrapper must abort instead, so no request outlives its owner.
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancelFlag(std::sync::Arc<AtomicBool>);
        impl Drop for CancelFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let flag = cancelled.clone();
        let handle = AbortOnDropHandle::new(tokio::spawn(async move {
            let _flag = CancelFlag(flag);
            std::future::pending::<()>().await;
        }));
        // Let the task start and park on its pending future first: a guard
        // inside a never-polled task could not observe its own cancellation.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !cancelled.load(Ordering::SeqCst),
            "the task must still be running before the handle drops"
        );
        drop(handle);
        for _ in 0..200 {
            if cancelled.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("dropping the handle must abort its task, not detach it");
    }

    #[tokio::test]
    async fn dropping_the_probe_cancels_pending_history_requests() {
        // cap#220 review follow-up: a wait that returns (success, error, or
        // timeout) drops its probe with requests still in flight. Those
        // requests must be cancelled -- a detached one would keep its
        // connection open until the client's 900-second request timeout
        // after the CLI has moved on or returned.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let closed = std::sync::Arc::new(AtomicUsize::new(0));
        let address = spawn_stalled_history_stub(accepted.clone(), closed.clone()).await;
        let api = ApiClient::new(&format!("http://{address}"), Some("test".to_string()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);

        let mut history = DeploymentHistoryProbe::new();
        history.ensure_request(&api, "demo", deadline);
        for _ in 0..200 {
            if accepted.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the request must reach the stalled endpoint"
        );

        drop(history);
        for _ in 0..200 {
            if closed.load(Ordering::SeqCst) >= 1 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("dropping the probe must cancel the pending request's connection");
    }

    #[tokio::test]
    async fn budgeted_status_read_cuts_stalled_responses() {
        // The standalone budgeted read (used by the unlock wait, runtime
        // direct fallback, and bootstrap fallback arms) must cut a stalled
        // response at its budget instead of holding the enclosing wait open
        // up to the client's own request timeout.
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let address = spawn_local_tls_raw_server(requests, |_path| None).await;
        let tee = {
            let _guard = tls_env_lock();
            unsafe {
                std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            }
            local_tee_client(address)
        };
        let started = std::time::Instant::now();
        let error = tee
            .bounded_status_json_within(std::time::Duration::from_millis(250))
            .await
            .unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(
            error.to_string().contains("exceeded its budget"),
            "unexpected error: {error}"
        );
        let _guard = tls_env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[tokio::test]
    async fn attestation_reads_are_bounded_before_authentication() {
        // /attestation responses are read through the bounded safe path for
        // both success and failure bodies, before SNP verification
        // authenticates the peer.
        let requests = std::sync::Arc::new(Mutex::new(Vec::new()));
        let oversized: Vec<u8> = {
            let mut body =
                br#"{"nonce":"a","runtime_data_binding":{},"evidence":{"payload_b64":""}}"#
                    .to_vec();
            body.extend_from_slice(&vec![b' '; 300 * 1024]);
            body
        };
        let error_body: Vec<u8> = format!("leak {SYNTHETIC_SECRET_MARKER} ",).into_bytes();
        let address = spawn_local_tls_raw_server(requests, move |path| {
            if path.starts_with("/.well-known/confidential/attestation") {
                // Streaming success body without a declared length: only the
                // per-chunk cap can reject it.
                let mut response = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n".to_vec();
                response.extend_from_slice(&oversized);
                Some(response)
            } else {
                let mut response = b"HTTP/1.1 500 Internal Server Error\r\nconnection: close\r\n\r\n".to_vec();
                response.extend_from_slice(&error_body);
                Some(response)
            }
        })
        .await;

        // The SPKI-pinned attestation fetch needs no staging env: the TLS
        // leaf fetch uses its own verifier and the pinned client pins the
        // synthetic certificate.
        let tee = TeeClient::new_with_resolve_ip(
            &format!("https://localhost:{}", address.port()),
            Some(address.ip()),
        );
        let error = match tee.attest_receipt_key().await {
            Ok(_) => panic!("oversized attestation body must be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("bounded read limit"),
            "oversized streaming attestation body must be rejected: {error}"
        );
        assert!(!error.contains(SYNTHETIC_SECRET_MARKER));
    }

    #[tokio::test]
    async fn health_wait_keeps_existing_deadline_when_probe_cannot_authenticate() {
        // Real caller control flow: the health wait consults the
        // deployment-bound probe, but without a verified attestation the
        // probe authorizes nothing and the wait keeps its own deadline
        // semantics (here: the timeout error).
        let api_address = spawn_json_api_stub(|path| {
            if path.ends_with("/deployments") {
                Some(serde_json::json!([deployment_entry_json(
                    "expected-1",
                    "watching"
                )]))
            } else {
                None
            }
        })
        .await;
        let api = ApiClient::new(&format!("http://{api_address}"), Some("test".to_string()));
        let error = wait_for_deployment_completion(
            &api,
            "demo",
            crate::commands::app::DeploymentWait::new("expected-1"),
            std::time::Duration::from_millis(120),
            std::time::Duration::from_millis(20),
            &ProgressBar::hidden(),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("did not become healthy"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn healthy_exit_reasks_history_instead_of_dropping_a_newer_failure() {
        // cap#220 self-check: the health wait's "healthy" answer may be
        // stale -- the deployment can fail after that answer was served, and
        // the exit used to return success on it at once (a false "Deployed
        // and healthy"). The success exit must reconcile the
        // deployment-state observation first: the fresh request shows the
        // failure and it is reported instead of masked.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let deployments = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = deployments.clone();
        let api_address = spawn_json_api_stub(move |path| {
            if !path.ends_with("/deployments") {
                return None;
            }
            let nth = seen.fetch_add(1, Ordering::SeqCst) + 1;
            Some(match nth {
                1 => serde_json::json!([deployment_entry_json("expected-1", "healthy")]),
                _ => serde_json::json!([{
                    "id": "expected-1",
                    "status": "failed",
                    "error_message": "signed_policy_budget_exceeded",
                    "image_digest": null,
                    "created_at": "2026-10-13T00:00:00Z",
                    "completed_at": "2026-10-13T00:01:00Z",
                }]),
            })
        })
        .await;
        let api = ApiClient::new(&format!("http://{api_address}"), Some("test".to_string()));
        let error = wait_for_deployment_completion(
            &api,
            "demo",
            crate::commands::app::DeploymentWait::new("expected-1"),
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(50),
            &ProgressBar::hidden(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("deployment expected-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn apply_start_exit_reasks_history_instead_of_dropping_a_newer_failure() {
        // cap#220 self-check: the same staleness at the apply-start wait's
        // success exit -- acting on the oldest landed answer and returning
        // dropped a newer failure (already landed or in flight). The exit
        // must reconcile the deployment-state observation first.
        use std::sync::atomic::{AtomicUsize, Ordering};
        let deployments = std::sync::Arc::new(AtomicUsize::new(0));
        let seen = deployments.clone();
        let api_address = spawn_json_api_stub(move |path| {
            if !path.ends_with("/deployments") {
                return None;
            }
            let nth = seen.fetch_add(1, Ordering::SeqCst) + 1;
            Some(match nth {
                1 => serde_json::json!([deployment_entry_json("expected-1", "applying")]),
                _ => serde_json::json!([{
                    "id": "expected-1",
                    "status": "failed",
                    "error_message": "signed_policy_budget_exceeded",
                    "image_digest": null,
                    "created_at": "2026-10-13T00:00:00Z",
                    "completed_at": "2026-10-13T00:01:00Z",
                }]),
            })
        })
        .await;
        let api = ApiClient::new(&format!("http://{api_address}"), Some("test".to_string()));
        let error = wait_for_deployment_apply_start(
            &api,
            "demo",
            "expected-1",
            std::time::Duration::from_secs(5),
            std::time::Duration::from_millis(50),
            &ProgressBar::hidden(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("deployment expected-1 failed: signed_policy_budget_exceeded"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn terminal_diagnostic_wiring_covers_every_post_claim_wait() {
        // Fail-if-bypassed wiring check (behavior is covered by the live
        // tests above): the runtime direct fallback classifies before
        // returning Ok, config retries probe, and the health wait uses the
        // deployment-bound probe.
        let source = include_str!("../../app.rs").replace("\r\n", "\n");

        let runtime_start = source.find("async fn wait_for_deploy_runtime").unwrap();
        let runtime_end = source[runtime_start..]
            .find("async fn find_deployment_entry")
            .unwrap()
            + runtime_start;
        let runtime = &source[runtime_start..runtime_end];
        let classify = runtime.find("direct_tee_runtime_outcome").unwrap();
        let ready = runtime[classify..]
            .find("return Ok(())")
            .map(|offset| offset + classify)
            .unwrap();
        assert!(
            classify < ready,
            "the direct TEE fallback must classify terminal diagnostics before reporting readiness"
        );
        assert!(runtime.contains("bounded_status_json"));

        let config_start = source.find("async fn set_deploy_config").unwrap();
        let config_end = source[config_start..]
            .find("fn should_retry_deploy_config")
            .unwrap()
            + config_start;
        let config = &source[config_start..config_end];
        assert!(
            config.contains("deployment_bound_terminal_bootstrap_error_on_channel"),
            "config write retries must stop on a deployment-bound terminal diagnostic from the attested channel"
        );

        let health_start = source
            .find("async fn wait_for_deployment_completion")
            .unwrap();
        let health_end = source[health_start..]
            .find("async fn ensure_password_storage_unlocked_for_config")
            .unwrap()
            + health_start;
        let health = &source[health_start..health_end];
        assert!(
            health.contains("deployment_bound_terminal_bootstrap_error"),
            "the health wait must use the deployment-bound terminal probe"
        );

        // Production ordering inside the post-auth reader is
        // verification -> predicate -> reader: the launch-identity predicate
        // must gate the bounded status read.
        let reader_start = source
            .find("async fn bound_tee_status_on_attested")
            .unwrap();
        let reader_end = source[reader_start..].find("\nasync fn ").unwrap() + reader_start;
        let reader = &source[reader_start..reader_end];
        let predicate = reader.find("launch_identity_binds_deployment").unwrap();
        let read = reader.find("bounded_status_json").unwrap();
        assert!(
            predicate < read,
            "the launch-identity predicate must gate the status read"
        );

        // No terminal-classifying status read may escape a complete budget:
        // the unlock wait, the runtime direct fallback, and the bootstrap
        // fallback arms all use the deadline-capped reads.
        let unlock_start = source
            .find("async fn wait_for_deploy_unlock_completion")
            .unwrap();
        let unlock_end = source[unlock_start..]
            .find("pub(crate) async fn claim_initial_ownership")
            .unwrap()
            + unlock_start;
        assert!(
            source[unlock_start..unlock_end]
                .contains("bounded_status_json_within(terminal_diagnostic_budget"),
            "the unlock wait's status read must be budget-capped to its deadline"
        );
        assert!(runtime.contains("bounded_status_json_within"));
        assert!(source.contains("bootstrap_status_within(terminal_diagnostic_budget"));
    }
}
