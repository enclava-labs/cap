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
                    omit_log_encryption_claim: false,
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

mod claim_recovery_sink_tests {
    /// Source-order and no-leak contracts for the auto-claim path shared by
    /// `enclava deploy` and `enclava template deploy`. The TEE mints the
    /// one-time recovery mnemonic exactly once and rejects a second claim, so
    /// these tests pin the two invariants that cannot be exercised against a
    /// real TEE in unit tests: the private sink is validated before any
    /// challenge/claim request, and no stdout/stderr statement ever interpolates
    /// the mnemonic.
    fn fn_body(source: &'static str, start_marker: &str, end_marker: &str) -> String {
        // CRLF checkouts (Windows autocrlf) must not break source matching:
        // normalize once so the LF-only multi-line markers below hold on
        // every checkout.
        let source = source.replace("\r\n", "\n");
        let start = source.find(start_marker).expect("start marker exists");
        let end = start + source[start..].find(end_marker).expect("end marker exists");
        source[start..end].to_string()
    }

    const APP_SOURCE: &str = include_str!("../../app.rs");

    #[test]
    fn fn_body_matches_markers_across_crlf_checkouts() {
        // Regression for the Windows failure: a CRLF checkout must not break
        // the LF-only multi-line end markers.
        let source = "start marker\r\n#[derive(Args)]\r\npub struct StatusArgs\r\nlater";
        let body = fn_body(
            source,
            "start marker",
            "#[derive(Args)]\npub struct StatusArgs",
        );
        // The slice spans from the start marker up to (not including) the
        // end marker, with normalized line endings.
        assert_eq!(body, "start marker\n");
    }

    #[test]
    fn claim_initial_ownership_gates_sink_before_any_network_claim() {
        let body = fn_body(
            APP_SOURCE,
            "pub(crate) async fn claim_initial_ownership",
            "#[derive(Args)]\npub struct StatusArgs",
        );

        let gate = body
            .find("prepare_recovery_mnemonic_sink")
            .expect("auto-claim runs the pre-claim sink gate");
        let challenge = body
            .find("bootstrap_challenge")
            .expect("auto-claim requests a challenge");
        let claim = body
            .find("bootstrap_claim")
            .expect("auto-claim sends the claim");
        assert!(
            gate < challenge && challenge < claim,
            "sink gate must reject unsafe modes/sessions/destinations before any claim request"
        );

        let store = body
            .find("store_recovery_mnemonic_after_claim")
            .expect("auto-claim persists the mnemonic post-claim");
        assert!(store > claim);
        assert!(
            !body.contains("present_and_capture_recovery_mnemonic"),
            "auto-claim must not use the removed stdout/stderr presentation path"
        );
    }

    #[test]
    fn claim_initial_ownership_halts_on_committed_incomplete_backup() {
        let body = fn_body(
            APP_SOURCE,
            "pub(crate) async fn claim_initial_ownership",
            "#[derive(Args)]\npub struct StatusArgs",
        );

        // Response loss after the TEE committed ownership must return the
        // stable incomplete-backup error (halting deploy/template), not warn and
        // proceed, and must never retry the claim.
        assert!(body.contains("ownership_committed_recovery_backup_incomplete"));
        assert!(
            !body.contains("accepted ownership; continuing"),
            "response loss must halt, not warn-and-continue"
        );
        let single_claim = body.match_indices("bootstrap_claim").count();
        assert_eq!(
            single_claim, 1,
            "auto-claim must never retry the claim after a committed ownership"
        );
    }

    #[test]
    fn deploy_rejects_no_store_mnemonic_before_submitting() {
        let body = fn_body(
            APP_SOURCE,
            "pub async fn deploy",
            "async fn set_deploy_config",
        );

        let guard = body
            .find("validate_recovery_mnemonic_sink_mode")
            .expect("deploy preflights the sink mode for predictable auto-claims");
        let submit = body
            .find("api.deploy(")
            .expect("deploy submits the deployment");
        assert!(
            guard < submit,
            "no-store rejection must run before the deployment is submitted"
        );
    }

    #[test]
    fn claim_paths_never_print_the_mnemonic_variable() {
        for line in APP_SOURCE.lines() {
            if line.contains("println!") || line.contains("eprintln!") {
                assert!(
                    !line.contains("{mnemonic"),
                    "stdout/stderr statement must not interpolate the mnemonic: {line}"
                );
            }
        }
    }
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
