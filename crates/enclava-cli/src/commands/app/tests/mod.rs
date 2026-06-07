use super::*;
use enclava_cli::app_config::{
    AppSection, EgressRuleConfig, EgressSection, ResourcesSection, StorageSection, UnlockSection,
};

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
        tee_domain: Some("demo.org.tee.enclava.dev".to_string()),
        custom_domain: None,
        status: "created".to_string(),
        unlock_mode: "password".to_string(),
        signer_identity_subject: Some(
            "https://github.com/acme/demo/.github/workflows/image.yml@refs/heads/main".to_string(),
        ),
        signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
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
        egress: EgressSection {
            allow: vec![EgressRuleConfig {
                host: "inference.tinfoil.sh".to_string(),
                ports: vec![443],
            }],
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
    }
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
            },
        )
        .unwrap();
    assert_eq!(app.api_signing_pubkey, "test-api-signing-pubkey");
    assert_eq!(app.egress_allowlist.len(), 1);
    assert_eq!(app.egress_allowlist[0].host, "inference.tinfoil.sh");

    let cc_toml = cc_init_data::build_toml_with_options(
        &app,
        &cc_init_data::CcInitDataOptions {
            kbs_url: "https://kbs.example.test:8080".to_string(),
            kbs_ca_cert_pem: None,
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
    };

    let app = confidential_app_for_cc_hash(
            &test_app_response(),
            &test_app_config(),
            ConfidentialAppForCcHash {
                image: enclava_common::image::ImageRef::parse(
                    "ghcr.io/acme/demo@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
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
            },
        )
        .unwrap();
    assert_eq!(app.api_signing_pubkey, "context-api-signing-pubkey");

    let cc_toml = cc_init_data::build_toml_with_options(
        &app,
        &cc_init_data::CcInitDataOptions {
            kbs_url: "https://kbs.example.test:8080".to_string(),
            kbs_ca_cert_pem: None,
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
fn deploy_claims_fresh_created_password_app_when_unlock_status_is_unavailable() {
    assert!(deploy_needs_initial_claim(true, None, "creating"));
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
fn deploy_bootstrap_probe_uses_ownership_timeout_client() {
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
        body.contains("TeeClient::new_for_ownership(&endpoint.tee_url)"),
        "bootstrap probe must allow ownership attestation to take longer than the short poll interval"
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
