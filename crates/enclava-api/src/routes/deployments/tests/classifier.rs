use super::*;
use crate::cosign::VerificationPolicy;
use crate::models::{App, AppStatus, DeployStatus, Deployment, Role, Trigger, UnlockMode};
use enclava_common::image::ImageRef;
use enclava_engine::types::AttestationConfig;

fn idempotency_app() -> App {
    App {
        id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
        org_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
        name: "customer-app".to_string(),
        namespace: "cap-test-customer-app".to_string(),
        instance_id: "test-customer-app".to_string(),
        tenant_id: "test".to_string(),
        service_account: "cap-customer-app-sa".to_string(),
        bootstrap_owner_pubkey_hash: "11".repeat(32),
        tenant_instance_identity_hash: "22".repeat(32),
        unlock_mode: UnlockMode::Auto,
        domain: "customer-app.test.enclava.dev".to_string(),
        tee_domain: Some("customer-app.test.tee.enclava.dev".to_string()),
        custom_domain: None,
        status: AppStatus::Creating,
        signer_identity_subject: Some(
            "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main"
                .to_string(),
        ),
        signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        signer_identity_set_at: Some(chrono::Utc::now()),
        source_provider: Some("github".to_string()),
        source_repository: Some("acme/confidential-app".to_string()),
        egress_allowlist: serde_json::json!([]),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn idempotency_deployment(app: &App) -> Deployment {
    Deployment {
        id: Uuid::parse_str("cccccccc-cccc-cccc-cccc-cccccccccccc").unwrap(),
        org_id: Some(app.org_id),
        app_id: app.id,
        trigger: Trigger::Api,
        status: DeployStatus::Pending,
        spec_snapshot: serde_json::json!({
            "app_name": app.name,
            "namespace": app.namespace,
            "instance_id": app.instance_id,
            "image": "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "container_name": "app",
            "resources": null,
            "external_id": "deploy-123",
            "source_provider": "github",
            "source_repository": "acme/confidential-app",
        }),
        manifest_hash: None,
        image_digest: Some(
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        error_message: None,
        created_at: chrono::Utc::now(),
        completed_at: None,
        cosign_verified: true,
        provenance_attestation: None,
        sbom: None,
        external_id: Some("deploy-123".to_string()),
        source_provider: Some("github".to_string()),
        source_repository: Some("acme/confidential-app".to_string()),
    }
}

fn idempotency_request(app_name: &str) -> GenericDeploymentRequest {
    GenericDeploymentRequest {
            external_id: Some("deploy-123".to_string()),
            app: GenericDeploymentApp {
                name: app_name.to_string(),
                create_if_missing: true,
                unlock_mode: "auto".to_string(),
                bootstrap_pubkey_hash: None,
                egress_allowlist: Vec::new(),
            },
            source: GenericDeploymentSource {
                provider: SourceProvider::GitHub,
                repository: "acme/confidential-app".to_string(),
            },
            workload: GenericDeploymentWorkload {
                image: "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
                container_name: Some("app".to_string()),
                resources: None,
            },
            signing: GenericDeploymentSigning {
                subject: "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main"
                    .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            security: GenericDeploymentSecurity::default(),
        }
}

fn attestation_config() -> AttestationConfig {
    AttestationConfig {
            proxy_image: ImageRef::parse("ghcr.io/enclava-labs/attestation-proxy@sha256:996c32b0726a90d82c08ae095b4bfbe01e47617cf929dc1eed3bd981f4e8155d")
                .unwrap(),
            caddy_image: ImageRef::parse("ghcr.io/enclava-labs/caddy-ingress@sha256:31a43cbfce0399cc83d22aabcb25346badcddfb46f4984eccd410c22e691ca6f")
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
        }
}

#[test]
fn github_actions_oidc_url_with_at_is_url_policy() {
    let policy = classify_signer_identity(
        "https://github.com/me/repo/.github/workflows/build.yml@refs/heads/main",
        "https://token.actions.githubusercontent.com",
    );
    assert!(matches!(
        policy,
        VerificationPolicy::FulcioUrlIdentity { .. }
    ));
}

#[test]
fn email_subject_is_email_policy() {
    let policy = classify_signer_identity("alice@example.com", "https://accounts.google.com");
    assert!(matches!(
        policy,
        VerificationPolicy::FulcioEmailIdentity { .. }
    ));
}

#[test]
fn http_url_subject_is_url_policy() {
    let policy = classify_signer_identity(
        "http://gitlab.example.com/foo@v1",
        "https://gitlab.example.com",
    );
    assert!(matches!(
        policy,
        VerificationPolicy::FulcioUrlIdentity { .. }
    ));
}

#[test]
fn signed_deploy_required_when_policy_signing_boundary_is_configured() {
    assert!(!customer_signed_deploy_required(None, false));
    assert!(customer_signed_deploy_required(None, true));

    let mut cfg = attestation_config();
    assert!(!customer_signed_deploy_required(Some(&cfg), false));

    cfg.signing_service_pubkey_hex = Some("11".repeat(32));
    assert!(customer_signed_deploy_required(Some(&cfg), false));

    cfg.signing_service_pubkey_hex = None;
    cfg.platform_trustee_policy_pubkey_hex = Some("22".repeat(32));
    assert!(customer_signed_deploy_required(Some(&cfg), false));

    cfg.platform_trustee_policy_pubkey_hex = None;
    cfg.trustee_policy_read_available = true;
    assert!(customer_signed_deploy_required(Some(&cfg), false));
}

#[test]
fn signed_deploy_hash_validation_uses_local_artifact_delivery_mode() {
    let mut cfg = attestation_config();
    cfg.trustee_policy_read_available = true;
    cfg.workload_artifacts_url = Some("https://api.example.test/workload-artifacts".into());
    cfg.trustee_policy_url = Some("https://kbs.example.test/resource-policy/body".into());

    select_local_signed_artifact_delivery(&mut cfg);

    assert_eq!(cfg.local_workload_artifacts_json.as_deref(), Some("{}"));
    assert_eq!(cfg.local_trustee_policy_json.as_deref(), Some("{}"));
}

#[test]
fn signed_deploy_path_ensures_app_and_tee_dns_pair() {
    let source = include_str!("../../deployments.rs");
    let deploy_body = source
        .split("pub async fn deploy")
        .nth(1)
        .expect("deploy route exists");

    assert!(
        deploy_body.contains("crate::dns::ensure_dns_pair"),
        "signed deploy must ensure both app and TEE DNS hostnames"
    );
}

#[test]
fn parse_memory_gi_accepts_large_mi_limits_after_conversion() {
    assert_eq!(parse_memory_gi("16384Mi").unwrap(), 16.0);
}

#[test]
fn deploy_persists_requested_resources_before_rendering_manifest() {
    let source = include_str!("../../deployments.rs");
    let deploy_body = source
        .split("pub async fn deploy")
        .nth(1)
        .expect("deploy route exists");
    let update_resources = deploy_body
        .find("UPDATE app_resources")
        .expect("deploy route must persist requested resources");
    let render_manifest = deploy_body
        .find("build_confidential_app")
        .expect("deploy route renders app manifest");

    assert!(
        update_resources < render_manifest,
        "requested resources must be persisted before manifest rendering reads app_resources"
    );
}

#[test]
fn signed_deploy_derives_missing_resources_from_descriptor_before_rendering_manifest() {
    let source = include_str!("../../deployments.rs");
    let deploy_body = source
        .split("pub async fn deploy")
        .nth(1)
        .expect("deploy route exists");
    let merge_resources = deploy_body
        .find("merge_signed_descriptor_resources")
        .expect("signed deploy must merge descriptor resources into deploy resources");
    let render_manifest = deploy_body
        .find("build_confidential_app")
        .expect("deploy route renders app manifest");

    assert!(
        merge_resources < render_manifest,
        "signed descriptor resources must be applied before manifest rendering reads app_resources"
    );
}

#[test]
fn descriptor_deploy_resources_extracts_cpu_and_memory_limits() {
    let resources = descriptor_deploy_resources_from_limits(&[
        enclava_common::descriptor::EnvVar {
            name: "memory".to_string(),
            value: "8Gi".to_string(),
        },
        enclava_common::descriptor::EnvVar {
            name: "cpu".to_string(),
            value: "4".to_string(),
        },
    ])
    .expect("descriptor resources should be present");

    assert_eq!(
        resources,
        DeployResources {
            cpu: Some("4".to_string()),
            memory: Some("8Gi".to_string()),
            storage: None,
        }
    );
}

#[test]
fn idempotent_retry_requires_same_deployment_payload() {
    let app = idempotency_app();
    let deployment = idempotency_deployment(&app);

    ensure_idempotent_retry_matches(&deployment, &app, &idempotency_request(&app.name)).unwrap();

    let err =
        ensure_idempotent_retry_matches(&deployment, &app, &idempotency_request("different-app"))
            .unwrap_err();

    assert_eq!(err.0, StatusCode::CONFLICT);
    assert_eq!(
        err.1.0["error"].as_str(),
        Some("external_id already exists with different app.name")
    );
}

#[test]
fn external_id_rejects_empty_or_padded_values() {
    validate_external_id(Some("deploy-123")).unwrap();

    for value in ["", " deploy-123", "deploy-123 "] {
        let err = validate_external_id(Some(value)).unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }
}

#[test]
fn cap_core_source_has_no_product_specific_deployment_customizations() {
    let source_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needles = [
        ["her", "mes"].concat(),
        ["secret", "_", "agent"].concat(),
        ["nut", "shell"].concat(),
    ];
    let mut findings = Vec::new();
    scan_rs_files_for_needles(&source_dir, &needles, &mut findings);

    assert!(
        findings.is_empty(),
        "CAP core source contains product-specific deployment customizations: {findings:?}"
    );
}

fn scan_rs_files_for_needles(
    dir: &std::path::Path,
    needles: &[String],
    findings: &mut Vec<String>,
) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            scan_rs_files_for_needles(&path, needles, findings);
            continue;
        }
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("rs") {
            continue;
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        let normalized = contents.to_ascii_lowercase();
        for needle in needles {
            if normalized.contains(needle) {
                findings.push(format!("{} contains {}", path.display(), needle));
            }
        }
    }
}

#[tokio::test]
async fn deploy_rejects_member_before_database_access() {
    let result = deploy(
        crate::test_support::auth_context(Role::Member, &[]),
        State(crate::test_support::lazy_state()),
        Path("demo".to_string()),
        Json(DeployRequest {
            image: "ghcr.io/example/demo:latest".to_string(),
            container_name: None,
            resources: None,
            external_id: None,
            source_provider: None,
            source_repository: None,
            customer_descriptor_blob: None,
            org_keyring_blob: None,
            signed_policy_artifact: None,
        }),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("member deploy unexpectedly passed authorization"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn rollback_rejects_unscoped_api_key_before_database_access() {
    let result = rollback(
        crate::test_support::auth_context(Role::Admin, &["apps:read"]),
        State(crate::test_support::lazy_state()),
        Path("demo".to_string()),
        Json(RollbackRequest {
            deployment_id: Some(Uuid::new_v4()),
        }),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("unscoped rollback unexpectedly passed authorization"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn generic_config_token_rejects_unscoped_api_key_before_database_access() {
    let result = generic_config_token(
        crate::test_support::auth_context(Role::Admin, &["apps:read"]),
        State(crate::test_support::lazy_state()),
        Path(Uuid::new_v4()),
    )
    .await;
    let err = match result {
        Ok(_) => panic!("unscoped generic config token unexpectedly passed authorization"),
        Err(err) => err,
    };

    assert_eq!(err.0, StatusCode::FORBIDDEN);
}
