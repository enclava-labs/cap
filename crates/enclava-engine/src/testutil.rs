//! Test fixtures for enclava-engine. Only available with the `testutil` feature.

use crate::types::*;
use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode};
use std::collections::HashMap;
use uuid::Uuid;

/// The pubkey hash used in all test fixtures.
pub const TEST_PUBKEY_HASH: &str =
    "aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd";

/// A minimal valid ConfidentialApp for testing (auto-unlock mode).
pub fn sample_app() -> ConfidentialApp {
    let tenant_id = "test-org".to_string();
    let instance_id = "test-org-a1b2c3d4".to_string();
    let identity_hash =
        enclava_common::crypto::compute_identity_hash(&tenant_id, &instance_id, TEST_PUBKEY_HASH);

    ConfidentialApp {
        app_id: Uuid::parse_str("a1b2c3d4-e5f6-7890-abcd-ef1234567890").unwrap(),
        deployment_id: Uuid::parse_str("11111111-2222-3333-4444-555555555555").unwrap(),
        name: "test-app".to_string(),
        namespace: "cap-test-org-test-app".to_string(),
        instance_id,
        tenant_id,
        bootstrap_owner_pubkey_hash: TEST_PUBKEY_HASH.to_string(),
        tenant_instance_identity_hash: identity_hash,
        service_account: "cap-test-app-sa".to_string(),
        image_pull_secret_name: None,
        signer_identity_subject: Some(
            "https://github.com/test/app/.github/workflows/build.yml@refs/heads/main".to_string(),
        ),
        signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
        containers: vec![Container {
            name: "web".to_string(),
            image: ImageRef::parse(
                "ghcr.io/test/app@sha256:\
                 abcd1234abcd1234abcd1234abcd1234\
                 abcd1234abcd1234abcd1234abcd1234",
            )
            .unwrap(),
            port: Some(3000),
            command: None,
            env: HashMap::new(),
            storage_paths: vec!["/app/data".to_string()],
            workload_security_profile: WorkloadSecurityProfile::Restricted,
            is_primary: true,
        }],
        storage: StorageSpec::new("10Gi", "2Gi"),
        unlock_mode: UnlockMode::Auto,
        domain: DomainSpec {
            platform_domain: "test-app.abcd1234.enclava.dev".to_string(),
            tee_domain: "test-app.abcd1234.tee.enclava.dev".to_string(),
            custom_domain: None,
        },
        api_signing_pubkey: "test-pubkey-placeholder".to_string(),
        api_url: "https://api.enclava.dev".to_string(),
        resources: ResourceLimits::default(),
        attestation: AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/attestation-proxy@sha256:\
                 1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/caddy-ingress@sha256:\
                 2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            acme_ca_url: default_acme_ca_url(),
            caddy_tls_mode: CaddyTlsMode::Acme,
            trustee_policy_read_available: false,
            workload_artifacts_url: None,
            tls_certificate_broker_url: None,
            amd_kds_base_url: Some(
                "http://amd-kds-relay.cap-test01.svc.cluster.local:8080/vcek/v1".to_string(),
            ),
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
            verification_material: None,
        },
        egress_mode: EgressMode::Restricted,
        public_internet_egress_excluded_cidrs: Vec::new(),
        allow_internal_egress: false,
        egress_allowlist: Vec::new(),
        log_encryption: None,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    }
}

/// A password-mode app with identity fields populated.
pub fn sample_password_app() -> ConfidentialApp {
    let mut app = sample_app();
    app.unlock_mode = UnlockMode::Password;
    app
}
