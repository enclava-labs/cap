use super::*;
use ed25519_dalek::{Signer, SigningKey};
use enclava_common::descriptor::{
    Capabilities, EnvVar, Mount, OciRuntimeSpec, Port, Resources, SecurityContext, Sidecars,
    SignerIdentity,
};
use enclava_common::image::ImageRef;
use enclava_common::types::{Durability, ResourceLimits, UnlockMode};
use enclava_engine::types::{
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, StorageSpec, VolumeSpec,
    WorkloadSecurityProfile,
};

#[test]
fn signing_service_timeout_defaults_to_genpolicy_friendly_value() {
    assert_eq!(
        parse_signing_service_timeout(None).unwrap(),
        Duration::from_secs(DEFAULT_SIGNING_SERVICE_TIMEOUT_SECONDS)
    );
    assert_eq!(
        parse_signing_service_timeout(Some("180".to_string())).unwrap(),
        Duration::from_secs(180)
    );
}

#[test]
fn signing_service_timeout_rejects_invalid_values() {
    assert!(matches!(
        parse_signing_service_timeout(Some("0".to_string())).unwrap_err(),
        SigningServiceError::InvalidTimeout(_)
    ));
    assert!(matches!(
        parse_signing_service_timeout(Some("abc".to_string())).unwrap_err(),
        SigningServiceError::InvalidTimeout(_)
    ));
}

fn descriptor() -> DeploymentDescriptor {
    DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            nonce: [1; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec![],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [2; 32],
            image_ref:
                "ghcr.io/enclava-labs/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject:
                    "https://github.com/example/repo/.github/workflows/deploy.yml@refs/heads/main"
                        .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec![ENCLAVA_WAIT_EXEC_PATH.to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![EnvVar {
                    name: "RUST_LOG".to_string(),
                    value: "info".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![Mount {
                    source: "/data/app".to_string(),
                    destination: "/app/data".to_string(),
                    mount_type: "bind".to_string(),
                    options: vec!["rw".to_string()],
                }],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest:
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                        .to_string(),
                caddy_digest:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-owner".to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "cap-test".to_string(),
            expected_agent_policy_hash: Sha256::digest(
                b"package agent_policy\n\ndefault CreateContainerRequest := true\n",
            )
            .into(),
            expected_cc_init_data_hash: [5; 32],
            expected_kbs_policy_hash: Sha256::digest(b"package policy\n\ndefault allow := false\n")
                .into(),
        }
}

fn signing_artifacts(descriptor: DeploymentDescriptor) -> DeploymentSigningArtifacts {
    DeploymentSigningArtifacts {
        customer_descriptor_blob: "{}".to_string(),
        org_keyring_blob: "{}".to_string(),
        org_keyring_envelope: serde_json::json!({
            "keyring": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "version": 1,
                "members": [],
                "updated_at": "2026-04-01T00:00:00Z"
            },
            "signature": "cc".repeat(64),
            "signing_pubkey": "dd".repeat(32)
        }),
        descriptor_core_hash: descriptor_core_hash(&descriptor),
        descriptor,
        descriptor_signature: [0xaa; 64],
        descriptor_signing_key_id: "deployer-key-1".to_string(),
        descriptor_signing_pubkey: [0xbb; 32],
        org_keyring: OrgKeyring {
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            version: 1,
            members: vec![],
            updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
        },
        org_keyring_signature: [0xcc; 64],
        org_keyring_signing_pubkey: [0xdd; 32],
        org_keyring_fingerprint: [0xdd; 32],
    }
}

fn api_app_for_descriptor(
    descriptor: &DeploymentDescriptor,
    unlock_mode: crate::models::UnlockMode,
) -> App {
    App {
        id: descriptor.app_id,
        org_id: descriptor.org_id,
        name: descriptor.app_name.clone(),
        namespace: descriptor.namespace.clone(),
        instance_id: "demo-instance".to_string(),
        tenant_id: descriptor.org_slug.clone(),
        service_account: descriptor.service_account.clone(),
        bootstrap_owner_pubkey_hash: "aa".repeat(32),
        tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
        unlock_mode,
        domain: descriptor.app_domain.clone(),
        tee_domain: Some(descriptor.tee_domain.clone()),
        custom_domain: None,
        status: crate::models::AppStatus::Creating,
        signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
        signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
        signer_identity_set_at: Some("2026-04-01T00:00:00Z".parse().unwrap()),
        source_provider: None,
        source_repository: None,
        egress_allowlist: sqlx::types::Json(Vec::new()),
        egress_mode: "restricted".to_string(),
        created_at: "2026-04-01T00:00:00Z".parse().unwrap(),
        updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
    }
}

fn signed_policy_artifact(
    artifacts: &DeploymentSigningArtifacts,
    signing_key: &SigningKey,
) -> SignedPolicyArtifact {
    let rego_text = "package policy\n\ndefault allow := false\n".to_string();
    let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
    let agent_policy_text =
        "package agent_policy\n\ndefault CreateContainerRequest := true\n".to_string();
    let agent_policy_hash: [u8; 32] = Sha256::digest(agent_policy_text.as_bytes()).into();
    let metadata = PolicyMetadata {
        app_id: artifacts.descriptor.app_id.to_string(),
        deploy_id: artifacts.descriptor.deploy_id.to_string(),
        descriptor_core_hash: hex::encode(artifacts.descriptor_core_hash),
        descriptor_signing_pubkey: hex::encode(artifacts.descriptor_signing_pubkey),
        platform_release_version: artifacts.descriptor.platform_release_version.clone(),
        policy_template_id: artifacts.descriptor.policy_template_id.clone(),
        policy_template_sha256: hex::encode(artifacts.descriptor.policy_template_sha256),
        agent_policy_sha256: hex::encode(agent_policy_hash),
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
        signed_at: "2026-04-01T12:30:00+00:00".to_string(),
        key_id: "policy-test-key-v1".to_string(),
    };
    let signing_input = policy_artifact_signing_input(&metadata, &rego_hash).unwrap();
    let signature = signing_key.sign(&signing_input);
    SignedPolicyArtifact {
        metadata,
        rego_text,
        rego_sha256: hex::encode(rego_hash),
        agent_policy_text,
        agent_policy_sha256: hex::encode(agent_policy_hash),
        signature: hex::encode(signature.to_bytes()),
        verify_pubkey_b64: B64.encode(signing_key.verifying_key().to_bytes()),
        org_keyring: None,
    }
}

fn agent_policy_response_for(artifact: &SignedPolicyArtifact) -> AgentPolicyResponse {
    AgentPolicyResponse {
        agent_policy_text: artifact.agent_policy_text.clone(),
        agent_policy_sha256: artifact.agent_policy_sha256.clone(),
        genpolicy_version_pin: artifact.metadata.genpolicy_version_pin.clone(),
        log_encryption: None,
    }
}

#[test]
fn decodes_descriptor_and_keyring_blobs() {
    let descriptor = descriptor();
    let descriptor_blob = serde_json::json!({
        "descriptor": descriptor,
        "signature": "aa".repeat(64),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": "bb".repeat(32)
    })
    .to_string();
    let keyring_blob = serde_json::json!({
        "keyring": {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "version": 1,
            "members": [{
                "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "pubkey": "bb".repeat(32),
                "role": "deployer",
                "added_at": "2026-04-01T00:00:00Z"
            }],
            "updated_at": "2026-04-01T00:00:00Z"
        },
        "signature": "cc".repeat(64),
        "signing_pubkey": "dd".repeat(32)
    })
    .to_string();

    let decoded = decode_optional_blobs(Some(descriptor_blob), Some(keyring_blob))
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded.descriptor_core_hash,
        descriptor_core_hash(&decoded.descriptor)
    );
    assert_eq!(decoded.descriptor_signing_pubkey, [0xbb; 32]);
    assert_eq!(decoded.descriptor_signature, [0xaa; 64]);
    assert_ne!(decoded.org_keyring_fingerprint, [0; 32]);
}

#[test]
fn rejects_descriptor_unlock_mode_that_does_not_match_app() {
    let mut descriptor = descriptor();
    descriptor.unlock_mode = "auto".to_string();
    let artifacts = signing_artifacts(descriptor.clone());
    let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

    let err = artifacts
        .validate_deployment_inputs(
            &app,
            &descriptor.image_digest,
            &descriptor.api_signing_pubkey,
        )
        .unwrap_err();

    assert!(matches!(err, SigningServiceError::Mismatch(field) if field == "unlock_mode"));
}

#[test]
fn rejects_descriptor_for_different_api_signing_key() {
    let descriptor = descriptor();
    let artifacts = signing_artifacts(descriptor.clone());
    let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

    let err = artifacts
        .validate_deployment_inputs(&app, &descriptor.image_digest, "other-api-signing-pubkey")
        .unwrap_err();

    assert!(matches!(err, SigningServiceError::Mismatch(field) if field == "api_signing_pubkey"));
}

#[test]
fn rejects_descriptor_for_different_app_signer_and_image() {
    let descriptor = descriptor();
    let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

    let mut different_app = descriptor.clone();
    different_app.app_id = Uuid::new_v4();
    let err = signing_artifacts(different_app)
        .validate_deployment_inputs(
            &app,
            &descriptor.image_digest,
            &descriptor.api_signing_pubkey,
        )
        .unwrap_err();
    assert!(matches!(err, SigningServiceError::Mismatch(field) if field == "app_id"));

    let mut different_signer = descriptor.clone();
    different_signer.signer_identity.subject = "https://example.test/attacker".to_string();
    let err = signing_artifacts(different_signer)
        .validate_deployment_inputs(
            &app,
            &descriptor.image_digest,
            &descriptor.api_signing_pubkey,
        )
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "signer_identity.subject")
    );

    let err = signing_artifacts(descriptor.clone())
        .validate_deployment_inputs(
            &app,
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            &descriptor.api_signing_pubkey,
        )
        .unwrap_err();
    assert!(matches!(err, SigningServiceError::Mismatch(field) if field == "image_digest"));
}

#[test]
fn rejects_descriptor_without_workload_command() {
    let mut descriptor = descriptor();
    descriptor.oci_runtime_spec.args.clear();
    let artifacts = signing_artifacts(descriptor.clone());
    let app = api_app_for_descriptor(&descriptor, crate::models::UnlockMode::Password);

    let err = artifacts
        .validate_deployment_inputs(
            &app,
            &descriptor.image_digest,
            &descriptor.api_signing_pubkey,
        )
        .unwrap_err();

    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "oci_runtime_spec.args")
    );
}

#[test]
fn rejects_partial_blobs() {
    let err = decode_optional_blobs(Some("{}".to_string()), None).unwrap_err();
    assert!(matches!(err, SigningServiceError::PartialBlobs));
}

#[test]
fn policy_artifact_signing_input_matches_rev14_vector() {
    let metadata = PolicyMetadata {
        app_id: "22222222-2222-2222-2222-222222222222".to_string(),
        deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
        descriptor_core_hash: "0de9db2fd278a795754120604b68a1fae95d1ba19a66ed9a1df3a76df76f0eea"
            .to_string(),
        descriptor_signing_pubkey:
            "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0".to_string(),
        key_id: "policy-test-key-v1".to_string(),
        platform_release_version: "platform-2026.04".to_string(),
        policy_template_id: "trustee-resource-policy-v1".to_string(),
        policy_template_sha256: "e808dd6a40402bad50ea9522cdcd60b6739b78e21006942f4072a08355a24f10"
            .to_string(),
        agent_policy_sha256: "749bf91b70ba77fff6ad79581c0b3319cbff946e8f3783f8a44517fa50d470e9"
            .to_string(),
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
        signed_at: "2026-04-01T12:30:00+00:00".to_string(),
    };
    let rego_hash: [u8; 32] =
        hex::decode("244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372")
            .unwrap()
            .try_into()
            .unwrap();

    assert_eq!(
        hex::encode(canonical_policy_metadata_hash(&metadata).unwrap()),
        "364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83"
    );
    assert_eq!(
        hex::encode(policy_artifact_signing_input(&metadata, &rego_hash).unwrap()),
        "0007707572706f73650000001a656e636c6176612d706f6c6963792d61727469666163742d763100086d6574616461746100000020364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83000b7265676f5f73686132353600000020244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372"
    );
}

#[test]
fn validates_signed_policy_artifact_with_configured_key() {
    let artifacts = signing_artifacts(descriptor());
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifact = signed_policy_artifact(&artifacts, &signing_key);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap();
}

#[test]
fn validates_customer_supplied_policy_artifact_with_platform_key() {
    let artifacts = signing_artifacts(descriptor());
    let platform_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifact = signed_policy_artifact(&artifacts, &platform_key);
    let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

    artifacts
        .validate_signed_artifact(&artifact, &platform_pubkey_hex)
        .unwrap();
}

#[test]
fn rejects_descriptor_key_signed_customer_supplied_policy_artifact() {
    let descriptor_key = SigningKey::from_bytes(&[0x33; 32]);
    let platform_key = SigningKey::from_bytes(&[0x44; 32]);
    let mut artifacts = signing_artifacts(descriptor());
    artifacts.descriptor_signing_pubkey = descriptor_key.verifying_key().to_bytes();
    let artifact = signed_policy_artifact(&artifacts, &descriptor_key);
    let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &platform_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "artifact.verify_pubkey_b64")
    );
}

#[test]
fn validates_customer_artifact_against_canonical_agent_policy() {
    let artifacts = signing_artifacts(descriptor());
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifact = signed_policy_artifact(&artifacts, &signing_key);
    let generated = agent_policy_response_for(&artifact);

    artifacts
        .validate_canonical_agent_policy(&artifact, &generated)
        .unwrap();
}

#[test]
fn rejects_customer_artifact_when_descriptor_policy_hash_is_stale() {
    let artifacts = signing_artifacts(descriptor());
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifact = signed_policy_artifact(&artifacts, &signing_key);
    let agent_policy_text =
        "package agent_policy\n\ndefault CreateContainerRequest := false\n".to_string();
    let generated = AgentPolicyResponse {
        agent_policy_sha256: hex::encode(Sha256::digest(agent_policy_text.as_bytes())),
        agent_policy_text,
        genpolicy_version_pin: artifact.metadata.genpolicy_version_pin.clone(),
        log_encryption: None,
    };

    let err = artifacts
        .validate_canonical_agent_policy(&artifact, &generated)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "generated_agent_policy.expected_agent_policy_hash")
    );
}

#[test]
fn rejects_customer_supplied_policy_artifact_from_unconfigured_key() {
    let platform_key = SigningKey::from_bytes(&[0x33; 32]);
    let other_key = SigningKey::from_bytes(&[0x44; 32]);
    let artifacts = signing_artifacts(descriptor());
    let artifact = signed_policy_artifact(&artifacts, &other_key);
    let platform_pubkey_hex = hex::encode(platform_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &platform_pubkey_hex)
        .unwrap_err();
    assert!(matches!(err, SigningServiceError::Mismatch(_)));
}

#[test]
fn rejects_signed_policy_artifact_with_wrong_expected_kbs_hash() {
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let mut artifacts = signing_artifacts(descriptor());
    artifacts.descriptor.expected_kbs_policy_hash = [0xee; 32];
    artifacts.descriptor_signing_pubkey = signing_key.verifying_key().to_bytes();
    let artifact = signed_policy_artifact(&artifacts, &signing_key);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "expected_kbs_policy_hash")
    );
}

#[test]
fn rejects_signed_policy_artifact_random_signature() {
    let artifacts = signing_artifacts(descriptor());
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifact.signature = "11".repeat(64);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(matches!(err, SigningServiceError::InvalidSignature));
}

#[test]
fn signed_artifact_agent_policy_drives_cc_init_data_hash() {
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let mut artifacts = signing_artifacts(descriptor());
    let artifact = signed_policy_artifact(&artifacts, &signing_key);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap();

    let generated = artifacts.generated_agent_policy(&artifact).unwrap();
    let mut app = confidential_app_for_descriptor(&artifacts.descriptor);
    app.workload_artifact_binding = Some(artifacts.binding());
    app.generated_agent_policy = Some(generated);

    let toml = enclava_engine::manifest::cc_init_data::build_toml(&app);
    assert!(toml.contains(&format!(
        "\"policy.rego\" = '''\n{}'''",
        artifact.agent_policy_text
    )));

    artifacts.descriptor.expected_cc_init_data_hash = Sha256::digest(toml.as_bytes()).into();
    let (_encoded, hash_hex) = enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app);
    artifacts
        .validate_rendered_cc_init_data_hash(&hash_hex)
        .unwrap();
}

#[test]
fn trustee_policy_copy_omits_only_duplicated_agent_policy_text() {
    let artifacts = signing_artifacts(descriptor());
    let artifact = signed_policy_artifact(&artifacts, &SigningKey::from_bytes(&[0x33; 32]));
    let mut expected = serde_json::to_value(&artifact).unwrap();
    expected
        .as_object_mut()
        .unwrap()
        .remove("agent_policy_text");

    let actual: serde_json::Value =
        serde_json::from_str(&super::trustee_policy_json(&artifact).unwrap()).unwrap();
    assert_eq!(actual, expected);
}

#[test]
fn rejects_rendered_cc_init_data_hash_mismatch() {
    let artifacts = signing_artifacts(descriptor());
    let err = artifacts
        .validate_rendered_cc_init_data_hash(&"00".repeat(32))
        .unwrap_err();

    assert!(
        matches!(err, SigningServiceError::Mismatch(field) if field == "expected_cc_init_data_hash")
    );
}

fn confidential_app_for_descriptor(descriptor: &DeploymentDescriptor) -> ConfidentialApp {
    let image = format!("ghcr.io/enclava-labs/demo@{}", descriptor.image_digest);
    ConfidentialApp {
        app_id: descriptor.app_id,
        deployment_id: descriptor.deploy_id,
        name: descriptor.app_name.clone(),
        namespace: descriptor.namespace.clone(),
        instance_id: "demo-instance".to_string(),
        tenant_id: descriptor.org_slug.clone(),
        bootstrap_owner_pubkey_hash: "aa".repeat(32),
        tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
        service_account: descriptor.service_account.clone(),
        image_pull_secret_name: None,
        signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
        signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
        containers: vec![Container {
            name: descriptor.app_name.clone(),
            image: ImageRef::parse(&image).unwrap(),
            port: Some(3000),
            command: None,
            env: std::collections::HashMap::new(),
            storage_paths: vec!["/app/data".to_string()],
            workload_security_profile: WorkloadSecurityProfile::Restricted,
            is_primary: true,
        }],
        storage: StorageSpec {
            app_data: VolumeSpec {
                size: "10Gi".to_string(),
                device_path: "/dev/csi0".to_string(),
                mount_path: "/data".to_string(),
                durability: Durability::DurableState,
                bootstrap_policy: enclava_common::types::BootstrapPolicy::FirstBootOnly,
                bind_mounts: vec![BindMount {
                    source: "/data/app".to_string(),
                    destination: "/app/data".to_string(),
                }],
            },
            tls_data: VolumeSpec {
                size: "1Gi".to_string(),
                device_path: "/dev/csi1".to_string(),
                mount_path: "/tls".to_string(),
                durability: Durability::DisposableState,
                bootstrap_policy: enclava_common::types::BootstrapPolicy::AllowReinit,
                bind_mounts: vec![],
            },
        },
        unlock_mode: UnlockMode::Password,
        domain: DomainSpec {
            platform_domain: descriptor.app_domain.clone(),
            tee_domain: descriptor.tee_domain.clone(),
            custom_domain: None,
        },
        api_signing_pubkey: String::new(),
        api_url: String::new(),
        resources: ResourceLimits {
            cpu: "1".to_string(),
            memory: "512Mi".to_string(),
        },
        attestation: AttestationConfig {
            proxy_image: ImageRef::parse(&format!(
                "ghcr.io/enclava-labs/attestation-proxy@{}",
                descriptor.sidecars.attestation_proxy_digest
            ))
            .unwrap(),
            caddy_image: ImageRef::parse(&format!(
                "ghcr.io/enclava-labs/caddy-ingress@{}",
                descriptor.sidecars.caddy_digest
            ))
            .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
            trustee_policy_read_available: true,
            workload_artifacts_url: Some("https://api.example.test/artifacts".to_string()),
            tls_certificate_broker_url: None,
            trustee_policy_url: Some("https://kbs.example.test/policy".to_string()),
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: Some("bb".repeat(32)),
            signing_service_pubkey_hex: Some("bb".repeat(32)),
            verification_material: None,
        },
        egress_mode: enclava_engine::types::EgressMode::Restricted,
        public_internet_egress_excluded_cidrs: Vec::new(),
        egress_allowlist: vec![],
        log_encryption: None,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    }
}
