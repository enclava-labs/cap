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
    WorkloadArtifactBinding, WorkloadSecurityProfile,
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
            independent_verification: true,
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
    // #128: decode verifies the customer signatures, so both envelopes are
    // signed with real keys (descriptor: deployer key, keyring: owner key).
    let deployer_key = SigningKey::from_bytes(&[0xbb; 32]);
    let owner_key = SigningKey::from_bytes(&[0xdd; 32]);
    let descriptor = descriptor();
    let descriptor_blob = serde_json::json!({
        "descriptor": descriptor,
        "signature": hex::encode(
            deployer_key
                .sign(&enclava_common::descriptor::descriptor_canonical_bytes(&descriptor))
                .to_bytes()
        ),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": hex::encode(deployer_key.verifying_key().to_bytes()),
    })
    .to_string();
    let keyring = OrgKeyring {
        org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        version: 1,
        members: vec![
            TestKeyringMember {
                user_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
                pubkey: deployer_key.verifying_key().to_bytes(),
                role: KeyringRole::Deployer,
                added_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            },
            TestKeyringMember {
                user_id: Uuid::parse_str("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb").unwrap(),
                pubkey: owner_key.verifying_key().to_bytes(),
                role: KeyringRole::Owner,
                added_at: "2026-04-01T00:00:00Z".parse().unwrap(),
            },
        ],
        updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
    };
    let keyring_blob = serde_json::json!({
        "keyring": keyring,
        "signature": hex::encode(
            owner_key
                .sign(&canonical_keyring_bytes(&keyring))
                .to_bytes()
        ),
        "signing_pubkey": hex::encode(owner_key.verifying_key().to_bytes()),
    })
    .to_string();

    let decoded = decode_optional_blobs(Some(descriptor_blob), Some(keyring_blob))
        .unwrap()
        .unwrap();
    assert_eq!(
        decoded.descriptor_core_hash,
        descriptor_core_hash(&decoded.descriptor)
    );
    assert_eq!(
        decoded.descriptor_signing_pubkey,
        deployer_key.verifying_key().to_bytes()
    );
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
fn rejects_descriptor_without_independent_verification_contract() {
    let mut descriptor = descriptor();
    descriptor.independent_verification = false;
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
        matches!(err, SigningServiceError::Mismatch(field) if field == "independent_verification")
    );
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
fn rejects_oversized_signing_blobs_before_parsing() {
    // #128: per-blob byte caps must reject oversized payloads before any
    // base64 decoding or JSON parsing, regardless of content validity.
    let mut descriptor = descriptor();
    descriptor.app_name = "x".repeat(300 * 1024);
    let descriptor_blob = serde_json::json!({
        "descriptor": descriptor,
        "signature": "aa".repeat(64),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": "bb".repeat(32)
    })
    .to_string();
    assert!(descriptor_blob.len() > MAX_DESCRIPTOR_BLOB_BYTES);

    let err = decode_optional_blobs(Some(descriptor_blob), Some(valid_keyring_blob())).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg)
            if msg.contains("customer_descriptor_blob") && msg.contains("exceeds")),
        "got: {err:?}"
    );

    let mut keyring_value: serde_json::Value = serde_json::from_str(&valid_keyring_blob()).unwrap();
    keyring_value["keyring"].as_object_mut().unwrap().insert(
        "padding".to_string(),
        serde_json::json!("e".repeat(300 * 1024)),
    );
    let err = decode_optional_blobs(
        Some(valid_descriptor_blob()),
        Some(keyring_value.to_string()),
    )
    .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg)
            if msg.contains("org_keyring_blob") && msg.contains("exceeds")),
        "got: {err:?}"
    );
}

#[test]
fn blob_cap_boundary_is_exact() {
    // #128: a blob at exactly the cap is not rejected as oversized (it then
    // fails signature checks, which is fine); one byte over is rejected as
    // oversized before parsing.
    let mut blob: String = "{".to_string();
    blob.push_str(&" ".repeat(MAX_ORG_KEYRING_BLOB_BYTES - 2));
    blob.push('}');
    assert_eq!(blob.len(), MAX_ORG_KEYRING_BLOB_BYTES);
    let err = decode_optional_blobs(Some(valid_descriptor_blob()), Some(blob.clone())).unwrap_err();
    assert!(
        !matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("exceeds")),
        "at-cap blob must not be rejected as oversized: {err:?}"
    );
    // Grow INSIDE the trimmed region (trailing whitespace is trimmed).
    blob.insert(blob.len() - 1, ' ');
    assert!(blob.trim().len() > MAX_ORG_KEYRING_BLOB_BYTES);
    let err = decode_optional_blobs(Some(valid_descriptor_blob()), Some(blob)).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("exceeds")),
        "got: {err:?}"
    );
}

fn valid_descriptor_blob() -> String {
    serde_json::json!({
        "descriptor": descriptor(),
        "signature": "aa".repeat(64),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": "bb".repeat(32)
    })
    .to_string()
}

/// Build a fully signed blob pair (descriptor signed by the deployer key,
/// keyring signed by the owner key) for decode-path tests (#128).
fn signed_blob_pair() -> (String, String, SigningKey, SigningKey) {
    let deployer_key = SigningKey::from_bytes(&[0xbb; 32]);
    let owner_key = SigningKey::from_bytes(&[0xdd; 32]);
    let descriptor = descriptor();
    let descriptor_blob = serde_json::json!({
        "descriptor": descriptor,
        "signature": hex::encode(
            deployer_key
                .sign(&enclava_common::descriptor::descriptor_canonical_bytes(&descriptor))
                .to_bytes()
        ),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": hex::encode(deployer_key.verifying_key().to_bytes()),
    })
    .to_string();
    let keyring = OrgKeyring {
        org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        version: 1,
        members: vec![TestKeyringMember {
            user_id: Uuid::parse_str("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa").unwrap(),
            pubkey: owner_key.verifying_key().to_bytes(),
            role: TestKeyringRole::Owner,
            added_at: "2026-04-01T00:00:00Z".parse().unwrap(),
        }],
        updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
    };
    let keyring_blob = serde_json::json!({
        "keyring": keyring,
        "signature": hex::encode(
            owner_key
                .sign(&canonical_keyring_bytes_test(&keyring))
                .to_bytes()
        ),
        "signing_pubkey": hex::encode(owner_key.verifying_key().to_bytes()),
    })
    .to_string();
    (descriptor_blob, keyring_blob, deployer_key, owner_key)
}

#[test]
fn decode_rejects_tampered_customer_signatures() {
    // #128 (review warning 2): the decode-time customer-signature verify
    // must actually bite — a tampered signature surfaces InvalidSignature
    // from decode_optional_blobs itself, before any hash/fingerprint work
    // or caller-side semantic comparison.
    let (descriptor_blob, keyring_blob, _deployer_key, _owner_key) = signed_blob_pair();
    // Sanity: the untampered pair decodes.
    assert!(
        decode_optional_blobs(Some(descriptor_blob.clone()), Some(keyring_blob.clone()))
            .unwrap()
            .is_some()
    );

    // Tampered descriptor signature.
    let mut value: serde_json::Value = serde_json::from_str(&descriptor_blob).unwrap();
    value["signature"] = serde_json::json!(hex::encode([0x99; 64]));
    let err =
        decode_optional_blobs(Some(value.to_string()), Some(keyring_blob.clone())).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::InvalidSignature),
        "tampered descriptor signature must fail as InvalidSignature, got: {err:?}"
    );

    // Tampered keyring signature.
    let mut value: serde_json::Value = serde_json::from_str(&keyring_blob).unwrap();
    value["signature"] = serde_json::json!(hex::encode([0x99; 64]));
    let err = decode_optional_blobs(Some(descriptor_blob), Some(value.to_string())).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::InvalidSignature),
        "tampered keyring signature must fail as InvalidSignature, got: {err:?}"
    );

    // Tampered keyring whose embedded signing_pubkey is NOT an owner member
    // must still surface InvalidSignature (crypto first), not a semantic
    // Mismatch("org_keyring.signing_pubkey owner member").
    let stray_key = SigningKey::from_bytes(&[0xee; 32]);
    let mut keyring_value: serde_json::Value = serde_json::from_str(&keyring_blob).unwrap();
    keyring_value["signature"] = serde_json::json!(hex::encode(
        stray_key
            .sign(&canonical_keyring_bytes_test(&valid_keyring()))
            .to_bytes()
    ));
    keyring_value["signing_pubkey"] =
        serde_json::json!(hex::encode(stray_key.verifying_key().to_bytes()));
    let err = decode_optional_blobs(Some(signed_blob_pair().0), Some(keyring_value.to_string()))
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::InvalidSignature),
        "bad keyring signature under a non-owner pubkey must fail as InvalidSignature, got: {err:?}"
    );
}

fn valid_keyring() -> OrgKeyring {
    OrgKeyring {
        org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        version: 1,
        members: vec![],
        updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
    }
}

#[test]
fn max_legal_caps_compose_under_proof_bundle_budgets() {
    // #128 (review warning 1): a max-legal combination (rego at
    // MAX_REGO_TEXT_BYTES, agent policy at MAX_POLICY_TEXT_BYTES) must
    // produce workload_artifacts_json and trustee_policy_json that both fit
    // the downstream verifier field budgets, so ingress acceptance implies
    // launchability.
    let artifacts = signing_artifacts(descriptor());
    let mut artifact = signed_policy_artifact(&artifacts, &SigningKey::from_bytes(&[0x11; 32]));
    artifact.rego_text = "r".repeat(MAX_REGO_TEXT_BYTES);
    artifact.agent_policy_text = "a".repeat(MAX_POLICY_TEXT_BYTES);
    // The stored row carries the attached keyring envelope.
    artifacts.attach_customer_authority(&mut artifact).unwrap();

    let workload = workload_artifacts_json(&artifacts, &artifact).unwrap();
    assert!(
        workload.len() <= MAX_WORKLOAD_ARTIFACTS_JSON_BYTES,
        "max-legal compose produced workload_artifacts_json of {} bytes (budget {})",
        workload.len(),
        MAX_WORKLOAD_ARTIFACTS_JSON_BYTES
    );
    let trustee = trustee_policy_json(&artifact).unwrap();
    assert!(
        trustee.len() <= MAX_TRUSTEE_POLICY_JSON_BYTES,
        "max-legal compose produced trustee_policy_json of {} bytes (budget {})",
        trustee.len(),
        MAX_TRUSTEE_POLICY_JSON_BYTES
    );
    // The exact-budget check accepts the max-legal composition.
    validate_proof_bundle_budget(&artifacts, &artifact).unwrap();
}

#[test]
fn legacy_padded_stored_artifact_is_rejected_at_dispatch() {
    // #128 review follow-up (Codex P2): a legacy row whose stored
    // signed_policy_artifact carries unknown-field padding inside
    // org_keyring normalizes cleanly in attach_customer_authority (so
    // validate_proof_bundle_budget passes on the normalized clone), but
    // dispatch forwards the RAW stored strings and
    // build_verification_material charges those exact bytes at apply time.
    // The dispatch-time revalidation must therefore reject the raw
    // forwarded strings too.
    // Simulate the legacy stored row: the padded envelope (matching
    // fingerprint/signature/pubkey) plus unknown-field padding that blows
    // the trustee_policy_json budget only in its raw serialized form. The
    // fixture's org_keyring_envelope must carry the REAL fingerprint of
    // artifacts.org_keyring for attach_customer_authority's matches to hold.
    let mut artifacts = signing_artifacts(descriptor());
    artifacts.org_keyring_fingerprint = keyring_fingerprint(&artifacts.org_keyring);
    let signing_key = SigningKey::from_bytes(&[0x11; 32]);
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifacts.attach_customer_authority(&mut artifact).unwrap();
    let mut padded_envelope = artifacts.org_keyring_envelope.clone();
    padded_envelope.as_object_mut().unwrap().insert(
        "legacy_padding".to_string(),
        serde_json::json!("p".repeat(MAX_TRUSTEE_POLICY_JSON_BYTES)),
    );
    let mut stored_artifact = artifact.clone();
    stored_artifact.org_keyring = Some(padded_envelope);

    // The normalized compose stays within budget: attach_customer_authority
    // replaces the padded envelope before validate_proof_bundle_budget.
    let mut normalized = stored_artifact.clone();
    artifacts
        .attach_customer_authority(&mut normalized)
        .unwrap();
    validate_proof_bundle_budget(&artifacts, &normalized).unwrap();

    // But the raw stored strings — what decode_loaded_workload_artifacts
    // composes and forwards — exceed the budget and must be rejected.
    let raw_workload = workload_artifacts_json(&artifacts, &stored_artifact).unwrap();
    let raw_trustee = trustee_policy_json(&stored_artifact).unwrap();
    assert!(
        raw_trustee.len() > MAX_TRUSTEE_POLICY_JSON_BYTES,
        "fixture must push the raw trustee string over budget, got {}",
        raw_trustee.len()
    );
    let err = validate_forwarded_proof_bundle_budget(&raw_workload, &raw_trustee).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("trustee_policy_json")),
        "expected raw trustee budget rejection, got: {err:?}"
    );

    // And a legal row (no padding) passes both checks.
    let workload = workload_artifacts_json(&artifacts, &artifact).unwrap();
    let trustee = trustee_policy_json(&artifact).unwrap();
    validate_forwarded_proof_bundle_budget(&workload, &trustee).unwrap();
}

#[test]
fn over_budget_composition_is_rejected_at_ingress() {
    // #128: validate_proof_bundle_budget itself must reject compositions
    // over either proof-bundle budget. The per-field caps are derived so a
    // capped artifact cannot reach these budgets (asserted above); this test
    // pins the guard that fires if the caps and budgets ever drift apart
    // (e.g. someone raises MAX_REGO_TEXT_BYTES without re-deriving).
    let artifacts = signing_artifacts(descriptor());
    let mut artifact = signed_policy_artifact(&artifacts, &SigningKey::from_bytes(&[0x11; 32]));
    // Uncapped rego text that alone exceeds the trustee budget.
    artifact.rego_text = "r".repeat(MAX_TRUSTEE_POLICY_JSON_BYTES + 1024);
    artifacts.attach_customer_authority(&mut artifact).unwrap();
    let err = validate_proof_bundle_budget(&artifacts, &artifact).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("trustee_policy_json")),
        "expected trustee budget rejection, got: {err:?}"
    );

    // Workload-budget rejection: everything within field caps except a
    // descriptor payload large enough to blow the 196_608-byte composed
    // budget (descriptor blob cap is per-ingress-blob; the stored payload
    // path composes descriptor + keyring + policy).
    let mut artifacts = signing_artifacts(descriptor());
    let mut padded = descriptor();
    padded.oci_runtime_spec.env = vec![EnvVar {
        name: "PAD".to_string(),
        value: "v".repeat(200 * 1024),
    }];
    artifacts.descriptor = padded;
    let mut artifact = signed_policy_artifact(
        &signing_artifacts(descriptor()),
        &SigningKey::from_bytes(&[0x11; 32]),
    );
    artifacts.attach_customer_authority(&mut artifact).unwrap();
    let err = validate_proof_bundle_budget(&artifacts, &artifact).unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("workload_artifacts_json")),
        "expected workload budget rejection, got: {err:?}"
    );
}

fn valid_keyring_blob() -> String {
    serde_json::json!({
        "keyring": {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "version": 1,
            "members": [],
            "updated_at": "2026-04-01T00:00:00Z"
        },
        "signature": "cc".repeat(64),
        "signing_pubkey": "dd".repeat(32)
    })
    .to_string()
}

#[test]
fn rego_cap_accounts_for_json_escaping() {
    // #128 review follow-up (P2): the per-field caps must measure the
    // JSON-escaped length — the form trustee_policy_json actually charges.
    // A rego text of raw quotes at the old raw-length cap would serialize to
    // ~2x and blow the 49,152-byte budget even though the raw length passed.
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifacts = signing_artifacts(descriptor());
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    // 12 KiB of raw quote chars: raw length well under the 24 KiB cap, but
    // the escaped form is ~24 KiB + overhead — at the cap boundary. Push it
    // decisively over: raw 20 KiB of quotes escapes to ~40 KiB > 24 KiB cap.
    artifact.rego_text = "\"".repeat(20 * 1024);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());
    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("artifact.rego_text")),
        "escaped-length rego over cap must be rejected, got: {err:?}"
    );

    // Sanity: the same raw length of a non-escaping char is accepted by the
    // cap (then fails later signature checks, which is fine).
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifact.rego_text = "r".repeat(20 * 1024);
    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        !matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("artifact.rego_text")),
        "raw 20 KiB rego must pass the escaped-length cap, got: {err:?}"
    );
}

#[test]
fn max_legal_escaped_compose_under_trustee_budget() {
    // #128 review follow-up (P2): the worst legal escaped payload must still
    // fit the trustee budget: rego at the cap composed entirely of a char
    // that doubles when escaped.
    let artifacts = signing_artifacts(descriptor());
    let mut artifact = signed_policy_artifact(&artifacts, &SigningKey::from_bytes(&[0x11; 32]));
    // MAX_REGO_TEXT_BYTES measured in escaped form; use backslashes (escape
    // to double) so the raw text is half the cap.
    artifact.rego_text = "\\".repeat(MAX_REGO_TEXT_BYTES / 2);
    artifacts.attach_customer_authority(&mut artifact).unwrap();
    let trustee = trustee_policy_json(&artifact).unwrap();
    assert!(
        trustee.len() <= MAX_TRUSTEE_POLICY_JSON_BYTES,
        "escaped-rego compose produced trustee_policy_json of {} bytes (budget {})",
        trustee.len(),
        MAX_TRUSTEE_POLICY_JSON_BYTES
    );
    validate_proof_bundle_budget(&artifacts, &artifact).unwrap();
}

#[test]
fn org_keyring_registration_budget_rejects_oversized_envelopes() {
    // #128 review follow-up (P1): a bare keyring_payload accepted by
    // put_keyring/rotate must fit the enveloped org_keyring_blob budget the
    // deploy path enforces, so accepted authority stays deployable.
    let signature = [0xcc; 64];
    let signing_pubkey = [0xdd; 32];
    // A minimal typed keyring is comfortably inside.
    let small = serde_json::to_vec(&OrgKeyring {
        org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        version: 1,
        members: vec![],
        updated_at: "2026-04-01T00:00:00Z".parse().unwrap(),
    })
    .unwrap();
    assert!(
        validate_org_keyring_registration_budget(small.len(), &signature, &signing_pubkey).is_ok()
    );

    // A keyring whose envelope exceeds 16 KiB is rejected at registration.
    let big = "x".repeat(MAX_ORG_KEYRING_BLOB_BYTES);
    let err = validate_org_keyring_registration_budget(big.len(), &signature, &signing_pubkey)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("org keyring envelope")),
        "oversized envelope must be rejected, got: {err:?}"
    );
}

#[test]
fn rejects_unknown_fields_in_signing_envelopes() {
    // #128: envelopes must not accept unbounded JSON padding via unknown
    // fields; only the exact envelope schema is accepted.
    let mut descriptor_value = serde_json::json!({
        "descriptor": descriptor(),
        "signature": "aa".repeat(64),
        "signing_key_id": "deployer-key-1",
        "signing_pubkey": "bb".repeat(32)
    });
    descriptor_value
        .as_object_mut()
        .unwrap()
        .insert("padding".to_string(), serde_json::json!("p".repeat(4096)));
    let err = decode_optional_blobs(
        Some(descriptor_value.to_string()),
        Some(
            serde_json::json!({
                "keyring": {
                    "org_id": "11111111-1111-1111-1111-111111111111",
                    "version": 1,
                    "members": [],
                    "updated_at": "2026-04-01T00:00:00Z"
                },
                "signature": "cc".repeat(64),
                "signing_pubkey": "dd".repeat(32)
            })
            .to_string(),
        ),
    )
    .unwrap_err();
    assert!(matches!(err, SigningServiceError::Blob(_)), "got: {err:?}");

    let mut keyring_value = serde_json::json!({
        "keyring": {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "version": 1,
            "members": [],
            "updated_at": "2026-04-01T00:00:00Z"
        },
        "signature": "cc".repeat(64),
        "signing_pubkey": "dd".repeat(32)
    });
    keyring_value
        .as_object_mut()
        .unwrap()
        .insert("padding".to_string(), serde_json::json!("p".repeat(4096)));
    let err = decode_optional_blobs(
        Some(valid_descriptor_blob()),
        Some(keyring_value.to_string()),
    )
    .unwrap_err();
    assert!(matches!(err, SigningServiceError::Blob(_)), "got: {err:?}");
}

#[test]
fn verifies_signature_before_payload_comparisons() {
    // #128: an artifact with BOTH an invalid signature and mismatched
    // payload metadata must fail with InvalidSignature, not a semantic
    // Mismatch — the platform signature over the canonical blob is checked
    // before any payload parsing/comparison work.
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let mut artifacts = signing_artifacts(descriptor());
    // Point the descriptor signing pubkey at the artifact key so the payload
    // comparison path would engage on mismatched metadata.
    artifacts.descriptor_signing_pubkey = signing_key.verifying_key().to_bytes();
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    // Tamper: invalid signature AND mismatched payload metadata.
    artifact.signature = "11".repeat(64);
    artifact.metadata.app_id = Uuid::new_v4().to_string();
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::InvalidSignature),
        "expected InvalidSignature before payload compares, got: {err:?}"
    );

    // The diagnostic pubkey compare also runs only after the crypto check:
    // an invalid signature plus a mismatched verify_pubkey_b64 echo must
    // still surface InvalidSignature, not Mismatch("artifact.verify_pubkey_b64").
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifact.signature = "11".repeat(64);
    artifact.verify_pubkey_b64 = B64.encode([0x44; 32]);
    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::InvalidSignature),
        "expected InvalidSignature before the diagnostic pubkey compare, got: {err:?}"
    );
}

#[test]
fn rejects_signed_artifact_fields_exceeding_caps() {
    // #128: per-field byte caps run before signature verification and
    // before hashing of the oversized text. The mutated fields invalidate
    // the signature, so this proves ordering (caps before verify), not that
    // a still-valid signature is rejected.
    let signing_key = SigningKey::from_bytes(&[0x33; 32]);
    let artifacts = signing_artifacts(descriptor());
    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifact.metadata.key_id = "k".repeat(MAX_POLICY_METADATA_FIELD_BYTES + 1);
    let configured_pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("artifact.metadata.key_id")),
        "got: {err:?}"
    );

    let mut artifact = signed_policy_artifact(&artifacts, &signing_key);
    artifact.rego_text = "x".repeat(MAX_POLICY_TEXT_BYTES + 1);
    let err = artifacts
        .validate_signed_artifact(&artifact, &configured_pubkey_hex)
        .unwrap_err();
    assert!(
        matches!(err, SigningServiceError::Blob(ref msg) if msg.contains("artifact.rego_text")),
        "got: {err:?}"
    );
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
    // #128: InvalidSignature precedes the diagnostic pubkey compare; the
    // descriptor key cannot produce a platform-valid signature.
    assert!(matches!(err, SigningServiceError::InvalidSignature));
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
    // #128: the ed25519 check runs before the diagnostic pubkey compare, so
    // an artifact signed by an unconfigured key surfaces InvalidSignature
    // (the echoed verify_pubkey_b64 disagreement is only reported for a
    // properly signed artifact, as Mismatch).
    assert!(matches!(err, SigningServiceError::InvalidSignature));
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
            amd_kds_base_url: None,
            trustee_policy_url: Some("https://kbs.example.test/policy".to_string()),
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: Some("bb".repeat(32)),
            signing_service_pubkey_hex: Some("bb".repeat(32)),
            verification_material: None,
        },
        egress_mode: enclava_engine::types::EgressMode::Restricted,
        public_internet_egress_excluded_cidrs: Vec::new(),
        allow_internal_egress: false,
        egress_allowlist: vec![],
        log_encryption: None,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    }
}

fn log_encryption_config() -> enclava_engine::types::LogEncryptionConfig {
    enclava_engine::types::LogEncryptionConfig {
        algorithm: enclava_common::log_encryption::LOG_ENCRYPTION_ALGORITHM.to_string(),
        key_id: "logs-prod".to_string(),
        public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
    }
}

fn pinned_app_for_descriptor(descriptor: &DeploymentDescriptor) -> ConfidentialApp {
    let mut app = confidential_app_for_descriptor(descriptor);
    app.log_encryption = Some(log_encryption_config());
    app.workload_artifact_binding = Some(WorkloadArtifactBinding {
        descriptor_core_hash: [1; 32],
        descriptor_signing_pubkey: [2; 32],
        org_keyring_fingerprint: [3; 32],
        omit_log_encryption_claim: false,
    });
    app
}

fn artifacts_with_expected_hash(
    descriptor: &DeploymentDescriptor,
    expected_hash: [u8; 32],
) -> DeploymentSigningArtifacts {
    let mut artifacts = signing_artifacts(descriptor.clone());
    artifacts.descriptor.expected_cc_init_data_hash = expected_hash;
    artifacts
}

#[test]
fn modern_render_match_clears_the_legacy_pin() {
    let descriptor = descriptor();
    let mut app = pinned_app_for_descriptor(&descriptor);
    app.workload_artifact_binding
        .as_mut()
        .unwrap()
        .omit_log_encryption_claim = true;
    let (_, modern_hash) = enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app);
    let artifacts = artifacts_with_expected_hash(
        &descriptor,
        hex::decode(modern_hash).unwrap().try_into().unwrap(),
    );
    artifacts
        .validate_and_pin_cc_init_data_render(&mut app)
        .expect("modern render must validate");
    assert!(
        !app.workload_artifact_binding
            .as_ref()
            .unwrap()
            .omit_log_encryption_claim,
        "a modern match must explicitly clear a stale legacy pin"
    );
}

#[test]
fn legacy_render_match_pins_the_binding() {
    let descriptor = descriptor();
    let mut app = pinned_app_for_descriptor(&descriptor);
    let mut legacy_app = app.clone();
    legacy_app
        .workload_artifact_binding
        .as_mut()
        .unwrap()
        .omit_log_encryption_claim = true;
    let (_, legacy_hash) =
        enclava_engine::manifest::cc_init_data::compute_cc_init_data(&legacy_app);
    let artifacts = artifacts_with_expected_hash(
        &descriptor,
        hex::decode(legacy_hash).unwrap().try_into().unwrap(),
    );
    artifacts
        .validate_and_pin_cc_init_data_render(&mut app)
        .expect("legacy render must validate");
    assert!(
        app.workload_artifact_binding
            .as_ref()
            .unwrap()
            .omit_log_encryption_claim,
        "a legacy-only match must pin the binding to the legacy render"
    );
}

#[test]
fn render_mismatch_resets_the_pin_and_errors() {
    let descriptor = descriptor();
    let mut app = pinned_app_for_descriptor(&descriptor);
    let artifacts = artifacts_with_expected_hash(&descriptor, [0xaa; 32]);
    let err = artifacts
        .validate_and_pin_cc_init_data_render(&mut app)
        .expect_err("neither render matches");
    assert!(matches!(err, SigningServiceError::Mismatch(_)));
    assert!(
        !app.workload_artifact_binding
            .as_ref()
            .unwrap()
            .omit_log_encryption_claim,
        "a failed validation must not leave the legacy pin set"
    );
}
