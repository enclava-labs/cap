use super::*;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tempfile::tempdir;

const AGENT_POLICY: &str = "package agent_policy\n\ndefault CreateContainerRequest := true\n";

fn metadata_for(rego: &str) -> PolicyMetadata {
    PolicyMetadata {
        app_id: "22222222-2222-2222-2222-222222222222".into(),
        deploy_id: "33333333-3333-3333-3333-333333333333".into(),
        descriptor_core_hash: "00".repeat(32),
        descriptor_signing_pubkey: "00".repeat(32),
        platform_release_version: "v1".into(),
        policy_template_id: "tmpl".into(),
        policy_template_sha256: hex::encode(Sha256::digest(rego.as_bytes())),
        agent_policy_sha256: hex::encode(Sha256::digest(AGENT_POLICY.as_bytes())),
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".into(),
        signed_at: "2026-01-01T00:00:00Z".into(),
        key_id: "k1".into(),
    }
}

fn mk_envelope(sk: &SigningKey, metadata: PolicyMetadata, rego: &str) -> PolicyEnvelope {
    let mut env = PolicyEnvelope {
        metadata,
        rego_text: rego.to_string(),
        agent_policy_text: AGENT_POLICY.to_string(),
        agent_policy_sha256: hex::encode(Sha256::digest(AGENT_POLICY.as_bytes())),
        signature: [0u8; 64],
    };
    let msg = ce_v1_policy_envelope_message(&env).unwrap();
    env.signature = sk.sign(&msg).to_bytes();
    env
}

fn descriptor_json() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "v1",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "org_slug": "abcd1234",
        "app_id": "22222222-2222-2222-2222-222222222222",
        "app_name": "demo",
        "deploy_id": "33333333-3333-3333-3333-333333333333",
        "created_at": "2026-04-01T12:00:00Z",
        "nonce": "07".repeat(32),
        "app_domain": "demo.abcd1234.enclava.dev",
        "tee_domain": "demo.abcd1234.tee.enclava.dev",
        "custom_domains": ["app.example.com"],
        "namespace": "cap-abcd1234-demo",
        "service_account": "cap-demo-sa",
        "identity_hash": "09".repeat(32),
        "image_ref": "ghcr.io/enclava-ai/demo@sha256:aaaa",
        "image_digest": "sha256:aaaa",
        "signer_identity": {
            "subject": "https://github.com/x/y/.github/workflows/build.yml",
            "issuer": "https://token.actions.githubusercontent.com"
        },
        "oci_runtime_spec": {
            "command": ["/app"],
            "args": ["--serve"],
            "env": [
                {"name": "A", "value": "1"},
                {"name": "B", "value": "2"}
            ],
            "ports": [{"container_port": 3000, "protocol": "TCP"}],
            "mounts": [],
            "capabilities": {"add": [], "drop": []},
            "security_context": {
                "run_as_user": 0,
                "run_as_group": 0,
                "read_only_root_fs": false,
                "allow_privilege_escalation": false,
                "privileged": false
            },
            "resources": {"requests": [], "limits": []}
        },
        "sidecars": {
            "attestation_proxy_digest": "sha256:1111",
            "caddy_digest": "sha256:2222"
        },
        "expected_firmware_measurement": "03".repeat(32),
        "expected_runtime_class": "kata-qemu-snp",
        "kbs_resource_path": "default/cap-abcd1234-demo-owner",
        "unlock_mode": "password",
        "policy_template_id": "tmpl-default",
        "policy_template_sha256": "04".repeat(32),
        "platform_release_version": "v1.2.3",
        "expected_agent_policy_hash": hex::encode(Sha256::digest(AGENT_POLICY.as_bytes())),
        "expected_cc_init_data_hash": "05".repeat(32),
        "expected_kbs_policy_hash": "06".repeat(32)
    })
}

fn keyring_json(deployer: &SigningKey, role: &str) -> serde_json::Value {
    serde_json::json!({
        "org_id": "11111111-1111-1111-1111-111111111111",
        "version": 1,
        "updated_at": "2026-04-01T12:00:00Z",
        "members": [
            {
                "user_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "pubkey": hex::encode(deployer.verifying_key().to_bytes()),
                "role": role,
                "added_at": "2026-04-01T12:00:00Z"
            }
        ]
    })
}

#[test]
fn ce_v1_byte_parity_with_enclava_common() {
    let bytes = ce_v1_bytes(&[("purpose", b"test"), ("k", b"v")]);
    let hash = ce_v1_hash(&[("purpose", b"test"), ("k", b"v")]);
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(hash, expected);
}

#[test]
fn policy_envelope_signature_round_trip() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    let env = mk_envelope(&sk, metadata_for("package x\n"), "package x\n");
    verify_policy_envelope_signature(&env, &pk.to_bytes(), None, None).unwrap();
}

#[test]
fn policy_envelope_tampered_rego_rejected() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk = sk.verifying_key();
    let mut env = mk_envelope(&sk, metadata_for("package x\n"), "package x\n");
    env.rego_text = "package y\n".into();
    assert!(verify_policy_envelope_signature(&env, &pk.to_bytes(), None, None).is_err());
}

#[test]
fn policy_artifact_signing_input_matches_cap_vector() {
    let env = PolicyEnvelope {
        metadata: PolicyMetadata {
            app_id: "22222222-2222-2222-2222-222222222222".to_string(),
            deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
            descriptor_core_hash:
                "0de9db2fd278a795754120604b68a1fae95d1ba19a66ed9a1df3a76df76f0eea".to_string(),
            descriptor_signing_pubkey:
                "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0".to_string(),
            platform_release_version: "platform-2026.04".to_string(),
            policy_template_id: "trustee-resource-policy-v1".to_string(),
            policy_template_sha256:
                "e808dd6a40402bad50ea9522cdcd60b6739b78e21006942f4072a08355a24f10".to_string(),
            agent_policy_sha256: "749bf91b70ba77fff6ad79581c0b3319cbff946e8f3783f8a44517fa50d470e9"
                .to_string(),
            genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            signed_at: "2026-04-01T12:30:00+00:00".to_string(),
            key_id: "policy-test-key-v1".to_string(),
        },
        rego_text: "package policy\n\ndefault allow := false\n".to_string(),
        agent_policy_text: AGENT_POLICY.to_string(),
        agent_policy_sha256: "749bf91b70ba77fff6ad79581c0b3319cbff946e8f3783f8a44517fa50d470e9"
            .to_string(),
        signature: [0u8; 64],
    };

    assert_eq!(
        hex::encode(canonical_policy_metadata_hash(&env.metadata).unwrap()),
        "364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83"
    );
    let metadata_hash = canonical_policy_metadata_hash(&env.metadata).unwrap();
    let rego_hash: [u8; 32] =
        hex::decode("244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372")
            .unwrap()
            .try_into()
            .unwrap();
    let signing_input = ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", metadata_hash.as_slice()),
        ("rego_sha256", rego_hash.as_slice()),
    ]);
    assert_eq!(
        hex::encode(signing_input),
        "0007707572706f73650000001a656e636c6176612d706f6c6963792d61727469666163742d763100086d6574616461746100000020364f70ca857400a41077c5e875579ef5bd2aafe2f373ffa17ac4d7cc621f0a83000b7265676f5f73686132353600000020244b1092b2392d188d72f06ac69347b7c8ae89777619a8e95f523a041f6e5372"
    );
}

#[test]
fn descriptor_core_hash_excludes_expected_fields() {
    let v1 = descriptor_json();
    let mut v2 = v1.clone();
    v2["expected_agent_policy_hash"] = serde_json::Value::String("cc".repeat(32));
    v2["expected_cc_init_data_hash"] = serde_json::Value::String("aa".repeat(32));
    v2["expected_kbs_policy_hash"] = serde_json::Value::String("bb".repeat(32));
    let h1 = compute_descriptor_core_hash(&v1).unwrap();
    let h2 = compute_descriptor_core_hash(&v2).unwrap();
    assert_eq!(h1, h2);
}

fn build_inputs(
    descriptor: &serde_json::Value,
    keyring: serde_json::Value,
    rego: &str,
    signing_sk: &SigningKey,
    descriptor_sk: &SigningKey,
    cc_init_toml: &[u8],
) -> (
    ArtifactsBundle,
    PolicyEnvelope,
    CcInitDataClaims,
    VerifyingKey,
    VerifyingKey,
) {
    let core_hash = compute_descriptor_core_hash(descriptor).unwrap();
    let pubkey_bytes = descriptor_sk.verifying_key().to_bytes();
    let local_hash_hex = hex::encode(Sha256::digest(cc_init_toml));
    let mut descriptor = descriptor.clone();
    descriptor["expected_cc_init_data_hash"] = serde_json::Value::String(local_hash_hex);
    descriptor["expected_kbs_policy_hash"] =
        serde_json::Value::String(hex::encode(Sha256::digest(rego.as_bytes())));

    let descriptor_msg = ce_v1_descriptor_full_message(&descriptor).unwrap();
    let descriptor_sig = descriptor_sk.sign(&descriptor_msg).to_bytes();

    let keyring_bytes = ce_v1_keyring_bytes(&keyring).unwrap();
    let keyring_fp: [u8; 32] = Sha256::digest(&keyring_bytes).into();

    let mut metadata = metadata_for(rego);
    metadata.app_id = descriptor.get("app_id").unwrap().as_str().unwrap().into();
    metadata.deploy_id = descriptor
        .get("deploy_id")
        .unwrap()
        .as_str()
        .unwrap()
        .into();
    metadata.descriptor_core_hash = hex::encode(core_hash);
    metadata.descriptor_signing_pubkey = hex::encode(pubkey_bytes);
    metadata.platform_release_version = descriptor
        .get("platform_release_version")
        .unwrap()
        .as_str()
        .unwrap()
        .into();
    metadata.policy_template_id = descriptor
        .get("policy_template_id")
        .unwrap()
        .as_str()
        .unwrap()
        .into();
    metadata.policy_template_sha256 = descriptor
        .get("policy_template_sha256")
        .unwrap()
        .as_str()
        .unwrap()
        .into();
    metadata.agent_policy_sha256 = descriptor
        .get("expected_agent_policy_hash")
        .unwrap()
        .as_str()
        .unwrap()
        .into();

    let env = mk_envelope(signing_sk, metadata, rego);

    let bundle = ArtifactsBundle {
        descriptor_payload: descriptor,
        descriptor_signature: descriptor_sig,
        descriptor_signing_key_id: "deployer-1".into(),
        org_keyring_payload: keyring,
        org_keyring_signature: [0u8; 64],
        signed_policy_artifact: env.clone(),
    };
    let cc = CcInitDataClaims {
        descriptor_core_hash: core_hash,
        descriptor_signing_pubkey: pubkey_bytes,
        org_keyring_fingerprint: keyring_fp,
    };
    (
        bundle,
        env,
        cc,
        signing_sk.verifying_key(),
        descriptor_sk.verifying_key(),
    )
}

#[test]
fn artifact_fetcher_reads_file_urls() {
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let (bundle, env, _, _, _) = build_inputs(
        &descriptor,
        keyring,
        rego,
        &deployer,
        &deployer,
        b"placeholder cc_init_data",
    );
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("workload-artifacts.json");
    let policy_path = dir.path().join("trustee-policy.json");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    std::fs::write(&policy_path, serde_json::to_vec(&env).unwrap()).unwrap();

    let fetcher = ArtifactFetcher {
        workload_artifacts_url: format!("file://{}", bundle_path.display()),
        trustee_policy_url: format!("file://{}", policy_path.display()),
        kbs_attestation_token: "unused-for-file".into(),
        timeout: Duration::from_secs(1),
    };
    let (fetched_bundle, fetched_policy) = fetcher.fetch().unwrap();
    assert_eq!(fetched_bundle.descriptor_payload, bundle.descriptor_payload);
    assert_eq!(
        fetched_bundle.descriptor_signature,
        bundle.descriptor_signature
    );
    assert_eq!(fetched_policy, env);
}

#[test]
fn artifact_fetcher_reads_policy_set_and_selects_matching_artifact() {
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let (bundle, env, _, _, _) = build_inputs(
        &descriptor,
        keyring,
        rego,
        &deployer,
        &deployer,
        b"placeholder cc_init_data",
    );
    let mut non_matching_metadata = env.metadata.clone();
    non_matching_metadata.descriptor_core_hash = "ff".repeat(32);
    let non_matching_env = mk_envelope(
        &deployer,
        non_matching_metadata,
        "package enclava\ndefault allow := true\n",
    );
    let policy_set = serde_json::json!({
        "schema_version": "enclava-signed-policy-set-v1",
        "artifacts": [non_matching_env, env.clone()],
    });
    let dir = tempdir().unwrap();
    let bundle_path = dir.path().join("workload-artifacts.json");
    let policy_path = dir.path().join("trustee-policy-set.json");
    std::fs::write(&bundle_path, serde_json::to_vec(&bundle).unwrap()).unwrap();
    std::fs::write(&policy_path, serde_json::to_vec(&policy_set).unwrap()).unwrap();

    let fetcher = ArtifactFetcher {
        workload_artifacts_url: format!("file://{}", bundle_path.display()),
        trustee_policy_url: format!("file://{}", policy_path.display()),
        kbs_attestation_token: "unused-for-file".into(),
        timeout: Duration::from_secs(1),
    };
    let (_, fetched_policy) = fetcher.fetch().unwrap();
    assert_eq!(fetched_policy, env);
}

#[test]
fn end_to_end_chain_passes_for_customer_signed_artifact_without_fallback() {
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let cc_toml = b"placeholder cc_init_data";
    let (bundle, env, cc, _, _) =
        build_inputs(&descriptor, keyring, rego, &deployer, &deployer, cc_toml);

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: None,
        signing_service_pubkey: None,
    };
    verify_chain(&inputs).expect("customer-signed chain should pass");
}

#[test]
fn end_to_end_chain_accepts_platform_signed_artifact_with_signing_service_key() {
    let signing = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let cc_toml = b"placeholder cc_init_data";
    let (bundle, env, cc, signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    verify_chain(&inputs).expect("platform-signed chain should pass");
}

#[test]
fn end_to_end_chain_rejects_descriptor_signed_artifact_when_signing_service_key_is_configured() {
    let signing = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let cc_toml = b"placeholder cc_init_data";
    let (bundle, env, cc, _, _) =
        build_inputs(&descriptor, keyring, rego, &deployer, &deployer, cc_toml);
    let signer_pk = signing.verifying_key();

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("signing service key")));
}

#[test]
fn end_to_end_chain_rejects_tampered_descriptor() {
    let signing = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\ndefault allow := false\n";
    let cc_toml = b"placeholder cc_init_data";
    let (mut bundle, env, cc, signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);

    bundle.descriptor_payload["app_name"] = serde_json::Value::String("evil".into());

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    match err {
        InitError::TrusteePolicy(s) => {
            assert!(s.starts_with("step 1") || s.contains("descriptor sig"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn end_to_end_chain_rejects_wrong_keyring_fingerprint() {
    let signing = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\n";
    let cc_toml = b"x";
    let (bundle, env, mut cc, signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
    cc.org_keyring_fingerprint = [0xFFu8; 32];

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("step 4a")));
}

#[test]
fn end_to_end_chain_rejects_rego_mismatch() {
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\n";
    let cc_toml = b"x";
    let (mut bundle, mut env, cc, signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &deployer, &deployer, cc_toml);

    // Point expected_kbs_policy_hash at one rego, but ship a different one.
    env.rego_text = "package different\n".into();
    // Re-sign the (now-different) envelope so we don't fail at step "envelope sig"
    // and instead reach step 6.
    let new_msg = ce_v1_policy_envelope_message(&env).unwrap();
    env.signature = deployer.sign(&new_msg).to_bytes();
    bundle.signed_policy_artifact = env.clone();

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("step 6")));
}

#[test]
fn end_to_end_chain_rejects_active_policy_not_in_artifact_bundle() {
    let signing = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\n";
    let cc_toml = b"x";
    let (bundle, mut env, cc, signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
    env.metadata.key_id = "different-active-policy".into();
    let new_msg = ce_v1_policy_envelope_message(&env).unwrap();
    env.signature = signing.sign(&new_msg).to_bytes();

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: Some(&signer_pk),
        signing_service_pubkey: Some(&signer_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    assert!(
        matches!(err, InitError::TrusteePolicy(s) if s.contains("does not match workload artifact"))
    );
}

#[test]
fn end_to_end_chain_rejects_policy_pubkey_mismatch() {
    let signing = SigningKey::generate(&mut OsRng);
    let other_signer = SigningKey::generate(&mut OsRng);
    let deployer = SigningKey::generate(&mut OsRng);
    let descriptor = descriptor_json();
    let keyring = keyring_json(&deployer, "deployer");
    let rego = "package enclava\n";
    let cc_toml = b"x";
    let (bundle, env, cc, _signer_pk, _) =
        build_inputs(&descriptor, keyring, rego, &signing, &deployer, cc_toml);
    let other_pk = other_signer.verifying_key();

    let inputs = VerifyInputs {
        policy_envelope: &env,
        artifacts: &bundle,
        cc_init_data_claims: &cc,
        local_cc_init_data_toml: cc_toml,
        platform_trustee_policy_pubkey: None,
        signing_service_pubkey: Some(&other_pk),
    };
    let err = verify_chain(&inputs).unwrap_err();
    assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("policy envelope sig")));
}

#[test]
fn skipped_chain_is_fatal() {
    let err = verify_chain_or_skip(None).unwrap_err();
    assert!(matches!(err, InitError::TrusteePolicy(s) if s.contains("verification required")));
}

#[test]
fn resolve_kbs_attestation_token_prefers_env_token() {
    let token = resolve_kbs_attestation_token(
        Some("  env-token  "),
        "http://127.0.0.1:1/unused",
        Duration::from_millis(1),
    )
    .unwrap();
    assert_eq!(token, "env-token");
}

#[test]
fn parse_kbs_attestation_token_payload_rejects_missing_token() {
    let err = parse_kbs_attestation_token_payload(&serde_json::json!({})).unwrap_err();
    assert!(matches!(err, InitError::Kbs(msg) if msg.contains("missing token")));
}

#[test]
fn parse_kbs_attestation_token_payload_accepts_token() {
    let token = parse_kbs_attestation_token_payload(&serde_json::json!({ "token": "abc.def.ghi" }))
        .unwrap();
    assert_eq!(token, "abc.def.ghi");
}
