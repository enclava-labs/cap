use enclava_engine::manifest::cc_init_data::{build_toml, encode_cc_init_data, sha256_hex};
use enclava_engine::testutil::sample_app;
use enclava_engine::types::{GeneratedAgentPolicy, WorkloadArtifactBinding};
use sha2::{Digest, Sha256};

#[test]
fn toml_contains_policy_rego() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("package agent_policy"));
    assert!(toml.contains("AllowRequestsFailingPolicy"));
}

#[test]
fn toml_embeds_generated_agent_policy_when_present() {
    let mut app = sample_app();
    let policy_text = "package agent_policy\n\ndefault CreateContainerRequest := true\n";
    app.generated_agent_policy = Some(GeneratedAgentPolicy {
        policy_text: policy_text.to_string(),
        policy_sha256: Sha256::digest(policy_text.as_bytes()).into(),
        genpolicy_version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
    });

    let toml = build_toml(&app);
    let parsed: toml::Value = toml::from_str(&toml).unwrap();
    let embedded = parsed
        .get("data")
        .and_then(toml::Value::as_table)
        .and_then(|data| data.get("policy.rego"))
        .and_then(toml::Value::as_str)
        .unwrap();

    assert_eq!(embedded, policy_text);
    assert!(!embedded.contains("AllowRequestsFailingPolicy"));
}

#[test]
fn agent_policy_fails_closed() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("default AllowRequestsFailingPolicy := false"));
    assert!(toml.contains("default CreateContainerRequest := false"));
    assert!(toml.contains("default ExecProcessRequest := false"));
    assert!(toml.contains("default CopyFileRequest := false"));
    assert!(toml.contains("default WriteStreamRequest := false"));
    assert!(!toml.contains("default AllowRequestsFailingPolicy := true"));
}

#[test]
fn agent_policy_create_container_is_bound_to_workload_identity() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("CreateContainerRequest {"));
    assert!(toml.contains(
        "input.OCI.Annotations[\"io.kubernetes.cri.image-name\"] == \"ghcr.io/test/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\""
    ));
    assert!(toml.contains(
        "input.OCI.Annotations[\"io.kubernetes.pod.namespace\"] == \"cap-test-org-test-app\""
    ));
    assert!(toml.contains(
        "input.OCI.Annotations[\"io.kubernetes.pod.service-account.name\"] == \"cap-test-app-sa\""
    ));
    assert!(
        toml.contains("input.OCI.Annotations[\"tenant.flowforge.sh/instance\"] == \"test-app\"")
    );
}

#[test]
fn toml_contains_image_digest() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains(
        "image_digest = \"ghcr.io/test/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234\""
    ));
    assert!(toml.contains(
        "ghcr.io/test/app@sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
    ));
}

#[test]
fn toml_contains_namespace() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("cap-test-org-test-app"));
}

#[test]
fn toml_contains_service_account() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("cap-test-app-sa"));
}

#[test]
fn data_claims_include_required_rego_descriptor_anchors() {
    let app = sample_app();
    let toml = build_toml(&app);
    let value: toml::Value = toml::from_str(&toml).unwrap();
    let data = value.get("data").and_then(toml::Value::as_table).unwrap();

    for key in [
        "image_digest",
        "signer_identity_subject",
        "signer_identity_issuer",
        "namespace",
        "service_account",
        "identity_hash",
        "runtime_class",
    ] {
        let value = data.get(key).and_then(toml::Value::as_str).unwrap();
        assert!(!value.is_empty(), "{key} must be non-empty");
    }

    assert_eq!(
        data["image_digest"].as_str().unwrap(),
        app.primary_container().unwrap().image.digest_ref()
    );
    assert_eq!(
        data["signer_identity_subject"].as_str().unwrap(),
        app.signer_identity_subject.as_deref().unwrap()
    );
    assert_eq!(
        data["signer_identity_issuer"].as_str().unwrap(),
        app.signer_identity_issuer.as_deref().unwrap()
    );
    assert_eq!(data["namespace"].as_str().unwrap(), app.namespace);
    assert_eq!(
        data["service_account"].as_str().unwrap(),
        app.service_account
    );
    assert_eq!(
        data["identity_hash"].as_str().unwrap(),
        app.tenant_instance_identity_hash
    );
    assert_eq!(data["runtime_class"].as_str().unwrap(), "kata-qemu-snp");

    let sidecars: serde_json::Value = serde_json::from_str(
        data.get("sidecar_digests")
            .and_then(toml::Value::as_str)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        sidecars["attestation_proxy"].as_str().unwrap(),
        app.attestation.proxy_image.digest()
    );
    assert_eq!(
        sidecars["caddy_ingress"].as_str().unwrap(),
        app.attestation.caddy_image.digest()
    );
}

#[test]
fn toml_contains_policy_instance_annotation() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("\"tenant.flowforge.sh/instance\":\"test-app\""));
}

#[test]
fn toml_contains_workload_artifact_binding_when_present() {
    let mut app = sample_app();
    app.workload_artifact_binding = Some(WorkloadArtifactBinding {
        descriptor_core_hash: [0xab; 32],
        descriptor_signing_pubkey: [0xcd; 32],
        org_keyring_fingerprint: [0xef; 32],
    });
    let toml = build_toml(&app);
    assert!(toml.contains(&format!("descriptor_core_hash = \"{}\"", "ab".repeat(32))));
    assert!(toml.contains(&format!(
        "descriptor_signing_pubkey = \"{}\"",
        "cd".repeat(32)
    )));
    assert!(toml.contains(&format!(
        "org_keyring_fingerprint = \"{}\"",
        "ef".repeat(32)
    )));
}

#[test]
fn toml_contains_aa_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("[token_configs]"));
    assert!(toml.contains("[token_configs.kbs]"));
    assert!(toml.contains("http://kbs-service.trustee-operator-system.svc.cluster.local:8080"));
}

#[test]
fn toml_contains_cdh_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("[kbc]"));
    assert!(toml.contains("cc_kbc"));
}

#[test]
fn toml_contains_identity_toml() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("identity.toml"));
    assert!(toml.contains(&format!("tenant_id = \"{}\"", app.namespace)));
    assert!(toml.contains(&format!("instance_id = \"{}\"", app.name)));
    assert!(toml.contains(&format!(
        "owner_resource_type = \"{}\"",
        app.owner_resource_type()
    )));
    assert!(toml.contains(&format!(
        "bootstrap_owner_pubkey_hash = \"{}\"",
        app.bootstrap_owner_pubkey_hash
    )));
    assert!(toml.contains(&format!(
        "tenant_instance_identity_hash = \"{}\"",
        app.tenant_instance_identity_hash
    )));
}

#[test]
fn sha256_hex_is_64_lowercase_hex() {
    let app = sample_app();
    let toml = build_toml(&app);
    let hash = sha256_hex(&toml);
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hash, hash.to_lowercase());
}

#[test]
fn sha256_hex_is_deterministic() {
    let app = sample_app();
    let toml = build_toml(&app);
    let h1 = sha256_hex(&toml);
    let h2 = sha256_hex(&toml);
    assert_eq!(h1, h2);
}

#[test]
fn encode_produces_valid_base64() {
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("must be valid base64");
    // Decoded is gzip data -- first two bytes are the gzip magic number
    assert_eq!(decoded[0], 0x1f);
    assert_eq!(decoded[1], 0x8b);
}

#[test]
fn encode_roundtrips_through_gzip() {
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);

    use base64::Engine;
    use std::io::Read;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
    let mut decompressed = String::new();
    decoder.read_to_string(&mut decompressed).unwrap();

    assert_eq!(decompressed, toml);
}

#[test]
fn encode_gzip_has_zero_mtime() {
    // gzip header: magic(2) + method(1) + flags(1) + mtime(4) + ...
    // mtime is at bytes 4-7 and must be all zeros.
    let app = sample_app();
    let toml = build_toml(&app);
    let encoded = encode_cc_init_data(&toml);

    use base64::Engine;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .unwrap();
    assert_eq!(compressed[4], 0, "mtime byte 0 must be zero");
    assert_eq!(compressed[5], 0, "mtime byte 1 must be zero");
    assert_eq!(compressed[6], 0, "mtime byte 2 must be zero");
    assert_eq!(compressed[7], 0, "mtime byte 3 must be zero");
}

#[test]
fn toml_structure_matches_python_template() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.starts_with("version = \"0.1.0\"\nalgorithm = \"sha256\""));
}

#[test]
fn toml_binds_runtime_class() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains("runtime_class = \"kata-qemu-snp\""));
}

#[test]
fn toml_binds_sidecar_digests() {
    let app = sample_app();
    let toml = build_toml(&app);
    assert!(toml.contains(
        "sidecar_digests = '{\"attestation_proxy\":\"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\"caddy_ingress\":\"sha256:2222"
    ));
    assert!(!toml.contains("[data.sidecar_digests]"));
}

#[test]
fn verify_runtime_class_binding_passes_for_default_render() {
    use enclava_engine::manifest::cc_init_data::verify_runtime_class_binding;
    let app = sample_app();
    let manifests = enclava_engine::manifest::generate_all_manifests(&app);
    verify_runtime_class_binding(&manifests.statefulset)
        .expect("default app must bind runtime class");
}
