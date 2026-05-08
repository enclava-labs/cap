//! cc_init_data generation: TOML + gzip + base64.
//!
//! Ports the Python implementation at platform_api/manifests/init_data.py.
//! The output must be byte-for-byte compatible for cc_init_data annotations.
//! The SHA256 hash is computed on the uncompressed TOML string.

use sha2::{Digest, Sha256};
use std::io::Write;

use crate::types::ConfidentialApp;

pub const DEFAULT_KBS_URL: &str =
    "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";

/// Trustee KBS base URL written into Kata guest components config.
///
/// Production deployments should set this to the HTTPS KBS service URL and
/// provide `TRUSTEE_KBS_CA_CERT_PEM` so AA/CDH can verify the KBS server cert.
pub fn trustee_kbs_url() -> String {
    nonempty_env("TRUSTEE_KBS_URL").unwrap_or_else(|| DEFAULT_KBS_URL.to_string())
}

/// Optional PEM root used by AA/CDH to trust the Trustee KBS HTTPS listener.
pub fn trustee_kbs_ca_cert_pem() -> Option<String> {
    nonempty_env("TRUSTEE_KBS_CA_CERT_PEM").map(|value| value.replace("\\n", "\n"))
}

pub fn trustee_kbs_resource_url() -> String {
    format!(
        "{}/kbs/v0/resource",
        trustee_kbs_url().trim_end_matches('/')
    )
}

#[derive(Debug, Clone)]
pub struct CcInitDataOptions {
    pub kbs_url: String,
    pub kbs_ca_cert_pem: Option<String>,
}

impl CcInitDataOptions {
    pub fn from_env() -> Self {
        Self {
            kbs_url: trustee_kbs_url(),
            kbs_ca_cert_pem: trustee_kbs_ca_cert_pem(),
        }
    }
}

/// Build the cc_init_data TOML string for a ConfidentialApp.
///
/// The TOML structure matches the Python template in init_data.py exactly.
/// It contains:
/// - policy.rego: agent policy with image digest and namespace
/// - aa.toml: attestation agent config pointing to KBS
/// - cdh.toml: confidential data hub config pointing to KBS
/// - identity.toml: tenant/instance identity for ownership binding
pub fn build_toml(app: &ConfidentialApp) -> String {
    build_toml_with_options(app, &CcInitDataOptions::from_env())
}

pub fn build_toml_with_options(app: &ConfidentialApp, options: &CcInitDataOptions) -> String {
    let kbs_url = options.kbs_url.clone();
    let kbs_ca_cert_pem = options.kbs_ca_cert_pem.clone();
    let primary = app
        .primary_container()
        .expect("app must have a primary container");
    let image_digest = primary.image.digest_ref();
    let signer_identity_subject = required_claim(
        "signer_identity_subject",
        app.signer_identity_subject.as_deref(),
    );
    let signer_identity_issuer = required_claim(
        "signer_identity_issuer",
        app.signer_identity_issuer.as_deref(),
    );
    assert_non_empty("image_digest", &image_digest);
    assert_non_empty("namespace", &app.namespace);
    assert_non_empty("service_account", &app.service_account);
    assert_non_empty("identity_hash", &app.tenant_instance_identity_hash);
    assert_non_empty("runtime_class", DEFAULT_RUNTIME_CLASS);
    assert_non_empty(
        "sidecar_digests.attestation_proxy",
        app.attestation.proxy_image.digest(),
    );
    assert_non_empty(
        "sidecar_digests.caddy_ingress",
        app.attestation.caddy_image.digest(),
    );

    let identity_toml = build_identity_toml(
        &app.namespace,
        &app.name,
        &app.owner_resource_type(),
        &app.bootstrap_owner_pubkey_hash,
        &app.tenant_instance_identity_hash,
    );

    // This format matches init_data.py _TOML_TEMPLATE exactly.
    // Whitespace and quoting must be identical for hash compatibility.
    let mut toml = String::new();
    toml.push_str("version = \"0.1.0\"\nalgorithm = \"sha256\"\n");
    toml.push('\n');
    toml.push_str("[data]\n");
    toml.push_str(&format!("image_digest = \"{}\"\n", image_digest));
    toml.push_str(&format!("runtime_class = \"{}\"\n", DEFAULT_RUNTIME_CLASS));
    toml.push_str(&format!("namespace = \"{}\"\n", app.namespace));
    toml.push_str(&format!("service_account = \"{}\"\n", app.service_account));
    toml.push_str(&format!(
        "identity_hash = \"{}\"\n",
        app.tenant_instance_identity_hash
    ));
    toml.push_str(&format!(
        "signer_identity_subject = \"{}\"\n",
        signer_identity_subject
    ));
    toml.push_str(&format!(
        "signer_identity_issuer = \"{}\"\n",
        signer_identity_issuer
    ));
    if let Some(binding) = &app.workload_artifact_binding {
        toml.push_str(&format!(
            "descriptor_core_hash = \"{}\"\n",
            hex::encode(binding.descriptor_core_hash)
        ));
        toml.push_str(&format!(
            "descriptor_signing_pubkey = \"{}\"\n",
            hex::encode(binding.descriptor_signing_pubkey)
        ));
        toml.push_str(&format!(
            "org_keyring_fingerprint = \"{}\"\n",
            hex::encode(binding.org_keyring_fingerprint)
        ));
    }
    toml.push('\n');

    // policy.rego
    toml.push_str("\"policy.rego\" = '''\n");
    if let Some(agent_policy) = &app.generated_agent_policy {
        let actual_hash: [u8; 32] = Sha256::digest(agent_policy.policy_text.as_bytes()).into();
        assert_eq!(
            actual_hash, agent_policy.policy_sha256,
            "generated_agent_policy.policy_sha256 must match policy_text"
        );
        assert_non_empty(
            "generated_agent_policy.genpolicy_version_pin",
            &agent_policy.genpolicy_version_pin,
        );
        toml.push_str(&agent_policy.policy_text);
        if !agent_policy.policy_text.ends_with('\n') {
            toml.push('\n');
        }
    } else {
        toml.push_str(&build_agent_policy(
            &image_digest,
            &app.namespace,
            &app.service_account,
            &app.name,
        ));
    }
    toml.push_str("'''\n");
    toml.push('\n');

    // aa.toml
    toml.push_str("\"aa.toml\" = '''\n");
    toml.push_str("[token_configs]\n");
    toml.push_str("[token_configs.kbs]\n");
    toml.push_str(&format!("url = \"{}\"\n", toml_basic_string(&kbs_url)));
    if let Some(cert) = &kbs_ca_cert_pem {
        append_multiline_basic_string(&mut toml, "cert", cert);
    }
    toml.push_str("'''\n");
    toml.push('\n');

    // cdh.toml
    toml.push_str("\"cdh.toml\" = '''\n");
    toml.push_str("[kbc]\n");
    toml.push_str("name = \"cc_kbc\"\n");
    toml.push_str(&format!("url = \"{}\"\n", toml_basic_string(&kbs_url)));
    if let Some(cert) = &kbs_ca_cert_pem {
        append_multiline_basic_string(&mut toml, "kbs_cert", cert);
    }
    toml.push_str("'''\n");

    // identity.toml (always present per OID-1)
    toml.push('\n');
    toml.push_str("\"identity.toml\" = '''\n");
    toml.push_str(&identity_toml);
    toml.push_str("'''\n");

    // Phase 11: bind sidecar digests so the customer-signed descriptor can
    // chain `expected_cc_init_data_hash` to the exact runtime identity. Kata's
    // initdata parser expects every [data] value to be a string, so keep the
    // structured claim as a JSON string instead of a nested TOML table.
    toml.push_str(&format!(
        "sidecar_digests = '{{\"attestation_proxy\":\"{}\",\"caddy_ingress\":\"{}\"}}'\n",
        app.attestation.proxy_image.digest(),
        app.attestation.caddy_image.digest()
    ));

    toml
}

/// The SNP runtime class CAP requires. enclava-init reads this from cc_init_data
/// at boot and refuses to start if the rendered Pod's `runtimeClassName` differs.
pub const DEFAULT_RUNTIME_CLASS: &str = "kata-qemu-snp";

fn required_claim<'a>(name: &str, value: Option<&'a str>) -> &'a str {
    let value = value.unwrap_or_else(|| panic!("cc_init_data requires non-empty {name}"));
    assert_non_empty(name, value);
    value
}

fn assert_non_empty(name: &str, value: &str) {
    assert!(!value.is_empty(), "cc_init_data requires non-empty {name}");
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn toml_basic_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn append_multiline_basic_string(toml: &mut String, key: &str, value: &str) {
    let value = value.trim();
    assert!(
        !value.contains("\"\"\""),
        "cc_init_data {key} must not contain TOML multiline string delimiter"
    );
    toml.push_str(&format!("{key} = \"\"\"\n{value}\n\"\"\"\n"));
}

fn build_agent_policy(
    image_digest: &str,
    namespace: &str,
    service_account: &str,
    instance: &str,
) -> String {
    let policy_data = serde_json::json!({
        "containers": [{
            "OCI": {
                "Annotations": {
                    "io.kubernetes.cri.image-name": image_digest,
                    "io.kubernetes.pod.namespace": namespace,
                    "io.kubernetes.pod.service-account.name": service_account,
                    "tenant.flowforge.sh/instance": instance
                }
            },
            "image_name": image_digest
        }]
    });

    let mut rego = String::new();
    rego.push_str("package agent_policy\n\n");
    rego.push_str("default AddARPNeighborsRequest := false\n");
    rego.push_str("default AddSwapRequest := false\n");
    rego.push_str("default CloseStdinRequest := true\n");
    rego.push_str("default CopyFileRequest := false\n");
    rego.push_str("default CreateContainerRequest := false\n");
    rego.push_str("default CreateSandboxRequest := true\n");
    rego.push_str("default DestroySandboxRequest := true\n");
    rego.push_str("default ExecProcessRequest := false\n");
    rego.push_str("default GetOOMEventRequest := true\n");
    rego.push_str("default GuestDetailsRequest := true\n");
    rego.push_str("default ListInterfacesRequest := false\n");
    rego.push_str("default ListRoutesRequest := false\n");
    rego.push_str("default MemHotplugByProbeRequest := false\n");
    rego.push_str("default OnlineCPUMemRequest := true\n");
    rego.push_str("default PauseContainerRequest := false\n");
    rego.push_str("default ReadStreamRequest := false\n");
    rego.push_str("default RemoveContainerRequest := true\n");
    rego.push_str("default RemoveStaleVirtiofsShareMountsRequest := true\n");
    rego.push_str("default ReseedRandomDevRequest := false\n");
    rego.push_str("default ResumeContainerRequest := false\n");
    rego.push_str("default SetGuestDateTimeRequest := false\n");
    rego.push_str("default SetPolicyRequest := false\n");
    rego.push_str("default SignalProcessRequest := true\n");
    rego.push_str("default StartContainerRequest := true\n");
    rego.push_str("default StartTracingRequest := false\n");
    rego.push_str("default StatsContainerRequest := true\n");
    rego.push_str("default StopTracingRequest := false\n");
    rego.push_str("default TtyWinResizeRequest := true\n");
    rego.push_str("default UpdateContainerRequest := false\n");
    rego.push_str("default UpdateEphemeralMountsRequest := false\n");
    rego.push_str("default UpdateInterfaceRequest := false\n");
    rego.push_str("default UpdateRoutesRequest := false\n");
    rego.push_str("default WaitProcessRequest := true\n");
    rego.push_str("default WriteStreamRequest := false\n\n");
    rego.push_str("default AllowRequestsFailingPolicy := false\n\n");
    rego.push_str("CreateContainerRequest {\n");
    rego.push_str(&format!(
        "  input.OCI.Annotations[\"io.kubernetes.cri.image-name\"] == {}\n",
        rego_string(image_digest)
    ));
    rego.push_str(&format!(
        "  input.OCI.Annotations[\"io.kubernetes.pod.namespace\"] == {}\n",
        rego_string(namespace)
    ));
    rego.push_str(&format!(
        "  input.OCI.Annotations[\"io.kubernetes.pod.service-account.name\"] == {}\n",
        rego_string(service_account)
    ));
    rego.push_str(&format!(
        "  input.OCI.Annotations[\"tenant.flowforge.sh/instance\"] == {}\n",
        rego_string(instance)
    ));
    rego.push_str("}\n\n");
    rego.push_str(&format!("policy_data := {}\n", policy_data));
    rego
}

fn rego_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
}

/// Build the identity.toml content.
fn build_identity_toml(
    tenant_id: &str,
    instance_id: &str,
    owner_resource_type: &str,
    bootstrap_owner_pubkey_hash: &str,
    identity_hash: &str,
) -> String {
    format!(
        "tenant_id = \"{tenant_id}\"\n\
         instance_id = \"{instance_id}\"\n\
         owner_resource_type = \"{owner_resource_type}\"\n\
         bootstrap_owner_pubkey_hash = \"{bootstrap_owner_pubkey_hash}\"\n\
         tenant_instance_identity_hash = \"{identity_hash}\"\n"
    )
}

/// Compute SHA256 hex digest of the TOML string.
/// This hash is used in the `storage.enclava.dev/secure-pv-init-data-sha256` annotation.
pub fn sha256_hex(toml: &str) -> String {
    let hash = Sha256::digest(toml.as_bytes());
    hex::encode(hash)
}

/// gzip compress (mtime=0) then base64 encode the TOML string.
/// Matches the Python `gzip.compress(data, mtime=0)` + `base64.b64encode()`.
pub fn encode_cc_init_data(toml: &str) -> String {
    let header = flate2::GzBuilder::new().mtime(0);
    let mut encoder = header.write(Vec::new(), flate2::Compression::default());
    encoder
        .write_all(toml.as_bytes())
        .expect("gzip write failed");
    let compressed = encoder.finish().expect("gzip finish failed");

    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(&compressed)
}

/// Convenience: build TOML, compute hash, and encode in one call.
/// Returns (encoded_base64, sha256_hash).
pub fn compute_cc_init_data(app: &ConfidentialApp) -> (String, String) {
    let toml = build_toml(app);
    encode_and_hash_toml(&toml)
}

pub fn compute_cc_init_data_with_options(
    app: &ConfidentialApp,
    options: &CcInitDataOptions,
) -> (String, String) {
    let toml = build_toml_with_options(app, options);
    encode_and_hash_toml(&toml)
}

fn encode_and_hash_toml(toml: &str) -> (String, String) {
    let hash = sha256_hex(toml);
    let encoded = encode_cc_init_data(toml);
    (encoded, hash)
}

/// Verify that the rendered StatefulSet's `runtimeClassName` matches what
/// cc_init_data binds. Phase 11: deploy fails fast if the chain breaks.
pub fn verify_runtime_class_binding(
    sts: &k8s_openapi::api::apps::v1::StatefulSet,
) -> Result<(), String> {
    let actual = sts
        .spec
        .as_ref()
        .and_then(|s| s.template.spec.as_ref())
        .and_then(|p| p.runtime_class_name.as_deref());
    match actual {
        Some(name) if name == DEFAULT_RUNTIME_CLASS => Ok(()),
        Some(other) => Err(format!(
            "rendered Pod runtimeClassName is `{other}`, expected `{DEFAULT_RUNTIME_CLASS}`"
        )),
        None => Err("rendered Pod has no runtimeClassName".to_string()),
    }
}
