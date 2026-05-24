//! cc_init_data generation: TOML + gzip + base64.
//!
//! Ports the Python implementation at platform_api/manifests/init_data.py.
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
/// The TOML structure follows the Python template in init_data.py, with all
/// interpolated scalar values emitted through a TOML-safe string encoder.
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

    // Keep this layout stable: descriptor signatures commit to the resulting
    // cc_init_data hash.
    let mut toml = String::new();
    toml.push_str("version = \"0.1.0\"\nalgorithm = \"sha256\"\n");
    toml.push('\n');
    toml.push_str("[data]\n");
    push_toml_string(&mut toml, "image_digest", &image_digest);
    push_toml_string(&mut toml, "runtime_class", DEFAULT_RUNTIME_CLASS);
    push_toml_string(&mut toml, "namespace", &app.namespace);
    push_toml_string(&mut toml, "service_account", &app.service_account);
    push_toml_string(
        &mut toml,
        "argon2_salt_hex",
        &crate::manifest::enclava_init_config::argon2_salt_hex(app),
    );
    push_toml_string(
        &mut toml,
        "kbs_url",
        crate::manifest::enclava_init_config::LOCAL_KATA_CDH_RESOURCE_URL,
    );
    push_toml_string(&mut toml, "kbs_resource_path", &app.owner_resource_path());
    push_toml_string(
        &mut toml,
        "kbs_attestation_token_url",
        crate::manifest::enclava_init_config::LOCAL_KBS_ATTESTATION_TOKEN_URL,
    );
    if app.attestation.trustee_policy_read_available {
        if let Some(url) = app
            .attestation
            .local_workload_artifacts_json
            .as_ref()
            .map(|_| "file:///etc/enclava-init/workload-artifacts.json")
            .or(app.attestation.workload_artifacts_url.as_deref())
        {
            push_toml_string(&mut toml, "workload_artifacts_url", url);
        }
        if let Some(url) = app.attestation.tls_certificate_broker_url.as_deref() {
            push_toml_string(&mut toml, "tls_certificate_broker_url", url);
            push_toml_string(
                &mut toml,
                "tls_certificate_hostnames",
                &serde_json::to_string(&tls_certificate_hostnames(app))
                    .expect("hostname list serialization is infallible"),
            );
        }
        if let Some(url) = app
            .attestation
            .local_trustee_policy_json
            .as_ref()
            .map(|_| "file:///etc/enclava-init/trustee-policy.json")
            .or(app.attestation.trustee_policy_url.as_deref())
        {
            push_toml_string(&mut toml, "trustee_policy_url", url);
        }
        if let Some(pubkey) = &app.attestation.platform_trustee_policy_pubkey_hex {
            push_toml_string(&mut toml, "platform_trustee_policy_pubkey_hex", pubkey);
        }
        if let Some(pubkey) = &app.attestation.signing_service_pubkey_hex {
            push_toml_string(&mut toml, "signing_service_pubkey_hex", pubkey);
        }
    }
    push_toml_string(
        &mut toml,
        "identity_hash",
        &app.tenant_instance_identity_hash,
    );
    push_toml_string(
        &mut toml,
        "signer_identity_subject",
        signer_identity_subject,
    );
    push_toml_string(&mut toml, "signer_identity_issuer", signer_identity_issuer);
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
    push_toml_string(&mut toml, "url", &kbs_url);
    if let Some(cert) = &kbs_ca_cert_pem {
        push_toml_string(&mut toml, "cert", cert.trim());
    }
    toml.push_str("'''\n");
    toml.push('\n');

    // cdh.toml
    toml.push_str("\"cdh.toml\" = '''\n");
    toml.push_str("[kbc]\n");
    toml.push_str("name = \"cc_kbc\"\n");
    push_toml_string(&mut toml, "url", &kbs_url);
    if let Some(cert) = &kbs_ca_cert_pem {
        push_toml_string(&mut toml, "kbs_cert", cert.trim());
    }
    toml.push_str("'''\n");

    // identity.toml (always present per OID-1)
    toml.push('\n');
    toml.push_str("\"identity.toml\" = '''\n");
    toml.push_str(&identity_toml);
    toml.push_str("'''\n");

    let sidecar_digests = serde_json::json!({
        "attestation_proxy": app.attestation.proxy_image.digest(),
        "caddy_ingress": app.attestation.caddy_image.digest(),
    })
    .to_string();
    push_toml_string(&mut toml, "sidecar_digests", &sidecar_digests);

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

fn push_toml_string(toml: &mut String, key: &str, value: &str) {
    toml.push_str(key);
    toml.push_str(" = ");
    toml.push_str(&toml_string(value));
    toml.push('\n');
}

fn tls_certificate_hostnames(app: &ConfidentialApp) -> Vec<String> {
    let mut hosts = vec![app.domain.platform_domain.clone()];
    if let Some(custom) = app.domain.custom_domain.as_ref()
        && !custom.is_empty()
        && !hosts.iter().any(|host| host == custom)
    {
        hosts.push(custom.clone());
    }
    hosts
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization is infallible")
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
                    crate::types::TENANT_INSTANCE_ANNOTATION: instance,
                    crate::types::LEGACY_TENANT_INSTANCE_ANNOTATION: instance
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
    rego.push_str("  tenant_instance_matches\n");
    rego.push_str("}\n\n");
    rego.push_str("tenant_instance_matches {\n");
    rego.push_str(&format!(
        "  input.OCI.Annotations[{}] == {}\n",
        rego_string(crate::types::TENANT_INSTANCE_ANNOTATION),
        rego_string(instance)
    ));
    rego.push_str("}\n\n");
    rego.push_str("tenant_instance_matches {\n");
    rego.push_str(&format!(
        "  input.OCI.Annotations[{}] == {}\n",
        rego_string(crate::types::LEGACY_TENANT_INSTANCE_ANNOTATION),
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
    let mut out = String::new();
    push_toml_string(&mut out, "tenant_id", tenant_id);
    push_toml_string(&mut out, "instance_id", instance_id);
    push_toml_string(&mut out, "owner_resource_type", owner_resource_type);
    push_toml_string(
        &mut out,
        "bootstrap_owner_pubkey_hash",
        bootstrap_owner_pubkey_hash,
    );
    push_toml_string(&mut out, "tenant_instance_identity_hash", identity_hash);
    out
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
