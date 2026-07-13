//! In-TEE Trustee policy verification chain (rev13/rev14, plan ~lines 811-833).
//!
//! Runs entirely inside the SEV-SNP TEE before any seed material is released.
//! Six steps; failure on any one refuses the seed write.
//!
//! Production uses receipt mode: fetch the signed deployment authorization
//! through direct guest CDH, fetch the claim-selected bundle from CAP over
//! pinned HTTPS, and verify both before any seed or LUKS operation. The old
//! active-policy fetch/parser remains compiled only into archival tests.
//!
//! Descriptor hashing uses `enclava_common::descriptor`, the same module the
//! CLI signer uses, so signer + verifier agree byte-for-byte across crates.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use enclava_common::descriptor::{
    DeploymentDescriptor, descriptor_canonical_bytes, descriptor_core_hash,
};
#[cfg(test)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

use crate::errors::{InitError, Result};

/// Envelope of the active Trustee policy as fetched from
/// `GET /resource-policy/<id>/body` (rev9 finding #2 — Phase 3 endpoint).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEnvelope {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    /// Detached Ed25519 signature over the CE-v1 raw bytes of (purpose,
    /// canonical_policy_metadata_hash, sha256(rego_text)). rev13 finding #5.
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

/// Active policy body fetched from Trustee/KBS.
///
/// Newer CAP policy sets omit `agent_policy_text` from the shared ConfigMap so
/// the Kubernetes object stays below its 1 MiB limit. The full text remains in
/// the workload artifact bundle and is verified against the signed
/// `agent_policy_sha256`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg(test)]
pub struct ActivePolicyEnvelope {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    pub agent_policy_sha256: String,
    #[serde(default)]
    pub agent_policy_text: Option<String>,
    /// Detached Ed25519 signature over the CE-v1 raw bytes of (purpose,
    /// canonical_policy_metadata_hash, sha256(rego_text)).
    #[serde(with = "hex::serde")]
    pub signature: [u8; 64],
}

#[cfg(test)]
impl From<&PolicyEnvelope> for ActivePolicyEnvelope {
    fn from(env: &PolicyEnvelope) -> Self {
        Self {
            metadata: env.metadata.clone(),
            rego_text: env.rego_text.clone(),
            agent_policy_sha256: env.agent_policy_sha256.clone(),
            agent_policy_text: Some(env.agent_policy_text.clone()),
            signature: env.signature,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub app_id: String,
    pub deploy_id: String,
    pub descriptor_core_hash: String,
    pub descriptor_signing_pubkey: String,
    pub platform_release_version: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
    pub signed_at: String,
    pub key_id: String,
}

/// Bundle returned by `GET /api/v1/workload/artifacts` (rev14 finding #2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactsBundle {
    pub descriptor_payload: serde_json::Value,
    #[serde(with = "hex::serde")]
    pub descriptor_signature: [u8; 64],
    pub descriptor_signing_key_id: String,
    pub org_keyring_payload: serde_json::Value,
    #[serde(with = "hex::serde")]
    pub org_keyring_signature: [u8; 64],
    pub signed_policy_artifact: PolicyEnvelope,
}

#[derive(Debug, Clone)]
pub struct CcInitDataClaims {
    pub descriptor_core_hash: [u8; 32],
    pub descriptor_signing_pubkey: [u8; 32],
    pub org_keyring_fingerprint: [u8; 32],
}

pub struct VerifyInputs<'a> {
    pub policy_envelope: &'a PolicyEnvelope,
    pub artifacts: &'a ArtifactsBundle,
    pub cc_init_data_claims: &'a CcInitDataClaims,
    pub local_cc_init_data_toml: &'a [u8],
    /// Preferred policy producer keys. In receipt mode this is the key selected
    /// by issuer ID from the authoritative trust map in signed cc_init_data;
    /// descriptor-key policy signing is only a legacy fallback for older
    /// releases with no configured platform policy key.
    pub platform_trustee_policy_pubkey: Option<&'a VerifyingKey>,
    pub signing_service_pubkey: Option<&'a VerifyingKey>,
}

/// Run all six in-TEE verification steps. Returns Ok(()) only if every step
/// passes; any mismatch returns `InitError::TrusteePolicy(<step>)`.
pub fn verify_chain(inputs: &VerifyInputs<'_>) -> Result<()> {
    if inputs.policy_envelope != &inputs.artifacts.signed_policy_artifact {
        return Err(InitError::TrusteePolicy(
            "active Trustee policy does not match workload artifact bundle".into(),
        ));
    }

    let core_hash = compute_descriptor_core_hash(&inputs.artifacts.descriptor_payload)?;
    if core_hash != inputs.cc_init_data_claims.descriptor_core_hash {
        return Err(InitError::TrusteePolicy(
            "step 1: descriptor_core_hash mismatch".into(),
        ));
    }

    verify_descriptor_full_signature(
        inputs.artifacts,
        &inputs.cc_init_data_claims.descriptor_signing_pubkey,
    )?;

    let descriptor = &inputs.artifacts.descriptor_payload;
    let expected_cc_init_data_hash = descriptor
        .get("expected_cc_init_data_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            InitError::TrusteePolicy("descriptor missing expected_cc_init_data_hash".into())
        })?;
    let local_hash = sha256_hex(inputs.local_cc_init_data_toml);
    if !ct_eq_hex(expected_cc_init_data_hash, &local_hash) {
        return Err(InitError::TrusteePolicy(
            "step 3: forward-chain expected_cc_init_data_hash mismatch".into(),
        ));
    }

    verify_keyring(
        inputs.artifacts,
        &inputs.cc_init_data_claims.org_keyring_fingerprint,
    )?;

    if !is_descriptor_signing_pubkey_in_keyring(
        &inputs.artifacts.org_keyring_payload,
        &inputs.cc_init_data_claims.descriptor_signing_pubkey,
    ) {
        return Err(InitError::TrusteePolicy(
            "step 4: descriptor_signing_pubkey not a deployer member of keyring".into(),
        ));
    }

    verify_policy_envelope_signature(
        inputs.policy_envelope,
        &inputs.cc_init_data_claims.descriptor_signing_pubkey,
        inputs.platform_trustee_policy_pubkey,
        inputs.signing_service_pubkey,
    )?;

    verify_signed_policy_artifact_metadata(
        inputs.policy_envelope,
        inputs.artifacts,
        inputs.cc_init_data_claims,
    )?;

    let expected_kbs_policy_hash = descriptor
        .get("expected_kbs_policy_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            InitError::TrusteePolicy("descriptor missing expected_kbs_policy_hash".into())
        })?;
    let actual_rego_hash = sha256_hex(inputs.policy_envelope.rego_text.as_bytes());
    if !ct_eq_hex(expected_kbs_policy_hash, &actual_rego_hash) {
        return Err(InitError::TrusteePolicy(
            "step 6: rego_text hash != descriptor.expected_kbs_policy_hash".into(),
        ));
    }
    let expected_agent_policy_hash = descriptor
        .get("expected_agent_policy_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            InitError::TrusteePolicy("descriptor missing expected_agent_policy_hash".into())
        })?;
    let actual_agent_hash = sha256_hex(inputs.policy_envelope.agent_policy_text.as_bytes());
    if !ct_eq_hex(expected_agent_policy_hash, &actual_agent_hash) {
        return Err(InitError::TrusteePolicy(
            "step 6: agent_policy_text hash != descriptor.expected_agent_policy_hash".into(),
        ));
    }
    if !ct_eq_hex(
        &inputs.policy_envelope.agent_policy_sha256,
        &actual_agent_hash,
    ) {
        return Err(InitError::TrusteePolicy(
            "step 6: agent_policy_sha256 mismatch".into(),
        ));
    }

    Ok(())
}

/// Returns true if the chain ran end-to-end. Missing verification inputs are
/// fatal because seeds must not be released without Trustee policy verification.
pub fn verify_chain_or_skip(inputs: Option<&VerifyInputs<'_>>) -> Result<bool> {
    match inputs {
        Some(i) => {
            verify_chain(i)?;
            Ok(true)
        }
        None => Err(InitError::TrusteePolicy(
            "in-TEE Trustee policy verification required before seed release".to_string(),
        )),
    }
}

#[derive(Debug, Clone)]
#[cfg(test)]
pub struct ArtifactFetcher {
    pub workload_artifacts_url: String,
    pub trustee_policy_url: String,
    pub kbs_attestation_token: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct ReceiptClaims {
    pub descriptor_core_hash: [u8; 32],
    pub expected_init_data_hash: [u8; 32],
    pub namespace: String,
    pub service_account: String,
    pub tenant_instance_identity_hash: [u8; 32],
    pub image_digest: String,
    pub signer_subject: String,
    pub signer_issuer: String,
}

#[derive(Debug, Clone)]
pub struct ReceiptArtifactFetcher {
    pub workload_artifacts_url: String,
    pub workload_artifacts_ca_cert_pem: Option<String>,
    pub kbs_attestation_token: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptBundleTransport {
    schema_version: String,
    artifact_bundle_digest: String,
    authorization_digest: String,
    receipt_resource_path: String,
    descriptor_payload: serde_json::Value,
    #[serde(with = "hex::serde")]
    descriptor_signature: [u8; 64],
    descriptor_signing_key_id: String,
    org_keyring_envelope: serde_json::Value,
    signed_policy_artifact: serde_json::Value,
}

impl ReceiptArtifactFetcher {
    pub fn fetch_and_verify(
        &self,
        claims: &ReceiptClaims,
        trusted_authorization_keys: &std::collections::BTreeMap<String, [u8; 32]>,
    ) -> Result<(
        ArtifactsBundle,
        enclava_common::kbs_authorization::DeploymentAuthorizationV1,
        [u8; 32],
    )> {
        let mut client_builder = reqwest::blocking::Client::builder().timeout(self.timeout);
        if let Some(ca_pem) = self.workload_artifacts_ca_cert_pem.as_deref() {
            let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes())
                .map_err(|e| InitError::Kbs(format!("artifact CA certificate: {e}")))?;
            client_builder = client_builder
                .tls_built_in_root_certs(false)
                .add_root_certificate(certificate);
        }
        let client = client_builder
            .build()
            .map_err(|e| InitError::Kbs(format!("client build: {e}")))?;
        let receipt_path =
            enclava_common::kbs_authorization::receipt_resource_path(&claims.descriptor_core_hash);
        let receipt_url = format!("http://127.0.0.1:8006/cdh/resource/{receipt_path}");
        let receipt_bytes = fetch_bounded_bytes(
            &client,
            &receipt_url,
            None,
            enclava_common::kbs_authorization::MAX_AUTHORIZATION_BYTES,
            "fetch deployment authorization",
        )?;
        let authorization =
            enclava_common::kbs_authorization::DeploymentAuthorizationV1::parse_exact_json(
                &receipt_bytes,
            )
            .map_err(|e| InitError::TrusteePolicy(format!("authorization schema: {e}")))?;
        let authorization_key =
            verify_authorization_signature(&authorization, trusted_authorization_keys)?;
        authorization
            .validate_time(Utc::now())
            .map_err(|e| InitError::TrusteePolicy(format!("authorization time: {e}")))?;
        verify_authorization_claims(&authorization, claims, &receipt_path)?;

        validate_workload_artifacts_url(&self.workload_artifacts_url)?;
        let bundle_bytes = fetch_bounded_bytes(
            &client,
            &self.workload_artifacts_url,
            Some(&self.kbs_attestation_token),
            2 * 1024 * 1024,
            "fetch workload artifact bundle",
        )?;
        let transport: ReceiptBundleTransport = serde_json::from_slice(&bundle_bytes)
            .map_err(|e| InitError::Kbs(format!("artifact bundle schema: {e}")))?;
        if transport.schema_version != "enclava-workload-artifact-bundle-v1"
            || transport.receipt_resource_path != receipt_path
            || decode_hex32("artifact_bundle_digest", &transport.artifact_bundle_digest)?
                != authorization.artifact_bundle_digest
            || decode_hex32("authorization_digest", &transport.authorization_digest)?
                != enclava_common::kbs_authorization::authorization_digest(&receipt_bytes)
        {
            return Err(InitError::TrusteePolicy(
                "artifact bundle receipt binding mismatch".into(),
            ));
        }
        let recomputed = recompute_receipt_bundle_digest(&transport, &authorization)?;
        if recomputed != authorization.artifact_bundle_digest {
            return Err(InitError::TrusteePolicy(
                "artifact bundle semantic digest mismatch".into(),
            ));
        }
        let bundle = receipt_transport_to_legacy(&transport)?;
        Ok((bundle, authorization, authorization_key))
    }
}

fn verify_authorization_signature(
    authorization: &enclava_common::kbs_authorization::DeploymentAuthorizationV1,
    trusted_authorization_keys: &std::collections::BTreeMap<String, [u8; 32]>,
) -> Result<[u8; 32]> {
    let authorization_key = enclava_common::kbs_authorization::trusted_authorization_key(
        trusted_authorization_keys,
        &authorization.issuer_key_id,
    )
    .map_err(|e| InitError::TrusteePolicy(format!("authorization issuer trust: {e}")))?;
    authorization
        .verify_signature(authorization_key)
        .map_err(|e| InitError::TrusteePolicy(format!("authorization signature: {e}")))?;
    Ok(*authorization_key)
}

fn verify_authorization_claims(
    authorization: &enclava_common::kbs_authorization::DeploymentAuthorizationV1,
    claims: &ReceiptClaims,
    receipt_path: &str,
) -> Result<()> {
    if authorization.descriptor_core_hash != claims.descriptor_core_hash
        || authorization.expected_init_data_hash != claims.expected_init_data_hash
        || authorization.namespace != claims.namespace
        || authorization.service_account != claims.service_account
        || authorization.tenant_instance_identity_hash != claims.tenant_instance_identity_hash
        || authorization.image_digest != claims.image_digest
        || authorization.signer_identity.subject != claims.signer_subject
        || authorization.signer_identity.issuer != claims.signer_issuer
        || authorization.receipt_resource_path != receipt_path
    {
        return Err(InitError::TrusteePolicy(
            "authorization measured identity mismatch".into(),
        ));
    }
    Ok(())
}

fn fetch_bounded_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
    attestation_token: Option<&str>,
    max_bytes: usize,
    context: &str,
) -> Result<Vec<u8>> {
    let mut request = client.get(url);
    if let Some(token) = attestation_token {
        request = request.header("Authorization", format!("Attestation {token}"));
    }
    let response = request
        .send()
        .map_err(|e| request_error(&format!("{context} send"), url, e))?
        .error_for_status()
        .map_err(|e| request_error(&format!("{context} status"), url, e))?;
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(InitError::Kbs(format!("{context}: response too large")));
    }
    let bytes = response
        .bytes()
        .map_err(|e| request_error(&format!("{context} body"), url, e))?;
    if bytes.len() > max_bytes {
        return Err(InitError::Kbs(format!("{context}: response too large")));
    }
    Ok(bytes.to_vec())
}

fn validate_workload_artifacts_url(value: &str) -> Result<()> {
    let url = reqwest::Url::parse(value)
        .map_err(|e| InitError::Kbs(format!("invalid workload artifact URL: {e}")))?;
    if url.scheme() == "https" {
        return Ok(());
    }
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| host == "127.0.0.1" || host == "::1" || host == "localhost");
    if loopback_http {
        return Ok(());
    }
    Err(InitError::Kbs(
        "workload artifact URL must use HTTPS outside loopback".into(),
    ))
}

fn recompute_receipt_bundle_digest(
    transport: &ReceiptBundleTransport,
    authorization: &enclava_common::kbs_authorization::DeploymentAuthorizationV1,
) -> Result<[u8; 32]> {
    let descriptor = parse_descriptor(&transport.descriptor_payload)?;
    let descriptor_bytes = descriptor_canonical_bytes(&descriptor);
    let envelope = transport
        .org_keyring_envelope
        .as_object()
        .ok_or_else(|| InitError::TrusteePolicy("org keyring envelope must be an object".into()))?;
    let keyring_value = envelope
        .get("keyring")
        .ok_or_else(|| InitError::TrusteePolicy("org keyring envelope missing keyring".into()))?;
    let keyring: InitOrgKeyring = serde_json::from_value(keyring_value.clone())
        .map_err(|e| InitError::TrusteePolicy(format!("keyring schema: {e}")))?;
    let keyring_bytes = canonical_keyring_bytes(&keyring)?;
    let keyring_signature = decode_hex64_value(envelope.get("signature"), "keyring signature")?;
    let keyring_pubkey = decode_hex32_value(envelope.get("signing_pubkey"), "keyring pubkey")?;
    if keyring.org_id != authorization.org_id
        || keyring.version != authorization.org_owner_version
        || sha256_bytes(&keyring_pubkey) != authorization.org_owner_pubkey_sha256
    {
        return Err(InitError::TrusteePolicy(
            "org keyring authorization binding mismatch".into(),
        ));
    }
    VerifyingKey::from_bytes(&keyring_pubkey)
        .map_err(|e| InitError::TrusteePolicy(format!("owner pubkey: {e}")))?
        .verify(&keyring_bytes, &Signature::from_bytes(&keyring_signature))
        .map_err(|_| InitError::TrusteePolicy("org keyring owner signature invalid".into()))?;

    let artifact: PolicyEnvelope = serde_json::from_value(transport.signed_policy_artifact.clone())
        .map_err(|e| InitError::TrusteePolicy(format!("signed policy artifact schema: {e}")))?;
    if transport.signed_policy_artifact.get("org_keyring") != Some(&transport.org_keyring_envelope)
    {
        return Err(InitError::TrusteePolicy(
            "signed policy artifact keyring envelope mismatch".into(),
        ));
    }
    let declared_rego = decode_hex32_value(
        transport.signed_policy_artifact.get("rego_sha256"),
        "rego_sha256",
    )?;
    let actual_rego: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
    let declared_agent = decode_hex32("agent_policy_sha256", &artifact.agent_policy_sha256)?;
    let actual_agent: [u8; 32] = Sha256::digest(artifact.agent_policy_text.as_bytes()).into();
    if declared_rego != actual_rego || declared_agent != actual_agent {
        return Err(InitError::TrusteePolicy(
            "signed policy artifact body hash mismatch".into(),
        ));
    }
    let policy_pubkey: [u8; 32] = B64
        .decode(
            transport
                .signed_policy_artifact
                .get("verify_pubkey_b64")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    InitError::TrusteePolicy("artifact missing verify_pubkey_b64".into())
                })?,
        )
        .map_err(|e| InitError::TrusteePolicy(format!("artifact verify pubkey: {e}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            InitError::TrusteePolicy(format!("artifact verify pubkey is {} bytes", bytes.len()))
        })?;
    let metadata_hash = canonical_policy_metadata_hash(&artifact.metadata)?;
    Ok(enclava_common::kbs_authorization::artifact_bundle_digest(
        &enclava_common::kbs_authorization::ArtifactBundleDigestInput {
            descriptor_canonical_bytes: &descriptor_bytes,
            descriptor_signature: &transport.descriptor_signature,
            descriptor_signing_key_id: &transport.descriptor_signing_key_id,
            org_keyring_canonical_bytes: &keyring_bytes,
            org_keyring_signature: &keyring_signature,
            org_keyring_signing_pubkey: &keyring_pubkey,
            policy_metadata_hash: &metadata_hash,
            rego_text: &artifact.rego_text,
            agent_policy_text: &artifact.agent_policy_text,
            policy_signature: &artifact.signature,
            policy_verify_pubkey: &policy_pubkey,
        },
    ))
}

fn receipt_transport_to_legacy(transport: &ReceiptBundleTransport) -> Result<ArtifactsBundle> {
    let envelope = transport
        .org_keyring_envelope
        .as_object()
        .ok_or_else(|| InitError::TrusteePolicy("org keyring envelope must be an object".into()))?;
    Ok(ArtifactsBundle {
        descriptor_payload: transport.descriptor_payload.clone(),
        descriptor_signature: transport.descriptor_signature,
        descriptor_signing_key_id: transport.descriptor_signing_key_id.clone(),
        org_keyring_payload: envelope
            .get("keyring")
            .cloned()
            .ok_or_else(|| InitError::TrusteePolicy("keyring missing".into()))?,
        org_keyring_signature: decode_hex64_value(envelope.get("signature"), "keyring signature")?,
        signed_policy_artifact: serde_json::from_value(transport.signed_policy_artifact.clone())
            .map_err(|e| InitError::TrusteePolicy(format!("policy artifact schema: {e}")))?,
    })
}

fn decode_hex32_value(value: Option<&serde_json::Value>, name: &str) -> Result<[u8; 32]> {
    let value = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| InitError::TrusteePolicy(format!("{name} missing")))?;
    decode_hex32(name, value)
}

fn decode_hex64_value(value: Option<&serde_json::Value>, name: &str) -> Result<[u8; 64]> {
    let value = value
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| InitError::TrusteePolicy(format!("{name} missing")))?;
    hex::decode(value)
        .map_err(|e| InitError::TrusteePolicy(format!("{name}: {e}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            InitError::TrusteePolicy(format!("{name} is {} bytes", bytes.len()))
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(test)]
struct SignedPolicyArtifactSet {
    schema_version: String,
    artifacts: Vec<ActivePolicyEnvelope>,
}

#[cfg(test)]
impl ArtifactFetcher {
    pub fn fetch(&self) -> Result<(ArtifactsBundle, PolicyEnvelope)> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| InitError::Kbs(format!("client build: {e}")))?;
        let bundle: ArtifactsBundle = fetch_json(
            &client,
            &self.workload_artifacts_url,
            &self.kbs_attestation_token,
            "fetch artifacts",
        )?;
        let policy_body: serde_json::Value = fetch_json(
            &client,
            &self.trustee_policy_url,
            &self.kbs_attestation_token,
            "fetch policy",
        )?;
        let active_policy = parse_trustee_policy_body(policy_body, &bundle)?;
        verify_active_policy_matches_artifact(&active_policy, &bundle.signed_policy_artifact)?;
        let policy = bundle.signed_policy_artifact.clone();
        Ok((bundle, policy))
    }
}

#[cfg(test)]
fn parse_trustee_policy_body(
    policy_body: serde_json::Value,
    bundle: &ArtifactsBundle,
) -> Result<ActivePolicyEnvelope> {
    if let Ok(policy) = serde_json::from_value::<ActivePolicyEnvelope>(policy_body.clone()) {
        return Ok(policy);
    }
    let policy_set: SignedPolicyArtifactSet = serde_json::from_value(policy_body).map_err(|e| {
        InitError::Kbs(format!("fetch policy: unsupported policy body format: {e}"))
    })?;
    if !matches!(
        policy_set.schema_version.as_str(),
        "enclava-signed-policy-set-v1" | "enclava-signed-policy-set-v2"
    ) {
        return Err(InitError::Kbs(format!(
            "fetch policy: unsupported policy set schema_version={}",
            policy_set.schema_version
        )));
    }
    policy_set
        .artifacts
        .into_iter()
        .find(|artifact| {
            artifact.metadata.descriptor_core_hash
                == bundle.signed_policy_artifact.metadata.descriptor_core_hash
        })
        .ok_or_else(|| {
            InitError::TrusteePolicy(
                "active Trustee policy set did not include matching workload artifact".into(),
            )
        })
}

#[cfg(test)]
fn fetch_json<T: DeserializeOwned>(
    client: &reqwest::blocking::Client,
    url: &str,
    attestation_token: &str,
    context: &str,
) -> Result<T> {
    if let Some(path) = url.strip_prefix("file://") {
        let bytes = std::fs::read(path)
            .map_err(|e| InitError::Kbs(format!("{context} file {path}: {e}")))?;
        return serde_json::from_slice(&bytes)
            .map_err(|e| InitError::Kbs(format!("{context} file {path} json: {e}")));
    }

    client
        .get(url)
        .header("Authorization", format!("Attestation {attestation_token}"))
        .send()
        .map_err(|e| request_error(&format!("{context} send"), url, e))?
        .error_for_status()
        .map_err(|e| request_error(&format!("{context} status"), url, e))?
        .json()
        .map_err(|e| request_error(&format!("{context} json"), url, e))
}

fn request_error(context: &str, url: &str, err: reqwest::Error) -> InitError {
    InitError::Kbs(format!("{context} {url}: {err}; debug={err:?}"))
}

pub fn resolve_kbs_attestation_token(
    env_token: Option<&str>,
    token_url: &str,
    timeout: Duration,
) -> Result<String> {
    if let Some(token) = env_token.map(str::trim).filter(|token| !token.is_empty()) {
        return Ok(token.to_string());
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
        .map_err(|e| InitError::Kbs(format!("token client build: {e}")))?;
    let payload: serde_json::Value = client
        .get(token_url)
        .send()
        .and_then(|r| r.error_for_status())
        .and_then(|r| r.json())
        .map_err(|e| InitError::Kbs(format!("fetch KBS attestation token: {e}")))?;
    parse_kbs_attestation_token_payload(&payload)
}

fn parse_kbs_attestation_token_payload(payload: &serde_json::Value) -> Result<String> {
    let token = payload
        .get("token")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| InitError::Kbs("KBS attestation token response missing token".into()))?;
    Ok(token.to_string())
}

fn verify_policy_envelope_signature(
    env: &PolicyEnvelope,
    descriptor_signing_pubkey: &[u8; 32],
    platform_trustee_policy_pubkey: Option<&VerifyingKey>,
    signing_service_pubkey: Option<&VerifyingKey>,
) -> Result<()> {
    let msg = ce_v1_policy_envelope_message(env)?;
    let sig = Signature::from_bytes(&env.signature);

    if let Some(signing_service_key) = signing_service_pubkey {
        return signing_service_key.verify(&msg, &sig).map_err(|_| {
            InitError::TrusteePolicy(
                "policy envelope sig did not verify with signing service key".into(),
            )
        });
    }

    if let Some(platform_key) = platform_trustee_policy_pubkey {
        return platform_key.verify(&msg, &sig).map_err(|_| {
            InitError::TrusteePolicy(
                "policy envelope sig did not verify with platform trustee policy key".into(),
            )
        });
    }

    let descriptor_key = VerifyingKey::from_bytes(descriptor_signing_pubkey)
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor policy pubkey: {e}")))?;
    if descriptor_key.verify(&msg, &sig).is_ok() {
        return Ok(());
    }

    Err(InitError::TrusteePolicy(
        "policy envelope sig did not verify with descriptor key".into(),
    ))
}

#[cfg(test)]
fn verify_active_policy_matches_artifact(
    active: &ActivePolicyEnvelope,
    artifact: &PolicyEnvelope,
) -> Result<()> {
    if active.metadata != artifact.metadata
        || active.rego_text != artifact.rego_text
        || active.agent_policy_sha256 != artifact.agent_policy_sha256
        || active.signature != artifact.signature
    {
        return Err(InitError::TrusteePolicy(
            "active Trustee policy does not match workload artifact bundle".into(),
        ));
    }
    if let Some(agent_policy_text) = active.agent_policy_text.as_deref()
        && agent_policy_text != artifact.agent_policy_text
    {
        return Err(InitError::TrusteePolicy(
            "active Trustee policy agent_policy_text does not match workload artifact bundle"
                .into(),
        ));
    }
    Ok(())
}

fn verify_descriptor_full_signature(
    artifacts: &ArtifactsBundle,
    descriptor_signing_pubkey: &[u8; 32],
) -> Result<()> {
    let pk = VerifyingKey::from_bytes(descriptor_signing_pubkey)
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor pubkey: {e}")))?;
    let msg = ce_v1_descriptor_full_message(&artifacts.descriptor_payload)?;
    let sig = Signature::from_bytes(&artifacts.descriptor_signature);
    pk.verify(&msg, &sig)
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor sig: {e}")))
}

fn verify_keyring(artifacts: &ArtifactsBundle, expected_fingerprint: &[u8; 32]) -> Result<()> {
    let bytes = ce_v1_keyring_bytes(&artifacts.org_keyring_payload)?;
    let fp = sha256_bytes(&bytes);
    if &fp != expected_fingerprint {
        return Err(InitError::TrusteePolicy(
            "step 4a: keyring fingerprint != cc_init_data.org_keyring_fingerprint".into(),
        ));
    }
    Ok(())
}

fn is_descriptor_signing_pubkey_in_keyring(keyring: &serde_json::Value, pubkey: &[u8; 32]) -> bool {
    let Some(members) = keyring.get("members").and_then(|m| m.as_array()) else {
        return false;
    };
    let pubkey_hex = hex::encode(pubkey);
    members.iter().any(|m| {
        let pk = m.get("pubkey").and_then(|p| p.as_str()).unwrap_or("");
        let role = m.get("role").and_then(|r| r.as_str()).unwrap_or("");
        ct_eq_hex(pk, &pubkey_hex) && (role == "deployer" || role == "admin" || role == "owner")
    })
}

fn verify_signed_policy_artifact_metadata(
    env: &PolicyEnvelope,
    artifacts: &ArtifactsBundle,
    cc: &CcInitDataClaims,
) -> Result<()> {
    let descriptor = &artifacts.descriptor_payload;
    let m = &env.metadata;

    let want_app = descriptor
        .get("app_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_deploy = descriptor
        .get("deploy_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_release = descriptor
        .get("platform_release_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_template_id = descriptor
        .get("policy_template_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_template_sha = descriptor
        .get("policy_template_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let want_agent_sha = descriptor
        .get("expected_agent_policy_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if m.app_id != want_app {
        return Err(InitError::TrusteePolicy("step 5: app_id mismatch".into()));
    }
    if m.deploy_id != want_deploy {
        return Err(InitError::TrusteePolicy(
            "step 5: deploy_id mismatch".into(),
        ));
    }
    if m.descriptor_core_hash != hex::encode(cc.descriptor_core_hash) {
        return Err(InitError::TrusteePolicy(
            "step 5: descriptor_core_hash mismatch".into(),
        ));
    }
    if m.descriptor_signing_pubkey != hex::encode(cc.descriptor_signing_pubkey) {
        return Err(InitError::TrusteePolicy(
            "step 5: descriptor_signing_pubkey mismatch".into(),
        ));
    }
    if m.platform_release_version != want_release {
        return Err(InitError::TrusteePolicy(
            "step 5: platform_release_version mismatch".into(),
        ));
    }
    if m.policy_template_id != want_template_id {
        return Err(InitError::TrusteePolicy(
            "step 5: policy_template_id mismatch".into(),
        ));
    }
    if m.policy_template_sha256 != want_template_sha {
        return Err(InitError::TrusteePolicy(
            "step 5: policy_template_sha256 mismatch".into(),
        ));
    }
    if m.agent_policy_sha256 != want_agent_sha {
        return Err(InitError::TrusteePolicy(
            "step 5: agent_policy_sha256 mismatch".into(),
        ));
    }
    Ok(())
}

fn compute_descriptor_core_hash(descriptor: &serde_json::Value) -> Result<[u8; 32]> {
    let d = parse_descriptor(descriptor)?;
    Ok(descriptor_core_hash(&d))
}

fn ce_v1_descriptor_full_message(descriptor: &serde_json::Value) -> Result<Vec<u8>> {
    let d = parse_descriptor(descriptor)?;
    Ok(descriptor_canonical_bytes(&d))
}

fn parse_descriptor(descriptor: &serde_json::Value) -> Result<DeploymentDescriptor> {
    serde_json::from_value(descriptor.clone())
        .map_err(|e| InitError::TrusteePolicy(format!("descriptor schema: {e}")))
}

fn ce_v1_policy_envelope_message(env: &PolicyEnvelope) -> Result<Vec<u8>> {
    let metadata_hash = canonical_policy_metadata_hash(&env.metadata)?;
    let rego_hash: [u8; 32] = Sha256::digest(env.rego_text.as_bytes()).into();
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", metadata_hash.as_slice()),
        ("rego_sha256", rego_hash.as_slice()),
    ]))
}

fn ce_v1_keyring_bytes(keyring: &serde_json::Value) -> Result<Vec<u8>> {
    let keyring: InitOrgKeyring = serde_json::from_value(keyring.clone())
        .map_err(|e| InitError::TrusteePolicy(format!("keyring schema: {e}")))?;
    canonical_keyring_bytes(&keyring)
}

fn canonical_policy_metadata_hash(metadata: &PolicyMetadata) -> Result<[u8; 32]> {
    let app_id = Uuid::parse_str(&metadata.app_id)
        .map_err(|e| InitError::TrusteePolicy(format!("metadata.app_id: {e}")))?;
    let deploy_id = Uuid::parse_str(&metadata.deploy_id)
        .map_err(|e| InitError::TrusteePolicy(format!("metadata.deploy_id: {e}")))?;
    let descriptor_core_hash = decode_hex32(
        "metadata.descriptor_core_hash",
        &metadata.descriptor_core_hash,
    )?;
    let descriptor_signing_pubkey = decode_hex32(
        "metadata.descriptor_signing_pubkey",
        &metadata.descriptor_signing_pubkey,
    )?;
    let policy_template_sha256 = decode_hex32(
        "metadata.policy_template_sha256",
        &metadata.policy_template_sha256,
    )?;
    let agent_policy_sha256 = decode_hex32(
        "metadata.agent_policy_sha256",
        &metadata.agent_policy_sha256,
    )?;

    Ok(ce_v1_hash(&[
        ("app_id", app_id.as_bytes().as_slice()),
        ("deploy_id", deploy_id.as_bytes().as_slice()),
        ("descriptor_core_hash", &descriptor_core_hash),
        ("descriptor_signing_pubkey", &descriptor_signing_pubkey),
        (
            "platform_release_version",
            metadata.platform_release_version.as_bytes(),
        ),
        ("policy_template_id", metadata.policy_template_id.as_bytes()),
        ("policy_template_sha256", &policy_template_sha256),
        ("agent_policy_sha256", &agent_policy_sha256),
        (
            "genpolicy_version_pin",
            metadata.genpolicy_version_pin.as_bytes(),
        ),
        ("signed_at", metadata.signed_at.as_bytes()),
        ("key_id", metadata.key_id.as_bytes()),
    ]))
}

#[derive(Debug, Deserialize)]
struct InitOrgKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<InitMember>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct InitMember {
    user_id: Uuid,
    pubkey: String,
    role: String,
    added_at: DateTime<Utc>,
}

fn canonical_keyring_bytes(keyring: &InitOrgKeyring) -> Result<Vec<u8>> {
    let members_hash = canonical_members_hash(&keyring.members)?;
    let version = keyring.version.to_be_bytes();
    let updated = keyring.updated_at.to_rfc3339();
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated.as_bytes()),
    ]))
}

fn canonical_member_hash(member: &InitMember) -> Result<[u8; 32]> {
    let pubkey = decode_hex32("keyring.member.pubkey", &member.pubkey)?;
    let added = member.added_at.to_rfc3339();
    Ok(ce_v1_hash(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", &pubkey),
        ("role", member.role.as_bytes()),
        ("added_at", added.as_bytes()),
    ]))
}

fn canonical_members_hash(members: &[InitMember]) -> Result<[u8; 32]> {
    let mut sorted: Vec<&InitMember> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let records: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| Ok((member.user_id.to_string(), canonical_member_hash(member)?)))
        .collect::<Result<_>>()?;
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    Ok(ce_v1_hash(&refs))
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    hex::decode(value.trim())
        .map_err(|e| InitError::TrusteePolicy(format!("{name}: {e}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            InitError::TrusteePolicy(format!("{name} must be 32 bytes, got {}", bytes.len()))
        })
}

fn sha256_bytes(b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b);
    h.finalize().into()
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(sha256_bytes(b))
}

fn ct_eq_hex(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
#[path = "trustee_verify/tests/mod.rs"]
mod tests;
