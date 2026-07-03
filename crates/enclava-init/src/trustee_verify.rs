//! In-TEE Trustee policy verification chain (rev13/rev14, plan ~lines 811-833).
//!
//! Runs entirely inside the SEV-SNP TEE before any seed material is released.
//! Six steps; failure on any one refuses the seed write.
//!
//! Network fetch of the policy envelope from `GET /resource-policy/<id>/body`
//! and the workload-attested artifact bundle from `GET
//! /api/v1/workload/artifacts` is gated behind `Config.trustee_policy_read_available`.
//! The flag defaults FALSE; while it's false the verifier emits a loud
//! `tracing::error!` saying the Phase 3 Trustee patch hasn't shipped yet,
//! and `verify_chain_or_skip` returns Ok(false) so the caller knows the
//! release happened without policy verification. We do NOT fall back to a
//! local descriptor file the way the earlier prototype did — that would be
//! pretending to verify something we didn't.
//!
//! Descriptor hashing uses `enclava_common::descriptor`, the same module the
//! CLI signer uses, so signer + verifier agree byte-for-byte across crates.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use enclava_common::descriptor::{
    DeploymentDescriptor, descriptor_canonical_bytes, descriptor_core_hash,
};
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
    /// Preferred policy producer keys. When a signing-service key is pinned in
    /// signed cc_init_data it is authoritative; descriptor-key policy signing is
    /// only a legacy fallback for older releases with no configured platform
    /// policy key.
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
pub struct ArtifactFetcher {
    pub workload_artifacts_url: String,
    pub trustee_policy_url: String,
    pub kbs_attestation_token: String,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedPolicyArtifactSet {
    schema_version: String,
    artifacts: Vec<ActivePolicyEnvelope>,
}

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
