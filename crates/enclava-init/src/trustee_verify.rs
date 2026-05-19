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

/// Returns true if the chain ran end-to-end, false if it was skipped because
/// the Phase 3 Trustee patch is not yet deployed. False return is logged as
/// an error so production deployments cannot quietly run without verification.
pub fn verify_chain_or_skip(inputs: Option<&VerifyInputs<'_>>) -> Result<bool> {
    match inputs {
        Some(i) => {
            verify_chain(i)?;
            Ok(true)
        }
        None => {
            tracing::error!(
                "Phase 3 Trustee patch not yet deployed; in-TEE policy verification SKIPPED"
            );
            Ok(false)
        }
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
    artifacts: Vec<PolicyEnvelope>,
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
        let policy = parse_trustee_policy_body(policy_body, &bundle)?;
        Ok((bundle, policy))
    }
}

fn parse_trustee_policy_body(
    policy_body: serde_json::Value,
    bundle: &ArtifactsBundle,
) -> Result<PolicyEnvelope> {
    if let Ok(policy) = serde_json::from_value::<PolicyEnvelope>(policy_body.clone()) {
        return Ok(policy);
    }
    let policy_set: SignedPolicyArtifactSet = serde_json::from_value(policy_body).map_err(|e| {
        InitError::Kbs(format!("fetch policy: unsupported policy body format: {e}"))
    })?;
    if policy_set.schema_version != "enclava-signed-policy-set-v1" {
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
mod tests {
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
                agent_policy_sha256:
                    "749bf91b70ba77fff6ad79581c0b3319cbff946e8f3783f8a44517fa50d470e9".to_string(),
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
    fn end_to_end_chain_rejects_descriptor_signed_artifact_when_signing_service_key_is_configured()
    {
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
    fn skipped_chain_logs_and_returns_false() {
        let result = verify_chain_or_skip(None).unwrap();
        assert!(!result);
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
        let token =
            parse_kbs_attestation_token_payload(&serde_json::json!({ "token": "abc.def.ghi" }))
                .unwrap();
        assert_eq!(token, "abc.def.ghi");
    }
}
