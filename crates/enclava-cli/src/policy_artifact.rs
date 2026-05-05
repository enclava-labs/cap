//! Customer-signed Trustee/KBS policy artifact generation.
//!
//! This mirrors CAP and Trustee CE-v1 signing bytes so the deployment key can
//! authorize the exact Rego and Kata agent policy bodies before CAP transports
//! them to Trustee.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use enclava_common::descriptor::{DeploymentDescriptor, descriptor_core_hash};
use enclava_engine::types::GeneratedAgentPolicy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::keys::UserSigningKey;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyArtifact {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    pub rego_sha256: String,
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub signature: String,
    pub verify_pubkey_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_keyring: Option<serde_json::Value>,
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

pub fn sign_policy_artifact(
    descriptor: &DeploymentDescriptor,
    descriptor_signing_key: &UserSigningKey,
    signing_key_id: String,
    rego_text: String,
    generated_agent_policy: &GeneratedAgentPolicy,
    org_keyring: Option<serde_json::Value>,
    signed_at: DateTime<Utc>,
) -> SignedPolicyArtifact {
    let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
    let agent_policy_hash: [u8; 32] =
        Sha256::digest(generated_agent_policy.policy_text.as_bytes()).into();
    assert_eq!(
        agent_policy_hash, generated_agent_policy.policy_sha256,
        "generated agent policy hash must match policy text"
    );
    let descriptor_signing_pubkey = descriptor_signing_key.public;
    let metadata = PolicyMetadata {
        app_id: descriptor.app_id.to_string(),
        deploy_id: descriptor.deploy_id.to_string(),
        descriptor_core_hash: hex::encode(descriptor_core_hash(descriptor)),
        descriptor_signing_pubkey: hex::encode(descriptor_signing_pubkey.to_bytes()),
        platform_release_version: descriptor.platform_release_version.clone(),
        policy_template_id: descriptor.policy_template_id.clone(),
        policy_template_sha256: hex::encode(descriptor.policy_template_sha256),
        agent_policy_sha256: hex::encode(agent_policy_hash),
        genpolicy_version_pin: generated_agent_policy.genpolicy_version_pin.clone(),
        signed_at: signed_at.to_rfc3339(),
        key_id: signing_key_id,
    };
    let signing_input = policy_artifact_signing_input(&metadata, &rego_hash);
    let signature = descriptor_signing_key.sign(&signing_input);
    SignedPolicyArtifact {
        metadata,
        rego_text,
        rego_sha256: hex::encode(rego_hash),
        agent_policy_text: generated_agent_policy.policy_text.clone(),
        agent_policy_sha256: hex::encode(agent_policy_hash),
        signature: hex::encode(signature.to_bytes()),
        verify_pubkey_b64: B64.encode(descriptor_signing_pubkey.to_bytes()),
        org_keyring,
    }
}

pub fn policy_artifact_signing_input(metadata: &PolicyMetadata, rego_hash: &[u8; 32]) -> Vec<u8> {
    let metadata_hash = canonical_policy_metadata_hash(metadata);
    ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", &metadata_hash),
        ("rego_sha256", rego_hash),
    ])
}

pub fn canonical_policy_metadata_hash(metadata: &PolicyMetadata) -> [u8; 32] {
    let app_id = Uuid::parse_str(&metadata.app_id)
        .expect("metadata.app_id must be UUID")
        .into_bytes();
    let deploy_id = Uuid::parse_str(&metadata.deploy_id)
        .expect("metadata.deploy_id must be UUID")
        .into_bytes();
    let descriptor_core_hash = decode_hex32("descriptor_core_hash", &metadata.descriptor_core_hash);
    let descriptor_signing_pubkey = decode_hex32(
        "descriptor_signing_pubkey",
        &metadata.descriptor_signing_pubkey,
    );
    let policy_template_sha256 =
        decode_hex32("policy_template_sha256", &metadata.policy_template_sha256);
    let agent_policy_sha256 = decode_hex32("agent_policy_sha256", &metadata.agent_policy_sha256);

    ce_v1_hash(&[
        ("app_id", &app_id),
        ("deploy_id", &deploy_id),
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
    ])
}

fn decode_hex32(name: &str, value: &str) -> [u8; 32] {
    hex::decode(value.trim())
        .unwrap_or_else(|err| panic!("{name} must be hex: {err}"))
        .try_into()
        .unwrap_or_else(|bytes: Vec<u8>| panic!("{name} must be 32 bytes, got {}", bytes.len()))
}
