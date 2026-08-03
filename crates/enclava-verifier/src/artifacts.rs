use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::{
    canonical::{ce_v1_bytes, ce_v1_hash},
    descriptor::{DeploymentDescriptor, descriptor_canonical_bytes, descriptor_core_hash},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ArtifactError {
    #[error("workload artifact is malformed")]
    Malformed,
    #[error("customer signature is invalid")]
    InvalidCustomerSignature,
    #[error("customer authority is not trusted by policy")]
    UntrustedCustomerAuthority,
    #[error("policy artifact signature is invalid")]
    InvalidPolicySignature,
    #[error("policy signing key is not trusted by policy")]
    UntrustedPolicySigner,
    #[error("artifact relationship is inconsistent")]
    RelationshipMismatch,
}

#[derive(Debug)]
pub struct VerifiedArtifacts {
    pub descriptor: DeploymentDescriptor,
}

#[derive(Deserialize)]
struct WorkloadArtifacts {
    descriptor_payload: DeploymentDescriptor,
    descriptor_signature: String,
    org_keyring_payload: OrgKeyring,
    org_keyring_signature: String,
    signed_policy_artifact: SignedPolicyArtifact,
}

#[derive(Deserialize, Serialize)]
struct OrgKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<KeyringMember>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, Serialize)]
struct KeyringMember {
    user_id: Uuid,
    pubkey: String,
    role: String,
    added_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, Serialize)]
struct SignedPolicyArtifact {
    metadata: PolicyMetadata,
    rego_text: String,
    rego_sha256: String,
    agent_policy_text: String,
    agent_policy_sha256: String,
    signature: String,
    verify_pubkey_b64: String,
    org_keyring: serde_json::Value,
}

#[derive(Deserialize, Serialize)]
struct PolicyMetadata {
    app_id: String,
    deploy_id: String,
    descriptor_core_hash: String,
    descriptor_signing_pubkey: String,
    platform_release_version: String,
    policy_template_id: String,
    policy_template_sha256: String,
    agent_policy_sha256: String,
    genpolicy_version_pin: String,
    signed_at: String,
    key_id: String,
}

pub fn verify_workload_artifacts(
    workload_json: &[u8],
    trustee_policy_json: &[u8],
    cc_init_data_toml: &[u8],
    trusted_keyring_sha256: &[String],
    trusted_policy_signing_pubkeys: &[String],
) -> Result<VerifiedArtifacts, ArtifactError> {
    let artifacts: WorkloadArtifacts =
        serde_json::from_slice(workload_json).map_err(|_| ArtifactError::Malformed)?;
    let trustee_value: serde_json::Value =
        serde_json::from_slice(trustee_policy_json).map_err(|_| ArtifactError::Malformed)?;
    verify_compact_trustee_policy(&trustee_value, &artifacts.signed_policy_artifact)?;

    let keyring_bytes = canonical_keyring_bytes(&artifacts.org_keyring_payload)?;
    let keyring_sha256 = hex::encode(Sha256::digest(&keyring_bytes));
    if !trusted_keyring_sha256
        .iter()
        .any(|trusted| trusted == &keyring_sha256)
    {
        return Err(ArtifactError::UntrustedCustomerAuthority);
    }
    let attached: OrgKeyringEnvelope =
        serde_json::from_value(artifacts.signed_policy_artifact.org_keyring.clone())
            .map_err(|_| ArtifactError::Malformed)?;
    if attached.keyring
        != serde_json::to_value(&artifacts.org_keyring_payload)
            .map_err(|_| ArtifactError::Malformed)?
        || attached.signature != artifacts.org_keyring_signature
    {
        return Err(ArtifactError::RelationshipMismatch);
    }
    let keyring_signer = decode_32(&attached.signing_pubkey)?;
    if !artifacts.org_keyring_payload.members.iter().any(|member| {
        member.role == "owner" && decode_32(&member.pubkey).ok() == Some(keyring_signer)
    }) {
        return Err(ArtifactError::UntrustedCustomerAuthority);
    }
    verify_ed25519(
        &keyring_signer,
        &keyring_bytes,
        &decode_64(&artifacts.org_keyring_signature)?,
    )
    .map_err(|_| ArtifactError::InvalidCustomerSignature)?;

    let descriptor_signer = decode_32(
        &artifacts
            .signed_policy_artifact
            .metadata
            .descriptor_signing_pubkey,
    )?;
    if !artifacts.org_keyring_payload.members.iter().any(|member| {
        matches!(member.role.as_str(), "owner" | "admin" | "deployer")
            && decode_32(&member.pubkey).ok() == Some(descriptor_signer)
    }) {
        return Err(ArtifactError::UntrustedCustomerAuthority);
    }
    verify_ed25519(
        &descriptor_signer,
        &descriptor_canonical_bytes(&artifacts.descriptor_payload),
        &decode_64(&artifacts.descriptor_signature)?,
    )
    .map_err(|_| ArtifactError::InvalidCustomerSignature)?;

    verify_policy_artifact(
        &artifacts.signed_policy_artifact,
        trusted_policy_signing_pubkeys,
    )?;
    verify_relationships(&artifacts, cc_init_data_toml)?;
    Ok(VerifiedArtifacts {
        descriptor: artifacts.descriptor_payload,
    })
}

fn verify_compact_trustee_policy(
    trustee_value: &serde_json::Value,
    artifact: &SignedPolicyArtifact,
) -> Result<(), ArtifactError> {
    let mut expected = serde_json::to_value(artifact).map_err(|_| ArtifactError::Malformed)?;
    expected
        .as_object_mut()
        .ok_or(ArtifactError::Malformed)?
        .remove("agent_policy_text");
    if trustee_value != &expected {
        return Err(ArtifactError::RelationshipMismatch);
    }
    Ok(())
}

#[derive(Deserialize)]
struct OrgKeyringEnvelope {
    keyring: serde_json::Value,
    signature: String,
    signing_pubkey: String,
}

fn verify_policy_artifact(
    artifact: &SignedPolicyArtifact,
    trusted_pubkeys: &[String],
) -> Result<(), ArtifactError> {
    let pubkey = base64::engine::general_purpose::STANDARD
        .decode(&artifact.verify_pubkey_b64)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArtifactError::Malformed)?;
    if !trusted_pubkeys
        .iter()
        .any(|trusted| decode_32(trusted).ok() == Some(pubkey))
    {
        return Err(ArtifactError::UntrustedPolicySigner);
    }
    let rego_hash: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
    if artifact.rego_sha256 != hex::encode(rego_hash) {
        return Err(ArtifactError::RelationshipMismatch);
    }
    let metadata_hash = canonical_policy_metadata_hash(&artifact.metadata)?;
    let input = ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", &metadata_hash),
        ("rego_sha256", &rego_hash),
    ]);
    verify_ed25519(&pubkey, &input, &decode_64(&artifact.signature)?)
        .map_err(|_| ArtifactError::InvalidPolicySignature)
}

fn verify_relationships(
    artifacts: &WorkloadArtifacts,
    cc_init_data_toml: &[u8],
) -> Result<(), ArtifactError> {
    let descriptor = &artifacts.descriptor_payload;
    let metadata = &artifacts.signed_policy_artifact.metadata;
    let core_hash = descriptor_core_hash(descriptor);
    let agent_hash: [u8; 32] = Sha256::digest(
        artifacts
            .signed_policy_artifact
            .agent_policy_text
            .as_bytes(),
    )
    .into();
    let rego_hash: [u8; 32] =
        Sha256::digest(artifacts.signed_policy_artifact.rego_text.as_bytes()).into();
    let cc_hash: [u8; 32] = Sha256::digest(cc_init_data_toml).into();
    if metadata.app_id != descriptor.app_id.to_string()
        || metadata.deploy_id != descriptor.deploy_id.to_string()
        || metadata.descriptor_core_hash != hex::encode(core_hash)
        || metadata.platform_release_version != descriptor.platform_release_version
        || metadata.policy_template_id != descriptor.policy_template_id
        || metadata.policy_template_sha256 != hex::encode(descriptor.policy_template_sha256)
        || metadata.agent_policy_sha256 != hex::encode(agent_hash)
        || artifacts.signed_policy_artifact.agent_policy_sha256 != hex::encode(agent_hash)
        || descriptor.expected_agent_policy_hash != agent_hash
        || descriptor.expected_kbs_policy_hash != rego_hash
        || descriptor.expected_cc_init_data_hash != cc_hash
    {
        return Err(ArtifactError::RelationshipMismatch);
    }
    Ok(())
}

fn canonical_policy_metadata_hash(metadata: &PolicyMetadata) -> Result<[u8; 32], ArtifactError> {
    let app_id = Uuid::parse_str(&metadata.app_id).map_err(|_| ArtifactError::Malformed)?;
    let deploy_id = Uuid::parse_str(&metadata.deploy_id).map_err(|_| ArtifactError::Malformed)?;
    let descriptor_core_hash = decode_32(&metadata.descriptor_core_hash)?;
    let descriptor_signing_pubkey = decode_32(&metadata.descriptor_signing_pubkey)?;
    let policy_template_sha256 = decode_32(&metadata.policy_template_sha256)?;
    let agent_policy_sha256 = decode_32(&metadata.agent_policy_sha256)?;
    Ok(ce_v1_hash(&[
        ("app_id", app_id.as_bytes()),
        ("deploy_id", deploy_id.as_bytes()),
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

fn canonical_keyring_bytes(keyring: &OrgKeyring) -> Result<Vec<u8>, ArtifactError> {
    let mut members = keyring.members.iter().collect::<Vec<_>>();
    members.sort_by_key(|member| member.user_id);
    let values = members
        .iter()
        .map(|member| {
            let pubkey = decode_32(&member.pubkey)?;
            let added_at = member.added_at.to_rfc3339();
            Ok((
                member.user_id.to_string(),
                ce_v1_hash(&[
                    ("user_id", member.user_id.as_bytes()),
                    ("pubkey", &pubkey),
                    ("role", member.role.as_bytes()),
                    ("added_at", added_at.as_bytes()),
                ]),
            ))
        })
        .collect::<Result<Vec<_>, ArtifactError>>()?;
    let refs = values
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect::<Vec<_>>();
    let members_hash = ce_v1_hash(&refs);
    let version = keyring.version.to_be_bytes();
    let updated_at = keyring.updated_at.to_rfc3339();
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated_at.as_bytes()),
    ]))
}

fn verify_ed25519(key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<(), ()> {
    VerifyingKey::from_bytes(key)
        .map_err(|_| ())?
        .verify(message, &Signature::from_bytes(signature))
        .map_err(|_| ())
}

fn decode_32(value: &str) -> Result<[u8; 32], ArtifactError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArtifactError::Malformed)
}

fn decode_64(value: &str) -> Result<[u8; 64], ArtifactError> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ArtifactError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact() -> SignedPolicyArtifact {
        SignedPolicyArtifact {
            metadata: PolicyMetadata {
                app_id: "app".into(),
                deploy_id: "deploy".into(),
                descriptor_core_hash: "00".repeat(32),
                descriptor_signing_pubkey: "11".repeat(32),
                platform_release_version: "release".into(),
                policy_template_id: "template".into(),
                policy_template_sha256: "22".repeat(32),
                agent_policy_sha256: "33".repeat(32),
                genpolicy_version_pin: "genpolicy@1".into(),
                signed_at: "2026-08-03T00:00:00Z".into(),
                key_id: "key".into(),
            },
            rego_text: "package policy".into(),
            rego_sha256: "44".repeat(32),
            agent_policy_text: "large generated policy".into(),
            agent_policy_sha256: "33".repeat(32),
            signature: "55".repeat(64),
            verify_pubkey_b64: "pubkey".into(),
            org_keyring: serde_json::json!({}),
        }
    }

    #[test]
    fn compact_trustee_policy_must_match_every_retained_field() {
        let artifact = artifact();
        let mut compact = serde_json::to_value(&artifact).unwrap();
        compact.as_object_mut().unwrap().remove("agent_policy_text");
        verify_compact_trustee_policy(&compact, &artifact).unwrap();

        compact["agent_policy_sha256"] = serde_json::Value::String("66".repeat(32));
        assert_eq!(
            verify_compact_trustee_policy(&compact, &artifact),
            Err(ArtifactError::RelationshipMismatch)
        );
    }
}
