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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{
        Capabilities, EnvVar, OciRuntimeSpec, Port, Resources, SecurityContext, Sidecars,
        SignerIdentity,
    };
    use chrono::TimeZone;
    use ed25519_dalek::Signature;

    fn fixed_metadata() -> PolicyMetadata {
        PolicyMetadata {
            app_id: "22222222-2222-2222-2222-222222222222".to_string(),
            deploy_id: "33333333-3333-3333-3333-333333333333".to_string(),
            descriptor_core_hash: hex::encode([0x11; 32]),
            descriptor_signing_pubkey: hex::encode([0x22; 32]),
            platform_release_version: "platform-2026.04".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: hex::encode([0x33; 32]),
            agent_policy_sha256: hex::encode([0x44; 32]),
            genpolicy_version_pin: "genpolicy-0.15".to_string(),
            signed_at: "2026-07-14T09:30:00+00:00".to_string(),
            key_id: "key-1".to_string(),
        }
    }

    fn fixed_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap(),
            nonce: [7; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec!["app.example.com".to_string()],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [9; 32],
            image_ref:
                "ghcr.io/enclava-labs/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/app".to_string()],
                args: vec!["--serve".to_string()],
                env: vec![EnvVar {
                    name: "A".to_string(),
                    value: "1".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: "sha256:1111".to_string(),
                caddy_digest: "sha256:2222".to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "platform-2026.04".to_string(),
            expected_agent_policy_hash: [7; 32],
            expected_cc_init_data_hash: [0; 32],
            expected_kbs_policy_hash: [6; 32],
        }
    }

    /// Pins the CE-v1 canonicalization of `PolicyMetadata` on the CLI side. Any
    /// change to the canonical field set or ordering breaks this test. NOTE:
    /// `PolicyMetadata` + this hash fn are triplicated (CLI / enclava-api
    /// `signing_service.rs` / enclava-init `trustee_verify.rs`), all private, so
    /// this pins the CLI copy against local drift, not cross-component drift. The
    /// stronger guard is a shared golden vector across all three (or de-dup into
    /// `enclava-common`); left as a follow-up.
    #[test]
    fn canonical_metadata_hash_pinned_vector() {
        let h = canonical_policy_metadata_hash(&fixed_metadata());
        assert_eq!(
            hex::encode(h),
            "dec7a5ce944de48bb447eacf65bfb8a610b5712665528aa766cfdf3d67a3ffb7"
        );
    }

    /// Pins the policy-artifact signing input (the bytes the descriptor key
    /// signs): `ce_v1_bytes([("purpose", b"enclava-policy-artifact-v1"),
    /// ("metadata", &hash), ("rego_sha256", &rego_hash)])`. Same CLI-only-drift
    /// caveat as the hash pin.
    #[test]
    fn policy_artifact_signing_input_pinned_vector() {
        let rego_hash = [0xaa; 32];
        let input = policy_artifact_signing_input(&fixed_metadata(), &rego_hash);
        assert_eq!(
            hex::encode(&input),
            "0007707572706f73650000001a656e636c6176612d706f6c6963792d61727469666163742d763100086d6574616461746100000020dec7a5ce944de48bb447eacf65bfb8a610b5712665528aa766cfdf3d67a3ffb7000b7265676f5f73686132353600000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
    }

    #[test]
    fn sign_policy_artifact_round_trips() {
        let descriptor = fixed_descriptor();
        let key = UserSigningKey::from_seed(
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            [0x55; 32],
        );
        let rego_text = "package enclava\ndefault allow := false".to_string();
        let policy_text = "allow := true".to_string();
        let policy_sha256: [u8; 32] = Sha256::digest(policy_text.as_bytes()).into();
        let generated = GeneratedAgentPolicy {
            policy_text: policy_text.clone(),
            policy_sha256,
            genpolicy_version_pin: "genpolicy-0.15".to_string(),
        };

        let artifact = sign_policy_artifact(
            &descriptor,
            &key,
            "key-1".to_string(),
            rego_text.clone(),
            &generated,
            None,
            Utc.with_ymd_and_hms(2026, 7, 14, 9, 30, 0).unwrap(),
        );

        // sha256 fields match their source texts (recomputed independently)
        assert_eq!(
            artifact.rego_sha256,
            hex::encode(Sha256::digest(rego_text.as_bytes()))
        );
        assert_eq!(
            artifact.agent_policy_sha256,
            hex::encode(Sha256::digest(policy_text.as_bytes()))
        );

        // embedded pubkey matches the signing key
        assert_eq!(
            artifact.metadata.descriptor_signing_pubkey,
            hex::encode(key.public.to_bytes())
        );
        assert_eq!(
            artifact.verify_pubkey_b64,
            B64.encode(key.public.to_bytes())
        );

        // signature independently verifies against the signing key over the
        // canonical signing input (not a re-sign-and-compare)
        let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
        let signing_input = policy_artifact_signing_input(&artifact.metadata, &rego_hash);
        let sig = Signature::from_slice(&hex::decode(&artifact.signature).unwrap()).unwrap();
        UserSigningKey::verify(&key.public, &signing_input, &sig).unwrap();

        // metadata mirrors the descriptor + generated policy
        assert_eq!(artifact.metadata.app_id, descriptor.app_id.to_string());
        assert_eq!(
            artifact.metadata.deploy_id,
            descriptor.deploy_id.to_string()
        );
        assert_eq!(
            artifact.metadata.descriptor_core_hash,
            hex::encode(descriptor_core_hash(&descriptor))
        );
        assert_eq!(
            artifact.metadata.agent_policy_sha256,
            hex::encode(policy_sha256)
        );
        assert_eq!(artifact.metadata.key_id, "key-1");
    }
}
