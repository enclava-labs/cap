//! Customer-signed deployment descriptor (Phase 7 — D10 / D11 rev14).
//!
//! Descriptor types and CE-v1 canonicalisation live in `enclava-common` so the
//! CLI signer, signing service, and in-TEE verifier share one byte layout.

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
pub use enclava_common::descriptor::{
    Capabilities, DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources,
    SecurityContext, Sidecars, SignerIdentity, canonical_oci_spec_bytes,
    canonical_sidecar_map_bytes, canonical_signer_bytes, descriptor_canonical_bytes,
    descriptor_core_canonical_bytes, descriptor_core_hash,
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::keys::UserSigningKey;

#[derive(Debug, Clone)]
pub struct DeploymentDescriptorBuildInput {
    pub org_id: uuid::Uuid,
    pub org_slug: String,
    pub app_id: uuid::Uuid,
    pub app_name: String,
    pub deploy_id: uuid::Uuid,
    pub created_at: DateTime<Utc>,
    pub app_domain: String,
    pub tee_domain: String,
    pub custom_domains: Vec<String>,
    pub namespace: String,
    pub service_account: String,
    pub identity_hash: [u8; 32],
    pub image_ref: String,
    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub oci_runtime_spec: OciRuntimeSpec,
    pub sidecars: Sidecars,
    pub expected_firmware_measurement: [u8; 32],
    pub expected_runtime_class: String,
    pub kbs_resource_path: String,
    pub policy_template_id: String,
    pub policy_template_sha256: [u8; 32],
    pub platform_release_version: String,
    pub expected_agent_policy_hash: [u8; 32],
    pub expected_cc_init_data_hash: [u8; 32],
    pub expected_kbs_policy_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CapAppOciRuntimeSpecInput {
    pub container_name: String,
    pub port: u16,
    pub workload_command: Vec<String>,
    pub storage_paths: Vec<String>,
    pub cpu_limit: String,
    pub memory_limit: String,
}

pub const CAP_WAIT_EXEC_PATH: &str = "/usr/local/bin/enclava-wait-exec";
pub const CAP_APP_UID: u32 = 10001;
pub const CAP_APP_GID: u32 = 10001;
pub const CAP_APP_CPU_REQUEST: &str = "250m";
pub const CAP_APP_MEMORY_REQUEST: &str = "512Mi";

fn storage_subdir(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
}

fn named_value(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: value.to_string(),
    }
}

/// Build the customer descriptor OCI subset for CAP's current non-legacy app
/// container shape.
///
/// The API remains the source of truth for the final manifest. This helper
/// mirrors only deterministic fields available to the CLI today: wait-exec
/// wrapping, app container env, port, app UID/GID/security flags, fixed
/// resource requests, caller-supplied limits, and storage path destinations.
/// Exact parity for API-only fields such as persisted primary container
/// command/name/resource overrides needs API-side descriptor generation.
pub fn cap_app_oci_runtime_spec(input: CapAppOciRuntimeSpecInput) -> OciRuntimeSpec {
    let mut mounts = vec![Mount {
        source: "state-mount".to_string(),
        destination: "/state".to_string(),
        mount_type: "kubernetes-volume".to_string(),
        options: vec!["rw".to_string()],
    }];
    mounts.extend(input.storage_paths.iter().map(|path| Mount {
        source: format!("state-mount:{}", storage_subdir(path)),
        destination: path.clone(),
        mount_type: "kubernetes-volume-subpath".to_string(),
        options: vec!["rw".to_string()],
    }));

    OciRuntimeSpec {
        command: vec![CAP_WAIT_EXEC_PATH.to_string()],
        args: input.workload_command,
        env: vec![
            named_value("APP_SEED_PATH", "/state/app/seed"),
            named_value("VOLUME_MOUNT_POINT", "/state"),
            named_value("ENCLAVA_CONTAINER_NAME", &input.container_name),
            named_value("ENCLAVA_STARTED_DIR", "/run/enclava/containers"),
            named_value("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        ],
        ports: vec![Port {
            container_port: input.port.into(),
            protocol: "TCP".to_string(),
        }],
        mounts,
        capabilities: Capabilities {
            add: Vec::new(),
            drop: vec!["ALL".to_string()],
        },
        security_context: SecurityContext {
            run_as_user: CAP_APP_UID,
            run_as_group: CAP_APP_GID,
            read_only_root_fs: true,
            allow_privilege_escalation: false,
            privileged: false,
        },
        resources: Resources {
            requests: vec![
                named_value("cpu", CAP_APP_CPU_REQUEST),
                named_value("memory", CAP_APP_MEMORY_REQUEST),
            ],
            limits: vec![
                named_value("cpu", &input.cpu_limit),
                named_value("memory", &input.memory_limit),
            ],
        },
    }
}

#[derive(Debug, Error)]
pub enum DescriptorError {
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("home directory not available")]
    NoHome,
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDescriptorEnvelope {
    pub descriptor: DeploymentDescriptor,
    #[serde(with = "hex_sig")]
    pub signature: Signature,
    pub signing_key_id: String,
    #[serde(with = "hex_pubkey")]
    pub signing_pubkey: VerifyingKey,
}

mod hex_sig {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 64"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

mod hex_pubkey {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(k: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(k.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 32"))?;
        VerifyingKey::from_bytes(&arr).map_err(D::Error::custom)
    }
}

pub fn sign(
    deployer: &UserSigningKey,
    descriptor: DeploymentDescriptor,
    signing_key_id: String,
) -> DeploymentDescriptorEnvelope {
    let bytes = descriptor_canonical_bytes(&descriptor);
    let signature = deployer.sign(&bytes);
    DeploymentDescriptorEnvelope {
        descriptor,
        signature,
        signing_key_id,
        signing_pubkey: deployer.public,
    }
}

pub fn build_descriptor(input: DeploymentDescriptorBuildInput) -> DeploymentDescriptor {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    DeploymentDescriptor {
        schema_version: "v1".to_string(),
        org_id: input.org_id,
        org_slug: input.org_slug,
        app_id: input.app_id,
        app_name: input.app_name,
        deploy_id: input.deploy_id,
        created_at: input.created_at,
        nonce,
        app_domain: input.app_domain,
        tee_domain: input.tee_domain,
        custom_domains: input.custom_domains,
        namespace: input.namespace,
        service_account: input.service_account,
        identity_hash: input.identity_hash,
        image_ref: input.image_ref,
        image_digest: input.image_digest,
        signer_identity: input.signer_identity,
        oci_runtime_spec: input.oci_runtime_spec,
        sidecars: input.sidecars,
        expected_firmware_measurement: input.expected_firmware_measurement,
        expected_runtime_class: input.expected_runtime_class,
        kbs_resource_path: input.kbs_resource_path,
        policy_template_id: input.policy_template_id,
        policy_template_sha256: input.policy_template_sha256,
        platform_release_version: input.platform_release_version,
        expected_agent_policy_hash: input.expected_agent_policy_hash,
        expected_cc_init_data_hash: input.expected_cc_init_data_hash,
        expected_kbs_policy_hash: input.expected_kbs_policy_hash,
    }
}

pub fn verify<'e>(
    envelope: &'e DeploymentDescriptorEnvelope,
    expected_pubkey: &VerifyingKey,
) -> Result<&'e DeploymentDescriptor, DescriptorError> {
    if envelope.signing_pubkey.to_bytes() != expected_pubkey.to_bytes() {
        return Err(DescriptorError::Verify(
            "signing pubkey mismatch".to_string(),
        ));
    }
    let bytes = descriptor_canonical_bytes(&envelope.descriptor);
    expected_pubkey
        .verify(&bytes, &envelope.signature)
        .map_err(|e| DescriptorError::Verify(e.to_string()))?;
    Ok(&envelope.descriptor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

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
            image_ref: "ghcr.io/enclava-ai/demo@sha256:aaaa".to_string(),
            image_digest: "sha256:aaaa".to_string(),
            signer_identity: SignerIdentity {
                subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/app".to_string()],
                args: vec!["--serve".to_string()],
                env: vec![
                    EnvVar {
                        name: "B".to_string(),
                        value: "2".to_string(),
                    },
                    EnvVar {
                        name: "A".to_string(),
                        value: "1".to_string(),
                    },
                ],
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
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "platform-2026.04".to_string(),
            expected_agent_policy_hash: [7; 32],
            expected_cc_init_data_hash: [5; 32],
            expected_kbs_policy_hash: [6; 32],
        }
    }

    #[test]
    fn signing_round_trips() {
        let key = UserSigningKey::generate(Uuid::new_v4());
        let env = sign(&key, fixed_descriptor(), "key-1".to_string());
        verify(&env, &key.public).unwrap();
    }

    #[test]
    fn descriptor_core_excludes_chain_anchors() {
        let mut d = fixed_descriptor();
        let h1 = descriptor_core_hash(&d);
        d.expected_agent_policy_hash = [0xEE; 32];
        d.expected_cc_init_data_hash = [0xFF; 32];
        d.expected_kbs_policy_hash = [0xFE; 32];
        let h2 = descriptor_core_hash(&d);
        assert_eq!(h1, h2, "core hash must NOT include expected_*_hash fields");
    }

    #[test]
    fn canonical_bytes_include_image_ref() {
        let mut d_a = fixed_descriptor();
        let mut d_b = d_a.clone();
        d_b.image_ref = "ghcr.io/enclava-ai/other@sha256:aaaa".to_string();

        assert_ne!(
            descriptor_core_canonical_bytes(&d_a),
            descriptor_core_canonical_bytes(&d_b),
            "core bytes must bind the full digest-pinned image reference"
        );
        assert_ne!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b),
            "signed bytes must bind the full digest-pinned image reference"
        );

        d_a.image_ref = d_b.image_ref.clone();
        assert_eq!(
            descriptor_core_canonical_bytes(&d_a),
            descriptor_core_canonical_bytes(&d_b)
        );
        assert_eq!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
    }

    #[test]
    fn full_signature_changes_when_chain_anchor_changes() {
        let mut d_a = fixed_descriptor();
        let mut d_b = d_a.clone();
        d_b.expected_agent_policy_hash = [0xEE; 32];
        assert_ne!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
        d_a.expected_agent_policy_hash = [0xEE; 32];
        assert_eq!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
        d_b.expected_cc_init_data_hash = [0xFF; 32];
        assert_ne!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
        d_a.expected_cc_init_data_hash = [0xFF; 32];
        assert_eq!(
            descriptor_canonical_bytes(&d_a),
            descriptor_canonical_bytes(&d_b)
        );
    }

    #[test]
    fn env_canonicalization_is_name_sorted() {
        let oci_a = OciRuntimeSpec {
            command: vec![],
            args: vec![],
            env: vec![
                EnvVar {
                    name: "B".into(),
                    value: "2".into(),
                },
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
            ],
            ports: vec![],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        };
        let oci_b = OciRuntimeSpec {
            command: vec![],
            args: vec![],
            env: vec![
                EnvVar {
                    name: "A".into(),
                    value: "1".into(),
                },
                EnvVar {
                    name: "B".into(),
                    value: "2".into(),
                },
            ],
            ports: vec![],
            mounts: vec![],
            capabilities: Capabilities::default(),
            security_context: SecurityContext::default(),
            resources: Resources::default(),
        };
        assert_eq!(
            canonical_oci_spec_bytes(&oci_a),
            canonical_oci_spec_bytes(&oci_b),
            "env must canonicalize regardless of input order"
        );
    }

    #[test]
    fn json_round_trip_preserves_canonical_hash() {
        let d = fixed_descriptor();
        let h1 = descriptor_core_hash(&d);
        let json = serde_json::to_string(&d).unwrap();
        let d2: DeploymentDescriptor = serde_json::from_str(&json).unwrap();
        let h2 = descriptor_core_hash(&d2);
        assert_eq!(h1, h2);
    }
}
