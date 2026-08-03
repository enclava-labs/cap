//! Customer-signed deployment descriptor canonicalization.
//!
//! This module is shared by the CLI signer and the in-TEE verifier. Keeping the
//! CE-v1 record list in one crate prevents the descriptor core hash used in
//! cc_init_data from drifting away from the bytes customers signed.

use crate::canonical::{ce_v1_bytes, ce_v1_hash};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub container_port: u32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub source: String,
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityContext {
    pub run_as_user: u32,
    pub run_as_group: u32,
    pub read_only_root_fs: bool,
    pub allow_privilege_escalation: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    #[serde(default)]
    pub requests: Vec<EnvVar>,
    #[serde(default)]
    pub limits: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRuntimeSpec {
    pub command: Vec<String>,
    pub args: Vec<String>,
    /// Sorted by name; canonical ordering is enforced by canonicalization.
    pub env: Vec<EnvVar>,
    pub ports: Vec<Port>,
    pub mounts: Vec<Mount>,
    pub capabilities: Capabilities,
    pub security_context: SecurityContext,
    pub resources: Resources,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecars {
    pub attestation_proxy_digest: String,
    pub caddy_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirmwareMeasurement {
    Legacy([u8; 32]),
    Full([u8; 48]),
}

impl FirmwareMeasurement {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Legacy(bytes) => bytes,
            Self::Full(bytes) => bytes,
        }
    }

    pub fn matches_report(&self, report: &[u8; 48]) -> bool {
        match self {
            Self::Legacy(expected) => report[..32] == *expected,
            Self::Full(expected) => report == expected,
        }
    }
}

impl From<[u8; 32]> for FirmwareMeasurement {
    fn from(value: [u8; 32]) -> Self {
        Self::Legacy(value)
    }
}

impl From<[u8; 48]> for FirmwareMeasurement {
    fn from(value: [u8; 48]) -> Self {
        Self::Full(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDescriptor {
    pub schema_version: String,
    pub org_id: Uuid,
    pub org_slug: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub deploy_id: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(with = "hex_bytes32")]
    pub nonce: [u8; 32],

    pub app_domain: String,
    pub tee_domain: String,
    #[serde(default)]
    pub custom_domains: Vec<String>,

    pub namespace: String,
    pub service_account: String,
    #[serde(with = "hex_bytes32")]
    pub identity_hash: [u8; 32],

    pub image_ref: String,
    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub oci_runtime_spec: OciRuntimeSpec,
    pub sidecars: Sidecars,
    #[serde(default)]
    pub api_signing_pubkey: String,
    #[serde(default)]
    pub independent_verification: bool,

    /// Legacy descriptors contain a 32-byte prefix; v2 contains the complete
    /// 48-byte SNP launch measurement.
    #[serde(with = "hex_measurement")]
    pub expected_firmware_measurement: FirmwareMeasurement,
    pub expected_runtime_class: String,
    pub kbs_resource_path: String,
    pub unlock_mode: String,

    pub policy_template_id: String,
    #[serde(with = "hex_bytes32")]
    pub policy_template_sha256: [u8; 32],
    pub platform_release_version: String,

    /// Forward-chain anchors. Excluded from descriptor_core_canonical_bytes.
    #[serde(with = "hex_bytes32")]
    #[serde(default)]
    pub expected_agent_policy_hash: [u8; 32],
    #[serde(with = "hex_bytes32")]
    pub expected_cc_init_data_hash: [u8; 32],
    #[serde(with = "hex_bytes32")]
    pub expected_kbs_policy_hash: [u8; 32],
}

mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 32"))
    }
}

mod hex_measurement {
    use super::FirmwareMeasurement;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &FirmwareMeasurement, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b.as_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<FirmwareMeasurement, D::Error> {
        use serde::de::Error;
        let bytes = hex::decode(String::deserialize(d)?).map_err(D::Error::custom)?;
        match bytes.len() {
            32 => Ok(FirmwareMeasurement::Legacy(bytes.try_into().unwrap())),
            48 => Ok(FirmwareMeasurement::Full(bytes.try_into().unwrap())),
            len => Err(D::Error::custom(format!("len {len} != 32 or 48"))),
        }
    }
}

pub fn canonical_signer_bytes(s: &SignerIdentity) -> [u8; 32] {
    ce_v1_hash(&[
        ("subject", s.subject.as_bytes()),
        ("issuer", s.issuer.as_bytes()),
    ])
}

pub fn canonical_sidecar_map_bytes(s: &Sidecars) -> [u8; 32] {
    ce_v1_hash(&[
        ("attestation_proxy", s.attestation_proxy_digest.as_bytes()),
        ("caddy", s.caddy_digest.as_bytes()),
    ])
}

fn canonical_string_list_bytes(items: &[String]) -> [u8; 32] {
    let records: Vec<(String, Vec<u8>)> = items
        .iter()
        .enumerate()
        .map(|(i, v)| (format!("i{i}"), v.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_env_bytes(env: &[EnvVar]) -> [u8; 32] {
    let mut sorted: Vec<&EnvVar> = env.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let records: Vec<(String, Vec<u8>)> = sorted
        .iter()
        .map(|e| (e.name.clone(), e.value.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_ports_bytes(ports: &[Port]) -> [u8; 32] {
    let parts: Vec<(String, Vec<u8>)> = ports
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut v = Vec::with_capacity(4 + p.protocol.len());
            v.extend_from_slice(&p.container_port.to_be_bytes());
            v.extend_from_slice(p.protocol.as_bytes());
            (format!("p{i}"), v)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_mounts_bytes(mounts: &[Mount]) -> [u8; 32] {
    let parts: Vec<(String, [u8; 32])> = mounts
        .iter()
        .enumerate()
        .map(|(i, m)| {
            (
                format!("m{i}"),
                ce_v1_hash(&[
                    ("source", m.source.as_bytes()),
                    ("destination", m.destination.as_bytes()),
                    ("type", m.mount_type.as_bytes()),
                    ("options", &canonical_string_list_bytes(&m.options)),
                ]),
            )
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(l, v)| (l.as_str(), v.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_secctx_bytes(s: &SecurityContext) -> [u8; 32] {
    let user = s.run_as_user.to_be_bytes();
    let group = s.run_as_group.to_be_bytes();
    let bits = [
        s.read_only_root_fs as u8,
        s.allow_privilege_escalation as u8,
        s.privileged as u8,
    ];
    ce_v1_hash(&[
        ("run_as_user", &user),
        ("run_as_group", &group),
        ("flags", &bits),
    ])
}

fn canonical_resources_bytes(r: &Resources) -> [u8; 32] {
    ce_v1_hash(&[
        ("requests", &canonical_env_bytes(&r.requests)),
        ("limits", &canonical_env_bytes(&r.limits)),
    ])
}

pub fn canonical_oci_spec_bytes(o: &OciRuntimeSpec) -> [u8; 32] {
    ce_v1_hash(&[
        ("command", &canonical_string_list_bytes(&o.command)),
        ("args", &canonical_string_list_bytes(&o.args)),
        ("env", &canonical_env_bytes(&o.env)),
        ("ports", &canonical_ports_bytes(&o.ports)),
        ("mounts", &canonical_mounts_bytes(&o.mounts)),
        (
            "capabilities_add",
            &canonical_string_list_bytes(&o.capabilities.add),
        ),
        (
            "capabilities_drop",
            &canonical_string_list_bytes(&o.capabilities.drop),
        ),
        (
            "security_context",
            &canonical_secctx_bytes(&o.security_context),
        ),
        ("resources", &canonical_resources_bytes(&o.resources)),
    ])
}

fn descriptor_records<'a>(
    d: &'a DeploymentDescriptor,
    purpose: &'a [u8],
    include_chain_anchors: bool,
    sub: &'a DescriptorSubHashes,
) -> Vec<(&'a str, &'a [u8])> {
    let mut r: Vec<(&str, &[u8])> = vec![
        ("purpose", purpose),
        ("schema_version", d.schema_version.as_bytes()),
        ("org_id", d.org_id.as_bytes().as_slice()),
        ("org_slug", d.org_slug.as_bytes()),
        ("app_id", d.app_id.as_bytes().as_slice()),
        ("app_name", d.app_name.as_bytes()),
        ("deploy_id", d.deploy_id.as_bytes().as_slice()),
        ("created_at", sub.created_at.as_bytes()),
        ("nonce", &d.nonce),
        ("app_domain", d.app_domain.as_bytes()),
        ("tee_domain", d.tee_domain.as_bytes()),
        ("custom_domains", &sub.custom_domains_hash),
        ("namespace", d.namespace.as_bytes()),
        ("service_account", d.service_account.as_bytes()),
        ("identity_hash", &d.identity_hash),
        ("image_ref", d.image_ref.as_bytes()),
        ("image_digest", d.image_digest.as_bytes()),
        ("signer_identity", &sub.signer_hash),
        ("oci_runtime_spec", &sub.oci_hash),
        ("sidecars", &sub.sidecar_hash),
        ("api_signing_pubkey", d.api_signing_pubkey.as_bytes()),
        (
            "expected_firmware_measurement",
            d.expected_firmware_measurement.as_bytes(),
        ),
        (
            "expected_runtime_class",
            d.expected_runtime_class.as_bytes(),
        ),
        ("kbs_resource_path", d.kbs_resource_path.as_bytes()),
        ("unlock_mode", d.unlock_mode.as_bytes()),
        ("policy_template_id", d.policy_template_id.as_bytes()),
        ("policy_template_sha256", &d.policy_template_sha256),
        (
            "platform_release_version",
            d.platform_release_version.as_bytes(),
        ),
    ];
    if d.independent_verification {
        r.push(("independent_verification", b"true"));
    }
    if include_chain_anchors {
        r.push(("expected_agent_policy_hash", &d.expected_agent_policy_hash));
        r.push(("expected_cc_init_data_hash", &d.expected_cc_init_data_hash));
        r.push(("expected_kbs_policy_hash", &d.expected_kbs_policy_hash));
    }
    r
}

struct DescriptorSubHashes {
    created_at: String,
    custom_domains_hash: [u8; 32],
    signer_hash: [u8; 32],
    oci_hash: [u8; 32],
    sidecar_hash: [u8; 32],
}

fn sub_hashes(d: &DeploymentDescriptor) -> DescriptorSubHashes {
    DescriptorSubHashes {
        created_at: d.created_at.to_rfc3339(),
        custom_domains_hash: canonical_string_list_bytes(&d.custom_domains),
        signer_hash: canonical_signer_bytes(&d.signer_identity),
        oci_hash: canonical_oci_spec_bytes(&d.oci_runtime_spec),
        sidecar_hash: canonical_sidecar_map_bytes(&d.sidecars),
    }
}

/// CE-v1 raw bytes over the full descriptor. This is what the deployer's
/// Ed25519 key signs.
pub fn descriptor_canonical_bytes(d: &DeploymentDescriptor) -> Vec<u8> {
    let sub = sub_hashes(d);
    let records = descriptor_records(d, b"enclava-deployment-descriptor-v1", true, &sub);
    ce_v1_bytes(&records)
}

/// CE-v1 raw bytes over the cycle-free descriptor subset.
pub fn descriptor_core_canonical_bytes(d: &DeploymentDescriptor) -> Vec<u8> {
    let sub = sub_hashes(d);
    let records = descriptor_records(d, b"enclava-deployment-descriptor-core-v1", false, &sub);
    ce_v1_bytes(&records)
}

pub fn descriptor_core_hash(d: &DeploymentDescriptor) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(descriptor_core_canonical_bytes(d)).into()
}
