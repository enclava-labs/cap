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
#[serde(deny_unknown_fields)]
pub struct SignerIdentity {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Port {
    pub container_port: u32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mount {
    pub source: String,
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityContext {
    pub run_as_user: u32,
    pub run_as_group: u32,
    pub read_only_root_fs: bool,
    pub allow_privilege_escalation: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    #[serde(default)]
    pub requests: Vec<EnvVar>,
    #[serde(default)]
    pub limits: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    /// Contract v1 (policy-templates#23): the pod-level supplemental
    /// groups the deployment DECLARES (canonical form: sorted unique).
    /// Under Nydus guest-pull, containerd 2.3.6 CRI only passes DECLARED
    /// groups into the OCI spec, and genpolicy 4.3.1 refuses to generate
    /// a policy whose AdditionalGids differ — so the descriptor, the
    /// agent policy and the running pod must agree on this list. Absent
    /// = legacy: the engine keeps the platform baseline [0, 6] and the
    /// field does not participate in descriptor_core_canonical_bytes, so
    /// legacy descriptors and pre-signed template artifacts keep their
    /// hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_supplemental_groups: Option<Vec<i64>>,

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

    /// Legacy descriptors retain their signed 32-byte prefix for migration
    /// compatibility; v2 descriptors contain all 48 bytes. Independent trust
    /// policy always evaluates the separate full-width `amd.measurement` check.
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

/// What a TEE launched for one deployment attests to: SNP HOST_DATA (the
/// cc_init_data hash) and the firmware measurement, as signed in its
/// descriptor. Serialized with the descriptor's own field names and encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchIdentity {
    #[serde(with = "hex_bytes32")]
    pub expected_cc_init_data_hash: [u8; 32],
    #[serde(with = "hex_measurement")]
    pub expected_firmware_measurement: FirmwareMeasurement,
}

impl LaunchIdentity {
    pub fn matches_report(&self, host_data: &[u8; 32], measurement: &[u8; 48]) -> bool {
        *host_data == self.expected_cc_init_data_hash
            && self
                .expected_firmware_measurement
                .matches_report(measurement)
    }
}

impl DeploymentDescriptor {
    pub fn launch_identity(&self) -> LaunchIdentity {
        LaunchIdentity {
            expected_cc_init_data_hash: self.expected_cc_init_data_hash,
            expected_firmware_measurement: self.expected_firmware_measurement.clone(),
        }
    }
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

/// Canonical decimal form of the declared pod supplemental groups:
/// sorted, deduplicated, comma-separated. Used both for the
/// descriptor_core_canonical_bytes record and for error text.
pub fn canonical_pod_groups_string(groups: &[i64]) -> String {
    let mut sorted: Vec<i64> = groups.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
        .iter()
        .map(|g| g.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// Admission validation for the declared pod supplemental groups
/// (contract v1, policy-templates#23). Some(list) must carry 1..=32
/// entries in 0..=2147483646 and MUST contain the platform baseline
/// members 0 and 6. None (legacy) is always valid.
pub fn validate_pod_supplemental_groups(groups: Option<&Vec<i64>>) -> Result<(), String> {
    let Some(groups) = groups else {
        return Ok(());
    };
    if groups.is_empty() || groups.len() > 32 {
        return Err("pod_supplemental_groups must carry 1 to 32 entries".to_string());
    }
    if groups.iter().any(|g| !(0..=2147483646).contains(g)) {
        return Err("pod_supplemental_groups entries must be in 0..=2147483646".to_string());
    }
    if !groups.contains(&0) || !groups.contains(&6) {
        return Err(
            "pod_supplemental_groups must contain the platform baseline 0 and 6".to_string(),
        );
    }
    // Reserved gids the platform itself assigns: 10001 is the workload
    // owner (runAsUser/runAsGroup/fsGroup), 10002 the SSH-relay profile,
    // 65535 the nobody-legacy range. A declared pod-level list carrying
    // one of these would grant EVERY container in the pod that identity,
    // so admission rejects them by name.
    if let Some(reserved) = groups.iter().find(|g| matches!(*g, 10001 | 10002 | 65535)) {
        return Err(format!(
            "pod_supplemental_groups must not contain the reserved gid {reserved}              (10001 workload owner, 10002 ssh-relay, 65535 nobody-legacy)"
        ));
    }
    Ok(())
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
    if let Some(bytes) = sub.pod_groups_bytes.as_deref() {
        r.push(("pod_supplemental_groups", bytes.as_bytes()));
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
    /// Canonical decimal render of the declared pod supplemental groups;
    /// present only when the descriptor declares groups (the record
    /// participates in descriptor_core_canonical_bytes only then).
    pod_groups_bytes: Option<String>,
    signer_hash: [u8; 32],
    oci_hash: [u8; 32],
    sidecar_hash: [u8; 32],
}

fn sub_hashes(d: &DeploymentDescriptor) -> DescriptorSubHashes {
    DescriptorSubHashes {
        created_at: d.created_at.to_rfc3339(),
        custom_domains_hash: canonical_string_list_bytes(&d.custom_domains),
        pod_groups_bytes: d
            .pod_supplemental_groups
            .as_ref()
            .map(|groups| canonical_pod_groups_string(groups)),
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

#[cfg(test)]
mod tests {
    use super::{
        DeploymentDescriptor, FirmwareMeasurement, LaunchIdentity, canonical_pod_groups_string,
        descriptor_core_canonical_bytes, descriptor_core_hash, validate_pod_supplemental_groups,
    };

    #[test]
    fn launch_identity_requires_host_data_and_firmware_to_match() {
        let identity = LaunchIdentity {
            expected_cc_init_data_hash: [7; 32],
            expected_firmware_measurement: FirmwareMeasurement::Full([9; 48]),
        };
        assert!(identity.matches_report(&[7; 32], &[9; 48]));
        // Another deployment's init-data, or the same one under other firmware.
        assert!(!identity.matches_report(&[0xaa; 32], &[9; 48]));
        assert!(!identity.matches_report(&[7; 32], &[0xab; 48]));

        // Legacy descriptors pin only the first 32 measurement bytes.
        let legacy = LaunchIdentity {
            expected_firmware_measurement: FirmwareMeasurement::Legacy([9; 32]),
            ..identity
        };
        let mut measurement = [9u8; 48];
        measurement[47] = 0;
        assert!(legacy.matches_report(&[7; 32], &measurement));
        measurement[0] = 0;
        assert!(!legacy.matches_report(&[7; 32], &measurement));
    }

    #[test]
    fn launch_identity_wire_format_is_the_descriptors_hex_fields() {
        let wire = serde_json::json!({
            "expected_cc_init_data_hash": "07".repeat(32),
            "expected_firmware_measurement": "09".repeat(48),
        });
        let identity: LaunchIdentity = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(identity.expected_cc_init_data_hash, [7; 32]);
        assert_eq!(
            identity.expected_firmware_measurement,
            FirmwareMeasurement::Full([9; 48])
        );
        assert_eq!(serde_json::to_value(&identity).unwrap(), wire);

        let mut short_hash = wire.clone();
        short_hash["expected_cc_init_data_hash"] = serde_json::json!("07".repeat(31));
        assert!(serde_json::from_value::<LaunchIdentity>(short_hash).is_err());
        let mut odd_measurement = wire;
        odd_measurement["expected_firmware_measurement"] = serde_json::json!("09".repeat(40));
        assert!(serde_json::from_value::<LaunchIdentity>(odd_measurement).is_err());
    }

    /// Contract v1 (policy-templates#23) golden: a legacy descriptor (the
    /// pod_supplemental_groups field ABSENT) keeps the exact core hash it
    /// had before the field existed. The pinned vector was produced by the
    /// same fixture against the pre-change tree (git worktree of main).
    #[test]
    fn legacy_descriptor_core_hash_is_byte_for_byte_unchanged() {
        let d = golden_pod_groups_descriptor(None);
        // The absent field serializes to nothing.
        let wire = serde_json::to_value(&d).unwrap();
        assert!(wire.get("pod_supplemental_groups").is_none());
        assert_eq!(
            hex::encode(descriptor_core_hash(&d)),
            "fb6fc939704e8427d9772e73f08cfe18bd1872365addca9f5f4df08877a77f9a",
            "legacy descriptors must keep their pre-change core hash"
        );
        // A None field is the same bytes as an absent field.
        let d2 = golden_pod_groups_descriptor(None);
        let mut d2 = d2;
        d2.pod_supplemental_groups = None;
        assert_eq!(
            descriptor_core_canonical_bytes(&d),
            descriptor_core_canonical_bytes(&d2)
        );
    }

    /// The declared list participates in the core hash ONLY when Some, and
    /// the canonical form is sorted unique (unsorted input canonicalizes to
    /// the same bytes).
    #[test]
    fn pod_supplemental_groups_join_the_core_hash_only_when_declared() {
        let legacy = golden_pod_groups_descriptor(None);
        let mut declared = golden_pod_groups_descriptor(None);
        declared.pod_supplemental_groups = Some(vec![0, 6, 27]);
        assert_ne!(
            descriptor_core_hash(&legacy),
            descriptor_core_hash(&declared),
            "a declared list must change the signed core hash"
        );
        let mut unsorted = golden_pod_groups_descriptor(None);
        unsorted.pod_supplemental_groups = Some(vec![27, 6, 0, 27]);
        assert_eq!(
            descriptor_core_canonical_bytes(&declared),
            descriptor_core_canonical_bytes(&unsorted),
            "unsorted/duplicated input canonicalizes to the same bytes"
        );
        let mut other = golden_pod_groups_descriptor(None);
        other.pod_supplemental_groups = Some(vec![0, 6, 55]);
        assert_ne!(
            descriptor_core_hash(&declared),
            descriptor_core_hash(&other)
        );
    }

    /// Admission validation: 1..=32 entries, 0..=2147483646, must contain
    /// the platform baseline 0 and 6; None (legacy) is always valid.
    #[test]
    fn pod_supplemental_groups_admission_validation() {
        assert!(validate_pod_supplemental_groups(None).is_ok());
        assert!(validate_pod_supplemental_groups(Some(&vec![0, 6])).is_ok());
        assert!(validate_pod_supplemental_groups(Some(&vec![6, 0, 27])).is_ok());
        // Missing the baseline members.
        assert!(validate_pod_supplemental_groups(Some(&vec![0, 27])).is_err());
        assert!(validate_pod_supplemental_groups(Some(&vec![6, 27])).is_err());
        assert!(validate_pod_supplemental_groups(Some(&vec![27])).is_err());
        // Empty and over-length lists.
        assert!(validate_pod_supplemental_groups(Some(&Vec::new())).is_err());
        let mut many = vec![0, 6];
        many.extend(std::iter::repeat_n(27, 31));
        assert_eq!(many.len(), 33);
        assert!(validate_pod_supplemental_groups(Some(&many)).is_err());
        // Reserved gids: each rejected by name.
        for reserved in [10001, 10002, 65535] {
            let err = validate_pod_supplemental_groups(Some(&vec![0, 6, reserved]))
                .expect_err("reserved gids must be rejected");
            assert!(
                err.contains(&format!("reserved gid {reserved}")),
                "the error names the reserved gid: {err}"
            );
        }
        // Out of range.
        assert!(validate_pod_supplemental_groups(Some(&vec![0, 6, -1])).is_err());
        assert!(validate_pod_supplemental_groups(Some(&vec![0, 6, 2147483647])).is_err());
        assert!(validate_pod_supplemental_groups(Some(&vec![0, 6, 2147483646])).is_ok());
    }

    /// The canonical string form is sorted unique, comma-separated.
    #[test]
    fn canonical_pod_groups_string_sorts_and_dedups() {
        assert_eq!(canonical_pod_groups_string(&[27, 6, 0, 27]), "0,6,27");
        assert_eq!(canonical_pod_groups_string(&[6, 0]), "0,6");
        assert_eq!(canonical_pod_groups_string(&[]), "");
    }

    fn golden_pod_groups_descriptor(
        pod_supplemental_groups: Option<Vec<i64>>,
    ) -> DeploymentDescriptor {
        let wire = serde_json::json!({
            "schema_version": "v1",
            "org_id": "11111111-1111-1111-1111-111111111111",
            "org_slug": "golden-org",
            "app_id": "22222222-2222-2222-2222-222222222222",
            "app_name": "golden-app",
            "deploy_id": "33333333-3333-3333-3333-333333333333",
            "created_at": "2026-01-01T00:00:00Z",
            "nonce": "00".repeat(32),
            "app_domain": "golden.example",
            "tee_domain": "tee.golden.example",
            "custom_domains": [],
            "namespace": "ns",
            "service_account": "sa",
            "identity_hash": "11".repeat(32),
            "image_ref": "ghcr.io/acme/golden",
            "image_digest": format!("sha256:{}", "22".repeat(32)),
            "signer_identity": {"subject": "s", "issuer": "i"},
            "oci_runtime_spec": {
                "command": [], "args": [], "env": [], "ports": [], "mounts": [],
                "capabilities": {"add": [], "drop": []},
                "security_context": {"run_as_user": 10001, "run_as_group": 10001, "read_only_root_fs": true, "allow_privilege_escalation": false, "privileged": false},
                "resources": {}
            },
            "sidecars": {
                "attestation_proxy_digest": format!("sha256:{}", "33".repeat(32)),
                "caddy_digest": format!("sha256:{}", "44".repeat(32))
            },
            "api_signing_pubkey": "pub",
            "independent_verification": true,
            "expected_firmware_measurement": "55".repeat(32),
            "expected_runtime_class": "rc",
            "kbs_resource_path": "default/x/seed",
            "unlock_mode": "password",
            "policy_template_id": "pt",
            "policy_template_sha256": "66".repeat(32),
            "platform_release_version": "v9",
            "expected_agent_policy_hash": "77".repeat(32),
            "expected_cc_init_data_hash": "88".repeat(32),
            "expected_kbs_policy_hash": "99".repeat(32),
            "pod_supplemental_groups": pod_supplemental_groups,
        });
        let mut d: DeploymentDescriptor = serde_json::from_value(wire).expect("parse fixture");
        d.pod_supplemental_groups = pod_supplemental_groups;
        d
    }
}
