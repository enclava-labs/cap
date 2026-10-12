use super::*;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DeploymentDescriptorEnvelope {
    pub(super) descriptor: DeploymentDescriptor,
    #[serde(deserialize_with = "deserialize_sig")]
    pub(super) signature: [u8; 64],
    pub(super) signing_key_id: String,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pub(super) signing_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OrgKeyringEnvelope {
    pub(super) keyring: OrgKeyring,
    #[serde(with = "hex_signature_array")]
    pub(super) signature: [u8; 64],
    #[allow(dead_code)]
    #[serde(with = "hex_bytes32")]
    pub(super) signing_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrgKeyring {
    pub(crate) org_id: Uuid,
    pub(crate) version: u64,
    pub(crate) members: Vec<KeyringMember>,
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyringMember {
    pub(crate) user_id: Uuid,
    #[serde(with = "hex_bytes32")]
    pub(crate) pubkey: [u8; 32],
    pub(crate) role: KeyringRole,
    pub(crate) added_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyringRole {
    Owner,
    Admin,
    Deployer,
}

impl KeyringRole {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Deployer => "deployer",
        }
    }
}

impl KeyringMember {
    pub(super) fn allows_deploy(&self) -> bool {
        matches!(
            self.role,
            KeyringRole::Owner | KeyringRole::Admin | KeyringRole::Deployer
        )
    }
}

/// Per-blob byte caps (#128): reject oversized payloads before any base64
/// decoding or JSON parsing so unauthenticated blobs cannot spend unbounded
/// CPU/memory. Caps are derived from the downstream proof-bundle field
/// budgets (enclava-verifier bundle.rs / deploy.rs build_verification_material):
/// trustee_policy_json is capped at 49_152 bytes and workload_artifacts_json
/// at 196_608 bytes. A max-legal combination (32 KiB descriptor + 16 KiB
/// keyring + 24 KiB rego + 48 KiB agent policy + 16 KiB keyring envelope +
/// metadata/signature overhead) must compose under both budgets, and
/// validate_proof_bundle_budget enforces the composed size exactly.
pub(super) const MAX_DESCRIPTOR_BLOB_BYTES: usize = 32 * 1024;
pub(super) const MAX_ORG_KEYRING_BLOB_BYTES: usize = 16 * 1024;
pub(super) const MAX_SIGNED_POLICY_ARTIFACT_BLOB_BYTES: usize = 128 * 1024;

pub(super) fn decode_json_blob<T: for<'de> Deserialize<'de>>(
    name: &str,
    blob: &str,
    max_bytes: usize,
) -> Result<T, SigningServiceError> {
    let trimmed = blob.trim();
    if trimmed.is_empty() {
        return Err(SigningServiceError::Blob(format!("{name} is required")));
    }
    if trimmed.len() > max_bytes {
        return Err(SigningServiceError::Blob(format!(
            "{name} exceeds {max_bytes} bytes (got {})",
            trimmed.len()
        )));
    }
    if let Ok(decoded) = B64.decode(trimmed.as_bytes())
        && let Ok(parsed) = serde_json::from_slice(&decoded)
    {
        return Ok(parsed);
    }
    serde_json::from_str(trimmed)
        .map_err(|err| SigningServiceError::Blob(format!("parsing {name}: {err}")))
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_hex32("pubkey", &value).map_err(serde::de::Error::custom)
}

fn deserialize_sig<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    decode_signature(&value).map_err(serde::de::Error::custom)
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

mod hex_signature_array {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        use serde::de::Error;
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 64"))
    }
}

/// Lenient keyring shapes shared by the tolerant parsers (#128): extract
/// only the known fields so rows written before deny_unknown_fields (or
/// legacy raw-JSON writes) keep re-verifying instead of failing dispatch.
/// Signatures are still enforced by callers over the canonical bytes.
#[derive(Deserialize)]
struct LenientMember {
    user_id: Uuid,
    #[serde(with = "hex_bytes32")]
    pubkey: [u8; 32],
    role: KeyringRole,
    added_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct LenientKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<LenientMember>,
    updated_at: DateTime<Utc>,
}

#[derive(Deserialize)]
struct LenientEnvelope {
    keyring: LenientKeyring,
    #[serde(with = "hex_signature_array")]
    signature: [u8; 64],
    #[serde(with = "hex_bytes32")]
    signing_pubkey: [u8; 32],
}

fn lenient_keyring_to_typed(lenient: LenientKeyring) -> OrgKeyring {
    OrgKeyring {
        org_id: lenient.org_id,
        version: lenient.version,
        members: lenient
            .members
            .into_iter()
            .map(|member| KeyringMember {
                user_id: member.user_id,
                pubkey: member.pubkey,
                role: member.role,
                added_at: member.added_at,
            })
            .collect(),
        updated_at: lenient.updated_at,
    }
}

pub(super) fn parse_org_keyring_envelope_tolerant(
    value: &serde_json::Value,
) -> Result<OrgKeyringEnvelope, SigningServiceError> {
    let lenient: LenientEnvelope =
        serde_json::from_value(value.clone()).map_err(SigningServiceError::Serde)?;
    Ok(OrgKeyringEnvelope {
        keyring: lenient_keyring_to_typed(lenient.keyring),
        signature: lenient.signature,
        signing_pubkey: lenient.signing_pubkey,
    })
}

/// Tolerant parse for a bare stored `org_keyrings.keyring_payload` value
/// (no envelope wrapper): rows registered before #128 stored the raw
/// request JSON, which may carry unknown keys. The signature over the
/// canonical bytes is still enforced by callers.
pub(super) fn parse_org_keyring_tolerant(
    value: &serde_json::Value,
) -> Result<OrgKeyring, SigningServiceError> {
    let lenient: LenientKeyring =
        serde_json::from_value(value.clone()).map_err(SigningServiceError::Serde)?;
    Ok(lenient_keyring_to_typed(lenient))
}

pub(super) fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32], SigningServiceError> {
    hex::decode(value.trim())
        .map_err(|err| SigningServiceError::Blob(format!("decoding {name}: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("{name} must be 32 bytes, got {}", bytes.len()))
        })
}

pub(super) fn decode_signature(value: &str) -> Result<[u8; 64], SigningServiceError> {
    let trimmed = value.trim();
    if let Ok(bytes) = hex::decode(trimmed) {
        return bytes.try_into().map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("signature must be 64 bytes, got {}", bytes.len()))
        });
    }
    B64.decode(trimmed.as_bytes())
        .map_err(|err| SigningServiceError::Blob(format!("decoding signature: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("signature must be 64 bytes, got {}", bytes.len()))
        })
}

pub(super) fn decode_pubkey_b64(name: &str, value: &str) -> Result<[u8; 32], SigningServiceError> {
    B64.decode(value.trim().as_bytes())
        .map_err(|err| SigningServiceError::Blob(format!("decoding {name}: {err}")))?
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            SigningServiceError::Blob(format!("{name} must be 32 bytes, got {}", bytes.len()))
        })
}

pub(super) fn keyring_fingerprint(keyring: &OrgKeyring) -> [u8; 32] {
    Sha256::digest(canonical_keyring_bytes(keyring)).into()
}

#[cfg(test)]
pub(crate) fn canonical_keyring_bytes_test(keyring: &OrgKeyring) -> Vec<u8> {
    canonical_keyring_bytes(keyring)
}

pub(super) fn canonical_keyring_bytes(keyring: &OrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&keyring.members);
    let version = keyring.version.to_be_bytes();
    let updated = keyring.updated_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version),
        ("members", &members_hash),
        ("updated_at", updated.as_bytes()),
    ])
}

fn canonical_member_hash(member: &KeyringMember) -> [u8; 32] {
    let added = member.added_at.to_rfc3339();
    ce_v1_hash(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", &member.pubkey),
        ("role", member.role.as_str().as_bytes()),
        ("added_at", added.as_bytes()),
    ])
}

fn canonical_members_hash(members: &[KeyringMember]) -> [u8; 32] {
    let mut sorted: Vec<&KeyringMember> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let records: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| (member.user_id.to_string(), canonical_member_hash(member)))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}
