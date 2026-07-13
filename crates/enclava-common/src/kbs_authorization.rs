//! Strict deployment authorization contract shared by CAP and `enclava-init`.
//!
//! JSON is only the transport and storage envelope. The Ed25519 signature is
//! over the CE-v1 semantic encoding returned by [`authorization_signing_bytes`].

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::canonical::{ce_v1_bytes, ce_v1_hash};
use crate::descriptor::SignerIdentity;

pub const AUTHORIZATION_SCHEMA_V1: &str = "enclava-kbs-deployment-authorization-v1";
pub const AUTHORIZATION_SIGNATURE_ALG: &str = "ed25519";
pub const MAX_AUTHORIZATION_BYTES: usize = 16 * 1024;
pub const MAX_AUTHORIZED_RESOURCE_PATHS: usize = 8;

/// Semantic inputs for `enclava-workload-artifact-bundle-v1`.
///
/// Callers must first verify that the declared Rego/agent-policy hashes equal
/// their bodies and that the policy metadata hash was produced by the shared
/// policy-artifact CE-v1 contract. This struct deliberately accepts semantic
/// components rather than JSON bytes so PostgreSQL `jsonb` reserialization is
/// irrelevant to the digest.
pub struct ArtifactBundleDigestInput<'a> {
    pub descriptor_canonical_bytes: &'a [u8],
    pub descriptor_signature: &'a [u8; 64],
    pub descriptor_signing_key_id: &'a str,
    pub org_keyring_canonical_bytes: &'a [u8],
    pub org_keyring_signature: &'a [u8; 64],
    pub org_keyring_signing_pubkey: &'a [u8; 32],
    pub policy_metadata_hash: &'a [u8; 32],
    pub rego_text: &'a str,
    pub agent_policy_text: &'a str,
    pub policy_signature: &'a [u8; 64],
    pub policy_verify_pubkey: &'a [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthorizationV1 {
    pub schema_version: String,
    pub authorization_id: Uuid,
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub descriptor_deploy_id: Uuid,
    #[serde(with = "hex32")]
    pub descriptor_core_hash: [u8; 32],
    #[serde(with = "hex32")]
    pub expected_init_data_hash: [u8; 32],
    pub namespace: String,
    pub service_account: String,
    #[serde(with = "hex32")]
    pub tenant_instance_identity_hash: [u8; 32],
    pub org_owner_version: u64,
    #[serde(with = "hex32")]
    pub org_owner_pubkey_sha256: [u8; 32],
    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub receipt_resource_path: String,
    pub authorized_resource_paths: Vec<String>,
    #[serde(with = "hex32")]
    pub rego_sha256: [u8; 32],
    #[serde(with = "hex32")]
    pub agent_policy_sha256: [u8; 32],
    #[serde(with = "hex32")]
    pub artifact_bundle_digest: [u8; 32],
    pub issuer_key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature_alg: String,
    pub signature: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthorizationError {
    #[error("authorization exceeds {MAX_AUTHORIZATION_BYTES} bytes")]
    TooLarge,
    #[error("authorization JSON is invalid: {0}")]
    InvalidJson(String),
    #[error("unsupported authorization schema")]
    UnsupportedSchema,
    #[error("unsupported authorization signature algorithm")]
    UnsupportedSignatureAlgorithm,
    #[error("authorization field is invalid: {0}")]
    InvalidField(&'static str),
    #[error("authorization resource path is invalid")]
    InvalidResourcePath,
    #[error("authorization receipt path does not match descriptor hash")]
    ReceiptPathMismatch,
    #[error("authorized resource paths must be sorted and unique")]
    PathsNotCanonical,
    #[error("authorization signature encoding is invalid")]
    InvalidSignatureEncoding,
    #[error("authorization signature verification failed")]
    InvalidSignature,
    #[error("authorization is not yet valid")]
    NotYetValid,
    #[error("authorization has expired")]
    Expired,
    #[error("authorization trust map is invalid: {0}")]
    InvalidTrustMap(&'static str),
    #[error("authorization issuer key id is not trusted")]
    UntrustedIssuerKeyId,
}

impl DeploymentAuthorizationV1 {
    pub fn parse_exact_json(bytes: &[u8]) -> Result<Self, AuthorizationError> {
        if bytes.len() > MAX_AUTHORIZATION_BYTES {
            return Err(AuthorizationError::TooLarge);
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|err| AuthorizationError::InvalidJson(err.to_string()))?;
        value.validate_contract()?;
        Ok(value)
    }

    pub fn validate_contract(&self) -> Result<(), AuthorizationError> {
        if self.schema_version != AUTHORIZATION_SCHEMA_V1 {
            return Err(AuthorizationError::UnsupportedSchema);
        }
        if self.signature_alg != AUTHORIZATION_SIGNATURE_ALG {
            return Err(AuthorizationError::UnsupportedSignatureAlgorithm);
        }
        if self.org_owner_version == 0 {
            return Err(AuthorizationError::InvalidField("org_owner_version"));
        }
        if self.namespace.is_empty() || self.namespace.len() > 253 || !is_dns_name(&self.namespace)
        {
            return Err(AuthorizationError::InvalidField("namespace"));
        }
        if self.service_account.is_empty()
            || self.service_account.len() > 253
            || !is_dns_name(&self.service_account)
        {
            return Err(AuthorizationError::InvalidField("service_account"));
        }
        if !is_sha256_digest(&self.image_digest) {
            return Err(AuthorizationError::InvalidField("image_digest"));
        }
        if self.signer_identity.subject.is_empty() || self.signer_identity.issuer.is_empty() {
            return Err(AuthorizationError::InvalidField("signer_identity"));
        }
        if self.issuer_key_id.is_empty() || self.issuer_key_id.len() > 255 {
            return Err(AuthorizationError::InvalidField("issuer_key_id"));
        }
        if self.authorized_resource_paths.is_empty()
            || self.authorized_resource_paths.len() > MAX_AUTHORIZED_RESOURCE_PATHS
        {
            return Err(AuthorizationError::InvalidField(
                "authorized_resource_paths",
            ));
        }
        if !is_kbs_resource_path(&self.receipt_resource_path)
            || self
                .authorized_resource_paths
                .iter()
                .any(|path| !is_kbs_resource_path(path))
        {
            return Err(AuthorizationError::InvalidResourcePath);
        }
        if self.receipt_resource_path != receipt_resource_path(&self.descriptor_core_hash) {
            return Err(AuthorizationError::ReceiptPathMismatch);
        }
        if self
            .authorized_resource_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err(AuthorizationError::PathsNotCanonical);
        }
        if self
            .authorized_resource_paths
            .binary_search(&self.receipt_resource_path)
            .is_err()
        {
            return Err(AuthorizationError::InvalidField(
                "authorized_resource_paths",
            ));
        }
        if let Some(expires_at) = self.expires_at
            && expires_at <= self.issued_at
        {
            return Err(AuthorizationError::InvalidField("expires_at"));
        }
        decode_signature(&self.signature)?;
        Ok(())
    }

    pub fn verify_signature(&self, public_key: &[u8; 32]) -> Result<(), AuthorizationError> {
        self.validate_contract()?;
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| AuthorizationError::InvalidSignature)?;
        let signature = Signature::from_bytes(&decode_signature(&self.signature)?);
        key.verify(&authorization_signing_bytes(self), &signature)
            .map_err(|_| AuthorizationError::InvalidSignature)
    }

    pub fn validate_time(&self, now: DateTime<Utc>) -> Result<(), AuthorizationError> {
        if now < self.issued_at {
            return Err(AuthorizationError::NotYetValid);
        }
        if self.expires_at.is_some_and(|expiry| now >= expiry) {
            return Err(AuthorizationError::Expired);
        }
        Ok(())
    }
}

/// Produce the CE-v1 bytes signed by the authorization issuer.
pub fn authorization_signing_bytes(value: &DeploymentAuthorizationV1) -> Vec<u8> {
    let paths_hash = canonical_paths_hash(&value.authorized_resource_paths);
    let signer_hash = ce_v1_hash(&[
        ("subject", value.signer_identity.subject.as_bytes()),
        ("issuer", value.signer_identity.issuer.as_bytes()),
    ]);
    let owner_version = value.org_owner_version.to_be_bytes();
    let issued_at = normalized_timestamp(value.issued_at);
    let expires_at = value
        .expires_at
        .map(normalized_timestamp)
        .unwrap_or_default();
    ce_v1_bytes(&[
        ("purpose", AUTHORIZATION_SCHEMA_V1.as_bytes()),
        ("schema_version", value.schema_version.as_bytes()),
        ("authorization_id", value.authorization_id.as_bytes()),
        ("org_id", value.org_id.as_bytes()),
        ("app_id", value.app_id.as_bytes()),
        (
            "descriptor_deploy_id",
            value.descriptor_deploy_id.as_bytes(),
        ),
        ("descriptor_core_hash", &value.descriptor_core_hash),
        ("expected_init_data_hash", &value.expected_init_data_hash),
        ("namespace", value.namespace.as_bytes()),
        ("service_account", value.service_account.as_bytes()),
        (
            "tenant_instance_identity_hash",
            &value.tenant_instance_identity_hash,
        ),
        ("org_owner_version", &owner_version),
        ("org_owner_pubkey_sha256", &value.org_owner_pubkey_sha256),
        ("image_digest", value.image_digest.as_bytes()),
        ("signer_identity", &signer_hash),
        (
            "receipt_resource_path",
            value.receipt_resource_path.as_bytes(),
        ),
        ("authorized_resource_paths", &paths_hash),
        ("rego_sha256", &value.rego_sha256),
        ("agent_policy_sha256", &value.agent_policy_sha256),
        ("artifact_bundle_digest", &value.artifact_bundle_digest),
        ("issuer_key_id", value.issuer_key_id.as_bytes()),
        ("issued_at", issued_at.as_bytes()),
        ("expires_at", expires_at.as_bytes()),
        ("signature_alg", value.signature_alg.as_bytes()),
    ])
}

pub fn authorization_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Parse the independently configured receipt-issuer trust map.
///
/// Receipt key selection must use this map directly. A scalar "current key"
/// must never be used as a fallback for an unknown or retired issuer key ID.
pub fn parse_authorization_trust_map(
    raw: &str,
) -> Result<BTreeMap<String, [u8; 32]>, AuthorizationError> {
    let encoded: BTreeMap<String, String> = serde_json::from_str(raw).map_err(|_| {
        AuthorizationError::InvalidTrustMap(
            "expected a JSON object mapping key IDs to public-key hex",
        )
    })?;
    if encoded.is_empty() {
        return Err(AuthorizationError::InvalidTrustMap(
            "at least one trusted issuer key is required",
        ));
    }

    encoded
        .into_iter()
        .map(|(key_id, encoded_key)| {
            if key_id.is_empty() || key_id.len() > 255 {
                return Err(AuthorizationError::InvalidTrustMap(
                    "issuer key IDs must contain 1 to 255 bytes",
                ));
            }
            let key = hex::decode(encoded_key)
                .ok()
                .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                .ok_or(AuthorizationError::InvalidTrustMap(
                    "issuer public keys must be 32-byte hex",
                ))?;
            Ok((key_id, key))
        })
        .collect()
}

/// Resolve an authorization issuer through the explicit trust map.
pub fn trusted_authorization_key<'a>(
    trusted_keys: &'a BTreeMap<String, [u8; 32]>,
    issuer_key_id: &str,
) -> Result<&'a [u8; 32], AuthorizationError> {
    trusted_keys
        .get(issuer_key_id)
        .ok_or(AuthorizationError::UntrustedIssuerKeyId)
}

/// Compute the semantic digest for a complete workload artifact bundle.
pub fn artifact_bundle_digest(input: &ArtifactBundleDigestInput<'_>) -> [u8; 32] {
    let descriptor_hash: [u8; 32] = Sha256::digest(input.descriptor_canonical_bytes).into();
    let keyring_hash: [u8; 32] = Sha256::digest(input.org_keyring_canonical_bytes).into();
    let rego_hash: [u8; 32] = Sha256::digest(input.rego_text.as_bytes()).into();
    let agent_policy_hash: [u8; 32] = Sha256::digest(input.agent_policy_text.as_bytes()).into();

    ce_v1_hash(&[
        ("purpose", b"enclava-workload-artifact-bundle-v1"),
        ("descriptor", &descriptor_hash),
        ("descriptor_signature", input.descriptor_signature),
        (
            "descriptor_signing_key_id",
            input.descriptor_signing_key_id.as_bytes(),
        ),
        ("org_keyring", &keyring_hash),
        ("org_keyring_signature", input.org_keyring_signature),
        (
            "org_keyring_signing_pubkey",
            input.org_keyring_signing_pubkey,
        ),
        ("policy_metadata", input.policy_metadata_hash),
        ("rego_sha256", &rego_hash),
        ("agent_policy_sha256", &agent_policy_hash),
        ("policy_signature", input.policy_signature),
        ("policy_verify_pubkey", input.policy_verify_pubkey),
    ])
}

pub fn receipt_resource_path(descriptor_core_hash: &[u8; 32]) -> String {
    format!(
        "default/policy-receipts/{}",
        hex::encode(descriptor_core_hash)
    )
}

pub fn encode_signature(signature: &[u8; 64]) -> String {
    URL_SAFE_NO_PAD.encode(signature)
}

fn decode_signature(value: &str) -> Result<[u8; 64], AuthorizationError> {
    if value.is_empty() || value.contains('=') {
        return Err(AuthorizationError::InvalidSignatureEncoding);
    }
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthorizationError::InvalidSignatureEncoding)?
        .try_into()
        .map_err(|_| AuthorizationError::InvalidSignatureEncoding)
}

fn normalized_timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn canonical_paths_hash(paths: &[String]) -> [u8; 32] {
    let records: Vec<(String, &[u8])> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("path-{index}"), path.as_bytes()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, path)| (label.as_str(), *path))
        .collect();
    ce_v1_hash(&refs)
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_dns_name(value: &str) -> bool {
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Trustee resource identifiers are exactly three canonical ASCII segments.
pub fn is_kbs_resource_path(value: &str) -> bool {
    if !value.is_ascii()
        || value.starts_with('/')
        || value.contains('%')
        || value.contains('\\')
        || value.len() > 1024
    {
        return false;
    }
    let segments: Vec<&str> = value.split('/').collect();
    segments.len() == 3
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && !segment.starts_with('.')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error as _;
        let value = String::deserialize(deserializer)?;
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(D::Error::custom(
                "expected 64 lowercase hexadecimal characters",
            ));
        }
        hex::decode(value)
            .map_err(D::Error::custom)?
            .try_into()
            .map_err(|_| D::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn unsigned_fixture() -> DeploymentAuthorizationV1 {
        let descriptor_core_hash = [0x11; 32];
        DeploymentAuthorizationV1 {
            schema_version: AUTHORIZATION_SCHEMA_V1.into(),
            authorization_id: Uuid::from_u128(1),
            org_id: Uuid::from_u128(2),
            app_id: Uuid::from_u128(3),
            descriptor_deploy_id: Uuid::from_u128(4),
            descriptor_core_hash,
            expected_init_data_hash: [0x22; 32],
            namespace: "cust-1234-app".into(),
            service_account: "workload".into(),
            tenant_instance_identity_hash: [0x33; 32],
            org_owner_version: 7,
            org_owner_pubkey_sha256: [0x44; 32],
            image_digest: format!("sha256:{}", "55".repeat(32)),
            signer_identity: SignerIdentity {
                subject: "subject".into(),
                issuer: "issuer".into(),
            },
            receipt_resource_path: receipt_resource_path(&descriptor_core_hash),
            authorized_resource_paths: vec![
                "default/acme-owner/seed-encrypted".into(),
                "default/acme-owner/seed-sealed".into(),
                receipt_resource_path(&descriptor_core_hash),
            ],
            rego_sha256: [0x66; 32],
            agent_policy_sha256: [0x77; 32],
            artifact_bundle_digest: [0x88; 32],
            issuer_key_id: "platform-authorization-1".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 10, 1, 2, 3).unwrap(),
            expires_at: None,
            signature_alg: AUTHORIZATION_SIGNATURE_ALG.into(),
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        }
    }

    fn signed_fixture() -> (DeploymentAuthorizationV1, VerifyingKey) {
        let key = SigningKey::from_bytes(&[0x42; 32]);
        let mut value = unsigned_fixture();
        value.signature =
            encode_signature(&key.sign(&authorization_signing_bytes(&value)).to_bytes());
        (value, key.verifying_key())
    }

    #[test]
    fn signed_fixture_verifies_and_round_trips_strict_json() {
        let (value, key) = signed_fixture();
        let bytes = serde_json::to_vec(&value).unwrap();
        let parsed = DeploymentAuthorizationV1::parse_exact_json(&bytes).unwrap();
        parsed.verify_signature(key.as_bytes()).unwrap();
        assert_eq!(parsed, value);
    }

    #[test]
    fn authorization_signing_bytes_have_a_fixed_cross_implementation_vector() {
        let value = unsigned_fixture();
        assert_eq!(
            hex::encode(Sha256::digest(authorization_signing_bytes(&value))),
            "8d723c0a2f9a19d6dbe37f11d8dd1707acb1623fb1c8f1c13d9d9920bbb28036"
        );
    }

    #[test]
    fn every_security_field_is_bound_by_signature() {
        let (value, key) = signed_fixture();
        let mut mutations = vec![
            {
                let mut v = value.clone();
                v.app_id = Uuid::from_u128(99);
                v
            },
            {
                let mut v = value.clone();
                v.expected_init_data_hash[0] ^= 1;
                v
            },
            {
                let mut v = value.clone();
                v.namespace = "other".into();
                v
            },
            {
                let mut v = value.clone();
                v.org_owner_version += 1;
                v
            },
            {
                let mut v = value.clone();
                v.artifact_bundle_digest[0] ^= 1;
                v
            },
            {
                let mut v = value.clone();
                v.issuer_key_id.push('x');
                v
            },
        ];
        for mutated in &mut mutations {
            assert_eq!(
                mutated.verify_signature(key.as_bytes()),
                Err(AuthorizationError::InvalidSignature)
            );
        }
    }

    #[test]
    fn parser_rejects_unknown_fields_uppercase_hashes_and_oversized_input() {
        let (value, _) = signed_fixture();
        let mut json = serde_json::to_value(value).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(matches!(
            DeploymentAuthorizationV1::parse_exact_json(&serde_json::to_vec(&json).unwrap()),
            Err(AuthorizationError::InvalidJson(_))
        ));

        json.as_object_mut().unwrap().remove("extra");
        json["descriptor_core_hash"] = "AA".repeat(32).into();
        assert!(matches!(
            DeploymentAuthorizationV1::parse_exact_json(&serde_json::to_vec(&json).unwrap()),
            Err(AuthorizationError::InvalidJson(_))
        ));

        assert_eq!(
            DeploymentAuthorizationV1::parse_exact_json(&vec![b' '; MAX_AUTHORIZATION_BYTES + 1]),
            Err(AuthorizationError::TooLarge)
        );
    }

    #[test]
    fn authorization_trust_map_is_nonempty_strict_and_keyed_by_issuer_id() {
        let keys = parse_authorization_trust_map(
            &serde_json::json!({
                "current": "11".repeat(32),
                "retiring": "22".repeat(32),
            })
            .to_string(),
        )
        .unwrap();
        assert_eq!(
            trusted_authorization_key(&keys, "current").unwrap(),
            &[0x11; 32]
        );
        assert_eq!(
            trusted_authorization_key(&keys, "unknown"),
            Err(AuthorizationError::UntrustedIssuerKeyId)
        );
        assert!(parse_authorization_trust_map("{}").is_err());
        assert!(parse_authorization_trust_map(r#"{"bad":"11"}"#).is_err());
    }

    #[test]
    fn resource_path_validation_rejects_noncanonical_forms() {
        for invalid in [
            "/default/type/tag",
            "default/type",
            "default/type/tag/extra",
            "default/../tag",
            "default/type/%2f",
            "default/type/back\\slash",
            "default/.hidden/tag",
        ] {
            assert!(!is_kbs_resource_path(invalid), "accepted {invalid}");
        }
        assert!(is_kbs_resource_path("default/policy-receipts/abc-123"));
    }

    #[test]
    fn artifact_bundle_digest_has_a_fixed_cross_implementation_vector() {
        let digest = artifact_bundle_digest(&ArtifactBundleDigestInput {
            descriptor_canonical_bytes: b"descriptor-ce-v1-fixture",
            descriptor_signature: &[0x11; 64],
            descriptor_signing_key_id: "customer-key-1",
            org_keyring_canonical_bytes: b"keyring-ce-v1-fixture",
            org_keyring_signature: &[0x22; 64],
            org_keyring_signing_pubkey: &[0x33; 32],
            policy_metadata_hash: &[0x44; 32],
            rego_text: "package enclava\ndefault allow := false\n",
            agent_policy_text: "{\"policy\":\"fixture\"}",
            policy_signature: &[0x55; 64],
            policy_verify_pubkey: &[0x66; 32],
        });
        assert_eq!(
            hex::encode(digest),
            "4021ebcbb15509de3b7ba0fb2e5e16cea8d7f9163ca4ebaff1da6c9deb588cf4"
        );
    }
}
