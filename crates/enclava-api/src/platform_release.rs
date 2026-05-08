//! Signed platform-release metadata consumed by the API at startup.
//!
//! The CLI already signs deployment descriptors from this artifact. The API
//! uses the same signed anchors to reject drift in platform-controlled release
//! values before it can mint cc_init_data or verify signed policy artifacts.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const BUNDLED_PLATFORM_RELEASE: &str = include_str!("../../enclava-cli/platform-release.json");

// Fixture release root used for the checked-in development release artifact.
// Production release builds can replace this by setting
// ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX at compile time.
const FALLBACK_RELEASE_ROOT_PUBKEY_HEX: &str =
    "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd";

#[derive(Debug, Error)]
pub enum PlatformReleaseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("invalid {field}: {message}")]
    InvalidField {
        field: &'static str,
        message: String,
    },
    #[error("platform release signature pubkey is not the pinned root")]
    RootMismatch,
    #[error("platform release signature verification failed: {0}")]
    BadSignature(String),
    #[error("policy_template_sha256 does not match policy_template_text")]
    TemplateHashMismatch,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformReleaseEnvelope {
    pub payload: PlatformRelease,
    pub signature: String,
    pub signing_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformRelease {
    pub schema_version: String,
    pub platform_release_version: String,
    pub signing_service_url: String,
    pub signing_service_pubkey_hex: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    pub policy_template_text: String,
    pub attestation_proxy_image: String,
    pub caddy_ingress_image: String,
    pub trustee_kbs_url: String,
    pub trustee_kbs_ca_cert_pem: String,
    pub tenant_caddy_tls_mode: String,
    pub tenant_caddy_acme_ca: String,
    pub expected_firmware_measurement: String,
    pub expected_runtime_class: String,
    pub genpolicy_version: String,
    pub created_at: String,
}

impl PlatformRelease {
    pub fn load_verified() -> Result<Self, PlatformReleaseError> {
        let raw = match std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH") {
            Ok(path) if !path.trim().is_empty() => std::fs::read_to_string(Path::new(&path))?,
            _ => BUNDLED_PLATFORM_RELEASE.to_string(),
        };
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw)?;
        verify_envelope(envelope)
    }

    pub fn policy_template_sha256_bytes(&self) -> Result<[u8; 32], PlatformReleaseError> {
        hex32("policy_template_sha256", &self.policy_template_sha256)
    }

    pub fn expected_firmware_measurement_bytes(&self) -> Result<[u8; 32], PlatformReleaseError> {
        hex32(
            "expected_firmware_measurement",
            &self.expected_firmware_measurement,
        )
    }

    pub fn signing_service_pubkey_bytes(&self) -> Result<[u8; 32], PlatformReleaseError> {
        hex32(
            "signing_service_pubkey_hex",
            &self.signing_service_pubkey_hex,
        )
    }
}

pub fn verify_envelope(
    envelope: PlatformReleaseEnvelope,
) -> Result<PlatformRelease, PlatformReleaseError> {
    let pinned = hex32(
        "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX",
        option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
            .unwrap_or(FALLBACK_RELEASE_ROOT_PUBKEY_HEX),
    )?;
    let signing = hex32("signing_pubkey", &envelope.signing_pubkey)?;
    if signing != pinned {
        return Err(PlatformReleaseError::RootMismatch);
    }
    let verifying_key =
        VerifyingKey::from_bytes(&signing).map_err(|err| PlatformReleaseError::InvalidField {
            field: "signing_pubkey",
            message: err.to_string(),
        })?;
    let signature_bytes = hex::decode(&envelope.signature)?;
    let signature_arr: [u8; 64] = signature_bytes.try_into().map_err(|bytes: Vec<u8>| {
        PlatformReleaseError::InvalidField {
            field: "signature",
            message: format!("expected 64 bytes, got {}", bytes.len()),
        }
    })?;
    let signature = Signature::from_bytes(&signature_arr);
    let canonical = canonical_platform_release_bytes(&envelope.payload)?;
    verifying_key
        .verify(&canonical, &signature)
        .map_err(|err| PlatformReleaseError::BadSignature(err.to_string()))?;

    let actual_template_hash = hex::encode(Sha256::digest(
        envelope.payload.policy_template_text.as_bytes(),
    ));
    if actual_template_hash != envelope.payload.policy_template_sha256 {
        return Err(PlatformReleaseError::TemplateHashMismatch);
    }
    validate_release_payload(&envelope.payload)?;
    Ok(envelope.payload)
}

pub fn canonical_platform_release_bytes(
    release: &PlatformRelease,
) -> Result<Vec<u8>, PlatformReleaseError> {
    let signing_service_pubkey = hex32(
        "signing_service_pubkey_hex",
        &release.signing_service_pubkey_hex,
    )?;
    let policy_template_sha256 = release.policy_template_sha256_bytes()?;
    let expected_firmware_measurement = release.expected_firmware_measurement_bytes()?;
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-platform-release-v1"),
        ("schema_version", release.schema_version.as_bytes()),
        (
            "platform_release_version",
            release.platform_release_version.as_bytes(),
        ),
        (
            "signing_service_url",
            release.signing_service_url.as_bytes(),
        ),
        ("signing_service_pubkey", &signing_service_pubkey),
        ("policy_template_id", release.policy_template_id.as_bytes()),
        ("policy_template_sha256", &policy_template_sha256),
        (
            "policy_template_text",
            release.policy_template_text.as_bytes(),
        ),
        (
            "attestation_proxy_image",
            release.attestation_proxy_image.as_bytes(),
        ),
        (
            "caddy_ingress_image",
            release.caddy_ingress_image.as_bytes(),
        ),
        ("trustee_kbs_url", release.trustee_kbs_url.as_bytes()),
        (
            "trustee_kbs_ca_cert_pem",
            release.trustee_kbs_ca_cert_pem.as_bytes(),
        ),
        (
            "tenant_caddy_tls_mode",
            release.tenant_caddy_tls_mode.as_bytes(),
        ),
        (
            "tenant_caddy_acme_ca",
            release.tenant_caddy_acme_ca.as_bytes(),
        ),
        (
            "expected_firmware_measurement",
            &expected_firmware_measurement,
        ),
        (
            "expected_runtime_class",
            release.expected_runtime_class.as_bytes(),
        ),
        ("genpolicy_version", release.genpolicy_version.as_bytes()),
        ("created_at", release.created_at.as_bytes()),
    ]))
}

fn validate_release_payload(release: &PlatformRelease) -> Result<(), PlatformReleaseError> {
    if release.schema_version != "v1" {
        return Err(PlatformReleaseError::InvalidField {
            field: "schema_version",
            message: "expected v1".to_string(),
        });
    }
    let signing_url = reqwest::Url::parse(&release.signing_service_url).map_err(|err| {
        PlatformReleaseError::InvalidField {
            field: "signing_service_url",
            message: err.to_string(),
        }
    })?;
    if !matches!(signing_url.scheme(), "http" | "https") {
        return Err(PlatformReleaseError::InvalidField {
            field: "signing_service_url",
            message: "scheme must be http or https".to_string(),
        });
    }
    hex32(
        "signing_service_pubkey_hex",
        &release.signing_service_pubkey_hex,
    )?;
    hex32("policy_template_sha256", &release.policy_template_sha256)?;
    hex32(
        "expected_firmware_measurement",
        &release.expected_firmware_measurement,
    )?;
    for (field, image) in [
        ("attestation_proxy_image", &release.attestation_proxy_image),
        ("caddy_ingress_image", &release.caddy_ingress_image),
    ] {
        let parsed = enclava_common::image::ImageRef::parse(image).map_err(|err| {
            PlatformReleaseError::InvalidField {
                field,
                message: err.to_string(),
            }
        })?;
        parsed
            .require_digest()
            .map_err(|err| PlatformReleaseError::InvalidField {
                field,
                message: err.to_string(),
            })?;
    }
    let kbs_url = reqwest::Url::parse(&release.trustee_kbs_url).map_err(|err| {
        PlatformReleaseError::InvalidField {
            field: "trustee_kbs_url",
            message: err.to_string(),
        }
    })?;
    if !matches!(kbs_url.scheme(), "http" | "https") {
        return Err(PlatformReleaseError::InvalidField {
            field: "trustee_kbs_url",
            message: "scheme must be http or https".to_string(),
        });
    }
    release
        .tenant_caddy_tls_mode
        .parse::<enclava_engine::types::CaddyTlsMode>()
        .map_err(|err| PlatformReleaseError::InvalidField {
            field: "tenant_caddy_tls_mode",
            message: err,
        })?;
    reqwest::Url::parse(&release.tenant_caddy_acme_ca).map_err(|err| {
        PlatformReleaseError::InvalidField {
            field: "tenant_caddy_acme_ca",
            message: err.to_string(),
        }
    })?;
    if release.genpolicy_version.trim().is_empty()
        || release.genpolicy_version.contains("unconfigured")
        || release.genpolicy_version.contains("unpinned")
    {
        return Err(PlatformReleaseError::InvalidField {
            field: "genpolicy_version",
            message: "must be a concrete pinned generator version".to_string(),
        });
    }
    Ok(())
}

fn hex32(field: &'static str, value: &str) -> Result<[u8; 32], PlatformReleaseError> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PlatformReleaseError::InvalidField {
            field,
            message: format!("expected 32 bytes, got {}", bytes.len()),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_release_verifies_and_hashes_template() {
        let release = PlatformRelease::load_verified().unwrap();
        assert_eq!(release.schema_version, "v1");
        assert_eq!(
            release.policy_template_sha256,
            hex::encode(Sha256::digest(release.policy_template_text.as_bytes()))
        );
        assert!(!release.genpolicy_version.contains("unpinned"));
    }

    #[test]
    fn tampering_breaks_signature() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut tampered = raw.clone();
        tampered
            .payload
            .platform_release_version
            .push_str("-tampered");
        let err = verify_envelope(tampered).unwrap_err();
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));
    }
}
