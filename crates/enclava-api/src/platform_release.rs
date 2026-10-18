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

#[cfg(any(test, feature = "prod-strict"))]
const FORBIDDEN_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str =
    "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd";

#[cfg(test)]
const TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str = FORBIDDEN_FIXTURE_RELEASE_ROOT_PUBKEY_HEX;

/// Public half of the dev-fixture trustee policy seed (c1*32) committed with
/// crates/enclava-cli/scripts/generate-platform-release.py. Rejected for any
/// release not signed by the dev fixture root (see verify_envelope).
const DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX: &str =
    "acdcc8494d458f44a7aaac1d6a84ec624daee88436db2ae26e67ba645a106228";

fn fixture_trustee_policy_pubkey() -> Vec<u8> {
    hex::decode(DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX).expect("static hex decodes")
}

/// Decoded dev-fixture release root (pubkey 5b9437ad...): releases signed by
/// it may pin the fixture trustee key; production roots may not.
fn fixture_root_pubkey() -> [u8; 32] {
    hex::decode("5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd")
        .expect("static hex decodes")
        .try_into()
        .expect("32 bytes")
}

#[cfg(any(test, feature = "prod-strict"))]
// ponytail: manual compare, u8::eq_ignore_ascii_case is not const at MSRV 1.85
#[allow(clippy::manual_ignore_case_cmp)]
const fn eq_ignore_ascii_case(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(any(test, feature = "prod-strict"))]
const fn is_forbidden_fixture_root(root: &str) -> bool {
    eq_ignore_ascii_case(root, FORBIDDEN_FIXTURE_RELEASE_ROOT_PUBKEY_HEX)
}

/// 64 ASCII hex characters (either case) = a 32-byte key.
#[cfg(any(test, feature = "prod-strict"))]
const fn is_hex32_root(root: &str) -> bool {
    let bytes = root.as_bytes();
    if bytes.len() != 64 {
        return false;
    }
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i].to_ascii_lowercase();
        if !(c.is_ascii_digit() || (c >= b'a' && c <= b'f')) {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(all(not(test), feature = "prod-strict"))]
const _: () = {
    match option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX") {
        Some(root) if is_forbidden_fixture_root(root) => {
            panic!("prod-strict builds must not pin the committed fixture platform-release root");
        }
        Some(root) if is_hex32_root(root) => {}
        _ => panic!(
            "prod-strict builds require ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX to be set to a 32-byte hex pubkey"
        ),
    }
};

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
    #[error("platform release root pubkey is not configured at compile time")]
    MissingRootPubkey,
    #[error(
        "platform release signature pubkey is not the pinned root: this build pins {pinned}, the release declares {signing}; verify the target platform and, if this is an expected root rotation, update this enclava-api deployment using a trusted build with the expected pin"
    )]
    RootMismatch { pinned: String, signing: String },
    #[error("platform release signature verification failed: {0}")]
    BadSignature(String),
    #[error("policy_template_sha256 does not match policy_template_text")]
    TemplateHashMismatch,
    #[error(
        "platform release downgrade refused: override is {override_version} ({override_created}) but the API bundles {bundled_version} ({bundled_created}); refusing a validly-signed stale release"
    )]
    DowngradeRefused {
        override_version: String,
        override_created: String,
        bundled_version: String,
        bundled_created: String,
    },
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
    pub platform_trustee_policy_pubkey_hex: String,
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
    /// LUKS2 header-seal rollout claim (`"adopt"` | `"required"`), carried
    /// by the signed release (cap#244 review). The rollout value must come
    /// from verified release metadata — never from a producer's private
    /// environment — so every producer of `expected_cc_init_data_hash`
    /// renders identical bytes. Empty for releases signed before this field
    /// existed; those keep the rollout-window ("adopt") semantics.
    #[serde(default)]
    pub luks2_header_seal: String,
    pub created_at: String,
}

impl PlatformRelease {
    pub fn load_verified() -> Result<Self, PlatformReleaseError> {
        Ok(PlatformReleaseEnvelope::load_verified()?.payload)
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
        let bytes = hex32(
            "signing_service_pubkey_hex",
            &self.signing_service_pubkey_hex,
        )?;
        require_ed25519_point("signing_service_pubkey_hex", &bytes)?;
        Ok(bytes)
    }

    /// Dedicated in-TEE policy authority key. Must differ from
    /// `signing_service_pubkey_hex`: the two are distinct trust domains
    /// (in-TEE policy authority vs off-cluster signing service) and a
    /// release that collapses them is rejected at validation time.
    pub fn platform_trustee_policy_pubkey_bytes(&self) -> Result<[u8; 32], PlatformReleaseError> {
        let bytes = hex32(
            "platform_trustee_policy_pubkey_hex",
            &self.platform_trustee_policy_pubkey_hex,
        )?;
        require_ed25519_point("platform_trustee_policy_pubkey_hex", &bytes)?;
        Ok(bytes)
    }

    /// Effective LUKS2 header-seal rollout claim: the signed value when the
    /// release carries one, otherwise the rollout-window default. Only ever
    /// read after [`verify_envelope`] / [`validate_release_payload`], which
    /// pin the value to `"adopt"` / `"required"`.
    pub fn luks2_header_seal_claim(&self) -> String {
        if self.luks2_header_seal.is_empty() {
            return "adopt".to_string();
        }
        self.luks2_header_seal.clone()
    }
}

impl PlatformReleaseEnvelope {
    pub fn load_verified() -> Result<Self, PlatformReleaseError> {
        let override_path = std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let raw = match &override_path {
            Some(path) => std::fs::read_to_string(Path::new(path))?,
            None => BUNDLED_PLATFORM_RELEASE.to_string(),
        };
        Self::load_verified_from_raw(&raw, override_path.is_some())
    }

    fn load_verified_from_raw(
        raw: &str,
        override_active: bool,
    ) -> Result<Self, PlatformReleaseError> {
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(raw)?;
        verify_envelope(envelope.clone())?;
        if override_active {
            enforce_release_not_older_than_bundled(&envelope.payload)?;
        }
        Ok(envelope)
    }
}

/// Reject `release` when it is older than the release compiled into this
/// binary. Ordering by the signed creation timestamp;
/// `platform_release_version` is opaque, so distinct releases at the same
/// timestamp are unorderable and fail closed rather than using the
/// identifier as a tiebreak. A malformed bundled baseline also fails closed
/// rather than silently disabling the check.
pub fn enforce_release_not_older_than_bundled(
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    let bundled: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE)?;
    let candidate_ts = parse_release_timestamp(&release.created_at)?;
    let bundled_ts = parse_release_timestamp(&bundled.payload.created_at)?;
    if candidate_ts < bundled_ts
        || (candidate_ts == bundled_ts
            && canonical_platform_release_bytes(release)?
                != canonical_platform_release_bytes(&bundled.payload)?)
    {
        return Err(PlatformReleaseError::DowngradeRefused {
            override_version: release.platform_release_version.clone(),
            override_created: release.created_at.clone(),
            bundled_version: bundled.payload.platform_release_version.clone(),
            bundled_created: bundled.payload.created_at.clone(),
        });
    }
    Ok(())
}

fn parse_release_timestamp(
    value: &str,
) -> Result<chrono::DateTime<chrono::FixedOffset>, PlatformReleaseError> {
    chrono::DateTime::parse_from_rfc3339(value).map_err(|error| {
        PlatformReleaseError::InvalidField {
            field: "created_at",
            message: format!("must be RFC3339: {error}"),
        }
    })
}

pub fn verify_envelope(
    envelope: PlatformReleaseEnvelope,
) -> Result<PlatformRelease, PlatformReleaseError> {
    #[cfg(test)]
    let configured_root = option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
        .unwrap_or(TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX);
    #[cfg(not(test))]
    let configured_root = option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
        .ok_or(PlatformReleaseError::MissingRootPubkey)?;
    let pinned = hex32("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX", configured_root)?;
    let signing = hex32("signing_pubkey", &envelope.signing_pubkey)?;
    if signing != pinned {
        return Err(PlatformReleaseError::RootMismatch {
            pinned: hex::encode(pinned),
            signing: hex::encode(signing),
        });
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
    refuse_fixture_keys_outside_fixture_root(&envelope.payload, &signing)?;
    validate_release_payload(&envelope.payload)?;
    Ok(envelope.payload)
}

/// cap#118: the dev-fixture trustee policy key's seed is public (c1*32,
/// committed with the generator). A non-fixture root must never sign a
/// release that pins it in either key slot: while both keys are pinned,
/// policy signatures verify against the signing-service key (#217), and
/// once the trustee key becomes the policy authority its slot matters
/// directly — a public-seed key in either slot would let anyone with the
/// repo forge policy envelopes the TEE accepts. Mirrored verbatim in
/// enclava-cli (keep both in sync).
pub fn refuse_fixture_keys_outside_fixture_root(
    release: &PlatformRelease,
    signing_pubkey: &[u8; 32],
) -> Result<(), PlatformReleaseError> {
    if *signing_pubkey == fixture_root_pubkey() {
        return Ok(());
    }
    for (field, value) in [
        (
            "platform_trustee_policy_pubkey_hex",
            &release.platform_trustee_policy_pubkey_hex,
        ),
        (
            "signing_service_pubkey_hex",
            &release.signing_service_pubkey_hex,
        ),
    ] {
        if hex::decode(value)? == fixture_trustee_policy_pubkey() {
            return Err(PlatformReleaseError::InvalidField {
                field,
                message:
                    "dev-fixture trustee policy key is only allowed under the dev fixture root"
                        .to_string(),
            });
        }
    }
    Ok(())
}

pub fn canonical_platform_release_bytes(
    release: &PlatformRelease,
) -> Result<Vec<u8>, PlatformReleaseError> {
    let signing_service_pubkey = hex32(
        "signing_service_pubkey_hex",
        &release.signing_service_pubkey_hex,
    )?;
    let platform_trustee_policy_pubkey = release.platform_trustee_policy_pubkey_bytes()?;
    let policy_template_sha256 = release.policy_template_sha256_bytes()?;
    let expected_firmware_measurement = release.expected_firmware_measurement_bytes()?;
    let mut records: Vec<(&str, &[u8])> = vec![
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
        (
            "platform_trustee_policy_pubkey",
            &platform_trustee_policy_pubkey,
        ),
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
    ];
    // The seal-rollout claim is signed when present (cap#244 review), but
    // only then: releases signed before the field existed carry no such
    // record and must keep verifying byte-for-byte, so the record is
    // emitted exactly when the payload carries a non-empty value. A
    // tampered or stripped value changes the signed bytes and fails
    // verification.
    if !release.luks2_header_seal.is_empty() {
        records.push(("luks2_header_seal", release.luks2_header_seal.as_bytes()));
    }
    records.push(("created_at", release.created_at.as_bytes()));
    Ok(ce_v1_bytes(&records))
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
    // The signing-service bearer token must not transit cleartext
    // off-cluster; reject at release-validation time so the failure names the
    // signed field (SigningServiceClient re-checks as a backstop).
    if signing_url.scheme() == "http"
        && !crate::signing_service::plain_http_host_allowed(signing_url.host_str())
    {
        return Err(PlatformReleaseError::InvalidField {
            field: "signing_service_url",
            message: "http scheme is only allowed for loopback/cluster-internal hosts".to_string(),
        });
    }
    hex32(
        "signing_service_pubkey_hex",
        &release.signing_service_pubkey_hex,
    )?;
    let platform_trustee_policy_pubkey = release.platform_trustee_policy_pubkey_bytes()?;
    if platform_trustee_policy_pubkey == release.signing_service_pubkey_bytes()? {
        return Err(PlatformReleaseError::InvalidField {
            field: "platform_trustee_policy_pubkey_hex",
            message: "platform trustee policy key must be distinct from the signing-service key (two trust domains must not share one key)".to_string(),
        });
    }
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
    if kbs_url.scheme() != "https" {
        return Err(PlatformReleaseError::InvalidField {
            field: "trustee_kbs_url",
            message: "scheme must be https".to_string(),
        });
    }
    let tls_mode = release
        .tenant_caddy_tls_mode
        .parse::<enclava_engine::types::CaddyTlsMode>()
        .map_err(|err| PlatformReleaseError::InvalidField {
            field: "tenant_caddy_tls_mode",
            message: err,
        })?;
    if tls_mode == enclava_engine::types::CaddyTlsMode::Internal {
        return Err(PlatformReleaseError::InvalidField {
            field: "tenant_caddy_tls_mode",
            message: "internal mode is only allowed for dev fixtures/local tests".to_string(),
        });
    }
    let acme_url = reqwest::Url::parse(&release.tenant_caddy_acme_ca).map_err(|err| {
        PlatformReleaseError::InvalidField {
            field: "tenant_caddy_acme_ca",
            message: err.to_string(),
        }
    })?;
    // The tenant Caddyfile is rendered from this value; a cleartext ACME
    // directory URL would leak ACME account credentials and challenge
    // traffic. Mirror of the KBS URL rule.
    if acme_url.scheme() != "https" {
        return Err(PlatformReleaseError::InvalidField {
            field: "tenant_caddy_acme_ca",
            message: "scheme must be https".to_string(),
        });
    }
    // Codex P1 (cap#165): the value is interpolated VERBATIM into the
    // tenant Caddyfile. Url::parse scheme checks (and any prefix-only
    // check) are NOT the renderer's predicate — `HTTPS://…`, `;`,
    // `{`/`}`, quotes, tabs/newlines, and non-ASCII all parse as valid
    // https URLs but fail Caddyfile rendering. Apply the engine's exact
    // validator so a release is rejected if its ACME-mode render would fail.
    if let Err(err) =
        enclava_engine::manifest::ingress::validate_https_url(release.tenant_caddy_acme_ca.trim())
    {
        return Err(PlatformReleaseError::InvalidField {
            field: "tenant_caddy_acme_ca",
            message: format!("must be renderable into the tenant Caddyfile ({err})"),
        });
    }
    if release.genpolicy_version.trim().is_empty()
        || release.genpolicy_version.contains("unconfigured")
        || release.genpolicy_version.contains("unpinned")
    {
        return Err(PlatformReleaseError::InvalidField {
            field: "genpolicy_version",
            message: "must be a concrete pinned generator version".to_string(),
        });
    }
    if !release.luks2_header_seal.is_empty()
        && !matches!(release.luks2_header_seal.as_str(), "adopt" | "required")
    {
        return Err(PlatformReleaseError::InvalidField {
            field: "luks2_header_seal",
            message: "expected \"adopt\" or \"required\"".to_string(),
        });
    }
    chrono::DateTime::parse_from_rfc3339(&release.created_at).map_err(|error| {
        PlatformReleaseError::InvalidField {
            field: "created_at",
            message: format!("must be RFC3339: {error}"),
        }
    })?;
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

/// A pin that the consumers cannot parse must fail release ingestion, not
/// tenant boots: enclava-init's `parse_pubkey` calls
/// `VerifyingKey::from_bytes` and aborts verification on failure, so one
/// malformed key in a signed release would prevent every workload from
/// starting. Verify the exact Ed25519 point encoding the consumers enforce
/// (codex cap#218 P2).
fn require_ed25519_point(
    field: &'static str,
    bytes: &[u8; 32],
) -> Result<(), PlatformReleaseError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|err| {
        PlatformReleaseError::InvalidField {
            field,
            message: format!("not a valid Ed25519 public key: {err}"),
        }
    })?;
    // Small-order keys (identity, 00*32, torsion points) provide no
    // unforgeability: policy acceptance uses verify(), not verify_strict(),
    // and a zero signature verifies against a small-order key for a large
    // share of messages. Reject at ingestion so a placeholder pin cannot
    // accept forged policy artifacts (mirror check in enclava-init
    // parse_pubkey).
    if key.is_weak() {
        return Err(PlatformReleaseError::InvalidField {
            field,
            message: "Ed25519 public key has small order and provides no unforgeability"
                .to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_reports_mismatched_declared_root() {
        let pinned = option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
            .unwrap_or(TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX);
        let mut foreign_root = hex32("test root", pinned).unwrap();
        foreign_root[0] ^= 1;
        let declared = hex::encode(foreign_root);
        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        envelope.signing_pubkey = declared.clone();

        let error = verify_envelope(envelope).expect_err("a foreign root must fail verification");
        assert!(matches!(error, PlatformReleaseError::RootMismatch { .. }));
        let message = error.to_string();
        assert!(message.contains(&pinned.to_ascii_lowercase()));
        assert!(message.contains(&declared));
    }

    #[test]
    fn fixture_trustee_policy_key_is_rejected_under_a_non_fixture_root() {
        // cap#118: the dev-fixture trustee seed is public (c1*32). A
        // production root signing a release that still pins the fixture
        // trustee key would let anyone with the repo forge policies.
        // The gate sits in verify_envelope: with a fixture root it passes
        // (the bundled envelope proves that), so exercise it by hand with a
        // non-fixture signing root.
        // NOTE: this API-side twin only asserts the gate's constants; the
        // full negative coverage (re-signing the envelope under a production
        // root and asserting verify_envelope rejects) lives in the CLI
        // crate's twin test — fixture_trustee_policy_key_is_rejected_...
        // in crates/enclava-cli/src/platform_release.rs. Keep both in sync
        // (the gate logic and constants are deliberately duplicated).
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        assert_eq!(
            raw.payload.platform_trustee_policy_pubkey_hex,
            DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX
        );
        assert_ne!(
            fixture_root_pubkey(),
            [0u8; 32],
            "sanity: fixture root is a real key"
        );
        // The gate condition itself: non-fixture root + fixture trustee key.
        let trustee = fixture_trustee_policy_pubkey();
        assert_ne!(fixture_root_pubkey().to_vec(), trustee);
        // Real negatives through the same gate verify_envelope calls (the
        // full re-sign path lives in the CLI crate's twin tests): a
        // non-fixture root must be refused in EITHER slot, while the
        // fixture root may pin the fixture trustee key.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let prod_root = [0x42u8; 32];
        let err = refuse_fixture_keys_outside_fixture_root(&raw.payload, &prod_root).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "platform_trustee_policy_pubkey_hex"),
            "expected trustee-slot fixture rejection, got: {err:?}"
        );
        let mut payload = raw.payload.clone();
        payload.signing_service_pubkey_hex = DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX.to_string();
        payload.platform_trustee_policy_pubkey_hex = "bb".repeat(32);
        let err = refuse_fixture_keys_outside_fixture_root(&payload, &prod_root).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "signing_service_pubkey_hex"),
            "expected signing-slot fixture rejection, got: {err:?}"
        );
        refuse_fixture_keys_outside_fixture_root(&raw.payload, &fixture_root_pubkey()).unwrap();
    }

    #[test]
    fn fixture_root_is_detected_case_insensitively() {
        assert!(is_forbidden_fixture_root(
            TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX
        ));
        assert!(is_forbidden_fixture_root(
            &TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX.to_ascii_uppercase()
        ));
        assert!(!is_forbidden_fixture_root(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
    }

    #[test]
    fn hex32_root_shape_is_validated() {
        assert!(is_hex32_root(
            "0000000000000000000000000000000000000000000000000000000000000001"
        ));
        // Uppercase hex is still a valid key (hex::decode accepts it).
        assert!(is_hex32_root(
            "000000000000000000000000000000000000000000000000000000000000000A"
        ));
        assert!(!is_hex32_root(""));
        assert!(!is_hex32_root(
            "000000000000000000000000000000000000000000000000000000000000001"
        ));
        assert!(!is_hex32_root(
            "00000000000000000000000000000000000000000000000000000000000000010"
        ));
        assert!(!is_hex32_root(
            "zzzz000000000000000000000000000000000000000000000000000000000001"
        ));
    }

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

    #[test]
    fn bundled_release_carries_a_distinct_platform_trustee_policy_key() {
        // cap#118: the in-TEE policy authority and the off-cluster signing
        // service are two trust domains. The bundled signed release must pin
        // a dedicated trustee policy key that differs from the
        // signing-service key.
        let release = PlatformRelease::load_verified().unwrap();
        let trustee = release.platform_trustee_policy_pubkey_bytes().unwrap();
        let signing = release.signing_service_pubkey_bytes().unwrap();
        assert_ne!(trustee, signing);
    }

    #[test]
    fn release_payload_rejects_collapsed_trustee_and_signing_keys() {
        // A release (hand-crafted or mis-rotated) that collapses the two
        // trust domains onto one key must fail validation, not fall back.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.platform_trustee_policy_pubkey_hex = payload.signing_service_pubkey_hex.clone();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "platform_trustee_policy_pubkey_hex")
        );
    }

    #[test]
    fn release_payload_rejects_non_point_policy_keys() {
        // codex cap#218 P2: both pins are parsed with
        // VerifyingKey::from_bytes by the consumers (enclava-init
        // parse_pubkey) and abort verification on failure, so a pin that is
        // not a valid Ed25519 point would brick every workload at boot.
        // Ingestion must reject it instead. The compressed encoding of a
        // y with no Edwards point on the curve (e.g. y = 2 for
        // edwards25519) is the canonical rejection case.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let non_point = format!("02{}", "00".repeat(31));
        let mut payload = raw.payload.clone();
        payload.platform_trustee_policy_pubkey_hex = non_point.clone();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, message }
                if field == "platform_trustee_policy_pubkey_hex"
                    && message.contains("not a valid Ed25519 public key"))
        );
        let mut payload = raw.payload;
        payload.signing_service_pubkey_hex = non_point;
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, message }
                if field == "signing_service_pubkey_hex"
                    && message.contains("not a valid Ed25519 public key"))
        );
    }

    #[test]
    fn release_payload_rejects_small_order_policy_keys() {
        // cap#218 follow-up: policy acceptance uses verify(), not
        // verify_strict(), and a zero signature verifies against a
        // small-order key (e.g. 00*32) for a large share of messages —
        // such a pin accepts forged policy artifacts.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload.clone();
        payload.signing_service_pubkey_hex = "00".repeat(32);
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(&err, PlatformReleaseError::InvalidField { field, message }
                if *field == "signing_service_pubkey_hex" && message.contains("small order")),
            "unexpected error: {err:?}"
        );
        let mut payload = raw.payload;
        payload.platform_trustee_policy_pubkey_hex = "00".repeat(32);
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(&err, PlatformReleaseError::InvalidField { field, message }
                if *field == "platform_trustee_policy_pubkey_hex" && message.contains("small order")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn release_payload_rejects_http_kbs_url() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.trustee_kbs_url = "http://kbs.example.test:8080".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "trustee_kbs_url")
        );
    }

    #[test]
    fn release_payload_rejects_internal_caddy_tls_mode() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.tenant_caddy_tls_mode = "internal".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_tls_mode")
        );
    }

    #[test]
    fn release_payload_rejects_unparseable_created_at() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.created_at = "not-a-timestamp".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "created_at")
        );
    }

    #[test]
    fn release_payload_rejects_http_acme_ca() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.tenant_caddy_acme_ca =
            "http://acme-staging-v02.api.letsencrypt.org/directory".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca")
        );
    }

    #[test]
    fn release_payload_rejects_non_http_acme_ca() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.tenant_caddy_acme_ca = "ftp://acme.example.test/directory".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca")
        );
    }

    #[test]
    fn release_payload_rejects_uppercase_scheme_acme_ca() {
        // Codex P1 (cap#165): `HTTPS://` parses with scheme https, but the
        // enclava-engine Caddyfile renderer interpolates the value verbatim
        // and requires the literal lowercase `https://` prefix — accepting
        // it would pass release validation and then fail ACME-mode rendering.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.tenant_caddy_acme_ca = "HTTPS://acme.example.test/directory".to_string();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca"),
            "uppercase-scheme ACME CA must be rejected: {err:?}"
        );
    }

    #[test]
    fn release_payload_rejects_url_parseable_but_unrenderable_acme_ca() {
        // Codex P1 (cap#165, reviewer follow-up): these all pass
        // Url::parse with scheme https yet fail the Caddyfile renderer's
        // predicate, so a prefix-only acceptance check is insufficient.
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        for bad in [
            "https://acme.example.test/directory;extra",
            "https://acme.example.test/dir{x}",
            "https://acme.example.test/dir}x",
            "https://acme.example.test/dir`x",
            "https://acme.example.test/dir\"x",
            "https://acme.example.test/dir'x",
            "https://acme.example.test/directory\tx",
            "https://acme.example.test/directory\nx",
            "https://exämple.test/directory",
        ] {
            let mut payload = raw.payload.clone();
            payload.tenant_caddy_acme_ca = bad.to_string();
            // Sanity: the url crate DOES accept these as https (that is
            // the trap the shared renderer predicate closes).
            assert!(
                reqwest::Url::parse(bad).is_ok_and(|u| u.scheme() == "https"),
                "sample {bad:?} must parse as https for this test to pin the trap"
            );
            let err = validate_release_payload(&payload).unwrap_err();
            assert!(
                matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca"),
                "unrenderable ACME CA {bad:?} must be rejected: {err:?}"
            );
        }
    }

    fn bundled_payload() -> PlatformRelease {
        serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
            .unwrap()
            .payload
    }

    #[test]
    fn bundled_not_older_than_itself_and_newer_passes() {
        let bundled = bundled_payload();
        assert!(enforce_release_not_older_than_bundled(&bundled).is_ok());

        let mut newer = bundled.clone();
        newer.created_at = "2999-01-01T00:00:00Z".to_string();
        newer.platform_release_version = "dev-2999.01.01-x".to_string();
        assert!(enforce_release_not_older_than_bundled(&newer).is_ok());
    }

    #[test]
    fn older_than_bundle_is_refused_regardless_of_version_suffix() {
        let mut stale = bundled_payload();
        stale.created_at = "2020-01-01T00:00:00Z".to_string();
        stale.platform_release_version = "zzz-newer-suffix".to_string();
        assert!(matches!(
            enforce_release_not_older_than_bundled(&stale),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn equal_timestamp_divergent_version_fails_closed() {
        let mut divergent = bundled_payload();
        divergent.platform_release_version =
            format!("{}-divergent", divergent.platform_release_version);
        assert!(matches!(
            enforce_release_not_older_than_bundled(&divergent),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn unparseable_override_timestamp_is_rejected_not_ignored() {
        let mut broken = bundled_payload();
        broken.created_at = "not-a-timestamp".to_string();
        assert!(matches!(
            enforce_release_not_older_than_bundled(&broken),
            Err(PlatformReleaseError::InvalidField {
                field: "created_at",
                ..
            })
        ));
    }

    fn resigned_envelope_with_created_at(created_at: &str) -> String {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[0xc0; 32]);
        let mut envelope =
            serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE).unwrap();
        envelope.payload.created_at = created_at.to_string();
        envelope.payload.platform_release_version = format!("release-{created_at}");
        let canonical = canonical_platform_release_bytes(&envelope.payload).unwrap();
        envelope.signature = hex::encode(key.sign(&canonical).to_bytes());
        envelope.signing_pubkey = hex::encode(key.verifying_key().as_bytes());
        serde_json::to_string(&envelope).unwrap()
    }

    fn sign_envelope_with_dev_key(payload: PlatformRelease) -> PlatformReleaseEnvelope {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[0xc0; 32]);
        let canonical = canonical_platform_release_bytes(&payload).unwrap();
        PlatformReleaseEnvelope {
            payload,
            signature: hex::encode(key.sign(&canonical).to_bytes()),
            signing_pubkey: hex::encode(key.verifying_key().as_bytes()),
        }
    }

    /// cap#244: the `luks2_header_seal` rollout claim is part of the signed
    /// bytes whenever the payload carries one — a tampered or stripped
    /// value must break the signature (API twin, kept in lockstep with the
    /// CLI twin's identically named test).
    #[test]
    fn seal_rollout_claim_is_covered_by_the_signature() {
        let mut payload = bundled_payload();
        payload.luks2_header_seal = "required".to_string();
        let envelope = sign_envelope_with_dev_key(payload);
        let verified = verify_envelope(envelope.clone()).unwrap();
        assert_eq!(verified.luks2_header_seal_claim(), "required");

        let mut tampered = envelope.clone();
        tampered.payload.luks2_header_seal = "adopt".to_string();
        let err = verify_envelope(tampered).expect_err("flip must break the signature");
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));

        let mut stripped = envelope;
        stripped.payload.luks2_header_seal = String::new();
        let err =
            verify_envelope(stripped).expect_err("stripping the field must break the signature");
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));
    }

    /// cap#244: releases signed before the field existed (no record in the
    /// signed bytes) must keep verifying byte-for-byte and resolve to the
    /// rollout-window default.
    #[test]
    fn pre_field_release_still_verifies_and_defaults_to_adopt() {
        let payload = bundled_payload();
        let mut value = serde_json::to_value(&payload).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("luks2_header_seal")
            .unwrap();
        let payload: PlatformRelease = serde_json::from_value(value).unwrap();
        assert!(payload.luks2_header_seal.is_empty());

        let envelope = sign_envelope_with_dev_key(payload);
        let verified = verify_envelope(envelope).expect("pre-field envelope must keep verifying");
        assert_eq!(verified.luks2_header_seal_claim(), "adopt");
    }

    #[test]
    fn release_payload_rejects_unknown_seal_rollout_value() {
        let mut payload = bundled_payload();
        payload.luks2_header_seal = "banana".to_string();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "luks2_header_seal")
        );
    }

    #[test]
    fn valid_signature_does_not_admit_a_release_older_than_the_bundle() {
        let raw = resigned_envelope_with_created_at("2020-01-01T00:00:00Z");
        verify_envelope(serde_json::from_str(&raw).unwrap()).unwrap();
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(&raw, true),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn newer_override_does_not_prevent_restoring_an_older_valid_override_or_bundle() {
        for timestamp in [
            "2999-01-01T00:00:00Z",
            "2999-01-02T00:00:00Z",
            "2999-01-01T00:00:00Z",
        ] {
            let raw = resigned_envelope_with_created_at(timestamp);
            let loaded = PlatformReleaseEnvelope::load_verified_from_raw(&raw, true).unwrap();
            assert_eq!(loaded.payload.created_at, timestamp);
        }
        PlatformReleaseEnvelope::load_verified_from_raw(BUNDLED_PLATFORM_RELEASE, false).unwrap();
        PlatformReleaseEnvelope::load_verified_from_raw(BUNDLED_PLATFORM_RELEASE, true).unwrap();
    }

    #[test]
    fn equal_timestamp_divergent_payload_fails_closed() {
        let mut divergent = bundled_payload();
        divergent.trustee_kbs_url = "https://different.example".into();
        assert!(matches!(
            enforce_release_not_older_than_bundled(&divergent),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }
}
