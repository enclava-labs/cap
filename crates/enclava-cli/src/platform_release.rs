//! Signed platform-release metadata bundled with the CLI.
//!
//! The descriptor signer must not learn release anchors from the CAP API or
//! environment. It verifies this artifact against a pinned Ed25519 release
//! root, then uses the signed template/image/measurement constants to derive
//! deployment descriptors.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
use enclava_common::release_profiles::{self, ProfileError, ReleaseProfile, ReleaseProfiles};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(test)]
const BUNDLED_PLATFORM_RELEASE: &str = include_str!("../platform-release.json");

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

#[cfg(test)]
const TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str = release_profiles::FIXTURE_ROOT;

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
    #[error(transparent)]
    Profile(#[from] ProfileError),
    #[error(
        "platform release signature pubkey is not the pinned root: this build pins {pinned}, the release declares {signing}; verify the target platform and, if this is an expected root rotation, update this CLI from a trusted source"
    )]
    RootMismatch { pinned: String, signing: String },
    #[error("platform release signature verification failed: {0}")]
    BadSignature(String),
    #[error("policy_template_sha256 does not match policy_template_text")]
    TemplateHashMismatch,
    #[error(
        "platform release downgrade refused: override is {override_version} ({override_created}) but the CLI bundles {bundled_version} ({bundled_created}); refusing a validly-signed stale release"
    )]
    DowngradeRefused {
        override_version: String,
        override_created: String,
        bundled_version: String,
        bundled_created: String,
    },
    #[error(
        "platform release downgrade refused: API {api} previously served {last_version} ({last_created}) but now offers {incoming_version} ({incoming_created}); refusing a validly-signed stale release"
    )]
    ApiDowngradeRefused {
        api: String,
        incoming_version: String,
        incoming_created: String,
        last_version: String,
        last_created: String,
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
    // Only a compiled-in pre-field downgrade floor may omit this. Runtime
    // releases still require a distinct policy authority key.
    #[serde(default)]
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
    pub fn load_verified(api_url: &str) -> Result<Self, PlatformReleaseError> {
        Ok(PlatformReleaseEnvelope::load_verified(api_url)?.payload)
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
    pub fn load_verified(api_url: &str) -> Result<Self, PlatformReleaseError> {
        let profile = release_profiles::bundled()?.for_api(api_url)?;
        let override_path = std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let override_raw = override_path
            .as_ref()
            .map(|path| std::fs::read_to_string(Path::new(path)))
            .transpose()?;
        let raw = override_raw.as_deref().unwrap_or(profile.baseline.get());
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(raw)?;
        verify_envelope(envelope.clone(), profile)?;
        if override_path.is_some() {
            enforce_release_not_older_than_bundled(&envelope.payload, profile)?;
        }
        Ok(envelope)
    }
}

/// File overrides use the selected profile's signed floor. API-served releases
/// instead retain their per-origin persisted floor, allowing staggered promotion.
pub fn enforce_release_not_older_than_bundled(
    release: &PlatformRelease,
    profile: &ReleaseProfile,
) -> Result<(), PlatformReleaseError> {
    let bundled =
        verify_signed_baseline_with_root(profile.baseline.get(), &profile.root_pubkey_hex)?;
    let candidate_ts = parse_release_timestamp(&release.created_at)?;
    let bundled_ts = parse_release_timestamp(&bundled.created_at)?;
    if candidate_ts < bundled_ts
        || (candidate_ts == bundled_ts
            && canonical_platform_release_bytes(release)? != bundled.canonical_bytes)
    {
        return Err(PlatformReleaseError::DowngradeRefused {
            override_version: release.platform_release_version.clone(),
            override_created: release.created_at.clone(),
            bundled_version: bundled.platform_release_version,
            bundled_created: bundled.created_at,
        });
    }
    Ok(())
}

/// Ordering by the signed creation timestamp. `platform_release_version` is
/// opaque, so distinct releases at the same timestamp are unorderable and
/// fail closed rather than using the identifier as a tiebreak.
#[cfg(test)]
fn release_is_older(
    candidate: &PlatformRelease,
    bundled: &PlatformRelease,
) -> Result<bool, PlatformReleaseError> {
    release_pair_is_older(
        (&candidate.platform_release_version, &candidate.created_at),
        (&bundled.platform_release_version, &bundled.created_at),
    )
}

/// Same ordering on bare (version, created_at) pairs — shared by the
/// API-baseline store, which persists only the pair.
fn release_pair_is_older(
    candidate: (&str, &str),
    baseline: (&str, &str),
) -> Result<bool, PlatformReleaseError> {
    let candidate_ts = parse_release_timestamp(candidate.1)?;
    let baseline_ts = parse_release_timestamp(baseline.1)?;
    Ok(candidate_ts < baseline_ts || (candidate_ts == baseline_ts && candidate.0 != baseline.0))
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
    profile: &ReleaseProfile,
) -> Result<PlatformRelease, PlatformReleaseError> {
    let release = verify_envelope_with_root(envelope, &profile.root_pubkey_hex)?;
    profile.require_installation_identity(
        &release.signing_service_pubkey_hex,
        &release.trustee_kbs_ca_cert_pem,
    )?;
    Ok(release)
}

/// Offline signature verification against an independently supplied root.
pub fn verify_envelope_with_root(
    envelope: PlatformReleaseEnvelope,
    root_hex: &str,
) -> Result<PlatformRelease, PlatformReleaseError> {
    let canonical = canonical_platform_release_bytes(&envelope.payload)?;
    let signing = verify_root_signature(&envelope, root_hex, &canonical)?;
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

/// A verified rollback floor cannot be used as runtime release authority.
pub struct VerifiedReleaseBaseline {
    pub platform_release_version: String,
    pub created_at: String,
    canonical_bytes: Vec<u8>,
}

/// Verify the image's signed downgrade floor. Only this gate understands
/// pre-trustee signed bytes; runtime envelopes still use verify_envelope.
pub fn verify_signed_baseline_with_root(
    raw: &str,
    root_hex: &str,
) -> Result<VerifiedReleaseBaseline, PlatformReleaseError> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let pre_trustee = value
        .get("payload")
        .and_then(|payload| payload.get("platform_trustee_policy_pubkey_hex"))
        .is_none();
    let envelope: PlatformReleaseEnvelope = serde_json::from_value(value)?;
    if !pre_trustee {
        verify_envelope_with_root(envelope.clone(), root_hex)?;
        return Ok(VerifiedReleaseBaseline {
            platform_release_version: envelope.payload.platform_release_version.clone(),
            created_at: envelope.payload.created_at.clone(),
            canonical_bytes: canonical_platform_release_bytes(&envelope.payload)?,
        });
    }
    let canonical = canonical_baseline_bytes(&envelope.payload)?;
    let signing = verify_root_signature(&envelope, root_hex, &canonical)?;
    if envelope.payload.schema_version != "v1" {
        return Err(PlatformReleaseError::InvalidField {
            field: "schema_version",
            message: "expected v1".to_string(),
        });
    }
    parse_release_timestamp(&envelope.payload.created_at)?;
    let actual_template_hash = hex::encode(Sha256::digest(
        envelope.payload.policy_template_text.as_bytes(),
    ));
    if actual_template_hash != envelope.payload.policy_template_sha256 {
        return Err(PlatformReleaseError::TemplateHashMismatch);
    }
    refuse_fixture_keys_outside_fixture_root(&envelope.payload, &signing)?;
    Ok(VerifiedReleaseBaseline {
        platform_release_version: envelope.payload.platform_release_version,
        created_at: envelope.payload.created_at,
        canonical_bytes: canonical,
    })
}

pub fn verify_profile_bundle(
    raw: &str,
    strict: bool,
) -> Result<ReleaseProfiles, PlatformReleaseError> {
    let profiles = ReleaseProfiles::parse(raw, strict)?;
    for (_, profile) in profiles.iter() {
        verify_signed_baseline_with_root(profile.baseline.get(), &profile.root_pubkey_hex)?;
    }
    Ok(profiles)
}

fn verify_root_signature(
    envelope: &PlatformReleaseEnvelope,
    root_hex: &str,
    canonical: &[u8],
) -> Result<[u8; 32], PlatformReleaseError> {
    let pinned = hex32("root_pubkey_hex", root_hex)?;
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
    verifying_key
        .verify(canonical, &signature)
        .map_err(|err| PlatformReleaseError::BadSignature(err.to_string()))?;
    Ok(signing)
}

/// cap#118: the dev-fixture trustee policy key's seed is public (c1*32,
/// committed with the generator). A non-fixture root must never sign a
/// release that pins it in either key slot: while both keys are pinned,
/// policy signatures verify against the signing-service key (#217), and
/// once the trustee key becomes the policy authority its slot matters
/// directly — a public-seed key in either slot would let anyone with the
/// repo forge policy envelopes the TEE accepts. Shared by
/// `verify_envelope_with_root` and the offline signing example so every
/// signer and verifier enforces one gate.
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
    canonical_release_bytes(release, false)
}

fn canonical_baseline_bytes(release: &PlatformRelease) -> Result<Vec<u8>, PlatformReleaseError> {
    canonical_release_bytes(
        release,
        release.platform_trustee_policy_pubkey_hex.is_empty(),
    )
}

fn canonical_release_bytes(
    release: &PlatformRelease,
    pre_trustee: bool,
) -> Result<Vec<u8>, PlatformReleaseError> {
    let signing_service_pubkey = hex32(
        "signing_service_pubkey_hex",
        &release.signing_service_pubkey_hex,
    )?;
    let platform_trustee_policy_pubkey = if pre_trustee {
        None
    } else {
        Some(release.platform_trustee_policy_pubkey_bytes()?)
    };
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
    if let Some(ref platform_trustee_policy_pubkey) = platform_trustee_policy_pubkey {
        records.insert(
            5,
            (
                "platform_trustee_policy_pubkey",
                platform_trustee_policy_pubkey,
            ),
        );
    }
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

fn hex32(field: &'static str, value: &str) -> Result<[u8; 32], PlatformReleaseError> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PlatformReleaseError::InvalidField {
            field,
            message: format!("expected 32 bytes, got {}", bytes.len()),
        })
}

/// A pin that the consumers cannot parse must fail release ingestion (and
/// ceremony signing), not tenant boots: enclava-init's `parse_pubkey` calls
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

/// Validates a release payload's semantic invariants (key shape, key
/// distinctness, URL schemes, digest pinning). Public so the offline
/// ceremony example can reject an invalid payload BEFORE signing it.
pub fn validate_release_payload(release: &PlatformRelease) -> Result<(), PlatformReleaseError> {
    if release.schema_version != "v1" {
        return Err(PlatformReleaseError::InvalidField {
            field: "schema_version",
            message: "expected v1".to_string(),
        });
    }
    // Match the API's payload validation exactly: a release the API would
    // refuse at startup must never pass the CLI-side publish gates.
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
    // signed field.
    if signing_url.scheme() == "http"
        && !enclava_common::hostnames::plain_http_host_allowed(signing_url.host_str())
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
    // Cleartext ACME directory URLs would leak ACME account credentials;
    // same rule as the KBS URL.
    if acme_url.scheme() != "https" {
        return Err(PlatformReleaseError::InvalidField {
            field: "tenant_caddy_acme_ca",
            message: "scheme must be https".to_string(),
        });
    }
    // Codex P1 (cap#165): parity with the API validator — apply the
    // enclava-engine Caddyfile renderer's EXACT predicate (not just a
    // scheme or prefix check), so a release whose ACME URL would fail
    // rendering is refused before it is ever offered or accepted.
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
    parse_release_timestamp(&release.created_at)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_profile() -> &'static ReleaseProfile {
        release_profiles::bundled().unwrap().named("dev").unwrap()
    }

    #[test]
    fn shared_root_does_not_authorize_a_different_installation() {
        let profiles = verify_profile_bundle(release_profiles::BUNDLED_PROFILES, false).unwrap();
        let preprod = profiles.named("preprod").unwrap();
        let production = profiles.named("production").unwrap();
        assert_eq!(preprod.root_pubkey_hex, production.root_pubkey_hex);
        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(preprod.baseline.get()).unwrap();
        envelope.payload.created_at = "2099-01-01T00:00:00Z".into();
        let envelope = sign_with_dev_fixture_key(envelope.payload);
        verify_envelope(envelope.clone(), preprod).unwrap();
        assert!(matches!(
            verify_envelope(envelope, production),
            Err(PlatformReleaseError::Profile(_)),
        ));
    }

    #[test]
    fn api_release_can_predate_profile_floor_but_not_last_seen_release() {
        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(test_profile().baseline.get()).unwrap();
        envelope.payload.created_at = "2020-01-01T00:00:00Z".into();
        let envelope = sign_with_dev_fixture_key(envelope.payload);
        let release = verify_envelope(envelope, test_profile()).unwrap();
        assert!(matches!(
            enforce_release_not_older_than_bundled(&release, test_profile()),
            Err(PlatformReleaseError::DowngradeRefused { .. }),
        ));
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().join("accepted.json");
        let api = "https://cap.dev.enclava.work";
        enforce_release_not_older_than_last_accepted(&store, api, &release).unwrap();
        let current = PlatformRelease::load_verified(api).unwrap();
        enforce_release_not_older_than_last_accepted(&store, api, &current).unwrap();
        assert!(matches!(
            enforce_release_not_older_than_last_accepted(&store, api, &release),
            Err(PlatformReleaseError::ApiDowngradeRefused { .. }),
        ));
    }

    fn release(version: &str, created_at: &str) -> PlatformRelease {
        PlatformRelease {
            schema_version: "v1".into(),
            platform_release_version: version.into(),
            signing_service_url: "https://signing.example".into(),
            signing_service_pubkey_hex: hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[0xd0; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            platform_trustee_policy_pubkey_hex: hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[0xe0; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
            policy_template_id: "t".into(),
            policy_template_sha256: "00".repeat(32),
            policy_template_text: "".into(),
            attestation_proxy_image: "img".into(),
            caddy_ingress_image: "img".into(),
            trustee_kbs_url: "https://kbs.example".into(),
            trustee_kbs_ca_cert_pem: "".into(),
            tenant_caddy_tls_mode: "letsencrypt".into(),
            tenant_caddy_acme_ca: "https://acme-staging.example".into(),
            expected_firmware_measurement: "00".repeat(48),
            expected_runtime_class: "kata-qemu-snp".into(),
            genpolicy_version: "0".into(),
            luks2_header_seal: String::new(),
            created_at: created_at.into(),
        }
    }

    #[test]
    fn release_ordering_uses_the_signed_timestamp_not_the_version_suffix() {
        // Identifiers carry a non-monotonic hash suffix: lexicographic
        // comparison would call the NEWER release (newer timestamp, suffix
        // sorting lower) older, and vice versa.
        let older = release("dev-2026.07.28-proxy-ffffffff", "2026-07-28T00:00:00Z");
        let newer = release("dev-2026.08.15-proxy-00000000", "2026-08-15T00:00:00Z");
        assert!(release_is_older(&older, &newer).unwrap());
        assert!(!release_is_older(&newer, &older).unwrap());
        assert!(!release_is_older(&newer, &newer).unwrap());

        let same_time_a = release("release-ffffffff", "2026-08-15T00:00:00Z");
        let same_time_b = release("release-00000000", "2026-08-15T00:00:00Z");
        assert!(release_is_older(&same_time_a, &same_time_b).unwrap());
        assert!(release_is_older(&same_time_b, &same_time_a).unwrap());
    }

    #[test]
    fn unparseable_candidate_timestamp_is_rejected() {
        let bundled = release("r1", "2026-08-15T00:00:00Z");
        let broken = release("r2", "not-a-timestamp");
        assert!(matches!(
            release_is_older(&broken, &bundled),
            Err(PlatformReleaseError::InvalidField {
                field: "created_at",
                ..
            })
        ));
    }

    #[test]
    fn malformed_baseline_fails_closed_instead_of_resetting_the_high_water_mark() {
        let dir = std::env::temp_dir().join(format!("pr-baseline-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("baselines.json");
        std::fs::write(&store, "{ not json").unwrap();

        let ok_release = release("r9", "2026-09-01T00:00:00Z");
        assert!(
            enforce_release_not_older_than_last_accepted(&store, "https://api", &ok_release)
                .is_err()
        );
        assert!(api_served_release_before(&store, "https://api").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unparseable_baseline_timestamp_is_rejected_without_replacement() {
        let dir = std::env::temp_dir().join(format!("pr-baseline-time-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("baselines.json");
        let baseline = r#"{
            "https://api": {
                "platform_release_version": "r8",
                "created_at": "not-a-timestamp"
            }
        }"#;
        std::fs::write(&store, baseline).unwrap();

        let incoming = release("r9", "2026-09-01T00:00:00Z");
        assert!(matches!(
            enforce_release_not_older_than_last_accepted(&store, "https://api", &incoming),
            Err(PlatformReleaseError::InvalidField {
                field: "created_at",
                ..
            })
        ));
        assert_eq!(std::fs::read_to_string(&store).unwrap(), baseline);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn per_api_baseline_allows_older_than_bundle_but_refuses_api_downgrades() {
        let dir = std::env::temp_dir().join(format!("pr-baseline-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("baselines.json");

        // A preprod API serving an OLDER-than-bundle release is fine the
        // first time (the bundle is not that environment's high-water mark).
        let api_release = release("preprod-2026.07.12-x", "2026-07-12T09:33:00Z");
        enforce_release_not_older_than_last_accepted(&store, "https://preprod.api", &api_release)
            .unwrap();

        // Same release again (idempotent) and a NEWER one both pass.
        enforce_release_not_older_than_last_accepted(&store, "https://preprod.api", &api_release)
            .unwrap();
        let newer = release("preprod-2026.08.01-y", "2026-08-01T00:00:00Z");
        enforce_release_not_older_than_last_accepted(&store, "https://preprod.api", &newer)
            .unwrap();

        let equal_time_divergence = release("preprod-2026.08.01-other", "2026-08-01T00:00:00Z");
        assert!(matches!(
            enforce_release_not_older_than_last_accepted(
                &store,
                "https://preprod.api",
                &equal_time_divergence,
            ),
            Err(PlatformReleaseError::ApiDowngradeRefused { .. })
        ));

        // An older one is refused (replayed stale envelope from the same API).
        let stale = release("preprod-2026.07.30-z", "2026-07-30T00:00:00Z");
        assert!(matches!(
            enforce_release_not_older_than_last_accepted(&store, "https://preprod.api", &stale),
            Err(PlatformReleaseError::ApiDowngradeRefused { .. })
        ));

        // A different API has its own baseline.
        assert!(
            enforce_release_not_older_than_last_accepted(&store, "https://other.api", &stale)
                .is_ok()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn baseline_store_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "pr-baseline-perms-{}-{}",
            std::process::id(),
            line!()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = dir.join("baselines.json");

        let api_release = release("preprod-2026.09.01-x", "2026-09-01T00:00:00Z");
        enforce_release_not_older_than_last_accepted(&store, "https://preprod.api", &api_release)
            .unwrap();

        let mode = std::fs::metadata(&store).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "baseline store must be owner-only");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn api_release_older_than_bundle_is_refused() {
        // The bundled release is current by definition; anything with an
        // older signed timestamp loses regardless of identifier.
        let bundled =
            PlatformReleaseEnvelope::load_verified("https://cap.dev.enclava.work").unwrap();
        let stale = release("zzz-newer-suffix", "2020-01-01T00:00:00Z");
        assert!(matches!(
            enforce_release_not_older_than_bundled(&stale, test_profile()),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
        drop(bundled);
    }

    #[test]
    fn bundled_release_verifies_and_hashes_template() {
        let release = PlatformRelease::load_verified("https://cap.dev.enclava.work").unwrap();
        assert_eq!(release.schema_version, "v1");
        assert_eq!(
            release.policy_template_sha256,
            hex::encode(Sha256::digest(release.policy_template_text.as_bytes()))
        );
        assert!(!release.genpolicy_version.contains("unpinned"));
    }

    #[test]
    fn bundled_release_uses_ghcr_digest_pinned_sidecars() {
        let release = PlatformRelease::load_verified("https://cap.dev.enclava.work").unwrap();
        for image in [release.attestation_proxy_image, release.caddy_ingress_image] {
            assert!(image.starts_with("ghcr.io/enclava-labs/"));
            assert!(image.contains("@sha256:"));
            assert!(!image.contains("ttl.sh/"));
        }
    }

    #[test]
    fn release_payload_rejects_http_acme_ca() {
        let mut payload = serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
            .unwrap()
            .payload;
        payload.tenant_caddy_acme_ca =
            "http://acme-staging-v02.api.letsencrypt.org/directory".into();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca")
        );
    }

    #[test]
    fn release_payload_rejects_uppercase_scheme_acme_ca() {
        // Codex P1 (cap#165): HTTPS:// parses as scheme https but the
        // Caddyfile renderer requires the literal lowercase prefix; the
        // CLI validator must reject before an override is even offered.
        let mut payload = serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
            .unwrap()
            .payload;
        payload.tenant_caddy_acme_ca = "HTTPS://acme.example.test/directory".into();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "tenant_caddy_acme_ca"),
            "uppercase-scheme ACME CA must be rejected: {err:?}"
        );
    }

    #[test]
    fn release_payload_rejects_url_parseable_but_unrenderable_acme_ca() {
        // Codex P1 (cap#165, reviewer follow-up): values that pass
        // Url::parse as https but fail the shared Caddyfile renderer
        // predicate must be refused before the release is offered.
        let base = serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
            .unwrap()
            .payload;
        for bad in [
            "https://acme.example.test/directory;extra",
            "https://acme.example.test/dir{x}",
            "https://acme.example.test/directory\tx",
            "https://exämple.test/directory",
        ] {
            let mut payload = base.clone();
            payload.tenant_caddy_acme_ca = bad.into();
            let err = validate_release_payload(&payload);
            assert!(
                matches!(err, Err(PlatformReleaseError::InvalidField { field, .. }) if field == "tenant_caddy_acme_ca"),
                "unrenderable ACME CA {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn legacy_signed_baseline_verifies_but_cannot_be_used_as_a_runtime_release() {
        use ed25519_dalek::Signer;

        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        envelope.payload.platform_trustee_policy_pubkey_hex.clear();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0xc0; 32]);
        envelope.signature = hex::encode(
            signing_key
                .sign(&canonical_baseline_bytes(&envelope.payload).unwrap())
                .to_bytes(),
        );
        let root = hex::encode(signing_key.verifying_key().as_bytes());
        let mut value = serde_json::to_value(envelope).unwrap();
        value["payload"]
            .as_object_mut()
            .unwrap()
            .remove("platform_trustee_policy_pubkey_hex");
        let raw = value.to_string();
        let baseline = verify_signed_baseline_with_root(&raw, &root).unwrap();
        assert_eq!(
            baseline.platform_release_version,
            serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
                .unwrap()
                .payload
                .platform_release_version
        );
        let old_runtime: PlatformReleaseEnvelope = serde_json::from_str(&raw).unwrap();
        assert!(verify_envelope_with_root(old_runtime, &root).is_err());

        value["payload"]["platform_release_version"] = "tampered".into();
        assert!(matches!(
            verify_signed_baseline_with_root(&value.to_string(), &root),
            Err(PlatformReleaseError::BadSignature(_))
        ));
        value = serde_json::from_str(&raw).unwrap();
        value["payload"]["platform_trustee_policy_pubkey_hex"] = "".into();
        assert!(verify_signed_baseline_with_root(&value.to_string(), &root).is_err());

        let mut stripped: serde_json::Value =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        stripped["payload"]
            .as_object_mut()
            .unwrap()
            .remove("platform_trustee_policy_pubkey_hex");
        assert!(matches!(
            verify_signed_baseline_with_root(&stripped.to_string(), &root),
            Err(PlatformReleaseError::BadSignature(_))
        ));
    }

    #[test]
    fn fixture_trustee_policy_key_is_rejected_under_a_non_fixture_root() {
        // cap#118: the dev-fixture trustee seed is public (c1*32). A
        // production root signing a release that still pins the fixture
        // trustee key would let anyone with the repo forge policy envelopes.
        // Take the bundled (fixture-signed) envelope, re-sign it with a
        // NON-fixture production root, and confirm the gate rejects it.
        use ed25519_dalek::Signer;
        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        assert_eq!(
            envelope.payload.platform_trustee_policy_pubkey_hex,
            DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX
        );
        let prod_root = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        let canonical =
            canonical_platform_release_bytes(&envelope.payload).expect("canonical bytes");
        envelope.signature = hex::encode(prod_root.sign(&canonical).to_bytes());
        envelope.signing_pubkey = hex::encode(prod_root.verifying_key().as_bytes());
        let root_hex = hex::encode(prod_root.verifying_key().as_bytes());
        let err = verify_envelope_with_root(envelope, &root_hex).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "platform_trustee_policy_pubkey_hex"),
            "expected fixture-trustee rejection, got: {err:?}"
        );
    }

    #[test]
    fn fixture_trustee_policy_key_is_rejected_in_the_signing_slot() {
        // cap#218 self-check: while both keys are pinned, policy signatures
        // verify against the signing-service key (#217), so the public
        // fixture seed must not be pinnable in signing_service_pubkey_hex
        // either — anyone with the repo could then forge policy envelopes
        // the TEE accepts.
        use ed25519_dalek::Signer;
        let mut envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let prod_root = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
        envelope.payload.signing_service_pubkey_hex =
            DEV_FIXTURE_TRUSTEE_POLICY_PUBKEY_HEX.to_string();
        envelope.payload.platform_trustee_policy_pubkey_hex =
            hex::encode(prod_root.verifying_key().as_bytes());
        let canonical =
            canonical_platform_release_bytes(&envelope.payload).expect("canonical bytes");
        envelope.signature = hex::encode(prod_root.sign(&canonical).to_bytes());
        envelope.signing_pubkey = hex::encode(prod_root.verifying_key().as_bytes());
        let root_hex = hex::encode(prod_root.verifying_key().as_bytes());
        let err = verify_envelope_with_root(envelope, &root_hex).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "signing_service_pubkey_hex"),
            "expected signing-slot fixture rejection, got: {err:?}"
        );
    }

    #[test]
    fn verify_envelope_with_root_pins_the_supplied_root() {
        // The ceremony helper passes the root at runtime; it must accept the
        // bundled fixture envelope against the fixture root and reject any
        // other root with RootMismatch, exactly like the compile-time pin.
        let envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        verify_envelope_with_root(envelope.clone(), TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX).unwrap();
        let mismatch = verify_envelope_with_root(
            envelope,
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .expect_err("a foreign root must fail verification");
        assert!(matches!(
            mismatch,
            PlatformReleaseError::RootMismatch { .. }
        ));
        let message = mismatch.to_string();
        assert!(
            message.contains("0000000000000000000000000000000000000000000000000000000000000001"),
            "error must name the pinned root: {message}"
        );
        assert!(
            message.contains(TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX),
            "error must name the release signing key: {message}"
        );
    }

    #[test]
    fn tampering_breaks_signature() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut tampered = raw.clone();
        tampered
            .payload
            .platform_release_version
            .push_str("-tampered");
        let err = verify_envelope(tampered, test_profile()).unwrap_err();
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));
    }

    #[test]
    fn older_override_release_is_detected() {
        let bundled: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();

        let mut older_version = bundled.payload.clone();
        older_version.platform_release_version =
            format!("dev-2000.01.01-{}", older_version.platform_release_version);
        assert!(release_is_older(&older_version, &bundled.payload).unwrap());

        let mut older_created = bundled.payload.clone();
        older_created.created_at = "2000-01-01T00:00:00Z".to_string();
        assert!(release_is_older(&older_created, &bundled.payload).unwrap());

        let mut divergent_version = bundled.payload.clone();
        divergent_version.platform_release_version =
            format!("z-{}", divergent_version.platform_release_version);
        assert!(release_is_older(&divergent_version, &bundled.payload).unwrap());

        assert!(!release_is_older(&bundled.payload, &bundled.payload).unwrap());
    }

    #[test]
    fn release_payload_rejects_tag_only_sidecar_image() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.attestation_proxy_image = "ghcr.io/enclava-labs/attestation-proxy:latest".into();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "attestation_proxy_image")
        );
    }

    #[test]
    fn release_payload_rejects_off_cluster_http_signing_service_url() {
        let raw: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let mut payload = raw.payload;
        payload.signing_service_url = "http://signing.example.test:8080".into();

        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "signing_service_url")
        );
        // The committed fixture uses a cluster-internal http URL and must
        // keep validating.
        validate_release_payload(
            &serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
                .unwrap()
                .payload,
        )
        .unwrap();
    }

    #[test]
    fn bundled_release_carries_a_distinct_platform_trustee_policy_key() {
        // cap#118: the in-TEE policy authority and the off-cluster signing
        // service are two trust domains. The bundled signed release must pin
        // a dedicated trustee policy key that differs from the
        // signing-service key.
        let release = PlatformRelease::load_verified("https://cap.dev.enclava.work").unwrap();
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
        // Ingestion (and ceremony signing, which validates first) must
        // reject it instead. The compressed encoding of a y with no Edwards
        // point on the curve (e.g. y = 2 for edwards25519) is the canonical
        // rejection case.
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

    /// The dev fixture key (`c0` * 32) — the checked-in fixture root is its
    /// public half. Tests use it to craft envelopes the pinned test root
    /// accepts, exactly like the ceremony helper would.
    const DEV_FIXTURE_SEED: [u8; 32] = [0xc0; 32];

    /// A `validate_release_payload`-clean payload (the `release()` helper
    /// predates those checks and carries placeholder shapes).
    fn valid_test_payload(version: &str, created_at: &str) -> PlatformRelease {
        let mut payload = release(version, created_at);
        let identity: PlatformReleaseEnvelope =
            serde_json::from_str(test_profile().baseline.get()).unwrap();
        payload.signing_service_pubkey_hex = identity.payload.signing_service_pubkey_hex;
        payload.trustee_kbs_ca_cert_pem = identity.payload.trustee_kbs_ca_cert_pem;
        payload.policy_template_text = "package policy\n".into();
        payload.policy_template_sha256 =
            hex::encode(Sha256::digest(payload.policy_template_text.as_bytes()));
        payload.attestation_proxy_image = format!(
            "ghcr.io/enclava-labs/attestation-proxy@sha256:{}",
            "aa".repeat(32)
        );
        payload.caddy_ingress_image = format!(
            "ghcr.io/enclava-labs/caddy-ingress@sha256:{}",
            "bb".repeat(32)
        );
        payload.tenant_caddy_tls_mode = "acme".into();
        payload.expected_firmware_measurement = "00".repeat(32);
        payload
    }

    fn sign_with_dev_fixture_key(payload: PlatformRelease) -> PlatformReleaseEnvelope {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&DEV_FIXTURE_SEED);
        let canonical = canonical_platform_release_bytes(&payload).expect("canonical bytes");
        PlatformReleaseEnvelope {
            payload,
            signature: hex::encode(key.sign(&canonical).to_bytes()),
            signing_pubkey: hex::encode(key.verifying_key().as_bytes()),
        }
    }

    fn sealed_test_envelope() -> PlatformReleaseEnvelope {
        let mut payload = valid_test_payload("r-seal", "2026-10-01T00:00:00Z");
        payload.luks2_header_seal = "required".into();
        sign_with_dev_fixture_key(payload)
    }

    /// cap#244: the `luks2_header_seal` rollout claim is part of the signed
    /// bytes whenever the payload carries one — a tampered or stripped
    /// value must break the signature.
    #[test]
    fn seal_rollout_claim_is_covered_by_the_signature() {
        let envelope = sealed_test_envelope();
        let verified =
            verify_envelope(envelope.clone(), test_profile()).expect("valid envelope verifies");
        assert_eq!(verified.luks2_header_seal_claim(), "required");

        let mut tampered = envelope.clone();
        tampered.payload.luks2_header_seal = "adopt".into();
        let err =
            verify_envelope(tampered, test_profile()).expect_err("flip must break the signature");
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));

        let mut stripped = envelope;
        stripped.payload.luks2_header_seal = String::new();
        let err = verify_envelope(stripped, test_profile())
            .expect_err("stripping the field must break the signature");
        assert!(matches!(err, PlatformReleaseError::BadSignature(_)));
    }

    /// cap#244: releases signed before the field existed (no record in the
    /// signed bytes) must keep verifying byte-for-byte and resolve to the
    /// rollout-window default.
    #[test]
    fn pre_field_release_still_verifies_and_defaults_to_adopt() {
        let mut payload = valid_test_payload("r-old", "2026-09-01T00:00:00Z");
        payload.luks2_header_seal = String::new();
        // JSON-level round trip: an old envelope literally lacks the key.
        let mut value = serde_json::to_value(&payload).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("luks2_header_seal")
            .unwrap();
        let payload: PlatformRelease = serde_json::from_value(value).unwrap();
        assert!(payload.luks2_header_seal.is_empty());

        let envelope = sign_with_dev_fixture_key(payload);
        let verified = verify_envelope(envelope, test_profile())
            .expect("pre-field envelope must keep verifying");
        assert_eq!(verified.luks2_header_seal_claim(), "adopt");
    }

    #[test]
    fn release_payload_rejects_unknown_seal_rollout_value() {
        let mut payload = valid_test_payload("r-seal", "2026-10-01T00:00:00Z");
        payload.luks2_header_seal = "banana".into();
        let err = validate_release_payload(&payload).unwrap_err();
        assert!(
            matches!(err, PlatformReleaseError::InvalidField { field, .. } if field == "luks2_header_seal")
        );
    }

    #[test]
    fn bundled_release_carries_a_valid_seal_rollout_claim() {
        let release = PlatformRelease::load_verified("https://cap.dev.enclava.work").unwrap();
        let claim = release.luks2_header_seal_claim();
        assert!(claim == "adopt" || claim == "required", "got {claim}");
    }
}

/// Per-API anti-downgrade baseline. The bundled release is NOT a high-water
/// mark for API-provided envelopes — a preprod API can legitimately serve an
/// older active release than this CLI bundles. Instead, persist the newest
/// release accepted from each API origin and refuse anything older than the
/// last one that API served. The bundled-release baseline stays reserved for
/// local env-path overrides (file-swap defense).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ApiReleaseBaseline {
    /// api origin (scheme://host[:port]) -> last accepted release
    #[serde(flatten)]
    pub entries: std::collections::BTreeMap<String, BaselineEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineEntry {
    pub platform_release_version: String,
    pub created_at: String,
}

/// Read the baseline store. Only a missing file means "first run": a
/// baseline that exists but cannot be read or parsed fails closed —
/// treating corruption as empty would accept a stale envelope and overwrite
/// the high-water mark.
fn read_baseline(store_path: &std::path::Path) -> Result<ApiReleaseBaseline, PlatformReleaseError> {
    match std::fs::read_to_string(store_path) {
        Ok(raw) => Ok(serde_json::from_str(&raw)?),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ApiReleaseBaseline::default()),
        Err(err) => Err(err.into()),
    }
}

/// True once this API origin has served a signed release. Used to fail
/// closed when an API that previously supplied an envelope stops supplying
/// one (a compromised API must not be able to drop the envelope and push
/// signing back onto the local fallback).
pub fn api_served_release_before(
    store_path: &std::path::Path,
    api_origin: &str,
) -> Result<bool, PlatformReleaseError> {
    Ok(read_baseline(store_path)?.entries.contains_key(api_origin))
}

pub fn enforce_release_not_older_than_last_accepted(
    store_path: &std::path::Path,
    api_origin: &str,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    // The whole read/compare/write is serialized across processes: two
    // concurrent deploys could otherwise both read the same state and one
    // write a stale mark (or drop the other API's entry entirely).
    let lock_path = store_path.with_extension("lock");
    crate::fslock::with_file_lock(&lock_path, || {
        enforce_release_not_older_than_last_accepted_locked(store_path, api_origin, release)
    })
}

fn enforce_release_not_older_than_last_accepted_locked(
    store_path: &std::path::Path,
    api_origin: &str,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    parse_release_timestamp(&release.created_at)?;
    let mut baseline = read_baseline(store_path)?;
    if let Some(last) = baseline.entries.get(api_origin)
        && release_pair_is_older(
            (&release.platform_release_version, &release.created_at),
            (&last.platform_release_version, &last.created_at),
        )?
    {
        return Err(PlatformReleaseError::ApiDowngradeRefused {
            api: api_origin.to_string(),
            incoming_version: release.platform_release_version.clone(),
            incoming_created: release.created_at.clone(),
            last_version: last.platform_release_version.clone(),
            last_created: last.created_at.clone(),
        });
    }
    let entry = BaselineEntry {
        platform_release_version: release.platform_release_version.clone(),
        created_at: release.created_at.clone(),
    };
    if baseline.entries.get(api_origin) != Some(&entry) {
        baseline.entries.insert(api_origin.to_string(), entry);
        let parent = store_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        // The baseline carries the per-API downgrade high-water mark; the
        // tempfile is pinned owner-only (explicit 0600 on unix -- not left
        // to tempfile's umask-dependent default) so no other local user can
        // read or tamper with it before the atomic rename, and a future
        // tempfile behavior change cannot silently widen it.
        #[cfg(unix)]
        let mut tmp = {
            use std::os::unix::fs::PermissionsExt;
            tempfile::Builder::new()
                .permissions(std::fs::Permissions::from_mode(0o600))
                .tempfile_in(parent)?
        };
        #[cfg(not(unix))]
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(tmp.as_file_mut(), &baseline)?;
        tmp.as_file().sync_all()?;
        tmp.persist(store_path).map_err(|error| error.error)?;
    }
    Ok(())
}
