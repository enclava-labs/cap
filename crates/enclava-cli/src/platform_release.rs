//! Signed platform-release metadata bundled with the CLI.
//!
//! The descriptor signer must not learn release anchors from the CAP API or
//! environment. It verifies this artifact against a pinned Ed25519 release
//! root, then uses the signed template/image/measurement constants to derive
//! deployment descriptors.

use std::path::Path;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const BUNDLED_PLATFORM_RELEASE: &str = include_str!("../platform-release.json");

#[cfg(any(test, feature = "prod-strict"))]
const FORBIDDEN_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str =
    "5b9437adeaffbe8f41b13d96ed49d2f51cd6c266cd8ecc284b0552ec4912b8dd";

#[cfg(test)]
const TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str = FORBIDDEN_FIXTURE_RELEASE_ROOT_PUBKEY_HEX;

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
    #[error("platform release signature pubkey is not the pinned root")]
    RootMismatch,
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
        hex32(
            "signing_service_pubkey_hex",
            &self.signing_service_pubkey_hex,
        )
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
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw)?;
        verify_envelope(envelope.clone())?;
        // Downgrade protection: an env-path override may never be older than
        // the release compiled into this binary. A validly-signed stale
        // release (pinned to old measurements/sidecar digests) is exactly
        // what a file-swap or env-var attack serves.
        if override_path.is_some() {
            enforce_release_not_older_than_bundled(&envelope.payload)?;
        }
        Ok(envelope)
    }
}

/// Reject `release` when it is older than the release compiled into this
/// binary. Applied to every release source that did not itself come from the
/// bundle: env-path overrides AND API-provided envelopes (a compromised API
/// can serve an old, still-validly-signed envelope with a matching
/// `current_platform_release_id`, otherwise the CLI would sign against
/// stale measurements, policy, and sidecar digests).
pub fn enforce_release_not_older_than_bundled(
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    // Parity with the API twin: a malformed bundled baseline fails closed
    // (Json error) rather than silently disabling the downgrade gate.
    let bundled: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE)?;
    if release_is_older(release, &bundled.payload)? {
        return Err(PlatformReleaseError::DowngradeRefused {
            override_version: release.platform_release_version.clone(),
            override_created: release.created_at.clone(),
            bundled_version: bundled.payload.platform_release_version.clone(),
            bundled_created: bundled.payload.created_at.clone(),
        });
    }
    Ok(())
}

/// Ordering by the signed creation timestamp. `platform_release_version` is
/// opaque, so distinct releases at the same timestamp are unorderable and
/// fail closed rather than using the identifier as a tiebreak.
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
) -> Result<PlatformRelease, PlatformReleaseError> {
    #[cfg(test)]
    let configured_root = option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
        .unwrap_or(TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX);
    #[cfg(not(test))]
    let configured_root = option_env!("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX")
        .ok_or(PlatformReleaseError::MissingRootPubkey)?;
    verify_envelope_with_root(envelope, configured_root)
}

/// Root-pinning variant used by the release ceremony helper
/// (`examples/platform-release.rs`), which takes the root as an argument
/// instead of a compile-time `option_env!`.
pub fn verify_envelope_with_root(
    envelope: PlatformReleaseEnvelope,
    root_hex: &str,
) -> Result<PlatformRelease, PlatformReleaseError> {
    let pinned = hex32("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX", root_hex)?;
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

fn hex32(field: &'static str, value: &str) -> Result<[u8; 32], PlatformReleaseError> {
    let bytes = hex::decode(value.trim())?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PlatformReleaseError::InvalidField {
            field,
            message: format!("expected 32 bytes, got {}", bytes.len()),
        })
}

fn validate_release_payload(release: &PlatformRelease) -> Result<(), PlatformReleaseError> {
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
    parse_release_timestamp(&release.created_at)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, created_at: &str) -> PlatformRelease {
        PlatformRelease {
            schema_version: "v1".into(),
            platform_release_version: version.into(),
            signing_service_url: "https://signing.example".into(),
            signing_service_pubkey_hex: "00".repeat(32),
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
        let bundled = PlatformReleaseEnvelope::load_verified().unwrap();
        let stale = release("zzz-newer-suffix", "2020-01-01T00:00:00Z");
        assert!(matches!(
            enforce_release_not_older_than_bundled(&stale),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
        drop(bundled);
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
    fn bundled_release_uses_ghcr_digest_pinned_sidecars() {
        let release = PlatformRelease::load_verified().unwrap();
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
    fn cli_dockerfile_requires_platform_release_root_build_arg() {
        let dockerfile = include_str!("../Dockerfile").replace("\r\n", "\n");
        assert!(
            !dockerfile.contains("ARG ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX="),
            "CLI Dockerfile must not default the platform-release root"
        );
        assert!(
            dockerfile.contains(
                "ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX must be provided as a build-arg"
            )
        );
        assert!(
            dockerfile
                .contains("cargo build --locked --release --bin enclava --features prod-strict")
        );
        assert!(dockerfile.contains("bash scripts/require-platform-release-root.sh"));
        assert!(dockerfile.contains("COPY scripts/require-platform-release-root.sh"));
        // The Dockerfile itself must verify the envelope signature, not just
        // compare pubkeys.
        assert!(dockerfile.contains("--example platform-release -- verify"));
    }

    #[test]
    fn tagged_cli_release_build_requires_platform_release_root_secret() {
        let workflow = include_str!("../../../.github/workflows/release.yml");
        // Windows checkouts use CRLF (autocrlf); normalize before matching.
        let workflow = workflow.replace("\r\n", "\n");
        let expected = "\nenv:\n  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX: ${{ secrets.ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX }}\n";

        assert!(
            workflow.contains(expected),
            "release workflow must take the root from a required secret, not a committed fixture"
        );
        assert!(
            workflow.contains("scripts/require-platform-release-root.sh"),
            "release workflow must run the production platform-release root gate"
        );
        assert!(
            !workflow.contains(TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX),
            "release workflow must not hardcode the committed dev fixture pubkey"
        );
        assert_eq!(
            workflow
                .matches("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX:")
                .count(),
            1
        );
        // Every published CLI binary is a prod-strict build, so an invalid,
        // missing, or fixture root fails at compile time, and no job builds
        // artifacts before the root gate has passed.
        assert_eq!(
            workflow
                .matches("--bin enclava --features prod-strict")
                .count(),
            3
        );
        assert_eq!(
            workflow
                .matches("needs: require-platform-release-root")
                .count(),
            4
        );
        // The gate is satisfiable only by supplying a matching production
        // envelope: the secret is materialized over the bundled envelope in
        // the gate job and every build job, and the gate job verifies the
        // full signature before anything builds.
        assert!(workflow.contains(
            "ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON: ${{ secrets.ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON }}"
        ));
        assert_eq!(
            workflow
                .matches("printf '%s' \"$ENCLAVA_PLATFORM_RELEASE_ENVELOPE_JSON\" > crates/enclava-cli/platform-release.json")
                .count(),
            4
        );
        assert!(workflow.contains("--example platform-release -- verify"));
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
    fn verify_envelope_with_root_pins_the_supplied_root() {
        // The ceremony helper passes the root at runtime; it must accept the
        // bundled fixture envelope against the fixture root and reject any
        // other root with RootMismatch, exactly like the compile-time pin.
        let envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        verify_envelope_with_root(envelope.clone(), TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX).unwrap();
        assert!(matches!(
            verify_envelope_with_root(
                envelope,
                "0000000000000000000000000000000000000000000000000000000000000001"
            ),
            Err(PlatformReleaseError::RootMismatch)
        ));
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
