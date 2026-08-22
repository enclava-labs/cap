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
#[cfg(test)]
const TEST_FIXTURE_RELEASE_ROOT_PUBKEY_HEX: &str =
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
        let override_active = matches!(std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH"), Ok(path) if !path.trim().is_empty());
        let raw = match std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH") {
            Ok(path) if !path.trim().is_empty() => std::fs::read_to_string(Path::new(&path))?,
            _ => BUNDLED_PLATFORM_RELEASE.to_string(),
        };
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw)?;
        verify_envelope(envelope.clone())?;
        // Downgrade protection: an env-path override may never be older than
        // the release compiled into this binary. A validly-signed stale
        // release (pinned to old measurements/sidecar digests) is exactly
        // what a file-swap or env-var attack serves.
        if override_active {
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
    let Ok(bundled) = serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)
    else {
        return Ok(());
    };
    if release_is_older(release, &bundled.payload) {
        return Err(PlatformReleaseError::DowngradeRefused {
            override_version: release.platform_release_version.clone(),
            override_created: release.created_at.clone(),
            bundled_version: bundled.payload.platform_release_version.clone(),
            bundled_created: bundled.payload.created_at.clone(),
        });
    }
    Ok(())
}

/// Ordering by the signed creation timestamp first, version identifier as a
/// tiebreak only. `platform_release_version` is an opaque identifier with a
/// non-monotonic hash suffix (`dev-2026.07.28-proxy-a8303c36`), so it must
/// never be the primary ordering axis; `created_at` is signed and monotonic
/// by construction.
fn release_is_older(candidate: &PlatformRelease, bundled: &PlatformRelease) -> bool {
    release_pair_is_older(
        (&candidate.platform_release_version, &candidate.created_at),
        (&bundled.platform_release_version, &bundled.created_at),
    )
}

/// Same ordering on bare (version, created_at) pairs — shared by the
/// API-baseline store, which persists only the pair.
fn release_pair_is_older(candidate: (&str, &str), baseline: (&str, &str)) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(candidate.1),
        chrono::DateTime::parse_from_rfc3339(baseline.1),
    ) {
        (Ok(candidate_ts), Ok(baseline_ts)) => {
            candidate_ts < baseline_ts || (candidate_ts == baseline_ts && candidate.0 < baseline.0)
        }
        // A candidate whose signed timestamp does not parse cannot be shown
        // to be current; fail closed and treat it as older.
        (Err(_), Ok(_)) => true,
        // Unorderable baseline (broken bundle): fall back to the identifier.
        _ => candidate.0 < baseline.0,
    }
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
        assert!(release_is_older(&older, &newer));
        assert!(!release_is_older(&newer, &older));
        assert!(!release_is_older(&newer, &newer));
    }

    #[test]
    fn unparseable_candidate_timestamp_fails_closed_as_older() {
        let bundled = release("r1", "2026-08-15T00:00:00Z");
        let broken = release("r2", "not-a-timestamp");
        assert!(release_is_older(&broken, &bundled));
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
    fn tagged_cli_release_build_pins_bundled_release_root() {
        let envelope: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let workflow = include_str!("../../../.github/workflows/release.yml");
        let expected = format!(
            "\nenv:\n  ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX: {}\n",
            envelope.signing_pubkey
        );

        assert!(workflow.contains(&expected));
        assert_eq!(
            workflow
                .matches("ENCLAVA_PLATFORM_RELEASE_ROOT_PUBKEY_HEX:")
                .count(),
            1
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
        assert!(release_is_older(&older_version, &bundled.payload));

        let mut older_created = bundled.payload.clone();
        older_created.created_at = "2000-01-01T00:00:00Z".to_string();
        assert!(release_is_older(&older_created, &bundled.payload));

        let mut newer_version = bundled.payload.clone();
        newer_version.platform_release_version =
            format!("z-{}", newer_version.platform_release_version);
        assert!(!release_is_older(&newer_version, &bundled.payload));

        assert!(!release_is_older(&bundled.payload, &bundled.payload));
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
    let mut baseline = read_baseline(store_path)?;
    if let Some(last) = baseline.entries.get(api_origin)
        && release_pair_is_older(
            (&release.platform_release_version, &release.created_at),
            (&last.platform_release_version, &last.created_at),
        )
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
        let tmp = store_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&baseline)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::rename(&tmp, store_path)?;
    }
    Ok(())
}
