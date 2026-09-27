//! Signed platform-release metadata consumed by the API at startup.
//!
//! The CLI already signs deployment descriptors from this artifact. The API
//! uses the same signed anchors to reject drift in platform-controlled release
//! values before it can mint cc_init_data or verify signed policy artifacts.

use std::path::Path;

use sqlx::PgPool;

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
    #[error(
        "platform release high-water mark {persisted_version} ({persisted_created}) and the bundled release {bundled_version} ({bundled_created}) share created_at but diverge (version or signed payload digest); the two are unorderable, so neither may silently replace the other — reconcile the database record against trusted release history before restarting"
    )]
    EqualTimestampDivergentMark {
        persisted_version: String,
        persisted_created: String,
        bundled_version: String,
        bundled_created: String,
    },
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
        "platform release downgrade refused: override is {override_version} ({override_created}) but the API bundles {bundled_version} ({bundled_created}); refusing a validly-signed stale release"
    )]
    DowngradeRefused {
        override_version: String,
        override_created: String,
        bundled_version: String,
        bundled_created: String,
    },
    #[error(
        "platform release downgrade refused: candidate is {override_version} ({override_created}) but the database floor is {accepted_version} ({accepted_created}); reconcile intentional recovery against trusted release history"
    )]
    OverrideDowngradeRefused {
        override_version: String,
        override_created: String,
        accepted_version: String,
        accepted_created: String,
    },
    #[error(
        "platform release database state is unavailable: {0}; refusing startup without the accepted-release floor"
    )]
    Database(#[from] sqlx::Error),
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

/// A verified envelope and whether startup owes an accepted-override commit.
/// Loading does not advance the database floor; main commits only after all
/// release-derived configuration validates.
pub struct LoadedPlatformRelease {
    pub envelope: PlatformReleaseEnvelope,
    pub override_active: bool,
}

impl PlatformReleaseEnvelope {
    pub fn load_verified() -> Result<Self, PlatformReleaseError> {
        Ok(Self::load_verified_for_startup()?.envelope)
    }

    pub fn load_verified_for_startup() -> Result<LoadedPlatformRelease, PlatformReleaseError> {
        let override_path = std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let raw = match &override_path {
            Some(path) => std::fs::read_to_string(Path::new(path))?,
            None => BUNDLED_PLATFORM_RELEASE.to_string(),
        };
        Self::load_verified_from_raw(raw, override_path.is_some())
    }

    fn load_verified_from_raw(
        raw: String,
        override_active: bool,
    ) -> Result<LoadedPlatformRelease, PlatformReleaseError> {
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw)?;
        verify_envelope(envelope.clone())?;
        if override_active {
            enforce_release_not_older_than_bundled(&envelope.payload)?;
        }
        Ok(LoadedPlatformRelease {
            envelope,
            override_active,
        })
    }
}

/// The state-only lane must enforce the compiled baseline without enabling
/// release-derived configuration or requiring a separate storage setting.
pub fn bundled_release_payload() -> Result<PlatformRelease, PlatformReleaseError> {
    Ok(serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE)?.payload)
}

/// Persisted newest-accepted override. `payload_sha256` digests the exact
/// canonical bytes the envelope signature covers, so two envelopes that reuse
/// the same `{version, created_at}` pair with different signed content
/// (measurements, policy, digests) cannot pass as "the same release".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AcceptedOverrideMark {
    platform_release_version: String,
    created_at: String,
    payload_sha256: String,
}

impl AcceptedOverrideMark {
    fn of(release: &PlatformRelease) -> Result<Self, PlatformReleaseError> {
        if release.platform_release_version.trim().is_empty() {
            return Err(PlatformReleaseError::InvalidField {
                field: "platform_release_version",
                message: "empty release version".into(),
            });
        }
        Ok(Self {
            platform_release_version: release.platform_release_version.clone(),
            created_at: release.created_at.clone(),
            payload_sha256: release_payload_sha256(release)?,
        })
    }
}

fn release_payload_sha256(release: &PlatformRelease) -> Result<String, PlatformReleaseError> {
    // Canonicalization re-validates the hex fields; for an envelope that
    // already passed verify_envelope this cannot fail, but refuse rather
    // than persist an empty (match-anything) digest if it ever does.
    Ok(hex::encode(Sha256::digest(
        &canonical_platform_release_bytes(release)?,
    )))
}

/// The downgrade baseline must never regress below the bundle: a newer API
/// image can bundle a release newer than a previously accepted override,
/// and the effective floor is whichever is newer.
fn newest_mark(
    persisted: Option<AcceptedOverrideMark>,
) -> Result<Option<AcceptedOverrideMark>, PlatformReleaseError> {
    let bundled: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE)?;
    let bundled_mark = AcceptedOverrideMark::of(&bundled.payload)?;
    Ok(match persisted {
        // Strictly older persisted mark: the bundle is the effective floor.
        Some(p)
            if matches!(
                mark_ordering(&p, &bundled_mark)?,
                MarkOrdering::CandidateOlder
            ) =>
        {
            Some(bundled_mark)
        }
        // Equal-timestamp divergence between the persisted mark and the
        // bundle (e.g. a binary rollback to a differently signed image
        // whose release reused the timestamp) is UNORDERABLE: silently
        // preferring either side would let a bundle-identical override
        // replace a divergent accepted mark (bypassing the equal-
        // timestamp fail-closed rule) or vice versa. Fail closed.
        Some(p)
            if matches!(
                mark_ordering(&p, &bundled_mark)?,
                MarkOrdering::EqualTimestampDivergent
            ) =>
        {
            return Err(PlatformReleaseError::EqualTimestampDivergentMark {
                persisted_version: p.platform_release_version,
                persisted_created: p.created_at,
                bundled_version: bundled_mark.platform_release_version,
                bundled_created: bundled_mark.created_at,
            });
        }
        // Equal or strictly newer persisted mark: it remains the floor.
        Some(p) => Some(p),
        None => Some(bundled_mark),
    })
}

/// Candidate is stale-or-suspect relative to the baseline: strictly older
/// timestamp, or an equal timestamp with ANY divergence — different opaque
/// version OR different signed payload digest. Two envelopes that reuse the
/// same `{version, created_at}` pair with different measurements, policy, or
/// image digests are unorderable and fail closed instead of passing as
/// "the same release".
enum MarkOrdering {
    CandidateOlder,
    CandidateNewer,
    Equal,
    EqualTimestampDivergent,
}

fn mark_ordering(
    candidate: &AcceptedOverrideMark,
    baseline: &AcceptedOverrideMark,
) -> Result<MarkOrdering, PlatformReleaseError> {
    let candidate_ts = parse_release_timestamp(&candidate.created_at)?;
    let baseline_ts = parse_release_timestamp(&baseline.created_at)?;
    Ok(if candidate_ts < baseline_ts {
        MarkOrdering::CandidateOlder
    } else if candidate_ts > baseline_ts {
        MarkOrdering::CandidateNewer
    } else if candidate.platform_release_version == baseline.platform_release_version
        && candidate.payload_sha256 == baseline.payload_sha256
    {
        MarkOrdering::Equal
    } else {
        MarkOrdering::EqualTimestampDivergent
    })
}

/// Candidate is stale-or-suspect relative to the baseline: strictly older
/// timestamp, or an equal timestamp with ANY divergence — different opaque
/// version OR different signed payload digest. Two envelopes that reuse the
/// same `{version, created_at}` pair with different measurements, policy, or
/// image digests are unorderable and fail closed instead of passing as
/// "the same release".
fn mark_is_older(
    candidate: &AcceptedOverrideMark,
    baseline: &AcceptedOverrideMark,
) -> Result<bool, PlatformReleaseError> {
    Ok(matches!(
        mark_ordering(candidate, baseline)?,
        MarkOrdering::CandidateOlder | MarkOrdering::EqualTimestampDivergent
    ))
}

/// Commit only after release-derived startup validation succeeds. A row lock
/// covers read, comparison and update, including the first acceptance: the
/// migration seeds the singleton row before any API process can use it.
pub async fn commit_override_acceptance(
    pool: &PgPool,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    enforce_database_floor(pool, release, true).await
}

/// Used before startup validation, again before serving, and by the watchdog.
/// Bundled and state-only replicas use their compiled release here too.
pub async fn check_running_release_current(
    pool: &PgPool,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    enforce_database_floor(pool, release, false).await
}

impl PlatformReleaseError {
    pub fn is_running_release_refused(&self) -> bool {
        matches!(
            self,
            Self::OverrideDowngradeRefused { .. } | Self::EqualTimestampDivergentMark { .. }
        )
    }
}

async fn enforce_database_floor(
    pool: &PgPool,
    release: &PlatformRelease,
    persist: bool,
) -> Result<(), PlatformReleaseError> {
    let candidate = AcceptedOverrideMark::of(release)?;
    let mut tx = pool.begin().await?;
    // Acceptance must survive a database restart even if the connection's
    // default was relaxed for ordinary application writes.
    sqlx::query("SET LOCAL synchronous_commit = on")
        .execute(&mut *tx)
        .await?;
    let (version, created_at, digest): (Option<String>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT platform_release_version, created_at, payload_sha256 \
                        FROM platform_release_state WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_one(&mut *tx)
        .await?;
    let persisted = match (version, created_at, digest) {
        (None, None, None) => None, // Only the migration creates this fresh state.
        (Some(platform_release_version), Some(created_at), Some(payload_sha256)) => {
            if platform_release_version.trim().is_empty() {
                return Err(PlatformReleaseError::InvalidField {
                    field: "platform_release_state",
                    message: "empty accepted release version".into(),
                });
            }
            parse_release_timestamp(&created_at)?;
            hex32("accepted payload_sha256", &payload_sha256)?;
            Some(AcceptedOverrideMark {
                platform_release_version,
                created_at,
                payload_sha256,
            })
        }
        _ => {
            return Err(PlatformReleaseError::InvalidField {
                field: "platform_release_state",
                message: "incomplete accepted release record".into(),
            });
        }
    };
    if let Some(floor) = newest_mark(persisted.clone())?
        && mark_is_older(&candidate, &floor)?
    {
        return Err(PlatformReleaseError::OverrideDowngradeRefused {
            override_version: candidate.platform_release_version,
            override_created: candidate.created_at,
            accepted_version: floor.platform_release_version,
            accepted_created: floor.created_at,
        });
    }
    if persist && persisted.as_ref() != Some(&candidate) {
        sqlx::query(
            "UPDATE platform_release_state SET platform_release_version = $1, \
                     created_at = $2, payload_sha256 = $3 WHERE singleton = TRUE",
        )
        .bind(&candidate.platform_release_version)
        .bind(&candidate.created_at)
        .bind(&candidate.payload_sha256)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
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
    let bundled_mark = AcceptedOverrideMark::of(&bundled.payload)?;
    let candidate_mark = AcceptedOverrideMark::of(release)?;
    if mark_is_older(&candidate_mark, &bundled_mark)? {
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
    // validator so the release can never be accepted (and its high-water
    // mark persisted) if any ACME-mode render would later fail.
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

#[cfg(test)]
mod tests {
    use super::*;

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
        // it would advance the high-water mark and then fail every
        // ACME-mode render with no rollback path.
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
        // predicate — a prefix-only acceptance check would strand the
        // deployment above its last working override.
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

    #[test]
    fn newest_mark_fails_closed_on_equal_timestamp_divergence_with_bundle() {
        // Codex P1 (cap#165 round 6): a persisted mark sharing created_at
        // with the bundled release but diverging in version/digest must
        // NOT be silently discarded in favor of the bundle — the state-only
        // removal guard would then compare the bundle against itself and
        // an override identical to the bundle could replace the divergent
        // accepted mark, bypassing the equal-timestamp fail-closed rule.
        let bundled = bundled_payload();
        let mut divergent = AcceptedOverrideMark::of(&bundled).unwrap();
        divergent.platform_release_version =
            format!("{}-divergent", divergent.platform_release_version);
        assert!(matches!(
            newest_mark(Some(divergent)),
            Err(PlatformReleaseError::EqualTimestampDivergentMark { .. })
        ));
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
        resigned_envelope_with(
            created_at,
            &format!("dev-stale-{}", created_at).replace(':', ""),
            None,
        )
    }

    fn resigned_envelope_with(
        created_at: &str,
        platform_release_version: &str,
        trustee_kbs_url: Option<&str>,
    ) -> String {
        use ed25519_dalek::{Signer, SigningKey};
        // The committed fixture key (DEV_FIXTURE_SIGNING_KEY_HEX in
        // crates/enclava-cli/scripts/generate-platform-release.py) matches
        // the test root pinned below, so the re-signed envelope is
        // "validly signed" for verify_envelope.
        let key = SigningKey::from_bytes(&[0xc0; 32]);
        let mut envelope =
            serde_json::from_str::<PlatformReleaseEnvelope>(BUNDLED_PLATFORM_RELEASE).unwrap();
        envelope.payload.created_at = created_at.to_string();
        envelope.payload.platform_release_version = platform_release_version.to_string();
        if let Some(url) = trustee_kbs_url {
            envelope.payload.trustee_kbs_url = url.to_string();
        }
        let canonical = canonical_platform_release_bytes(&envelope.payload).unwrap();
        envelope.signature = hex::encode(key.sign(&canonical).to_bytes());
        envelope.signing_pubkey = hex::encode(key.verifying_key().as_bytes());
        serde_json::to_string(&envelope).unwrap()
    }

    // Each case owns a schema in the caller's disposable PostgreSQL database.
    async fn state_database() -> (PgPool, String) {
        let url =
            std::env::var("DATABASE_URL").expect("set DATABASE_URL to a disposable test database");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("release_state_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let options = url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .unwrap()
            .options([("search_path", schema.as_str())]);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../migrations/0050_platform_release_state.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        admin.close().await;
        (pool, schema)
    }

    async fn drop_state_database(pool: PgPool, schema: String) {
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;
    }

    fn signed_release(timestamp: &str) -> PlatformRelease {
        PlatformReleaseEnvelope::load_verified_from_raw(
            resigned_envelope_with_created_at(timestamp),
            true,
        )
        .unwrap()
        .envelope
        .payload
    }

    #[test]
    fn valid_signature_does_not_admit_a_release_older_than_the_bundle() {
        let raw = resigned_envelope_with_created_at("2020-01-01T00:00:00Z");
        verify_envelope(serde_json::from_str(&raw).unwrap()).unwrap();
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(raw, true),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }

    #[tokio::test]
    async fn whitespace_release_versions_cannot_advance_the_floor() {
        let (pool, schema) = state_database().await;
        let accepted = signed_release("2999-01-01T00:00:00Z");
        commit_override_acceptance(&pool, &accepted).await.unwrap();
        for version in ["", " ", "\t", "\r\n", "\u{00a0}", "\u{2003}"] {
            let raw = resigned_envelope_with("2999-01-02T00:00:00Z", version, None);
            let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw).unwrap();
            assert!(matches!(
                PlatformReleaseEnvelope::load_verified_from_raw(raw, true),
                Err(PlatformReleaseError::InvalidField {
                    field: "platform_release_version",
                    ..
                })
            ));
            assert!(matches!(
                commit_override_acceptance(&pool, &envelope.payload).await,
                Err(PlatformReleaseError::InvalidField {
                    field: "platform_release_version",
                    ..
                })
            ));
        }
        check_running_release_current(&pool, &accepted)
            .await
            .unwrap();
        drop_state_database(pool, schema).await;
    }

    #[tokio::test]
    async fn postgres_floor_survives_reconnect_and_override_removal() {
        let (pool, schema) = state_database().await;
        let older = signed_release("2999-01-01T00:00:00Z");
        let newer = signed_release("2999-01-02T00:00:00Z");
        // Startup may still fail configuration validation after this read.
        check_running_release_current(&pool, &newer).await.unwrap();
        let untouched: Option<String> =
            sqlx::query_scalar("SELECT platform_release_version FROM platform_release_state")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            untouched.is_none(),
            "validation alone must not advance the floor"
        );
        commit_override_acceptance(&pool, &older).await.unwrap();
        commit_override_acceptance(&pool, &newer).await.unwrap();
        let options = (*pool.connect_options()).clone();
        pool.close().await;
        let pool = PgPool::connect_with(options).await.unwrap();
        check_running_release_current(&pool, &newer).await.unwrap();
        for release in [&older, &bundled_release_payload().unwrap()] {
            let error = check_running_release_current(&pool, release)
                .await
                .unwrap_err();
            assert!(error.is_running_release_refused());
            assert!(commit_override_acceptance(&pool, release).await.is_err());
        }
        // Removing the override/policy flags uses this same bundled comparison.
        drop_state_database(pool, schema).await;
    }

    #[tokio::test]
    async fn postgres_serializes_first_acceptance_and_rechecks_after_waiting() {
        let (pool, schema) = state_database().await;
        let older = signed_release("2999-01-01T00:00:00Z");
        let newer = signed_release("2999-01-02T00:00:00Z");
        let (old_result, new_result) = tokio::join!(
            commit_override_acceptance(&pool, &older),
            commit_override_acceptance(&pool, &newer),
        );
        new_result.unwrap();
        assert!(old_result.is_ok() || old_result.unwrap_err().is_running_release_refused());
        check_running_release_current(&pool, &newer).await.unwrap();
        assert!(
            check_running_release_current(&pool, &older)
                .await
                .unwrap_err()
                .is_running_release_refused()
        );

        // Hold the real database row as another replica advances it. A stale
        // writer must wait and compare the newly committed value, not its old snapshot.
        let newest = signed_release("2999-01-03T00:00:00Z");
        let mark = AcceptedOverrideMark::of(&newest).unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE platform_release_state SET platform_release_version=$1, created_at=$2, payload_sha256=$3")
            .bind(&mark.platform_release_version).bind(&mark.created_at).bind(&mark.payload_sha256)
            .execute(&mut *tx).await.unwrap();
        let contender_pool = pool.clone();
        let mut contender =
            tokio::spawn(async move { commit_override_acceptance(&contender_pool, &newer).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut contender)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), contender)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err()
                .is_running_release_refused()
        );
        check_running_release_current(&pool, &newest).await.unwrap();
        drop_state_database(pool, schema).await;
    }

    #[tokio::test]
    async fn postgres_refuses_equal_timestamp_divergence_and_corrupt_state() {
        let (pool, schema) = state_database().await;
        let accepted = signed_release("2999-01-01T00:00:00Z");
        commit_override_acceptance(&pool, &accepted).await.unwrap();
        for (version, url) in [
            ("different-version", None),
            (
                accepted.platform_release_version.as_str(),
                Some("https://different.example"),
            ),
        ] {
            let release = PlatformReleaseEnvelope::load_verified_from_raw(
                resigned_envelope_with(&accepted.created_at, version, url),
                true,
            )
            .unwrap()
            .envelope
            .payload;
            assert!(
                commit_override_acceptance(&pool, &release)
                    .await
                    .unwrap_err()
                    .is_running_release_refused()
            );
        }
        sqlx::query("UPDATE platform_release_state SET created_at='corrupt'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            check_running_release_current(&pool, &accepted).await,
            Err(PlatformReleaseError::InvalidField {
                field: "created_at",
                ..
            })
        ));
        sqlx::query("DELETE FROM platform_release_state")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            commit_override_acceptance(&pool, &accepted).await,
            Err(PlatformReleaseError::Database(sqlx::Error::RowNotFound))
        ));
        sqlx::query("DROP TABLE platform_release_state")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            check_running_release_current(&pool, &accepted).await,
            Err(PlatformReleaseError::Database(_))
        ));
        let closed_pool = pool.clone();
        drop_state_database(pool, schema).await;
        assert!(matches!(
            check_running_release_current(&closed_pool, &accepted).await,
            Err(PlatformReleaseError::Database(sqlx::Error::PoolClosed))
        ));
    }

    #[tokio::test]
    async fn postgres_preserves_bundle_floor_and_records_matching_override() {
        let (pool, schema) = state_database().await;
        let bundled = bundled_payload();
        check_running_release_current(&pool, &bundled)
            .await
            .unwrap();
        let mark: Option<String> =
            sqlx::query_scalar("SELECT payload_sha256 FROM platform_release_state")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            mark.is_none(),
            "bundled checks must not advance the override floor"
        );
        commit_override_acceptance(&pool, &bundled).await.unwrap();
        let digest: String =
            sqlx::query_scalar("SELECT payload_sha256 FROM platform_release_state")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(digest, release_payload_sha256(&bundled).unwrap());
        sqlx::query("UPDATE platform_release_state SET platform_release_version='divergent'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(
            check_running_release_current(&pool, &bundled).await,
            Err(PlatformReleaseError::EqualTimestampDivergentMark { .. })
        ));
        let newer = signed_release("2999-01-01T00:00:00Z");
        assert!(matches!(
            commit_override_acceptance(&pool, &newer).await,
            Err(PlatformReleaseError::EqualTimestampDivergentMark { .. })
        ));
        sqlx::query("UPDATE platform_release_state SET created_at='2020-01-01T00:00:00Z'")
            .execute(&pool)
            .await
            .unwrap();
        check_running_release_current(&pool, &bundled)
            .await
            .unwrap();
        let mut stale = bundled.clone();
        stale.created_at = "2020-01-02T00:00:00Z".into();
        assert!(
            commit_override_acceptance(&pool, &stale)
                .await
                .unwrap_err()
                .is_running_release_refused()
        );
        drop_state_database(pool, schema).await;
    }
}
