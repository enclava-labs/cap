//! Signed platform-release metadata consumed by the API at startup.
//!
//! The CLI already signs deployment descriptors from this artifact. The API
//! uses the same signed anchors to reject drift in platform-controlled release
//! values before it can mint cc_init_data or verify signed policy artifacts.

use std::path::{Path, PathBuf};

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
        "platform release override downgrade refused: override is {override_version} ({override_created}) but this API previously accepted {accepted_version} ({accepted_created}) from the same override lane; \
         if the rollback is intentional, clear the high-water-mark state at {state_path} after verifying with the operator. \
         Refusing to silently revert measurements, policy, and sidecar digests"
    )]
    OverrideDowngradeRefused {
        override_version: String,
        override_created: String,
        accepted_version: String,
        accepted_created: String,
        state_path: String,
    },
    #[error(
        "cannot persist the platform-release override high-water mark at {state_path}: {source}. \
         Refusing to start without it: if the mark were skipped, a later file swap to an older \
         validly-signed release would be accepted. Point ENCLAVA_PLATFORM_RELEASE_STATE at a \
         writable path (the override file itself is typically a read-only configmap mount)"
    )]
    HighWaterMarkPersistFailed {
        state_path: String,
        source: std::io::Error,
    },
    #[error(
        "ENCLAVA_PLATFORM_RELEASE_PATH is set but ENCLAVA_PLATFORM_RELEASE_STATE is not: \
         the override anti-rollback floor must live at an explicit, writable path that \
         survives removal of the override variable. Without it, clearing the override \
         would also erase the only pointer to the persisted high-water mark and silently \
         re-admit an older bundled or override release. Set ENCLAVA_PLATFORM_RELEASE_STATE \
         (see deploy/api/components/platform-release-state) or unset \
         ENCLAVA_PLATFORM_RELEASE_PATH"
    )]
    MissingOverrideStatePath,
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

/// A verified platform release plus the deferred high-water-mark commit
/// obligation that comes with it. The load itself only CHECKS the override
/// against the persisted mark; the mark is advanced by
/// `enforce_override_not_older_than_last_accepted` only after startup
/// validation has accepted the release (runtime class, env-match, sidecar
/// pins). Otherwise a signed-but-incompatible override would raise the
/// floor and then fail startup, locking the deployment out of its last
/// working release (Devin review, cap#165).
pub struct LoadedPlatformRelease {
    pub envelope: PlatformReleaseEnvelope,
    /// State path to commit once startup validation accepts the release.
    /// `None` when no high-water lane is active.
    pub pending_high_water: Option<PathBuf>,
}

impl PlatformReleaseEnvelope {
    pub fn load_verified() -> Result<Self, PlatformReleaseError> {
        Ok(Self::load_verified_with_pending_state()?.envelope)
    }

    pub fn load_verified_with_pending_state() -> Result<LoadedPlatformRelease, PlatformReleaseError>
    {
        let override_path = std::env::var("ENCLAVA_PLATFORM_RELEASE_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty());
        let state_env = std::env::var("ENCLAVA_PLATFORM_RELEASE_STATE")
            .ok()
            .filter(|v| !v.trim().is_empty());
        let high_water = resolve_high_water_state(override_path.as_deref(), state_env)?;
        let raw = match &override_path {
            Some(path) => std::fs::read_to_string(Path::new(path))?,
            None => BUNDLED_PLATFORM_RELEASE.to_string(),
        };
        Self::load_verified_from_raw(raw, override_path.is_some(), high_water.as_deref())
    }

    fn load_verified_from_raw(
        raw: String,
        override_active: bool,
        high_water_state: Option<&Path>,
    ) -> Result<LoadedPlatformRelease, PlatformReleaseError> {
        let envelope: PlatformReleaseEnvelope = serde_json::from_str(&raw)?;
        verify_envelope(envelope.clone())?;
        // Downgrade protection: an env-path override may never be older than
        // the release compiled into this binary. A validly-signed stale
        // release (pinned to old measurements/sidecar digests) is exactly
        // what a file-swap or env-var attack serves. Parity with the CLI's
        // `enforce_release_not_older_than_bundled` gate.
        //
        // This is the CHECK pass only: the high-water mark is not persisted
        // here. Callers advance it via
        // `enforce_override_not_older_than_last_accepted` once the rest of
        // startup validation has accepted the release, so a release that
        // fails a later check cannot strand the deployment above its last
        // working override.
        if override_active {
            enforce_release_not_older_than_bundled(&envelope.payload)?;
            if let Some(state_path) = high_water_state {
                check_override_not_older_than_last_accepted(state_path, &envelope.payload)?;
            }
        } else if let Some(state_path) = high_water_state {
            // The override lane is inactive, but persisted accepted-release
            // state exists: removing ENCLAVA_PLATFORM_RELEASE_PATH must not
            // silently drop the API back to an older bundled release. Only
            // deployments that wired the state var are affected; fresh
            // installs (no state file) start untouched.
            enforce_bundle_not_older_than_persisted_mark(state_path)?;
        }
        // The pending-commit obligation exists only on the override lane:
        // the bundled lane must never persist a mark (a bundle roll-forward
        // cannot raise the override lane's floor).
        let pending_high_water = if override_active {
            high_water_state.map(Path::to_path_buf)
        } else {
            None
        };
        Ok(LoadedPlatformRelease {
            envelope,
            pending_high_water,
        })
    }
}

/// Resolve the high-water-mark state lane.
///
/// The override lane (ENCLAVA_PLATFORM_RELEASE_PATH set) REQUIRES an explicit
/// ENCLAVA_PLATFORM_RELEASE_STATE: when the mark's location is only derived
/// from the override path (the old `<override-path>.accepted` default),
/// removing the override var also erases the only pointer to the mark, and
/// the bundled release is served without consulting the existing floor —
/// re-enabling the T2→T0 rollback the gate exists to refuse. Fail closed at
/// startup instead; the wired kustomize component sets the state var, so
/// correctly-wired deployments are unaffected.
///
/// Without an override, an explicit state var still guards the bundled lane
/// against a vanished override (accidental manifest rollback, env-var
/// removal); no state var at all means no high-water lane (fresh installs).
fn resolve_high_water_state(
    override_path: Option<&str>,
    state_env: Option<String>,
) -> Result<Option<PathBuf>, PlatformReleaseError> {
    match (override_path, state_env) {
        (Some(_), Some(state)) => Ok(Some(PathBuf::from(state))),
        (Some(_), None) => Err(PlatformReleaseError::MissingOverrideStatePath),
        (None, Some(state)) => Ok(Some(PathBuf::from(state))),
        (None, None) => Ok(None),
    }
}

/// Persisted newest-accepted override. `payload_sha256` digests the exact
/// canonical bytes the envelope signature covers, so two envelopes that reuse
/// the same `{version, created_at}` pair with different signed content
/// (measurements, policy, digests) cannot pass as "the same release".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct AcceptedOverrideMark {
    platform_release_version: String,
    created_at: String,
    /// Empty for marks persisted by the pre-digest version (serde default):
    /// such a legacy mark still floors timestamp-downgrades but can never
    /// equal a freshly computed digest, so any equal-timestamp candidate
    /// fails closed against it.
    #[serde(default)]
    payload_sha256: String,
}

impl AcceptedOverrideMark {
    fn of(release: &PlatformRelease) -> Result<Self, PlatformReleaseError> {
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
        Some(p) if !mark_is_older(&p, &bundled_mark)? => Some(p),
        _ => Some(bundled_mark),
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
    let candidate_ts = parse_release_timestamp(&candidate.created_at)?;
    let baseline_ts = parse_release_timestamp(&baseline.created_at)?;
    Ok(candidate_ts < baseline_ts
        || (candidate_ts == baseline_ts
            && (candidate.platform_release_version != baseline.platform_release_version
                || candidate.payload_sha256 != baseline.payload_sha256)))
}

/// Second downgrade gate for the env-path override lane: compare against the
/// newest release this host has ever accepted, not just the bundle. Without
/// it, a file swap from an accepted T2 release to a validly-signed T1
/// release (T0 < T1 < T2) sails through `enforce_release_not_older_than_
/// bundled`. Corrupt state fails closed (an attacker must not be able to
/// disable the gate by scribbling on the state file), and a failed persist
/// fails closed too (accepting without recording would reset the mark).
///
/// The whole read-compare-persist sequence runs under an exclusive flock on
/// `<state>.lock`: with two API replicas racing a projected override that
/// changes T2 → T1, both would otherwise read the same older floor before
/// either persists, and the T1 replica could overwrite the T2 mark and start
/// with the stale release. The lock makes the sequence atomic across
/// processes; it is auto-released on process death.
#[cfg_attr(not(test), allow(dead_code))]
fn enforce_override_not_older_than_last_accepted(
    state_path: &Path,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    enforce_override_gate(state_path, release, true)
}

/// Advance the persisted high-water mark for an override that startup
/// validation has fully accepted (runtime class, env-match, sidecar pins).
/// Split from the load-time check so a release failing a later startup
/// check cannot raise the floor and strand the deployment above its last
/// working override. Re-runs the comparison under the flock: if a
/// concurrent replica already accepted something newer, this refuses
/// instead of lowering the mark.
pub fn commit_override_acceptance(
    state_path: &Path,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    enforce_override_gate(state_path, release, true)
}

/// Check-only twin of `enforce_override_not_older_than_last_accepted`: same
/// corrupt-state and comparison semantics, but never persists the mark. Used
/// during load so a release that later fails startup validation cannot
/// advance the floor; the full gate runs once startup has accepted it.
fn check_override_not_older_than_last_accepted(
    state_path: &Path,
    release: &PlatformRelease,
) -> Result<(), PlatformReleaseError> {
    enforce_override_gate(state_path, release, false)
}

fn enforce_override_gate(
    state_path: &Path,
    release: &PlatformRelease,
    persist: bool,
) -> Result<(), PlatformReleaseError> {
    parse_release_timestamp(&release.created_at)?;
    let mut lock_path = state_path.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| {
            PlatformReleaseError::HighWaterMarkPersistFailed {
                state_path: state_path.display().to_string(),
                source: error,
            }
        })?;
    }
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .map_err(|error| PlatformReleaseError::HighWaterMarkPersistFailed {
            state_path: state_path.display().to_string(),
            source: error,
        })?;
    let mut lock = fd_lock::RwLock::new(lock_file);
    let _guard = lock
        .write()
        .map_err(|err| PlatformReleaseError::HighWaterMarkPersistFailed {
            state_path: state_path.display().to_string(),
            source: std::io::Error::new(
                err.kind(),
                format!("acquire {}: {err}", lock_path.display()),
            ),
        })?;
    enforce_override_not_older_than_last_accepted_locked(state_path, release, persist)
}

fn enforce_override_not_older_than_last_accepted_locked(
    state_path: &Path,
    release: &PlatformRelease,
    persist: bool,
) -> Result<(), PlatformReleaseError> {
    let persisted =
        match std::fs::read_to_string(state_path) {
            Ok(raw) => Some(serde_json::from_str::<AcceptedOverrideMark>(&raw).map_err(
                |error| PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: std::io::Error::other(format!(
                        "corrupt high-water-mark state ({error}); \
                         if the corruption is benign, remove the file after verifying \
                         with the operator"
                    )),
                },
            )?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: err,
                });
            }
        };
    let floor = newest_mark(persisted)?;
    if let Some(mark) = &floor
        && mark_is_older(&AcceptedOverrideMark::of(release)?, mark)?
    {
        return Err(PlatformReleaseError::OverrideDowngradeRefused {
            override_version: release.platform_release_version.clone(),
            override_created: release.created_at.clone(),
            accepted_version: mark.platform_release_version.clone(),
            accepted_created: mark.created_at.clone(),
            state_path: state_path.display().to_string(),
        });
    }
    let mark = AcceptedOverrideMark::of(release)?;
    if floor.as_ref() != Some(&mark) && persist {
        // Durable atomic persist: write a sibling temp file, fsync it, then
        // rename over the mark. A bare truncate-in-place write could tear on
        // crash (next boot fails closed) or silently lose the mark on power
        // loss — resetting the anti-rollback floor to the bundle, which is
        // exactly the downgrade this gate exists to refuse.
        let mut tmp = state_path.as_os_str().to_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let bytes = serde_json::to_vec_pretty(&mark)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .map_err(|error| PlatformReleaseError::HighWaterMarkPersistFailed {
                state_path: state_path.display().to_string(),
                source: error,
            })?;
        std::io::Write::write_all(&mut file, &bytes).map_err(|error| {
            PlatformReleaseError::HighWaterMarkPersistFailed {
                state_path: state_path.display().to_string(),
                source: error,
            }
        })?;
        file.sync_all()
            .map_err(|error| PlatformReleaseError::HighWaterMarkPersistFailed {
                state_path: state_path.display().to_string(),
                source: error,
            })?;
        drop(file);
        std::fs::rename(&tmp, state_path).map_err(|error| {
            PlatformReleaseError::HighWaterMarkPersistFailed {
                state_path: state_path.display().to_string(),
                source: error,
            }
        })?;
        // fsync the directory so the rename itself survives power loss.
        // Failure to make the rename durable is a failed persist, not a
        // warning: after a crash the old mark could resurface and re-admit
        // a release the gate already refused. An empty parent (relative
        // means the working directory — resolve it to `.` so the sync
        // target can actually be opened (and the rename made durable)
        // instead of skipping the directory fsync entirely.
        let parent = state_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        {
            let dir = std::fs::File::open(parent).map_err(|error| {
                PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: error,
                }
            })?;
            dir.sync_all()
                .map_err(|error| PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: error,
                })?;
        }
    }
    Ok(())
}

/// Bundled-lane companion to the override high-water gate: when a deployment
/// wires `ENCLAVA_PLATFORM_RELEASE_STATE` but `ENCLAVA_PLATFORM_RELEASE_PATH`
/// is unset/empty, the bundled release is compared against the persisted
/// mark before it is served. Removing the override env var (accidental
/// manifest rollback, env-var tampering) must not silently drop the API back
/// to a release older than anything this state lane has already accepted.
/// No state file yet (fresh install, override never used) → no-op, so
/// deployments that wire the state var "for later" are not blocked. Corrupt
/// state fails closed exactly like the override lane.
fn enforce_bundle_not_older_than_persisted_mark(
    state_path: &Path,
) -> Result<(), PlatformReleaseError> {
    let persisted =
        match std::fs::read_to_string(state_path) {
            Ok(raw) => Some(serde_json::from_str::<AcceptedOverrideMark>(&raw).map_err(
                |error| PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: std::io::Error::other(format!(
                        "corrupt high-water-mark state ({error}); \
                     if the corruption is benign, remove the file after verifying \
                     with the operator"
                    )),
                },
            )?),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(PlatformReleaseError::HighWaterMarkPersistFailed {
                    state_path: state_path.display().to_string(),
                    source: err,
                });
            }
        };
    let Some(mark) = newest_mark(persisted)? else {
        return Ok(());
    };    let bundled: PlatformReleaseEnvelope = serde_json::from_str(BUNDLED_PLATFORM_RELEASE)?;
    let bundled_mark = AcceptedOverrideMark::of(&bundled.payload)?;
    if mark_is_older(&bundled_mark, &mark)? {
        return Err(PlatformReleaseError::OverrideDowngradeRefused {
            override_version: bundled_mark.platform_release_version,
            override_created: bundled_mark.created_at,
            accepted_version: mark.platform_release_version,
            accepted_created: mark.created_at,
            state_path: state_path.display().to_string(),
        });
    }
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

    /// Mirrors main.rs: load is check-only; the mark advances only when
    /// startup validation accepts, via commit_override_acceptance.
    fn load_and_maybe_commit(
        raw: String,
        state: &std::path::Path,
        commit: bool,
    ) -> Result<(), PlatformReleaseError> {
        let loaded = PlatformReleaseEnvelope::load_verified_from_raw(raw, true, Some(state))?;
        if commit && let Some(path) = loaded.pending_high_water.as_ref() {
            commit_override_acceptance(path, &loaded.envelope.payload)?;
        }
        Ok(())
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

    #[test]
    fn override_lane_requires_explicit_state_path() {
        // Codex P1 (cap#165): with only ENCLAVA_PLATFORM_RELEASE_PATH set,
        // the old derived default (`<override-path>.accepted`) left the mark
        // undiscoverable once the override var was removed, silently
        // re-enabling the T2→T0 rollback. The override lane now fails closed
        // unless the state var is wired explicitly.
        assert!(matches!(
            resolve_high_water_state(Some("/etc/platform-release.json"), None),
            Err(PlatformReleaseError::MissingOverrideStatePath)
        ));
        // Explicit state on the override lane: used as-is.
        assert_eq!(
            resolve_high_water_state(
                Some("/etc/platform-release.json"),
                Some("/var/lib/enclava/platform-release.accepted".into())
            )
            .unwrap(),
            Some(PathBuf::from("/var/lib/enclava/platform-release.accepted"))
        );
        // Bundled lane: explicit state still guards against a vanished
        // override; no state var at all means no high-water lane.
        assert_eq!(
            resolve_high_water_state(None, Some("release.accepted".into())).unwrap(),
            Some(PathBuf::from("release.accepted"))
        );
        assert_eq!(resolve_high_water_state(None, None).unwrap(), None);
    }

    #[test]
    fn env_override_path_rejects_validly_signed_stale_release() {
        // A stale envelope that PASSES signature verification must still be
        // refused when it arrives via the ENCLAVA_PLATFORM_RELEASE_PATH
        // override lane.
        let stale_raw = resigned_envelope_with_created_at("2020-06-01T00:00:00Z");
        // Signature/root verification alone accepts it...
        let parsed: PlatformReleaseEnvelope = serde_json::from_str(&stale_raw).unwrap();
        assert!(verify_envelope(parsed).is_ok());
        // ...but the override lane refuses the downgrade.
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(stale_raw, true, None),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));
    }

    #[test]
    fn env_override_path_accepts_validly_signed_newer_release() {
        let newer_raw = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        assert!(PlatformReleaseEnvelope::load_verified_from_raw(newer_raw, true, None).is_ok());
    }

    #[test]
    fn bundled_lane_skips_the_downgrade_gate() {
        // The bundled release passes even though it is "the same age" as
        // itself; the gate only applies to the override lane.
        assert!(
            PlatformReleaseEnvelope::load_verified_from_raw(
                BUNDLED_PLATFORM_RELEASE.to_string(),
                false,
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn override_high_water_mark_blocks_file_swap_to_older_release() {
        // Codex review scenario: bundle T0, accepted override T2; a later
        // file swap to a validly-signed T1 (T0 < T1 < T2) must be refused —
        // the persisted high-water mark, not the bundle, is the baseline.
        let dir = std::env::temp_dir().join(format!("pr-hwm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        let t1 = resigned_envelope_with_created_at("2998-01-01T00:00:00Z");
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");

        // First boot with override T2: accepted, mark persisted (the
        // commit happens after startup validation, mirroring main.rs).
        assert!(load_and_maybe_commit(t2.clone(), &state, true).is_ok());
        let mark: AcceptedOverrideMark =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(mark.created_at, "2999-01-01T00:00:00Z");

        // File swap to T1 (still newer than the bundle): refused.
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(t1, true, Some(&state)),
            Err(PlatformReleaseError::OverrideDowngradeRefused { .. })
        ));

        // Steady state: same T2 reload-and-commit writes nothing new.
        let before = std::fs::metadata(&state).unwrap().modified().unwrap();
        assert!(load_and_maybe_commit(t2.clone(), &state, true).is_ok());
        let after = std::fs::metadata(&state).unwrap().modified().unwrap();
        assert_eq!(before, after);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_high_water_mark_corrupt_state_fails_closed() {
        let dir = std::env::temp_dir().join(format!("pr-hwm-corrupt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");
        std::fs::write(&state, "{ not json").unwrap();

        let newer = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(newer, true, Some(&state)),
            Err(PlatformReleaseError::HighWaterMarkPersistFailed { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_high_water_mark_never_regresses_below_bundle() {
        // A persisted mark older than the current bundle (e.g. left over
        // from an older API image) must not LOWER the floor: the effective
        // baseline is max(bundled, persisted).
        let dir = std::env::temp_dir().join(format!("pr-hwm-floor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");
        let bundled: PlatformReleaseEnvelope =
            serde_json::from_str(BUNDLED_PLATFORM_RELEASE).unwrap();
        let stale_mark = AcceptedOverrideMark {
            platform_release_version: "ancient".to_string(),
            created_at: "2020-01-01T00:00:00Z".to_string(),
            payload_sha256: "0".repeat(64),
        };
        std::fs::write(&state, serde_json::to_vec(&stale_mark).unwrap()).unwrap();

        // Something strictly older than the bundle is refused even though
        // the persisted mark would have allowed it.
        let stale_release = resigned_envelope_with_created_at("2021-01-01T00:00:00Z");
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(stale_release, true, Some(&state)),
            Err(PlatformReleaseError::DowngradeRefused { .. })
        ));

        // Something newer than both is accepted and RAISES the persisted
        // mark above the bundle.
        let newer = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        assert!(load_and_maybe_commit(newer, &state, true).is_ok());
        let mark: AcceptedOverrideMark =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(mark.created_at, "2999-01-01T00:00:00Z");
        assert_ne!(
            mark.platform_release_version,
            bundled.payload.platform_release_version
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_high_water_mark_unwritable_state_fails_closed() {
        // Persisting the mark is part of accepting the release: a read-only
        // state location must fail startup with the actionable error, not
        // silently skip the mark.
        let dir = std::env::temp_dir().join(format!("pr-hwm-ro-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("subdir").join("release.accepted");
        std::fs::create_dir_all(dir.join("subdir")).unwrap();
        let mut perms = std::fs::metadata(dir.join("subdir")).unwrap().permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.join("subdir"), perms).unwrap();

        let newer = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        let result = PlatformReleaseEnvelope::load_verified_from_raw(newer, true, Some(&state));
        let mut perms = std::fs::metadata(dir.join("subdir")).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir.join("subdir"), perms).unwrap();
        assert!(matches!(
            result,
            Err(PlatformReleaseError::HighWaterMarkPersistFailed { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_high_water_mark_same_pair_divergent_payload_refused() {
        // Codex P1: two validly-signed envelopes reusing the same
        // {platform_release_version, created_at} pair with different signed
        // content must not pass as "the same release" — the mark now binds
        // the canonical payload digest (the exact bytes the signature
        // covers).
        let dir = std::env::temp_dir().join(format!("pr-hwm-digest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        let first = resigned_envelope_with(
            "2999-01-01T00:00:00Z",
            "dev-same-pair",
            Some("https://kbs-first.example.test"),
        );
        let divergent = resigned_envelope_with(
            "2999-01-01T00:00:00Z",
            "dev-same-pair",
            Some("https://kbs-second.example.test"),
        );
        // Both pass signature verification on their own.
        for raw in [&first, &divergent] {
            let parsed: PlatformReleaseEnvelope = serde_json::from_str(raw).unwrap();
            assert!(verify_envelope(parsed).is_ok());
        }

        // First accepted; the divergent same-pair envelope is then refused.
        assert!(load_and_maybe_commit(first, &state, true).is_ok());
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(divergent, true, Some(&state)),
            Err(PlatformReleaseError::OverrideDowngradeRefused { .. })
        ));

        // Re-presenting the exact same envelope is still fine (steady state).
        let again = resigned_envelope_with(
            "2999-01-01T00:00:00Z",
            "dev-same-pair",
            Some("https://kbs-first.example.test"),
        );
        assert!(load_and_maybe_commit(again, &state, true).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bundled_lane_does_not_persist_or_commit_a_mark() {
        // main.rs commits the pending high-water mark after startup
        // validation; the bundled lane must never carry that obligation
        // (pending_high_water is None), or a bundle roll-forward could
        // raise the override lane's floor.
        let dir = std::env::temp_dir().join(format!("pr-hwm-bundled-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        let bundled = BUNDLED_PLATFORM_RELEASE.to_string();
        let loaded =
            PlatformReleaseEnvelope::load_verified_from_raw(bundled, false, Some(&state)).unwrap();
        assert!(
            loaded.pending_high_water.is_none(),
            "bundled lane must not carry a pending high-water commit"
        );
        assert!(!state.exists(), "bundled lane must not persist a mark");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn failed_startup_does_not_advance_the_high_water_mark() {
        // Devin P1 (cap#165): a signed-but-incompatible override that fails
        // a LATER startup check (runtime class, env match, sidecar pins)
        // must not raise the floor. Load is check-only; only
        // commit_override_acceptance (called after startup validation in
        // main.rs) persists. Scenario: load T2 without committing, then
        // restoring T1 must still be accepted — the deployment is not
        // stranded above its last working release.
        let dir = std::env::temp_dir().join(format!("pr-hwm-nocommit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        let t1 = resigned_envelope_with_created_at("2998-01-01T00:00:00Z");
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");

        // Load T2 (check passes) but startup fails before the commit.
        assert!(load_and_maybe_commit(t2, &state, false).is_ok());
        assert!(!state.exists(), "check-only load must not persist a mark");

        // Restoring T1 is still accepted: the floor was never raised.
        assert!(load_and_maybe_commit(t1.clone(), &state, true).is_ok());
        let mark: AcceptedOverrideMark =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(mark.created_at, "2998-01-01T00:00:00Z");

        // Once T2 IS committed (startup accepted it), T1 is refused.
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        assert!(load_and_maybe_commit(t2, &state, true).is_ok());
        assert!(matches!(
            load_and_maybe_commit(t1, &state, true),
            Err(PlatformReleaseError::OverrideDowngradeRefused { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Devin P2 (cap#165): a relative `ENCLAVA_PLATFORM_RELEASE_STATE`
    /// (empty `.parent()`) must resolve the dir-sync target to `.` — first
    /// acceptance previously failed with HighWaterMarkPersistFailed despite
    /// having written the mark.
    #[test]
    fn relative_state_path_persists_and_syncs_cwd() {
        let dir = std::env::temp_dir().join(format!("pr-hwm-relpath-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let state = std::path::PathBuf::from("release.accepted"); // relative — no parent
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        let result = load_and_maybe_commit(t2, &state, true);

        std::env::set_current_dir(prev_cwd).unwrap();
        assert!(
            result.is_ok(),
            "relative state path must not fail persist: {result:?}"
        );
        let mark: AcceptedOverrideMark =
            serde_json::from_str(&std::fs::read_to_string(dir.join("release.accepted")).unwrap())
                .unwrap();
        assert_eq!(mark.created_at, "2999-01-01T00:00:00Z");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_high_water_mark_gate_is_serialized_by_flock() {
        // Codex P1: two replicas racing a projected override change must not
        // interleave read/compare/write. The gate serializes on an exclusive
        // flock at `<state>.lock`; while another process holds that lock the
        // gate must block, so a stale accept can never slip between a
        // concurrent accept's read and persist.
        let dir = std::env::temp_dir().join(format!("pr-hwm-lock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        // Bootstrap: accept T2 once so the floor exists (creates the lock file).
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        let parsed: PlatformReleaseEnvelope = serde_json::from_str(&t2).unwrap();
        let release_t2 = verify_envelope(parsed).unwrap();
        assert!(enforce_override_not_older_than_last_accepted(&state, &release_t2).is_ok());

        // Hold the gate's lock the way a concurrent replica would.
        let lock_path = dir.join("release.accepted.lock");
        let lock_file = std::fs::OpenOptions::new()
            .write(true)
            .open(&lock_path)
            .unwrap();
        let mut external = fd_lock::RwLock::new(lock_file);
        let guard = external.write().unwrap();

        let state_clone = state.clone();
        let release_clone = release_t2.clone();
        let gate = std::thread::spawn(move || {
            enforce_override_not_older_than_last_accepted(&state_clone, &release_clone)
        });

        // While the lock is held the gate cannot finish.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !gate.is_finished(),
            "gate must block on the flock, not read torn state"
        );
        drop(guard);

        // Once released it completes (steady-state reload of the same release).
        assert!(gate.join().unwrap().is_ok());
        let mark: AcceptedOverrideMark =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        assert_eq!(mark.created_at, "2999-01-01T00:00:00Z");
        assert_eq!(mark.payload_sha256.len(), 64);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn override_removal_does_not_bypass_the_persisted_mark() {
        // Codex P1: after accepting an override at T2, removing/emptying
        // ENCLAVA_PLATFORM_RELEASE_PATH while the state lane stays wired
        // must not silently serve the (older) bundled release.
        let dir = std::env::temp_dir().join(format!("pr-hwm-removal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");

        // Accept T2 via the override lane (persists the mark).
        let t2 = resigned_envelope_with_created_at("2999-01-01T00:00:00Z");
        assert!(load_and_maybe_commit(t2, &state, true).is_ok());

        // Override env var removed: the bundled lane now compares against
        // the persisted mark and refuses (bundle < T2).
        assert!(matches!(
            PlatformReleaseEnvelope::load_verified_from_raw(
                BUNDLED_PLATFORM_RELEASE.to_string(),
                false,
                Some(&state)
            ),
            Err(PlatformReleaseError::OverrideDowngradeRefused { .. })
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn bundled_lane_without_state_file_starts_untouched() {
        // Fresh install: state var wired but no mark persisted yet — the
        // bundled release serves normally.
        let dir = std::env::temp_dir().join(format!("pr-hwm-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = dir.join("release.accepted");
        assert!(
            PlatformReleaseEnvelope::load_verified_from_raw(
                BUNDLED_PLATFORM_RELEASE.to_string(),
                false,
                Some(&state)
            )
            .is_ok()
        );
        // No mark is created by the bundled lane read-only check.
        assert!(!state.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}
