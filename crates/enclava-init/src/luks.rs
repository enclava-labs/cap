//! cryptsetup luksFormat / luksOpen via `libcryptsetup-rs`, with every open
//! authenticated by the HMAC-sealed LUKS2 header (see `luks2_seal`).
//!
//! Threat model: the host controls the persistent disk, so on-disk LUKS2
//! metadata is attacker-controlled (cap#242, Trail of Bits
//! CVE-2025-59054/58356 class). No cryptsetup operation ever consumes the
//! on-disk header: the full header region is read, MAC-verified, strictly
//! validated, and only a detached, MAC-slot-zeroed copy on tmpfs is handed to
//! cryptsetup.
//!
//! Requires `libcryptsetup-dev` (Debian) / `libcryptsetup-devel` (Fedora) at
//! build time and `libcryptsetup.so.12` at runtime. Inside the Kata SEV-SNP
//! guest the `dm_mod` and `dm_crypt` kernel features must be present. On
//! the production guest image they are built in, so CAP must not ask
//! kata-agent to modprobe them via `io.katacontainers.config.agent.kernel_modules`.
//!
//! Live Kata SEV-SNP validation showed LUKS format/open/mount works in the
//! guest when the runtime uses block hotplug plus `virtio-9p` filesystem
//! sharing. CAP avoids Kubernetes mountPropagation and starts app/caddy under
//! wait-exec helpers first, then this mounter sidecar bind-mounts the decrypted
//! paths into their mount namespaces and stays alive for the pod lifetime.
//! Fresh LUKS2 volumes are formatted AES-256-XTS with hmac-sha256
//! (dm-integrity) tags, 4096-byte sectors and a fixed Argon2id keyslot
//! profile (4 passes, 256 MiB, 1 lane, no benchmark) (cap#248) and then
//! ext4 before the first mount, so the runtime image must include
//! `mkfs.ext4`.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libcryptsetup_rs::{
    CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref, CryptPbkdfType, consts::flags::CryptActivate,
    consts::flags::CryptDeactivate, consts::flags::CryptPbkdf, consts::vals::CryptKdf,
    consts::vals::EncryptionFormat,
};

use crate::errors::{InitError, Result};
use crate::luks2_seal::{self, HeaderSeal, Luks2Region, validate_region};
use crate::secrets::DerivedSeed;
use crate::volume_profile::{Stage, VolumeProfile};

// Match ext4's block size and reduce per-data-byte integrity tag overhead.
const LUKS2_SECTOR_SIZE: u32 = 4096;
/// Minimum size for a FRESH format. The LUKS2 header occupies the first
/// 16 MiB and luksFormat succeeds even when the device ends inside it —
/// activation then has no data area and the volume is bricked. The floor
/// adds 16 MiB of payload headroom; it is a fresh-provisioning policy, not
/// an activation bound (17–31 MiB volumes DO activate and keep operating —
/// the scan never runs once a header exists). Keep in lockstep with
/// `enclava-engine` `validate.rs` `MIN_VOLUME_SIZE_MIB`, which refuses
/// undersized fresh volumes at admission.
const MIN_VOLUME_BYTES: u64 = 32 * 1024 * 1024;
static KEY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);
static DETACHED_HEADER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Total LUKS2 volume-key bytes: 64 cipher key (AES-256-XTS) + 32 integrity
/// key (hmac-sha256). The library takes the total; 64 silently downgrades to
/// a non-integrity volume (cap#248).
const VOLUME_KEY_BYTES: usize = 96;
/// Library spelling of the integrity algorithm (the CLI spells it
/// `hmac-sha256`; see [`INTEGRITY_CLI`]).
const INTEGRITY_LIB: &str = "hmac(sha256)";
/// Zero-write chunk for integrity-tag initialization through the wipe
/// mapper (4 MiB keeps write amplification bounded on large volumes).
const INTEGRITY_WIPE_CHUNK: usize = 4 * 1024 * 1024;
/// CLI spelling of the integrity algorithm.
const INTEGRITY_CLI: &str = "hmac-sha256";

// A fixed memory/work budget avoids calibrating against throttled startup CPU.
// Keep this below the 512-MiB container limit without reducing password-unlock costs.
const LUKS2_PBKDF_CLI: &str = "argon2id";
const LUKS2_PBKDF_PASSES: u32 = 4;
const LUKS2_PBKDF_MEMORY_KIB: u32 = 262144;
const LUKS2_PBKDF_PARALLEL: u32 = 1;

/// Path to the activated mapper device.
#[derive(Debug, Clone)]
pub struct LuksOpened {
    pub mapper_path: PathBuf,
    /// True when this call formatted a fresh device (LUKS format + mkfs) rather
    /// than opening an existing volume. Numeric telemetry only; the decision
    /// itself stays in `format_decision`.
    pub formatted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormatDecision {
    FormatFreshDevice,
    OpenExisting,
}

/// Everything the authenticated-open flow needs per volume.
#[derive(Clone)]
pub struct VolumeKeys {
    /// LUKS passphrase (HKDF branch of the owner seed, per volume).
    pub passphrase: DerivedSeed,
    /// Header-MAC key (a *different* HKDF branch, per volume).
    pub header_mac_key: DerivedSeed,
}

impl VolumeKeys {
    pub fn new(passphrase: DerivedSeed, header_mac_key: DerivedSeed) -> Self {
        Self {
            passphrase,
            header_mac_key,
        }
    }
}

/// Detect whether the device carries a LUKS2 header we recognize, without
/// handing attacker-controlled bytes to cryptsetup.
///
/// A sealed header (MAC slots nonzero) makes the on-disk header
/// checksum-invalid for stock cryptsetup, so legacy probes (libcryptsetup
/// load / `isLuks` / raw magic) all fail on sealed volumes. Recognition
/// therefore goes through [`luks2_seal::read_header_region`]: success means
/// the region parses as one of ours, sealed or legacy.
pub fn is_formatted(device: &Path) -> Result<bool> {
    match luks2_seal::read_header_region(device) {
        Ok(_) => Ok(true),
        Err(region_err) => {
            // A raw LUKS2 magic probe is deliberately retained as a positive
            // fallback: if a reattached block device has LUKS2 magic but the
            // region read is temporarily inconclusive, opening it may still
            // succeed; reformatting it would irreversibly destroy tenant
            // state. Any open still runs the full MAC + strict validation
            // gate, so this cannot bypass authentication.
            if device_has_luks2_header_magic(device)? {
                tracing::warn!(
                    device = %device.display(),
                    error = %region_err,
                    "LUKS2 magic present but header region unreadable; deferring decision to open-time validation"
                );
                return Ok(true);
            }
            if cryptsetup_is_luks(device)? == Some(true) {
                return Ok(true);
            }
            Ok(false)
        }
    }
}

/// Format `device` as LUKS2, add `keys.passphrase` as keyslot 0, and seal the
/// header with `keys.header_mac_key`.
///
/// Used on first boot when the underlying block device is fresh.
pub fn format(device: &Path, keys: &VolumeKeys, profile: &mut VolumeProfile) -> Result<()> {
    if let Err(cli_err) = profile.run(Stage::FormatCli, |_| {
        format_with_cryptsetup_cli(device, &keys.passphrase)
    }) {
        tracing::warn!(
            device = %device.display(),
            error = %cli_err,
            "cryptsetup CLI format failed; falling back to libcryptsetup"
        );
        profile
            .run(Stage::FormatFallback, |profile| {
                format_with_libcryptsetup(device, &keys.passphrase, profile)
            })
            .map_err(|lib_err| {
                InitError::Luks(format!(
                    "format cli: {cli_err}; libcryptsetup fallback: {lib_err}"
                ))
            })?;
    }

    // Validate the actual formatter output before authenticating it.
    profile.run(Stage::HeaderSeal, |_| {
        let region = luks2_seal::read_header_region(device)?;
        validate_region(&region)?;
        luks2_seal::seal_on_disk(device, &region, &keys.header_mac_key)
    })?;
    tracing::info!(
        device = %device.display(),
        "formatted and HMAC-sealed LUKS2 header"
    );
    Ok(())
}

/// Open `device` to `/dev/mapper/<mapping_name>` using `keys`.
///
/// The header must already exist (call [`format`] first on a fresh device).
/// Every path through this function authenticates the header (MAC, or
/// adoption for legacy volumes) before cryptsetup sees any bytes, and only
/// ever via a detached copy on tmpfs.
pub fn open(device: &Path, mapping_name: &str, keys: &VolumeKeys) -> Result<LuksOpened> {
    open_with_policy(device, mapping_name, keys, &LuksOpenPolicy::default())
}

/// [`open`] with an explicit rollout policy; see [`LuksOpenPolicy`].
pub fn open_with_policy(
    device: &Path,
    mapping_name: &str,
    keys: &VolumeKeys,
    policy: &LuksOpenPolicy,
) -> Result<LuksOpened> {
    let mapper_path = PathBuf::from(format!("/dev/mapper/{mapping_name}"));
    if mapper_path.exists() {
        validate_existing_mapper(device, mapping_name, keys, policy)?;
        return Ok(LuksOpened {
            mapper_path,
            formatted: false,
        });
    }

    luks2_seal::read_header_region(device)
        .and_then(|region| {
            validate_region(&region)?;
            authenticated_open(device, &region, mapping_name, keys, policy)
        })
        .map(|_| LuksOpened {
            mapper_path,
            formatted: false,
        })
}

/// Policy for the LUKS2 header-seal rollout gate (cap#242 review: sealed
/// volumes must not accept unsealed-header rollback).
///
/// `allow_legacy_adoption` governs the `HeaderSeal::Unsealed` branch: during
/// the rollout window a pre-seal ("legacy") volume is adopted after the
/// strict-validation + passphrase gate, but once the signed cc_init_data
/// declares the seal required, an unsealed header on a formatted device is
/// rejected as a rollback/host substitution instead of re-adopted. The value
/// comes from the *signed* `luks2_header_seal` claim, so the host cannot
/// flip it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LuksOpenPolicy {
    pub allow_legacy_adoption: bool,
}

impl Default for LuksOpenPolicy {
    fn default() -> Self {
        // Rollout window: unsealed headers can still occur (interrupted
        // seal, older signed artifacts without the claim), so absence of
        // the signed claim keeps adoption allowed.
        Self {
            allow_legacy_adoption: true,
        }
    }
}

/// Shared authenticated-open core: verify the seal (adopting legacy volumes
/// after a strict-validation + passphrase gate), materialize the detached
/// copy on tmpfs, and activate through it.
fn authenticated_open(
    device: &Path,
    region: &Luks2Region,
    mapping_name: &str,
    keys: &VolumeKeys,
    policy: &LuksOpenPolicy,
) -> Result<()> {
    let seal = luks2_seal::verify_header_seal(region, &keys.header_mac_key)?;
    let detached_path = detached_header_path(mapping_name);

    // Remove detached header copies orphaned by earlier (crashed/killed)
    // boots: they are PID-named and would otherwise accumulate until the
    // tmpfs size check rejects every subsequent boot (cap#244 review).
    cleanup_stale_detached_copies();

    let result = (|| -> Result<()> {
        luks2_seal::write_detached_copy(region, &detached_path)?;

        match seal {
            HeaderSeal::Sealed => {
                activate_detached(device, &detached_path, mapping_name, &keys.passphrase)?;
            }
            HeaderSeal::InterruptedSeal => {
                // A previous boot's seal was interrupted between the two slot
                // writes. verify_header_seal already proved the surviving MAC
                // authenticates this exact payload under our key (the host
                // cannot forge that), so the header is not attacker-chosen:
                // finish the seal and activate through the detached copy.
                luks2_seal::seal_on_disk(device, region, &keys.header_mac_key)?;
                tracing::info!(
                    device = %device.display(),
                    "completed interrupted header seal from previous boot"
                );
                activate_detached(device, &detached_path, mapping_name, &keys.passphrase)?;
            }
            HeaderSeal::Unsealed => {
                // Legacy pre-seal volume — but only while the signed rollout
                // gate still allows adoption. With the seal required, an
                // unsealed header on a formatted device means the host
                // restored a pre-seal header (rollback) or zeroed both MAC
                // slots; fail closed either way.
                if !policy.allow_legacy_adoption {
                    return Err(InitError::Luks(format!(
                        "LUKS2 header on {} carries no HMAC seal but the signed \
                         configuration requires sealing; possible header rollback \
                         or tampering, refusing to open",
                        device.display()
                    )));
                }
                // Gate adoption on a passphrase test through the detached
                // copy, then seal. Adoption never falls back to an in-place
                // open.
                tracing::warn!(
                    device = %device.display(),
                    "LUKS2 header carries no HMAC seal (pre-#242 volume); adopting after strict validation and passphrase gate"
                );
                if let Err(e) = test_passphrase_detached(device, &detached_path, &keys.passphrase) {
                    return Err(InitError::Luks(format!(
                        "refusing to adopt legacy unsealed header: passphrase gate failed: {e}"
                    )));
                }
                luks2_seal::seal_on_disk(device, region, &keys.header_mac_key)?;
                tracing::info!(
                    device = %device.display(),
                    "adopted legacy LUKS2 volume and sealed its header"
                );
                activate_detached(device, &detached_path, mapping_name, &keys.passphrase)?;
            }
        }

        Ok(())
    })();

    luks2_seal::wipe_detached_copy(&detached_path, region.bytes.len());
    result
}

fn activate_detached(
    device: &Path,
    detached_path: &Path,
    mapping_name: &str,
    passphrase: &DerivedSeed,
) -> Result<()> {
    if let Err(cli_err) =
        open_detached_with_cryptsetup_cli(device, detached_path, mapping_name, passphrase)
    {
        tracing::warn!(
            device = %device.display(),
            mapping = mapping_name,
            error = %cli_err,
            "cryptsetup CLI activate failed; falling back to libcryptsetup"
        );
        activate_detached_with_libcryptsetup(device, detached_path, mapping_name, passphrase)
            .map_err(|lib_err| {
                InitError::Luks(format!(
                    "activate cli: {cli_err}; libcryptsetup fallback: {lib_err}"
                ))
            })?;
    }
    Ok(())
}

fn validate_existing_mapper(
    device: &Path,
    mapping_name: &str,
    keys: &VolumeKeys,
    policy: &LuksOpenPolicy,
) -> Result<()> {
    // The status fields (device, cipher, keysize, offset) tie the live
    // mapper to the exact header shape we MAC-verified: cryptsetup reports
    // them from the header it activated with, so a mapper activated from a
    // substituted header (e.g. cipher_null-swapped metadata with the
    // legitimate UUID cloned in) diverges here. A missing device line is an
    // error, not a pass (cap#244 self-review).
    let status = cryptsetup_status_full(mapping_name)?;
    let Some(status_device) = &status.device else {
        return Err(InitError::Luks(format!(
            "cryptsetup status {mapping_name} reported no backing device; \
             refusing to reuse the mapper"
        )));
    };
    if !paths_equivalent(status_device, device) {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} is backed by {}, expected {}",
            status_device.display(),
            device.display()
        )));
    }
    let region = luks2_seal::read_header_region(device)?;
    validate_region(&region)?;
    // Bind the live mapper to the authenticated header through kernel dm state.
    verify_active_mapper_volume_key(device, &region, mapping_name, keys)?;
    // The top dm-crypt table sits over dm-integrity, so its offset is zero,
    // not the backing device's header offset. The lower stack is checked separately.
    if status.cipher.as_deref() != Some("aes-xts-plain64") {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} cipher is {:?}, expected \
             aes-xts-plain64; refusing to reuse the mapper",
            status.cipher
        )));
    }
    if status.keysize_bits != Some(768) {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} keysize is {:?} bits, expected 768 \
             (512 cipher + 256 integrity); refusing to reuse the mapper",
            status.keysize_bits
        )));
    }
    if status.integrity.as_deref() != Some(INTEGRITY_LIB) {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} reports integrity {:?}, expected \
             {INTEGRITY_LIB}; refusing to reuse the mapper",
            status.integrity
        )));
    }
    if status.offset_sectors != Some(0) {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} offset is {:?} sectors, expected 0 \
             (dm-crypt table over the integrity device); refusing to reuse the mapper",
            status.offset_sectors
        )));
    }
    verify_stacked_integrity_mapper(device, &region, mapping_name)?;
    let mut seal = luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?;
    if let HeaderSeal::Unsealed = seal {
        // Mapper already active for a legacy volume this boot; adopt+seal
        // through the same gate the open path uses — including the signed
        // rollout gate: once sealing is required, an unsealed header is a
        // rollback, not a legacy volume.
        if !policy.allow_legacy_adoption {
            return Err(InitError::Luks(format!(
                "existing mapper {mapping_name}: header on {} carries no HMAC seal but \
                 the signed configuration requires sealing; possible header rollback \
                 or tampering, refusing to reuse the mapper",
                device.display()
            )));
        }
        // Same orphan sweep as the open path: a previous interrupted
        // adoption could have left detached copies behind (cap#244 review).
        cleanup_stale_detached_copies();
        let detached_path = detached_header_path(mapping_name);
        let result = (|| -> Result<()> {
            luks2_seal::write_detached_copy(&region, &detached_path)?;
            test_passphrase_detached(device, &detached_path, &keys.passphrase)?;
            luks2_seal::seal_on_disk(device, &region, &keys.header_mac_key)
        })();
        luks2_seal::wipe_detached_copy(&detached_path, region.bytes.len());
        result?;
        seal = HeaderSeal::Sealed;
    }
    if let HeaderSeal::InterruptedSeal = seal {
        // Same recovery as the open path: the surviving MAC authenticated
        // this exact payload under our key, so finish the interrupted seal.
        luks2_seal::seal_on_disk(device, &region, &keys.header_mac_key)?;
    }
    Ok(())
}

/// Validate the stacked dm-integrity pairing of a retained integrity mapper
/// using kernel sysfs truth (cap#244 review).
///
/// A legitimate `cryptsetup open` of a dm-integrity LUKS2 volume builds TWO
/// stacked device-mapper tables: a lower `<name>_dif` dm-integrity device
/// over the backing device (kernel uuid
/// `CRYPT-INTEGRITY-<luks-uuid-hex>-<name>_dif`, table start offset
/// `data_offset/512` sectors) and the top `<name>` dm-crypt device over that
/// (uuid `CRYPT-LUKS2-<luks-uuid-hex>-<name>`). `cryptsetup status <name>`
/// reports only the TOP table — offset 0 — so the header payload offset
/// cannot be checked there; instead both mappers are resolved through sysfs
/// (`/sys/block/dm-N/dm/{name,uuid}`, `/sys/block/dm-N/slaves`), which
/// userspace cannot forge for active tables, and checked to form the exact
/// expected stack for the MAC-verified header.
fn verify_stacked_integrity_mapper(
    device: &Path,
    region: &Luks2Region,
    mapping_name: &str,
) -> Result<()> {
    let expected_uuid: String = region_header_uuid(region)?
        .chars()
        .filter(|c| *c != '-')
        .collect();
    let dif_name = format!("{mapping_name}_dif");

    let top = sysfs_dm_of_mapper(mapping_name)?;
    let top_uuid = read_sysfs_trim(&format!("{}/uuid", top.display()))?;
    let expected_top = format!("CRYPT-LUKS2-{expected_uuid}-{mapping_name}");
    if top_uuid != expected_top {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} dm UUID {top_uuid:?} != expected \
             {expected_top:?}; refusing to reuse the mapper"
        )));
    }

    // The top dm-crypt table must sit over exactly the `_dif` sub-mapper.
    // `slaves` entries are kernel block-device names (dm-N); resolve each
    // to its kernel dm name for the comparison.
    let top_slaves = dm_slave_names(&top)?;
    if top_slaves != [dif_name.clone()] {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} is stacked over {top_slaves:?}, expected exactly \
             [{dif_name:?}]; refusing to reuse the mapper"
        )));
    }

    // The `_dif` dm-integrity device must carry the integrity uuid of the
    // same LUKS header and sit directly over the backing device, with its
    // table starting at the header's data_offset — this is where the LUKS
    // JSON payload offset actually lives for the stacked layout.
    let dif = sysfs_dm_by_name(&dif_name)?;
    let dif_uuid = read_sysfs_trim(&format!("{}/uuid", dif.display()))?;
    let expected_dif = format!("CRYPT-INTEGRITY-{expected_uuid}-{dif_name}");
    if dif_uuid != expected_dif {
        return Err(InitError::Luks(format!(
            "integrity sub-mapper {dif_name} dm UUID {dif_uuid:?} != expected \
             {expected_dif:?}; refusing to reuse the mapper"
        )));
    }
    let dif_slaves = read_sysfs_dir(&format!("{}/../slaves", dif.display()))?;
    if dif_slaves.len() != 1 {
        return Err(InitError::Luks(format!(
            "integrity sub-mapper {dif_name} is stacked over {dif_slaves:?}; expected exactly \
             one backing device; refusing to reuse the mapper"
        )));
    }
    // The backing-device identity check must compare KERNEL device
    // identity, not path strings: sysfs `slaves` reports the kernel block
    // name (e.g. vdb), while the device enclava-init was given may be a
    // container-local bind mount of the same node (e.g. /dev/csi0). Both
    // resolve to the same major:minor in sysfs, which is the identity the
    // kernel actually uses (cap#244 review).
    if !same_block_device(&dif_slaves[0], device) {
        return Err(InitError::Luks(format!(
            "integrity sub-mapper {dif_name} is backed by kernel device {}, which is not \
             the device opened as {} (major/minor mismatch)",
            dif_slaves[0],
            device.display()
        )));
    }

    tracing::info!(
        mapping = mapping_name,
        uuid = %expected_uuid,
        "existing stacked integrity mapper bound to authenticated header via kernel dm state"
    );
    Ok(())
}

/// Resolve the sysfs `/sys/block/dm-N` directory of an active mapper by its
/// `/dev/mapper/<name>` device number (same kernel-truth resolution as
/// [`mapper_dm_uuid`]).
fn sysfs_dm_of_mapper(mapping_name: &str) -> Result<PathBuf> {
    dm_sysfs_dir(mapping_name).map(PathBuf::from)
}

/// Resolve the sysfs `/sys/block/dm-N` directory whose kernel dm name is
/// exactly `name`. Scanning by name is safe here: `/sys/block/dm-*/dm/name`
/// is kernel-written, and duplicate active dm names cannot exist.
fn sysfs_dm_by_name(name: &str) -> Result<PathBuf> {
    let entries = std::fs::read_dir("/sys/block")
        .map_err(|e| InitError::Luks(format!("read /sys/block: {e}")))?;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(dm_name) = file_name.to_str() else {
            continue;
        };
        if !dm_name.starts_with("dm-") {
            continue;
        }
        let dir = entry.path().join("dm");
        if read_sysfs_trim(&dir.join("name").display().to_string()).is_ok_and(|n| n == name) {
            return Ok(dir);
        }
    }
    Err(InitError::Luks(format!(
        "no active dm device named {name:?} found in sysfs; refusing to reuse the mapper"
    )))
}

fn read_sysfs_trim(path: &str) -> Result<String> {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .map_err(|e| InitError::Luks(format!("read {path}: {e}")))
}

/// Kernel block-device names (e.g. `dm-0`) backing a dm device, resolved
/// to their kernel dm names (`/sys/block/dm-N/dm/name`) when they are
/// themselves dm devices; non-dm slaves (the raw backing device) are
/// returned as-is.
fn dm_slave_names(dm_sysfs: &Path) -> Result<Vec<String>> {
    let slaves = read_sysfs_dir(&format!("{}/../slaves", dm_sysfs.display()))?;
    slaves
        .into_iter()
        .map(|slave| {
            let name_file = format!("/sys/block/{slave}/dm/name");
            match std::fs::read_to_string(&name_file) {
                Ok(name) => Ok(name.trim().to_string()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(slave),
                Err(e) => Err(InitError::Luks(format!("read {name_file}: {e}"))),
            }
        })
        .collect()
}

fn read_sysfs_dir(path: &str) -> Result<Vec<String>> {
    let entries =
        std::fs::read_dir(path).map_err(|e| InitError::Luks(format!("read {path}: {e}")))?;
    Ok(entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect())
}

/// Bind the active mapper to the authenticated header.
///
/// The host controls the disk and could substitute a mapper we did not
/// create, so an existing `/dev/mapper/<name>` is never trusted on its
/// backing device alone. Two properties tie the live mapper to the header we
/// just MAC-verified:
///
/// 1. `cryptsetup status` reports the backing device, already checked by the
///    caller (`paths_equivalent`).
/// 2. The kernel-held dm UUID for the mapper (sysfs
///    `/sys/block/dm-N/dm/uuid`, written by device-mapper at table load and
///    not writable from userspace) has the form
///    `CRYPT-LUKS2-<luks-uuid>-<mapping-name>` where `<luks-uuid>` is the
///    UUID of the header cryptsetup loaded *at activation time*. Requiring that
///    UUID to equal the UUID of the MAC-verified on-disk header binds the
///    active mapper to this exact authenticated header — a mapper activated
///    from any other header (including a substituted or rolled-back one)
///    carries a different UUID and is rejected. The UUID sits at binary
///    offset 0xa8 of each metadata copy, inside the region the header MAC
///    covers, so it cannot be forged without the MAC key.
fn verify_active_mapper_volume_key(
    device: &Path,
    region: &Luks2Region,
    mapping_name: &str,
    _keys: &VolumeKeys,
) -> Result<()> {
    let expected_uuid = region_header_uuid(region)?;
    // cryptsetup strips the hyphens from the LUKS UUID when it builds the dm
    // UUID (CRYPT-LUKS2-<32 lowercase hex>-<name>), so compare the
    // normalized forms (cap#244 review).
    let expected_uuid_norm: String = expected_uuid.chars().filter(|c| *c != '-').collect();
    let dm_uuid = mapper_dm_uuid(mapping_name)?;
    // Kernel-held dm UUID format: CRYPT-LUKS2-<luks-uuid>-<mapping-name>
    let bound_uuid = dm_uuid
        .strip_prefix("CRYPT-LUKS2-")
        .and_then(|rest| rest.strip_suffix(&format!("-{mapping_name}")))
        .ok_or_else(|| {
            InitError::Luks(format!(
                "existing mapper {mapping_name} dm UUID {dm_uuid:?} is not a LUKS2 \
                 cryptsetup mapper bound to this name; refusing to use it"
            ))
        })?;
    if bound_uuid != expected_uuid_norm {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} was activated from header UUID {bound_uuid}, \
             but the authenticated header for {} has UUID {expected_uuid_norm}; possible mapper \
             or header substitution, refusing to use it",
            device.display()
        )));
    }
    tracing::info!(
        mapping = mapping_name,
        uuid = %expected_uuid,
        "existing mapper bound to authenticated header via kernel dm UUID"
    );
    Ok(())
}

/// LUKS2 UUID field offset inside each binary metadata copy (canonical
/// on-disk layout; strictly inside the MAC-covered region and outside the
/// checksum field our seal slot avoids).
const LUKS2_UUID_OFFSET: usize = 0xa8;
const LUKS2_UUID_LEN: usize = 36;

/// Extract the LUKS2 UUID string from the (MAC-verified) header region.
fn region_header_uuid(region: &Luks2Region) -> Result<String> {
    let raw = &region.bytes[LUKS2_UUID_OFFSET..LUKS2_UUID_OFFSET + LUKS2_UUID_LEN];
    let uuid = std::str::from_utf8(raw)
        .map_err(|_| InitError::Luks("LUKS2 header UUID is not UTF-8".into()))?
        .to_string();
    if uuid.bytes().any(|b| !(b.is_ascii_hexdigit() || b == b'-')) || uuid.len() != 36 {
        return Err(InitError::Luks(format!(
            "LUKS2 header UUID {uuid:?} is malformed"
        )));
    }
    Ok(uuid)
}

/// The kernel-held device-mapper UUID of an active mapper, read from sysfs.
///
/// The dm device backing `/dev/mapper/<mapping_name>` is resolved through
/// its `stat` device number to `/sys/dev/block/<maj:min>/dm/name`, which is
/// verified to equal the mapping name, and the sibling `dm/uuid` file holds
/// the UUID device-mapper assigned at table load
/// (`CRYPT-LUKS2-<luks-uuid>-<name>` for cryptsetup LUKS2 mappers). Both are
/// kernel-truth: userspace (including a malicious host process in the
/// guest's mount namespace view) cannot rewrite them for an active mapper.
/// Fails closed when the mapper is not backed by sysfs-visible dm state
/// (unexpected for a LUKS2 mapper). No `dmsetup` binary is required — the
/// runtime image does not install one (cap#244 review).
fn mapper_dm_uuid(mapping_name: &str) -> Result<String> {
    let sys_dm = dm_sysfs_dir(mapping_name)?;
    let uuid = std::fs::read_to_string(format!("{sys_dm}/uuid"))
        .map_err(|e| InitError::Luks(format!("read {sys_dm}/uuid: {e}")))?;
    let uuid = uuid.trim();
    if uuid.is_empty() {
        return Err(InitError::Luks(format!(
            "dm device for mapper {mapping_name} has an empty kernel UUID; \
             refusing to use it"
        )));
    }
    Ok(uuid.to_string())
}

/// Resolve the kernel sysfs dm directory (`/sys/dev/block/<maj:min>/dm`) of
/// the dm device backing `/dev/mapper/<mapping_name>`, verifying along the
/// way that the kernel dm name equals the mapping name (same kernel-truth
/// resolution `mapper_dm_uuid` uses).
fn dm_sysfs_dir(mapping_name: &str) -> Result<String> {
    let mapper_path = PathBuf::from(format!("/dev/mapper/{mapping_name}"));
    let meta = std::fs::metadata(&mapper_path)
        .map_err(|e| InitError::Luks(format!("stat {}: {e}", mapper_path.display())))?;
    // Decode the raw dev_t with glibc's exact gnu_dev_major/gnu_dev_minor
    // masks, so dm minors >= 256 (and extended majors) decode correctly
    // (cap#244 review). Mask constants mirror bits/sysmacros.h:
    // major = [0xfff00]>>8 | [0xfffff00000000000]>>32,
    // minor = [0xff] | [0xffffff00000]>>12.
    let rdev = {
        use std::os::unix::fs::MetadataExt;
        meta.rdev()
    };
    let major = ((rdev & 0x0000_0000_000f_ff00) >> 8) | ((rdev & 0xffff_f000_0000_0000) >> 32);
    let minor = (rdev & 0x0000_0000_0000_00ff) | ((rdev & 0x00000ffffff00000) >> 12);
    let sys_dm = format!("/sys/dev/block/{major}:{minor}/dm");
    let name = std::fs::read_to_string(format!("{sys_dm}/name"))
        .map_err(|e| InitError::Luks(format!("read {sys_dm}/name: {e}")))?;
    let name = name.trim();
    if name != mapping_name {
        return Err(InitError::Luks(format!(
            "dm device backing {mapping_name} reports name {name:?}; refusing to use it"
        )));
    }
    Ok(sys_dm)
}

/// Format the device if it's not yet a LUKS2 volume, then activate it.
pub fn format_if_unformatted_then_open(
    device: &Path,
    mapping_name: &str,
    keys: &VolumeKeys,
    profile: &mut VolumeProfile,
) -> Result<LuksOpened> {
    format_if_unformatted_then_open_with_policy(
        device,
        mapping_name,
        keys,
        &LuksOpenPolicy::default(),
        profile,
    )
}

/// [`format_if_unformatted_then_open`] with an explicit rollout policy; see
/// [`LuksOpenPolicy`]. A freshly formatted device is sealed before anyone
/// reads it back, so the policy only governs how an *existing* header is
/// opened.
pub fn format_if_unformatted_then_open_with_policy(
    device: &Path,
    mapping_name: &str,
    keys: &VolumeKeys,
    policy: &LuksOpenPolicy,
    profile: &mut VolumeProfile,
) -> Result<LuksOpened> {
    let (formatted, has_keyslots) = profile.run(Stage::HeaderProbe, |_| {
        let formatted = is_formatted(device)?;
        let has_keyslots = if formatted {
            has_luks_keyslots(device)?
        } else {
            None
        };
        Ok::<_, InitError>((formatted, has_keyslots))
    })?;
    let blank = if formatted {
        false
    } else {
        profile.run(Stage::BlankScan, |profile| {
            device_appears_blank(device, profile)
        })?
    };
    let needs_mkfs = matches!(
        format_decision(formatted, has_keyslots, blank)?,
        FormatDecision::FormatFreshDevice
    );
    if needs_mkfs {
        format(device, keys, profile)?;
    }
    let mut opened = profile.run(Stage::Open, |_| {
        open_with_policy(device, mapping_name, keys, policy)
    })?;
    if needs_mkfs {
        profile.run(Stage::Mkfs, |_| mkfs_ext4(&opened.mapper_path))?;
        opened.formatted = true;
    }
    Ok(opened)
}

fn format_decision(
    formatted: bool,
    has_keyslots: Option<bool>,
    blank: bool,
) -> Result<FormatDecision> {
    if formatted {
        if has_keyslots == Some(false) {
            return Err(InitError::Luks(
                "existing LUKS header has no keyslots; refusing to reformat persistent volume"
                    .to_string(),
            ));
        }
        return Ok(FormatDecision::OpenExisting);
    }

    if blank {
        Ok(FormatDecision::FormatFreshDevice)
    } else {
        Err(InitError::Luks(
            "device is not LUKS2 and is not blank; refusing to format persistent volume"
                .to_string(),
        ))
    }
}

fn mkfs_ext4(mapper_path: &Path) -> Result<()> {
    let status = std::process::Command::new(luks2_seal::MKFS_EXT4_BIN)
        .arg("-F")
        .arg(mapper_path)
        .status()
        .map_err(|e| InitError::Luks(format!("mkfs.ext4 {}: {e}", mapper_path.display())))?;
    if !status.success() {
        return Err(InitError::Luks(format!(
            "mkfs.ext4 {} exited with {status}",
            mapper_path.display()
        )));
    }
    Ok(())
}

fn format_with_libcryptsetup(
    device: &Path,
    key: &DerivedSeed,
    profile: &mut VolumeProfile,
) -> Result<()> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;
    let params = luks2_format_params();
    let mut params: CryptParamsLuks2Ref<'_> = (&params)
        .try_into()
        .map_err(|e| InitError::Luks(format!("luks2 params: {e}")))?;

    profile.run(Stage::LibFormat, |_| {
        dev.context_handle()
            .format(
                EncryptionFormat::Luks2,
                ("aes", "xts-plain64"),
                None,
                // The full key includes both AES-XTS and integrity key bytes.
                libcryptsetup_rs::Either::Right(VOLUME_KEY_BYTES),
                Some(&mut params),
            )
            .map_err(|e| InitError::Luks(format!("format: {e}")))
    })?;

    profile.run(Stage::Keyslot, |_| {
        // Keyslot creation reads device-level settings, not the format parameters.
        dev.settings_handle()
            .set_pbkdf_type(&fixed_argon2id_pbkdf())
            .map_err(|e| InitError::Luks(format!("set_pbkdf_type: {e}")))?;
        dev.keyslot_handle()
            .add_by_key(
                None,
                None,
                key.as_bytes(),
                libcryptsetup_rs::consts::flags::CryptVolumeKey::empty(),
            )
            .map_err(|e| InitError::Luks(format!("add_by_key: {e}")))
    })?;

    profile.run(Stage::IntegrityInitialize, |profile| {
        initialize_integrity_tags(&mut dev, key, profile)
    })
}

fn luks2_format_params() -> CryptParamsLuks2 {
    CryptParamsLuks2 {
        // Apply the same budget to format and subsequent keyslot creation.
        pbkdf: Some(fixed_argon2id_pbkdf()),
        integrity: Some(INTEGRITY_LIB.to_string()),
        // Let libcryptsetup derive dm-integrity defaults; the binding emits
        // empty CStrings for CryptParamsIntegrity fields.
        integrity_params: None,
        data_alignment: 0,
        data_device: None,
        sector_size: LUKS2_SECTOR_SIZE,
        label: None,
        subsystem: None,
    }
}

// The C API calls Argon2 passes "iterations" and validates the hash at format.
fn fixed_argon2id_pbkdf() -> CryptPbkdfType {
    CryptPbkdfType {
        type_: CryptKdf::Argon2Id,
        hash: "sha256".to_string(),
        time_ms: 0,
        iterations: LUKS2_PBKDF_PASSES,
        max_memory_kb: LUKS2_PBKDF_MEMORY_KIB,
        parallel_threads: LUKS2_PBKDF_PARALLEL,
        flags: CryptPbkdf::NO_BENCHMARK,
    }
}

/// crypt_format does not initialize dm-integrity tags like `luksFormat` does,
/// so reads of never-written sectors would fail. Writing zeros through the
/// activated mapper tags the whole data area.
fn initialize_integrity_tags(
    dev: &mut libcryptsetup_rs::CryptDevice,
    key: &DerivedSeed,
    profile: &mut VolumeProfile,
) -> Result<()> {
    let wipe_name = format!("enclava-init-wipe-{}", unguessable_suffix());

    // Match cryptsetup's own integrity initialization (`_wipe_data_device`):
    // activate the temporary mapper with NO_JOURNAL so the whole-area zero
    // write goes directly to dm-integrity tags instead of through the
    // journal, halving the write amplification of this already long wipe.
    // PRIVATE skips global udev rules for the throwaway device, as upstream.
    dev.activate_handle()
        .activate_by_passphrase(
            Some(&wipe_name),
            None,
            key.as_bytes(),
            CryptActivate::PRIVATE | CryptActivate::NO_JOURNAL,
        )
        .map_err(|e| {
            // Loading the dm-integrity target is the first kernel touch in
            // this flow. A failure here most often means the guest kernel
            // lacks CONFIG_DM_INTEGRITY (it is a Kconfig target separate
            // from dm_mod/dm_crypt); name it so operators see the actual
            // fix instead of a generic activation error.
            InitError::Luks(format!(
                "activate wipe mapper (does the guest kernel provide \
                 dm-integrity, CONFIG_DM_INTEGRITY?): {e}"
            ))
        })?;

    let result =
        write_zeros_through_mapper(&PathBuf::from(format!("/dev/mapper/{wipe_name}")), profile);
    let deactivate = dev
        .activate_handle()
        .deactivate(&wipe_name, CryptDeactivate::empty())
        .map_err(|e| InitError::Luks(format!("deactivate {wipe_name}: {e}")));

    result.and(deactivate)
}

fn unguessable_suffix() -> String {
    let mut bytes = [0u8; 16];
    let random = std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
    if random.is_ok() {
        return bytes.iter().map(|b| format!("{b:02x}")).collect();
    }
    let counter = KEY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{}-{counter}-{nanos:x}", std::process::id())
}

fn write_zeros_through_mapper(mapper_path: &Path, profile: &mut VolumeProfile) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(mapper_path)
        .map_err(|e| InitError::Luks(format!("open {}: {e}", mapper_path.display())))?;
    let len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| InitError::Luks(format!("seek {}: {e}", mapper_path.display())))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| InitError::Luks(format!("seek {}: {e}", mapper_path.display())))?;

    let zeros = vec![0u8; INTEGRITY_WIPE_CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = &zeros[..zeros.len().min(remaining as usize)];
        file.write_all(chunk)
            .map_err(|e| InitError::Luks(format!("zero {}: {e}", mapper_path.display())))?;
        remaining -= chunk.len() as u64;
        profile.initialized_bytes += chunk.len() as u64;
    }
    profile.run(Stage::IntegritySync, |_| {
        file.sync_all()
            .map_err(|e| InitError::Luks(format!("sync {}: {e}", mapper_path.display())))
    })
}

fn format_with_cryptsetup_cli(device: &Path, key: &DerivedSeed) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "--debug".to_string(),
            "--disable-locks".to_string(),
            "luksFormat".to_string(),
            path_arg(device)?,
            "--key-file".to_string(),
            path_arg(key_file)?,
            "--type".to_string(),
            "luks2".to_string(),
            "--cipher".to_string(),
            "aes-xts-plain64".to_string(),
            "--key-size".to_string(),
            "512".to_string(),
            "--sector-size".to_string(),
            LUKS2_SECTOR_SIZE.to_string(),
            "--integrity".to_string(),
            INTEGRITY_CLI.to_string(),
            // --pbkdf-force-iterations disables the benchmark (cryptsetup
            // requires --pbkdf alongside it); memory is in KiB.
            "--pbkdf".to_string(),
            LUKS2_PBKDF_CLI.to_string(),
            "--pbkdf-force-iterations".to_string(),
            LUKS2_PBKDF_PASSES.to_string(),
            "--pbkdf-memory".to_string(),
            LUKS2_PBKDF_MEMORY_KIB.to_string(),
            "--pbkdf-parallel".to_string(),
            LUKS2_PBKDF_PARALLEL.to_string(),
            "--batch-mode".to_string(),
        ];
        run_command(luks2_seal::CRYPTSETUP_BIN, &args)
    })
}

/// Open via the detached header using the cryptsetup CLI.
fn open_detached_with_cryptsetup_cli(
    device: &Path,
    detached_path: &Path,
    mapping_name: &str,
    key: &DerivedSeed,
) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "--debug".to_string(),
            "--disable-locks".to_string(),
            "open".to_string(),
            "--header".to_string(),
            path_arg(detached_path)?,
            "--key-file".to_string(),
            path_arg(key_file)?,
            path_arg(device)?,
            mapping_name.to_string(),
        ];
        run_command(luks2_seal::CRYPTSETUP_BIN, &args)
    })
}

/// Open via the detached header using libcryptsetup
/// (`crypt_init_data_device`: header device + data device).
fn activate_detached_with_libcryptsetup(
    device: &Path,
    detached_path: &Path,
    mapping_name: &str,
    key: &DerivedSeed,
) -> Result<()> {
    let mut dev =
        CryptInit::init_with_data_device(libcryptsetup_rs::Either::Right((detached_path, device)))
            .map_err(|e| {
                InitError::Luks(format!(
                    "init detached header {} + data {}: {e}",
                    detached_path.display(),
                    device.display()
                ))
            })?;

    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .map_err(|e| InitError::Luks(format!("load: {e}")))?;

    dev.activate_handle()
        .activate_by_passphrase(
            Some(mapping_name),
            None,
            key.as_bytes(),
            CryptActivate::empty(),
        )
        .map(|_| ())
        .map_err(|e| InitError::Luks(format!("activate: {e}")))
}

/// `cryptsetup open --test-passphrase` against the detached header copy.
fn test_passphrase_detached(device: &Path, detached_path: &Path, key: &DerivedSeed) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "--debug".to_string(),
            "--disable-locks".to_string(),
            "open".to_string(),
            "--test-passphrase".to_string(),
            "--header".to_string(),
            path_arg(detached_path)?,
            path_arg(device)?,
            "--key-file".to_string(),
            path_arg(key_file)?,
        ];
        run_command(luks2_seal::CRYPTSETUP_BIN, &args)
    })
}

/// Selected `cryptsetup status <name>` fields for an active mapper.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CryptsetupStatus {
    device: Option<PathBuf>,
    cipher: Option<String>,
    keysize_bits: Option<u64>,
    /// `integrity:` line (dm-integrity activations only), e.g.
    /// `hmac(sha256)`. `None` for plain dm-crypt mappers AND for outputs
    /// that do not carry the line at all.
    integrity: Option<String>,
    offset_sectors: Option<u64>,
}

fn cryptsetup_status_full(mapping_name: &str) -> Result<CryptsetupStatus> {
    let output = std::process::Command::new(luks2_seal::CRYPTSETUP_BIN)
        .args(["status", mapping_name])
        .output()
        .map_err(|e| InitError::Luks(format!("cryptsetup status {mapping_name}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(InitError::Luks(format!(
            "cryptsetup status {mapping_name} exited with {}: stdout={} stderr={}",
            output.status,
            truncate_output(stdout.trim()),
            truncate_output(stderr.trim())
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_cryptsetup_status(&stdout))
}

fn parse_cryptsetup_status(output: &str) -> CryptsetupStatus {
    let mut status = CryptsetupStatus {
        device: None,
        cipher: None,
        keysize_bits: None,
        integrity: None,
        offset_sectors: None,
    };
    for line in output.lines() {
        let line = line.trim_start();
        if let Some(value) = line.strip_prefix("device:").map(str::trim) {
            if !value.is_empty() {
                status.device = Some(PathBuf::from(value));
            }
        } else if let Some(value) = line.strip_prefix("cipher:").map(str::trim) {
            status.cipher = Some(value.to_string());
        } else if let Some(first) = line
            .strip_prefix("keysize:")
            .map(str::trim)
            .and_then(|v| v.split_whitespace().next())
        {
            // "512 bits" -> 512; bare "512" also accepted.
            status.keysize_bits = first.strip_suffix("bits").unwrap_or(first).parse().ok();
        } else if let Some(value) = line.strip_prefix("integrity:").map(str::trim) {
            if !value.is_empty() {
                status.integrity = Some(value.to_string());
            }
        } else if let Some(value) = line
            .strip_prefix("offset:")
            .map(str::trim)
            .and_then(|v| v.split_whitespace().next())
        {
            status.offset_sectors = value.parse().ok();
        }
    }
    status
}

/// Kernel device number (major:minor) of a block device, decoded from
/// `stat`'s `rdev` with glibc's exact masks (same as dm_sysfs_dir).
/// None for non-block-devices and unstat-able paths.
fn dev_number(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::metadata(path).ok()?;
    if !meta.file_type().is_block_device() {
        return None;
    }
    let rdev = meta.rdev();
    let major = ((rdev & 0x0000_0000_000f_ff00) >> 8) | ((rdev & 0xffff_f000_0000_0000) >> 32);
    let minor = (rdev & 0x0000_0000_0000_00ff) | ((rdev & 0x00000ffffff00000) >> 12);
    Some((major, minor))
}

/// Kernel-identity block-device comparison: two paths name the same device
/// when their `stat` device numbers (major:minor) match — independent of
/// the path spelling (kernel name vs container-local bind mount).
fn same_block_device(kernel_name: &str, device: &Path) -> bool {
    let slave = PathBuf::from("/dev").join(kernel_name);
    match (dev_number(&slave), dev_number(device)) {
        (Some(a), Some(b)) => a == b,
        // If either side cannot be stat'ed as a block device (unexpected),
        // fall back to path equivalence rather than silently passing.
        _ => paths_equivalent(&slave, device),
    }
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    if let (Ok(left), Ok(right)) = (std::fs::canonicalize(left), std::fs::canonicalize(right))
        && left == right
    {
        return true;
    }
    // cryptsetup status reports the kernel's underlying device name (e.g.
    // /dev/vdb) while generated workloads name the same disk through a
    // container-local node (e.g. /dev/csi0): distinct nodes, one device.
    // Kernel identity (major:minor) decides, not the spelling.
    matches!((dev_number(left), dev_number(right)), (Some(a), Some(b)) if a == b)
}

/// Keyslot probe against the *detached* copy of an already region-validated
/// header. Reading the metadata ourselves would duplicate JSON parsing; the
/// region read in `is_formatted` already proved the copies parse, so hand
/// cryptsetup a zeroed-slot copy and ask it.
fn has_luks_keyslots(device: &Path) -> Result<Option<bool>> {
    let region = match luks2_seal::read_header_region(device) {
        Ok(region) => region,
        Err(_) => return Ok(None),
    };
    let json = luks2_seal::parse_json_copy(&region.bytes[..luks2_seal::LUKS2_METADATA_COPY_SIZE])?;
    Ok(json
        .get("keyslots")
        .and_then(|value| value.as_object())
        .map(|keyslots| !keyslots.is_empty()))
}

fn cryptsetup_is_luks(device: &Path) -> Result<Option<bool>> {
    let status = match std::process::Command::new(luks2_seal::CRYPTSETUP_BIN)
        .args(["isLuks", "--type", "luks2"])
        .arg(device)
        .status()
    {
        Ok(status) => status,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(InitError::Luks(format!("cryptsetup isLuks: {err}"))),
    };
    if status.success() {
        return Ok(Some(true));
    }
    if status.code() == Some(1) {
        return Ok(Some(false));
    }
    tracing::warn!(
        device = %device.display(),
        status = %status,
        "cryptsetup isLuks returned an inconclusive status; falling back to header probe"
    );
    Ok(None)
}

fn device_has_luks2_header_magic(device: &Path) -> Result<bool> {
    const LUKS_HEADER_BYTES: usize = 8;
    let mut file = OpenOptions::new()
        .read(true)
        .open(device)
        .map_err(|e| InitError::Luks(format!("open {} for LUKS probe: {e}", device.display())))?;
    let mut buf = [0u8; LUKS_HEADER_BYTES];
    let read = file
        .read(&mut buf)
        .map_err(|e| InitError::Luks(format!("read {} LUKS probe: {e}", device.display())))?;
    Ok(buffer_has_luks2_header_magic(&buf[..read]))
}

fn buffer_has_luks2_header_magic(buf: &[u8]) -> bool {
    const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";
    buf.len() >= 8 && &buf[..6] == LUKS_MAGIC && u16::from_be_bytes([buf[6], buf[7]]) == 2
}

// Full-device zero scan: blank=true authorizes luksFormat, so every byte is
// checked — sampling cannot prove blank, and a 0-byte/short read must never
// count as blank (the original bug). Runs only when no LUKS2 header exists;
// the O(device size) cost is paid once at first boot. Progress tracing keeps
// a slow first deploy diagnosable instead of looking hung.
fn device_appears_blank(device: &Path, profile: &mut VolumeProfile) -> Result<bool> {
    const CHUNK: usize = 1024 * 1024;
    // Progress heartbeat for long scans; short scans only log begin/complete.
    const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);
    let mut file = OpenOptions::new()
        .read(true)
        .open(device)
        .map_err(|e| InitError::Luks(format!("open {} for blank probe: {e}", device.display())))?;
    // SeekFrom::End works on block devices; metadata().len() reports 0 for them.
    let len = file
        .seek(SeekFrom::End(0))
        .map_err(|e| InitError::Luks(format!("seek {} for blank probe: {e}", device.display())))?;
    profile.device_bytes = len;
    if len < MIN_VOLUME_BYTES {
        // Fresh-format floor: at or under 16 MiB the header would consume
        // the device and the volume bricks; up to the floor the payload is
        // too thin for a viable fs. Refusing the format is recoverable —
        // formatting is not.
        return Err(InitError::Luks(format!(
            "device {} is only {len} bytes — below the {} MiB minimum (16 MiB LUKS2 header + 16 MiB payload floor); refusing to treat it as blank",
            device.display(),
            MIN_VOLUME_BYTES / (1024 * 1024),
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| InitError::Luks(format!("seek {} for blank probe: {e}", device.display())))?;
    tracing::info!(
        device = %device.display(),
        bytes = len,
        "no LUKS2 header found; scanning device for zero-only content before first format"
    );
    let started = Instant::now();
    let mut last_progress = started;
    let mut buf = vec![0u8; CHUNK];
    let mut remaining = len;
    while remaining > 0 {
        let take = remaining.min(CHUNK as u64) as usize;
        // read_exact: EOF before len is an error, not "blank".
        file.read_exact(&mut buf[..take])
            .map_err(|e| InitError::Luks(format!("read {} blank probe: {e}", device.display())))?;
        profile.scanned_bytes += take as u64;
        if let Some(pos) = buf[..take].iter().position(|byte| *byte != 0) {
            let offset = len - remaining + pos as u64;
            tracing::info!(
                device = %device.display(),
                non_zero_offset = offset,
                "device is not blank: found non-zero data"
            );
            return Ok(false);
        }
        remaining -= take as u64;
        if last_progress.elapsed() >= PROGRESS_INTERVAL {
            tracing::info!(
                device = %device.display(),
                scanned_bytes = len - remaining,
                total_bytes = len,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "blank scan still in progress"
            );
            last_progress = Instant::now();
        }
    }
    tracing::info!(
        device = %device.display(),
        bytes = len,
        duration_ms = started.elapsed().as_millis() as u64,
        "blank scan complete: device is all zeros"
    );
    Ok(true)
}

fn with_key_file<F>(key: &DerivedSeed, f: F) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let key_file = temporary_key_path();
    if let Some(parent) = key_file.parent() {
        luks2_seal::ensure_private_material_dir(parent)?;
        // The passphrase must never land on host-visible storage: the same
        // tmpfs gate the detached headers get. Checking only the later
        // header copies cannot undo a key file already written to disk
        // (cap#244 self-review).
        luks2_seal::ensure_private_material_filesystem(parent, key.as_bytes().len())?;
    }
    // Registered for the whole write-to-wipe lifetime: the orphan sweep
    // also sweeps `luks-key-*` (crash leftovers), and a concurrent
    // operation's key file must not be wiped while this call uses it
    // (cap#244 review).
    luks2_seal::register_active_material_path(&key_file);
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_file)
            .map_err(|e| InitError::Luks(format!("create key file {}: {e}", key_file.display())))?;
        file.write_all(key.as_bytes())
            .map_err(|e| InitError::Luks(format!("write key file {}: {e}", key_file.display())))?;
        file.sync_all()
            .map_err(|e| InitError::Luks(format!("sync key file {}: {e}", key_file.display())))?;
        drop(file);
        f(&key_file)
    })();
    // Best-effort wipe on every path, including a partial write: plaintext
    // key bytes must not outlive this call.
    wipe_key_file(&key_file, key.as_bytes().len());
    luks2_seal::unregister_active_material_path(&key_file);
    result
}

fn temporary_key_path() -> PathBuf {
    let counter = KEY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(luks2_seal::PRIVATE_MATERIAL_DIR)
        .join(format!("luks-key-{}-{counter}", std::process::id()))
}

fn detached_header_path(_mapping_name: &str) -> PathBuf {
    let counter = DETACHED_HEADER_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(luks2_seal::PRIVATE_MATERIAL_DIR)
        .join(format!("luks-header-{}-{counter}", std::process::id()))
}

/// Delete orphaned `luks-header-*` and `luks-key-*` files left behind by
/// processes that no longer exist (crash/kill/OOM between write and wipe).
/// A live PID that is not us still owns its file, and a file currently
/// registered by THIS process (a concurrent operation's in-flight file,
/// cap#244 review) is never touched: its PID component is ours, but wiping
/// it would race the operation still using it. A crashed process's
/// passphrase file must not survive for the life of the emptyDir, so the
/// key files get the same sweep as the detached headers (cap#244
/// self-review).
fn cleanup_stale_detached_copies() {
    cleanup_stale_detached_copies_in(Path::new(luks2_seal::PRIVATE_MATERIAL_DIR));
}

fn cleanup_stale_detached_copies_in(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let my_pid = std::process::id();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(rest) = name
            .strip_prefix("luks-header-")
            .or_else(|| name.strip_prefix("luks-key-"))
        else {
            continue;
        };
        let Some(pid_str) = rest.split('-').next() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };
        if pid != my_pid && Path::new(&format!("/proc/{pid}")).exists() {
            continue;
        }
        if luks2_seal::is_active_material_path(&entry.path()) {
            // In-flight copy of a concurrent open in this process: owned by
            // our PID but not stale.
            continue;
        }
        // Our own PID entry after a crash-restart (PID reuse with the
        // counter reset) or a dead owner's leftover. Never follow symlinks:
        // the directory is shared with the workload, which could plant a
        // symlink and have root wipe its target. Only regular files whose
        // name still matches our exact generation scheme are removed.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() {
            // Not a regular file (symlink/otherwise): do not touch. Our own
            // writer only creates regular files, so anything else was not
            // written by enclava-init.
            tracing::warn!(
                path = %entry.path().display(),
                "non-regular file in detached-header directory left untouched"
            );
            continue;
        }
        // Best effort: plaintext header bytes never outlive the dead owner.
        if let Ok(meta) = entry.metadata() {
            let len = meta.len() as usize;
            luks2_seal::wipe_detached_copy(&entry.path(), len);
        }
    }
}

fn wipe_key_file(path: &Path, len: usize) {
    // Same hardened wipe as detached headers: O_NOFOLLOW + regular-file
    // check, so a replaced pathname can never redirect the zeroize.
    luks2_seal::wipe_detached_copy(path, len);
}

fn path_arg(path: &Path) -> Result<String> {
    path.to_str()
        .map(|s| s.to_string())
        .ok_or_else(|| InitError::Luks(format!("non-utf8 path {}", path.display())))
}

fn run_command(program: &str, args: &[String]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| InitError::Luks(format!("{program}: {e}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    Err(InitError::Luks(format!(
        "{program} exited with {}: stdout={} stderr={}",
        output.status,
        truncate_output(stdout.trim()),
        truncate_output(stderr.trim())
    )))
}

fn truncate_output(value: &str) -> String {
    const EDGE: usize = 2048;
    const LIMIT: usize = EDGE * 2;
    if value.len() <= LIMIT {
        value.to_string()
    } else {
        format!(
            "{}...[truncated]...{}",
            &value[..EDGE],
            &value[value.len() - EDGE..]
        )
    }
}

/// Mount `mapper_path` (a filesystem) at `mount_point`.
pub fn mount(mapper_path: &Path, mount_point: &Path) -> Result<()> {
    use nix::mount::{MsFlags, mount as nix_mount};
    std::fs::create_dir_all(mount_point)?;
    nix_mount(
        Some(mapper_path),
        mount_point,
        Some("ext4"),
        MsFlags::empty(),
        None::<&str>,
    )
    .map_err(|e| {
        InitError::Luks(format!(
            "mount {} -> {}: {e}",
            mapper_path.display(),
            mount_point.display()
        ))
    })?;
    Ok(())
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn format_decision_only_formats_blank_unformatted_devices() {
        assert_eq!(
            format_decision(false, None, true).expect("blank device is first boot"),
            FormatDecision::FormatFreshDevice
        );
        assert_eq!(
            format_decision(true, Some(true), false).expect("formatted device opens"),
            FormatDecision::OpenExisting
        );
        assert_eq!(
            format_decision(true, None, false).expect("inconclusive keyslot probe opens"),
            FormatDecision::OpenExisting
        );
    }

    #[test]
    fn format_decision_refuses_ambiguous_or_damaged_devices() {
        assert!(format_decision(false, None, false).is_err());
        assert!(format_decision(true, Some(false), false).is_err());
    }

    #[test]
    fn luks2_header_magic_detects_only_luks2() {
        let mut header = [0u8; 16];
        header[..6].copy_from_slice(b"LUKS\xba\xbe");
        header[6..8].copy_from_slice(&2u16.to_be_bytes());

        assert!(buffer_has_luks2_header_magic(&header));
        header[6..8].copy_from_slice(&1u16.to_be_bytes());
        assert!(!buffer_has_luks2_header_magic(&header));
        assert!(!buffer_has_luks2_header_magic(&[0u8; 16]));
    }

    #[test]
    fn blank_probe_refuses_devices_below_minimum_size() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let device = dir.path().join("device");

        // 16 MiB (the bricking size from self-check) and anything below the
        // 32 MiB floor must error rather than read as blank.
        for size in [0u64, 1024, 16 * 1024 * 1024, MIN_VOLUME_BYTES - 1] {
            std::fs::File::create(&device)
                .expect("create device")
                .set_len(size)
                .expect("size device");
            device_appears_blank(&device, &mut VolumeProfile::default())
                .expect_err("undersized device must not read as blank");
        }
    }

    #[test]
    fn blank_probe_distinguishes_fresh_and_nonempty_devices() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let device = dir.path().join("device");

        // Exact lower bound: scanned like any larger device, not refused.
        std::fs::File::create(&device)
            .expect("create sparse device")
            .set_len(MIN_VOLUME_BYTES)
            .expect("size sparse device");
        let mut profile = VolumeProfile::default();
        assert!(device_appears_blank(&device, &mut profile).expect("probe boundary-size device"));
        assert_eq!(profile.device_bytes, 32 * 1024 * 1024);
        assert_eq!(profile.scanned_bytes, profile.device_bytes);

        for offset in [24 * 1024 * 1024, 32 * 1024 * 1024 - 4096] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&device)
                .expect("open sparse device");
            file.seek(SeekFrom::Start(offset)).expect("seek");
            file.write_all(&[1]).expect("write non-zero byte");
            assert!(
                !device_appears_blank(&device, &mut VolumeProfile::default())
                    .expect("probe dirty device")
            );
            file.seek(SeekFrom::Start(offset)).expect("seek back");
            file.write_all(&[0]).expect("restore zero byte");
        }
    }

    #[test]
    fn parses_cryptsetup_status_fields() {
        let output = r#"
/dev/mapper/cap-state is active and is in use.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 512 bits
  keyslot: 0
  token:   --
  device:  /dev/vdb
  sector size:  512
  offset:  32768 sectors
  size:    98304 sectors
  mode:    read/write
"#;

        let status = parse_cryptsetup_status(output);
        assert_eq!(status.device, Some(PathBuf::from("/dev/vdb")));
        assert_eq!(status.cipher.as_deref(), Some("aes-xts-plain64"));
        assert_eq!(status.keysize_bits, Some(512));
        assert_eq!(status.integrity, None);
        assert_eq!(status.offset_sectors, Some(32768));
    }

    #[test]
    fn parses_cryptsetup_status_stacked_integrity_fields() {
        // Output captured from `cryptsetup status` on a dm-integrity LUKS2
        // activation (cap#248 layout): the top dm-crypt table reports the
        // combined 768-bit volume key, the integrity line, and offset 0.
        let output = r#"
/dev/mapper/cap-state is active.
  type:    LUKS2
  cipher:  aes-xts-plain64
  keysize: 768 bits
  key location: keyring
  integrity: hmac(sha256)
  integrity keysize: 256 bits
  integrity tag size: 32 bytes
  device:  /dev/vdb
  sector size:  512
  offset:  0 sectors
  size:    91184 sectors
  mode:    read/write
"#;

        let status = parse_cryptsetup_status(output);
        assert_eq!(status.device, Some(PathBuf::from("/dev/vdb")));
        assert_eq!(status.cipher.as_deref(), Some("aes-xts-plain64"));
        assert_eq!(status.keysize_bits, Some(768));
        assert_eq!(status.integrity.as_deref(), Some("hmac(sha256)"));
        assert_eq!(status.offset_sectors, Some(0));
    }

    #[test]
    fn cryptsetup_status_parser_missing_fields_yield_none() {
        let status = parse_cryptsetup_status("inactive\n");
        assert_eq!(status.device, None);
        assert_eq!(status.cipher, None);
        assert_eq!(status.keysize_bits, None);
        assert_eq!(status.integrity, None);
        assert_eq!(status.offset_sectors, None);
    }

    #[test]
    fn sweep_removes_own_pid_leftovers_but_never_in_flight_copies() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let my_pid = std::process::id();

        // Leftover of ours (crash-restart with PID reuse + counter reset):
        // not registered => stale.
        let stale = dir.path().join(format!("luks-header-{my_pid}-0"));
        std::fs::write(&stale, b"leftover").expect("write stale copy");

        // In-flight copy of a concurrent open in THIS process: registered
        // while cryptsetup is still reading it (cap#244 review) — the sweep
        // must leave it alone even though its PID component is ours.
        let inflight = dir.path().join(format!("luks-header-{my_pid}-1"));
        std::fs::write(&inflight, b"in-flight").expect("write in-flight copy");
        luks2_seal::register_active_material_path_for_test(&inflight);

        // Copy owned by another live process (PID 1 always exists).
        let foreign = dir.path().join("luks-header-1-0");
        std::fs::write(&foreign, b"live owner").expect("write foreign copy");

        cleanup_stale_detached_copies_in(dir.path());

        assert!(!stale.exists(), "own unregistered leftover must be wiped");
        assert!(
            inflight.exists(),
            "in-flight copy of a concurrent open must never be wiped"
        );
        assert!(foreign.exists(), "live other-PID copy must be kept");

        // After the open completes (wipe), the same name becomes stale.
        luks2_seal::unregister_active_material_path_for_test(&inflight);
        cleanup_stale_detached_copies_in(dir.path());
        assert!(!inflight.exists(), "unregistered copy must be swept");
    }

    /// cap#244 self-review: a crash between key-file write and wipe must not
    /// leave the passphrase in the private dir for the life of the emptyDir —
    /// `luks-key-*` gets the same sweep, with the same in-flight exemption.
    #[test]
    fn sweep_removes_stale_key_files_but_never_in_flight_ones() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let my_pid = std::process::id();

        let stale = dir.path().join(format!("luks-key-{my_pid}-0"));
        std::fs::write(&stale, b"passphrase leftover").expect("write stale key file");

        let inflight = dir.path().join(format!("luks-key-{my_pid}-1"));
        std::fs::write(&inflight, b"in-flight key").expect("write in-flight key file");
        luks2_seal::register_active_material_path_for_test(&inflight);

        let foreign = dir.path().join("luks-key-1-0");
        std::fs::write(&foreign, b"live owner").expect("write foreign key file");

        cleanup_stale_detached_copies_in(dir.path());

        assert!(!stale.exists(), "own unregistered key file must be wiped");
        assert!(
            inflight.exists(),
            "in-flight key file of a concurrent operation must never be wiped"
        );
        assert!(foreign.exists(), "live other-PID key file must be kept");

        luks2_seal::unregister_active_material_path_for_test(&inflight);
        cleanup_stale_detached_copies_in(dir.path());
        assert!(!inflight.exists(), "unregistered key file must be swept");
    }

    #[test]
    fn sweep_leaves_non_regular_files_untouched() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let my_pid = std::process::id();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"untouched").expect("write victim");
        let link = dir.path().join(format!("luks-header-{my_pid}-9"));
        std::os::unix::fs::symlink(&victim, &link).expect("plant symlink");

        cleanup_stale_detached_copies_in(dir.path());

        assert!(link.exists(), "symlink entries are left in place");
        assert_eq!(
            std::fs::read(&victim).expect("read victim"),
            b"untouched",
            "the sweep must never write through a symlink"
        );
    }
}

#[cfg(all(test, feature = "luks-integration"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use tempfile::tempdir;

    const PAYLOAD: &[u8] = b"enclava-init integrity payload";

    fn make_backing_file(size_mb: u64) -> Result<(tempfile::TempDir, PathBuf)> {
        let dir = tempdir()?;
        let path = dir.path().join("disk.img");
        let mut f = File::create(&path)?;
        f.seek(SeekFrom::Start(size_mb * 1024 * 1024 - 1))?;
        f.write_all(&[0u8])?;
        Ok((dir, path))
    }

    fn volume_keys() -> VolumeKeys {
        VolumeKeys::new(
            DerivedSeed([0x11u8; 32]),
            crate::seeds::derive(
                &crate::secrets::OwnerSeed([0x11u8; 32]),
                crate::seeds::STATE_HEADER_MAC_INFO,
            )
            .expect("mac key"),
        )
    }

    fn assert_formatted_profile(device: &Path) -> Result<()> {
        let region = luks2_seal::read_header_region(device)?;
        validate_region(&region)?;
        let json =
            luks2_seal::parse_json_copy(&region.bytes[..luks2_seal::LUKS2_METADATA_COPY_SIZE])?;
        assert_eq!(
            json["segments"]["0"]["sector_size"].as_u64(),
            Some(u64::from(LUKS2_SECTOR_SIZE)),
            "segment 0 sector size"
        );
        let kdf = &json["keyslots"]["0"]["kdf"];
        assert_eq!(
            kdf["type"].as_str(),
            Some(LUKS2_PBKDF_CLI),
            "keyslot KDF type"
        );
        assert_eq!(
            kdf["time"].as_u64(),
            Some(u64::from(LUKS2_PBKDF_PASSES)),
            "argon2id passes"
        );
        assert_eq!(
            kdf["memory"].as_u64(),
            Some(u64::from(LUKS2_PBKDF_MEMORY_KIB)),
            "argon2id memory KiB"
        );
        assert_eq!(
            kdf["cpus"].as_u64(),
            Some(u64::from(LUKS2_PBKDF_PARALLEL)),
            "argon2id lanes"
        );
        Ok(())
    }

    /// Attach a loop device for the image when running privileged, so that
    /// `cryptsetup status` reports exactly the device we pass (cryptsetup
    /// otherwise silently auto-attaches its own loop device for file images
    /// and the backing-device equivalence check sees /dev/loopN instead of
    /// the image path). Falls back to the raw image when `losetup` is
    /// unavailable or we lack privileges.
    fn attach_loop_device(img: &Path) -> PathBuf {
        let output = std::process::Command::new("losetup")
            .args(["--find", "--show", "--partscan"])
            .arg(img)
            .output();
        match output {
            Ok(out) if out.status.success() => {
                let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if path.is_empty() {
                    img.to_path_buf()
                } else {
                    PathBuf::from(path)
                }
            }
            _ => img.to_path_buf(),
        }
    }

    fn detach_loop_device(device: &Path) {
        if device.starts_with("/dev/loop") {
            let _ = std::process::Command::new("losetup")
                .arg("--detach")
                .arg(device)
                .status();
        }
    }

    /// Best-effort removal of a mapper left behind by an earlier (possibly
    /// crashed) test run, so fixed mapping names stay idempotent.
    fn close_mapper(mapping_name: &str) {
        let _ = std::process::Command::new("cryptsetup")
            .args(["close", mapping_name])
            .status();
    }

    /// Detached-header plumbing writes under the private-material dir;
    /// without root or a RAM-backed mount the tmpfs copy cannot be created,
    /// so integration tests run privileged (CI runs them compile-only; the
    /// SEV-SNP nightlies run them for real). write_detached_copy also
    /// enforces tmpfs, so skip on dev machines whose mount is not RAM-backed.
    fn can_write_run_enclava() -> bool {
        // Create the private dir the way production does (0700, euid-owned);
        // a bare create_dir_all would leave umask-default permissions that
        // ensure_private_material_dir correctly refuses.
        luks2_seal::ensure_private_material_dir(Path::new(luks2_seal::PRIVATE_MATERIAL_DIR)).is_ok()
            && nix::sys::statfs::statfs(luks2_seal::PRIVATE_MATERIAL_DIR)
                .map(|s| s.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC)
                .unwrap_or(false)
            && {
                let probe = format!(
                    "{}/.luks-integration-probe-{}-{}",
                    luks2_seal::PRIVATE_MATERIAL_DIR,
                    std::process::id(),
                    DETACHED_HEADER_COUNTER.fetch_add(1, Ordering::Relaxed)
                );
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&probe)
                    .map(|f| {
                        drop(f);
                        let _ = std::fs::remove_file(&probe);
                        true
                    })
                    .unwrap_or(false)
            }
    }

    #[test]
    fn format_seals_then_open_round_trip() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(32)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");

        // The CLI formatter must have written the exact on-disk profile.
        assert_formatted_profile(&device)?;

        // On-disk header must now be invalid for stock cryptsetup.
        let status = std::process::Command::new("cryptsetup")
            .args(["isLuks", "--type", "luks2"])
            .arg(&device)
            .status()
            .expect("run isLuks");
        assert_eq!(status.code(), Some(1), "sealed header must fail isLuks");

        let opened = open(&device, "enclava-init-test", &keys).expect("open sealed volume");
        assert!(opened.mapper_path.starts_with("/dev/mapper/"));

        // Synced data must survive close + authenticated reopen.
        {
            let mapper = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&opened.mapper_path)?;
            mapper.write_all_at(PAYLOAD, 0).expect("write payload");
            mapper.sync_all().expect("sync payload");
        }
        close_mapper("enclava-init-test");
        let reopened = open(&device, "enclava-init-test", &keys).expect("reopen after close");
        let mut buf = vec![0u8; PAYLOAD.len()];
        File::open(&reopened.mapper_path)?
            .read_exact_at(&mut buf, 0)
            .expect("read payload back");
        assert_eq!(buf, PAYLOAD, "synced payload must survive close/reopen");

        close_mapper("enclava-init-test");
        detach_loop_device(&device);
        Ok(())
    }

    /// The libcryptsetup fallback must land the identical on-disk profile
    /// (sector size + fixed Argon2id) as the CLI formatter and produce a
    /// volume that opens normally (adopted + sealed — the library path
    /// itself does not seal).
    #[test]
    fn libcryptsetup_fallback_formats_identical_profile() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        let mapping = "enclava-init-test-fallback";
        close_mapper(mapping);

        format_with_libcryptsetup(&device, &keys.passphrase, &mut VolumeProfile::default())
            .expect("libcryptsetup fallback format");
        assert_formatted_profile(&device)?;

        let opened = open(&device, mapping, &keys).expect("fallback-formatted volume opens");
        assert!(opened.mapper_path.exists());
        let region = luks2_seal::read_header_region(&device)?;
        assert_eq!(
            luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?,
            HeaderSeal::Sealed,
            "opening must seal the unsealed fallback header"
        );
        close_mapper(mapping);
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn tampered_header_fails_closed() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-tamper");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");

        // Flip one byte inside the keyslots area (host-tamper simulation).
        let mut f = OpenOptions::new().write(true).open(&device)?;
        f.seek(SeekFrom::Start(0x80000))?;
        f.write_all(&[0xAA])?;
        drop(f);

        let err = open(&device, "enclava-init-test-tamper", &keys)
            .expect_err("tampered header must fail closed");
        assert!(
            err.to_string().contains("MAC mismatch"),
            "expected MAC mismatch, got: {err}"
        );
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn wrong_mac_key_fails_closed() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-wrongkey");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");

        let wrong = VolumeKeys::new(keys.passphrase.clone(), DerivedSeed([0xEEu8; 32]));
        let err = open(&device, "enclava-init-test-wrongkey", &wrong)
            .expect_err("wrong MAC key must fail closed");
        assert!(err.to_string().contains("MAC mismatch"));
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn unsealed_header_is_adopted_and_sealed() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-adopt");

        // An unsealed header formatted exactly as production does (e.g. a
        // crash between luksFormat and the seal): adoption must gate on the
        // passphrase, then seal.
        with_key_file(&keys.passphrase, |key_file| {
            let args = luks_format_args(&device, key_file);
            run_command("cryptsetup", &args)
        })?;

        let opened =
            open(&device, "enclava-init-test-adopt", &keys).expect("unsealed header is adopted");
        assert!(opened.mapper_path.exists());

        // After adoption the header must be sealed on disk.
        let region = luks2_seal::read_header_region(&device)?;
        assert_eq!(
            luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?,
            HeaderSeal::Sealed
        );
        close_mapper("enclava-init-test-adopt");
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn interrupted_seal_is_completed_and_volume_opens() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-interrupted");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");

        // Simulate a crash between the two seal slot writes: zero the second
        // slot, leaving the first MAC in place.
        let start = luks2_seal::LUKS2_METADATA_COPY_SIZE + luks2_seal::HEADER_MAC_SLOT_OFFSET;
        let mut f = OpenOptions::new().write(true).open(&device)?;
        f.seek(SeekFrom::Start(start as u64))?;
        f.write_all(&[0u8; luks2_seal::HEADER_MAC_LEN])?;
        drop(f);

        // Interrupted seal must be reported as such and then self-heal.
        let region = luks2_seal::read_header_region(&device)?;
        assert_eq!(
            luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?,
            HeaderSeal::InterruptedSeal
        );

        let opened = open(&device, "enclava-init-test-interrupted", &keys)
            .expect("interrupted seal recovers and opens");
        assert!(opened.mapper_path.exists());

        let region = luks2_seal::read_header_region(&device)?;
        assert_eq!(
            luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?,
            HeaderSeal::Sealed
        );
        close_mapper("enclava-init-test-interrupted");
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn existing_mapper_is_revalidated_against_authenticated_header() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-mapper");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");
        let opened = open(&device, "enclava-init-test-mapper", &keys).expect("open");
        assert!(opened.mapper_path.exists());

        // Re-open with the mapper already active: validate_existing_mapper
        // must pass (the mapper is genuinely ours) and complete without error.
        let reopened = open(&device, "enclava-init-test-mapper", &keys)
            .expect("existing mapper is revalidated and reused");
        assert_eq!(reopened.mapper_path, opened.mapper_path);
        close_mapper("enclava-init-test-mapper");
        detach_loop_device(&device);
        Ok(())
    }
    /// Rollout gate (cap#242 review): with the signed policy requiring the
    /// seal, an unsealed header (host restored a pre-seal header / zeroed
    /// both MAC slots) must be rejected instead of re-adopted.
    #[test]
    fn required_seal_rejects_unsealed_header_rollback() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-rollback");
        let strict = LuksOpenPolicy {
            allow_legacy_adoption: false,
        };

        // Simulate an unsealed header: production-shape format, no seal.
        with_key_file(&keys.passphrase, |key_file| {
            let args = luks_format_args(&device, key_file);
            run_command("cryptsetup", &args)
        })?;

        // Rollout window: adopted and sealed.
        let opened = open_with_policy(
            &device,
            "enclava-init-test-rollback",
            &keys,
            &LuksOpenPolicy::default(),
        )
        .expect("unsealed volume adopted during rollout window");
        assert!(opened.mapper_path.exists());
        close_mapper("enclava-init-test-rollback");

        // Simulate the host restoring the unsealed header (re-format without
        // sealing), then demand the seal: must fail closed.
        with_key_file(&keys.passphrase, |key_file| {
            let args = luks_format_args(&device, key_file);
            run_command("cryptsetup", &args)
        })?;
        let err = open_with_policy(&device, "enclava-init-test-rollback", &keys, &strict)
            .expect_err("unsealed header must be rejected under required policy");
        assert!(
            err.to_string().contains("requires sealing"),
            "expected rollback rejection, got: {err}"
        );
        detach_loop_device(&device);
        Ok(())
    }

    /// A sealed volume opens normally under the strict policy.
    #[test]
    fn required_seal_still_opens_sealed_volume() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-strict-open");
        format(&device, &keys, &mut VolumeProfile::default()).expect("format+seal");
        let strict = LuksOpenPolicy {
            allow_legacy_adoption: false,
        };
        let opened = open_with_policy(&device, "enclava-init-test-strict-open", &keys, &strict)
            .expect("sealed volume opens under strict policy");
        assert!(opened.mapper_path.exists());
        close_mapper("enclava-init-test-strict-open");
        detach_loop_device(&device);
        Ok(())
    }

    fn luks_format_args(device: &Path, key_file: &Path) -> Vec<String> {
        vec![
            "--disable-locks".to_string(),
            "luksFormat".to_string(),
            path_arg(device).expect("utf8 path"),
            "--key-file".to_string(),
            path_arg(key_file).expect("utf8 path"),
            "--type".to_string(),
            "luks2".to_string(),
            "--cipher".to_string(),
            "aes-xts-plain64".to_string(),
            "--key-size".to_string(),
            "512".to_string(),
            "--sector-size".to_string(),
            LUKS2_SECTOR_SIZE.to_string(),
            "--integrity".to_string(),
            INTEGRITY_CLI.to_string(),
            "--pbkdf".to_string(),
            LUKS2_PBKDF_CLI.to_string(),
            "--pbkdf-force-iterations".to_string(),
            LUKS2_PBKDF_PASSES.to_string(),
            "--pbkdf-memory".to_string(),
            LUKS2_PBKDF_MEMORY_KIB.to_string(),
            "--pbkdf-parallel".to_string(),
            LUKS2_PBKDF_PARALLEL.to_string(),
            "--batch-mode".to_string(),
        ]
    }
}
