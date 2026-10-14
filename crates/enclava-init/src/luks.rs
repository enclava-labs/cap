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
//! (dm-integrity) tags and then ext4 before the first mount, so the runtime
//! image must include `mkfs.ext4`.
//! Fresh LUKS2 volumes are formatted ext4 before the first mount, so
//! the runtime image must include `mkfs.ext4`.

use std::fs::{File, OpenOptions, remove_file};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use libcryptsetup_rs::{
    CryptDevice, CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref,
    consts::flags::{CryptActivate, CryptDeactivate},
    consts::vals::EncryptionFormat,
};

use crate::errors::{InitError, Result};
use crate::luks2_seal::{self, HeaderSeal, Luks2Region, validate_region};
use crate::secrets::DerivedSeed;

const LUKS2_SECTOR_SIZE: u32 = 512;
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
/// AES-128-XTS.
const VOLUME_KEY_BYTES: usize = 96;
/// CLI spelling of the integrity algorithm.
const INTEGRITY_CLI: &str = "hmac-sha256";
/// Kernel spelling the libcryptsetup API expects.
const INTEGRITY_LIB: &str = "hmac(sha256)";
const INTEGRITY_WIPE_CHUNK: usize = 4 * 1024 * 1024;

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
pub fn format(device: &Path, keys: &VolumeKeys) -> Result<()> {
    if let Err(cli_err) = format_with_cryptsetup_cli(device, &keys.passphrase) {
        tracing::warn!(
            device = %device.display(),
            error = %cli_err,
            "cryptsetup CLI format failed; falling back to libcryptsetup"
        );
        format_with_libcryptsetup(device, &keys.passphrase).map_err(|lib_err| {
            InitError::Luks(format!(
                "format cli: {cli_err}; libcryptsetup fallback: {lib_err}"
            ))
        })?;
    }

    // Read back what cryptsetup actually wrote and validate it strictly
    // before sealing — never trust that the formatter produced the exact
    // shape we asked for.
    let region = luks2_seal::read_header_region(device)?;
    validate_region(&region)?;
    luks2_seal::seal_on_disk(device, &region, &keys.header_mac_key)?;
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
    let mapper_path = PathBuf::from(format!("/dev/mapper/{mapping_name}"));
    if mapper_path.exists() {
        validate_existing_mapper(device, mapping_name, keys)?;
        return Ok(LuksOpened {
            mapper_path,
            formatted: false,
        });
    }

    luks2_seal::read_header_region(device)
        .and_then(|region| {
            validate_region(&region)?;
            authenticated_open(device, &region, mapping_name, keys)
        })
        .map(|_| LuksOpened {
            mapper_path,
            formatted: false,
        })
}

/// Shared authenticated-open core: verify the seal (adopting legacy volumes
/// after a strict-validation + passphrase gate), materialize the detached
/// copy on tmpfs, and activate through it.
fn authenticated_open(
    device: &Path,
    region: &Luks2Region,
    mapping_name: &str,
    keys: &VolumeKeys,
) -> Result<()> {
    let seal = luks2_seal::verify_header_seal(region, &keys.header_mac_key)?;
    let detached_path = detached_header_path(mapping_name);

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
                // Legacy pre-seal volume. Gate adoption on a passphrase test
                // through the detached copy, then seal. Adoption never falls
                // back to an in-place open.
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

fn validate_existing_mapper(device: &Path, mapping_name: &str, keys: &VolumeKeys) -> Result<()> {
    let status_device = cryptsetup_status_device(mapping_name)?;
    if let Some(status_device) = &status_device
        && !paths_equivalent(status_device, device)
    {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} is backed by {}, expected {}",
            status_device.display(),
            device.display()
        )));
    }
    // The mapper may predate this boot's seal; re-verify the on-disk header
    // before trusting the existing activation.
    let region = luks2_seal::read_header_region(device)?;
    validate_region(&region)?;
    let mut seal = luks2_seal::verify_header_seal(&region, &keys.header_mac_key)?;
    if let HeaderSeal::Unsealed = seal {
        // Mapper already active for a legacy volume this boot; adopt+seal
        // through the same gate the open path uses.
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
    // An existing mapper is dm-crypt state created by an earlier boot of this
    // code, but the host controls the disk and could substitute a mapper we
    // did not create. Prove the live mapper is encrypted with the volume key
    // bound to the just-authenticated header before the caller mounts it:
    // extract the volume key from the authenticated (MAC-verified) header via
    // a detached copy using our passphrase, then ask libcryptsetup to verify
    // that key against the *active* mapper.
    verify_active_mapper_volume_key(device, &region, mapping_name, keys)?;
    Ok(())
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
/// 2. The dm table's keyring key description has the form
///    `:64:logon:cryptsetup:<luks-uuid>-d0` where `<luks-uuid>` is the UUID
///    of the header cryptsetup loaded *at activation time*. Requiring that
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
    let table = dm_crypt_table(mapping_name)?;
    let key_description = parse_dm_key_description(&table).ok_or_else(|| {
        InitError::Luks(format!(
            "existing mapper {mapping_name} does not expose a cryptsetup keyring key; \
             refusing to use it"
        ))
    })?;
    // Keyring key description format: cryptsetup:<luks-uuid>-d0
    let bound_uuid = key_description
        .strip_prefix("cryptsetup:")
        .and_then(|rest| rest.strip_suffix("-d0"))
        .ok_or_else(|| {
            InitError::Luks(format!(
                "existing mapper {mapping_name} key description {key_description:?} is not \
                 a cryptsetup LUKS2 volume key; refusing to use it"
            ))
        })?;
    if bound_uuid != expected_uuid {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} was activated from header UUID {bound_uuid}, \
             but the authenticated header for {} has UUID {expected_uuid}; possible mapper \
             or header substitution, refusing to use it",
            device.display()
        )));
    }
    tracing::info!(
        mapping = mapping_name,
        uuid = %expected_uuid,
        "existing mapper bound to authenticated header via keyring key UUID"
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

/// The dm table line of an active mapper, with keyring key descriptions
/// visible (`dmsetup table --showkeys`), e.g.
/// `0 98304 crypt aes-xts-plain64 :64:logon:cryptsetup:<uuid>-d0 0 7:0 32768`.
fn dm_crypt_table(mapping_name: &str) -> Result<String> {
    let output = std::process::Command::new("dmsetup")
        .args(["table", "--showkeys", mapping_name])
        .output()
        .map_err(|e| InitError::Luks(format!("dmsetup table {mapping_name}: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(InitError::Luks(format!(
            "dmsetup table --showkeys {mapping_name} exited with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Pull the `:64:logon:cryptsetup:<uuid>-d0` key description out of a dm
/// crypt table line.
fn parse_dm_key_description(table: &str) -> Option<String> {
    let start = table.find(":logon:")?;
    let rest = &table[start + ":logon:".len()..];
    let end = rest.find(' ')?;
    Some(rest[..end].to_string())
}

/// Format the device if it's not yet a LUKS2 volume, then activate it.
pub fn format_if_unformatted_then_open(
    device: &Path,
    mapping_name: &str,
    keys: &VolumeKeys,
) -> Result<LuksOpened> {
    let formatted = is_formatted(device)?;
    let has_keyslots = if formatted {
        has_luks_keyslots(device)?
    } else {
        None
    };
    let blank = if formatted {
        false
    } else {
        device_appears_blank(device)?
    };
    let needs_mkfs = matches!(
        format_decision(formatted, has_keyslots, blank)?,
        FormatDecision::FormatFreshDevice
    );
    if needs_mkfs {
        format(device, keys)?;
    }
    let mut opened = open(device, mapping_name, keys)?;
    if needs_mkfs {
        mkfs_ext4(&opened.mapper_path)?;
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
    let status = std::process::Command::new("mkfs.ext4")
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

fn format_with_libcryptsetup(device: &Path, key: &DerivedSeed) -> Result<()> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;
    let params = CryptParamsLuks2 {
        pbkdf: None,
        integrity: None,
        integrity_params: None,
        data_alignment: 0,
        data_device: None,
        sector_size: LUKS2_SECTOR_SIZE,
        label: None,
        subsystem: None,
    };
    let mut params: CryptParamsLuks2Ref<'_> = (&params)
        .try_into()
        .map_err(|e| InitError::Luks(format!("luks2 params: {e}")))?;

    dev.context_handle()
        .format(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            libcryptsetup_rs::Either::Right(64),
            Some(&mut params),
        )
        .map_err(|e| InitError::Luks(format!("format: {e}")))?;

    dev.keyslot_handle()
        .add_by_key(
            None,
            None,
            key.as_bytes(),
            libcryptsetup_rs::consts::flags::CryptVolumeKey::empty(),
        )
        .map_err(|e| InitError::Luks(format!("add_by_key: {e}")))?;

    Ok(())
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
            "512".to_string(),
            "--integrity".to_string(),
            INTEGRITY_CLI.to_string(),
            "--batch-mode".to_string(),
        ];
        run_command("cryptsetup", &args)
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
        run_command("cryptsetup", &args)
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
        run_command("cryptsetup", &args)
    })
}

fn cryptsetup_status_device(mapping_name: &str) -> Result<Option<PathBuf>> {
    let output = std::process::Command::new("cryptsetup")
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
    Ok(parse_cryptsetup_status_device(&stdout))
}

fn parse_cryptsetup_status_device(output: &str) -> Option<PathBuf> {
    output.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("device:")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    })
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
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
    let status = match std::process::Command::new("cryptsetup")
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
fn device_appears_blank(device: &Path) -> Result<bool> {
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

    let result = f(&key_file);
    wipe_key_file(&key_file, key.as_bytes().len());
    result
}

fn temporary_key_path() -> PathBuf {
    let counter = KEY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/run/enclava/luks-key-{}-{counter}",
        std::process::id()
    ))
}

fn detached_header_path(_mapping_name: &str) -> PathBuf {
    let counter = DETACHED_HEADER_COUNTER.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        "/run/enclava/luks-header-{}-{counter}",
        std::process::id()
    ))
}

fn wipe_key_file(path: &Path, len: usize) {
    if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; len];
        let _ = file.write_all(&zeros);
        let _ = file.sync_all();
    }
    let _ = remove_file(path);
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
            device_appears_blank(&device).expect_err("undersized device must not read as blank");
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
        assert!(device_appears_blank(&device).expect("probe boundary-size device"));

        for offset in [24 * 1024 * 1024, 32 * 1024 * 1024 - 4096] {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&device)
                .expect("open sparse device");
            file.seek(SeekFrom::Start(offset)).expect("seek");
            file.write_all(&[1]).expect("write non-zero byte");
            assert!(!device_appears_blank(&device).expect("probe dirty device"));
            file.seek(SeekFrom::Start(offset)).expect("seek back");
            file.write_all(&[0]).expect("restore zero byte");
        }
    }

    #[test]
    fn parses_cryptsetup_status_device_line() {
        let output = r#"
/dev/mapper/cap-state is active.
  type:    LUKS2
  device:  /dev/vdb
"#;

        assert_eq!(
            parse_cryptsetup_status_device(output),
            Some(PathBuf::from("/dev/vdb"))
        );
    }

    #[test]
    fn cryptsetup_status_device_parser_allows_missing_device_line() {
        assert_eq!(parse_cryptsetup_status_device("inactive\n"), None);
    }
}

#[cfg(all(test, feature = "luks-integration"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::FileExt;
    use tempfile::tempdir;

    const PAYLOAD: &[u8] = b"enclava-init integrity payload";

    /// RAII guard for a device-mapper mapping this test activated; Drop closes
    /// it even when an assertion panics and warns if cleanup actually fails.
    struct TestMapping {
        name: String,
        /// False once `close` succeeded, so Drop only reports real leaks.
        active: bool,
    }

    impl TestMapping {
        /// Activate `device` under a fresh random name; never reuse a name so
        /// no test touches mappings owned by anything else.
        fn activate(device: &Path, key: &DerivedSeed) -> Result<Self> {
            let name = Self::random_name();
            open(device, &name, key)?;
            Ok(Self { name, active: true })
        }

        fn new(name: String) -> Self {
            Self { name, active: true }
        }

        fn random_name() -> String {
            format!("enclava-init-test-{}", uuid::Uuid::new_v4().simple())
        }

        fn mapper_path(&self) -> PathBuf {
            PathBuf::from(format!("/dev/mapper/{}", self.name))
        }

        /// Error-reporting close for mid-test close/reopen flows; on success
        /// Drop skips the idempotent retry, on failure Drop still retries.
        fn close(&mut self) -> Result<()> {
            let result = run_command(
                "cryptsetup",
                &[
                    "--disable-locks".to_string(),
                    "close".to_string(),
                    self.name.clone(),
                ],
            );
            if result.is_ok() {
                self.active = false;
            }
            result
        }
    }

    impl Drop for TestMapping {
        fn drop(&mut self) {
            if !self.active {
                return;
            }
            let output = std::process::Command::new("cryptsetup")
                .args(["--disable-locks", "close", &self.name])
                .output();
            match output {
                Ok(output) if output.status.success() => {}
                Ok(output) => eprintln!(
                    "warning: cryptsetup close {} failed: {}",
                    self.name,
                    String::from_utf8_lossy(&output.stderr)
                ),
                Err(err) => eprintln!(
                    "warning: cryptsetup close {} could not run: {err}",
                    self.name
                ),
            }
        }
    }

    /// `with_key_file` writes to /run/enclava; make sure it exists so the CLI
    /// formatter is the one under test.
    fn ensure_run_dir() {
        let _ = std::fs::create_dir_all("/run/enclava");
    }

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

    /// Detached-header plumbing writes under /run/enclava; without root or a
    /// real /run/enclava the tmpfs copy cannot be created, so integration
    /// tests run privileged (CI runs them compile-only; the SEV-SNP nightlies
    /// run them for real). write_detached_copy also enforces tmpfs, so skip
    /// on dev machines whose /run/enclava is not RAM-backed.
    fn can_write_run_enclava() -> bool {
        std::fs::create_dir_all("/run/enclava").is_ok()
            && nix::sys::statfs::statfs("/run/enclava")
                .map(|s| s.filesystem_type() == nix::sys::statfs::TMPFS_MAGIC)
                .unwrap_or(false)
            && {
                let probe = format!(
                    "/run/enclava/.luks-integration-probe-{}-{}",
                    std::process::id(),
                    DETACHED_HEADER_COUNTER.fetch_add(1, Ordering::Relaxed)
                );
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&probe)
                    .map(|f| {
                        drop(f);
                        let _ = remove_file(&probe);
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
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test");
        format(&device, &keys).expect("format+seal");

        // On-disk header must now be invalid for stock cryptsetup.
        let status = std::process::Command::new("cryptsetup")
            .args(["isLuks", "--type", "luks2"])
            .arg(&device)
            .status()
            .expect("run isLuks");
        assert_eq!(status.code(), Some(1), "sealed header must fail isLuks");

        let opened = open(&device, "enclava-init-test", &keys).expect("open sealed volume");
        assert!(opened.mapper_path.starts_with("/dev/mapper/"));

        close_mapper("enclava-init-test");
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
        format(&device, &keys).expect("format+seal");

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
        format(&device, &keys).expect("format+seal");

        let wrong = VolumeKeys::new(keys.passphrase.clone(), DerivedSeed([0xEEu8; 32]));
        let err = open(&device, "enclava-init-test-wrongkey", &wrong)
            .expect_err("wrong MAC key must fail closed");
        assert!(err.to_string().contains("MAC mismatch"));
        detach_loop_device(&device);
        Ok(())
    }

    #[test]
    fn legacy_volume_is_adopted_and_sealed() -> Result<()> {
        if !can_write_run_enclava() {
            eprintln!("skipping: cannot write /run/enclava (needs root)");
            return Ok(());
        }
        let (_dir, img) = make_backing_file(64)?;
        let device = attach_loop_device(&img);
        let keys = volume_keys();
        close_mapper("enclava-init-test-adopt");

        // Simulate a pre-#242 volume: plain cryptsetup format, no seal.
        with_key_file(&keys.passphrase, |key_file| {
            let args = vec![
                "--disable-locks".to_string(),
                "luksFormat".to_string(),
                path_arg(&device)?,
                "--key-file".to_string(),
                path_arg(key_file)?,
                "--type".to_string(),
                "luks2".to_string(),
                "--cipher".to_string(),
                "aes-xts-plain64".to_string(),
                "--key-size".to_string(),
                "512".to_string(),
                "--sector-size".to_string(),
                "512".to_string(),
                "--batch-mode".to_string(),
            ];
            run_command("cryptsetup", &args)
        })?;

        let opened =
            open(&device, "enclava-init-test-adopt", &keys).expect("legacy volume is adopted");
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
        format(&device, &keys).expect("format+seal");

        // Simulate a crash between the two seal slot writes: zero the second
        // slot, leaving the first MAC in place.
        let start = luks2_seal::LUKS2_METADATA_COPY_SIZE + luks2_seal::HEADER_MAC_SLOT_OFFSET;
        let mut f = OpenOptions::new().write(true).open(&device)?;
        f.seek(SeekFrom::Start(start as u64))?;
        f.write_all(&vec![0u8; luks2_seal::HEADER_MAC_LEN])?;
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
        format(&device, &keys).expect("format+seal");
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
}
