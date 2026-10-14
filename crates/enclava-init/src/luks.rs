//! cryptsetup luksOpen / luksFormat via `libcryptsetup-rs`.
//!
//! Requires `libcryptsetup-dev` (Debian) / `cryptsetup-devel` (Fedora) at
//! build time and `libcryptsetup.so.12` at runtime. Inside the Kata SEV-SNP
//! guest the `dm_mod` and `dm_crypt` kernel features must be present. On the
//! production guest image they are built in, so CAP must not ask kata-agent to
//! modprobe them via `io.katacontainers.config.agent.kernel_modules`.
//!
//! Live Kata SEV-SNP validation showed LUKS format/open/mount works in the
//! guest when the runtime uses block hotplug plus `virtio-9p` filesystem
//! sharing. CAP avoids Kubernetes mountPropagation and starts app/caddy under
//! wait-exec helpers first, then this mounter sidecar bind-mounts the decrypted
//! paths into their mount namespaces and stays alive for the pod lifetime.
//! Fresh LUKS2 volumes are formatted AES-256-XTS with hmac-sha256
//! (dm-integrity) tags and then ext4 before the first mount, so the runtime
//! image must include `mkfs.ext4`.

use std::fs::{File, OpenOptions, remove_file};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libcryptsetup_rs::{
    CryptDevice, CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref,
    consts::flags::{CryptActivate, CryptDeactivate},
    consts::vals::EncryptionFormat,
};

use crate::errors::{InitError, Result};
use crate::secrets::DerivedSeed;

const LUKS2_SECTOR_SIZE: u32 = 512;
static KEY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

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

/// Detect whether the device carries a LUKS2 header without mutating it.
pub fn is_formatted(device: &Path) -> Result<bool> {
    match CryptInit::init(device) {
        Ok(mut dev) => {
            if dev
                .context_handle()
                .load::<()>(Some(EncryptionFormat::Luks2), None)
                .is_ok()
            {
                return Ok(true);
            }
        }
        Err(err) => {
            tracing::warn!(
                device = %device.display(),
                error = %err,
                "libcryptsetup init failed while probing LUKS header; falling back to CLI/header probe"
            );
        }
    }

    if cryptsetup_is_luks(device)? == Some(true) {
        return Ok(true);
    }

    // A raw header check is deliberately the last positive fallback. If a
    // reattached block device has LUKS2 magic but a library/CLI probe is
    // temporarily inconclusive, opening it may still succeed; reformatting it
    // would irreversibly destroy tenant state.
    device_has_luks2_header_magic(device)
}

/// Format `device` as LUKS2 and add `key` as keyslot 0.
/// Used on first boot when the underlying block device is fresh.
///
/// If we are interrupted after the LUKS header/keyslot is committed (during
/// the integrity-tag wipe or before mkfs), the volume is left formatted but
/// never initialized; later boots open it and fail at mount. That is by
/// design: no on-disk marker may authorize re-running wipe/mkfs, since a
/// replayed marker over a populated volume would destroy data. Recovery is
/// operator recreation of the never-ready volume until external
/// initialization state exists.
pub fn format(device: &Path, key: &DerivedSeed) -> Result<()> {
    if let Err(cli_err) = format_with_cryptsetup_cli(device, key) {
        tracing::warn!(
            device = %device.display(),
            error = %cli_err,
            "cryptsetup CLI format failed; falling back to libcryptsetup"
        );
        format_with_libcryptsetup(device, key).map_err(|lib_err| {
            InitError::Luks(format!(
                "format cli: {cli_err}; libcryptsetup fallback: {lib_err}"
            ))
        })?;
    }

    Ok(())
}

fn format_with_libcryptsetup(device: &Path, key: &DerivedSeed) -> Result<()> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;
    let params = luks2_format_params();
    let mut params: CryptParamsLuks2Ref<'_> = (&params)
        .try_into()
        .map_err(|e| InitError::Luks(format!("luks2 params: {e}")))?;

    dev.context_handle()
        .format(
            EncryptionFormat::Luks2,
            ("aes", "xts-plain64"),
            None,
            libcryptsetup_rs::Either::Right(VOLUME_KEY_BYTES),
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

    initialize_integrity_tags(&mut dev, key)
}

fn luks2_format_params() -> CryptParamsLuks2 {
    CryptParamsLuks2 {
        pbkdf: None,
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

/// crypt_format does not initialize dm-integrity tags like `luksFormat` does,
/// so reads of never-written sectors would fail. Writing zeros through the
/// activated mapper tags the whole data area.
fn initialize_integrity_tags(dev: &mut CryptDevice, key: &DerivedSeed) -> Result<()> {
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
        .map_err(|e| InitError::Luks(format!("activate wipe mapper: {e}")))?;

    let result = write_zeros_through_mapper(&PathBuf::from(format!("/dev/mapper/{wipe_name}")));
    let deactivate = dev
        .activate_handle()
        .deactivate(&wipe_name, CryptDeactivate::empty())
        .map_err(|e| InitError::Luks(format!("deactivate {wipe_name}: {e}")));

    result.and(deactivate)
}

fn unguessable_suffix() -> String {
    let mut bytes = [0u8; 16];
    let random = File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut bytes));
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

fn write_zeros_through_mapper(mapper_path: &Path) -> Result<()> {
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
    }
    file.sync_all()
        .map_err(|e| InitError::Luks(format!("sync {}: {e}", mapper_path.display())))
}

/// Open `device` to `/dev/mapper/<mapping_name>` using `key`.
///
/// The header must already exist (call [`format`] first on a fresh device).
pub fn open(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<LuksOpened> {
    let mapper_path = PathBuf::from(format!("/dev/mapper/{mapping_name}"));
    if mapper_path.exists() {
        validate_existing_mapper(device, mapping_name, key)?;
        return Ok(LuksOpened {
            mapper_path,
            formatted: false,
        });
    }

    if let Err(cli_err) = open_with_cryptsetup_cli(device, mapping_name, key) {
        tracing::warn!(
            device = %device.display(),
            mapping = mapping_name,
            error = %cli_err,
            "cryptsetup CLI activate failed; falling back to libcryptsetup"
        );
        open_with_libcryptsetup(device, mapping_name, key).map_err(|lib_err| {
            InitError::Luks(format!(
                "activate cli: {cli_err}; libcryptsetup fallback: {lib_err}"
            ))
        })?;
    }

    Ok(LuksOpened {
        mapper_path,
        formatted: false,
    })
}

fn validate_existing_mapper(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<()> {
    let status_device = cryptsetup_status_device(mapping_name)?;
    if let Some(status_device) = status_device
        && !paths_equivalent(&status_device, device)
    {
        return Err(InitError::Luks(format!(
            "existing mapper {mapping_name} is backed by {}, expected {}",
            status_device.display(),
            device.display()
        )));
    }
    test_passphrase_with_cryptsetup_cli(device, key)
}

fn open_with_libcryptsetup(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<()> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;

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

/// Format the device if it's not yet a LUKS2 volume, then activate it.
pub fn format_if_unformatted_then_open(
    device: &Path,
    mapping_name: &str,
    key: &DerivedSeed,
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
        format(device, key)?;
    }
    let mut opened = open(device, mapping_name, key)?;
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

fn open_with_cryptsetup_cli(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "--debug".to_string(),
            "--disable-locks".to_string(),
            "luksOpen".to_string(),
            path_arg(device)?,
            mapping_name.to_string(),
            "--key-file".to_string(),
            path_arg(key_file)?,
        ];
        run_command("cryptsetup", &args)
    })
}

fn test_passphrase_with_cryptsetup_cli(device: &Path, key: &DerivedSeed) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "--debug".to_string(),
            "--disable-locks".to_string(),
            "open".to_string(),
            "--test-passphrase".to_string(),
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

fn has_luks_keyslots(device: &Path) -> Result<Option<bool>> {
    let output = match std::process::Command::new("cryptsetup")
        .args(["luksDump", "--dump-json-metadata"])
        .arg(device)
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(InitError::Luks(format!("cryptsetup luksDump: {err}"))),
    };
    if !output.status.success() {
        return Ok(None);
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| InitError::Luks(format!("cryptsetup luksDump json: {e}")))?;
    Ok(metadata
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

fn device_appears_blank(device: &Path) -> Result<bool> {
    const PROBE_BYTES: usize = 4096;
    let mut file = OpenOptions::new()
        .read(true)
        .open(device)
        .map_err(|e| InitError::Luks(format!("open {} for blank probe: {e}", device.display())))?;
    let mut buf = [0u8; PROBE_BYTES];
    let read = file
        .read(&mut buf)
        .map_err(|e| InitError::Luks(format!("read {} blank probe: {e}", device.display())))?;
    Ok(buf[..read].iter().all(|byte| *byte == 0))
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
    fn blank_probe_distinguishes_fresh_and_nonempty_devices() {
        let dir = tempfile::tempdir().expect("temporary directory");
        let device = dir.path().join("device");
        std::fs::write(&device, [0u8; 4096]).expect("write blank device");
        assert!(device_appears_blank(&device).expect("probe blank device"));

        let mut nonempty = [0u8; 4096];
        nonempty[512] = 1;
        std::fs::write(&device, nonempty).expect("write nonempty device");
        assert!(!device_appears_blank(&device).expect("probe nonempty device"));
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

    fn luks_dump_json(device: &Path) -> Result<serde_json::Value> {
        let output = std::process::Command::new("cryptsetup")
            .args(["luksDump", "--dump-json-metadata"])
            .arg(device)
            .output()?;
        assert!(
            output.status.success(),
            "cryptsetup luksDump failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout)
            .map_err(|e| InitError::Luks(format!("luksDump json: {e}")))
    }

    /// dm-integrity superblock fields needed to map logical data sectors to
    /// physical sectors. On-disk layout (kernel drivers/md/dm-integrity.c):
    /// 8-sector superblock, then journal sections, then per interleave block
    /// of `interleave` data sectors a run of `metadata_run` tag sectors.
    struct IntegrityGeometry {
        /// Absolute byte offset of the superblock (== LUKS segment offset).
        base_bytes: u64,
        /// Sectors from the superblock to the first data sector.
        initial_sectors: u64,
        /// Tag-sector run after each interleave block.
        metadata_run: u64,
        log2_interleave_sectors: u8,
        /// Logical data sectors the device exposes.
        provided_data_sectors: u64,
    }

    impl IntegrityGeometry {
        /// Physical byte offset of logical data sector `logical_sector`,
        /// kernel `get_data_sector` for journaled interleaved layout.
        fn physical_byte_offset(&self, logical_sector: u64) -> u64 {
            let interleave = 1u64 << self.log2_interleave_sectors;
            let area = logical_sector >> self.log2_interleave_sectors;
            let offset = logical_sector & (interleave - 1);
            self.base_bytes
                + (self.initial_sectors
                    + area * interleave
                    + (area + 1) * self.metadata_run
                    + offset)
                    * 512
        }
    }

    /// Absolute byte offset of the dm-integrity superblock on the backing
    /// device (== LUKS2 segment offset; sector 0 of the integrity device).
    fn data_area_offset(device: &Path) -> Result<u64> {
        let metadata = luks_dump_json(device)?;
        let offset = metadata["segments"]["0"]["offset"].clone();
        match offset {
            serde_json::Value::String(s) => s
                .parse::<u64>()
                .map_err(|e| InitError::Luks(format!("segment offset parse: {e}"))),
            serde_json::Value::Number(n) => n
                .as_u64()
                .ok_or_else(|| InitError::Luks("segment offset not u64".to_string())),
            other => Err(InitError::Luks(format!("segment offset json: {other}"))),
        }
    }

    /// Read the plaintext dm-integrity superblock and reproduce the kernel's
    /// journal/tag geometry so a logical sector's ciphertext can be located.
    fn integrity_geometry(device: &Path) -> Result<IntegrityGeometry> {
        // Field offsets mirror `struct superblock` in drivers/md/dm-integrity.c.
        const SB_SECTORS: u64 = 8;
        const JOURNAL_ENTRY_ROUNDUP: usize = 8;
        const JOURNAL_MAC_PER_SECTOR: usize = 8;
        const JOURNAL_BLOCK_SECTORS: u64 = 8;
        const JOURNAL_SECTOR_DATA: usize = 512 - 8; // one commit_id_t header
        const SB_FLAG_HAVE_JOURNAL_MAC: u32 = 0x1;
        const SB_FLAG_FIXED_PADDING: u32 = 0x8;
        const METADATA_PADDING_SECTORS: u64 = 8;

        let base_bytes = data_area_offset(device)?;
        let mut sb = [0u8; 4096];
        File::open(device)?.read_exact_at(&mut sb, base_bytes)?;
        assert_eq!(&sb[..7], b"integrt", "dm-integrity superblock magic");

        // Offsets in struct superblock: magic 0..7, version 8,
        // log2_interleave 9, tag_size 10, journal_sections 12,
        // provided_data_sectors 16, flags 24, log2_sectors_per_block 28.
        let log2_interleave_sectors = sb[9];
        let tag_size = u16::from_le_bytes([sb[10], sb[11]]) as u64;
        let journal_sections = u32::from_le_bytes(sb[12..16].try_into().unwrap()) as u64;
        let provided_data_sectors = u64::from_le_bytes(sb[16..24].try_into().unwrap());
        let flags = u32::from_le_bytes(sb[24..28].try_into().unwrap());
        let log2_sectors_per_block = sb[28];

        // Kernel calculate_journal_section_size().
        let journal_entry_size = (8 + (8usize << log2_sectors_per_block) + tag_size as usize)
            .next_multiple_of(JOURNAL_ENTRY_ROUNDUP);
        let mut sector_space = JOURNAL_SECTOR_DATA;
        if flags & SB_FLAG_HAVE_JOURNAL_MAC != 0 {
            sector_space -= JOURNAL_MAC_PER_SECTOR;
        }
        let journal_section_entries =
            (sector_space / journal_entry_size) as u64 * JOURNAL_BLOCK_SECTORS;
        let journal_section_sectors =
            (journal_section_entries << log2_sectors_per_block) + JOURNAL_BLOCK_SECTORS;
        let initial_sectors = SB_SECTORS + journal_section_sectors * journal_sections;

        // Kernel calculate_device_limits(): tag run per interleave block,
        // padded for compatibility with volumes formatted by older versions.
        let padding_bytes = if flags & SB_FLAG_FIXED_PADDING != 0 {
            METADATA_PADDING_SECTORS << 9
        } else {
            1u64 << (9 + METADATA_PADDING_SECTORS)
        };
        let run_bytes = ((tag_size << log2_interleave_sectors) >> log2_sectors_per_block)
            .next_multiple_of(padding_bytes);
        let metadata_run = run_bytes / 512;

        Ok(IntegrityGeometry {
            base_bytes,
            initial_sectors,
            metadata_run,
            log2_interleave_sectors,
            provided_data_sectors,
        })
    }

    #[test]
    fn format_then_open_round_trip() -> Result<()> {
        ensure_run_dir();
        let key = DerivedSeed([0x11u8; 32]);

        // Exact 32 MiB backing exercises the smallest volume the stack must
        // support: LUKS2 header + integrity metadata + journal + ext4.
        let (_cli_dir, cli_img) = make_backing_file(32)?;
        format_with_cryptsetup_cli(&cli_img, &key).expect("cli format");
        assert_integrity_header(&cli_img)?;
        integrity_round_trip(&cli_img, &key)?;

        let (_lib_dir, lib_img) = make_backing_file(32)?;
        format_with_libcryptsetup(&lib_img, &key).expect("libcryptsetup format");
        assert_integrity_header(&lib_img)?;
        integrity_round_trip(&lib_img, &key)?;

        Ok(())
    }

    fn integrity_round_trip(device: &Path, key: &DerivedSeed) -> Result<()> {
        let mut mapping = TestMapping::activate(device, key)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(mapping.mapper_path())?;
        file.write_all(PAYLOAD)?;
        // Reads on never-written sectors must succeed: dm-integrity tags are
        // initialized over the whole data area at format time, tail included.
        let len = file.seek(SeekFrom::End(0))?;
        for offset in [(len / 2) & !0xfff, len - 4096] {
            file.seek(SeekFrom::Start(offset))?;
            let mut buf = [0xAAu8; 4096];
            file.read_exact(&mut buf)?;
            assert!(
                buf.iter().all(|b| *b == 0),
                "uninitialized tags at {offset}"
            );
        }
        file.sync_all()?;
        drop(file);
        mapping.close()?;

        let mut reopened = TestMapping::activate(device, key)?;
        let mut file = File::open(reopened.mapper_path())?;
        let mut buf = [0u8; PAYLOAD.len()];
        file.read_exact(&mut buf)?;
        assert_eq!(&buf[..], PAYLOAD, "payload must survive close and reopen");
        drop(file);
        // Real consumer flow after the raw round trip: mkfs (which erases the
        // boot sector holding the payload) must fit inside the integrity data
        // area and produce a checkable filesystem.
        mkfs_ext4(&reopened.mapper_path())?;
        run_command(
            "e2fsck",
            &[
                "-f".to_string(),
                "-n".to_string(),
                path_arg(&reopened.mapper_path())?,
            ],
        )?;
        reopened.close()
    }

    /// A wrong key must be refused without activating a mapping and without
    /// mutating the volume; the right key must still read the payload back.
    #[test]
    fn wrong_key_refused_without_mutating_volume() -> Result<()> {
        ensure_run_dir();
        let key = DerivedSeed([0x22u8; 32]);
        let wrong = DerivedSeed([0x33u8; 32]);

        let (_dir, img) = make_backing_file(64)?;
        format(&img, &key)?;
        let mut mapping = TestMapping::activate(&img, &key)?;
        let mut file = OpenOptions::new().write(true).open(mapping.mapper_path())?;
        file.write_all(PAYLOAD)?;
        file.sync_all()?;
        drop(file);
        mapping.close()?;

        let bad_name = TestMapping::random_name();
        assert!(
            open(&img, &bad_name, &wrong).is_err(),
            "wrong key must not activate"
        );
        assert!(
            !PathBuf::from(format!("/dev/mapper/{bad_name}")).exists(),
            "wrong key must not leave a mapping"
        );

        let reopened = TestMapping::activate(&img, &key)?;
        let mut buf = [0u8; PAYLOAD.len()];
        File::open(reopened.mapper_path())?.read_exact(&mut buf)?;
        assert_eq!(&buf[..], PAYLOAD, "failed open must not mutate the volume");
        Ok(())
    }

    /// Flipping one ciphertext byte of an initialized sector must turn reads
    /// of that sector into an I/O error on the next activation.
    #[test]
    fn tampered_ciphertext_sector_fails_reads() -> Result<()> {
        ensure_run_dir();
        let key = DerivedSeed([0x44u8; 32]);

        let (_dir, img) = make_backing_file(64)?;
        format(&img, &key)?;

        let mut mapping = TestMapping::activate(&img, &key)?;
        let mut file = File::open(mapping.mapper_path())?;
        let len = file.seek(SeekFrom::End(0))?;
        let tail = len - 4096;
        file.seek(SeekFrom::Start(tail))?;
        let mut buf = [0xAAu8; 4096];
        file.read_exact(&mut buf)?;
        assert!(buf.iter().all(|b| *b == 0), "tail tags uninitialized");
        drop(file);
        mapping.close()?;

        // The tail sector was never written through the mapper, so no journal
        // entry can replay over the tamper; its tag covers zeros. Locate its
        // ciphertext through the dm-integrity superblock: data sits after the
        // journal with a tag run after every interleave block, not at a linear
        // offset behind the LUKS segment start.
        let geometry = integrity_geometry(&img)?;
        assert_eq!(
            geometry.provided_data_sectors * 512,
            len,
            "superblock must describe the exposed data size"
        );
        let tampered_sector = geometry.physical_byte_offset(tail / 512);
        assert!(
            tampered_sector >= geometry.base_bytes + geometry.initial_sectors * 512,
            "tamper must land in the data area, not the journal"
        );

        let mut byte = [0u8; 1];
        let device_file = OpenOptions::new().read(true).write(true).open(&img)?;
        device_file.read_exact_at(&mut byte, tampered_sector)?;
        byte[0] ^= 0x01;
        device_file.write_all_at(&byte, tampered_sector)?;
        device_file.sync_all()?;
        drop(device_file);

        let reopened = TestMapping::activate(&img, &key)?;
        let mut file = File::open(reopened.mapper_path())?;
        file.seek(SeekFrom::Start(tail))?;
        let mut tampered = [0u8; 4096];
        assert!(
            file.read_exact(&mut tampered).is_err(),
            "tampered ciphertext sector must not read back"
        );
        Ok(())
    }

    /// Volumes formatted before integrity support have no integrity segment;
    /// they must open and stay usable without reformatting.
    #[test]
    fn existing_volume_without_integrity_reopens() -> Result<()> {
        ensure_run_dir();
        let key = DerivedSeed([0x55u8; 32]);

        let (_dir, img) = make_backing_file(32)?;
        with_key_file(&key, |key_file| {
            run_command(
                "cryptsetup",
                &[
                    "--disable-locks".to_string(),
                    "luksFormat".to_string(),
                    path_arg(&img)?,
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
                ],
            )
        })?;

        let mapping_name = TestMapping::random_name();
        let opened = format_if_unformatted_then_open(&img, &mapping_name, &key)?;
        assert!(!opened.formatted, "existing volume must not be reformatted");
        let mapping = TestMapping::new(mapping_name);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(mapping.mapper_path())?;
        file.write_all(PAYLOAD)?;
        file.sync_all()?;
        file.seek(SeekFrom::Start(0))?;
        let mut buf = [0u8; PAYLOAD.len()];
        file.read_exact(&mut buf)?;
        assert_eq!(&buf[..], PAYLOAD);

        let metadata = luks_dump_json(&img)?;
        for segment in metadata["segments"].as_object().expect("segments").values() {
            assert!(
                segment["integrity"].is_null(),
                "legacy volume must gain no integrity segment"
            );
        }
        Ok(())
    }

    fn assert_integrity_header(device: &Path) -> Result<()> {
        let metadata = luks_dump_json(device)?;

        let segments = metadata["segments"].as_object().expect("segments");
        let segment = segments["0"].as_object().expect("segment 0");
        assert_eq!(
            segment["encryption"].as_str(),
            Some("aes-xts-plain64"),
            "cipher must be AES-256-XTS"
        );
        assert_eq!(
            segment["integrity"]["type"].as_str(),
            Some("hmac(sha256)"),
            "integrity must be hmac(sha256)"
        );

        let keyslots = metadata["keyslots"].as_object().expect("keyslots");
        for keyslot in keyslots.values() {
            assert_eq!(
                keyslot["key_size"].as_u64(),
                Some(VOLUME_KEY_BYTES as u64),
                "volume key must be 64 cipher + 32 integrity bytes"
            );
        }
        Ok(())
    }
}
