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
//! Fresh LUKS2 volumes are formatted ext4 before the first mount, so the
//! runtime image must include `mkfs.ext4`.

use std::fs::{OpenOptions, remove_file};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use libcryptsetup_rs::{
    CryptInit, CryptParamsLuks2, CryptParamsLuks2Ref, consts::flags::CryptActivate,
    consts::vals::EncryptionFormat,
};

use crate::errors::{InitError, Result};
use crate::secrets::DerivedSeed;

const LUKS2_SECTOR_SIZE: u32 = 512;
static KEY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Path to the activated mapper device.
#[derive(Debug, Clone)]
pub struct LuksOpened {
    pub mapper_path: PathBuf,
}

/// True iff the device already carries a LUKS2 header that loads cleanly.
pub fn is_formatted(device: &Path) -> Result<bool> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;
    Ok(dev
        .context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .is_ok())
}

/// Format `device` as LUKS2 and add `key` as keyslot 0.
///
/// Used on first boot when the underlying block device is fresh.
pub fn format(device: &Path, key: &DerivedSeed) -> Result<()> {
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

    if let Err(err) = dev.context_handle().format(
        EncryptionFormat::Luks2,
        ("aes", "xts-plain64"),
        None,
        libcryptsetup_rs::Either::Right(64),
        Some(&mut params),
    ) {
        tracing::warn!(
            device = %device.display(),
            error = %err,
            "libcryptsetup format failed; falling back to cryptsetup CLI"
        );
        format_with_cryptsetup_cli(device, key).map_err(|cli_err| {
            InitError::Luks(format!("format: {err}; cli fallback: {cli_err}"))
        })?;
    }

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

/// Open `device` to `/dev/mapper/<mapping_name>` using `key`.
///
/// The header must already exist (call [`format`] first on a fresh device).
pub fn open(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<LuksOpened> {
    let mut dev = CryptInit::init(device)
        .map_err(|e| InitError::Luks(format!("init {}: {e}", device.display())))?;

    dev.context_handle()
        .load::<()>(Some(EncryptionFormat::Luks2), None)
        .map_err(|e| InitError::Luks(format!("load: {e}")))?;

    if let Err(err) = dev.activate_handle().activate_by_passphrase(
        Some(mapping_name),
        None,
        key.as_bytes(),
        CryptActivate::empty(),
    ) {
        tracing::warn!(
            device = %device.display(),
            mapping = mapping_name,
            error = %err,
            "libcryptsetup activate failed; falling back to cryptsetup CLI"
        );
        open_with_cryptsetup_cli(device, mapping_name, key).map_err(|cli_err| {
            InitError::Luks(format!("activate: {err}; cli fallback: {cli_err}"))
        })?;
    }

    Ok(LuksOpened {
        mapper_path: PathBuf::from(format!("/dev/mapper/{mapping_name}")),
    })
}

/// Format the device if it's not yet a LUKS2 volume, then activate it.
pub fn format_if_unformatted_then_open(
    device: &Path,
    mapping_name: &str,
    key: &DerivedSeed,
) -> Result<LuksOpened> {
    let needs_mkfs = !is_formatted(device)?;
    if needs_mkfs {
        format(device, key)?;
    }
    let opened = open(device, mapping_name, key)?;
    if needs_mkfs {
        mkfs_ext4(&opened.mapper_path)?;
    }
    Ok(opened)
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
            "--batch-mode".to_string(),
        ];
        run_command("cryptsetup", &args)
    })
}

fn open_with_cryptsetup_cli(device: &Path, mapping_name: &str, key: &DerivedSeed) -> Result<()> {
    with_key_file(key, |key_file| {
        let args = vec![
            "luksOpen".to_string(),
            path_arg(device)?,
            mapping_name.to_string(),
            "--key-file".to_string(),
            path_arg(key_file)?,
        ];
        run_command("cryptsetup", &args)
    })
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
    const LIMIT: usize = 2048;
    if value.len() <= LIMIT {
        value.to_string()
    } else {
        format!("{}...[truncated]", &value[..LIMIT])
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

#[cfg(all(test, feature = "luks-integration"))]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Seek, SeekFrom, Write};
    use tempfile::tempdir;

    fn make_backing_file(size_mb: u64) -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("disk.img");
        let mut f = File::create(&path).unwrap();
        f.seek(SeekFrom::Start(size_mb * 1024 * 1024 - 1)).unwrap();
        f.write_all(&[0u8]).unwrap();
        (dir, path)
    }

    #[test]
    fn format_then_open_round_trip() {
        let (_dir, img) = make_backing_file(32);
        let key = DerivedSeed([0x11u8; 32]);
        format(&img, &key).expect("format");
        let opened = open(&img, "enclava-init-test", &key).expect("open");
        assert!(opened.mapper_path.starts_with("/dev/mapper/"));
    }
}
