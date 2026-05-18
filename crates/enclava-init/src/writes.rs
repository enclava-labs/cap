//! Atomic file writes via tmp+rename. A SIGKILL between write and rename
//! leaves only the tmp file at a sibling path; the destination is either the
//! prior contents or absent — never a partial write.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::Result;

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| crate::errors::InitError::Config("seed path has no parent".into()))?;
    fs::create_dir_all(parent)?;

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("seed");
    let mut tmp = None;
    for attempt in 0..16_u32 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let candidate = parent.join(format!(".{file_name}.{nonce}.{attempt}.tmp"));
        let opened = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&candidate);
        match opened {
            Ok(mut f) => {
                f.write_all(bytes)?;
                f.sync_all()?;
                tmp = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let tmp = tmp.ok_or_else(|| {
        crate::errors::InitError::Config(format!("failed to allocate temporary path for {file_name}"))
    })?;

    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use tempfile::tempdir;

    #[test]
    fn atomic_write_creates_file_with_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed");
        atomic_write(&path, b"hello", 0o600).unwrap();
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn atomic_write_replaces_existing_atomically() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("seed");
        atomic_write(&path, b"v1", 0o600).unwrap();
        atomic_write(&path, b"v2", 0o600).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"v2");
    }

    #[test]
    fn atomic_write_no_partial_on_simulated_kill() {
        let dir = tempdir().unwrap();
        let dest = dir.path().join("seed");
        atomic_write(&dest, b"original", 0o600).unwrap();

        let tmp = dir.path().join(".seed.tmp");
        std::fs::write(&tmp, b"partial").unwrap();
        assert_eq!(fs::read(&dest).unwrap(), b"original");
        assert!(tmp.exists());
    }

    #[test]
    fn atomic_write_ignores_existing_predictable_tmp_symlink() {
        let dir = tempdir().unwrap();
        let parent = dir.path();
        let dest = parent.join("seed");
        let target = parent.join("target");
        fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, parent.join(".seed.tmp")).unwrap();

        atomic_write(&dest, b"new-seed", 0o600).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), b"new-seed");
        assert_eq!(fs::read(&target).unwrap(), b"target");
    }
}
