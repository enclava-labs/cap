//! Replicates the `resolve_exec_identity` + chown logic from the legacy
//! `bootstrap_script.sh` (lines 567-606). The workload may pass either:
//!   - a named user existing in /etc/passwd (resolved via `getpwnam_r`)
//!   - a numeric `<uid>` or `<uid>:<gid>` pair
//!
//! On resolution we recursively chown the seed file (and optionally the
//! decrypted mount root) to the target identity so the unprivileged app
//! container can read it.

use std::path::Path;

use crate::errors::{InitError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityKind {
    Named,
    Numeric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecIdentity {
    pub uid: u32,
    pub gid: u32,
    pub kind: IdentityKind,
}

pub fn resolve_exec_identity(target: &str) -> Result<ExecIdentity> {
    if let Some((uid, gid)) = lookup_user(target)? {
        return Ok(ExecIdentity {
            uid,
            gid,
            kind: IdentityKind::Named,
        });
    }

    let (uid_part, gid_part) = match target.split_once(':') {
        Some((u, g)) => (u, g),
        None => (target, target),
    };

    let uid = uid_part
        .parse::<u32>()
        .map_err(|_| InitError::Config(format!("invalid exec identity: {target}")))?;
    let gid = gid_part
        .parse::<u32>()
        .map_err(|_| InitError::Config(format!("invalid exec identity: {target}")))?;

    Ok(ExecIdentity {
        uid,
        gid,
        kind: IdentityKind::Numeric,
    })
}

fn lookup_user(name: &str) -> Result<Option<(u32, u32)>> {
    use nix::unistd::User;
    match User::from_name(name) {
        Ok(Some(u)) => Ok(Some((u.uid.as_raw(), u.gid.as_raw()))),
        Ok(None) => Ok(None),
        Err(e) => Err(InitError::Config(format!("getpwnam_r: {e}"))),
    }
}

/// Change ownership of `path` without following symlinks (lchown
/// semantics, #137). A symlink planted at a state path is owned as a
/// symlink instead of redirecting the chown at its target.
pub fn chown(path: &Path, ident: ExecIdentity) -> Result<()> {
    use nix::unistd::{Gid, Uid, fchownat};
    fchownat(
        None,
        path,
        Some(Uid::from_raw(ident.uid)),
        Some(Gid::from_raw(ident.gid)),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|e| InitError::Config(format!("chown: {e}")))?;
    Ok(())
}

pub fn chown_recursive(path: &Path, ident: ExecIdentity) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    if meta.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            chown_recursive(&entry.path(), ident)?;
        }
    }
    chown(path, ident)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn resolve_numeric_uid_only() {
        let id = resolve_exec_identity("10001").unwrap();
        assert_eq!(id.uid, 10001);
        assert_eq!(id.gid, 10001);
        assert_eq!(id.kind, IdentityKind::Numeric);
    }

    #[test]
    fn resolve_numeric_uid_gid() {
        let id = resolve_exec_identity("10001:20002").unwrap();
        assert_eq!(id.uid, 10001);
        assert_eq!(id.gid, 20002);
        assert_eq!(id.kind, IdentityKind::Numeric);
    }

    #[test]
    fn resolve_invalid() {
        assert!(resolve_exec_identity("not-a-real-user-xyzzy:abc").is_err());
    }

    #[test]
    fn chown_recursive_skips_symlinks() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let id = ExecIdentity {
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
            kind: IdentityKind::Numeric,
        };
        chown_recursive(dir.path(), id).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn chown_on_symlink_does_not_follow_the_link() {
        use std::os::unix::fs::MetadataExt;

        let current = ExecIdentity {
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
            kind: IdentityKind::Numeric,
        };

        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        let link = dir.path().join("link");
        std::fs::write(&target, b"secret").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // ctime granularity: give the filesystem a moment so a chown of the
        // wrong inode is always observable as a changed ctime.
        std::thread::sleep(std::time::Duration::from_millis(1100));

        let target_ctime_before = std::fs::metadata(&target).unwrap().ctime();
        let link_ctime_before = std::fs::symlink_metadata(&link).unwrap().ctime();

        chown(&link, current).unwrap();

        // The referent must be untouched: a following chown would have
        // updated its ctime (chown to the current ids still bumps ctime).
        assert_eq!(
            std::fs::metadata(&target).unwrap().ctime(),
            target_ctime_before,
            "chown followed the symlink: target inode was modified"
        );
        // The link inode itself must have been re-owned.
        assert_ne!(
            std::fs::symlink_metadata(&link).unwrap().ctime(),
            link_ctime_before,
            "symlink inode was not re-owned (lchown did not take effect)"
        );
    }
}
