//! Replicates the `resolve_exec_identity` + chown logic from the legacy
//! `bootstrap_script.sh` (lines 567-606). The workload may pass either:
//!   - a numeric `<uid>` or `<uid>:<gid>` pair (parsed directly, no NSS
//!     lookup — matches runc semantics and keeps numeric identities
//!     working on minimal hosts without a configured NSS backend)
//!   - a named user existing in /etc/passwd (resolved via `getpwnam_r`)
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
    // Numeric identities (`<uid>` or `<uid>:<gid>`) are parsed directly and
    // must not depend on NSS availability: `getpwnam_r` can fail with
    // ENOENT on minimal hosts (distroless containers, missing passwd
    // databases), and the legacy `bootstrap_script.sh` resolve_exec_identity
    // also falls through to numeric parsing whenever `id` fails for any
    // reason. Match runc semantics: an all-numeric spec is a UID, not a
    // username lookup.
    let (uid_part, gid_part) = match target.split_once(':') {
        Some((u, g)) => (u, g),
        None => (target, target),
    };

    if let (Ok(uid), Ok(gid)) = (uid_part.parse::<u32>(), gid_part.parse::<u32>()) {
        return Ok(ExecIdentity {
            uid,
            gid,
            kind: IdentityKind::Numeric,
        });
    }

    if let Some((uid, gid)) = lookup_user(target)? {
        return Ok(ExecIdentity {
            uid,
            gid,
            kind: IdentityKind::Named,
        });
    }

    Err(InitError::Config(format!(
        "invalid exec identity: {target}"
    )))
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

/// [`chown_recursive`] relative to an open directory fd (cap#290 round-2
/// review): the tree below a host-influenced path can be raced with
/// symlinks between operations, so traversal stays fd-anchored — every
/// entry is re-owned with `AT_SYMLINK_NOFOLLOW` (symlink inodes are owned,
/// never followed) and only entries that open as real directories under
/// `O_NOFOLLOW` are recursed into. `dir_fd` itself is not re-owned; the
/// caller owns the mount contract for the directory it opened.
pub fn chown_recursive_at(dir_fd: std::os::fd::RawFd, ident: ExecIdentity) -> Result<()> {
    use nix::dir::Dir;
    use nix::fcntl::{AtFlags, OFlag, openat};
    use nix::sys::stat::Mode;
    use nix::unistd::{Gid, Uid, fchownat};
    use std::os::fd::{AsRawFd, FromRawFd};

    const OPEN_DIR_FLAGS: OFlag = OFlag::from_bits_retain(
        OFlag::O_DIRECTORY.bits() | OFlag::O_NOFOLLOW.bits() | OFlag::O_CLOEXEC.bits(),
    );

    let mut dir = Dir::openat(Some(dir_fd), ".", OPEN_DIR_FLAGS, Mode::empty())
        .map_err(|e| InitError::Config(format!("opendir at fd {dir_fd}: {e}")))?;
    let entries: Vec<_> = dir
        .iter()
        .map(|entry| {
            let entry = entry.map_err(|e| InitError::Config(format!("readdir: {e}")))?;
            Ok((entry.file_name().to_bytes().to_vec(), entry.file_type()))
        })
        .collect::<Result<_>>()?;
    drop(dir);

    for (name_bytes, file_type) in entries {
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = std::ffi::CString::new(name_bytes)
            .map_err(|_| InitError::Config("directory entry contains NUL".to_string()))?;
        fchownat(
            Some(dir_fd),
            name.as_c_str(),
            Some(Uid::from_raw(ident.uid)),
            Some(Gid::from_raw(ident.gid)),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(|e| InitError::Config(format!("fchownat: {e}")))?;
        let is_dir = match file_type {
            Some(nix::dir::Type::Directory) => true,
            Some(_) => false,
            // Filesystem did not report the type; stat without following.
            None => {
                nix::sys::stat::fstatat(Some(dir_fd), name.as_c_str(), AtFlags::AT_SYMLINK_NOFOLLOW)
                    .map(|stat| (stat.st_mode & nix::libc::S_IFMT) == nix::libc::S_IFDIR)
                    .unwrap_or(false)
            }
        };
        if is_dir {
            // Re-open under O_NOFOLLOW: a directory raced to a symlink
            // between the type check and the open fails closed with ELOOP
            // instead of being followed.
            match openat(Some(dir_fd), name.as_c_str(), OPEN_DIR_FLAGS, Mode::empty()) {
                Ok(child_fd) => {
                    // SAFETY: openat returned a fresh owned descriptor.
                    let child = unsafe { std::os::fd::OwnedFd::from_raw_fd(child_fd) };
                    chown_recursive_at(child.as_raw_fd(), ident)?;
                }
                Err(nix::errno::Errno::ELOOP) | Err(nix::errno::Errno::ENOENT) => {}
                Err(e) => return Err(InitError::Config(format!("openat: {e}"))),
            }
        }
    }
    Ok(())
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
    fn resolve_numeric_takes_precedence_over_lookup() {
        // All-numeric specs are UIDs (runc semantics), never passed through
        // NSS — this holds even if a user literally named "0" existed.
        let id = resolve_exec_identity("0").unwrap();
        assert_eq!(id.kind, IdentityKind::Numeric);
        assert_eq!((id.uid, id.gid), (0, 0));
    }

    #[test]
    fn resolve_named_user_when_lookup_succeeds() {
        // Root exists on any POSIX test host with a passwd database.
        let id = resolve_exec_identity("root").unwrap();
        assert_eq!(id.uid, 0);
        assert_eq!(id.kind, IdentityKind::Named);
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

    #[cfg(unix)]
    #[test]
    fn chown_recursive_at_owns_entries_without_following_symlinks() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::io::AsRawFd;

        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let inner = nested.join("inner");
        std::fs::write(&inner, b"x").unwrap();
        // Referent lives OUTSIDE the scanned tree: only the symlink inside
        // the tree points at it, so any ctime change proves following.
        let outside_dir = tempdir().unwrap();
        let outside = outside_dir.path().join("outside");
        std::fs::write(&outside, b"secret").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&outside, &link).unwrap();

        // Same ctime trick as the lchown regression test: a following
        // chown would bump the referent's ctime.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let outside_ctime = std::fs::metadata(&outside).unwrap().ctime();

        let id = ExecIdentity {
            uid: nix::unistd::Uid::current().as_raw(),
            gid: nix::unistd::Gid::current().as_raw(),
            kind: IdentityKind::Numeric,
        };
        let fd = std::fs::File::open(dir.path()).unwrap();
        chown_recursive_at(fd.as_raw_fd(), id).unwrap();

        assert_eq!(
            std::fs::metadata(&outside).unwrap().ctime(),
            outside_ctime,
            "chown_recursive_at followed a symlink to its referent"
        );
        assert_eq!(std::fs::metadata(&inner).unwrap().uid(), id.uid);
        assert_eq!(std::fs::metadata(&nested).unwrap().uid(), id.uid);
        // The symlink inode itself was re-owned (lchown semantics).
        assert_eq!(std::fs::symlink_metadata(&link).unwrap().uid(), id.uid);
    }
}
