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

pub fn chown(path: &Path, ident: ExecIdentity) -> Result<()> {
    use nix::unistd::{Gid, Uid, chown};
    chown(
        path,
        Some(Uid::from_raw(ident.uid)),
        Some(Gid::from_raw(ident.gid)),
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
}
