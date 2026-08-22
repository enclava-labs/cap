//! Tiny cross-process file lock (flock via fd-lock). Used to serialize
//! read-modify-write sequences on CLI state (keyring envelopes, per-API
//! release baselines) so concurrent `enclava` invocations cannot interleave
//! their high-water-mark updates.

/// Run `f` while holding an exclusive lock on `lock_path`. The lock file is
/// created if absent and auto-released when the guard drops (including on
/// process death).
pub(crate) fn with_file_lock<T, E>(
    lock_path: &std::path::Path,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E>
where
    E: From<std::io::Error>,
{
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(lock_path)?;
    let mut lock = fd_lock::RwLock::new(file);
    let _guard = lock.write().map_err(|err| {
        std::io::Error::new(
            err.kind(),
            format!("acquire {}: {err}", lock_path.display()),
        )
    })?;
    f()
}
