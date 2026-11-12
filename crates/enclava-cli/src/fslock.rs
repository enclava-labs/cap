//! Tiny cross-process file lock (flock via fd-lock). Used to serialize
//! read-modify-write sequences on CLI state (keyring envelopes, per-API
//! release baselines, template-deploy resume) so concurrent `enclava`
//! invocations cannot interleave them.
//!
//! `FileLockGuard` is `Send` and holds the lock until drop, including across
//! `.await` points. The flock itself lives on a helper thread because
//! `fd_lock`'s guard borrows its `RwLock` and cannot be returned directly.
//! Process death closes that thread's fd and releases the lock.

use std::io::{self, ErrorKind};
use std::path::Path;
use std::sync::mpsc;
use std::thread::JoinHandle;

/// Exclusive lock on `lock_path`, released when this guard drops.
#[must_use = "dropping the guard releases the file lock"]
pub(crate) struct FileLockGuard {
    release: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for FileLockGuard {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Run `f` while holding an exclusive lock on `lock_path`. The lock file is
/// created if absent and auto-released when the guard drops (including on
/// process death).
pub(crate) fn with_file_lock<T, E>(
    lock_path: &Path,
    f: impl FnOnce() -> Result<T, E>,
) -> Result<T, E>
where
    E: From<std::io::Error>,
{
    let _guard = acquire_file_lock(lock_path)?;
    f()
}

/// Block until `lock_path` can be locked exclusively.
pub(crate) fn acquire_file_lock(lock_path: &Path) -> io::Result<FileLockGuard> {
    spawn_lock(lock_path, true)
}

/// Lock `lock_path` if it is free. `Ok(None)` means another process holds it.
pub(crate) fn try_acquire_file_lock(lock_path: &Path) -> io::Result<Option<FileLockGuard>> {
    match spawn_lock(lock_path, false) {
        Ok(guard) => Ok(Some(guard)),
        Err(err) if err.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(err) => Err(err),
    }
}

fn spawn_lock(lock_path: &Path, blocking: bool) -> io::Result<FileLockGuard> {
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let path = lock_path.to_path_buf();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let thread = std::thread::Builder::new()
        .name("enclava-file-lock".to_string())
        .spawn(move || {
            // The write guard borrows `lock`, so both have to stay on this
            // thread until the caller drops `FileLockGuard`. Returning the
            // guard would unlock at the end of the acquire closure.
            let file = match std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
            {
                Ok(file) => file,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            let mut lock = fd_lock::RwLock::new(file);
            let guard = if blocking {
                lock.write().map_err(|err| {
                    io::Error::new(err.kind(), format!("acquire {}: {err}", path.display()))
                })
            } else {
                lock.try_write().map_err(|err| {
                    let kind = if err.kind() == ErrorKind::WouldBlock {
                        ErrorKind::WouldBlock
                    } else {
                        err.kind()
                    };
                    io::Error::new(kind, format!("acquire {}: {err}", path.display()))
                })
            };
            match guard {
                Ok(guard) => {
                    let _ = ready_tx.send(Ok(()));
                    let _ = release_rx.recv();
                    drop(guard);
                }
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                }
            }
        })
        .map_err(|err| io::Error::other(format!("spawn file lock thread: {err}")))?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(FileLockGuard {
            release: Some(release_tx),
            thread: Some(thread),
        }),
        Ok(Err(err)) => {
            let _ = thread.join();
            Err(err)
        }
        Err(_) => {
            let _ = thread.join();
            Err(io::Error::other(format!(
                "file lock thread exited before acquiring {}",
                lock_path.display()
            )))
        }
    }
}
