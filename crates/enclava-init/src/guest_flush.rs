//! Flush the Kata guest page cache before VM teardown.
//!
//! A write to the persistent home (`/state`, ext4-on-LUKS) updates the
//! inode in the journal and leaves the data blocks in the guest page
//! cache. Process exit does not write that cache back. Pod delete delivers
//! SIGTERM and then destroys the VM, so an unflushed file comes back with
//! its directory entry intact and zero length. `sync`/`syncfs` from any
//! process on this kernel pushes those pages through dm-crypt before the
//! hypervisor tears the guest down. Containers share that kernel, so the
//! flush covers workload writes even when they happened in another mount
//! namespace.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long to wait for workload processes to exit before the first
/// post-sibling flush.
///
/// Must stay well under the pod termination grace (Kubernetes default 30s)
/// so this flush runs before SIGKILL. The SIGTERM handler's immediate
/// `sync` is the backstop if the wait is cut short.
pub const SIBLING_EXIT_WAIT: Duration = Duration::from_secs(15);

/// Hard stop for the whole teardown sequence, measured from SIGTERM.
///
/// Kubernetes SIGKILLs the pod at the 30s grace boundary. Stopping just
/// short of it keeps the final flush (and its log records) observable
/// before the kill (cap#193 round-2 review, warning 3: exiting at the
/// 15s sibling budget abandoned the second half of the grace period in
/// which an exec-path workload may still be writing).
pub const TEARDOWN_DEADLINE: Duration = Duration::from_secs(28);

/// Re-flush cadence while lingering for siblings that ignore SIGTERM.
pub const RELUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Hard cap on one sentinel read. The started dir is group-writable by the
/// tenant workload, so a planted multi-gigabyte sentinel must not OOM the
/// sidecar mid-teardown (cap#193 round-2 review, warning 1).
pub const SENTINEL_READ_LIMIT: usize = 4 * 1024;

/// Poll interval while waiting for sibling processes to exit.
pub const WAIT_SLICE: Duration = Duration::from_millis(200);

/// Why a flush is running. Logged so an operator can see that teardown
/// actually synced, which the silent zero-length failure never did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushReason {
    /// Dirty pages that already existed when SIGTERM arrived.
    OnSignal,
    /// Writes the workload made while handling its own SIGTERM.
    AfterSiblings,
}

impl FlushReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OnSignal => "signal",
            Self::AfterSiblings => "after-siblings",
        }
    }
}

/// A workload process recorded by `enclava-wait-exec` before it execs or
/// waits. `start_time_ticks` distinguishes a reused pid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingProcess {
    pub pid: u32,
    pub start_time_ticks: Option<u64>,
}

#[derive(Debug)]
pub struct MountFlush {
    pub path: PathBuf,
    pub result: io::Result<()>,
}

#[derive(Debug)]
pub struct FlushReport {
    pub mounts: Vec<MountFlush>,
    /// `sync(2)` has no error return. This is true only after we invoked it.
    pub global_sync: bool,
}

/// Operations the flush performs. Production uses [`LibcGuestSync`]; tests
/// record the calls so a regression that skips the flush fails closed.
pub trait GuestSync {
    fn syncfs(&mut self, path: &Path) -> io::Result<()>;
    fn sync(&mut self);
}

/// libc `syncfs` + `sync`. The Kata guest and the unit tests both run on Linux.
#[derive(Debug, Default)]
pub struct LibcGuestSync;

impl GuestSync for LibcGuestSync {
    fn syncfs(&mut self, path: &Path) -> io::Result<()> {
        syncfs_path(path)
    }

    fn sync(&mut self) {
        signal_safe_sync();
    }
}

/// Async-signal-safe. The SIGTERM handler calls this so a later SIGKILL
/// cannot discard pages that were already dirty when deletion started.
pub fn signal_safe_sync() {
    // SAFETY: sync(2) takes no arguments and is async-signal-safe. It
    // writes every dirty page on this kernel, including the workload's
    // cache on the shared Kata guest.
    unsafe { nix::libc::sync() };
}

pub fn syncfs_path(path: &Path) -> io::Result<()> {
    let file = File::open(path)?;
    syncfs_fd(file.as_raw_fd())
}

pub fn syncfs_fd(fd: i32) -> io::Result<()> {
    // SAFETY: `fd` is an open descriptor owned by the caller for this call.
    // syncfs(2) is async-signal-safe and only operates on that descriptor.
    let rc = unsafe { nix::libc::syncfs(fd) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Sync every mount, then the whole kernel cache. A failure on one mount
/// must not skip the others or the global `sync`: the persistent home and
/// the tls-state volume are separate LUKS devices, and either one can be
/// the volume a workload just wrote.
pub fn flush_mounts_with(mounts: &[impl AsRef<Path>], ops: &mut impl GuestSync) -> FlushReport {
    let mut report = FlushReport {
        mounts: Vec::with_capacity(mounts.len()),
        global_sync: false,
    };
    for mount in mounts {
        let path = mount.as_ref();
        let result = ops.syncfs(path);
        report.mounts.push(MountFlush {
            path: path.to_path_buf(),
            result,
        });
    }
    ops.sync();
    report.global_sync = true;
    report
}

pub fn flush_mounts(mounts: &[impl AsRef<Path>]) -> FlushReport {
    flush_mounts_with(mounts, &mut LibcGuestSync)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiblingLiveness {
    Alive,
    Exited,
    /// `/proc` could not be read. Keep waiting; the budget still bounds it,
    /// so a transient read error cannot cut the wait short of the sibling's
    /// shutdown writes.
    Unreadable,
}

pub fn sibling_liveness(proc_root: &Path, sibling: &SiblingProcess) -> SiblingLiveness {
    if sibling.pid == 0 {
        return SiblingLiveness::Exited;
    }
    let stat_path = proc_root.join(sibling.pid.to_string()).join("stat");
    let stat = match fs::read_to_string(&stat_path) {
        Ok(stat) => stat,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return SiblingLiveness::Exited,
        Err(_) => return SiblingLiveness::Unreadable,
    };
    let Some(expected) = sibling.start_time_ticks else {
        // Legacy sentinel: pid only. A live `/proc` entry is the best
        // evidence available; the wait budget bounds pid-reuse damage.
        return SiblingLiveness::Alive;
    };
    match start_time_ticks_from_stat(&stat) {
        Ok(actual) if actual == expected => SiblingLiveness::Alive,
        Ok(_) => SiblingLiveness::Exited,
        Err(_) => SiblingLiveness::Unreadable,
    }
}

pub fn pending_siblings(proc_root: &Path, siblings: &[SiblingProcess]) -> Vec<u32> {
    siblings
        .iter()
        .filter(|sibling| {
            !matches!(
                sibling_liveness(proc_root, sibling),
                SiblingLiveness::Exited
            )
        })
        .map(|sibling| sibling.pid)
        .collect()
}

/// Parse one wait-exec sentinel. Returns `None` for our own pid, pid 0, and
/// records that do not name a pid — those must not stall teardown.
pub fn sibling_from_sentinel(text: &str, self_pid: u32) -> Option<SiblingProcess> {
    let mut pid = None;
    let mut start_time_ticks = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "pid" => pid = value.parse::<u32>().ok(),
            "start_time_ticks" => start_time_ticks = value.parse::<u64>().ok(),
            _ => {}
        }
    }
    let pid = pid.filter(|pid| *pid != 0 && *pid != self_pid)?;
    Some(SiblingProcess {
        pid,
        start_time_ticks,
    })
}

/// Read workload sentinels. Symlinks and non-regular entries (a planted
/// FIFO) are skipped: the started dir is group-writable, and neither a
/// symlink redirect, a blocking open, nor an oversized file may stall or
/// exhaust the teardown flush (see [`read_regular_nofollow`]).
pub fn load_siblings(started_dir: &Path, self_pid: u32) -> Vec<SiblingProcess> {
    let Ok(entries) = fs::read_dir(started_dir) else {
        return Vec::new();
    };
    let mut siblings = Vec::new();
    for entry in entries.flatten() {
        let Ok(text) = read_regular_nofollow(&entry.path()) else {
            continue;
        };
        if let Some(sibling) = sibling_from_sentinel(&text, self_pid) {
            siblings.push(sibling);
        }
    }
    siblings
}

/// Read one sentinel from the group-writable started dir without letting
/// its content stall or exhaust the sidecar (cap#193 round-2 review,
/// warning 1).
///
/// - `O_NOFOLLOW`: a planted symlink must not redirect the read.
/// - `O_NONBLOCK` + `S_ISREG` (fstat of the fd we hold, so the check
///   cannot be raced by a path swap): a planted FIFO would otherwise
///   block the open indefinitely with no writer — verified live against
///   the round-1 code. The spool reader in enclava-wait-exec refuses
///   non-regular files for the same reason.
/// - `take(SENTINEL_READ_LIMIT)`: a planted multi-gigabyte regular file
///   must not be buffered whole into the sidecar mid-teardown.
fn read_regular_nofollow(path: &Path) -> io::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    // O_NONBLOCK is a no-op on regular files; the fstat is what rejects
    // the FIFO. stat the fd, not the path: the fd stays pinned to the
    // inode we opened even if the name is swapped underneath us.
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sentinel is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    // `take` wants u64; usize widens to it losslessly on every platform
    // this builds for.
    file.take(SENTINEL_READ_LIMIT as u64)
        .read_to_end(&mut bytes)?;
    // Lossy: a planted sentinel that is not valid UTF-8 simply parses to
    // no pid and is skipped; a real sentinel is ASCII.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// `starttime` is field 22 of `/proc/<pid>/stat`, index 19 after the `) `
/// that ends the comm field (which may itself contain spaces).
pub fn start_time_ticks_from_stat(stat: &str) -> io::Result<u64> {
    let (_, rest) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat missing comm delimiter"))?;
    let field = rest
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat missing starttime"))?;
    field.parse::<u64>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "stat starttime is not an integer",
        )
    })
}

pub struct TeardownFlushOutcome {
    pub waited: Duration,
    pub siblings_remaining: Vec<u32>,
    /// How many times the post-sibling flush ran. One after the initial
    /// wait, then one per `RELUSH_INTERVAL` spent lingering, then one
    /// final flush at the end.
    pub after_sibling_flushes: u32,
}

/// Flush immediately, wait until siblings have exited or `initial_wait`
/// elapses, then flush again. While siblings remain, keep waiting and
/// re-flushing every [`RELUSH_INTERVAL`] until `deadline` (measured from
/// entry, i.e. from SIGTERM), then flush a final time.
///
/// The first flush is what saves the writes that were already dirty when
/// pod delete arrived — the reported failure. The second flush covers
/// writes the workload made in its own SIGTERM handler before it exited.
/// The linger loop keeps re-flushing for a workload that ignores SIGTERM
/// instead of exiting at the sibling budget and abandoning the rest of
/// the grace period (cap#193 round-2 review, warning 3). No flush may be
/// dropped: a sibling that ignores SIGTERM must not turn the wait into a
/// skip.
pub fn run_teardown_flush<F, P, S>(
    siblings: &[SiblingProcess],
    initial_wait: Duration,
    deadline: Duration,
    mut flush: F,
    mut pending: P,
    mut sleep: S,
) -> TeardownFlushOutcome
where
    F: FnMut(FlushReason),
    P: FnMut(&[SiblingProcess]) -> Vec<u32>,
    S: FnMut(Duration),
{
    flush(FlushReason::OnSignal);
    let mut waited = Duration::ZERO;
    let mut remaining = pending(siblings);
    while !remaining.is_empty() && waited < initial_wait {
        let slice = WAIT_SLICE.min(initial_wait.saturating_sub(waited));
        if slice.is_zero() {
            break;
        }
        sleep(slice);
        waited = waited.saturating_add(slice);
        remaining = pending(siblings);
    }
    flush(FlushReason::AfterSiblings);
    let mut after_sibling_flushes = 1u32;
    // Linger: siblings that ignore SIGTERM keep the guest alive until the
    // grace boundary; keep their ongoing writes flushed while we wait.
    let mut next_flush = waited.saturating_add(RELUSH_INTERVAL);
    let mut lingered = false;
    while !remaining.is_empty() && waited < deadline {
        lingered = true;
        let slice = WAIT_SLICE.min(deadline.saturating_sub(waited));
        if slice.is_zero() {
            break;
        }
        sleep(slice);
        waited = waited.saturating_add(slice);
        remaining = pending(siblings);
        if waited >= next_flush {
            flush(FlushReason::AfterSiblings);
            after_sibling_flushes += 1;
            next_flush = waited.saturating_add(RELUSH_INTERVAL);
        }
    }
    if lingered {
        // Final flush: covers a sibling that exited during the linger, and
        // leaves the guest as clean as possible at the deadline.
        flush(FlushReason::AfterSiblings);
        after_sibling_flushes += 1;
    }
    TeardownFlushOutcome {
        waited,
        siblings_remaining: remaining,
        after_sibling_flushes,
    }
}

pub struct TeardownRequest<'a> {
    pub mounts: &'a [PathBuf],
    pub siblings: &'a [SiblingProcess],
    pub initial_wait: Duration,
    pub deadline: Duration,
}

/// Production teardown: every flush pass goes through [`flush_mounts_with`].
pub fn execute_teardown_with<G, P, S>(
    request: &TeardownRequest<'_>,
    ops: &mut G,
    mut pending: P,
    sleep: S,
) -> (Vec<FlushReport>, TeardownFlushOutcome)
where
    G: GuestSync,
    P: FnMut(&[SiblingProcess]) -> Vec<u32>,
    S: FnMut(Duration),
{
    let mut reports = Vec::new();
    let outcome = run_teardown_flush(
        request.siblings,
        request.initial_wait,
        request.deadline,
        |_| {
            reports.push(flush_mounts_with(request.mounts, ops));
        },
        &mut pending,
        sleep,
    );
    (reports, outcome)
}

pub fn execute_teardown<P, S>(
    request: &TeardownRequest<'_>,
    pending: P,
    sleep: S,
) -> (Vec<FlushReport>, TeardownFlushOutcome)
where
    P: FnMut(&[SiblingProcess]) -> Vec<u32>,
    S: FnMut(Duration),
{
    execute_teardown_with(request, &mut LibcGuestSync, pending, sleep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Recorder {
        calls: Vec<String>,
        fail_suffix: &'static str,
    }

    impl GuestSync for Recorder {
        fn syncfs(&mut self, path: &Path) -> io::Result<()> {
            self.calls.push(format!("syncfs:{}", path.display()));
            if path.ends_with(self.fail_suffix) {
                Err(io::Error::new(io::ErrorKind::NotFound, "missing mount"))
            } else {
                Ok(())
            }
        }

        fn sync(&mut self) {
            self.calls.push("sync".to_string());
        }
    }

    #[test]
    fn flush_attempts_every_mount_then_syncs_even_if_one_fails() {
        let mut ops = Recorder {
            calls: Vec::new(),
            fail_suffix: "tls-state",
        };
        let report = flush_mounts_with(
            &[Path::new("/state"), Path::new("/state/tls-state")],
            &mut ops,
        );
        assert_eq!(
            ops.calls,
            vec![
                "syncfs:/state".to_string(),
                "syncfs:/state/tls-state".to_string(),
                "sync".to_string(),
            ],
            "a failed mount must not skip the sibling volume or the global sync"
        );
        assert!(report.mounts[0].result.is_ok());
        assert!(report.mounts[1].result.is_err());
        assert!(report.global_sync);
    }

    #[test]
    fn teardown_flushes_before_the_wait_and_again_after_the_sibling_exits() {
        let sibling = SiblingProcess {
            pid: 42,
            start_time_ticks: Some(7),
        };
        let events = std::cell::RefCell::new(Vec::new());
        let mut checks = 0;
        let outcome = run_teardown_flush(
            &[sibling],
            SIBLING_EXIT_WAIT,
            TEARDOWN_DEADLINE,
            |reason| {
                events
                    .borrow_mut()
                    .push(format!("flush:{}", reason.as_str()))
            },
            |_| {
                checks += 1;
                if checks == 1 { vec![42] } else { vec![] }
            },
            |delay| {
                events
                    .borrow_mut()
                    .push(format!("sleep:{}ms", delay.as_millis()))
            },
        );
        assert_eq!(
            events.into_inner(),
            vec![
                "flush:signal".to_string(),
                format!("sleep:{}ms", WAIT_SLICE.as_millis()),
                "flush:after-siblings".to_string(),
            ],
            "pod delete must flush pages already dirty, then flush again only after the workload exits"
        );
        assert!(outcome.siblings_remaining.is_empty());
        assert_eq!(outcome.waited, WAIT_SLICE);
        assert_eq!(
            outcome.after_sibling_flushes, 1,
            "a sibling that exits promptly must not trigger linger re-flushes"
        );
    }

    #[test]
    fn teardown_still_flushes_when_the_sibling_ignores_sigterm() {
        let mut events = Vec::new();
        let outcome = run_teardown_flush(
            &[SiblingProcess {
                pid: 9,
                start_time_ticks: Some(1),
            }],
            Duration::from_millis(400),
            Duration::from_millis(800),
            |reason| events.push(reason),
            |_| vec![9],
            |_| {},
        );
        assert_eq!(
            events,
            vec![
                FlushReason::OnSignal,
                FlushReason::AfterSiblings,
                FlushReason::AfterSiblings,
            ],
            "the post-sibling flush runs once after the initial wait and once more when lingering ends"
        );
        assert_eq!(outcome.siblings_remaining, vec![9]);
        assert_eq!(outcome.waited, Duration::from_millis(800));
        assert_eq!(outcome.after_sibling_flushes, 2);
    }

    #[test]
    fn teardown_linger_keeps_reflushing_until_the_deadline() {
        // A sibling that ignores SIGTERM must not make teardown give up at
        // the initial wait: the remaining grace period is spent re-flushing
        // so the workload's ongoing writes keep landing (round-2 review
        // warning 3).
        let mut events = Vec::new();
        let outcome = run_teardown_flush(
            &[SiblingProcess {
                pid: 9,
                start_time_ticks: Some(1),
            }],
            Duration::from_millis(100),
            Duration::from_millis(11_100),
            |reason| events.push(reason),
            |_| vec![9],
            |_| {},
        );
        let signal_flushes = events
            .iter()
            .filter(|reason| **reason == FlushReason::OnSignal)
            .count();
        let after_flushes = events
            .iter()
            .filter(|reason| **reason == FlushReason::AfterSiblings)
            .count();
        assert_eq!(signal_flushes, 1);
        // 100ms initial wait; re-flushes once waited passes 5.1s and 10.1s
        // (RELUSH_INTERVAL after each), then the final flush at the 11.1s
        // deadline: 1 + 2 + 1.
        assert_eq!(after_flushes, 4);
        assert_eq!(outcome.after_sibling_flushes, 4);
        assert_eq!(outcome.waited, Duration::from_millis(11_100));
        assert_eq!(outcome.siblings_remaining, vec![9]);
    }

    #[test]
    fn execute_teardown_syncs_both_volumes_on_signal_and_after_siblings() {
        let mut ops = Recorder {
            calls: Vec::new(),
            fail_suffix: "tls-state",
        };
        let mounts = vec![PathBuf::from("/state"), PathBuf::from("/state/tls-state")];
        let siblings = vec![SiblingProcess {
            pid: 42,
            start_time_ticks: Some(7),
        }];
        let mut checks = 0;
        let (reports, outcome) = execute_teardown_with(
            &TeardownRequest {
                mounts: &mounts,
                siblings: &siblings,
                initial_wait: SIBLING_EXIT_WAIT,
                deadline: TEARDOWN_DEADLINE,
            },
            &mut ops,
            |_| {
                checks += 1;
                if checks == 1 { vec![42] } else { vec![] }
            },
            |_| {},
        );
        assert_eq!(reports.len(), 2);
        assert!(reports.iter().all(|report| report.global_sync));
        assert_eq!(
            ops.calls,
            vec![
                "syncfs:/state",
                "syncfs:/state/tls-state",
                "sync",
                "syncfs:/state",
                "syncfs:/state/tls-state",
                "sync",
            ]
        );
        assert!(outcome.siblings_remaining.is_empty());
    }

    #[test]
    fn syncfs_fd_rejects_a_bad_fd_and_accepts_a_directory() {
        let err = syncfs_fd(-1).expect_err("bad fd");
        assert_eq!(err.raw_os_error(), Some(nix::libc::EBADF));
        let dir = tempfile::tempdir().expect("tempdir");
        let file = File::open(dir.path()).expect("open tempdir");
        syncfs_fd(file.as_raw_fd()).expect("syncfs on a real directory");
        // A missing mount surfaces as NotFound without a global sync(2):
        // the real global sync is deliberately not exercised in unit tests
        // (round-2 review suggestion 3 — a slow CI disk would add
        // unbounded latency); flush_mounts_with ordering is covered by the
        // Recorder tests above.
        let err =
            syncfs_path(Path::new("/no/such/enclava-flush-mount")).expect_err("missing mount");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn sibling_liveness_treats_missing_and_reused_pids_as_exited() {
        let root = tempfile::tempdir().expect("proc root");
        let sibling = SiblingProcess {
            pid: 42,
            start_time_ticks: Some(99),
        };
        assert_eq!(
            sibling_liveness(root.path(), &sibling),
            SiblingLiveness::Exited
        );

        let pid_dir = root.path().join("42");
        fs::create_dir(&pid_dir).unwrap();
        fs::write(
            pid_dir.join("stat"),
            "42 (workload) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99\n",
        )
        .unwrap();
        assert_eq!(
            sibling_liveness(root.path(), &sibling),
            SiblingLiveness::Alive
        );
        let reused = SiblingProcess {
            pid: 42,
            start_time_ticks: Some(100),
        };
        assert_eq!(
            sibling_liveness(root.path(), &reused),
            SiblingLiveness::Exited
        );
        fs::write(pid_dir.join("stat"), "not a stat").unwrap();
        assert_eq!(
            sibling_liveness(root.path(), &sibling),
            SiblingLiveness::Unreadable
        );
        assert_eq!(
            pending_siblings(root.path(), &[sibling]),
            vec![42],
            "an unreadable stat must keep the wait alive until the budget"
        );
    }

    #[test]
    fn load_siblings_skips_symlinks_self_and_pid_zero() {
        let dir = tempfile::tempdir().expect("started dir");
        fs::write(
            dir.path().join("web"),
            "version=1\ncontainer=web\npid=50\nstart_time_ticks=8\nuid=1\ngid=1\n",
        )
        .unwrap();
        fs::write(dir.path().join("self"), "pid=7\nstart_time_ticks=1\n").unwrap();
        fs::write(dir.path().join("bogus"), "pid=0\n").unwrap();
        symlink("/etc/passwd", dir.path().join("planted")).unwrap();
        let siblings = load_siblings(dir.path(), 7);
        assert_eq!(
            siblings,
            vec![SiblingProcess {
                pid: 50,
                start_time_ticks: Some(8),
            }]
        );
    }

    #[test]
    fn load_siblings_skips_a_planted_fifo_without_blocking() {
        // cap#193 round-2 review warning 1: the started dir is
        // group-writable by the workload. A planted FIFO must be skipped,
        // not block the teardown flush forever — the round-1 code hung on
        // exactly this open. A hung test times out; a fixed one is instant.
        let dir = tempfile::tempdir().expect("started dir");
        fs::write(
            dir.path().join("web"),
            "version=1\ncontainer=web\npid=50\nstart_time_ticks=8\n",
        )
        .unwrap();
        nix::unistd::mkfifo(
            &dir.path().join("planted"),
            nix::sys::stat::Mode::from_bits(0o666).unwrap(),
        )
        .unwrap();
        let siblings = load_siblings(dir.path(), 7);
        assert_eq!(
            siblings,
            vec![SiblingProcess {
                pid: 50,
                start_time_ticks: Some(8),
            }],
            "a planted FIFO must be skipped, not stall or abort the sentinel scan"
        );
    }

    #[test]
    fn load_siblings_bounds_a_planted_oversized_sentinel() {
        // A multi-megabyte planted sentinel must not be buffered whole
        // into the sidecar mid-teardown: the read is capped, and the
        // record still parses from its capped prefix.
        let dir = tempfile::tempdir().expect("started dir");
        let mut body = String::from("version=1\ncontainer=web\npid=50\nstart_time_ticks=8\n");
        // Well past SENTINEL_READ_LIMIT (~28 KiB): only the capped prefix
        // is ever buffered, and the pid record still parses from it.
        body.push_str(&"filler\n".repeat(SENTINEL_READ_LIMIT / 7));
        fs::write(dir.path().join("web"), body).unwrap();
        let siblings = load_siblings(dir.path(), 7);
        assert_eq!(
            siblings,
            vec![SiblingProcess {
                pid: 50,
                start_time_ticks: Some(8),
            }]
        );
    }

    #[test]
    fn start_time_parser_accepts_a_comm_with_spaces() {
        let stat = "12 (my proc) S 0 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 12345 extra";
        assert_eq!(start_time_ticks_from_stat(stat).unwrap(), 12345);
        assert!(start_time_ticks_from_stat("no delimiter").is_err());
    }
}
