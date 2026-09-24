use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

/// O_NOFOLLOW for Linux: reject a final-path-component symlink instead of
/// following it. The relay runs as root inside enclava-init and reads files
/// from `/run/enclava-logs`, a directory the workload user (gid 10001) can
/// write to — a compromised workload must not be able to swap the spool for
/// a symlink into init-only state (TLS seeds, KBS material) and have the
/// relay stream it to logs clients.
const O_NOFOLLOW: i32 = 0o400000;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_SPOOL_PATH: &str = "/run/enclava-logs/app.jsonl";
const SPOOL_DIR: &str = "/run/enclava-logs";
const DEFAULT_CONTAINER: &str = "app";
const DEFAULT_TAIL_LINES: usize = 100;
const MAX_TAIL_LINES: usize = 1_000;
const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024;
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Hard ceiling on one blocking socket write/read during a follow stream.
/// A stalled or dead client must not pin the relay thread (and the rotated
/// spool inode it holds open) forever: on expiry the connection errors out,
/// the follower handle is dropped, and the unlinked old inode is finally
/// released. Generous enough that a slow-but-alive client on a cold
/// connection is never cut off mid-stream.
const FOLLOW_IO_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct LogRelayConfig {
    pub bind: std::net::SocketAddr,
    pub spool_path: PathBuf,
    pub container: String,
}

impl LogRelayConfig {
    pub fn from_env_defaults() -> io::Result<Self> {
        Ok(Self {
            bind: require_loopback_bind(
                &std::env::var("ENCLAVA_LOG_RELAY_BIND")
                    .unwrap_or_else(|_| DEFAULT_BIND.to_string()),
            )?,
            spool_path: require_spool_under_log_dir(
                &std::env::var_os("ENCLAVA_LOG_RELAY_SPOOL_PATH")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL_PATH)),
            )?,
            container: std::env::var("ENCLAVA_LOG_RELAY_CONTAINER")
                .unwrap_or_else(|_| DEFAULT_CONTAINER.to_string()),
        })
    }

    pub fn from_env_optional() -> io::Result<Option<Self>> {
        if std::env::var_os("ENCLAVA_LOG_RELAY_SPOOL_PATH").is_none() {
            return Ok(None);
        }
        Some(Self::from_env_defaults()).transpose()
    }
}

/// The relay serves unauthenticated tenant log tails, so only a loopback
/// bind is ever allowed. A host-controlled `ENCLAVA_LOG_RELAY_BIND` pointing
/// off-loopback (including wildcard 0.0.0.0/::) must fail closed instead of
/// exposing the relay pod-wide.
///
/// Resolves the bind string once and returns the validated `SocketAddr`:
/// callers bind that exact address. Returning the original string (and
/// letting `TcpListener::bind` resolve it again) would let a host
/// controlling DNS answer validation with a loopback address and binding
/// with a pod-reachable one (TOCTOU re-resolution).
fn require_loopback_bind(bind: &str) -> io::Result<std::net::SocketAddr> {
    use std::net::ToSocketAddrs;
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("log relay bind {bind:?} must be loopback"),
        )
    };
    let addr = bind
        .to_socket_addrs()
        .map_err(|_| invalid())?
        .next()
        .ok_or_else(invalid)?;
    match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_loopback() => Ok(addr),
        std::net::IpAddr::V6(ip) if ip.is_loopback() => Ok(addr),
        _ => Err(invalid()),
    }
}

/// The relay spool must live directly under the dedicated log spool
/// directory (`/run/enclava-logs`, a k8s volume mount that is a real
/// directory in the guest). `O_NOFOLLOW` only rejects a symlinked final
/// component; a host-controlled `ENCLAVA_LOG_RELAY_SPOOL_PATH` pointing
/// directly at some other regular sensitive file (for example a mounted
/// TLS key) would otherwise be streamed through the unauthenticated
/// relay endpoint. Fail closed on any path that is not an absolute
/// `<log-spool-dir>/<single-component>` path.
fn require_spool_under_log_dir(path: &Path) -> io::Result<PathBuf> {
    use std::path::Component;
    let spool_dir = Path::new(SPOOL_DIR);
    let invalid = |reason: &str| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("log relay spool {path:?} must live directly under {SPOOL_DIR}: {reason}"),
        )
    };
    if !path.is_absolute() {
        return Err(invalid("must be an absolute path"));
    }
    if path
        .components()
        .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid(
            "must not contain traversal or CurDir/ParentDir components",
        ));
    }
    if path.parent() != Some(spool_dir) {
        return Err(invalid("parent directory must be the log spool dir"));
    }
    Ok(path.to_path_buf())
}

pub fn run_from_env() -> io::Result<()> {
    run(LogRelayConfig::from_env_defaults()?)
}

pub fn spawn(config: LogRelayConfig) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(config.bind)?;
    eprintln!("enclava-log-relay: listening on {}", config.bind);
    Ok(thread::spawn(move || serve(listener, config)))
}

pub fn run(config: LogRelayConfig) -> io::Result<()> {
    let listener = TcpListener::bind(config.bind)?;
    eprintln!("enclava-log-relay: listening on {}", config.bind);
    serve(listener, config);
    Ok(())
}

fn serve(listener: TcpListener, config: LogRelayConfig) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let spool_path = config.spool_path.clone();
                let container = config.container.clone();
                thread::spawn(move || {
                    if let Err(err) =
                        handle_connection(stream, &spool_path, &container, FOLLOW_IO_TIMEOUT)
                    {
                        eprintln!("enclava-log-relay: request failed: {err}");
                    }
                });
            }
            Err(err) => eprintln!("enclava-log-relay: accept failed: {err}"),
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    spool_path: &Path,
    container: &str,
    io_timeout: Duration,
) -> io::Result<()> {
    // Bound every blocking socket operation on this connection. Follow
    // streams are long-lived, and the follower KEEPS the adopted spool
    // handle open across rotation resyncs: a client that stops reading
    // would otherwise block `write_all` forever while pinning unlinked
    // rotated inodes (~32 MiB each, retained by the rotation design).
    // SO_SNDTIMEO turns that indefinite block into a WouldBlock/TimedOut
    // error that unwinds the handler, drops the held inode, and frees the
    // thread. The read timeout bounds `read_request_head`: a client that
    // connects and never sends its request would otherwise pin the thread
    // forever. Follow polling is strictly write-driven once the head
    // arrives, so neither timeout fires for a healthy client.
    stream.set_write_timeout(Some(io_timeout))?;
    stream.set_read_timeout(Some(io_timeout))?;
    let request = read_request_head(&mut stream)?;
    let Some((method, uri)) = request_line(&request) else {
        return write_json_error(&mut stream, 400, "bad_request");
    };
    if method != "GET" {
        return write_json_error(&mut stream, 405, "method_not_allowed");
    }
    let (path, query) = split_uri(uri);
    if path == "/health" {
        return write_response_head(&mut stream, 200, "text/plain", Some(2))
            .and_then(|_| stream.write_all(b"ok"));
    }
    if path != "/.well-known/confidential/logs" {
        return write_json_error(&mut stream, 404, "not_found");
    }
    let query = LogRelayQuery::parse(query);
    if let Some(requested) = query.container.as_deref()
        && requested != container
    {
        return write_json_error(&mut stream, 404, "container_not_available");
    }
    let (lines, mut offset, spool_file) = match tail_lines(spool_path, query.tail_lines) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return write_json_error(&mut stream, 409, "logs_not_ready");
        }
        Err(err) => return Err(err),
    };
    // Release the tail handle BEFORE any client write (round-10 review P1):
    // the writes below can block for up to FOLLOW_IO_TIMEOUT on a client
    // that stops reading — follow or not — and a rotation landing in that
    // window unlinks the inode this fd pins (~32 MiB). Staggered stalled
    // clients could otherwise pin successive rotation generations past the
    // 64 MiB emptyDir cap, exactly the hazard the rotation-resync path
    // already guards against inside follow_spool. For followers, SEED the
    // follow anchor from the tail cursor first (round-15 review P2) so the
    // tail's inode identity and boundary fingerprint survive the drop.
    let follow_anchor = if query.follow {
        Some(anchor_from_file(&spool_file, offset)?)
    } else {
        None
    };
    drop(spool_file);
    write_response_head(&mut stream, 200, "application/x-ndjson", None)?;
    let mut delivered = DeliveredSequences::new();
    for line in &lines {
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        remember_delivered_line(line.as_bytes(), &mut delivered);
    }
    stream.flush()?;
    if query.follow {
        // Release the tail BUFFER before entering follow mode (round-12
        // review P1): `lines` can carry up to MAX_TAIL_BYTES (2 MiB) of
        // decoded frames per connection; leaving it borrowed here would
        // keep the entire initial tail alive in `handle_connection` for
        // the whole unbounded follow session. The ingress template
        // exposes this endpoint directly, so a few hundred idle followers
        // could retain hundreds of MiB inside enclava-init (512 MiB
        // memory limit) and OOM-kill the privileged sidecar. Everything
        // follow_spool needs (`offset`, `last_seq`) is an extracted copy.
        drop(lines);
        // `delivered` was seeded while streaming the initial tail above,
        // and `held` carries the SEEDED tail anchor (round-15 review P2):
        // the first poll's probe passes on the unchanged inode and the
        // follower continues exactly AT the tail cursor, so `follow=true`
        // streams only what is new — never a replay of the older complete
        // frames the requested tail left out (the held-less entry of
        // round-10 rescanned from offset 0 and could replay the whole
        // spool after the initial 100 lines). The anchor still holds NO
        // descriptor (the tail fd was dropped before the writes above),
        // and rotation safety is unchanged: a swap landing anywhere from
        // the tail read onward fails the identity/fingerprint probe and
        // takes the genuine resync path, where offsets are re-derived
        // against the CURRENT inode and only the delivered set is trusted
        // — which is also correct when a rotation lands mid-tail-write.
        let mut held = follow_anchor;
        follow_spool(&mut stream, spool_path, &mut offset, &mut held, delivered)?;
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct LogRelayQuery {
    follow: bool,
    tail_lines: usize,
    container: Option<String>,
}

impl LogRelayQuery {
    fn parse(query: Option<&str>) -> Self {
        let mut parsed = Self {
            follow: false,
            tail_lines: DEFAULT_TAIL_LINES,
            container: None,
        };
        let Some(query) = query else {
            return parsed;
        };
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            match key {
                "follow" => parsed.follow = value == "true",
                "tail_lines" => {
                    if let Ok(value) = value.parse::<usize>() {
                        parsed.tail_lines = value.clamp(1, MAX_TAIL_LINES);
                    }
                }
                "container" if !value.is_empty() => parsed.container = Some(value.to_string()),
                _ => {}
            }
        }
        parsed
    }
}

/// Identity of the spool file being followed: `enclava-wait-exec` rotates
/// the spool by atomic rename (new inode), so a follower must detect the
/// swap, not just length regression — a truncate-and-regrow within one
/// poll window would otherwise silently desynchronize the byte stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SpoolIdentity {
    dev: u64,
    ino: u64,
}

fn spool_identity(file: &File) -> io::Result<SpoolIdentity> {
    let metadata = file.metadata()?;
    Ok(SpoolIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// Minimal sequence probe for an encrypted log frame line. Only the
/// plaintext envelope fields are inspected; the ciphertext stays opaque
/// to the relay.
fn frame_sequence(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("sequence")?
        .as_u64()
}

/// Cap on the per-follower delivered-sequence set. Rotation retains the
/// last LOG_SPOOL_KEEP_BYTES (8 MiB) of frames and real encrypted frames
/// are hundreds of bytes, so a retained window holds at most a few tens
/// of thousands of frames — this cap covers it with >2x margin. The set
/// grows lazily with frames actually delivered, so an idle follower that
/// received little holds a near-empty one.
const DELIVERED_SET_CAP: usize = 65_536;

/// Sequences already SENT to this follower (round-14 self-check
/// Critical): rotation dedup is SET MEMBERSHIP, not a `<= last_seq`
/// frontier. The spool directory is workload-writable, so any line's
/// `sequence` field is attacker-controlled — the old frontier latched
/// from a single forged `{"sequence":u64::MAX}` line and permanently
/// suppressed every later legitimate frame for that client (and for
/// every NEW follower, whose held=None resync re-read the poison from
/// offset 0). Membership is poison-resistant: a forged line occupies
/// only its own sequence slot; every other sequence still delivers.
/// Documented residual: the workload can pre-burn sequence numbers it
/// predicts (the writer's counter is monotonic), suppressing future
/// frames of its OWN workload carrying those exact numbers — one forged
/// line can no longer suppress the whole stream, and no other
/// workload's spool is affected.
/// Bounded: past DELIVERED_SET_CAP the oldest-inserted sequences are
/// evicted (FIFO). Only a deliberately poisoned spool (millions of
/// forged micro-frames) can reach the cap, and the cost is replaying
/// some duplicate lines to that one client — bounded per-follower
/// memory is the harder guarantee (round-13 P1).
#[derive(Debug)]
struct DeliveredSequences {
    set: std::collections::HashSet<u64>,
    insertion_order: std::collections::VecDeque<u64>,
}

impl DeliveredSequences {
    fn new() -> Self {
        Self {
            set: std::collections::HashSet::new(),
            insertion_order: std::collections::VecDeque::new(),
        }
    }

    fn contains(&self, sequence: u64) -> bool {
        self.set.contains(&sequence)
    }

    fn insert(&mut self, sequence: u64) {
        if self.set.insert(sequence) {
            self.insertion_order.push_back(sequence);
            if self.set.len() > DELIVERED_SET_CAP {
                if let Some(evicted) = self.insertion_order.pop_front() {
                    self.set.remove(&evicted);
                }
            }
        }
    }
}

/// Remember the sequences of every complete line sent to the client, so a
/// post-rotation resync can skip retained-window replays. Sequences come
/// from spool content — attacker-influenced — which is exactly why dedup
/// is set membership over what this client was actually sent, never a
/// max-frontier (see `DeliveredSequences`).
fn remember_delivered_line(bytes: &[u8], delivered: &mut DeliveredSequences) {
    if let Some(sequence) = frame_sequence(&String::from_utf8_lossy(bytes)) {
        delivered.insert(sequence);
    }
}

/// Open the spool for reading without following a final-component symlink
/// and without accepting anything but a regular file. The spool directory
/// is group-writable by the workload, so a compromised workload could
/// otherwise point the relay (root) at init-only state and have it streamed
/// out as "logs". Returns NotFound on a symlink so the follow loop's
/// existing `else { continue; }` path simply retries until the spool is a
/// real file again.
fn open_spool_for_read(path: &Path) -> io::Result<File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|e| {
            // ELOOP (40) is what O_NOFOLLOW returns for a final-component
            // symlink; normalize it to NotFound so the follow loop's existing
            // `else { continue; }` path treats a planted symlink exactly like
            // a missing spool (retry until it is a real file again).
            // ErrorKind::FilesystemLoop is still unstable (io_error_more),
            // so match the raw errno.
            if e.raw_os_error() == Some(40) {
                io::Error::new(io::ErrorKind::NotFound, e.to_string())
            } else {
                e
            }
        })?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "spool is not a regular file",
        ));
    }
    Ok(file)
}

fn tail_lines(path: &Path, count: usize) -> io::Result<(Vec<String>, u64, File)> {
    let mut file = open_spool_for_read(path)?;
    let len = file.metadata()?.len();
    let start = len.saturating_sub(MAX_TAIL_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    // A trailing segment without a newline is an in-flight frame (writer
    // mid-append): never emit it as a line. Drop it from the tail and point
    // the follow offset at its first byte so the follow loop completes it
    // once the writer finishes the append.
    let complete_len = match bytes.iter().rposition(|&b| b == b'\n') {
        Some(idx) => idx + 1,
        None => 0,
    };
    let follow_from = start + complete_len as u64;
    let text = String::from_utf8_lossy(&bytes[..complete_len]);
    let text = if start > 0 {
        text.split_once('\n').map(|(_, rest)| rest).unwrap_or("")
    } else {
        text.as_ref()
    };
    let mut lines = text
        .lines()
        .rev()
        .take(count)
        .map(str::to_string)
        .collect::<Vec<_>>();
    lines.reverse();
    // The File handle is returned (rather than dropped here) so callers
    // control its lifetime explicitly: handle_connection drops it BEFORE
    // any client write so a stalled client cannot pin the tail inode
    // across a rotation (the follow loop re-adopts a handle itself).
    Ok((lines, follow_from, file))
}

/// Anchor for rotation detection that does NOT require holding a spool fd
/// across (potentially blocking) client writes. `identity` is the dev/ino of
/// the inode the follower's `offset` was computed against, plus a content
/// FINGERPRINT of up to 16 bytes around the delivered boundary. Holding an
/// open fd was the old rotation signal — while pinned, the filesystem
/// cannot recycle the inode number — but a stalled client can block a socket
/// write for up to FOLLOW_IO_TIMEOUT and every open fd keeps an unlinked
/// ~32 MiB rotation generation alive against the 64 MiB emptyDir cap.
///
/// The anchor trades the fd's non-recycling guarantee for a fingerprint
/// probe: two rotations inside one blocked client write CAN numerically
/// recycle the old inode onto the spool path again, but the recycled file
/// would have to reproduce 16 bytes of encrypted-frame ciphertext at the
/// exact delivered boundary to pass — 2^-128 for high-entropy frames, and
/// deterministic mismatch for any rewritten tail. (A one-byte probe does
/// NOT suffice: both anchor sites park the offset on a newline, so a
/// single '\n' comparison is nearly always a vacuous pass — the round-11
/// self-check Critical.) The only fingerprint-less anchor is a resync of a
/// completely EMPTY spool (nothing delivered from that generation), where
/// the probe degenerates to identity-only; documented residual, since no
/// boundary bytes exist to fingerprint and normal appends must be followed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FollowAnchor {
    identity: SpoolIdentity,
    /// Absolute file position of the fingerprint window.
    fp_pos: u64,
    /// Length of the valid prefix of `fingerprint` (0 = empty-anchor).
    fp_len: u8,
    fingerprint: [u8; ANCHOR_FINGERPRINT_BYTES],
}

/// Size of the anchor's content fingerprint window.
const ANCHOR_FINGERPRINT_BYTES: usize = 16;

/// Build an anchor for `identity` from the file contents `bytes` (read from
/// offset 0) with the follower's delivered boundary at `boundary` (bytes
/// before it are confirmed delivered; bytes after are not). The fingerprint
/// window is the up-to-16 bytes ending at the boundary; for a boundary of 0
/// (nothing delivered yet — an empty or fragment-only file) it is the head
/// of the file instead, which is equally stable under append-only growth.
// Test-only helper: production follow state is built inline by
// `plan_delivery` from the plan's fingerprint fields.
#[cfg(test)]
fn anchor_for(bytes: &[u8], boundary: usize, identity: SpoolIdentity) -> FollowAnchor {
    let window: &[u8] = if boundary >= ANCHOR_FINGERPRINT_BYTES {
        &bytes[boundary - ANCHOR_FINGERPRINT_BYTES..boundary]
    } else if boundary > 0 {
        &bytes[..boundary]
    } else {
        &bytes[..bytes.len().min(ANCHOR_FINGERPRINT_BYTES)]
    };
    let mut fingerprint = [0u8; ANCHOR_FINGERPRINT_BYTES];
    fingerprint[..window.len()].copy_from_slice(window);
    // Branch 3 (boundary 0, head-of-file window) parks at position 0; the
    // other branches always have boundary >= window.len().
    FollowAnchor {
        identity,
        fp_pos: boundary.saturating_sub(window.len()) as u64,
        fp_len: window.len() as u8,
        fingerprint,
    }
}

/// Probe the current file for the anchor's fingerprint window. A shorter
/// read (EOF inside the window — truncation or a shorter recycled file) is
/// a mismatch.
fn probe_matches(file: &mut File, anchor: &FollowAnchor) -> io::Result<bool> {
    let len = anchor.fp_len as usize;
    let mut buf = [0u8; ANCHOR_FINGERPRINT_BYTES];
    let n = file.read_at(&mut buf[..len], anchor.fp_pos)?;
    Ok(n == len && buf[..n] == anchor.fingerprint[..len])
}

/// Build a follow anchor for a delivered boundary directly from the
/// (still-open) spool file: the inode identity the boundary was computed
/// against plus the exact fingerprint window `plan_delivery` maintains —
/// the up-to-16 bytes ENDING at the boundary, or the head of the file for
/// a boundary of 0 (matching `anchor_for`; a short read just yields a
/// shorter window, which the next probe treats as a mismatch if the bytes
/// changed).
///
/// This SEEDS a follower's first poll (round-15 review P2): the tail
/// cursor computed by `tail_lines` must survive into follow mode, or the
/// held-less first poll rescans from offset 0 and `plan_delivery` streams
/// every older complete frame the requested tail left out — `follow=true`
/// would replay up to the whole spool instead of following after its
/// tail. With a seeded anchor the no-rotation startup continues exactly
/// at the cursor. Rotation safety is unchanged: a swap landing between
/// the tail read and the first poll fails the identity/fingerprint probe
/// and funnels into the genuine resync path, where the cursor is never
/// trusted against replaced content.
fn anchor_from_file(file: &File, boundary: u64) -> io::Result<FollowAnchor> {
    let identity = spool_identity(file)?;
    let mut fingerprint = [0u8; ANCHOR_FINGERPRINT_BYTES];
    let (fp_pos, fp_len) = if boundary > 0 {
        let len = boundary.min(ANCHOR_FINGERPRINT_BYTES as u64) as usize;
        let pos = boundary - len as u64;
        let mut n = 0;
        while n < len {
            let read = file.read_at(&mut fingerprint[n..len], pos + n as u64)?;
            if read == 0 {
                break;
            }
            n += read;
        }
        (pos, n)
    } else {
        let mut n = 0;
        while n < ANCHOR_FINGERPRINT_BYTES {
            let read = file.read_at(&mut fingerprint[n..], n as u64)?;
            if read == 0 {
                break;
            }
            n += read;
        }
        (0, n)
    };
    Ok(FollowAnchor {
        identity,
        fp_pos,
        fp_len: fp_len as u8,
        fingerprint,
    })
}

fn follow_spool<W: Write>(
    stream: &mut W,
    path: &Path,
    offset: &mut u64,
    held: &mut Option<FollowAnchor>,
    initial_delivered: DeliveredSequences,
) -> io::Result<()> {
    // Sequences already SENT to this client. On rotation the spool is
    // replaced by a new inode whose retained window re-contains frames
    // the client already received; byte offsets do not survive the
    // rewrite, so the follower skips retained frames whose sequence is
    // IN THIS SET. Dedup is set membership over what this client was
    // actually sent — NOT a `<= last_seq` frontier: the spool directory
    // is workload-writable, so a `sequence` field is attacker-controlled
    // and a frontier latched from one forged
    // `{"sequence":18446744073709551615}` line would permanently
    // suppress every later legitimate frame (round-14 self-check
    // Critical). Membership poisoning costs only the forged slot.
    // Unparseable lines are passed through unchanged (historical
    // behavior for anything not a frame).
    let mut delivered = initial_delivered;
    loop {
        thread::sleep(FOLLOW_POLL_INTERVAL);
        // The spool fd is opened fresh each poll and dropped before ANY
        // client write below: no descriptor survives across blocking socket
        // I/O, so a stalled client cannot pin a rotation generation for the
        // FOLLOW_IO_TIMEOUT window (round-11 review P1). Rotation is
        // detected from the remembered FollowAnchor instead.
        let Ok(mut file) = open_spool_for_read(path) else {
            continue;
        };
        let current_identity = spool_identity(&file)?;
        let len = file.metadata()?.len();
        // Same-inode check: remembered identity PLUS a content-fingerprint
        // probe of the delivered boundary. This catches everything the old
        // held-fd comparison caught (atomic-rename rotations change the
        // inode) and the residual hazard of a numerically recycled inode:
        // a rewritten file at the same (dev,ino) no longer reproduces the
        // 16 ciphertext bytes at the follower's delivered boundary.
        // `len < offset` (the writer's rollback truncation, or a shorter
        // recycled file) also fails the probe and funnels into the same
        // resync path.
        let same_as_held = match held.as_ref() {
            Some(anchor) if anchor.identity == current_identity => {
                probe_matches(&mut file, anchor)?
            }
            _ => false,
        };
        // Re-derive the follow state against the CURRENT file on every
        // poll that has work to do — from offset 0 when the anchor's
        // probe failed (rotation via atomic rename, the writer's rollback
        // truncation, or a replaced/recycled inode: never seek a stale
        // byte offset into rewritten content) or from the delivered
        // boundary on a same-inode append. Idle followers (nothing past
        // the delivered boundary) skip the scan entirely.
        //
        // Round-13 review P1: BOTH paths use the same STREAMING planner
        // with a bounded send buffer (~MAX_TAIL_BYTES) instead of
        // buffering the whole spool / whole undelivered tail in a
        // per-follower Vec — the ingress template exposes this endpoint
        // directly, and ~16 synchronized followers could allocate past
        // enclava-init's 512 MiB limit and OOM the privileged sidecar. A
        // catch-up larger than the bound is delivered in bounded quanta
        // across polls: the scan stops before the next never-delivered
        // line and the next poll resumes exactly there — nothing dropped,
        // nothing replayed.
        if same_as_held && len == *offset {
            continue;
        }
        let from = if same_as_held { *offset } else { 0 };
        let plan = plan_delivery(&mut file, from, &mut delivered)?;
        // Resume at the END OF THE LAST ACCOUNTED LINE (plan.offset): an
        // in-flight trailing fragment (writer mid-append) or a
        // budget-stopped line is withheld from the client, so the next
        // poll re-reads it from its first byte and delivers it whole.
        *offset = plan.offset;
        // Anchor the delivered boundary and drop the spool fd BEFORE the
        // (potentially blocking) client write + flush: a stalled client
        // can block write_all for up to FOLLOW_IO_TIMEOUT — during that
        // window no fd may pin an unlinked previous generation (~32 MiB
        // against the emptyDir cap). The anchor carries no descriptor.
        *held = Some(FollowAnchor {
            identity: current_identity,
            fp_pos: plan.fp_pos,
            fp_len: plan.fp_len,
            fingerprint: plan.fingerprint,
        });
        drop(file);
        if !plan.out.is_empty() {
            stream.write_all(&plan.out)?;
        }
        stream.flush()?;
    }
}

/// Bounded streaming delivery plan (round-13 review P1): scan the spool
/// from `from` line-by-line with a bounded reader and collect whole frames
/// whose sequence is NOT in the `delivered` set (sequences this client
/// was actually sent) into a send buffer that
/// never outgrows `MAX_TAIL_BYTES` (a single line is always kept whole —
/// the bounded scan caps lines at `MAX_TAIL_BYTES` + 1). When the buffer
/// is full the scan STOPS before the next never-delivered line: the
/// remaining catch-up is delivered by later polls in bounded quanta, with
/// NOTHING dropped and NOTHING replayed — the pipeline contract is "same
/// stream, consecutive sequence numbers, order preserved, no data
/// dropped", so a drop-oldest variant (loss for latency, client-visible
/// sequence gaps) is not acceptable here. Both follow branches plan
/// through this one function: the rotation-resync branch scans from 0
/// with sequence dedup, the same-inode append branch from the delivered
/// boundary (dedup is then a no-op by writer sequence monotonicity and
/// doubles as defense in depth against a rewritten tail).
///
/// Memory per follower is bounded (~MAX_TAIL_BYTES of send buffer plus
/// one line of scan state): previously the resync buffered the ENTIRE
/// spool and the append branch everything past the delivered boundary in
/// a per-follower Vec — the ingress template exposes this endpoint
/// directly, so ~16 synchronized followers could allocate past
/// enclava-init's 512 MiB limit and OOM the privileged sidecar (round-13
/// review P1). The scan itself is bounded too: a "line" longer than
/// `MAX_TAIL_BYTES` cannot be a writer-produced frame (records are capped
/// at `MAX_LOG_RECORD_BYTES`) and the spool directory is
/// workload-writable, so oversized lines are consumed and DISCARDED
/// without ever being buffered whole. Blank lines cannot be
/// writer-produced frames either and are dropped. A trailing segment
/// without a newline is an in-flight frame (writer mid-append) and is NOT
/// forwarded: the completed frame is re-read whole from this inode on the
/// next poll. (≤ `MAX_TAIL_BYTES`-long) lines that do not parse as frames
/// are forwarded unchanged (historical pass-through). `offset` ends at
/// the last ACCOUNTED-FOR line (delivered, dedup-skipped, or discarded) —
/// never past an undelivered line or an in-flight fragment — and the
/// fingerprint anchors that boundary for the next poll's same-inode
/// probe.
struct DeliveryPlan {
    out: Vec<u8>,
    offset: u64,
    fp_pos: u64,
    fp_len: u8,
    fingerprint: [u8; ANCHOR_FINGERPRINT_BYTES],
}

fn plan_delivery(
    file: &mut File,
    from: u64,
    delivered: &mut DeliveredSequences,
) -> io::Result<DeliveryPlan> {
    file.seek(SeekFrom::Start(from))?;
    let cap = MAX_TAIL_BYTES as usize;
    let mut out: Vec<u8> = Vec::new();
    // File position of the end of the last accounted-for line.
    let mut scanned_end = from;
    {
        let mut reader = BufReader::with_capacity(64 * 1024, &mut *file);
        let mut line: Vec<u8> = Vec::new();
        loop {
            line.clear();
            // Bounded per-line scan: spool lines are writer-capped frames
            // (records are capped at MAX_LOG_RECORD_BYTES in
            // enclava-wait-exec, far below MAX_TAIL_BYTES), so a "line"
            // claiming more than MAX_TAIL_BYTES cannot be a
            // writer-produced frame — and the spool directory is
            // workload-writable, so a hostile mega-line must not be
            // buffered whole per follower either (that would re-open the
            // exact multi-follower OOM this function closes). The take
            // cap is one past MAX_TAIL_BYTES so a frame of exactly
            // MAX_TAIL_BYTES content bytes plus its newline stays
            // in-bounds.
            let n = reader
                .by_ref()
                .take(MAX_TAIL_BYTES + 1)
                .read_until(b'\n', &mut line)?;
            if n == 0 {
                break;
            }
            if !line.ends_with(b"\n") {
                if (n as u64) < MAX_TAIL_BYTES + 1 {
                    // In-flight trailing fragment (writer mid-append):
                    // withhold it — do not emit, do not advance the
                    // boundary past its first byte. The completed frame is
                    // re-read whole on the next poll.
                    break;
                }
                // Oversized line (the bounded read filled without ever
                // seeing a newline): consume-and-discard the rest of it
                // WITHOUT buffering — never split it into the send
                // stream, since it is not a writer-produced frame. The
                // boundary advances past it only once its newline arrives
                // (below), so a still-growing mega-line stays an
                // in-flight fragment and is re-scanned whole next poll.
                let mut skipped: u64 = 0;
                let mut terminated = false;
                while !terminated {
                    let available = reader.fill_buf()?;
                    if available.is_empty() {
                        break;
                    }
                    match available.iter().position(|&b| b == b'\n') {
                        Some(i) => {
                            reader.consume(i + 1);
                            skipped += (i + 1) as u64;
                            terminated = true;
                        }
                        None => {
                            let m = available.len();
                            reader.consume(m);
                            skipped += m as u64;
                        }
                    }
                }
                if !terminated {
                    // EOF mid-mega-line: the whole segment is an
                    // in-flight fragment — withhold it like any other.
                    break;
                }
                scanned_end += n as u64 + skipped;
                continue;
            }
            // Complete line INCLUDING its terminating newline.
            let content = &line[..line.len() - 1];
            if !content.is_empty() {
                let text = String::from_utf8_lossy(content);
                let sequence = frame_sequence(&text);
                if sequence.is_some_and(|sequence| delivered.contains(sequence)) {
                    // Already delivered to THIS client (rotation replay):
                    // skip WITHOUT consuming send budget — membership is
                    // unchanged but the boundary advances past the replay.
                    // Membership — not a `<= frontier` — so a forged
                    // sequence can only suppress its own slot
                    // (round-14 self-check Critical).
                    scanned_end += n as u64;
                    continue;
                }
                // Bounded send buffer (round-13 P1): stop BEFORE this
                // never-delivered line once it would not fit — the next
                // poll delivers it whole (the first line always fits: the
                // scan caps lines at MAX_TAIL_BYTES + 1, so every poll
                // makes progress). Frames are never split across quanta
                // and never dropped.
                if !out.is_empty() && out.len() + n > cap {
                    break;
                }
                if let Some(sequence) = sequence {
                    delivered.insert(sequence);
                }
                out.extend_from_slice(content);
                out.push(b'\n');
            }
            // Blank lines cannot be writer-produced frames: dropped from
            // the send stream, but the boundary still advances past them.
            scanned_end += n as u64;
        }
    }
    let mut plan = DeliveryPlan {
        out,
        offset: scanned_end,
        fp_pos: 0,
        fp_len: 0,
        fingerprint: [0u8; ANCHOR_FINGERPRINT_BYTES],
    };
    // Fingerprint the delivered boundary directly from the file (the same
    // construction `anchor_for` documents): the 16 bytes ENDING at the
    // boundary, so the next poll's probe catches a rewritten file at a
    // recycled inode number. For a boundary of 0 (empty or fragment-only
    // file) fingerprint the HEAD of the file instead — it is equally
    // stable under append-only growth (the fragment completes by
    // appending past it), matching `anchor_for` exactly; only a completely
    // EMPTY spool has no bytes to fingerprint (identity-only residual).
    let boundary = plan.offset as usize;
    let fp_start = boundary.saturating_sub(ANCHOR_FINGERPRINT_BYTES);
    if boundary > fp_start {
        let mut window = [0u8; ANCHOR_FINGERPRINT_BYTES];
        file.seek(SeekFrom::Start(fp_start as u64))?;
        file.read_exact(&mut window[..boundary - fp_start])?;
        plan.fingerprint[..boundary - fp_start].copy_from_slice(&window[..boundary - fp_start]);
        plan.fp_pos = fp_start as u64;
        plan.fp_len = (boundary - fp_start) as u8;
    } else {
        file.seek(SeekFrom::Start(0))?;
        let mut n = 0usize;
        while n < ANCHOR_FINGERPRINT_BYTES {
            let read = file.read(&mut plan.fingerprint[n..])?;
            if read == 0 {
                break;
            }
            n += read;
        }
        plan.fp_pos = 0;
        plan.fp_len = n as u8;
    }
    Ok(plan)
}

fn read_request_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while buf.len() < 16 * 1024 {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn request_line(request: &str) -> Option<(&str, &str)> {
    let line = request.lines().next()?;
    let mut parts = line.split_whitespace();
    Some((parts.next()?, parts.next()?))
}

fn split_uri(uri: &str) -> (&str, Option<&str>) {
    match uri.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (uri, None),
    }
}

fn write_json_error(stream: &mut TcpStream, status: u16, code: &str) -> io::Result<()> {
    let body = format!(r#"{{"code":"{code}","error":"{code}"}}"#);
    write_response_head(stream, status, "application/json", Some(body.len()))?;
    stream.write_all(body.as_bytes())
}

fn write_response_head(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    content_length: Option<usize>,
) -> io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\ncontent-type: {content_type}\r\ncache-control: no-store\r\npragma: no-cache\r\nconnection: close\r\n"
    )?;
    if let Some(len) = content_length {
        write!(stream, "content-length: {len}\r\n")?;
    }
    stream.write_all(b"\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: a DeliveredSequences seeded with the given sequences.
    fn delivered_of(seqs: &[u64]) -> DeliveredSequences {
        let mut d = DeliveredSequences::new();
        for s in seqs {
            d.insert(*s);
        }
        d
    }

    #[test]
    fn frame_sequence_reads_plain_envelope_field() {
        let line = r#"{"version":"enclava-log-frame-v1","sequence":42,"stream":"stdout"}"#;
        assert_eq!(frame_sequence(line), Some(42));
        assert_eq!(frame_sequence("not json"), None);
        assert_eq!(frame_sequence(r#"{"sequence":"x"}"#), None);
    }

    /// Round-14 self-check Critical: the spool directory is
    /// workload-writable, so a `sequence` field is attacker-controlled.
    /// The OLD dedup kept a `<= last_seq` frontier: one forged
    /// `{"sequence":u64::MAX}` line latched the frontier and permanently
    /// suppressed every later legitimate frame for that client — and for
    /// every NEW follower, whose held=None resync re-read the poison from
    /// offset 0. Set-membership dedup must be immune: the forged line
    /// occupies only its own slot and every legit sequence still
    /// delivers.
    #[test]
    fn forged_max_sequence_does_not_suppress_later_frames() {
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(frame(7).as_bytes());
        bytes.push(b'\n');
        // The poison: a workload-written line claiming u64::MAX.
        bytes.extend_from_slice(frame(u64::MAX).as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(frame(8).as_bytes());
        bytes.push(b'\n');
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[7]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        let sent = String::from_utf8(plan.out.clone()).unwrap();
        assert_eq!(
            sent,
            format!("{}\n{}\n", frame(u64::MAX), frame(8)),
            "the forged line itself is forwarded (pass-through), and frame 8 \
             is NOT suppressed by the forged sequence"
        );
        assert!(delivered.contains(8));
    }

    /// Round-14 self-check Critical (new-client variant): a brand-new
    /// follower (empty delivered set, held=None resync from offset 0)
    /// must not be blinded by a forged high sequence either.
    #[test]
    fn forged_max_sequence_does_not_blind_new_followers() {
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(frame(u64::MAX).as_bytes());
        bytes.push(b'\n');
        bytes.extend_from_slice(frame(1).as_bytes());
        bytes.push(b'\n');
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = DeliveredSequences::new();
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        let sent = String::from_utf8(plan.out.clone()).unwrap();
        assert_eq!(
            sent,
            format!("{}\n{}\n", frame(u64::MAX), frame(1)),
            "a new follower receives both lines: the poison suppresses nothing"
        );
    }

    /// The delivered set is bounded: past DELIVERED_SET_CAP the
    /// oldest-inserted sequences are evicted. Only reachable with a
    /// deliberately poisoned spool; the cost is duplicate replay to that
    /// one client, never unbounded memory.
    #[test]
    fn delivered_sequences_set_is_bounded() {
        let mut delivered = DeliveredSequences::new();
        for seq in 0..DELIVERED_SET_CAP as u64 {
            delivered.insert(seq);
        }
        assert!(delivered.contains(0));
        assert!(delivered.contains(DELIVERED_SET_CAP as u64 - 1));
        delivered.insert(DELIVERED_SET_CAP as u64);
        assert!(
            delivered.contains(DELIVERED_SET_CAP as u64),
            "new insert lands"
        );
        assert!(
            !delivered.contains(0),
            "oldest-inserted sequence was evicted"
        );
        assert!(delivered.contains(1));
    }

    /// Round-5 review finding: after a rotation resync, the retained window
    /// re-contains frames the follower already received. The resync re-send
    /// must drop those by sequence number instead of replaying them, and
    /// must forward newer frames exactly once. (Round-13: re-targeted at
    /// the streaming `plan_delivery`, which must preserve the exact dedup
    /// semantics of the old whole-buffer implementation.)
    #[test]
    fn rotation_resync_dedups_already_delivered_sequences() {
        // Follower already received sequences 1-3; the current file
        // retains 2-4 plus two new frames (5, 6) appended after the swap.
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = Vec::new();
        for seq in [2u64, 3, 4, 5, 6] {
            bytes.extend_from_slice(frame(seq).as_bytes());
            bytes.push(b'\n');
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[1, 2, 3]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        let sent = String::from_utf8(plan.out.clone()).unwrap();
        assert_eq!(
            sent,
            format!("{}\n{}\n{}\n", frame(4), frame(5), frame(6)),
            "sequences <= 3 must be dropped, 4-6 forwarded once each"
        );
        assert!(
            delivered.contains(6),
            "sequence 6 must be in the delivered set"
        );
        // Offset ends at the last accounted-for line (skipped replays
        // advance it too — they are never re-scanned).
        assert_eq!(plan.offset, bytes.len() as u64);
        // Fingerprint anchors that boundary: the last 16 bytes of the file.
        let fp_len = plan.fp_len as usize;
        assert_eq!(plan.fp_pos + plan.fp_len as u64, plan.offset);
        assert_eq!(plan.fingerprint[..fp_len], bytes[bytes.len() - fp_len..]);
    }

    /// An in-flight trailing fragment (writer mid-append) must NOT be
    /// forwarded during a resync: emitting a partial NDJSON line risks
    /// the client concatenating it with the next complete frame. The
    /// completed frame is re-delivered whole on the next poll.
    #[test]
    fn rotation_resync_drops_incomplete_tail() {
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = format!("{}\n", frame(7)).into_bytes();
        bytes.extend_from_slice(b"{\"version\":\"enclava-log-fra"); // partial
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[6]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        let sent = String::from_utf8(plan.out.clone()).unwrap();
        assert_eq!(sent, format!("{}\n", frame(7)));
        // The partial tail carries no parseable sequence: the frontier
        // reflects only the complete frame 7 forwarded above it.
        assert!(
            delivered.contains(7),
            "sequence 7 must be in the delivered set"
        );
        // Offset stops at the end of the last ACCOUNTED-FOR line — the
        // fragment is re-read (and delivered) whole by the next poll.
        assert_eq!(plan.offset, (frame(7).len() + 1) as u64);
    }

    /// Non-frame lines pass through the resync filter unchanged.
    #[test]
    fn rotation_resync_passes_through_non_frame_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, b"garbage line\n{\"sequence\":9}\n").unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[5]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        assert_eq!(plan.out, b"garbage line\n{\"sequence\":9}\n");
        assert!(
            delivered.contains(9),
            "sequence 9 must be in the delivered set"
        );
        assert_eq!(plan.offset, "garbage line\n{\"sequence\":9}\n".len() as u64);
    }
    /// Round-13 review P1: the delivery planner must not buffer the whole
    /// spool (or the whole undelivered tail) per follower. A catch-up
    /// larger than the bounded send buffer is delivered in QUANTA across
    /// polls: the scan stops before the next never-delivered line and the
    /// next poll resumes at exactly that boundary — bounded memory with NO
    /// frame loss and no replay (the pipeline contract is "same stream,
    /// consecutive sequence numbers, order preserved, no data dropped"; a
    /// drop-oldest variant would trade loss for latency and leave
    /// client-visible sequence gaps).
    #[test]
    fn delivery_stops_at_buffer_bound_and_resumes_losslessly() {
        // 3 frames of ~1 MiB each: any two consecutive frames exceed the
        // MAX_TAIL_BYTES send buffer, so each poll delivers exactly one.
        let frame = |seq: u64| {
            format!(
                r#"{{"version":"enclava-log-frame-v1","sequence":{seq},"pad":"{}"}}"#,
                "x".repeat(1024 * 1024 + 4096)
            )
        };
        let line = |seq: u64| format!("{}\n", frame(seq));
        let mut bytes = Vec::new();
        for seq in [1u64, 2, 3] {
            bytes.extend_from_slice(line(seq).as_bytes());
        }
        assert!(
            line(1).len() + line(2).len() > MAX_TAIL_BYTES as usize,
            "fixture: any two frames must outgrow one send quantum"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = DeliveredSequences::new();

        // Poll 1: frame 1 alone — frame 2 does not fit the bound.
        let plan1 = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        assert_eq!(plan1.out, line(1).as_bytes());
        assert!(
            plan1.out.len() < MAX_TAIL_BYTES as usize,
            "send buffer stays bounded, got {}",
            plan1.out.len()
        );
        assert_eq!(plan1.offset, line(1).len() as u64);
        assert!(
            delivered.contains(1),
            "only delivered frames enter the delivered set"
        );

        // Poll 2 resumes at exactly the stopped boundary: frame 2 alone.
        let plan2 = plan_delivery(&mut file, plan1.offset, &mut delivered).unwrap();
        assert_eq!(plan2.out, line(2).as_bytes());
        assert_eq!(plan2.offset, (line(1).len() + line(2).len()) as u64);
        assert!(
            delivered.contains(2),
            "sequence 2 must be in the delivered set"
        );

        // Poll 3: frame 3 and EOF.
        let plan3 = plan_delivery(&mut file, plan2.offset, &mut delivered).unwrap();
        assert_eq!(plan3.out, line(3).as_bytes());
        assert_eq!(plan3.offset, bytes.len() as u64);
        assert!(
            delivered.contains(3),
            "sequence 3 must be in the delivered set"
        );

        // Lossless: the three quanta concatenated are the entire file.
        let mut delivered = plan1.out.clone();
        delivered.extend_from_slice(&plan2.out);
        delivered.extend_from_slice(&plan3.out);
        assert_eq!(delivered, bytes, "bounded quanta must lose nothing");
    }

    /// Round-13 review P1 hardening: the spool directory is
    /// workload-writable and the writer caps records at
    /// MAX_LOG_RECORD_BYTES, so a "line" longer than MAX_TAIL_BYTES is
    /// never a writer-produced frame — a hostile mega-line must not be
    /// buffered whole per follower either (that re-opens the exact
    /// multi-follower OOM this fix closes). Oversized lines are consumed
    /// and DISCARDED without buffering; the delivered boundary advances
    /// past one only once its newline arrives.
    #[test]
    fn rotation_resync_drops_oversized_line_without_buffering() {
        let mut bytes = vec![b'z'; MAX_TAIL_BYTES as usize + 4096];
        bytes.push(b'\n');
        bytes.extend_from_slice(b"{\"version\":\"enclava-log-frame-v1\",\"sequence\":5}\n");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[4]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        // The mega-line is gone; the real frame after it is forwarded.
        assert_eq!(
            plan.out,
            b"{\"version\":\"enclava-log-frame-v1\",\"sequence\":5}\n"
        );
        assert!(
            delivered.contains(5),
            "sequence 5 must be in the delivered set"
        );
        // The boundary advanced past the dropped line AND the frame.
        assert_eq!(plan.offset, bytes.len() as u64);
    }

    /// An oversized segment with NO newline yet is an in-flight fragment
    /// like any other: nothing is forwarded and the boundary does not
    /// advance past its first byte — the completed segment is re-scanned
    /// (and dropped) once its newline arrives.
    #[test]
    fn rotation_resync_withholds_oversized_fragment() {
        let bytes = vec![b'z'; MAX_TAIL_BYTES as usize + 4096]; // no newline
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[4]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        assert!(plan.out.is_empty());
        assert_eq!(plan.offset, 0, "in-flight fragment is withheld");
    }

    /// The boundary-0 anchor (empty or fragment-only file) fingerprints
    /// the HEAD of the file — the construction `anchor_for` documents —
    /// so the next poll's probe catches a rewritten file even when
    /// nothing has been delivered from this generation yet. Only a
    /// completely EMPTY spool stays identity-only.
    #[test]
    fn rotation_resync_zero_boundary_fingerprints_head() {
        let bytes = b"{\"version\":\"enclava-log-frag".to_vec(); // fragment only
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, &bytes).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();
        let mut delivered = delivered_of(&[4]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        assert_eq!(plan.offset, 0);
        assert_eq!(plan.fp_pos, 0);
        let fp_len = plan.fp_len as usize;
        assert_eq!(fp_len, bytes.len().min(ANCHOR_FINGERPRINT_BYTES));
        assert_eq!(plan.fingerprint[..fp_len], bytes[..fp_len]);
        // Cross-check against the anchor_for construction tests build.
        let anchor = anchor_for(&bytes, 0, SpoolIdentity { dev: 0, ino: 0 });
        assert_eq!(plan.fp_pos, anchor.fp_pos);
        assert_eq!(plan.fp_len, anchor.fp_len);
        assert_eq!(plan.fingerprint, anchor.fingerprint);
    }

    /// The relay runs as root and the spool directory is group-writable by
    /// the workload: a planted symlink at the spool path must be REJECTED,
    /// not followed — otherwise the relay would stream whatever init-only
    /// file the workload pointed it at as "logs" (grok round-8 self-check).
    #[test]
    fn tail_lines_rejects_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "init-only material\n").unwrap();
        let spool = dir.path().join("spool.jsonl");
        std::os::unix::fs::symlink(&secret, &spool).unwrap();
        let err = tail_lines(&spool, 10).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        // The follow path's per-poll open uses the same guarded helper.
        let err = open_spool_for_read(&spool).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        // A regular file at the same path still opens fine.
        std::fs::remove_file(&spool).unwrap();
        std::fs::write(&spool, "frame\n").unwrap();
        assert!(open_spool_for_read(&spool).is_ok());
    }

    #[test]
    fn tail_lines_returns_open_spool_handle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        let (lines, offset, file) = tail_lines(&path, 10).unwrap();
        assert_eq!(
            lines,
            vec!["one".to_string(), "two".to_string(), "three".to_string()]
        );
        assert_eq!(offset, "one\ntwo\nthree\n".len() as u64);
        // The returned handle is open and pins the spool inode: while it is
        // held the filesystem cannot recycle that inode number.
        assert!(spool_identity(&file).is_ok());
    }

    /// Round-6 review finding (connect path): a spool ending mid-frame must
    /// not emit the in-flight fragment as a tail line, and the follow offset
    /// must point at the fragment's first byte so the follow loop can
    /// complete it once the writer finishes the append.
    #[test]
    fn tail_lines_holds_back_incomplete_trailing_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, "one\ntwo\nthree\n{\"partial").unwrap();
        let (lines, offset, _file) = tail_lines(&path, 10).unwrap();
        assert_eq!(
            lines,
            vec!["one".to_string(), "two".to_string(), "three".to_string()]
        );
        // Offset points at the start of the incomplete fragment, not past it.
        assert_eq!(offset, "one\ntwo\nthree\n".len() as u64);
    }

    /// Round-6 review finding, re-pinned at the delivery planner: the
    /// delivered boundary must reflect the lines actually SCANNED, never a
    /// pre-read metadata length — the writer is a separate process and can
    /// append concurrently. Lines the scan observed are delivered exactly
    /// once (not replayed next poll even though the pre-scan length was
    /// stale) and lines landing after the scan stay for the next poll
    /// (not skipped).
    #[test]
    fn delivery_offset_tracks_scanned_lines_not_prestale_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let first = "{\"sequence\":1}\n";
        let second = "{\"sequence\":2}\n";
        std::fs::write(&path, first).unwrap();
        let mut file = std::fs::File::open(&path).unwrap();

        // The "pre-read" length is stale immediately: frame 2 lands before
        // the scan runs, as an interleaved writer would.
        {
            use std::io::Write as _;
            let mut writer = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writer.write_all(second.as_bytes()).unwrap();
        }
        let mut delivered = delivered_of(&[0]);
        let plan = plan_delivery(&mut file, 0, &mut delivered).unwrap();
        // The scan SAW both lines: both delivered once and the boundary is
        // their combined end (the scanned boundary, not the stale length).
        assert_eq!(plan.out, format!("{first}{second}").as_bytes());
        assert_eq!(plan.offset, (first.len() + second.len()) as u64);
        assert!(
            delivered.contains(2),
            "sequence 2 must be in the delivered set"
        );

        // A line landing AFTER the scan is not skipped: the next poll from
        // the scanned boundary picks it up.
        let third = "{\"sequence\":3}\n";
        {
            use std::io::Write as _;
            let mut writer = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writer.write_all(third.as_bytes()).unwrap();
        }
        let plan = plan_delivery(&mut file, plan.offset, &mut delivered).unwrap();
        assert_eq!(plan.out, third.as_bytes());
        assert_eq!(
            plan.offset,
            (first.len() + second.len() + third.len()) as u64
        );
    }

    /// A rename-based rotation swaps the inode: the follower must detect the
    /// identity change and reset, not keep reading stale offsets. This pins
    /// the round-4 review finding (truncate-and-regrow within one poll
    /// window previously desynchronized `len < offset`-only followers) and
    /// the round-5 Critical (identity must be compared against a HELD fd,
    /// which the filesystem cannot recycle — a remembered bare number can
    /// be recycled by the next rotation's temp file on ext4).
    #[test]
    fn rotation_via_rename_resets_follow_offset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");

        // Initial spool with frames; the tail handle is HELD open.
        std::fs::write(&path, "old-a\nold-b\nold-c\n").unwrap();
        let (_, offset, held_file) = tail_lines(&path, 10).unwrap();
        let held_identity = spool_identity(&held_file).unwrap();
        assert_eq!(offset, "old-a\nold-b\nold-c\n".len() as u64);

        // Rotation: retained tail written to a temp file and renamed over
        // the path (new inode), then new appends land on the new file and
        // grow it PAST the old offset — the case `len < offset` misses.
        // Critically, the OLD fd stays open across the rename (as in the
        // live follower), pinning the old inode number against recycling.
        std::fs::write(
            dir.path().join("spool.jsonl.rotate"),
            "old-b\nold-c\nnew-a\nnew-b\nnew-c\nnew-d\n",
        )
        .unwrap();
        std::fs::rename(dir.path().join("spool.jsonl.rotate"), &path).unwrap();

        // The follower opens the path fresh each poll and compares against
        // the HELD identity → rotation detected, offset resets to 0.
        let mut file = std::fs::File::open(&path).unwrap();
        let new_identity = spool_identity(&file).unwrap();
        assert_ne!(
            new_identity, held_identity,
            "rename rotation must change identity vs the held handle"
        );
        let len = file.metadata().unwrap().len();
        // New file grew past the old offset — the exact case a length-only
        // follower misreads. Identity tracking resets to 0.
        assert!(len > offset);
        file.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&bytes),
            "old-b\nold-c\nnew-a\nnew-b\nnew-c\nnew-d\n"
        );
        // The held old fd still reads the pre-rotation content (unlinked
        // but pinned) — no data race between the two handles.
        drop(file);
        drop(held_file);
    }

    /// Round-9 review finding (P1): the OLD held fd must be dropped BEFORE
    /// the post-rotation client write, not only after adopting the new one.
    /// A stalled client can block the post-rotation client write for up to
    /// FOLLOW_IO_TIMEOUT while the unlinked old inode (~32 MiB) stays
    /// pinned; staggered stalled followers could each pin a different
    /// rotation generation past the 64 MiB emptyDir cap. Deterministic pin:
    /// a writer that fails the post-rotation write must leave `held` empty —
    /// previously the old handle was only replaced after a successful write
    /// and flush, so a failed/blocked write kept it pinned.
    #[test]
    fn rotation_resync_drops_old_handle_before_client_write() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("simulated stalled client"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, "{\"sequence\":1}\n{\"sequence\":2}\n").unwrap();
        let (_, mut offset, held_file) = tail_lines(&path, 10).unwrap();
        let old_identity = spool_identity(&held_file).unwrap();
        // Seed the anchor the way a live follower would after delivering
        // the tail: identity of the (old) inode plus its last delivered
        // byte. Round-11: `held` carries NO file descriptor — rotation
        // tracking is anchor-based precisely so a client stalled in the
        // blocking write below cannot pin any inode.
        drop(held_file);
        // Anchor built exactly as follow_spool's resync path does.
        let contents = std::fs::read(&path).unwrap();
        let boundary = contents
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|idx| idx + 1)
            .unwrap_or(0);
        let mut held = Some(anchor_for(&contents, boundary, old_identity));

        // Rotate: new inode over the spool path.
        let rotated = dir.path().join("spool.jsonl.rotate");
        std::fs::write(&rotated, "{\"sequence\":2}\n{\"sequence\":3}\n").unwrap();
        std::fs::rename(&rotated, &path).unwrap();

        let mut sink = FailingWriter;
        let delivered = delivered_of(&[2]);
        let result = follow_spool(&mut sink, &path, &mut offset, &mut held, delivered);
        assert!(result.is_err(), "failing writer must unwind the follower");
        // The follower may hold an ANCHOR (identity + probe byte, no fd)
        // across the blocking write — never a descriptor — and the anchor
        // already points at the NEW inode, so the pinned old generation is
        // released the moment the rotation was detected, not after the
        // client write returns.
        let new_identity = spool_identity(&std::fs::File::open(&path).unwrap()).unwrap();
        assert_ne!(new_identity, old_identity);
        match held {
            Some(anchor) => assert_eq!(
                anchor.identity, new_identity,
                "anchor must reference the rotated-in inode, not the old one"
            ),
            None => panic!("anchor must be established before the client write"),
        }
    }

    /// Round-7 review finding (P1): a follow client that stops reading
    /// must not pin the relay thread (and the rotated spool inode it
    /// holds) forever. The connection must carry socket timeouts: a short
    /// one in tests (FOLLOW_IO_TIMEOUT in production), so a stalled
    /// write_all/strandead head read errors out and unwinds the handler.
    /// Round-10 review finding (P1, connect path): handle_connection
    /// drops the tail handle BEFORE the (potentially blocking) initial
    /// client writes. Since round-15 it seeds the tail anchor first and
    /// enters with `held = Some(anchor)`; the held-less entry pinned here
    /// is what the first poll sees when that anchor's probe FAILS — a
    /// rotation landing between the tail read and the first poll. That
    /// resync must not replay already-delivered frames: it dedups by
    /// sequence against the tail-seeded set and forwards only what is
    /// new, and it must re-derive the offset against the CURRENT inode.
    #[test]
    fn follow_entry_without_held_handle_resyncs_without_replay() {
        // Fails the resync flush so follow_spool unwinds after exactly one
        // poll — otherwise the loop would spin on the len==offset no-op
        // branch forever (a healthy idle follower never blocks).
        struct FailingFlushWriter {
            sink: Vec<u8>,
        }
        impl std::io::Write for FailingFlushWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.sink.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("stop after first resync flush"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        // Tail delivered sequences 1-2 from the (now gone) old inode;
        // `offset` was computed against that old inode and must not be
        // trusted against the current one.
        std::fs::write(&path, "{\"sequence\":2}\n{\"sequence\":3}\n").unwrap();
        let mut offset = 100u64; // stale, points past the current file
        let mut held = None; // handle_connection drops the tail fd pre-write
        let mut sink = FailingFlushWriter { sink: Vec::new() };
        let delivered = delivered_of(&[2]);
        let result = follow_spool(&mut sink, &path, &mut offset, &mut held, delivered);
        assert!(result.is_err(), "failing flush must unwind the loop");
        // Sequence 2 was already delivered in the tail: it must NOT be
        // replayed by the held=None resync; sequence 3 is forwarded once.
        let sent = String::from_utf8(sink.sink).unwrap();
        assert_eq!(sent, "{\"sequence\":3}\n");
        // The resync recomputed the offset against the CURRENT inode
        // (end of last complete line), ignoring the stale entry offset.
        assert_eq!(offset, "{\"sequence\":2}\n{\"sequence\":3}\n".len() as u64);
        // The flush error unwound the loop AFTER the resync established its
        // anchor but BEFORE any further work: `held` is an anchor (no fd)
        // referencing the current inode — nothing is pinned by a descriptor.
        match held {
            Some(anchor) => assert_eq!(
                anchor.identity,
                spool_identity(&std::fs::File::open(&path).unwrap()).unwrap()
            ),
            None => panic!("resync must anchor the current inode"),
        }
    }

    /// Round-15 review P2: the tail cursor must survive into follow mode.
    /// `tail_lines` computes `offset` at the end of the complete lines but
    /// returns only the REQUESTED tail (the API defaults to 100 lines), so
    /// the held-less entry of round-10 rescanned from offset 0 and
    /// `plan_delivery` streamed every older complete frame the tail limit
    /// left out — `enclava logs --follow` replayed up to the whole spool
    /// instead of following after its tail. With the anchor seeded from
    /// the tail cursor (as `handle_connection` now does), the no-rotation
    /// first poll continues exactly at the cursor: only post-tail frames
    /// are delivered, never the pre-tail history.
    #[test]
    fn seeded_tail_cursor_follows_without_history_replay() {
        // Succeeds the write, fails the flush: follow_spool unwinds after
        // exactly one poll.
        struct FailingFlushWriter {
            sink: Vec<u8>,
        }
        impl std::io::Write for FailingFlushWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.sink.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("stop after first poll"))
            }
        }

        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        // Six complete frames of history in the spool.
        let mut body = String::new();
        for seq in 1..=6u64 {
            body.push_str(&format!("{}\n", frame(seq)));
        }
        std::fs::write(&path, &body).unwrap();

        // The connect path exactly as handle_connection runs it: a 2-line
        // tail delivers frames 5-6, the cursor lands at EOF, and the
        // anchor is seeded from the tail fd BEFORE it is dropped.
        let (lines, mut offset, tail_file) = tail_lines(&path, 2).unwrap();
        assert_eq!(lines, vec![frame(5), frame(6)]);
        let mut held = Some(anchor_from_file(&tail_file, offset).unwrap());
        drop(tail_file);
        let mut delivered = DeliveredSequences::new();
        for line in &lines {
            remember_delivered_line(line.as_bytes(), &mut delivered);
        }

        // A new frame lands before the first follow poll.
        {
            use std::io::Write as _;
            let mut writer = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writer
                .write_all(format!("{}\n", frame(7)).as_bytes())
                .unwrap();
        }

        let mut sink = FailingFlushWriter { sink: Vec::new() };
        let result = follow_spool(&mut sink, &path, &mut offset, &mut held, delivered);
        assert!(result.is_err(), "failing flush must unwind the loop");
        // ONLY the post-tail frame is streamed: the pre-tail history
        // (frames 1-4) must NOT be replayed to a client that asked for a
        // 2-line tail and then follow.
        let sent = String::from_utf8(sink.sink).unwrap();
        assert_eq!(sent, format!("{}\n", frame(7)));
        // The cursor advanced to the new end of the last complete line.
        assert_eq!(offset, (body.len() + frame(7).len() + 1) as u64);
    }

    /// `anchor_from_file` must build the EXACT anchor construction
    /// `anchor_for` documents (and `plan_delivery` maintains): the window
    /// ending at the boundary, or the head of the file at boundary 0 — the
    /// seeded anchor and a post-poll anchor must probe identically, or a
    /// healthy follower would resync (and replay) on its second poll.
    #[test]
    fn anchor_from_file_matches_the_test_construction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let contents = b"0123456789abcdefghijklmnopqrstuv"; // 32 bytes
        std::fs::write(&path, contents).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let identity = spool_identity(&file).unwrap();
        for boundary in [0u64, 1, 8, 15, 16, 17, 32] {
            let from_file = anchor_from_file(&file, boundary).unwrap();
            let expected = anchor_for(contents, boundary as usize, identity);
            assert_eq!(from_file, expected, "boundary {boundary}");
        }
        // A boundary-0 anchor on a completely EMPTY spool is
        // identity-only (documented residual: no bytes to fingerprint).
        std::fs::write(&path, b"").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let anchor = anchor_from_file(&file, 0).unwrap();
        assert_eq!(anchor.fp_len, 0);
    }

    /// Round-11 review finding (P1): in the SAME-INODE append branch no
    /// spool descriptor may survive across the (potentially blocking)
    /// client write + flush. Previously both the freshly opened fd and the
    /// held fd stayed open across `write_all`, so a rotation landing under
    /// a stalled client pinned the unlinked ~32 MiB inode for the whole
    /// FOLLOW_IO_TIMEOUT window. The follow state is now a FollowAnchor
    /// (identity + probe byte, NO descriptor), and the fd is dropped
    /// before the write. This test pins the ordering: a write that fails
    /// must still observe the offset advanced and the anchor moved to the
    /// new delivered boundary — state that can only be committed before
    /// the blocking write, because no fd exists to commit afterwards.
    /// Round-11 self-check Critical: a numerically recycled inode number
    /// (two rotations inside one blocked client write can produce one) must
    /// NOT pass the same-inode check. The identity matches, but the 16-byte
    /// content fingerprint at the delivered boundary cannot: a rewritten
    /// tail is different ciphertext. Previously a one-byte '\n' probe made
    /// this a near-vacuous pass, silently dropping or splicing frames.
    #[test]
    fn recycled_inode_fails_fingerprint_probe_and_resyncs() {
        // Succeeds the write, fails the flush: follow_spool unwinds after
        // one poll having performed exactly one resync.
        struct FailingFlushWriter {
            sink: Vec<u8>,
        }
        impl std::io::Write for FailingFlushWriter {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.sink.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("stop after first resync"))
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        // The "old" generation: sequences 1-2 delivered, boundary at end.
        std::fs::write(&path, "{\"sequence\":1}\n{\"sequence\":2}\n").unwrap();
        let identity = spool_identity(&std::fs::File::open(&path).unwrap()).unwrap();
        let contents = std::fs::read(&path).unwrap();
        let mut offset = contents.len() as u64;
        let mut held = Some(anchor_for(&contents, contents.len(), identity));

        // SIMULATE inode-number recycling: an unlink + create + rename dance
        // that lands a DIFFERENT file on the same (dev,ino) pair. This is
        // best-effort on any given filesystem; the assertion that matters
        // is that a same-identity/different-content file fails the probe.
        // If the inode number is not reused, the identity itself differs
        // and the resync triggers anyway — both paths resync.
        let rotated = dir.path().join("spool.jsonl.rotate");
        std::fs::write(&rotated, "{\"sequence\":9}\n{\"sequence\":10}\n").unwrap();
        std::fs::rename(&rotated, &path).unwrap();
        // Overwrite the anchor's identity with the NEW file's identity to
        // force the worst case (recycled inode number): the fingerprint is
        // the only remaining defense.
        let new_identity = spool_identity(&std::fs::File::open(&path).unwrap()).unwrap();
        held = held.map(|mut a| {
            a.identity = new_identity;
            a
        });

        let mut sink = FailingFlushWriter { sink: Vec::new() };
        let result = follow_spool(&mut sink, &path, &mut offset, &mut held, delivered_of(&[2]));
        assert!(result.is_err(), "failing flush must unwind the loop");
        // The probe failed → resync: sequence dedup against frontier 2
        // dropped nothing bogus, and the client received the frames of the
        // rewritten file that are above the frontier (9, 10) exactly once.
        let sent = String::from_utf8(sink.sink).unwrap();
        assert_eq!(sent, "{\"sequence\":9}\n{\"sequence\":10}\n");
        // Offset re-derived against the current file (its full length: both
        // frames are complete lines).
        let rewritten = "{\"sequence\":9}\n{\"sequence\":10}\n";
        assert_eq!(offset, rewritten.len() as u64);
        assert!(held.is_some());
    }

    #[test]
    fn same_inode_append_holds_no_fd_across_client_write() {
        struct FailingWriter;
        impl std::io::Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("simulated stalled client"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, "{\"sequence\":1}\n").unwrap();
        let identity = spool_identity(&std::fs::File::open(&path).unwrap()).unwrap();
        let mut offset = "{\"sequence\":1}\n".len() as u64;
        let first = std::fs::read(&path).unwrap();
        let mut held = Some(anchor_for(&first, first.len(), identity));

        // Same inode, new complete frame appended: takes the append branch.
        let mut append = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        append.write_all(b"{\"sequence\":2}\n").unwrap();
        drop(append);

        let mut sink = FailingWriter;
        let result = follow_spool(&mut sink, &path, &mut offset, &mut held, delivered_of(&[1]));
        assert!(result.is_err(), "failing writer must unwind the follower");
        // The delivered boundary was committed BEFORE the write: offset
        // spans both frames and the anchor probes the new last byte on the
        // SAME inode — the state the next poll (had the client survived)
        // would resume from, with no descriptor ever held across the write.
        assert_eq!(offset, "{\"sequence\":1}\n{\"sequence\":2}\n".len() as u64);
        let anchor = held.expect("anchor must be established before the write");
        assert_eq!(anchor.identity, identity, "same inode: no rotation");
        // The fingerprint window ends at the new delivered boundary and its
        // final byte is the frame terminator.
        assert_eq!(anchor.fp_pos + anchor.fp_len as u64, offset);
        assert_eq!(anchor.fingerprint[(anchor.fp_len as usize) - 1], b'\n');
    }

    #[test]
    fn stalled_follow_client_times_out_and_releases_thread() {
        use std::io::{Read as _, Write as _};
        use std::net::{TcpListener, TcpStream};

        let dir = tempfile::tempdir().unwrap();
        let spool_path = dir.path().join("spool.jsonl");
        std::fs::write(&spool_path, "{\"sequence\":1}\n").unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let spool = spool_path.clone();
        let server = thread::spawn(move || {
            // Reuse the server loop's per-connection setup: accept one
            // connection and run handle_connection with a short timeout.
            let (stream, _peer) = listener.accept().unwrap();
            handle_connection(stream, &spool, "app", Duration::from_millis(200))
        });

        // Stalled client: connect, send a valid follow request, then never
        // read another byte. A filler writer keeps appending spool lines so
        // the relay has data to send every poll: the kernel socket buffer
        // fills, write_all blocks, and the write timeout must fire.
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .write_all(
                b"GET /.well-known/confidential/logs?follow=true&container=app HTTP/1.1\r\n\
                  Host: x\r\n\r\n",
            )
            .unwrap();
        // Do NOT read: leave the request in flight and the socket open.

        let filler_path = spool_path.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let filler_stop = std::sync::Arc::clone(&stop);
        let filler = thread::spawn(move || {
            use std::io::Write as _;
            let mut spool = std::fs::OpenOptions::new()
                .append(true)
                .open(&filler_path)
                .unwrap();
            // One 4 KiB line per write, in a tight loop: the relay drains
            // the spool each 500 ms poll, so the kernel socket buffer (a
            // few MB on loopback, with autotuning) fills within a second
            // or two and write_all starts blocking.
            let line = format!("{}\n", "x".repeat(4096));
            let mut written: u64 = 0;
            while !filler_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = spool.write_all(line.as_bytes());
                let _ = spool.flush();
                written += 1;
                if written % 64 == 0 {
                    thread::yield_now();
                }
            }
        });

        let started = std::time::Instant::now();
        let outcome = server.join();
        let elapsed = started.elapsed();
        // The handler must have terminated via the timeout, not blocked
        // forever (join returning at all is the assertion; the elapsed
        // bound guards against a future regression to a poll loop that
        // never writes and thus never times out).
        assert!(
            elapsed < Duration::from_secs(30),
            "handler must terminate via IO timeout, took {elapsed:?}"
        );
        assert!(
            outcome.is_ok(),
            "handler must return (Err is fine — a hang is not): {outcome:?}"
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        filler.join().unwrap();
        // Best-effort drain so the test client does not RST.
        let _ = client.set_read_timeout(Some(Duration::from_millis(100)));
        let mut sink = Vec::new();
        let _ = client.read_to_end(&mut sink);
    }

    #[test]
    fn loopback_binds_are_accepted() {
        for bind in ["127.0.0.1:8082", "localhost:8082", "[::1]:9000"] {
            let addr = require_loopback_bind(bind).unwrap();
            assert!(addr.ip().is_loopback(), "{bind}: {addr}");
            // The validated address is what gets bound: no string
            // re-resolution at TcpListener::bind time.
            assert_eq!(addr.port().to_string(), bind.rsplit(':').next().unwrap());
        }
    }

    #[test]
    fn off_loopback_binds_are_rejected() {
        for bind in [
            "0.0.0.0:8082",
            "[::]:8082",
            "10.0.0.5:8082",
            "192.168.1.10:9443",
            "example.com:80",
            "not-a-bind",
        ] {
            let err = require_loopback_bind(bind).expect_err("off-loopback bind must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bind}: {err}");
            assert!(
                err.to_string().contains("must be loopback"),
                "{bind}: {err}"
            );
        }
    }

    #[test]
    fn spool_paths_outside_the_log_dir_are_rejected() {
        for spool in [
            "/state/tls-state/tenant-ingress/certificates/tls.key",
            "/run/enclava-logs/nested/app.jsonl",
            "/run/enclava-logs/../app.jsonl",
            "run/enclava-logs/app.jsonl",
            "/etc/passwd",
            "/run/enclava-logs",
        ] {
            let err = require_spool_under_log_dir(Path::new(spool))
                .expect_err("off-spool-dir spool path must be rejected");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{spool}: {err}");
        }
    }

    #[test]
    fn spool_paths_directly_under_the_log_dir_are_accepted() {
        for spool in ["/run/enclava-logs/app.jsonl", "/run/enclava-logs/web.jsonl"] {
            assert_eq!(
                require_spool_under_log_dir(Path::new(spool)).unwrap(),
                PathBuf::from(spool)
            );
        }
    }
}
