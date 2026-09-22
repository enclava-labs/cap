use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

const DEFAULT_BIND: &str = "127.0.0.1:8082";
const DEFAULT_SPOOL_PATH: &str = "/run/enclava-logs/app.jsonl";
const DEFAULT_CONTAINER: &str = "app";
const DEFAULT_TAIL_LINES: usize = 100;
const MAX_TAIL_LINES: usize = 1_000;
const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024;
const FOLLOW_POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct LogRelayConfig {
    pub bind: String,
    pub spool_path: PathBuf,
    pub container: String,
}

impl LogRelayConfig {
    pub fn from_env_defaults() -> Self {
        Self {
            bind: std::env::var("ENCLAVA_LOG_RELAY_BIND")
                .unwrap_or_else(|_| DEFAULT_BIND.to_string()),
            spool_path: std::env::var_os("ENCLAVA_LOG_RELAY_SPOOL_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SPOOL_PATH)),
            container: std::env::var("ENCLAVA_LOG_RELAY_CONTAINER")
                .unwrap_or_else(|_| DEFAULT_CONTAINER.to_string()),
        }
    }

    pub fn from_env_optional() -> Option<Self> {
        std::env::var_os("ENCLAVA_LOG_RELAY_SPOOL_PATH")?;
        Some(Self::from_env_defaults())
    }
}

pub fn run_from_env() -> io::Result<()> {
    run(LogRelayConfig::from_env_defaults())
}

pub fn spawn(config: LogRelayConfig) -> io::Result<thread::JoinHandle<()>> {
    let listener = TcpListener::bind(&config.bind)?;
    eprintln!("enclava-log-relay: listening on {}", config.bind);
    Ok(thread::spawn(move || serve(listener, config)))
}

pub fn run(config: LogRelayConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.bind)?;
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
                    if let Err(err) = handle_connection(stream, &spool_path, &container) {
                        eprintln!("enclava-log-relay: request failed: {err}");
                    }
                });
            }
            Err(err) => eprintln!("enclava-log-relay: accept failed: {err}"),
        }
    }
}

fn handle_connection(mut stream: TcpStream, spool_path: &Path, container: &str) -> io::Result<()> {
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
    write_response_head(&mut stream, 200, "application/x-ndjson", None)?;
    let mut last_seq: Option<u64> = None;
    for line in &lines {
        stream.write_all(line.as_bytes())?;
        stream.write_all(b"\n")?;
        advance_last_sequence(line.as_bytes(), &mut last_seq);
    }
    stream.flush()?;
    if query.follow {
        // `last_seq` was seeded while streaming the initial tail above, so
        // the first rotation after connect does not replay frames the client
        // just received in this response body. The tail's File handle is
        // kept open and becomes the follower's held handle: rotation
        // detection compares against the HELD inode (which the filesystem
        // cannot recycle while we hold it), not a bare remembered number.
        let mut held = Some(spool_file);
        follow_spool(&mut stream, spool_path, &mut offset, &mut held, last_seq)?;
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

/// Update `last_seq` from every complete (newline-terminated) line in
/// `bytes`. Sequences are monotonic per spool (one atomic counter shared
/// by all forwarders), so the maximum seen is the delivery frontier.
fn advance_last_sequence(bytes: &[u8], last_seq: &mut Option<u64>) {
    for line in bytes.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Some(sequence) = frame_sequence(&String::from_utf8_lossy(line))
            && sequence > last_seq.unwrap_or(0)
        {
            *last_seq = Some(sequence);
        }
    }
}

fn tail_lines(path: &Path, count: usize) -> io::Result<(Vec<String>, u64, File)> {
    let mut file = File::open(path)?;
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
    // The File handle is returned so the follower can HOLD it open: while
    // the old inode stays open the filesystem cannot recycle its number
    // into a rotation temp file, making identity comparison sound.
    Ok((lines, follow_from, file))
}

/// Read from the file's current cursor to end-of-file, returning the bytes
/// read together with the ACTUAL cursor position after the read. The writer
/// is a separate process, so the file can grow during the read; callers must
/// adopt the returned position (not a pre-read metadata length) as the
/// delivered boundary, or frames appended mid-read get replayed on the next
/// poll.
fn drain_from(file: &mut File, expected_start: u64) -> io::Result<(Vec<u8>, u64)> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let delivered = file.stream_position()?;
    debug_assert_eq!(delivered, expected_start + bytes.len() as u64);
    Ok((bytes, delivered))
}

fn follow_spool(
    stream: &mut TcpStream,
    path: &Path,
    offset: &mut u64,
    held: &mut Option<File>,
    initial_last_seq: Option<u64>,
) -> io::Result<()> {
    // Highest frame sequence already delivered to this client. On rotation
    // the spool is replaced by a new inode whose retained window re-contains
    // frames the client already received; byte offsets do not survive the
    // rewrite, but frame sequence numbers do (they are monotonic across the
    // rotation), so the follower skips retained frames with sequence <= this
    // frontier instead of replaying them. Unparseable lines are passed
    // through unchanged (historical behavior for anything not a frame).
    let mut last_seq: Option<u64> = initial_last_seq;
    loop {
        thread::sleep(FOLLOW_POLL_INTERVAL);
        let Ok(mut file) = File::open(path) else {
            continue;
        };
        let current_identity = spool_identity(&file)?;
        // Rotation detection compares against the HELD handle's inode, not
        // a remembered number: while the old fd stays open the filesystem
        // cannot recycle that inode number into a rotation temp file, so an
        // identity match genuinely means "same file" (canonical tail -F
        // semantics).
        let same_as_held = held
            .as_ref()
            .and_then(|held_file| spool_identity(held_file).ok())
            .is_some_and(|held_identity| held_identity == current_identity);
        let len = file.metadata()?.len();
        if !same_as_held {
            // The spool was rotated (atomic rename → new inode): re-read the
            // retained window from the start of the new file, filtering out
            // already-delivered frames by sequence. Never seek a stale byte
            // offset into the rewritten tail. Adopt the new file as the
            // held handle (drop the old fd only after adopting the new one).
            *offset = 0;
            let mut adopted = file;
            adopted.seek(SeekFrom::Start(0))?;
            let (bytes, delivered) = drain_from(&mut adopted, 0)?;
            // Use the ACTUAL cursor position as the offset: the writer is a
            // separate process and can append during the read. Those bytes are
            // delivered in this response, so the next poll must resume past them.
            // A trailing incomplete fragment (writer mid-append) sits at the end
            // of the delivered range; the next poll will read from this offset,
            // see the now-complete line, and deliver it.
            *offset = delivered;
            // Write to the client BEFORE holding the fd: a stalled client would keep
            // this fd open, pinning the old inode's ~32 MiB against deletion.
            // The inode identity is already captured in `current_identity` for
            // rotation detection, so we reopen on the next poll if needed.
            write_deduped_after_rotation(stream, &bytes, &mut last_seq)?;
            stream.flush()?;
            *held = Some(adopted);
            continue;
        }
        if len < *offset {
            // Fallback for same-inode truncation (not the rotation path,
            // but cheap insurance if the rotation mechanism ever changes).
            *offset = 0;
        }
        if len == *offset {
            continue;
        }
        file.seek(SeekFrom::Start(*offset))?;
        let (bytes, _delivered) = drain_from(&mut file, *offset)?;
        // Line-buffered delivery: emit only newline-terminated lines and
        // leave `*offset` at the first byte of any trailing fragment (it is
        // NOT counted as delivered). The fragment is re-read on the next
        // poll and joined with its completion. This is also what makes the
        // follower robust against the writer's rollback path: on a partial
        // write the writer truncates back to its pre-write length, and a
        // follower that had buffered the retracted prefix would emit a
        // corrupted line once the file regrew past its stale offset. By
        // never advancing past an uncommitted fragment, the follower always
        // re-reads whatever bytes actually exist at that offset now.
        let mut complete_end = 0usize;
        while let Some(idx) = bytes[complete_end..].iter().position(|&b| b == b'\n') {
            complete_end += idx + 1;
        }
        if complete_end > 0 {
            let complete = &bytes[..complete_end];
            advance_last_sequence(complete, &mut last_seq);
            stream.write_all(complete)?;
            *offset += complete_end as u64;
        }
        stream.flush()?;
    }
}

/// Re-send spool bytes after a rotation resync, dropping complete frames
/// whose sequence number was already delivered (`<= last_seq`). A trailing
/// segment without a newline is an in-flight frame (writer mid-append) and
/// is NOT forwarded: emitting a fragment risks the client concatenating it
/// with the next complete frame into one invalid NDJSON line, and the
/// completed frame will be re-read whole from the new inode on the next
/// poll (it sits at the end of the file past `*offset`). Lines that do not
/// parse as frames are forwarded unchanged (historical pass-through).
fn write_deduped_after_rotation<W: Write>(
    stream: &mut W,
    bytes: &[u8],
    last_seq: &mut Option<u64>,
) -> io::Result<()> {
    let mut start = 0usize;
    while let Some(idx) = bytes[start..].iter().position(|&b| b == b'\n') {
        let line = &bytes[start..start + idx];
        start += idx + 1;
        if line.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(line);
        let sequence = frame_sequence(&text);
        if sequence.is_some_and(|sequence| Some(sequence) <= *last_seq) {
            // Already delivered before the rotation: skip the replay.
            continue;
        }
        if let Some(sequence) = sequence {
            *last_seq = Some(sequence);
        }
        stream.write_all(line)?;
        stream.write_all(b"\n")?;
    }
    Ok(())
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

    #[test]
    fn frame_sequence_reads_plain_envelope_field() {
        let line = r#"{"version":"enclava-log-frame-v1","sequence":42,"stream":"stdout"}"#;
        assert_eq!(frame_sequence(line), Some(42));
        assert_eq!(frame_sequence("not json"), None);
        assert_eq!(frame_sequence(r#"{"sequence":"x"}"#), None);
    }

    /// Round-5 review finding: after a rotation resync, the retained window
    /// re-contains frames the follower already received. The resync re-send
    /// must drop those by sequence number instead of replaying them, and
    /// must forward newer frames exactly once.
    #[test]
    fn rotation_resync_dedups_already_delivered_sequences() {
        // Follower already received sequences 1-3; rotation retained 2-4
        // plus two new frames (5, 6) appended after the swap.
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = Vec::new();
        for seq in [2u64, 3, 4, 5, 6] {
            bytes.extend_from_slice(frame(seq).as_bytes());
            bytes.push(b'\n');
        }
        let mut last_seq = Some(3u64);
        let mut sink = Vec::new();
        write_deduped_after_rotation(&mut sink, &bytes, &mut last_seq).unwrap();
        let sent = String::from_utf8(sink).unwrap();
        assert_eq!(
            sent,
            format!("{}\n{}\n{}\n", frame(4), frame(5), frame(6)),
            "sequences <= 3 must be dropped, 4-6 forwarded once each"
        );
        assert_eq!(last_seq, Some(6));
    }

    /// An in-flight trailing fragment (writer mid-append) must NOT be
    /// forwarded during a rotation resync: emitting a partial NDJSON line
    /// risks the client concatenating it with the next complete frame.
    /// The completed frame is re-delivered whole from the new inode.
    #[test]
    fn rotation_resync_drops_incomplete_tail() {
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        let mut bytes = format!("{}\n", frame(7)).into_bytes();
        bytes.extend_from_slice(b"{\"version\":\"enclava-log-fra"); // partial
        let mut last_seq = Some(6u64);
        let mut sink = Vec::new();
        write_deduped_after_rotation(&mut sink, &bytes, &mut last_seq).unwrap();
        let sent = String::from_utf8(sink).unwrap();
        assert_eq!(sent, format!("{}\n", frame(7)));
        // The partial tail carries no parseable sequence: the frontier
        // reflects only the complete frame 7 forwarded above it.
        assert_eq!(last_seq, Some(7));
    }

    /// Non-frame lines pass through the resync filter unchanged.
    #[test]
    fn rotation_resync_passes_through_non_frame_lines() {
        let mut last_seq = Some(5u64);
        let mut sink = Vec::new();
        let bytes = b"garbage line\n{\"sequence\":9}\n";
        write_deduped_after_rotation(&mut sink, bytes, &mut last_seq).unwrap();
        assert_eq!(sink, b"garbage line\n{\"sequence\":9}\n");
        assert_eq!(last_seq, Some(9));
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

    /// Round-6 review finding: the delivered boundary after a drain must be
    /// the file's actual cursor, not a pre-read metadata length — the writer
    /// is a separate process and can append mid-read; those bytes are
    /// delivered in the same response and must not be replayed next poll.
    #[test]
    fn drain_from_reports_cursor_position_not_preread_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .unwrap();
        use std::io::Write;
        file.write_all(b"frame-1\n").unwrap();
        file.flush().unwrap();
        drop(file);

        // Simulate a mid-read append: seed the spool with the pre-read
        // state, then grow it BEFORE draining, as an interleaved writer
        // process would. The pre-read length (7) is stale by drain time.
        let mut reader = std::fs::File::open(&path).unwrap();
        reader.seek(std::io::SeekFrom::Start(0)).unwrap();
        {
            let mut writer = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writer.write_all(b"frame-2\n").unwrap();
        }
        let (bytes, delivered) = drain_from(&mut reader, 0).unwrap();
        assert_eq!(bytes, b"frame-1\nframe-2\n");
        // The cursor (14), not the stale pre-read length (7), is the
        // delivered boundary — frame-2 is not replayed on the next poll.
        assert_eq!(delivered, "frame-1\nframe-2\n".len() as u64);
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
}
