use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI32, AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use enclava_common::log_encryption::{
    LogEncryptionPublicKey, LogFrameContext, encrypt_log_frame, validate_public_key,
};
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

const DEFAULT_STARTED_DIR: &str = "/run/enclava/containers";
const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";
const DEFAULT_STARTUP: &str = "/startup/startup.sh";
const DEFAULT_LOG_SPOOL_DIR: &str = "/run/enclava-logs";
const STARTED_DIR_MODE: u32 = 0o2770;
const O_NOFOLLOW: i32 = 0o400000;
/// Soft cap on the encrypted log spool before rotation. The `logs` emptyDir
/// is capped at 64 MiB by the engine manifest (see
/// `LOGS_EMPTY_DIR_SIZE_LIMIT`); rotating well below that (aligned to the
/// relay's 2 MiB MAX_TAIL_BYTES tail window, with ample margin) keeps the
/// volume from ever hitting ENOSPC, which would otherwise kill the forwarding
/// thread and expose the child to SIGPIPE on its next stdout/stderr write.
const LOG_SPOOL_ROTATE_BYTES: u64 = 32 * 1024 * 1024;
/// After rotation, keep this prefix of the pre-rotation spool so the relay's
/// tail reads still span the rotation boundary.
const LOG_SPOOL_KEEP_BYTES: u64 = 8 * 1024 * 1024;
/// Cap on a single input record buffered from the child. Longer lines are
/// split at this boundary into consecutive frames (same stream, consecutive
/// sequence numbers, order preserved) so a pathological writer cannot grow
/// the wrapper's memory without bound or produce a frame larger than the
/// rotation headroom below the 64 MiB volume cap. 256 KiB of plaintext
/// encodes to well under 512 KiB of framed output.
const MAX_LOG_RECORD_BYTES: usize = 256 * 1024;
const TERMINATION_SIGNALS: [Signal; 4] = [
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
];
static CHILD_PID: AtomicI32 = AtomicI32::new(0);
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);

fn main() {
    if let Err(err) = run(env::args_os().skip(1).collect()) {
        eprintln!("enclava-wait-exec: {err}");
        std::process::exit(127);
    }
}

fn run(argv: Vec<OsString>) -> Result<(), String> {
    let name = env::var("ENCLAVA_CONTAINER_NAME").unwrap_or_else(|_| "unknown".to_string());
    validate_sentinel_name(&name)?;

    let started_dir = env::var_os("ENCLAVA_STARTED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STARTED_DIR));
    let ready_file = env::var_os("ENCLAVA_INIT_READY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_READY_FILE));

    signal_started(&started_dir, &name)?;
    wait_until_ready(&ready_file);

    let (program, args) = command_from_args(argv);
    if let Some(logs) = encrypted_log_config_from_env(&name)? {
        let code = run_with_encrypted_logs(program, args, logs)?;
        process::exit(code);
    }
    // Without encrypted logging there is no permitted output reader:
    // ReadStreamRequest is denied by the agent policy. Inheriting those pipes
    // eventually blocks a chatty payload (and its recovery path) on write.
    let err = Command::new(&program)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .exec();
    Err(format!(
        "failed to exec {}: {err}",
        PathBuf::from(program).display()
    ))
}

fn validate_sentinel_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("ENCLAVA_CONTAINER_NAME must not be empty".to_string());
    }
    if name == "." || name == ".." {
        return Err("ENCLAVA_CONTAINER_NAME must be a single path component".to_string());
    }
    if name.as_bytes().contains(&b'/') || name.as_bytes().contains(&0) {
        return Err("ENCLAVA_CONTAINER_NAME must be a single path component".to_string());
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct EncryptedLogConfig {
    recipient: LogEncryptionPublicKey,
    context: LogFrameContext,
    spool_path: PathBuf,
    container: String,
}

fn encrypted_log_config_from_env(
    default_container: &str,
) -> Result<Option<EncryptedLogConfig>, String> {
    let Some(key_id) = env::var_os("ENCLAVA_LOG_ENCRYPTION_KEY_ID") else {
        return Ok(None);
    };
    let key_id = key_id
        .into_string()
        .map_err(|_| "ENCLAVA_LOG_ENCRYPTION_KEY_ID must be UTF-8".to_string())?;
    let public_key = env::var("ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL")
        .map_err(|_| "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL is required".to_string())?;
    let public_key_sha256 = env::var("ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256")
        .map_err(|_| "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256 is required".to_string())?;
    let recipient = validate_public_key(key_id, public_key, public_key_sha256)
        .map_err(|err| format!("invalid log encryption public key metadata: {err}"))?;
    let context = LogFrameContext {
        org_id: required_env("ENCLAVA_LOG_ORG_ID")?,
        app_name: required_env("ENCLAVA_LOG_APP_NAME")?,
        deployment_id: required_env("ENCLAVA_LOG_DEPLOYMENT_ID")?,
    };
    let container = env::var("ENCLAVA_LOG_CONTAINER_NAME")
        .unwrap_or_else(|_| default_container.to_string())
        .trim()
        .to_string();
    validate_sentinel_name(&container)?;
    let spool_path = env::var_os("ENCLAVA_LOG_SPOOL_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LOG_SPOOL_DIR).join(format!("{container}.jsonl")));
    Ok(Some(EncryptedLogConfig {
        recipient,
        context,
        spool_path,
        container,
    }))
}

fn required_env(name: &str) -> Result<String, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
    {
        return Err(format!("{name} must not be empty or contain line breaks"));
    }
    Ok(value)
}

fn run_with_encrypted_logs(
    program: OsString,
    args: Vec<OsString>,
    logs: EncryptedLogConfig,
) -> Result<i32, String> {
    install_signal_forwarding()?;
    let spool = open_log_spool(&logs.spool_path)?;
    let spool = Arc::new(Mutex::new(spool));
    let sequence = Arc::new(AtomicU64::new(1));
    let mut child = Command::new(&program)
        .args(&args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            format!(
                "failed to spawn {} under encrypted log wrapper: {err}",
                PathBuf::from(&program).display()
            )
        })?;
    let child_pid = i32::try_from(child.id()).map_err(|_| "child PID exceeds i32".to_string())?;
    CHILD_PID.store(child_pid, Ordering::Release);
    let pending = PENDING_SIGNAL.swap(0, Ordering::AcqRel);
    if pending != 0 {
        forward_signal_to_child(child_pid, pending);
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "child stdout was not captured".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "child stderr was not captured".to_string())?;
    let stdout_thread = spawn_log_forwarder(
        stdout,
        "stdout",
        logs.clone(),
        Arc::clone(&spool),
        Arc::clone(&sequence),
    );
    let stderr_thread = spawn_log_forwarder(
        stderr,
        "stderr",
        logs,
        Arc::clone(&spool),
        Arc::clone(&sequence),
    );

    let status = child
        .wait()
        .map_err(|err| format!("failed to wait for encrypted log child: {err}"))?;
    CHILD_PID.store(0, Ordering::Release);
    for result in [stdout_thread.join(), stderr_thread.join()] {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("enclava-wait-exec encrypted log forwarding failed: {err}"),
            Err(_) => eprintln!("enclava-wait-exec encrypted log forwarding panicked"),
        }
    }
    Ok(status.code().unwrap_or(1))
}

fn install_signal_forwarding() -> Result<(), String> {
    let action = SigAction::new(
        SigHandler::Handler(handle_termination_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );
    for signal in TERMINATION_SIGNALS {
        // SAFETY: the handler only performs lock-free atomic operations and kill(2).
        unsafe { sigaction(signal, &action) }
            .map_err(|err| format!("failed to register {signal:?} handler: {err}"))?;
    }
    Ok(())
}

extern "C" fn handle_termination_signal(signal: i32) {
    let child_pid = CHILD_PID.load(Ordering::Acquire);
    if child_pid == 0 {
        PENDING_SIGNAL.store(signal, Ordering::Release);
    } else {
        forward_signal_to_child(child_pid, signal);
    }
}

fn forward_signal_to_child(child_pid: i32, signal: i32) {
    // SAFETY: kill(2) is async-signal-safe and child_pid is a spawned child process.
    unsafe {
        nix::libc::kill(child_pid, signal);
    }
}

fn open_log_spool(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log spool dir {}: {err}", parent.display()))?;
    }
    // read+append: appends position writes at end-of-file, while the read
    // side lets the rotation path retain the newest frames in place.
    OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o640)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|err| {
            format!(
                "failed to open encrypted log spool {}: {err}",
                path.display()
            )
        })
}

fn spawn_log_forwarder<R>(
    reader: R,
    stream: &'static str,
    logs: EncryptedLogConfig,
    spool: Arc<Mutex<File>>,
    sequence: Arc<AtomicU64>,
) -> thread::JoinHandle<Result<(), String>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || forward_encrypted_logs(reader, stream, &logs, &spool, &sequence))
}

fn forward_encrypted_logs<R>(
    reader: R,
    stream: &'static str,
    logs: &EncryptedLogConfig,
    spool: &Arc<Mutex<File>>,
    sequence: &AtomicU64,
) -> Result<(), String>
where
    R: Read,
{
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    let mut dropped_frames: u64 = 0;
    loop {
        buf.clear();
        let n = read_capped_record(&mut reader, &mut buf)
            .map_err(|err| format!("failed to read child {stream}: {err}"))?;
        if n == 0 {
            return Ok(());
        }
        while buf.ends_with(b"\n") || buf.ends_with(b"\r") {
            buf.pop();
        }
        let frame = encrypt_log_frame(
            &logs.recipient,
            &logs.context,
            sequence.fetch_add(1, Ordering::Relaxed),
            stream,
            &logs.container,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            &buf,
        )
        .map_err(|err| format!("failed to encrypt child {stream} log frame: {err}"))?;
        let line = serde_json::to_vec(&frame)
            .map_err(|err| format!("failed to encode encrypted log frame: {err}"))?;
        let mut spool = spool
            .lock()
            .map_err(|_| "encrypted log spool lock poisoned".to_string())?;
        // Rotate BEFORE writing, projected against the encoded frame length:
        // records are capped (see MAX_LOG_RECORD_BYTES), so the spool never
        // grows past the rotate threshold between checks and a single frame
        // can never outrun the headroom below the emptyDir cap. Best-effort
        // by design — a rotation failure is logged and skipped so the
        // forwarding thread keeps draining the child's pipe.
        if let Err(err) =
            rotate_spool_if_needed(&mut spool, line.len() as u64 + 1, &logs.spool_path)
        {
            eprintln!("enclava-wait-exec: log spool rotation failed: {err}");
        }
        // A spool write failure (e.g. a transient ENOSPC against the volume
        // cap) must not terminate the forwarding thread either: exiting here
        // closes the child's pipe and exposes a healthy workload to SIGPIPE.
        // Drop the frame instead and keep draining; report the first failure
        // and then every 1000th dropped frame so persistent loss is visible.
        if let Err(err) = spool
            .write_all(&line)
            .and_then(|_| spool.write_all(b"\n"))
            .and_then(|_| spool.flush())
        {
            dropped_frames += 1;
            if dropped_frames == 1 || dropped_frames % 1000 == 0 {
                eprintln!(
                    "enclava-wait-exec: encrypted log spool write failed \
                     ({dropped_frames} frames dropped so far): {err}"
                );
            }
        }
    }
}

/// Read one input record from the child, capped at
/// `MAX_LOG_RECORD_BYTES`: a longer line is returned as consecutive
/// chunks (each without a trailing newline except the final chunk), which
/// the caller frames separately — same stream, consecutive sequence
/// numbers, order preserved, no data dropped. The cap bounds both the
/// wrapper's memory and the largest frame the spool can ever see.
/// Implemented via fill_buf/consume rather than `Take::read_until` so the
/// cap boundary is exact (no byte duplication or loss at the limit).
fn read_capped_record<R: BufRead>(reader: &mut R, buf: &mut Vec<u8>) -> std::io::Result<usize> {
    buf.clear();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(buf.len());
        }
        let remaining = MAX_LOG_RECORD_BYTES - buf.len();
        let search = &available[..available.len().min(remaining)];
        match search.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&search[..=i]);
                reader.consume(i + 1);
                return Ok(buf.len());
            }
            None => {
                buf.extend_from_slice(search);
                let n = search.len();
                reader.consume(n);
                if buf.len() == MAX_LOG_RECORD_BYTES {
                    return Ok(buf.len());
                }
            }
        }
    }
}

/// Bound the encrypted log spool: rotate when the current length plus the
/// incoming encoded frame would exceed `LOG_SPOOL_ROTATE_BYTES`, retaining
/// only the last `LOG_SPOOL_KEEP_BYTES` of frames. Rotation writes the
/// retained tail to a sibling temp file and atomically renames it over the
/// spool path, so the spool always becomes a NEW inode and readers never
/// observe a half-truncated file: the relay's `follow_spool` tracks the
/// file identity (dev/ino) and restarts from offset 0 when it changes
/// (with `len < offset` kept as a belt-and-braces fallback), and `tail_lines`
/// reads the last MAX_TAIL_BYTES by path regardless. The caller holds the
/// spool mutex, and the handle is reopened onto the new inode in-place, so
/// the check-rotate-rename sequence is race-free for both forwarders.
/// Rotation is best-effort: failures are logged by the caller and never
/// terminate the forwarding threads, which keep draining the child pipes.
/// If the reopen fails after a successful rename, the old handle keeps
/// absorbing appends on the unlinked inode and the next call retries —
/// writes stay lossless-visible once a reopen succeeds.
fn rotate_spool_if_needed(spool: &mut File, incoming: u64, path: &Path) -> std::io::Result<()> {
    let len = spool.metadata()?.len();
    if len + incoming <= LOG_SPOOL_ROTATE_BYTES {
        return Ok(());
    }
    // Copy the retained tail to a scratch buffer from the old inode, then
    // atomically swap the spool to a fresh inode carrying only that tail.
    let keep_from = len.saturating_sub(LOG_SPOOL_KEEP_BYTES);
    let mut retain_buf = Vec::new();
    spool.seek(SeekFrom::Start(keep_from))?;
    spool.read_to_end(&mut retain_buf)?;
    // Align the retained window to the next frame boundary: rotation can
    // start mid-line, and the relay's tail_lines only discards a partial
    // first line when its read offset is nonzero.
    if keep_from > 0 {
        if let Some(nl) = retain_buf.iter().position(|b| *b == b'\n') {
            retain_buf.drain(..=nl);
        } else {
            // No newline in the retained window (one gigantic frame);
            // dropping it entirely is the only safe truncation point.
            retain_buf.clear();
        }
    }
    let rotate_tmp = PathBuf::from(format!("{}.rotate.{}", path.display(), process::id()));
    // Clear a leftover temp from a crashed rotation; O_NOFOLLOW below makes
    // a pre-planted symlink fail safely with ELOOP instead of being opened.
    let _ = fs::remove_file(&rotate_tmp);
    {
        let mut tmp = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o640)
            .custom_flags(O_NOFOLLOW)
            .open(&rotate_tmp)?;
        tmp.write_all(&retain_buf)?;
        tmp.sync_all()?;
    }
    fs::rename(&rotate_tmp, path)?;
    // Reopen the spool path so subsequent appends land on the new inode.
    // An error here leaves the old handle appending to the unlinked inode —
    // visible to no reader, but safe (no pipe close); the next rotation
    // call retries the swap.
    *spool = open_log_spool(path)
        .map_err(|message| io::Error::other(format!("spool reopen after rotation: {message}")))?;
    Ok(())
}

fn signal_started(started_dir: &Path, name: &str) -> Result<(), String> {
    prepare_started_dir(started_dir)?;
    let sentinel = started_dir.join(name);
    if let Ok(metadata) = fs::symlink_metadata(&sentinel)
        && metadata.file_type().is_symlink()
    {
        return Err(format!(
            "sentinel {} must not be a symlink",
            sentinel.display()
        ));
    }
    let body = sentinel_record(name)?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o640)
        .custom_flags(O_NOFOLLOW)
        .open(&sentinel)
        .map_err(|err| format!("failed to write sentinel {}: {err}", sentinel.display()))?;
    use std::io::Write;
    file.write_all(body.as_bytes())
        .map_err(|err| format!("failed to write sentinel {}: {err}", sentinel.display()))?;
    Ok(())
}

fn prepare_started_dir(started_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(started_dir).map_err(|err| {
        format!(
            "failed to create started dir {}: {err}",
            started_dir.display()
        )
    })?;
    let metadata = fs::symlink_metadata(started_dir).map_err(|err| {
        format!(
            "failed to stat started dir {}: {err}",
            started_dir.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        return Err(format!(
            "started dir {} is not a directory",
            started_dir.display()
        ));
    }
    let (uid, _) = current_uid_gid()?;
    if metadata.uid() == uid {
        fs::set_permissions(started_dir, fs::Permissions::from_mode(STARTED_DIR_MODE)).map_err(
            |err| {
                format!(
                    "failed to chmod started dir {}: {err}",
                    started_dir.display()
                )
            },
        )?;
        return Ok(());
    }

    let mode = metadata.permissions().mode() & 0o7777;
    if mode & 0o007 != 0 {
        return Err(format!(
            "started dir {} must not be world-accessible",
            started_dir.display()
        ));
    }
    if mode & 0o020 == 0 {
        return Err(format!(
            "started dir {} must be group-writable",
            started_dir.display()
        ));
    }
    Ok(())
}

fn sentinel_record(name: &str) -> Result<String, String> {
    let (uid, gid) = current_uid_gid()?;
    let start_time_ticks = current_start_time_ticks()?;
    Ok(format!(
        "version=1\ncontainer={name}\npid={}\nstart_time_ticks={start_time_ticks}\nuid={uid}\ngid={gid}\n",
        process::id()
    ))
}

fn current_uid_gid() -> Result<(u32, u32), String> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|err| format!("failed to read /proc/self/status: {err}"))?;
    uid_gid_from_status(&status)
}

fn uid_gid_from_status(status: &str) -> Result<(u32, u32), String> {
    let uid = first_status_id(status, "Uid:")?;
    let gid = first_status_id(status, "Gid:")?;
    Ok((uid, gid))
}

fn first_status_id(status: &str, key: &str) -> Result<u32, String> {
    let line = status
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| format!("missing {key} in process status"))?;
    line[key.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| format!("missing value for {key} in process status"))?
        .parse::<u32>()
        .map_err(|err| format!("invalid {key} in process status: {err}"))
}

fn current_start_time_ticks() -> Result<u64, String> {
    let stat = fs::read_to_string("/proc/self/stat")
        .map_err(|err| format!("failed to read /proc/self/stat: {err}"))?;
    start_time_ticks_from_stat(&stat)
}

fn start_time_ticks_from_stat(stat: &str) -> Result<u64, String> {
    let (_, rest) = stat
        .rsplit_once(") ")
        .ok_or_else(|| "process stat is missing command delimiter".to_string())?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| "process stat is missing start_time".to_string())?
        .parse::<u64>()
        .map_err(|err| format!("invalid process stat start_time: {err}"))
}

fn wait_until_ready(ready_file: &Path) {
    while !ready_file_is_ready(ready_file) {
        thread::sleep(Duration::from_secs(1));
    }
}

fn ready_file_is_ready(ready_file: &Path) -> bool {
    fs::read_to_string(ready_file)
        .map(|value| value.trim() == "ready")
        .unwrap_or(false)
}

fn command_from_args(argv: Vec<OsString>) -> (OsString, Vec<OsString>) {
    let mut argv = argv.into_iter();
    match argv.next() {
        Some(program) => (program, argv.collect()),
        None => (OsString::from(DEFAULT_STARTUP), Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("enclava-wait-exec-test-{}-{nanos}", process::id()))
    }

    #[test]
    fn rejects_path_like_sentinel_names() {
        for name in ["", ".", "..", "../web", "web/sidecar"] {
            assert!(validate_sentinel_name(name).is_err(), "{name:?}");
        }
        assert!(validate_sentinel_name("tenant-ingress").is_ok());
    }

    #[test]
    fn signal_started_creates_named_sentinel() {
        let dir = unique_dir();
        signal_started(&dir, "web").unwrap();
        assert!(dir.join("web").exists());
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o7777,
            STARTED_DIR_MODE
        );
        let sentinel = fs::read_to_string(dir.join("web")).unwrap();
        assert!(sentinel.contains("version=1\n"));
        assert!(sentinel.contains("container=web\n"));
        assert!(sentinel.contains(&format!("pid={}\n", process::id())));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ready_file_requires_ready_content() {
        let dir = unique_dir();
        fs::create_dir_all(&dir).unwrap();
        let ready = dir.join("init-ready");

        fs::write(&ready, "not-ready\n").unwrap();
        assert!(!ready_file_is_ready(&ready));

        fs::write(&ready, "ready\n").unwrap();
        assert!(ready_file_is_ready(&ready));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn status_parser_reads_effective_uid_and_gid() {
        let status =
            "Name:\ttest\nUid:\t10001\t10001\t10001\t10001\nGid:\t10002\t10002\t10002\t10002\n";

        assert_eq!(uid_gid_from_status(status).unwrap(), (10001, 10002));
    }

    #[test]
    fn stat_parser_reads_start_time_ticks() {
        let fields = std::iter::once("S")
            .chain((4..=21).map(|_| "0"))
            .chain(std::iter::once("123456"))
            .collect::<Vec<_>>()
            .join(" ");
        let stat = format!("99 (enclava wait exec) {fields}");

        assert_eq!(start_time_ticks_from_stat(&stat).unwrap(), 123456);
    }

    #[test]
    fn command_defaults_to_startup_script() {
        let (program, args) = command_from_args(Vec::new());
        assert_eq!(program, OsString::from(DEFAULT_STARTUP));
        assert!(args.is_empty());
    }

    #[test]
    fn command_preserves_argv() {
        let (program, args) = command_from_args(vec![
            OsString::from("caddy"),
            OsString::from("run"),
            OsString::from("--config"),
        ]);
        assert_eq!(program, OsString::from("caddy"));
        assert_eq!(
            args,
            vec![OsString::from("run"), OsString::from("--config")]
        );
    }

    #[test]
    fn encrypted_log_config_absent_by_default() {
        unsafe {
            env::remove_var("ENCLAVA_LOG_ENCRYPTION_KEY_ID");
        }
        assert!(encrypted_log_config_from_env("web").unwrap().is_none());
    }

    #[test]
    fn encrypted_log_config_requires_and_reads_routing_context() {
        let keypair = enclava_common::log_encryption::generate_log_keypair();
        unsafe {
            env::set_var("ENCLAVA_LOG_ENCRYPTION_KEY_ID", "logs-prod");
            env::set_var(
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL",
                &keypair.public_key_base64url,
            );
            env::set_var(
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256",
                &keypair.public_key_sha256,
            );
            env::remove_var("ENCLAVA_LOG_ORG_ID");
            env::remove_var("ENCLAVA_LOG_APP_NAME");
            env::remove_var("ENCLAVA_LOG_DEPLOYMENT_ID");
        }
        assert!(
            encrypted_log_config_from_env("web")
                .unwrap_err()
                .contains("ENCLAVA_LOG_ORG_ID is required")
        );

        unsafe {
            env::set_var("ENCLAVA_LOG_ORG_ID", "org-123");
            env::set_var("ENCLAVA_LOG_APP_NAME", "secure-app");
            env::set_var("ENCLAVA_LOG_DEPLOYMENT_ID", "deploy-123");
        }
        let config = encrypted_log_config_from_env("web").unwrap().unwrap();
        assert_eq!(config.context.org_id, "org-123");
        assert_eq!(config.context.app_name, "secure-app");
        assert_eq!(config.context.deployment_id, "deploy-123");
        assert_eq!(config.container, "web");
    }

    // ---- spool rotation (round-3 review) ----

    /// Rotation must bound the spool: once past the rotate threshold the
    /// file shrinks to roughly the retained window, the retained content is
    /// the newest frames (line-aligned), rotation swaps in a NEW inode, and
    /// subsequent appends still land at end-of-file. Regression test for the
    /// round-3 review SIGPIPE/ENOSPC finding: without rotation a full
    /// `logs` emptyDir killed the forwarder thread and exposed the child
    /// to SIGPIPE.
    #[test]
    fn spool_rotation_bounds_file_and_keeps_newest_frames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let mut spool = open_log_spool(&path).unwrap();
        let inode_before = fs::metadata(&path).unwrap().ino();

        // Write just past the rotate threshold using complete frames.
        let line: String = "x".repeat(63);
        let frame = format!("{line}\n");
        let frame_len = frame.len() as u64;
        let total = (LOG_SPOOL_ROTATE_BYTES + 1024 * 1024) / frame_len;
        for i in 0..total {
            write!(spool, "{i:06}{frame}").unwrap();
        }
        spool.flush().unwrap();

        rotate_spool_if_needed(&mut spool, 0, &path).unwrap();

        let len = fs::metadata(&path).unwrap().len();
        assert!(
            len <= LOG_SPOOL_KEEP_BYTES + frame_len,
            "spool must shrink to ~KEEP_BYTES, got {len}"
        );
        // Rotation swaps in a new inode so identity-tracking followers
        // (the relay's follow_spool) resynchronize deterministically.
        assert_ne!(
            fs::metadata(&path).unwrap().ino(),
            inode_before,
            "rotation must replace the spool inode"
        );
        // Appends still land at end-of-file after rotation.
        let before = fs::metadata(&path).unwrap().len();
        writeln!(spool, "tail-marker").unwrap();
        spool.flush().unwrap();
        let after = fs::metadata(&path).unwrap().len();
        assert_eq!(after, before + b"tail-marker\n".len() as u64);
        // The retained window starts at a frame boundary: the first line is
        // a complete 6-digit-prefixed frame.
        let content = fs::read_to_string(&path).unwrap();
        let first_line = content.lines().next().unwrap();
        assert!(
            first_line.len() == 69 && first_line.starts_with(|c: char| c.is_ascii_digit()),
            "first retained line must be a complete frame, got {first_line:?}"
        );
    }

    /// No rotation below the threshold: the benign-layout invariant.
    #[test]
    fn spool_rotation_is_noop_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let mut spool = open_log_spool(&path).unwrap();
        writeln!(spool, "small").unwrap();
        spool.flush().unwrap();
        let len_before = fs::metadata(&path).unwrap().len();
        let inode_before = fs::metadata(&path).unwrap().ino();
        rotate_spool_if_needed(&mut spool, 0, &path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), len_before);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode_before);
    }

    /// Rotation is projected against the incoming frame: the spool never
    /// grows past the rotate threshold even when the check races a large
    /// frame (round-4 review finding — oversized lines previously filled
    /// the volume before the post-write check could fire).
    #[test]
    fn spool_rotation_projects_incoming_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let mut spool = open_log_spool(&path).unwrap();

        let line: String = "x".repeat(63);
        let frame = format!("{line}\n");
        let frame_len = frame.len() as u64;
        // Each record is the 6-digit index + the 64-byte frame; stop below
        // the rotate threshold with room for a 1 MiB incoming frame.
        let record_len = 6 + frame.len() as u64;
        let total = (LOG_SPOOL_ROTATE_BYTES - 1024) / record_len;
        for i in 0..total {
            write!(spool, "{i:06}{frame}").unwrap();
        }
        spool.flush().unwrap();
        let len_before = fs::metadata(&path).unwrap().len();
        assert!(len_before <= LOG_SPOOL_ROTATE_BYTES - 1024);

        // A 1 MiB incoming frame would push past the threshold: rotation
        // must fire now, not after the write.
        rotate_spool_if_needed(&mut spool, 1024 * 1024, &path).unwrap();
        let len_after = fs::metadata(&path).unwrap().len();
        assert!(
            len_after <= LOG_SPOOL_KEEP_BYTES + frame_len,
            "projected rotation must bound the spool, got {len_after}"
        );
    }

    /// Input records are capped at MAX_LOG_RECORD_BYTES: a longer line is
    /// returned as consecutive chunks preserving order and content, so the
    /// wrapper's memory and the maximum frame size stay bounded (round-4
    /// review finding — one unbounded line previously bypassed rotation).
    #[test]
    fn read_capped_record_splits_oversized_lines() {
        // The newline must land beyond the cap so the first read is a
        // newline-free chunk of exactly MAX_LOG_RECORD_BYTES.
        let chunk = "a".repeat(MAX_LOG_RECORD_BYTES + 8);
        let input = format!("{chunk}BCDEFGHIJKLMNOPQRSTUVWXYZ\nsecond line\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());

        let mut first = Vec::new();
        let n1 = read_capped_record(&mut reader, &mut first).unwrap();
        assert_eq!(n1, MAX_LOG_RECORD_BYTES);
        assert_eq!(first.len(), MAX_LOG_RECORD_BYTES);
        assert!(!first.ends_with(b"\n"), "capped chunk has no newline yet");

        // The remainder of the same line (up to its newline) is the next
        // record — content is preserved across the split, nothing dropped.
        let mut second = Vec::new();
        let n2 = read_capped_record(&mut reader, &mut second).unwrap();
        let expected_remainder = format!("{}BCDEFGHIJKLMNOPQRSTUVWXYZ\n", "a".repeat(8));
        assert_eq!(second, expected_remainder.as_bytes());
        assert!(n2 > 0);

        let mut third = Vec::new();
        let n3 = read_capped_record(&mut reader, &mut third).unwrap();
        assert_eq!(third, b"second line\n");
        assert!(n3 > 0);

        let mut fourth = Vec::new();
        assert_eq!(read_capped_record(&mut reader, &mut fourth).unwrap(), 0);
        assert!(fourth.is_empty());

        // Reassembled content equals the input minus the record split.
        let mut reassembled = first.clone();
        reassembled.extend_from_slice(&second);
        reassembled.extend_from_slice(&third);
        assert_eq!(reassembled, input.as_bytes());
    }
}
