use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
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

/// Read a host-mutable env override for a wait-exec operational parameter
/// (ready-file and started-dir paths).
///
/// Prod-strict builds bind operational behavior to the compiled defaults
/// only: the pod environment is host-controlled and unbound to the signed
/// cc_init_data, so honoring it there would let a tampered host point this
/// process at a planted "ready" file (starting the workload before init
/// verifies policy and releases seeds) or desync the started-dir sentinel
/// handshake with enclava-init. Overrides are honored exclusively in
/// non-prod-strict (dev/CI debug) builds; mirrors enclava_init::env_override.
fn env_override(name: &str) -> Option<OsString> {
    env_override_for(env::var_os(name))
}

fn env_override_for(raw: Option<OsString>) -> Option<OsString> {
    if cfg!(feature = "prod-strict") {
        return None;
    }
    raw
}

fn main() {
    if let Err(err) = run(env::args_os().skip(1).collect()) {
        eprintln!("enclava-wait-exec: {err}");
        std::process::exit(127);
    }
}

fn run(argv: Vec<OsString>) -> Result<(), String> {
    let name = env::var("ENCLAVA_CONTAINER_NAME").unwrap_or_else(|_| "unknown".to_string());
    validate_sentinel_name(&name)?;

    let started_dir = env_override("ENCLAVA_STARTED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_STARTED_DIR));
    let ready_file = env_override("ENCLAVA_INIT_READY_FILE")
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
    // The name lands in the sentinel's key=value record (`container=<name>`)
    // and in file paths: newlines would inject extra record lines and `=`
    // would corrupt the key; reject both along with all other control
    // characters (#137).
    if name.bytes().any(|b| b.is_ascii_control() || b == b'=') {
        return Err(
            "ENCLAVA_CONTAINER_NAME must not contain control characters or '='".to_string(),
        );
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
    // Prod-strict resolves the recipient key and frame context exclusively
    // from the trusted handoff enclava-init writes onto the decrypted state
    // volume from the signed cc_init_data claim — never from the
    // host-controlled pod environment, which a tampered host could populate
    // with its own self-consistent key pair and thereby capture all workload
    // log plaintext. ENCLAVA_LOG_ENCRYPTION_KEY_ID (platform-set in prod
    // manifests) is read only as an activation hint: its presence selects
    // encrypted logging, its value is not trusted.
    #[cfg(feature = "prod-strict")]
    {
        let _ = default_container;
        if env::var_os("ENCLAVA_LOG_ENCRYPTION_KEY_ID").is_none() {
            return Ok(None);
        }
        encrypted_log_config_from_handoff()
    }
    #[cfg(not(feature = "prod-strict"))]
    {
        encrypted_log_config_from_raw_env(default_container)
    }
}

#[cfg(not(feature = "prod-strict"))]
fn encrypted_log_config_from_raw_env(
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

#[cfg(not(feature = "prod-strict"))]
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

/// Trusted encrypted-log recipient handoff written by enclava-init onto the
/// decrypted state volume (contents from the signed cc_init_data
/// `log_encryption_json` claim). Prod-strict builds read this instead of the
/// host-controlled log-encryption env vars. The file carries the claim's key
/// material plus the rollback-stable frame labels (org_id, app_name);
/// deployment_id is not part of the measured claim (rollback re-renders under
/// a fresh deployment UUID) and is taken from the validated pod env instead.
#[cfg(feature = "prod-strict")]
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
struct LogEncryptionHandoff {
    key_id: String,
    public_key_base64url: String,
    public_key_sha256: String,
    algorithm: String,
    org_id: String,
    app_name: String,
}

/// Location of the trusted handoff on the decrypted state volume; mirrors
/// enclava-init's `write_log_encryption_handoff` compiled default
/// (`<state-root>/app/log-encryption.json`). The state volume is only ever
/// writable from inside the guest after LUKS unlock — the host sees
/// ciphertext — so this is the trust root for the recipient key.
#[cfg(feature = "prod-strict")]
const LOG_ENCRYPTION_HANDOFF_FILE: &str = "/state/app/log-encryption.json";

/// Container-name source for the spool file name in prod-strict.
/// ENCLAVA_CONTAINER_NAME is validated by the sentinel handshake
/// (`validate_sentinel_name`) and only selects the spool sibling name, never
/// key material or paths outside the spool dir.
#[cfg(feature = "prod-strict")]
fn handoff_container_name() -> Result<String, String> {
    let name = env::var("ENCLAVA_CONTAINER_NAME")
        .unwrap_or_else(|_| "app".to_string())
        .trim()
        .to_string();
    validate_sentinel_name(&name)?;
    Ok(name)
}

#[cfg(feature = "prod-strict")]
fn encrypted_log_config_from_handoff() -> Result<Option<EncryptedLogConfig>, String> {
    encrypted_log_config_from_handoff_at(Path::new(LOG_ENCRYPTION_HANDOFF_FILE))
}

/// Read and validate the trusted handoff at `path`.
///
/// Three outcomes are possible after readiness:
/// - the handoff file parses: encrypted logging engages with the claim's key
///   material and frame labels;
/// - the file carries the explicit `{"disabled": true}` marker enclava-init
///   writes during the init-first rollout transition window (ConfigMap
///   `[log-encryption]` present, no signed claim): encrypted logging is off —
///   there is no trustable recipient key, so proceeding unencrypted is the
///   only safe option;
/// - the file is absent (with a warning): init published no decision at all.
///   The state volume is guest-only after LUKS unlock and init writes its
///   decision strictly before the ready file flips, so after readiness an
///   absent file means no signed claim existed. Fail-closed on
///   confidentiality: launch unencrypted rather than exit 127 and brick the
///   workload. Key material is never taken from host-controlled sources.
#[cfg(feature = "prod-strict")]
fn encrypted_log_config_from_handoff_at(path: &Path) -> Result<Option<EncryptedLogConfig>, String> {
    let handoff_content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "enclava-wait-exec: log-encryption handoff {} absent after readiness; encrypted logging disabled",
                path.display()
            );
            return Ok(None);
        }
        Err(err) => {
            return Err(format!("reading {}: {}", path.display(), err));
        }
    };
    // Explicit disabled marker (init-first rollout transition window).
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&handoff_content)
        && value.get("disabled").and_then(|flag| flag.as_bool()) == Some(true)
    {
        eprintln!(
            "enclava-wait-exec: log-encryption handoff {} is explicitly disabled (no signed cc_init_data claim); encrypted logging disabled",
            path.display()
        );
        return Ok(None);
    }
    let handoff: LogEncryptionHandoff = serde_json::from_str(&handoff_content)
        .map_err(|err| format!("parsing {}: {}", path.display(), err))?;
    // The claim's algorithm must be the one supported scheme; a future
    // algorithm must not silently encrypt under the hardcoded scheme.
    if handoff.algorithm != enclava_common::log_encryption::LOG_ENCRYPTION_ALGORITHM {
        return Err(format!(
            "log-encryption handoff {} carries unsupported algorithm {} (expected {})",
            path.display(),
            handoff.algorithm,
            enclava_common::log_encryption::LOG_ENCRYPTION_ALGORITHM
        ));
    }
    let recipient = validate_public_key(
        handoff.key_id,
        handoff.public_key_base64url,
        handoff.public_key_sha256,
    )
    .map_err(|err| format!("invalid log encryption public key metadata: {err}"))?;
    // deployment_id is a routing label only (it is not part of the measured
    // claim because rollback re-renders under a fresh deployment UUID); the
    // manifest always sets it when log encryption is configured.
    let deployment_id = env::var("ENCLAVA_LOG_DEPLOYMENT_ID")
        .map_err(|_| "ENCLAVA_LOG_DEPLOYMENT_ID is required".to_string())?;
    for (name, value) in [
        ("org_id", &handoff.org_id),
        ("app_name", &handoff.app_name),
        ("deployment_id", &deployment_id),
    ] {
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
        {
            return Err(format!(
                "log-encryption frame label {name} must not be empty or contain line breaks"
            ));
        }
    }
    let context = LogFrameContext {
        org_id: handoff.org_id,
        app_name: handoff.app_name,
        deployment_id,
    };
    let container = handoff_container_name()?;
    // Spool pinned to the dedicated log spool dir: the host-controlled
    // ENCLAVA_LOG_SPOOL_PATH env is not honored in prod-strict.
    let spool_path = PathBuf::from(DEFAULT_LOG_SPOOL_DIR).join(format!("{container}.jsonl"));
    Ok(Some(EncryptedLogConfig {
        recipient,
        context,
        spool_path,
        container,
    }))
}

fn run_with_encrypted_logs(
    program: OsString,
    args: Vec<OsString>,
    logs: EncryptedLogConfig,
) -> Result<i32, String> {
    install_signal_forwarding()?;
    let mut spool = open_log_spool(&logs.spool_path)?;
    // The spool lives on the shared `logs` emptyDir, which SURVIVES a
    // container restart without replacing the Pod — and so do the frames
    // the previous wrapper process wrote. Sequence numbers must therefore
    // stay monotonic across the restart, not restart at 1: the relay's
    // rotation dedup keeps the highest delivered sequence as its frontier
    // and would silently drop every post-restart frame whose reset
    // sequence lands at or below it. Scan the surviving spool tail (the
    // rotation-retained window is the only part that matters for the
    // frontier a connected relay can hold) for the highest frame sequence
    // and resume from it. Non-frame lines are skipped; a spool with no
    // parseable frame sequences resumes at 1.
    let sequence_start = initial_spool_sequence(&mut spool)?;
    let spool = Arc::new(Mutex::new(spool));
    let sequence = Arc::new(AtomicU64::new(sequence_start));
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

/// Highest frame sequence present in the surviving spool, plus one. Called
/// once at wrapper startup so a restarted process resumes sequence numbers
/// ABOVE everything the previous process wrote (the `logs` emptyDir and its
/// spool survive container restarts; the relay's rotation dedup would drop
/// post-restart frames whose reset sequences land at or below its retained
/// frontier). The spool is bounded by the rotation threshold, so one
/// startup scan is cheap; lines that do not parse as frames are skipped.
fn initial_spool_sequence(spool: &mut File) -> Result<u64, String> {
    spool
        .seek(SeekFrom::Start(0))
        .map_err(|err| format!("failed to seek log spool for sequence scan: {err}"))?;
    let mut max_sequence = 0u64;
    for line in BufReader::new(spool).lines() {
        let Ok(line) = line else {
            break;
        };
        if let Ok(frame) = serde_json::from_str::<serde_json::Value>(&line)
            && let Some(sequence) = frame.get("sequence").and_then(|s| s.as_u64())
            && sequence > max_sequence
        {
            max_sequence = sequence;
        }
    }
    Ok(max_sequence + 1)
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
    // Round-12: carries a lone `\r` peeked at the cap boundary whose `\n`
    // had not yet arrived (pipes may split the CRLF terminator across
    // writes) — see `read_capped_record`.
    let mut pending_cr = false;
    loop {
        buf.clear();
        let record = read_capped_record(&mut reader, &mut buf, &mut pending_cr)
            .map_err(|err| format!("failed to read child {stream}: {err}"))?;
        if record.terminator_only {
            // The previous capped chunk's boundary CRLF was resolved here:
            // its record was already framed and appended — just read on.
            continue;
        }
        if record.len == 0 {
            return Ok(());
        }
        // Strip CR/LF line terminators only from records that actually ended
        // at a newline (or at EOF, preserving the historical cleanup): an
        // artificially capped chunk that happens to end in `\r` carries
        // record content, not a terminator — stripping it would corrupt the
        // encrypted plaintext of the reassembled record.
        if !record.capped {
            while buf.ends_with(b"\n") || buf.ends_with(b"\r") {
                buf.pop();
            }
        }
        // Genuine blank records (a lone `\n`, or `\r\n`) survive the strip as
        // an empty buffer and MUST still be encrypted and appended — they are
        // real log entries the previous implementation preserved. The only
        // other historical source of an empty buffer, the synthetic
        // newline-only read after an exact capped-boundary chunk, can no
        // longer occur: read_capped_record consumes that newline itself.
        // Allocate the sequence number while HOLDING the spool mutex and
        // only after acquiring it: encrypt_log_frame runs here, inside the
        // lock, so a faster forwarder cannot reserve a higher sequence,
        // lose the CPU to its peer, and let the lower sequence reach the
        // spool second. File order therefore always equals sequence order,
        // which is the invariant the relay's rotation dedup relies on
        // (last_seq is a contiguous delivery frontier, only sound when
        // spool position is monotonic in sequence).
        let mut spool = spool
            .lock()
            .map_err(|_| "encrypted log spool lock poisoned".to_string())?;
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
        // Use a single atomic write (line + newline) to avoid partial-frame
        // corruption: if the write succeeds, both frame and newline are on disk;
        // if it fails, neither is, so the log stream stays valid NDJSON.
        let mut frame_with_newline = line;
        frame_with_newline.push(b'\n');
        // A single write_all is not transactional: a short write followed by
        // an error (e.g. ENOSPC) can leave a frame prefix on disk. Snapshot
        // the pre-write file length from the inode (NOT stream_position():
        // the spool is O_APPEND and rotation reopens the handle, so the fd's
        // cached offset can be stale relative to end-of-file) and truncate
        // back to it on any write/flush failure, so the spool never carries
        // a partial NDJSON line that the next successful append would extend
        // into a permanently malformed record.
        let pre_write_len = spool.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        if let Err(err) = spool
            .write_all(&frame_with_newline)
            .and_then(|_| spool.flush())
        {
            if spool.set_len(pre_write_len).is_ok() {
                let _ = spool.seek(SeekFrom::Start(pre_write_len));
            }
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

/// One input record (or capped chunk of one) returned by `read_capped_record`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CappedRecord {
    /// Bytes buffered into `buf` for this record/chunk.
    len: usize,
    /// True when the chunk was cut at `MAX_LOG_RECORD_BYTES` before any
    /// newline was seen — the record continues in the next chunk, so its
    /// final byte is record content, not a line terminator. A chunk whose
    /// boundary terminator was consumed by the reader is also reported
    /// `capped` (the terminator is already gone; the caller must not
    /// strip payload bytes).
    capped: bool,
    /// True when this call produced no record bytes because it only
    /// resolved a parked boundary CR into a consumed terminator (see
    /// `pending_cr`): the terminated record was already returned by the
    /// previous call, so the caller must just call again. Distinct from
    /// EOF, which also returns `len == 0`.
    terminator_only: bool,
}

/// Read one input record from the child, capped at
/// `MAX_LOG_RECORD_BYTES`: a longer line is returned as consecutive
/// chunks (each without a trailing newline except the final chunk), which
/// the caller frames separately — same stream, consecutive sequence
/// numbers, order preserved, no data dropped. The cap bounds both the
/// wrapper's memory and the largest frame the spool can ever see.
/// Implemented via fill_buf/consume rather than `Take::read_until` so the
/// cap boundary is exact (no byte duplication or loss at the limit).
///
/// `pending_cr` carries split-terminator state ACROSS calls (round-12):
/// pipes may deliver the `\r` of a record's CRLF terminator in a
/// different write/fill_buf window than its `\n`. When a chunk fills to
/// exactly the cap and the boundary peek exposes ONLY a lone `\r`, that
/// byte is consumed from the reader and parked in `pending_cr`; the next
/// call resolves it — `\n` next means the pair was the record's
/// terminator (consumed, nothing returned), anything else means the `\r`
/// was record content (round-5) and is prepended to the next chunk.
fn read_capped_record<R: BufRead>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    pending_cr: &mut bool,
) -> std::io::Result<CappedRecord> {
    buf.clear();
    // Round-12: resolve a CR parked at the previous call's cap boundary.
    // It was already consumed from the reader, so decide from the next
    // visible byte only.
    if *pending_cr {
        *pending_cr = false;
        let peek = reader.fill_buf()?;
        if let Some(b'\n') = peek.first() {
            reader.consume(1);
            // The parked `\r` plus this `\n` were the capped record's
            // terminator. That record was returned by the previous call
            // (as a capped chunk that has already been framed and
            // appended); the terminator is consumed here with no record
            // bytes — signal the caller to just read on.
            return Ok(CappedRecord {
                len: 0,
                capped: false,
                terminator_only: true,
            });
        }
        // EOF or a non-LF byte: the parked `\r` was record CONTENT.
        // Prepend it so the chunk below starts with it.
        buf.push(b'\r');
    }
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(CappedRecord {
                len: buf.len(),
                capped: false,
                terminator_only: false,
            });
        }
        let remaining = MAX_LOG_RECORD_BYTES - buf.len();
        let search = &available[..available.len().min(remaining)];
        match search.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&search[..=i]);
                reader.consume(i + 1);
                return Ok(CappedRecord {
                    len: buf.len(),
                    capped: false,
                    terminator_only: false,
                });
            }
            None => {
                buf.extend_from_slice(search);
                let n = search.len();
                reader.consume(n);
                if buf.len() == MAX_LOG_RECORD_BYTES {
                    // If the record's terminator lands EXACTLY at the cap
                    // boundary, consume it here instead of letting the
                    // next call return it as a lone-terminator record: the
                    // caller's terminator strip would leave an empty
                    // plaintext that still gets encrypted and appended,
                    // fabricating an empty log frame after every record
                    // whose length is an exact multiple of the cap. Both
                    // terminator forms are recognized — `\n` and `\r\n`
                    // (round-11). Consuming the boundary terminator keeps
                    // the chunk marked `capped` (its last byte is record
                    // content, not a terminator — the round-5 strip
                    // protection), because the caller's strip-all-CR/LF
                    // would otherwise eat a legitimate content `\r` that
                    // happens to sit at payload position cap-1 (latent
                    // hazard in the round-11 shape). At EOF there is no
                    // terminator to consume and the chunk also stays
                    // `capped`. A lone `\r` with NO following byte yet is
                    // undecidable (round-12): consume it and park it in
                    // `pending_cr` for the next call to resolve.
                    let peek = reader.fill_buf()?;
                    match peek.first() {
                        Some(b'\n') => {
                            reader.consume(1);
                            // Round-13 review P2: a CRLF-terminated record
                            // with exactly cap-1 payload bytes fills the
                            // buffer with the terminator's `\r` (the `\n`
                            // sits just past the cap window). The buffered
                            // `\r` plus this consumed `\n` IS the two-byte
                            // terminator — pop exactly that one byte,
                            // matching what the short-record path's strip
                            // does at every other record length. A content
                            // `\r` ADJACENT to the terminator's CR (a
                            // buffered `\r\r` before this LF) keeps its
                            // content byte: only the terminator's CR goes,
                            // the same content-preservation policy the
                            // consume-`\r\n` arm below applies to a
                            // payload-ending CR (round-5/round-12).
                            // (`\rX` content is untouched — that case
                            // never reaches this arm: the `\r` would be
                            // followed by `X`, not `\n`.)
                            if buf.last() == Some(&b'\r') {
                                buf.pop();
                            }
                        }
                        Some(b'\r') if peek.get(1) == Some(&b'\n') => {
                            reader.consume(2);
                        }
                        Some(b'\r') if peek.len() == 1 => {
                            reader.consume(1);
                            *pending_cr = true;
                        }
                        _ => {}
                    }
                    return Ok(CappedRecord {
                        len: buf.len(),
                        capped: true,
                        terminator_only: false,
                    });
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
    // 0o600 (#137): the started dir is group-writable (0o2770) so sibling
    // containers can create their own sentinels; the sentinel itself must
    // stay owner-writable only, or a same-group process could overwrite
    // another container's record.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(&sentinel)
        .map_err(|err| format!("failed to write sentinel {}: {err}", sentinel.display()))?;
    // Normalize ownership to the writer's own uid:gid (#137). The started
    // dir is setgid, so a fresh file inherits the directory's group; the
    // reader (enclava-init) validates the sentinel's owner gid against the
    // container's expected identity, and this fchown is what makes that
    // hold for every writer. fd-based, so it cannot be redirected by a
    // path race. Note: chowning to the process's own ids is permitted for
    // a fresh or self-owned inode; a pre-created inode owned by another
    // uid fails with EPERM here, which is the safe outcome (#175 review).
    let (uid, gid) = current_uid_gid()?;
    // SAFETY: plain libc wrappers around the process's own ids and an
    // owned fd; no path traversal is involved.
    unsafe {
        if nix::libc::fchown(
            file.as_raw_fd(),
            uid as nix::libc::uid_t,
            gid as nix::libc::gid_t,
        ) != 0
        {
            return Err(format!(
                "failed to own sentinel {}: {}",
                sentinel.display(),
                std::io::Error::last_os_error()
            ));
        }
        // `.mode(0o600)` above only applies when the file is created; a
        // reused inode (container restart with the dir still present)
        // keeps its previous mode. fchmod the fd so the owner-only
        // invariant holds on reopen too (#175 review).
        if nix::libc::fchmod(file.as_raw_fd(), 0o600) != 0 {
            return Err(format!(
                "failed to set sentinel {} mode: {}",
                sentinel.display(),
                std::io::Error::last_os_error()
            ));
        }
    }
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
    fn rejects_record_injection_sentinel_names() {
        // Names land in the sentinel key=value record: newlines inject
        // lines, '=' corrupts keys, and other control characters have no
        // legitimate use (#137).
        for name in [
            "web\npid=1",
            "web\n",
            "con=tainer",
            "web\r",
            "web\ttab",
            "web\0nul",
        ] {
            assert!(validate_sentinel_name(name).is_err(), "{name:?}");
        }
        assert!(validate_sentinel_name("tenant-ingress").is_ok());
    }

    #[test]
    fn signal_started_writes_owner_only_sentinel() {
        let dir = unique_dir();
        signal_started(&dir, "web").unwrap();
        let mode = fs::metadata(dir.join("web")).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "sentinel must be owner-writable only (group writes would let a same-group process overwrite it)"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn signal_started_renormalizes_reused_sentinel_mode() {
        // A reused inode (container restart, started dir still populated)
        // can carry a group-writable mode; `.mode(0o600)` only applies at
        // creation, so signal_started must fchmod the fd back to 0o600
        // (#175 review).
        use std::os::unix::fs::PermissionsExt;
        let dir = unique_dir();
        fs::create_dir_all(&dir).unwrap();
        let sentinel = dir.join("web");
        fs::write(&sentinel, "stale").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o664)).unwrap();
        signal_started(&dir, "web").unwrap();
        let mode = fs::metadata(&sentinel).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "reused sentinel must be re-chmodded to owner-only"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signal_started_normalizes_sentinel_gid_under_setgid_dir() {
        // Model the deployed started dir: setgid (0o2770) with a group the
        // writer is a member of. A freshly created file inherits the dir's
        // gid; the sentinel must still end up owned by the writer's own
        // uid:gid because enclava-init validates the owner gid (#137).
        let dir = unique_dir();
        fs::create_dir_all(&dir).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let uid = unsafe { nix::libc::getuid() } as u32;
            let primary_gid = unsafe { nix::libc::getgid() } as u32;
            // Prefer a supplemental group distinct from the primary gid —
            // that models the deployed started dir most faithfully. When
            // none exists (minimal containers), fall back so the test
            // always exercises signal_started instead of skipping: root
            // can adopt any arbitrary gid, and otherwise the primary gid
            // still drives the file through the setgid-inherit + re-own
            // path, just with a weaker pre-state.
            let dir_gid = supplemental_gid()
                .filter(|g| *g != primary_gid)
                .or({
                    if uid == 0 {
                        Some(65534) // nobody: any gid works for root
                    } else {
                        None
                    }
                })
                .unwrap_or(primary_gid);
            let strong_case = dir_gid != primary_gid;
            if !strong_case {
                eprintln!(
                    "NOTE: no supplemental group available; setgid-inherit gid \
                     normalization tested only in the weak form (dir gid == \
                     primary gid, so inheritance alone cannot detect a \
                     missing fchown). Run the suite with a supplemental \
                     group or as root for full coverage."
                );
            }
            let c_path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).unwrap();
            let rc = unsafe { nix::libc::chown(c_path.as_ptr(), uid, dir_gid) };
            assert_eq!(rc, 0, "failed to set up test dir group");
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o2770)).unwrap();

            signal_started(&dir, "web").unwrap();

            let meta = fs::metadata(dir.join("web")).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o600);
            assert_eq!(
                (meta.uid(), meta.gid()),
                (uid, primary_gid),
                "sentinel must be re-owned to the writer's uid:gid despite the setgid dir"
            );
            if strong_case {
                assert_ne!(
                    meta.gid(),
                    dir_gid,
                    "setgid dir must not leave its group on the sentinel"
                );
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    fn supplemental_gid() -> Option<u32> {
        // Supplemental groups of the test process; one distinct from the
        // primary gid models the deployed started dir's group.
        let path = std::path::Path::new("/proc/self/status");
        let status = fs::read_to_string(path).ok()?;
        let line = status.lines().find(|l| l.starts_with("Groups:"))?;
        line.split_whitespace()
            .skip(1)
            .filter_map(|g| g.parse::<u32>().ok())
            .find(|g| *g != unsafe { nix::libc::getgid() } as u32)
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

    #[cfg(feature = "prod-strict")]
    #[test]
    fn prod_strict_ignores_env_overrides() {
        assert!(env_override_for(Some(OsString::from("/tmp/planted"))).is_none());
        assert!(env_override_for(None).is_none());
    }

    #[cfg(not(feature = "prod-strict"))]
    #[test]
    fn dev_builds_honor_env_overrides() {
        assert_eq!(
            env_override_for(Some(OsString::from("/tmp/override"))),
            Some(OsString::from("/tmp/override"))
        );
        assert!(env_override_for(None).is_none());
    }

    #[test]
    #[cfg(not(feature = "prod-strict"))]
    fn prod_strict_pins_readiness_paths_to_compiled_defaults() {
        // This test verifies that prod-strict builds don't read certain env vars directly.
        // It runs in dev builds but checks the source for patterns that should not exist
        // in prod-strict.
        //
        // Note: The log encryption key checks are intentionally omitted here because
        // encrypted_log_config_from_raw_env is already gated with #[cfg(not(feature = "prod-strict"))],
        // so the env::var calls exist in the source but are compiled out in prod-strict.
        let source = include_str!("main.rs").replace("\r\n", "\n");
        for var in ["ENCLAVA_INIT_READY_FILE", "ENCLAVA_STARTED_DIR"] {
            assert!(
                !source.contains(&format!("env::var_os(\"{var}\")")),
                "{var} must not be read via env::var_os"
            );
            assert!(
                source.contains(&format!("env_override(\"{var}\")")),
                "{var} must resolve through env_override"
            );
        }
    }

    #[test]
    #[cfg(feature = "prod-strict")]
    fn prod_strict_uses_handoff_for_log_encryption() {
        // Verify prod-strict reads log encryption from handoff file, not env.
        let source = include_str!("main.rs").replace("\r\n", "\n");
        assert!(
            source.contains("LOG_ENCRYPTION_HANDOFF_FILE"),
            "prod-strict must read log encryption from handoff file"
        );
        // Note: We don't check that encrypted_log_config_from_raw_env is absent because
        // it's gated with #[cfg(not(feature = "prod-strict"))] in the source, which is correct.
        // The function exists in dev builds but is compiled out in prod-strict.
    }

    #[cfg(feature = "prod-strict")]
    fn unique_handoff_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "enclava-wait-exec-handoff-{}-{}-{}.json",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    /// Serializes tests that mutate process env (Rust runs tests on parallel
    /// threads; set_var/remove_var on shared env would otherwise race).
    #[cfg(feature = "prod-strict")]
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    #[cfg(feature = "prod-strict")]
    fn handoff_marker_disables_encrypted_logging() {
        let path = unique_handoff_path("marker");
        fs::write(&path, "{\"disabled\": true}").unwrap();
        assert!(
            encrypted_log_config_from_handoff_at(&path)
                .unwrap()
                .is_none()
        );
        fs::remove_file(&path).unwrap();
    }

    #[test]
    #[cfg(feature = "prod-strict")]
    fn handoff_absent_disables_encrypted_logging() {
        let path = unique_handoff_path("absent");
        assert!(
            encrypted_log_config_from_handoff_at(&path)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[cfg(feature = "prod-strict")]
    fn handoff_parses_claim_and_env_deployment_label() {
        let _guard = ENV_LOCK.lock().unwrap();
        let keypair = enclava_common::log_encryption::generate_log_keypair();
        let path = unique_handoff_path("claim");
        let claim = serde_json::json!({
            "algorithm": enclava_common::log_encryption::LOG_ENCRYPTION_ALGORITHM.to_string(),
            "key_id": "logs-prod".to_string(),
            "public_key_base64url": keypair.public_key_base64url.clone(),
            "public_key_sha256": keypair.public_key_sha256.clone(),
            "org_id": "acme".to_string(),
            "app_name": "secure-app".to_string(),
        });
        fs::write(&path, claim.to_string()).unwrap();
        unsafe {
            env::set_var(
                "ENCLAVA_LOG_DEPLOYMENT_ID",
                "11111111-1111-1111-1111-111111111111",
            );
            env::set_var("ENCLAVA_CONTAINER_NAME", "web");
        }
        let config = encrypted_log_config_from_handoff_at(&path)
            .unwrap()
            .expect("handoff engages encrypted logging");
        assert_eq!(config.context.org_id, "acme");
        assert_eq!(config.context.app_name, "secure-app");
        assert_eq!(
            config.context.deployment_id,
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(config.container, "web");
        unsafe {
            env::remove_var("ENCLAVA_LOG_DEPLOYMENT_ID");
            env::remove_var("ENCLAVA_CONTAINER_NAME");
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    #[cfg(feature = "prod-strict")]
    fn handoff_with_unsupported_algorithm_fails() {
        let keypair = enclava_common::log_encryption::generate_log_keypair();
        let path = unique_handoff_path("badalg");
        let claim = serde_json::json!({
            "algorithm": "x25519-xsalsa20-poly1305".to_string(),
            "key_id": "logs-prod".to_string(),
            "public_key_base64url": keypair.public_key_base64url.clone(),
            "public_key_sha256": keypair.public_key_sha256.clone(),
            "org_id": "acme".to_string(),
            "app_name": "secure-app".to_string(),
        });
        fs::write(&path, claim.to_string()).unwrap();
        unsafe {
            env::set_var("ENCLAVA_LOG_DEPLOYMENT_ID", "deploy-123");
            env::set_var("ENCLAVA_CONTAINER_NAME", "web");
        }
        let err = encrypted_log_config_from_handoff_at(&path).unwrap_err();
        assert!(err.contains("unsupported algorithm"), "got: {err}");
        unsafe {
            env::remove_var("ENCLAVA_LOG_DEPLOYMENT_ID");
            env::remove_var("ENCLAVA_CONTAINER_NAME");
        }
        fs::remove_file(&path).unwrap();
    }

    #[test]
    #[cfg(feature = "prod-strict")]
    fn handoff_without_deployment_env_label_fails() {
        let _guard = ENV_LOCK.lock().unwrap();
        let keypair = enclava_common::log_encryption::generate_log_keypair();
        let path = unique_handoff_path("nolabel");
        let claim = serde_json::json!({
            "algorithm": enclava_common::log_encryption::LOG_ENCRYPTION_ALGORITHM.to_string(),
            "key_id": "logs-prod".to_string(),
            "public_key_base64url": keypair.public_key_base64url.clone(),
            "public_key_sha256": keypair.public_key_sha256.clone(),
            "org_id": "acme".to_string(),
            "app_name": "secure-app".to_string(),
        });
        fs::write(&path, claim.to_string()).unwrap();
        unsafe {
            env::remove_var("ENCLAVA_LOG_DEPLOYMENT_ID");
            env::set_var("ENCLAVA_CONTAINER_NAME", "web");
        }
        let err = encrypted_log_config_from_handoff_at(&path).unwrap_err();
        assert!(err.contains("ENCLAVA_LOG_DEPLOYMENT_ID"), "got: {err}");
        unsafe {
            env::remove_var("ENCLAVA_CONTAINER_NAME");
        }
        fs::remove_file(&path).unwrap();
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
    #[cfg(not(feature = "prod-strict"))]
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

    /// Round-6 review finding: the relay's rotation dedup treats the max
    /// delivered sequence as a contiguous frontier, which is only sound when
    /// spool file order is monotonic in sequence order. The sequence must
    /// therefore be allocated (and the frame encrypted) while HOLDING the
    /// spool mutex — previously `fetch_add` ran before the lock, so a
    /// forwarder could reserve a higher sequence, lose the CPU, and let its
    /// peer's lower sequence reach the file first; a later rotation resync
    /// would then drop that unseen lower frame as "already delivered".
    /// This test drives both forwarder threads concurrently and pins that
    /// the spool's sequence numbers are strictly increasing in file order.
    #[test]
    fn concurrent_forwarders_keep_spool_order_monotonic_in_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let spool = Arc::new(Mutex::new(open_log_spool(&path).unwrap()));

        let keypair = enclava_common::log_encryption::generate_log_keypair();
        let recipient = validate_public_key(
            "logs-prod",
            &keypair.public_key_base64url,
            &keypair.public_key_sha256,
        )
        .unwrap();
        let logs = EncryptedLogConfig {
            recipient,
            context: enclava_common::log_encryption::LogFrameContext {
                org_id: "org-123".to_string(),
                app_name: "secure-app".to_string(),
                deployment_id: "deploy-123".to_string(),
            },
            spool_path: path.clone(),
            container: "web".to_string(),
        };

        let sequence = Arc::new(AtomicU64::new(1));
        let handles: Vec<_> = ["stdout", "stderr"]
            .iter()
            .map(|stream| {
                let input = (0..400)
                    .map(|i| format!("{stream} record {i} {}\n", "x".repeat(i % 97)))
                    .collect::<String>();
                let reader = std::io::Cursor::new(input);
                let spool = Arc::clone(&spool);
                let sequence = Arc::clone(&sequence);
                let logs = logs.clone();
                let stream: &'static str = match *stream {
                    "stdout" => "stdout",
                    _ => "stderr",
                };
                thread::spawn(move || {
                    forward_encrypted_logs(reader, stream, &logs, &spool, &sequence).unwrap()
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("forwarder panicked");
        }

        let content = fs::read_to_string(&path).unwrap();
        let mut prev = 0u64;
        let mut count = 0u64;
        for line in content.lines() {
            let frame: serde_json::Value =
                serde_json::from_str(line).expect("spool must contain valid NDJSON frames");
            let seq = frame["sequence"].as_u64().expect("sequence is plaintext");
            assert!(
                seq > prev,
                "spool order must be monotonic in sequence: {seq} followed {prev}"
            );
            prev = seq;
            count += 1;
        }
        assert_eq!(count, 800, "both streams' 400 frames must be on disk");
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
        let mut pending_cr = false;

        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert_eq!(first.len(), MAX_LOG_RECORD_BYTES);
        assert!(!first.ends_with(b"\n"), "capped chunk has no newline yet");
        assert!(r1.capped, "chunk hit the cap before any newline");

        // The remainder of the same line (up to its newline) is the next
        // record — content is preserved across the split, nothing dropped.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        let expected_remainder = format!("{}BCDEFGHIJKLMNOPQRSTUVWXYZ\n", "a".repeat(8));
        assert_eq!(second, expected_remainder.as_bytes());
        assert!(r2.len > 0);
        assert!(!r2.capped);

        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(third, b"second line\n");
        assert!(r3.len > 0);
        assert!(!r3.capped);

        let mut fourth = Vec::new();
        let r4 = read_capped_record(&mut reader, &mut fourth, &mut pending_cr).unwrap();
        assert_eq!(r4.len, 0);
        assert!(fourth.is_empty());

        // Reassembled content equals the input minus the record split.
        let mut reassembled = first.clone();
        reassembled.extend_from_slice(&second);
        reassembled.extend_from_slice(&third);
        assert_eq!(reassembled, input.as_bytes());
    }

    /// Genuine blank records must be preserved as empty-plaintext frames;
    /// a capped-boundary newline must not fabricate one. Round-7 finding.
    #[test]
    fn blank_records_are_preserved_and_boundary_newlines_fabricate_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let spool = Arc::new(Mutex::new(open_log_spool(&path).unwrap()));

        let keypair = enclava_common::log_encryption::generate_log_keypair();
        let recipient = validate_public_key(
            "logs-prod",
            &keypair.public_key_base64url,
            &keypair.public_key_sha256,
        )
        .unwrap();
        let logs = EncryptedLogConfig {
            recipient,
            context: enclava_common::log_encryption::LogFrameContext {
                org_id: "org-123".to_string(),
                app_name: "secure-app".to_string(),
                deployment_id: "deploy-123".to_string(),
            },
            spool_path: path.clone(),
            container: "web".to_string(),
        };

        let sequence = Arc::new(AtomicU64::new(1));
        // `before`, one blank line, `after`, then a record whose length is an
        // EXACT multiple of the cap followed by `next`: the boundary newline
        // must be consumed by the reader, not become an empty frame.
        let mut input = "before\n\nafter\n".to_string();
        input.push_str(&"a".repeat(MAX_LOG_RECORD_BYTES));
        input.push_str("\nnext\n");
        let reader = std::io::Cursor::new(input);
        forward_encrypted_logs(reader, "stdout", &logs, &spool, &sequence).unwrap();

        // Exactly 5 frames: before, blank, after, capped record, next — the
        // genuine blank record preserved, no fabricated empty frame at the cap.
        let content = fs::read_to_string(&path).unwrap();
        let frames: Vec<&str> = content.lines().collect();
        assert_eq!(
            frames.len(),
            5,
            "before, blank, after, capped record, next — and no fabricated empty frame"
        );
    }

    /// Round-11 review finding (P2): a record of EXACTLY
    /// MAX_LOG_RECORD_BYTES followed by `\r\n` must have the two-byte
    /// terminator consumed at the boundary. Previously the peek saw `\r`
    /// (not `\n`), returned the chunk as capped, and the next read
    /// returned only `\r\n` — stripped to an empty buffer and encrypted as
    /// a fabricated blank frame between the capped record and `next`.
    /// Round-12: the chunk stays `capped: true` even though its terminator
    /// was consumed — the flag means "do not strip" and the payload's last
    /// byte may be a content `\r` that the strip would corrupt.
    #[test]
    fn read_capped_record_consumes_crlf_at_chunk_boundary() {
        let payload = "a".repeat(MAX_LOG_RECORD_BYTES);
        let input = format!("{payload}\r\nnext\r\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;

        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert_eq!(first, payload.as_bytes());
        assert!(
            r1.capped,
            "boundary-terminated chunk stays capped so the caller never strips payload bytes"
        );

        // The next record is `next`, not a leftover `\r\n` terminator.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert_eq!(second, b"next\r\n");
        assert!(!r2.capped);

        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(r3.len, 0);
        assert!(third.is_empty());
    }

    /// Round-5 review finding: a `\r` that happens to sit exactly at an
    /// artificial chunk boundary is record content, not a line terminator.
    /// `read_capped_record` must report the chunk as capped so the caller
    /// does not strip that byte (previously the trailing-CR cleanup
    /// corrupted the encrypted plaintext of the reassembled record).
    #[test]
    fn read_capped_record_marks_cr_at_chunk_boundary_as_content() {
        // 262,143 ordinary bytes followed by `\rX\n`: byte at index
        // MAX_LOG_RECORD_BYTES - 1 (the chunk's last byte) is the `\r`.
        let prefix = "a".repeat(MAX_LOG_RECORD_BYTES - 1);
        let input = format!("{prefix}\rX\nsecond line\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;

        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert!(r1.capped, "chunk must be marked capped so CR survives");
        assert_eq!(first.last(), Some(&b'\r'), "boundary CR is record content");

        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert_eq!(second, b"X\n");
        assert!(!r2.capped);

        let mut third = Vec::new();
        read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(third, b"second line\n");

        // Full record reassembly preserves the CR byte.
        let mut reassembled = first.clone();
        reassembled.extend_from_slice(&second);
        reassembled.extend_from_slice(&third);
        assert_eq!(reassembled, input.as_bytes());
    }

    /// Cross-restart sequence monotonicity (round-8 review finding): the
    /// spool on the shared `logs` emptyDir survives a container restart,
    /// so a restarted wrapper must resume ABOVE the highest sequence the
    /// previous process wrote — the relay's rotation dedup keeps the max
    /// delivered sequence as its frontier and would silently drop every
    /// post-restart frame whose reset counter lands at or below it.
    #[test]
    fn initial_spool_sequence_resumes_above_surviving_frames() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        let frame = |seq: u64| format!(r#"{{"version":"enclava-log-frame-v1","sequence":{seq}}}"#);
        // A surviving spool whose highest frame is 417 (rotation retains
        // only a tail, so the lowest present sequence is not 1).
        let body: String = (400..=417).map(|s| format!("{}\n", frame(s))).collect();
        std::fs::write(&path, body).unwrap();
        let mut spool = open_log_spool(&path).unwrap();
        assert_eq!(initial_spool_sequence(&mut spool).unwrap(), 418);

        // An empty spool resumes at 1.
        std::fs::write(&path, "").unwrap();
        let mut spool = open_log_spool(&path).unwrap();
        assert_eq!(initial_spool_sequence(&mut spool).unwrap(), 1);

        // A spool with no parseable frames resumes at 1.
        std::fs::write(&path, "not-json\nalso not json\n").unwrap();
        let mut spool = open_log_spool(&path).unwrap();
        assert_eq!(initial_spool_sequence(&mut spool).unwrap(), 1);
    }

    /// Round-11 review finding (P2): a record whose payload is EXACTLY
    /// MAX_LOG_RECORD_BYTES followed by `\r\n` — the boundary peek sees
    /// `\r` (not `\n`), and previously fell through as a capped chunk whose
    /// next read returned only the `\r\n` remainder. Terminator stripping
    /// reduced that remainder to an empty buffer which the caller still
    /// encrypted, fabricating a blank log frame. The two-byte CRLF
    /// terminator must be recognized and consumed at the boundary.
    #[test]
    fn read_capped_record_consumes_crlf_at_exact_chunk_boundary() {
        let payload = "a".repeat(MAX_LOG_RECORD_BYTES);
        let input = format!("{payload}\r\nnext\r\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;

        // First read: the full cap of payload with the boundary CRLF
        // consumed as the record terminator. Round-12: the chunk is still
        // `capped` — that flag tells the caller "do not strip", and the
        // payload's last byte may be legitimate content (a `\r` at
        // position cap-1 would previously have been eaten by the strip).
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert!(
            r1.capped,
            "boundary-terminated chunk stays capped (no strip)"
        );
        assert_eq!(first.as_slice(), payload.as_bytes());

        // Second read is `next\r\n` — NOT the orphaned `\r\n` remainder.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert_eq!(
            second, b"next\r\n",
            "no fabricated blank frame before `next`"
        );
        assert!(!r2.capped);

        // EOF.
        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(r3.len, 0);
        assert!(third.is_empty());
    }

    /// A lone `\r` at the cap boundary (not followed by `\n`) is record
    /// content, not a terminator — the chunk stays capped (round-5 rule
    /// still holds under the round-11 CRLF handling).
    #[test]
    fn read_capped_record_lone_cr_at_boundary_stays_capped() {
        let prefix = "a".repeat(MAX_LOG_RECORD_BYTES - 1);
        let input = format!("{prefix}\rX\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert!(r1.capped, "lone CR at the boundary is content, not CRLF");
        assert_eq!(first.last(), Some(&b'\r'));
    }

    /// A `BufRead` whose fill_buf windows are exactly the given parts —
    /// models a pipe that splits writes at arbitrary boundaries (far
    /// coarser control than BufReader's fixed 8 KiB coalescing).
    struct ChunkedReader {
        parts: std::collections::VecDeque<Vec<u8>>,
    }
    impl std::io::Read for ChunkedReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let n = self.fill_buf()?.len().min(out.len());
            out[..n].copy_from_slice(&self.fill_buf()?[..n]);
            self.consume(n);
            Ok(n)
        }
    }
    impl std::io::BufRead for ChunkedReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            while self.parts.front().is_some_and(Vec::is_empty) {
                self.parts.pop_front();
            }
            Ok(self.parts.front().map(|v| v.as_slice()).unwrap_or(&[]))
        }
        fn consume(&mut self, n: usize) {
            if let Some(front) = self.parts.front_mut() {
                front.drain(..n);
            }
        }
    }

    /// Round-12 review finding (P2, split CRLF at the record cap): when a
    /// child writes exactly MAX_LOG_RECORD_BYTES of payload and the pipe
    /// exposes the trailing `\r` before the `\n`, the boundary peek sees
    /// only a lone `\r` and cannot classify it. The pending-CR state must
    /// defer the decision to the next call, which resolves the pair into
    /// a consumed terminator — no fabricated blank frame and no orphaned
    /// `\r\n` record between the capped chunk and `next`.
    #[test]
    fn read_capped_record_handles_split_crlf_at_cap() {
        let payload = "a".repeat(MAX_LOG_RECORD_BYTES);
        // Windows: exactly the cap of payload, then the lone `\r`, then
        // the `\n` and the next record — a pipe that split the CRLF
        // terminator across writes.
        let mut reader = ChunkedReader {
            parts: [
                payload.clone().into_bytes(),
                b"\r".to_vec(),
                b"\nnext\n".to_vec(),
            ]
            .into_iter()
            .collect(),
        };

        // First read: the capped chunk. The lone `\r` is parked as
        // pending state (undecidable — it could be content per round-5),
        // NOT consumed into the record.
        let mut pending_cr = false;
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert!(r1.capped, "undecided boundary CR keeps the chunk capped");
        assert!(pending_cr, "boundary CR is preserved as pending state");
        assert_eq!(first.as_slice(), payload.as_bytes());
        assert!(
            !first.ends_with(b"\r"),
            "the CR byte is not record content here"
        );

        // Second read resolves the pending CR into the CRLF terminator: no
        // record bytes — the caller just reads on. Previously this call
        // returned the orphaned `\r\n`, which the caller's strip emptied
        // and encrypted as a bogus blank frame between the capped record
        // and `next`.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert!(r2.terminator_only, "pending CR resolves into consumed CRLF");
        assert!(second.is_empty());
        assert!(!pending_cr);

        // The stream continues with `next` — no `\r\n` remainder.
        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(third.as_slice(), b"next\n");
        assert!(!r3.capped);
        assert!(!r3.terminator_only);

        // EOF.
        let mut fourth = Vec::new();
        let r4 = read_capped_record(&mut reader, &mut fourth, &mut pending_cr).unwrap();
        assert_eq!(r4.len, 0);
        assert!(!r4.terminator_only);
    }

    /// Round-5 rule under the round-12 pending-CR machinery: a lone `\r`
    /// parked at the boundary that turns out to be CONTENT (the next byte
    /// is not `\n`) must survive verbatim at the head of the next chunk —
    /// the pending state must neither swallow it nor duplicate it.
    #[test]
    fn read_capped_record_pending_cr_resolved_as_content() {
        let payload = "a".repeat(MAX_LOG_RECORD_BYTES);
        let input = format!("{payload}\rX\nsecond\n");
        let mut reader = ChunkedReader {
            parts: [
                payload.clone().into_bytes(),
                b"\r".to_vec(),
                b"X\nsecond\n".to_vec(),
            ]
            .into_iter()
            .collect(),
        };

        let mut pending_cr = false;
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES);
        assert!(r1.capped, "undecided CR keeps the chunk capped");
        assert_eq!(first.as_slice(), payload.as_bytes());
        assert!(pending_cr);

        // Next window exposes `X...`: the parked CR was content and is
        // prepended to this chunk — nothing swallowed, nothing replayed.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert!(!r2.terminator_only);
        assert_eq!(second.as_slice(), b"\rX\n");

        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(third.as_slice(), b"second\n");
        assert!(!r3.terminator_only);

        // Full reassembly preserves the CR byte exactly once.
        let mut reassembled = first.clone();
        reassembled.extend_from_slice(&second);
        reassembled.extend_from_slice(&third);
        assert_eq!(reassembled, input.as_bytes());
    }

    /// Round-13 review P2: a CRLF-terminated record with exactly
    /// cap-1 payload bytes fills the capped buffer with the terminator's
    /// `\r` and leaves the `\n` just past the cap window. The buffered
    /// `\r` plus the consumed `\n` are the two-byte terminator: the `\r`
    /// must be popped, matching what the short-record strip does at every
    /// other record length (previously the `\r` was encrypted as record
    /// content, so CLI output differed for the same record at cap-1).
    #[test]
    fn read_capped_record_strips_crlf_when_cr_fills_last_cap_byte() {
        let payload = "a".repeat(MAX_LOG_RECORD_BYTES - 1);
        let input = format!("{payload}\r\nnext\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        // The buffer held cap bytes (payload + the terminator's CR) and
        // the pop removed the CR: the record is the cap-1 payload bytes.
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES - 1);
        // The chunk stays `capped` (do-not-strip by the caller) — the
        // terminator was already removed by read_capped_record itself.
        assert!(r1.capped);
        assert_eq!(first.as_slice(), payload.as_bytes());
        assert_eq!(first.last(), Some(&b'a'), "the terminator CR is stripped");

        // The next record is `next` — no orphaned terminator bytes.
        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert_eq!(second.as_slice(), b"next\n");
        assert!(!r2.capped);

        // EOF.
        let mut third = Vec::new();
        let r3 = read_capped_record(&mut reader, &mut third, &mut pending_cr).unwrap();
        assert_eq!(r3.len, 0);
    }

    /// The boundary-LF pop removes exactly ONE buffered byte — the
    /// terminator's CR. A record whose CONTENT ends in a CR right before a
    /// CRLF terminator landing at the boundary keeps that content CR, the
    /// same content-preservation policy the consume-`\r\n`-at-boundary arm
    /// pins (round-12): the terminator's own CR is consumed, everything
    /// before it is record content.
    #[test]
    fn read_capped_record_keeps_content_cr_before_boundary_lf() {
        // Content is cap-1 bytes ending in `\r`; the terminator CRLF
        // straddles the cap window: its `\r` is the buffer's last byte,
        // its `\n` is the boundary peek.
        let payload = format!("{}\r", "a".repeat(MAX_LOG_RECORD_BYTES - 2));
        let input = format!("{payload}\r\nnext\n");
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;
        let mut first = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut first, &mut pending_cr).unwrap();
        assert_eq!(r1.len, MAX_LOG_RECORD_BYTES - 1);
        assert!(r1.capped);
        assert_eq!(
            first.as_slice(),
            payload.as_bytes(),
            "the terminator's CR is popped, the content CR survives"
        );

        let mut second = Vec::new();
        let r2 = read_capped_record(&mut reader, &mut second, &mut pending_cr).unwrap();
        assert_eq!(second.as_slice(), b"next\n");
        assert!(!r2.capped);
    }

    /// CR/LF terminators are still stripped from records that ended at a
    /// real newline (or EOF) — the historical cleanup behavior.
    #[test]
    fn read_capped_record_strips_terminators_on_complete_records() {
        let input = "line-one\nline-two\r\nline-three\r\n";
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut pending_cr = false;
        let mut buf = Vec::new();
        let r1 = read_capped_record(&mut reader, &mut buf, &mut pending_cr).unwrap();
        assert_eq!(buf, b"line-one\n");
        assert!(!r1.capped);
        let r2 = read_capped_record(&mut reader, &mut buf, &mut pending_cr).unwrap();
        assert_eq!(buf, b"line-two\r\n");
        assert!(!r2.capped);
        let r3 = read_capped_record(&mut reader, &mut buf, &mut pending_cr).unwrap();
        assert_eq!(buf, b"line-three\r\n");
        assert!(!r3.capped);
    }
}
