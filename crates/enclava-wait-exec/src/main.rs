use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::thread;
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use enclava_common::log_encryption::{
    LogEncryptionPublicKey, encrypt_log_frame, validate_public_key,
};

const DEFAULT_STARTED_DIR: &str = "/run/enclava/containers";
const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";
const DEFAULT_STARTUP: &str = "/startup/startup.sh";
const DEFAULT_LOG_SPOOL_DIR: &str = "/run/enclava-logs";
const STARTED_DIR_MODE: u32 = 0o2770;
const O_NOFOLLOW: i32 = 0o400000;

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
    let err = Command::new(&program).args(&args).exec();
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

#[derive(Clone)]
struct EncryptedLogConfig {
    recipient: LogEncryptionPublicKey,
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
        spool_path,
        container,
    }))
}

fn run_with_encrypted_logs(
    program: OsString,
    args: Vec<OsString>,
    logs: EncryptedLogConfig,
) -> Result<i32, String> {
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
    for result in [stdout_thread.join(), stderr_thread.join()] {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => eprintln!("enclava-wait-exec encrypted log forwarding failed: {err}"),
            Err(_) => eprintln!("enclava-wait-exec encrypted log forwarding panicked"),
        }
    }
    Ok(status.code().unwrap_or(1))
}

fn open_log_spool(path: &Path) -> Result<File, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create log spool dir {}: {err}", parent.display()))?;
    }
    OpenOptions::new()
        .create(true)
        .append(true)
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
    loop {
        buf.clear();
        let n = reader
            .read_until(b'\n', &mut buf)
            .map_err(|err| format!("failed to read child {stream}: {err}"))?;
        if n == 0 {
            return Ok(());
        }
        while buf.ends_with(b"\n") || buf.ends_with(b"\r") {
            buf.pop();
        }
        let frame = encrypt_log_frame(
            &logs.recipient,
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
        spool
            .write_all(&line)
            .and_then(|_| spool.write_all(b"\n"))
            .and_then(|_| spool.flush())
            .map_err(|err| format!("failed to write encrypted log spool: {err}"))?;
    }
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
}
