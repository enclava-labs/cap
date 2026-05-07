use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::thread;
use std::time::Duration;

const DEFAULT_STARTED_DIR: &str = "/run/enclava/containers";
const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";
const DEFAULT_STARTUP: &str = "/startup/startup.sh";

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

fn signal_started(started_dir: &Path, name: &str) -> Result<(), String> {
    fs::create_dir_all(started_dir).map_err(|err| {
        format!(
            "failed to create started dir {}: {err}",
            started_dir.display()
        )
    })?;
    let _ = fs::set_permissions(started_dir, fs::Permissions::from_mode(0o1777));
    let sentinel = started_dir.join(name);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&sentinel)
        .map_err(|err| format!("failed to write sentinel {}: {err}", sentinel.display()))?;
    use std::io::Write;
    writeln!(file, "{}", process::id())
        .map_err(|err| format!("failed to write sentinel {}: {err}", sentinel.display()))?;
    Ok(())
}

fn wait_until_ready(ready_file: &Path) {
    while !ready_file.exists() {
        thread::sleep(Duration::from_secs(1));
    }
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
            0o1777
        );
        let pid = fs::read_to_string(dir.join("web")).unwrap();
        assert_eq!(pid.trim(), process::id().to_string());
        fs::remove_dir_all(dir).unwrap();
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
}
