use super::*;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Component;
use std::thread;

const DEFAULT_WAIT_FOR_CONTAINERS_TIMEOUT_SECONDS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkloadNamespace {
    pub(super) name: String,
    pub(super) pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ExpectedIdentity {
    pub(super) uid: u32,
    pub(super) gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SentinelRecord {
    pub(super) container: Option<String>,
    pub(super) pid: u32,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    pub(super) start_time_ticks: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NamespaceBindMount {
    pub(super) source: PathBuf,
    pub(super) target: PathBuf,
}

pub(super) fn wait_for_container_start_sentinels(cfg: &Config) -> Result<Vec<WorkloadNamespace>> {
    let names = std::env::var("ENCLAVA_INIT_WAIT_FOR_CONTAINERS").unwrap_or_default();
    let containers = names
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(validate_sentinel_name)
        .collect::<Result<Vec<_>>>()?;
    if containers.is_empty() {
        return Ok(Vec::new());
    }

    let dir = started_dir_path();
    let timeout = workload_wait_timeout();
    tracing::info!(
        dir = %dir.display(),
        containers = containers.join(","),
        timeout_seconds = timeout.as_secs(),
        "waiting for workload containers before bind-mounting decrypted volumes"
    );
    let started = Instant::now();
    let mut last_error = anyhow!("workload containers did not signal startup");
    loop {
        match collect_workload_namespaces_once(cfg, &dir, Path::new("/proc"), &containers) {
            Ok(namespaces) => return Ok(namespaces),
            Err(err) => last_error = err,
        }
        if started.elapsed() >= timeout {
            return Err(last_error).context(format!(
                "timed out after {}s waiting for workload containers",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn workload_wait_timeout() -> Duration {
    std::env::var("ENCLAVA_INIT_WAIT_FOR_CONTAINERS_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_WAIT_FOR_CONTAINERS_TIMEOUT_SECONDS))
}

fn collect_workload_namespaces_once(
    cfg: &Config,
    dir: &Path,
    proc_root: &Path,
    containers: &[String],
) -> Result<Vec<WorkloadNamespace>> {
    let mut pending = Vec::new();
    let mut namespaces = Vec::new();
    for name in containers {
        let sentinel = dir.join(name);
        let expected = expected_identity(cfg, name);
        match read_sentinel_pid(&sentinel, proc_root, name, expected).or_else(|sentinel_err| {
            find_workload_pid_by_env_checked(proc_root, name, Some(expected)).with_context(|| {
                format!(
                    "sentinel {} unavailable ({sentinel_err}) and /proc fallback failed",
                    sentinel.display()
                )
            })
        }) {
            Ok(pid) => namespaces.push(WorkloadNamespace {
                name: name.clone(),
                pid,
            }),
            Err(err) => pending.push(format!("{name}: {err}")),
        }
    }
    if !pending.is_empty() {
        return Err(anyhow!(
            "workload startup sentinels unavailable: {}",
            pending.join(", ")
        ));
    }
    Ok(namespaces)
}

fn expected_identity(cfg: &Config, name: &str) -> ExpectedIdentity {
    if name == "tenant-ingress" {
        ExpectedIdentity {
            uid: cfg.caddy_uid,
            gid: cfg.caddy_gid,
        }
    } else {
        ExpectedIdentity {
            uid: cfg.app_uid,
            gid: cfg.app_gid,
        }
    }
}

fn read_sentinel_pid(
    path: &Path,
    proc_root: &Path,
    expected_name: &str,
    expected: ExpectedIdentity,
) -> Result<u32> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow!("sentinel must not be a symlink"));
    }
    if !metadata.file_type().is_file() {
        return Err(anyhow!("sentinel must be a regular file"));
    }
    if metadata.uid() != expected.uid {
        return Err(anyhow!(
            "sentinel owner uid {} does not match expected uid {}",
            metadata.uid(),
            expected.uid
        ));
    }
    if metadata.permissions().mode() & 0o002 != 0 {
        return Err(anyhow!("sentinel must not be world-writable"));
    }
    let text = std::fs::read_to_string(path)?;
    let record = parse_sentinel_record(&text)?;
    validate_sentinel_record(proc_root, expected_name, expected, &record)?;
    Ok(record.pid)
}

pub(super) fn parse_sentinel_record(text: &str) -> Result<SentinelRecord> {
    if let Ok(pid) = text.trim().parse::<u32>() {
        return Ok(SentinelRecord {
            container: None,
            pid,
            uid: None,
            gid: None,
            start_time_ticks: None,
        });
    }
    let mut container = None;
    let mut pid = None;
    let mut uid = None;
    let mut gid = None;
    let mut start_time_ticks = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "version" if value != "1" => return Err(anyhow!("unsupported sentinel version")),
            "container" if !value.is_empty() => container = Some(validate_sentinel_name(value)?),
            "pid" => pid = Some(value.parse::<u32>().context("invalid sentinel pid")?),
            "uid" => uid = Some(value.parse::<u32>().context("invalid sentinel uid")?),
            "gid" => gid = Some(value.parse::<u32>().context("invalid sentinel gid")?),
            "start_time_ticks" => {
                start_time_ticks = Some(
                    value
                        .parse::<u64>()
                        .context("invalid sentinel start_time_ticks")?,
                )
            }
            _ => {}
        }
    }
    Ok(SentinelRecord {
        container,
        pid: pid.ok_or_else(|| anyhow!("sentinel missing pid"))?,
        uid,
        gid,
        start_time_ticks,
    })
}

pub(super) fn validate_sentinel_record(
    proc_root: &Path,
    expected_name: &str,
    expected: ExpectedIdentity,
    record: &SentinelRecord,
) -> Result<()> {
    if let Some(container) = record.container.as_deref()
        && container != expected_name
    {
        return Err(anyhow!(
            "sentinel container {container} does not match expected {expected_name}"
        ));
    }
    if let Some(uid) = record.uid
        && uid != expected.uid
    {
        return Err(anyhow!(
            "sentinel uid {uid} does not match expected uid {}",
            expected.uid
        ));
    }
    if let Some(gid) = record.gid
        && gid != expected.gid
    {
        return Err(anyhow!(
            "sentinel gid {gid} does not match expected gid {}",
            expected.gid
        ));
    }
    validate_pid_mount_namespace(proc_root, record.pid)?;
    validate_pid_env(proc_root, record.pid, expected_name)?;
    validate_proc_pid_identity(proc_root, record.pid, expected)?;
    if let Some(start_time_ticks) = record.start_time_ticks {
        let actual = pid_start_time_ticks(proc_root, record.pid)?;
        if actual != start_time_ticks {
            return Err(anyhow!(
                "sentinel start_time_ticks {start_time_ticks} does not match live pid start_time {actual}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn find_workload_pid_by_env(proc_root: &Path, name: &str) -> Result<u32> {
    find_workload_pid_by_env_checked(proc_root, name, None)
}

fn find_workload_pid_by_env_checked(
    proc_root: &Path,
    name: &str,
    expected: Option<ExpectedIdentity>,
) -> Result<u32> {
    let expected_env = format!("ENCLAVA_CONTAINER_NAME={name}");
    for entry in std::fs::read_dir(proc_root)? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let environ = match std::fs::read(entry.path().join("environ")) {
            Ok(environ) => environ,
            Err(_) => continue,
        };
        if environ
            .split(|byte| *byte == 0)
            .any(|var| var == expected_env.as_bytes())
        {
            validate_pid_mount_namespace(proc_root, pid)?;
            if let Some(expected) = expected {
                validate_proc_pid_identity(proc_root, pid, expected)?;
            }
            return Ok(pid);
        }
    }
    Err(anyhow!("no running workload helper found for {name}"))
}

fn validate_pid_env(proc_root: &Path, pid: u32, name: &str) -> Result<()> {
    let expected = format!("ENCLAVA_CONTAINER_NAME={name}");
    let environ = std::fs::read(proc_root.join(pid.to_string()).join("environ"))
        .with_context(|| format!("reading environ for pid {pid}"))?;
    if environ
        .split(|byte| *byte == 0)
        .any(|var| var == expected.as_bytes())
    {
        Ok(())
    } else {
        Err(anyhow!("sentinel pid {pid} does not belong to {name}"))
    }
}

fn validate_proc_pid_identity(
    proc_root: &Path,
    pid: u32,
    expected: ExpectedIdentity,
) -> Result<()> {
    let status = std::fs::read_to_string(proc_root.join(pid.to_string()).join("status"))
        .with_context(|| format!("reading status for pid {pid}"))?;
    let uid = first_status_id(&status, "Uid:")?;
    let gid = first_status_id(&status, "Gid:")?;
    if uid != expected.uid || gid != expected.gid {
        return Err(anyhow!(
            "sentinel pid {pid} identity {uid}:{gid} does not match expected {}:{}",
            expected.uid,
            expected.gid
        ));
    }
    Ok(())
}

fn first_status_id(status: &str, key: &str) -> Result<u32> {
    let line = status
        .lines()
        .find(|line| line.starts_with(key))
        .ok_or_else(|| anyhow!("missing {key} in process status"))?;
    line[key.len()..]
        .split_whitespace()
        .next()
        .ok_or_else(|| anyhow!("missing value for {key} in process status"))?
        .parse::<u32>()
        .with_context(|| format!("invalid {key} in process status"))
}

fn pid_start_time_ticks(proc_root: &Path, pid: u32) -> Result<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat"))
        .with_context(|| format!("reading stat for pid {pid}"))?;
    start_time_ticks_from_stat(&stat)
}

fn start_time_ticks_from_stat(stat: &str) -> Result<u64> {
    let (_, rest) = stat
        .rsplit_once(") ")
        .ok_or_else(|| anyhow!("process stat is missing command delimiter"))?;
    let fields = rest.split_whitespace().collect::<Vec<_>>();
    fields
        .get(19)
        .ok_or_else(|| anyhow!("process stat is missing start_time"))?
        .parse::<u64>()
        .context("invalid process stat start_time")
}

fn validate_pid_mount_namespace(proc_root: &Path, pid: u32) -> Result<()> {
    if !proc_root.join(pid.to_string()).join("ns/mnt").exists() {
        return Err(anyhow!("sentinel pid {pid} has no mount namespace"));
    }
    Ok(())
}

pub(super) fn validate_sentinel_name(name: &str) -> Result<String> {
    let path = Path::new(name);
    if path.components().count() == 1
        && matches!(path.components().next(), Some(Component::Normal(_)))
    {
        Ok(name.to_string())
    } else {
        Err(anyhow!("invalid container sentinel name: {name}"))
    }
}

pub(super) fn bind_mounts_into_workload_namespaces(
    cfg: &Config,
    workloads: &[WorkloadNamespace],
) -> Result<()> {
    if dev_no_luks_override() {
        tracing::warn!("ENCLAVA_INIT_DEV_NO_LUKS=true — skipping workload namespace bind mounts");
        return Ok(());
    }

    let self_pid = std::process::id();
    for workload in workloads {
        bind_for_workload(cfg, self_pid, workload)?;
    }
    Ok(())
}

fn bind_for_workload(cfg: &Config, self_pid: u32, workload: &WorkloadNamespace) -> Result<()> {
    let mounts = bind_mount_plan_for_workload(cfg, self_pid, workload)?;

    for mount in mounts {
        bind_mount_into_namespace(workload.pid, &mount.source, &mount.target).with_context(
            || {
                format!(
                    "binding {} to {} in {} pid {}",
                    mount.source.display(),
                    mount.target.display(),
                    workload.name,
                    workload.pid
                )
            },
        )?;
    }
    Ok(())
}

pub(super) fn bind_mount_plan_for_workload(
    cfg: &Config,
    self_pid: u32,
    workload: &WorkloadNamespace,
) -> Result<Vec<NamespaceBindMount>> {
    let mut mounts = Vec::new();
    if workload.name != "tenant-ingress" {
        for bind in &cfg.app_bind_mounts {
            mounts.push(NamespaceBindMount {
                source: namespace_source(
                    self_pid,
                    &app_bind_mount_dir(Path::new(&cfg.state.mount_path), &bind.subdir)?
                        .to_string_lossy(),
                ),
                target: PathBuf::from(&bind.mount_path),
            });
        }
    }
    Ok(mounts)
}

fn namespace_source(pid: u32, mount_path: &str) -> PathBuf {
    let rel = mount_path.trim_start_matches('/');
    PathBuf::from(format!("/proc/{pid}/root/{rel}"))
}

fn bind_mount_into_namespace(pid: u32, source: &Path, target: &Path) -> Result<()> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .arg("--bind-mount-into-ns")
        .arg(pid.to_string())
        .arg(source)
        .arg(target)
        .output()
        .with_context(|| format!("spawning namespace binder for pid {pid}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let detail = [stderr.trim(), stdout.trim()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("; ");
        if detail.is_empty() {
            return Err(anyhow!("namespace binder exited with {}", output.status));
        }
        return Err(anyhow!(
            "namespace binder exited with {}: {}",
            output.status,
            detail
        ));
    }
    Ok(())
}

pub(super) fn run_bind_mount_into_ns(args: &[String]) -> Result<()> {
    if args.len() != 3 {
        return Err(anyhow!(
            "--bind-mount-into-ns requires <pid> <source> <target>"
        ));
    }
    let pid = args[0]
        .parse::<u32>()
        .map_err(|_| anyhow!("invalid pid {}", args[0]))?;
    let source = PathBuf::from(&args[1]);
    let target = PathBuf::from(&args[2]);
    let source_dir = std::fs::File::open(&source)
        .with_context(|| format!("open source {}", source.display()))?;
    std::fs::metadata(&source).with_context(|| format!("stat source {}", source.display()))?;
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/mnt"))
        .with_context(|| format!("opening mount namespace for pid {pid}"))?;
    nix::sched::setns(&ns, nix::sched::CloneFlags::CLONE_NEWNS)
        .with_context(|| format!("setns to pid {pid} mount namespace"))?;
    let source_mount_path = proc_self_fd_path(source_dir.as_raw_fd());
    let target_mount_path = workload_target_path(pid, &target)?;
    std::fs::create_dir_all(&target_mount_path)
        .with_context(|| format!("creating target {}", target_mount_path.display()))?;
    if paths_resolve_to_same_object(&source_mount_path, &target_mount_path).with_context(|| {
        format!(
            "checking whether {} is already mounted at {}",
            source.display(),
            target_mount_path.display()
        )
    })? {
        return Ok(());
    }
    nix::mount::mount(
        Some(source_mount_path.as_path()),
        target_mount_path.as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| {
        format!(
            "bind mounting {} to {}",
            source.display(),
            target_mount_path.display()
        )
    })?;
    Ok(())
}

pub(super) fn proc_self_fd_path(fd: RawFd) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{fd}"))
}

pub(super) fn workload_target_path(pid: u32, target: &Path) -> Result<PathBuf> {
    if !target.is_absolute() {
        return Err(anyhow!(
            "workload bind target must be absolute: {}",
            target.display()
        ));
    }
    let rel = target
        .strip_prefix("/")
        .with_context(|| format!("normalizing target {}", target.display()))?;
    Ok(workload_proc_root_path(pid).join(rel))
}

pub(super) fn mount_source_path_after_workload_chroot(source: &Path) -> PathBuf {
    let source = source.to_string_lossy();
    let Some(rest) = source.strip_prefix("/proc/") else {
        return PathBuf::from(source.as_ref());
    };
    let Some((pid, path)) = rest.split_once("/root/") else {
        return PathBuf::from(source.as_ref());
    };
    if !pid.bytes().all(|b| b.is_ascii_digit()) {
        return PathBuf::from(source.as_ref());
    }
    PathBuf::from("/").join(path)
}

pub(super) fn workload_proc_root_path(pid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/root"))
}

pub(super) fn paths_resolve_to_same_object(a: &Path, b: &Path) -> Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let a_meta = std::fs::metadata(a).with_context(|| format!("stat {}", a.display()))?;
    let b_meta = std::fs::metadata(b).with_context(|| format!("stat {}", b.display()))?;
    Ok(a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino())
}

pub(super) fn app_bind_mount_dir(state_root: &Path, subdir: &str) -> Result<PathBuf> {
    if subdir.is_empty() {
        return Err(anyhow!("app bind mount subdir cannot be empty"));
    }
    let rel = Path::new(subdir);
    if rel.is_absolute() || rel.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(anyhow!("invalid app bind mount subdir: {subdir}"));
    }
    Ok(state_root.join(rel))
}
