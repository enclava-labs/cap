use super::*;
use std::path::Component;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct WorkloadNamespace {
    pub(super) name: String,
    pub(super) pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NamespaceBindMount {
    pub(super) source: PathBuf,
    pub(super) target: PathBuf,
}

pub(super) fn wait_for_container_start_sentinels() -> Result<Vec<WorkloadNamespace>> {
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
    tracing::info!(
        dir = %dir.display(),
        containers = containers.join(","),
        "waiting for workload containers before bind-mounting decrypted volumes"
    );
    let mut pending = Vec::new();
    let mut namespaces = Vec::new();
    for name in &containers {
        let sentinel = dir.join(name);
        match read_sentinel_pid(&sentinel).or_else(|sentinel_err| {
            find_workload_pid_by_env(Path::new("/proc"), name).with_context(|| {
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
        tracing::warn!(
            pending = %pending.join(", "),
            "continuing without some workload namespace bind mounts"
        );
    }
    Ok(namespaces)
}

fn read_sentinel_pid(path: &Path) -> Result<u32> {
    let text = std::fs::read_to_string(path)?;
    let pid = text
        .trim()
        .parse::<u32>()
        .map_err(|_| anyhow!("sentinel does not contain a numeric pid"))?;
    validate_pid_mount_namespace(Path::new("/proc"), pid)?;
    Ok(pid)
}

pub(super) fn find_workload_pid_by_env(proc_root: &Path, name: &str) -> Result<u32> {
    let expected = format!("ENCLAVA_CONTAINER_NAME={name}");
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
            .any(|var| var == expected.as_bytes())
        {
            validate_pid_mount_namespace(proc_root, pid)?;
            return Ok(pid);
        }
    }
    Err(anyhow!("no running workload helper found for {name}"))
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
    let _source_dir = std::fs::File::open(&source)
        .with_context(|| format!("open source {}", source.display()))?;
    std::fs::metadata(&source).with_context(|| format!("stat source {}", source.display()))?;
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/mnt"))
        .with_context(|| format!("opening mount namespace for pid {pid}"))?;
    nix::sched::setns(&ns, nix::sched::CloneFlags::CLONE_NEWNS)
        .with_context(|| format!("setns to pid {pid} mount namespace"))?;
    let workload_root = workload_proc_root_path(pid);
    std::env::set_current_dir(&workload_root)
        .with_context(|| format!("entering workload root {}", workload_root.display()))?;
    nix::unistd::chroot(&workload_root)
        .with_context(|| format!("chroot to workload root {}", workload_root.display()))?;
    std::env::set_current_dir("/").context("entering chroot /")?;
    let source_mount_path = mount_source_path_after_workload_chroot(&source);
    std::fs::create_dir_all(&target)
        .with_context(|| format!("creating target {}", target.display()))?;
    if paths_resolve_to_same_object(&source_mount_path, &target).with_context(|| {
        format!(
            "checking whether {} is already mounted at {}",
            source.display(),
            target.display()
        )
    })? {
        return Ok(());
    }
    nix::mount::mount(
        Some(source_mount_path.as_path()),
        target.as_path(),
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("bind mounting {} to {}", source.display(), target.display()))?;
    Ok(())
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
