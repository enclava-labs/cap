use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use enclava_init::chown::{self, ExecIdentity, IdentityKind};
use enclava_init::config::{
    Config, LOG_SPOOL_STORAGE_STATE_BIND, LogEncryptionHandoff, LogEncryptionHandoffFile, Mode,
    VolumeConfig,
};
use enclava_init::safe_diagnostics::SafeBootstrapDiagnostic;
use enclava_init::secrets::{DerivedSeed, OwnerSeed, Password};
use enclava_init::{
    dev_no_luks_override, env_override, log_relay, luks, luks2_seal, seeds, socket,
    tls_certificate, trustee_verify, unlock, writes,
};
use serde::Deserialize;

const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";
const DEFAULT_ERROR_FILE: &str = "/run/enclava/init-error";
const DEFAULT_ACME_COOLDOWN_FILE: &str = "/run/enclava/init-acme-cooldown";
const DEFAULT_AA_TOKEN_WAIT_SECONDS: u64 = 300;
const DEFAULT_KBS_PROXY_HEALTH_POLL_SECONDS: u64 = 2;
const CADDY_RUNTIME_HANDOFF_PATH: &str = "/run/enclava/caddy-runtime";
const PUBLIC_TLS_CERT_HANDOFF_PATH: &str = "/run/enclava/public-tls/certificates/tls.crt";
const CADDY_RUNTIME_SYNC_INTERVAL_SECONDS: u64 = 5;
const DEFAULT_STAGE_FILE: &str = "/run/enclava/init-stage";
const MANAGED_CONFIG_ROOT: &str = ".enclava";
const MANAGED_CONFIG_DIR: &str = ".enclava/config";
const MANAGED_CONFIG_DIR_MODE: u32 = 0o750;

fn main() -> ExitCode {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(String::as_str) == Some("--bind-mount-into-ns") {
        return match run_bind_mount_into_ns(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("enclava-init namespace bind: {e:#}");
                ExitCode::from(1)
            }
        };
    }

    if args.first().map(String::as_str) == Some("--probe-ready") {
        return if ready_file_exists(&ready_file_path()) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .init();

    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            report_failure(&e);
            // Prod-strict fails fast: an indefinitely-alive failed sidecar
            // masks the failure from orchestration (no restart, no backoff).
            // Dev builds keep the diagnostics-readable stay-alive; the
            // predicate compiles the bypass out of prod-strict builds.
            if stay_alive_after_failure_enabled() {
                tracing::error!(
                    "enclava-init failed; keeping sidecar alive so diagnostics remain readable"
                );
                stay_alive_after_failure();
            }
            ExitCode::from(1)
        }
    }
}

/// Report a failed bootstrap on every ordinary failure surface with the
/// same bounded safe fields: the init-error file, the termination log,
/// tracing, and stderr.
///
/// The safe diagnostic recovers the TLS broker's typed terminal failure by
/// downcast (preserving its code and validated deadline through the
/// contextual anyhow wrappers); every other failure degrades to the generic
/// `enclava_init_failed` code. The raw anyhow chain — which may carry
/// paths, supplied values, or provider text — is never rendered here.
fn report_failure(error: &anyhow::Error) {
    let diagnostic = SafeBootstrapDiagnostic::diagnose(error);
    let safe_json = diagnostic.render_json();
    record_failure_file(&safe_json);
    tracing::error!(
        error = diagnostic.code.as_str(),
        terminal = true,
        retry_after = diagnostic.retry_after_rfc3339().as_deref(),
        "enclava-init failed"
    );
    eprintln!("enclava-init: {safe_json}");
}

fn run() -> Result<()> {
    let mut stats = init_stats::BootStats::begin();
    let result = run_with_stats(&mut stats);
    if result.is_err() {
        let _ = stats.write(&init_stats::stats_path_for(&ready_file_path()));
    }
    result
}

fn run_with_stats(stats: &mut init_stats::BootStats) -> Result<()> {
    record_stage("loading config").ok();
    let cfg_path = std::env::var("ENCLAVA_INIT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/enclava-init/config.toml"));
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {}", cfg_path.display()))?;
    record_stage("validating signed config").ok();
    // Read the projected cc_init_data ConfigMap exactly once per boot and use
    // this single byte snapshot for BOTH the ConfigMap transport cross-check
    // and the later in-TEE hash/signature verification. Re-reading the file
    // between those steps would let a malicious host swap in different bytes
    // after the cross-check (e.g. an attacker-controlled log_encryption_json)
    // but before the forward-chain hash check pins the authentic bytes again.
    let cc_init_data = read_cc_init_data(&cfg)?;
    let log_encryption_handoff =
        validate_configmap_transport_against_signed_cc_init_data(&cfg, cc_init_data.as_deref())?;
    // The relay starts only after the signed-config check passes: it serves
    // an unauthenticated log-tail endpoint keyed off host-visible env, so
    // it must not come up while the transport is still unverified.
    let _log_relay = start_log_relay_if_configured().context("starting encrypted log relay")?;
    let stay_alive = stay_alive_enabled();
    let ready_file = ready_file_path();
    if stay_alive {
        clear_ready_file(&ready_file)
            .with_context(|| format!("clearing stale ready file {}", ready_file.display()))?;
    }

    record_stage("verifying trustee policy").ok();
    // Fail-closed: any verification gap (missing inputs, missing policy-read
    // availability) returns Err and aborts before seed release. This must
    // run BEFORE the volume open path: open_luks_volumes may mutate the
    // on-disk header (seal adoption), and the claim it enforces has to be
    // pinned to the in-TEE-verified cc_init_data bytes first — otherwise a
    // host could present a downgraded/stripped claim for exactly one
    // adoption, keep the disk mutation after verification fails, and hand
    // the next boot a rolled-back header that now carries a valid MAC
    // (cap#244 self-review).
    let phase = stats.elapsed_ms();
    run_in_tee_verification(&cfg, cc_init_data.as_deref())?;
    stats.record_tee_verify(phase);

    record_stage("waiting for owner seed").ok();
    let phase = stats.elapsed_ms();
    // Legacy auto metadata must still accept owner-authorized manual handoff.
    let owner = acquire_owner_seed_password(&cfg)?;
    stats.record_owner_seed(phase);
    clear_error_file(&error_file_path());

    record_stage("opening luks volumes").ok();
    open_luks_volumes(
        &cfg,
        &owner,
        stats,
        &luks_rollout_policy(cc_init_data.as_deref())?,
    )?;
    record_stage("preparing mount ownership").ok();
    prepare_mount_ownership(&cfg)?;
    // The spool dir is prepared fd-relative (a symlinked <state-root>/
    // .enclava or log-spool fails closed) and the bind pins the verified
    // inode via /proc/self/fd rather than a re-resolved path (cap#290
    // round-2 review).
    let spool_dir = prepare_log_spool_dir(&cfg, &log_encryption_handoff)
        .context("preparing log spool directory on encrypted state")?;
    bind_log_spool_to_state(&cfg, &log_encryption_handoff, spool_dir.as_ref())
        .context("binding log spool to encrypted state")?;

    record_stage("provisioning static tls certificate").ok();
    provision_static_tls_certificate(&cfg).context("provisioning static TLS certificate")?;
    record_stage("writing component seeds").ok();
    let phase = stats.elapsed_ms();
    write_per_component_seeds(&cfg, &owner)?;
    write_log_encryption_handoff(&cfg, &log_encryption_handoff)?;
    stats.record_component_seeds(phase);

    if stay_alive {
        record_stage("waiting for workload containers").ok();
        let workload_namespaces = wait_for_container_start_sentinels(&cfg)
            .context("waiting for workload containers before bind-mounting decrypted volumes")?;
        record_stage("binding workload mount namespaces").ok();
        let phase = stats.elapsed_ms();
        bind_mounts_into_workload_namespaces(&cfg, &workload_namespaces)
            .context("binding decrypted mounts into workload namespaces")?;
        stats.record_bind_mounts(phase);
        record_stage("seeding caddy runtime handoff").ok();
        seed_caddy_runtime_handoff(&cfg).context("seeding caddy runtime handoff")?;
    }

    // Write the numeric boot summary before flipping ready so consumers
    // polling the ready file never observe readiness without the record.
    // Telemetry is best-effort: a failed write must not block the workload.
    let stats_path = init_stats::stats_path_for(&ready_file);
    if let Err(err) = stats.write(&stats_path) {
        tracing::warn!(path = %stats_path.display(), error = %err, "failed to write init stats");
    }

    if stay_alive {
        record_stage("marking ready").ok();
        mark_ready_file(&ready_file)
            .with_context(|| format!("writing ready file {}", ready_file.display()))?;
        tracing::info!(
            ready_file = %ready_file.display(),
            "enclava-init: seeds released; keeping mounter sidecar alive"
        );
        stay_alive_forever(&cfg);
    }

    tracing::info!("enclava-init: seeds released");
    Ok(())
}

fn stay_alive_enabled() -> bool {
    std::env::var("ENCLAVA_INIT_STAY_ALIVE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Whether a failed bootstrap keeps the sidecar alive for diagnostics.
/// Prod-strict compiles this to false: a failed init must exit so
/// orchestration sees the failure instead of a mounter that stays up.
fn stay_alive_after_failure_enabled() -> bool {
    stay_alive_enabled() && !cfg!(feature = "prod-strict")
}

fn start_log_relay_if_configured() -> Result<Option<std::thread::JoinHandle<()>>> {
    let Some(config) = log_relay::LogRelayConfig::from_env_optional()
        .context("resolving encrypted log relay configuration")?
    else {
        return Ok(None);
    };
    tracing::info!(
        bind = %config.bind,
        spool_path = %config.spool_path.display(),
        container = %config.container,
        "starting encrypted log relay"
    );
    Ok(Some(log_relay::spawn(config)?))
}

fn ready_file_path() -> PathBuf {
    init_surface_path("ENCLAVA_INIT_READY_FILE", DEFAULT_READY_FILE)
}

fn error_file_path() -> PathBuf {
    init_surface_path("ENCLAVA_INIT_ERROR_FILE", DEFAULT_ERROR_FILE)
}

fn acme_cooldown_file_path() -> PathBuf {
    init_surface_path(
        "ENCLAVA_INIT_ACME_COOLDOWN_FILE",
        DEFAULT_ACME_COOLDOWN_FILE,
    )
}

fn stage_file_path() -> PathBuf {
    init_surface_path("ENCLAVA_INIT_STAGE_FILE", DEFAULT_STAGE_FILE)
}

fn started_dir_path() -> PathBuf {
    init_surface_path("ENCLAVA_INIT_STARTED_DIR", "/run/enclava/containers")
}

/// Resolve the path of an init output surface (ready/error/stage/started/
/// termination/cooldown files).
///
/// Prod-strict builds bind these surfaces to the compiled defaults only:
/// [`env_override`] returns `None`, so the host-controlled pod environment
/// can never redirect them. Test builds (cfg(test) — compiled exclusively
/// for the test harness, never into release binaries) additionally consult
/// an in-process override map so the failure-path tests can redirect the
/// surfaces into a temp directory even under `--features prod-strict`,
/// without reopening the env bypass those tests would otherwise need.
fn init_surface_path(name: &str, default: &str) -> PathBuf {
    #[cfg(test)]
    if let Some(path) = test_surface_paths::get(name) {
        return path;
    }
    env_override(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

#[cfg(test)]
mod test_surface_paths {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    static OVERRIDES: Mutex<Option<HashMap<String, PathBuf>>> = Mutex::new(None);

    fn lock() -> MutexGuard<'static, Option<HashMap<String, PathBuf>>> {
        // A poisoned lock only means some earlier test panicked while
        // holding it; the map itself is still structurally valid.
        OVERRIDES.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn get(name: &str) -> Option<PathBuf> {
        lock().as_ref().and_then(|map| map.get(name).cloned())
    }

    /// Install path overrides for the named init surfaces, returning a
    /// guard that restores the previous state on drop. Installed values
    /// take precedence over the environment in test builds only. The
    /// snapshot/restore semantics keep an inner guard's drop from
    /// un-redirecting an outer guard's surfaces.
    pub fn install(entries: &[(&'static str, PathBuf)]) -> Guard {
        let mut slot = lock();
        let previous = slot.take();
        let map = slot.get_or_insert_with(HashMap::new);
        for (name, path) in entries {
            map.insert((*name).to_string(), path.clone());
        }
        Guard { previous }
    }

    pub struct Guard {
        previous: Option<HashMap<String, PathBuf>>,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            *lock() = self.previous.take();
        }
    }
}

#[path = "main/init_stats.rs"]
mod init_stats;
#[path = "main/namespace_bind.rs"]
mod namespace_bind;
#[cfg(test)]
use namespace_bind::{
    ExpectedIdentity, MountSourceStrategy, SentinelRecord, WorkloadNamespace,
    bind_mount_plan_for_workload, expected_identity, find_workload_pid_by_env,
    mount_source_strategy, namespace_source, parse_sentinel_record, paths_resolve_to_same_object,
    read_sentinel_pid, validate_sentinel_name, validate_sentinel_record, workload_proc_root_path,
    workload_target_path,
};
use namespace_bind::{
    app_bind_mount_dir, bind_mounts_into_workload_namespaces, run_bind_mount_into_ns,
    wait_for_container_start_sentinels,
};
fn clear_ready_file(path: &Path) -> Result<()> {
    write_ready_file_state(path, b"not-ready\n")
}

fn clear_error_file(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::warn!(path = %path.display(), error = %e, "failed to clear error file"),
    }
}

/// Write the safe failure JSON to the init-error file and the termination
/// log.
///
/// Both files carry exactly the bounded safe contract
/// (`{"error","terminal","retry_after"}`) consumed by the attestation
/// proxy worker and operators — never the anyhow chain, raw broker
/// response text, or other supplied values. Stage markers stay in their
/// own init-stage file.
fn record_failure_file(safe_json: &str) {
    let body = format!("{safe_json}\n");
    let path = error_file_path();
    if let Err(err) = writes::atomic_write(&path, body.as_bytes(), 0o644) {
        eprintln!("enclava-init: failed to write init error file: {err}");
    }
    let termination_path =
        init_surface_path("ENCLAVA_INIT_TERMINATION_LOG", "/dev/termination-log");
    if let Err(err) = write_termination_log_in_place(&termination_path, body.as_bytes()) {
        eprintln!("enclava-init: failed to write termination log: {err}");
    }
}

/// Write the Kubernetes termination log in place.
///
/// The kubelet bind-mounts `/dev/termination-log` into the container, and
/// renaming over a mounted file fails with `EBUSY` — the tmp+rename of
/// [`writes::atomic_write`] can never replace it, so the safe JSON would
/// never reach that surface. Write the existing file in place instead
/// (open + truncate + write + fsync). This advisory surface does not need
/// rename atomicity: a crash mid-write leaves at most a truncated log,
/// never cross-file corruption. The private init-error file keeps the
/// atomic tmp+rename write.
fn write_termination_log_in_place(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn record_stage(stage: &str) -> Result<()> {
    tracing::info!(stage, "enclava-init stage");
    writes::atomic_write(&stage_file_path(), format!("{stage}\n").as_bytes(), 0o644)
        .map_err(Into::into)
}

fn mark_ready_file(path: &Path) -> Result<()> {
    write_ready_file_state(path, b"ready\n")
}

fn ready_file_exists(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .map(|value| value.trim() == "ready")
        .unwrap_or(false)
}

fn write_ready_file_state(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("ready file path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    let dir = std::fs::OpenOptions::new().read(true).open(parent)?;
    dir.sync_all()?;
    Ok(())
}

fn stay_alive_forever(cfg: &Config) -> ! {
    loop {
        if caddy_runtime_back_sync_required(cfg)
            && let Err(err) = sync_caddy_runtime_back(cfg)
        {
            tracing::warn!(error = %err, "caddy runtime persistence sync failed");
        }
        std::thread::sleep(Duration::from_secs(CADDY_RUNTIME_SYNC_INTERVAL_SECONDS));
    }
}

fn caddy_runtime_back_sync_required(cfg: &Config) -> bool {
    cfg.tls_certificate_broker_url.is_none()
}

fn stay_alive_after_failure() -> ! {
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

fn acquire_owner_seed_password(cfg: &Config) -> Result<OwnerSeed> {
    let salt_hex = cfg
        .argon2_salt_hex
        .as_deref()
        .ok_or_else(|| anyhow!("password mode requires argon2_salt_hex in config"))?;
    let salt = hex::decode(salt_hex).context("decoding argon2_salt_hex")?;

    let listener =
        socket::bind_with_peer_gid(Path::new(&cfg.unlock_socket), unlock_socket_peer_gid())?;
    tracing::info!(socket = %cfg.unlock_socket, "awaiting unlock request");

    loop {
        let (mut stream, _) = listener.accept()?;
        let request = match socket::read_unlock_request(&mut stream) {
            Ok(request) => request,
            Err(e) => {
                let _ = socket::reply_err(&mut stream, &format!("read: {e}"));
                continue;
            }
        };

        match request {
            socket::UnlockRequest::OwnerSeed(seed) => {
                clear_error_file(&error_file_path());
                socket::reply_ok(&mut stream).ok();
                return Ok(seed);
            }
            socket::UnlockRequest::Password(pw_str) => {
                let now = unlock::now_secs();
                if let Err(e) = unlock::check_rate_limit(Path::new(&cfg.attempts_path), now) {
                    return Err(anyhow!("rate limit: {e}"));
                }

                let password = Password::from_plaintext(&pw_str);
                unlock::record_attempt(Path::new(&cfg.attempts_path), now)?;

                match unlock::derive_owner_seed(&password, &salt) {
                    Ok(seed) => {
                        clear_error_file(&error_file_path());
                        socket::reply_ok(&mut stream).ok();
                        return Ok(seed);
                    }
                    Err(e) => {
                        socket::reply_err(&mut stream, &format!("derive: {e}")).ok();
                    }
                }
            }
        }
    }
}

/// Read the projected cc_init_data ConfigMap once so the exact same byte
/// snapshot feeds both the transport cross-check and the in-TEE hash /
/// signature verification (TOCTOU hardening against a host that rewrites the
/// file between the two reads).
fn read_cc_init_data(cfg: &Config) -> Result<Option<Vec<u8>>> {
    if !cfg.trustee_policy_read_available {
        if cfg!(feature = "prod-strict") {
            anyhow::bail!(
                "prod-strict refuses trustee_policy_read_available=false; signed cc_init_data verification cannot be skipped"
            );
        }
        if cfg.cc_init_data_path.is_none() {
            return Ok(None);
        }
    }
    let cc_path = cfg
        .cc_init_data_path
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires cc_init_data_path"))?;
    let bytes = std::fs::read(cc_path).with_context(|| format!("reading {cc_path}"))?;
    Ok(Some(bytes))
}

/// LUKS2 header-seal rollout policy from the signed cc_init_data (cap#242
/// review: sealed volumes must not accept unsealed-header rollback).
///
/// The signed `luks2_header_seal` claim takes two values:
/// - `"adopt"` (or claim absent — pre-claim signed artifacts): legacy
///   pre-seal volumes are adopted through the strict-validation +
///   passphrase gate. This is the rollout window.
/// - `"required"`: every formatted volume must already carry a valid HMAC
///   seal. An unsealed header is rejected as rollback/tampering instead of
///   re-adopted. Operators flip the platform default to "required" once the
///   fleet has migrated; the claim is signed and its cc_init_data bytes are
///   pinned by the in-TEE chain verification that now runs BEFORE the open
///   path can mutate any header, so the host cannot downgrade it per-guest
///   (a presented downgrade fails verification first, before adoption).
///
/// Do not flip the signed release value to `"required"` until the crash
/// window between `luksFormat` and the first MAC-slot write is recoverable
/// (or formally accepted as a manual-reset case): an interrupted format
/// leaves a valid unsealed header that `"required"` rejects on every later
/// boot, wedging the volume. `"adopt"` still recovers from that state
/// (cap#244 self-review).
///
/// Any other value fails the boot rather than guessing the intent.
fn luks_rollout_policy(cc_init_data: Option<&[u8]>) -> Result<luks::LuksOpenPolicy> {
    let Some(cc_bytes) = cc_init_data else {
        // Non-prod path (trustee_policy_read_available=false, debug builds):
        // same rollout-window default as a claim-less artifact.
        return Ok(luks::LuksOpenPolicy::default());
    };
    // Fail closed on unreadable cc_init_data: these bytes were already
    // parsed once by validate_configmap_transport_against_signed_cc_init_data
    // this boot, so a parse failure here means the file changed underneath
    // us (host tampering) and the boot must stop, not default to adopt
    // (cap#244 self-review).
    let cc_toml = std::str::from_utf8(cc_bytes).context("parsing cc_init_data as utf-8")?;
    let parsed: toml::Value = toml::from_str(cc_toml).context("parsing cc_init_data")?;
    // A missing claim keeps the rollout-window default (pre-claim signed
    // artifacts); an unknown value fails the boot rather than guessing.
    let claim = parsed
        .get("data")
        .and_then(|d| d.get("luks2_header_seal"))
        .and_then(toml::Value::as_str);
    match claim {
        Some("required") => Ok(luks::LuksOpenPolicy {
            allow_legacy_adoption: false,
        }),
        Some("adopt") | None => Ok(luks::LuksOpenPolicy::default()),
        Some(other) => anyhow::bail!(
            "signed cc_init_data carries unknown luks2_header_seal value {other:?} \
             (expected \"adopt\" or \"required\")"
        ),
    }
}

fn validate_configmap_transport_against_signed_cc_init_data(
    cfg: &Config,
    cc_init_data: Option<&[u8]>,
) -> Result<LogEncryptionHandoffFile> {
    if !cfg.trustee_policy_read_available {
        if cfg!(feature = "prod-strict") {
            anyhow::bail!(
                "prod-strict refuses trustee_policy_read_available=false; signed cc_init_data verification cannot be skipped"
            );
        }
        if cc_init_data.is_none() {
            return Ok(LogEncryptionHandoffFile::Unconfigured);
        }
    }
    let cc_bytes =
        cc_init_data.ok_or_else(|| anyhow!("verification requires cc_init_data bytes"))?;
    let cc_toml = std::str::from_utf8(cc_bytes).context("parsing cc_init_data as utf-8")?;
    let parsed: toml::Value = toml::from_str(cc_toml).context("parsing cc_init_data")?;
    let data = parsed
        .get("data")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| anyhow!("cc_init_data missing [data] claims"))?;

    require_signed_config_match(
        data,
        "argon2_salt_hex",
        cfg.argon2_salt_hex.as_deref(),
        "argon2-salt-hex",
    )?;
    require_signed_config_match(
        data,
        "kbs_attestation_token_url",
        Some(&cfg.kbs_attestation_token_url),
        "kbs-attestation-token-url",
    )?;
    require_signed_config_match(
        data,
        "mode",
        Some(match cfg.mode {
            Mode::Autounlock => "autounlock",
            Mode::Password => "password",
        }),
        "mode",
    )?;
    if cfg.mode == Mode::Autounlock {
        require_signed_config_match(data, "kbs_url", cfg.kbs_url.as_deref(), "kbs-url")?;
        require_signed_config_match(
            data,
            "kbs_resource_path",
            cfg.kbs_resource_path.as_deref(),
            "kbs-resource-path",
        )?;
    }
    require_signed_config_match(
        data,
        "state_device",
        Some(&cfg.state.device),
        "state.device",
    )?;
    require_signed_config_match(
        data,
        "state_mapping_name",
        Some(&cfg.state.mapping_name),
        "state.mapping-name",
    )?;
    require_signed_config_match(
        data,
        "state_mount_path",
        Some(&cfg.state.mount_path),
        "state.mount-path",
    )?;
    require_signed_config_match(
        data,
        "state_hkdf_info",
        Some(&cfg.state.hkdf_info),
        "state.hkdf-info",
    )?;
    require_signed_config_match(
        data,
        "tls_state_device",
        Some(&cfg.tls_state.device),
        "tls-state.device",
    )?;
    require_signed_config_match(
        data,
        "tls_state_mapping_name",
        Some(&cfg.tls_state.mapping_name),
        "tls-state.mapping-name",
    )?;
    require_signed_config_match(
        data,
        "tls_state_mount_path",
        Some(&cfg.tls_state.mount_path),
        "tls-state.mount-path",
    )?;
    require_signed_config_match(
        data,
        "tls_state_hkdf_info",
        Some(&cfg.tls_state.hkdf_info),
        "tls-state.hkdf-info",
    )?;
    require_signed_config_match(
        data,
        "unlock_socket",
        Some(&cfg.unlock_socket),
        "unlock-socket",
    )?;
    require_signed_config_match(
        data,
        "attempts_path",
        Some(&cfg.attempts_path),
        "attempts-path",
    )?;
    require_signed_config_match(data, "state_root", Some(&cfg.state_root), "state-root")?;
    require_signed_u32_match(data, "app_uid", cfg.app_uid, "app-uid")?;
    require_signed_u32_match(data, "app_gid", cfg.app_gid, "app-gid")?;
    require_signed_u32_match(data, "caddy_uid", cfg.caddy_uid, "caddy-uid")?;
    require_signed_u32_match(data, "caddy_gid", cfg.caddy_gid, "caddy-gid")?;
    require_optional_signed_u32_match(
        data,
        "managed_config_gid",
        cfg.managed_config_gid,
        "managed-config-gid",
    )?;
    require_optional_signed_u32_match(
        data,
        "managed_config_dir_mode",
        cfg.managed_config_dir_mode,
        "managed-config-dir-mode",
    )?;
    require_signed_app_bind_mounts_match(data, &cfg.app_bind_mounts)?;
    require_signed_config_match(
        data,
        "trustee_policy_read_available",
        Some(if cfg.trustee_policy_read_available {
            "true"
        } else {
            "false"
        }),
        "trustee-policy-read-available",
    )?;
    if cfg.trustee_policy_read_available {
        require_signed_config_match(
            data,
            "workload_artifacts_url",
            cfg.workload_artifacts_url.as_deref(),
            "workload-artifacts-url",
        )?;
        require_optional_signed_config_match(
            data,
            "tls_certificate_broker_url",
            cfg.tls_certificate_broker_url.as_deref(),
            "tls-certificate-broker-url",
        )?;
        require_optional_signed_string_list_match(
            data,
            "tls_certificate_hostnames",
            &cfg.tls_certificate_hostnames,
            "tls-certificate-hostnames",
        )?;
        require_signed_config_match(
            data,
            "trustee_policy_url",
            cfg.trustee_policy_url.as_deref(),
            "trustee-policy-url",
        )?;
        require_optional_signed_config_match(
            data,
            "platform_trustee_policy_pubkey_hex",
            cfg.platform_trustee_policy_pubkey_hex.as_deref(),
            "platform-trustee-policy-pubkey-hex",
        )?;
        require_optional_signed_config_match(
            data,
            "signing_service_pubkey_hex",
            cfg.signing_service_pubkey_hex.as_deref(),
            "signing-service-pubkey-hex",
        )?;
    }
    require_optional_signed_config_match(
        data,
        "log_spool_storage",
        cfg.log_encryption
            .as_ref()
            .and_then(|section| section.spool_storage.as_deref()),
        "log-encryption.spool-storage",
    )?;
    // cap#290 review: the v2 spool lives below <state-root>/.enclava and
    // is bound over /run/enclava-logs. A signed artifact whose bind mounts
    // claim the reserved subdir — or whose mount_path covers the spool
    // target (equal, an ancestor that shadows the bind, or a descendant
    // the bind mounts over) — would collide the spool with tenant
    // storage. Even though claims and ConfigMap agree, the combination is
    // refused rather than rendered into a corrupting mount layout.
    // (Validation should have rejected it upstream; this is the guest-side
    // fail-closed check.)
    if log_spool_state_bind_enabled(cfg)
        && cfg
            .app_bind_mounts
            .iter()
            .any(|bind| bind.subdir == MANAGED_CONFIG_ROOT)
    {
        anyhow::bail!(
            "app bind mount uses the reserved .enclava ({MANAGED_CONFIG_ROOT}) state subdir, \
             which collides with the encrypted log spool"
        );
    }
    if log_spool_state_bind_enabled(cfg)
        && let Some(bind) = cfg
            .app_bind_mounts
            .iter()
            .find(|bind| mount_path_covers_log_spool_target(&bind.mount_path))
    {
        anyhow::bail!(
            "app bind mount mount_path {:?} covers /run/enclava-logs, the encrypted \
             log spool bind target",
            bind.mount_path
        );
    }
    let handoff = signed_log_encryption_handoff(data, cfg)?;

    Ok(handoff)
}

/// Bind the `[log-encryption]` ConfigMap section to the signed
/// `log_encryption_json` cc_init_data claim and return the authoritative
/// handoff for re-publication.
///
/// The recipient public key decides who can decrypt workload log plaintext,
/// so the signed claim is authoritative and the host-controlled ConfigMap
/// copy is only a cross-check: every field present in the section must match
/// the claim, and any mismatch fails closed. A section with no signed claim
/// is likewise rejected (the host must not be able to introduce log
/// encryption where the signed data has none). A claim without a section is
/// tolerated in dev builds but refused in prod-strict, where the section is
/// expected to ride along; the handoff itself is written from the claim
/// either way, so a tampered section can never redirect it.
fn signed_log_encryption_handoff(
    data: &toml::map::Map<String, toml::Value>,
    cfg: &Config,
) -> Result<LogEncryptionHandoffFile> {
    let signed = data
        .get("log_encryption_json")
        .and_then(toml::Value::as_str);
    match (signed, cfg.log_encryption.as_ref()) {
        (None, None) => Ok(LogEncryptionHandoffFile::Unconfigured),
        // Init-first rollout compatibility: during the transition window where
        // the new init binary is live but the old API still renders manifests,
        // the ConfigMap may have [log-encryption] while cc_init_data lacks the
        // new log_encryption_json claim (the same shape occurs on every later
        // restart of a pre-claim signed artifact pinned to the legacy render).
        // We tolerate this but the trust binding is DOWNGRADED: encrypted logs
        // stay off until the app is re-signed because we cannot verify the key
        // material came from a trusted manifest source (it's purely
        // host-controlled ConfigMap at this point), and an explicit disabled
        // marker is published so prod-strict wait-exec treats encryption as
        // off instead of failing on a handoff that can never exist. The relay
        // discards log frames rather than emitting them in plaintext; key
        // material is never taken from env or ConfigMap.
        (None, Some(_)) => {
            tracing::warn!(
                "ConfigMap has [log-encryption] but signed cc_init_data lacks \
                 log_encryption_json claim (legacy API manifest or pre-claim \
                 signed artifact): encrypted logging stays DISABLED until the \
                 app is re-signed; log frames are discarded, not emitted in \
                 plaintext."
            );
            Ok(LogEncryptionHandoffFile::DisabledMarker)
        }
        (Some(signed), section) => {
            let handoff: LogEncryptionHandoff = serde_json::from_str(signed)
                .with_context(|| "parsing signed log_encryption_json claim")?;
            if let Some(section) = section {
                let mismatches = [
                    ("algorithm", (&section.algorithm, &handoff.algorithm)),
                    ("key-id", (&section.key_id, &handoff.key_id)),
                    (
                        "public-key-base64url",
                        (&section.public_key_base64url, &handoff.public_key_base64url),
                    ),
                    (
                        "public-key-sha256",
                        (&section.public_key_sha256, &handoff.public_key_sha256),
                    ),
                ];
                for (field, (section_value, claim_value)) in mismatches {
                    if let Some(section_value) = section_value
                        && section_value != claim_value
                    {
                        anyhow::bail!(
                            "ConfigMap log-encryption {field} does not match signed cc_init_data claim log_encryption_json"
                        );
                    }
                }
            } else if cfg!(feature = "prod-strict") {
                anyhow::bail!(
                    "signed cc_init_data carries log_encryption_json but the ConfigMap has no [log-encryption] section"
                );
            }
            Ok(LogEncryptionHandoffFile::Enabled(handoff))
        }
    }
}

fn require_signed_u32_match(
    data: &toml::map::Map<String, toml::Value>,
    signed_key: &str,
    config_value: u32,
    config_key: &str,
) -> Result<()> {
    let signed = signed_u32_claim(data, signed_key)?;
    if signed != config_value {
        anyhow::bail!(
            "ConfigMap {config_key} does not match signed cc_init_data claim {signed_key}"
        );
    }
    Ok(())
}

fn require_optional_signed_u32_match(
    data: &toml::map::Map<String, toml::Value>,
    signed_key: &str,
    config_value: Option<u32>,
    config_key: &str,
) -> Result<()> {
    match (data.get(signed_key), config_value) {
        (Some(value), Some(config)) => {
            let signed = parse_signed_u32(value, signed_key)?;
            if signed != config {
                anyhow::bail!(
                    "ConfigMap {config_key} does not match signed cc_init_data claim {signed_key}"
                );
            }
            Ok(())
        }
        (None, None) => Ok(()),
        (Some(_), None) => anyhow::bail!("config missing {config_key}"),
        (None, Some(_)) => anyhow::bail!("cc_init_data missing signed claim {signed_key}"),
    }
}

fn signed_u32_claim(data: &toml::map::Map<String, toml::Value>, signed_key: &str) -> Result<u32> {
    let value = data
        .get(signed_key)
        .ok_or_else(|| anyhow!("cc_init_data missing signed claim {signed_key}"))?;
    parse_signed_u32(value, signed_key)
}

fn parse_signed_u32(value: &toml::Value, signed_key: &str) -> Result<u32> {
    if let Some(int) = value.as_integer() {
        return u32::try_from(int)
            .map_err(|_| anyhow!("cc_init_data claim {signed_key} is out of range"));
    }
    if let Some(text) = value.as_str() {
        return text
            .parse::<u32>()
            .map_err(|_| anyhow!("cc_init_data claim {signed_key} is not a u32"));
    }
    Err(anyhow!("cc_init_data claim {signed_key} is not an integer"))
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SignedAppBindMount {
    subdir: String,
    mount_path: String,
}

fn require_signed_app_bind_mounts_match(
    data: &toml::map::Map<String, toml::Value>,
    mounts: &[enclava_init::config::AppBindMountConfig],
) -> Result<()> {
    let signed = data
        .get("app_bind_mounts")
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow!("cc_init_data missing signed claim app_bind_mounts"))?;
    let signed_mounts: Vec<SignedAppBindMount> = serde_json::from_str(signed)
        .with_context(|| "parsing cc_init_data claim app_bind_mounts JSON list")?;
    if signed_mounts.len() != mounts.len()
        || signed_mounts.iter().zip(mounts).any(|(signed, config)| {
            signed.subdir != config.subdir || signed.mount_path != config.mount_path
        })
    {
        anyhow::bail!(
            "ConfigMap app-bind-mounts does not match signed cc_init_data claim app_bind_mounts"
        );
    }
    for mount in mounts {
        validate_app_bind_mount_path(&mount.mount_path)?;
    }
    Ok(())
}

fn validate_app_bind_mount_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        anyhow::bail!("app bind mount mount_path must be absolute: {path}");
    }
    if path.trim_matches('/').is_empty() {
        anyhow::bail!("app bind mount mount_path must name a path below root: {path}");
    }
    if path.split('/').any(|segment| segment == "..") {
        anyhow::bail!("app bind mount mount_path must not contain '..' path segments: {path}");
    }
    Ok(())
}

/// Whether an app bind mount path covers the encrypted log spool bind
/// target `/run/enclava-logs` (cap#290 round-2 review): equal, an ancestor
/// that would shadow the bind (e.g. `/run`, `/`), or a descendant the bind
/// would mount over (`/run/enclava-logs/sub`). Lexical on normalized
/// components (`.` skipped); `..` fails closed as covering (such paths are
/// already rejected by [`validate_app_bind_mount_path`]).
fn mount_path_covers_log_spool_target(path: &str) -> bool {
    fn normal_components(path: &str) -> Option<Vec<std::ffi::OsString>> {
        let mut out = Vec::new();
        for component in std::path::Path::new(path).components() {
            match component {
                std::path::Component::Normal(part) => out.push(part.to_os_string()),
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => return None,
                std::path::Component::RootDir | std::path::Component::Prefix(_) => {}
            }
        }
        Some(out)
    }
    let Some(mount) = normal_components(path) else {
        return true;
    };
    let Some(target) = normal_components("/run/enclava-logs") else {
        return true;
    };
    (mount.len() <= target.len() && target.starts_with(&mount))
        || (target.len() <= mount.len() && mount.starts_with(&target))
}

fn require_signed_config_match(
    data: &toml::map::Map<String, toml::Value>,
    signed_key: &str,
    config_value: Option<&str>,
    config_key: &str,
) -> Result<()> {
    let signed = data
        .get(signed_key)
        .and_then(toml::Value::as_str)
        .ok_or_else(|| anyhow!("cc_init_data missing signed claim {signed_key}"))?;
    let config = config_value.ok_or_else(|| anyhow!("config missing {config_key}"))?;
    if signed != config {
        anyhow::bail!(
            "ConfigMap {config_key} does not match signed cc_init_data claim {signed_key}"
        );
    }
    Ok(())
}

fn require_optional_signed_config_match(
    data: &toml::map::Map<String, toml::Value>,
    signed_key: &str,
    config_value: Option<&str>,
    config_key: &str,
) -> Result<()> {
    let signed = data.get(signed_key).and_then(toml::Value::as_str);
    match (signed, config_value) {
        (Some(signed), Some(config)) if signed == config => Ok(()),
        (None, None) => Ok(()),
        (Some(_), Some(_)) => anyhow::bail!(
            "ConfigMap {config_key} does not match signed cc_init_data claim {signed_key}"
        ),
        (Some(_), None) => anyhow::bail!("config missing {config_key}"),
        (None, Some(_)) => anyhow::bail!("cc_init_data missing signed claim {signed_key}"),
    }
}

fn require_optional_signed_string_list_match(
    data: &toml::map::Map<String, toml::Value>,
    signed_key: &str,
    config_values: &[String],
    config_key: &str,
) -> Result<()> {
    let signed = data.get(signed_key);
    match (signed, config_values.is_empty()) {
        (None, true) => Ok(()),
        (Some(value), false) => {
            let signed_values = signed_string_list(value, signed_key)?;
            if signed_values != config_values {
                anyhow::bail!(
                    "ConfigMap {config_key} does not match signed cc_init_data claim {signed_key}"
                );
            }
            Ok(())
        }
        (Some(_), true) => anyhow::bail!(
            "ConfigMap {config_key} missing but signed cc_init_data claim {signed_key} is present"
        ),
        (None, false) => {
            anyhow::bail!("cc_init_data missing signed claim {signed_key}")
        }
    }
}

fn signed_string_list(value: &toml::Value, signed_key: &str) -> Result<Vec<String>> {
    if let Some(items) = value.as_array() {
        return items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| anyhow!("cc_init_data claim {signed_key} contains non-string"))
            })
            .collect::<Result<Vec<_>>>();
    }
    if let Some(json_value) = value.as_str() {
        return serde_json::from_str::<Vec<String>>(json_value)
            .with_context(|| format!("parsing cc_init_data claim {signed_key} JSON list"));
    }
    Err(anyhow!(
        "cc_init_data claim {signed_key} is not a string list"
    ))
}

fn unlock_socket_peer_gid() -> Option<u32> {
    std::env::var("ENCLAVA_INIT_UNLOCK_SOCKET_GID")
        .ok()
        .as_deref()
        .and_then(parse_positive_u32)
}

fn kbs_proxy_health_poll_interval() -> Duration {
    let explicit = std::env::var("ENCLAVA_INIT_KBS_PROXY_HEALTH_POLL_SECONDS")
        .ok()
        .or_else(|| std::env::var("KBS_PROXY_HEALTH_POLL_SECONDS").ok());
    explicit
        .as_deref()
        .and_then(parse_positive_seconds)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_KBS_PROXY_HEALTH_POLL_SECONDS))
}

fn parse_positive_seconds(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|seconds| *seconds > 0)
}

fn parse_positive_u32(value: &str) -> Option<u32> {
    value.parse::<u32>().ok().filter(|value| *value > 0)
}

/// Bounded readiness wait for a LOCAL attestation-agent token endpoint
/// (default http://127.0.0.1:8006/aa/token): poll with a short per-request
/// timeout until the endpoint answers with a NON-5xx HTTP status — a
/// listener can accept connections and answer 5xx while the token service
/// is still starting, so those keep polling, as do connection errors —
/// then return so the real single-shot token fetch runs and surfaces any
/// genuine AA error verbatim. Uses its own 300s default budget
/// ([`aa_token_wait_timeout`], env-overridable via
/// ENCLAVA_INIT_AA_TOKEN_WAIT_SECONDS) and the shared 2s poll interval.
/// Remote URLs return immediately (cap#244 review).
fn wait_for_local_aa_token_endpoint(token_url: &str) {
    let Ok(url) = reqwest::Url::parse(token_url) else {
        return;
    };
    let is_local = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"));
    if !is_local {
        return;
    }
    // Own default budget: the KBS-proxy helper's 300s default keys on the
    // proxy's port 8081, while the AA token endpoint defaults to 8006 —
    // reusing that helper gave this wait a zero default. Explicit env
    // overrides still win (cap#244 review).
    let wait_timeout = aa_token_wait_timeout();
    if wait_timeout.is_zero() {
        return;
    }
    let poll = kbs_proxy_health_poll_interval();
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(_) => return,
    };
    tracing::info!(
        token_url_host = url.host_str().unwrap_or(""),
        wait_seconds = wait_timeout.as_secs(),
        "waiting for local attestation-agent token endpoint before TEE verification"
    );
    let deadline = std::time::Instant::now() + wait_timeout;
    while std::time::Instant::now() < deadline {
        // A listener can accept connections before the token service is
        // ready and answer 5xx during startup — keep polling those. Any
        // non-5xx response means the endpoint is serving; the real fetch
        // then surfaces any genuine AA error verbatim. Connection errors
        // (agent not yet listening) also keep polling.
        match client.get(token_url).send() {
            Ok(resp) if resp.status().as_u16() >= 500 => {}
            Ok(_) => return,
            Err(_) => {}
        }
        // A failed probe can outlast the remaining budget (5s request
        // timeout); saturate so the sleep never underflows (cap#244 review).
        std::thread::sleep(poll.min(deadline.saturating_duration_since(std::time::Instant::now())));
    }
    tracing::warn!(
        wait_seconds = wait_timeout.as_secs(),
        "local attestation-agent token endpoint still not serving; proceeding to the token fetch"
    );
}

fn aa_token_wait_timeout() -> Duration {
    let explicit = std::env::var("ENCLAVA_INIT_AA_TOKEN_WAIT_SECONDS")
        .ok()
        .or_else(|| std::env::var("AA_TOKEN_WAIT_SECONDS").ok());
    if let Some(value) = explicit {
        return parse_positive_seconds(&value)
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO);
    }
    Duration::from_secs(DEFAULT_AA_TOKEN_WAIT_SECONDS)
}

fn open_luks_volumes(
    cfg: &Config,
    owner: &OwnerSeed,
    stats: &mut init_stats::BootStats,
    luks_policy: &luks::LuksOpenPolicy,
) -> Result<()> {
    if dev_no_luks_override() {
        tracing::warn!("ENCLAVA_INIT_DEV_NO_LUKS=true — skipping luks open (debug builds only)");
        return Ok(());
    }
    // cap#242: reject cryptsetup releases below the null-cipher keyslot
    // hardening floor before touching any volume.
    luks2_seal::ensure_cryptsetup_floor()?;
    let state_phase = stats.elapsed_ms();
    let state_result = open_one_volume(
        &cfg.state,
        owner,
        // The passphrase stays derived from the signed per-volume
        // `hkdf_info` exactly as before this change: volumes provisioned
        // with a custom signed value must keep unlocking (cap#242 review).
        &cfg.state.hkdf_info,
        seeds::STATE_HEADER_MAC_INFO,
        luks_policy,
        &mut stats.state_profile,
    );
    stats.record_state_volume(state_phase, stats.state_profile.format_completed());
    state_result.with_context(|| format!("opening state volume {}", cfg.state.device))?;
    let tls_phase = stats.elapsed_ms();
    let tls_result = open_one_volume(
        &cfg.tls_state,
        owner,
        &cfg.tls_state.hkdf_info,
        seeds::TLS_STATE_HEADER_MAC_INFO,
        luks_policy,
        &mut stats.tls_profile,
    );
    stats.record_tls_volume(tls_phase, stats.tls_profile.format_completed());
    tls_result.with_context(|| format!("opening tls-state volume {}", cfg.tls_state.device))?;
    stats.record_post_luks_memory();
    Ok(())
}

fn open_one_volume(
    vol: &VolumeConfig,
    owner: &OwnerSeed,
    // Passphrase HKDF info: the signed per-volume value (validated against
    // the signed cc-init-data by
    // `validate_configmap_transport_against_signed_cc_init_data` before boot
    // proceeds).
    passphrase_info: &str,
    // Header-MAC HKDF branch: pinned per volume kind, never configurable, so
    // the MAC key cannot be steered by config data.
    header_mac_info: &[u8],
    policy: &luks::LuksOpenPolicy,
    profile: &mut enclava_init::volume_profile::VolumeProfile,
) -> Result<luks::LuksOpened> {
    // Distinct HKDF branches: the volume passphrase and the header MAC key
    // must never share material (cap#242).
    let keys = luks::VolumeKeys::new(
        derive_volume_key(owner, passphrase_info.as_bytes())?,
        derive_volume_key(owner, header_mac_info)?,
    );
    let device = Path::new(&vol.device);
    profile.device_bytes = std::fs::File::open(device)
        .and_then(|mut file| std::io::Seek::seek(&mut file, std::io::SeekFrom::End(0)))
        .unwrap_or(0);
    let opened = luks::format_if_unformatted_then_open_with_policy(
        device,
        &vol.mapping_name,
        &keys,
        policy,
        profile,
    )?;
    profile.run(enclava_init::volume_profile::Stage::Mount, |_| {
        luks::mount(&opened.mapper_path, Path::new(&vol.mount_path))
    })?;
    tracing::info!(
        device = %vol.device,
        mapper = %opened.mapper_path.display(),
        mount = %vol.mount_path,
        "opened luks volume"
    );
    Ok(opened)
}

fn prepare_mount_ownership(cfg: &Config) -> Result<()> {
    let app_identity = numeric_identity(cfg.app_uid, cfg.app_gid);
    let caddy_identity = numeric_identity(cfg.caddy_uid, cfg.caddy_gid);

    let state_root = Path::new(&cfg.state.mount_path);
    let tls_state_root = Path::new(&cfg.tls_state.mount_path);
    std::fs::create_dir_all(state_root)
        .with_context(|| format!("creating {}", state_root.display()))?;
    std::fs::create_dir_all(tls_state_root)
        .with_context(|| format!("creating {}", tls_state_root.display()))?;

    chown::chown(state_root, app_identity)
        .with_context(|| format!("chown {}", state_root.display()))?;
    chown::chown_recursive(tls_state_root, caddy_identity)
        .with_context(|| format!("chown {}", tls_state_root.display()))?;
    prepare_managed_config_dir(
        state_root,
        cfg.managed_config_gid.unwrap_or(cfg.app_gid),
        cfg.managed_config_dir_mode
            .unwrap_or(MANAGED_CONFIG_DIR_MODE),
    )?;

    let caddy_tls_dir = caddy_tls_bind_dir(tls_state_root);
    std::fs::create_dir_all(&caddy_tls_dir)
        .with_context(|| format!("creating {}", caddy_tls_dir.display()))?;
    chown::chown_recursive(&caddy_tls_dir, caddy_identity)
        .with_context(|| format!("chown {}", caddy_tls_dir.display()))?;
    let caddy_runtime_handoff = Path::new(CADDY_RUNTIME_HANDOFF_PATH);
    std::fs::create_dir_all(caddy_runtime_handoff)
        .with_context(|| format!("creating {}", caddy_runtime_handoff.display()))?;
    chown::chown_recursive(caddy_runtime_handoff, caddy_identity)
        .with_context(|| format!("chown {}", caddy_runtime_handoff.display()))?;

    let app_seed_dir = Path::new(&cfg.state_root).join("app");
    std::fs::create_dir_all(&app_seed_dir)
        .with_context(|| format!("creating {}", app_seed_dir.display()))?;
    chown::chown_recursive(&app_seed_dir, app_identity)
        .with_context(|| format!("chown {}", app_seed_dir.display()))?;

    let caddy_seed_dir = Path::new(&cfg.state_root).join("caddy");
    std::fs::create_dir_all(&caddy_seed_dir)
        .with_context(|| format!("creating {}", caddy_seed_dir.display()))?;
    chown::chown_recursive(&caddy_seed_dir, caddy_identity)
        .with_context(|| format!("chown {}", caddy_seed_dir.display()))?;

    for bind in &cfg.app_bind_mounts {
        let dir = app_bind_mount_dir(state_root, &bind.subdir)?;
        std::fs::create_dir_all(&dir).with_context(|| {
            format!(
                "creating app bind mount source {} for {}",
                dir.display(),
                bind.mount_path
            )
        })?;
        chown::chown_recursive(&dir, app_identity)
            .with_context(|| format!("chown {}", dir.display()))?;
    }

    Ok(())
}

fn prepare_managed_config_dir(state_root: &Path, managed_gid: u32, mode: u32) -> Result<()> {
    prepare_managed_config_dir_at(state_root, managed_gid, mode, |path, identity| {
        chown::chown(path, identity).map_err(Into::into)
    })
}

fn prepare_managed_config_dir_at<F>(
    state_root: &Path,
    managed_gid: u32,
    mode: u32,
    mut chown_dir: F,
) -> Result<()>
where
    F: FnMut(&Path, chown::ExecIdentity) -> Result<()>,
{
    let managed_root = state_root.join(MANAGED_CONFIG_ROOT);
    let config_dir = state_root.join(MANAGED_CONFIG_DIR);
    let config_identity = chown::ExecIdentity {
        uid: 0,
        gid: managed_gid,
        kind: chown::IdentityKind::Numeric,
    };

    fs::create_dir_all(&config_dir)
        .with_context(|| format!("creating {}", config_dir.display()))?;
    for dir in [&managed_root, &config_dir] {
        chown_dir(dir, config_identity).with_context(|| format!("chown {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", dir.display()))?;
    }

    Ok(())
}

fn seed_caddy_runtime_handoff(cfg: &Config) -> Result<()> {
    let persistent = caddy_tls_bind_dir(Path::new(&cfg.tls_state.mount_path));
    let runtime = Path::new(CADDY_RUNTIME_HANDOFF_PATH);
    let caddy_identity = numeric_identity(cfg.caddy_uid, cfg.caddy_gid);
    seed_caddy_runtime_handoff_at(&persistent, runtime, caddy_identity, |path, identity| {
        chown::chown_recursive(path, identity).map_err(Into::into)
    })
}

fn seed_caddy_runtime_handoff_at<F>(
    persistent: &Path,
    runtime: &Path,
    caddy_identity: chown::ExecIdentity,
    chown_runtime: F,
) -> Result<()>
where
    F: FnOnce(&Path, chown::ExecIdentity) -> Result<()>,
{
    sync_dir_contents(persistent, runtime)
        .with_context(|| format!("copying {} to {}", persistent.display(), runtime.display()))?;
    chown_runtime(runtime, caddy_identity).with_context(|| format!("chown {}", runtime.display()))
}

fn provision_static_tls_certificate(cfg: &Config) -> Result<()> {
    let persistent = caddy_tls_bind_dir(Path::new(&cfg.tls_state.mount_path));
    tls_certificate::provision_static_tls_certificate(
        cfg,
        &persistent,
        &acme_cooldown_file_path(),
    )?;
    let caddy_identity = numeric_identity(cfg.caddy_uid, cfg.caddy_gid);
    for path in [
        tls_certificate::cert_path(&persistent),
        tls_certificate::key_path(&persistent),
    ] {
        if path.exists() {
            chown::chown(&path, caddy_identity)
                .with_context(|| format!("chown {}", path.display()))?;
        }
    }
    let cert_path = tls_certificate::cert_path(&persistent);
    publish_public_tls_certificate(&cert_path, Path::new(PUBLIC_TLS_CERT_HANDOFF_PATH))?;
    Ok(())
}

fn publish_public_tls_certificate(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }
    let certificate =
        std::fs::read(source).context("reading public TLS certificate for proxy handoff")?;
    writes::atomic_write(destination, &certificate, 0o644)
        .context("publishing public TLS certificate for proxy handoff")
}

fn sync_caddy_runtime_back(cfg: &Config) -> Result<()> {
    let persistent = caddy_tls_bind_dir(Path::new(&cfg.tls_state.mount_path));
    let runtime = Path::new(CADDY_RUNTIME_HANDOFF_PATH);
    sync_dir_contents(runtime, &persistent)
        .with_context(|| format!("copying {} to {}", runtime.display(), persistent.display()))?;
    publish_caddy_runtime_certificate(runtime, Path::new(PUBLIC_TLS_CERT_HANDOFF_PATH))
}

fn publish_caddy_runtime_certificate(runtime: &Path, destination: &Path) -> Result<()> {
    let certificates = runtime.join("certificates");
    let Some(source) = newest_certificate(&certificates)? else {
        return Ok(());
    };
    publish_public_tls_certificate(&source, destination)
}

fn newest_certificate(directory: &Path) -> Result<Option<PathBuf>> {
    if !directory.is_dir() {
        return Ok(None);
    }
    let mut newest = None;
    for entry in
        std::fs::read_dir(directory).with_context(|| format!("reading {}", directory.display()))?
    {
        let entry = entry.with_context(|| format!("reading entry in {}", directory.display()))?;
        let ty = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        let path = entry.path();
        if ty.is_dir() {
            if let Some(candidate) = newest_certificate(&path)? {
                newest = newer_certificate(newest, candidate)?;
            }
        } else if ty.is_file() && path.extension().is_some_and(|ext| ext == "crt") {
            newest = newer_certificate(newest, path)?;
        }
    }
    Ok(newest)
}

fn newer_certificate(current: Option<PathBuf>, candidate: PathBuf) -> Result<Option<PathBuf>> {
    let candidate_modified = std::fs::metadata(&candidate)?.modified()?;
    match current {
        Some(current) if std::fs::metadata(&current)?.modified()? > candidate_modified => {
            Ok(Some(current))
        }
        _ => Ok(Some(candidate)),
    }
}

fn sync_dir_contents(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    if !src.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(src).with_context(|| format!("reading {}", src.display()))? {
        let entry = entry.with_context(|| format!("reading entry in {}", src.display()))?;
        if entry.file_name() == "locks" {
            continue;
        }
        let ty = entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?;
        if ty.is_symlink() {
            continue;
        }
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            sync_dir_contents(&src_path, &dst_path)?;
        } else if ty.is_file() {
            if let Some(parent) = dst_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            std::fs::copy(&src_path, &dst_path).with_context(|| {
                format!("copying {} to {}", src_path.display(), dst_path.display())
            })?;
        }
    }
    Ok(())
}

fn caddy_tls_bind_dir(tls_state_root: &Path) -> PathBuf {
    tls_state_root.join("tenant-ingress")
}

/// Whether the signed/config render pins the log spool onto the encrypted
/// state PVC (`[log-encryption] spool-storage = "state-bind-v1"`, cap#289).
fn log_spool_state_bind_enabled(cfg: &Config) -> bool {
    cfg.log_encryption.as_ref().is_some_and(|section| {
        section.spool_storage.as_deref() == Some(LOG_SPOOL_STORAGE_STATE_BIND)
    })
}

/// Spool source directory on the encrypted state volume. Lives below the
/// platform-reserved `.enclava` namespace so no tenant `storage_paths`
/// bind (which maps to `<state-root>/<subdir>`) can collide with the
/// spool (cap#290 review). Kept for tests that pin the on-disk location;
/// runtime traversal is fd-relative via [`prepare_log_spool_dir`].
#[cfg(test)]
fn log_spool_state_dir(state_root: &Path) -> PathBuf {
    state_root.join(MANAGED_CONFIG_ROOT).join("log-spool")
}

/// `O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`: every component of the spool
/// source path is opened under these flags so a symlink or non-directory
/// swapped in at any level fails closed (ELOOP/ENOTDIR) instead of being
/// followed or silently accepted (cap#290 round-2 review).
const SPOOL_OPEN_FLAGS: nix::fcntl::OFlag = nix::fcntl::OFlag::from_bits_retain(
    nix::fcntl::OFlag::O_DIRECTORY.bits()
        | nix::fcntl::OFlag::O_NOFOLLOW.bits()
        | nix::fcntl::OFlag::O_CLOEXEC.bits(),
);

/// Minimum total capacity of the filesystem backing the state-bound spool.
/// Validation requires ≥128Mi state PVC for these renders; the runtime
/// check is the fail-closed floor for grandfathered or bypassed renders —
/// 64 MiB covers the 32 MiB live spool plus its rotation temp with a small
/// margin (cap#290 round-2 review).
const LOG_SPOOL_MIN_STATE_BYTES: u64 = 64 * 1024 * 1024;

fn log_spool_capacity_sufficient(total_bytes: u64) -> bool {
    total_bytes >= LOG_SPOOL_MIN_STATE_BYTES
}

/// Prepare `<state-root>/.enclava/log-spool` for the state bind, entirely
/// fd-relative. Returns `None` when the bind is not enabled or no signed
/// log-encryption claim exists.
fn prepare_log_spool_dir(
    cfg: &Config,
    handoff: &LogEncryptionHandoffFile,
) -> Result<Option<std::os::fd::OwnedFd>> {
    let LogEncryptionHandoffFile::Enabled(handoff) = handoff else {
        return Ok(None);
    };
    if !log_spool_state_bind_enabled(cfg) {
        return Ok(None);
    }
    prepare_log_spool_dir_at(
        Path::new(&cfg.state_root),
        numeric_identity(cfg.app_uid, cfg.app_gid),
        0,
        cfg.app_gid,
        &log_spool_keep_file_name(&handoff.public_key_sha256),
    )
    .map(Some)
}

/// Fd-relative `prepare_log_spool_dir` for tests (cap#290 round-2 review).
/// Opens `<state_root>/.enclava/log-spool` component-wise under
/// [`SPOOL_OPEN_FLAGS`], creating `.enclava` (0o750) or `log-spool`
/// (0o2770) only when missing — `.enclava` is normally already created by
/// `prepare_managed_config_dir`. Any symlinked or non-directory component
/// fails closed, and the returned fd pins the verified spool inode for the
/// later bind mount.
fn prepare_log_spool_dir_at(
    state_root: &Path,
    app_identity: ExecIdentity,
    // The spool dir's owner uid: always root (0) in production so only the
    // privileged init sidecar manages it; tests pass the current euid.
    dir_uid: u32,
    dir_gid: u32,
    keep_file_name: &str,
) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};

    fn open_dir(path: &Path) -> Result<std::os::fd::OwnedFd> {
        let fd = nix::fcntl::open(path, SPOOL_OPEN_FLAGS, nix::sys::stat::Mode::empty())
            .with_context(|| format!("opening {}", path.display()))?;
        // SAFETY: open returned a fresh owned descriptor.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
    fn open_or_mkdir_at(
        dir: &std::os::fd::OwnedFd,
        name: &str,
        mode: nix::sys::stat::Mode,
    ) -> Result<std::os::fd::OwnedFd> {
        match nix::fcntl::openat(
            Some(dir.as_raw_fd()),
            name,
            SPOOL_OPEN_FLAGS,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }),
            Err(nix::errno::Errno::ENOENT) => {
                nix::sys::stat::mkdirat(Some(dir.as_raw_fd()), name, mode)
                    .with_context(|| format!("creating {name}"))?;
                let fd = nix::fcntl::openat(
                    Some(dir.as_raw_fd()),
                    name,
                    SPOOL_OPEN_FLAGS,
                    nix::sys::stat::Mode::empty(),
                )
                .with_context(|| format!("opening {name}"))?;
                Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
            }
            Err(err) => Err(err).with_context(|| format!("opening {name}")),
        }
    }

    let root = open_dir(state_root)?;
    let managed = open_or_mkdir_at(
        &root,
        MANAGED_CONFIG_ROOT,
        nix::sys::stat::Mode::from_bits_truncate(0o750),
    )?;
    let spool = open_or_mkdir_at(
        &managed,
        "log-spool",
        nix::sys::stat::Mode::from_bits_truncate(0o2770),
    )?;

    // Retire previous key-generation spools: `.jsonl` files (and their
    // `.rotate.` temp copies) not belonging to the current generation are
    // unlinked fd-relatively — files/symlinks only, directories are never
    // removed (cap#290 round-2 review).
    {
        let keep = keep_file_name.as_bytes();
        let mut stale = Vec::new();
        let mut iter_dir = nix::dir::Dir::openat(
            Some(spool.as_raw_fd()),
            ".",
            SPOOL_OPEN_FLAGS,
            nix::sys::stat::Mode::empty(),
        )
        .context("listing log spool directory")?;
        for entry in iter_dir.iter() {
            let entry = entry.context("reading log spool directory")?;
            let name = entry.file_name().to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            let keep_seq = [keep, b".seq".as_slice()].concat();
            let kept = name == keep
                || name == keep_seq.as_slice()
                || (name.starts_with(keep) && name[keep.len()..].starts_with(b".rotate."));
            if kept {
                continue;
            }
            let looks_like_spool = name.ends_with(b".jsonl")
                || name.ends_with(b".jsonl.seq")
                || name
                    .windows(b".jsonl.rotate.".len())
                    .any(|w| w == b".jsonl.rotate.");
            let is_dir = match entry.file_type() {
                Some(nix::dir::Type::Directory) => true,
                Some(_) => false,
                None => nix::sys::stat::fstatat(
                    Some(spool.as_raw_fd()),
                    entry.file_name(),
                    nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
                )
                .map(|stat| (stat.st_mode & nix::libc::S_IFMT) == nix::libc::S_IFDIR)
                .unwrap_or(false),
            };
            if looks_like_spool && !is_dir {
                stale.push(entry.file_name().to_owned());
            }
        }
        drop(iter_dir);
        for name in stale {
            match nix::unistd::unlinkat(
                Some(spool.as_raw_fd()),
                name.as_c_str(),
                nix::unistd::UnlinkatFlags::NoRemoveDir,
            ) {
                Ok(()) => {}
                // Removed concurrently, or raced into a directory —
                // directories are never unlinked either way.
                Err(nix::errno::Errno::ENOENT)
                | Err(nix::errno::Errno::EISDIR)
                | Err(nix::errno::Errno::EPERM) => {}
                Err(err) => {
                    return Err(err).context("removing previous-generation log spool file");
                }
            }
        }
    }

    // The current-generation keep entry must be a regular file or absent:
    // a planted symlink/FIFO would be followed by wait-exec's append path
    // (writing outside the spool), and a directory would shadow the file
    // the workload writes. fstatat without following; a non-regular entry
    // is unlinked, a non-empty directory fails closed (cap#290 round-3
    // review).
    let keep_cname = std::ffi::CString::new(keep_file_name)
        .map_err(|_| anyhow!("log spool keep file name contains NUL"))?;
    match nix::sys::stat::fstatat(
        Some(spool.as_raw_fd()),
        keep_cname.as_c_str(),
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Err(nix::errno::Errno::ENOENT) => {}
        Err(err) => return Err(err).context("stating log spool file"),
        Ok(stat) => match stat.st_mode & nix::libc::S_IFMT {
            m if m == nix::libc::S_IFREG => {
                // Normalize mode on the verified inode: a planted 0o000
                // spool must not wedge wait-exec. The openat O_NOFOLLOW
                // closes the stat->open swap race.
                let fd = nix::fcntl::openat(
                    Some(spool.as_raw_fd()),
                    keep_cname.as_c_str(),
                    nix::fcntl::OFlag::O_NOFOLLOW | nix::fcntl::OFlag::O_CLOEXEC,
                    nix::sys::stat::Mode::empty(),
                )
                .with_context(|| format!("opening log spool file {keep_file_name}"))?;
                let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
                nix::sys::stat::fchmod(
                    fd.as_raw_fd(),
                    nix::sys::stat::Mode::from_bits_truncate(0o640),
                )
                .context("chmod log spool file")?;
            }
            m if m == nix::libc::S_IFDIR => {
                nix::unistd::unlinkat(
                    Some(spool.as_raw_fd()),
                    keep_cname.as_c_str(),
                    nix::unistd::UnlinkatFlags::RemoveDir,
                )
                .with_context(|| {
                    format!("removing directory {keep_file_name} from the log spool dir")
                })?;
            }
            _ => {
                nix::unistd::unlinkat(
                    Some(spool.as_raw_fd()),
                    keep_cname.as_c_str(),
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                )
                .with_context(|| {
                    format!("removing non-regular {keep_file_name} from the log spool dir")
                })?;
            }
        },
    }

    // The spool survives on the state PVC across profile changes:
    // entries written under a root-running workload stay root:root and
    // would wedge a redeploy to the restricted identity. Reconcile
    // existing contents to the current app identity fd-relatively
    // (symlink-safe), then restore the dir's group-writable mount
    // contract on the verified inode.
    chown::chown_recursive_at(spool.as_raw_fd(), app_identity)
        .context("chown log spool contents")?;
    nix::unistd::fchown(
        spool.as_raw_fd(),
        Some(nix::unistd::Uid::from_raw(dir_uid)),
        Some(nix::unistd::Gid::from_raw(dir_gid)),
    )
    .context("chown log spool directory")?;
    nix::sys::stat::fchmod(
        spool.as_raw_fd(),
        nix::sys::stat::Mode::from_bits_truncate(0o2770),
    )
    .context("chmod log spool directory")?;
    Ok(spool)
}

/// Name of the current key generation's spool file inside the prepared
/// spool dir. Prefers the basename of ENCLAVA_LOG_RELAY_SPOOL_PATH (the
/// engine renders the key-namespaced name there for the relay); when the
/// env is unset or its basename is not a single `.jsonl` file name, falls
/// back to deriving `<container>-<digest>.jsonl` from
/// ENCLAVA_LOG_RELAY_CONTAINER (default "app") and the signed recipient
/// digest — the derivation is write-free (compare-only), so a hostile env
/// can at worst retire files that never belonged to this generation.
fn log_spool_keep_file_name(recipient_sha256: &str) -> String {
    let digest = recipient_sha256
        .strip_prefix("sha256:")
        .unwrap_or(recipient_sha256);
    let derived = format!(
        "{}-{digest}.jsonl",
        std::env::var("ENCLAVA_LOG_RELAY_CONTAINER").unwrap_or_else(|_| "app".to_string())
    );
    let Some(env_path) = std::env::var_os("ENCLAVA_LOG_RELAY_SPOOL_PATH") else {
        return derived;
    };
    match Path::new(&env_path).file_name().and_then(|n| n.to_str()) {
        Some(name) if name.ends_with(".jsonl") => name.to_string(),
        _ => derived,
    }
}

/// Re-bind the "logs" Memory emptyDir mountpoint onto the encrypted state
/// PVC so the plaintext spool is bounded by the PVC, not host disk
/// (cap#289). Runs after LUKS unlock, before readiness; the pod mount
/// propagations (Bidirectional here, HostToContainer on the app side) carry
/// the re-bind to the workload. No-op for any layout that did not opt in.
/// The bind source is `/proc/self/fd/<spool_dir>` so the mount pins the
/// inode verified by [`prepare_log_spool_dir`] instead of re-resolving a
/// host-raceable path (cap#290 round-2 review).
fn bind_log_spool_to_state(
    cfg: &Config,
    handoff: &LogEncryptionHandoffFile,
    spool_dir: Option<&std::os::fd::OwnedFd>,
) -> Result<()> {
    if !log_spool_state_bind_enabled(cfg)
        || !matches!(handoff, LogEncryptionHandoffFile::Enabled(_))
    {
        return Ok(());
    }
    use std::os::fd::AsRawFd;
    let spool_dir = spool_dir
        .ok_or_else(|| anyhow!("log spool state bind enabled without a prepared spool fd"))?;
    // The bind target must be the real directory the manifest mounted;
    // a host-planted symlink would redirect the bind outside the pod's
    // view of /run/enclava-logs.
    let target = Path::new("/run/enclava-logs");
    let target_meta =
        fs::symlink_metadata(target).with_context(|| format!("stating {}", target.display()))?;
    if !target_meta.is_dir() || target_meta.file_type().is_symlink() {
        anyhow::bail!(
            "log spool bind target {} is not a real directory",
            target.display()
        );
    }
    // Capacity of the filesystem the spool will live on, taken on the
    // verified fd: validation requires a ≥128Mi state PVC for these
    // renders; this floor (64Mi — 32Mi live spool plus rotation temp and
    // a small margin) is the fail-closed bound for grandfathered or
    // bypassed renders.
    let statfs = nix::sys::statfs::fstatfs(spool_dir).context("statfs on log spool directory")?;
    let total_bytes = (statfs.blocks() as u128)
        .saturating_mul(u64::try_from(statfs.block_size()).unwrap_or(0) as u128);
    let total_bytes = u64::try_from(total_bytes).unwrap_or(u64::MAX);
    if !log_spool_capacity_sufficient(total_bytes) {
        anyhow::bail!(
            "log spool state filesystem has only {total_bytes} bytes total capacity; \
             need at least {LOG_SPOOL_MIN_STATE_BYTES} (32Mi spool rotation plus temp and fs/platform headroom)"
        );
    }
    let source = format!("/proc/self/fd/{}", spool_dir.as_raw_fd());
    nix::mount::mount(
        Some(source.as_str()),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .with_context(|| format!("bind mounting {source} to {}", target.display()))
}

fn numeric_identity(uid: u32, gid: u32) -> ExecIdentity {
    ExecIdentity {
        uid,
        gid,
        kind: IdentityKind::Numeric,
    }
}

fn derive_volume_key(owner: &OwnerSeed, info: &[u8]) -> Result<DerivedSeed> {
    let derived = seeds::derive(owner, info)?;
    Ok(derived)
}

fn run_in_tee_verification(cfg: &Config, cc_init_data: Option<&[u8]>) -> Result<()> {
    if !cfg.trustee_policy_read_available {
        return Ok(trustee_verify::verify_chain_required(None)?);
    }

    let workload_url = cfg.workload_artifacts_url.as_deref().ok_or_else(|| {
        anyhow!("trustee_policy_read_available=true requires workload_artifacts_url")
    })?;
    let policy_url = cfg
        .trustee_policy_url
        .as_deref()
        .ok_or_else(|| anyhow!("trustee_policy_read_available=true requires trustee_policy_url"))?;
    // Reuse the byte snapshot read before the ConfigMap transport cross-check:
    // the forward-chain expected_cc_init_data_hash must pin the exact bytes
    // that produced the log-encryption handoff, not a fresh host-controlled
    // read of the projected ConfigMap.
    let cc_bytes =
        cc_init_data.ok_or_else(|| anyhow!("verification requires cc_init_data bytes"))?;
    let cc_claims = parse_cc_init_data_claims(cc_bytes)?;
    let signer_pk = cfg
        .platform_trustee_policy_pubkey_hex
        .as_deref()
        .map(parse_pubkey)
        .transpose()?;
    let signing_pk = cfg
        .signing_service_pubkey_hex
        .as_deref()
        .map(parse_pubkey)
        .transpose()?;

    // Verification now runs BEFORE owner-seed acquisition (verify before
    // any header mutation), so it can no longer inherit the KBS-proxy
    // readiness wait that the autounlock path performs. A local
    // attestation-agent that is slow to start would otherwise fail this
    // single token fetch and bounce the container through restart backoff
    // (cap#244 review). Wait (bounded) for the local AA endpoint to accept
    // connections first; remote token URLs skip the wait.
    if enclava_init::env_override("KBS_ATTESTATION_TOKEN")
        .as_deref()
        .map(str::trim)
        .is_none_or(str::is_empty)
    {
        wait_for_local_aa_token_endpoint(&cfg.kbs_attestation_token_url);
    }
    let token = trustee_verify::resolve_kbs_attestation_token(
        enclava_init::env_override("KBS_ATTESTATION_TOKEN").as_deref(),
        &cfg.kbs_attestation_token_url,
        std::time::Duration::from_secs(15),
    )
    .context("resolving KBS attestation token")?;
    let fetcher = trustee_verify::ArtifactFetcher {
        workload_artifacts_url: workload_url.into(),
        trustee_policy_url: policy_url.into(),
        kbs_attestation_token: token,
        timeout: std::time::Duration::from_secs(15),
    };
    let (bundle, envelope) = fetcher.fetch().context("fetching trustee artifacts")?;
    let inputs = trustee_verify::VerifyInputs {
        policy_envelope: &envelope,
        artifacts: &bundle,
        cc_init_data_claims: &cc_claims,
        local_cc_init_data_toml: cc_bytes,
        platform_trustee_policy_pubkey: signer_pk.as_ref(),
        signing_service_pubkey: signing_pk.as_ref(),
    };
    trustee_verify::verify_chain_required(Some(&inputs)).map_err(Into::into)
}

fn parse_pubkey(hex_str: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let raw = hex::decode(hex_str).context("decoding pubkey hex")?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| anyhow!("pubkey must be 32 bytes"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&arr)?;
    // Small-order keys provide no unforgeability: verification uses
    // verify(), not verify_strict(), and a zero signature verifies against a
    // small-order key for a large share of messages. Mirror of the API's
    // require_ed25519_point (cap#218 follow-up).
    if key.is_weak() {
        return Err(anyhow!(
            "pubkey has small order and provides no unforgeability"
        ));
    }
    Ok(key)
}

fn parse_cc_init_data_claims(toml_bytes: &[u8]) -> Result<trustee_verify::CcInitDataClaims> {
    let s = std::str::from_utf8(toml_bytes).context("cc_init_data not utf-8")?;
    let v: toml::Value = toml::from_str(s).context("cc_init_data parse")?;
    let data = v
        .get("data")
        .ok_or_else(|| anyhow!("cc_init_data missing [data] section"))?;
    let core_hash = read_hex32(data, "descriptor_core_hash")?;
    let signing_pk = read_hex32(data, "descriptor_signing_pubkey")?;
    let keyring_fp = read_hex32(data, "org_keyring_fingerprint")?;
    Ok(trustee_verify::CcInitDataClaims {
        descriptor_core_hash: core_hash,
        descriptor_signing_pubkey: signing_pk,
        org_keyring_fingerprint: keyring_fp,
    })
}

fn read_hex32(v: &toml::Value, key: &str) -> Result<[u8; 32]> {
    let s = v
        .get(key)
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("cc_init_data.data.{key} missing or not string"))?;
    let raw = hex::decode(s).with_context(|| format!("decoding {key}"))?;
    raw.try_into().map_err(|_| anyhow!("{key} not 32 bytes"))
}

fn write_per_component_seeds(cfg: &Config, owner: &OwnerSeed) -> Result<()> {
    let caddy_seed = seeds::derive(owner, seeds::CADDY_INFO)?;
    let app_seed = seeds::derive(owner, seeds::APP_INFO)?;

    let caddy_path = Path::new(&cfg.state_root).join("caddy/seed");
    let app_path = Path::new(&cfg.state_root).join("app/seed");
    writes::atomic_write(&caddy_path, caddy_seed.as_bytes(), 0o600)?;
    writes::atomic_write(&app_path, app_seed.as_bytes(), 0o600)?;
    chown::chown(&caddy_path, numeric_identity(cfg.caddy_uid, cfg.caddy_gid))
        .with_context(|| format!("chown {}", caddy_path.display()))?;
    chown::chown(&app_path, numeric_identity(cfg.app_uid, cfg.app_gid))
        .with_context(|| format!("chown {}", app_path.display()))?;

    Ok(())
}

/// Publish the trusted encrypted-log recipient handoff for wait-exec.
///
/// The recipient metadata comes from the signed `log_encryption_json`
/// cc_init_data claim, extracted during
/// [`validate_configmap_transport_against_signed_cc_init_data`] (which also
/// cross-checks the host-controlled ConfigMap section against it). It is
/// published onto the decrypted state volume — the only path the host
/// cannot write (it only ever sees LUKS ciphertext) — so prod-strict
/// enclava-wait-exec resolves the recipient (and the rollback-stable frame
/// labels) from this file instead of the host-controlled pod environment.
/// The file carries the key material plus org_id/app_name and is written
/// after unlock and strictly before the ready file flips, so consumers
/// never see readiness without it. When the ConfigMap has a
/// `[log-encryption]` section but no signed claim exists (init-first
/// rollout transition window), an explicit `{"disabled": true}` marker is
/// written instead so wait-exec disables encrypted logging rather than
/// failing on a handoff that can never exist.
fn write_log_encryption_handoff(cfg: &Config, outcome: &LogEncryptionHandoffFile) -> Result<()> {
    let path = Path::new(&cfg.state_root).join("app/log-encryption.json");
    let body = match outcome {
        // No log encryption configured anywhere this boot: make sure no
        // handoff from an earlier boot survives — the file is init's
        // decision for THIS boot, and a stale one must not be readable
        // as an enabled handoff after readiness. Removal, not rewrite,
        // keeps "absent" unambiguous. (Defense in depth: honest renders
        // set no activation hint in this case either.)
        LogEncryptionHandoffFile::Unconfigured => {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(anyhow!(err).context(format!(
                        "removing stale log-encryption handoff {}",
                        path.display()
                    )));
                }
            }
            return Ok(());
        }
        LogEncryptionHandoffFile::DisabledMarker => {
            serde_json::to_vec_pretty(&serde_json::json!({ "disabled": true }))
                .context("serializing log-encryption disabled marker")?
        }
        LogEncryptionHandoffFile::Enabled(handoff) => {
            serde_json::to_vec_pretty(handoff).context("serializing log-encryption handoff")?
        }
    };
    writes::atomic_write(&path, &body, 0o640)
        .with_context(|| format!("writing log-encryption handoff {}", path.display()))?;
    chown::chown(&path, numeric_identity(cfg.app_uid, cfg.app_gid))
        .with_context(|| format!("chown {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
#[path = "main/tests/mod.rs"]
mod tests;
