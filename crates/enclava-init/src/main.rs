use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use enclava_init::chown::{self, ExecIdentity, IdentityKind};
use enclava_init::config::{Config, Mode, VolumeConfig};
use enclava_init::secrets::{DerivedSeed, OwnerSeed, Password};
use enclava_init::{
    kbs_fetch, log_relay, luks, seeds, socket, tls_certificate, trustee_verify, unlock, writes,
};
use sha2::{Digest as _, Sha256};

const DEFAULT_READY_FILE: &str = "/run/enclava/init-ready";
const DEFAULT_ERROR_FILE: &str = "/run/enclava/init-error";
const DEFAULT_KBS_PROXY_HEALTH_WAIT_SECONDS: u64 = 300;
const DEFAULT_KBS_PROXY_HEALTH_POLL_SECONDS: u64 = 2;
const KBS_PROXY_HEALTH_REQUEST_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_KBS_FETCH_ATTEMPTS: u32 = 30;
const DEFAULT_KBS_FETCH_RETRY_SLEEP_SECONDS: u64 = 2;
const DEFAULT_KBS_FETCH_REQUEST_TIMEOUT_SECONDS: u64 = 10;
const CADDY_RUNTIME_HANDOFF_PATH: &str = "/run/enclava/caddy-runtime";
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
            let message = format!("{e:#}\n");
            record_failure_file(&message);
            tracing::error!(error = %e, "enclava-init failed");
            eprintln!("enclava-init: {e:#}");
            if stay_alive_enabled() {
                tracing::error!(
                    "enclava-init failed; keeping sidecar alive so diagnostics remain readable"
                );
                stay_alive_after_failure();
            }
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    record_stage("loading config").ok();
    let cfg_path = std::env::var("ENCLAVA_INIT_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/enclava-init/config.toml"));
    let cfg = Config::load(&cfg_path).with_context(|| format!("loading {}", cfg_path.display()))?;
    let _log_relay = start_log_relay_if_configured().context("starting encrypted log relay")?;
    record_stage("validating signed config").ok();
    validate_configmap_transport_against_signed_cc_init_data(&cfg)?;
    let stay_alive = stay_alive_enabled();
    let ready_file = ready_file_path();
    if stay_alive {
        clear_ready_file(&ready_file)
            .with_context(|| format!("clearing stale ready file {}", ready_file.display()))?;
    }

    record_stage("verifying deployment authorization").ok();
    if !run_in_tee_verification(&cfg)? {
        return Err(anyhow!(
            "deployment authorization verification did not complete"
        ));
    }

    record_stage("waiting for owner seed").ok();
    let owner = match cfg.mode {
        Mode::Password => acquire_owner_seed_password(&cfg)?,
        Mode::Autounlock => acquire_owner_seed_autounlock(&cfg)?,
    };
    clear_error_file(&error_file_path());

    record_stage("opening luks volumes").ok();
    open_luks_volumes(&cfg, &owner)?;
    record_stage("preparing mount ownership").ok();
    prepare_mount_ownership(&cfg)?;

    record_stage("provisioning static tls certificate").ok();
    provision_static_tls_certificate(&cfg).context("provisioning static TLS certificate")?;
    record_stage("writing component seeds").ok();
    write_per_component_seeds(&cfg, &owner)?;

    if stay_alive {
        record_stage("waiting for workload containers").ok();
        let workload_namespaces = wait_for_container_start_sentinels(&cfg)
            .context("waiting for workload containers before bind-mounting decrypted volumes")?;
        record_stage("binding workload mount namespaces").ok();
        bind_mounts_into_workload_namespaces(&cfg, &workload_namespaces)
            .context("binding decrypted mounts into workload namespaces")?;
        record_stage("seeding caddy runtime handoff").ok();
        seed_caddy_runtime_handoff(&cfg).context("seeding caddy runtime handoff")?;
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

fn start_log_relay_if_configured() -> Result<Option<std::thread::JoinHandle<()>>> {
    let Some(config) = log_relay::LogRelayConfig::from_env_optional() else {
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
    std::env::var("ENCLAVA_INIT_READY_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_READY_FILE))
}

fn error_file_path() -> PathBuf {
    std::env::var("ENCLAVA_INIT_ERROR_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_ERROR_FILE))
}

fn stage_file_path() -> PathBuf {
    std::env::var("ENCLAVA_INIT_STAGE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_STAGE_FILE))
}

fn started_dir_path() -> PathBuf {
    std::env::var("ENCLAVA_INIT_STARTED_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/enclava/containers"))
}

#[path = "main/namespace_bind.rs"]
mod namespace_bind;
#[cfg(test)]
use namespace_bind::{
    ExpectedIdentity, MountSourceStrategy, SentinelRecord, WorkloadNamespace,
    bind_mount_plan_for_workload, expected_identity, find_workload_pid_by_env,
    mount_source_strategy, namespace_source, parse_sentinel_record, paths_resolve_to_same_object,
    validate_sentinel_name, validate_sentinel_record, workload_proc_root_path,
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

fn record_failure_file(message: &str) {
    let body = format_failure_message(message);
    let path = error_file_path();
    if let Err(err) = writes::atomic_write(&path, body.as_bytes(), 0o644) {
        eprintln!("enclava-init: failed to write {}: {err}", path.display());
    }
    let termination_path = std::env::var("ENCLAVA_INIT_TERMINATION_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/dev/termination-log"));
    if let Err(err) = writes::atomic_write(&termination_path, body.as_bytes(), 0o644) {
        eprintln!(
            "enclava-init: failed to write {}: {err}",
            termination_path.display()
        );
    }
}

fn record_stage(stage: &str) -> Result<()> {
    tracing::info!(stage, "enclava-init stage");
    writes::atomic_write(&stage_file_path(), format!("{stage}\n").as_bytes(), 0o644)
        .map_err(Into::into)
}

fn format_failure_message(message: &str) -> String {
    match std::fs::read_to_string(stage_file_path()) {
        Ok(stage) => {
            let stage = stage.trim();
            if stage.is_empty() {
                message.to_string()
            } else {
                format!("last_stage={stage}\n{message}")
            }
        }
        Err(_) => message.to_string(),
    }
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
        if let Err(err) = sync_caddy_runtime_back(cfg) {
            tracing::warn!(error = %err, "caddy runtime persistence sync failed");
        }
        std::thread::sleep(Duration::from_secs(CADDY_RUNTIME_SYNC_INTERVAL_SECONDS));
    }
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

fn validate_configmap_transport_against_signed_cc_init_data(cfg: &Config) -> Result<()> {
    if !cfg.trustee_policy_read_available {
        return Ok(());
    }
    let cc_path = cfg
        .cc_init_data_path
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires cc_init_data_path"))?;
    let cc_toml = std::fs::read_to_string(cc_path).with_context(|| format!("reading {cc_path}"))?;
    let parsed: toml::Value =
        toml::from_str(&cc_toml).with_context(|| format!("parsing {cc_path}"))?;
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
        "workload_artifacts_ca_cert_pem",
        cfg.workload_artifacts_ca_cert_pem.as_deref(),
        "workload-artifacts-ca-cert-pem",
    )?;
    require_signed_config_match(
        data,
        "kbs_attestation_token_url",
        Some(&cfg.kbs_attestation_token_url),
        "kbs-attestation-token-url",
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

    Ok(())
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

fn acquire_owner_seed_autounlock(cfg: &Config) -> Result<OwnerSeed> {
    let url = cfg
        .kbs_url
        .as_deref()
        .ok_or_else(|| anyhow!("autounlock mode requires kbs_url"))?;
    let path = cfg
        .kbs_resource_path
        .as_deref()
        .ok_or_else(|| anyhow!("autounlock mode requires kbs_resource_path"))?;
    wait_for_kbs_proxy_health_if_needed(url).context("waiting for local KBS proxy health")?;
    let mut client = kbs_fetch::KbsClient::new(url.into(), path.into());
    client.timeout = kbs_fetch_request_timeout();
    let wrap =
        fetch_wrap_key_with_retries(&client).with_context(|| "fetching wrap key from KBS")?;
    Ok(OwnerSeed(*wrap.as_bytes()))
}

fn fetch_wrap_key_with_retries(
    client: &kbs_fetch::KbsClient,
) -> Result<enclava_init::secrets::WrapKey> {
    let attempts = kbs_fetch_attempts();
    let sleep = kbs_fetch_retry_sleep_interval();

    for attempt in 1..=attempts {
        match client.fetch_wrap_key() {
            Ok(wrap_key) => return Ok(wrap_key),
            Err(err) => {
                let err_text = err.to_string();
                if attempt == attempts {
                    return Err(err).with_context(|| {
                        format!(
                            "KBS fetch failed after {attempts} attempt(s); last error: {err_text}"
                        )
                    });
                }
                tracing::warn!(
                    attempt,
                    attempts,
                    retry_sleep_seconds = sleep.as_secs(),
                    error = %err_text,
                    "KBS autounlock fetch failed; retrying"
                );
                std::thread::sleep(sleep);
            }
        }
    }

    Err(anyhow!("KBS fetch did not run"))
}

fn wait_for_kbs_proxy_health_if_needed(kbs_url: &str) -> Result<()> {
    let wait_timeout = kbs_proxy_health_wait_timeout(kbs_url);
    if wait_timeout.is_zero() {
        return Ok(());
    }
    let poll = kbs_proxy_health_poll_interval();
    let health_url = kbs_proxy_health_url(kbs_url);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(
            KBS_PROXY_HEALTH_REQUEST_TIMEOUT_SECONDS,
        ))
        .build()
        .context("building KBS proxy health client")?;

    tracing::info!(
        url = %health_url,
        wait_seconds = wait_timeout.as_secs(),
        poll_seconds = poll.as_secs(),
        "waiting for local KBS proxy before autounlock"
    );

    let started = Instant::now();
    loop {
        match client.get(&health_url).send() {
            Ok(resp) if kbs_proxy_health_status_is_ready(resp.status().as_u16()) => {
                tracing::info!(
                    elapsed_seconds = started.elapsed().as_secs(),
                    status = resp.status().as_u16(),
                    "local KBS proxy ready"
                );
                return Ok(());
            }
            Ok(resp) => {
                tracing::debug!(
                    status = resp.status().as_u16(),
                    "local KBS proxy health not ready"
                );
            }
            Err(err) => {
                tracing::debug!(
                    error = %err,
                    "local KBS proxy health request failed"
                );
            }
        }

        let elapsed = started.elapsed();
        if elapsed >= wait_timeout {
            return Err(anyhow!(
                "timed out after {}s waiting for {}",
                wait_timeout.as_secs(),
                health_url
            ));
        }
        std::thread::sleep(poll.min(wait_timeout - elapsed));
    }
}

fn kbs_proxy_health_wait_timeout(kbs_url: &str) -> Duration {
    let explicit = std::env::var("ENCLAVA_INIT_KBS_PROXY_HEALTH_WAIT_SECONDS")
        .ok()
        .or_else(|| std::env::var("KBS_PROXY_HEALTH_WAIT_SECONDS").ok());
    if let Some(value) = explicit {
        return parse_positive_seconds(&value)
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO);
    }
    if is_local_kbs_proxy_url(kbs_url) {
        Duration::from_secs(DEFAULT_KBS_PROXY_HEALTH_WAIT_SECONDS)
    } else {
        Duration::ZERO
    }
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

fn kbs_fetch_attempts() -> u32 {
    std::env::var("ENCLAVA_INIT_KBS_FETCH_RETRIES")
        .ok()
        .or_else(|| std::env::var("KBS_FETCH_RETRIES").ok())
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|attempts| *attempts > 0)
        .unwrap_or(DEFAULT_KBS_FETCH_ATTEMPTS)
}

fn kbs_fetch_retry_sleep_interval() -> Duration {
    let seconds = std::env::var("ENCLAVA_INIT_KBS_FETCH_RETRY_SLEEP_SECONDS")
        .ok()
        .or_else(|| std::env::var("KBS_FETCH_RETRY_SLEEP_SECONDS").ok())
        .as_deref()
        .and_then(parse_positive_seconds)
        .unwrap_or(DEFAULT_KBS_FETCH_RETRY_SLEEP_SECONDS);
    Duration::from_secs(seconds)
}

fn kbs_fetch_request_timeout() -> Duration {
    let seconds = std::env::var("ENCLAVA_INIT_KBS_FETCH_REQUEST_TIMEOUT_SECONDS")
        .ok()
        .or_else(|| std::env::var("KBS_FETCH_REQUEST_TIMEOUT_SECONDS").ok())
        .as_deref()
        .and_then(parse_positive_seconds)
        .unwrap_or(DEFAULT_KBS_FETCH_REQUEST_TIMEOUT_SECONDS);
    Duration::from_secs(seconds)
}

fn parse_positive_seconds(value: &str) -> Option<u64> {
    value.parse::<u64>().ok().filter(|seconds| *seconds > 0)
}

fn parse_positive_u32(value: &str) -> Option<u32> {
    value.parse::<u32>().ok().filter(|value| *value > 0)
}

fn kbs_proxy_health_url(kbs_url: &str) -> String {
    if let Ok(value) = std::env::var("ENCLAVA_INIT_ATTESTATION_PROXY_HEALTH_URL")
        .or_else(|_| std::env::var("ATTESTATION_PROXY_HEALTH_URL"))
    {
        if !value.trim().is_empty() {
            return value;
        }
    }

    let trimmed = kbs_url.trim_end_matches('/');
    let base = trimmed
        .strip_suffix("/cdh/resource")
        .unwrap_or(trimmed)
        .trim_end_matches('/');
    format!("{base}/health")
}

fn is_local_kbs_proxy_url(kbs_url: &str) -> bool {
    reqwest::Url::parse(kbs_url)
        .ok()
        .and_then(|url| {
            Some(matches!(
                (url.host_str()?, url.port_or_known_default()),
                ("127.0.0.1" | "localhost", Some(8081))
            ))
        })
        .unwrap_or_else(|| kbs_url.contains("127.0.0.1:8081") || kbs_url.contains("localhost:8081"))
}

fn kbs_proxy_health_status_is_ready(status: u16) -> bool {
    status == 200 || status == 423
}

fn open_luks_volumes(cfg: &Config, owner: &OwnerSeed) -> Result<()> {
    if dev_no_luks_override() {
        tracing::warn!("ENCLAVA_INIT_DEV_NO_LUKS=true — skipping luks open (debug builds only)");
        return Ok(());
    }
    open_one_volume(&cfg.state, owner)
        .with_context(|| format!("opening state volume {}", cfg.state.device))?;
    open_one_volume(&cfg.tls_state, owner)
        .with_context(|| format!("opening tls-state volume {}", cfg.tls_state.device))?;
    Ok(())
}

fn open_one_volume(vol: &VolumeConfig, owner: &OwnerSeed) -> Result<()> {
    let key = derive_volume_key(owner, &vol.hkdf_info)?;
    let device = Path::new(&vol.device);
    let opened = luks::format_if_unformatted_then_open(device, &vol.mapping_name, &key)?;
    luks::mount(&opened.mapper_path, Path::new(&vol.mount_path))?;
    tracing::info!(
        device = %vol.device,
        mapper = %opened.mapper_path.display(),
        mount = %vol.mount_path,
        "opened luks volume"
    );
    Ok(())
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
    tls_certificate::provision_static_tls_certificate(cfg, &persistent)?;
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
    Ok(())
}

fn sync_caddy_runtime_back(cfg: &Config) -> Result<()> {
    let persistent = caddy_tls_bind_dir(Path::new(&cfg.tls_state.mount_path));
    let runtime = Path::new(CADDY_RUNTIME_HANDOFF_PATH);
    sync_dir_contents(runtime, &persistent)
        .with_context(|| format!("copying {} to {}", runtime.display(), persistent.display()))
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

fn numeric_identity(uid: u32, gid: u32) -> ExecIdentity {
    ExecIdentity {
        uid,
        gid,
        kind: IdentityKind::Numeric,
    }
}

fn derive_volume_key(owner: &OwnerSeed, info: &str) -> Result<DerivedSeed> {
    let derived = seeds::derive(owner, info.as_bytes())?;
    Ok(derived)
}

fn run_in_tee_verification(cfg: &Config) -> Result<bool> {
    if !cfg.trustee_policy_read_available {
        return Ok(trustee_verify::verify_chain_or_skip(None)?);
    }

    let workload_url = cfg.workload_artifacts_url.as_deref().ok_or_else(|| {
        anyhow!("trustee_policy_read_available=true requires workload_artifacts_url")
    })?;
    let cc_path = cfg
        .cc_init_data_path
        .as_deref()
        .ok_or_else(|| anyhow!("verification requires cc_init_data_path"))?;
    let cc_bytes =
        std::fs::read(cc_path).with_context(|| format!("reading cc_init_data from {cc_path}"))?;
    let cc_claims = parse_cc_init_data_claims(&cc_bytes)?;
    let trusted_signing_keys = cfg
        .signing_service_trusted_pubkeys_json
        .as_deref()
        .ok_or_else(|| {
            anyhow!("receipt verification requires signing_service_trusted_pubkeys_json")
        })
        .and_then(|raw| {
            enclava_common::kbs_authorization::parse_authorization_trust_map(raw)
                .context("parsing signing_service_trusted_pubkeys_json")
        })?;

    let token = trustee_verify::resolve_kbs_attestation_token(
        std::env::var("KBS_ATTESTATION_TOKEN").ok().as_deref(),
        &cfg.kbs_attestation_token_url,
        std::time::Duration::from_secs(15),
    )
    .context("resolving KBS attestation token")?;
    let receipt_claims = parse_receipt_claims(&cc_bytes)?;
    let fetcher = trustee_verify::ReceiptArtifactFetcher {
        workload_artifacts_url: workload_url.into(),
        workload_artifacts_ca_cert_pem: cfg.workload_artifacts_ca_cert_pem.clone(),
        kbs_attestation_token: token,
        timeout: std::time::Duration::from_secs(15),
    };
    let (bundle, _authorization, authorization_key) = fetcher
        .fetch_and_verify(&receipt_claims, &trusted_signing_keys)
        .context("fetching and verifying deployment authorization")?;
    let signing_pk = ed25519_dalek::VerifyingKey::from_bytes(&authorization_key)
        .context("parsing trusted authorization key")?;
    let envelope = bundle.signed_policy_artifact.clone();
    let inputs = trustee_verify::VerifyInputs {
        policy_envelope: &envelope,
        artifacts: &bundle,
        cc_init_data_claims: &cc_claims,
        local_cc_init_data_toml: &cc_bytes,
        platform_trustee_policy_pubkey: None,
        signing_service_pubkey: Some(&signing_pk),
    };
    trustee_verify::verify_chain_or_skip(Some(&inputs)).map_err(Into::into)
}

fn parse_receipt_claims(toml_bytes: &[u8]) -> Result<trustee_verify::ReceiptClaims> {
    let value: toml::Value =
        toml::from_str(std::str::from_utf8(toml_bytes).context("cc_init_data not utf-8")?)
            .context("cc_init_data parse")?;
    let data = value
        .get("data")
        .ok_or_else(|| anyhow!("cc_init_data missing [data] section"))?;
    Ok(trustee_verify::ReceiptClaims {
        descriptor_core_hash: read_hex32(data, "descriptor_core_hash")?,
        expected_init_data_hash: Sha256::digest(toml_bytes).into(),
        namespace: read_string(data, "namespace")?,
        service_account: read_string(data, "service_account")?,
        tenant_instance_identity_hash: read_hex32(data, "identity_hash")?,
        image_digest: read_string(data, "image_digest")?,
        signer_subject: read_string(data, "signer_identity_subject")?,
        signer_issuer: read_string(data, "signer_identity_issuer")?,
    })
}

fn read_string(value: &toml::Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(toml::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("cc_init_data.data.{key} missing or empty"))
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

fn dev_no_luks_override() -> bool {
    cfg!(debug_assertions)
        && std::env::var("ENCLAVA_INIT_DEV_NO_LUKS")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false)
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

#[cfg(test)]
#[path = "main/tests/mod.rs"]
mod tests;
