use chrono::Utc;
use enclava_common::validate::{
    ValidateError, validate_app_name, validate_fqdn, validate_org_slug,
};
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{ConfigMap, Service},
};
use kube::{
    Api, Client,
    api::{ApiResource, DynamicObject, Patch, PatchParams},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::IpAddr;

/// Fixed PostgreSQL advisory lock id for serialising HAProxy ConfigMap edits.
///
/// The 64-bit value is the truncated SHA-256 of the literal string
/// "cap-haproxy-config" — chosen so the constant is reproducible from the
/// label rather than a magic number, and unlikely to clash with any other
/// advisory lock used elsewhere in the platform. See `haproxy_lock_id` for
/// the derivation.
pub const HAPROXY_LOCK_ID: i64 = haproxy_lock_id();

const fn haproxy_lock_id() -> i64 {
    0xe9_d6_37_8a_9d_46_b5_88u64 as i64
}

#[derive(Debug, thiserror::Error)]
pub enum EdgeRouteError {
    #[error("Kubernetes client error: {0}")]
    Kube(#[from] kube::Error),
    #[error("haproxy ConfigMap {namespace}/{name} is missing data key 'haproxy.cfg'")]
    MissingConfig { namespace: String, name: String },
    #[error("database error while taking HAProxy advisory lock: {0}")]
    Db(#[from] sqlx::Error),
    #[error("invalid hostname for HAProxy route: {0}")]
    InvalidHostname(#[from] ValidateError),
    #[error("invalid app name for HAProxy backend: {0}")]
    InvalidAppName(String),
    #[error(
        "haproxy ConfigMap {namespace}/{name} exceeds byte budget: bytes={bytes}, max_bytes={max_bytes}"
    )]
    ConfigTooLarge {
        namespace: String,
        name: String,
        bytes: usize,
        max_bytes: usize,
    },
}

/// Maximum serialized size of the shared HAProxy ConfigMap entry CAP is
/// willing to write. Kubernetes rejects objects over its own limit, but failing
/// early on CAP's side keeps the failure observable, avoids rendering a config
/// that the cluster will reject, and guards the shared object's growth (the
/// lesson from #18). 1 MiB leaves substantial headroom under Kubernetes' default
/// etcd request limit while catching unbounded route growth in tests.
pub const HAPROXY_CONFIGMAP_MAX_BYTES: usize = 1024 * 1024;

/// Pod-template annotation recording the generation (SHA-256 of the config
/// text) that the DaemonSet was last asked to load. Reconciliation compares the
/// desired generation against this value, not against the ConfigMap text, so a
/// retry after a partial failure (ConfigMap written, reload lost) redoes the
/// missing reload instead of returning early.
pub const HAPROXY_LOADED_HASH_ANNOTATION: &str = "cap.enclava.dev/haproxy-loaded-hash";

#[derive(Clone, Debug)]
pub struct EdgeRouteConfig {
    pub namespace: String,
    pub configmap_name: String,
    pub daemonset_name: String,
}

impl EdgeRouteConfig {
    pub fn from_env() -> Self {
        Self {
            namespace: std::env::var("TENANT_HAPROXY_NAMESPACE")
                .unwrap_or_else(|_| "tenant-envoy".to_string()),
            configmap_name: std::env::var("TENANT_HAPROXY_CONFIGMAP")
                .unwrap_or_else(|_| "haproxy-tenant".to_string()),
            daemonset_name: std::env::var("TENANT_HAPROXY_DAEMONSET")
                .unwrap_or_else(|_| "haproxy-tenant".to_string()),
        }
    }
}

/// A single SNI -> backend route to add to the tenant HAProxy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SniRoute {
    /// Validated SNI hostname (FQDN).
    pub host: String,
    /// Validated HAProxy backend identifier (alphanumeric + underscore only).
    pub backend_name: String,
    /// Backend target `ip_or_hostname:port` -- not user input.
    pub target: String,
}

impl SniRoute {
    pub fn new(host: &str, backend_name: &str, target: &str) -> Result<Self, EdgeRouteError> {
        validate_fqdn(host)?;
        if backend_name.is_empty()
            || !backend_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            return Err(EdgeRouteError::InvalidAppName(format!(
                "invalid backend name: {backend_name}"
            )));
        }
        // Target is constructed from a Service ClusterIP / DNS name + a
        // numeric port; we still strict-validate to keep the contract clear.
        if target.is_empty()
            || target
                .bytes()
                .any(|b| !b.is_ascii() || b.is_ascii_whitespace())
        {
            return Err(EdgeRouteError::InvalidAppName(format!(
                "invalid backend target: {target}"
            )));
        }
        Ok(Self {
            host: host.to_string(),
            backend_name: backend_name.to_string(),
            target: target.to_string(),
        })
    }
}

/// Insert two SNI routes (app + TEE) for an app under a single advisory lock.
pub async fn ensure_haproxy_routes(
    pool: &PgPool,
    config: &EdgeRouteConfig,
    routes: &[SniRoute],
) -> Result<(), EdgeRouteError> {
    mutate_haproxy_config(pool, config, |current| {
        let mut out = current.to_string();
        for r in routes {
            out = render_route_into(&out, r);
        }
        out
    })
    .await?;

    for r in routes {
        tracing::info!(host = %r.host, backend = %r.backend_name, target = %r.target, "ensured tenant HAProxy SNI route");
    }
    Ok(())
}

pub async fn remove_haproxy_routes(
    pool: &PgPool,
    config: &EdgeRouteConfig,
    routes: &[(String, String)],
) -> Result<(), EdgeRouteError> {
    let changed = mutate_haproxy_config(pool, config, |current| {
        let mut out = current.to_string();
        for (backend, host) in routes {
            out = remove_route_from(&out, backend, host);
        }
        out
    })
    .await?;

    if changed {
        for (backend, host) in routes {
            tracing::info!(host = %host, backend = %backend, "removed tenant HAProxy SNI route");
        }
    }
    Ok(())
}

/// Kubernetes operations performed while reconciling HAProxy routing.
///
/// This is a seam, not an abstraction over all of `kube`: it exposes exactly
/// the reads and writes `reconcile_haproxy` needs so that the reconciliation
/// logic is independently testable against a fake that simulates partial
/// failures and lost responses (the failure mode described in #42).
trait HaproxyKubeOps {
    /// Read the current `haproxy.cfg` entry from the shared ConfigMap.
    async fn read_configmap(&self) -> Result<String, EdgeRouteError>;

    /// Write the `haproxy.cfg` entry. Idempotent: writing identical text is a
    /// no-op that still succeeds.
    async fn write_configmap(&self, cfg: &str) -> Result<(), EdgeRouteError>;

    /// Read the pod-template `haproxy-loaded-hash` annotation, recording the
    /// generation the DaemonSet was last asked to load. `None` means no reload
    /// has ever been recorded.
    async fn read_loaded_hash(&self) -> Result<Option<String>, EdgeRouteError>;

    /// Restart the DaemonSet so it loads the new config, stamping both the
    /// `haproxy-restarted-at` trigger and the `haproxy-loaded-hash` generation.
    /// Idempotent: stamping the same hash repeatedly converges.
    async fn restart_with_hash(&self, hash: &str) -> Result<(), EdgeRouteError>;
}

/// Stable generation of a rendered HAProxy config: the hex SHA-256 of its text.
/// Used to compare desired against applied state independently of the ConfigMap
/// text itself, so a missing reload after a partial failure is detectable.
fn config_generation(cfg: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cfg.as_bytes());
    hex::encode(hasher.finalize())
}

/// Reconcile desired HAProxy config against applied state as generations, not
/// as a two-call request side effect. Returns `true` when any Kubernetes object
/// was actually mutated.
///
/// Convergence rules (make retries idempotent after any individual call fails):
/// - `config_dirty = desired != current` -- ConfigMap text changed.
/// - `reload_needed = loaded != Some(desired_gen)` -- the live proxy has not
///   been told to load this generation yet.
/// - If neither, the system has converged; nothing is written.
/// - If the config is dirty, the ConfigMap is written. If a reload is still
///   needed, the DaemonSet is restarted and stamped with `desired_gen`.
///
/// Because the reload decision keys on the DaemonSet's stamped generation
/// rather than on the ConfigMap text, a retry after "ConfigMap patch succeeded,
/// reload patch failed/lost" sees `reload_needed` still true and redoes only the
/// reload -- instead of the old behaviour of returning success because the
/// ConfigMap text already matched.
async fn reconcile_haproxy<K: HaproxyKubeOps>(
    ops: &K,
    config: &EdgeRouteConfig,
    mutate: impl FnOnce(&str) -> String,
) -> Result<bool, EdgeRouteError> {
    let current = ops.read_configmap().await?;
    let desired = mutate(&current);

    if desired.len() > HAPROXY_CONFIGMAP_MAX_BYTES {
        return Err(EdgeRouteError::ConfigTooLarge {
            namespace: config.namespace.clone(),
            name: config.configmap_name.clone(),
            bytes: desired.len(),
            max_bytes: HAPROXY_CONFIGMAP_MAX_BYTES,
        });
    }

    let desired_gen = config_generation(&desired);
    let config_dirty = desired != current;
    let loaded = ops.read_loaded_hash().await?;
    let reload_needed = loaded.as_deref() != Some(desired_gen.as_str());

    if !config_dirty && !reload_needed {
        return Ok(false);
    }

    if config_dirty {
        ops.write_configmap(&desired).await?;
    }

    if reload_needed {
        ops.restart_with_hash(&desired_gen).await?;
    }

    Ok(true)
}

async fn mutate_haproxy_config<F>(
    pool: &PgPool,
    config: &EdgeRouteConfig,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: FnOnce(&str) -> String,
{
    // Take a session-scoped transaction and a transaction-scoped advisory
    // lock. The lock is released automatically on commit/rollback. This is
    // the multi-replica replacement for the previous process-local Mutex.
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(HAPROXY_LOCK_ID)
        .execute(&mut *tx)
        .await?;

    let ops = KubeHaproxyOps::new(config).await?;
    let changed = reconcile_haproxy(&ops, config, mutate).await?;

    tx.commit().await?;
    Ok(changed)
}

/// Production [`HaproxyKubeOps`] backed by a live Kubernetes client.
struct KubeHaproxyOps {
    namespace: String,
    configmap_name: String,
    daemonset_name: String,
    cm_api: Api<ConfigMap>,
    ds_api: Api<DaemonSet>,
}

impl KubeHaproxyOps {
    async fn new(config: &EdgeRouteConfig) -> Result<Self, EdgeRouteError> {
        let client = Client::try_default().await?;
        Ok(Self {
            namespace: config.namespace.clone(),
            configmap_name: config.configmap_name.clone(),
            daemonset_name: config.daemonset_name.clone(),
            cm_api: Api::namespaced(client.clone(), &config.namespace),
            ds_api: Api::namespaced(client, &config.namespace),
        })
    }

    fn missing_config(&self) -> EdgeRouteError {
        EdgeRouteError::MissingConfig {
            namespace: self.namespace.clone(),
            name: self.configmap_name.clone(),
        }
    }
}

impl HaproxyKubeOps for KubeHaproxyOps {
    async fn read_configmap(&self) -> Result<String, EdgeRouteError> {
        let cm = self.cm_api.get(&self.configmap_name).await?;
        cm.data
            .as_ref()
            .and_then(|data| data.get("haproxy.cfg"))
            .cloned()
            .ok_or_else(|| self.missing_config())
    }

    async fn write_configmap(&self, cfg: &str) -> Result<(), EdgeRouteError> {
        let patch = json!({
            "data": {
                "haproxy.cfg": cfg,
            }
        });
        self.cm_api
            .patch(
                &self.configmap_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await?;
        Ok(())
    }

    async fn read_loaded_hash(&self) -> Result<Option<String>, EdgeRouteError> {
        let ds = self.ds_api.get(&self.daemonset_name).await?;
        Ok(ds
            .spec
            .map(|spec| spec.template)
            .and_then(|template| template.metadata)
            .and_then(|meta| meta.annotations)
            .and_then(|annotations| annotations.get(HAPROXY_LOADED_HASH_ANNOTATION).cloned()))
    }

    async fn restart_with_hash(&self, hash: &str) -> Result<(), EdgeRouteError> {
        let restart_patch = json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "cap.enclava.dev/haproxy-restarted-at": Utc::now().to_rfc3339(),
                            HAPROXY_LOADED_HASH_ANNOTATION: hash,
                        }
                    }
                }
            }
        });
        self.ds_api
            .patch(
                &self.daemonset_name,
                &PatchParams::default(),
                &Patch::Merge(&restart_patch),
            )
            .await?;
        Ok(())
    }
}

/// Build a backend identifier scoped by tenant `org_slug` and tagged by the
/// destination port (`app` for the workload, `tee` for the attestation
/// channel). Both inputs validate; tenant scoping prevents two orgs that pick
/// the same `app_name` from colliding on the HAProxy backend block.
pub fn backend_name_for(
    org_slug: &str,
    app_name: &str,
    tag: BackendTag,
) -> Result<String, EdgeRouteError> {
    validate_org_slug(org_slug)?;
    validate_app_name(app_name)?;
    let sanitized = app_name.replace('-', "_");
    Ok(format!("be_cap_{org_slug}_{sanitized}_{}", tag.as_str()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendTag {
    App,
    Tee,
}

impl BackendTag {
    fn as_str(self) -> &'static str {
        match self {
            BackendTag::App => "app",
            BackendTag::Tee => "tee",
        }
    }
}

/// Build the backend target string for a Service in the given namespace and
/// port. Inputs are validated DNS labels; the namespace and app come from
/// trusted DB rows but we still validate as defense in depth.
pub async fn resolve_backend_target(
    app_name: &str,
    namespace: &str,
    port: u16,
) -> Result<String, EdgeRouteError> {
    let client = Client::try_default().await?;
    let service_api: Api<Service> = Api::namespaced(client, namespace);
    let service = service_api.get(app_name).await?;
    let cluster_ip = service
        .spec
        .and_then(|spec| spec.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .unwrap_or_else(|| format!("{app_name}.{namespace}.svc.cluster.local"));
    Ok(format!("{cluster_ip}:{port}"))
}

fn gateway_api_resource() -> ApiResource {
    ApiResource {
        group: "gateway.networking.k8s.io".to_string(),
        version: "v1".to_string(),
        api_version: "gateway.networking.k8s.io/v1".to_string(),
        kind: "Gateway".to_string(),
        plural: "gateways".to_string(),
    }
}

/// Resolve the in-cluster dataplane IP for an instance-scoped tenant Gateway.
///
/// This is intended for internal platform callers such as PaaS workers that
/// must preserve the tenant TEE Host/SNI while avoiding public edge hairpinning.
pub async fn resolve_gateway_address(
    app_name: &str,
    namespace: &str,
) -> Result<Option<IpAddr>, EdgeRouteError> {
    validate_app_name(app_name)
        .map_err(|_| EdgeRouteError::InvalidAppName(format!("invalid app name: {app_name}")))?;
    let client = Client::try_default().await?;
    let api: Api<DynamicObject> = Api::namespaced_with(client, namespace, &gateway_api_resource());
    let gateway_name = format!("tenant-gateway-{app_name}");
    let gateway = match api.get(&gateway_name).await {
        Ok(gateway) => gateway,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let serialized = serde_json::to_value(&gateway).unwrap_or_else(|_| gateway.data.clone());
    Ok(gateway_resolve_ip_from_value(&serialized)
        .or_else(|| gateway_resolve_ip_from_value(&gateway.data)))
}

fn gateway_resolve_ip_from_value(value: &Value) -> Option<IpAddr> {
    value
        .pointer("/status/addresses")
        .and_then(Value::as_array)?
        .iter()
        .filter(|entry| {
            entry
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| kind.eq_ignore_ascii_case("IPAddress"))
        })
        .filter_map(|entry| entry.get("value").and_then(Value::as_str))
        .find_map(|value| value.parse::<IpAddr>().ok())
}

fn render_route_into(config: &str, route: &SniRoute) -> String {
    let SniRoute {
        host,
        backend_name,
        target,
    } = route;
    let cleaned =
        remove_backend_block(&remove_route_from(config, backend_name, host), backend_name);
    let use_backend = format!("  use_backend {backend_name} if {{ req.ssl_sni -i {host} }}");
    let server = format!("  server tenant {target} check");
    let backend = format!(
        "backend {backend_name}\n  # Generated from CAP caddy-sni-route ConfigMap.\n  # TLS termination remains inside the confidential workload.\n{server}\n"
    );

    let mut out = cleaned;
    if !out.lines().any(|line| line.trim() == use_backend.trim())
        && let Some(index) = out.find("  default_backend be_reject")
    {
        out.insert_str(index, &format!("{use_backend}\n"));
    }

    if !out
        .lines()
        .any(|line| line.trim() == format!("backend {backend_name}"))
    {
        while out.ends_with("\n\n") {
            out.pop();
        }
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push('\n');
        out.push_str(&backend);
    }

    out
}

fn remove_route_from(config: &str, backend_name: &str, domain: &str) -> String {
    // First pass: remove only the SNI mapping line for this (backend, host).
    // Other hostnames may still route to the same backend (e.g. the platform
    // hostname keeps its mapping when only the custom domain is removed), so
    // tearing down the backend block here unconditionally would leave dangling
    // `use_backend` references.
    let use_backend = format!("use_backend {backend_name} if {{ req.ssl_sni -i {domain} }}");
    let pruned_lines: Vec<&str> = config
        .lines()
        .filter(|line| line.trim() != use_backend)
        .collect();

    // Second pass: only drop the `backend {name}` block if no remaining
    // `use_backend {name} ...` line references it.
    let backend_use_prefix = format!("use_backend {backend_name} ");
    let still_referenced = pruned_lines
        .iter()
        .any(|line| line.trim().starts_with(&backend_use_prefix));

    let final_lines: Vec<&str> = if still_referenced {
        pruned_lines
    } else {
        let mut out = Vec::with_capacity(pruned_lines.len());
        let mut skipping_backend = false;
        for line in pruned_lines {
            let trimmed = line.trim();
            if trimmed == format!("backend {backend_name}") {
                skipping_backend = true;
                continue;
            }
            if skipping_backend {
                if trimmed.starts_with("backend ") {
                    skipping_backend = false;
                } else {
                    continue;
                }
            }
            out.push(line);
        }
        out
    };

    let mut rendered = final_lines.join("\n");
    if config.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

fn remove_backend_block(config: &str, backend_name: &str) -> String {
    let mut out = Vec::new();
    let mut skipping_backend = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed == format!("backend {backend_name}") {
            skipping_backend = true;
            continue;
        }
        if skipping_backend {
            if trimmed.starts_with("backend ") {
                skipping_backend = false;
            } else {
                continue;
            }
        }
        out.push(line);
    }
    let mut rendered = out.join("\n");
    if config.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn lock_id_matches_label_hash() {
        let mut hasher = Sha256::new();
        hasher.update(b"cap-haproxy-config");
        let digest = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest[0..8]);
        let computed = i64::from_be_bytes(buf);
        assert_eq!(computed, HAPROXY_LOCK_ID);
    }

    #[test]
    fn backend_name_includes_tenant_slug() {
        let n = backend_name_for("abcd1234", "test-app", BackendTag::App).unwrap();
        assert_eq!(n, "be_cap_abcd1234_test_app_app");
        let n = backend_name_for("abcd1234", "test-app", BackendTag::Tee).unwrap();
        assert_eq!(n, "be_cap_abcd1234_test_app_tee");
    }

    #[test]
    fn backend_name_separates_same_app_in_different_orgs() {
        // Two orgs deploying an app called `api` must not collide.
        let a = backend_name_for("aaaaaaaa", "api", BackendTag::App).unwrap();
        let b = backend_name_for("bbbbbbbb", "api", BackendTag::App).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn backend_name_rejects_invalid_inputs() {
        assert!(backend_name_for("abcd1234", "Bad", BackendTag::App).is_err());
        assert!(backend_name_for("abcd1234", "a/b", BackendTag::App).is_err());
        assert!(backend_name_for("abcd1234", "", BackendTag::App).is_err());
        assert!(backend_name_for("ABCD1234", "ok", BackendTag::App).is_err());
        assert!(backend_name_for("abc", "ok", BackendTag::App).is_err());
        assert!(backend_name_for("", "ok", BackendTag::App).is_err());
    }

    #[test]
    fn sni_route_validates_host() {
        let r = SniRoute::new(
            "test-app.abcd1234.enclava.dev",
            "be_cap_test_app_app",
            "10.43.1.2:443",
        );
        assert!(r.is_ok());
    }

    #[test]
    fn sni_route_rejects_injection_in_host() {
        // backticks, semicolons, newlines, NUL, quotes, braces -- all blocked
        // by validate_fqdn.
        for bad in [
            "host}\n  acl evil",
            "host;\n",
            "host`",
            "host\0",
            "host'",
            "host\"",
            "host`whoami`",
            "host\nuse_backend evil",
        ] {
            assert!(
                SniRoute::new(bad, "be_cap_a_app", "10.0.0.1:443").is_err(),
                "expected error for {bad}"
            );
        }
    }

    #[test]
    fn sni_route_rejects_injection_in_backend_name() {
        for bad in ["be cap", "be-cap", "be;evil", "be\nevil", ""] {
            assert!(SniRoute::new("a.b.c", bad, "10.0.0.1:443").is_err());
        }
    }

    #[test]
    fn render_inserts_use_backend_before_default() {
        let cfg =
            "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n";
        let r = SniRoute::new(
            "test-app.abcd1234.enclava.dev",
            "be_cap_test_app_app",
            "10.43.1.2:443",
        )
        .unwrap();
        let rendered = render_route_into(cfg, &r);
        let use_idx = rendered.find("use_backend be_cap_test_app_app").unwrap();
        let def_idx = rendered.find("default_backend be_reject").unwrap();
        assert!(use_idx < def_idx);
        assert!(rendered.contains("backend be_cap_test_app_app"));
        assert!(rendered.contains("server tenant 10.43.1.2:443 check"));
    }

    #[test]
    fn render_is_idempotent() {
        let cfg =
            "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n";
        let r = SniRoute::new(
            "test-app.abcd1234.enclava.dev",
            "be_cap_test_app_app",
            "10.43.1.2:443",
        )
        .unwrap();
        let once = render_route_into(cfg, &r);
        let twice = render_route_into(&once, &r);
        assert_eq!(once, twice);
    }

    #[test]
    fn render_two_routes_app_and_tee() {
        let cfg =
            "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n";
        let app =
            SniRoute::new("api.abcd1234.enclava.dev", "be_cap_api_app", "10.0.0.1:443").unwrap();
        let tee = SniRoute::new(
            "api.abcd1234.tee.enclava.dev",
            "be_cap_api_tee",
            "10.0.0.1:8081",
        )
        .unwrap();
        let mut out = cfg.to_string();
        out = render_route_into(&out, &app);
        out = render_route_into(&out, &tee);
        assert!(
            out.contains(
                "use_backend be_cap_api_app if { req.ssl_sni -i api.abcd1234.enclava.dev }"
            )
        );
        assert!(out.contains(
            "use_backend be_cap_api_tee if { req.ssl_sni -i api.abcd1234.tee.enclava.dev }"
        ));
        assert!(out.contains("server tenant 10.0.0.1:443 check"));
        assert!(out.contains("server tenant 10.0.0.1:8081 check"));
    }

    #[test]
    fn remove_route_strips_backend_block_and_use_line() {
        let cfg = "frontend fe_443\n  bind :443\n  use_backend be_cap_x_app if { req.ssl_sni -i x.y.z }\n  default_backend be_reject\n\nbackend be_cap_x_app\n  server tenant 1.2.3.4:443 check\n\nbackend be_reject\n";
        let out = remove_route_from(cfg, "be_cap_x_app", "x.y.z");
        assert!(!out.contains("be_cap_x_app"));
        assert!(out.contains("backend be_reject"));
    }

    #[test]
    fn remove_route_keeps_shared_backend_when_other_hosts_use_it() {
        // Custom domain and platform hostname both target the same app
        // backend. Removing only the custom domain mapping must leave the
        // backend block intact so the platform hostname's `use_backend`
        // still resolves.
        let cfg = "frontend fe_443\n  bind :443\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i app.abcd1234.enclava.dev }\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i custom.example.com }\n\
            \x20\x20default_backend be_reject\n\nbackend be_cap_x_app\n  server tenant 1.2.3.4:443 check\n\nbackend be_reject\n";
        let out = remove_route_from(cfg, "be_cap_x_app", "custom.example.com");
        assert!(
            out.contains("backend be_cap_x_app"),
            "shared backend block must be preserved while another host still references it: {out}",
        );
        assert!(!out.contains("custom.example.com"));
        assert!(out.contains("app.abcd1234.enclava.dev"));
    }

    #[test]
    fn remove_route_drops_backend_only_when_last_reference_goes() {
        let cfg = "frontend fe_443\n  bind :443\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i a.host }\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i b.host }\n\
            \x20\x20default_backend be_reject\n\nbackend be_cap_x_app\n  server tenant 1.2.3.4:443 check\n\nbackend be_reject\n";
        let after_first = remove_route_from(cfg, "be_cap_x_app", "a.host");
        assert!(after_first.contains("backend be_cap_x_app"));
        let after_second = remove_route_from(&after_first, "be_cap_x_app", "b.host");
        assert!(!after_second.contains("be_cap_x_app"));
    }

    #[test]
    fn render_refreshes_shared_backend_target() {
        let cfg = "frontend fe_443\n  bind :443\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i app.abcd1234.enclava.dev }\n\
            \x20\x20use_backend be_cap_x_app if { req.ssl_sni -i custom.example.com }\n\
            \x20\x20default_backend be_reject\n\nbackend be_cap_x_app\n  server tenant 1.2.3.4:443 check\n\nbackend be_reject\n";
        let route = SniRoute::new("custom.example.com", "be_cap_x_app", "5.6.7.8:443").unwrap();

        let rendered = render_route_into(cfg, &route);

        assert!(rendered.contains("app.abcd1234.enclava.dev"));
        assert!(rendered.contains("custom.example.com"));
        assert!(rendered.contains("server tenant 5.6.7.8:443 check"));
        assert!(!rendered.contains("server tenant 1.2.3.4:443 check"));
    }

    #[test]
    fn gateway_resolve_ip_reads_gateway_status_address() {
        let gateway = json!({
            "status": {
                "addresses": [
                    {"type": "Hostname", "value": "ignored.internal"},
                    {"type": "IPAddress", "value": "10.43.77.218"}
                ]
            }
        });

        assert_eq!(
            gateway_resolve_ip_from_value(&gateway),
            Some("10.43.77.218".parse().unwrap())
        );
    }

    #[test]
    fn gateway_resolve_ip_ignores_missing_or_invalid_status_address() {
        for gateway in [
            json!({}),
            json!({"status": {"addresses": []}}),
            json!({"status": {"addresses": [{"type": "IPAddress", "value": "not-an-ip"}]}}),
        ] {
            assert_eq!(gateway_resolve_ip_from_value(&gateway), None);
        }
    }

    // -- reconcile_haproxy: convergence after partial failure (#42) --

    /// Mutable in-memory state behind [`OpsRecorder`]: the rendered config, the
    /// DaemonSet's stamped loaded-hash, which (if any) operation should "lose
    /// its response" by applying its side effect before erroring, and call
    /// counters for assertions.
    #[derive(Default, Clone)]
    struct FakeOpsState {
        configmap: String,
        loaded_hash: Option<String>,
        /// Operation whose response is lost: the side effect is applied, then
        /// an error is returned. Set to `Some("restart")` to model "ConfigMap
        /// patch succeeded, reload patch failed".
        lose_response: Option<&'static str>,
        write_calls: usize,
        restart_calls: usize,
    }

    fn test_config() -> EdgeRouteConfig {
        EdgeRouteConfig {
            namespace: "cap-edge".to_string(),
            configmap_name: "haproxy-config".to_string(),
            daemonset_name: "haproxy".to_string(),
        }
    }

    fn base_cfg() -> String {
        "frontend fe_443\n  bind :443\n  default_backend be_reject\n\nbackend be_reject\n"
            .to_string()
    }

    /// Mutate fn for reconcile tests: append a route block if absent, mirroring
    /// the idempotency of the production `render_route_into`. Convergence logic
    /// only holds when the mutate fn returns identical text for already-applied
    /// input, so `config_dirty` can be false once the desired config is live.
    fn append_route(cfg: &str) -> String {
        const BLOCK: &str = "\nbackend be_cap_new_app\n  server tenant 10.0.0.9:443 check\n";
        if cfg.contains("backend be_cap_new_app") {
            cfg.to_string()
        } else {
            format!("{cfg}{BLOCK}")
        }
    }

    fn generation(cfg: &str) -> String {
        config_generation(cfg)
    }

    #[tokio::test]
    async fn reconcile_writes_config_and_restarts_on_first_apply() {
        // Fresh DaemonSet: no config ever loaded.
        let ops = OpsRecorder::new(FakeOpsState {
            configmap: base_cfg(),
            loaded_hash: None,
            ..Default::default()
        });

        let changed = reconcile_haproxy(&ops, &test_config(), append_route)
            .await
            .unwrap();

        assert!(changed, "first apply should mutate objects");
        assert_eq!(ops.write_calls(), 1, "ConfigMap written once");
        assert_eq!(ops.restart_calls(), 1, "DaemonSet restarted once");
        assert_eq!(
            ops.loaded_hash(),
            Some(generation(&append_route(&base_cfg()))),
            "loaded-hash stamped with the desired generation"
        );
    }

    #[tokio::test]
    async fn reconcile_converges_when_config_and_loaded_hash_match() {
        // ConfigMap already holds the desired text and the DaemonSet already
        // loaded exactly that generation: nothing to do.
        let desired = append_route(&base_cfg());
        let ops = OpsRecorder::new(FakeOpsState {
            configmap: desired.clone(),
            loaded_hash: Some(generation(&desired)),
            ..Default::default()
        });

        let changed = reconcile_haproxy(&ops, &test_config(), append_route)
            .await
            .unwrap();

        assert!(!changed, "converged state needs no writes");
        assert_eq!(ops.write_calls(), 0);
        assert_eq!(ops.restart_calls(), 0);
    }

    #[tokio::test]
    async fn reconcile_redoes_reload_when_config_written_but_reload_lost() {
        // #42 regression: ConfigMap patch succeeded (desired text is live) but
        // the reload patch failed. The OLD code saw desired==current and
        // returned Ok(false) without reloading. The new code must see that the
        // DaemonSet never loaded this generation and redo the reload.
        let desired = append_route(&base_cfg());
        let ops = OpsRecorder::new(FakeOpsState {
            configmap: desired.clone(),
            loaded_hash: Some(generation(&base_cfg())), // stale: never reloaded
            ..Default::default()
        });

        let changed = reconcile_haproxy(&ops, &test_config(), append_route)
            .await
            .unwrap();

        assert!(changed, "a missing reload must still report a change");
        assert_eq!(
            ops.write_calls(),
            0,
            "ConfigMap already matches desired text; no rewrite needed"
        );
        assert_eq!(ops.restart_calls(), 1, "the missing reload is redone");
        assert_eq!(ops.loaded_hash(), Some(generation(&desired)));
    }

    #[tokio::test]
    async fn reconcile_is_safe_after_lost_reload_response() {
        // The reload's side effect (hash stamped) applies but the response is
        // lost, so the caller retries. The retry must converge (not restart
        // again) and not error.
        let desired = append_route(&base_cfg());
        let ops = OpsRecorder::new(FakeOpsState {
            configmap: desired.clone(),
            loaded_hash: Some(generation(&base_cfg())),
            // First reconcile: lose the reload response AFTER stamping the hash.
            lose_response: Some("restart"),
            ..Default::default()
        });

        let first = reconcile_haproxy(&ops, &test_config(), append_route).await;
        assert!(
            first.is_err(),
            "lost reload response must surface as an error on the failed attempt"
        );
        assert_eq!(ops.restart_calls(), 1);
        // Side effect was applied before the response was lost:
        assert_eq!(ops.loaded_hash(), Some(generation(&desired)));

        // Caller retries; lose_response now cleared.
        ops.clear_lose_response();
        let changed = reconcile_haproxy(&ops, &test_config(), append_route)
            .await
            .unwrap();
        assert!(
            !changed,
            "retry must converge with no further mutation once the hash is stamped"
        );
        assert_eq!(ops.restart_calls(), 1, "no duplicate restart on retry");
        assert_eq!(ops.write_calls(), 0);
    }

    #[tokio::test]
    async fn reconcile_rejects_oversized_config_before_any_write() {
        // Guard the shared object's size budget (lesson from #18) and fail
        // before touching the cluster.
        let ops = OpsRecorder::new(FakeOpsState {
            configmap: base_cfg(),
            loaded_hash: None,
            ..Default::default()
        });

        let err = reconcile_haproxy(&ops, &test_config(), |cfg| {
            format!("{cfg}{}", "x".repeat(HAPROXY_CONFIGMAP_MAX_BYTES + 1))
        })
        .await
        .unwrap_err();

        assert!(matches!(err, EdgeRouteError::ConfigTooLarge { .. }));
        assert_eq!(ops.write_calls(), 0, "no write on size failure");
        assert_eq!(ops.restart_calls(), 0, "no restart on size failure");
    }

    /// [`HaproxyKubeOps`] test double holding [`FakeOpsState`] behind interior
    /// mutability, mirroring how the real kube `Api` calls take `&self` but
    /// mutate server-side state. Records call counts for assertions.
    struct OpsRecorder {
        inner: std::cell::RefCell<FakeOpsState>,
    }

    impl OpsRecorder {
        fn new(state: FakeOpsState) -> Self {
            Self {
                inner: std::cell::RefCell::new(state),
            }
        }
        fn clear_lose_response(&self) {
            self.inner.borrow_mut().lose_response = None;
        }
        fn write_calls(&self) -> usize {
            self.inner.borrow().write_calls
        }
        fn restart_calls(&self) -> usize {
            self.inner.borrow().restart_calls
        }
        fn loaded_hash(&self) -> Option<String> {
            self.inner.borrow().loaded_hash.clone()
        }
    }

    impl HaproxyKubeOps for OpsRecorder {
        async fn read_configmap(&self) -> Result<String, EdgeRouteError> {
            Ok(self.inner.borrow().configmap.clone())
        }
        async fn write_configmap(&self, cfg: &str) -> Result<(), EdgeRouteError> {
            let mut ops = self.inner.borrow_mut();
            ops.configmap = cfg.to_string();
            ops.write_calls += 1;
            Ok(())
        }
        async fn read_loaded_hash(&self) -> Result<Option<String>, EdgeRouteError> {
            Ok(self.inner.borrow().loaded_hash.clone())
        }
        async fn restart_with_hash(&self, hash: &str) -> Result<(), EdgeRouteError> {
            let mut ops = self.inner.borrow_mut();
            ops.restart_calls += 1;
            let lose = ops.lose_response;
            ops.loaded_hash = Some(hash.to_string());
            match lose {
                Some("restart") => Err(fake_kube_error()),
                _ => Ok(()),
            }
        }
    }

    fn fake_kube_error() -> EdgeRouteError {
        // A representative non-fatal error the caller would surface and retry on
        // (e.g. a dropped apiserver response surfaced as a deserialization
        // failure). SerdeError is the cheapest kube::Error variant to
        // construct without a live cluster.
        let serde_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        EdgeRouteError::Kube(kube::Error::SerdeError(serde_err))
    }
}
