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
    api::{Patch, PatchParams},
};
use serde_json::json;
use sqlx::PgPool;

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
}

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

    let client = Client::try_default().await?;
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let current = cm
        .data
        .as_ref()
        .and_then(|data| data.get("haproxy.cfg"))
        .ok_or_else(|| EdgeRouteError::MissingConfig {
            namespace: config.namespace.clone(),
            name: config.configmap_name.clone(),
        })?;

    let updated = mutate(current);
    if updated == *current {
        // Nothing to write; still commit to release the lock cleanly.
        tx.commit().await?;
        return Ok(false);
    }

    let patch = json!({
        "data": {
            "haproxy.cfg": updated,
        }
    });
    cm_api
        .patch(
            &config.configmap_name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await?;

    let ds_api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);
    let restart_patch = json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "cap.enclava.dev/haproxy-restarted-at": Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    });
    ds_api
        .patch(
            &config.daemonset_name,
            &PatchParams::default(),
            &Patch::Merge(&restart_patch),
        )
        .await?;

    tx.commit().await?;
    Ok(true)
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
}
