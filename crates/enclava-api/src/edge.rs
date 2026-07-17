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

const HAPROXY_CONFIG_GENERATION_ANNOTATION: &str = "config.enclava.dev/haproxy-sha256";
const HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES: usize = 900 * 1024;

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
    #[error("failed to serialize the HAProxy ConfigMap for its size check: {0}")]
    ConfigSerialization(serde_json::Error),
    #[error(
        "HAProxy ConfigMap serialized size {actual} bytes exceeds the {limit}-byte safety budget"
    )]
    ConfigTooLarge { actual: usize, limit: usize },
    #[error("Kubernetes accepted the HAProxy ConfigMap patch without returning the desired config")]
    ConfigNotApplied,
    #[error(
        "Kubernetes accepted the HAProxy DaemonSet patch without applying generation {expected} (found {actual:?})"
    )]
    GenerationNotApplied {
        expected: String,
        actual: Option<String>,
    },
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
    let changed = reconcile_haproxy_config(client, config, mutate).await?;

    tx.commit().await?;
    Ok(changed)
}

async fn reconcile_haproxy_config<F>(
    client: Client,
    config: &EdgeRouteConfig,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: FnOnce(&str) -> String,
{
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let cm = cm_api.get(&config.configmap_name).await?;
    let current = cm
        .data
        .as_ref()
        .and_then(|data| data.get("haproxy.cfg"))
        .cloned()
        .ok_or_else(|| EdgeRouteError::MissingConfig {
            namespace: config.namespace.clone(),
            name: config.configmap_name.clone(),
        })?;

    let updated = mutate(&current);
    let generation = haproxy_config_generation(&updated);
    let config_changed = updated != current;

    if config_changed {
        let serialized_size = serialized_configmap_size_with_config(&cm, &updated)
            .map_err(EdgeRouteError::ConfigSerialization)?;
        if serialized_size > HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES
            && updated.len() >= current.len()
        {
            return Err(EdgeRouteError::ConfigTooLarge {
                actual: serialized_size,
                limit: HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES,
            });
        }

        let patch = json!({
            "data": {
                "haproxy.cfg": &updated,
            }
        });
        let patched = cm_api
            .patch(
                &config.configmap_name,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await?;
        if patched
            .data
            .as_ref()
            .and_then(|data| data.get("haproxy.cfg"))
            .map(String::as_str)
            != Some(updated.as_str())
        {
            return Err(EdgeRouteError::ConfigNotApplied);
        }
    }

    let ds_api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);
    let daemonset = ds_api.get(&config.daemonset_name).await?;
    let generation_changed = daemonset_config_generation(&daemonset) != Some(&generation);

    if generation_changed {
        let generation_patch = json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            HAPROXY_CONFIG_GENERATION_ANNOTATION: &generation,
                        }
                    }
                }
            }
        });
        let patched = ds_api
            .patch(
                &config.daemonset_name,
                &PatchParams::default(),
                &Patch::Merge(&generation_patch),
            )
            .await?;
        let applied = daemonset_config_generation(&patched);
        if applied != Some(generation.as_str()) {
            return Err(EdgeRouteError::GenerationNotApplied {
                expected: generation,
                actual: applied.map(str::to_string),
            });
        }
    }

    Ok(config_changed || generation_changed)
}

fn haproxy_config_generation(config: &str) -> String {
    hex::encode(Sha256::digest(config.as_bytes()))
}

fn daemonset_config_generation(daemonset: &DaemonSet) -> Option<&str> {
    daemonset
        .spec
        .as_ref()?
        .template
        .metadata
        .as_ref()?
        .annotations
        .as_ref()?
        .get(HAPROXY_CONFIG_GENERATION_ANNOTATION)
        .map(String::as_str)
}

fn serialized_configmap_size_with_config(
    configmap: &ConfigMap,
    updated: &str,
) -> Result<usize, serde_json::Error> {
    let mut prospective = configmap.clone();
    prospective
        .data
        .get_or_insert_default()
        .insert("haproxy.cfg".to_string(), updated.to_string());
    serde_json::to_vec(&prospective).map(|serialized| serialized.len())
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
    use axum::http::{Method, Request, Response};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Mutex},
    };
    use tower::service_fn;

    const CONFIGMAP_PATH: &str = "/api/v1/namespaces/tenant-envoy/configmaps/haproxy-tenant";
    const DAEMONSET_PATH: &str = "/apis/apps/v1/namespaces/tenant-envoy/daemonsets/haproxy-tenant";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum FakePatchOutcome {
        Success,
        FailBeforeApply,
        LoseResponseAfterApply,
    }

    #[derive(Debug)]
    struct FakeKubeState {
        config: String,
        generation: Option<String>,
        configmap_patch_outcomes: VecDeque<FakePatchOutcome>,
        daemonset_patch_outcomes: VecDeque<FakePatchOutcome>,
        configmap_patch_attempts: usize,
        daemonset_patch_attempts: usize,
    }

    impl FakeKubeState {
        fn new(config: &str) -> Self {
            Self {
                config: config.to_string(),
                generation: Some(haproxy_config_generation(config)),
                configmap_patch_outcomes: VecDeque::new(),
                daemonset_patch_outcomes: VecDeque::new(),
                configmap_patch_attempts: 0,
                daemonset_patch_attempts: 0,
            }
        }

        fn configmap(&self) -> Value {
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "haproxy-tenant",
                    "namespace": "tenant-envoy",
                },
                "data": {
                    "haproxy.cfg": self.config,
                },
            })
        }

        fn daemonset(&self) -> Value {
            let annotations = self
                .generation
                .as_ref()
                .map(|generation| json!({ HAPROXY_CONFIG_GENERATION_ANNOTATION: generation }));
            json!({
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {
                    "name": "haproxy-tenant",
                    "namespace": "tenant-envoy",
                },
                "spec": {
                    "selector": { "matchLabels": { "app": "haproxy-tenant" } },
                    "template": {
                        "metadata": {
                            "labels": { "app": "haproxy-tenant" },
                            "annotations": annotations,
                        },
                        "spec": {
                            "containers": [{ "name": "haproxy", "image": "haproxy:3" }],
                        },
                    },
                },
            })
        }
    }

    fn fake_kube_client(state: Arc<Mutex<FakeKubeState>>) -> Client {
        let service =
            service_fn(move |request| handle_fake_kube_request(request, Arc::clone(&state)));
        Client::new(service, "default")
    }

    async fn handle_fake_kube_request(
        request: Request<Body>,
        state: Arc<Mutex<FakeKubeState>>,
    ) -> Result<Response<Body>, io::Error> {
        let method = request.method().clone();
        let path = request.uri().path().to_string();
        let body = request
            .into_body()
            .collect()
            .await
            .map_err(io::Error::other)?
            .to_bytes();
        let mut state = state.lock().expect("fake Kubernetes state poisoned");

        match (method, path.as_str()) {
            (Method::GET, CONFIGMAP_PATH) => Ok(json_response(state.configmap())),
            (Method::GET, DAEMONSET_PATH) => Ok(json_response(state.daemonset())),
            (Method::PATCH, CONFIGMAP_PATH) => {
                state.configmap_patch_attempts += 1;
                let outcome = state
                    .configmap_patch_outcomes
                    .pop_front()
                    .unwrap_or(FakePatchOutcome::Success);
                if outcome == FakePatchOutcome::FailBeforeApply {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "ConfigMap patch failed before apply",
                    ));
                }

                let patch: Value = serde_json::from_slice(&body).expect("valid ConfigMap patch");
                state.config = patch
                    .pointer("/data/haproxy.cfg")
                    .and_then(Value::as_str)
                    .expect("ConfigMap patch includes haproxy.cfg")
                    .to_string();
                if outcome == FakePatchOutcome::LoseResponseAfterApply {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "ConfigMap patch response timed out after apply",
                    ));
                }
                Ok(json_response(state.configmap()))
            }
            (Method::PATCH, DAEMONSET_PATH) => {
                state.daemonset_patch_attempts += 1;
                let outcome = state
                    .daemonset_patch_outcomes
                    .pop_front()
                    .unwrap_or(FakePatchOutcome::Success);
                if outcome == FakePatchOutcome::FailBeforeApply {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "DaemonSet patch failed before apply",
                    ));
                }

                let patch: Value = serde_json::from_slice(&body).expect("valid DaemonSet patch");
                state.generation = Some(
                    patch
                        .pointer(&format!(
                            "/spec/template/metadata/annotations/{}",
                            HAPROXY_CONFIG_GENERATION_ANNOTATION
                                .replace('~', "~0")
                                .replace('/', "~1")
                        ))
                        .and_then(Value::as_str)
                        .expect("DaemonSet patch includes the HAProxy generation")
                        .to_string(),
                );
                if outcome == FakePatchOutcome::LoseResponseAfterApply {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DaemonSet patch response timed out after apply",
                    ));
                }
                Ok(json_response(state.daemonset()))
            }
            (method, path) => Err(io::Error::other(format!(
                "unexpected fake Kubernetes request: {method} {path}"
            ))),
        }
    }

    fn json_response(value: Value) -> Response<Body> {
        Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&value).expect("serialize response"),
            ))
            .expect("build fake Kubernetes response")
    }

    fn edge_config() -> EdgeRouteConfig {
        EdgeRouteConfig {
            namespace: "tenant-envoy".to_string(),
            configmap_name: "haproxy-tenant".to_string(),
            daemonset_name: "haproxy-tenant".to_string(),
        }
    }

    async fn reconcile_to(client: Client, desired: &str) -> Result<bool, EdgeRouteError> {
        reconcile_haproxy_config(client, &edge_config(), |_| desired.to_string()).await
    }

    #[tokio::test]
    async fn retry_reconciles_reload_after_configmap_success_and_daemonset_failure() {
        let desired = "global\n  maxconn 4096\n";
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        state
            .lock()
            .unwrap()
            .daemonset_patch_outcomes
            .push_back(FakePatchOutcome::FailBeforeApply);
        let client = fake_kube_client(Arc::clone(&state));

        assert!(reconcile_to(client.clone(), desired).await.is_err());
        {
            let after_failure = state.lock().unwrap();
            assert_eq!(after_failure.config, desired);
            assert_ne!(
                after_failure.generation.as_deref(),
                Some(haproxy_config_generation(desired).as_str())
            );
        }

        assert!(reconcile_to(client, desired).await.unwrap());
        let converged = state.lock().unwrap();
        assert_eq!(
            converged.generation.as_deref(),
            Some(haproxy_config_generation(desired).as_str())
        );
        assert_eq!(converged.configmap_patch_attempts, 1);
        assert_eq!(converged.daemonset_patch_attempts, 2);
    }

    #[tokio::test]
    async fn retry_converges_after_configmap_patch_response_is_lost() {
        let desired = "global\n  maxconn 4096\n";
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        state
            .lock()
            .unwrap()
            .configmap_patch_outcomes
            .push_back(FakePatchOutcome::LoseResponseAfterApply);
        let client = fake_kube_client(Arc::clone(&state));

        assert!(reconcile_to(client.clone(), desired).await.is_err());
        assert!(reconcile_to(client, desired).await.unwrap());

        let converged = state.lock().unwrap();
        assert_eq!(converged.config, desired);
        assert_eq!(
            converged.generation.as_deref(),
            Some(haproxy_config_generation(desired).as_str())
        );
        assert_eq!(converged.configmap_patch_attempts, 1);
        assert_eq!(converged.daemonset_patch_attempts, 1);
    }

    #[tokio::test]
    async fn retry_converges_after_daemonset_patch_response_is_lost() {
        let desired = "global\n  maxconn 4096\n";
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        state
            .lock()
            .unwrap()
            .daemonset_patch_outcomes
            .push_back(FakePatchOutcome::LoseResponseAfterApply);
        let client = fake_kube_client(Arc::clone(&state));

        assert!(reconcile_to(client.clone(), desired).await.is_err());
        assert!(!reconcile_to(client, desired).await.unwrap());

        let converged = state.lock().unwrap();
        assert_eq!(converged.configmap_patch_attempts, 1);
        assert_eq!(converged.daemonset_patch_attempts, 1);
        assert_eq!(
            converged.generation.as_deref(),
            Some(haproxy_config_generation(desired).as_str())
        );
    }

    #[tokio::test]
    async fn configmap_growth_over_serialized_budget_is_rejected_before_patch() {
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        let client = fake_kube_client(Arc::clone(&state));
        let oversized = "x".repeat(HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES);

        let error = reconcile_to(client, &oversized).await.unwrap_err();
        assert!(matches!(
            error,
            EdgeRouteError::ConfigTooLarge {
                actual,
                limit: HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES,
            } if actual > HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES
        ));
        let unchanged = state.lock().unwrap();
        assert_eq!(unchanged.config, "global\n");
        assert_eq!(unchanged.configmap_patch_attempts, 0);
        assert_eq!(unchanged.daemonset_patch_attempts, 0);
    }

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
}
