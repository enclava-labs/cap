use enclava_common::validate::{
    ValidateError, validate_app_name, validate_fqdn, validate_org_slug,
};
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{ConfigMap, Service},
};
use kube::{
    Api, Client,
    api::{ApiResource, DynamicObject, PostParams},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::IpAddr;
use uuid::Uuid;

use crate::{runtime_authority::RuntimeAuthority, state::AppState};

const HAPROXY_CONFIG_GENERATION_ANNOTATION: &str = "config.enclava.dev/haproxy-sha256";
const HAPROXY_MUTATION_GENERATION_ANNOTATION: &str =
    "config.enclava.dev/haproxy-mutation-generation";
const HAPROXY_AUTHORITY_EPOCH_ANNOTATION: &str = "config.enclava.dev/cap-authority-epoch";
const HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION: &str =
    "config.enclava.dev/cap-restore-generation";
const HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES: usize = 900 * 1024;
const KUBERNETES_CAS_ATTEMPTS: usize = 8;
const KUBERNETES_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum EdgeRouteError {
    #[error("database error")]
    Database(#[from] sqlx::Error),
    #[error("Kubernetes client error: {0}")]
    Kube(#[from] kube::Error),
    #[error("haproxy ConfigMap {namespace}/{name} is missing data key 'haproxy.cfg'")]
    MissingConfig { namespace: String, name: String },
    #[error("Kubernetes HAProxy mutation exceeded its 30 second deadline")]
    ProviderWriteTimeout,
    #[error("Kubernetes HAProxy compare-and-swap retries were exhausted")]
    CasExhausted,
    #[error("HAProxy ConfigMap has invalid durable mutation generation metadata")]
    InvalidMutationGeneration,
    #[error("HAProxy runtime object has invalid authority epoch metadata")]
    InvalidAuthorityEpoch,
    #[error(
        "HAProxy mutation generation {expected} was superseded by generation {actual} in the same authority epoch"
    )]
    SupersededMutationGeneration { expected: i64, actual: i64 },
    #[error("HAProxy restore generation {expected} was superseded by restore generation {actual}")]
    SupersededAuthorityRestoreGeneration { expected: i64, actual: i64 },
    #[error("HAProxy has a divergent authority epoch in restore generation {restore_generation}")]
    DivergentAuthorityEpoch { restore_generation: i64 },
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

#[derive(Debug, thiserror::Error)]
pub enum EdgeReconciliationError {
    #[error("durable edge mutation fence failed")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
    #[error("edge runtime reconciliation failed")]
    Edge(#[from] EdgeRouteError),
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

#[derive(Debug, sqlx::FromRow)]
struct DesiredEdgeApp {
    app_id: Uuid,
    name: String,
    namespace: String,
    domain: String,
    tee_domain: Option<String>,
    custom_domain: Option<String>,
    org_slug: String,
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
    authority: RuntimeAuthority,
    mutation_generation: Option<i64>,
    routes: &[SniRoute],
) -> Result<(), EdgeRouteError> {
    mutate_haproxy_config(pool, config, authority, mutation_generation, |current| {
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
    authority: RuntimeAuthority,
    mutation_generation: Option<i64>,
    routes: &[(String, String)],
) -> Result<(), EdgeRouteError> {
    let changed = mutate_haproxy_config(pool, config, authority, mutation_generation, |current| {
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

/// Rebuild every CAP-owned route from Postgres authority.
///
/// This is run before durable deployment dispatch and periodically thereafter.
/// It removes retained routes that belong to a previous database epoch and
/// repairs partial route mutations without disturbing operator-owned HAProxy
/// configuration or the fail-closed default backend.
pub async fn reconcile_all_haproxy_routes(state: &AppState) -> Result<(), EdgeReconciliationError> {
    let fence = crate::mutation_leases::ResourceFence::edge_config();
    let lease = crate::mutation_leases::claim_resources(
        state,
        "edge_config_reconcile",
        Uuid::new_v4(),
        vec![fence.clone()],
    )
    .await?;
    let generation = lease
        .resource_generation(&fence)
        .ok_or(crate::mutation_leases::MutationLeaseError::Lost)?;
    let client = Client::try_default().await.map_err(EdgeRouteError::Kube)?;
    let config = EdgeRouteConfig::from_env();
    lease
        .guard_provider(async {
            let routes = load_desired_haproxy_routes(&state.db, client.clone()).await?;
            mutate_haproxy_config_with_client(
                &state.db,
                client,
                &config,
                state.runtime_authority,
                Some(generation),
                |current| {
                    let mut desired = remove_all_cap_managed_routes(current);
                    for route in &routes {
                        desired = render_route_into(&desired, route);
                    }
                    desired
                },
            )
            .await
        })
        .await??;
    lease.finish().await?;
    Ok(())
}

async fn retry_busy_reconciliation<F, Fut>(
    mut reconcile: F,
    retry_delay: std::time::Duration,
) -> Result<(), EdgeReconciliationError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<(), EdgeReconciliationError>>,
{
    loop {
        match reconcile().await {
            Err(EdgeReconciliationError::Mutation(
                crate::mutation_leases::MutationLeaseError::Busy,
            )) => tokio::time::sleep(retry_delay).await,
            result => return result,
        }
    }
}

/// Converge edge authority before accepting traffic or dispatching jobs.
///
/// A previous process can leave the global edge fence in its bounded reclaim
/// quarantine after an ordinary restart. Treat only that contention as
/// transient; every database, Kubernetes, authority, or provider error remains
/// fatal to startup.
pub async fn reconcile_all_haproxy_routes_at_startup(
    state: &AppState,
) -> Result<(), EdgeReconciliationError> {
    retry_busy_reconciliation(
        || reconcile_all_haproxy_routes(state),
        std::time::Duration::from_secs(2),
    )
    .await
}

pub fn spawn_haproxy_reconciler(state: AppState) {
    tokio::spawn(async move {
        loop {
            match reconcile_all_haproxy_routes(&state).await {
                Ok(()) => {}
                Err(EdgeReconciliationError::Mutation(
                    crate::mutation_leases::MutationLeaseError::Busy,
                )) => {}
                Err(EdgeReconciliationError::Mutation(_)) => tracing::warn!(
                    error_code = "edge_reconciliation_fence_unavailable",
                    "could not claim durable HAProxy reconciliation"
                ),
                Err(EdgeReconciliationError::Edge(_)) => tracing::warn!(
                    error_code = "edge_reconciliation_failed",
                    "durable HAProxy reconciliation remains pending"
                ),
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
}

async fn load_desired_haproxy_routes(
    pool: &PgPool,
    client: Client,
) -> Result<Vec<SniRoute>, EdgeRouteError> {
    let apps = sqlx::query_as::<_, DesiredEdgeApp>(
        "SELECT app.id AS app_id, app.name, app.namespace, app.domain,
                app.tee_domain, app.custom_domain,
                organization.cust_slug AS org_slug
           FROM apps AS app
           JOIN organizations AS organization ON organization.id = app.org_id
          WHERE app.status <> 'deleting'::app_status_enum
          ORDER BY app.id",
    )
    .fetch_all(pool)
    .await?;
    let mut routes = Vec::new();
    for app in apps {
        let Some(address) =
            resolve_existing_service_address(client.clone(), &app.name, &app.namespace).await?
        else {
            tracing::warn!(
                app_id = %app.app_id,
                error_code = "edge_reconciliation_service_absent",
                "excluding a route whose authoritative workload Service is absent"
            );
            continue;
        };
        let app_backend = backend_name_for(&app.org_slug, &app.name, BackendTag::App)?;
        let tee_backend = backend_name_for(&app.org_slug, &app.name, BackendTag::Tee)?;
        routes.push(SniRoute::new(
            &app.domain,
            &app_backend,
            &format!("{address}:443"),
        )?);
        if let Some(tee_domain) = app.tee_domain.as_deref() {
            routes.push(SniRoute::new(
                tee_domain,
                &tee_backend,
                &format!("{address}:8081"),
            )?);
        }
        if let Some(custom_domain) = app.custom_domain.as_deref() {
            routes.push(SniRoute::new(
                custom_domain,
                &app_backend,
                &format!("{address}:443"),
            )?);
        }
    }
    Ok(routes)
}

async fn mutate_haproxy_config<F>(
    pool: &PgPool,
    config: &EdgeRouteConfig,
    authority: RuntimeAuthority,
    mutation_generation: Option<i64>,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: Fn(&str) -> String,
{
    // Runtime callers already own the durable global edge_config generation.
    // Do not hold a second PostgreSQL connection across Kubernetes I/O: with a
    // two-connection pool that would starve both job and mutation heartbeats.
    let client = Client::try_default().await?;
    mutate_haproxy_config_with_client(pool, client, config, authority, mutation_generation, mutate)
        .await
}

async fn mutate_haproxy_config_with_client<F>(
    _pool: &PgPool,
    client: Client,
    config: &EdgeRouteConfig,
    authority: RuntimeAuthority,
    mutation_generation: Option<i64>,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: Fn(&str) -> String,
{
    reconcile_haproxy_config(client, config, authority, mutation_generation, mutate).await
}

async fn reconcile_haproxy_config<F>(
    client: Client,
    config: &EdgeRouteConfig,
    authority: RuntimeAuthority,
    mutation_generation: Option<i64>,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: Fn(&str) -> String,
{
    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let mut changed = false;
    let mut converged = false;
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        let mut cm = cm_api.get(&config.configmap_name).await?;
        let current = cm
            .data
            .as_ref()
            .and_then(|data| data.get("haproxy.cfg"))
            .cloned()
            .ok_or_else(|| EdgeRouteError::MissingConfig {
                namespace: config.namespace.clone(),
                name: config.configmap_name.clone(),
            })?;
        let (
            current_authority_epoch,
            current_authority_restore_generation,
            current_mutation_generation,
        ) = configmap_mutation_authority(&cm)?;
        ensure_current_authority_is_not_newer(
            current_authority_epoch,
            current_authority_restore_generation,
            authority,
        )?;
        if let Some(expected_generation) = mutation_generation
            && current_authority_epoch == Some(authority.epoch)
            && current_authority_restore_generation == Some(authority.restore_generation)
            && current_mutation_generation > expected_generation
        {
            // This closure belongs to an older durable resource owner. Never
            // recompute it atop the newer intent after an RV conflict.
            return Err(EdgeRouteError::SupersededMutationGeneration {
                expected: expected_generation,
                actual: current_mutation_generation,
            });
        }
        let updated = mutate(&current);
        let mutation_authority_changed = current_authority_epoch != Some(authority.epoch)
            || current_authority_restore_generation != Some(authority.restore_generation)
            || mutation_generation.is_some_and(|expected| current_mutation_generation != expected);
        if updated == current && !mutation_authority_changed {
            converged = true;
            break;
        }
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
        cm.data
            .get_or_insert_default()
            .insert("haproxy.cfg".to_string(), updated.clone());
        let annotations = cm.metadata.annotations.get_or_insert_default();
        annotations.insert(
            HAPROXY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
            authority.epoch.to_string(),
        );
        annotations.insert(
            HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION.to_string(),
            authority.restore_generation.to_string(),
        );
        if let Some(expected_generation) = mutation_generation {
            annotations.insert(
                HAPROXY_MUTATION_GENERATION_ANNOTATION.to_string(),
                expected_generation.to_string(),
            );
        }
        match bounded_kube_write(cm_api.replace(
            &config.configmap_name,
            &PostParams::default(),
            &cm,
        ))
        .await
        {
            Ok(replaced)
                if replaced
                    .data
                    .as_ref()
                    .and_then(|data| data.get("haproxy.cfg"))
                    .map(String::as_str)
                    == Some(updated.as_str()) =>
            {
                changed |= updated != current;
                converged = true;
                break;
            }
            Ok(_) => return Err(EdgeRouteError::ConfigNotApplied),
            Err(EdgeRouteError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    if !converged {
        return Err(EdgeRouteError::CasExhausted);
    }

    let ds_api: Api<DaemonSet> = Api::namespaced(client, &config.namespace);
    for _ in 0..KUBERNETES_CAS_ATTEMPTS {
        // Always derive the rollout generation from the latest ConfigMap. A
        // delayed older writer can therefore repair, but never roll back, a
        // newer ConfigMap publication.
        let cm = cm_api.get(&config.configmap_name).await?;
        let current = cm
            .data
            .as_ref()
            .and_then(|data| data.get("haproxy.cfg"))
            .ok_or_else(|| EdgeRouteError::MissingConfig {
                namespace: config.namespace.clone(),
                name: config.configmap_name.clone(),
            })?;
        let (cm_authority_epoch, cm_restore_generation, _) = configmap_mutation_authority(&cm)?;
        ensure_current_authority_is_not_newer(
            cm_authority_epoch,
            cm_restore_generation,
            authority,
        )?;
        if cm_authority_epoch != Some(authority.epoch)
            || cm_restore_generation != Some(authority.restore_generation)
        {
            return Err(EdgeRouteError::DivergentAuthorityEpoch {
                restore_generation: authority.restore_generation,
            });
        }
        let generation = haproxy_config_generation(current);
        let mut daemonset = ds_api.get(&config.daemonset_name).await?;
        let daemonset_authority_epoch = daemonset_authority_epoch(&daemonset)?;
        let daemonset_restore_generation = daemonset_authority_restore_generation(&daemonset)?;
        if daemonset_restore_generation.is_some() && daemonset_authority_epoch.is_none() {
            return Err(EdgeRouteError::InvalidAuthorityEpoch);
        }
        ensure_current_authority_is_not_newer(
            daemonset_authority_epoch,
            daemonset_restore_generation,
            authority,
        )?;
        if daemonset_config_generation(&daemonset) == Some(generation.as_str())
            && daemonset_authority_epoch == Some(authority.epoch)
            && daemonset_restore_generation == Some(authority.restore_generation)
        {
            return Ok(changed);
        }
        daemonset
            .spec
            .as_mut()
            .ok_or_else(|| EdgeRouteError::GenerationNotApplied {
                expected: generation.clone(),
                actual: None,
            })?
            .template
            .metadata
            .get_or_insert_default()
            .annotations
            .get_or_insert_default()
            .extend([
                (
                    HAPROXY_CONFIG_GENERATION_ANNOTATION.to_string(),
                    generation.clone(),
                ),
                (
                    HAPROXY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
                    authority.epoch.to_string(),
                ),
                (
                    HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION.to_string(),
                    authority.restore_generation.to_string(),
                ),
            ]);
        match bounded_kube_write(ds_api.replace(
            &config.daemonset_name,
            &PostParams::default(),
            &daemonset,
        ))
        .await
        {
            Ok(replaced) => {
                let applied = daemonset_config_generation(&replaced);
                if applied != Some(generation.as_str()) {
                    return Err(EdgeRouteError::GenerationNotApplied {
                        expected: generation,
                        actual: applied.map(str::to_string),
                    });
                }
                changed = true;
            }
            Err(EdgeRouteError::Kube(error)) if is_kubernetes_conflict(&error) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(EdgeRouteError::CasExhausted)
}

async fn bounded_kube_write<F, T>(future: F) -> Result<T, EdgeRouteError>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    tokio::time::timeout(KUBERNETES_WRITE_TIMEOUT, future)
        .await
        .map_err(|_| EdgeRouteError::ProviderWriteTimeout)?
        .map_err(EdgeRouteError::Kube)
}

fn is_kubernetes_conflict(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 409)
}

fn haproxy_config_generation(config: &str) -> String {
    hex::encode(Sha256::digest(config.as_bytes()))
}

fn configmap_mutation_authority(
    configmap: &ConfigMap,
) -> Result<(Option<Uuid>, Option<i64>, i64), EdgeRouteError> {
    let authority_epoch = configmap
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(HAPROXY_AUTHORITY_EPOCH_ANNOTATION))
        .map(|epoch| {
            epoch
                .parse::<Uuid>()
                .map_err(|_| EdgeRouteError::InvalidAuthorityEpoch)
        })
        .transpose()?;
    let restore_generation = configmap
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION))
        .map(|generation| {
            generation
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(EdgeRouteError::InvalidMutationGeneration)
        })
        .transpose()?;
    if restore_generation.is_some() && authority_epoch.is_none() {
        return Err(EdgeRouteError::InvalidAuthorityEpoch);
    }
    let generation = configmap
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(HAPROXY_MUTATION_GENERATION_ANNOTATION))
        .map(|generation| {
            generation
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(EdgeRouteError::InvalidMutationGeneration)
        })
        .transpose()
        .map(|generation| generation.unwrap_or(0))?;
    Ok((authority_epoch, restore_generation, generation))
}

fn ensure_current_authority_is_not_newer(
    current_epoch: Option<Uuid>,
    current_restore_generation: Option<i64>,
    desired: RuntimeAuthority,
) -> Result<(), EdgeRouteError> {
    match current_restore_generation {
        Some(current) if current > desired.restore_generation => {
            Err(EdgeRouteError::SupersededAuthorityRestoreGeneration {
                expected: desired.restore_generation,
                actual: current,
            })
        }
        Some(current)
            if current == desired.restore_generation && current_epoch != Some(desired.epoch) =>
        {
            Err(EdgeRouteError::DivergentAuthorityEpoch {
                restore_generation: current,
            })
        }
        _ => Ok(()),
    }
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

fn daemonset_authority_epoch(daemonset: &DaemonSet) -> Result<Option<Uuid>, EdgeRouteError> {
    daemonset
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|metadata| metadata.annotations.as_ref())
        .and_then(|annotations| annotations.get(HAPROXY_AUTHORITY_EPOCH_ANNOTATION))
        .map(|epoch| {
            epoch
                .parse::<Uuid>()
                .map_err(|_| EdgeRouteError::InvalidAuthorityEpoch)
        })
        .transpose()
}

fn daemonset_authority_restore_generation(
    daemonset: &DaemonSet,
) -> Result<Option<i64>, EdgeRouteError> {
    daemonset
        .spec
        .as_ref()
        .and_then(|spec| spec.template.metadata.as_ref())
        .and_then(|metadata| metadata.annotations.as_ref())
        .and_then(|annotations| annotations.get(HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION))
        .map(|generation| {
            generation
                .parse::<i64>()
                .ok()
                .filter(|generation| *generation >= 0)
                .ok_or(EdgeRouteError::InvalidMutationGeneration)
        })
        .transpose()
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

async fn resolve_existing_service_address(
    client: Client,
    app_name: &str,
    namespace: &str,
) -> Result<Option<String>, EdgeRouteError> {
    validate_app_name(app_name)
        .map_err(|_| EdgeRouteError::InvalidAppName(format!("invalid app name: {app_name}")))?;
    let service_api: Api<Service> = Api::namespaced(client, namespace);
    let service = match service_api.get(app_name).await {
        Ok(service) => service,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let cluster_ip = service
        .spec
        .and_then(|spec| spec.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .unwrap_or_else(|| format!("{app_name}.{namespace}.svc.cluster.local"));
    Ok(Some(cluster_ip))
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

fn remove_all_cap_managed_routes(config: &str) -> String {
    let mut out = Vec::new();
    let mut skipping_cap_backend = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if skipping_cap_backend {
            if is_haproxy_section_header(line) {
                skipping_cap_backend = false;
            } else {
                continue;
            }
        }
        if trimmed.starts_with("backend ") {
            skipping_cap_backend = trimmed
                .strip_prefix("backend ")
                .is_some_and(|backend| backend.starts_with("be_cap_"));
            if skipping_cap_backend {
                continue;
            }
        }
        if trimmed.starts_with("use_backend be_cap_") {
            continue;
        }
        out.push(line);
    }

    let mut rendered = out.join("\n");
    if config.ends_with('\n') {
        rendered.push('\n');
    }
    rendered
}

fn is_haproxy_section_header(line: &str) -> bool {
    let line = line.trim_start();
    if line.is_empty() || line.starts_with('#') {
        return false;
    }
    matches!(
        line.split_ascii_whitespace().next(),
        Some(
            "global"
                | "defaults"
                | "frontend"
                | "backend"
                | "listen"
                | "peers"
                | "resolvers"
                | "mailers"
                | "cache"
                | "program"
                | "ring"
                | "userlist"
                | "http-errors"
                | "crt-store"
                | "log-forward"
                | "log-profile"
                | "fcgi-app"
                | "namespace_list"
                | "traces"
                | "acme"
        )
    )
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
    use axum::http::{Method, Request, Response, StatusCode};
    use http_body_util::BodyExt;
    use kube::client::Body;
    use serde_json::json;
    use std::{
        collections::VecDeque,
        io,
        sync::{Arc, Mutex},
    };
    use tower::service_fn;

    const CONFIGMAP_PATH: &str = "/api/v1/namespaces/tenant-envoy/configmaps/haproxy-tenant";
    const DAEMONSET_PATH: &str = "/apis/apps/v1/namespaces/tenant-envoy/daemonsets/haproxy-tenant";

    #[tokio::test]
    async fn startup_reconciliation_retries_busy_fence_until_available() {
        let mut attempts = 0;
        retry_busy_reconciliation(
            || {
                attempts += 1;
                std::future::ready(if attempts < 3 {
                    Err(EdgeReconciliationError::Mutation(
                        crate::mutation_leases::MutationLeaseError::Busy,
                    ))
                } else {
                    Ok(())
                })
            },
            std::time::Duration::ZERO,
        )
        .await
        .expect("startup reconciliation succeeds after contention clears");
        assert_eq!(attempts, 3);
    }

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
        mutation_generation: Option<i64>,
        configmap_authority_epoch: Option<Uuid>,
        configmap_restore_generation: Option<i64>,
        daemonset_authority_epoch: Option<Uuid>,
        daemonset_restore_generation: Option<i64>,
        configmap_patch_outcomes: VecDeque<FakePatchOutcome>,
        daemonset_patch_outcomes: VecDeque<FakePatchOutcome>,
        configmap_patch_attempts: usize,
        daemonset_patch_attempts: usize,
        configmap_resource_version: u64,
        daemonset_resource_version: u64,
        pause_next_configmap_replace: bool,
        configmap_replace_entered: Arc<tokio::sync::Notify>,
        configmap_replace_release: Arc<tokio::sync::Notify>,
    }

    impl FakeKubeState {
        fn new(config: &str) -> Self {
            Self {
                config: config.to_string(),
                generation: Some(haproxy_config_generation(config)),
                mutation_generation: None,
                configmap_authority_epoch: None,
                configmap_restore_generation: None,
                daemonset_authority_epoch: None,
                daemonset_restore_generation: None,
                configmap_patch_outcomes: VecDeque::new(),
                daemonset_patch_outcomes: VecDeque::new(),
                configmap_patch_attempts: 0,
                daemonset_patch_attempts: 0,
                configmap_resource_version: 1,
                daemonset_resource_version: 1,
                pause_next_configmap_replace: false,
                configmap_replace_entered: Arc::new(tokio::sync::Notify::new()),
                configmap_replace_release: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn configmap(&self) -> Value {
            let mut annotations = serde_json::Map::new();
            if let Some(generation) = self.mutation_generation {
                annotations.insert(
                    HAPROXY_MUTATION_GENERATION_ANNOTATION.to_string(),
                    json!(generation.to_string()),
                );
            }
            if let Some(epoch) = self.configmap_authority_epoch {
                annotations.insert(
                    HAPROXY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
                    json!(epoch.to_string()),
                );
            }
            if let Some(generation) = self.configmap_restore_generation {
                annotations.insert(
                    HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION.to_string(),
                    json!(generation.to_string()),
                );
            }
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "haproxy-tenant",
                    "namespace": "tenant-envoy",
                    "resourceVersion": self.configmap_resource_version.to_string(),
                    "annotations": Value::Object(annotations),
                },
                "data": {
                    "haproxy.cfg": self.config,
                },
            })
        }

        fn daemonset(&self) -> Value {
            let mut annotations = serde_json::Map::new();
            if let Some(generation) = self.generation.as_ref() {
                annotations.insert(
                    HAPROXY_CONFIG_GENERATION_ANNOTATION.to_string(),
                    json!(generation),
                );
            }
            if let Some(epoch) = self.daemonset_authority_epoch {
                annotations.insert(
                    HAPROXY_AUTHORITY_EPOCH_ANNOTATION.to_string(),
                    json!(epoch.to_string()),
                );
            }
            if let Some(generation) = self.daemonset_restore_generation {
                annotations.insert(
                    HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION.to_string(),
                    json!(generation.to_string()),
                );
            }
            json!({
                "apiVersion": "apps/v1",
                "kind": "DaemonSet",
                "metadata": {
                    "name": "haproxy-tenant",
                    "namespace": "tenant-envoy",
                    "resourceVersion": self.daemonset_resource_version.to_string(),
                },
                "spec": {
                    "selector": { "matchLabels": { "app": "haproxy-tenant" } },
                    "template": {
                        "metadata": {
                            "labels": { "app": "haproxy-tenant" },
                            "annotations": Value::Object(annotations),
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
        match (method, path.as_str()) {
            (Method::GET, CONFIGMAP_PATH) => Ok(json_response(
                state
                    .lock()
                    .expect("fake Kubernetes state poisoned")
                    .configmap(),
            )),
            (Method::GET, DAEMONSET_PATH) => Ok(json_response(
                state
                    .lock()
                    .expect("fake Kubernetes state poisoned")
                    .daemonset(),
            )),
            (Method::PUT, CONFIGMAP_PATH) => {
                let replacement: Value =
                    serde_json::from_slice(&body).expect("valid ConfigMap replacement");
                let pause = {
                    let mut locked = state.lock().expect("fake Kubernetes state poisoned");
                    if locked.pause_next_configmap_replace {
                        locked.pause_next_configmap_replace = false;
                        Some((
                            locked.configmap_replace_entered.clone(),
                            locked.configmap_replace_release.clone(),
                        ))
                    } else {
                        None
                    }
                };
                if let Some((entered, release)) = pause {
                    entered.notify_one();
                    release.notified().await;
                }
                let mut locked = state.lock().expect("fake Kubernetes state poisoned");
                locked.configmap_patch_attempts += 1;
                let expected_resource_version = replacement
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let current_resource_version = locked.configmap_resource_version.to_string();
                if expected_resource_version != Some(current_resource_version.as_str()) {
                    return Ok(conflict_response());
                }
                let outcome = locked
                    .configmap_patch_outcomes
                    .pop_front()
                    .unwrap_or(FakePatchOutcome::Success);
                if outcome == FakePatchOutcome::FailBeforeApply {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "ConfigMap replacement failed before apply",
                    ));
                }
                locked.config = replacement
                    .pointer("/data/haproxy.cfg")
                    .and_then(Value::as_str)
                    .expect("ConfigMap replacement includes haproxy.cfg")
                    .to_string();
                locked.mutation_generation = replacement
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        HAPROXY_MUTATION_GENERATION_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|generation| generation.parse().ok());
                locked.configmap_authority_epoch = replacement
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        HAPROXY_AUTHORITY_EPOCH_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|epoch| epoch.parse().ok());
                locked.configmap_restore_generation = replacement
                    .pointer(&format!(
                        "/metadata/annotations/{}",
                        HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|generation| generation.parse().ok());
                locked.configmap_resource_version += 1;
                if outcome == FakePatchOutcome::LoseResponseAfterApply {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "ConfigMap replacement response timed out after apply",
                    ));
                }
                Ok(json_response(locked.configmap()))
            }
            (Method::PUT, DAEMONSET_PATH) => {
                let replacement: Value =
                    serde_json::from_slice(&body).expect("valid DaemonSet replacement");
                let mut locked = state.lock().expect("fake Kubernetes state poisoned");
                locked.daemonset_patch_attempts += 1;
                let expected_resource_version = replacement
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str);
                let current_resource_version = locked.daemonset_resource_version.to_string();
                if expected_resource_version != Some(current_resource_version.as_str()) {
                    return Ok(conflict_response());
                }
                let outcome = locked
                    .daemonset_patch_outcomes
                    .pop_front()
                    .unwrap_or(FakePatchOutcome::Success);
                if outcome == FakePatchOutcome::FailBeforeApply {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "DaemonSet replacement failed before apply",
                    ));
                }
                locked.generation = Some(
                    replacement
                        .pointer(&format!(
                            "/spec/template/metadata/annotations/{}",
                            HAPROXY_CONFIG_GENERATION_ANNOTATION
                                .replace('~', "~0")
                                .replace('/', "~1")
                        ))
                        .and_then(Value::as_str)
                        .expect("DaemonSet replacement includes the HAProxy generation")
                        .to_string(),
                );
                locked.daemonset_authority_epoch = replacement
                    .pointer(&format!(
                        "/spec/template/metadata/annotations/{}",
                        HAPROXY_AUTHORITY_EPOCH_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|epoch| epoch.parse().ok());
                locked.daemonset_restore_generation = replacement
                    .pointer(&format!(
                        "/spec/template/metadata/annotations/{}",
                        HAPROXY_AUTHORITY_RESTORE_GENERATION_ANNOTATION
                            .replace('~', "~0")
                            .replace('/', "~1")
                    ))
                    .and_then(Value::as_str)
                    .and_then(|generation| generation.parse().ok());
                locked.daemonset_resource_version += 1;
                if outcome == FakePatchOutcome::LoseResponseAfterApply {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "DaemonSet replacement response timed out after apply",
                    ));
                }
                Ok(json_response(locked.daemonset()))
            }
            (method, path) => Err(io::Error::other(format!(
                "unexpected fake Kubernetes request: {method} {path}"
            ))),
        }
    }

    fn conflict_response() -> Response<Body> {
        Response::builder()
            .status(StatusCode::CONFLICT)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "apiVersion": "v1",
                    "kind": "Status",
                    "status": "Failure",
                    "reason": "Conflict",
                    "message": "resourceVersion conflict",
                    "code": 409,
                }))
                .expect("serialize conflict response"),
            ))
            .expect("build conflict response")
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
        reconcile_haproxy_config(
            client,
            &edge_config(),
            test_runtime_authority(),
            Some(1),
            |_| desired.to_string(),
        )
        .await
    }

    fn test_runtime_authority() -> RuntimeAuthority {
        RuntimeAuthority {
            epoch: Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap(),
            restore_generation: 7,
        }
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
    async fn new_database_epoch_replaces_retained_higher_edge_generation() {
        let desired = "global\n  maxconn 4096\n";
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        {
            let mut retained = state.lock().unwrap();
            retained.mutation_generation = Some(99);
            retained.configmap_authority_epoch = Some(Uuid::new_v4());
            retained.daemonset_authority_epoch = retained.configmap_authority_epoch;
        }
        let client = fake_kube_client(Arc::clone(&state));

        assert!(reconcile_to(client, desired).await.unwrap());

        let converged = state.lock().unwrap();
        assert_eq!(converged.config, desired);
        assert_eq!(converged.mutation_generation, Some(1));
        assert_eq!(
            converged.configmap_authority_epoch,
            Some(test_runtime_authority().epoch)
        );
        assert_eq!(
            converged.daemonset_authority_epoch,
            Some(test_runtime_authority().epoch)
        );
        assert_eq!(
            converged.configmap_restore_generation,
            Some(test_runtime_authority().restore_generation)
        );
        assert_eq!(
            converged.daemonset_restore_generation,
            Some(test_runtime_authority().restore_generation)
        );
    }

    #[tokio::test]
    async fn delayed_old_ensure_cannot_readd_route_removed_by_new_generation() {
        let route = SniRoute::new("stale.example.test", "be_stale_app", "10.0.0.1:443")
            .expect("valid stale-writer route");
        let initial = render_route_into("global\n", &route);
        let state = Arc::new(Mutex::new(FakeKubeState::new(&initial)));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_next_configmap_replace = true;
            (
                locked.configmap_replace_entered.clone(),
                locked.configmap_replace_release.clone(),
            )
        };
        let old_route = route.clone();
        let old_client = fake_kube_client(Arc::clone(&state));
        let old = tokio::spawn(async move {
            reconcile_haproxy_config(
                old_client,
                &edge_config(),
                test_runtime_authority(),
                Some(1),
                |current| render_route_into(current, &old_route),
            )
            .await
        });
        entered.notified().await;

        let new_client = fake_kube_client(Arc::clone(&state));
        reconcile_haproxy_config(
            new_client,
            &edge_config(),
            test_runtime_authority(),
            Some(2),
            |current| remove_route_from(current, &route.backend_name, &route.host),
        )
        .await
        .expect("newer delete publishes while old ensure request is delayed");
        release.notify_one();
        let old_error = old
            .await
            .expect("old writer joins")
            .expect_err("old writer reports the newer mutation generation");
        assert!(matches!(
            old_error,
            EdgeRouteError::SupersededMutationGeneration {
                expected: 1,
                actual: 2
            }
        ));

        let converged = state.lock().unwrap();
        assert!(!converged.config.contains("stale.example.test"));
        assert_eq!(converged.mutation_generation, Some(2));
        assert_eq!(
            converged.generation.as_deref(),
            Some(haproxy_config_generation(&converged.config).as_str())
        );
        assert_eq!(converged.configmap_patch_attempts, 2);
    }

    #[tokio::test]
    async fn delayed_writer_from_superseded_restore_generation_cannot_write_back() {
        let route = SniRoute::new("stale.example.test", "be_stale_app", "10.0.0.1:443")
            .expect("valid stale-writer route");
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_next_configmap_replace = true;
            (
                locked.configmap_replace_entered.clone(),
                locked.configmap_replace_release.clone(),
            )
        };
        let old_route = route.clone();
        let old_client = fake_kube_client(Arc::clone(&state));
        let old = tokio::spawn(async move {
            reconcile_haproxy_config(
                old_client,
                &edge_config(),
                test_runtime_authority(),
                Some(1),
                |current| render_route_into(current, &old_route),
            )
            .await
        });
        entered.notified().await;

        let restored_authority = RuntimeAuthority {
            epoch: Uuid::new_v4(),
            restore_generation: test_runtime_authority().restore_generation + 1,
        };
        reconcile_haproxy_config(
            fake_kube_client(Arc::clone(&state)),
            &edge_config(),
            restored_authority,
            Some(1),
            |current| current.to_string(),
        )
        .await
        .expect("restored authority publishes its comparable incarnation");
        release.notify_one();

        let old_error = old
            .await
            .expect("old writer joins")
            .expect_err("old writer is fenced after its resourceVersion conflict");
        assert!(matches!(
            old_error,
            EdgeRouteError::SupersededAuthorityRestoreGeneration {
                expected: 7,
                actual: 8
            }
        ));

        let converged = state.lock().unwrap();
        assert!(!converged.config.contains(&route.host));
        assert_eq!(
            converged.configmap_restore_generation,
            Some(restored_authority.restore_generation)
        );
        assert_eq!(
            converged.configmap_authority_epoch,
            Some(restored_authority.epoch)
        );
    }

    #[tokio::test]
    async fn pool_two_edge_reconcile_does_not_take_nested_database_connection() {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .expect("connect edge liveness database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate edge liveness database");
        let authority_lane = pool.begin().await.expect("hold caller authority lane");
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        let (entered, release) = {
            let mut locked = state.lock().unwrap();
            locked.pause_next_configmap_replace = true;
            (
                locked.configmap_replace_entered.clone(),
                locked.configmap_replace_release.clone(),
            )
        };
        let reconcile_pool = pool.clone();
        let client = fake_kube_client(Arc::clone(&state));
        let reconcile = tokio::spawn(async move {
            mutate_haproxy_config_with_client(
                &reconcile_pool,
                client,
                &edge_config(),
                test_runtime_authority(),
                Some(1),
                |_| "global\n  maxconn 4096\n".to_string(),
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .expect("edge reaches provider without waiting for a second DB connection");
        let heartbeat_headroom: i32 = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sqlx::query_scalar("SELECT 1").fetch_one(&pool),
        )
        .await
        .expect("reserved connection remains available")
        .expect("heartbeat-style query succeeds");
        assert_eq!(heartbeat_headroom, 1);
        release.notify_one();
        reconcile
            .await
            .expect("edge task joins")
            .expect("edge reconcile succeeds");
        authority_lane
            .rollback()
            .await
            .expect("release authority lane");
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
    fn full_reconcile_strips_only_cap_owned_routes_and_backends() {
        let cfg = "global\n  maxconn 4096\n\nfrontend fe_443\n  bind :443\n  use_backend operator_backend if { req.ssl_sni -i operator.example }\n  use_backend be_cap_old_app if { req.ssl_sni -i stale.example }\n  default_backend be_reject\n\nbackend operator_backend\n  server operator 10.0.0.9:443 check\n\nbackend be_cap_old_app\n  server tenant 10.0.0.1:443 check\n\nresolvers cluster_dns\n  nameserver dns 10.43.0.10:53\n\nbackend be_reject\n  tcp-request content reject\n";

        let out = remove_all_cap_managed_routes(cfg);

        assert!(!out.contains("be_cap_old_app"));
        assert!(!out.contains("stale.example"));
        assert!(out.contains("use_backend operator_backend"));
        assert!(out.contains("backend operator_backend"));
        assert!(out.contains("resolvers cluster_dns"));
        assert!(out.contains("backend be_reject"));
        assert!(out.ends_with('\n'));
    }

    #[test]
    fn full_reconcile_preserves_every_haproxy_3_3_operator_section() {
        for section in [
            "global",
            "defaults",
            "frontend",
            "backend",
            "listen",
            "userlist",
            "peers",
            "mailers",
            "namespace_list",
            "traces",
            "ring",
            "acme",
            "fcgi-app",
            "resolvers",
            "crt-store",
            "cache",
            "log-forward",
            "log-profile",
            "http-errors",
            // Retain compatibility with older HAProxy releases accepted by CAP.
            "program",
        ] {
            for indentation in ["", "  "] {
                let cfg = format!(
                    "frontend fe_443\n  use_backend be_cap_old_app if {{ req.ssl_sni -i stale.example }}\n\nbackend be_cap_old_app\n  server tenant 10.0.0.1:443 check\n\n{indentation}{section} operator_owned\n  operator-directive preserved\n"
                );

                let out = remove_all_cap_managed_routes(&cfg);

                assert!(
                    !out.contains("be_cap_old_app"),
                    "{section} with {indentation:?}: {out}"
                );
                assert!(
                    out.contains(&format!("{indentation}{section} operator_owned")),
                    "{section} with {indentation:?}: {out}"
                );
                assert!(
                    out.contains("operator-directive preserved"),
                    "{section} with {indentation:?}: {out}"
                );
            }
        }
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
