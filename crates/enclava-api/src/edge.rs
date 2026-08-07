use enclava_common::validate::{
    ValidateError, validate_app_name, validate_fqdn, validate_org_slug,
};
use k8s_openapi::api::{
    apps::v1::DaemonSet,
    core::v1::{ConfigMap, Pod, Service},
};
use kube::{
    Api, Client,
    api::{ApiResource, DynamicObject, ListParams, PostParams},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::{collections::HashSet, net::IpAddr};
use uuid::Uuid;

use crate::state::AppState;

const HAPROXY_CONFIG_GENERATION_ANNOTATION: &str = "config.enclava.dev/haproxy-sha256";
const HAPROXY_MUTATION_GENERATION_ANNOTATION: &str =
    "config.enclava.dev/haproxy-mutation-generation";
const HAPROXY_CONFIGMAP_SERIALIZED_BUDGET_BYTES: usize = 900 * 1024;
const KUBERNETES_CAS_ATTEMPTS: usize = 8;
const KUBERNETES_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const HAPROXY_ROLLOUT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);
const HAPROXY_ROLLOUT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

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
    #[error("HAProxy DaemonSet rollout did not converge within 5 minutes")]
    DaemonSetRolloutTimeout,
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
    mutation_generation: Option<i64>,
    routes: &[SniRoute],
) -> Result<(), EdgeRouteError> {
    mutate_haproxy_config(pool, config, mutation_generation, |current| {
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
    mutation_generation: Option<i64>,
    routes: &[(String, String)],
) -> Result<(), EdgeRouteError> {
    let changed = mutate_haproxy_config(pool, config, mutation_generation, |current| {
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

/// Rebuild every CAP-owned route from current Postgres and Kubernetes state.
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
    lease
        .guard_provider(reconcile_all_haproxy_routes_for_generation(
            state, generation,
        ))
        .await??;
    lease.finish().await?;
    Ok(())
}

async fn reconcile_all_haproxy_routes_for_generation(
    state: &AppState,
    generation: i64,
) -> Result<(), EdgeRouteError> {
    let client = Client::try_default().await?;
    let config = EdgeRouteConfig::from_env();
    let routes = load_desired_haproxy_routes(&state.db, client.clone()).await?;
    // This full rebuild owns the global fence and reloads authoritative state
    // on every claim, so reset authority must survive a failed first lease.
    reconcile_haproxy_config(client.clone(), &config, Some(generation), true, |current| {
        render_authoritative_haproxy_config(current, &routes)
    })
    .await?;
    let expected_generation = current_haproxy_config_generation(client.clone(), &config).await?;
    wait_for_haproxy_daemonset_rollout(client, &config, &expected_generation).await?;
    Ok(())
}

/// Startup waits out only an existing bounded mutation lease. Every provider
/// or database failure remains fatal and keeps readiness false.
pub async fn reconcile_all_haproxy_routes_at_startup(
    state: &AppState,
) -> Result<(), EdgeReconciliationError> {
    loop {
        match reconcile_all_haproxy_routes(state).await {
            Err(EdgeReconciliationError::Mutation(
                crate::mutation_leases::MutationLeaseError::Busy,
            )) => tokio::time::sleep(std::time::Duration::from_secs(2)).await,
            result => return result,
        }
    }
}

pub fn spawn_haproxy_reconciler(state: AppState) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            match haproxy_routes_need_reconciliation(&state).await {
                Ok(false) => continue,
                Ok(true) => {}
                Err(error) => {
                    tracing::warn!(%error, "could not inspect tenant HAProxy convergence");
                    continue;
                }
            }
            match reconcile_all_haproxy_routes(&state).await {
                Ok(()) => {}
                Err(EdgeReconciliationError::Mutation(
                    crate::mutation_leases::MutationLeaseError::Busy,
                )) => {}
                Err(error) => {
                    tracing::warn!(%error, "tenant HAProxy reconciliation remains pending")
                }
            }
        }
    });
}

async fn haproxy_routes_need_reconciliation(state: &AppState) -> Result<bool, EdgeRouteError> {
    let client = Client::try_default().await?;
    let config = EdgeRouteConfig::from_env();
    let routes = load_desired_haproxy_routes(&state.db, client.clone()).await?;
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
    let durable_generation: Option<i64> = sqlx::query_scalar(
        "SELECT generation
           FROM external_resource_mutation_leases
          WHERE resource_scope = 'edge_config'
            AND resource_key = 'global'",
    )
    .fetch_optional(&state.db)
    .await?;
    if durable_generation != Some(configmap_mutation_generation(&cm)?)
        || render_authoritative_haproxy_config(current, &routes) != *current
    {
        return Ok(true);
    }

    Ok(
        !haproxy_daemonset_rollout_complete(client, &config, &haproxy_config_generation(current))
            .await?,
    )
}

async fn load_desired_haproxy_routes(
    pool: &PgPool,
    client: Client,
) -> Result<Vec<SniRoute>, EdgeRouteError> {
    let apps = load_desired_edge_apps(pool).await?;
    let mut routes = Vec::new();
    for app in apps {
        let Some(address) =
            resolve_existing_service_address(client.clone(), &app.name, &app.namespace).await?
        else {
            tracing::warn!(
                app_id = %app.app_id,
                "excluding HAProxy route because its workload Service is absent"
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

async fn load_desired_edge_apps(pool: &PgPool) -> Result<Vec<DesiredEdgeApp>, sqlx::Error> {
    sqlx::query_as::<_, DesiredEdgeApp>(
        "SELECT app.id AS app_id, app.name, app.namespace, app.domain,
                app.tee_domain, app.custom_domain,
                organization.cust_slug AS org_slug
           FROM apps AS app
           JOIN organizations AS organization ON organization.id = app.org_id
           JOIN LATERAL (
                SELECT deployment.status
                  FROM deployment_apply_jobs AS job
                  JOIN deployments AS deployment
                    ON deployment.id = job.deployment_id
                   AND deployment.app_id = job.app_id
                 WHERE job.app_id = app.id
                   AND deployment.status IN (
                        'watching'::deploy_status_enum,
                        'healthy'::deploy_status_enum
                   )
                 ORDER BY job.generation DESC
                 LIMIT 1
           ) AS latest ON true
          WHERE app.status IN (
                'creating'::app_status_enum,
                'running'::app_status_enum
          )
          ORDER BY app.id",
    )
    .fetch_all(pool)
    .await
}

async fn mutate_haproxy_config<F>(
    _pool: &PgPool,
    config: &EdgeRouteConfig,
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
    mutate_haproxy_config_with_client(_pool, client, config, mutation_generation, mutate).await
}

async fn mutate_haproxy_config_with_client<F>(
    _pool: &PgPool,
    client: Client,
    config: &EdgeRouteConfig,
    mutation_generation: Option<i64>,
    mutate: F,
) -> Result<bool, EdgeRouteError>
where
    F: Fn(&str) -> String,
{
    reconcile_haproxy_config(client, config, mutation_generation, false, mutate).await
}

async fn reconcile_haproxy_config<F>(
    client: Client,
    config: &EdgeRouteConfig,
    mutation_generation: Option<i64>,
    allow_generation_reset: bool,
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
        let current_mutation_generation = configmap_mutation_generation(&cm)?;
        if let Some(expected_generation) = mutation_generation
            && current_mutation_generation > expected_generation
            && !allow_generation_reset
        {
            // This closure belongs to an older durable resource owner. Never
            // recompute it atop the newer intent after an RV conflict.
            return Ok(false);
        }
        let updated = mutate(&current);
        let mutation_generation_changed =
            mutation_generation.is_some_and(|expected| current_mutation_generation != expected);
        if updated == current && !mutation_generation_changed {
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
        if let Some(expected_generation) = mutation_generation {
            cm.metadata.annotations.get_or_insert_default().insert(
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
        let generation = haproxy_config_generation(current);
        let mut daemonset = ds_api.get(&config.daemonset_name).await?;
        if daemonset_config_generation(&daemonset) == Some(generation.as_str()) {
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
            .insert(
                HAPROXY_CONFIG_GENERATION_ANNOTATION.to_string(),
                generation.clone(),
            );
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

fn configmap_mutation_generation(configmap: &ConfigMap) -> Result<i64, EdgeRouteError> {
    configmap
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
        .map(|generation| generation.unwrap_or(0))
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

async fn wait_for_haproxy_daemonset_rollout(
    client: Client,
    config: &EdgeRouteConfig,
    expected_generation: &str,
) -> Result<(), EdgeRouteError> {
    tokio::time::timeout(HAPROXY_ROLLOUT_TIMEOUT, async {
        loop {
            if haproxy_daemonset_rollout_complete(client.clone(), config, expected_generation)
                .await?
            {
                return Ok(());
            }
            tokio::time::sleep(HAPROXY_ROLLOUT_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| EdgeRouteError::DaemonSetRolloutTimeout)?
}

async fn current_haproxy_config_generation(
    client: Client,
    config: &EdgeRouteConfig,
) -> Result<String, EdgeRouteError> {
    let configmaps: Api<ConfigMap> = Api::namespaced(client, &config.namespace);
    let configmap = configmaps.get(&config.configmap_name).await?;
    let current = configmap
        .data
        .as_ref()
        .and_then(|data| data.get("haproxy.cfg"))
        .ok_or_else(|| EdgeRouteError::MissingConfig {
            namespace: config.namespace.clone(),
            name: config.configmap_name.clone(),
        })?;
    Ok(haproxy_config_generation(current))
}

async fn haproxy_daemonset_rollout_complete(
    client: Client,
    config: &EdgeRouteConfig,
    expected_generation: &str,
) -> Result<bool, EdgeRouteError> {
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), &config.namespace);
    let daemonset = daemonsets.get(&config.daemonset_name).await?;
    if !daemonset_rollout_status_complete(&daemonset, expected_generation) {
        return Ok(false);
    }
    let pods: Api<Pod> = Api::namespaced(client, &config.namespace);
    let pods = pods.list(&ListParams::default()).await?;
    Ok(daemonset_pods_rollout_complete(
        &daemonset,
        &pods.items,
        expected_generation,
    ))
}

fn daemonset_rollout_status_complete(daemonset: &DaemonSet, expected_generation: &str) -> bool {
    if daemonset_config_generation(daemonset) != Some(expected_generation) {
        return false;
    }
    let Some(generation) = daemonset.metadata.generation else {
        return false;
    };
    let Some(status) = daemonset.status.as_ref() else {
        return false;
    };
    let desired = status.desired_number_scheduled;
    desired > 0
        && status
            .observed_generation
            .is_some_and(|observed| observed >= generation)
        && status.updated_number_scheduled == Some(desired)
        && status.number_ready == desired
        && status.number_available == Some(desired)
        && status.number_unavailable.unwrap_or_default() == 0
        && status.number_misscheduled == 0
}

fn daemonset_pods_rollout_complete(
    daemonset: &DaemonSet,
    pods: &[Pod],
    expected_generation: &str,
) -> bool {
    let Some(uid) = daemonset.metadata.uid.as_deref() else {
        return false;
    };
    let Some(desired) = daemonset
        .status
        .as_ref()
        .map(|status| status.desired_number_scheduled)
        .filter(|desired| *desired > 0)
    else {
        return false;
    };
    let owned = pods.iter().filter(|pod| {
        pod.metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| {
                owners
                    .iter()
                    .any(|owner| owner.controller == Some(true) && owner.uid == uid)
            })
    });
    let mut count = 0;
    for pod in owned {
        count += 1;
        let exact_generation = pod
            .metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(HAPROXY_CONFIG_GENERATION_ANNOTATION))
            .is_some_and(|generation| generation == expected_generation);
        let ready = pod.status.as_ref().is_some_and(|status| {
            status.conditions.as_ref().is_some_and(|conditions| {
                conditions
                    .iter()
                    .any(|condition| condition.type_ == "Ready" && condition.status == "True")
            })
        });
        if !exact_generation || !ready || pod.metadata.deletion_timestamp.is_some() {
            return false;
        }
    }
    count == desired as usize
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
    Ok(Some(
        service
            .spec
            .and_then(|spec| spec.cluster_ip)
            .filter(|ip| !ip.is_empty() && ip != "None")
            .unwrap_or_else(|| format!("{app_name}.{namespace}.svc.cluster.local")),
    ))
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

fn render_authoritative_haproxy_config(config: &str, routes: &[SniRoute]) -> String {
    let mut rendered = remove_all_cap_managed_routes(config);
    for route in routes {
        rendered = render_route_into(&rendered, route);
    }
    rendered
}

fn remove_all_cap_managed_routes(config: &str) -> String {
    let lines: Vec<&str> = config.lines().collect();
    let mut managed_backends = HashSet::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(name) = line.trim().strip_prefix("backend ") else {
            continue;
        };
        let name = name.split_ascii_whitespace().next().unwrap_or_default();
        let end = lines[index + 1..]
            .iter()
            .position(|candidate| is_haproxy_section_header(candidate))
            .map_or(lines.len(), |offset| index + 1 + offset);
        let generated_marker = lines[index + 1..end]
            .iter()
            .any(|candidate| candidate.contains("Generated from CAP caddy-sni-route ConfigMap."));
        if is_cap_managed_backend_name(name) || generated_marker {
            managed_backends.insert(name.to_string());
        }
    }

    let mut out = Vec::with_capacity(lines.len());
    let mut skipping_backend = false;
    for line in lines {
        if skipping_backend {
            if is_haproxy_section_header(line) {
                skipping_backend = false;
            } else {
                continue;
            }
        }
        let tokens: Vec<&str> = line.split_ascii_whitespace().collect();
        if tokens.first() == Some(&"backend")
            && tokens
                .get(1)
                .is_some_and(|backend| managed_backends.contains(*backend))
        {
            skipping_backend = true;
            continue;
        }
        if tokens.first() == Some(&"use_backend")
            && tokens
                .get(1)
                .is_some_and(|backend| managed_backends.contains(*backend))
        {
            continue;
        }
        if tokens.first() == Some(&"acl")
            && tokens
                .get(1)
                .is_some_and(|acl| acl.starts_with("acl_cap_") || acl.starts_with("acl_flowforge_"))
        {
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

fn is_cap_managed_backend_name(name: &str) -> bool {
    name.starts_with("be_cap_")
        || (name.starts_with("be_flowforge_") && name.contains("_sni_route_"))
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
            let annotations = self.mutation_generation.map(|generation| {
                json!({ HAPROXY_MUTATION_GENERATION_ANNOTATION: generation.to_string() })
            });
            json!({
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": "haproxy-tenant",
                    "namespace": "tenant-envoy",
                    "resourceVersion": self.configmap_resource_version.to_string(),
                    "annotations": annotations,
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
                    "resourceVersion": self.daemonset_resource_version.to_string(),
                    "generation": self.daemonset_resource_version,
                    "uid": "fake-haproxy-daemonset",
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
                "status": {
                    "currentNumberScheduled": 1,
                    "desiredNumberScheduled": 1,
                    "numberAvailable": 1,
                    "numberMisscheduled": 0,
                    "numberReady": 1,
                    "numberUnavailable": 0,
                    "observedGeneration": self.daemonset_resource_version,
                    "updatedNumberScheduled": 1,
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

    #[test]
    fn rollout_requires_observed_status_and_exact_ready_owned_pods() {
        let state = Arc::new(Mutex::new(FakeKubeState::new("global\n")));
        let ready: DaemonSet = serde_json::from_value(state.lock().unwrap().daemonset())
            .expect("valid ready DaemonSet");
        let expected = haproxy_config_generation("global\n");
        assert!(daemonset_rollout_status_complete(&ready, &expected));

        let mut wrong_config = ready.clone();
        wrong_config
            .spec
            .as_mut()
            .unwrap()
            .template
            .metadata
            .as_mut()
            .unwrap()
            .annotations
            .as_mut()
            .unwrap()
            .insert(
                HAPROXY_CONFIG_GENERATION_ANNOTATION.to_string(),
                "wrong".to_string(),
            );
        assert!(!daemonset_rollout_status_complete(&wrong_config, &expected));

        let mut stale = ready.clone();
        stale.status.as_mut().unwrap().observed_generation = Some(0);
        assert!(!daemonset_rollout_status_complete(&stale, &expected));

        let mut not_updated = ready.clone();
        not_updated
            .status
            .as_mut()
            .unwrap()
            .updated_number_scheduled = Some(0);
        assert!(!daemonset_rollout_status_complete(&not_updated, &expected));

        let mut not_ready = ready.clone();
        not_ready.status.as_mut().unwrap().number_ready = 0;
        assert!(!daemonset_rollout_status_complete(&not_ready, &expected));

        let mut not_available = ready.clone();
        not_available.status.as_mut().unwrap().number_available = Some(0);
        assert!(!daemonset_rollout_status_complete(
            &not_available,
            &expected
        ));

        let mut misscheduled = ready.clone();
        misscheduled.status.as_mut().unwrap().number_misscheduled = 1;
        assert!(!daemonset_rollout_status_complete(&misscheduled, &expected));

        let mut zero_desired = ready.clone();
        zero_desired
            .status
            .as_mut()
            .unwrap()
            .desired_number_scheduled = 0;
        assert!(!daemonset_rollout_status_complete(&zero_desired, &expected));

        let ready_pod: Pod = serde_json::from_value(json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "haproxy-ready",
                "namespace": "tenant-envoy",
                "annotations": { HAPROXY_CONFIG_GENERATION_ANNOTATION: expected },
                "ownerReferences": [{
                    "apiVersion": "apps/v1",
                    "kind": "DaemonSet",
                    "name": "haproxy-tenant",
                    "uid": "fake-haproxy-daemonset",
                    "controller": true,
                }],
            },
            "status": { "conditions": [{ "type": "Ready", "status": "True" }] },
        }))
        .expect("valid ready HAProxy pod");
        assert!(daemonset_pods_rollout_complete(
            &ready,
            std::slice::from_ref(&ready_pod),
            &expected,
        ));

        let mut old_ready = ready_pod.clone();
        old_ready.metadata.annotations.as_mut().unwrap().insert(
            HAPROXY_CONFIG_GENERATION_ANNOTATION.to_string(),
            "old".to_string(),
        );
        let mut updated_unready = ready_pod;
        updated_unready.metadata.name = Some("haproxy-updated".to_string());
        updated_unready
            .status
            .as_mut()
            .unwrap()
            .conditions
            .as_mut()
            .unwrap()[0]
            .status = "False".to_string();
        assert!(!daemonset_pods_rollout_complete(
            &ready,
            &[old_ready, updated_unready],
            &expected,
        ));
    }

    async fn edge_database_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect edge authority test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate edge authority test database");
        pool
    }

    async fn insert_edge_deployment_job(
        pool: &PgPool,
        org_id: Uuid,
        app_id: Uuid,
        deployment_id: Uuid,
        deployment_status: &str,
        job_state: &str,
    ) {
        let mut tx = pool.begin().await.expect("begin edge deployment fixture");
        sqlx::query(
            "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
             VALUES ($1, $2, $3, $4::deploy_status_enum, '{}'::jsonb)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(deployment_status)
        .execute(&mut *tx)
        .await
        .expect("insert edge test deployment");
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required, state
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, false, $5
             )",
        )
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7_u8; 32])
        .bind(job_state)
        .execute(&mut *tx)
        .await
        .expect("insert edge test apply job");
        tx.commit().await.expect("commit edge deployment fixture");
    }

    async fn reconcile_to(client: Client, desired: &str) -> Result<bool, EdgeRouteError> {
        reconcile_haproxy_config(client, &edge_config(), Some(1), false, |_| {
            desired.to_string()
        })
        .await
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
            reconcile_haproxy_config(old_client, &edge_config(), Some(1), false, |current| {
                render_route_into(current, &old_route)
            })
            .await
        });
        entered.notified().await;

        let new_client = fake_kube_client(Arc::clone(&state));
        reconcile_haproxy_config(new_client, &edge_config(), Some(2), false, |current| {
            remove_route_from(current, &route.backend_name, &route.host)
        })
        .await
        .expect("newer delete publishes while old ensure request is delayed");
        release.notify_one();
        let old_changed = old
            .await
            .expect("old writer joins")
            .expect("old writer observes the newer mutation generation");
        assert!(!old_changed);

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
    async fn authoritative_retry_replaces_stale_configmap_after_first_lease_fails() {
        let current = "global\n  maxconn 4096\n";
        let desired = "global\n  maxconn 2048\n";
        let state = Arc::new(Mutex::new(FakeKubeState::new(current)));
        {
            let mut initial = state.lock().unwrap();
            initial.mutation_generation = Some(4);
            initial
                .configmap_patch_outcomes
                .push_back(FakePatchOutcome::FailBeforeApply);
        }
        let client = fake_kube_client(Arc::clone(&state));

        assert!(
            reconcile_haproxy_config(client.clone(), &edge_config(), Some(1), true, |_| {
                desired.to_string()
            })
            .await
            .is_err(),
            "the first durable lease can fail before changing Kubernetes"
        );
        assert!(
            reconcile_haproxy_config(client, &edge_config(), Some(2), true, |_| {
                desired.to_string()
            })
            .await
            .expect("a later authoritative retry resets stale cluster metadata")
        );

        let converged = state.lock().unwrap();
        assert_eq!(converged.config, desired);
        assert_eq!(converged.mutation_generation, Some(2));
        assert_eq!(
            converged.generation.as_deref(),
            Some(haproxy_config_generation(desired).as_str())
        );
    }

    #[tokio::test]
    async fn pending_replacement_keeps_latest_routable_app_selected() {
        let pool = edge_database_test_pool().await;
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = app_id.simple().to_string();
        sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
            .bind(org_id)
            .bind(format!("edge-{suffix}"))
            .bind(&suffix[..8])
            .execute(&pool)
            .await
            .expect("insert edge test organization");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain, status
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'running'
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("edge-{}", &suffix[..12]))
        .bind(format!("cap-edge-{}", &suffix[..12]))
        .bind(format!("instance-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-edge-{}-sa", &suffix[..12]))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("edge-{}.example.test", &suffix[..12]))
        .bind(format!("edge-{}.tee.example.test", &suffix[..12]))
        .execute(&pool)
        .await
        .expect("insert edge test app");

        let healthy_id = Uuid::new_v4();
        insert_edge_deployment_job(&pool, org_id, app_id, healthy_id, "healthy", "completed").await;
        insert_edge_deployment_job(
            &pool,
            org_id,
            app_id,
            Uuid::new_v4(),
            "pending",
            "setup_pending",
        )
        .await;

        let selected = load_desired_edge_apps(&pool)
            .await
            .expect("select latest routable apps");
        assert!(
            selected.iter().any(|app| app.app_id == app_id),
            "a newer pending replacement must not purge the serving route"
        );

        sqlx::query(
            "UPDATE deployments
                SET status = 'failed'::deploy_status_enum
              WHERE id = $1",
        )
        .bind(healthy_id)
        .execute(&pool)
        .await
        .expect("make old deployment non-routable");
        let selected = load_desired_edge_apps(&pool)
            .await
            .expect("reselect without a routable deployment");
        assert!(!selected.iter().any(|app| app.app_id == app_id));
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete edge selection fixture");
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
    fn authoritative_rebuild_repairs_routes_and_purges_retired_deployments() {
        let current = "global\n  maxconn 4096\n\nfrontend fe_443\n  bind :443\n  acl is_mgmt_sni req.ssl_sni -i management.example.test\n  acl acl_flowforge_stale req.ssl_sni -i stale.example.test\n  use_backend be_reject if is_mgmt_sni\n  use_backend be_cap_old_app if is_mgmt_sni\n  use_backend be_cap_old_app if { req.ssl_sni -i stale-cap.example.test }\n  use_backend be_flowforge_1_retired_sni_route_app if acl_flowforge_stale\n  default_backend be_reject\n\nbackend be_cap_old_app\n  # Generated from CAP caddy-sni-route ConfigMap.\n  server tenant 10.0.0.1:443 check\n\nbackend be_flowforge_1_retired_sni_route_app\n  server tenant 10.0.0.2:443 check\n\nresolvers cluster_dns\n  nameserver dns 10.43.0.10:53\n\nbackend be_reject\n  tcp-request content reject\n";
        let routes = vec![
            SniRoute::new(
                "api.abcd1234.enclava.dev",
                "be_cap_abcd1234_api_app",
                "10.43.1.2:443",
            )
            .unwrap(),
            SniRoute::new(
                "api.abcd1234.tee.enclava.dev",
                "be_cap_abcd1234_api_tee",
                "10.43.1.2:8081",
            )
            .unwrap(),
            SniRoute::new(
                "web.ef567890.enclava.dev",
                "be_cap_ef567890_web_app",
                "10.43.1.3:443",
            )
            .unwrap(),
            SniRoute::new(
                "web.ef567890.tee.enclava.dev",
                "be_cap_ef567890_web_tee",
                "10.43.1.3:8081",
            )
            .unwrap(),
        ];

        let rebuilt = render_authoritative_haproxy_config(current, &routes);

        for retired in [
            "be_cap_old_app",
            "be_flowforge_1_retired_sni_route_app",
            "acl_flowforge_stale",
            "stale-cap.example.test",
            "stale.example.test",
        ] {
            assert!(
                !rebuilt.contains(retired),
                "{retired} remained in:\n{rebuilt}"
            );
        }
        for preserved in [
            "acl is_mgmt_sni",
            "use_backend be_reject if is_mgmt_sni",
            "resolvers cluster_dns",
            "backend be_reject",
        ] {
            assert!(
                rebuilt.contains(preserved),
                "{preserved} was removed from:\n{rebuilt}"
            );
        }
        assert!(rebuilt.contains("use_backend be_cap_abcd1234_api_app"));
        assert!(rebuilt.contains("use_backend be_cap_abcd1234_api_tee"));
        let backends: Vec<&str> = rebuilt
            .lines()
            .filter_map(|line| line.strip_prefix("backend "))
            .collect();
        let mappings: Vec<&str> = rebuilt
            .lines()
            .filter_map(|line| line.trim().strip_prefix("use_backend "))
            .filter_map(|line| line.split_ascii_whitespace().next())
            .collect();
        assert_eq!(
            backends
                .iter()
                .filter(|backend| backend.starts_with("be_cap_"))
                .count(),
            4
        );
        assert_eq!(
            mappings
                .iter()
                .filter(|backend| backend.starts_with("be_cap_"))
                .count(),
            4
        );
        assert_eq!(backends.len(), 5);
        assert_eq!(mappings.len(), 5);
        assert_eq!(
            backends.iter().copied().collect::<HashSet<_>>(),
            mappings.iter().copied().collect::<HashSet<_>>()
        );
        assert_eq!(
            backends
                .iter()
                .filter(|backend| **backend == "be_reject")
                .count(),
            1
        );
        assert_eq!(
            render_authoritative_haproxy_config(&rebuilt, &routes),
            rebuilt
        );
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
