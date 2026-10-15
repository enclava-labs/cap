//! Deploy orchestrator: builds ConfidentialApp from DB state, calls engine, records result.

use enclava_common::image::ImageRef;
use enclava_common::types::{ResourceLimits, UnlockMode as CommonUnlockMode};
use enclava_engine::apply::{
    engine::ApplyEngine,
    gateway::apply_gateway_resources,
    generation::MutationGeneration,
    namespace::apply_namespace,
    network_policy::apply_network_policy,
    orchestrator::{MANIFEST_HASH_ANNOTATION, manifest_hash},
    resources::{apply_namespaced_resource, apply_standard_resources},
    statefulset::apply_statefulset,
    types::{DeployPhase, DeployStatus as EngineDeployStatus},
    watch::watch_rollout,
};
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::types::{
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, EgressMode,
    LogEncryptionConfig, StorageSpec, WorkloadArtifactBinding, WorkloadSecurityProfile,
};
use k8s_openapi::api::core::v1::{Secret, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{
    Api, Resource as _,
    api::{DeleteParams, ListParams, Patch, PatchParams},
};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::BTreeSet;
use std::net::IpAddr;
use uuid::Uuid;

use crate::models::{App, AppContainer, AppResources, AppStatus};

const DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME: &str = "enclava-registry-auth";

/// The tenant image-pull secret name the cleanup sweep must delete from
/// adopted namespaces. Re-uses `configured_tenant_image_pull_secret_name`'s
/// env-derived value so the sweep always matches what apply published.
pub(crate) fn default_tenant_image_pull_secret_name_for_cleanup() -> String {
    configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string())
}
const TENANT_IMAGE_PULL_SECRET_NAME_ENV: &str = "TENANT_IMAGE_PULL_SECRET_NAME";
const TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV: &str = "TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES";
const PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV: &str = "CAP_PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS";
/// Ownership marker on every generated tenant pull secret: the cleanup and
/// reconcile paths recognize CAP-generated secrets by this label regardless of
/// the secret's name (review finding on #243 — a changed
/// `TENANT_IMAGE_PULL_SECRET_NAME` must not strand an old platform PAT).
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "enclava-platform";
/// The cleanup's discovery/deletion selector, distinct from the generic
/// managed-by marker (review finding on #243): only Secrets carrying this
/// label enter the pull-secret reconciliation, so a later Secret that merely
/// shares the platform managed-by marker can never be swept.
const TENANT_PULL_SECRET_LABEL: &str = "cap.enclava.dev/tenant-image-pull-secret";
const TENANT_PULL_SECRET_LABEL_VALUE: &str = "true";
const PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION: &str =
    "cap.enclava.dev/pull-secret-credential-generation";

fn pull_secret_credential_generation() -> u64 {
    std::env::var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn newer_pull_secret_credentials(secret: &Secret) -> bool {
    secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION))
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|generation| generation > pull_secret_credential_generation())
}
/// Durable repair intent on a generated ServiceAccount (Codex review on #243,
/// P2 "persist failed pull-secret reference restorations"): a comma-separated
/// list of pull-secret names whose `imagePullSecrets` references this cleanup
/// CLEARED but whose restoration is not yet proven — written atomically with
/// the clear itself, discharged when the reference is restored or the removal
/// provably completed. Without it, a transient failure in the restoration path
/// (e.g. after the delete discovered a mid-cleanup replacement) left the next
/// sweep with no record of the cleared reference: an unmanaged replacement is
/// excluded from discovery and an in-scope managed secret is simply kept, so
/// the sweep reported convergence with the ServiceAccount permanently detached
/// from the surviving pull secret.
const PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION: &str =
    "cap.enclava.dev/pending-pull-secret-reference-repairs";
pub(crate) const PERSISTED_DEPLOYMENT_ERROR_MESSAGE: &str = "deployment_error";

#[derive(Debug, Clone)]
struct TenantImagePullSecretConfig {
    name: String,
    username: String,
    token: String,
    allowed_repositories: Vec<ImagePullRepositoryScope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImagePullRepositoryScope {
    registry: String,
    repository: String,
    include_subrepositories: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct DeploymentOutcome {
    deploy_status: &'static str,
    app_status: &'static str,
    error_message: Option<String>,
    terminal: bool,
}

fn classify_rollout_result(
    result: Result<EngineDeployStatus, String>,
    previous_app_status: AppStatus,
    unlock_mode: crate::models::UnlockMode,
) -> DeploymentOutcome {
    match result {
        Ok(status) if status.phase == DeployPhase::Running => DeploymentOutcome {
            deploy_status: "healthy",
            app_status: "running",
            error_message: None,
            terminal: true,
        },
        Ok(status)
            if status.phase == DeployPhase::TimedOut
                && previous_app_status == AppStatus::Running
                && unlock_mode == crate::models::UnlockMode::Password =>
        {
            DeploymentOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_message: None,
                terminal: true,
            }
        }
        Ok(status)
            if status.phase == DeployPhase::TimedOut
                && previous_app_status == AppStatus::Creating
                && unlock_mode == crate::models::UnlockMode::Password =>
        {
            DeploymentOutcome {
                deploy_status: "watching",
                app_status: "creating",
                error_message: None,
                terminal: false,
            }
        }
        Ok(_) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE.to_string()),
            terminal: true,
        },
        Err(_) => DeploymentOutcome {
            deploy_status: "failed",
            app_status: "failed",
            error_message: Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE.to_string()),
            terminal: true,
        },
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn configured_tenant_image_pull_secret_name() -> Option<String> {
    if let Some(name) = env_nonempty(TENANT_IMAGE_PULL_SECRET_NAME_ENV) {
        return Some(name);
    }

    match (env_nonempty("GHCR_USERNAME"), env_nonempty("GHCR_TOKEN")) {
        (Some(_), Some(_)) => Some(DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string()),
        _ => None,
    }
}

/// Startup validation (issue #225): GHCR pull-secret credentials without an
/// explicit, valid `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` scope are refused.
/// The platform GHCR PAT must never default into every tenant namespace.
pub fn tenant_image_pull_secret_startup_error() -> Option<String> {
    if let Ok(raw) = std::env::var("TENANT_IMAGE_PULL_CREDENTIAL_GENERATION")
        && raw.parse::<u64>().is_err()
    {
        return Some(
            "TENANT_IMAGE_PULL_CREDENTIAL_GENERATION must be an unsigned integer".to_string(),
        );
    }
    if tenant_image_pull_secret_config_from_env().is_some() {
        return None;
    }
    let ghcr_configured =
        env_nonempty("GHCR_USERNAME").is_some() && env_nonempty("GHCR_TOKEN").is_some();
    if !ghcr_configured {
        return None;
    }
    match env_nonempty(TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV) {
        None => Some(
            "GHCR_USERNAME/GHCR_TOKEN are set but TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES is \
             unset; the tenant image pull secret is never attached without an explicit \
             repository scope (issue #225). Set \
             TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES (e.g. ghcr.io/enclava-ai/templates/*) \
             or remove the GHCR credentials"
                .to_string(),
        ),
        Some(raw) => {
            // Name the specific malformed entries: a list with one valid and
            // one malformed scope must not report "no valid entries" (review
            // finding), or operators cannot identify what to fix.
            let reason = parse_image_pull_scopes_strict(&raw)
                .err()
                .unwrap_or_else(|| "no parseable entries".to_string());
            Some(format!(
                "GHCR_USERNAME/GHCR_TOKEN are set but TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES \
                 is unusable: {reason}. Every comma-separated entry must be valid — use \
                 registry/repository or registry/repository/* — and the tenant image pull \
                 secret is never attached without a valid scope (issue #225)"
            ))
        }
    }
}

fn tenant_image_pull_secret_config_from_env() -> Option<TenantImagePullSecretConfig> {
    let username = env_nonempty("GHCR_USERNAME")?;
    let token = env_nonempty("GHCR_TOKEN")?;
    let name = configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string());

    // Fail closed (issue #225): the platform GHCR credential is only
    // materialized into tenant namespaces when the operator pinned an
    // explicit, valid repository scope. An unset, empty, or invalid
    // TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES yields no secret at all rather
    // than the previous default of every tenant namespace.
    let allowed_repositories = tenant_image_pull_allowed_repositories_from_env_strict()?;

    Some(TenantImagePullSecretConfig {
        name,
        username,
        token,
        allowed_repositories,
    })
}

/// Parse TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES, surfacing invalid entries
/// instead of silently dropping them (issue #225): a scope list with a bad
/// entry must not degrade into a narrower — or worse, unscoped — secret.
/// `None` means unset/empty/invalid — no scoping information at all.
fn tenant_image_pull_allowed_repositories_from_env_strict() -> Option<Vec<ImagePullRepositoryScope>>
{
    let raw = env_nonempty(TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV)?;
    match parse_image_pull_scopes_strict(&raw) {
        Ok(scopes) => Some(scopes),
        Err(reason) => {
            tracing::error!(
                env = TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV,
                %reason,
                "tenant image pull secret disabled: TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES is unusable"
            );
            None
        }
    }
}

/// Pure core of [`tenant_image_pull_allowed_repositories_from_env_strict`]:
/// every comma-separated entry must parse; any invalid entry rejects the
/// whole list so a typo can never widen (or silently drop) the scope. The
/// error names each malformed entry so operators can fix the exact typo.
fn parse_image_pull_scopes_strict(raw: &str) -> Result<Vec<ImagePullRepositoryScope>, String> {
    let mut scopes = Vec::new();
    let mut invalid = Vec::new();
    for (index, entry) in raw.split(',').enumerate() {
        match parse_image_pull_repository_scope(entry) {
            Ok(scope) => scopes.push(scope),
            Err(reason) => invalid.push(format!("#{} {:?}: {}", index + 1, entry.trim(), reason)),
        }
    }
    if !invalid.is_empty() {
        return Err(format!("invalid entries {}", invalid.join("; ")));
    }
    if scopes.is_empty() {
        return Err("the list contains no entries".to_string());
    }
    Ok(scopes)
}

fn parse_image_pull_repository_scope(raw: &str) -> Result<ImagePullRepositoryScope, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("entry is empty".to_string());
    }

    // Strip exactly one trailing "/*" subrepository marker. Stripping all
    // trailing "/*" repetitions (e.g. `trim_end_matches`) would silently widen
    // a malformed `registry/repository/*/*` into the broader
    // `registry/repository/*` scope (P1 review): a repeated wildcard suffix
    // must be rejected, never widened.
    let (value, include_subrepositories) = match value.strip_suffix("/*") {
        Some(base) => (base, true),
        None => (value, false),
    };
    if value.contains('*') {
        return Err(
            "wildcard '*' is only allowed as a single trailing '/*' subrepository suffix"
                .to_string(),
        );
    }
    // Review finding on #243: entries such as `registry/repository:latest`,
    // `registry/repository@sha256:…`, or `https://registry/repository` used
    // to parse into scopes whose repository can never equal the parsed
    // repository of a digest-pinned workload image, so startup succeeded but
    // every affected private workload silently lost its pull secret. Reject
    // tags, digests, and schemes outright.
    if value.contains('@') {
        return Err(
            "digests ('@…') are not allowed in a repository scope; use registry/repository \
             (workload images are digest-pinned separately)"
                .to_string(),
        );
    }
    if value.contains("://") {
        return Err(
            "URL schemes are not allowed in a repository scope; use registry/repository[:port] \
             without a scheme"
                .to_string(),
        );
    }
    let value = value.trim_end_matches('/');
    let Some((registry, repository)) = value.split_once('/') else {
        return Err("expected registry/repository or registry/repository/*".to_string());
    };
    if repository.contains(':') {
        return Err(
            "tags (':…') are not allowed in a repository scope; use registry/repository"
                .to_string(),
        );
    }
    validate_repository_scope_registry(registry)?;
    // The generated tenant pull secret only authenticates the literal `ghcr.io`
    // host (its `.dockerconfigjson` carries a single `ghcr.io` auth entry made
    // from GHCR_USERNAME/GHCR_TOKEN). A scope at any other registry can only
    // attach the platform PAT to namespaces that can never use it — the token
    // would be readable there without authenticating anything (review
    // finding) — so every scope must live under ghcr.io.
    if registry != "ghcr.io" {
        return Err(format!(
            "scope registry {registry:?} is not \"ghcr.io\"; the generated tenant image pull \
             secret only authenticates ghcr.io (GHCR_USERNAME/GHCR_TOKEN are GitHub credentials), \
             so a scope at another registry would expose the platform token to workloads that \
             cannot use it"
        ));
    }
    for component in repository.split('/') {
        if component.is_empty() {
            return Err(
                "repository path components must be non-empty (no leading or repeated '/')"
                    .to_string(),
            );
        }
        if component == "." || component == ".." {
            return Err(format!(
                "repository path component {component:?} is not a valid path component"
            ));
        }
        if !component
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
        {
            return Err(format!(
                "repository path component {component:?} contains characters the workload-image \
                 grammar does not allow"
            ));
        }
    }

    // Compatibility guarantee: the scope must round-trip through the workload
    // image parser unchanged, so `image_matches_repository_scope` compares
    // registry/repository values that both sides derive with the same grammar.
    let rendered = format!("{registry}/{repository}");
    let parsed = ImageRef::parse(&rendered)
        .map_err(|error| format!("{rendered:?} is not a valid repository reference: {error}"))?;
    if parsed.registry() != registry || parsed.repository() != repository {
        return Err(format!(
            "{rendered:?} is not written the way workload images name their repositories \
             (the image grammar reads it as {}/{}); use registry/repository exactly as it \
             appears in image references",
            parsed.registry(),
            parsed.repository()
        ));
    }

    Ok(ImagePullRepositoryScope {
        registry: registry.to_string(),
        repository: repository.to_string(),
        include_subrepositories,
    })
}

/// Registry side of a scope entry: an explicit `host[:port]` following the
/// same grammar the workload-image parser enforces for registries
/// (alphanumeric/`.`/`-` host with an optional numeric `:port`), plus the
/// explicitness that grammar implies. An `ImageRef` registry is always either
/// `docker.io` (the implicit-registry normalization) or contains a dot or a
/// port, so a bare first component such as `org/private` — which the image
/// grammar reads as the Docker Hub repository path `org/private` — can never
/// equal any parsed registry. Rejecting it at startup beats accepting a scope
/// that silently never matches (review finding on #243).
fn validate_repository_scope_registry(registry: &str) -> Result<(), String> {
    let (host, has_port) = match registry.split_once(':') {
        Some((host, port)) => {
            if port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!(
                    "registry {registry:?} must be host[:port] with a numeric port \
                     (a URL scheme like \"https:\" is not a registry name)"
                ));
            }
            if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
                return Err(format!(
                    "registry {registry:?} must have a numeric port in 1..=65535"
                ));
            }
            (host, true)
        }
        None => (registry, false),
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err(format!(
            "registry {registry:?} is not a valid registry host name"
        ));
    }
    if !has_port && !host.contains('.') {
        return Err(format!(
            "registry {registry:?} must be explicit (a dotted host name or host:port); workload \
             images without an explicit registry are parsed as Docker Hub paths, so write \
             \"docker.io/…\" if a Docker Hub repository is meant"
        ));
    }
    Ok(())
}

fn tenant_image_pull_secret_config_for_containers(
    containers: &[Container],
) -> Option<TenantImagePullSecretConfig> {
    let config = tenant_image_pull_secret_config_from_env()?;
    if tenant_image_pull_secret_applies_to_containers(containers, &config) {
        return Some(config);
    }

    tracing::warn!(
        secret = %config.name,
        allowed_repositories = ?config.allowed_repositories,
        "tenant image pull secret not attached because workload images are outside configured repository scope"
    );
    None
}

fn tenant_image_pull_secret_applies_to_containers(
    containers: &[Container],
    config: &TenantImagePullSecretConfig,
) -> bool {
    if containers.is_empty() {
        return false;
    }
    // Issue #225: an unscoped config must never attach the platform pull
    // secret to tenant workloads. `tenant_image_pull_secret_config_from_env`
    // already refuses to build a config without an explicit scope; treat an
    // empty scope here as fail-closed defense in depth.
    if config.allowed_repositories.is_empty() {
        tracing::warn!(
            secret = %config.name,
            "tenant image pull secret has no repository scope; refusing to attach"
        );
        return false;
    }

    images_match_repository_scopes(config, containers.iter().map(|container| &container.image))
}

fn image_matches_repository_scope(image: &ImageRef, scope: &ImagePullRepositoryScope) -> bool {
    if image.registry() != scope.registry {
        return false;
    }
    if image.repository() == scope.repository {
        return true;
    }
    scope.include_subrepositories
        && image
            .repository()
            .strip_prefix(&scope.repository)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn public_internet_egress_excluded_cidrs_from_env() -> Vec<String> {
    let Some(raw) = env_nonempty(PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV) else {
        return Vec::new();
    };
    raw.split(',')
        .filter_map(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return None;
            }
            match normalize_ipv4_cidr(entry) {
                Some(cidr) => Some(cidr),
                None => {
                    tracing::warn!(
                        env = PUBLIC_INTERNET_EGRESS_EXCLUDED_CIDRS_ENV,
                        cidr = entry,
                        "ignoring invalid public internet egress exclusion CIDR"
                    );
                    None
                }
            }
        })
        .collect()
}

fn normalize_ipv4_cidr(value: &str) -> Option<String> {
    let (addr, bits) = value.split_once('/')?;
    let bits = bits.trim().parse::<u8>().ok()?;
    if bits > 32 {
        return None;
    }
    let IpAddr::V4(addr) = addr.trim().parse::<IpAddr>().ok()? else {
        return None;
    };
    Some(format!("{addr}/{bits}"))
}

fn should_reconcile_global_signed_policy_artifacts(
    signed_policy_artifact_present: bool,
    _attestation: &AttestationConfig,
) -> bool {
    signed_policy_artifact_present
}

fn generate_tenant_image_pull_secret(
    namespace: &str,
    config: &TenantImagePullSecretConfig,
) -> Secret {
    use base64::Engine as _;

    let auth = base64::engine::general_purpose::STANDARD
        .encode(format!("{}:{}", config.username, config.token));
    let docker_config_json = serde_json::json!({
        "auths": {
            "ghcr.io": {
                "username": config.username,
                "password": config.token,
                "auth": auth,
            }
        }
    })
    .to_string();

    let mut string_data = std::collections::BTreeMap::new();
    string_data.insert(".dockerconfigjson".to_string(), docker_config_json);

    let mut labels = std::collections::BTreeMap::new();
    // Ownership marker: the stale-secret cleanup only ever deletes CAP-managed
    // secrets, and this label is how it recognizes them going forward.
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    // The pull-secret cleanup's discovery/deletion selector (review finding):
    // distinct from the generic managed-by marker so no other managed Secret
    // can ever enter the sweep.
    labels.insert(
        TENANT_PULL_SECRET_LABEL.to_string(),
        TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
    );

    let mut annotations = std::collections::BTreeMap::new();
    annotations.insert(
        PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION.to_string(),
        pull_secret_credential_generation().to_string(),
    );
    Secret {
        metadata: ObjectMeta {
            name: Some(config.name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        string_data: Some(string_data),
        type_: Some("kubernetes.io/dockerconfigjson".to_string()),
        ..Default::default()
    }
}

/// The `.dockerconfigjson` payload the current configuration would generate
/// for the managed pull secret (Codex review on #243, P1 "refresh kept pull
/// secrets after credential rotation"): a kept configured-name secret is
/// reconciled to this data so a rotated `GHCR_USERNAME`/`GHCR_TOKEN` reaches
/// every in-scope namespace without waiting for each app to redeploy. `None`
/// when no scoped config exists — nothing is generated, so nothing is
/// refreshed either.
fn expected_tenant_image_pull_secret_dockerconfigjson() -> Option<String> {
    let config = tenant_image_pull_secret_config_from_env()?;
    let secret = generate_tenant_image_pull_secret("", &config);
    secret
        .string_data
        .as_ref()?
        .get(".dockerconfigjson")
        .cloned()
}

/// The tenant image pull secret name CAP manages inside tenant namespaces.
fn managed_tenant_image_pull_secret_name() -> String {
    configured_tenant_image_pull_secret_name()
        .unwrap_or_else(|| DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string())
}

/// Whether an on-cluster Secret is the managed tenant image pull secret CAP
/// owns. Newly generated secrets carry the dedicated pull-secret label; a
/// secret without it is recognized only by the legacy generated shape — a
/// `kubernetes.io/dockerconfigjson` secret whose single auth entry is
/// `ghcr.io` and whose embedded credentials match the configured GHCR pair.
/// The credential match is required: a tenant (or operator) can legitimately
/// store their own GHCR pull secret under the same name, and the cleanup must
/// never delete a secret it cannot prove CAP generated (review finding).
/// Anything else in the namespace is tenant-owned and must never be deleted
/// by the stale-secret cleanup.
///
/// The generic `app.kubernetes.io/managed-by=enclava-platform` marker is
/// deliberately NOT sufficient proof (review finding on #243): it is used
/// broadly across platform resources, so accepting it alone would put every
/// generic-managed Secret at a managed name inside this cleanup's blast
/// radius. Only the dedicated pull-secret label — introduced specifically to
/// distinguish these secrets — or the legacy credential-shape proof counts.
fn is_managed_tenant_image_pull_secret(
    secret: &Secret,
    ghcr_credentials: Option<(&str, &str)>,
) -> bool {
    if is_labeled_managed_pull_secret(secret) {
        return true;
    }
    let Some((expected_username, expected_token)) = ghcr_credentials else {
        // Without the configured credentials there is no way to prove an
        // unlabeled secret is CAP-generated; leave it alone.
        return false;
    };
    if secret.type_.as_deref() != Some("kubernetes.io/dockerconfigjson") {
        return false;
    }
    let Some(raw) = secret
        .data
        .as_ref()
        .and_then(|data| data.get(".dockerconfigjson"))
    else {
        return false;
    };
    let Ok(config) = serde_json::from_slice::<serde_json::Value>(&raw.0) else {
        return false;
    };
    let Some(auths) = config.get("auths").and_then(|auths| auths.as_object()) else {
        return false;
    };
    if auths.len() != 1 {
        return false;
    }
    let Some(entry) = auths.get("ghcr.io") else {
        return false;
    };
    entry.get("username").and_then(|v| v.as_str()) == Some(expected_username)
        && entry.get("password").and_then(|v| v.as_str()) == Some(expected_token)
}

/// The GHCR credential pair CAP would have embedded in a generated pull
/// secret, when configured.
fn ghcr_pull_secret_credentials() -> Option<(String, String)> {
    Some((env_nonempty("GHCR_USERNAME")?, env_nonempty("GHCR_TOKEN")?))
}

/// Every image must match at least one configured scope — the deploy-time
/// gate for attaching the managed pull secret to a workload.
fn images_match_repository_scopes<'a>(
    config: &TenantImagePullSecretConfig,
    images: impl IntoIterator<Item = &'a ImageRef>,
) -> bool {
    let mut seen_any = false;
    for image in images {
        seen_any = true;
        if !config
            .allowed_repositories
            .iter()
            .any(|scope| image_matches_repository_scope(image, scope))
        {
            return false;
        }
    }
    seen_any
}

/// Whether any app in a namespace still qualifies for the managed pull secret
/// under the current scope. The startup cleanup sweep keeps the secret in a
/// namespace only while at least one of its apps would attach it on the next
/// deploy (`None` in an app slot means its stored image refs are unparsable,
/// which never qualifies).
fn namespace_keeps_tenant_image_pull_secret(
    config: Option<&TenantImagePullSecretConfig>,
    app_images: &[Option<Vec<ImageRef>>],
) -> bool {
    let Some(config) = config else {
        return false;
    };
    if config.allowed_repositories.is_empty() {
        return false;
    }
    app_images.iter().any(|images| {
        images
            .as_ref()
            .is_some_and(|images| images_match_repository_scopes(config, images.iter()))
    })
}

/// Environment-derived pull-secret settings for one reconciliation pass.
struct PullSecretSettings {
    /// The tenant image pull secret name CAP generates under the current
    /// configuration.
    configured_name: String,
    /// The configured GHCR pair, when set — the credential proof used to
    /// recognize unlabeled pre-label secrets.
    ghcr_credentials: Option<(String, String)>,
    /// The `.dockerconfigjson` payload the current configuration generates
    /// for the configured-name secret, when a scoped config exists (Codex
    /// review on #243, P1): kept in-scope secrets are refreshed to it after a
    /// credential rotation.
    configured_secret_data: Option<String>,
}

impl PullSecretSettings {
    fn from_env() -> Self {
        Self {
            configured_name: managed_tenant_image_pull_secret_name(),
            ghcr_credentials: ghcr_pull_secret_credentials(),
            configured_secret_data: expected_tenant_image_pull_secret_dockerconfigjson(),
        }
    }

    fn ghcr(&self) -> Option<(&str, &str)> {
        self.ghcr_credentials
            .as_ref()
            .map(|(username, token)| (username.as_str(), token.as_str()))
    }
}

/// How a reconciliation pass deletes the managed secrets it must remove.
#[derive(Clone, Copy, Debug)]
enum PullSecretDeleteMode {
    /// Per-deploy cleanup, inside the deploy's mutation lease: deleted fenced
    /// by the deploy's mutation generation.
    Fenced(MutationGeneration),
    /// Startup sweep and background retry, outside any mutation lease:
    /// deleted on the observed UID/resourceVersion preconditions instead of
    /// the mutation-generation fence. The sweep snapshots the namespace's
    /// kubernetes mutation generation BEFORE reading its app inventory
    /// (review findings on #243, Devin SEC + Codex P1): any discovered secret
    /// carrying a NEWER mutation-generation annotation was applied by a
    /// deploy that postdates the inventory snapshot — a workload entering
    /// scope mid-sweep — and is skipped together with its ServiceAccount
    /// references instead of being erased.
    Unfenced {
        /// The `kubernetes_namespace` lease generation observed before the
        /// sweep's app-inventory query; `0` when the namespace has no lease
        /// row yet (only unannotated legacy secrets can predate it).
        namespace_generation: i64,
    },
}

/// Same-object delete conflicts are retried with the engine's bounded but
/// patient budget (see `enclava_engine::apply::generation`, staging incident
/// 2026-09-13): three immediate attempts terminally failed live cleanup
/// against ordinary concurrent writers (Devin review on #243). Worst-case
/// total wait ≈ 60 s, matching `delete_resource`.
const PULL_SECRET_DELETE_CONFLICT_RETRIES: usize = 64;

/// Exponential backoff between same-object 409 retries, doubling from 25 ms
/// and capped at 800 ms — the engine's `conflict_retry_delay` formula.
fn pull_secret_conflict_retry_delay(attempt: usize) -> std::time::Duration {
    std::time::Duration::from_millis((25 * (1 << attempt.min(5))).min(1000))
}

/// A successful Kubernetes DELETE is only acceptance: a finalizer can keep
/// the Secret present and readable with a deletion timestamp (Codex review
/// on #243, P2). Poll for the 404 that proves the platform PAT is gone.
const PULL_SECRET_DELETION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const PULL_SECRET_DELETION_POLL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Hard bound on ONE namespace's pull-secret reconciliation (Codex review on
/// #243, P1, follow-up "let oversized cleanup sweeps make forward progress"):
/// the reconcile path's Kubernetes calls are not individually time-bounded
/// everywhere, so a stalled API server must degrade to "this namespace not
/// converged, retried with backoff" — never to a cancelled whole sweep whose
/// every retry restarts from the first namespace and deterministically
/// starves the tail (keeping workload admission closed forever on clusters
/// whose healthy traversal exceeds a whole-pass budget).
const PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(180);

/// The mutation generation a live Secret carries, if any (`None` covers both
/// unannotated legacy secrets and unparsable annotation values).
fn secret_mutation_generation(secret: &Secret) -> Option<i64> {
    use enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION;
    secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION))
        .and_then(|raw| raw.parse::<i64>().ok())
}

/// Keep/remove decision for one discovered managed pull secret (review
/// findings on #243). A managed secret stays only while the namespace is
/// within the configured repository scope AND the secret is either the one
/// the current configuration generates or still referenced by one of the
/// namespace's generated ServiceAccounts — a workload deployed under an older
/// `TENANT_IMAGE_PULL_SECRET_NAME` keeps pulling with its old secret until it
/// redeploys. Everything else (every managed secret in an out-of-scope
/// namespace; unreferenced residue such as a renamed old secret) is removed.
fn keep_managed_pull_secret(
    namespace_in_scope: bool,
    secret_name: &str,
    configured_name: &str,
    referenced_names: &BTreeSet<String>,
) -> bool {
    namespace_in_scope && (secret_name == configured_name || referenced_names.contains(secret_name))
}

/// Every CAP-managed tenant pull secret in one namespace, discovered
/// independently of the currently configured name (review finding on #243):
///
/// - every secret labeled `cap.enclava.dev/tenant-image-pull-secret=true`,
///   under any name — so a changed `TENANT_IMAGE_PULL_SECRET_NAME` can never
///   strand an old platform PAT; plus
/// - unlabeled pre-label secrets at the names CAP could have generated them
///   under (the configured name, the historical default name, or a name a
///   generated ServiceAccount still references), recognized by their
///   generated shape through [`is_managed_tenant_image_pull_secret`].
///
/// A tenant-owned secret is never returned: recognition is the label or the
/// exact generated shape with the configured GHCR pair, never the name alone.
/// Also returns every name the given ServiceAccounts reference in
/// `imagePullSecrets` — the keep decision needs it and it seeds the legacy
/// name candidates — and the fetched ServiceAccount objects themselves, whose
/// pending-repair annotations (see
/// [`PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION`]) drive the repair pass
/// in [`reconcile_managed_pull_secrets`].
async fn discover_managed_pull_secrets(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
) -> Result<(Vec<Secret>, BTreeSet<String>, Vec<ServiceAccount>), DeployError> {
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let sa_api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);

    let mut managed: Vec<Secret> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut referenced_names: BTreeSet<String> = BTreeSet::new();
    let mut accounts: Vec<ServiceAccount> = Vec::new();

    // Label-selected list: pull secrets under any name, without reading
    // tenant-owned secret contents. The dedicated label is the selector (and
    // the deletion marker), so no other managed Secret can enter the sweep
    // (review finding).
    let labeled = match api
        .list(&ListParams::default().labels(&format!(
            "{TENANT_PULL_SECRET_LABEL}={TENANT_PULL_SECRET_LABEL_VALUE}"
        )))
        .await
    {
        Ok(labeled) => labeled,
        // A missing namespace has no stale secrets (review finding on #243):
        // an app row can exist before its namespace is created, or outlive the
        // namespace after deletion. Treating the 404 as a sweep failure would
        // keep workload admission closed and the dispatcher unspawned while
        // the very pending work that creates the namespace or removes the row
        // can never run — the sweep must see an already-clean namespace and
        // continue.
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return Ok((Vec::new(), BTreeSet::new(), Vec::new()));
        }
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    for secret in labeled.items {
        if let Some(name) = secret.metadata.name.clone() {
            seen.insert(name);
        }
        managed.push(secret);
    }

    // Legacy (pre-label) secrets carry no label and are recognized by shape at
    // the names CAP could have generated them under.
    let mut legacy_names = vec![
        settings.configured_name.clone(),
        DEFAULT_TENANT_IMAGE_PULL_SECRET_NAME.to_string(),
    ];
    for service_account in service_accounts {
        let account = match sa_api.get(service_account).await {
            Ok(account) => account,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        for reference in account.image_pull_secrets.iter().flatten() {
            referenced_names.insert(reference.name.clone());
            legacy_names.push(reference.name.clone());
        }
        accounts.push(account);
    }
    legacy_names.sort();
    legacy_names.dedup();
    for name in legacy_names {
        if seen.contains(&name) {
            continue;
        }
        match api.get(&name).await {
            Ok(secret) => {
                if is_managed_tenant_image_pull_secret(&secret, settings.ghcr()) {
                    seen.insert(name);
                    managed.push(secret);
                }
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(DeployError::Apply(error.into())),
        }
    }
    Ok((managed, referenced_names, accounts))
}

/// Give a pre-label legacy secret the managed-by ownership label (review
/// finding on #243). Unlabeled secrets are recognized by the configured GHCR
/// pair, which stops proving ownership once the operator rotates the token —
/// labeling the secret while the match still holds makes the ownership proof
/// permanent, so the documented upgrade-then-rotate sequence cannot orphan
/// it. Only kept secrets need this: removed ones are deleted while the match
/// still proves ownership.
async fn adopt_managed_pull_secret(
    engine: &ApplyEngine,
    namespace: &str,
    secret: &Secret,
) -> Result<(), DeployError> {
    let Some(name) = secret.metadata.name.as_deref() else {
        return Ok(());
    };
    let mut labels = std::collections::BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    labels.insert(
        TENANT_PULL_SECRET_LABEL.to_string(),
        TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
    );
    let patch = serde_json::json!({
        "metadata": {
            "name": name,
            "resourceVersion": secret.metadata.resource_version,
            "labels": labels,
        }
    });
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let patch_params = PatchParams::apply(&engine.config().field_manager);
    api.patch(name, &patch_params, &Patch::Merge(&patch))
        .await
        .map_err(|error| DeployError::Apply(error.into()))?;
    tracing::info!(
        %namespace,
        secret = %name,
        "pre-label tenant image pull secret adopted: managed-by ownership label applied"
    );
    Ok(())
}

/// Reconcile a kept managed secret's credential data to the current
/// configuration (Codex review on #243, P1 "refresh kept pull secrets after
/// credential rotation"): when `GHCR_USERNAME`/`GHCR_TOKEN` rotate while a
/// namespace remains in scope, the configured-name secret must carry the new
/// pair — otherwise every pod in the namespace keeps pulling with the old
/// platform PAT until its app happens to redeploy, and image pulls fail
/// outright once the old token is revoked.
///
/// The sweep holds no mutation lease, so instead of the deployment fence the
/// write is fenced by (a) ownership — only secrets already proven CAP-managed
/// (label, or legacy shape matching the current pair) are rewritten, never a
/// tenant look-alike under the managed name; and (b) the live object's
/// `resourceVersion` — a concurrent deploy or writer conflicts instead of
/// being clobbered, and the conflicting pass simply retries on the next
/// sweep. Live annotations (including the mutation-generation marker) and
/// labels are carried forward, and the write is idempotent: it converges the
/// secret to exactly what the current configuration generates. Returns
/// whether the data was rewritten.
async fn refresh_managed_pull_secret_credentials(
    engine: &ApplyEngine,
    namespace: &str,
    secret: &Secret,
    expected_dockerconfigjson: &str,
) -> Result<bool, DeployError> {
    use k8s_openapi::ByteString;

    let Some(name) = secret.metadata.name.as_deref() else {
        return Ok(false);
    };
    if secret.metadata.deletion_timestamp.is_some() || newer_pull_secret_credentials(secret) {
        // Do not let an older replica roll back a newer rollout's credential.
        return Ok(false);
    }
    let current = secret
        .data
        .as_ref()
        .and_then(|data| data.get(".dockerconfigjson"))
        .map(|payload| payload.0.as_slice());
    if current == Some(expected_dockerconfigjson.as_bytes()) {
        return Ok(false);
    }
    let mut labels = secret.metadata.labels.clone().unwrap_or_default();
    labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
    labels.insert(
        TENANT_PULL_SECRET_LABEL.to_string(),
        TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
    );
    let mut annotations = secret.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(
        PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION.to_string(),
        pull_secret_credential_generation().to_string(),
    );
    let patch = serde_json::json!({
        "metadata": {
            "name": name,
            "resourceVersion": secret.metadata.resource_version,
            "labels": labels,
            "annotations": annotations,
        },
        "type": "kubernetes.io/dockerconfigjson",
        "data": {
            ".dockerconfigjson": serde_json::to_value(ByteString(
                expected_dockerconfigjson.as_bytes().to_vec(),
            ))
            .expect("ByteString always serializes to base64"),
        },
    });
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let patch_params = PatchParams::apply(&engine.config().field_manager);
    match api.patch(name, &patch_params, &Patch::Merge(&patch)).await {
        Ok(_) => {
            tracing::info!(
                %namespace,
                secret = %name,
                "tenant image pull secret refreshed: credential data reconciled to the current \
                 GHCR pair (rotation applied without waiting for each app to redeploy)"
            );
            Ok(true)
        }
        Err(kube::Error::Api(error)) if error.code == 404 => Err(DeployError::Validation(format!(
            "desired tenant pull secret {namespace}/{name} disappeared during refresh"
        ))),
        Err(error) => Err(DeployError::Apply(error.into())),
    }
}

/// Reconcile the managed tenant pull secrets of one namespace to the set CAP
/// should hold there (review findings on #243): discovery is name-independent
/// (labeled secrets plus shape-recognized legacy secrets), kept secrets are
/// adopted and left in place, and every other managed secret is removed
/// together with its ServiceAccount references. Returns whether every write
/// converged; the caller must treat `false` as "stale platform credentials may
/// still be out there".
async fn reconcile_managed_pull_secrets(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
    namespace_in_scope: bool,
    delete_mode: PullSecretDeleteMode,
) -> Result<bool, DeployError> {
    let (managed, referenced_names, accounts) =
        discover_managed_pull_secrets(engine, namespace, service_accounts, settings).await?;
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let mut converged = true;
    let mut removed = 0usize;
    let mut kept = 0usize;
    // Durable repair pass (Codex review on #243, P2 "persist failed pull-
    // secret reference restorations" + reviewer follow-up): a ServiceAccount
    // carrying the pending-repairs annotation records a reference an earlier
    // pass cleared but never proven restored or removed, together with the
    // UID of the object that was cleared. Per name:
    //
    // - no object behind the name → the removal completed → discharge;
    // - same UID still lives there → the earlier VERIFIED delete never
    //   finished → complete it now (UID-proven ownership survives a GHCR
    //   rotation, which would otherwise make an unlabeled old-PAT secret
    //   invisible to discovery — re-attaching it would re-open the exact
    //   exposure the sweep exists to close);
    // - a different UID lives there → a replacement → restore the reference
    //   (the earlier clear was the mistake) and discharge.
    //
    // Sweep contexts only (Unfenced): the per-deploy path's own SSA of the
    // generated ServiceAccount is the authoritative newest decision about
    // its `imagePullSecrets` — restoring ahead of it would be pruned and the
    // record discharged — so the deploy path discharges stale intents AFTER
    // its applies instead (see `apply_all_with_tenant_image_pull_secret`).
    if let PullSecretDeleteMode::Unfenced { .. } = delete_mode {
        for account in &accounts {
            let pending = pending_reference_repairs(account);
            if pending.is_empty() {
                continue;
            }
            let Some(account_name) = account.metadata.name.as_deref() else {
                continue;
            };
            for repair in pending {
                let secret_name = repair.secret_name.clone();
                let live_result = api.get(&secret_name).await;
                let live_uid = match &live_result {
                    Ok(live) => live.metadata.uid.clone(),
                    Err(_) => None,
                };
                let cleared_uid_matches = repair
                    .cleared_uid
                    .as_deref()
                    .is_some_and(|uid| live_uid.as_deref() == Some(uid));
                match live_result {
                    Ok(live) => {
                        if namespace_in_scope && secret_name == settings.configured_name {
                            if live.metadata.deletion_timestamp.is_some() {
                                // An accepted old delete may still finish. Keep
                                // the intent until 404, then recreate first.
                                converged = false;
                                continue;
                            }
                            // Scope may have expanded since the removal intent was
                            // recorded. The desired secret wins over stale cleanup.
                            if let Err(error) = restore_pull_secret_reference_to_service_account(
                                engine,
                                namespace,
                                account_name,
                                &secret_name,
                            )
                            .await
                            {
                                converged = false;
                                tracing::warn!(%namespace, %error, "failed to restore newly in-scope pull secret reference");
                            }
                            continue;
                        }
                        if cleared_uid_matches
                            && let Some(cleared_uid) = repair.cleared_uid.as_deref()
                        {
                            // The verified removal never finished: complete
                            // it, pinned to the recorded UID.
                            match delete_managed_pull_secret(
                                engine,
                                namespace,
                                &secret_name,
                                settings.ghcr(),
                                Some(cleared_uid),
                                delete_mode,
                            )
                            .await
                            {
                                Ok(
                                    PullSecretRemovalOutcome::Deleted
                                    | PullSecretRemovalOutcome::Missing,
                                ) => {
                                    if let Err(error) = forget_pending_reference_repair(
                                        engine,
                                        namespace,
                                        account_name,
                                        &secret_name,
                                    )
                                    .await
                                    {
                                        converged = false;
                                        tracing::warn!(
                                            %namespace,
                                            service_account = %account_name,
                                            secret = %secret_name,
                                            %error,
                                            "tenant image pull secret reconcile: failed to \
                                             discharge a completed pending removal"
                                        );
                                    }
                                }
                                Ok(PullSecretRemovalOutcome::NotOurs)
                                | Ok(PullSecretRemovalOutcome::Superseded) => {
                                    // A different object (or a newer deploy's
                                    // rewrite) won the name: restore the
                                    // reference it inherits by name.
                                    if let Err(error) =
                                        restore_pull_secret_reference_to_service_account(
                                            engine,
                                            namespace,
                                            account_name,
                                            &secret_name,
                                        )
                                        .await
                                    {
                                        converged = false;
                                        tracing::warn!(
                                            %namespace,
                                            service_account = %account_name,
                                            secret = %secret_name,
                                            %error,
                                            "tenant image pull secret reconcile: failed to \
                                             restore a reference whose pending removal was \
                                             superseded — durable repair intent retained"
                                        );
                                    }
                                }
                                Err(error) => {
                                    converged = false;
                                    tracing::warn!(
                                        %namespace,
                                        service_account = %account_name,
                                        secret = %secret_name,
                                        %error,
                                        "tenant image pull secret reconcile: failed to \
                                         complete a pending verified removal — intent \
                                         retained, the reference stays cleared"
                                    );
                                }
                            }
                        } else {
                            // A replacement (or a UID-less legacy record)
                            // lives under the name: the earlier clear was the
                            // mistake — restore the reference. `live` is only
                            // needed for the UID comparison above.
                            let _ = live;
                            if let Err(error) = restore_pull_secret_reference_to_service_account(
                                engine,
                                namespace,
                                account_name,
                                &secret_name,
                            )
                            .await
                            {
                                converged = false;
                                tracing::warn!(
                                    %namespace,
                                    service_account = %account_name,
                                    secret = %secret_name,
                                    %error,
                                    "tenant image pull secret reconcile: failed to restore a \
                                     reference left cleared by an earlier pass — durable \
                                     repair intent retained"
                                );
                            }
                        }
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => {
                        if namespace_in_scope && secret_name == settings.configured_name {
                            // A previous delete finished after scope expanded. Recreate
                            // before reattaching; never declare a missing desired
                            // credential converged merely because refresh saw 404.
                            if let Some(config) = tenant_image_pull_secret_config_from_env() {
                                let desired = generate_tenant_image_pull_secret(namespace, &config);
                                match api
                                    .create(&kube::api::PostParams::default(), &desired)
                                    .await
                                {
                                    Ok(_) => {
                                        if let Err(error) =
                                            restore_pull_secret_reference_to_service_account(
                                                engine,
                                                namespace,
                                                account_name,
                                                &secret_name,
                                            )
                                            .await
                                        {
                                            converged = false;
                                            tracing::warn!(%namespace, %error, "failed to restore desired pull secret reference");
                                        }
                                    }
                                    Err(error) => {
                                        converged = false;
                                        tracing::warn!(%namespace, %error, "failed to recreate newly in-scope pull secret");
                                    }
                                }
                            } else {
                                converged = false;
                            }
                            continue;
                        }
                        // No object behind the name: the removal completed, so
                        // the intent is discharged.
                        if let Err(error) = forget_pending_reference_repair(
                            engine,
                            namespace,
                            account_name,
                            &secret_name,
                        )
                        .await
                        {
                            converged = false;
                            tracing::warn!(
                                %namespace,
                                service_account = %account_name,
                                secret = %secret_name,
                                %error,
                                "tenant image pull secret reconcile: failed to discharge a \
                                 completed pull-secret repair intent"
                            );
                        }
                    }
                    Err(error) => {
                        converged = false;
                        tracing::warn!(
                            %namespace,
                            service_account = %account_name,
                            secret = %secret_name,
                            %error,
                            "tenant image pull secret reconcile: failed to re-read a secret \
                             named by a pending reference repair"
                        );
                    }
                }
            }
        }
    }
    for secret in &managed {
        let Some(name) = secret.metadata.name.as_deref() else {
            continue;
        };
        if keep_managed_pull_secret(
            namespace_in_scope,
            name,
            &settings.configured_name,
            &referenced_names,
        ) {
            kept += 1;
            if !is_labeled_managed_pull_secret(secret)
                && let Err(error) = adopt_managed_pull_secret(engine, namespace, secret).await
            {
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    %error,
                    "failed to label a kept legacy tenant image pull secret; a later GHCR \
                     token rotation could no longer prove its ownership — will retry"
                );
            }
            // Codex review on #243 (P1 "refresh kept pull secrets after
            // credential rotation"): the kept configured-name secret is
            // reconciled to the CURRENT credential data, so a rotated
            // GHCR_USERNAME/GHCR_TOKEN reaches this namespace without waiting
            // for its app to redeploy. Ownership is re-proven on the live
            // object — a tenant look-alike under the managed name (unlabeled,
            // foreign credentials) is never rewritten.
            if namespace_in_scope
                && name == settings.configured_name
                && let Some(expected) = settings.configured_secret_data.as_deref()
                && (is_labeled_managed_pull_secret(secret)
                    || is_managed_tenant_image_pull_secret(secret, settings.ghcr()))
                && let Err(error) =
                    refresh_managed_pull_secret_credentials(engine, namespace, secret, expected)
                        .await
            {
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    %error,
                    "tenant image pull secret reconcile: failed to refresh the kept secret to \
                     the current GHCR credentials — will retry"
                );
            }
            continue;
        }
        removed += 1;
        // Re-check ownership on the LIVE object right before the writes
        // (review finding on #243): the discovery pass may be stale, and a
        // tenant who replaced the secret in the meantime must keep both the
        // secret and its ServiceAccount references.
        let live = match api.get(name).await {
            Ok(live) => live,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    %error,
                    "tenant image pull secret reconcile: failed to re-read the secret before \
                     cleanup"
                );
                continue;
            }
        };
        if !is_managed_tenant_image_pull_secret(&live, settings.ghcr()) {
            tracing::warn!(
                %namespace,
                secret = %name,
                "tenant image pull secret reconcile: skipped — the secret is no longer \
                 CAP-managed (replaced after discovery); keeping it and its references"
            );
            continue;
        }
        // Sweep runs must never erase a secret a NEWER deploy applied (Devin
        // SEC + Codex P1 review findings on #243): the sweep's app inventory
        // is a DB snapshot taken BEFORE this generation was observed, so a
        // secret carrying a newer mutation-generation annotation was applied
        // by a deploy the snapshot never saw — typically a workload entering
        // the repository scope mid-sweep. Skip it and its references; the
        // next sweep (whose snapshot includes that deploy) decides. Checked
        // on the live object so an annotation that landed after discovery is
        // honored too.
        if let PullSecretDeleteMode::Unfenced {
            namespace_generation,
        } = delete_mode
            && secret_mutation_generation(&live).is_some_and(|actual| actual > namespace_generation)
        {
            kept += 1;
            tracing::info!(
                %namespace,
                secret = %name,
                "tenant image pull secret reconcile: skipped — a mutation generation newer \
                 than the sweep's inventory snapshot wrote it (concurrent deploy); leaving it \
                 and its ServiceAccount references for the next sweep"
            );
            continue;
        }
        // Only proven CAP-managed names are ever cleared from
        // ServiceAccounts (review finding): a tenant-owned secret under the
        // same name keeps both itself and its references.
        let mut cleared_references: Vec<String> = Vec::new();
        // Defer the delete while any reference clear failed (Codex review on
        // #243, P2 "defer secret deletion when reference cleanup fails"):
        // deleting the Secret after a failed ServiceAccount patch strands a
        // dangling imagePullSecrets reference the next sweep can no longer
        // discover (its discovery marker — the Secret — is gone), so it
        // would report convergence without ever retrying the cleanup. Keep
        // the secret for now; a later pass retries the reference clear and
        // the delete together.
        let mut reference_cleanup_failed = false;
        for service_account in service_accounts {
            match clear_pull_secret_reference_from_service_account(
                engine,
                namespace,
                service_account,
                name,
                // Record the verified object's UID with the durable repair
                // intent: it is what lets a later pass tell an unfinished
                // removal apart from a replacement (reviewer finding on #243).
                live.metadata.uid.as_deref(),
            )
            .await
            {
                Ok(true) => cleared_references.push(service_account.clone()),
                Ok(false) => {}
                Err(error) => {
                    converged = false;
                    reference_cleanup_failed = true;
                    tracing::warn!(
                        %namespace,
                        service_account = %service_account,
                        secret = %name,
                        %error,
                        "tenant image pull secret reconcile: failed to clear stale \
                         ServiceAccount reference — deferring the secret delete so the \
                         reference cleanup can be retried on a later pass"
                    );
                }
            }
        }
        if reference_cleanup_failed {
            // Nothing was deleted, so nothing must be reversed: the secret
            // keeps its name, and the references that WERE cleared are
            // restored so the (still-present) secret stays attached.
            for service_account in &cleared_references {
                if let Err(error) = restore_pull_secret_reference_to_service_account(
                    engine,
                    namespace,
                    service_account,
                    name,
                )
                .await
                {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        service_account = %service_account,
                        secret = %name,
                        %error,
                        "tenant image pull secret reconcile: failed to restore the \
                         ServiceAccount reference after a deferred delete"
                    );
                }
            }
            continue;
        }
        // The delete is the final ownership decision (review finding on
        // #243): it re-reads the live secret, re-verifies CAP ownership, and
        // deletes exactly the object that verification saw. The reference
        // clears above were made from the earlier read, so whenever the
        // delete does NOT remove that verified managed secret — the tenant
        // replaced it mid-cleanup and the delete preserves the replacement —
        // the clears are reversed: a replacement detected at deletion keeps
        // its ServiceAccount references and its pods keep registry access.
        let removal =
            delete_managed_pull_secret(engine, namespace, name, settings.ghcr(), None, delete_mode)
                .await;
        let reverse_reference_clears = match &removal {
            Ok(PullSecretRemovalOutcome::Deleted | PullSecretRemovalOutcome::Missing) => false,
            Ok(PullSecretRemovalOutcome::Superseded) => {
                tracing::info!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: a concurrent deploy rewrote the secret \
                     mid-cleanup (newer mutation generation) — keeping it and restoring its \
                     ServiceAccount references; the next sweep decides"
                );
                true
            }
            Ok(PullSecretRemovalOutcome::NotOurs) => {
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: the secret was replaced while it was \
                     being cleaned up — keeping the replacement and restoring its ServiceAccount \
                     references"
                );
                true
            }
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    %error,
                    "tenant image pull secret reconcile: delete outcome unknown; leaving references \
                     cleared and repair intent durable until a follow-up read resolves it"
                );
                false
            }
        };
        if reverse_reference_clears {
            for service_account in &cleared_references {
                match restore_pull_secret_reference_to_service_account(
                    engine,
                    namespace,
                    service_account,
                    name,
                )
                .await
                {
                    Ok(()) => {}
                    Err(error) => {
                        converged = false;
                        tracing::warn!(
                            %namespace,
                            service_account = %service_account,
                            secret = %name,
                            %error,
                            "tenant image pull secret reconcile: failed to restore the \
                             ServiceAccount reference after a mid-cleanup replacement"
                        );
                    }
                }
            }
        } else if matches!(
            removal,
            Ok(PullSecretRemovalOutcome::Deleted | PullSecretRemovalOutcome::Missing)
        ) {
            // The verified managed secret is provably gone (`Deleted` /
            // `Missing`): the cleared references are final, so their durable
            // repair intent is discharged (Codex review on #243, P2). A
            // transient failure here self-heals — the repair pass forgets
            // names with no object behind them — but still marks this pass
            // unconverged.
            for service_account in &cleared_references {
                if let Err(error) =
                    forget_pending_reference_repair(engine, namespace, service_account, name).await
                {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        service_account = %service_account,
                        secret = %name,
                        %error,
                        "tenant image pull secret reconcile: failed to discharge the repair \
                         intent of a completed removal"
                    );
                }
            }
        }
    }
    tracing::info!(
        %namespace,
        removed,
        kept,
        converged,
        "tenant image pull secret reconcile complete"
    );
    Ok(converged)
}

/// Whether the secret carries the dedicated pull-secret label (the ownership
/// proof that survives GHCR token rotation and the cleanup's discovery
/// marker).
fn is_labeled_managed_pull_secret(secret: &Secret) -> bool {
    secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(TENANT_PULL_SECRET_LABEL))
        .is_some_and(|value| value == TENANT_PULL_SECRET_LABEL_VALUE)
}

/// What happened to the managed pull secret one cleanup removal attempted.
/// This is the final ownership decision of a removal (review finding on
/// #243): only [`PullSecretRemovalOutcome::Deleted`] and
/// [`PullSecretRemovalOutcome::Missing`] mean the name no longer holds a
/// tenant-replaceable secret, so only those two may leave the
/// ServiceAccount reference cleared.
#[derive(Debug)]
enum PullSecretRemovalOutcome {
    /// The verified managed secret was deleted.
    Deleted,
    /// No secret lives under the name.
    Missing,
    /// A secret exists (or appeared) under the name but the live object fails
    /// the CAP-ownership check — a tenant replacement. It is preserved
    /// together with its ServiceAccount references. A same-object update that
    /// merely moved `resourceVersion` is NOT this outcome: it is retried and,
    /// if it never settles, reported as an error so the caller stays closed.
    NotOurs,
    /// The live object still passes the ownership check, but carries a
    /// mutation generation NEWER than the sweep's pre-inventory snapshot
    /// (self-check on #243): a concurrent deploy rewrote the secret after the
    /// reconcile-time check. Treated exactly like `NotOurs` — the secret is
    /// kept and the already-cleared ServiceAccount references are restored —
    /// but with distinct telemetry so the race is visible in logs.
    Superseded,
}

/// Delete one proven managed pull secret, fenced by the deploy's mutation
/// generation (per-deploy cleanup) or by the observed UID/resourceVersion
/// alone (startup sweep and background retry — see [`PullSecretDeleteMode`]).
///
/// This is the final ownership decision of the cleanup (review finding on
/// #243): it re-reads the live secret, re-verifies CAP ownership right before
/// deleting, and pins the delete to exactly the object that verification saw
/// — a secret replaced after that check must conflict and survive, never be
/// deleted. Callers coordinate their ServiceAccount reference cleanup with
/// the returned outcome: references are only left cleared when the verified
/// managed secret is provably gone ([`PullSecretRemovalOutcome::Deleted`] /
/// [`PullSecretRemovalOutcome::Missing`]).
async fn delete_managed_pull_secret(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    ghcr_credentials: Option<(&str, &str)>,
    verified_uid: Option<&str>,
    delete_mode: PullSecretDeleteMode,
) -> Result<PullSecretRemovalOutcome, DeployError> {
    use enclava_engine::apply::engine::ApplyError;
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    // Kubernetes reports 409 both for a replaced object (different UID) and
    // for the SAME managed object merely updated (resourceVersion moved)
    // (review finding on #243). Only a real replacement is "not ours": a
    // same-object update is still the managed secret, and reporting it as a
    // clean removal would let the sweep converge while the platform PAT stays
    // in the namespace. Every attempt re-reads and re-verifies the live
    // object; a bounded, patient retry with backoff absorbs transient writers
    // (Devin review on #243: three immediate attempts terminally failed
    // deploys against ordinary concurrent writers), and once exhausted the
    // error keeps the caller's gate closed.
    for attempt in 0..PULL_SECRET_DELETE_CONFLICT_RETRIES {
        let existing = match api.get(name).await {
            Ok(existing) => existing,
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Ok(PullSecretRemovalOutcome::Missing);
            }
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        // Ownership is proven by the label / legacy credential shape, OR —
        // for the pending-repair completion path — by the UID recorded when
        // an earlier pass already verified and cleared this exact object
        // (reviewer finding on #243): after a GHCR rotation the unlabeled
        // secret's credentials no longer match, but the recorded UID still
        // proves this is the object whose verified removal must complete.
        let uid_verified =
            verified_uid.is_some_and(|uid| existing.meta().uid.as_deref() == Some(uid));
        if !uid_verified && !is_managed_tenant_image_pull_secret(&existing, ghcr_credentials) {
            tracing::warn!(
                namespace = %namespace,
                secret = %name,
                "tenant image pull secret cleanup skipped: secret exists but is not CAP-managed"
            );
            return Ok(PullSecretRemovalOutcome::NotOurs);
        }
        if let PullSecretDeleteMode::Fenced(generation) = delete_mode {
            // The same generation fence `delete_resource` applies — but checked
            // against the object this cleanup verified, not against a fresh read
            // that could already be a replacement.
            ensure_pull_secret_generation_not_stale(&existing, generation, name)?;
        }
        if let PullSecretDeleteMode::Unfenced {
            namespace_generation,
        } = delete_mode
            && secret_mutation_generation(&existing)
                .is_some_and(|actual| actual > namespace_generation)
        {
            // Self-check on #243: the reconcile-time skip can race a deploy
            // that claims the namespace lease and rewrites the secret after
            // it — including the rewrite that caused a 409 on a previous
            // attempt of this very loop. The re-read object passes the
            // ownership check but belongs to a deploy the sweep's inventory
            // never saw, so it must be kept, exactly like the reconcile-time
            // skip above.
            tracing::info!(
                namespace = %namespace,
                secret = %name,
                "tenant image pull secret delete skipped: a mutation generation newer \
                 than the sweep's inventory snapshot rewrote it mid-cleanup (concurrent deploy)"
            );
            return Ok(PullSecretRemovalOutcome::Superseded);
        }
        // Pin the delete to the verified object's identity: a replacement that
        // lands after the ownership check conflicts (409) instead of being
        // deleted in the managed secret's place.
        let delete_params = DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: existing.meta().uid.clone(),
                resource_version: existing.meta().resource_version.clone(),
            }),
            ..Default::default()
        };
        match enclava_engine::apply::bounded_kube_write(api.delete(name, &delete_params)).await {
            Ok(_) => {
                // Acceptance is not removal (Codex review on #243, P2): a
                // finalizer can keep the Secret present and readable with a
                // deletionTimestamp while the platform PAT is still exposed.
                // Poll for the 404 that proves the object is gone — like the
                // namespace deletion path — and only then report Deleted.
                return wait_for_secret_removal(&api, namespace, name).await;
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 404 => {
                return Ok(PullSecretRemovalOutcome::Missing);
            }
            Err(ApplyError::Kube(kube::Error::Api(error))) if error.code == 409 => {
                // The next attempt's read decides (review finding on #243):
                // an unmanaged live object is a replacement and is kept
                // (NotOurs), a still-managed one is the same secret updated
                // mid-cleanup and is retried, and an exhausted retry errors so
                // the caller stays closed instead of claiming a clean sweep.
                tracing::warn!(
                    namespace = %namespace,
                    secret = %name,
                    attempt,
                    "tenant image pull secret delete conflicted; backing off before re-reading"
                );
                tokio::time::sleep(pull_secret_conflict_retry_delay(attempt)).await;
                continue;
            }
            Err(error) => return Err(DeployError::Apply(error)),
        }
    }
    Err(DeployError::PullSecretDeleteConflict(format!(
        "{namespace}/{name}"
    )))
}

/// Wait until an accepted Secret delete has actually removed the object
/// (Codex review on #243, P2): with a finalizer the Secret lingers, still
/// readable, with a deletionTimestamp — reporting `Deleted` then would let
/// the sweep converge and open workload admission while the platform PAT is
/// exposed. Bounded poll; a still-present object at the deadline is an error
/// so the caller stays unconverged and retries.
async fn wait_for_secret_removal(
    api: &Api<Secret>,
    namespace: &str,
    name: &str,
) -> Result<PullSecretRemovalOutcome, DeployError> {
    let deadline = tokio::time::Instant::now() + PULL_SECRET_DELETION_POLL_DEADLINE;
    loop {
        match api.get(name).await {
            Err(kube::Error::Api(error)) if error.code == 404 => {
                return Ok(PullSecretRemovalOutcome::Deleted);
            }
            Err(error) => return Err(DeployError::Apply(error.into())),
            Ok(secret) => {
                let terminating = secret.metadata.deletion_timestamp.is_some();
                if tokio::time::Instant::now() >= deadline {
                    tracing::warn!(
                        namespace = %namespace,
                        secret = %name,
                        terminating,
                        "tenant image pull secret still present after the accepted delete \
                         (finalizer?); reporting non-convergence so the sweep stays closed"
                    );
                    return Err(DeployError::PullSecretDeleteConflict(format!(
                        "{namespace}/{name}"
                    )));
                }
                tracing::debug!(
                    namespace = %namespace,
                    secret = %name,
                    terminating,
                    "waiting for the accepted tenant image pull secret delete to converge"
                );
            }
        }
        tokio::time::sleep(PULL_SECRET_DELETION_POLL_INTERVAL).await;
    }
}

/// The mutation-generation fence [`enclava_engine::apply::generation::delete_resource`]
/// applies before deleting, checked against the object this cleanup already
/// verified as CAP-managed: a secret written by a NEWER mutation generation
/// belongs to a newer deploy of the app and must never be deleted by this
/// (stale) pass.
fn ensure_pull_secret_generation_not_stale(
    secret: &Secret,
    desired: MutationGeneration,
    name: &str,
) -> Result<(), DeployError> {
    use enclava_engine::apply::engine::ApplyError;
    use enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION;

    let raw = secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(MUTATION_GENERATION_ANNOTATION));
    let actual = match raw {
        None => 0,
        Some(raw) => raw
            .parse::<i64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                DeployError::Apply(ApplyError::InvalidLiveMutationGeneration {
                    kind: "Secret".to_string(),
                    name: name.to_string(),
                })
            })?,
    };
    if actual > desired.get() {
        return Err(DeployError::Apply(ApplyError::StaleMutationGeneration {
            kind: "Secret".to_string(),
            name: name.to_string(),
            desired: desired.get(),
            actual,
        }));
    }
    Ok(())
}

/// One sweep attempt for stale tenant image pull secrets (review findings on
/// #243): scope changes (narrowing `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES`,
/// changing `TENANT_IMAGE_PULL_SECRET_NAME`, removing GHCR credentials)
/// previously left platform tokens in namespaces whose workloads fell out of
/// scope until each app happened to redeploy — and only under the single
/// currently configured secret name. Sweep the known app namespaces and
/// reconcile each one's managed pull secrets (any name) through
/// [`sweep_namespace_with_budget`]. Returns whether the sweep converged; on
/// failure the caller must keep workload admission closed (review finding):
/// the dispatcher would re-apply workloads and re-attach secrets while a
/// stale platform token is still exposed. The per-deploy cleanup in
/// [`apply_all_with_tenant_image_pull_secret`] remains the hard gate.
pub async fn cleanup_stale_tenant_image_pull_secrets_at_startup(pool: &PgPool) -> bool {
    // No whole-sweep timeout (Codex review on #243, P1 follow-up): every
    // namespace's reconciliation is individually bounded by
    // `sweep_namespace_with_budget`, so the sweep always terminates — a
    // stalled API server can no longer hang the pre-listen startup (or the
    // background reconciler) forever — while a whole-pass budget would cancel
    // the sweep at an arbitrary namespace and make every retry restart from
    // the first one, deterministically starving the tail namespaces on
    // clusters whose healthy traversal exceeds the budget.
    match cleanup_stale_tenant_image_pull_secrets(pool).await {
        Ok(true) => true,
        Ok(false) => {
            tracing::error!(
                "tenant image pull secret cleanup did not converge: stale secrets may remain \
                 and workload admission stays closed until a clean sweep converges"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                %error,
                "tenant image pull secret cleanup failed; stale secrets may remain and \
                 workload admission stays closed until a clean sweep converges"
            );
            false
        }
    }
}

/// Bound ONE namespace's reconciliation instead of the whole sweep (Codex
/// review on #243, P1 follow-up "let oversized cleanup sweeps make forward
/// progress"): a whole-pass timeout cancels the sweep at an arbitrary
/// namespace and every retry rebuilds the inventory and starts again from the
/// first one, so on clusters whose healthy traversal exceeds the budget the
/// tail namespaces are never checked and workload admission can stay closed
/// forever. The per-namespace budget keeps forward progress — every namespace
/// is visited on every attempt, and a stalled namespace only fails itself —
/// while a stalled Kubernetes API server still degrades to "not converged,
/// retried with bounded backoff" instead of hanging anything forever.
async fn sweep_namespace_with_budget(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
    namespace_in_scope: bool,
    delete_mode: PullSecretDeleteMode,
) -> Result<bool, DeployError> {
    match tokio::time::timeout(
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
        reconcile_managed_pull_secrets(
            engine,
            namespace,
            service_accounts,
            settings,
            namespace_in_scope,
            delete_mode,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::error!(
                %namespace,
                budget_secs = PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT.as_secs(),
                "tenant image pull secret cleanup sweep: reconciling this namespace exceeded \
                 its budget (stalled Kubernetes API?); treating it as not converged and \
                 continuing with the remaining namespaces"
            );
            Ok(false)
        }
    }
}

/// Per-namespace janitor inventory: per-app image lists (`None` in an app
/// slot means one of its stored image refs is unparsable, which never
/// qualifies for the secret) plus the generated ServiceAccount names whose
/// live `imagePullSecrets` references the keep decision protects.
type NamespacePullSecretInventory =
    std::collections::BTreeMap<String, (Vec<Option<Vec<ImageRef>>>, Vec<String>)>;

async fn cleanup_stale_tenant_image_pull_secrets(pool: &PgPool) -> Result<bool, DeployError> {
    let settings = PullSecretSettings::from_env();
    let config = tenant_image_pull_secret_config_from_env();

    // Snapshot the namespaces' kubernetes mutation generations BEFORE the
    // app-inventory read (Devin SEC + Codex P1 review findings on #243): the
    // inventory is a DB snapshot, and a deploy that enters scope after it was
    // taken applies a pull secret the snapshot classifies as out of scope.
    // Any secret annotated with a generation NEWER than this snapshot is
    // skipped by the reconcile pass, so the sweep can never erase a fresh
    // deploy's credentials; the next sweep (snapshot taken after that deploy)
    // decides. Read once for all namespaces — one extra query per sweep.
    // Bound both inventory queries together, separately from per-namespace
    // reconciliation. A stalled DB must not block startup indefinitely.
    let inventory = async {
        let leases: Vec<(String, i64)> = sqlx::query_as(
            "SELECT resource_key, generation FROM external_resource_mutation_leases \
             WHERE resource_scope = 'kubernetes_namespace'",
        )
        .fetch_all(pool)
        .await?;
        let rows: Vec<(Uuid, String, String, Option<String>)> = sqlx::query_as(
            "SELECT apps.id, apps.namespace, apps.service_account, \
                    app_containers.image_ref \
               FROM apps \
               LEFT JOIN app_containers ON app_containers.app_id = apps.id",
        )
        .fetch_all(pool)
        .await?;
        Ok::<_, sqlx::Error>((leases, rows))
    };
    let (lease_rows, rows) = match tokio::time::timeout(
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
        inventory,
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            tracing::error!(
                "tenant image pull secret inventory timed out; workload admission remains closed"
            );
            return Ok(false);
        }
    };
    let lease_rows: std::collections::BTreeMap<String, i64> = lease_rows.into_iter().collect();

    // LEFT JOIN: an app with no container rows must still be inventoried
    // (as an app with no images), or its namespace is invisible to the sweep
    // and a stale secret can survive there (review finding).
    // Per app: namespace, service account, and its images (None = a stored
    // image ref failed to parse, so the app cannot qualify for the secret).
    let mut apps: std::collections::BTreeMap<Uuid, (String, String, Option<Vec<ImageRef>>)> =
        std::collections::BTreeMap::new();
    for (app_id, namespace, service_account, image_ref) in rows {
        let entry = apps
            .entry(app_id)
            .or_insert_with(|| (namespace.clone(), service_account.clone(), Some(Vec::new())));
        let Some(images) = entry.2.as_mut() else {
            continue;
        };
        // NULL image_ref = the app has no container rows; it contributes no
        // images and therefore never qualifies for the secret.
        let Some(image_ref) = image_ref else {
            continue;
        };
        match ImageRef::parse(&image_ref) {
            Ok(image) => images.push(image),
            Err(error) => {
                tracing::warn!(
                    %namespace,
                    %image_ref,
                    %error,
                    "tenant image pull secret cleanup sweep: unparsable stored image; treating the app as out of scope"
                );
                entry.2 = None;
            }
        }
    }

    let mut by_namespace: NamespacePullSecretInventory = Default::default();
    for (_app_id, (namespace, service_account, images)) in apps {
        let entry = by_namespace.entry(namespace).or_default();
        entry.0.push(images);
        entry.1.push(service_account);
    }

    let engine = ApplyEngine::try_default().await?;
    // A failed write leaves the platform token exposed in the namespace — the
    // sweep must report that as not-converged, not "sweep complete" (review
    // finding): the caller keeps workload admission closed on it and retries.
    let mut converged = true;
    for (namespace, (app_images, service_accounts)) in &by_namespace {
        // In-scope namespaces are reconciled too (review finding): pre-label
        // secrets there must be adopted (labeled) before the keep decision
        // applies, and unreferenced residue (e.g. a renamed old secret) must
        // not survive.
        let namespace_in_scope =
            namespace_keeps_tenant_image_pull_secret(config.as_ref(), app_images);
        match sweep_namespace_with_budget(
            &engine,
            namespace,
            service_accounts,
            &settings,
            namespace_in_scope,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: lease_rows.get(namespace).copied().unwrap_or(0),
            },
        )
        .await
        {
            Ok(converged_namespace) => converged &= converged_namespace,
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    %error,
                    "tenant image pull secret cleanup sweep: reconciliation failed"
                );
            }
        }
    }
    tracing::info!(converged, "tenant image pull secret cleanup sweep complete");
    Ok(converged)
}

/// One durable repair-intent entry (see
/// [`PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION`]): the pull-secret
/// name whose `imagePullSecrets` reference was cleared, plus the UID of the
/// verified object at clear time. The UID distinguishes "the delete never
/// finished — complete it" (same UID) from "a replacement lives under the
/// name — restore the reference" (different UID); without it, a credential
/// rotation makes the still-present old-PAT secret invisible to discovery and
/// the repair pass would re-attach it and converge (reviewer finding on
/// #243).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingReferenceRepair {
    secret_name: String,
    cleared_uid: Option<String>,
}

/// The pull-secret repair intents a ServiceAccount's pending-repairs
/// annotation records. Entries are `name` or `name=uid`, comma-separated.
fn pending_reference_repairs(account: &ServiceAccount) -> Vec<PendingReferenceRepair> {
    account
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION))
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| match entry.split_once('=') {
                    Some((name, uid)) => PendingReferenceRepair {
                        secret_name: name.to_string(),
                        cleared_uid: Some(uid.to_string()),
                    },
                    None => PendingReferenceRepair {
                        secret_name: entry.to_string(),
                        cleared_uid: None,
                    },
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Render repair intents back into the annotation value (`name=uid` entries,
/// comma-separated).
fn render_pending_reference_repairs(entries: &[PendingReferenceRepair]) -> String {
    entries
        .iter()
        .map(|entry| match &entry.cleared_uid {
            Some(uid) => format!("{}={}", entry.secret_name, uid),
            None => entry.secret_name.clone(),
        })
        .collect::<Vec<String>>()
        .join(",")
}

/// Drop `secret_name` from a ServiceAccount's `imagePullSecrets`, keeping any
/// other references. No-op when the ServiceAccount is gone or does not
/// reference the secret. The patch is attributed to the engine field manager
/// and pinned to the observed resourceVersion so a concurrent write wins.
/// Returns whether a reference was actually removed — the caller needs it to
/// reverse the clear when the delete later detects a mid-cleanup replacement
/// (review finding on #243).
///
/// The same patch also records the cleared name — and the verified object's
/// UID — in the ServiceAccount's pending-repairs annotation (Codex review on
/// #243, P2): the clear and the durable repair intent land atomically, so
/// even a process death or a per-namespace budget timeout between this clear
/// and the delete/restore leaves the next pass a record to repair from. The
/// UID lets that pass tell "the delete never finished" (same UID: complete
/// the removal — never re-attach the old platform PAT) apart from "a
/// replacement lives under the name" (different UID: restore).
async fn clear_pull_secret_reference_from_service_account(
    engine: &ApplyEngine,
    namespace: &str,
    service_account: &str,
    secret_name: &str,
    cleared_uid: Option<&str>,
) -> Result<bool, DeployError> {
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::{Patch, PatchParams};

    let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
    let existing = match api.get(service_account).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(false),
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    let Some(references) = existing.image_pull_secrets.as_ref() else {
        return Ok(false);
    };
    if !references.iter().any(|r| r.name == secret_name) {
        return Ok(false);
    }
    let kept: Vec<serde_json::Value> = references
        .iter()
        .filter(|r| r.name != secret_name)
        .map(|r| serde_json::json!({ "name": r.name }))
        .collect();
    let image_pull_secrets = if kept.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Array(kept)
    };
    let mut pending = pending_reference_repairs(&existing);
    if !pending.iter().any(|entry| entry.secret_name == secret_name) {
        pending.push(PendingReferenceRepair {
            secret_name: secret_name.to_string(),
            cleared_uid: cleared_uid.map(str::to_string),
        });
    }
    let mut annotations = existing.metadata.annotations.clone().unwrap_or_default();
    annotations.insert(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        render_pending_reference_repairs(&pending),
    );
    let patch = serde_json::json!({
        "metadata": {
            "name": service_account,
            "resourceVersion": existing.meta().resource_version,
            "annotations": annotations,
        },
        "imagePullSecrets": image_pull_secrets,
    });
    let patch_params = PatchParams::apply(&engine.config().field_manager);
    match api
        .patch(service_account, &patch_params, &Patch::Merge(&patch))
        .await
    {
        Ok(_) => {
            tracing::info!(
                namespace = %namespace,
                service_account = %service_account,
                secret = %secret_name,
                "stale imagePullSecrets reference cleared from ServiceAccount"
            );
            Ok(true)
        }
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(false),
        Err(error) => Err(DeployError::Apply(error.into())),
    }
}

/// Re-add `secret_name` to a ServiceAccount's `imagePullSecrets` after a
/// reference clear turned out to rest on stale ownership information (review
/// finding on #243): when the delete detects that the secret was replaced
/// mid-cleanup, the replacement survives and must keep the reference it
/// inherits by name — otherwise its pods lose registry access. No-op when the
/// ServiceAccount is gone or already references the secret. The patch mirrors
/// [`clear_pull_secret_reference_from_service_account`]: attributed to the
/// engine field manager and pinned to the observed resourceVersion. It also
/// discharges the name's durable repair intent — a proven restore is exactly
/// what the pending-repairs annotation was waiting for (Codex review on #243,
/// P2).
async fn restore_pull_secret_reference_to_service_account(
    engine: &ApplyEngine,
    namespace: &str,
    service_account: &str,
    secret_name: &str,
) -> Result<(), DeployError> {
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::{Patch, PatchParams};

    let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
    let existing = match api.get(service_account).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    let pending = pending_reference_repairs(&existing);
    let mut references: Vec<serde_json::Value> = existing
        .image_pull_secrets
        .iter()
        .flatten()
        .map(|r| serde_json::json!({ "name": r.name }))
        .collect();
    let already_referenced = references
        .iter()
        .any(|r| r.get("name").and_then(|name| name.as_str()) == Some(secret_name));
    if already_referenced && !pending.iter().any(|entry| entry.secret_name == secret_name) {
        return Ok(());
    }
    if !already_referenced {
        references.push(serde_json::json!({ "name": secret_name }));
    }
    let mut annotations: serde_json::Map<String, serde_json::Value> = existing
        .metadata
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();
    if pending.iter().any(|entry| entry.secret_name == secret_name) {
        let remaining: Vec<PendingReferenceRepair> = pending
            .iter()
            .filter(|entry| entry.secret_name != secret_name)
            .cloned()
            .collect();
        // Merge-patch semantics: an omitted key is left untouched — only an
        // explicit null removes the annotation.
        let discharged = if remaining.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::Value::String(render_pending_reference_repairs(&remaining))
        };
        annotations.insert(
            PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
            discharged,
        );
    }
    let patch = serde_json::json!({
        "metadata": {
            "name": service_account,
            "resourceVersion": existing.meta().resource_version,
            "annotations": annotations,
        },
        "imagePullSecrets": references,
    });
    let patch_params = PatchParams::apply(&engine.config().field_manager);
    api.patch(service_account, &patch_params, &Patch::Merge(&patch))
        .await
        .map_err(|error| DeployError::Apply(error.into()))?;
    tracing::info!(
        namespace = %namespace,
        service_account = %service_account,
        secret = %secret_name,
        "imagePullSecrets reference restored (the secret was replaced mid-cleanup)"
    );
    Ok(())
}

/// Discharge one name's durable repair intent without touching the
/// `imagePullSecrets` references (Codex review on #243, P2): used after a
/// removal provably completed — the cleared reference is final, so the
/// ServiceAccount must stop carrying the name as pending repair. No-op when
/// the ServiceAccount is gone or does not record the name.
async fn forget_pending_reference_repair(
    engine: &ApplyEngine,
    namespace: &str,
    service_account: &str,
    secret_name: &str,
) -> Result<(), DeployError> {
    use k8s_openapi::api::core::v1::ServiceAccount;
    use kube::api::{Patch, PatchParams};

    let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
    let existing = match api.get(service_account).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(()),
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    let pending = pending_reference_repairs(&existing);
    if !pending.iter().any(|entry| entry.secret_name == secret_name) {
        return Ok(());
    }
    let remaining: Vec<PendingReferenceRepair> = pending
        .iter()
        .filter(|entry| entry.secret_name != secret_name)
        .cloned()
        .collect();
    let mut annotations: serde_json::Map<String, serde_json::Value> = existing
        .metadata
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|(key, value)| (key, serde_json::Value::String(value)))
        .collect();
    // Merge-patch semantics: an omitted key is left untouched — only an
    // explicit null removes the annotation.
    let discharged = if remaining.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::String(render_pending_reference_repairs(&remaining))
    };
    annotations.insert(
        PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
        discharged,
    );
    let patch = serde_json::json!({
        "metadata": {
            "name": service_account,
            "resourceVersion": existing.meta().resource_version,
            "annotations": annotations,
        },
    });
    let patch_params = PatchParams::apply(&engine.config().field_manager);
    match api
        .patch(service_account, &patch_params, &Patch::Merge(&patch))
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 404 => Ok(()),
        Err(error) => Err(DeployError::Apply(error.into())),
    }
}

async fn apply_all_with_tenant_image_pull_secret(
    engine: &ApplyEngine,
    pool: &sqlx::PgPool,
    deployment_id: Uuid,
    manifests: &enclava_engine::manifest::GeneratedManifests,
    manifest_hash: &str,
    image_pull_secret_config: Option<&TenantImagePullSecretConfig>,
    generation: MutationGeneration,
) -> Result<(), DeployError> {
    let ns_name = manifests
        .namespace
        .metadata
        .name
        .as_deref()
        .ok_or_else(|| {
            enclava_engine::apply::engine::ApplyError::NamespaceNotReady(
                "namespace has no name".to_string(),
            )
        })?;

    apply_namespace(engine, &manifests.namespace, generation).await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    let settings = PullSecretSettings::from_env();
    let service_accounts = manifests
        .service_account
        .metadata
        .name
        .iter()
        .cloned()
        .collect::<Vec<String>>();

    if let Some(config) = image_pull_secret_config {
        let secret = generate_tenant_image_pull_secret(ns_name, config);
        apply_namespaced_resource(engine, ns_name, &secret, generation).await?;
        // A previous out-of-scope sweep may still have a same-UID removal
        // intent. Once this deploy has applied the desired credential, restore
        // its reference and discharge that intent before any later step can
        // fail (or a concurrent sweep can replay the stale deletion).
        for account in &service_accounts {
            restore_pull_secret_reference_to_service_account(
                engine,
                ns_name,
                account,
                &config.name,
            )
            .await?;
        }
        discharge_reference_repair_intent_after_deploy(engine, ns_name, &service_accounts).await?;
        tracing::info!(
            namespace = %ns_name,
            secret = %config.name,
            "tenant image pull secret applied"
        );
    } else {
        // The scope gate rejected this workload (or no scoped config exists).
        // Skipping the apply is not enough: a pull secret applied by an
        // earlier deployment would survive here with the platform credential
        // still readable by namespace readers, so reconcile the whole managed
        // inventory down to nothing — every CAP-managed secret, under any
        // name, together with its ServiceAccount references (review findings
        // on #243). This runs before the standard resources so a later apply
        // failure cannot leave the token behind, and a cleanup that cannot
        // converge fails the deploy instead of proceeding with a stale
        // platform token in the namespace.
        let converged = reconcile_managed_pull_secrets(
            engine,
            ns_name,
            &service_accounts,
            &settings,
            false,
            PullSecretDeleteMode::Fenced(generation),
        )
        .await?;
        if !converged {
            return Err(DeployError::Validation(
                "tenant image pull secret cleanup did not converge; refusing to continue with a \
                 stale platform pull secret in the namespace"
                    .to_string(),
            ));
        }
    }

    apply_standard_resources(engine, manifests, generation).await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    if image_pull_secret_config.is_some() {
        // Once the generated ServiceAccount carries its final
        // `imagePullSecrets`, reconcile residue in this in-scope namespace
        // (review findings on #243): pre-label secrets are adopted (labeled)
        // while the configured GHCR pair still proves ownership, and managed
        // secrets the workload no longer references — e.g. under a previous
        // `TENANT_IMAGE_PULL_SECRET_NAME` — are removed. This is strict like
        // the out-of-scope branch (review finding): a residue cleanup that
        // cannot converge fails the deploy instead of silently leaving the
        // old platform credential readable — once admission is open there is
        // no background retry, so a quiet "will retry" here would be a lie
        // and the stale token would outlive the deploy.
        let converged = reconcile_managed_pull_secrets(
            engine,
            ns_name,
            &service_accounts,
            &settings,
            true,
            PullSecretDeleteMode::Fenced(generation),
        )
        .await?;
        if !converged {
            return Err(DeployError::Validation(
                "tenant image pull secret residue cleanup did not converge; refusing to finish \
                 the deploy with a stale platform pull secret readable in the namespace"
                    .to_string(),
            ));
        }
    }

    apply_network_policy(engine, ns_name, &manifests.network_policy, generation).await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
        generation,
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 4/5: Gateway API resources applied");

    let mut sts = manifests.statefulset.clone();
    sts.metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            MANIFEST_HASH_ANNOTATION.to_string(),
            manifest_hash.to_string(),
        );

    // Codex P1: creation-specific evidence for the PVC sweep. Stamped
    // immediately before the StatefulSet step is attempted (the final
    // apply phase). Under Retain/Retain the controller attaches no PVC
    // ownerReferences, so this stamp — not apply_started_at (which
    // precedes KBS reconciliation and every Kubernetes write) — is the
    // earliest point a claim of this workload's lineage could exist: a
    // tenant-created same-named claim predates it and is never swept.
    // First-writer-wins (COALESCE) so a retry of a partially-failed apply
    // does not advance the bound past claims the first attempt created.
    sqlx::query(
        "UPDATE deployments
            SET sts_apply_started_at = COALESCE(sts_apply_started_at, clock_timestamp())
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(pool)
    .await?;
    // Conservative workload-apply evidence. The StatefulSet write is the
    // first operation that can replace the TEE, so the settling guard's
    // marker is stamped at ITS entry -- not at the multi-resource apply's
    // entry (a namespace/standard-resource/gateway failure never touched
    // the workload and must not count as a rollout) and not after the SSA
    // response (a request Kubernetes accepted but whose response was lost
    // to a timeout or connection error must still count). Idempotent
    // re-applies keep the first stamp time.
    sqlx::query(
        "UPDATE deployments
            SET apply_committed_at = COALESCE(apply_committed_at, clock_timestamp())
          WHERE id = $1",
    )
    .bind(deployment_id)
    .execute(pool)
    .await?;
    let sts_live = apply_statefulset(engine, ns_name, &sts, generation).await?;
    // Persist the server-reported UID and creationTimestamp of the
    // StatefulSet object this apply produced (the POST/SSA response — not
    // a pre-call stamp). This is the identity the claim sweep matches
    // ownerReferences against. Grok P2: only persist when the RESPONSE
    // itself carries CAP creation evidence (the same gate the sweep uses):
    // an SSA patch of a PRE-EXISTING StatefulSet returns that set's UID,
    // and recording it would let the claim sweep treat a tenant's set as
    // proven CAP lineage. First-writer-wins keeps a retry from advancing
    // the record past claims the first attempt created.
    if crate::deployment_failure_cleanup::is_cap_created_generation_leftover(
        &sts_live,
        generation.get(),
    ) {
        if let (Some(uid), Some(created)) = (
            sts_live.metadata.uid.as_deref(),
            sts_live
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| ts.0.to_string())
                .and_then(|raw| raw.parse::<chrono::DateTime<chrono::Utc>>().ok()),
        ) && let Err(error) = crate::deployment_failure_cleanup::persist_sts_provenance(
            pool,
            None,
            deployment_id,
            uid,
            created,
            None,
        )
        .await
        {
            tracing::warn!(
                deployment_id = %deployment_id,
                error = %error,
                "could not persist StatefulSet provenance; PVC sweep will require a live sts observation (fail closed)"
            );
        }
    } else {
        // No CAP creation evidence on the response (e.g. an SSA patch of a
        // pre-existing set, or a mutating admission rewrote the creation
        // annotation): recording this UID would forge claim-deletion
        // authority. The sweep's no-window path stays fail-closed.
        tracing::warn!(
            deployment_id = %deployment_id,
            namespace = %ns_name,
            "StatefulSet apply response lacks CAP creation evidence; not recording provenance"
        );
    }
    tracing::info!(
        namespace = %ns_name,
        manifest_hash = %manifest_hash,
        "step 5/5: StatefulSet applied"
    );

    // Reviewer finding on #243 (Critical): this deploy's server-side apply of
    // the generated ServiceAccount is the authoritative newest decision about
    // its `imagePullSecrets` — an out-of-scope deploy prunes the field. Any
    // pull-secret repair intent still recorded on the manifest's
    // ServiceAccounts is therefore obsolete: leaving it would make the next
    // sweep re-attach a reference this deploy just decided against, while the
    // deploy's own reconcile never repairs (the repair pass is sweep-only).
    // Discharge it now that the applies have re-decided the final state.
    discharge_reference_repair_intent_after_deploy(engine, ns_name, &service_accounts).await?;

    tracing::info!(namespace = %ns_name, "apply_all complete");
    Ok(())
}

/// The SNI (backend-tag, host) pairs a deployment of this app publishes,
/// derived from the authoritative app row exactly as
/// `build_confidential_app_from_rows` derives its `DomainSpec`: the TEE host
/// falls back to the platform domain when `tee_domain` is null, and an empty
/// custom domain is skipped. Apply and failed-apply cleanup both build their
/// route lists from this helper so they can never diverge.
pub(crate) fn app_route_hosts(app: &App) -> Vec<(crate::edge::BackendTag, String)> {
    let mut hosts = vec![
        (crate::edge::BackendTag::App, app.domain.clone()),
        (
            crate::edge::BackendTag::Tee,
            match app.tee_domain.as_deref() {
                Some(tee_domain) if !tee_domain.is_empty() => tee_domain.to_string(),
                // build_confidential_app_from_rows falls back to the platform
                // domain when tee_domain is null, and apply publishes that
                // route unconditionally.
                _ => app.domain.clone(),
            },
        ),
    ];
    if let Some(custom_domain) = app.custom_domain.as_deref()
        && !custom_domain.is_empty()
    {
        hosts.push((crate::edge::BackendTag::App, custom_domain.to_string()));
    }
    hosts
}

/// Forget every pull-secret repair intent recorded on the given
/// ServiceAccounts after a deploy has (re)applied them (reviewer finding on
/// #243, Critical): the deploy's SSA is the authoritative decision about the
/// generated ServiceAccount's `imagePullSecrets`, so intents recorded by
/// earlier sweeps must not survive it.
async fn discharge_reference_repair_intent_after_deploy(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
) -> Result<(), DeployError> {
    for service_account in service_accounts {
        let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
        let existing = match api.get(service_account).await {
            Ok(existing) => existing,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        for repair in pending_reference_repairs(&existing) {
            forget_pending_reference_repair(
                engine,
                namespace,
                service_account,
                &repair.secret_name,
            )
            .await?;
            tracing::info!(
                namespace = %namespace,
                service_account = %service_account,
                secret = %repair.secret_name,
                "stale pull-secret repair intent discharged: this deploy re-decided the \
                 ServiceAccount's imagePullSecrets"
            );
        }
    }
    Ok(())
}

pub struct ApplyDeploymentManifestsRequest {
    pub pool: PgPool,
    pub app: App,
    pub snapshot: DeploymentApplySnapshot,
    pub engine: ApplyEngine,
    pub fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims,
    pub deployment_id: Uuid,
    pub attestation_config: Option<AttestationConfig>,
    pub kbs_policy_config: Option<crate::kbs::KbsPolicyConfig>,
    pub edge_config_generation: i64,
    pub kubernetes_mutation_generation: i64,
    pub api_signing_pubkey: String,
    pub api_url: String,
    pub workload_artifact_binding: Option<WorkloadArtifactBinding>,
    pub signed_policy_artifact: Option<crate::signing_service::SignedPolicyArtifact>,
    pub local_workload_artifacts_json: Option<String>,
    pub local_trustee_policy_json: Option<String>,
    pub sigstore_material: Vec<u8>,
    pub provenance_oci_material: Vec<u8>,
    pub log_encryption: Option<LogEncryptionConfig>,
}

/// Immutable database-row inputs captured for one queued deployment apply.
///
/// The API can accept another deployment while this one waits for the apply
/// semaphore. Keeping these rows on the queued request prevents a later
/// deployment from changing the manifest rendered for this deployment ID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeploymentApplySnapshot {
    pub containers: Vec<AppContainer>,
    pub resources: AppResources,
}

impl DeploymentApplySnapshot {
    pub fn new(containers: Vec<AppContainer>, resources: AppResources) -> Self {
        Self {
            containers,
            resources,
        }
    }
}

/// Authoritative database rows used while validating an existing app
/// deployment. Acceptance locks and compares this snapshot before committing
/// any candidate changes.
#[derive(Debug, Clone)]
pub(crate) struct ExistingAppAuthoritySnapshot {
    app_updated_at: chrono::DateTime<chrono::Utc>,
    containers: Vec<AppContainer>,
    resources: AppResources,
}

impl ExistingAppAuthoritySnapshot {
    pub(crate) fn new(
        app_updated_at: chrono::DateTime<chrono::Utc>,
        containers: Vec<AppContainer>,
        resources: AppResources,
    ) -> Self {
        Self {
            app_updated_at,
            containers,
            resources,
        }
    }

    pub(crate) fn app_id(&self) -> Uuid {
        self.resources.app_id
    }
}

pub(crate) async fn lock_and_verify_existing_app_authority(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
) -> Result<bool, sqlx::Error> {
    verify_existing_app_authority_rows(tx, app_id, expected, true).await
}

/// Compare the accepted app/runtime rows while the caller holds the app
/// advisory lane, without taking row locks. Durable workers use this form
/// because manifest application updates app/deployment status through other
/// pooled connections while the advisory lane remains held. Taking a row lock
/// here would make the worker wait on itself.
pub(crate) async fn verify_existing_app_authority(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
) -> Result<bool, sqlx::Error> {
    verify_existing_app_authority_rows(tx, app_id, expected, false).await
}

async fn verify_existing_app_authority_rows(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    expected: &ExistingAppAuthoritySnapshot,
    lock_rows: bool,
) -> Result<bool, sqlx::Error> {
    let app_query = if lock_rows {
        "SELECT updated_at FROM apps WHERE id = $1 FOR UPDATE"
    } else {
        "SELECT updated_at FROM apps WHERE id = $1"
    };
    let current_updated_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(app_query)
        .bind(app_id)
        .fetch_optional(&mut **tx)
        .await?;
    if current_updated_at != Some(expected.app_updated_at) {
        return Ok(false);
    }

    let containers_query = if lock_rows {
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id FOR UPDATE"
    } else {
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY id"
    };
    let current_containers: Vec<AppContainer> = sqlx::query_as(containers_query)
        .bind(app_id)
        .fetch_all(&mut **tx)
        .await?;
    let mut expected_containers = expected.containers.clone();
    expected_containers.sort_by_key(|container| container.id);
    if current_containers != expected_containers {
        return Ok(false);
    }

    let resources_query = if lock_rows {
        "SELECT * FROM app_resources WHERE app_id = $1 FOR UPDATE"
    } else {
        "SELECT * FROM app_resources WHERE app_id = $1"
    };
    let current_resources: Option<AppResources> = sqlx::query_as(resources_query)
        .bind(app_id)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(current_resources.as_ref() == Some(&expected.resources))
}

#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("no containers defined for app")]
    NoContainers,
    #[error("image parse error: {0}")]
    ImageParse(String),
    #[error("image must have a digest: {0}")]
    NoDigest(String),
    #[error("engine validation error: {0}")]
    Validation(String),
    #[error(
        "deploy runtime is not configured: set ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE"
    )]
    MissingAttestationConfig,
    #[error("Kubernetes apply error: {0}")]
    Apply(#[from] enclava_engine::apply::engine::ApplyError),
    #[error("app is not deployed: {0}")]
    NotDeployed(String),
    #[error("KBS policy error: {0}")]
    KbsPolicy(#[from] crate::kbs::KbsPolicyError),
    #[error("edge route error: {0}")]
    EdgeRoute(#[from] crate::edge::EdgeRouteError),
    #[error("durable mutation fence error: {0}")]
    Mutation(#[from] crate::mutation_leases::MutationLeaseError),
    #[error(
        "managed pull secret {0} keeps changing under the cleanup (conflicting updates); \
         removal did not converge"
    )]
    PullSecretDeleteConflict(String),
}

impl DeployError {
    /// Return a bounded code safe for persistence and operator logs.
    pub(crate) fn public_code(&self) -> &'static str {
        match self {
            Self::Db(_) => "database_error",
            Self::NoContainers => "no_containers",
            Self::ImageParse(_) => "image_parse_error",
            Self::NoDigest(_) => "image_digest_required",
            Self::Validation(_) => "deployment_validation_error",
            Self::MissingAttestationConfig => "deploy_runtime_not_configured",
            Self::Apply(error) => error.public_code(),
            Self::NotDeployed(_) => "app_not_deployed",
            Self::KbsPolicy(_) => "kbs_policy_error",
            Self::EdgeRoute(_) => "edge_route_error",
            Self::Mutation(_) => "mutation_fence_error",
            Self::PullSecretDeleteConflict(_) => "pull_secret_delete_conflict",
        }
    }
}

fn persisted_deployment_error(error_message: Option<&str>) -> Option<&'static str> {
    error_message.map(|_| PERSISTED_DEPLOYMENT_ERROR_MESSAGE)
}

pub(crate) fn serialize_workload_command(
    command: &[String],
) -> Result<Option<String>, serde_json::Error> {
    if command.is_empty() {
        Ok(None)
    } else {
        serde_json::to_string(command).map(Some)
    }
}

pub(crate) fn descriptor_primary_port(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Option<i32> {
    descriptor
        .oci_runtime_spec
        .ports
        .first()
        .and_then(|port| i32::try_from(port.container_port).ok())
}

pub(crate) fn descriptor_storage_paths(
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) -> Vec<String> {
    descriptor
        .oci_runtime_spec
        .mounts
        .iter()
        .filter(|mount| {
            mount.mount_type == "kubernetes-volume-subpath"
                || mount.source.starts_with("state-mount:")
        })
        .map(|mount| mount.destination.clone())
        .filter(|path| path != "/state")
        .collect()
}

fn deserialize_workload_command(command: Option<&str>) -> Option<Vec<String>> {
    let raw = command?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    match serde_json::from_str::<Vec<String>>(trimmed) {
        Ok(argv) if !argv.is_empty() => Some(argv),
        Ok(_) => None,
        Err(_) => Some(vec![raw.to_string()]),
    }
}

fn parse_workload_security_profile(
    value: Option<&str>,
) -> Result<WorkloadSecurityProfile, DeployError> {
    value
        .unwrap_or("restricted")
        .parse()
        .map_err(DeployError::Validation)
}

pub(crate) fn set_primary_descriptor_runtime(
    app: &mut ConfidentialApp,
    descriptor: &enclava_common::descriptor::DeploymentDescriptor,
) {
    let command = &descriptor.oci_runtime_spec.args;
    let port = descriptor_primary_port(descriptor).and_then(|port| u16::try_from(port).ok());
    let storage_paths = descriptor_storage_paths(descriptor);

    for container in app.containers.iter_mut().filter(|c| c.is_primary) {
        if !command.is_empty() {
            container.command = Some(command.to_vec());
        }
        if let Some(port) = port {
            container.port = Some(port);
        }
        container.storage_paths = storage_paths.clone();
    }
}

/// Build a ConfidentialApp spec from database state.
/// This is the bridge between the API's data model and the engine's input type.
pub async fn build_confidential_app(
    pool: &PgPool,
    app: &App,
    deployment_id: Uuid,
    attestation_config: &AttestationConfig,
    api_signing_pubkey: &str,
    api_url: &str,
) -> Result<ConfidentialApp, DeployError> {
    let containers_rows: Vec<AppContainer> =
        sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC")
            .bind(app.id)
            .fetch_all(pool)
            .await?;

    if containers_rows.is_empty() {
        return Err(DeployError::NoContainers);
    }

    let resources: AppResources = sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
        .bind(app.id)
        .fetch_one(pool)
        .await?;

    build_confidential_app_from_rows(
        app,
        deployment_id,
        attestation_config,
        api_signing_pubkey,
        api_url,
        &containers_rows,
        &resources,
    )
}

/// Build a `ConfidentialApp` from an immutable snapshot of database rows.
///
/// Deployment request validation uses this helper to render a candidate spec
/// before any requested app or container changes are persisted.
pub(crate) fn build_confidential_app_from_rows(
    app: &App,
    deployment_id: Uuid,
    attestation_config: &AttestationConfig,
    api_signing_pubkey: &str,
    api_url: &str,
    containers_rows: &[AppContainer],
    resources: &AppResources,
) -> Result<ConfidentialApp, DeployError> {
    if containers_rows.is_empty() {
        return Err(DeployError::NoContainers);
    }

    let mut containers = Vec::new();
    for row in containers_rows {
        let mut image =
            ImageRef::parse(&row.image_ref).map_err(|e| DeployError::ImageParse(e.to_string()))?;
        if let Some(d) = row.image_digest.as_ref() {
            // The digest is authoritative: render the digest-pinned name with
            // any tag stripped, so the cc-init render matches the signed
            // descriptor's registry/repository@digest even when the request
            // carried a tag (#210 review).
            image = ImageRef::parse(&format!(
                "{}/{}@{}",
                image.registry(),
                image.repository(),
                d
            ))
            .map_err(|e| DeployError::ImageParse(e.to_string()))?;
        }

        let storage_paths = row.storage_paths.clone().unwrap_or_default();

        containers.push(Container {
            name: row.name.clone(),
            image,
            port: row.port.map(|p| p as u16),
            command: deserialize_workload_command(row.command.as_deref()),
            env: std::collections::HashMap::new(),
            storage_paths,
            workload_security_profile: parse_workload_security_profile(
                row.workload_security_profile.as_deref(),
            )?,
            is_primary: row.is_primary,
        });
    }

    let unlock_mode = match app.unlock_mode {
        crate::models::UnlockMode::Auto => CommonUnlockMode::Auto,
        crate::models::UnlockMode::Password => CommonUnlockMode::Password,
    };
    let egress_mode = app.egress_mode.parse::<EgressMode>().map_err(|error| {
        DeployError::Validation(format!(
            "stored egress_mode for app {} is invalid: {error}",
            app.name
        ))
    })?;

    let mut storage = StorageSpec::new(&resources.app_data_size, &resources.tls_data_size);
    // Set bind mounts from the primary container
    if let Some(primary) = containers_rows.iter().find(|c| c.is_primary) {
        let paths = primary.storage_paths.clone().unwrap_or_default();
        storage.app_data.bind_mounts = paths
            .iter()
            .map(|path| {
                let subdir = path.strip_prefix('/').unwrap_or(path).replace('/', "-");
                BindMount {
                    source: format!("/data/{subdir}"),
                    destination: path.clone(),
                }
            })
            .collect();
    }

    let image_pull_secret_name =
        tenant_image_pull_secret_config_for_containers(&containers).map(|config| config.name);

    Ok(ConfidentialApp {
        app_id: app.id,
        deployment_id,
        name: app.name.clone(),
        namespace: app.namespace.clone(),
        instance_id: app.instance_id.clone(),
        tenant_id: app.tenant_id.clone(),
        bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
        tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
        service_account: app.service_account.clone(),
        image_pull_secret_name,
        signer_identity_subject: app.signer_identity_subject.clone(),
        signer_identity_issuer: app.signer_identity_issuer.clone(),
        containers,
        storage,
        unlock_mode,
        domain: DomainSpec {
            platform_domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
        },
        api_signing_pubkey: api_signing_pubkey.to_string(),
        api_url: api_url.to_string(),
        resources: ResourceLimits {
            cpu: resources.cpu_limit.clone(),
            memory: resources.memory_limit.clone(),
        },
        attestation: attestation_config.clone(),
        egress_mode,
        public_internet_egress_excluded_cidrs: public_internet_egress_excluded_cidrs_from_env(),
        allow_internal_egress: crate::routes::apps::internal_egress_allowlist_enabled()
            && app.egress_allowlist.0.iter().any(|rule| {
                !crate::routes::apps::egress_allowlist_host_audit_reasons(&rule.host).is_empty()
            }),
        egress_allowlist: app.egress_allowlist.0.clone(),
        log_encryption: None,
        workload_artifact_binding: None,
        generated_agent_policy: None,
    })
}

pub(crate) async fn latest_deployment_id_for_app(
    pool: &PgPool,
    app_id: Uuid,
) -> Result<Uuid, sqlx::Error> {
    let deployment_id = sqlx::query_scalar::<_, Uuid>(
        "SELECT deployment.id
           FROM deployments AS deployment
           LEFT JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
          ORDER BY (apply_job.generation IS NOT NULL) DESC,
                   apply_job.generation DESC NULLS LAST,
                   deployment.created_at DESC,
                   deployment.id DESC
          LIMIT 1",
    )
    .bind(app_id)
    .fetch_optional(pool)
    .await?;
    Ok(deployment_id.unwrap_or_else(Uuid::nil))
}

pub(crate) const DEPLOYMENT_SUPERSEDED_ERROR: &str = "deployment_superseded";

#[derive(Debug, thiserror::Error)]
pub(crate) enum SupersedeDeploymentError {
    #[error("an unexpired deployment mutation is still in progress")]
    Busy,
    #[error("database error")]
    Database(#[from] sqlx::Error),
}

fn app_deployment_lane_key(app_id: Uuid) -> i64 {
    let (high, low) = app_id.as_u64_pair();
    (high ^ low) as i64
}

/// Serialize deployment acceptance, manifest application, and terminal result
/// publication for one app across every API replica.
///
/// A 64-bit advisory key collision can only serialize unrelated apps; it
/// cannot allow two operations for the same app to overlap.
pub(crate) async fn lock_app_deployment_lane(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(app_deployment_lane_key(app_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Mark accepted-but-incomplete deployments as superseded before inserting a
/// newer deployment for the same app. The caller must hold the app deployment
/// lane for the surrounding transaction.
pub(crate) async fn supersede_incomplete_deployments(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
) -> Result<u64, SupersedeDeploymentError> {
    // Config tokens are app-scoped, so supersession cannot cancel a CLI's
    // writes. Keep its live hold exclusive; deletion may still stop the app.
    let active_mutation: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
               FROM deployment_apply_jobs AS job
               JOIN deployments AS deployment ON deployment.id = job.deployment_id
              WHERE job.app_id = $1
                AND job.locked_until >= clock_timestamp()
                AND (
                    job.state IN ('setting_up', 'cleaning_up')
                    OR (
                        job.state = 'running'
                        AND deployment.status IN (
                            'pending'::deploy_status_enum,
                            'applying'::deploy_status_enum
                        )
                    )
                )
         ) OR EXISTS (
             SELECT 1
               FROM deployment_apply_jobs AS job
               JOIN apps AS app ON app.id = job.app_id
              WHERE job.app_id = $1
                AND job.customer_config_hold
                AND job.customer_config_released_at IS NULL
                AND job.state = 'setup_pending'
                AND job.customer_config_hold_until > clock_timestamp()
                AND app.status <> 'deleting'::app_status_enum
         )",
    )
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await?;
    if active_mutation {
        return Err(SupersedeDeploymentError::Busy);
    }
    // Stop every queued or leased operation before terminalizing its
    // deployment. A worker that already holds a lease must acquire the same
    // app lane before any setup/apply/cleanup side effect, so once this update
    // commits it can only observe a lost lease / terminal generation.
    sqlx::query(
        "UPDATE deployment_apply_jobs
         SET state = 'failed',
             lock_token = NULL,
             locked_until = NULL,
             next_attempt_at = clock_timestamp(),
             last_error_code = $1,
             updated_at = clock_timestamp()
         WHERE app_id = $2
           AND state IN (
               'setup_pending', 'setting_up',
               'cleanup_pending', 'cleaning_up',
               'pending', 'running'
           )",
    )
    .bind(DEPLOYMENT_SUPERSEDED_ERROR)
    .bind(app_id)
    .execute(&mut **tx)
    .await?;

    let result = sqlx::query(
        "UPDATE deployments
         SET status = 'failed'::deploy_status_enum,
             error_message = $1,
             completed_at = clock_timestamp()
         WHERE app_id = $2
           AND status::text IN ('pending', 'applying', 'watching')",
    )
    .bind(DEPLOYMENT_SUPERSEDED_ERROR)
    .bind(app_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected())
}

pub(crate) async fn deployment_is_active_for_apply(
    tx: &mut Transaction<'_, Postgres>,
    app_id: Uuid,
    deployment_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1
             FROM deployments AS deployment
             JOIN apps AS app ON app.id = deployment.app_id
             WHERE deployment.id = $1
               AND deployment.app_id = $2
               -- A worker can die after idempotent SSA apply and before its
               -- rollout watcher publishes a terminal result. Reclaiming a
               -- watching generation must re-apply and re-watch it; treating
               -- it as inactive would complete the job while stranding the
               -- deployment forever in watching.
               AND deployment.status::text IN ('pending', 'applying', 'watching')
               AND app.status <> 'deleting'::app_status_enum
         )",
    )
    .bind(deployment_id)
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await
}

/// Publish a rollout observation only while it still belongs to the active
/// watching deployment and exact manifest hash. A newer acceptance first
/// supersedes the old row under the same app deployment lane, so a late old
/// watcher becomes a no-op for both deployment and app status.
#[cfg(test)]
pub(crate) struct DeploymentResultUpdate<'a> {
    pub app_id: Uuid,
    pub deployment_id: Uuid,
    pub deploy_status: &'a str,
    pub expected_manifest_hash: &'a str,
    pub app_status: &'a str,
    pub error_code: Option<&'a str>,
    pub terminal: bool,
}

#[cfg(test)]
pub(crate) async fn record_deployment_result_if_current(
    pool: &PgPool,
    update: DeploymentResultUpdate<'_>,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    lock_app_deployment_lane(&mut tx, update.app_id).await?;

    let result = sqlx::query(
        "UPDATE deployments
         SET status = $1::deploy_status_enum,
             error_message = $2,
             completed_at = CASE WHEN $3 THEN clock_timestamp() ELSE completed_at END
         WHERE id = $4
           AND app_id = $5
           AND status = 'watching'::deploy_status_enum
           AND manifest_hash = $6",
    )
    .bind(update.deploy_status)
    .bind(update.error_code)
    .bind(update.terminal)
    .bind(update.deployment_id)
    .bind(update.app_id)
    .bind(update.expected_manifest_hash)
    .execute(&mut *tx)
    .await?;

    let recorded = result.rows_affected() == 1;
    if recorded {
        sqlx::query(
            "UPDATE apps
             SET status = $1::app_status_enum,
                 updated_at = clock_timestamp()
             WHERE id = $2",
        )
        .bind(update.app_status)
        .bind(update.app_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(recorded)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use enclava_common::descriptor::{
        Capabilities, DeploymentDescriptor, EnvVar, Mount, OciRuntimeSpec, Port, Resources,
        SecurityContext, Sidecars, SignerIdentity,
    };
    use std::sync::{Arc, Mutex};

    fn test_attestation_config() -> AttestationConfig {
        AttestationConfig {
            proxy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
            .unwrap(),
            caddy_image: ImageRef::parse(
                "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            acme_ca_url: enclava_engine::types::default_acme_ca_url(),
            caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
            trustee_policy_read_available: true,
            workload_artifacts_url: None,
            tls_certificate_broker_url: None,
            amd_kds_base_url: None,
            trustee_policy_url: None,
            local_workload_artifacts_json: None,
            local_trustee_policy_json: None,
            platform_trustee_policy_pubkey_hex: None,
            signing_service_pubkey_hex: None,
            verification_material: None,
        }
    }

    fn queued_apply_app() -> App {
        let now = chrono::Utc::now();
        App {
            id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            name: "queued-app".to_string(),
            namespace: "cap-queued-app".to_string(),
            instance_id: "queued-app-instance".to_string(),
            tenant_id: "8f346820".to_string(),
            service_account: "cap-queued-app-sa".to_string(),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: crate::models::UnlockMode::Password,
            domain: "queued-app.8f346820.enclava.dev".to_string(),
            tee_domain: Some("queued-app.8f346820.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: AppStatus::Creating,
            signer_identity_subject: Some("https://github.com/acme/app".to_string()),
            signer_identity_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            signer_identity_set_at: Some(now),
            source_provider: Some("github".to_string()),
            source_repository: Some("acme/app".to_string()),
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: now,
            updated_at: now,
        }
    }

    fn queued_apply_snapshot(digest_byte: char) -> DeploymentApplySnapshot {
        let app = queued_apply_app();
        let digest = format!("sha256:{}", digest_byte.to_string().repeat(64));
        DeploymentApplySnapshot::new(
            vec![AppContainer {
                id: uuid::Uuid::new_v4(),
                app_id: app.id,
                name: "web".to_string(),
                image_ref: "ghcr.io/acme/app:latest".to_string(),
                image_digest: Some(digest),
                port: Some(8080),
                command: None,
                storage_paths: Some(vec!["/data".to_string()]),
                workload_security_profile: Some("restricted".to_string()),
                is_primary: true,
            }],
            AppResources {
                app_id: app.id,
                cpu_limit: "1".to_string(),
                memory_limit: "1Gi".to_string(),
                app_data_size: "5Gi".to_string(),
                tls_data_size: "2Gi".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn queued_apply_renders_its_captured_rows_after_later_state_changes() {
        let app = queued_apply_app();
        let first_snapshot = queued_apply_snapshot('a');
        let later_snapshot = queued_apply_snapshot('b');
        let gate = std::sync::Arc::new(tokio::sync::Semaphore::new(0));
        let queued_gate = gate.clone();
        let queued_app = app.clone();
        let queued = tokio::spawn(async move {
            let _permit = queued_gate.acquire().await.expect("queue remains open");
            build_confidential_app_from_rows(
                &queued_app,
                uuid::Uuid::new_v4(),
                &test_attestation_config(),
                "api-signing-key",
                "https://api.enclava.dev",
                &first_snapshot.containers,
                &first_snapshot.resources,
            )
            .expect("captured apply snapshot")
        });

        tokio::task::yield_now().await;
        let later = build_confidential_app_from_rows(
            &app,
            uuid::Uuid::new_v4(),
            &test_attestation_config(),
            "api-signing-key",
            "https://api.enclava.dev",
            &later_snapshot.containers,
            &later_snapshot.resources,
        )
        .expect("later apply snapshot");
        gate.add_permits(1);
        let first = queued.await.expect("queued renderer");

        assert_eq!(
            first.containers[0].image.digest(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert_eq!(
            later.containers[0].image.digest(),
            format!("sha256:{}", "b".repeat(64))
        );
    }

    #[test]
    fn tagged_rows_render_the_digest_pinned_name() {
        let app = queued_apply_app();
        let snapshot = queued_apply_snapshot('c');
        let rendered = build_confidential_app_from_rows(
            &app,
            uuid::Uuid::new_v4(),
            &test_attestation_config(),
            "api-signing-key",
            "https://api.enclava.dev",
            &snapshot.containers,
            &snapshot.resources,
        )
        .expect("render");
        // A stored tag must not leak into the rendered name: the signed
        // descriptor binds registry/repository@digest (#210 review).
        assert_eq!(
            rendered.containers[0].image.digest_ref(),
            format!("ghcr.io/acme/app@sha256:{}", "c".repeat(64))
        );
    }

    #[test]
    fn password_redeploy_timeout_stays_healthy_for_manual_unlock() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Running,
            crate::models::UnlockMode::Password,
        );

        assert_eq!(
            outcome,
            DeploymentOutcome {
                deploy_status: "healthy",
                app_status: "running",
                error_message: None,
                terminal: true,
            }
        );
    }

    #[test]
    fn auto_redeploy_timeout_still_fails() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Running,
            crate::models::UnlockMode::Auto,
        );

        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(
            outcome.error_message.as_deref(),
            Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE)
        );
    }

    #[test]
    fn deployment_error_persistence_discards_plaintext() {
        const SENSITIVE_ERROR: &str =
            "kubernetes response included customer-secret-name and private-config";

        let persisted = persisted_deployment_error(Some(SENSITIVE_ERROR));
        assert_eq!(persisted, Some(PERSISTED_DEPLOYMENT_ERROR_MESSAGE));
        assert!(!persisted.unwrap().contains("customer-secret-name"));
        assert_eq!(persisted_deployment_error(None), None);

        let error = DeployError::Apply(enclava_engine::apply::engine::ApplyError::RolloutFailed(
            SENSITIVE_ERROR.to_string(),
        ));
        assert_eq!(error.public_code(), "rollout_failed");
        assert!(!error.public_code().contains("customer-secret-name"));

        let mutation_error =
            DeployError::Mutation(crate::mutation_leases::MutationLeaseError::Busy);
        assert_eq!(mutation_error.public_code(), "mutation_fence_error");
        assert_eq!(
            crate::deployment_jobs::DeploymentJobError::from(mutation_error).code(),
            "mutation_fence_error"
        );
    }

    #[test]
    fn password_create_timeout_stays_watchable_for_initial_claim() {
        let outcome = classify_rollout_result(
            Ok(EngineDeployStatus::timed_out(
                "rollout did not complete within 600s",
            )),
            AppStatus::Creating,
            crate::models::UnlockMode::Password,
        );

        assert_eq!(
            outcome,
            DeploymentOutcome {
                deploy_status: "watching",
                app_status: "creating",
                error_message: None,
                terminal: false,
            }
        );
    }

    #[test]
    fn tenant_image_pull_secret_uses_dockerconfigjson_shape() {
        let config = TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_fake".to_string(),
            allowed_repositories: Vec::new(),
        };

        let secret = generate_tenant_image_pull_secret("tenant-ns", &config);
        let string_data = secret.string_data.as_ref().unwrap();
        let docker_config: serde_json::Value =
            serde_json::from_str(string_data.get(".dockerconfigjson").unwrap()).unwrap();

        assert_eq!(
            secret.metadata.name.as_deref(),
            Some("enclava-registry-auth")
        );
        assert_eq!(secret.metadata.namespace.as_deref(), Some("tenant-ns"));
        assert_eq!(
            secret
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
                .map(String::as_str),
            Some("enclava-platform")
        );
        assert_eq!(
            secret.type_.as_deref(),
            Some("kubernetes.io/dockerconfigjson")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["username"].as_str(),
            Some("cap-bot")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["password"].as_str(),
            Some("ghp_fake")
        );
        assert_eq!(
            docker_config["auths"]["ghcr.io"]["auth"].as_str(),
            Some("Y2FwLWJvdDpnaHBfZmFrZQ==")
        );
    }

    fn pull_secret_config(
        allowed_repositories: Vec<ImagePullRepositoryScope>,
    ) -> TenantImagePullSecretConfig {
        TenantImagePullSecretConfig {
            name: "enclava-registry-auth".to_string(),
            username: "cap-bot".to_string(),
            token: "ghp_fake".to_string(),
            allowed_repositories,
        }
    }

    fn test_container(image_ref: &str) -> Container {
        Container {
            name: "web".to_string(),
            image: ImageRef::parse(image_ref).unwrap(),
            port: Some(8080),
            command: None,
            env: std::collections::HashMap::new(),
            storage_paths: Vec::new(),
            workload_security_profile: WorkloadSecurityProfile::Restricted,
            is_primary: true,
        }
    }

    #[test]
    fn tenant_image_pull_scope_parses_exact_and_prefix_repositories() {
        assert_eq!(
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template").unwrap(),
            ImagePullRepositoryScope {
                registry: "ghcr.io".to_string(),
                repository: "enclava-ai/private-template".to_string(),
                include_subrepositories: false,
            }
        );
        assert_eq!(
            parse_image_pull_repository_scope(" ghcr.io/enclava-ai/templates/* ").unwrap(),
            ImagePullRepositoryScope {
                registry: "ghcr.io".to_string(),
                repository: "enclava-ai/templates".to_string(),
                include_subrepositories: true,
            }
        );
        assert!(parse_image_pull_repository_scope("ghcr.io").is_err());
    }

    /// A repeated wildcard suffix must be rejected, never stripped down into
    /// the broader scope (P1 review): `registry/repository/*/*` would widen to
    /// `registry/repository/*` if all `/*` repetitions were trimmed.
    #[test]
    fn tenant_image_pull_scope_rejects_repeated_wildcard_suffixes() {
        assert!(parse_image_pull_repository_scope("ghcr.io/company/private/*/*").is_err());
        assert!(parse_image_pull_repository_scope("ghcr.io/company/private/**").is_err());
        assert!(parse_image_pull_repository_scope("ghcr.io/company*/private").is_err());
        assert!(parse_image_pull_repository_scope("*/company/private").is_err());
        assert!(parse_image_pull_repository_scope("ghcr.io/company/private/*x").is_err());

        // A single trailing "/*" keeps its subrepository semantics — the
        // rejection must not break the documented grammar.
        assert_eq!(
            parse_image_pull_repository_scope("ghcr.io/company/private/*").unwrap(),
            ImagePullRepositoryScope {
                registry: "ghcr.io".to_string(),
                repository: "company/private".to_string(),
                include_subrepositories: true,
            }
        );
    }

    /// Issue #225: an unscoped config must never attach the platform pull
    /// secret to tenant workloads — this was the previous "global fallback"
    /// that materialized the platform GHCR PAT into every tenant namespace.
    #[test]
    fn tenant_image_pull_secret_without_scope_fails_closed() {
        let config = pull_secret_config(Vec::new());
        let containers = vec![test_container(
            "ghcr.io/tenant/private-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )];

        assert!(!tenant_image_pull_secret_applies_to_containers(
            &containers,
            &config
        ));
    }

    /// Issue #225: a scope list with invalid entries must not silently
    /// degrade into a different (or missing) scope.
    #[test]
    fn tenant_image_pull_scope_parser_rejects_invalid_entries() {
        assert!(parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*,bogus").is_err());
        assert!(parse_image_pull_scopes_strict("ghcr.io").is_err());
        assert_eq!(
            parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*").unwrap(),
            vec![parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap()]
        );
    }

    /// A list with one valid and one malformed scope must name the malformed
    /// entry in the error instead of claiming no valid entries exist (review
    /// finding): operators need the exact offending entry to fix the typo.
    #[test]
    fn tenant_image_pull_scope_errors_name_malformed_entries() {
        let error =
            parse_image_pull_scopes_strict("ghcr.io/enclava-ai/templates/*,bogus,ghcr.io/a/b")
                .unwrap_err();
        assert!(error.contains("bogus"), "error should name entry: {error}");
        assert!(error.contains("#2"), "error should give position: {error}");
        assert!(
            !error.contains("ghcr.io/a/b"),
            "valid entries must not be reported: {error}"
        );

        let empty_entry = parse_image_pull_scopes_strict("ghcr.io/a/b,").unwrap_err();
        assert!(
            empty_entry.contains("#2"),
            "error should give position: {empty_entry}"
        );
    }

    #[test]
    fn managed_tenant_image_pull_secret_detection_matches_label_and_legacy_shape() {
        use k8s_openapi::ByteString;

        let matching = Some(("cap-bot", "x"));
        let mut labeled = generate_tenant_image_pull_secret(
            "tenant-ns",
            &pull_secret_config(vec![
                parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
            ]),
        );
        // The managed-by label is the ownership proof for generated secrets:
        // detection passes on the label alone, without reading any data.
        assert!(is_managed_tenant_image_pull_secret(&labeled, matching));
        // Labeled secrets are proven ours by the label alone.
        assert!(is_managed_tenant_image_pull_secret(&labeled, None));

        // Legacy pre-label secret: dockerconfigjson with exactly one ghcr.io
        // auth entry carrying the configured GHCR pair, as the old global
        // fallback generated it.
        let legacy_json =
            serde_json::json!({"auths": {"ghcr.io": {"username": "cap-bot", "password": "x"}}})
                .to_string();
        let mut legacy = Secret {
            metadata: ObjectMeta {
                name: Some("enclava-registry-auth".to_string()),
                ..Default::default()
            },
            type_: Some("kubernetes.io/dockerconfigjson".to_string()),
            ..Default::default()
        };
        legacy.data = Some(std::collections::BTreeMap::from([(
            ".dockerconfigjson".to_string(),
            ByteString(legacy_json.into_bytes()),
        )]));
        assert!(is_managed_tenant_image_pull_secret(&legacy, matching));
        // An unlabeled secret with a tenant's own GHCR credentials under the
        // managed name is NOT CAP-generated: never delete it (review finding).
        assert!(!is_managed_tenant_image_pull_secret(
            &legacy,
            Some(("tenant-user", "tenant-token"))
        ));
        assert!(!is_managed_tenant_image_pull_secret(&legacy, None));

        // A tenant's own multi-registry secret is never CAP-managed.
        let tenant_json = serde_json::json!({
            "auths": {
                "ghcr.io": {"username": "cap-bot", "password": "x"},
                "registry.example": {"username": "tenant"}
            }
        })
        .to_string();
        let mut tenant = legacy.clone();
        tenant.data = Some(std::collections::BTreeMap::from([(
            ".dockerconfigjson".to_string(),
            ByteString(tenant_json.into_bytes()),
        )]));
        assert!(!is_managed_tenant_image_pull_secret(&tenant, matching));

        // Wrong type / missing payload is never CAP-managed.
        let opaque = Secret {
            metadata: ObjectMeta {
                name: Some("enclava-registry-auth".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!is_managed_tenant_image_pull_secret(&opaque, matching));

        // A stray managed-by label on an unparseable secret is still ours.
        labeled.data = None;
        labeled.string_data = None;
        assert!(is_managed_tenant_image_pull_secret(&labeled, matching));
    }

    #[test]
    fn namespace_keeps_pull_secret_only_while_an_app_is_in_scope() {
        let config = pull_secret_config(vec![
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
        ]);
        let in_scope = Some(vec![test_container(
            "ghcr.io/enclava-ai/templates/ssh@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .image
        .clone()]);
        let out_of_scope = Some(vec![test_container(
            "ghcr.io/tenant/private-app@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .image
        .clone()]);

        assert!(namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            std::slice::from_ref(&in_scope)
        ));
        assert!(namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            &[out_of_scope.clone(), in_scope.clone()]
        ));
        assert!(!namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            &[out_of_scope]
        ));
        // Unparsable stored images never keep the secret by themselves …
        assert!(!namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            &[None]
        ));
        // … but they never evict it from a namespace with a valid in-scope app.
        assert!(namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            &[None, in_scope.clone()]
        ));
        assert!(namespace_keeps_tenant_image_pull_secret(
            Some(&config),
            &[Some(vec![]), in_scope]
        ));
        // No scoped config at all: nothing keeps the secret.
        assert!(!namespace_keeps_tenant_image_pull_secret(None, &[]));
    }

    #[test]
    fn tenant_image_pull_secret_scope_requires_every_container_to_match() {
        let config = pull_secret_config(vec![
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/private-template").unwrap(),
            parse_image_pull_repository_scope("ghcr.io/enclava-ai/templates/*").unwrap(),
        ]);
        let allowed = vec![
            test_container(
                "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            test_container(
                "ghcr.io/enclava-ai/templates/ssh@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        ];
        let mixed = vec![
            test_container(
                "ghcr.io/enclava-ai/private-template@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            test_container(
                "ghcr.io/tenant/private-app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            ),
        ];

        assert!(tenant_image_pull_secret_applies_to_containers(
            &allowed, &config
        ));
        assert!(!tenant_image_pull_secret_applies_to_containers(
            &mixed, &config
        ));
    }

    #[test]
    fn signed_deploy_with_local_artifacts_still_reconciles_global_kbs_policy() {
        let mut attestation = test_attestation_config();
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));

        attestation.local_workload_artifacts_json = Some("{\"bundle\":true}".to_string());
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));

        attestation.local_trustee_policy_json = Some("{\"policy\":true}".to_string());
        assert!(should_reconcile_global_signed_policy_artifacts(
            true,
            &attestation
        ));
        assert!(!should_reconcile_global_signed_policy_artifacts(
            false,
            &attestation
        ));
    }

    fn customer_app_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "8f346820".to_string(),
            app_id: uuid::Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "customer-app".to_string(),
            deploy_id: uuid::Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: chrono::Utc.with_ymd_and_hms(2026, 5, 8, 12, 0, 0).unwrap(),
            nonce: [1; 32],
            app_domain: "customer-app.8f346820.enclava.dev".to_string(),
            tee_domain: "customer-app.8f346820.tee.enclava.dev".to_string(),
            custom_domains: Vec::new(),
            namespace: "cap-demo-org-customer-app".to_string(),
            service_account: "cap-customer-app-sa".to_string(),
            identity_hash: [2; 32],
            image_ref:
                "ghcr.io/acme/customer-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            signer_identity: SignerIdentity {
                subject:
                    "https://github.com/acme/customer-app/.github/workflows/docker.yaml@refs/heads/main"
                        .to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/usr/local/bin/enclava-wait-exec".to_string()],
                args: vec!["/usr/local/bin/app".to_string()],
                env: vec![EnvVar {
                    name: "APP_SEED_PATH".to_string(),
                    value: "/run/enclava/seeds/app/seed".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3338,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![
                    Mount {
                        source: "state-mount".to_string(),
                        destination: "/state".to_string(),
                        mount_type: "kubernetes-volume".to_string(),
                        options: vec!["rw".to_string()],
                    },
                    Mount {
                        source: "state-mount:data".to_string(),
                        destination: "/data".to_string(),
                        mount_type: "kubernetes-volume-subpath".to_string(),
                        options: vec!["rw".to_string()],
                    },
                ],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest:
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                        .to_string(),
                caddy_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    .to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            independent_verification: true,
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-demo-org-customer-app-customer-app-owner/seed-encrypted"
                .to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "enclava-kbs-policy-v1".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "test".to_string(),
            expected_agent_policy_hash: [5; 32],
            expected_cc_init_data_hash: [6; 32],
            expected_kbs_policy_hash: [7; 32],
        }
    }

    #[test]
    fn signed_descriptor_runtime_fields_match_descriptor_expectations() {
        let descriptor = customer_app_descriptor();

        assert_eq!(
            serialize_workload_command(&descriptor.oci_runtime_spec.args).unwrap(),
            Some("[\"/usr/local/bin/app\"]".to_string())
        );
        assert_eq!(descriptor_primary_port(&descriptor), Some(3338));
        assert_eq!(
            descriptor_storage_paths(&descriptor),
            vec!["/data".to_string()]
        );
    }

    #[test]
    fn descriptor_runtime_overrides_stale_primary_container_fields() {
        let descriptor = customer_app_descriptor();
        let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: Vec::new(),
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: None,
                tls_certificate_broker_url: None,
                amd_kds_base_url: None,
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
                verification_material: None,
            },
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

        set_primary_descriptor_runtime(&mut app, &descriptor);

        let primary = app.primary_container().unwrap();
        assert_eq!(
            primary.command,
            Some(vec!["/usr/local/bin/app".to_string()])
        );
        assert_eq!(primary.port, Some(3338));
        assert_eq!(primary.storage_paths, vec!["/data".to_string()]);
    }

    #[test]
    fn signed_descriptor_without_subpath_mounts_clears_stale_storage_paths() {
        let mut descriptor = customer_app_descriptor();
        descriptor
            .oci_runtime_spec
            .mounts
            .retain(|mount| mount.destination == "/state");
        let mut app = ConfidentialApp {
            app_id: descriptor.app_id,
            deployment_id: descriptor.deploy_id,
            name: descriptor.app_name.clone(),
            namespace: descriptor.namespace.clone(),
            instance_id: "customer-app-test".to_string(),
            tenant_id: descriptor.org_slug.clone(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
            service_account: descriptor.service_account.clone(),
            image_pull_secret_name: None,
            signer_identity_subject: Some(descriptor.signer_identity.subject.clone()),
            signer_identity_issuer: Some(descriptor.signer_identity.issuer.clone()),
            containers: vec![Container {
                name: "web".to_string(),
                image: ImageRef::parse(&descriptor.image_ref).unwrap(),
                port: Some(8080),
                command: None,
                env: std::collections::HashMap::new(),
                storage_paths: vec!["/data".to_string()],
                workload_security_profile: WorkloadSecurityProfile::Restricted,
                is_primary: true,
            }],
            storage: StorageSpec::new("5Gi", "2Gi"),
            unlock_mode: CommonUnlockMode::Password,
            domain: DomainSpec {
                platform_domain: descriptor.app_domain.clone(),
                tee_domain: descriptor.tee_domain.clone(),
                custom_domain: None,
            },
            api_signing_pubkey: String::new(),
            api_url: String::new(),
            resources: ResourceLimits {
                cpu: "1".to_string(),
                memory: "1Gi".to_string(),
            },
            attestation: AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                )
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: None,
                tls_certificate_broker_url: None,
                amd_kds_base_url: None,
                trustee_policy_url: None,
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: None,
                signing_service_pubkey_hex: None,
                verification_material: None,
            },
            egress_mode: EgressMode::Restricted,
            public_internet_egress_excluded_cidrs: Vec::new(),
            allow_internal_egress: false,
            egress_allowlist: Vec::new(),
            log_encryption: None,
            workload_artifact_binding: None,
            generated_agent_policy: None,
        };

        set_primary_descriptor_runtime(&mut app, &descriptor);

        assert!(descriptor_storage_paths(&descriptor).is_empty());
        assert!(app.primary_container().unwrap().storage_paths.is_empty());
    }

    /// A Kubernetes API double with configurable readiness and an empty pod list.
    fn rollout_client(ready: bool) -> kube::Client {
        rollout_client_with(1, 1, i32::from(ready))
    }

    fn rollout_client_with(
        generation: i64,
        observed_generation: i64,
        ready_replicas: i32,
    ) -> kube::Client {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        kube::Client::new(
            service_fn(move |request: Request<Body>| async move {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                let path = request.uri().path().to_string();
                let _ = request.into_body().collect().await;
                let value = if path.ends_with("/pods") {
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PodList",
                        "items": [],
                    })
                } else {
                    serde_json::json!({
                        "apiVersion": "apps/v1",
                        "kind": "StatefulSet",
                        "metadata": {
                            "name": "queued-app",
                            "namespace": "cap-queued-app",
                            "generation": generation,
                        },
                        "spec": { "replicas": 1 },
                        "status": {
                            "observedGeneration": observed_generation,
                            "replicas": ready_replicas,
                            "readyReplicas": ready_replicas,
                            "currentReplicas": ready_replicas,
                            "updatedReplicas": ready_replicas,
                        },
                    })
                };
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(200)
                        .body(Body::from(serde_json::to_vec(&value).unwrap()))
                        .unwrap(),
                )
            }),
            "default",
        )
    }

    fn rollout_test_engine() -> ApplyEngine {
        ApplyEngine::new(
            rollout_client(false),
            enclava_engine::apply::types::ApplyConfig {
                rollout_timeout: std::time::Duration::from_secs(600),
                poll_interval: std::time::Duration::from_millis(5),
                ..enclava_engine::apply::types::ApplyConfig::default()
            },
        )
    }

    fn expired_rollout_anchor(budget: std::time::Duration) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now()
            - chrono::Duration::from_std(budget).unwrap()
            - chrono::Duration::seconds(1)
    }

    /// The base budget an initialized redeploy would carry: no fresh claim
    /// contributes the first-boot allowance.
    fn initialized_redeploy_budget() -> std::time::Duration {
        rollout_test_engine()
            .config()
            .rollout_timeout_for_storage(
                "2Ti",
                "2Ti",
                enclava_engine::apply::orchestrator::FreshVolumeClaims::NONE,
            )
            .expect("fixture rollout budget")
    }

    /// The budget a first render that must freshly initialize both volumes
    /// would record with its watching marker.
    fn fresh_initialization_budget(
        app_data_size: &str,
        tls_data_size: &str,
    ) -> std::time::Duration {
        rollout_test_engine()
            .config()
            .rollout_timeout_for_storage(
                app_data_size,
                tls_data_size,
                enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            )
            .expect("fixture rollout budget")
    }

    #[tokio::test]
    async fn rollout_watch_slice_returns_nonterminal_while_budget_remains() {
        // An owner-waiting workload must release its worker slot between
        // observation slices instead of holding it for the full rollout
        // timeout.
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            rollout_test_engine(),
            "slice-manifest".to_string(),
            chrono::Utc::now(),
            fresh_initialization_budget("32Mi", "32Mi"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
        assert_eq!(outcome.manifest_hash, "slice-manifest");
    }

    #[tokio::test]
    async fn rollout_watch_respects_anchored_cumulative_deadline() {
        // A restarted observer anchors at `observing_since`: once the
        // cumulative rollout budget is spent, the slice ends immediately and
        // returns the engine timeout classification instead of restarting a
        // fresh initialization budget.
        let mut auto_app = queued_apply_app();
        auto_app.unlock_mode = crate::models::UnlockMode::Auto;
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            auto_app,
            rollout_test_engine(),
            "deadline-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
    }

    #[tokio::test]
    async fn initialized_redeploy_expires_at_base_budget() {
        // A redeploy whose volumes are already initialized carries only the
        // base rollout budget. A 2 Ti manifest must NOT inherit a
        // multi-hour first-boot allowance: once the recorded base budget is
        // spent, the cumulative deadline ends the rollout normally.
        let mut app = queued_apply_app();
        app.unlock_mode = crate::models::UnlockMode::Auto;
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "initialized-redeploy-manifest".to_string(),
            expired_rollout_anchor(initialized_redeploy_budget()),
            initialized_redeploy_budget(),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "failed");
        assert_eq!(outcome.app_status, "failed");
        assert!(outcome.terminal);
        assert_eq!(outcome.error_code, Some("deployment_rollout_failed"));
    }

    #[tokio::test]
    async fn resumed_observer_keeps_recorded_budget() {
        // The budget persisted with the watching marker is the deadline.
        // Simulating a restart where live pod/volume state has changed, the
        // resumed observer must reuse the recorded value: a record smaller
        // than any size-derived budget still expires, a record larger than
        // one still keeps observing. Neither recomputes.
        let mut expired_app = queued_apply_app();
        expired_app.unlock_mode = crate::models::UnlockMode::Auto;
        let recorded_small = std::time::Duration::from_secs(1);
        let expired = DeploymentRollout::observe_only(
            expired_app,
            rollout_test_engine(),
            "resumed-expired-manifest".to_string(),
            expired_rollout_anchor(recorded_small),
            recorded_small,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(expired.deploy_status, "failed");
        assert!(expired.terminal);

        let mut waiting_app = queued_apply_app();
        waiting_app.unlock_mode = crate::models::UnlockMode::Auto;
        let waiting = DeploymentRollout::observe_only(
            waiting_app,
            rollout_test_engine(),
            "resumed-waiting-manifest".to_string(),
            chrono::Utc::now() - chrono::Duration::minutes(30),
            fresh_initialization_budget("2Ti", "2Ti"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(waiting.deploy_status, "watching");
        assert!(!waiting.terminal);
        assert_eq!(waiting.error_code, None);
    }

    #[tokio::test]
    async fn rollout_watch_observes_late_owner_unlock_after_deadline() {
        let engine = ApplyEngine::new(
            rollout_client(true),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            engine,
            "late-unlock-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "healthy");
        assert_eq!(outcome.app_status, "running");
        assert!(outcome.terminal);
    }

    #[tokio::test]
    async fn rollout_watch_password_timeout_stays_nonterminal_for_owner_wait() {
        // Password-mode creates classify an exhausted rollout budget as a
        // continuing owner wait, but the observation slice still returns
        // promptly so the worker slot is released between probes.
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            queued_apply_app(),
            rollout_test_engine(),
            "password-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
    }

    #[tokio::test]
    async fn rollout_watch_password_timeout_stays_nonterminal_for_failed_app_redeploy() {
        // The job payload freezes the app snapshot at accept time, so a
        // redeploy of a previously-failed app carries status "failed". The
        // apply already persisted "creating" for the new rollout; the stale
        // snapshot must not terminalize a legitimate owner wait.
        let mut app = queued_apply_app();
        app.status = AppStatus::Failed;
        let budget = fresh_initialization_budget("32Mi", "32Mi");
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "password-redeploy-manifest".to_string(),
            expired_rollout_anchor(budget),
            budget,
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
    }

    fn settled_statefulset(
        generation: i64,
        observed: i64,
        desired: i32,
        ready: i32,
        current: i32,
        updated: i32,
    ) -> k8s_openapi::api::apps::v1::StatefulSet {
        serde_json::from_value(serde_json::json!({
            "apiVersion": "apps/v1",
            "kind": "StatefulSet",
            "metadata": {"name": "app", "namespace": "cap-app", "generation": generation},
            "spec": {"replicas": desired},
            "status": {
                "observedGeneration": observed,
                "readyReplicas": ready,
                "currentReplicas": current,
                "updatedReplicas": updated,
            },
        }))
        .expect("statefulset settling fixture")
    }

    #[test]
    fn statefulset_rollout_settled_matches_the_rollout_completion_criterion() {
        // Fully converged: the controller has observed the current
        // generation and every replica matches the latest spec.
        assert!(statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 1, 1, 1
        )));
        // The controller has not observed the newest applied generation:
        // a failed rollout's spec is still being reconciled and its
        // controller can still replace the TEE.
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 2, 1, 1, 1, 1
        )));
        // The replacement is not up yet: the workload is mid-swap even
        // though the controller caught up with the generation.
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 0, 1, 1
        )));
        assert!(!statefulset_rollout_settled(&settled_statefulset(
            3, 3, 1, 1, 1, 0
        )));
        // A scaled-down workload has no TEE that could be replaced.
        assert!(statefulset_rollout_settled(&settled_statefulset(
            3, 3, 0, 0, 0, 0
        )));
    }

    #[tokio::test]
    async fn supersession_serializes_customer_config_delivery() {
        let pool = crate::test_support::database_test_pool().await;
        let (app, deployment_id, _, _) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET customer_config_hold = true,
                    customer_config_hold_until = clock_timestamp() + interval '1 hour',
                    next_attempt_at = 'infinity'
              WHERE deployment_id = $1",
        )
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("arm config delivery hold");

        for (scenario, blocked) in [
            ("active", true),
            ("expired", false),
            ("released", false),
            ("deleting", false),
        ] {
            let mut tx = pool.begin().await.expect("begin supersession scenario");
            lock_app_deployment_lane(&mut tx, app.id).await.unwrap();
            if scenario == "expired" {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET customer_config_hold_until = clock_timestamp() - interval '1 second'
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            if scenario == "released" {
                sqlx::query(
                    "UPDATE deployment_apply_jobs
                        SET customer_config_released_at = clock_timestamp(),
                            next_attempt_at = clock_timestamp()
                      WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            if scenario == "deleting" {
                sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
                    .bind(app.id)
                    .execute(&mut *tx)
                    .await
                    .unwrap();
            }
            let result = supersede_incomplete_deployments(&mut tx, app.id).await;
            if blocked {
                assert!(matches!(result, Err(SupersedeDeploymentError::Busy)));
                let state: String = sqlx::query_scalar(
                    "SELECT state FROM deployment_apply_jobs WHERE deployment_id = $1",
                )
                .bind(deployment_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
                assert_eq!(state, "setup_pending");
            } else {
                assert_eq!(result.expect(scenario), 1);
            }
            tx.rollback().await.unwrap();
        }
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn workload_rollout_settled_reads_the_live_generation() {
        let converged = ApplyEngine::new(
            rollout_client(true),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&converged, "cap-queued-app", "queued-app")
                .await
                .expect("probe converged workload"),
            Some(true)
        );

        let converging = ApplyEngine::new(
            rollout_client(false),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&converging, "cap-queued-app", "queued-app")
                .await
                .expect("probe converging workload"),
            Some(false)
        );
    }

    #[tokio::test]
    async fn workload_rollout_settled_rejects_an_unobserved_generation() {
        // observedGeneration behind metadata.generation: the controller has
        // not caught up to the newest applied spec yet, so the failed
        // rollout is still reconciling even though the replica counts look
        // ready. The probe must read both fields through the client.
        let lagging = ApplyEngine::new(
            rollout_client_with(3, 2, 1),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        assert_eq!(
            workload_rollout_settled(&lagging, "cap-queued-app", "queued-app")
                .await
                .expect("probe lagging workload"),
            Some(false)
        );
    }

    #[tokio::test]
    async fn workload_rollout_settled_distinguishes_a_missing_workload() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| async move {
                let _ = request.into_body().collect().await;
                let status = serde_json::json!({
                    "apiVersion": "v1", "kind": "Status",
                    "status": "Failure", "reason": "NotFound",
                    "message": "absent", "code": 404,
                });
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(404)
                        .body(Body::from(serde_json::to_vec(&status).unwrap()))
                        .unwrap(),
                )
            }),
            "default",
        );
        let engine = ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default());
        assert_eq!(
            workload_rollout_settled(&engine, "cap-absent-app", "absent-app")
                .await
                .expect("probe missing workload"),
            None
        );
    }

    #[tokio::test]
    async fn large_volume_initialization_keeps_observing_after_base_deadline() {
        // The recorded first-boot budget extends past the base deadline: 30
        // minutes into observation a fresh 2 Ti render is still watching.
        let mut app = queued_apply_app();
        app.unlock_mode = crate::models::UnlockMode::Auto;
        let outcome = DeploymentRollout::observe_only(
            app,
            rollout_test_engine(),
            "initializing-manifest".to_string(),
            chrono::Utc::now() - chrono::Duration::minutes(30),
            fresh_initialization_budget("2Ti", "2Gi"),
        )
        .expect("valid rollout budget")
        .with_observation_slice(std::time::Duration::from_millis(50))
        .watch()
        .await;
        assert_eq!(outcome.deploy_status, "watching");
        assert_eq!(outcome.app_status, "creating");
        assert!(!outcome.terminal);
        assert_eq!(outcome.error_code, None);
    }

    /// Kubernetes API double for `ingress_restart_verdict`: exact-path GET
    /// responses, 404 `Status` for anything absent — the same shape the real
    /// API server returns to `get`/`get_opt`.
    struct GateCluster {
        responses: std::collections::HashMap<String, (u16, serde_json::Value)>,
    }

    impl GateCluster {
        fn empty() -> Self {
            Self {
                responses: std::collections::HashMap::new(),
            }
        }

        /// A live StatefulSet plus both claims created at a fixed timestamp.
        fn deployed(namespace: &str, workload: &str) -> Self {
            let mut cluster = Self::empty();
            cluster.put(
                format!("/apis/apps/v1/namespaces/{namespace}/statefulsets/{workload}"),
                200,
                serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "StatefulSet",
                    "metadata": {"name": workload, "namespace": namespace},
                }),
            );
            cluster.with_claims(namespace, workload, &["state", "tls-state"]);
            cluster
        }

        fn with_claims(&mut self, namespace: &str, workload: &str, vcts: &[&str]) {
            for vct in vcts {
                let claim_name = format!("{vct}-{workload}-0");
                self.put(
                    format!("/api/v1/namespaces/{namespace}/persistentvolumeclaims/{claim_name}"),
                    200,
                    serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PersistentVolumeClaim",
                        "metadata": {
                            "name": claim_name,
                            "namespace": namespace,
                            "creationTimestamp": "2025-01-01T00:00:00Z",
                        },
                    }),
                );
            }
        }

        /// Ordinal-0 pod created AFTER both claims (strict whole-second
        /// ordering satisfied), mounting both claims, with configurable
        /// readiness — a still-formatting initializer reports `ready=false`.
        fn with_pod(&mut self, namespace: &str, workload: &str, ready: bool) {
            let pod_name = format!("{workload}-0");
            let state_claim = format!("state-{workload}-0");
            let tls_claim = format!("tls-state-{workload}-0");
            let ready_status = if ready { "True" } else { "False" };
            self.put(
                format!("/api/v1/namespaces/{namespace}/pods/{pod_name}"),
                200,
                serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {
                        "name": pod_name,
                        "namespace": namespace,
                        "creationTimestamp": "2025-01-01T00:01:00Z",
                    },
                    "spec": {
                        "containers": [],
                        "volumes": [
                            {"name": "state",
                             "persistentVolumeClaim": {"claimName": state_claim}},
                            {"name": "tls-state",
                             "persistentVolumeClaim": {"claimName": tls_claim}},
                        ],
                    },
                    "status": {
                        "conditions": [{
                            "type": "Ready",
                            "status": ready_status,
                        }],
                    },
                }),
            );
        }

        fn put(&mut self, path: String, status: u16, body: serde_json::Value) {
            self.responses.insert(path, (status, body));
        }

        fn client(self) -> kube::Client {
            use axum::http::{Request, Response};
            use http_body_util::BodyExt;
            use kube::client::Body;
            use tower::service_fn;

            kube::Client::new(
                service_fn(move |request: Request<Body>| {
                    let responses = self.responses.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        let _ = request.into_body().collect().await;
                        let (status, body) = responses.get(&path).cloned().unwrap_or_else(|| {
                            (
                                404,
                                serde_json::json!({
                                    "apiVersion": "v1",
                                    "kind": "Status",
                                    "status": "Failure",
                                    "reason": "NotFound",
                                    "code": 404,
                                    "message": format!("{path} not found"),
                                }),
                            )
                        });
                        Ok::<_, std::io::Error>(
                            Response::builder()
                                .status(status)
                                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                                .unwrap(),
                        )
                    }
                }),
                "default",
            )
        }
    }

    fn gate_engine(cluster: GateCluster) -> ApplyEngine {
        ApplyEngine::new(
            cluster.client(),
            enclava_engine::apply::types::ApplyConfig::default(),
        )
    }

    #[tokio::test]
    async fn ingress_restart_not_deployed_without_statefulset() {
        // No StatefulSet: nothing to restart, so the predeploy verify keeps
        // its DNS-only path. The probe must not provision or wait.
        let engine = gate_engine(GateCluster::empty());
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("404 StatefulSet lookup is a verdict, not an error");
        assert_eq!(verdict, IngressRestartVerdict::NotDeployed);
    }

    #[tokio::test]
    async fn ingress_restart_ready_when_live_pod_proves_both_claims() {
        // Exact ordinal-0 Ready pod, created after both claims, mounting both:
        // the restart only re-opens initialized volumes under the base budget.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", true);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Ready);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_when_claim_missing() {
        // The tls-state claim is gone: a restart lands the replacement pod on
        // a never-formatted device under the base deadline — refuse, never
        // wait longer under the shared fences.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", true);
        cluster
            .responses
            .remove("/api/v1/namespaces/cap-app/persistentvolumeclaims/tls-state-app-0");
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_while_initializer_not_ready() {
        // Live pod mounting both claims but not yet Ready: enclava-init may
        // still be scanning/formatting — a restart now could strand a
        // partially formatted volume.
        let mut cluster = GateCluster::deployed("cap-app", "app");
        cluster.with_pod("cap-app", "app", false);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn ingress_restart_unproven_without_live_pod() {
        // Claims exist but the ordinal-0 pod is absent (evicted/scaled): no
        // live proof of completed initialization, fail closed.
        let cluster = GateCluster::deployed("cap-app", "app");
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, "cap-app", "app")
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);
    }

    #[tokio::test]
    async fn terminal_failed_deployment_cannot_admit_restart_of_live_unready_pod() {
        // A 'failed' deployment row is terminal — the DB guard passes it —
        // but the pod it left behind is still mid first-boot. The verdict
        // consults live cluster state only, so it must refuse regardless of
        // the recorded status.
        let pool = crate::test_support::database_test_pool().await;
        let (app, deployment_id, _, _) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        sqlx::query("UPDATE deployments SET status = 'failed'::deploy_status_enum WHERE id = $1")
            .bind(deployment_id)
            .execute(&pool)
            .await
            .expect("record terminal deployment status");

        let mut cluster = GateCluster::deployed(&app.namespace, &app.name);
        cluster.with_pod(&app.namespace, &app.name, false);
        let engine = gate_engine(cluster);
        let verdict = ingress_restart_verdict(&engine, &app.namespace, &app.name)
            .await
            .expect("live cluster proof must resolve");
        assert_eq!(verdict, IngressRestartVerdict::Unproven);

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("clean up fixture");
    }

    /// Codex review on #243 (P2): a scope entry must use the workload-image
    /// reference grammar. Tags, digests, URL schemes, and malformed path
    /// components used to parse into scopes that can never equal the parsed
    /// repository of a digest-pinned image, so startup succeeded but every
    /// affected private workload silently lost its pull secret.
    #[test]
    fn tenant_image_pull_scope_rejects_image_reference_syntax_errors() {
        for invalid in [
            "ghcr.io/org/private:latest",
            "ghcr.io/org/private@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://ghcr.io/org/private",
            "ghcr.io/org//private",
            "ghcr.io//private",
            "ghcr.io/org/.",
            "ghcr.io/org/..",
            "org/private",
        ] {
            assert!(
                parse_image_pull_repository_scope(invalid).is_err(),
                "scope {invalid:?} must be rejected"
            );
        }
        // The generated pull secret only authenticates ghcr.io, so scopes at
        // any other registry are rejected instead of exposing the platform
        // token to workloads that cannot use it.
        for foreign in [
            "registry.example.com:5000/org/private",
            "registry.corp.example/team/private",
            "ghcr.io:443/org/private",
        ] {
            let error = parse_image_pull_repository_scope(foreign).unwrap_err();
            assert!(
                error.contains("ghcr.io"),
                "error should explain the ghcr.io binding: {error}"
            );
        }
        // Valid scopes — exact and wildcard — keep parsing unchanged.
        assert!(parse_image_pull_repository_scope("ghcr.io/org/private").is_ok());
        assert!(parse_image_pull_repository_scope("ghcr.io/org/private/*").is_ok());
    }

    /// Keep/remove decision gate (review findings on #243): a managed secret
    /// stays only in an in-scope namespace, and only while it is the
    /// configured name or still referenced by a generated ServiceAccount.
    #[test]
    fn keep_managed_pull_secret_gates_on_scope_name_and_references() {
        let mut referenced = BTreeSet::new();
        referenced.insert("old-name".to_string());

        // In scope: the configured name and still-referenced old names stay.
        assert!(keep_managed_pull_secret(
            true,
            "enclava-registry-auth",
            "enclava-registry-auth",
            &referenced
        ));
        assert!(keep_managed_pull_secret(
            true,
            "old-name",
            "enclava-registry-auth",
            &referenced
        ));
        // In scope: unreferenced residue (a renamed old secret) is removed.
        assert!(!keep_managed_pull_secret(
            true,
            "renamed-old",
            "enclava-registry-auth",
            &referenced
        ));
        // Out of scope: nothing managed stays, references or not.
        assert!(!keep_managed_pull_secret(
            false,
            "enclava-registry-auth",
            "enclava-registry-auth",
            &referenced
        ));
        assert!(!keep_managed_pull_secret(
            false,
            "old-name",
            "enclava-registry-auth",
            &referenced
        ));
    }

    /// In-memory Kubernetes API double for the pull-secret reconcile tests:
    /// holds Secrets and ServiceAccounts and serves exactly the verbs the
    /// reconcile path exercises (label-selected list, get, merge patch and
    /// delete on Secrets; get and merge patch on ServiceAccounts).
    /// `namespace_missing` models an app row whose namespace does not exist
    /// yet (or is already gone) — every namespaced request 404s. The two
    /// `replace_*` hooks model a tenant replacing the pull secret mid-cleanup
    /// at the exact windows the review asked to be tested: as the
    /// ServiceAccount patch lands, and as the delete lands.
    #[derive(Default)]
    struct FakeCluster {
        secrets: Vec<Secret>,
        service_accounts: Vec<ServiceAccount>,
        namespace_missing: bool,
        replace_on_sa_patch: Option<Secret>,
        replace_on_delete: Option<Secret>,
        /// Simulated same-object updates between the cleanup's ownership read
        /// and its pinned delete: each delete request first bumps the live
        /// secret's `resourceVersion` (same UID) this many times, forcing a
        /// 409 precondition conflict without replacing the object.
        rv_bumps_on_delete: u8,
        /// Fail ServiceAccount patches with a 500: the reference cleanup
        /// fails and the secret delete must be deferred (Codex review on
        /// #243, P2).
        sa_patch_fails: bool,
        /// Simulate a finalizer on the managed Secret: the accepted DELETE
        /// leaves the object present with a `deletionTimestamp` for this many
        /// subsequent GETs before it actually disappears (`u8::MAX` keeps it
        /// stuck forever). Acceptance is not removal (Codex review on #243,
        /// P2).
        delete_lingering_polls: u8,
        /// Scratch counter for `delete_lingering_polls` — GETs remaining
        /// before the finalizer releases the terminating Secret.
        lingering_polls_left: u8,
        /// Simulate a concurrent deploy rewriting the managed secret mid-
        /// cleanup: the first delete request annotates the live object (same
        /// UID) with a NEWER mutation generation — the self-check race on
        /// #243, where the rewrite that causes the 409 must not be deleted.
        annotate_generation_on_delete: Option<i64>,
        /// Simulate a stalled API server (Codex review on #243, P1 follow-up):
        /// the label-selected Secret list hangs until the caller's per-
        /// namespace budget cancels it.
        stall_secrets_list: bool,
        /// Fail ServiceAccount patches that ADD an `imagePullSecrets` entry
        /// (reference restores) with a 500 this many times — the durable
        /// repair-intent path (Codex review on #243, P2): the clear succeeds,
        /// the delete finds a replacement, and the restore fails.
        fail_reference_restores: u8,
    }

    fn fake_managed_secret(name: &str, labeled: bool, username: &str, token: &str) -> Secret {
        use k8s_openapi::ByteString;
        let mut labels = std::collections::BTreeMap::new();
        if labeled {
            labels.insert(MANAGED_BY_LABEL.to_string(), MANAGED_BY_VALUE.to_string());
            labels.insert(
                TENANT_PULL_SECRET_LABEL.to_string(),
                TENANT_PULL_SECRET_LABEL_VALUE.to_string(),
            );
        }
        let docker_config = serde_json::json!({
            "auths": {
                "ghcr.io": { "username": username, "password": token }
            }
        });
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("tenant-ns".to_string()),
                uid: Some(format!("uid-{name}")),
                resource_version: Some("1".to_string()),
                labels: if labels.is_empty() {
                    None
                } else {
                    Some(labels)
                },
                ..Default::default()
            },
            type_: Some("kubernetes.io/dockerconfigjson".to_string()),
            data: Some(std::collections::BTreeMap::from([(
                ".dockerconfigjson".to_string(),
                ByteString(serde_json::to_vec(&docker_config).unwrap()),
            )])),
            ..Default::default()
        }
    }

    fn fake_service_account(name: &str, references: &[&str]) -> ServiceAccount {
        use k8s_openapi::api::core::v1::LocalObjectReference;
        ServiceAccount {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some("tenant-ns".to_string()),
                uid: Some(format!("uid-{name}")),
                resource_version: Some("1".to_string()),
                ..Default::default()
            },
            image_pull_secrets: if references.is_empty() {
                None
            } else {
                Some(
                    references
                        .iter()
                        .map(|name| LocalObjectReference {
                            name: (*name).to_string(),
                        })
                        .collect(),
                )
            },
            ..Default::default()
        }
    }

    fn reconcile_engine(cluster: Arc<Mutex<FakeCluster>>) -> ApplyEngine {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let cluster = cluster.clone();
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let query = request.uri().query().map(str::to_string);
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    // Stalled-API-server simulation (Codex review on #243, P1
                    // follow-up): the label-selected Secret list hangs far
                    // beyond the per-namespace reconcile budget, until the
                    // caller's timeout cancels the request. The guard's scope
                    // ends before the sleep so the future stays Send.
                    let stall = {
                        let state = cluster.lock().unwrap();
                        state.stall_secrets_list
                            && method.as_str() == "GET"
                            && path.trim_end_matches('/').ends_with("/secrets")
                    };
                    if stall {
                        tokio::time::sleep(std::time::Duration::from_secs(600)).await;
                    }
                    let mut state = cluster.lock().unwrap();
                    let (status, value) = route_fake_cluster(
                        &mut state,
                        method.as_str(),
                        &path,
                        query.as_deref(),
                        &body,
                    );
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(serde_json::to_vec(&value).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        ApplyEngine::new(client, enclava_engine::apply::types::ApplyConfig::default())
    }

    fn route_fake_cluster(
        state: &mut FakeCluster,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: &[u8],
    ) -> (u16, serde_json::Value) {
        fn not_found() -> (u16, serde_json::Value) {
            (
                404,
                serde_json::json!({
                    "kind": "Status", "apiVersion": "v1", "status": "Failure",
                    "reason": "NotFound", "code": 404,
                }),
            )
        }
        fn conflict() -> (u16, serde_json::Value) {
            (
                409,
                serde_json::json!({
                    "kind": "Status", "apiVersion": "v1", "status": "Failure",
                    "reason": "Conflict", "code": 409,
                }),
            )
        }
        if state.namespace_missing {
            // The namespace does not exist: every namespaced request is a 404
            // (Codex review on #243, P1).
            return not_found();
        }
        let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        let (kind, name) = match segments.as_slice() {
            ["api", "v1", "namespaces", _, "secrets"] => ("secrets", None),
            ["api", "v1", "namespaces", _, "secrets", name] => ("secrets", Some(*name)),
            ["api", "v1", "namespaces", _, "serviceaccounts", name] => {
                ("serviceaccounts", Some(*name))
            }
            _ => return not_found(),
        };
        match (kind, method) {
            ("secrets", "GET") if name.is_none() => {
                // Label-selected list. `labelSelector=key=value` is compared
                // against each secret's labels.
                let selector = query
                    .and_then(|query| {
                        query.split('&').find_map(|pair| {
                            let (key, value) = pair.split_once('=')?;
                            (key == "labelSelector").then(|| decode_query_component(value))
                        })
                    })
                    .unwrap_or_default();
                let items: Vec<serde_json::Value> = state
                    .secrets
                    .iter()
                    .filter(|secret| {
                        selector.split(',').all(|requirement| {
                            let Some((key, value)) = requirement.split_once('=') else {
                                return false;
                            };
                            secret
                                .metadata
                                .labels
                                .as_ref()
                                .and_then(|labels| labels.get(key))
                                .map(String::as_str)
                                == Some(value)
                        })
                    })
                    .map(|secret| serde_json::to_value(secret).unwrap())
                    .collect();
                (
                    200,
                    serde_json::json!({
                        "apiVersion": "v1", "kind": "SecretList",
                        "metadata": {}, "items": items,
                    }),
                )
            }
            ("secrets", "GET") => {
                let index = state
                    .secrets
                    .iter()
                    .position(|secret| secret.metadata.name.as_deref() == name);
                let Some(index) = index else {
                    return not_found();
                };
                // Finalizer simulation (Codex review on #243, P2): the
                // accepted delete left the object terminating; it stays
                // readable until the simulated finalizer releases it.
                if state.secrets[index].metadata.deletion_timestamp.is_some() {
                    if state.lingering_polls_left > 0 {
                        state.lingering_polls_left -= 1;
                    } else {
                        state.secrets.remove(index);
                        return not_found();
                    }
                }
                (200, serde_json::to_value(&state.secrets[index]).unwrap())
            }
            ("secrets", "PATCH") => {
                let patch: serde_json::Value = serde_json::from_slice(body).unwrap();
                let Some(secret) = state
                    .secrets
                    .iter_mut()
                    .find(|secret| secret.metadata.name.as_deref() == name)
                else {
                    return not_found();
                };
                if let Some(labels) = patch
                    .pointer("/metadata/labels")
                    .and_then(|labels| labels.as_object())
                {
                    let entry = secret.metadata.labels.get_or_insert_with(Default::default);
                    for (key, value) in labels {
                        entry.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
                    }
                }
                if let Some(annotations) = patch
                    .pointer("/metadata/annotations")
                    .and_then(|annotations| annotations.as_object())
                {
                    let entry = secret
                        .metadata
                        .annotations
                        .get_or_insert_with(Default::default);
                    for (key, value) in annotations {
                        entry.insert(key.clone(), value.as_str().unwrap_or_default().to_string());
                    }
                }
                // Credential-refresh writes (Codex review on #243, P1): the
                // data map carries base64-encoded `.dockerconfigjson`
                // payloads, exactly like the real API server.
                if let Some(data) = patch.pointer("/data").and_then(|data| data.as_object()) {
                    use base64::Engine as _;
                    let entry = secret.data.get_or_insert_with(Default::default);
                    for (key, value) in data {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD
                            .decode(value.as_str().unwrap_or_default())
                        {
                            entry.insert(key.clone(), k8s_openapi::ByteString(bytes));
                        }
                    }
                }
                if let Some(type_) = patch.get("type").and_then(|type_| type_.as_str()) {
                    secret.type_ = Some(type_.to_string());
                }
                (200, serde_json::to_value(secret).unwrap())
            }
            ("secrets", "DELETE") => {
                if let Some(replacement) = state.replace_on_delete.take() {
                    // The tenant replaces the secret between the cleanup's
                    // ownership check and its delete (review finding on #243).
                    swap_secret(&mut state.secrets, replacement);
                }
                if let Some(generation) = state.annotate_generation_on_delete.take() {
                    // A concurrent deploy rewrites the managed secret (same
                    // UID) under a NEWER mutation generation mid-cleanup —
                    // the self-check race on #243: the re-read after the 409
                    // must keep it instead of deleting.
                    if let Some(secret) = state
                        .secrets
                        .iter_mut()
                        .find(|secret| secret.metadata.name.as_deref() == name)
                    {
                        secret
                            .metadata
                            .annotations
                            .get_or_insert_with(Default::default)
                            .insert(
                                enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION
                                    .to_string(),
                                generation.to_string(),
                            );
                        secret.metadata.resource_version =
                            Some(format!("rv-rewritten-{}", generation));
                    }
                }
                if state.rv_bumps_on_delete > 0 {
                    // A concurrent writer updates the SAME managed secret
                    // between the cleanup's ownership check and its delete:
                    // only resourceVersion moves, and the pinned delete must
                    // conflict without the object being replaced.
                    state.rv_bumps_on_delete -= 1;
                    if let Some(secret) = state
                        .secrets
                        .iter_mut()
                        .find(|secret| secret.metadata.name.as_deref() == name)
                    {
                        secret.metadata.resource_version =
                            Some(format!("rv-bumped-{}", state.rv_bumps_on_delete));
                    }
                }
                let index = state
                    .secrets
                    .iter()
                    .position(|secret| secret.metadata.name.as_deref() == name);
                let Some(index) = index else {
                    return not_found();
                };
                // Preconditions mirror the API server: a stale uid or
                // resourceVersion must conflict instead of deleting.
                let delete_options: serde_json::Value = serde_json::from_slice(body).unwrap();
                let preconditions = delete_options.pointer("/preconditions");
                let live = &state.secrets[index];
                if let Some(preconditions) = preconditions {
                    let uid = preconditions.get("uid").and_then(|uid| uid.as_str());
                    let resource_version = preconditions
                        .get("resourceVersion")
                        .and_then(|rv| rv.as_str());
                    let uid_mismatch =
                        uid.is_some_and(|uid| live.metadata.uid.as_deref() != Some(uid));
                    let rv_mismatch = resource_version
                        .is_some_and(|rv| live.metadata.resource_version.as_deref() != Some(rv));
                    if uid_mismatch || rv_mismatch {
                        return conflict();
                    }
                }
                if state.lingering_polls_left == 0 && state.delete_lingering_polls == 0 {
                    state.secrets.remove(index);
                } else {
                    // Finalizer simulation: the delete is accepted but the
                    // object lingers, terminating, until the poll budget in
                    // the GET handler releases it.
                    if state.lingering_polls_left == 0 {
                        state.lingering_polls_left = state.delete_lingering_polls;
                    }
                    state.secrets[index].metadata.deletion_timestamp =
                        Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                            k8s_openapi::jiff::Timestamp::now(),
                        ));
                }
                (
                    200,
                    serde_json::json!({
                        "kind": "Status", "apiVersion": "v1", "status": "Success", "code": 200,
                    }),
                )
            }
            ("serviceaccounts", "GET") => match state
                .service_accounts
                .iter()
                .find(|account| account.metadata.name.as_deref() == name)
            {
                Some(account) => (200, serde_json::to_value(account).unwrap()),
                None => not_found(),
            },
            ("serviceaccounts", "PATCH") => {
                if state.sa_patch_fails {
                    // Codex review on #243 (P2): the ServiceAccount patch
                    // transiently fails, so the reference cleanup fails and
                    // the secret delete must be deferred.
                    return (
                        500,
                        serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "reason": "InternalError", "code": 500,
                        }),
                    );
                }
                if let Some(replacement) = state.replace_on_sa_patch.take() {
                    // The tenant replaces the secret between the cleanup's
                    // ownership read and its ServiceAccount patch — the exact
                    // window the review asked to be tested (review finding on
                    // #243).
                    swap_secret(&mut state.secrets, replacement);
                }
                let patch: serde_json::Value = serde_json::from_slice(body).unwrap();
                let Some(account) = state
                    .service_accounts
                    .iter_mut()
                    .find(|account| account.metadata.name.as_deref() == name)
                else {
                    return not_found();
                };
                if let Some(references) = patch.get("imagePullSecrets") {
                    use k8s_openapi::api::core::v1::LocalObjectReference;
                    // A patch whose reference list is LONGER than the live one
                    // is a restore (it adds an entry); a shorter/null one is a
                    // clear. `fail_reference_restores` fails restores — the
                    // durable repair-intent window (Codex review on #243, P2).
                    let is_restore = references.as_array().is_some_and(|patched| {
                        patched.len()
                            > account
                                .image_pull_secrets
                                .as_ref()
                                .map_or(0, |live| live.len())
                    });
                    if is_restore && state.fail_reference_restores > 0 {
                        state.fail_reference_restores -= 1;
                        return (
                            500,
                            serde_json::json!({
                                "kind": "Status", "apiVersion": "v1", "status": "Failure",
                                "reason": "InternalError", "code": 500,
                            }),
                        );
                    }
                    account.image_pull_secrets = references.as_array().map(|references| {
                        references
                            .iter()
                            .map(|reference| LocalObjectReference {
                                name: reference
                                    .get("name")
                                    .and_then(|name| name.as_str())
                                    .unwrap_or_default()
                                    .to_string(),
                            })
                            .collect()
                    });
                }
                if let Some(annotations) = patch
                    .pointer("/metadata/annotations")
                    .and_then(|annotations| annotations.as_object())
                {
                    let entry = account
                        .metadata
                        .annotations
                        .get_or_insert_with(Default::default);
                    for (key, value) in annotations {
                        if value.is_null() {
                            entry.remove(key);
                        } else {
                            entry.insert(
                                key.clone(),
                                value.as_str().unwrap_or_default().to_string(),
                            );
                        }
                    }
                }
                (200, serde_json::to_value(account).unwrap())
            }
            _ => not_found(),
        }
    }

    fn decode_query_component(raw: &str) -> String {
        raw.replace("%3D", "=")
            .replace("%2F", "/")
            .replace("%2C", ",")
    }

    /// Replace (or insert) a secret by name — models a tenant replacing the
    /// pull secret between two of the cleanup's requests.
    fn swap_secret(secrets: &mut Vec<Secret>, replacement: Secret) {
        let name = replacement.metadata.name.clone();
        secrets.retain(|secret| secret.metadata.name != name);
        secrets.push(replacement);
    }

    fn expected_dockerconfigjson(username: &str, token: &str) -> String {
        use base64::Engine as _;
        let auth = base64::engine::general_purpose::STANDARD.encode(format!("{username}:{token}"));
        serde_json::json!({
            "auths": {
                "ghcr.io": { "username": username, "password": token, "auth": auth }
            }
        })
        .to_string()
    }

    fn reconcile_settings() -> PullSecretSettings {
        let ghcr_credentials = Some(("cap-bot".to_string(), "ghp_platform".to_string()));
        let configured_secret_data = ghcr_credentials
            .as_ref()
            .map(|(username, token)| expected_dockerconfigjson(username, token));
        PullSecretSettings {
            configured_name: "enclava-registry-auth".to_string(),
            ghcr_credentials,
            configured_secret_data,
        }
    }

    /// Devin review on #243 (BUG_…​_0002): an unlabeled secret holding a
    /// tenant's OWN GHCR credentials under the managed name is not
    /// CAP-generated. The sweep keeps it, so it must also keep the
    /// ServiceAccount reference to it — clearing the reference would strip
    /// the tenant's pods of their private-registry credentials.
    #[tokio::test]
    async fn reconcile_keeps_tenant_owned_look_alike_and_its_reference() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![
                // The tenant's own pull secret under the configured name,
                // carrying the tenant's own credentials.
                fake_managed_secret(
                    "enclava-registry-auth",
                    false,
                    "tenant-user",
                    "tenant-token",
                ),
            ],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1, "tenant-owned secret must survive");
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "tenant-owned reference must survive"
        );
    }

    /// Codex review on #243 (P1, "sweep all previously managed pull-secret
    /// names"): a secret created under an older TENANT_IMAGE_PULL_SECRET_NAME
    /// is discovered by its managed label and removed — with its
    /// ServiceAccount references — even though the current configuration
    /// generates a different name. While a generated ServiceAccount still
    /// references it, it is kept until the workload redeploys (the documented
    /// convergence order).
    #[tokio::test]
    async fn reconcile_removes_renamed_managed_secrets_and_clears_references() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![
                fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform"),
                // Created before TENANT_IMAGE_PULL_SECRET_NAME was renamed;
                // still labeled, no longer referenced by the workload.
                fake_managed_secret("pull-secret-old-name", true, "cap-bot", "ghp_old_token"),
            ],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth", "pull-secret-old-name"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());

        // In-scope with the old name still referenced: kept until redeploy.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            true,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.secrets.len(),
                2,
                "referenced old secret stays in scope"
            );
        }

        // Post-redeploy: the workload now references only the new name. The
        // unreferenced old secret is removed by name-independent discovery.
        cluster.lock().unwrap().service_accounts[0].image_pull_secrets =
            Some(vec![k8s_openapi::api::core::v1::LocalObjectReference {
                name: "enclava-registry-auth".to_string(),
            }]);
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            true,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        {
            let state = cluster.lock().unwrap();
            assert_eq!(state.secrets.len(), 1);
            assert_eq!(
                state.secrets[0].metadata.name.as_deref(),
                Some("enclava-registry-auth")
            );
        }

        // Out of scope: the referenced old secret is removed together with
        // its reference, while the current name is removed too.
        cluster.lock().unwrap().secrets.push(fake_managed_secret(
            "pull-secret-old-name",
            true,
            "cap-bot",
            "ghp_old_token",
        ));
        cluster.lock().unwrap().service_accounts[0].image_pull_secrets = Some(vec![
            k8s_openapi::api::core::v1::LocalObjectReference {
                name: "enclava-registry-auth".to_string(),
            },
            k8s_openapi::api::core::v1::LocalObjectReference {
                name: "pull-secret-old-name".to_string(),
            },
        ]);
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        {
            let state = cluster.lock().unwrap();
            assert!(state.secrets.is_empty(), "out-of-scope secrets are removed");
            assert!(
                state.service_accounts[0].image_pull_secrets.is_none(),
                "managed references are cleared out of scope"
            );
        }
    }

    /// Codex review on #243 (P1, "adopt legacy secrets before skipping
    /// in-scope namespaces"): in an in-scope namespace a pre-label secret is
    /// adopted (labeled) while its credentials still prove the generated
    /// shape — before any in-scope skip — so the documented upgrade-then-
    /// rotate sequence cannot orphan it when the GHCR token is later rotated.
    #[tokio::test]
    async fn reconcile_adopts_kept_legacy_secrets_in_scope() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![
                // Pre-label (unlabeled) legacy secret whose shape matches the
                // configured GHCR pair.
                fake_managed_secret("enclava-registry-auth", false, "cap-bot", "ghp_platform"),
            ],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            true,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        let labels = state.secrets[0].metadata.labels.as_ref().unwrap();
        assert_eq!(
            labels.get(TENANT_PULL_SECRET_LABEL).map(String::as_str),
            Some(TENANT_PULL_SECRET_LABEL_VALUE),
            "kept legacy secret must carry the dedicated pull-secret label (discovery marker)"
        );
        assert_eq!(
            labels.get(MANAGED_BY_LABEL).map(String::as_str),
            Some(MANAGED_BY_VALUE),
            "kept legacy secret must carry the managed-by ownership label"
        );
    }

    /// A tenant's own replacement secret under the managed name: a distinct
    /// object (own UID/resourceVersion) with the tenant's credentials.
    fn fake_replacement_secret(name: &str) -> Secret {
        let mut secret = fake_managed_secret(name, false, "tenant-user", "tenant-token");
        secret.metadata.uid = Some(format!("uid-replacement-{name}"));
        secret.metadata.resource_version = Some("42".to_string());
        secret
    }

    /// Devin review on #243 (BUG_…​_0001): a tenant that replaces the managed
    /// pull secret after the cleanup's ownership read must keep both the
    /// replacement and its ServiceAccount reference. The replacement lands in
    /// the exact reviewed window — between the first Secret GET and the
    /// ServiceAccount patch — and the delete that later detects it must
    /// reverse the reference clear so the replacement's pods keep registry
    /// access.
    #[tokio::test]
    async fn reconcile_restores_reference_when_secret_replaced_mid_cleanup() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The tenant swaps in their own secret right as the reference
            // clear is written.
            replace_on_sa_patch: Some(fake_replacement_secret("enclava-registry-auth")),
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets[0].metadata.uid.as_deref(),
            Some("uid-replacement-enclava-registry-auth"),
            "the tenant replacement must survive"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the replacement keeps the ServiceAccount reference it inherits by name"
        );
    }

    /// Devin review on #243 (BUG_…​_0001), second window: a replacement that
    /// lands between the delete's ownership read and the delete itself must
    /// survive — the delete is pinned to the verified object's
    /// UID/resourceVersion — and its ServiceAccount reference must survive
    /// with it.
    #[tokio::test]
    async fn reconcile_never_deletes_a_replacement_that_lands_at_delete_time() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            replace_on_delete: Some(fake_replacement_secret("enclava-registry-auth")),
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets[0].metadata.uid.as_deref(),
            Some("uid-replacement-enclava-registry-auth"),
            "the pinned delete must conflict instead of deleting the replacement"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the cleared reference must be restored for the replacement"
        );
    }

    /// Codex review on #243 (P2, "require the pull-secret label before
    /// treating secrets as owned"): the generic managed-by label is used
    /// broadly across platform resources and must not make an arbitrary
    /// Secret fair game for this cleanup. Ownership requires the dedicated
    /// pull-secret label or the legacy credential-shape proof — a
    /// generically-labeled secret with foreign contents at the managed name
    /// is tenant/operator-owned and must keep itself and its reference.
    #[tokio::test]
    async fn reconcile_keeps_generic_managed_by_look_alike() {
        use std::sync::{Arc, Mutex};

        let mut secret = fake_managed_secret(
            "enclava-registry-auth",
            false,
            "tenant-user",
            "tenant-token",
        );
        secret.metadata.labels = Some(std::collections::BTreeMap::from([(
            MANAGED_BY_LABEL.to_string(),
            MANAGED_BY_VALUE.to_string(),
        )]));
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![secret],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "a generic-managed-by look-alike is not CAP's pull secret"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the generic-managed-by look-alike keeps its ServiceAccount reference"
        );
    }

    /// Codex review on #243 (P1, "treat missing tenant namespaces as an
    /// already-clean sweep"): an app row can exist before its namespace is
    /// created, or outlive the namespace after deletion, and the namespaced
    /// Secret list then 404s. The sweep must treat that as "no stale
    /// secrets" — a failure here would keep workload admission closed and
    /// the dispatcher unspawned while the very pending setup/cleanup work
    /// that would create the namespace or remove the row can never run, and
    /// the background retry would loop on the same 404 forever.
    #[tokio::test]
    async fn reconcile_treats_missing_namespace_as_clean() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            namespace_missing: true,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            converged,
            "a missing namespace is an already-clean sweep, not a failure"
        );
    }

    /// Self-check blocking finding on #243 ("a delete conflict is treated as
    /// a clean removal"): Kubernetes 409s both for a replaced object and for
    /// the SAME managed secret merely updated between the ownership read and
    /// the pinned delete. A same-object conflict must be retried — the secret
    /// is still CAP's — and the sweep must still converge and remove the
    /// token once the concurrent writer settles.
    #[tokio::test(start_paused = true)]
    async fn delete_retries_same_object_conflicts_until_the_writer_settles() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // A concurrent writer updates the SAME managed secret before each
            // of the first two delete attempts; the third attempt settles.
            rv_bumps_on_delete: 2,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        )
        .await
        .unwrap();
        assert!(
            converged,
            "a same-object resourceVersion conflict is retried, not reported as a replacement"
        );

        let state = cluster.lock().unwrap();
        assert!(
            state.secrets.is_empty(),
            "the managed secret must be removed once the writer settles"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len())
                .unwrap_or(0),
            0,
            "a converged removal keeps the ServiceAccount reference cleared"
        );
    }

    /// The complement of the retry case: when the same managed secret keeps
    /// changing under the delete and the bounded retries never settle, the
    /// sweep must NOT report a clean removal (that is what let admission open
    /// while the platform PAT stayed out), the error path must restore the
    /// cleared references, and the live object must survive untouched.
    #[tokio::test(start_paused = true)]
    async fn persistent_same_object_conflicts_stay_closed_and_restore_references() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The writer never settles: every one of the bounded retry
            // budget's attempts conflicts (u8::MAX outlasts the budget).
            rv_bumps_on_delete: u8::MAX,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            !converged,
            "a sweep that cannot delete the managed secret must not report success"
        );

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "the managed secret must survive the conflicting deletes"
        );
        assert_eq!(
            state.secrets[0].metadata.uid.as_deref(),
            Some("uid-enclava-registry-auth"),
            "no attempt may have deleted or replaced the object"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            None,
            "ambiguous delete leaves the reference cleared until the next sweep"
        );
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]).len(),
            1
        );
    }

    /// Codex review on #243 (P2, "defer secret deletion when reference
    /// cleanup fails"): a failed ServiceAccount patch must defer the Secret
    /// delete — deleting it anyway would strand a dangling
    /// `imagePullSecrets` reference the next sweep can no longer discover.
    /// The pass reports non-convergence, the secret survives, and its
    /// reference stays attached.
    #[tokio::test]
    async fn reconcile_defers_delete_when_reference_cleanup_fails() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            sa_patch_fails: true,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            !converged,
            "a failed reference cleanup must keep the pass unconverged"
        );

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "the secret must survive so the reference cleanup can be retried"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "no dangling reference: the failed patch left the reference in place"
        );
    }

    /// Codex review on #243 (P1, Devin SEC — "fence background cleanup
    /// against concurrent deploys"): a sweep whose app-inventory snapshot
    /// predates a deploy must not delete the pull secret that deploy applied.
    /// The secret carries a mutation-generation annotation newer than the
    /// generation the sweep snapshotted before its inventory read; the
    /// reconcile pass skips it together with its ServiceAccount references.
    #[tokio::test]
    async fn sweep_skips_secrets_from_newer_mutation_generations() {
        use std::sync::{Arc, Mutex};

        let mut secret =
            fake_managed_secret("enclava-registry-auth", true, "cap-bot", "ghp_platform");
        secret.metadata.annotations = Some(std::collections::BTreeMap::from([(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            "7".to_string(),
        )]));
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![secret],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        // The sweep snapshotted generation 5; the live secret carries 7 — a
        // deploy the sweep's inventory never saw. Out-of-scope inventory, but
        // the newer generation wins.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 5,
            },
        )
        .await
        .unwrap();
        assert!(converged, "skipping a newer-generation secret is converged");

        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.secrets.len(),
                1,
                "a secret applied by a newer mutation generation must survive the stale sweep"
            );
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map(|references| references.len()),
                Some(1),
                "its ServiceAccount reference must survive with it"
            );
        }

        // A sweep whose snapshot INCLUDES that generation (snapshot >= 7)
        // proceeds with the removal — the fence only protects secrets newer
        // than the snapshot.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 7,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        let state = cluster.lock().unwrap();
        assert!(
            state.secrets.is_empty(),
            "once the snapshot includes the generation, the stale secret is removed"
        );
    }

    /// Self-check on #243: a deploy rewrites the managed secret under a NEWER
    /// mutation generation AFTER the reconcile-time skip check — the rewrite
    /// that causes the delete's 409. The delete-loop re-read must keep the
    /// rewritten secret and restore the already-cleared ServiceAccount
    /// reference instead of deleting it.
    #[tokio::test(start_paused = true)]
    async fn delete_keeps_secret_rewritten_under_newer_generation_mid_cleanup() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The rewrite lands on the FIRST delete attempt: the pinned
            // delete conflicts, and the retry's re-read sees generation 9 —
            // newer than the sweep's snapshot of 5.
            annotate_generation_on_delete: Some(9),
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 5,
            },
        )
        .await
        .unwrap();
        assert!(
            converged,
            "keeping a concurrently rewritten secret is a converged skip"
        );

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "a secret rewritten under a newer mutation generation mid-cleanup must survive"
        );
        assert_eq!(
            state.secrets[0]
                .metadata
                .annotations
                .as_ref()
                .and_then(|annotations| {
                    annotations
                        .get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
                })
                .map(String::as_str),
            Some("9"),
            "the surviving object is the deploy's rewrite, not the original"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            Some(1),
            "the cleared ServiceAccount reference must be restored for the rewrite"
        );
    }

    /// Codex review on #243 (P2, "wait for Secret deletion to converge"): an
    /// accepted DELETE with a finalizer keeps the Secret readable with a
    /// deletionTimestamp. The removal must wait for the actual 404 (bounded),
    /// and only then report Deleted — the ServiceAccount references stay
    /// cleared because the token is provably gone.
    #[tokio::test(start_paused = true)]
    async fn delete_waits_for_finalizer_to_release_the_secret() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The finalizer holds the terminating secret for two polls, then
            // releases it.
            delete_lingering_polls: 2,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            converged,
            "a finalizer that releases within the poll budget converges"
        );

        let state = cluster.lock().unwrap();
        assert!(
            state.secrets.is_empty(),
            "Deleted may only be reported once the secret is actually gone"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len())
                .unwrap_or(0),
            0,
            "references stay cleared once removal provably converged"
        );
    }

    /// Codex review on #243 (P2), stuck-finalizer complement: when the
    /// terminating Secret never disappears within the bounded poll deadline,
    /// the removal must report failure (not Deleted), the pass stays
    /// unconverged, and the cleared ServiceAccount references are restored so
    /// the still-readable secret stays attached while the sweep retries.
    #[tokio::test(start_paused = true)]
    async fn stuck_finalizer_keeps_the_sweep_unconverged_and_restores_references() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The finalizer never releases the terminating secret.
            delete_lingering_polls: u8::MAX,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            !converged,
            "a stuck finalizer must keep the sweep unconverged (PAT still readable)"
        );

        let state = cluster.lock().unwrap();
        assert_eq!(
            state.secrets.len(),
            1,
            "the terminating-but-present secret is still in the fake cluster"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map(|references| references.len()),
            None,
            "ambiguous finalizer delay leaves the reference cleared with repair intent"
        );
        assert_eq!(
            pending_reference_repairs(&state.service_accounts[0]).len(),
            1
        );
    }

    #[test]
    fn newer_rotation_generation_fences_stale_replica_refresh() {
        let mut secret = fake_managed_secret("enclava-registry-auth", true, "cap-bot", "new-token");
        secret
            .metadata
            .annotations
            .get_or_insert_with(Default::default)
            .insert(
                PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION.to_string(),
                "18446744073709551615".to_string(),
            );
        assert!(newer_pull_secret_credentials(&secret));
    }

    /// Codex review on #243 (P1, "refresh kept pull secrets after credential
    /// rotation"): a labeled configured-name secret in an in-scope namespace
    /// still carrying the PRE-rotation platform PAT is reconciled to the
    /// current GHCR pair — no redeploy needed — and a secret already carrying
    /// the current pair is left byte-identical (idempotence).
    #[tokio::test]
    async fn reconcile_refreshes_rotated_credentials_of_kept_configured_secret() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_stale_pre_rotation_token",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            true,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);

        let assert_live_token = |token: &str| {
            let state = cluster.lock().unwrap();
            assert_eq!(state.secrets.len(), 1, "the kept secret survives");
            let payload = &state.secrets[0]
                .data
                .as_ref()
                .unwrap()
                .get(".dockerconfigjson")
                .unwrap()
                .0;
            let config: serde_json::Value = serde_json::from_slice(payload).unwrap();
            assert_eq!(
                config
                    .pointer("/auths/ghcr.io/password")
                    .and_then(|v| v.as_str()),
                Some(token),
                "the live secret must carry the expected credential"
            );
            assert_eq!(
                config
                    .pointer("/auths/ghcr.io/username")
                    .and_then(|v| v.as_str()),
                Some("cap-bot")
            );
        };

        // The rotation reached the namespace without a redeploy.
        assert_live_token("ghp_platform");

        // Idempotence: a second pass finds the current pair and rewrites
        // nothing (still converged, still the current pair).
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            true,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        assert_live_token("ghp_platform");
    }

    /// Codex review on #243 (P1, follow-up "let oversized cleanup sweeps make
    /// forward progress"): one namespace's stalled reconciliation consumes its
    /// own per-namespace budget and is reported unconverged — a bounded
    /// failure, not a cancelled sweep — and once the API server recovers the
    /// next attempt reconciles the same namespace to convergence. Every
    /// namespace is visited on every attempt, so the tail can no longer be
    /// starved by a slow head.
    #[tokio::test(start_paused = true)]
    async fn stalled_namespace_is_bounded_and_the_next_attempt_recovers() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            stall_secrets_list: true,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());

        // The stalled list hangs far beyond the per-namespace budget: the
        // budget converts the hang into "this namespace not converged".
        let converged = sweep_namespace_with_budget(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            !converged,
            "a stalled namespace is reported unconverged, not left hanging"
        );

        // Recovery: the API server answers again and the same namespace
        // reconciles — the sweep retries per namespace instead of restarting
        // a doomed whole pass forever.
        cluster.lock().unwrap().stall_secrets_list = false;
        let converged = sweep_namespace_with_budget(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        let state = cluster.lock().unwrap();
        assert!(
            state.secrets.is_empty(),
            "the recovered attempt completes the removal"
        );
    }

    /// Codex review on #243 (P2, "persist failed pull-secret reference
    /// restorations"): the reference clear writes durable repair intent onto
    /// the ServiceAccount; when the delete then discovers a tenant
    /// replacement AND the restoration fails transiently, the pass is
    /// unconverged — and the NEXT pass still knows about the cleared
    /// reference, restores it onto the surviving replacement, and discharges
    /// the intent. Convergence is only reported once the ServiceAccount is
    /// re-attached (the exact detachment the finding described).
    #[tokio::test]
    async fn failed_reference_restore_is_repaired_by_the_next_pass() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // The tenant swaps in their own secret as the delete lands…
            replace_on_delete: Some(fake_replacement_secret("enclava-registry-auth")),
            // …and the first restoration attempt fails transiently.
            fail_reference_restores: 1,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());

        // Pass 1: clear ok (+ intent recorded), delete sees the replacement,
        // restore 500s — unconverged, but the intent is on the SA.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(!converged, "the failed restore keeps the pass unconverged");
        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.secrets[0].metadata.uid.as_deref(),
                Some("uid-replacement-enclava-registry-auth"),
                "the tenant replacement survived the delete"
            );
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map_or(0, |references| references.len()),
                0,
                "the reference is still cleared after the failed restore"
            );
            assert_eq!(
                pending_reference_repairs(&state.service_accounts[0]),
                vec![PendingReferenceRepair {
                    secret_name: "enclava-registry-auth".to_string(),
                    cleared_uid: Some("uid-enclava-registry-auth".to_string()),
                }],
                "the durable repair intent (with the cleared object's UID) survived the failed \
                 restore"
            );
        }

        // Pass 2: the repair pass restores the reference onto the surviving
        // replacement (unmanaged — invisible to the removal loop) and
        // discharges the intent; only then is the namespace converged.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);
        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map(|references| references.len()),
                Some(1),
                "the replacement keeps the ServiceAccount reference it inherits by name"
            );
            assert!(
                pending_reference_repairs(&state.service_accounts[0]).is_empty(),
                "the repair intent is discharged once the reference is restored"
            );
        }
    }

    /// Complement of the repair-intent test (Codex review on #243, P2): when
    /// a removal completes (`Deleted`), the cleared references are final and
    /// their repair intent must be discharged in the same pass — a completed
    /// cleanup leaves no pending-repair annotations behind.
    #[tokio::test]
    async fn completed_removals_discharge_their_repair_intent() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(converged);

        let state = cluster.lock().unwrap();
        assert!(state.secrets.is_empty(), "the managed secret is removed");
        assert!(
            state.service_accounts[0].image_pull_secrets.is_none(),
            "the reference stays cleared after a completed removal"
        );
        assert!(
            pending_reference_repairs(&state.service_accounts[0]).is_empty(),
            "a completed removal discharges its durable repair intent"
        );
    }

    /// Reviewer follow-up on #243 (Critical): the repair pass must complete an
    /// UNFINISHED verified removal instead of re-attaching the reference.
    /// After a GHCR rotation the unlabeled old-PAT secret no longer matches
    /// the legacy credential shape, so discovery cannot recognize it — only
    /// the UID recorded with the repair intent proves which object was being
    /// removed. The pass must delete that exact object (UID-pinned, never
    /// re-attached) and only then converge.
    #[tokio::test(start_paused = true)]
    async fn repair_intent_completes_an_unfinished_removal_after_credential_rotation() {
        use std::sync::{Arc, Mutex};

        let cluster = Arc::new(Mutex::new(FakeCluster {
            // UNLABELED pre-label secret whose shape matches the pass-1
            // credentials — discoverable as managed only while they match.
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                false,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![fake_service_account(
                "cap-tenant-app",
                &["enclava-registry-auth"],
            )],
            // Every delete attempt of the bounded budget conflicts, so the
            // removal errors out…
            rv_bumps_on_delete: 64,
            // …and the reverse restore fails once, leaving the intent on the
            // ServiceAccount with the reference cleared.
            fail_reference_restores: 1,
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());

        // Pass 1 (out of scope, credentials still prove the legacy shape):
        // clear ok, delete never converges, restore fails — unconverged with
        // durable intent recorded against the verified object's UID.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(!converged);
        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map_or(0, |references| references.len()),
                0,
                "the reference is cleared"
            );
            assert_eq!(
                pending_reference_repairs(&state.service_accounts[0]),
                vec![PendingReferenceRepair {
                    secret_name: "enclava-registry-auth".to_string(),
                    cleared_uid: Some("uid-enclava-registry-auth".to_string()),
                }],
                "the intent records the cleared object's UID"
            );
        }

        // Pass 2 after the GHCR rotation: the legacy shape no longer matches,
        // the secret is invisible to discovery, and the writer settled. Only
        // the recorded UID proves the pending verified removal — the repair
        // pass must COMPLETE it, never re-attach the old platform PAT.
        let rotated = PullSecretSettings {
            configured_name: "enclava-registry-auth".to_string(),
            ghcr_credentials: Some(("cap-bot".to_string(), "ghp_rotated".to_string())),
            configured_secret_data: Some(expected_dockerconfigjson("cap-bot", "ghp_rotated")),
        };
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &rotated,
            false,
            PullSecretDeleteMode::Unfenced {
                namespace_generation: 0,
            },
        )
        .await
        .unwrap();
        assert!(
            converged,
            "completing the UID-proven removal converges the namespace"
        );
        {
            let state = cluster.lock().unwrap();
            assert!(
                state.secrets.is_empty(),
                "the old-PAT secret must be deleted by its recorded UID, not kept"
            );
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map_or(0, |references| references.len()),
                0,
                "the reference stays cleared — the old PAT is never re-attached"
            );
            assert!(
                pending_reference_repairs(&state.service_accounts[0]).is_empty(),
                "the completed removal discharges its intent"
            );
        }
    }

    #[tokio::test]
    async fn expanded_scope_cancels_pending_same_uid_removal() {
        use std::sync::{Arc, Mutex};
        let mut account = fake_service_account("cap-tenant-app", &[]);
        account.metadata.annotations = Some(std::collections::BTreeMap::from([(
            PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
            "enclava-registry-auth=uid-enclava-registry-auth".to_string(),
        )]));
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_managed_secret(
                "enclava-registry-auth",
                true,
                "cap-bot",
                "ghp_platform",
            )],
            service_accounts: vec![account],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());
        assert!(
            reconcile_managed_pull_secrets(
                &engine,
                "tenant-ns",
                &["cap-tenant-app".to_string()],
                &reconcile_settings(),
                true,
                PullSecretDeleteMode::Unfenced {
                    namespace_generation: 0
                },
            )
            .await
            .unwrap()
        );
        let state = cluster.lock().unwrap();
        assert_eq!(state.secrets.len(), 1);
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .unwrap()[0]
                .name,
            "enclava-registry-auth"
        );
        assert!(pending_reference_repairs(&state.service_accounts[0]).is_empty());
    }

    /// Reviewer follow-up on #243 (Critical): the per-deploy reconcile (the
    /// Fenced path) must NOT run the repair pass — its own SSA of the
    /// generated ServiceAccount is about to re-decide `imagePullSecrets`, so
    /// an up-front restore would be pruned and the record lost. Instead the
    /// deploy discharges stale intents after its applies.
    #[tokio::test]
    async fn deploy_reconcile_skips_repair_and_discharges_stale_intent_after_apply() {
        use std::sync::{Arc, Mutex};

        // A stale intent from an earlier sweep: a replacement lives under the
        // name (a sweep would restore the reference), and the recorded UID
        // no longer matches anything.
        let mut stale_intent = fake_service_account("cap-tenant-app", &[]);
        stale_intent.metadata.annotations = Some(std::collections::BTreeMap::from([(
            PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
            "enclava-registry-auth=uid-long-gone".to_string(),
        )]));
        let cluster = Arc::new(Mutex::new(FakeCluster {
            secrets: vec![fake_replacement_secret("enclava-registry-auth")],
            service_accounts: vec![stale_intent],
            ..Default::default()
        }));
        let engine = reconcile_engine(cluster.clone());

        // The deploy-path reconcile (Fenced) neither restores the reference
        // nor touches the intent.
        let converged = reconcile_managed_pull_secrets(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
            &reconcile_settings(),
            false,
            PullSecretDeleteMode::Fenced(MutationGeneration::new(1).unwrap()),
        )
        .await
        .unwrap();
        assert!(converged);
        {
            let state = cluster.lock().unwrap();
            assert_eq!(
                state.service_accounts[0]
                    .image_pull_secrets
                    .as_ref()
                    .map_or(0, |references| references.len()),
                0,
                "the deploy-path reconcile must not restore ahead of its own ServiceAccount apply"
            );
            assert_eq!(
                pending_reference_repairs(&state.service_accounts[0]).len(),
                1,
                "the deploy-path reconcile leaves the intent to the post-apply discharge"
            );
        }

        // After the deploy's applies, the intent is discharged: this deploy
        // re-decided the ServiceAccount's imagePullSecrets.
        discharge_reference_repair_intent_after_deploy(
            &engine,
            "tenant-ns",
            &["cap-tenant-app".to_string()],
        )
        .await
        .unwrap();
        let state = cluster.lock().unwrap();
        assert!(
            pending_reference_repairs(&state.service_accounts[0]).is_empty(),
            "the deploy's post-apply discharge clears the stale intent"
        );
        assert_eq!(
            state.service_accounts[0]
                .image_pull_secrets
                .as_ref()
                .map_or(0, |references| references.len()),
            0,
            "the deploy's decision stands: no reference"
        );
    }
}

/// Project a worker's deployment status transition. Two evidence-preserving
/// quirks (devin 🔴 round-6 follow-up): the `watching` transition stamps
/// `observing_since` as the observation anchor, AND a transition AWAY from a
/// `watching` row keeps that stamp — the legacy re-apply path (a pre-0047
/// watched row has NULL `observing_since`; `claim_rollout_observation` cannot
/// resume it and re-applies) demotes `watching` -> `applying` here, and that
/// demotion is the moment the row proves it already served a watched
/// generation. Without the stamp the later failure publisher would see a
/// NULL-`observing_since` partial apply and arm retryable cleanup whose sweep
/// can then remove the routes and namespace under the still-live workload.
pub async fn set_deployment_status(
    pool: &PgPool,
    deployment_id: Uuid,
    status: &str,
    manifest_hash: Option<&str>,
    error_message: Option<&str>,
    terminal: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE deployments
         SET status = $1::deploy_status_enum,
             manifest_hash = COALESCE($2, manifest_hash),
             error_message = $3,
             completed_at = CASE WHEN $4 THEN now() ELSE completed_at END,
             observing_since = CASE
                 WHEN $1 = 'watching' OR status = 'watching'
                     THEN COALESCE(observing_since, clock_timestamp())
                 ELSE observing_since
             END,
             apply_started_at = CASE
                 WHEN $1 = 'applying' THEN COALESCE(apply_started_at, clock_timestamp())
                 ELSE apply_started_at
             END
         WHERE id = $5",
    )
    .bind(status)
    .bind(manifest_hash)
    .bind(persisted_deployment_error(error_message))
    .bind(terminal)
    .bind(deployment_id)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn set_app_status(pool: &PgPool, app_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
    // This is a nonterminal worker projection, not a change to accepted app
    // authority. Advancing updated_at here would make a reclaimed durable job
    // reject its own immutable payload after a crash between apply phases.
    sqlx::query("UPDATE apps SET status = $1::app_status_enum WHERE id = $2")
        .bind(status)
        .bind(app_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Whether a domain-triggered tenant-ingress restart may proceed.
///
/// `NotDeployed`: the workload StatefulSet does not exist yet, so there is
/// nothing to restart — the caller keeps the DNS-only predeploy path.
///
/// `Ready`: a live StatefulSet exists and both persistent claims are proven
/// initialized by the exact live Ready ordinal-0 pod, so the restart only
/// re-opens finished volumes under the base rollout deadline.
///
/// `Unproven`: a live StatefulSet exists but at least one claim is missing,
/// terminating, or not proven initialized — restarting could kill a still
/// formatting first-boot pod or strand a fresh claim under the base wait,
/// so the caller must conflict before any domain effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRestartVerdict {
    NotDeployed,
    Ready,
    Unproven,
}

/// Probe live Kubernetes state before a domain mutation may restart the
/// workload pod. Deployment-row status is NOT consulted: 'failed'/'healthy'
/// rows cannot prove a first-boot formatter is finished, so only the shared
/// live-proof inspector admits the restart. Lookup errors propagate (fail
/// closed) and never admit.
pub async fn ingress_restart_verdict(
    engine: &ApplyEngine,
    namespace: &str,
    workload: &str,
) -> Result<IngressRestartVerdict, DeployError> {
    if !statefulset_exists(engine, namespace, workload).await? {
        return Ok(IngressRestartVerdict::NotDeployed);
    }
    let fresh = enclava_engine::apply::orchestrator::inspect_fresh_volume_claims(
        engine,
        namespace,
        workload,
        enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
    )
    .await
    .map_err(DeployError::Apply)?;
    if fresh.app_data || fresh.tls_data {
        Ok(IngressRestartVerdict::Unproven)
    } else {
        Ok(IngressRestartVerdict::Ready)
    }
}

/// Re-render and SSA-apply only the tenant-ingress ConfigMap for an app.
///
/// Used when domain-only state changes (e.g. a custom-domain verification)
/// must reach the running pod's Caddyfile without a full redeploy. Caddy
/// inside the pod runs `caddy run` with no live config-watch sidecar, so this
/// function applies the new Caddyfile, triggers a StatefulSet rollout restart,
/// and waits for the replacement pod to become ready before returning.
///
/// Callers MUST obtain `IngressRestartVerdict::Ready` (or `NotDeployed` for
/// the DNS-only path) from [`ingress_restart_verdict`] before invoking this:
/// it does not re-check initialization, and the rollout wait below assumes
/// the restart only re-opens already-initialized volumes.
///
/// Returns `DeployError::NotDeployed` when the app has no live StatefulSet yet.
pub async fn reapply_tenant_ingress(
    pool: &PgPool,
    app: &App,
    attestation_config: Option<&AttestationConfig>,
    api_signing_pubkey: &str,
    api_url: &str,
    mutation: &crate::mutation_leases::AppMutationLease,
    kubernetes_mutation_generation: i64,
) -> Result<(), DeployError> {
    let Some(attestation_config) = attestation_config else {
        return Err(DeployError::MissingAttestationConfig);
    };

    let deployment_id = latest_deployment_id_for_app(pool, app.id).await?;
    let app_spec = build_confidential_app(
        pool,
        app,
        deployment_id,
        attestation_config,
        api_signing_pubkey,
        api_url,
    )
    .await?;
    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    let cm = enclava_engine::manifest::ingress::generate_ingress_configmap(&app_spec);

    let engine = ApplyEngine::try_default().await?;
    // Domain-only reapply: the pod restart re-opens existing volumes, so the
    // base rollout budget applies — the fresh-initialization allowance is
    // reserved for renders that provision a new claim.
    let rollout_timeout = engine.config().rollout_timeout;
    ensure_statefulset_exists(&engine, &app_spec.namespace, &app_spec.name).await?;
    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    enclava_engine::apply::resources::apply_namespaced_resource(
        &engine,
        &app_spec.namespace,
        &cm,
        generation,
    )
    .await?;
    restart_statefulset_for_ingress(&engine, &app_spec.namespace, &app_spec.name, generation)
        .await?;

    let status = watch_rollout(
        &engine,
        &app_spec.namespace,
        &app_spec.name,
        rollout_timeout,
    )
    .await?;
    if status.phase != DeployPhase::Running {
        return Err(enclava_engine::apply::engine::ApplyError::RolloutFailed(
            status
                .message
                .unwrap_or_else(|| format!("tenant ingress rollout ended in {:?}", status.phase)),
        )
        .into());
    }

    Ok(())
}

async fn statefulset_exists(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<bool, DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match api.get(name).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(false),
        Err(e) => Err(enclava_engine::apply::engine::ApplyError::Kube(e).into()),
    }
}

/// Probe under the app deployment lane: terminal SQL rows cannot prove a
/// Kubernetes controller stopped replacing the TEE. `None` means no live
/// workload exists, so recovery must not wait for config delivery to it.
pub async fn workload_rollout_settled(
    engine: &ApplyEngine,
    namespace: &str,
    workload_name: &str,
) -> Result<Option<bool>, DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    match api.get(workload_name).await {
        Ok(sts)
            if sts
                .spec
                .as_ref()
                .and_then(|spec| spec.replicas)
                .unwrap_or(1)
                <= 0 =>
        {
            Ok(None)
        }
        Ok(sts) => Ok(Some(statefulset_rollout_settled(&sts))),
        Err(kube::Error::Api(ae)) if ae.code == 404 => Ok(None),
        Err(e) => Err(enclava_engine::apply::engine::ApplyError::Kube(e).into()),
    }
}

/// Whether a live StatefulSet is fully converged: the controller has
/// observed the current generation and every replica matches the latest
/// spec. Anything less means the cluster may still replace the workload's
/// pod — including past any SQL settling window, because a controller never
/// abandons an applied generation. A scaled-down workload (`desired == 0`)
/// has no TEE that could be replaced.
pub fn statefulset_rollout_settled(sts: &k8s_openapi::api::apps::v1::StatefulSet) -> bool {
    let status = sts.status.as_ref();
    let generation = sts.metadata.generation.unwrap_or(0);
    let observed_generation = status.and_then(|s| s.observed_generation).unwrap_or(0);
    let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
    let ready = status.and_then(|s| s.ready_replicas).unwrap_or(0);
    let current = status.and_then(|s| s.current_replicas).unwrap_or(0);
    let updated = status.and_then(|s| s.updated_replicas).unwrap_or(0);
    if desired <= 0 {
        return true;
    }
    observed_generation >= generation
        && ready >= desired
        && current >= desired
        && updated >= desired
}

async fn ensure_statefulset_exists(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
) -> Result<(), DeployError> {
    if statefulset_exists(engine, namespace, name).await? {
        Ok(())
    } else {
        Err(DeployError::NotDeployed(format!(
            "StatefulSet {namespace}/{name} not found"
        )))
    }
}

async fn restart_statefulset_for_ingress(
    engine: &ApplyEngine,
    namespace: &str,
    name: &str,
    generation: MutationGeneration,
) -> Result<(), DeployError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use kube::Api;

    let api: Api<StatefulSet> = Api::namespaced(engine.client().clone(), namespace);
    let patch = serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "cap.enclava.dev/tenant-ingress-restarted-at": chrono::Utc::now().to_rfc3339(),
                    }
                }
            }
        }
    });
    enclava_engine::apply::generation::apply_existing_partial(
        &api,
        name,
        &patch,
        generation,
        &engine.config().field_manager,
    )
    .await?;

    tracing::info!(
        namespace = %namespace,
        statefulset = %name,
        "triggered tenant ingress rollout restart"
    );

    Ok(())
}

/// One rollout-observation slice. A durable watcher owns no mutation fence, so
/// this bound is also the maximum time a waiting workload keeps a worker slot
/// before the job is released for the next dispatch.
const ROLLOUT_OBSERVATION_SLICE: std::time::Duration = std::time::Duration::from_secs(90);

/// A rollout handle returned after Kubernetes accepted the rendered manifests.
///
/// Callers must await [`DeploymentRollout::watch`]. Durable deployment workers
/// publish each observed outcome under their job lease, so a replacement API
/// process resumes observation after a crash without re-applying manifests.
pub struct DeploymentRollout {
    app: App,
    engine: ApplyEngine,
    namespace: String,
    workload_name: String,
    pub(crate) manifest_hash: String,
    observing_since: chrono::DateTime<chrono::Utc>,
    observation_slice: std::time::Duration,
    /// Cumulative budget recorded by the watching transition. Resumed
    /// observers reuse this value verbatim rather than recomputing it from
    /// changing live cluster state.
    pub(crate) rollout_timeout: std::time::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentRolloutOutcome {
    pub deploy_status: &'static str,
    pub app_status: &'static str,
    pub error_code: Option<&'static str>,
    pub terminal: bool,
    pub manifest_hash: String,
}

impl DeploymentRollout {
    /// Read-only rollout observer for a generation whose durable deployment
    /// row is already `watching`. It shares the recorded manifest hash, the
    /// anchored observation window, and the `rollout_timeout` budget that was
    /// computed once before this generation's first provider apply and
    /// persisted with the watching transition — resumed observation never
    /// recomputes it from changing live pod or volume state. Performs no
    /// provider mutation.
    pub(crate) fn observe_only(
        app: App,
        engine: ApplyEngine,
        manifest_hash: String,
        observing_since: chrono::DateTime<chrono::Utc>,
        rollout_timeout: std::time::Duration,
    ) -> Result<Self, DeployError> {
        let namespace = app.namespace.clone();
        let workload_name = app.name.clone();
        Ok(Self {
            app,
            engine,
            namespace,
            workload_name,
            manifest_hash,
            observing_since,
            observation_slice: ROLLOUT_OBSERVATION_SLICE,
            rollout_timeout,
        })
    }

    #[cfg(test)]
    fn with_observation_slice(mut self, slice: std::time::Duration) -> Self {
        self.observation_slice = slice;
        self
    }

    /// Observe Kubernetes only, in one bounded slice. The durable job owner
    /// publishes this outcome after atomically revalidating its lease. When
    /// the slice elapses while cumulative rollout budget remains, the outcome
    /// is a nonterminal `watching` so the worker releases its slot and the
    /// job resumes observation on the next dispatch. The total
    /// `rollout_timeout` is anchored at `observing_since`, so restarted
    /// observation cannot extend a rollout deadline forever.
    pub async fn watch(self) -> DeploymentRolloutOutcome {
        // `self.app` is the snapshot frozen into the job payload at accept
        // time. `apply_deployment_manifests` has already persisted status
        // "creating" for this rollout, so a pre-existing terminal "failed"
        // must not drive classification: a redeployed failed app is creating
        // again, and password-mode owner wait must stay nonterminal rather
        // than terminalizing on the stale snapshot.
        let previous_app_status = match self.app.status {
            AppStatus::Failed => AppStatus::Creating,
            status => status,
        };
        let unlock_mode = self.app.unlock_mode;
        let total = self.rollout_timeout;
        let elapsed = chrono::Utc::now()
            .signed_duration_since(self.observing_since)
            .to_std()
            .unwrap_or(std::time::Duration::ZERO);
        let remaining = total.saturating_sub(elapsed);
        // Owner wait is deliberately nonterminal. Keep observing after its
        // initial budget expires so a later unlock can still become healthy.
        let owner_wait = unlock_mode == crate::models::UnlockMode::Password
            && previous_app_status == AppStatus::Creating;
        let slice = if owner_wait && remaining.is_zero() {
            self.observation_slice
        } else {
            remaining.min(self.observation_slice)
        };
        let result = match tokio::time::timeout(
            slice,
            watch_rollout(&self.engine, &self.namespace, &self.workload_name, total),
        )
        .await
        {
            Ok(result) => result.map_err(|error| error.public_code().to_string()),
            Err(_) if remaining > self.observation_slice => {
                // Slice elapsed with rollout budget remaining: return a
                // nonterminal observation so the worker frees its slot.
                return DeploymentRolloutOutcome {
                    deploy_status: "watching",
                    app_status: app_status_label(previous_app_status),
                    error_code: None,
                    terminal: false,
                    manifest_hash: self.manifest_hash,
                };
            }
            // The cumulative rollout budget is exhausted; preserve the engine
            // timeout classification for this generation.
            Err(_) => Ok(EngineDeployStatus::timed_out(&format!(
                "rollout did not complete within {total:?}"
            ))),
        };
        let outcome = classify_rollout_result(result, previous_app_status, unlock_mode);
        DeploymentRolloutOutcome {
            deploy_status: outcome.deploy_status,
            app_status: outcome.app_status,
            error_code: (outcome.deploy_status == "failed").then_some("deployment_rollout_failed"),
            terminal: outcome.terminal,
            manifest_hash: self.manifest_hash,
        }
    }
}

fn app_status_label(status: AppStatus) -> &'static str {
    match status {
        AppStatus::Creating => "creating",
        AppStatus::Running => "running",
        AppStatus::Stopped => "stopped",
        AppStatus::Failed => "failed",
        AppStatus::Deleting => "deleting",
    }
}

/// Apply manifests and return durable rollout-observation context.
pub async fn apply_deployment_manifests(
    request: ApplyDeploymentManifestsRequest,
    mutation: &crate::mutation_leases::AppMutationLease,
) -> Result<Option<DeploymentRollout>, DeployError> {
    let ApplyDeploymentManifestsRequest {
        pool,
        app,
        snapshot,
        engine,
        fresh_volume_claims,
        deployment_id,
        attestation_config,
        kbs_policy_config,
        edge_config_generation,
        kubernetes_mutation_generation,
        api_signing_pubkey,
        api_url,
        workload_artifact_binding,
        signed_policy_artifact,
        local_workload_artifacts_json,
        local_trustee_policy_json,
        sigstore_material,
        provenance_oci_material,
        log_encryption,
    } = request;
    let attestation_config = attestation_config.ok_or(DeployError::MissingAttestationConfig)?;

    let mut app_spec = build_confidential_app_from_rows(
        &app,
        deployment_id,
        &attestation_config,
        &api_signing_pubkey,
        &api_url,
        &snapshot.containers,
        &snapshot.resources,
    )?;
    app_spec.workload_artifact_binding = workload_artifact_binding;
    app_spec.log_encryption = log_encryption;
    if let (Some(workload_artifacts), Some(trustee_policy)) = (
        local_workload_artifacts_json.as_ref(),
        local_trustee_policy_json.as_ref(),
    ) {
        app_spec.attestation.local_workload_artifacts_json = Some(workload_artifacts.clone());
        app_spec.attestation.local_trustee_policy_json = Some(trustee_policy.clone());
    }
    if let Some(signed_policy_artifact) = signed_policy_artifact.as_ref() {
        let policy_sha256: [u8; 32] = hex::decode(&signed_policy_artifact.agent_policy_sha256)
            .map_err(|err| DeployError::Validation(format!("agent_policy_sha256: {err}")))?
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                DeployError::Validation(format!(
                    "agent_policy_sha256 must be 32 bytes, got {}",
                    bytes.len()
                ))
            })?;
        app_spec.generated_agent_policy = Some(enclava_engine::types::GeneratedAgentPolicy {
            policy_text: signed_policy_artifact.agent_policy_text.clone(),
            policy_sha256,
            genpolicy_version_pin: signed_policy_artifact
                .metadata
                .genpolicy_version_pin
                .clone(),
        });
    }

    app_spec.attestation.verification_material = Some(build_verification_material(
        &app_spec,
        local_workload_artifacts_json.as_deref().unwrap_or_default(),
        local_trustee_policy_json.as_deref().unwrap_or_default(),
        &sigstore_material,
        &provenance_oci_material,
    )?);

    enclava_engine::validate::validate_app(&app_spec)
        .map_err(|e| DeployError::Validation(e.to_string()))?;

    // Reuse the under-fence verdict the worker reinspected immediately
    // before this call: reading again here could terminalize a transient
    // lookup failure after provider writes already began.
    enclava_engine::apply::orchestrator::enforce_floor_on_claims(&app_spec, fresh_volume_claims)?;
    let rollout_timeout = engine
        .config()
        .rollout_timeout_for_storage(
            &app_spec.storage.app_data.size,
            &app_spec.storage.tls_data.size,
            fresh_volume_claims,
        )
        .map_err(DeployError::Validation)?;

    let tenant_image_pull_secret_config =
        tenant_image_pull_secret_config_for_containers(&app_spec.containers);
    let manifests = generate_all_manifests(&app_spec);
    let hash = manifest_hash(&manifests);
    set_deployment_status(&pool, deployment_id, "applying", Some(&hash), None, false).await?;
    set_app_status(&pool, app.id, "creating").await?;
    if signed_policy_artifact.is_some() {
        if should_reconcile_global_signed_policy_artifacts(true, &app_spec.attestation) {
            // Acceptance already advanced the durable desired generation in
            // the same transaction that persisted this artifact.  Converge
            // that generation here while the caller holds the global KBS
            // mutation fence; do not enqueue a second generation.
            crate::kbs::reconcile_pending_signed_policy_artifacts(
                &pool,
                kbs_policy_config.as_ref(),
            )
            .await?;
        } else {
            tracing::info!(
                app_id = %app.id,
                deployment_id = %deployment_id,
                "signed deployment did not request global KBS policy aggregate reconciliation"
            );
        }
    } else {
        crate::kbs::ensure_owner_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::ensure_tls_binding(&pool, kbs_policy_config.as_ref(), &app_spec).await?;
        crate::kbs::reconcile_policy(&pool, kbs_policy_config.as_ref()).await?;
    }

    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    // The floor verdict was already derived from live PVC evidence before
    // the first provider write above; provisioned sub-floor claims pass
    // through unchanged.

    apply_all_with_tenant_image_pull_secret(
        &engine,
        &pool,
        deployment_id,
        &manifests,
        &hash,
        tenant_image_pull_secret_config.as_ref(),
        generation,
    )
    .await?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .fetch_one(&pool)
        .await?;
    // Host list shared with failed-apply cleanup
    // (`crate::deployment_failure_cleanup`) so publication and removal can
    // never diverge.
    let app_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 443).await?;
    let tee_target =
        crate::edge::resolve_backend_target(&app_spec.name, &app_spec.namespace, 8081).await?;
    let mut routes = Vec::with_capacity(3);
    for (tag, host) in crate::deploy::app_route_hosts(&app) {
        let backend = crate::edge::backend_name_for(&org_slug, &app_spec.name, tag)?;
        let target = match tag {
            crate::edge::BackendTag::App => &app_target,
            crate::edge::BackendTag::Tee => &tee_target,
        };
        routes.push(crate::edge::SniRoute::new(&host, &backend, target)?);
    }
    crate::edge::ensure_haproxy_routes(&pool, &edge_config, Some(edge_config_generation), &routes)
        .await?;

    Ok(Some(DeploymentRollout {
        app,
        engine,
        namespace: app_spec.namespace.clone(),
        workload_name: app_spec.name.clone(),
        manifest_hash: hash,
        observing_since: chrono::Utc::now(),
        observation_slice: ROLLOUT_OBSERVATION_SLICE,
        rollout_timeout,
    }))
}

fn build_verification_material(
    app: &enclava_engine::types::ConfidentialApp,
    workload_artifacts_json: &str,
    trustee_policy_json: &str,
    sigstore_material: &[u8],
    provenance_oci_material: &[u8],
) -> Result<Vec<u8>, DeployError> {
    let cc_init_data = enclava_engine::manifest::cc_init_data::build_toml(app);
    let fields = [
        ("cc_init_data_toml", cc_init_data.as_bytes(), 196_608),
        (
            "workload_artifacts_json",
            workload_artifacts_json.as_bytes(),
            196_608,
        ),
        (
            "trustee_policy_json",
            trustee_policy_json.as_bytes(),
            49_152,
        ),
        ("sigstore_material", sigstore_material, 196_608),
        ("provenance_oci_material", provenance_oci_material, 311_296),
    ];
    if fields.iter().any(|(_, value, limit)| value.len() > *limit) {
        return Err(DeployError::Validation(
            "verification material field exceeds v1 limit".into(),
        ));
    }
    let records = fields
        .iter()
        .map(|(label, value, _)| (*label, *value))
        .collect::<Vec<_>>();
    let material = enclava_common::canonical::ce_v1_bytes(&records);
    if material.len() > enclava_engine::manifest::verification_material::MAX_BYTES {
        return Err(DeployError::Validation(
            "verification material exceeds 700 KiB".into(),
        ));
    }
    Ok(material)
}
