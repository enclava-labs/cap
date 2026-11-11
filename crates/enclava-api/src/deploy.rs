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
    resources::{apply_namespaced_resource, apply_standard_resources_with_service_account},
    statefulset::apply_statefulset,
    types::{ApplyConfig, DeployPhase, DeployStatus as EngineDeployStatus},
    watch::watch_rollout,
};
use enclava_engine::manifest::generate_all_manifests;
use enclava_engine::types::{
    AttestationConfig, BindMount, ConfidentialApp, Container, DomainSpec, EgressMode,
    LogEncryptionConfig, StorageSpec, WorkloadArtifactBinding, WorkloadSecurityProfile,
};
use k8s_openapi::api::core::v1::{Namespace, Secret, ServiceAccount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{
    Api, Resource as _,
    api::{DeleteParams, ListParams, Patch, PatchParams},
};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
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

const PULL_SECRET_SCOPE_GENERATION_ANNOTATION: &str =
    "cap.enclava.dev/pull-secret-scope-generation";

/// Operator-controlled monotonic epoch; bump BEFORE broadening repository scope
/// in a rolling deployment, after all replicas have received this fence.
fn pull_secret_scope_generation() -> u64 {
    std::env::var("TENANT_IMAGE_PULL_SCOPE_GENERATION")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0)
}

fn newer_pull_secret_scope(secret: &Secret) -> bool {
    secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(PULL_SECRET_SCOPE_GENERATION_ANNOTATION))
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|epoch| epoch > pull_secret_scope_generation())
}

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

/// Codex review on #243, P1 "fence narrowed scopes against older replicas":
/// the scope-epoch marker lived only as an annotation on the managed Secret,
/// so a scope-narrowing rollout that deleted it left older replicas (whose
/// broader configuration still matches the repository) nothing to compare
/// against — their deploy path's create-on-404 branch and the sweep's repair
/// pass recreated the platform PAT and reattached it on the next deployment.
/// This durable, shared-DB fence (`tenant_pull_secret_scope_fences`) records
/// the newest [`pull_secret_scope_generation`] epoch that has made a
/// pull-secret decision for a namespace, outside the deletable Secret.
///
/// Whether a namespace's recorded fence epoch defers THIS replica: a newer
/// epoch means a newer rollout's policy owns the namespace's pull secrets, so
/// this replica must create, refresh, and delete nothing there — it defers
/// (deploy: requeueable `PullSecretReconcileDeferred`; sweep: not converged)
/// instead of resurrecting credentials the newer replica removed. Same
/// contract the on-secret annotation already documents for workload
/// admission: stale replicas stay closed until upgraded or retired.
fn pull_secret_scope_fence_defers(fence_epoch: i64) -> bool {
    i128::from(fence_epoch) > i128::from(pull_secret_scope_generation())
}

/// PostgreSQL stores rollout epochs as BIGINT. Never collapse distinct epochs
/// above its range onto the same fence value, even if startup was bypassed.
fn pull_secret_epoch_for_db(epoch: u64, name: &str) -> Result<i64, sqlx::Error> {
    i64::try_from(epoch).map_err(|_| {
        sqlx::Error::Protocol(format!(
            "{name} must be an unsigned integer no greater than {}",
            i64::MAX
        ))
    })
}

/// Rollout-wide pull-secret authority (Codex review on #243, round 3, P1
/// "stop stale-scope replicas from dispatching new namespaces" + P1 "fence
/// pull-secret creation against credential rollouts"): the per-namespace
/// fence above only protects namespaces the NEWER replica already swept —
/// a namespace created after that sweep has no fence row, and the credential
/// epoch lived only on live Secret annotations, so a namespace without the
/// configured-name Secret had no authority rejecting a stale token. Every
/// deploy/sweep that records a per-namespace fence also raises these
/// fleet-wide maxima; a replica whose own epoch is below either maximum
/// defers all tenant pull-secret work — the same closed-until-upgraded
/// admission contract, extended to namespaces the newer rollout has not
/// reached yet. Monotonic: a stale replica can never rewind them.
async fn raise_tenant_pull_secret_rollout_authority(
    pool: &sqlx::PgPool,
    scope_epoch: u64,
    credential_epoch: u64,
) -> Result<(i64, i64), sqlx::Error> {
    let scope_epoch = pull_secret_epoch_for_db(scope_epoch, "TENANT_IMAGE_PULL_SCOPE_GENERATION")?;
    let credential_epoch =
        pull_secret_epoch_for_db(credential_epoch, "TENANT_IMAGE_PULL_CREDENTIAL_GENERATION")?;
    // Same-epoch rechecks must not wait on our own shared mutation guard.
    let current: (i64, i64) = sqlx::query_as(
        "SELECT max_scope_epoch, max_credential_epoch FROM tenant_pull_secret_rollout_authority WHERE id",
    )
    .fetch_one(pool)
    .await?;
    if current.0 >= scope_epoch && current.1 >= credential_epoch {
        return Ok(current);
    }
    let mut transition = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(278225)")
        .execute(&mut *transition)
        .await?;
    let (max_scope_epoch, max_credential_epoch) = sqlx::query_as::<_, (i64, i64)>(
        "UPDATE tenant_pull_secret_rollout_authority \
         SET max_scope_epoch = GREATEST(max_scope_epoch, $1), \
             max_credential_epoch = GREATEST(max_credential_epoch, $2), \
             updated_at = clock_timestamp() \
         WHERE id \
         RETURNING max_scope_epoch, max_credential_epoch",
    )
    .bind(scope_epoch)
    .bind(credential_epoch)
    .fetch_one(&mut *transition)
    .await?;
    transition.commit().await?;
    Ok((max_scope_epoch, max_credential_epoch))
}

/// Hold through all Secret and ServiceAccount writes, including sweep recreation.
/// An epoch transition takes the exclusive side before publishing authority, so
/// it cannot finish its narrowing sweep ahead of an older in-flight mutation.
async fn pull_secret_mutation_guard(
    pool: &PgPool,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, DeployError> {
    let mut guard = pool.begin().await?;
    // Kubernetes writes use other connections; keep this guard's lock alive while idle.
    sqlx::query("SET LOCAL idle_in_transaction_session_timeout = 0")
        .execute(&mut *guard)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock_shared(278225)")
        .execute(&mut *guard)
        .await?;
    let (scope, credential): (i64, i64) = sqlx::query_as(
        "SELECT max_scope_epoch, max_credential_epoch FROM tenant_pull_secret_rollout_authority WHERE id",
    )
    .fetch_one(&mut *guard)
    .await?;
    if pull_secret_rollout_authority_defers(scope, credential) {
        return Err(DeployError::PullSecretReconcileDeferred(
            "a newer pull-secret rollout owns the fleet; refusing guarded mutation".to_string(),
        ));
    }
    Ok(guard)
}

/// Whether the rollout-wide authority defers THIS replica: any newer scope
/// or credential epoch observed anywhere in the fleet means a newer rollout
/// exists, and this replica must not create, refresh, delete, or attach
/// tenant pull secrets in ANY namespace — including ones without a fence
/// row yet (created after the newer replica's sweep) and ones without the
/// configured-name Secret (where no annotation epoch exists to compare
/// against). Callers defer (deploy: requeueable
/// `PullSecretReconcileDeferred`; sweep: not converged).
fn pull_secret_rollout_authority_defers(max_scope_epoch: i64, max_credential_epoch: i64) -> bool {
    let own_scope = i128::from(pull_secret_scope_generation());
    let own_credential = i128::from(pull_secret_credential_generation());
    i128::from(max_scope_epoch) > own_scope || i128::from(max_credential_epoch) > own_credential
}

/// Re-read the fleet rollout authority immediately before a Kubernetes write
/// that can create or refresh a tenant pull secret (Devin review on #278,
/// "Stale rollout resurrects narrowed credentials"). Passing
/// [`raise_tenant_pull_secret_rollout_authority`] once at the start of a
/// deploy is not a fence for later writes: a narrowing rollout can raise the
/// epoch and delete credentials after that check returns, and the create-on-404
/// path then has no live Secret annotation to compare against.
async fn ensure_pull_secret_rollout_authority_current(pool: &PgPool) -> Result<(), DeployError> {
    let (scope_epoch, credential_epoch) = raise_tenant_pull_secret_rollout_authority(
        pool,
        pull_secret_scope_generation(),
        pull_secret_credential_generation(),
    )
    .await?;
    if pull_secret_rollout_authority_defers(scope_epoch, credential_epoch) {
        return Err(DeployError::PullSecretReconcileDeferred(format!(
            "a newer pull-secret rollout exists (scope epoch {scope_epoch} / credential \
             epoch {credential_epoch} vs this replica's {}/{}); deferring the Kubernetes \
             write so a stale replica cannot recreate credentials a newer rollout removed",
            pull_secret_scope_generation(),
            pull_secret_credential_generation()
        )));
    }
    Ok(())
}

/// The newest scope epoch recorded for one namespace (`0` = never fenced).
async fn tenant_pull_secret_scope_fence_epoch(
    pool: &sqlx::PgPool,
    namespace: &str,
) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT scope_epoch FROM tenant_pull_secret_scope_fences WHERE namespace = $1",
    )
    .bind(namespace)
    .fetch_optional(pool)
    .await?
    .unwrap_or(0))
}

/// Record this replica's scope epoch as the newest pull-secret authority for
/// a namespace (monotonic: an existing NEWER fence is never lowered, so a
/// stale replica can never rewind a newer rollout's authority). Returns the
/// AUTHORITATIVE epoch the row holds after the statement (Codex review on
/// #243, round 2, P1 "make scope-fence recording detect a newer concurrent
/// epoch"): when a newer replica raised the epoch between the caller's read
/// and this upsert, the monotonic guard rejects the stale stamp, the
/// `RETURNING` clause yields no row, and the fallback re-read returns the
/// newer epoch — callers must re-check
/// [`pull_secret_scope_fence_defers`] against it instead of assuming the
/// stamp succeeded.
async fn record_tenant_pull_secret_scope_fence(
    pool: &sqlx::PgPool,
    namespace: &str,
    epoch: u64,
) -> Result<i64, sqlx::Error> {
    let epoch = pull_secret_epoch_for_db(epoch, "TENANT_IMAGE_PULL_SCOPE_GENERATION")?;
    let updated = sqlx::query_scalar::<_, i64>(
        "INSERT INTO tenant_pull_secret_scope_fences (namespace, scope_epoch) \
         VALUES ($1, $2) \
         ON CONFLICT (namespace) DO UPDATE \
            SET scope_epoch = EXCLUDED.scope_epoch, updated_at = clock_timestamp() \
          WHERE EXCLUDED.scope_epoch > tenant_pull_secret_scope_fences.scope_epoch \
         RETURNING scope_epoch",
    )
    .bind(namespace)
    .bind(epoch)
    .fetch_optional(pool)
    .await?;
    match updated {
        Some(epoch) => Ok(epoch),
        // The monotonic guard rejected our (older or equal) stamp: report
        // the epoch the row actually holds.
        None => tenant_pull_secret_scope_fence_epoch(pool, namespace).await,
    }
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

/// Durable proof that a live Secret UID is a tenant replacement, not the
/// object a pending repair cleared (Codex review on #276, P1 "preserve UID
/// mismatch protection across replacement repairs"). Written in the same
/// ServiceAccount patch that restores the reference and discharges the pending
/// intent, so a later sweep still has the UID after the pending annotation is
/// gone. Entries are `name=uid`, comma-separated; a name may record more than
/// one UID. SSA of the generated ServiceAccount must copy this annotation into
/// the desired object or the apply prunes it.
const FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION: &str =
    "cap.enclava.dev/foreign-pull-secret-replacements";
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
    for name in [
        "TENANT_IMAGE_PULL_CREDENTIAL_GENERATION",
        "TENANT_IMAGE_PULL_SCOPE_GENERATION",
    ] {
        if let Ok(raw) = std::env::var(name) {
            let epoch = raw.parse::<u64>().ok();
            if epoch.is_none_or(|epoch| pull_secret_epoch_for_db(epoch, name).is_err()) {
                return Some(format!(
                    "{name} must be an unsigned integer no greater than {}",
                    i64::MAX
                ));
            }
        }
    }
    let username_present = env_nonempty("GHCR_USERNAME").is_some();
    let token_present = env_nonempty("GHCR_TOKEN").is_some();
    // Devin review on #276: token-only GHCR authentication is deliberately
    // NOT accepted here even though cosign's registry auth would synthesize
    // an `oauth2` username for verification (see
    // `cosign::registry_auth_with_allowlist`). The tenant pull secret is a
    // dockerconfigjson Basic credential that can only be materialized from
    // BOTH values — `tenant_image_pull_secret_config_from_env` yields `None`
    // otherwise — and a half-rotated pair must not boot the API into the
    // startup cleanup sweep: with no config, every namespace computes
    // out-of-scope and the sweep deletes every managed pull secret over a
    // transient misconfiguration. Refusing startup surfaces the incomplete
    // rotation before any cleanup can run; verification-only deployments set
    // both values (cosign uses the username verbatim when present), so no
    // legitimate configuration is lost.
    if username_present != token_present {
        return Some(
            "GHCR_USERNAME and GHCR_TOKEN must both be nonempty or both absent; refusing cleanup with incomplete credentials".to_string(),
        );
    }
    if tenant_image_pull_secret_config_from_env().is_some() {
        return None;
    }
    let ghcr_configured = username_present && token_present;
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
    // #252: a trailing '/' (e.g. the typo `ghcr.io/company/private//*`,
    // which strips exactly one `/*` and leaves a trailing slash) must be a
    // validation error, never silently normalized — the empty-component
    // check below rejects it instead of trimming it away.
    let Some((registry, repository)) = value.split_once('/') else {
        return Err("expected registry/repository or registry/repository/*".to_string());
    };
    if repository.contains(':') {
        return Err(
            "tags (':…') are not allowed in a repository scope; use registry/repository"
                .to_string(),
        );
    }
    // DNS hostnames are case-insensitive. `GHCR.IO` and `ghcr.io` are the
    // same registry, and ImageRef preserves the spelling from the workload
    // reference. Canonicalize before the ghcr.io gate and the image-grammar
    // round-trip so an uppercase scope is not rejected here while a
    // lowercase scope later fails an exact compare against `GHCR.IO/...`
    // (Codex review on #276, P2).
    let registry = registry.to_ascii_lowercase();
    validate_repository_scope_registry(&registry)?;
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
                "repository path components must be non-empty (no leading, repeated, or trailing '/')"
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
        registry,
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
    repository_in_pull_scope(image.registry(), image.repository(), scope)
}

/// Same host, different spelling (`GHCR.IO` vs the canonical `ghcr.io`
/// stored on the scope). Repository paths stay case-sensitive. An exact
/// scope matches only that repository; `/*` also matches subrepositories
/// and never a sibling prefix (`team/app` does not match `team/app-other`).
fn repository_in_pull_scope(
    registry: &str,
    repository: &str,
    scope: &ImagePullRepositoryScope,
) -> bool {
    // A tenant-controlled image can contain `.` or `..` (ImageRef allows
    // them; the allowlist parser does not). reqwest normalizes those
    // segments out of the manifest URL, so a string prefix match would
    // attach credentials for a different repository than the one fetched.
    // Literal segments only — the same rule the allowlist parser uses.
    if !enclava_common::registry::repository_path_is_literal(repository) {
        return false;
    }
    if !registry.eq_ignore_ascii_case(&scope.registry) {
        return false;
    }
    if repository == scope.repository {
        return true;
    }
    scope.include_subrepositories
        && repository
            .strip_prefix(&scope.repository)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

/// Platform pull credentials for OCI tag resolution (issue #228).
///
/// Fail-closed, and deliberately stricter than pull-secret attachment:
/// both `GHCR_USERNAME` and `GHCR_TOKEN` must be nonempty, and the image
/// must match a non-empty `TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES` entry.
/// An empty, absent, or invalid allowlist yields no credentials — anonymous
/// resolution — never a universal attach. These credentials authenticate
/// only `ghcr.io`; any other registry is refused even before the allowlist
/// is consulted, so a scope typo cannot forward the platform PAT elsewhere.
pub(crate) fn resolution_pull_credentials(
    registry: &str,
    repository: &str,
) -> Option<(String, String)> {
    resolution_pull_credentials_from(
        registry,
        repository,
        env_nonempty("GHCR_USERNAME").as_deref(),
        env_nonempty("GHCR_TOKEN").as_deref(),
        env_nonempty(TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES_ENV).as_deref(),
    )
}

pub(crate) fn resolution_pull_credentials_from(
    registry: &str,
    repository: &str,
    username: Option<&str>,
    token: Option<&str>,
    allowed_repositories: Option<&str>,
) -> Option<(String, String)> {
    if !registry.eq_ignore_ascii_case("ghcr.io") {
        return None;
    }
    let username = trimmed_nonempty(username)?;
    let token = trimmed_nonempty(token)?;
    let Some(raw) = trimmed_nonempty(allowed_repositories) else {
        tracing::debug!(
            registry,
            "platform pull credentials not used for tag resolution: \
             TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES is empty or unset"
        );
        return None;
    };
    let Ok(scopes) = parse_image_pull_scopes_strict(&raw) else {
        tracing::debug!(
            registry,
            "platform pull credentials not used for tag resolution: \
             TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES is unusable"
        );
        return None;
    };
    if scopes.is_empty()
        || !scopes
            .iter()
            .any(|scope| repository_in_pull_scope(registry, repository, scope))
    {
        tracing::debug!(
            registry,
            repository,
            "platform pull credentials not used for tag resolution: repository is outside \
             TENANT_IMAGE_PULL_ALLOWED_REPOSITORIES"
        );
        return None;
    }
    Some((username, token))
}

fn trimmed_nonempty(value: Option<&str>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
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
    annotations.insert(
        PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
        pull_secret_scope_generation().to_string(),
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

/// The engine's attached creation ledger, or a throwaway empty one for
/// engines constructed without provenance recording (tests, non-apply
/// paths). The default empty ledger is strict: no unrecorded object gains
/// deletion authority from a forged stamp or an implicit legacy cutoff.
fn engine_ledger_or_empty(
    engine: &ApplyEngine,
) -> Arc<enclava_engine::apply::creation_ledger::CreationLedgerBuffer> {
    engine.creation_ledger().cloned().unwrap_or_else(|| {
        Arc::new(enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new())
    })
}

/// Drain the creations an apply step observed and durably record them
/// (cap#272). A persistence failure is NEVER swallowed: the just-created
/// objects are compensated (UID-preconditioned deletes) and the apply
/// fails closed, because an unrecorded post-cutover creation could only
/// resurface later as a permanently unresolved sweep target. Compensation
/// failures are warned, not retried — the failed-apply sweep then holds
/// the object unresolved (fail closed, operator-resolvable).
async fn persist_and_gate_creation_records(
    engine: &ApplyEngine,
    pool: &PgPool,
    app_id: Uuid,
    deployment_id: Uuid,
    namespace: &str,
    mutation: &crate::mutation_leases::AppMutationLease,
) -> Result<(), DeployError> {
    let Some(ledger) = engine.creation_ledger() else {
        return Ok(());
    };
    let pending = ledger.drain_pending();
    if pending.is_empty() {
        return Ok(());
    }
    if let Err(error) = crate::deployment_failure_cleanup::persist_creation_records(
        pool,
        app_id,
        deployment_id,
        &pending,
    )
    .await
    {
        tracing::error!(
            app_id = %app_id,
            deployment_id = %deployment_id,
            namespace = %namespace,
            error = %error,
            "cannot persist the creation ledger; compensating this step's created objects and failing the apply closed (cap#272)"
        );
        // Restore before awaiting compensation, so cancellation cannot lose
        // observations that were refused, failed, or only accepted for delete.
        for record in &pending {
            ledger.record(record.clone());
        }
        compensate_unledgered_creations(engine, &pending, mutation).await;
        return Err(DeployError::Db(error));
    }
    Ok(())
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

/// Whether one app still qualifies for the managed pull secret under the
/// current scope (`None` means one of its stored image refs is unparsable,
/// which never qualifies). The per-app half of
/// [`namespace_keeps_tenant_image_pull_secret`] (Codex review on #243, P1
/// "reconcile pull-secret references per app in shared namespaces"): it
/// decides which generated ServiceAccount keeps its `imagePullSecrets`
/// attachment while the namespace-level decision only keeps the Secret.
fn app_keeps_tenant_image_pull_secret(
    config: &TenantImagePullSecretConfig,
    images: Option<&Vec<ImageRef>>,
) -> bool {
    images.is_some_and(|images| images_match_repository_scopes(config, images))
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
    app_images
        .iter()
        .any(|images| app_keeps_tenant_image_pull_secret(config, images.as_ref()))
}

/// One app's pull-secret qualification inputs for a shared-namespace deploy
/// (Codex review on #276, P1 "reconcile shared namespaces before completing
/// out-of-scope deploys").
struct NamespacePullSecretApp {
    app_id: Uuid,
    service_account: String,
    /// `None` means a stored image ref failed to parse, so the app never
    /// qualifies.
    images: Option<Vec<ImageRef>>,
}

/// Scope for one deploy in a shared namespace. The deploying app is forced
/// in or out from THIS deploy's images: stored rows can lag the snapshot
/// being applied. Other apps keep their stored-image decision.
fn scope_for_shared_namespace_deploy(
    config: Option<&TenantImagePullSecretConfig>,
    deploying_app_id: Uuid,
    deploying_in_scope: bool,
    apps: &[NamespacePullSecretApp],
    deploy_service_accounts: &[String],
) -> PullSecretAccountScope {
    let Some(config) = config else {
        return PullSecretAccountScope::uniform(false);
    };
    let mut in_scope_accounts: std::collections::BTreeSet<String> = apps
        .iter()
        .filter(|app| app.app_id != deploying_app_id)
        .filter(|app| app_keeps_tenant_image_pull_secret(config, app.images.as_ref()))
        .map(|app| app.service_account.clone())
        .collect();
    if deploying_in_scope {
        in_scope_accounts.extend(deploy_service_accounts.iter().cloned());
    }
    PullSecretAccountScope {
        namespace_in_scope: !in_scope_accounts.is_empty(),
        in_scope_accounts,
    }
}

/// Scope for an out-of-scope deploy in a shared namespace. The deploying app
/// is forced out of scope even when its stored image rows still match: those
/// rows can lag the snapshot this deploy is applying. Other apps keep the
/// secret only while their stored images still qualify.
#[cfg(test)]
fn scope_for_shared_namespace_out_of_scope_deploy(
    config: Option<&TenantImagePullSecretConfig>,
    deploying_app_id: Uuid,
    apps: &[NamespacePullSecretApp],
) -> PullSecretAccountScope {
    scope_for_shared_namespace_deploy(config, deploying_app_id, false, apps, &[])
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

    /// Config for the sweep's 404-recreate arm: the settings already carry
    /// the configured name and credential pair (snapshotted from the env in
    /// production, explicit in tests), so the arm must not re-read the env
    /// and diverge from the settings this reconcile was invoked with —
    /// `generate_tenant_image_pull_secret` only consumes the name and the
    /// credential pair (scope epochs are stamped from the generation env).
    fn tenant_image_pull_secret_config(&self) -> Option<TenantImagePullSecretConfig> {
        let (username, token) = self.ghcr_credentials.as_ref()?;
        Some(TenantImagePullSecretConfig {
            name: self.configured_name.clone(),
            username: username.clone(),
            token: token.clone(),
            allowed_repositories: Vec::new(),
        })
    }
}

/// Per-app scope decisions for one namespace's pull-secret reconciliation
/// (Codex review on #243, P1 "reconcile pull-secret references per app in
/// shared namespaces"): `namespace_in_scope` keeps the namespace-level secret
/// decision (at least one qualifying app keeps the configured secret), while
/// `in_scope_accounts` records WHICH generated ServiceAccounts' apps still
/// qualify. A shared namespace can hold one app that still matches the
/// repository scope and another that no longer does: reducing both to a
/// single `namespace_in_scope=true` kept the configured Secret AND every
/// ServiceAccount reference, so the out-of-scope app retained its
/// `imagePullSecrets` attachment and kept using the platform PAT across pod
/// restarts. With per-app decisions the Secret stays for the matching app,
/// but the nonmatching app's reference is cleared (durably, so a later
/// broadening re-attaches without waiting for a redeploy).
#[derive(Clone, Debug, Default)]
struct PullSecretAccountScope {
    namespace_in_scope: bool,
    /// ServiceAccounts whose app still qualifies. Empty while
    /// `namespace_in_scope` means "every account shares the namespace
    /// decision" (single-app namespaces and the pre-per-app behavior).
    in_scope_accounts: std::collections::BTreeSet<String>,
}

impl PullSecretAccountScope {
    /// Every ServiceAccount in the namespace shares the namespace-level
    /// decision — single-app namespaces, and the deploy path whose app either
    /// qualified (its ServiceAccount is the only one reconciled) or did not.
    fn uniform(namespace_in_scope: bool) -> Self {
        Self {
            namespace_in_scope,
            in_scope_accounts: Default::default(),
        }
    }

    fn account_in_scope(&self, account: &str) -> bool {
        self.namespace_in_scope
            && (self.in_scope_accounts.is_empty() || self.in_scope_accounts.contains(account))
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
        /// Whether that lease was HELD by an in-flight deploy at snapshot
        /// time (Codex review on #243, P1 "fence secret-name rollouts before
        /// deleting new secrets"): a deploy that acquired the namespace lease
        /// BEFORE the snapshot writes with a mutation generation EQUAL to
        /// `namespace_generation`, so the strict `>` skip cannot protect its
        /// newly created Secret — during a `TENANT_IMAGE_PULL_SECRET_NAME`
        /// rollout that Secret is unreferenced residue until the deploy's
        /// ServiceAccount apply lands, and an old replica's sweep must not
        /// delete it out from under the in-flight deploy. While the lease is
        /// held — including reclaim quarantine, where `owner_token` is retained
        /// through `reclaim_after` after `locked_until` expires — the ACTIVE
        /// generation is treated as concurrent; once ownership is released the
        /// strict fence resumes (a secret still unreferenced and unkept at the
        /// SAME generation is then completed residue).
        lease_held: bool,
    },
    /// The deploy that holds the namespace lease and has just written
    /// `generation`. Runs the durable repair pass (fenced deploy cleanup
    /// skips it), but that generation is this caller's authoritative write,
    /// not a concurrent deploy a background sweep must defer to. A strictly
    /// newer marker still belongs to someone else.
    DeployOwned { generation: i64 },
}

/// Sweep and deploy-owned passes both run the durable repair pass. Fenced
/// per-deploy cleanup does not: its ServiceAccount SSA is the authoritative
/// `imagePullSecrets` decision.
fn runs_durable_pull_secret_repair(mode: PullSecretDeleteMode) -> bool {
    matches!(
        mode,
        PullSecretDeleteMode::Unfenced { .. } | PullSecretDeleteMode::DeployOwned { .. }
    )
}

/// A mutation generation this pass must not delete as completed residue.
///
/// Background sweeps protect a strictly newer generation, and an equal
/// generation while the snapshot lease is still owned (live heartbeat or
/// reclaim quarantine). The deploy's own pass wrote `generation` and must
/// not delete that object as residue either; a strictly newer rewrite is
/// still someone else's.
fn generation_blocks_pull_secret_removal(mode: PullSecretDeleteMode, actual: i64) -> bool {
    match mode {
        PullSecretDeleteMode::Unfenced {
            namespace_generation,
            lease_held,
        } => actual > namespace_generation || (lease_held && actual == namespace_generation),
        PullSecretDeleteMode::DeployOwned { generation } => actual >= generation,
        PullSecretDeleteMode::Fenced(_) => false,
    }
}

/// Whether a kept secret's per-app reference clear must wait for another deploy.
///
/// Distinct from [`generation_blocks_pull_secret_removal`]: the deploy that
/// just wrote `generation` has the authoritative scope and must clear
/// out-of-scope accounts. A background sweep must not clear references a
/// concurrent owner — including one still inside reclaim quarantine —
/// attached at the snapshot generation.
fn concurrent_deploy_owns_pull_secret(mode: PullSecretDeleteMode, actual: i64) -> bool {
    match mode {
        PullSecretDeleteMode::Unfenced {
            namespace_generation,
            lease_held,
        } => actual > namespace_generation || (lease_held && actual == namespace_generation),
        // Equal generation is this caller. A strictly newer marker is someone else.
        PullSecretDeleteMode::DeployOwned { generation } => actual > generation,
        PullSecretDeleteMode::Fenced(_) => false,
    }
}

/// Missing or unparsable markers skip [`generation_blocks_pull_secret_removal`].
/// A mutating admission webhook can strip `enclava.dev/cap-provider-mutation-generation`
/// from a concurrent deploy's Secret write while the snapshot lease is still
/// held. Treat that object as fenced, not as completed residue. Once the lease
/// is released, an unannotated legacy secret remains removable.
fn observed_generation_blocks_removal(mode: PullSecretDeleteMode, actual: Option<i64>) -> bool {
    // Nonpositive markers are as invalid as unparsable ones (Codex review on
    // #280, P1): real namespace generations are positive, so a webhook
    // rewriting the annotation to 0 or a negative must not make the object
    // compare as "older than" an active lease and escape its protection.
    match actual.filter(|generation| *generation > 0) {
        Some(actual) => generation_blocks_pull_secret_removal(mode, actual),
        None => matches!(
            mode,
            PullSecretDeleteMode::Unfenced {
                lease_held: true,
                ..
            }
        ),
    }
}

/// Same fail-closed rule for per-app reference clears. A stripped marker must
/// not let a stale sweep detach a reference the held lease's deploy just
/// attached.
fn observed_concurrent_deploy_owns(mode: PullSecretDeleteMode, actual: Option<i64>) -> bool {
    match actual.filter(|generation| *generation > 0) {
        Some(actual) => concurrent_deploy_owns_pull_secret(mode, actual),
        None => matches!(
            mode,
            PullSecretDeleteMode::Unfenced {
                lease_held: true,
                ..
            }
        ),
    }
}

/// Mode passed to a namespace reconcile from the pre-inventory lease snapshot.
///
/// A missing row is not the same as generation 0 after a completed deploy.
/// Migration 0042 did not backfill existing namespaces, and the sweep itself
/// stamps [`SWEEP_CREATED_PULL_SECRET_GENERATION`] (1) when it creates the
/// configured Secret. Passing `(0, false)` then classifies that stamp as a
/// concurrent deploy on every pass. Publishing a released row at generation 1
/// and reconciling under that generation keeps the sweep's own lineage from
/// closing admission forever, without exempting a real generation-1 deploy:
/// if the insert loses a race, `published_missing_row` is false and `actual > 0`
/// still protects the claim that appeared after the snapshot.
fn unfenced_pull_secret_delete_mode(
    snapshot: Option<(i64, bool)>,
    published_missing_row: bool,
) -> PullSecretDeleteMode {
    let (namespace_generation, lease_held) = match (snapshot, published_missing_row) {
        (Some((generation, held)), _) => (generation, held),
        (None, true) => (SWEEP_CREATED_PULL_SECRET_GENERATION, false),
        (None, false) => (0, false),
    };
    PullSecretDeleteMode::Unfenced {
        namespace_generation,
        lease_held,
    }
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

/// Per-apply create provenance nonce (Devin review on #280, SEC "Unproven
/// Secret gains deletion authority"): stamped on the object BEFORE the POST,
/// so a re-read after an ambiguous timeout can prove the object is this
/// apply's creation. The generation markers alone are namespace-shared and
/// predictable, so a name-race winner carrying trusted-looking metadata must
/// never be adopted as ours — or deleted as ours.
const PULL_SECRET_CREATE_NONCE_ANNOTATION: &str = "enclava.dev/pull-secret-create-nonce";

/// How long a submitted Secret POST can still commit server-side after our
/// client gave up: kube-apiserver's default `--request-timeout` bounds the
/// request's execution at 60 s, so probing the name until this window closes
/// resolves create-vs-no-create for good (Codex review on #280, P1 "Poll for
/// the full late-commit window") instead of three immediate 404s concluding
/// in ~2 s while the POST is still executing.
const PULL_SECRET_CREATE_LATE_COMMIT_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(75);
// Coupling (Devin review on #280): the window is sized on kube-apiserver's
// default 60s `--request-timeout`, which bounds the stalled POST's server-side
// execution. A commit after the window implies a non-default apiserver
// configuration — it is NOT impossible, and its residue is owned, not lost:
// the mutation lease's reclaim quarantine keeps the namespace fenced, and the
// stale sweep removes a labeled pull secret once its lease releases (an
// unproven late object is removable residue exactly like an unannotated legacy
// secret). The platform PAT of such a late create therefore stays readable at
// most until the next sweep pass, never forever.

/// Interval between late-commit-window absence probes.
const PULL_SECRET_CREATE_PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Hard bound on the whole ambiguity recovery — probes and compensation
/// together (Devin review on #280: a stalled DELETE or deletion poll must not
/// hold the deploy's mutation guard and apply permit indefinitely). On
/// overrun the caller returns the deferred error; the mutation lease's own
/// reclaim quarantine keeps any late create fenced.
const PULL_SECRET_CREATE_RECOVERY_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

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

/// The absence probe's cap. Grounded in the platform, not tuning: kube-apiserver's
/// default `--request-timeout` is 60s — a namespace GET either answers within
/// that or never (reviews on #306, rounds 4–5: an unbounded probe starves the
/// mutation guard and reconcile when GETs stall while Secret requests stay
/// healthy; a too-small one wedges admission on slow-but-valid 404s). At this
/// cap every legitimately answerable 404 fits, and a stalled GET still leaves
/// two-thirds of the namespace budget for the guard and reconcile — under
/// which a healthy Secret API reconciles this namespace to convergence.
const NAMESPACE_ABSENCE_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

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

/// Whether a kept secret should be attached to this in-scope account.
///
/// The configured name is attached to every qualifying account, including one
/// that never held it. A legacy name is restored only where a reference or
/// pending repair already exists. Spreading the old name onto accounts that
/// only used the current secret would keep it in `in_scope_referenced_names`
/// after the original account redeploys, so rename cleanup could never remove
/// the redundant platform credential (Codex review on #276, P2).
fn kept_pull_secret_should_attach(
    secret_name: &str,
    configured_name: &str,
    service_account: &str,
    accounts: &[ServiceAccount],
) -> bool {
    if secret_name == configured_name {
        return true;
    }
    accounts.iter().any(|account| {
        account.metadata.name.as_deref() == Some(service_account)
            && (account
                .image_pull_secrets
                .iter()
                .flatten()
                .any(|reference| reference.name == secret_name)
                || pending_reference_repairs(account)
                    .iter()
                    .any(|repair| repair.secret_name == secret_name))
    })
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
    if secret.metadata.deletion_timestamp.is_some()
        || newer_pull_secret_credentials(secret)
        || newer_pull_secret_scope(secret)
    {
        // Do not let an older replica roll back a newer rollout's credential.
        return Ok(false);
    }
    let current = secret
        .data
        .as_ref()
        .and_then(|data| data.get(".dockerconfigjson"))
        .map(|payload| payload.0.as_slice());
    // Idempotence requires BOTH rollout epochs to be current (Codex review
    // on #243, round 2, P2): matching bytes alone are not enough. After a
    // credential rollback or reuse, a new replica can legitimately select
    // bytes an older epoch already wrote; returning early there would leave
    // the OLD credential-generation annotation in place, and an
    // intermediate old replica (seeing no newer credential epoch) would
    // overwrite the bytes with its stale token. A generation bump must be
    // persisted even when the payload needs no rewrite.
    if current == Some(expected_dockerconfigjson.as_bytes())
        && secret
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(PULL_SECRET_SCOPE_GENERATION_ANNOTATION))
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|epoch| epoch >= pull_secret_scope_generation())
        && secret
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get(PULL_SECRET_CREDENTIAL_GENERATION_ANNOTATION))
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|generation| generation >= pull_secret_credential_generation())
    {
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
    annotations.insert(
        PULL_SECRET_SCOPE_GENERATION_ANNOTATION.to_string(),
        pull_secret_scope_generation().to_string(),
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

/// Build the configured pull secret from the settings snapshot this pass
/// already derived, so a sweep can recreate it without a second env read.
fn configured_pull_secret_from_settings(
    namespace: &str,
    settings: &PullSecretSettings,
) -> Option<Secret> {
    let (username, token) = settings.ghcr()?;
    let config = TenantImagePullSecretConfig {
        name: settings.configured_name.clone(),
        username: username.to_string(),
        token: token.to_string(),
        allowed_repositories: Vec::new(),
    };
    Some(generate_tenant_image_pull_secret(namespace, &config))
}

/// Minimum valid mutation generation. A sweep-created pull secret has no
/// deployment apply of its own; stamping this value makes every later failed
/// generation (`live <= failed`) classify the secret as a leftover. See
/// [`stamp_sweep_created_pull_secret_lineage`].
const SWEEP_CREATED_PULL_SECRET_GENERATION: i64 = 1;

/// POST params whose field manager is the platform manager
/// `classify_generation_leftover` requires. A raw POST without `fieldManager`
/// leaves `managedFields` empty, so creation-evidence annotations are still
/// classified as foreign.
fn pull_secret_create_params(engine: &ApplyEngine) -> kube::api::PostParams {
    kube::api::PostParams {
        field_manager: Some(engine.config().field_manager.clone()),
        ..kube::api::PostParams::default()
    }
}

fn pull_secret_label_owned(engine: &ApplyEngine, secret: &Secret) -> bool {
    is_labeled_managed_pull_secret(secret)
        && enclava_engine::apply::generation::label_owned_by_manager(
            secret,
            TENANT_PULL_SECRET_LABEL,
            &engine.config().field_manager,
        )
}

async fn remove_untrusted_created_pull_secret(
    api: &Api<Secret>,
    namespace: &str,
    name: &str,
    created: &Secret,
) -> Result<(), DeployError> {
    let (Some(uid), Some(resource_version)) = (
        created.metadata.uid.as_ref().filter(|uid| !uid.is_empty()),
        created
            .metadata
            .resource_version
            .as_ref()
            .filter(|version| !version.is_empty()),
    ) else {
        return Err(DeployError::PullSecretReconcileDeferred(format!(
            "cannot safely remove untrusted pull secret {namespace}/{name} without UID and \
             resourceVersion; the platform PAT may remain readable"
        )));
    };
    let params = kube::api::DeleteParams {
        preconditions: Some(kube::api::Preconditions {
            uid: Some(uid.clone()),
            resource_version: Some(resource_version.clone()),
        }),
        ..Default::default()
    };
    match api.delete(name, &params).await {
        Ok(_) => {
            // Finalizers can leave the PAT readable after DELETE acceptance.
            wait_for_secret_removal(api, namespace, name).await.map_err(|error| {
                DeployError::PullSecretReconcileDeferred(format!(
                    "compensating deletion of pull secret {namespace}/{name} has not converged: \
                     {error}; the platform PAT may remain readable"
                ))
            })?;
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {}
        Err(error) => {
            return Err(DeployError::PullSecretReconcileDeferred(format!(
                "could not delete pull secret {namespace}/{name} with untrusted creation evidence: \
                 {error}; the platform PAT may remain readable"
            )));
        }
    }
    Ok(())
}

/// Stamp the engine's creation evidence on a pull secret this process is
/// creating outside `apply_resource`. Adopted-namespace failure cleanup
/// deletes only objects whose `RESOURCE_CREATED_BY_ANNOTATION` is owned by
/// the platform field manager and whose mutation generation is positive and
/// not newer than the failed one. An unstamped secret is `Foreign`, skipped,
/// and — once the app row is gone — invisible to the lifetime sweep, which
/// inventories namespaces from app rows only (Codex review on #276, P1).
///
/// Stamped only on the create branch. A generation of
/// [`SWEEP_CREATED_PULL_SECRET_GENERATION`] is the minimum valid generation,
/// so any failed apply that reaches the classifier can delete it. Shared
/// namespaces are protected separately: failure cleanup does not delete a
/// pull secret while another app row still occupies the namespace.
fn stamp_sweep_created_pull_secret_lineage(secret: &mut Secret) {
    use enclava_engine::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION,
    };
    let annotations = secret
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    let generation = SWEEP_CREATED_PULL_SECRET_GENERATION.to_string();
    annotations.insert(
        RESOURCE_CREATED_BY_ANNOTATION.to_string(),
        generation.clone(),
    );
    annotations.insert(MUTATION_GENERATION_ANNOTATION.to_string(), generation);
}

/// Record a pull Secret this process just created via its own POST into the
/// engine's creation ledger (cap#272): the stamp alone no longer authorizes
/// failure-cleanup deletion, only a server-recorded creation row does. The
/// caller's next gated apply step drains and persists the record.
/// shortcut: engines without an attached ledger (the startup sweep) record
/// nothing, so a sweep-created secret classifies ProvenanceUnproven in
/// failure cleanup (retained, fail closed) until a deploy-path creation or
/// the pull-secret reconcile itself removes it; upgrade by giving the sweep
/// a persisted ledger sink.
fn record_pull_secret_creation(
    engine: &ApplyEngine,
    namespace: &str,
    secret: &Secret,
    generation: i64,
) {
    let Some(ledger) = engine.creation_ledger() else {
        return;
    };
    let (Some(name), Some(uid)) = (secret.metadata.name.clone(), secret.metadata.uid.clone())
    else {
        return;
    };
    ledger.record(enclava_engine::apply::creation_ledger::CreationRecord {
        kind: "Secret".to_string(),
        name,
        namespace: Some(namespace.to_string()),
        uid,
        mutation_generation: generation,
    });
}

/// Trusted creation evidence for a pull Secret this process POSTed: the
/// per-apply create nonce proves the object is THIS attempt's creation (the
/// generation markers are namespace-shared and predictable — a name-race
/// winner carrying trusted-looking metadata must not be recorded as ours,
/// which is what grants failed-deployment cleanup its deletion authority),
/// both generation markers match, the platform manager owns each annotation
/// path, and the dedicated label is owned. A webhook that strips or rewrites
/// any of them fails this check.
fn pull_secret_create_evidence_trusted(
    engine: &ApplyEngine,
    secret: &Secret,
    generation: i64,
    create_nonce: &str,
) -> bool {
    use enclava_engine::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION, annotation_owned_by_manager,
    };
    let expected = generation.to_string();
    let manager = engine.config().field_manager.as_str();
    let created_by = secret
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(RESOURCE_CREATED_BY_ANNOTATION));
    created_by == Some(&expected)
        && secret_create_nonce(secret) == Some(create_nonce)
        && secret_mutation_generation(secret) == Some(generation)
        && annotation_owned_by_manager(secret, RESOURCE_CREATED_BY_ANNOTATION, manager)
        && annotation_owned_by_manager(secret, MUTATION_GENERATION_ANNOTATION, manager)
        && pull_secret_label_owned(engine, secret)
}

/// The per-apply create nonce stamped on the object before the POST.
fn secret_create_nonce(secret: &Secret) -> Option<&str> {
    secret
        .metadata
        .annotations
        .as_ref()?
        .get(PULL_SECRET_CREATE_NONCE_ANNOTATION)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// Re-read after an apply budget timeout that may have dropped an accepted
/// Secret POST. Recording trusted evidence lets the caller persist the ledger
/// row (returning `Ok` continues into that gate). An accepted create whose
/// marker was stripped is compensated before the deferred error, so a later
/// patch retry cannot leave an unledgered platform PAT. A timeout that never
/// entered the create arm does not delete whatever object is there.
async fn recover_ambiguous_pull_secret_create(
    engine: &ApplyEngine,
    api: &Api<Secret>,
    namespace: &str,
    name: &str,
    generation: MutationGeneration,
    create_submitted: bool,
    create_nonce: &str,
) -> Result<(), DeployError> {
    let deferred = || {
        DeployError::PullSecretReconcileDeferred(format!(
            "pull-secret apply for {namespace}/{name} exceeded its budget (stalled Kubernetes \
             API?); retry the deployment — the namespace lease and apply permit are released"
        ))
    };
    if !create_submitted {
        return Err(deferred());
    }
    // Probe for the whole late-commit window: a 404 two seconds in proves
    // nothing about a POST that is still executing server-side (Codex review
    // on #280, P1 "Poll for the full late-commit window").
    let started = tokio::time::Instant::now();
    let mut probe = 0u32;
    loop {
        if probe > 0 {
            if tokio::time::Instant::now().duration_since(started)
                >= PULL_SECRET_CREATE_LATE_COMMIT_WINDOW
            {
                // The window has closed: a submitted create would be visible
                // by now, so nothing landed and the ambiguity is resolved
                // without recording or deleting anything.
                return Err(deferred());
            }
            tokio::time::sleep(PULL_SECRET_CREATE_PROBE_INTERVAL).await;
        }
        probe += 1;
        let live =
            match tokio::time::timeout(std::time::Duration::from_secs(30), api.get(name)).await {
                Ok(Ok(live)) => live,
                Ok(Err(kube::Error::Api(error))) if error.code == 404 => continue,
                // A transient read failure (timeout, 5xx, transport) proves
                // nothing about the create either: keep probing the window
                // instead of abandoning it — abandoning re-creates the
                // permanent provenance hole the 404 case closed (Codex review
                // on #280, round 3).
                Ok(Err(_)) | Err(_) => continue,
            };
        if pull_secret_create_evidence_trusted(engine, &live, generation.get(), create_nonce) {
            record_pull_secret_creation(engine, namespace, &live, generation.get());
            return Ok(());
        }
        // Compensate only an object that PROVES it is this apply's creation —
        // the per-apply nonce stamped before the POST (Devin review on #280,
        // SEC) — AND is still in the state we created (its generation marker
        // is ours or stripped): a marker owned by a NEWER writer means the
        // object changed hands after our create, and deleting it would
        // destroy that writer's live state. Creation provenance and current
        // ownership are two separate facts and deletion authority needs
        // both. The dedicated label is deliberately NOT required here: a
        // webhook that strips it while leaving the nonce must not strand the
        // platform PAT un-recorded and un-deleted — the nonce is the stronger,
        // request-specific proof (Codex review on #280, round 3).
        let marker = secret_mutation_generation(&live);
        let still_ours = marker.is_none() || marker == Some(generation.get());
        if secret_create_nonce(&live) == Some(create_nonce) && still_ours {
            remove_untrusted_created_pull_secret(api, namespace, name, &live).await?;
        }
        return Err(deferred());
    }
}

/// Bound the whole ambiguity recovery — probes and compensation together
/// (Devin review on #280): a stalled DELETE or deletion poll must not hold the
/// deploy's mutation guard and apply permit indefinitely. On overrun return
/// the deferred error; the mutation lease's own reclaim quarantine keeps any
/// late create fenced.
async fn bounded_recover_ambiguous_pull_secret_create(
    engine: &ApplyEngine,
    api: &Api<Secret>,
    namespace: &str,
    name: &str,
    generation: MutationGeneration,
    create_submitted: bool,
    create_nonce: &str,
) -> Result<(), DeployError> {
    match tokio::time::timeout(
        PULL_SECRET_CREATE_RECOVERY_BUDGET,
        recover_ambiguous_pull_secret_create(
            engine,
            api,
            namespace,
            name,
            generation,
            create_submitted,
            create_nonce,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(DeployError::PullSecretReconcileDeferred(format!(
            "pull-secret apply for {namespace}/{name} did not resolve its create ambiguity within \
             the recovery budget (stalled Kubernetes API?); retry the deployment — the namespace \
             lease and apply permit are released and the mutation lease's reclaim quarantine keeps \
             any late create fenced"
        ))),
    }
}

/// Whether failure cleanup must leave this Secret for a sibling app. The
/// platform pull secret is namespace-scoped: deleting it because one app's
/// apply failed would strip credentials another app in the same namespace
/// still pulls with. The lifetime sweep still inventories that namespace
/// through the sibling row.
pub(crate) fn secret_is_shared_tenant_pull_secret(
    name: &str,
    labels: Option<&std::collections::BTreeMap<String, String>>,
) -> bool {
    let labeled = labels
        .and_then(|labels| labels.get(TENANT_PULL_SECRET_LABEL))
        .is_some_and(|value| value == TENANT_PULL_SECRET_LABEL_VALUE);
    labeled || name == default_tenant_image_pull_secret_name_for_cleanup()
}

/// What to do with the live object at the configured pull-secret name.
enum ConfiguredPullSecretObservation {
    /// Attach this UID (if any) to in-scope accounts and detach the rest.
    Attach(Option<String>),
    /// Do not attach, and do not report this pass converged.
    Unconverged,
}

/// Decide whether the live configured secret may be attached by this replica.
/// A newer scope epoch defers — including after a create conflict, where the
/// ordinary GET path's check would otherwise be skipped (Codex review on
/// #276, P1). A terminating object does not satisfy reconciliation: attaching
/// it and reporting convergence leaves qualifying workloads with no pull
/// secret once the finalizer releases, until the next periodic sweep.
fn observe_configured_pull_secret(
    live: &Secret,
    namespace: &str,
    name: &str,
    placeable: bool,
) -> Result<ConfiguredPullSecretObservation, DeployError> {
    if newer_pull_secret_scope(live) {
        return Err(DeployError::PullSecretReconcileDeferred(format!(
            "newer repository-scope epoch owns {namespace}/{name}"
        )));
    }
    if live.metadata.deletion_timestamp.is_some() {
        tracing::warn!(
            %namespace,
            secret = %name,
            "tenant image pull secret reconcile: configured secret is terminating; waiting for removal before recreating and attaching"
        );
        return Ok(ConfiguredPullSecretObservation::Unconverged);
    }
    if !placeable {
        tracing::warn!(
            %namespace,
            secret = %name,
            "tenant image pull secret reconcile: configured name is a tenant replacement \
             or is not CAP-managed; refusing to overwrite it or declare convergence"
        );
        return Ok(ConfiguredPullSecretObservation::Unconverged);
    }
    Ok(ConfiguredPullSecretObservation::Attach(
        live.metadata.uid.clone().filter(|uid| !uid.is_empty()),
    ))
}

/// Create the configured pull secret and attach it to in-scope accounts when
/// no managed secret remains kept after repairs and cleanup (Codex review
/// on #276, P1). A narrowing that already deleted the secret and discharged
/// its pending repair leaves a later expansion with no managed object and no
/// intent; reporting convergence then opens admission while private
/// workloads still cannot pull. Use the outcome of this pass, not the
/// pre-repair discovery snapshot: deleting a stale old-name object or
/// discharging an intent must not postpone creation until the next sweep
/// while admission reports convergence.
#[allow(clippy::too_many_arguments)]
async fn ensure_configured_pull_secret_for_in_scope_accounts(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
    scope: &PullSecretAccountScope,
    api: &Api<Secret>,
    foreign_replacements: &BTreeMap<String, BTreeSet<String>>,
    delete_mode: PullSecretDeleteMode,
) -> Result<bool, DeployError> {
    if !scope.namespace_in_scope {
        return Ok(true);
    }
    let name = settings.configured_name.as_str();
    let Some(desired) = configured_pull_secret_from_settings(namespace, settings) else {
        return Ok(false);
    };
    let placeable = |live: &Secret| {
        !uid_is_foreign_replacement(foreign_replacements, name, live.metadata.uid.as_deref())
            && is_managed_tenant_image_pull_secret(live, settings.ghcr())
    };
    let live_uid = match api.get(name).await {
        Ok(live) => {
            match observe_configured_pull_secret(&live, namespace, name, placeable(&live))? {
                ConfiguredPullSecretObservation::Attach(uid) => uid,
                ConfiguredPullSecretObservation::Unconverged => return Ok(false),
            }
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            // Codex review on #276, P1: this POST is the startup path that
            // materializes a missing secret for an in-scope app. Without
            // cleanup lineage, a later failed apply in an adopted namespace
            // classifies the secret as foreign and leaves the platform PAT
            // readable after the app row disappears.
            let mut created = desired.clone();
            stamp_sweep_created_pull_secret_lineage(&mut created);
            match api
                .create(&pull_secret_create_params(engine), &created)
                .await
            {
                Ok(created) => {
                    if !pull_secret_label_owned(engine, &created) {
                        remove_untrusted_created_pull_secret(api, namespace, name, &created)
                            .await?;
                        return Ok(false);
                    }
                    record_pull_secret_creation(
                        engine,
                        namespace,
                        &created,
                        SWEEP_CREATED_PULL_SECRET_GENERATION,
                    );
                    created.metadata.uid.filter(|uid| !uid.is_empty())
                }
                // Lost the create race. The winner may be a newer scope
                // rollout; accepting it on `placeable` alone would attach
                // that secret to this replica's stale, broader account set.
                Err(kube::Error::Api(error)) if error.code == 409 => match api.get(name).await {
                    Ok(live) => {
                        match observe_configured_pull_secret(
                            &live,
                            namespace,
                            name,
                            placeable(&live),
                        )? {
                            ConfiguredPullSecretObservation::Attach(uid) => uid,
                            ConfiguredPullSecretObservation::Unconverged => return Ok(false),
                        }
                    }
                    Err(kube::Error::Api(error)) if error.code == 404 => return Ok(false),
                    Err(error) => return Err(DeployError::Apply(error.into())),
                },
                Err(error) => return Err(DeployError::Apply(error.into())),
            }
        }
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    let mut ok = true;
    for account in service_accounts {
        if scope.account_in_scope(account) {
            if let Err(error) = restore_pull_secret_reference_to_service_account(
                engine, namespace, account, name, None,
            )
            .await
            {
                ok = false;
                tracing::warn!(
                    %namespace,
                    service_account = %account,
                    secret = %name,
                    %error,
                    "tenant image pull secret reconcile: failed to attach the configured secret \
                     to an in-scope account"
                );
            }
        } else if let Err(error) = clear_pull_secret_reference_from_service_account(
            engine,
            namespace,
            account,
            name,
            live_uid.as_deref(),
            delete_mode,
        )
        .await
        {
            ok = false;
            tracing::warn!(
                %namespace,
                service_account = %account,
                secret = %name,
                %error,
                "tenant image pull secret reconcile: failed to keep an out-of-scope account \
                 detached from the recreated configured secret"
            );
        }
    }
    Ok(ok)
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
    scope: &PullSecretAccountScope,
    delete_mode: PullSecretDeleteMode,
) -> Result<bool, DeployError> {
    let (managed, _all_referenced_names, accounts) =
        discover_managed_pull_secrets(engine, namespace, service_accounts, settings).await?;
    // Per-app scope decisions (Codex review on #243, P1 "reconcile pull-secret
    // references per app in shared namespaces"): only an IN-SCOPE app's
    // reference justifies keeping a secret — an out-of-scope app's stale
    // attachment must not keep the platform PAT alive for the whole
    // namespace, and its reference is cleared while the secret stays for the
    // still-matching apps.
    //
    // KEEP/REMOVE decision only. Credential writes are gated on the durable
    // foreign-replacement UID record (Codex review on #276, P1), not on
    // whether a pending intent or a live reference mentions the name.
    let mut in_scope_referenced_names: BTreeSet<String> = BTreeSet::new();
    for account in &accounts {
        if !account
            .metadata
            .name
            .as_deref()
            .is_some_and(|name| scope.account_in_scope(name))
        {
            continue;
        }
        for reference in account.image_pull_secrets.iter().flatten() {
            in_scope_referenced_names.insert(reference.name.clone());
        }
        // Pending references for in-scope accounts are desired too. Seed
        // them before any repairs, so an out-of-scope account processed
        // first cannot delete a secret another account will restore.
        if runs_durable_pull_secret_repair(delete_mode) {
            for repair in pending_reference_repairs(account) {
                in_scope_referenced_names.insert(repair.secret_name.clone());
            }
        }
    }
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let mut converged = true;
    let mut removed = 0usize;
    let mut kept = 0usize;
    // Codex review on #276, P1: a UID mismatch proves the live object is a
    // tenant replacement. Seed from annotations written by earlier sweeps,
    // then add UIDs observed in this pass so the keep loop cannot refresh
    // them even before the annotation write is visible on a re-read.
    let mut foreign_replacements: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for account in &accounts {
        for entry in foreign_pull_secret_replacements(account) {
            note_foreign_replacement(
                &mut foreign_replacements,
                &entry.secret_name,
                entry.cleared_uid.as_deref(),
            );
        }
    }
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
    if runs_durable_pull_secret_repair(delete_mode) {
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
                        if newer_pull_secret_scope(&live) {
                            return Err(DeployError::PullSecretReconcileDeferred(format!(
                                "newer repository-scope epoch owns {namespace}/{secret_name}"
                            )));
                        }
                        let account_in_scope = scope.account_in_scope(account_name);
                        if scope.namespace_in_scope
                            && secret_name == settings.configured_name
                            && !account_in_scope
                        {
                            // Codex review on #243, P1 "reconcile pull-secret
                            // references per app in shared namespaces": this
                            // account's app no longer matches the repository
                            // scope while another app in the namespace still
                            // does — the configured Secret STAYS for those
                            // apps, so neither restoring this account's
                            // reference nor completing its pending removal is
                            // correct. The cleared reference is the desired
                            // narrowed state for THIS account; the durable
                            // intent is kept (not discharged) so a later
                            // broadening re-attaches it without waiting for a
                            // redeploy. A different UID is a tenant
                            // replacement — not ours to detach — so its
                            // reference is restored by name and the intent
                            // discharged by that restore.
                            if live.metadata.deletion_timestamp.is_some() {
                                // An accepted old delete may still finish; wait
                                // for the 404 before deciding anything.
                                converged = false;
                                continue;
                            }
                            if !cleared_uid_matches {
                                let Some(replacement_uid) =
                                    live.metadata.uid.clone().filter(|uid| !uid.is_empty())
                                else {
                                    converged = false;
                                    tracing::warn!(
                                        %namespace,
                                        secret = %secret_name,
                                        "tenant image pull secret reconcile: UID mismatch but the \
                                         replacement has no UID; retaining the repair intent"
                                    );
                                    continue;
                                };
                                note_foreign_replacement(
                                    &mut foreign_replacements,
                                    &secret_name,
                                    Some(&replacement_uid),
                                );
                                if let Err(error) =
                                    restore_pull_secret_reference_to_service_account(
                                        engine,
                                        namespace,
                                        account_name,
                                        &secret_name,
                                        Some(&replacement_uid),
                                    )
                                    .await
                                {
                                    converged = false;
                                    tracing::warn!(%namespace, %error, "failed to restore replacement pull secret reference");
                                }
                                continue;
                            }
                            tracing::info!(
                                %namespace,
                                service_account = %account_name,
                                secret = %secret_name,
                                "tenant image pull secret reconcile: kept the configured secret for \
                                 in-scope apps; this out-of-scope app's reference stays cleared \
                                 (durable intent retained, re-attached on a later broadening)"
                            );
                            continue;
                        }
                        if account_in_scope
                            && (secret_name == settings.configured_name || cleared_uid_matches)
                        {
                            // Scope may have expanded since the removal intent was
                            // recorded. The desired secret wins over stale cleanup.
                            // A UID-proven unlabeled pre-rotation secret is invisible
                            // to discovery: refresh/adopt it before reattaching.
                            // Codex review on #243, P2 "restore pending old-name
                            // secrets after scope expansion": a UID-proven OLD-name
                            // intent is desired too — after a rename plus a
                            // narrowing-then-expansion, the workload has not
                            // redeployed and still needs its recorded old-name
                            // reference, so refreshing/restoring it beats deleting
                            // valid credentials the earlier cleanup itself
                            // recorded (falling through to the removal path here
                            // used to delete them and converge, leaving pod
                            // restarts unable to pull until another deployment).
                            if live.metadata.deletion_timestamp.is_some() {
                                // An accepted old delete may still finish. Keep
                                // the intent until 404, then recreate first.
                                converged = false;
                                continue;
                            }
                            // Scope may have expanded since the removal intent was
                            // recorded. The desired secret wins over stale cleanup.
                            // A UID-proven unlabeled pre-rotation secret is invisible
                            // to discovery: refresh/adopt it before reattaching.
                            let Some(expected) = settings.configured_secret_data.as_deref() else {
                                converged = false;
                                continue;
                            };
                            // Only the recorded object is ownership-proven. A different UID
                            // may be a tenant replacement: restore its reference by name,
                            // but never label it or overwrite it with the platform PAT.
                            if !cleared_uid_matches {
                                let Some(replacement_uid) =
                                    live.metadata.uid.clone().filter(|uid| !uid.is_empty())
                                else {
                                    converged = false;
                                    tracing::warn!(
                                        %namespace,
                                        secret = %secret_name,
                                        "tenant image pull secret reconcile: UID mismatch but the \
                                         replacement has no UID; retaining the repair intent"
                                    );
                                    continue;
                                };
                                note_foreign_replacement(
                                    &mut foreign_replacements,
                                    &secret_name,
                                    Some(&replacement_uid),
                                );
                                if let Err(error) =
                                    restore_pull_secret_reference_to_service_account(
                                        engine,
                                        namespace,
                                        account_name,
                                        &secret_name,
                                        Some(&replacement_uid),
                                    )
                                    .await
                                {
                                    converged = false;
                                    tracing::warn!(%namespace, %error, "failed to restore replacement pull secret reference");
                                }
                                continue;
                            }
                            let refreshed = refresh_managed_pull_secret_credentials(
                                engine, namespace, &live, expected,
                            )
                            .await;
                            if let Err(error) = &refreshed {
                                converged = false;
                                tracing::warn!(%namespace, %error, "failed to refresh pending in-scope secret before restoring its reference");
                                continue;
                            }
                            if matches!(refreshed, Ok(false))
                                && !is_labeled_managed_pull_secret(&live)
                                && let Err(error) =
                                    adopt_managed_pull_secret(engine, namespace, &live).await
                            {
                                converged = false;
                                tracing::warn!(%namespace, %error, "failed to adopt pending in-scope secret");
                                continue;
                            }
                            if let Err(error) = restore_pull_secret_reference_to_service_account(
                                engine,
                                namespace,
                                account_name,
                                &secret_name,
                                None,
                            )
                            .await
                            {
                                converged = false;
                                tracing::warn!(%namespace, %error, "failed to restore newly in-scope pull secret reference");
                            }
                            continue;
                        }
                        if scope.namespace_in_scope
                            && !account_in_scope
                            && cleared_uid_matches
                            && in_scope_referenced_names.contains(&secret_name)
                        {
                            // Codex review on #243, P1 per-app guard: another
                            // in-scope app's ServiceAccount still references
                            // this old-name secret, so completing THIS
                            // account's pending removal would delete the
                            // in-scope app's credential. Keep the intent —
                            // this out-of-scope account's cleared reference is
                            // the desired state, and a later broadening
                            // re-attaches it.
                            tracing::info!(
                                %namespace,
                                service_account = %account_name,
                                secret = %secret_name,
                                "tenant image pull secret reconcile: pending removal kept open — an \
                                 in-scope app still references this old-name secret; the \
                                 out-of-scope account's reference stays cleared"
                            );
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
                                Ok(PullSecretRemovalOutcome::NotOurs) => {
                                    // A different object won the name. Record
                                    // its UID before discharging the pending
                                    // intent, or the next sweep refreshes it.
                                    match api.get(&secret_name).await {
                                        Ok(replacement) => {
                                            let Some(uid) = replacement
                                                .metadata
                                                .uid
                                                .clone()
                                                .filter(|uid| !uid.is_empty())
                                            else {
                                                converged = false;
                                                tracing::warn!(
                                                    %namespace,
                                                    secret = %secret_name,
                                                    "tenant image pull secret reconcile: replacement \
                                                     has no UID; retaining the repair intent"
                                                );
                                                continue;
                                            };
                                            note_foreign_replacement(
                                                &mut foreign_replacements,
                                                &secret_name,
                                                Some(&uid),
                                            );
                                            if let Err(error) =
                                                restore_pull_secret_reference_to_service_account(
                                                    engine,
                                                    namespace,
                                                    account_name,
                                                    &secret_name,
                                                    Some(&uid),
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
                                                secret = %secret_name,
                                                %error,
                                                "tenant image pull secret reconcile: failed to re-read \
                                                 a replacement before recording its UID"
                                            );
                                        }
                                    }
                                }
                                Ok(PullSecretRemovalOutcome::Superseded) => {
                                    // This is still the UID-proven managed object,
                                    // not a replacement. Let the active deploy
                                    // attach its own reference; preserve the only
                                    // durable discovery proof for the next sweep.
                                    converged = false;
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
                            // lives under the name. A recorded cleared UID
                            // that does not match is proof the live object is
                            // not ours: record that UID in the same patch that
                            // discharges the intent. A UID-less legacy record
                            // has no such proof.
                            let foreign_uid = if repair.cleared_uid.is_some() {
                                live.metadata.uid.clone().filter(|uid| !uid.is_empty())
                            } else {
                                None
                            };
                            if repair.cleared_uid.is_some() && foreign_uid.is_none() {
                                converged = false;
                                tracing::warn!(
                                    %namespace,
                                    secret = %secret_name,
                                    "tenant image pull secret reconcile: UID mismatch but the \
                                     replacement has no UID; retaining the repair intent"
                                );
                                continue;
                            }
                            if let Some(uid) = foreign_uid.as_deref() {
                                note_foreign_replacement(
                                    &mut foreign_replacements,
                                    &secret_name,
                                    Some(uid),
                                );
                            }
                            if let Err(error) = restore_pull_secret_reference_to_service_account(
                                engine,
                                namespace,
                                account_name,
                                &secret_name,
                                foreign_uid.as_deref(),
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
                        if scope.namespace_in_scope && secret_name == settings.configured_name {
                            // A previous delete finished after scope expanded. Recreate
                            // before reattaching; never declare a missing desired
                            // credential converged merely because refresh saw 404.
                            if let Some(config) = settings.tenant_image_pull_secret_config() {
                                let mut desired =
                                    generate_tenant_image_pull_secret(namespace, &config);
                                stamp_sweep_created_pull_secret_lineage(&mut desired);
                                match api
                                    .create(&pull_secret_create_params(engine), &desired)
                                    .await
                                {
                                    Ok(applied) => {
                                        if !pull_secret_label_owned(engine, &applied) {
                                            if let Err(error) =
                                                remove_untrusted_created_pull_secret(
                                                    &api,
                                                    namespace,
                                                    &config.name,
                                                    &applied,
                                                )
                                                .await
                                            {
                                                tracing::error!(%namespace, secret = %config.name, %error,
                                                    "untrusted pull-secret cleanup has not converged");
                                            }
                                            converged = false;
                                            continue;
                                        }
                                        record_pull_secret_creation(
                                            engine,
                                            namespace,
                                            &applied,
                                            SWEEP_CREATED_PULL_SECRET_GENERATION,
                                        );
                                        // Per-app scope (Codex review on #243, P1):
                                        // only an in-scope account's reference is
                                        // restored; an out-of-scope account keeps
                                        // its cleared reference and its durable
                                        // intent, so a later broadening re-attaches.
                                        if scope.account_in_scope(account_name)
                                            && let Err(error) =
                                                restore_pull_secret_reference_to_service_account(
                                                    engine,
                                                    namespace,
                                                    account_name,
                                                    &secret_name,
                                                    None,
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
    // Codex review on #276, P1: in-scope reconciliation must create the
    // configured secret and attach it to qualifying accounts when discovery
    // returned no managed object and no pending intent remains. A discovered
    // old-name secret or a pending repair already owns that credential; creating
    // a second object there would duplicate the platform PAT.
    let pending_intent = accounts
        .iter()
        .any(|account| !pending_reference_repairs(account).is_empty());
    if scope.namespace_in_scope && managed.is_empty() && !pending_intent {
        match ensure_configured_pull_secret_for_in_scope_accounts(
            engine,
            namespace,
            service_accounts,
            settings,
            scope,
            &api,
            &foreign_replacements,
            delete_mode,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => converged = false,
            Err(DeployError::PullSecretReconcileDeferred(message)) => {
                return Err(DeployError::PullSecretReconcileDeferred(message));
            }
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    %error,
                    "tenant image pull secret reconcile: failed to recreate the configured secret \
                     after scope expansion"
                );
            }
        }
    }
    // Repairs can adopt previously undiscoverable old-name objects. Refresh
    // discovery before deciding which credentials remain available.
    let (managed, _, accounts) =
        discover_managed_pull_secrets(engine, namespace, service_accounts, settings).await?;
    for secret in &managed {
        let Some(name) = secret.metadata.name.as_deref() else {
            continue;
        };
        if keep_managed_pull_secret(
            scope.namespace_in_scope,
            name,
            &settings.configured_name,
            &in_scope_referenced_names,
        ) {
            // Adoption and pending-repair refresh both advance resourceVersion.
            // Always re-read before a second write, and re-prove ownership on
            // that live object rather than reusing the discovery snapshot.
            let live = api
                .get(name)
                .await
                .map_err(|error| DeployError::Apply(error.into()))?;
            if live.metadata.uid != secret.metadata.uid
                || !is_managed_tenant_image_pull_secret(&live, settings.ghcr())
            {
                converged = false;
                continue;
            }
            if newer_pull_secret_scope(&live) {
                return Err(DeployError::PullSecretReconcileDeferred(format!(
                    "newer repository-scope epoch owns {namespace}/{name}"
                )));
            }
            // Even post-apply cleanup must not refresh a replacement before
            // a sweep has converted its pending UID proof into a durable
            // foreign record. Keep the intent intact in Deploy context.
            for account in &accounts {
                for repair in pending_reference_repairs(account) {
                    if repair.secret_name == name
                        && repair.cleared_uid.as_deref().is_some_and(|uid| {
                            live.metadata
                                .uid
                                .as_deref()
                                .is_some_and(|live_uid| live_uid != uid)
                        })
                    {
                        note_foreign_replacement(
                            &mut foreign_replacements,
                            name,
                            live.metadata.uid.as_deref(),
                        );
                    }
                }
            }
            // Codex review on #276, P1: a recorded mismatched UID excludes this
            // object from adoption and credential refresh whether it sits at
            // the configured name, is already referenced by an in-scope
            // account, or only became referenced because the repair pass
            // restored it. Clearing an out-of-scope reference would detach
            // the tenant from their own secret, so skip that too.
            if uid_is_foreign_replacement(&foreign_replacements, name, live.metadata.uid.as_deref())
            {
                tracing::info!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: kept without adopting or refreshing — \
                     this object's UID is a recorded tenant replacement; the platform credential \
                     is never written into it"
                );
                continue;
            }
            kept += 1;
            let terminating = live.metadata.deletion_timestamp.is_some();
            if terminating {
                // Do not attach, and do not clear. A clear would record this
                // dying UID as a pending repair; after the finalizer releases
                // and the next pass recreates the configured secret under a
                // new UID, the repair pass would treat that object as a tenant
                // replacement and reattach it to the excluded account. Leave
                // the references as they are. This pass stays unconverged, so
                // the retry — once the name is free — creates the secret and
                // clears excluded accounts against the new UID.
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: kept secret is terminating; waiting for removal before recreating and attaching"
                );
                continue;
            }
            if !is_labeled_managed_pull_secret(&live)
                && let Err(error) = adopt_managed_pull_secret(engine, namespace, &live).await
            {
                converged = false;
                tracing::warn!(%namespace, secret = %name, %error,
                        "failed to label a kept legacy pull secret — will retry");
                continue;
            } else if let Some(expected) = settings.configured_secret_data.as_deref() {
                match api.get(name).await {
                    Ok(refreshed)
                        if is_managed_tenant_image_pull_secret(&refreshed, settings.ghcr()) =>
                    {
                        if newer_pull_secret_scope(&refreshed)
                            || newer_pull_secret_credentials(&refreshed)
                        {
                            return Err(DeployError::PullSecretReconcileDeferred(format!(
                                "newer repository-scope epoch owns {namespace}/{name}"
                            )));
                        }
                        if refreshed.metadata.deletion_timestamp.is_some() {
                            converged = false;
                            tracing::warn!(
                                %namespace,
                                secret = %name,
                                "tenant image pull secret reconcile: kept secret is terminating; waiting for removal before recreating and attaching"
                            );
                            continue;
                        } else if let Err(error) = refresh_managed_pull_secret_credentials(
                            engine, namespace, &refreshed, expected,
                        )
                        .await
                        {
                            converged = false;
                            tracing::warn!(%namespace, secret = %name, %error,
                                    "failed to refresh kept pull secret — will retry");
                        }
                    }
                    Ok(_) => {
                        converged = false;
                        tracing::warn!(%namespace, secret = %name,
                                "kept pull secret changed ownership after discovery");
                    }
                    Err(error) => {
                        converged = false;
                        tracing::warn!(%namespace, secret = %name, %error,
                                "failed to re-read kept pull secret");
                    }
                }
            }
            // Codex review on #243, P1 "reconcile pull-secret references per
            // app in shared namespaces": a KEPT secret can still be
            // referenced by an out-of-scope app's ServiceAccount — the
            // namespace-level keep decision (another app still qualifies)
            // used to leave that stale attachment in place, so the
            // out-of-scope app kept pulling with the platform PAT across pod
            // restarts. Clear it per app; the clear records the durable
            // repair intent (with this verified object's UID) so a later
            // broadening refreshes and re-attaches the reference without
            // waiting for the app to redeploy. A clear failure is retried by
            // the next pass — the secret stays, so discovery keeps finding
            // both the reference and the intent.
            //
            // Codex review on #243, round 2, P1 "fence per-app reference
            // clears against concurrent deploys": the per-app scope comes
            // from the sweep's inventory snapshot. If a concurrent deploy of
            // this app re-scoped it back in, it rewrote the Secret under a
            // mutation generation newer than (or equal-and-active with) the
            // snapshot and attached the reference we are about to clear.
            // Fence the clears with the same generation/lease check the
            // delete path uses; the next sweep — whose inventory includes
            // the deploy — re-decides per app.
            let concurrent_deploy_owns_secret =
                observed_concurrent_deploy_owns(delete_mode, secret_mutation_generation(&live));
            if concurrent_deploy_owns_secret {
                // Uniform in-scope deploy callers have no clears to defer.
                // Mixed-scope sweeps cannot certify the skipped cleanup.
                if service_accounts
                    .iter()
                    .any(|account| !scope.account_in_scope(account))
                {
                    converged = false;
                }
                tracing::info!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: skipped per-app reference clears — a \
                     concurrent deploy (mutation generation newer than or equal-and-active with \
                     the sweep snapshot) owns the secret; the next sweep re-decides per app"
                );
                continue;
            }
            for service_account in service_accounts {
                if scope.account_in_scope(service_account) {
                    // Configured name: attach even to newly qualifying accounts
                    // with no pending repair. Legacy names: only accounts that
                    // already reference them or have a pending repair, so a
                    // rename can still drop the old credential (Codex review
                    // on #276, P2).
                    if runs_durable_pull_secret_repair(delete_mode)
                        && kept_pull_secret_should_attach(
                            name,
                            &settings.configured_name,
                            service_account,
                            &accounts,
                        )
                        && let Err(error) = restore_pull_secret_reference_to_service_account(
                            engine,
                            namespace,
                            service_account,
                            name,
                            None,
                        )
                        .await
                    {
                        converged = false;
                        tracing::warn!(%namespace, %service_account, secret = %name, %error,
                            "failed to attach kept pull secret to an in-scope account");
                    }
                    continue;
                }
                match clear_pull_secret_reference_from_service_account(
                    engine,
                    namespace,
                    service_account,
                    name,
                    live.metadata.uid.as_deref(),
                    delete_mode,
                )
                .await
                {
                    Ok(_) => {}
                    Err(error) => {
                        converged = false;
                        tracing::warn!(
                            %namespace,
                            service_account = %service_account,
                            secret = %name,
                            %error,
                            "tenant image pull secret reconcile: failed to clear an out-of-scope \
                             app's ServiceAccount reference to a kept secret — retried on the \
                             next pass"
                        );
                    }
                }
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
        if newer_pull_secret_scope(&live) {
            // An older replica cannot certify this namespace clean. Keeping
            // the secret is necessary, but calling that convergence would open
            // admission while an unknown newer policy owns the PAT.
            return Err(DeployError::PullSecretReconcileDeferred(format!(
                "newer repository-scope epoch owns {namespace}/{name}"
            )));
        }
        if !is_managed_tenant_image_pull_secret(&live, settings.ghcr()) {
            tracing::warn!(
                %namespace,
                secret = %name,
                "tenant image pull secret reconcile: skipped — the secret is no longer \
                 CAP-managed (replaced after discovery); keeping it and its references"
            );
            continue;
        }
        if uid_is_foreign_replacement(&foreign_replacements, name, live.metadata.uid.as_deref()) {
            tracing::info!(
                %namespace,
                secret = %name,
                "tenant image pull secret reconcile: not deleting a recorded tenant replacement"
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
        //
        // Codex review on #243, P1 "fence secret-name rollouts before
        // deleting new secrets": a deploy that acquired the namespace lease
        // BEFORE the sweep snapshot writes at a mutation generation EQUAL to
        // `namespace_generation`, which the strict `>` cannot distinguish
        // from completed residue. While that lease was still HELD at snapshot
        // time, the generation is concurrent (the deploy's ServiceAccount
        // apply may not have landed — e.g. a mid-rollout new-name Secret is
        // unreferenced residue only until then), so an equal generation is
        // skipped too. Once the lease is released the strict fence resumes:
        // an unreferenced, unkept secret at the same generation is then
        // completed residue a later sweep may remove.
        if observed_generation_blocks_removal(delete_mode, secret_mutation_generation(&live)) {
            converged = false;
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
                delete_mode,
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
                    None,
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
                converged = false;
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
            let replacement_uid = match api.get(name).await {
                Ok(replacement) => replacement.metadata.uid.filter(|uid| !uid.is_empty()),
                Err(error) => {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        secret = %name,
                        %error,
                        "tenant image pull secret reconcile: failed to re-read a mid-cleanup \
                         replacement before recording its UID; references stay cleared"
                    );
                    continue;
                }
            };
            let Some(replacement_uid) = replacement_uid else {
                converged = false;
                tracing::warn!(
                    %namespace,
                    secret = %name,
                    "tenant image pull secret reconcile: mid-cleanup replacement has no UID; \
                     references stay cleared until it can be recorded"
                );
                continue;
            };
            note_foreign_replacement(&mut foreign_replacements, name, Some(&replacement_uid));
            for service_account in &cleared_references {
                match restore_pull_secret_reference_to_service_account(
                    engine,
                    namespace,
                    service_account,
                    name,
                    Some(&replacement_uid),
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
    // Use post-repair/removal outcomes, never the discovery snapshot.
    // Kept old-name credentials already serve the qualifying accounts.
    if scope.namespace_in_scope && kept == 0 && converged {
        match ensure_configured_pull_secret_for_in_scope_accounts(
            engine,
            namespace,
            service_accounts,
            settings,
            scope,
            &api,
            &foreign_replacements,
            delete_mode,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => converged = false,
            Err(DeployError::PullSecretReconcileDeferred(message)) => {
                return Err(DeployError::PullSecretReconcileDeferred(message));
            }
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    %error,
                    "tenant image pull secret reconcile: failed to recreate the configured secret \
                     after scope expansion"
                );
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
        if verified_uid.is_some() && !uid_verified {
            return Ok(PullSecretRemovalOutcome::NotOurs);
        }
        if newer_pull_secret_scope(&existing) {
            return Err(DeployError::PullSecretReconcileDeferred(format!(
                "newer repository-scope epoch owns {namespace}/{name}"
            )));
        }
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
        if observed_generation_blocks_removal(delete_mode, secret_mutation_generation(&existing)) {
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

/// Best-effort, UID-preconditioned compensation of objects a step created
/// whose ledger rows could not be persisted. Only objects THIS apply just
/// created (records drained from the engine's own observation of its
/// create POSTs) are ever touched; a 404 is the already-gone success.
async fn compensate_unledgered_creations(
    engine: &ApplyEngine,
    records: &[enclava_engine::apply::creation_ledger::CreationRecord],
    mutation: &crate::mutation_leases::AppMutationLease,
) {
    for record in records {
        if record.kind == "Namespace" {
            if mutation
                .resource_generation(&crate::mutation_leases::ResourceFence::new(
                    "kubernetes_namespace",
                    &record.name,
                ))
                .is_none()
            {
                tracing::error!(name = %record.name,
                    "no matching namespace fence; refusing compensation DELETE");
                continue;
            }
            // DELETE acceptance is not absence. Persist the retained marker
            // BEFORE sending it: cleanup cannot prove this unledgered UID's
            // lineage and would otherwise classify it as adopted and release
            // the name while Kubernetes is still terminating the namespace.
            if let Err(error) = mutation
                .relabel_namespace_fence_fail_closed(
                    "kubernetes_namespace",
                    crate::mutation_leases::RETAINED_DEPLOYMENT_NAMESPACE_OPERATION,
                )
                .await
            {
                tracing::error!(name = %record.name, error = %error,
                    "cannot retain namespace fence; refusing compensation DELETE");
                continue;
            }
        }
        let ar = crate::deployment_failure_cleanup::sweep_api_resource(&record.kind);
        let api: kube::Api<kube::api::DynamicObject> = match &record.namespace {
            Some(namespace) => kube::Api::namespaced_with(engine.client().clone(), namespace, &ar),
            // Cluster-scoped creations (the namespace itself).
            None => kube::Api::all_with(engine.client().clone(), &ar),
        };
        let delete_params = kube::api::DeleteParams {
            preconditions: Some(kube::api::Preconditions {
                uid: Some(record.uid.clone()),
                resource_version: None,
            }),
            ..kube::api::DeleteParams::default()
        };
        let delete = api.delete(&record.name, &delete_params);
        match enclava_engine::apply::bounded_kube_write(delete).await {
            Ok(_) => {
                tracing::info!(
                    kind = %record.kind,
                    name = %record.name,
                    "compensated an unledgered creation (delete accepted)"
                );
            }
            Err(enclava_engine::apply::engine::ApplyError::Kube(kube::Error::Api(error)))
                if error.code == 404 =>
            {
                // Already gone: successful compensation.
            }
            Err(error) => {
                tracing::warn!(
                    kind = %record.kind,
                    name = %record.name,
                    error = %error,
                    "could not compensate an unledgered creation; the failed-apply sweep will hold it unresolved (fail closed)"
                );
            }
        }
    }
}

/// Insert a released `kubernetes_namespace` lease at the sweep-created
/// generation when the snapshot has no row. Returns whether this call
/// inserted it. `ON CONFLICT DO NOTHING` loses to a deploy that claimed the
/// namespace after the snapshot; that caller must keep the conservative
/// no-row mode. A released row does not hold the lease, so the next claim
/// increments generation and a real deploy write stays strictly newer.
async fn publish_missing_namespace_pull_secret_lease(
    pool: &PgPool,
    namespace: &str,
) -> Result<bool, sqlx::Error> {
    let inserted = sqlx::query(
        "INSERT INTO external_resource_mutation_leases(\
            resource_scope, resource_key, generation) \
         VALUES ('kubernetes_namespace', $1, $2) \
         ON CONFLICT (resource_scope, resource_key) DO NOTHING",
    )
    .bind(namespace)
    .bind(SWEEP_CREATED_PULL_SECRET_GENERATION)
    .execute(pool)
    .await?;
    Ok(inserted.rows_affected() == 1)
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
pub async fn cleanup_stale_tenant_image_pull_secrets_at_startup(
    pool: &PgPool,
    client: &kube::Client,
) -> bool {
    // No whole-sweep timeout (Codex review on #243, P1 follow-up): every
    // namespace's reconciliation is individually bounded by
    // `sweep_namespace_with_budget`, so the sweep always terminates — a
    // stalled API server can no longer hang the pre-listen startup (or the
    // background reconciler) forever — while a whole-pass budget would cancel
    // the sweep at an arbitrary namespace and make every retry restart from
    // the first one, deterministically starving the tail namespaces on
    // clusters whose healthy traversal exceeds the budget.
    match cleanup_stale_tenant_image_pull_secrets(pool, client).await {
        Ok(true) => true,
        Ok(false) => {
            tracing::error!(
                "tenant image pull secret cleanup did not converge: stale secrets may remain"
            );
            false
        }
        Err(error) => {
            tracing::error!(
                %error,
                "tenant image pull secret cleanup failed; stale secrets may remain"
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
/// The `budget` is the namespace's REMAINING single deadline — the probe,
/// mutation guard, and this reconciliation draw from one shared window, so
/// a stalled probe cannot buy a second full one (codex review on #306).
async fn sweep_namespace_with_budget(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
    scope: &PullSecretAccountScope,
    delete_mode: PullSecretDeleteMode,
    budget: std::time::Duration,
) -> Result<bool, DeployError> {
    match tokio::time::timeout(
        budget,
        reconcile_managed_pull_secrets(
            engine,
            namespace,
            service_accounts,
            settings,
            scope,
            delete_mode,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            tracing::error!(
                %namespace,
                budget_secs = budget.as_secs(),
                "tenant image pull secret cleanup sweep: reconciling this namespace exceeded \
                 its budget (stalled Kubernetes API?); treating it as not converged and \
                 continuing with the remaining namespaces"
            );
            Ok(false)
        }
    }
}

/// Per-namespace janitor inventory: per-app (generated ServiceAccount, image
/// list) pairs (`None` in an app's images means one of its stored image refs
/// is unparsable, which never qualifies for the secret). Per-app granularity
/// (Codex review on #243, P1 "reconcile pull-secret references per app in
/// shared namespaces"): a shared namespace can hold one app that still
/// matches the repository scope and another that no longer does, and the
/// sweep must keep the secret for the first while clearing the second's
/// `imagePullSecrets` attachment.
type NamespacePullSecretInventory =
    std::collections::BTreeMap<String, Vec<(String, Option<Vec<ImageRef>>)>>;

/// True only on an explicit NotFound. A namespace that does not exist cannot
/// hold a stale pull secret, so the sweep skips its app rows entirely (#305):
/// a `deleting` row whose namespace is already gone — or a blocked create
/// whose namespace never materialized because admission was closed — must not
/// keep workload admission closed fleet-wide. Any other outcome (the
/// namespace exists, or the API server answered something other than
/// NotFound) falls through to the normal reconcile, preserving today's
/// behavior; the per-deploy cleanup remains the hard gate for everything that
/// does exist.
async fn namespace_absent(
    engine: &ApplyEngine,
    namespace: &str,
    budget: std::time::Duration,
) -> bool {
    let api: Api<Namespace> = Api::all(engine.client().clone());
    // Draws from the namespace's shared deadline, not a fresh window
    // (review on #306): a stalled API server must not hang the sweep on
    // this probe — a timeout falls through to the normal reconcile, which
    // spends only what is left of the same budget and reports its own
    // outcome.
    let probe = tokio::time::timeout(budget, api.get(namespace));
    matches!(
        probe.await,
        Ok(Err(kube::Error::Api(error))) if error.code == 404
    )
}

async fn cleanup_stale_tenant_image_pull_secrets(
    pool: &PgPool,
    client: &kube::Client,
) -> Result<bool, DeployError> {
    let settings = PullSecretSettings::from_env();
    let config = tenant_image_pull_secret_config_from_env();

    // Publish the rollout even for an empty fleet, before any inventory can
    // stall or omit namespaces created by concurrent older replicas. Retain
    // the per-namespace recheck below to observe subsequent authority raises.
    let (scope_epoch, credential_epoch) = tokio::time::timeout(
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
        raise_tenant_pull_secret_rollout_authority(
            pool,
            pull_secret_scope_generation(),
            pull_secret_credential_generation(),
        ),
    )
    .await
    .map_err(|_| {
        DeployError::PullSecretReconcileDeferred(
            "timed out publishing rollout-wide pull-secret authority".to_string(),
        )
    })??;
    if pull_secret_rollout_authority_defers(scope_epoch, credential_epoch) {
        return Ok(false);
    }

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
        // Codex review on #243, P1 "fence secret-name rollouts before
        // deleting new secrets": the snapshot also records whether the
        // namespace's lease was HELD by an in-flight deploy at read time —
        // an ACTIVE lease generation is concurrent (the deploy's
        // ServiceAccount apply may not have landed), so secrets it wrote at
        // that exact generation are skipped instead of being erased as
        // unreferenced residue.
        let leases = crate::mutation_leases::snapshot_namespace_mutation_leases(pool).await?;
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
    let lease_rows: std::collections::BTreeMap<String, (i64, bool)> = lease_rows
        .into_iter()
        .map(|(namespace, generation, held)| (namespace, (generation, held)))
        .collect();

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
        by_namespace
            .entry(namespace)
            .or_default()
            .push((service_account, images));
    }

    let engine = ApplyEngine::new(client.clone(), ApplyConfig::default());
    // A failed write leaves the platform token exposed in the namespace — the
    // sweep must report that as not-converged, not "sweep complete" (review
    // finding): the caller keeps workload admission closed on it and retries.
    let mut converged = true;
    for (namespace, apps_in_namespace) in &by_namespace {
        // In-scope namespaces are reconciled too (review finding): pre-label
        // secrets there must be adopted (labeled) before the keep decision
        // applies, and unreferenced residue (e.g. a renamed old secret) must
        // not survive.
        //
        // Per-app scope decisions (Codex review on #243, P1 "reconcile
        // pull-secret references per app in shared namespaces"): the
        // namespace-level keep decision only keeps the Secret; WHICH
        // ServiceAccounts keep their `imagePullSecrets` attachment is decided
        // per app, so a still-matching app retains the credential while a
        // no-longer-matching app's reference is cleared in the same pass.
        let service_accounts: Vec<String> = apps_in_namespace
            .iter()
            .map(|(service_account, _)| service_account.clone())
            .collect();
        let app_images: Vec<Option<Vec<ImageRef>>> = apps_in_namespace
            .iter()
            .map(|(_, images)| images.clone())
            .collect();
        let scope = PullSecretAccountScope {
            namespace_in_scope: namespace_keeps_tenant_image_pull_secret(
                config.as_ref(),
                &app_images,
            ),
            in_scope_accounts: match config.as_ref() {
                Some(config) => apps_in_namespace
                    .iter()
                    .filter(|(_, images)| {
                        app_keeps_tenant_image_pull_secret(config, images.as_ref())
                    })
                    .map(|(service_account, _)| service_account.clone())
                    .collect(),
                None => Default::default(),
            },
        };
        // Codex review on #243, P1 "fence narrowed scopes against older
        // replicas" + round 2 P1: a NEWER recorded scope epoch owns this
        // namespace's pull secrets — this replica's (possibly broader)
        // policy must not create, refresh, or delete anything there, and
        // cannot certify it converged; the newer replica's sweep converges
        // it. The stamp is checked against the AUTHORITATIVE epoch the
        // monotonic upsert leaves behind: a concurrent newer replica that
        // raised the fence between the inventory read and this write wins,
        // and this sweep defers. Otherwise this sweep acts under the
        // current epoch and records it durably (outside the deletable
        // Secret), so any older replica that later sweeps or deploys here
        // defers instead of resurrecting the platform PAT a newer rollout
        // removed.
        let authoritative_fence_epoch = match record_tenant_pull_secret_scope_fence(
            pool,
            namespace,
            pull_secret_scope_generation(),
        )
        .await
        {
            Ok(epoch) => epoch,
            Err(error) => {
                converged = false;
                tracing::warn!(
                    %namespace,
                    %error,
                    "tenant image pull secret cleanup sweep: failed to record the scope-epoch \
                     fence — treating the namespace as not converged"
                );
                continue;
            }
        };
        if pull_secret_scope_fence_defers(authoritative_fence_epoch) {
            converged = false;
            tracing::warn!(
                %namespace,
                fence_epoch = authoritative_fence_epoch,
                replica_epoch = pull_secret_scope_generation(),
                "tenant image pull secret cleanup sweep: a newer repository-scope epoch \
                 owns this namespace's pull secrets — deferring to the newer policy; this \
                 replica's sweep cannot converge or touch it"
            );
            continue;
        }
        // Codex review on #243, round 3: rollout-wide authority (see
        // [`raise_tenant_pull_secret_rollout_authority`]). The per-namespace
        // fence above only defers namespaces a newer replica already swept;
        // a namespace created after that sweep has no row, and a namespace
        // without the configured-name Secret carries no credential epoch to
        // compare against. A replica below either fleet-wide maximum defers
        // the whole namespace (not converged): no create-on-404, no repair,
        // no reference restores — the newer rollout's sweep converges it.
        let (authority_scope_epoch, authority_credential_epoch) =
            match raise_tenant_pull_secret_rollout_authority(
                pool,
                pull_secret_scope_generation(),
                pull_secret_credential_generation(),
            )
            .await
            {
                Ok(maxima) => maxima,
                Err(error) => {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        %error,
                        "tenant image pull secret cleanup sweep: failed to raise the \
                         rollout-wide pull-secret authority — treating the namespace as \
                         not converged"
                    );
                    continue;
                }
            };
        if pull_secret_rollout_authority_defers(authority_scope_epoch, authority_credential_epoch) {
            converged = false;
            tracing::warn!(
                %namespace,
                authority_scope_epoch,
                authority_credential_epoch,
                replica_scope_epoch = pull_secret_scope_generation(),
                replica_credential_epoch = pull_secret_credential_generation(),
                "tenant image pull secret cleanup sweep: a newer pull-secret rollout \
                 exists fleet-wide — this replica defers all tenant pull-secret work \
                 (including namespaces without a fence row or a live Secret) until \
                 upgraded"
            );
            continue;
        }
        // Authority rechecks above stay in force for absent namespaces too
        // (review on #306): a stale replica must still defer when a newer
        // epoch was raised mid-sweep — and the guard below is what makes
        // the rechecks stick for the skip path (see its comment). Nothing
        // to clean in an absent namespace, and the per-deploy cleanup gates
        // whatever deploy later creates it.
        // One shared deadline per namespace covers the probe, the mutation
        // guard, and the reconcile (codex review on #306): a stalled step
        // must not buy a second full window — once the budget is spent the
        // remaining steps time out immediately, the namespace reports
        // unconverged for this pass, and the next sweep cycle retries it.
        let namespace_deadline_started = tokio::time::Instant::now();
        let remaining_namespace_budget = || {
            PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT
                .saturating_sub(namespace_deadline_started.elapsed())
        };
        // Probe BEFORE taking the guard — it is a read-only GET that needs
        // no mutation fence, and running it under the guard held the shared
        // advisory lock across a network op (Devin review on #306, rounds
        // 3–4: a stalled or merely slow GET then either blocked a newer
        // replica's exclusive authority publication or surrendered too
        // early and resurrected the admission wedge on slow API servers).
        // Absence is only ACCEPTED afterwards, under the guard: its epoch
        // read under the shared advisory lock is the authority fence (codex
        // review on #306, round 2) — a fleet epoch raised before the guard
        // is caught there and defers this stale replica, and none can be
        // raised between that read and the skip because the exclusive side
        // waits on our shared hold. An in-flight, not-yet-published raise
        // matches present-namespace mid-pass semantics: the next sweep's
        // start-of-sweep authority read defers the whole pass.
        let namespace_is_absent = namespace_absent(
            &engine,
            namespace,
            remaining_namespace_budget().min(NAMESPACE_ABSENCE_PROBE_TIMEOUT),
        )
        .await;
        let _mutation_guard = match tokio::time::timeout(
            remaining_namespace_budget(),
            pull_secret_mutation_guard(pool),
        )
        .await
        {
            Ok(Ok(guard)) => guard,
            _ => {
                converged = false;
                continue;
            }
        };
        if namespace_is_absent {
            tracing::info!(
                %namespace,
                "tenant image pull secret cleanup sweep: namespace does not exist — \
                 skipping (no stale secret can live there)"
            );
            continue;
        }
        let snapshot = lease_rows.get(namespace).copied();
        // Codex review on #278, P1: a namespace with no lease row (migration
        // 0042 did not backfill) must not reconcile under generation 0 after
        // this sweep stamps generation 1. Publish a released row first. A
        // lost insert means a deploy claimed the namespace after the
        // snapshot; keep generation 0 so that write stays protected.
        let published_missing_row = if snapshot.is_none() {
            // Codex review on #280, P1: a concurrent transaction holding the
            // same lease key open would make this INSERT ... ON CONFLICT wait
            // indefinitely under the mutation guard — bound it by the same
            // namespace budget as every other await here.
            match tokio::time::timeout(
                remaining_namespace_budget(),
                publish_missing_namespace_pull_secret_lease(pool, namespace),
            )
            .await
            {
                Ok(Ok(inserted)) => inserted,
                Ok(Err(error)) => {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        %error,
                        "tenant image pull secret cleanup sweep: failed to publish a released \
                         lease for a namespace with no row — treating it as not converged"
                    );
                    continue;
                }
                Err(_) => {
                    converged = false;
                    tracing::warn!(
                        %namespace,
                        "tenant image pull secret cleanup sweep: publishing a released lease \
                         for a namespace with no row exceeded the namespace budget — treating \
                         it as not converged"
                    );
                    continue;
                }
            }
        } else {
            false
        };
        match sweep_namespace_with_budget(
            &engine,
            namespace,
            &service_accounts,
            &settings,
            &scope,
            unfenced_pull_secret_delete_mode(snapshot, published_missing_row),
            remaining_namespace_budget(),
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
    delete_mode: PullSecretDeleteMode,
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
    // Devin review on #278: the sweep's generation check already passed, then
    // a deploy attached this reference. The clear reads the latest
    // ServiceAccount, so its resourceVersion cannot see that the scope
    // decision is stale. Re-read the secret AFTER this ServiceAccount GET
    // and refuse the clear when a concurrent deploy now owns it.
    if runs_durable_pull_secret_repair(delete_mode) {
        let secret_api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
        match secret_api.get(secret_name).await {
            Ok(live)
                if observed_concurrent_deploy_owns(
                    delete_mode,
                    secret_mutation_generation(&live),
                ) =>
            {
                tracing::info!(
                    namespace = %namespace,
                    service_account = %service_account,
                    secret = %secret_name,
                    "tenant image pull secret reconcile: refused to clear a ServiceAccount \
                     reference — a concurrent deploy rewrote the secret after the sweep's \
                     generation check"
                );
                return Err(DeployError::PullSecretReconcileDeferred(format!(
                    "concurrent deploy owns {namespace}/{secret_name}; refusing to clear \
                     {service_account}'s reference attached after the sweep snapshot"
                )));
            }
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 404 => {}
            Err(error) => return Err(DeployError::Apply(error.into())),
        }
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
            if runs_durable_pull_secret_repair(delete_mode) {
                let secret_api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
                match secret_api.get(secret_name).await {
                    Ok(live)
                        if observed_concurrent_deploy_owns(
                            delete_mode,
                            secret_mutation_generation(&live),
                        ) =>
                    {
                        restore_pull_secret_reference_to_service_account(
                            engine,
                            namespace,
                            service_account,
                            secret_name,
                            None,
                        )
                        .await?;
                        return Err(DeployError::PullSecretReconcileDeferred(format!(
                            "concurrent deploy rewrote {namespace}/{secret_name} during reference \
                             clear; restored {service_account}'s reference and deferred"
                        )));
                    }
                    Ok(_) => {}
                    Err(kube::Error::Api(error)) if error.code == 404 => {}
                    Err(error) => return Err(DeployError::Apply(error.into())),
                }
            }
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

/// `name=uid` entries on [`FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION`].
/// Entries without a UID are ignored: a name alone is not proof that a live
/// object is a tenant replacement.
fn foreign_pull_secret_replacements(account: &ServiceAccount) -> Vec<PendingReferenceRepair> {
    account
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION))
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter_map(|entry| {
                    let (name, uid) = entry.split_once('=')?;
                    if name.is_empty() || uid.is_empty() {
                        return None;
                    }
                    Some(PendingReferenceRepair {
                        secret_name: name.to_string(),
                        cleared_uid: Some(uid.to_string()),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn render_foreign_pull_secret_replacements(entries: &[PendingReferenceRepair]) -> String {
    entries
        .iter()
        .filter_map(|entry| {
            entry
                .cleared_uid
                .as_ref()
                .map(|uid| format!("{}={}", entry.secret_name, uid))
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn note_foreign_replacement(
    foreign: &mut BTreeMap<String, BTreeSet<String>>,
    name: &str,
    uid: Option<&str>,
) {
    if let Some(uid) = uid.filter(|uid| !uid.is_empty()) {
        foreign
            .entry(name.to_string())
            .or_default()
            .insert(uid.to_string());
    }
}

fn uid_is_foreign_replacement(
    foreign: &BTreeMap<String, BTreeSet<String>>,
    name: &str,
    uid: Option<&str>,
) -> bool {
    uid.is_some_and(|uid| foreign.get(name).is_some_and(|uids| uids.contains(uid)))
}

/// Re-add `secret_name` to a ServiceAccount's `imagePullSecrets` after a
/// reference clear turned out to rest on stale ownership information (review
/// finding on #243): when the delete detects that the secret was replaced
/// mid-cleanup, the replacement survives and must keep the reference it
/// inherits by name — otherwise its pods lose registry access. No-op when the
/// ServiceAccount is gone or already references the secret and no foreign-UID
/// record is outstanding. The patch mirrors
/// [`clear_pull_secret_reference_from_service_account`]: attributed to the
/// engine field manager and pinned to the observed resourceVersion. It also
/// discharges the name's durable repair intent — a proven restore is exactly
/// what the pending-repairs annotation was waiting for (Codex review on #243,
/// P2).
///
/// `foreign_replacement_uid`, when set, is written into
/// [`FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION`] in the same patch that
/// discharges the pending intent (Codex review on #276, P1). The pending
/// annotation is the only other copy of that UID; discharging it without
/// recording the replacement would let the next sweep refresh the object.
async fn restore_pull_secret_reference_to_service_account(
    engine: &ApplyEngine,
    namespace: &str,
    service_account: &str,
    secret_name: &str,
    foreign_replacement_uid: Option<&str>,
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
    let foreign = foreign_pull_secret_replacements(&existing);
    let foreign_uid = foreign_replacement_uid.filter(|uid| !uid.is_empty());
    let needs_foreign_record = foreign_uid.is_some_and(|uid| {
        !foreign.iter().any(|entry| {
            entry.secret_name == secret_name && entry.cleared_uid.as_deref() == Some(uid)
        })
    });
    let mut references: Vec<serde_json::Value> = existing
        .image_pull_secrets
        .iter()
        .flatten()
        .map(|r| serde_json::json!({ "name": r.name }))
        .collect();
    let already_referenced = references
        .iter()
        .any(|r| r.get("name").and_then(|name| name.as_str()) == Some(secret_name));
    if already_referenced
        && !pending.iter().any(|entry| entry.secret_name == secret_name)
        && !needs_foreign_record
    {
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
    if needs_foreign_record && let Some(uid) = foreign_uid {
        let mut recorded = foreign;
        recorded.push(PendingReferenceRepair {
            secret_name: secret_name.to_string(),
            cleared_uid: Some(uid.to_string()),
        });
        annotations.insert(
            FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
            serde_json::Value::String(render_foreign_pull_secret_replacements(&recorded)),
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

async fn recorded_foreign_replacement_uids(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    secret_name: &str,
) -> Result<BTreeSet<String>, DeployError> {
    let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
    let mut uids = BTreeSet::new();
    for account in service_accounts {
        let existing = match api.get(account).await {
            Ok(existing) => existing,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        for entry in foreign_pull_secret_replacements(&existing) {
            if entry.secret_name == secret_name
                && let Some(uid) = entry.cleared_uid
            {
                uids.insert(uid);
            }
        }
    }
    Ok(uids)
}

async fn apply_scoped_pull_secret(
    engine: &ApplyEngine,
    namespace: &str,
    config: &TenantImagePullSecretConfig,
    generation: MutationGeneration,
    service_accounts: &[String],
    authority: Option<&PgPool>,
) -> Result<(), DeployError> {
    use enclava_engine::apply::generation::{
        MUTATION_GENERATION_ANNOTATION, RESOURCE_CREATED_BY_ANNOTATION,
    };
    let api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let mut desired = generate_tenant_image_pull_secret(namespace, config);
    desired
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(
            MUTATION_GENERATION_ANNOTATION.to_string(),
            generation.get().to_string(),
        );
    // Codex review on #243, round 2, P1 "bound the custom pull-secret apply
    // path": every raw GET/PATCH/POST below is unbounded, and this apply runs
    // BEFORE `reconcile_managed_pull_secrets_for_deploy`, so a Kubernetes API
    // server that accepts a connection but stalls would hold the deploy's
    // namespace lease and apply permit indefinitely. Bound the whole apply —
    // reads and writes — by the shared per-namespace budget; a timeout
    // defers (requeueable) exactly like the reconciliation paths.
    let create_submitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let create_submitted_in_apply = std::sync::Arc::clone(&create_submitted);
    // Per-apply create provenance nonce, stamped on the Secret before the
    // POST so recovery can prove a re-read object is this attempt's creation.
    let create_nonce = uuid::Uuid::new_v4().to_string();
    let apply = async {
        for _ in 0..5 {
            match api.get(&config.name).await {
                Ok(live) => {
                    if newer_pull_secret_scope(&live) {
                        return Err(DeployError::PullSecretReconcileDeferred(format!(
                            "newer repository-scope epoch owns {namespace}/{}",
                            config.name
                        )));
                    }
                    if newer_pull_secret_credentials(&live) {
                        return Err(DeployError::PullSecretReconcileDeferred(format!(
                            "newer pull-secret credential generation owns {namespace}/{}",
                            config.name
                        )));
                    }
                    // Codex review on #243, round 2, P1 "refuse to overwrite
                    // an unowned configured-name Secret": an adopted or
                    // otherwise pre-existing tenant namespace can hold a
                    // TENANT-owned secret at the configured name. This raw
                    // merge patch ignores SSA field ownership, so without an
                    // ownership proof it would destroy the tenant's registry
                    // credentials and stamp CAP's labels onto their object —
                    // converting it into a platform-PAT secret the later
                    // cleanup considers CAP-owned. Require the same proof the
                    // sweep demands (dedicated label, or the legacy generated
                    // shape carrying the configured pair) and fail closed.
                    if !is_managed_tenant_image_pull_secret(
                        &live,
                        Some((config.username.as_str(), config.token.as_str())),
                    ) {
                        return Err(DeployError::Validation(format!(
                            "secret {namespace}/{} exists but is not CAP-managed (neither the \
                             dedicated pull-secret label nor the configured GHCR credential \
                             shape); refusing to overwrite a tenant-owned object with the \
                             platform pull secret — remove or rename it, or change \
                             TENANT_IMAGE_PULL_SECRET_NAME",
                            config.name
                        )));
                    }
                    let foreign = recorded_foreign_replacement_uids(
                        engine,
                        namespace,
                        service_accounts,
                        &config.name,
                    )
                    .await?;
                    if live
                        .metadata
                        .uid
                        .as_deref()
                        .is_some_and(|uid| foreign.contains(uid))
                    {
                        return Err(DeployError::Validation(format!(
                            "secret {namespace}/{} is a recorded tenant replacement (uid {}); refusing \
                             to overwrite it with the platform pull secret — remove or rename it, or \
                             change TENANT_IMAGE_PULL_SECRET_NAME",
                            config.name,
                            live.metadata.uid.as_deref().unwrap_or("")
                        )));
                    }
                    ensure_pull_secret_generation_not_stale(&live, generation, &config.name)?;
                    // A previous compensating DELETE may still be held by a
                    // finalizer. Keep the durable deployment retry alive: a
                    // merge patch of this readable PAT must not turn the next
                    // attempt into success before deletion reaches 404.
                    if live.metadata.deletion_timestamp.is_some() {
                        return Err(DeployError::PullSecretReconcileDeferred(format!(
                            "pull secret {namespace}/{} is still terminating; retry after \
                             compensating deletion has converged",
                            config.name
                        )));
                    }
                    // Devin review on #278: a narrowing rollout can raise the
                    // fleet epoch after this replica's pre-write check. Re-check
                    // immediately before overwriting the live secret.
                    if let Some(pool) = authority {
                        ensure_pull_secret_rollout_authority_current(pool).await?;
                    }
                    let Some(resource_version) = live.metadata.resource_version.as_deref() else {
                        return Err(DeployError::Validation(
                            "pull secret has no resourceVersion".to_string(),
                        ));
                    };
                    let mut annotations = live.metadata.annotations.clone().unwrap_or_default();
                    annotations.extend(desired.metadata.annotations.clone().unwrap_or_default());
                    let patch = serde_json::json!({
                        "metadata": {
                            "resourceVersion": resource_version,
                            "annotations": annotations,
                            "labels": desired.metadata.labels,
                        },
                        "type": "kubernetes.io/dockerconfigjson",
                        "stringData": desired.string_data,
                    });
                    match api
                        .patch(&config.name, &PatchParams::default(), &Patch::Merge(&patch))
                        .await
                    {
                        Ok(patched) => {
                            // Codex review on #278, P1: a webhook can strip the
                            // mutation-generation marker from an accepted patch.
                            // Do not treat that write as success — the caller
                            // would attach a ServiceAccount reference the stale
                            // sweep then clears. Merge-patch responses are not
                            // required to carry managedFields (this patch does
                            // not set a field manager); the marker value is the
                            // evidence this response can prove.
                            if secret_mutation_generation(&patched) != Some(generation.get()) {
                                return Err(DeployError::PullSecretReconcileDeferred(format!(
                                    "pull secret {namespace}/{} was written but came back without \
                                     mutation generation {}; refusing to attach a ServiceAccount \
                                     reference to an unmarked platform PAT",
                                    config.name,
                                    generation.get()
                                )));
                            }
                            return Ok(());
                        }
                        Err(kube::Error::Api(error)) if error.code == 409 || error.code == 404 => {
                            continue;
                        }
                        Err(error) => return Err(DeployError::Apply(error.into())),
                    }
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    // Devin review on #278: the secret is gone, so no annotation
                    // epoch can fence this create. A narrowing rollout may have
                    // deleted it and raised the fleet authority after this
                    // replica passed its pre-write check. Re-check before POST.
                    if let Some(pool) = authority {
                        ensure_pull_secret_rollout_authority_current(pool).await?;
                    }
                    // Stamp the engine's creation evidence on this raw POST (the
                    // applied-resource path does the same in `annotate_created`;
                    // Codex review on #243, P1): the adopted-namespace
                    // compensating sweep classifies leftovers by
                    // `RESOURCE_CREATED_BY_ANNOTATION`, so an unstamped Secret is
                    // classified as foreign, skipped by cleanup, and its evidence
                    // can be cleared — leaving the platform PAT refreshed in a
                    // tenant namespace forever. Stamped ONLY on the create branch:
                    // the patch path must not claim creation of an object that
                    // already existed.
                    let mut created = desired.clone();
                    created
                        .metadata
                        .annotations
                        .get_or_insert_with(Default::default)
                        .insert(
                            RESOURCE_CREATED_BY_ANNOTATION.to_string(),
                            generation.get().to_string(),
                        );
                    created
                        .metadata
                        .annotations
                        .as_mut()
                        .expect("annotations initialized above")
                        .insert(
                            PULL_SECRET_CREATE_NONCE_ANNOTATION.to_string(),
                            create_nonce.clone(),
                        );
                    create_submitted_in_apply.store(true, std::sync::atomic::Ordering::SeqCst);
                    match api
                        .create(&pull_secret_create_params(engine), &created)
                        .await
                    {
                        Ok(applied) => {
                            // The response resolves the CREATE ambiguity, but
                            // the candidate stays armed until the confirmed
                            // create is fully dispositioned — recorded or
                            // compensated with removal CONFIRMED (Codex review
                            // on #280, P1 "Keep confirmed-create compensation
                            // armed until removal"): a compensation cut off by
                            // the outer budget must remain recoverable.
                            // Codex review on #243, round 2, P1 "verify
                            // creation evidence returned by the Secret POST":
                            // a mutating admission webhook can strip the
                            // annotation from an ACCEPTED create. The engine's
                            // create path verifies the response and
                            // compensates; this raw POST must too — an
                            // unattributable platform PAT in an adopted
                            // namespace is worse than no secret, so the
                            // just-created object is deleted (pinned to the
                            // response's UID/resourceVersion) and the deploy
                            // fails closed.
                            if !pull_secret_create_evidence_trusted(
                                engine,
                                &applied,
                                generation.get(),
                                &create_nonce,
                            ) {
                                remove_untrusted_created_pull_secret(
                                    &api,
                                    namespace,
                                    &config.name,
                                    &applied,
                                )
                                .await?;
                                create_submitted_in_apply
                                    .store(false, std::sync::atomic::Ordering::SeqCst);
                                return Err(DeployError::Validation(format!(
                                    "created pull secret {namespace}/{} came back without trusted \
                                 creation evidence (annotation value or field ownership; \
                                 mutating admission webhook?); deletion was confirmed and the \
                                 deploy fails closed — an unattributable platform PAT must not \
                                 land in a tenant namespace",
                                    config.name
                                )));
                            }
                            record_pull_secret_creation(
                                engine,
                                namespace,
                                &applied,
                                generation.get(),
                            );
                            create_submitted_in_apply
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            return Ok(());
                        }
                        Err(kube::Error::Api(error)) if error.code == 409 => {
                            // A server response — including the name-race
                            // winner's 409 — resolves the create ambiguity:
                            // recovery must not later treat this definitively
                            // completed POST as ours to ledger or delete
                            // (Codex review on #280, P1).
                            create_submitted_in_apply
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            continue;
                        }
                        Err(kube::Error::Api(error)) if (400..500).contains(&error.code) => {
                            // A 4xx is a definitive refusal: nothing of ours
                            // exists to ledger or compensate.
                            create_submitted_in_apply
                                .store(false, std::sync::atomic::Ordering::SeqCst);
                            return Err(DeployError::Apply(kube::Error::Api(error).into()));
                        }
                        // Anything else — a transport error, or a 5xx Api
                        // response — is NOT a definitive outcome: the POST may
                        // still commit server-side, so the create candidate
                        // stays armed and the wrapper below routes the armed
                        // failure through the same ambiguity recovery used for
                        // a timed-out future (Codex review on #280, P1
                        // "Recover ambiguous POST transport failures before
                        // returning").
                        Err(error) => return Err(DeployError::Apply(error.into())),
                    }
                }
                Err(error) => return Err(DeployError::Apply(error.into())),
            }
        }
        // Codex review on #243, P2: exhausting the immediate retries on
        // resource-version contention (a sweep, controller, or other writer
        // racing each GET→patch) is transient — a fresh mutation attempt
        // converges — so defer (requeueable via
        // `should_requeue_without_terminal_failure`) instead of terminally
        // failing the deployment.
        Err(DeployError::PullSecretReconcileDeferred(format!(
            "pull-secret apply for {namespace}/{} exhausted its immediate retries on \
             concurrent writes; retrying the deployment under a fresh mutation attempt converges",
            config.name
        )))
    };
    match tokio::time::timeout(PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT, apply).await {
        Ok(result) => {
            // A failed apply that left the create candidate armed is as
            // ambiguous as a timed-out future: its POST (or its owed
            // compensation) may still land server-side. Resolve the ambiguity
            // through the same bounded recovery before returning — recovery's
            // own error (still ambiguous) takes precedence; otherwise the
            // apply's real failure reason is returned (Codex review on #280,
            // P1 "Recover ambiguous POST transport failures before returning").
            if result.is_err() && create_submitted.load(std::sync::atomic::Ordering::SeqCst) {
                bounded_recover_ambiguous_pull_secret_create(
                    engine,
                    &api,
                    namespace,
                    &config.name,
                    generation,
                    true,
                    &create_nonce,
                )
                .await?;
            }
            result
        }
        Err(_) => {
            bounded_recover_ambiguous_pull_secret_create(
                engine,
                &api,
                namespace,
                &config.name,
                generation,
                create_submitted.load(std::sync::atomic::Ordering::SeqCst),
                &create_nonce,
            )
            .await
        }
    }
}

/// Deployment reconciliation must release its namespace lease and apply permit
/// even when a Kubernetes read accepts a connection but never responds.
async fn reconcile_managed_pull_secrets_for_deploy(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    settings: &PullSecretSettings,
    scope: &PullSecretAccountScope,
    delete_mode: PullSecretDeleteMode,
) -> Result<bool, DeployError> {
    tokio::time::timeout(
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
        reconcile_managed_pull_secrets(
            engine,
            namespace,
            service_accounts,
            settings,
            scope,
            delete_mode,
        ),
    )
    .await
    .map_err(|_| {
        DeployError::PullSecretReconcileDeferred(format!(
            "pull secret reconciliation timed out in namespace {namespace}; retry deployment"
        ))
    })?
}

async fn load_namespace_pull_secret_apps(
    pool: &PgPool,
    namespace: &str,
) -> Result<Vec<NamespacePullSecretApp>, DeployError> {
    let rows: Vec<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT apps.id, apps.service_account, app_containers.image_ref \
           FROM apps \
           LEFT JOIN app_containers ON app_containers.app_id = apps.id \
          WHERE apps.namespace = $1",
    )
    .bind(namespace)
    .fetch_all(pool)
    .await?;
    let mut apps: BTreeMap<Uuid, NamespacePullSecretApp> = BTreeMap::new();
    for (app_id, service_account, image_ref) in rows {
        let entry = apps
            .entry(app_id)
            .or_insert_with(|| NamespacePullSecretApp {
                app_id,
                service_account,
                images: Some(Vec::new()),
            });
        let Some(images) = entry.images.as_mut() else {
            continue;
        };
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
                    "tenant image pull secret deploy: unparsable stored image; treating the app as out of scope"
                );
                entry.images = None;
            }
        }
    }
    Ok(apps.into_values().collect())
}

fn with_deploy_service_accounts(
    namespace_accounts: &[String],
    deploy_accounts: &[String],
) -> Vec<String> {
    let mut accounts = namespace_accounts.to_vec();
    for account in deploy_accounts {
        if !accounts.iter().any(|known| known == account) {
            accounts.push(account.clone());
        }
    }
    accounts
}

async fn service_account_preserving_pull_secret_records(
    engine: &ApplyEngine,
    namespace: &str,
    desired: &ServiceAccount,
) -> Result<ServiceAccount, DeployError> {
    let Some(name) = desired.metadata.name.as_deref() else {
        return Ok(desired.clone());
    };
    let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
    let existing = match api.get(name).await {
        Ok(existing) => existing,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(desired.clone()),
        Err(error) => return Err(DeployError::Apply(error.into())),
    };
    let annotations = existing.metadata.annotations.as_ref();
    let mut foreign = annotations
        .and_then(|annotations| annotations.get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION))
        .filter(|value| !value.is_empty())
        .cloned();
    // Retained pending repairs are the only ownership proof of a renamed,
    // unlabeled pre-rotation secret the repair pass deliberately kept. SSA of
    // the generated ServiceAccount must copy them or it prunes that proof.
    let pending = annotations
        .and_then(|annotations| annotations.get(PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION))
        .filter(|value| !value.is_empty())
        .cloned();
    // Codex review on #276, P1: an operator can replace a CAP-managed Secret
    // with a tenant-owned object before cleanup runs. Reconciliation refuses
    // to treat that object as managed and writes no pending or foreign
    // annotation, so the early return below used to feed an out-of-scope
    // ServiceAccount — with no imagePullSecrets — into SSA, which pruned the
    // tenant's still-valid reference. Record the live UID the same way the
    // mid-cleanup replacement path does, and keep the reference. A stale
    // `name=old-uid` entry is not enough: the annotation allows several UIDs
    // per name, and merge keeps the reference only while a recorded UID still
    // matches the live object. CAP-owned secrets are not recorded; reconcile
    // owns those.
    let secrets_api: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
    let ownership_settings = PullSecretSettings::from_env();
    for reference in existing.image_pull_secrets.iter().flatten() {
        let live = match secrets_api.get(&reference.name).await {
            Ok(live) => live,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        if is_managed_tenant_image_pull_secret(&live, ownership_settings.ghcr()) {
            continue;
        }
        let Some(uid) = live.metadata.uid.clone().filter(|uid| !uid.is_empty()) else {
            return Err(DeployError::PullSecretReconcileDeferred(format!(
                "unrecorded tenant pull secret {namespace}/{} has no UID; refusing to apply a ServiceAccount that would prune its reference",
                reference.name
            )));
        };
        append_foreign_replacement_record(&mut foreign, &reference.name, &uid);
    }
    if foreign.is_none() && pending.is_none() {
        return Ok(desired.clone());
    }
    let mut preserved = desired.clone();
    let dest = preserved
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    if let Some(foreign) = foreign {
        dest.insert(
            FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
            foreign,
        );
    }
    if let Some(pending) = pending {
        dest.insert(
            PENDING_PULL_SECRET_REFERENCE_REPAIRS_ANNOTATION.to_string(),
            pending,
        );
    }
    // A UID-mismatch repair restores the tenant's reference and discharges the
    // pending intent in the same patch. SSA of the generated ServiceAccount
    // would then drop that name, and nothing would put it back. Keep every
    // foreign-replacement name on imagePullSecrets only while its recorded UID
    // still identifies the live Secret.
    let foreign_for_references = preserved
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION))
        .cloned();
    if let Some(foreign) = foreign_for_references.as_deref() {
        let secrets: Api<Secret> = Api::namespaced(engine.client().clone(), namespace);
        merge_foreign_pull_secret_references(&secrets, &mut preserved, foreign).await?;
    }
    Ok(preserved)
}

fn foreign_annotation_records_pair(annotation: &str, name: &str, uid: &str) -> bool {
    annotation.split(',').any(|entry| {
        entry
            .trim()
            .split_once('=')
            .is_some_and(|(recorded, recorded_uid)| recorded == name && recorded_uid == uid)
    })
}

fn append_foreign_replacement_record(annotation: &mut Option<String>, name: &str, uid: &str) {
    // Another UID for this name is not this object. The annotation stores
    // several UIDs per name; merge drops the ones that no longer match.
    if annotation
        .as_deref()
        .is_some_and(|value| foreign_annotation_records_pair(value, name, uid))
    {
        return;
    }
    let entry = format!("{name}={uid}");
    match annotation {
        Some(value) if value.is_empty() => *value = entry,
        Some(value) => {
            value.push(',');
            value.push_str(&entry);
        }
        None => *annotation = Some(entry),
    }
}

async fn merge_foreign_pull_secret_references(
    secrets: &Api<Secret>,
    desired: &mut ServiceAccount,
    foreign_annotation: &str,
) -> Result<(), DeployError> {
    use k8s_openapi::api::core::v1::LocalObjectReference;
    let mut retained = Vec::new();
    for entry in foreign_annotation.split(',') {
        let Some((name, uid)) = entry.trim().split_once('=') else {
            continue;
        };
        if name.is_empty() || uid.is_empty() {
            continue;
        }
        let live = match secrets.get(name).await {
            Ok(live) => live,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        // A remembered tenant replacement is proof only for that exact object,
        // not a later managed Secret recreated at the same configured name.
        if live.metadata.uid.as_deref() == Some(uid) {
            retained.push((name, uid));
        }
    }
    // Do not change the desired object until every lookup succeeded. API
    // failures must stop SSA rather than preserve unverified references.
    let mut references = desired.image_pull_secrets.take().unwrap_or_default();
    for (name, _) in &retained {
        if !references.iter().any(|reference| reference.name == *name) {
            references.push(LocalObjectReference {
                name: (*name).to_string(),
            });
        }
    }
    if !references.is_empty() {
        desired.image_pull_secrets = Some(references);
    }
    let annotations = desired
        .metadata
        .annotations
        .get_or_insert_with(Default::default);
    if retained.is_empty() {
        annotations.remove(FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION);
    } else {
        annotations.insert(
            FOREIGN_PULL_SECRET_REPLACEMENTS_ANNOTATION.to_string(),
            retained
                .into_iter()
                .map(|(name, uid)| format!("{name}={uid}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    Ok(())
}

/// Settle provenance even when a batched step fails after earlier creates.
/// Preserve the provider error (including structured evidence loss) after the
/// persistence/compensation future has run; gate errors fail successful steps.
async fn complete_creation_step<T>(
    result: Result<T, enclava_engine::apply::engine::ApplyError>,
    gate: impl std::future::Future<Output = Result<(), DeployError>>,
) -> Result<T, DeployError> {
    let persistence = gate.await;
    match result {
        Err(error) => Err(error.into()),
        Ok(value) => persistence.map(|()| value),
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_all_with_tenant_image_pull_secret(
    engine: &ApplyEngine,
    pool: &sqlx::PgPool,
    app_id: Uuid,
    deployment_id: Uuid,
    manifests: &enclava_engine::manifest::GeneratedManifests,
    manifest_hash: &str,
    image_pull_secret_config: Option<&TenantImagePullSecretConfig>,
    generation: MutationGeneration,
    mutation: &crate::mutation_leases::AppMutationLease,
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

    let step = apply_namespace(engine, &manifests.namespace, generation).await;
    // cap#272: creations observed by a step MUST be durably recorded
    // before the apply proceeds — an object whose ledger row cannot be
    // persisted is compensated where safe and the apply fails closed.
    // Failed steps must pass the same gate: a batch may have created earlier
    // objects before a later write failed.
    complete_creation_step(
        step,
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation),
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 1/5: namespace ready");

    // Codex review on #243, P1 "fence narrowed scopes against older replicas"
    // + round 2 P1 "detect a newer concurrent epoch": the scope-epoch marker
    // lived only on the (deletable) managed Secret, so after a
    // scope-narrowing rollout deleted it, an older replica running the
    // broader configuration would take the create-on-404 path below and
    // resurrect the platform PAT on the next deployment. The durable
    // per-namespace fence lives in the shared DB: this deploy records the
    // epoch it acts under and re-checks the AUTHORITATIVE epoch the row
    // holds after the monotonic upsert — if a newer replica raised the fence
    // concurrently, the upsert is rejected and the returned epoch defers
    // this whole deploy (requeueable) instead of letting a stale replica
    // re-expose credentials a newer rollout removed.
    let authoritative_fence_epoch =
        record_tenant_pull_secret_scope_fence(pool, ns_name, pull_secret_scope_generation())
            .await?;
    if pull_secret_scope_fence_defers(authoritative_fence_epoch) {
        return Err(DeployError::PullSecretReconcileDeferred(format!(
            "a newer repository-scope epoch ({authoritative_fence_epoch}) owns {ns_name}'s pull \
             secrets; this replica's scope generation ({}) is older — deferring instead of \
             re-attaching credentials a newer rollout removed",
            pull_secret_scope_generation()
        )));
    }
    // Codex review on #243, round 3, P1 "stop stale-scope replicas from
    // dispatching new namespaces" + P1 "fence pull-secret creation against
    // credential rollouts": the per-namespace fence above only defers
    // namespaces the newer replica already swept. A namespace created after
    // that sweep has NO fence row, and the credential epoch exists only on
    // live Secret annotations — so without a rollout-wide authority an old
    // replica could take the create-on-404 path below and stamp its broader
    // scope / revoked token into a brand-new namespace. Raise the fleet-wide
    // maxima with this replica's epochs and defer the whole reconcile when
    // ANY newer epoch has been observed anywhere: the newer rollout's sweep
    // converges the namespace; this replica stays closed until upgraded.
    let (authority_scope_epoch, authority_credential_epoch) =
        raise_tenant_pull_secret_rollout_authority(
            pool,
            pull_secret_scope_generation(),
            pull_secret_credential_generation(),
        )
        .await?;
    if pull_secret_rollout_authority_defers(authority_scope_epoch, authority_credential_epoch) {
        return Err(DeployError::PullSecretReconcileDeferred(format!(
            "a newer pull-secret rollout exists (scope epoch {authority_scope_epoch} / credential \
             epoch {authority_credential_epoch} vs this replica's {}/{}); deferring all tenant \
             pull-secret work — including namespaces without a fence row or a live Secret — \
             until this replica is upgraded",
            pull_secret_scope_generation(),
            pull_secret_credential_generation()
        )));
    }

    let _mutation_guard = tokio::time::timeout(
        PULL_SECRET_NAMESPACE_RECONCILE_TIMEOUT,
        pull_secret_mutation_guard(pool),
    )
    .await
    .map_err(|_| {
        DeployError::PullSecretReconcileDeferred(
            "timed out waiting for pull-secret rollout mutation guard".to_string(),
        )
    })??;
    let settings = PullSecretSettings::from_env();
    let service_accounts = manifests
        .service_account
        .metadata
        .name
        .iter()
        .cloned()
        .collect::<Vec<String>>();

    let shared_namespace: bool =
        sqlx::query_scalar("SELECT COUNT(*) > 1 FROM apps WHERE namespace = $1")
            .bind(ns_name)
            .fetch_one(pool)
            .await?;
    let namespace_service_accounts: Vec<String> =
        sqlx::query_scalar("SELECT service_account FROM apps WHERE namespace = $1")
            .bind(ns_name)
            .fetch_all(pool)
            .await?;
    let namespace_service_accounts =
        with_deploy_service_accounts(&namespace_service_accounts, &service_accounts);
    // Shared namespaces need the real per-account scope before SSA. A uniform
    // decision would either restore every account or delete secrets another
    // app still needs. The deploying app is forced from this snapshot; stored
    // rows can lag.
    let scope = if shared_namespace {
        let deploying_app_id: Uuid =
            sqlx::query_scalar("SELECT app_id FROM deployments WHERE id = $1")
                .bind(deployment_id)
                .fetch_one(pool)
                .await?;
        let apps = load_namespace_pull_secret_apps(pool, ns_name).await?;
        scope_for_shared_namespace_deploy(
            tenant_image_pull_secret_config_from_env().as_ref(),
            deploying_app_id,
            image_pull_secret_config.is_some(),
            &apps,
            &service_accounts,
        )
    } else {
        PullSecretAccountScope::uniform(image_pull_secret_config.is_some())
    };
    let reconcile_accounts = if shared_namespace {
        namespace_service_accounts.as_slice()
    } else {
        service_accounts.as_slice()
    };
    if let Some(config) = image_pull_secret_config {
        ensure_pull_secret_rollout_authority_current(pool).await?;
        let scoped_step = apply_scoped_pull_secret(
            engine,
            ns_name,
            config,
            generation,
            &namespace_service_accounts,
            Some(pool),
        )
        .await;
        // cap#272 gate, extended by Codex review on #280 round 3: the
        // ambiguity recovery inside that step may have recorded a created
        // Secret into the in-memory ledger right before the step failed —
        // an early `?` here would exit apply_all with the record still
        // memory-only (the failure cleanup loads its ledger from the DB), so
        // its provenance would be unprovable. Persist BEFORE the step's
        // error propagates (same contract as complete_creation_step, for
        // the DeployError-typed step).
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation)
            .await?;
        scoped_step?;
        // The create/patch re-checked authority, but the reference restore is
        // another Kubernetes write. A newer rollout that landed between them
        // must still defer this replica.
        ensure_pull_secret_rollout_authority_current(pool).await?;
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
                None,
            )
            .await?;
        }
        discharge_reference_repair_intent_after_deploy(
            engine,
            ns_name,
            &service_accounts,
            &config.name,
        )
        .await?;
        tracing::info!(
            namespace = %ns_name,
            secret = %config.name,
            "tenant image pull secret applied"
        );
    } else {
        // Codex review on #276, P1: a shared namespace whose last qualifying
        // app is redeployed out of scope must not wait for the periodic
        // sweep. The scope above already forces THIS deploy's app out of
        // scope (its stored rows can still show the old images). Other apps
        // that still qualify keep the secret; this app's reference is cleared.
        // This is a pre-apply inventory pass, not post-apply cleanup. Repair
        // pending UID evidence before any kept-object credential refresh.
        let converged = reconcile_managed_pull_secrets_for_deploy(
            engine,
            ns_name,
            reconcile_accounts,
            &settings,
            &scope,
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

    // Codex review on #276, P1: do not assume the background sweeper has
    // already finished pending repairs. A shared-namespace deploy's
    // ServiceAccount apply preserves only the annotations copied below, so
    // it can prune the pending name/UID that is the sole ownership proof of
    // a renamed, unlabeled pre-rotation secret. Run the sweep-context repair
    // pass with the complete namespace account list first. The durable repair
    // pass runs here (`DeployOwned`), but this generation is the caller's own
    // write — not a background-sweep snapshot — so mixed-scope per-app clears
    // still happen. A strictly newer marker remains someone else's.
    let repaired = reconcile_managed_pull_secrets_for_deploy(
        engine,
        ns_name,
        reconcile_accounts,
        &settings,
        &scope,
        PullSecretDeleteMode::DeployOwned {
            generation: generation.get(),
        },
    )
    .await?;
    if !repaired {
        return Err(DeployError::Validation(
            "pending pull-secret repair did not converge before ServiceAccount apply".to_string(),
        ));
    }
    let preserved_service_account =
        service_account_preserving_pull_secret_records(engine, ns_name, &manifests.service_account)
            .await?;
    let step = apply_standard_resources_with_service_account(
        engine,
        manifests,
        &preserved_service_account,
        generation,
    )
    .await;
    complete_creation_step(
        step,
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation),
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 2/5: standard resources applied");

    if image_pull_secret_config.is_some() && !shared_namespace {
        // Only reconcile residue here when this deploy sees all accounts.
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
        let converged = reconcile_managed_pull_secrets_for_deploy(
            engine,
            ns_name,
            &service_accounts,
            &settings,
            &PullSecretAccountScope::uniform(true),
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

    let step = apply_network_policy(engine, ns_name, &manifests.network_policy, generation).await;
    complete_creation_step(
        step,
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation),
    )
    .await?;
    tracing::info!(namespace = %ns_name, "step 3/5: CiliumNetworkPolicy applied");

    let step = apply_gateway_resources(
        engine,
        ns_name,
        &manifests.envoy_proxy,
        &manifests.gateway,
        &manifests.tls_route,
        &manifests.tee_tls_route,
        generation,
    )
    .await;
    complete_creation_step(
        step,
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation),
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

    // Observability stamp: when the StatefulSet step (the final apply
    // phase) was first attempted. #273 removed the claim-age bound this
    // column used to feed — the adopted-namespace sweep now retains every
    // name-matching claim regardless of age — so nothing reads it for a
    // deletion decision anymore; it is kept (applied migration 0072) as
    // lineage history. First-writer-wins (COALESCE) so a retry of a
    // partially-failed apply does not advance the record.
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
    let step = apply_statefulset(engine, ns_name, &sts, generation).await;
    let sts_live = complete_creation_step(
        step,
        persist_and_gate_creation_records(engine, pool, app_id, deployment_id, ns_name, mutation),
    )
    .await?;
    // Persist the server-reported UID and creationTimestamp of the
    // StatefulSet object this apply produced (the POST/SSA response — not
    // a pre-call stamp). Observability-only since #273: no sweep or
    // deletion decision reads this ledger. The Grok P2 gate is kept so
    // the ledger stays honest — only persist when the RESPONSE itself
    // carries CAP creation evidence, because an SSA patch of a
    // PRE-EXISTING StatefulSet returns that set's UID and this record
    // must never attribute a tenant's set to CAP. First-writer-wins
    // keeps a retry from advancing the record.
    if crate::deployment_failure_cleanup::is_cap_created_generation_leftover(
        &sts_live,
        generation.get(),
        // cap#272: claim-sweep provenance follows the same ledger gate as
        // the sweep — the engine's ledger holds this apply's own create
        // records plus the app's preloaded durable rows, so a forged
        // stamp on a pre-existing set never becomes claim-deletion
        // authority. Engines without a ledger use strict no-legacy trust.
        &engine_ledger_or_empty(engine),
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
                "could not persist StatefulSet provenance (observability-only since #273; no sweep decision reads it)"
            );
        }
    } else {
        // No CAP creation evidence on the response (e.g. an SSA patch of a
        // pre-existing set, or a mutating admission rewrote the creation
        // annotation): the observability ledger stays honest — it must
        // never attribute a tenant's StatefulSet to CAP. Claim retention
        // itself is unconditional since #273 and reads nothing here.
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

    // The sweep-context repair above already finished UID-proven removals
    // whose annotations this ServiceAccount apply would otherwise prune.
    // Retained intents were copied onto the desired ServiceAccount.

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

/// Forget only the configured name this deploy just applied. Other repair
/// intents may be the last proof of ownership of renamed pre-label secrets.
async fn discharge_reference_repair_intent_after_deploy(
    engine: &ApplyEngine,
    namespace: &str,
    service_accounts: &[String],
    applied_secret_name: &str,
) -> Result<(), DeployError> {
    for service_account in service_accounts {
        let api: Api<ServiceAccount> = Api::namespaced(engine.client().clone(), namespace);
        let existing = match api.get(service_account).await {
            Ok(existing) => existing,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(DeployError::Apply(error.into())),
        };
        for repair in pending_reference_repairs(&existing)
            .into_iter()
            .filter(|repair| repair.secret_name == applied_secret_name)
        {
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
    #[error("pull-secret reconciliation deferred: {0}")]
    PullSecretReconcileDeferred(String),
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
            Self::KbsPolicy(error) => error.public_code(),
            Self::EdgeRoute(_) => "edge_route_error",
            Self::Mutation(_) => "mutation_fence_error",
            Self::PullSecretReconcileDeferred(_) => "pull_secret_reconcile_deferred",
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
        // Hard-disabled: no deployment, redeploy, rollback, or transition
        // reapply may build an auto-unlock workload from stored state. The
        // auto->password transition commits the password row before this
        // builder runs, so conversion redeploys are unaffected.
        crate::models::UnlockMode::Auto => {
            return Err(DeployError::Validation(format!(
                "{}: app {} is recorded as auto-unlock; transition it to password mode",
                crate::routes::apps::AUTO_UNLOCK_DISABLED_REJECTION,
                app.name
            )));
        }
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

fn desired_state_json_error(
    status: axum::http::StatusCode,
    error: &'static str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (status, axum::Json(serde_json::json!({"error": error})))
}

fn desired_state_db_error() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    desired_state_json_error(
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "database error",
    )
}

fn desired_state_retryable_error() -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    desired_state_json_error(
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "desired_state_retryable",
    )
}

/// Drive one app's desired running/stopped state: claim the mutation lease,
/// patch the workload StatefulSet's replicas under its mutation generation,
/// and publish the terminal app status. The internal PaaS route owns
/// authentication, validation, idempotency, and the response body; it
/// forwards here with the caller's `operation_id` as the lease authority.
///
/// `desired_state` is the persisted app status ("running" or "stopped"); the
/// replica count is derived from it. The provider wait runs WITHOUT the app
/// advisory lane (a bounded convergence must not block other mutations): the
/// heartbeated mutation lease keeps fencing concurrent mutations, and the
/// generation-checked patch cannot be overwritten by a stale deploy.
pub(crate) async fn set_app_desired_state(
    state: &crate::state::AppState,
    engine: &ApplyEngine,
    cap_org_id: Uuid,
    app_name: &str,
    desired_state: &str,
    operation_id: Uuid,
) -> Result<(), (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    use axum::http::StatusCode;

    let (app_id, namespace, current_status): (Uuid, String, AppStatus) = sqlx::query_as(
        "SELECT id, namespace, status
           FROM apps
          WHERE org_id = $1
            AND name = $2
            AND status <> 'deleting'::app_status_enum",
    )
    .bind(cap_org_id)
    .bind(app_name)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| desired_state_db_error())?
    .ok_or_else(|| desired_state_json_error(StatusCode::NOT_FOUND, "application not found"))?;
    if current_status == AppStatus::Failed {
        return Err(desired_state_json_error(
            StatusCode::CONFLICT,
            "failed applications require a successful redeployment before changing desired state",
        ));
    }
    let resource = crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &namespace);
    let mut mutation = match crate::mutation_leases::claim(
        state,
        app_id,
        "app_desired_state",
        operation_id,
        false,
        vec![resource.clone()],
    )
    .await
    {
        Ok(mutation) => mutation,
        // Lane etiquette: this fifth Busy arm carries the same lease hints
        // as the HTTP-facing ones so the contract is uniform.
        Err(crate::mutation_leases::MutationLeaseError::Busy) => {
            return Err(crate::routes::apps::app_mutation_busy_error(
                &state.db,
                app_id,
                std::slice::from_ref(&resource),
            )
            .await);
        }
        Err(_) => {
            return Err(desired_state_retryable_error());
        }
    };
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| desired_state_db_error())?;
    lock_app_deployment_lane(&mut tx, app_id)
        .await
        .map_err(|_| desired_state_db_error())?;
    let claimed_status: AppStatus = sqlx::query_scalar("SELECT status FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| desired_state_db_error())?;
    if claimed_status == AppStatus::Failed {
        mutation
            .finish_in_tx(&mut tx)
            .await
            .map_err(|_| desired_state_db_error())?;
        tx.commit().await.map_err(|_| desired_state_db_error())?;
        return Err(desired_state_json_error(
            StatusCode::CONFLICT,
            "failed applications require a successful redeployment before changing desired state",
        ));
    }
    let deployment_in_progress = desired_state == "stopped"
        && sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                 SELECT 1
                   FROM deployment_apply_jobs
                  WHERE app_id = $1
                    AND state IN (
                        'setup_pending', 'setting_up',
                        'cleanup_pending', 'cleaning_up',
                        'pending', 'running'
                    )
             )",
        )
        .bind(app_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| desired_state_db_error())?;
    if deployment_in_progress {
        mutation
            .finish_in_tx(&mut tx)
            .await
            .map_err(|_| desired_state_db_error())?;
        tx.commit().await.map_err(|_| desired_state_db_error())?;
        return Err(desired_state_json_error(
            StatusCode::CONFLICT,
            "current deployment generation is still in progress",
        ));
    }
    // Release the deployment lane and the pooled connection before the
    // bounded Kubernetes convergence wait (#95). Concurrent app mutations
    // stay fenced out by the heartbeated mutation lease (they fail busy
    // on claim), and the StatefulSet patch itself is generation-checked,
    // so a deploy that slips in cannot be overwritten by a stale patch.
    tx.commit().await.map_err(|_| desired_state_db_error())?;
    let generation = mutation
        .resource_generation(&resource)
        .ok_or_else(desired_state_retryable_error)?;
    let generation =
        MutationGeneration::new(generation).map_err(|_| desired_state_retryable_error())?;
    let replicas = match desired_state {
        "running" => 1,
        "stopped" => 0,
        _ => {
            return Err(desired_state_json_error(
                StatusCode::BAD_REQUEST,
                "invalid desired_state",
            ));
        }
    };
    let convergence = mutation
        .guard_provider(
            enclava_engine::apply::cleanup::set_statefulset_desired_replicas(
                engine,
                &namespace,
                app_name,
                replicas,
                std::time::Duration::from_secs(300),
                generation,
            ),
        )
        .await
        .map_err(|_| desired_state_retryable_error())?;
    if let Err(error) = convergence {
        tracing::warn!(
            cap_app_id = %app_id,
            outcome = error.public_code(),
            "application desired-state convergence failed"
        );
        // Codex P2: a replicas/desired-state write whose accepted
        // response lost CAP creation evidence must durably mark the
        // app — this path has no deployment job, so without the marker
        // a later failed apply's sweep would treat the stripped object
        // as foreign and clear cleanup evidence over it.
        if matches!(
            error,
            enclava_engine::apply::engine::ApplyError::CreationEvidenceLost { .. }
        ) && !crate::deployment_failure_cleanup::persist_creation_evidence_loss(
            &state.db, app_id,
        )
        .await
        {
            // The marker is the only durable signal for later sweeps;
            // surface its loss distinctly instead of silently
            // continuing (the request already failed).
            tracing::error!(
                cap_app_id = %app_id,
                "creation-evidence-loss marker could not be persisted; later sweeps will not know unmarked targets may be CAP-created"
            );
        }
        // The failure path deliberately does NOT re-take the lane: the
        // lease is dropped and stays owned through its reclaim
        // quarantine, which is the documented safe outcome after an
        // uncertain provider response.
        return Err(desired_state_retryable_error());
    }

    // Re-take the lane and publish the terminal status in a fresh short
    // transaction. finish_in_tx requires the caller to hold the app
    // advisory lane (see its doc comment) and re-asserts lease ownership
    // (token and generation) before this status write can commit. A
    // `failed` status published while the lane was released (for example
    // a deployment worker terminalizing an in-flight job) must not be
    // overwritten by the desired state, so the UPDATE guards it too.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| desired_state_db_error())?;
    lock_app_deployment_lane(&mut tx, app_id)
        .await
        .map_err(|_| desired_state_db_error())?;
    let updated = sqlx::query(
        "UPDATE apps
            SET status = $2::app_status_enum,
                updated_at = now()
          WHERE id = $1
            AND org_id = $3
            AND namespace = $4
            AND status NOT IN ('deleting'::app_status_enum, 'failed'::app_status_enum)",
    )
    .bind(app_id)
    .bind(desired_state)
    .bind(cap_org_id)
    .bind(&namespace)
    .execute(&mut *tx)
    .await
    .map_err(|_| desired_state_db_error())?;
    if updated.rows_affected() != 1 {
        return Err(desired_state_json_error(
            StatusCode::CONFLICT,
            "application authority changed",
        ));
    }
    mutation
        .finish_in_tx(&mut tx)
        .await
        .map_err(|_| desired_state_db_error())?;
    tx.commit().await.map_err(|_| desired_state_db_error())?;
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
#[allow(clippy::too_many_arguments)]
pub async fn reapply_tenant_ingress(
    client: &kube::Client,
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

    let ledger = crate::deployment_failure_cleanup::load_creation_ledger(pool, app.id).await?;
    let engine =
        ApplyEngine::new(client.clone(), ApplyConfig::default()).with_creation_ledger(ledger);
    // Domain-only reapply: the pod restart re-opens existing volumes, so the
    // base rollout budget applies — the fresh-initialization allowance is
    // reserved for renders that provision a new claim.
    let rollout_timeout = engine.config().rollout_timeout;
    ensure_statefulset_exists(&engine, &app_spec.namespace, &app_spec.name).await?;
    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    let step = apply_namespaced_resource(&engine, &app_spec.namespace, &cm, generation).await;
    complete_creation_step(
        step,
        persist_and_gate_creation_records(
            &engine,
            pool,
            app.id,
            deployment_id,
            &app_spec.namespace,
            mutation,
        ),
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

/// Stamp attempts for `record_workload_spec_published` before the failure is
/// allowed to terminalize a job whose StatefulSet write already happened.
const WORKLOAD_SPEC_PUBLISHED_STAMP_ATTEMPTS: u32 = 4;

async fn record_workload_spec_published(
    pool: &PgPool,
    deployment_id: Uuid,
) -> Result<(), DeployError> {
    // shortcut: crash after StatefulSet apply and before this commit, then lease expiry and supersession, looks unpublished; upgrade when supersession can tell a written spec from an applying row that never reached the StatefulSet
    //
    // The stamp runs in its own autocommit after the StatefulSet write. A
    // failed stamp would terminalize a job whose StatefulSet is already live
    // and leave the generation looking unpublished forever — its teardown
    // unit would then pin no authority. Retry before failing so only a
    // sustained database outage (which breaks every path anyway) can lose
    // the stamp to an error return; the crash window above stays the only
    // known gap.
    let mut attempts = 0;
    loop {
        attempts += 1;
        match sqlx::query(
            "UPDATE deployments
                SET workload_spec_published_at = COALESCE(
                        workload_spec_published_at,
                        clock_timestamp()
                    )
              WHERE id = $1",
        )
        .bind(deployment_id)
        .execute(pool)
        .await
        {
            Ok(result) => {
                if result.rows_affected() != 1 {
                    return Err(DeployError::Db(sqlx::Error::RowNotFound));
                }
                return Ok(());
            }
            Err(error) if attempts < WORKLOAD_SPEC_PUBLISHED_STAMP_ATTEMPTS => {
                tracing::warn!(
                    %deployment_id,
                    attempts,
                    error = %error,
                    "workload spec publication stamp failed; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(250 * u64::from(attempts)))
                    .await;
            }
            Err(error) => return Err(DeployError::Db(error)),
        }
    }
}

/// Apply manifests and return durable rollout-observation context.
pub async fn apply_deployment_manifests(
    request: ApplyDeploymentManifestsRequest,
    client: &kube::Client,
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
                client,
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
        crate::kbs::reconcile_policy(&pool, kbs_policy_config.as_ref(), client).await?;
    }

    let generation = MutationGeneration::new(kubernetes_mutation_generation)?;
    // cap#272: attach the app's durable creation ledger to the engine
    // BEFORE any provider write. The engine records every object its own
    // create POST produces (persisted step-by-step below) and refuses to
    // preserve creation evidence on live objects whose lineage is neither
    // recorded nor grandfathered by the migration cutover. A load failure
    // fails the apply closed — nothing has been written yet.
    let engine = {
        let ledger = crate::deployment_failure_cleanup::load_creation_ledger(&pool, app.id).await?;
        engine.with_creation_ledger(ledger)
    };
    mutation
        .arm_resource_scope_until_reconciled("kubernetes_namespace")
        .await?;
    // The floor verdict was already derived from live PVC evidence before
    // the first provider write above; provisioned sub-floor claims pass
    // through unchanged.

    apply_all_with_tenant_image_pull_secret(
        &engine,
        &pool,
        app.id,
        deployment_id,
        &manifests,
        &hash,
        tenant_image_pull_secret_config.as_ref(),
        generation,
        mutation,
    )
    .await?;
    // After the StatefulSet write, before edge routes. setup_state and
    // manifest_hash are both recorded earlier and do not mean this succeeded.
    record_workload_spec_published(&pool, deployment_id).await?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(app.org_id)
        .fetch_one(&pool)
        .await?;
    // Host list shared with failed-apply cleanup
    // (`crate::deployment_failure_cleanup`) so publication and removal can
    // never diverge.
    let app_target =
        crate::edge::resolve_backend_target(client, &app_spec.name, &app_spec.namespace, 443)
            .await?;
    let tee_target =
        crate::edge::resolve_backend_target(client, &app_spec.name, &app_spec.namespace, 8081)
            .await?;
    let mut routes = Vec::with_capacity(3);
    for (tag, host) in crate::deploy::app_route_hosts(&app) {
        let backend = crate::edge::backend_name_for(&org_slug, &app_spec.name, tag)?;
        let target = match tag {
            crate::edge::BackendTag::App => &app_target,
            crate::edge::BackendTag::Tee => &tee_target,
        };
        routes.push(crate::edge::SniRoute::new(&host, &backend, target)?);
    }
    crate::edge::ensure_haproxy_routes(
        client,
        &pool,
        &edge_config,
        Some(edge_config_generation),
        &routes,
    )
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
#[cfg(test)]
mod tests;
