//! Compensating cleanup after a terminal deployment-apply failure.
//!
//! A failed apply can leave two classes of orphaned provider state:
//!
//! * HAProxy SNI routes published by `ensure_haproxy_routes` during the apply.
//!   The periodic desired-state reconciler would eventually drop them, but
//!   until then the edge keeps forwarding tenant traffic for a deployment that
//!   will never become healthy.
//! * Kubernetes objects created by `apply_all_with_tenant_image_pull_secret`
//!   (namespace, image-pull secret, network policy, Gateway API resources,
//!   StatefulSet). When the namespace was CAP-created (creation-evidence
//!   annotation), deleting the namespace is sufficient cleanup: every object
//!   the apply creates is namespaced and dies with it. When the namespace
//!   pre-existed and was merely adopted, the namespace is NOT deleted — the
//!   objects this generation published are swept individually instead.
//!
//! Cleanup is strictly conservative and gated on live provider evidence, not
//! on deployment-row status alone:
//!
//! * the live namespace must carry this exact generation's mutation-generation
//!   annotation AND CAP creation evidence to authorize a namespace delete —
//!   the mutation annotation alone proves only last-writer (an adopted
//!   namespace carries it too), so without creation evidence the namespace
//!   is treated as adopted and never destroyed
//!   (the deployment row's `manifest_hash` is
//!   written at `applying`, before any provider call, so it is not evidence
//!   of publication);
//! * no OTHER deployment of the app may carry any provider-state evidence
//!   (`manifest_hash`, `observing_since`, or a non-failed status including
//!   `rolled_back`) — a superseded `watching`/`applying` predecessor
//!   terminalized to `failed` keeps its namespace (and its PVCs, whose
//!   StatefulSet retention the namespace cascade would bypass) and its shared
//!   generation-independent routes;
//! * the app must not be `deleting` (the delete path owns teardown).
//!
//! Both provider steps run while the failing worker still owns the durable
//! mutation fences (`edge_config`, `kubernetes_namespace/<ns>`), under
//! `guard_provider`, so a concurrently accepted redeploy cannot mutate the
//! same providers until this worker releases them, and a lost lease heartbeat
//! cancels the provider calls the same way apply does. Route removal is
//! best-effort (idempotent; the periodic edge reconciler converges the rest).
//! Namespace deletion fails closed: if a delete was issued but 404 was not
//! observed within the bounded wait, the pre-armed namespace fence is
//! retained (not converted to the bounded reclaim quarantine), so a retry
//! cannot claim the fence while the namespace is still Terminating. A crash
//! before cleanup simply leaves the pre-existing (slower) convergence
//! behavior — never a worse one.

use uuid::Uuid;

use crate::models::App;
use crate::mutation_leases::{AppMutationLease, ResourceFence};
use crate::state::AppState;

/// Objects a failed generation published into an ADOPTED namespace and must
/// delete individually (the namespace itself is not CAP's to destroy).
/// Mirrors the deterministic names in `enclava-engine`'s manifest
/// generators and the tenant image-pull secret in `deploy.rs`.
struct AdoptedNamespaceSweep {
    kind: &'static str,
    name: String,
}

/// The four Gateway-API / Cilium CRDs apply publishes, as (group, version,
/// kind, plural) — mirroring the private constructors in
/// `enclava-engine/src/apply/gateway.rs` and `network_policy.rs`.
fn crd_api_resource(
    group: &str,
    version: &str,
    kind: &str,
    plural: &str,
) -> kube::api::ApiResource {
    kube::api::ApiResource {
        group: group.to_string(),
        version: version.to_string(),
        api_version: format!("{group}/{version}"),
        kind: kind.to_string(),
        plural: plural.to_string(),
    }
}

fn adopted_namespace_sweep_targets(app: &App) -> Vec<AdoptedNamespaceSweep> {
    let mut targets = Vec::new();
    // Tenant image-pull secret (GHCR credentials): the most security-
    // sensitive object. Deletion is still evidence-gated
    // (is_cap_created_generation_leftover on the Secret), so a
    // same-named PRE-EXISTING secret without creation evidence is
    // skipped; the env-derived name only selects the candidate.
    targets.push(AdoptedNamespaceSweep {
        kind: "Secret",
        name: crate::deploy::default_tenant_image_pull_secret_name_for_cleanup(),
    });
    // StatefulSet (app name) — deleting it stops any partially rolled-out
    // workload CAP started in the adopted namespace.
    targets.push(AdoptedNamespaceSweep {
        kind: "StatefulSet",
        name: app.name.clone(),
    });
    // CiliumNetworkPolicy ("tenant-isolation")
    targets.push(AdoptedNamespaceSweep {
        kind: "CiliumNetworkPolicy",
        name: "tenant-isolation".to_string(),
    });
    // Gateway API resources (names mirror gateway.rs's generators).
    targets.push(AdoptedNamespaceSweep {
        kind: "EnvoyProxy",
        name: format!("tenant-gateway-proxy-{}", app.name),
    });
    targets.push(AdoptedNamespaceSweep {
        kind: "Gateway",
        name: format!("tenant-gateway-{}", app.name),
    });
    targets.push(AdoptedNamespaceSweep {
        kind: "TLSRoute",
        name: format!("tenant-passthrough-{}", app.name),
    });
    targets.push(AdoptedNamespaceSweep {
        kind: "TLSRoute",
        name: format!("tenant-tee-passthrough-{}", app.name),
    });
    // service_account
    targets.push(AdoptedNamespaceSweep {
        kind: "ServiceAccount",
        name: app.service_account.clone(),
    });
    // resource_quota ("tenant-quota")
    targets.push(AdoptedNamespaceSweep {
        kind: "ResourceQuota",
        name: "tenant-quota".to_string(),
    });
    // service (app name)
    targets.push(AdoptedNamespaceSweep {
        kind: "Service",
        name: app.name.clone(),
    });
    // ConfigMaps: bootstrap, startup, ingress, enclava-init, verification,
    // sni-route
    for name in [
        "secure-pv-bootstrap-script".to_string(),
        format!("{}-startup", app.name),
        format!("{}-tenant-ingress", app.name),
        enclava_engine::manifest::enclava_init_config::configmap_name(&app.name),
        enclava_engine::manifest::verification_material::configmap_name(&app.name),
        format!("{}-sni-route", app.name),
    ] {
        targets.push(AdoptedNamespaceSweep {
            kind: "ConfigMap",
            name,
        });
    }
    targets
}

/// Per-request cap for adopted-namespace sweep reads (GET/list). A stalled
/// Kubernetes API server must not hold the failed mutation's shared
/// `edge_config`/`kbs_policy` fences and side-effect admission permit for
/// the client's default (~295 s) read timeout per target: across the ~17
/// enumerated targets that aggregates to well over an hour of fence
/// retention blocking unrelated deployments platform-wide.
const SWEEP_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Overall deadline for the whole adopted-namespace sweep. Bounding each
/// request alone still allows ~17 targets x (bounded GET + up to 3 bounded
/// delete attempts + conflict backoff) to stretch into many minutes under
/// sustained API-server degradation, so the sweep as a whole is bounded
/// too: once the deadline passes, remaining targets count as failures and
/// the caller reports `AdoptedIncomplete` (evidence kept, fences release,
/// the next apply or app deletion converges the leftovers).
const SWEEP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(300);

/// Bound a single sweep read by BOTH the per-request budget and the
/// sweep's overall deadline: a target started near the deadline must not
/// stretch the sweep (and its shared fence retention) by further 30 s
/// reads, delete attempts, and conflict retries. Returns Err on transport
/// failure, deadline expiry, and per-request-budget expiry — all three
/// mean the target's state is undecidable within the sweep's budget.
async fn bounded_sweep_read<F, T>(
    deadline: tokio::time::Instant,
    future: F,
) -> Result<T, kube::Error>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    let per_request = tokio::time::Instant::now() + SWEEP_READ_TIMEOUT;
    match tokio::time::timeout_at(deadline.min(per_request), future).await {
        Ok(result) => result,
        Err(_) => Err(kube::Error::Service(
            "adopted-namespace sweep read exceeded its budget".into(),
        )),
    }
}

/// List ALL pages of a namespaced collection. kube 3.1's `Api::list`
/// returns whatever single page the server sent and does NOT follow
/// `continue` tokens; a truncated first page that misses a target-shaped
/// object would look like a complete listing and let the sweep report
/// completion over live objects (self-check P2 — the Secret discovery
/// list and the PVC sweep list both depended on a single page). Follow
/// the tokens until exhausted; every page is one bounded read.
async fn bounded_sweep_list_all<K>(
    api: &kube::Api<K>,
    sweep_deadline: tokio::time::Instant,
) -> Result<Vec<K>, kube::Error>
where
    K: kube::Resource<DynamicType = ()> + serde::de::DeserializeOwned + Clone + std::fmt::Debug,
{
    let mut items = Vec::new();
    let mut continue_token: Option<String> = None;
    loop {
        let mut params = kube::api::ListParams::default();
        if let Some(token) = continue_token.take() {
            params = params.continue_token(&token);
        }
        let page = bounded_sweep_read(sweep_deadline, api.list(&params)).await?;
        items.extend(page.items);
        match page.metadata.continue_ {
            Some(token) if !token.is_empty() => continue_token = Some(token),
            _ => break,
        }
    }
    Ok(items)
}

/// Per-object budget for confirming a DELETE's absence. An accepted
/// orphan delete can remain visible while the orphan finalizer detaches
/// dependents, and other finalizers can hold it indefinitely. Poll rather
/// than treating the first live response as failure. The budget is capped
/// per object so a wedged target cannot starve the remaining targets.
const SWEEP_CONFIRM_ABSENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Poll interval while waiting for an accepted DELETE to converge.
const SWEEP_CONFIRM_ABSENCE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Never cascade through tenant-writable ownerReferences in an adopted
/// namespace, even for non-workload targets (a PVC can reference a Secret).
fn adopted_sweep_delete_params(preconditions: kube::api::Preconditions) -> kube::api::DeleteParams {
    kube::api::DeleteParams {
        preconditions: Some(preconditions),
        propagation_policy: Some(kube::api::PropagationPolicy::Orphan),
        ..kube::api::DeleteParams::default()
    }
}

/// Outcome of polling an accepted DELETE for confirmed absence.
#[derive(Debug, PartialEq, Eq)]
enum SweepAbsence {
    /// The object is confirmed gone (404 observed).
    Absent,
    /// The object is still live when the confirmation window closed
    /// (orphaning or another finalizer still holds it): the sweep must not
    /// report completion while the object may survive.
    StillLive,
    /// Absence could not be confirmed (read failures/deadline): undecidable.
    Uninspectable,
}

/// Poll for the object's absence within `min(sweep deadline, per-object
/// confirmation budget)` instead of a single immediate GET.
async fn wait_for_sweep_absence<K>(
    api: &kube::Api<K>,
    name: &str,
    sweep_deadline: tokio::time::Instant,
) -> SweepAbsence
where
    K: kube::Resource + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let confirm_deadline =
        (tokio::time::Instant::now() + SWEEP_CONFIRM_ABSENCE_TIMEOUT).min(sweep_deadline);
    loop {
        match bounded_sweep_read(confirm_deadline, api.get_opt(name)).await {
            Ok(None) => return SweepAbsence::Absent,
            Ok(Some(_)) => {
                if tokio::time::Instant::now() + SWEEP_CONFIRM_ABSENCE_INTERVAL >= confirm_deadline
                {
                    return SweepAbsence::StillLive;
                }
                tokio::time::sleep(SWEEP_CONFIRM_ABSENCE_INTERVAL).await;
            }
            Err(_) => return SweepAbsence::Uninspectable,
        }
    }
}

/// Delete exactly the objects this failed generation created in an adopted
/// namespace. Each target is first GET'd: an object is deleted only when
/// its live mutation-generation annotation is positive and not newer than
/// the failed generation (proving the last writer was a CAP apply of this
/// app) AND it carries
/// CAP creation evidence (`RESOURCE_CREATED_BY_ANNOTATION`, stamped only by
/// the create POST in `apply_resource` — never by an SSA patch of a
/// pre-existing object). The delete carries UID + resourceVersion
/// preconditions from that same GET (so a replaced object cannot be
/// deleted by a stale decision). Objects that are absent, carry another
/// generation, or were merely patched by CAP (no creation evidence) are
/// skipped: a pre-existing same-named Secret, Service, or ConfigMap in an
/// adopted namespace may retain fields and consumers owned by the
/// namespace owner, and last-writer proof is not deletion authority.
/// Returns the number of objects whose deletion was attempted and failed:
/// non-zero means the sweep is incomplete and must be retried (the caller
/// retains provider-state evidence so later failed generations stay
/// cleanup-eligible).
/// Durably record that a mutating webhook stripped CAP creation evidence
/// from an accepted write of this app (and from its compensating restores):
/// sets the app-level `creation_evidence_lost` marker consumed by the
/// adopted-namespace sweep. Called from the terminal-apply-failure cleanup
/// and from the non-job control-plane write paths (replicas changes, ingress
/// restarts) that surface `ApplyError::CreationEvidenceLost`. The marker is
/// cleared only by operator remediation — no automatic path can prove the
/// stripped object was not CAP-created.
pub(crate) async fn persist_creation_evidence_loss(pool: &sqlx::PgPool, app_id: Uuid) -> bool {
    match sqlx::query(
        "UPDATE apps SET creation_evidence_lost = true, updated_at = now() WHERE id = $1",
    )
    .bind(app_id)
    .execute(pool)
    .await
    {
        Ok(_) => true,
        Err(error) => {
            tracing::error!(
                app_id = %app_id,
                error = %error,
                "cannot persist the creation-evidence-loss marker; sweeps will not know unmarked targets may be CAP-created"
            );
            false
        }
    }
}

/// Whether this app carries the durable creation-evidence-loss marker.
/// Fails closed: a database error counts as marker-present so the sweep
/// stays incomplete rather than silently clearing evidence.
async fn app_creation_evidence_lost(state: &crate::state::AppState, app_id: Uuid) -> bool {
    match sqlx::query_scalar::<_, bool>("SELECT creation_evidence_lost FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(true)) => true,
        Ok(_) => false,
        Err(error) => {
            tracing::warn!(
                app_id = %app_id,
                error = %error,
                "cannot read the creation-evidence-loss marker; treating the app as marked (fail closed)"
            );
            true
        }
    }
}

pub(crate) async fn sweep_published_objects_from_adopted_namespace(
    state: &crate::state::AppState,
    app: &App,
    failed_deployment_id: Uuid,
    generation: enclava_engine::apply::generation::MutationGeneration,
    // Codex P2 (webhook-stripped evidence): the terminal apply failure of
    // `failed_deployment_id` was `creation_evidence_lost` — a mutating
    // webhook stripped the creation annotation from an accepted update and
    // from every compensating restore, so a live unmarked target may be a
    // CAP-created object whose evidence is unrecoverable. Passed by the
    // caller from the in-memory terminal error (deployment rows persist
    // only a coarse error message; the structured codes live on
    // deployment_apply_jobs behind a CHECK that cannot hold this one).
    evidence_loss_unresolved: bool,
) -> usize {
    let client = match kube::Client::try_default().await {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "adopted-namespace sweep cannot reach Kubernetes; leaving published objects for reconciliation"
            );
            return usize::MAX;
        }
    };
    let sweep_deadline = tokio::time::Instant::now() + SWEEP_DEADLINE;
    // The legacy temporal bound (devin 🔴 round-6): rows published before
    // the `apply_started_at` column existed (manifest_hash set,
    // apply_started_at NULL) can only be pre-release rows whose objects
    // never carry creation evidence — a live unmarked target under them is
    // UNRESOLVED, not foreign (see `unmarked_target_is_unresolved`).
    // Loaded fail-closed: a query failure counts as sweep failure
    // (retryable), not as "no legacy rows" (which would silently skip
    // unmarked targets as foreign and clear evidence over them).
    //
    // (#273) The StatefulSet lineage columns (sts_uid, sts_proven_uids,
    // ...) are deliberately NOT loaded here anymore: they used to feed the
    // claim-deletion authority (`classify_claim_lineage` matched PVC
    // ownerReferences against proven UIDs), which was tenant-forgeable in
    // an adopted namespace and is removed — see
    // `sweep_statefulset_pvcs`. The columns stay populated for
    // observability only.
    let legacy_row_started_at: Option<chrono::DateTime<chrono::Utc>> = {
        let rows: Vec<SweepScopeRow> = match sqlx::query_as(
            "SELECT manifest_hash, apply_started_at, created_at
           FROM deployments
          WHERE app_id = $1
            AND (id = $2 OR cleanup_sweep_incomplete)",
        )
        .bind(app.id)
        .bind(failed_deployment_id)
        .fetch_all(&state.db)
        .await
        {
            Ok(rows) => rows,
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    deployment_id = %failed_deployment_id,
                    error = %error,
                    "adopted-namespace sweep cannot load the legacy row bound; counting the sweep as failed for retry"
                );
                return usize::MAX;
            }
        };
        earliest_legacy_row_started_at(rows.iter().map(
            |(manifest_hash, apply_started, row_created_at)| {
                (manifest_hash.as_deref(), *apply_started, *row_created_at)
            },
        ))
    };
    // Codex P2: the in-memory flag covers THIS failure; the durable
    // app-level marker covers earlier losses (a later sweep of a different
    // failed generation, or a loss surfaced on a non-job write path).
    let evidence_loss_unresolved =
        evidence_loss_unresolved || app_creation_evidence_lost(state, app.id).await;
    // cap#272: deletion authority requires server-recorded creation
    // lineage. Load the app's durable ledger rows fail-closed — a query
    // failure aborts the sweep (retryable) rather than running it with an
    // unenforced ledger.
    let creation_ledger = match load_creation_ledger(&state.db, app.id).await {
        Ok(ledger) => ledger,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "adopted-namespace sweep cannot load the creation ledger; counting the sweep as failed for retry"
            );
            return usize::MAX;
        }
    };
    let mut failures = 0usize;
    let mut targets = adopted_namespace_sweep_targets(app);
    // Codex P2 (renamed pull secrets): candidate Secret discovery must not
    // depend on the CURRENT process's `TENANT_IMAGE_PULL_SECRET_NAME`. An
    // incomplete adopted-namespace cleanup can survive a restart into a
    // world where the configured name changed or was removed; searching
    // only the current name would sweep everything, clear all sibling
    // cleanup evidence, and strand the earlier CAP-created Secret — and
    // its registry credentials — indefinitely. Enumerate Secrets carrying
    // CAP creation evidence and add them as candidates (per-target
    // deletion stays evidence-gated below).
    let secrets_api: kube::Api<k8s_openapi::api::core::v1::Secret> =
        kube::Api::namespaced(client.clone(), &app.namespace);
    match bounded_sweep_list_all(&secrets_api, sweep_deadline).await {
        Ok(list) => {
            for secret in list {
                let Some(name) = secret.metadata.name.clone() else {
                    continue;
                };
                let has_creation_evidence = secret
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| {
                        annotations
                            .get(enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION)
                    })
                    .and_then(|raw| raw.parse::<i64>().ok())
                    .is_some_and(|created_by| created_by > 0);
                // Codex P2 (renamed legacy secrets): a pre-release failure
                // that migration 0072 made cleanup-eligible can have created
                // the image-pull Secret under an OLD configured name, and
                // that generation can never carry RESOURCE_CREATED_BY_ANNOTATION.
                // If the configured name changed before this sweep, the old
                // Secret is invisible to both the configured-name target and
                // the annotation filter above — the sweep would report
                // success and clear both rows' evidence over live registry
                // credentials. CAP's pull secret is always
                // `kubernetes.io/dockerconfigjson`, so when a legacy evidence
                // row is in scope an UNMARKED Secret of that type is a
                // plausible legacy product: add it as a candidate. Deletion
                // stays evidence-gated (an unmarked Secret cannot be deleted)
                // and the per-target legacy handling below counts it
                // UNRESOLVED — keeping the sweep incomplete — unless it
                // provably predates every legacy row (then it is a foreign
                // pre-existing Secret and is skipped).
                // Codex P2 (webhook-stripped evidence): the same
                // discovery gap applies to a CAP pull secret whose creation
                // annotation a webhook stripped — trigger on the durable
                // marker exactly like the legacy-row case.
                let plausible_legacy_pull_secret = !has_creation_evidence
                    && (legacy_row_started_at.is_some() || evidence_loss_unresolved)
                    && secret.type_.as_deref() == Some("kubernetes.io/dockerconfigjson");
                if (has_creation_evidence || plausible_legacy_pull_secret)
                    && !targets
                        .iter()
                        .any(|target| target.kind == "Secret" && target.name == name)
                {
                    tracing::info!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        secret = %name,
                        created_evidence = has_creation_evidence,
                        "adopted-namespace sweep discovered a CAP-created Secret outside the configured pull-secret name; adding it as a sweep candidate"
                    );
                    targets.push(AdoptedNamespaceSweep {
                        kind: "Secret",
                        name,
                    });
                }
            }
        }
        Err(error) => {
            // Fail closed: a renamed CAP credential Secret may still be in
            // the namespace. Clearing evidence over an uninspected
            // namespace would strand its registry credentials with no
            // later cleanup eligibility.
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "adopted-namespace sweep cannot enumerate Secrets for creation evidence; counting the sweep as failed for retry"
            );
            failures += 1;
        }
    }
    for target in targets {
        if tokio::time::Instant::now() >= sweep_deadline {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                kind = target.kind,
                name = %target.name,
                "adopted-namespace sweep hit its overall deadline; counting remaining targets as failures"
            );
            failures += 1;
            continue;
        }
        let ar = sweep_api_resource(target.kind);
        let api: kube::Api<kube::api::DynamicObject> =
            kube::Api::namespaced_with(client.clone(), &app.namespace, &ar);
        // Bounded re-read retry: a controller can bump the resourceVersion
        // between our GET and the delete (409). Each retry re-reads the
        // live object and re-checks ownership before deleting, so a
        // replaced object of another generation is never hit.
        let mut deleted = false;
        let mut exhausted_conflicts = false;
        for attempt in 0..SWEEP_DELETE_RETRIES {
            let live = match bounded_sweep_read(sweep_deadline, api.get_opt(&target.name)).await {
                Ok(live) => live,
                Err(error) => {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        error = %error,
                        "adopted-namespace sweep cannot inspect object; will retry via reconciliation"
                    );
                    failures += 1;
                    break;
                }
            };
            let Some(live) = live else {
                // Dependents are inspected below even on this absent-owner
                // retry path: orphaned Pods and PVCs can still be live.
                break; // never created, or already deleted
            };
            let classification =
                classify_generation_leftover(&live, generation.get(), &creation_ledger);
            if !matches!(classification, GenerationLeftover::Leftover) {
                // Codex P2: valid CAP creation evidence but a lost/unparseable
                // generation marker (an admission webhook can drop or rewrite
                // it on update; the update path's verify_applied_generation
                // then fails without compensation) — ownership of the
                // still-live object is UNRESOLVED: it may be another
                // generation's adopted object, so never delete it; and
                // skipping it silently would let the caller declare the sweep
                // complete and clear evidence over a partially updated
                // resource. Fail closed: count the failure, keep retrying.
                //
                // cap#272 (ProvenanceUnproven): creation evidence and manager
                // ownership both LOOK right, but the object postdates the
                // ledger cutover and no recorded creation row matches its
                // UID — the forged-stamp shape. Deletion refuses and the
                // sweep stays incomplete over it (retryable; the namespace
                // owner resolves it by deleting their own object, exactly
                // like a MarkerLost webhook casualty).
                if matches!(
                    classification,
                    GenerationLeftover::MarkerLost | GenerationLeftover::ProvenanceUnproven
                ) {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        unresolved = ?classification,
                        "sweep found a CAP-evidence object with unresolved ownership (lost marker or unproven creation lineage); keeping the sweep incomplete"
                    );
                    failures += 1;
                    break;
                }
                // Foreign (no creation evidence — includes objects CAP
                // merely SSA-patched), or a newer generation's publication:
                // never delete on name alone.
                //
                // Codex P1 (legacy unmarked rows): objects created by
                // pre-release rows can never carry creation evidence —
                // if a legacy evidence row (manifest_hash without
                // apply_started_at, i.e. published before the column
                // existed) is part of this sweep's row set, a live
                // unmarked target is UNRESOLVED, not foreign. Skipping it
                // silently would let the caller declare the sweep complete
                // and clear both rows' evidence over the still-live legacy
                // StatefulSet/Secret/Service/ConfigMaps (no later
                // eligibility would ever exist). Count it as a failure:
                // fail closed, keep both rows retryable.
                // Temporal carve-out (devin 🔴 follow-up): an object
                // provably created BEFORE the earliest legacy row existed
                // cannot be a legacy row's product — the pre-existing
                // tenant ServiceAccount/ResourceQuota/Service with a
                // target-shaped name. It stays foreign and is skipped:
                // counting it would wedge the sweep (the ownership gate
                // keeps it forever) and block storage-size changes
                // permanently.
                let provably_predates_legacy_rows = live
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .and_then(|ts| {
                        ts.0.to_string()
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .ok()
                    })
                    .zip(legacy_row_started_at)
                    .is_some_and(|(object_created, legacy_started)| {
                        object_created < legacy_started
                    });
                if unmarked_target_is_unresolved(
                    legacy_row_started_at.is_some(),
                    provably_predates_legacy_rows,
                    evidence_loss_unresolved,
                ) {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        evidence_loss_unresolved,
                        legacy_row_in_scope = legacy_row_started_at.is_some(),
                        "adopted-namespace sweep cannot attribute live unmarked object; counting the sweep incomplete"
                    );
                    failures += 1;
                } else {
                    tracing::info!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        "adopted-namespace sweep skips object not created by a CAP failed apply"
                    );
                    // A foreign replacement must not hide orphaned Pods or
                    // PVCs from a previous sweep. Inspect dependents below,
                    // irrespective of the owner's classification.
                }
                break;
            }
            let preconditions = kube::api::Preconditions {
                uid: live.metadata.uid.clone(),
                resource_version: live.metadata.resource_version.clone(),
            };
            if target.kind == "StatefulSet" {
                // Persist the StatefulSet's proven lineage record BEFORE
                // the delete (server-reported uid + creationTimestamp) for
                // observability: which StatefulSet UIDs this app's failed
                // applies created. (#273: this record no longer authorizes
                // claim deletion — PVC ownerReferences are matched against
                // nothing; see `sweep_statefulset_pvcs`.) The deletion edge
                // is recorded alongside for observability.
                let observed_created_at =
                    live.metadata.creation_timestamp.as_ref().and_then(|ts| {
                        ts.0.to_string()
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .ok()
                    });
                let deleted_edge = chrono::Utc::now();
                if let (Some(uid), Some(created)) =
                    (live.metadata.uid.as_deref(), observed_created_at)
                    && let Err(error) = persist_sts_provenance(
                        &state.db,
                        Some(app.id),
                        failed_deployment_id,
                        uid,
                        created,
                        Some(deleted_edge),
                    )
                    .await
                {
                    tracing::warn!(
                        app_id = %app.id,
                        deployment_id = %failed_deployment_id,
                        error = %error,
                        "adopted-namespace sweep could not persist the observed sts lineage record (observability-only; no sweep decision reads it)"
                    );
                }
            }
            match bounded_sweep_read(
                sweep_deadline,
                api.delete(&target.name, &adopted_sweep_delete_params(preconditions)),
            )
            .await
            {
                Ok(_) => {
                    // Accepted DELETE is not absence: a finalizer can hold
                    // the object in Terminating indefinitely — and with the
                    // orphan propagation above, the orphan finalizer must
                    // finish detaching dependents before the owner vanishes.
                    // Poll for confirmed 404 within the confirmation window
                    // (codex P2) instead of treating the first live response
                    // as the final outcome, then count the target complete.
                    match wait_for_sweep_absence(&api, &target.name, sweep_deadline).await {
                        SweepAbsence::Absent => {
                            deleted = true;
                            break;
                        }
                        SweepAbsence::StillLive => {
                            // Still Terminating or finalizer-stuck when the
                            // confirmation window closed: the sweep must not
                            // report completion while the object may survive.
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                kind = target.kind,
                                name = %target.name,
                                "adopted-namespace sweep delete accepted but object still live after the confirmation window (orphaning or finalizer?); counting as incomplete"
                            );
                            failures += 1;
                            break;
                        }
                        SweepAbsence::Uninspectable => {
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                kind = target.kind,
                                name = %target.name,
                                "adopted-namespace sweep cannot confirm absence after delete; counting as incomplete"
                            );
                            failures += 1;
                            break;
                        }
                    }
                }
                Err(kube::Error::Api(error)) if error.code == 404 => {
                    // Raced deletion: the object vanished between our GET
                    // and this DELETE. It is already absent — that IS
                    // successful cleanup, not a failure.
                    deleted = true;
                    break;
                }
                Err(kube::Error::Api(error)) if error.code == 409 => {
                    // Preconditions raced with a controller write: re-read
                    // and retry under the same ownership check. Burning the
                    // whole budget on conflicts leaves a live object — an
                    // incomplete sweep, not a completed one.
                    if attempt + 1 == SWEEP_DELETE_RETRIES {
                        exhausted_conflicts = true;
                    }
                    continue;
                }
                Err(error) => {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        error = %error,
                        "adopted-namespace sweep deletion failed; will retry via reconciliation"
                    );
                    failures += 1;
                    break;
                }
            }
        }
        if !deleted && exhausted_conflicts {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                kind = target.kind,
                name = %target.name,
                "adopted-namespace sweep exhausted its delete retries on conflicts; counting as failure"
            );
            failures += 1;
        }
        // Always inspect StatefulSet dependents, including absent owners,
        // foreign same-name replacements, refused deletes, and conflicts.
        // Orphaned Pods lose refs; the current owner's UID/creation evidence
        // says nothing about whether an earlier sweep left them running.
        if target.kind == "StatefulSet" {
            // A deleted StatefulSet leaves its PVCs behind (the manifest's
            // retention policy is Retain): inspect the name-matching
            // claims too. Since #273 the claim sweep deletes NOTHING (in
            // an adopted namespace, PVC ownerReferences are tenant-writable
            // and the live UID tenant-readable, so no claim field is
            // non-forgeable); it counts every remaining name-matching
            // claim as a failure so the sweep stays INCOMPLETE and the
            // storage-size guard stays armed until the claims are gone
            // (namespace owner or app deletion — #251). Orphaned Pods
            // also keep cleanup incomplete; they are not deleted via GC.
            failures +=
                sweep_statefulset_dependents(&client, &app.namespace, &target.name, sweep_deadline)
                    .await;
        }
    }
    failures
}

/// A live object's metadata makes it a leftover of this app's failed
/// applies that CAP itself CREATED: it carries creation evidence
/// (`RESOURCE_CREATED_BY_ANNOTATION` > 0 — stamped only by the create POST
/// in `apply_resource`, so a pre-existing object CAP merely SSA-patched can
/// never acquire it) whose last-writer generation is positive and not
/// newer than the failed one (a newer generation's publication is not this
/// failure's partial state). The sweep only runs after the ownership gate
/// proved no other deployment of this app retains provider state, so an
/// older created object can only be a leftover of an earlier failed
/// apply — exactly what must not survive generation after generation.
/// Ownership of a live object relative to a failed generation's cleanup.
#[derive(Clone, Copy, Debug)]
pub(crate) enum GenerationLeftover {
    /// CAP creation evidence plus a generation marker of this or an earlier
    /// generation: a leftover of the failed generation's apply — a sweep may
    /// remove it under its other gates.
    Leftover,
    /// No CAP creation evidence (objects CAP merely SSA-patched, tenant
    /// artifacts), or the marker pins a NEWER generation's publication:
    /// never delete on name alone.
    Foreign,
    /// Valid CAP creation evidence but the mutation-generation annotation is
    /// absent or unparseable (Codex P2: an admission webhook can drop or
    /// rewrite it on an update, and the update path's
    /// `verify_applied_generation` then fails without compensation).
    /// Ownership of the still-live object is UNRESOLVED — it may be another
    /// generation's adopted object, so it is never deleted; and silently
    /// skipping it as foreign would let the caller declare the sweep
    /// complete and clear cleanup evidence over it, leaving a partially
    /// updated resource with no later eligibility. Fail closed instead.
    MarkerLost,
    /// cap#272: valid-looking CAP creation evidence (annotation + manager
    /// ownership), but the object was created after the ledger cutover and
    /// its (name, uid) has NO recorded creation row — the exact shape a
    /// tenant forges by pre-creating a target-named object and submitting
    /// the write with `fieldManager=enclava-platform`. Deletion refuses;
    /// foreign-skip would let the sweep complete and clear evidence over
    /// an object that (in the rare unrecorded-creation case) may still be
    /// CAP's own, so the sweep stays incomplete over it instead: fail
    /// closed, retryable, operator-resolvable.
    ProvenanceUnproven,
}

pub(crate) fn classify_generation_leftover<K>(
    resource: &K,
    failed_generation: i64,
    creation_ledger: &enclava_engine::apply::creation_ledger::CreationLedgerBuffer,
) -> GenerationLeftover
where
    K: kube::Resource,
{
    let metadata = resource.meta();
    let annotation = |key: &str| {
        metadata
            .annotations
            .as_ref()
            .and_then(|annotations| annotations.get(key))
            .and_then(|raw| raw.parse::<i64>().ok())
    };
    let Some(created_by) =
        annotation(enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION)
    else {
        return GenerationLeftover::Foreign;
    };
    if !(created_by > 0) {
        return GenerationLeftover::Foreign;
    }
    // Value alone is not proof: SSA omission cannot remove a marker a
    // tenant's field manager owns, so a pre-existing object carrying a
    // tenant-authored creation annotation keeps it after CAP stamps the
    // mutation generation. Require CAP field-manager provenance over
    // that annotation on the LIVE object (the create POST attributes
    // its fields to the enclava-platform manager). Fails closed when
    // managed fields are absent.
    if !enclava_engine::apply::generation::annotation_owned_by_manager(
        resource,
        enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION,
        &enclava_engine::apply::types::ApplyConfig::default().field_manager,
    ) {
        return GenerationLeftover::Foreign;
    }
    // Creation evidence is proven; only the generation marker is missing or
    // garbled (Codex P2) or the marker settles the attribution.
    let raw_generation = metadata.annotations.as_ref().and_then(|annotations| {
        annotations.get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
    });
    let live_generation = raw_generation.and_then(|raw| raw.parse::<i64>().ok());
    match live_generation {
        Some(live) if live > 0 && live <= failed_generation => {
            // cap#272: the manager string itself is client-selected, so
            // even a manager-owned annotation is not creation proof. For a
            // candidate LEFTOVER, deletion authority additionally requires
            // server-recorded lineage — the live UID matches a row the
            // control plane wrote at its own create POST, or the object
            // predates the ledger cutover (bounded one-time migration
            // trust). A newer generation's publication stays Foreign and
            // an unparseable marker stays MarkerLost regardless of
            // provenance: neither ever deletes, so provenance cannot
            // settle them further.
            let lineage = enclava_engine::apply::creation_ledger::creation_lineage_provenance(
                metadata.name.as_deref(),
                metadata.uid.as_deref(),
                metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|ts| ts.0.to_string())
                    .as_deref(),
                Some(creation_ledger),
            );
            if lineage == enclava_engine::apply::creation_ledger::LineageProvenance::Unproven {
                return GenerationLeftover::ProvenanceUnproven;
            }
            GenerationLeftover::Leftover
        }
        Some(live) if live > failed_generation => GenerationLeftover::Foreign,
        _ => GenerationLeftover::MarkerLost,
    }
}

pub(crate) fn is_cap_created_generation_leftover<K>(
    resource: &K,
    failed_generation: i64,
    creation_ledger: &enclava_engine::apply::creation_ledger::CreationLedgerBuffer,
) -> bool
where
    K: kube::Resource,
{
    matches!(
        classify_generation_leftover(resource, failed_generation, creation_ledger),
        GenerationLeftover::Leftover
    )
}

/// (manifest_hash, apply_started_at, created_at) of one sweep-scope
/// deployment row.
type SweepScopeRow = (
    Option<String>,
    Option<chrono::DateTime<chrono::Utc>>,
    chrono::DateTime<chrono::Utc>,
);

/// Codex P1 (legacy unmarked rows): a failed row that holds provider-state
/// evidence (`manifest_hash`) but predates the migration that added
/// `apply_started_at` — the column is stamped in the SAME atomic UPDATE
/// that writes `manifest_hash` (the `'applying'` transition in
/// `set_deployment_status`), so evidence without it can only belong to a
/// row published before the column existed. Objects such a row created
/// can never carry `RESOURCE_CREATED_BY_ANNOTATION` (stamped only by the
/// create POST of this release), so the evidence-gated sweep skip below
/// would silently exempt them; the caller would then clear BOTH rows'
/// evidence over possibly-live legacy objects. When such a row is in the
/// sweep's row set, a live target WITHOUT creation evidence is therefore
/// unresolved, not foreign: count it as a failure so the sweep stays
/// incomplete and both rows keep their evidence (retryable, fail closed).
///
/// Returns the EARLIEST such row's `created_at` so the caller can
/// temporally carve out objects that provably predate every legacy row
/// (devin 🔴 follow-up): a pre-existing tenant object with a target-shaped
/// name — the ServiceAccount or ResourceQuota every namespace shares, a
/// Service matching the app name — can never be deleted by the sweep (the
/// ownership gate keeps it), so counting it as a failure would wedge
/// cleanup and block storage-size changes forever. An object created
/// strictly before the earliest legacy row's row-creation instant cannot
/// be any legacy row's product and is skipped as foreign.
fn earliest_legacy_row_started_at<'a>(
    rows: impl Iterator<
        Item = (
            Option<&'a str>,
            Option<chrono::DateTime<chrono::Utc>>,
            chrono::DateTime<chrono::Utc>,
        ),
    >,
) -> Option<chrono::DateTime<chrono::Utc>> {
    rows.filter(|(manifest_hash, apply_started, _)| {
        manifest_hash.is_some() && apply_started.is_none()
    })
    .map(|(_, _, row_created_at)| row_created_at)
    .min()
}

/// Whether a live sweep target WITHOUT creation evidence is UNRESOLVED
/// rather than foreign. Two independent reasons:
///
/// 1. Codex P1 (legacy unmarked rows): a legacy evidence row is in the
///    sweep's row set and the object does not provably predate it — see
///    `earliest_legacy_row_started_at`.
/// 2. Codex P2 (webhook-stripped evidence): this apply failed with
///    `creation_evidence_lost`, or the app carries the durable
///    `creation_evidence_lost` marker — a mutating admission webhook
///    stripped the creation annotation from an ACCEPTED update and from
///    every compensating restore (a deterministic webhook strips every
///    write, so no write can ever re-stamp it). A live
///    unmarked target may then be a CAP-created object whose evidence is
///    unrecoverable: deleting it is unproven, and skipping it silently
///    would let the sweep complete and clear cleanup evidence over a
///    partially updated resource with no later eligibility. Fail closed
///    instead — the sweep stays incomplete and the rows keep their
///    evidence. The legacy temporal carve-out deliberately does NOT apply
///    to this arm: the at-risk object is typically OLD (created by an
///    earlier generation, updated by the failed one), so predating the
///    failing row proves nothing.
fn unmarked_target_is_unresolved(
    legacy_row_in_scope: bool,
    provably_predates_legacy_rows: bool,
    evidence_loss_unresolved: bool,
) -> bool {
    (legacy_row_in_scope && !provably_predates_legacy_rows) || evidence_loss_unresolved
}

/// Bounded re-read retry budget for preconditioned sweep deletes.
const SWEEP_DELETE_RETRIES: usize = 3;

/// VCT names the CAP manifest renders (`manifest::volumes`): the sweep's
/// claim-name shape and the controller's claim set are these two templates.
const CAP_VCT_NAMES: [&str; 2] = ["state", "tls-state"];

/// Durably record a server-reported StatefulSet provenance (uid +
/// creationTimestamp) for a deployment row. Every proven UID accumulates in
/// `sts_proven_uids` (Codex P2 — a reclaimed deployment can re-create the
/// set under a NEW UID, and every incarnation stays recorded);
/// `sts_uid`/`sts_created_at` keep first-writer-wins as the
/// primary lineage record, `observed_deleted_at` (sweep path) records the
/// deletion edge. Callers gate WHAT is proven (CAP creation evidence) —
/// this only records it. (#273: this record is observability-only — it no
/// longer feeds any deletion decision; claim deletion authority was
/// removed from the adopted-namespace sweep entirely.)
pub(crate) async fn persist_sts_provenance(
    pool: &sqlx::PgPool,
    app_id: Option<uuid::Uuid>,
    deployment_id: uuid::Uuid,
    uid: &str,
    created_at: chrono::DateTime<chrono::Utc>,
    observed_deleted_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE deployments
            SET sts_uid = COALESCE(sts_uid, $3),
                sts_created_at = COALESCE(sts_created_at, $4),
                sts_observed_deleted_at = COALESCE(sts_observed_deleted_at, $5),
                sts_proven_uids = CASE
                    WHEN $3 = ANY(sts_proven_uids) THEN sts_proven_uids
                    ELSE array_append(COALESCE(sts_proven_uids, '{}'), $3)
                END
          WHERE id = $2
            AND ($1::uuid IS NULL OR app_id = $1)",
    )
    .bind(app_id)
    .bind(deployment_id)
    .bind(uid)
    .bind(created_at)
    .bind(observed_deleted_at)
    .execute(pool)
    .await
    .map(|_| ())
}

/// Trusted operator-only rollout configuration, snapshotted once per process.
/// `CAP_CREATION_LEDGER_ACTIVATED_AT` is an absolute activation timestamp, NOT
/// a duration, startup time, or tenant setting. Absent means no legacy trust;
/// malformed/future values abort ledger loading (and therefore cleanup).
///
/// Activation procedure and accepted legacy-forgery risk are documented in
/// `enclava_engine::apply::creation_ledger`. Quiesce writers, drain old binaries,
/// deploy ledger recording everywhere, audit legacy objects, then pin the
/// observed activation instant consistently in every replica's deployment
/// configuration. Retain that exact value across upgrades; never advance it
/// to make an unresolved object deletable. Clearing it only removes trust.
fn configured_creation_ledger()
-> Result<enclava_engine::apply::creation_ledger::CreationLedgerBuffer, sqlx::Error> {
    use enclava_engine::apply::creation_ledger::CreationLedgerBuffer;
    use k8s_openapi::jiff::Timestamp;

    static CUTOFF: std::sync::OnceLock<Result<Option<String>, String>> = std::sync::OnceLock::new();
    let cutoff = CUTOFF.get_or_init(|| match std::env::var("CAP_CREATION_LEDGER_ACTIVATED_AT") {
        Ok(raw) => {
            CreationLedgerBuffer::with_legacy_cutover(&raw, Timestamp::now())?;
            Ok(Some(raw))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(format!("CAP_CREATION_LEDGER_ACTIVATED_AT: {error}")),
    });
    let result = match cutoff {
        Ok(Some(raw)) => CreationLedgerBuffer::with_legacy_cutover(raw, Timestamp::now()),
        Ok(None) => Ok(CreationLedgerBuffer::new()),
        Err(error) => Err(error.clone()),
    };
    result.map_err(|error| {
        sqlx::Error::Configuration(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("CAP_CREATION_LEDGER_ACTIVATED_AT: {error}"),
        )))
    })
}

/// Load the app's durable creation-ledger rows (cap#272) into an
/// engine-side [`CreationLedgerBuffer`]. Every deletion-authority check in
/// this module (object sweep, namespace teardown, StatefulSet provenance)
/// matches live UIDs against this set. Fails closed on a database error —
/// the caller aborts the sweep/teardown rather than proceeding with an
/// empty (unenforced) ledger.
pub(crate) async fn load_creation_ledger(
    pool: &sqlx::PgPool,
    app_id: uuid::Uuid,
) -> Result<std::sync::Arc<enclava_engine::apply::creation_ledger::CreationLedgerBuffer>, sqlx::Error>
{
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT kind, name, uid FROM resource_creation_ledger WHERE app_id = $1")
            .bind(app_id)
            .fetch_all(pool)
            .await?;
    let ledger = std::sync::Arc::new(configured_creation_ledger()?);
    ledger.preload(rows);
    Ok(ledger)
}

/// Resolve an app's creation ledger from its namespace name (used by the
/// retained-fence reconciler, which only knows the namespace). Fails
/// closed on lookup errors: callers retain their fence and retry.
pub(crate) async fn load_creation_ledger_for_namespace(
    pool: &sqlx::PgPool,
    namespace: &str,
) -> Result<std::sync::Arc<enclava_engine::apply::creation_ledger::CreationLedgerBuffer>, sqlx::Error>
{
    let app_id: Option<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM apps WHERE namespace = $1")
        .bind(namespace)
        .fetch_optional(pool)
        .await?;
    match app_id {
        Some(app_id) => load_creation_ledger(pool, app_id).await,
        // No app row owns the namespace anymore: no ledger rows can match.
        // Only the explicitly configured bounded legacy trust may remain.
        None => Ok(std::sync::Arc::new(configured_creation_ledger()?)),
    }
}

/// Durably append creation records observed by an apply (drained from the
/// engine's ledger buffer). Idempotent per (app_id, uid): a retried apply
/// re-observing the same creation must not fail. The apply path calls this
/// after every apply step and MUST fail closed (compensating the created
/// objects) when it errors — "created but unrecorded" must never leak into
/// cleanup, where it could only surface as a permanently unresolved sweep
/// target.
pub(crate) async fn persist_creation_records(
    pool: &sqlx::PgPool,
    app_id: uuid::Uuid,
    deployment_id: uuid::Uuid,
    records: &[enclava_engine::apply::creation_ledger::CreationRecord],
) -> Result<(), sqlx::Error> {
    for record in records {
        sqlx::query(
            "INSERT INTO resource_creation_ledger
                 (app_id, deployment_id, kind, name, namespace, uid, mutation_generation)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (app_id, uid) DO NOTHING",
        )
        .bind(app_id)
        .bind(deployment_id)
        .bind(&record.kind)
        .bind(&record.name)
        .bind(&record.namespace)
        .bind(&record.uid)
        .bind(record.mutation_generation)
        .execute(pool)
        .await?;
    }
    Ok(())
}

/// Orphan deletion must not let the owner reaching 404 hide running Pods.
/// Names, not ownerReferences, identify candidates: orphaning removes refs,
/// and retries must still find the Pods after the StatefulSet has vanished.
/// Retain rather than delete them: cascading a Pod delete could likewise
/// remove a tenant PVC with a forged reference to that Pod. Pods may still
/// be running; the namespace owner must remove them (or delete the app).
/// Until then, cleanup remains incomplete even when no PVCs exist.
async fn sweep_statefulset_dependents(
    client: &kube::Client,
    namespace: &str,
    statefulset: &str,
    sweep_deadline: tokio::time::Instant,
) -> usize {
    let claims = sweep_statefulset_pvcs(client, namespace, statefulset, sweep_deadline).await;
    let pods: kube::Api<k8s_openapi::api::core::v1::Pod> =
        kube::Api::namespaced(client.clone(), namespace);
    match bounded_sweep_list_all(&pods, sweep_deadline).await {
        Ok(pods) => {
            claims
                + pods
                    .iter()
                    .filter(|pod| {
                        pod.metadata.name.as_deref().is_some_and(|name| {
                            name.strip_prefix(statefulset)
                                .and_then(|suffix| suffix.strip_prefix('-'))
                                .is_some_and(|ordinal| {
                                    !ordinal.is_empty()
                                        && ordinal.bytes().all(|c| c.is_ascii_digit())
                                        && (ordinal == "0" || !ordinal.starts_with('0'))
                                })
                        })
                    })
                    .count()
        }
        Err(error) => {
            tracing::warn!(%namespace, %statefulset, %error,
                "cannot inspect orphaned Pods; retaining adopted-namespace cleanup evidence");
            claims + 1
        }
    }
}

/// Inspect the name-matching PVC claims of a swept StatefulSet in an
/// ADOPTED namespace and report how many claims keep the sweep INCOMPLETE.
/// Since #273 this sweep DELETES NOTHING: deletion authority used to be the
/// claim's own `ownerReferences` — a StatefulSet-kind ref pinning the UID
/// of a StatefulSet a CAP apply created (`classify_claim_lineage`, now
/// removed) — but in an adopted namespace every input to that proof is
/// tenant-controllable: `ownerReferences` on the tenant's own PVCs are
/// tenant-writable, and the live StatefulSet's UID is namespace-readable
/// (so even requiring apiVersion/kind/name/controller/UID to match exactly
/// what the controller stamps only raises the forgery bar — every field
/// stays forgeable). A tenant could plant a predictable
/// `<vct>-<sts>-<ordinal>` claim (any canonical ordinal) with a forged
/// StatefulSet ownerRef and the sweep would delete it as "proven".
///
/// Deletion authority must be CAP-recorded evidence the namespace tenant
/// cannot manufacture, and no such evidence exists for claims here:
/// - the recorded StatefulSet provenance proves the SET is CAP's, not the
///   claim (the controller, not CAP, creates claims);
/// - a CAP-observed claim-UID ledger (the issue's option 1) does not exist
///   for these rows: apply ever only observes the ordinal-0 claims
///   (`inspect_fresh_volume_claims`) and persists none of their UIDs, and
///   the ownership gate confines this sweep to failed rows that never
///   reached `watching` — so no recorded claim UID is available to
///   authorize a delete here (option 1 is unimplemented state, not an
///   impossible one; building it is far more machinery than option 2);
/// - the sweep only ever runs in ADOPTED namespaces (a CAP-created
///   namespace is deleted wholesale and its claims die with it), so
///   restricting claim deletion to CAP-created namespaces (option 2) means
///   this path never deletes — which is what this implements, retaining
///   claims fail-closed exactly as the issue directs.
///
/// Every name-matching claim — forged or legitimate — is therefore
/// RETAINED and counted as a failure so the sweep reports INCOMPLETE
/// while any remain: reporting zero would let the caller clear manifest
/// evidence over retained claims, allowing a later resized deployment to
/// silently adopt them at their old size (the deploy route's storage-size
/// guard — `status <> 'failed' OR manifest_hash IS NOT NULL` — is the only
/// resize protection and must stay armed). Owner deletion uses Orphan
/// propagation as well: delegating deletion to Kubernetes GC would still
/// destroy tenant PVCs carrying forged references. Orphaned Pods are also
/// retained and counted by `sweep_statefulset_dependents`.
/// Resolution paths for retained claims: the namespace
/// owner removes the claim, or the app is deleted (issue #251).
pub(crate) async fn sweep_statefulset_pvcs(
    client: &kube::Client,
    namespace: &str,
    statefulset: &str,
    sweep_deadline: tokio::time::Instant,
) -> usize {
    let api: kube::Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
        kube::Api::namespaced(client.clone(), namespace);
    let list = match bounded_sweep_list_all(&api, sweep_deadline).await {
        Ok(list) => list,
        Err(error) => {
            tracing::warn!(
                namespace = %namespace,
                statefulset = %statefulset,
                error = %error,
                "adopted-namespace sweep cannot list PVCs; will retry via reconciliation"
            );
            return 1;
        }
    };
    // Inspect only name-matching claims; an empty match set is a complete
    // sweep. Anything else is retained fail-closed (#273): no claim field
    // is non-forgeable in an adopted namespace, so no claim is deleted.
    let matching_claims: Vec<_> = list
        .into_iter()
        .filter(|pvc| {
            pvc.metadata
                .name
                .as_deref()
                .is_some_and(|name| is_cap_claim_name(name, statefulset, &CAP_VCT_NAMES))
        })
        .collect();
    if matching_claims.is_empty() {
        return 0;
    }
    tracing::warn!(
        namespace = %namespace,
        statefulset = %statefulset,
        claims = matching_claims.len(),
        "adopted-namespace PVC sweep retains every name-matching claim (#273): in an adopted namespace ownerReferences are tenant-writable and the live StatefulSet UID is tenant-readable, so no claim field can authorize deletion; counting the sweep incomplete so manifest evidence (and the storage-size guard) survives"
    );
    matching_claims.len()
}

/// `<vct>-<statefulset>-<ordinal>` with a canonical ordinal, mirroring the
/// engine's `is_cap_owned_pvc_name`.
fn is_cap_claim_name(name: &str, statefulset: &str, vct_names: &[&str]) -> bool {
    let Some((stem, ordinal)) = name.rsplit_once('-') else {
        return false;
    };
    if ordinal.is_empty() || !ordinal.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if ordinal.len() > 1 && ordinal.starts_with('0') {
        return false;
    }
    vct_names
        .iter()
        .any(|vct| stem == format!("{vct}-{statefulset}"))
}

/// ApiResource descriptors for every kind the sweep targets (core, apps,
/// and the Gateway/Cilium CRDs), mirroring the constructors in
/// `enclava-engine`'s apply modules. Also covers "Namespace" for the
/// creation-ledger compensation path (cluster-scoped; callers use
/// `Api::all_with` for it).
pub(crate) fn sweep_api_resource(kind: &str) -> kube::api::ApiResource {
    match kind {
        "Secret" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "Secret".to_string(),
            plural: "secrets".to_string(),
        },
        "StatefulSet" => kube::api::ApiResource {
            group: "apps".to_string(),
            version: "v1".to_string(),
            api_version: "apps/v1".to_string(),
            kind: "StatefulSet".to_string(),
            plural: "statefulsets".to_string(),
        },
        "ServiceAccount" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "ServiceAccount".to_string(),
            plural: "serviceaccounts".to_string(),
        },
        "ResourceQuota" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "ResourceQuota".to_string(),
            plural: "resourcequotas".to_string(),
        },
        "Service" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "Service".to_string(),
            plural: "services".to_string(),
        },
        "ConfigMap" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "ConfigMap".to_string(),
            plural: "configmaps".to_string(),
        },
        "CiliumNetworkPolicy" => crd_api_resource(
            "cilium.io",
            "v2",
            "CiliumNetworkPolicy",
            "ciliumnetworkpolicies",
        ),
        "EnvoyProxy" => crd_api_resource(
            "gateway.envoyproxy.io",
            "v1alpha1",
            "EnvoyProxy",
            "envoyproxies",
        ),
        "Gateway" => crd_api_resource("gateway.networking.k8s.io", "v1", "Gateway", "gateways"),
        "TLSRoute" => crd_api_resource(
            "gateway.networking.k8s.io",
            "v1alpha3",
            "TLSRoute",
            "tlsroutes",
        ),
        "Namespace" => kube::api::ApiResource {
            group: String::new(),
            version: "v1".to_string(),
            api_version: "v1".to_string(),
            kind: "Namespace".to_string(),
            plural: "namespaces".to_string(),
        },
        other => unreachable!("unexpected kind {other}"),
    }
}

/// Mirrors the app-delete namespace teardown envelope: bounded convergence
/// wait once the delete has been accepted. `delete_resource`'s internal
/// conflict retries are short-lived (409 backoff only), so this wait starts
/// after the delete is accepted and is not nested inside a second budget.
const NAMESPACE_CONVERGENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Bounded retry budget for UID-conflicted namespace deletes. Each retry
/// re-verifies the pinned UID against the live object, so the loop cannot
/// delete a replacement and cannot spin unbounded.
const NAMESPACE_DELETE_RETRIES: usize = 3;

/// Per-request budget for the preconditioned namespace DELETE itself, so a
/// stalled API server cannot stretch the teardown phase past its advertised
/// budget while the shared fences are held.
const NAMESPACE_DELETE_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Outcome of the bounded namespace teardown.
#[derive(Debug, PartialEq, Eq)]
enum NamespaceTeardown {
    /// The namespace is confirmed gone (404 observed, or absent throughout).
    ConfirmedAbsent,
    /// An adopted namespace whose object sweep did not fully complete:
    /// provider-state evidence stays intact so the storage guard and
    /// ownership gates keep working; fences still release (unlike a
    /// retained CAP-created namespace fence, the retained-fence
    /// reconciler would never observe a 404 here).
    AdoptedIncomplete,
    /// A pre-existing namespace this apply adopted (mutation annotation
    /// matches but no creation evidence): never deleted. Only the routes
    /// this apply published are compensated.
    Adopted,
    /// A delete was issued but 404 was not confirmed, or the step failed or
    /// lost its lease after deciding to delete. The caller must retain the
    /// pre-armed namespace fence for reconciliation instead of quarantining
    /// it, so a retry cannot claim the fence while the namespace may still be
    /// Terminating.
    DeleteIncomplete,
    /// Ownership WAS proven but no delete could be issued (client
    /// construction or request building failed before anything was sent,
    /// or the conflict budget burned with the namespace still live). The
    /// namespace is still live, so provider-state evidence must be
    /// retained — but no delete is in flight, so the fence must NOT be
    /// retained (that would wedge every later deployment on permanent
    /// Busy). The row is marked cleanup_sweep_incomplete so later failed
    /// generations stay cleanup-eligible and their sweeps converge.
    DeleteNotIssued,
    /// The SAME-UID namespace no longer classifies as this generation's
    /// (an external writer rewrote its ownership annotations between the
    /// owning GET and the preconditioned DELETE; every attempt 409'd
    /// against the pinned resourceVersion). NOT confirmed absence — the
    /// namespace and this generation's CAP-created children are live, so
    /// provider evidence must be retained and the row marked retryable;
    /// no delete is in flight, so fences release normally and a LATER
    /// failed generation's evidence-gated sweep converges the leftovers.
    OwnedRewritten,
}

/// How the caller should release the mutation fences after cleanup.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CleanupFenceOutcome {
    /// Fences may be released through the normal bounded reclaim quarantine.
    ReleaseNormally,
    /// The `kubernetes_namespace` fence must stay armed until reconciliation;
    /// the other fences may be released.
    RetainNamespaceFence,
}

/// Persist the retained-namespace marker durably BEFORE an ambiguous
/// namespace DELETE is issued (Codex P1). The marker is the ONLY durable
/// distinction between an intentional infinite retain and a crashed
/// worker's pre-armed fence (which
/// `reconcile_orphaned_deployment_apply_leases` repairs into the bounded
/// 360 s reclaim window); writing it only after the awaited teardown
/// returns leaves the exact window Codex describes: a process exit after
/// Kubernetes accepts the DELETE — or during the convergence wait — would
/// leave the terminal job labeled `deployment_apply`, so after the
/// heartbeat expires the orphan repair converts the infinite fence to the
/// 360-second quarantine while the deletion (possibly stuck on finalizers)
/// is still unresolved. The write is retried before accepting the bounded
/// fallback: losing it to a transient database error would silently convert
/// the pre-armed infinite namespace fence into finite quarantine.
///
/// Returns true when the marker is durable (full write or the fail-closed
/// relabel fallback). On false the caller must NOT issue the delete.
async fn persist_retained_namespace_marker(
    mutation: &mut AppMutationLease,
    app_id: Uuid,
    failed_deployment_id: Uuid,
) -> bool {
    let mut retain_attempt = 0usize;
    loop {
        match mutation
            .retain_resource_scope_under_marker(
                "kubernetes_namespace",
                crate::mutation_leases::RETAINED_DEPLOYMENT_NAMESPACE_OPERATION,
            )
            .await
        {
            Ok(()) => return true,
            Err(crate::mutation_leases::MutationLeaseError::Lost) => {
                // The lease itself is gone — no retry can help.
                tracing::error!(
                    app_id = %app_id,
                    deployment_id = %failed_deployment_id,
                    "namespace-fence lease lost while persisting the retained marker"
                );
                return false;
            }
            Err(retain_error) if retain_attempt < 2 => {
                retain_attempt += 1;
                tracing::warn!(
                    app_id = %app_id,
                    deployment_id = %failed_deployment_id,
                    error = %retain_error,
                    retain_attempt,
                    "transient failure persisting the retained namespace-fence marker; retrying"
                );
                tokio::time::sleep(std::time::Duration::from_millis(
                    250 * retain_attempt as u64,
                ))
                .await;
            }
            Err(retain_error) => {
                // Codex P1 (relabel on failure): the durable label is what
                // keeps `reconcile_orphaned_deployment_apply_leases` from
                // re-bounding the pre-armed infinite fence into the 360 s
                // reclaim window. Retry a lane-lock-free relabel before
                // giving up: it persists the same fail-closed marker state
                // the full write would have.
                let mut relabeled = false;
                for relabel_attempt in 0..2 {
                    match mutation
                        .relabel_namespace_fence_fail_closed(
                            "kubernetes_namespace",
                            crate::mutation_leases::RETAINED_DEPLOYMENT_NAMESPACE_OPERATION,
                        )
                        .await
                    {
                        Ok(()) => {
                            relabeled = true;
                            break;
                        }
                        Err(relabel_error) => {
                            tracing::warn!(
                                app_id = %app_id,
                                deployment_id = %failed_deployment_id,
                                error = %relabel_error,
                                relabel_attempt,
                                "fail-closed namespace fence relabel failed; retrying"
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                        }
                    }
                }
                if !relabeled {
                    tracing::error!(
                        app_id = %app_id,
                        deployment_id = %failed_deployment_id,
                        error = %retain_error,
                        "failed to persist the retained namespace fence marker AND its fail-closed relabel"
                    );
                }
                return relabeled;
            }
        }
    }
}

/// Best-effort compensating cleanup for a deployment whose apply failed
/// terminally. `app` is the immutable payload snapshot of the failed
/// generation; `mutation` still owns that generation's provider fences.
pub(crate) async fn cleanup_after_terminal_apply_failure(
    state: &AppState,
    app: &App,
    failed_deployment_id: Uuid,
    mutation: &mut AppMutationLease,
    // The terminal apply failure was `creation_evidence_lost` (Codex P2:
    // a webhook stripped creation evidence from an accepted update and
    // its compensating restores) — forwarded to the adopted-namespace
    // sweep so unmarked live targets count as unresolved there.
    evidence_loss_unresolved: bool,
) -> CleanupFenceOutcome {
    // Ledger-persistence compensation may have sent a namespace DELETE
    // already. Never downgrade its durable retained marker merely because
    // the missing ledger row now makes this namespace look adopted. This
    // check precedes ALL ordinary-release exits; the retained reconciler
    // observes absence/termination with bounded requests after we drop.
    let namespace_fence_retained = match mutation.has_retained_namespace_fence().await {
        Ok(retained) => retained,
        Err(error) => {
            tracing::warn!(app_id = %app.id, error = %error,
                "cannot inspect retained namespace marker; keeping the fence for reconciliation");
            true
        }
    };
    // Durably record the evidence loss BEFORE any later step: even if this
    // process dies mid-cleanup, a later sweep of any failed generation of
    // this app must still see the marker and count unmarked live targets as
    // unresolved instead of clearing cleanup evidence over them.
    if evidence_loss_unresolved && !persist_creation_evidence_loss(&state.db, app.id).await {
        // The durable marker is the only signal a LATER generation's sweep
        // will have; without it this failure's knowledge dies with this
        // call. Failing to persist is a database outage: skip the sweep
        // entirely (nothing is cleared) and mark the row incomplete so a
        // later cleanup retries from the top.
        tracing::error!(
            app_id = %app.id,
            deployment_id = %failed_deployment_id,
            "creation-evidence-loss marker could not be persisted; skipping the compensating sweep for a later retry"
        );
        if let Err(mark_error) = sqlx::query(
            "UPDATE deployments
             SET cleanup_sweep_incomplete = true
             WHERE id = $1 AND app_id = $2 AND status = 'failed'",
        )
        .bind(failed_deployment_id)
        .bind(app.id)
        .execute(&state.db)
        .await
        {
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %mark_error,
                "failed-apply cleanup could not mark the row's sweep incomplete"
            );
        }
        return if namespace_fence_retained {
            CleanupFenceOutcome::RetainNamespaceFence
        } else {
            CleanupFenceOutcome::ReleaseNormally
        };
    }
    if namespace_fence_retained {
        return CleanupFenceOutcome::RetainNamespaceFence;
    }
    // Row-level gate: no other generation of this app may carry ANY
    // provider-state evidence, and the app must not be deleting. Whether THIS
    // generation published anything is proven separately against the live
    // namespace annotation, because the deployment row's manifest_hash is
    // written before any provider call.
    match no_other_generation_owns_provider_state(&state.db, app.id, failed_deployment_id).await {
        Ok(false) => {
            tracing::info!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                "skipping failed-apply compensating cleanup: another generation owns or previously owned the provider state"
            );
            return CleanupFenceOutcome::ReleaseNormally;
        }
        Ok(true) => {}
        Err(error) => {
            // Uncertain durable state: do not guess. Skip cleanup; the
            // periodic reconcilers retain the pre-existing convergence.
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "failed-apply cleanup precondition check failed; leaving provider cleanup to reconciliation"
            );
            return CleanupFenceOutcome::ReleaseNormally;
        }
    }

    let namespace_generation = match mutation
        .resource_generation(&ResourceFence::new("kubernetes_namespace", &app.namespace))
    {
        Some(raw) => match enclava_engine::apply::generation::MutationGeneration::new(raw) {
            Ok(generation) => generation,
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply cleanup cannot validate kubernetes_namespace generation; skipping provider cleanup"
                );
                return CleanupFenceOutcome::ReleaseNormally;
            }
        },
        None => {
            tracing::info!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply cleanup holds no kubernetes_namespace generation; skipping provider cleanup"
            );
            return CleanupFenceOutcome::ReleaseNormally;
        }
    };

    // Namespace teardown first: the live annotation check is the proof that
    // this generation published provider state at all. Route removal is
    // NOT gated on namespace ownership (see the AbsentBeforeDelete arm
    // below): an initial 404 cannot prove the generation never published
    // routes, so the routes are compensated in every outcome where no
    // other generation owns provider state.
    //
    // cap#272: namespace-deletion authority additionally requires the
    // creation ledger. Loaded fail-closed BEFORE the guarded step: a
    // database failure must not downgrade the check to unenforced — the
    // namespace is then treated exactly like an unprobeable one (no
    // delete issued, routes compensated, row retryable).
    //
    // The classification GET and the teardown run as separate guarded
    // provider steps: a lease lost during the classification (or the
    // adopted-namespace sweep) released nothing harmful — no namespace
    // delete can have been issued — so the fence must NOT be retained (an
    // adopted namespace never 404s, and the retained-fence reconciler only
    // releases on an observed 404; retaining would wedge every later
    // deployment of this app on permanent Busy). Only a lease lost while a
    // CAP-created namespace delete may be in flight retains the fence.
    let namespace_creation_ledger = load_creation_ledger(&state.db, app.id).await;
    let ownership = match &namespace_creation_ledger {
        Ok(ledger) => {
            match mutation
                .guard_provider(classify_failed_generation_namespace(
                    app,
                    namespace_generation,
                    ledger.as_ref(),
                ))
                .await
            {
                Ok(ownership) => ownership,
                Err(error) => {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        error = %error,
                        "failed-apply cleanup lost its mutation lease while classifying the namespace; releasing fences"
                    );
                    return CleanupFenceOutcome::ReleaseNormally;
                }
            }
        }
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply cleanup cannot load the creation ledger; treating the namespace as unprobeable (no delete, retryable)"
            );
            InitialNamespaceOwnership::Uninspectable
        }
    };
    if matches!(ownership, InitialNamespaceOwnership::AbsentBeforeDelete) {
        tracing::info!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed-apply cleanup found no live namespace before any delete; clearing this generation's routes and evidence"
        );
        // An initial 404 does not prove this generation never published:
        // the apply may have finished ensure_haproxy_routes, failed
        // afterward, and had its namespace deleted externally before this
        // probe. The row-level gate above already proved no OTHER
        // generation owns provider state, so removing this app's routes
        // here is exactly as safe as in the confirmed-absence path below.
        compensate_failed_generation_routes(state, app, mutation).await;
        // A confirmed 404 proves this generation published nothing: every
        // object the apply creates is namespaced and died with the
        // namespace. Clearing the row's provider-state evidence unblocks
        // LATER failed generations whose own cleanup the stale
        // manifest_hash (written before any provider call) would
        // otherwise block forever. An UNINSPECTABLE namespace keeps the
        // evidence (fail closed).
        //
        // Namespace absence equally proves the leftovers of the app's
        // OTHER incomplete-sweep rows are gone (all namespaced, shared
        // names): clear those siblings' evidence and markers exactly like
        // the retained-fence and completed-sweep paths, or the
        // storage-size guard stays armed on rows whose objects died with
        // the namespace.
        if let Err(error) = sqlx::query(
            "UPDATE deployments
             SET manifest_hash = NULL, observing_since = NULL, cleanup_sweep_incomplete = false
             WHERE app_id = $2 AND status = 'failed'
               AND (id = $1 OR cleanup_sweep_incomplete)",
        )
        .bind(failed_deployment_id)
        .bind(app.id)
        .execute(&state.db)
        .await
        {
            // Best-effort bookkeeping: failing to clear only keeps the
            // previous (more conservative) behavior.
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "failed-apply cleanup could not clear pre-publication row's provider-state evidence"
            );
        }
        return CleanupFenceOutcome::ReleaseNormally;
    }
    if matches!(ownership, InitialNamespaceOwnership::Foreign) {
        tracing::info!(
            app_id = %app.id,
            namespace = %app.namespace,
            expected_generation = namespace_generation.get(),
            "failed-apply cleanup skips namespace: it does not carry this generation's mutation annotation; marking row for a later sweep to converge older leftovers"
        );
        // Codex P2: the row-level gate above already proved no OTHER
        // generation owns provider state, so the app-specific routes this
        // apply may have published are exactly as safe to compensate as in
        // the absent path — an external writer rewriting the namespace
        // annotation cannot make this generation's stale routes safe to
        // keep. Leaving them would forward traffic to a terminally failed
        // deployment until periodic edge reconciliation runs. The foreign
        // namespace itself stays untouched.
        compensate_failed_generation_routes(state, app, mutation).await;
        // The live namespace may retain an older generation's leftovers
        // (e.g. a prior incomplete sweep that failed before reaching the
        // namespace). This row's evidence would otherwise permanently
        // gate every later failed generation of the app
        // (no_other_generation_owns_provider_state). Mark THIS row
        // incomplete instead: later failed generations stay
        // cleanup-eligible (gate exemption) and their sweeps converge
        // the shared-name leftovers. Evidence is retained.
        if let Err(error) = sqlx::query(
            "UPDATE deployments
             SET cleanup_sweep_incomplete = true
             WHERE id = $1 AND app_id = $2 AND status = 'failed'",
        )
        .bind(failed_deployment_id)
        .bind(app.id)
        .execute(&state.db)
        .await
        {
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "failed-apply cleanup could not mark the foreign-namespace row's sweep incomplete"
            );
        }
        return CleanupFenceOutcome::ReleaseNormally;
    }
    if matches!(ownership, InitialNamespaceOwnership::Uninspectable) {
        tracing::warn!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed-apply cleanup cannot inspect the namespace; skipping deletion"
        );
        // Same argument as the Foreign path: the row-level gate proved no
        // other generation owns provider state, so the app-specific routes
        // this apply may have published are safe to compensate now — an
        // unprobeable namespace cannot prove the routes were never
        // published. The namespace itself is untouched.
        compensate_failed_generation_routes(state, app, mutation).await;
        // An undecidable probe is a retryable outcome, not proof this row
        // owns no provider state: the row keeps its evidence (storage
        // guard) but is marked cleanup_sweep_incomplete so it cannot veto
        // every later failed generation's own cleanup — their sweeps
        // converge the same shared-name leftovers once the namespace
        // becomes inspectable again. No provider state was touched.
        if let Err(error) = sqlx::query(
            "UPDATE deployments
             SET cleanup_sweep_incomplete = true
             WHERE id = $1 AND app_id = $2 AND status = 'failed'",
        )
        .bind(failed_deployment_id)
        .bind(app.id)
        .execute(&state.db)
        .await
        {
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "failed-apply cleanup could not mark the uninspectable-namespace row's sweep incomplete"
            );
        }
        return CleanupFenceOutcome::ReleaseNormally;
    }
    let teardown = match ownership {
        InitialNamespaceOwnership::Owned {
            uid,
            resource_version,
        } => {
            // Codex P1: relabel the pre-armed namespace fence to the
            // retained-namespace marker BEFORE issuing the DELETE. The
            // DELETE is the ambiguous step — Kubernetes may accept it and
            // the deletion can then stick on finalizers while the process
            // exits or the convergence wait runs; the marker must already
            // be durable by then so the orphaned-lease repair can never
            // convert the infinite fence into the 360-second quarantine
            // and let the namespace name be reclaimed while the old
            // deletion is unresolved. Outcomes where retention proves
            // unnecessary (confirmed absence, no delete issued, rewritten
            // namespace) release through the ordinary bounded quarantine
            // below.
            if !persist_retained_namespace_marker(mutation, app.id, failed_deployment_id).await {
                // Fail closed: without the durable marker, issuing the
                // delete would recreate exactly the window this fixes.
                // Nothing was sent; the row is marked retryable and the
                // fences release like any no-delete outcome.
                tracing::error!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    deployment_id = %failed_deployment_id,
                    "failed-apply cleanup could not persist the retained-namespace marker; skipping the namespace delete"
                );
                NamespaceTeardown::DeleteNotIssued
            } else {
                match mutation
                    .guard_provider(delete_owned_namespace(
                        app,
                        namespace_generation,
                        uid,
                        resource_version,
                        // cap#272: the 409 re-check re-classifies with the
                        // same ledger gate that authorized the delete.
                        match &namespace_creation_ledger {
                            Ok(ledger) => ledger.as_ref(),
                            Err(_) => unreachable!(
                                "namespace delete requires an owned classification, which requires the ledger"
                            ),
                        },
                    ))
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        // Lease heartbeat lost with a namespace delete possibly in
                        // flight: fail closed on the namespace fence. The
                        // retained marker is already durable.
                        tracing::warn!(
                            app_id = %app.id,
                            namespace = %app.namespace,
                            error = %error,
                            "failed-apply namespace cleanup lost its mutation lease; retaining the namespace fence for reconciliation"
                        );
                        return CleanupFenceOutcome::RetainNamespaceFence;
                    }
                }
            }
        }
        InitialNamespaceOwnership::Adopted => {
            // Pre-existing namespace this apply adopted: not CAP's to
            // destroy. Delete only the objects this generation created
            // (creation-evidence gated). A lease lost mid-sweep releases
            // the fences — the retained-fence reconciler can never clear a
            // retained marker for a namespace that will never 404.
            tracing::info!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply cleanup sweeps published objects from adopted namespace (no creation evidence; namespace not deleted)"
            );
            // (#273) The PVC claim sweep retains every name-matching claim
            // (tenant-writable ownerReferences can never authorize
            // deletion in an adopted namespace), so the old fail-closed
            // pre-fetch of the "PVC ownership bound" here is gone: no
            // bound is derived from the row set anymore. The sweep's own
            // listing still fails closed inside
            // `sweep_published_objects_from_adopted_namespace`.
            match mutation
                .guard_provider(sweep_published_objects_from_adopted_namespace(
                    state,
                    app,
                    failed_deployment_id,
                    namespace_generation,
                    evidence_loss_unresolved,
                ))
                .await
            {
                Ok(failures) if failures > 0 => {
                    // Incomplete sweep. The namespace fence must NOT be
                    // retained: the retained-fence reconciler releases only
                    // on an observed namespace 404, which never happens for
                    // an adopted namespace — retaining would reintroduce the
                    // permanent-Busy bug this change fixes. The evidence
                    // stays (storage guard), but the row is MARKED so the
                    // ownership gate exempts it: a LATER failed generation
                    // of this app can still run its own sweep, which
                    // converges the same shared object names.
                    if let Err(error) = sqlx::query(
                        "UPDATE deployments
                         SET cleanup_sweep_incomplete = true
                         WHERE id = $1 AND app_id = $2 AND status = 'failed'",
                    )
                    .bind(failed_deployment_id)
                    .bind(app.id)
                    .execute(&state.db)
                    .await
                    {
                        tracing::warn!(
                            app_id = %app.id,
                            deployment_id = %failed_deployment_id,
                            error = %error,
                            "failed-apply cleanup could not mark the row's sweep incomplete"
                        );
                    }
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        failures,
                        error_code = "adopted_namespace_sweep_incomplete",
                        "adopted-namespace sweep left objects behind; the next apply, later failed generation, or app deletion converges them"
                    );
                    NamespaceTeardown::AdoptedIncomplete
                }
                Ok(_) => NamespaceTeardown::Adopted,
                Err(error) => {
                    if let Err(error) = sqlx::query(
                        "UPDATE deployments
                         SET cleanup_sweep_incomplete = true
                         WHERE id = $1 AND app_id = $2 AND status = 'failed'",
                    )
                    .bind(failed_deployment_id)
                    .bind(app.id)
                    .execute(&state.db)
                    .await
                    {
                        tracing::warn!(
                            app_id = %app.id,
                            deployment_id = %failed_deployment_id,
                            error = %error,
                            "failed-apply cleanup could not mark the row's sweep incomplete"
                        );
                    }
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        error = %error,
                        error_code = "adopted_namespace_sweep_interrupted",
                        "failed-apply cleanup lost its mutation lease during the adopted-namespace sweep; fences release and leftovers converge via the next apply or app deletion"
                    );
                    NamespaceTeardown::AdoptedIncomplete
                }
            }
        }
        // Handled above; the probe outcomes that skip teardown entirely.
        _ => unreachable!("absent/foreign/uninspectable returned early"),
    };

    // The namespace was this generation's, so its SNI routes are this
    // generation's publication. Remove them while still holding the
    // edge_config fence generation. Route removal is idempotent and covered
    // by the periodic edge reconciler, so a Lost/failed removal does not
    // retain any fence.
    if let Some(edge_config_generation) =
        mutation.resource_generation(&ResourceFence::edge_config())
    {
        let removed = mutation
            .guard_provider(remove_failed_generation_edge_routes(
                state,
                app,
                edge_config_generation,
            ))
            .await;
        if let Err(error) = removed {
            tracing::warn!(
                app_id = %app.id,
                error = %error,
                "failed-apply HAProxy route cleanup did not complete under the mutation lease; periodic edge reconciliation will converge"
            );
        }
    } else {
        tracing::info!(
            app_id = %app.id,
            "failed-apply cleanup holds no edge_config generation; skipping route removal"
        );
    }

    match teardown {
        NamespaceTeardown::ConfirmedAbsent | NamespaceTeardown::Adopted => {
            // The provider state this generation published is now gone (or
            // was never this generation's). Clear the row's provider-state
            // evidence so a LATER failed apply of the same app is not
            // forever blocked from its own compensating cleanup by this
            // historical row's stale `manifest_hash`/`observing_since`.
            // Earlier incomplete-sweep rows of the same app clear too:
            // every swept object name is shared across the app's
            // generations, so this completed sweep converged their
            // leftovers as well.
            if let Err(error) = sqlx::query(
                "UPDATE deployments
                 SET manifest_hash = NULL, observing_since = NULL, cleanup_sweep_incomplete = false
                 WHERE app_id = $2 AND status = 'failed'
                   AND (id = $1 OR cleanup_sweep_incomplete)",
            )
            .bind(failed_deployment_id)
            .bind(app.id)
            .execute(&state.db)
            .await
            {
                // Best-effort bookkeeping: failing to clear only keeps the
                // previous (more conservative) behavior for future
                // failures of this app.
                tracing::warn!(
                    app_id = %app.id,
                    deployment_id = %failed_deployment_id,
                    error = %error,
                    "failed-apply cleanup could not clear compensated row's provider-state evidence"
                );
            }
            CleanupFenceOutcome::ReleaseNormally
        }
        NamespaceTeardown::AdoptedIncomplete => CleanupFenceOutcome::ReleaseNormally,
        NamespaceTeardown::DeleteNotIssued | NamespaceTeardown::OwnedRewritten => {
            // Evidence kept (storage guard + ownership gates), fences
            // release: nothing was deleted, so there is no 404 to converge
            // — and even a crash-stranded marker now settles (the
            // retained-fence reconciler bounds a settled marker whose live
            // namespace no longer classifies as ours; Devin, round 7).
            // Marking the row cleanup_sweep_incomplete keeps later failed
            // generations cleanup-eligible so their sweeps converge the
            // leftovers.
            if let Err(error) = sqlx::query(
                "UPDATE deployments
                 SET cleanup_sweep_incomplete = true
                 WHERE id = $1 AND app_id = $2 AND status = 'failed'",
            )
            .bind(failed_deployment_id)
            .bind(app.id)
            .execute(&state.db)
            .await
            {
                tracing::warn!(
                    app_id = %app.id,
                    deployment_id = %failed_deployment_id,
                    error = %error,
                    "failed-apply cleanup could not mark the row's delete-not-issued outcome"
                );
            }
            CleanupFenceOutcome::ReleaseNormally
        }
        NamespaceTeardown::DeleteIncomplete => {
            // A delete may be in flight: the fence stays retained so a
            // retry cannot claim the name while the namespace may still be
            // Terminating. The row keeps its evidence (storage guard) but
            // is marked cleanup_sweep_incomplete so that once the fence
            // resolves — the retained-fence reconciler observes the 404,
            // or the retain falls back to the bounded quarantine — this
            // historical row cannot veto every later failed generation's
            // cleanup forever.
            if let Err(error) = sqlx::query(
                "UPDATE deployments
                 SET cleanup_sweep_incomplete = true
                 WHERE id = $1 AND app_id = $2 AND status = 'failed'",
            )
            .bind(failed_deployment_id)
            .bind(app.id)
            .execute(&state.db)
            .await
            {
                tracing::warn!(
                    app_id = %app.id,
                    deployment_id = %failed_deployment_id,
                    error = %error,
                    "failed-apply cleanup could not mark the row's delete-incomplete outcome"
                );
            }
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply namespace deletion is not confirmed complete; retaining the pre-armed namespace fence for reconciliation"
            );
            CleanupFenceOutcome::RetainNamespaceFence
        }
    }
}

/// No OTHER deployment of this app may carry ANY provider-state evidence:
/// `manifest_hash` or `observing_since` set (both survive
/// `supersede_incomplete_deployments` terminalizing a watching/applying row
/// to `failed`), or any non-failed status including `rolled_back`. The app
/// must not be `deleting`.
///
/// The failed row itself is exempt from the OTHER-row evidence clause — its
/// stale `manifest_hash` (written before any provider call) is exactly what
/// its own compensating cleanup exists to clear — but NEVER from the
/// observation veto (Codex P1): a row that carries `observing_since` backed
/// a WATCHED generation and may still back its live workload (the legacy
/// re-apply path stamps `observing_since` at its watching->applying
/// demotion precisely to record that history). Such a generation must not
/// compensate itself: cleanup would treat the namespace as adopted, remove
/// the routes of the still-live historical workload, and clear its provider
/// evidence. The unconditional self-veto cannot block a retryable sweep:
/// `cleanup_sweep_incomplete` is only ever armed for rows with NULL
/// `observing_since`, and a failed row can never reach watching again.
async fn no_other_generation_owns_provider_state(
    pool: &sqlx::PgPool,
    app_id: Uuid,
    failed_deployment_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        // A row whose compensating sweep already ran but could not finish
        // (cleanup_sweep_incomplete) keeps its evidence for the storage
        // guard, yet must not veto LATER failed generations' own cleanup:
        // every swept object NAME is shared across the app's generations,
        // so the later generation's sweep converges the same leftovers.
        // Its marker and evidence clear when any sweep completes.
        "SELECT NOT EXISTS (
             SELECT 1 FROM deployments
              WHERE id = $2
                AND observing_since IS NOT NULL
         ) AND NOT EXISTS (
             SELECT 1 FROM deployments
              WHERE app_id = $1
                AND id <> $2
                AND (
                    (
                        (manifest_hash IS NOT NULL OR observing_since IS NOT NULL)
                        AND NOT cleanup_sweep_incomplete
                    )
                    OR status::text IN ('pending', 'applying', 'watching', 'healthy', 'rolled_back')
                )
         ) AND NOT EXISTS (
             SELECT 1 FROM apps
              WHERE id = $1 AND status = 'deleting'::app_status_enum
         )",
    )
    .bind(app_id)
    .bind(failed_deployment_id)
    .fetch_one(pool)
    .await
}

/// Compensate this generation's SNI routes under the mutation lease, for
/// every probe outcome where the row-level gate already proved no other
/// generation owns provider state but the namespace itself does not prove
/// the routes were never published (initial 404, an externally rewritten
/// namespace annotation, an unprobeable namespace). Route removal is
/// idempotent and covered by the periodic edge reconciler, so a lost lease
/// or failed removal retains nothing.
async fn compensate_failed_generation_routes(
    state: &AppState,
    app: &App,
    mutation: &AppMutationLease,
) {
    if let Some(edge_config_generation) =
        mutation.resource_generation(&ResourceFence::edge_config())
        && let Err(error) = mutation
            .guard_provider(remove_failed_generation_edge_routes(
                state,
                app,
                edge_config_generation,
            ))
            .await
    {
        tracing::warn!(
            app_id = %app.id,
            error = %error,
            "failed-apply HAProxy route cleanup did not complete under the mutation lease; periodic edge reconciliation will converge"
        );
    }
}

/// Remove the SNI routes this failed generation's domains route through.
/// Backend names are generation-independent (derived from org/app slug), so
/// removal is only safe once the gates confirmed no other generation ever
/// published routes. The host list comes from the same
/// [`crate::deploy::app_route_hosts`] helper apply uses, so it cannot diverge
/// from what was published.
async fn remove_failed_generation_edge_routes(
    state: &AppState,
    app: &App,
    edge_config_generation: i64,
) {
    let org_slug: Result<String, _> =
        sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
            .bind(app.org_id)
            .fetch_one(&state.db)
            .await;
    let org_slug = match org_slug {
        Ok(org_slug) => org_slug,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                error = %error,
                "failed-apply cleanup cannot resolve organization slug; skipping route removal"
            );
            return;
        }
    };

    let mut routes_to_remove = Vec::new();
    for (tag, host) in crate::deploy::app_route_hosts(app) {
        match crate::edge::backend_name_for(&org_slug, &app.name, tag) {
            Ok(backend) => routes_to_remove.push((backend, host)),
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    error = %error,
                    "failed-apply cleanup cannot derive a backend name; skipping route removal"
                );
                return;
            }
        }
    }

    if let Err(error) = crate::edge::remove_haproxy_routes(
        &state.db,
        &crate::edge::EdgeRouteConfig::from_env(),
        Some(edge_config_generation),
        &routes_to_remove,
    )
    .await
    {
        tracing::warn!(
            app_id = %app.id,
            error = %error,
            "failed-apply HAProxy route removal failed; periodic edge reconciliation will converge"
        );
    }
}

/// The pre-delete namespace GET, classified. Only a live object carrying
/// this exact generation's mutation-generation annotation authorizes a
/// delete; every other outcome — including an initial 404 — does not.
/// Route removal is NOT skipped on these outcomes: an initial 404 cannot
/// prove the generation never published (`ensure_haproxy_routes` may have
/// completed before a later failure, and the namespace can be deleted
/// externally), so `cleanup_after_terminal_apply_failure` compensates this
/// generation's routes whenever the row-level provider-ownership gate
/// shows no other generation owns provider state — the same safety
/// condition as the confirmed-absence path.
pub(crate) enum InitialNamespaceOwnership {
    /// Live object carries this generation's annotation AND creation
    /// evidence (`enclava.dev/cap-namespace-created-by-generation`): CAP
    /// created it and this generation was the last writer — safe to delete.
    /// Carries the exact UID AND resourceVersion of the object that
    /// passed the ownership check: the DELETE is preconditioned on both,
    /// so it can neither hit a same-named replacement nor a same-UID
    /// object a newer deployment has since written.
    Owned {
        uid: String,
        resource_version: String,
    },
    /// Live object carries this generation's mutation annotation but no
    /// creation evidence: a pre-existing namespace this apply adopted.
    /// Never delete it — only the resources this apply published (routes)
    /// are compensated.
    Adopted,
    /// GET returned 404 before any delete was issued. The namespace is
    /// gone, but routes may still exist (the apply can publish routes and
    /// then fail; the namespace can be deleted externally) — the caller
    /// compensates this generation's routes on this outcome.
    AbsentBeforeDelete,
    /// Live object carries another generation's annotation (or none).
    Foreign,
    /// GET failed for a non-404 reason: ownership is undecidable, so no
    /// provider state may be touched.
    Uninspectable,
}

pub(crate) fn classify_initial_namespace_get(
    result: &Result<k8s_openapi::api::core::v1::Namespace, kube::Error>,
    generation: enclava_engine::apply::generation::MutationGeneration,
    creation_ledger: &enclava_engine::apply::creation_ledger::CreationLedgerBuffer,
) -> InitialNamespaceOwnership {
    match result {
        Ok(namespace) => {
            let annotations = namespace.metadata.annotations.as_ref();
            let live = annotations
                .and_then(|annotations| {
                    annotations
                        .get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
                })
                .and_then(|raw| raw.parse::<i64>().ok());
            if live == Some(generation.get()) {
                // Last-writer proof alone is not creation proof: only the
                // creation annotation (stamped by `apply_namespace`'s
                // create POST) distinguishes a CAP-created namespace from a
                // pre-existing one this apply adopted and stamped. The
                // value must parse as a positive generation — a planted
                // empty or non-numeric key proves nothing.
                // Value alone is not proof: SSA omission does not remove
                // an annotation a tenant's field manager owns, so a
                // pre-existing namespace carrying a tenant-authored
                // creation marker keeps it after CAP stamps the current
                // mutation generation. Require the marker to ALSO be
                // managed-fields-attributed to CAP's field manager —
                // evidence a tenant cannot forge without seizing the
                // field-manager identity itself.
                let value_proves_creation = annotations
                    .and_then(|annotations| {
                        annotations
                            .get(enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION)
                    })
                    .and_then(|raw| raw.parse::<i64>().ok())
                    .is_some_and(|value| value > 0);
                let manager_proves_authorship = value_proves_creation
                    && enclava_engine::apply::generation::annotation_owned_by_manager(
                        namespace,
                        enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION,
                        &enclava_engine::apply::types::ApplyConfig::default().field_manager,
                    );
                if !manager_proves_authorship {
                    return InitialNamespaceOwnership::Adopted;
                }
                // cap#272: the manager string is client-selected, so a
                // tenant can mint the same managed-fields entry on a
                // namespace they created. Deletion authority for the
                // namespace — the whole-namespace delete below —
                // additionally requires server-recorded lineage: the live
                // UID matches a creation row CAP wrote at its own POST, or
                // the namespace predates the ledger cutover (bounded
                // one-time migration trust).
                let lineage = enclava_engine::apply::creation_ledger::creation_lineage_provenance(
                    namespace.metadata.name.as_deref(),
                    namespace.metadata.uid.as_deref(),
                    namespace
                        .metadata
                        .creation_timestamp
                        .as_ref()
                        .map(|ts| ts.0.to_string())
                        .as_deref(),
                    Some(creation_ledger),
                );
                if lineage == enclava_engine::apply::creation_ledger::LineageProvenance::Unproven {
                    tracing::warn!(
                        namespace = ?namespace.metadata.name,
                        "namespace carries CAP-shaped creation evidence with no recorded lineage; treating it as adopted (cap#272)"
                    );
                    return InitialNamespaceOwnership::Adopted;
                }
                // The DELETE preconditions come from THIS object. A live
                // object missing uid/resourceVersion cannot be pinned and
                // is treated as undecidable (the API server always
                // populates both on real reads).
                match (
                    namespace.metadata.uid.clone(),
                    namespace.metadata.resource_version.clone(),
                ) {
                    (Some(uid), Some(resource_version)) => InitialNamespaceOwnership::Owned {
                        uid,
                        resource_version,
                    },
                    _ => InitialNamespaceOwnership::Uninspectable,
                }
            } else {
                InitialNamespaceOwnership::Foreign
            }
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            InitialNamespaceOwnership::AbsentBeforeDelete
        }
        Err(_) => InitialNamespaceOwnership::Uninspectable,
    }
}

/// Classify the live namespace against this failed generation: the
/// ownership probe that authorizes (or forbids) every later teardown step.
/// Runs as its own guarded provider step so a lease lost during
/// classification cannot retain the namespace fence (no delete could have
/// been issued yet).
async fn classify_failed_generation_namespace(
    app: &App,
    generation: enclava_engine::apply::generation::MutationGeneration,
    creation_ledger: &enclava_engine::apply::creation_ledger::CreationLedgerBuffer,
) -> InitialNamespaceOwnership {
    let client = match kube::Client::try_default().await {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply cleanup cannot reach Kubernetes; skipping namespace deletion"
            );
            // No delete was issued through this path.
            return InitialNamespaceOwnership::Uninspectable;
        }
    };
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);
    // Bound the probe: a stalled API server must not hold the failed
    // mutation's shared fences for the client's ~295 s read timeout on
    // this pre-teardown GET (it is outside both the sweep deadline and
    // the namespace convergence deadline). A timed-out probe is simply
    // undecidable — same handling as any other GET error.
    let probed = tokio::time::timeout(SWEEP_READ_TIMEOUT, api.get(&app.namespace))
        .await
        .map_err(|_| kube::Error::Service("namespace ownership probe timed out".into()))
        .and_then(|inner| inner);
    classify_initial_namespace_get(&probed, generation, creation_ledger)
}

/// Delete the namespace that ALREADY passed the ownership classification,
/// carrying BOTH the UID and the resourceVersion of that owning GET into
/// the DELETE preconditions. The UID blocks a same-named replacement; the
/// resourceVersion blocks a STALE delete against the same object after a
/// newer deployment has written it (generation advance, controller status
/// bump, any write): the delayed delete 409s instead of destroying the
/// newer deployment's namespace.
///
/// On 409 the live object is re-read and FULLY re-classified (exact
/// mutation-generation annotation + creation evidence + same UID): the
/// retry proceeds only when every check still holds against the fresh
/// object, using its new resourceVersion. A replaced or foreign object
/// completes as ConfirmedAbsent (nothing of ours remains); a same-UID
/// object that no longer classifies as ours also completes — the newer
/// deployment now owns it.
///
/// Failures BEFORE the delete could have been accepted (client creation,
/// transport rejection) return `ReleaseNormally` via [`NamespaceTeardown::ConfirmedAbsent`]
/// semantics handled by the caller only when absence is proven; here they
/// map to a distinct pre-acceptance outcome so the caller need not retain
/// the fence for a delete that was never issued. Failures after issuance
/// (or ambiguous ones) are `DeleteIncomplete` and retain the fence.
async fn delete_owned_namespace(
    app: &App,
    generation: enclava_engine::apply::generation::MutationGeneration,
    owned_uid: String,
    owned_resource_version: String,
    creation_ledger: &enclava_engine::apply::creation_ledger::CreationLedgerBuffer,
) -> NamespaceTeardown {
    let client = match kube::Client::try_default().await {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply cleanup cannot reach Kubernetes before issuing the namespace delete; no delete was sent"
            );
            // Pre-acceptance: no DELETE reached the API server, so there
            // is nothing in flight to converge — but the namespace IS
            // still live, so this is not confirmed absence either.
            return NamespaceTeardown::DeleteNotIssued;
        }
    };
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);

    let pinned_uid = owned_uid;
    let mut pinned_resource_version = owned_resource_version;
    for _attempt in 0..NAMESPACE_DELETE_RETRIES {
        // Bound the mutation itself: a stalled API server must not hold
        // the failed mutation's shared fences for the client's ~295 s
        // request timeout before the convergence wait even starts.
        let delete_result = match tokio::time::timeout(
            NAMESPACE_DELETE_REQUEST_TIMEOUT,
            api.delete(
                &app.namespace,
                &kube::api::DeleteParams {
                    preconditions: Some(kube::api::Preconditions {
                        uid: Some(pinned_uid.clone()),
                        resource_version: Some(pinned_resource_version.clone()),
                    }),
                    ..kube::api::DeleteParams::default()
                },
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_elapsed) => {
                // The DELETE exceeded its request budget: whether it was
                // accepted is undecidable. Releasing the fence would let a
                // later deployment claim the name while Kubernetes may
                // still be processing the original DELETE (or the object
                // sits Terminating under finalizers); the retained-fence
                // reconciler now converges BOTH cases — it observes the
                // eventual 404 for a converging delete, and retries the
                // UID+resourceVersion-pinned delete after full
                // re-classification when the namespace is live and not
                // deleting. Retain on every ambiguous outcome.
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    "failed-apply namespace delete exceeded its request budget; retaining the namespace fence for reconciliation"
                );
                // The re-probe itself is not decisive: absence may mean the
                // delete is converging (the reconciler observes the 404),
                // and a live object may be Terminating with the delete in
                // flight. The reconciler converges both — it observes the
                // eventual 404, or retries the UID+resourceVersion-pinned
                // delete after full re-classification when live and not
                // deleting. Retain on every outcome.
                let _ = tokio::time::timeout(
                    NAMESPACE_DELETE_REQUEST_TIMEOUT,
                    api.get_opt(&app.namespace),
                )
                .await;
                return NamespaceTeardown::DeleteIncomplete;
            }
        };
        match delete_result {
            Ok(_) => {
                // Accepted: converge on observed absence.
                return wait_for_namespace_absence(app, &api).await;
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {
                // Vanished between the owning GET and the delete: complete.
                return NamespaceTeardown::ConfirmedAbsent;
            }
            Err(kube::Error::Api(error)) if error.code == 409 => {
                // The pinned write raced. Re-read and FULLY re-classify:
                // only an object that still carries this generation's
                // exact annotation, creation evidence, AND the same UID
                // may be deleted (with its fresh resourceVersion).
                // Bound the conflict re-read: it sits outside both the
                // delete request budget and the convergence deadline, so
                // a stalled GET here could otherwise hold the shared
                // fences for the client's ~295 s default.
                let live = match tokio::time::timeout(
                    NAMESPACE_DELETE_REQUEST_TIMEOUT,
                    api.get(&app.namespace),
                )
                .await
                {
                    Ok(result) => match result {
                        Ok(live) => live,
                        Err(kube::Error::Api(error)) if error.code == 404 => {
                            // Vanished during the conflict handling:
                            // nothing of ours remains.
                            return NamespaceTeardown::ConfirmedAbsent;
                        }
                        Err(error) => {
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                error = %error,
                                "failed-apply namespace delete conflict re-read failed; retaining the namespace fence for reconciliation"
                            );
                            return NamespaceTeardown::DeleteIncomplete;
                        }
                    },
                    Err(_) => {
                        tracing::warn!(
                            app_id = %app.id,
                            namespace = %app.namespace,
                            "failed-apply namespace delete conflict re-read timed out; retaining the namespace fence for reconciliation"
                        );
                        return NamespaceTeardown::DeleteIncomplete;
                    }
                };
                // Codex P2 (round 4): distinguish a same-UID replacement
                // from the SAME namespace losing classified ownership. A
                // different UID means the object was deleted and recreated
                // under the same name — nothing of this generation's
                // remains, and its CAP-created children died with the old
                // object's namespace deletion by whoever replaced it. The
                // SAME UID that no longer classifies as Owned (an external
                // writer rewrote the mutation/creation annotations) is a
                // still-live namespace this generation DID own: reporting
                // ConfirmedAbsent would clear provider evidence and skip
                // the object sweep while the namespace and this
                // generation's CAP-created children are live. Report an
                // incomplete outcome instead: evidence retained, row
                // marked retryable, fences release (the retained-fence
                // reconciler would never observe a 404 for a namespace we
                // are not authorized to delete).
                let same_uid = live.metadata.uid.as_deref() == Some(pinned_uid.as_str());
                let still_ours = same_uid
                    && matches!(
                        classify_initial_namespace_get(
                            &Ok(live.clone()),
                            generation,
                            creation_ledger
                        ),
                        InitialNamespaceOwnership::Owned { .. }
                    )
                    && live.metadata.resource_version.is_some();
                if !still_ours {
                    if same_uid {
                        tracing::warn!(
                            app_id = %app.id,
                            namespace = %app.namespace,
                            "failed-apply cleanup: the owned namespace was externally rewritten (same UID, ownership annotations changed); retaining evidence for a later sweep"
                        );
                        return NamespaceTeardown::OwnedRewritten;
                    }
                    tracing::info!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        "failed-apply cleanup: the namespace no longer classifies as this generation's (replaced or advanced); leaving it to its current owner"
                    );
                    return NamespaceTeardown::ConfirmedAbsent;
                }
                let Some(fresh_version) = live.metadata.resource_version.clone() else {
                    return NamespaceTeardown::DeleteIncomplete;
                };
                pinned_resource_version = fresh_version;
                continue;
            }
            Err(kube::Error::Api(error)) if (400..500).contains(&error.code) => {
                // A definitive 4xx rejection (403, 422, 400, ... — the 404
                // and 409 cases are handled above): Kubernetes answered
                // with a rejection BEFORE accepting the request, so no
                // delete is in flight. Retaining the fence would wait for a
                // 404 that cannot occur and wedge every later deployment on
                // permanent Busy — but the proven-owned namespace is still
                // live, so this is not confirmed absence either.
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace delete was definitively rejected before acceptance; nothing is in flight"
                );
                return NamespaceTeardown::DeleteNotIssued;
            }
            Err(kube::Error::Api(error)) if error.code >= 500 => {
                // Server-side rejection before acceptance is likely but not
                // provable: treat as issued (fail closed).
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace deletion was server-rejected; retaining the namespace fence for reconciliation"
                );
                return NamespaceTeardown::DeleteIncomplete;
            }
            Err(kube::Error::BuildRequest(_)) => {
                // Request construction failed BEFORE anything was sent: no
                // delete is in flight, but the proven-owned namespace is
                // still live — evidence stays, fence releases.
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    "failed-apply namespace delete could not build its request; nothing is in flight"
                );
                return NamespaceTeardown::DeleteNotIssued;
            }
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace deletion failed ambiguously; retaining the namespace fence for reconciliation"
                );
                // The delete request may have reached the API server
                // before the error surfaced: treat as incomplete.
                return NamespaceTeardown::DeleteIncomplete;
            }
        }
    }

    // The retry budget burned entirely on conflicts while the owned
    // namespace stayed live: no delete was accepted, so entering the
    // convergence wait would be waiting for a 404 that cannot happen.
    // Mark not-issued (evidence retained, later generations unblocked)
    // and release the fence — nothing is in flight.
    tracing::warn!(
        app_id = %app.id,
        namespace = %app.namespace,
        "failed-apply namespace delete exhausted its conflict retries; leaving the live namespace for the next reconciliation"
    );
    NamespaceTeardown::DeleteNotIssued
}

async fn wait_for_namespace_absence(
    app: &App,
    api: &kube::Api<k8s_openapi::api::core::v1::Namespace>,
) -> NamespaceTeardown {
    // The delete was accepted. Bound the convergence wait; if it elapses
    // without a 404 the caller must retain the fence. Each GET is itself
    // bounded by the remaining deadline: a stalled API server must not
    // hold this apply's shared fences past the advertised convergence
    // budget via the client's ~295s read timeout.
    let deadline = tokio::time::Instant::now() + NAMESPACE_CONVERGENCE_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, api.get(&app.namespace)).await {
            Ok(Err(kube::Error::Api(error))) if error.code == 404 => {
                return NamespaceTeardown::ConfirmedAbsent;
            }
            Ok(Ok(ns)) => {
                // A live read here is the NORMAL mid-deletion state after an
                // ACCEPTED delete: namespace finalizers (kubernetes, other
                // controllers) routinely hold the object Terminating for
                // seconds before the observed 404 — a deletionTimestamp is
                // expected progress, not proof of failure. Keep polling
                // within the bounded wait so the worker that still holds the
                // fences converges the teardown synchronously; only the
                // deadline expiring (or the wait failing) retains the fence,
                // handing convergence to the retained-fence reconciler. The
                // request-timeout path above is the one that must retain on
                // a live read — there, acceptance is undecidable.
                let _ = ns;
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        "failed-apply namespace deletion did not converge within the bounded wait; retaining the namespace fence for reconciliation"
                    );
                    return NamespaceTeardown::DeleteIncomplete;
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Ok(Err(error)) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace deletion wait failed; retaining the namespace fence for reconciliation"
                );
                return NamespaceTeardown::DeleteIncomplete;
            }
            Err(_) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    "failed-apply namespace convergence wait hit its deadline mid-GET; retaining the namespace fence for reconciliation"
                );
                return NamespaceTeardown::DeleteIncomplete;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;
    use uuid::Uuid;

    async fn cleanup_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:***@localhost:5432/test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect cleanup test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate cleanup test database");
        pool
    }

    #[tokio::test]
    async fn deleting_app_cascades_creation_ledger_rows() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let record = enclava_engine::apply::creation_ledger::CreationRecord {
            kind: "ConfigMap".to_string(),
            name: "ingress".to_string(),
            namespace: Some("ledger-cascade".to_string()),
            uid: Uuid::new_v4().to_string(),
            mutation_generation: 1,
        };
        persist_creation_records(&pool, app_id, Uuid::new_v4(), &[record])
            .await
            .expect("persist app creation lineage");
        let before: i64 =
            sqlx::query_scalar("SELECT count(*) FROM resource_creation_ledger WHERE app_id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(before, 1);
        delete_cleanup_fixture(&pool, app_id).await;
        let after: i64 =
            sqlx::query_scalar("SELECT count(*) FROM resource_creation_ledger WHERE app_id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(after, 0, "app teardown must not orphan ledger rows");
    }

    async fn insert_cleanup_app_fixture(pool: &PgPool) -> Uuid {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = app_id.simple().to_string();
        let mut tx = pool.begin().await.expect("begin cleanup fixture");
        sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
            .bind(org_id)
            .bind(format!("cleanup-{org_id}"))
            .bind(&suffix[..8])
            .execute(&mut *tx)
            .await
            .expect("insert cleanup organization");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                 status, egress_allowlist, egress_mode, created_at, updated_at
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, 'auto',
                 $10, $11, 'creating', '[]'::jsonb, 'restricted',
                 clock_timestamp(), clock_timestamp()
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("cleanup-{}", &suffix[..12]))
        .bind(format!("cap-cleanup-{}", &suffix[..12]))
        .bind(format!("cleanup-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-cleanup-{}-sa", &suffix[..12]))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("cleanup-{}.example.test", &suffix[..12]))
        .bind(format!("cleanup-{}.tee.example.test", &suffix[..12]))
        .execute(&mut *tx)
        .await
        .expect("insert cleanup app");
        tx.commit().await.expect("commit cleanup fixture");
        app_id
    }

    async fn insert_cleanup_deployment(
        pool: &PgPool,
        app_id: Uuid,
        deployment_id: Uuid,
        status: &str,
        manifest_hash: Option<&str>,
        observing_since: bool,
    ) {
        let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load cleanup app org");
        let mut tx = pool
            .begin()
            .await
            .expect("begin cleanup deployment fixture");
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, status, spec_snapshot, manifest_hash,
                 observing_since
             ) VALUES (
                 $1, $2, $3, $4::deploy_status_enum, '{}'::jsonb, $5,
                 CASE WHEN $6 THEN clock_timestamp() ELSE NULL END
             )",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(status)
        .bind(manifest_hash)
        .bind(observing_since)
        .execute(&mut *tx)
        .await
        .expect("insert cleanup deployment");
        // Nonterminal deployments must own a durable apply job (database
        // constraint); terminal states do not require one.
        sqlx::query(
            "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required, state
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, false, 'pending'
             )",
        )
        .bind(deployment_id)
        .bind(app_id)
        .bind(org_id)
        .bind(vec![7_u8; 32])
        .execute(&mut *tx)
        .await
        .expect("insert cleanup apply job");
        tx.commit()
            .await
            .expect("commit cleanup deployment fixture");
    }

    async fn delete_cleanup_fixture(pool: &PgPool, app_id: Uuid) {
        let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load cleanup app org for teardown");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(pool)
            .await
            .expect("delete cleanup fixture");
    }

    #[tokio::test]
    async fn compensated_failed_row_no_longer_blocks_later_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;

        // A historical failed apply whose compensation completed: its
        // provider-state evidence is cleared, so a LATER failed apply of
        // the same app must not be blocked from its own cleanup.
        let compensated = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, compensated, "failed", Some("old-gen"), false)
            .await;
        sqlx::query(
            "UPDATE deployments
             SET manifest_hash = NULL, observing_since = NULL
             WHERE id = $1 AND app_id = $2 AND status = 'failed'",
        )
        .bind(compensated)
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("clear compensated row evidence");

        let later_failed = Uuid::new_v4();
        insert_cleanup_deployment(
            &pool,
            app_id,
            later_failed,
            "failed",
            Some("new-gen"),
            false,
        )
        .await;
        assert!(
            no_other_generation_owns_provider_state(&pool, app_id, later_failed)
                .await
                .expect("check compensated predecessor"),
            "a compensated failed row (evidence cleared) must not block a later failed apply's cleanup"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn cleanup_incomplete_row_no_longer_blocks_later_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;

        // An earlier failed apply whose sweep could not finish: evidence
        // retained (storage guard) but marked cleanup_sweep_incomplete, so
        // a LATER failed apply must still be allowed its own cleanup.
        let incomplete = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, incomplete, "failed", Some("old-gen"), false)
            .await;
        sqlx::query(
            "UPDATE deployments SET cleanup_sweep_incomplete = true
             WHERE id = $1 AND app_id = $2 AND status = 'failed'",
        )
        .bind(incomplete)
        .bind(app_id)
        .execute(&pool)
        .await
        .expect("mark sweep incomplete");

        let later_failed = Uuid::new_v4();
        insert_cleanup_deployment(
            &pool,
            app_id,
            later_failed,
            "failed",
            Some("new-gen"),
            false,
        )
        .await;
        assert!(
            no_other_generation_owns_provider_state(&pool, app_id, later_failed)
                .await
                .expect("check incomplete predecessor"),
            "an evidence-retaining but sweep-incomplete row must not block a later failed apply's cleanup"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn sole_generation_allows_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            allowed,
            "with no other generation, the row gate must allow provider cleanup"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    /// Codex P2 regression: a reclaimed deployment can re-create its
    /// StatefulSet under a NEW UID. Every proven UID accumulates exactly
    /// once (observability ledger — #273: no longer a deletion authority,
    /// but operators still read which UIDs this app's failed applies
    /// created). First-writer-wins still applies to the primary
    /// sts_uid/sts_created_at record.
    #[tokio::test]
    async fn recreated_statefulset_uids_all_accumulate() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;

        let first = "2026-01-01T00:00:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("parse fixed timestamp");
        let second = "2026-01-01T00:05:00Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .expect("parse fixed timestamp");
        persist_sts_provenance(&pool, Some(app_id), failed_id, "uid-a", first, None)
            .await
            .expect("persist first set provenance");
        persist_sts_provenance(
            &pool,
            Some(app_id),
            failed_id,
            "uid-b",
            second,
            Some(second),
        )
        .await
        .expect("persist recreated set provenance");
        // Idempotent: re-persisting a known UID must not duplicate it.
        persist_sts_provenance(
            &pool,
            Some(app_id),
            failed_id,
            "uid-b",
            second,
            Some(second),
        )
        .await
        .expect("re-persist recreated set provenance");

        let (first_uid, first_created, proven_uids): (
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Vec<String>,
        ) = sqlx::query_as(
            "SELECT sts_uid, sts_created_at, sts_proven_uids
               FROM deployments WHERE id = $1",
        )
        .bind(failed_id)
        .fetch_one(&pool)
        .await
        .expect("load recorded lineage");
        assert_eq!(
            first_uid.as_deref(),
            Some("uid-a"),
            "the primary record keeps first-writer-wins"
        );
        assert_eq!(
            first_created,
            Some(first),
            "the primary creation record keeps first-writer-wins"
        );
        assert_eq!(
            proven_uids,
            vec!["uid-a".to_string(), "uid-b".to_string()],
            "every proven UID accumulates exactly once"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    /// Codex P1 regression: a failed row that carries `observing_since`
    /// backed a WATCHED generation (the legacy re-apply path stamps it at
    /// its watching->applying demotion) and may still back its live
    /// workload. Even as the sole generation it must NOT pass the gate —
    /// `id <> $2` used to exempt the row itself, letting cleanup treat the
    /// namespace as adopted, remove the routes of the still-live historical
    /// workload, and clear its provider evidence.
    #[tokio::test]
    async fn observed_failed_generation_cannot_compensate_itself() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), true).await;

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a previously watched generation must never compensate itself"
        );

        // The same row with cleanup_sweep_incomplete marked still vetoes:
        // the observation veto is unconditional (armed sweeps only ever
        // target rows with NULL observing_since).
        sqlx::query("UPDATE deployments SET cleanup_sweep_incomplete = true WHERE id = $1")
            .bind(failed_id)
            .execute(&pool)
            .await
            .expect("mark sweep incomplete");
        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "marking the sweep incomplete must not unblock a watched generation"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn prior_healthy_generation_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;
        insert_cleanup_deployment(&pool, app_id, Uuid::new_v4(), "healthy", Some("old"), false)
            .await;

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a prior healthy generation still owns the namespace and shared routes"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn newer_active_generation_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;
        insert_cleanup_deployment(&pool, app_id, Uuid::new_v4(), "watching", None, false).await;

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a newer watching generation must not have its namespace deleted underneath it"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    /// The round-1 data-loss regression: a predecessor that reached
    /// `applying` (manifest_hash written, namespace possibly applied) or
    /// `watching` and was then terminalized to `failed` by
    /// `supersede_incomplete_deployments`. The newer generation under test
    /// HAS published (hash set), so only the other-row evidence clause can
    /// block cleanup.
    #[tokio::test]
    async fn superseded_predecessor_with_evidence_blocks_published_failure_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;

        // Case A: superseded `applying` predecessor — failed with hash.
        let failed_a = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_a, "failed", Some("new-gen"), false).await;
        let predecessor_a = Uuid::new_v4();
        insert_cleanup_deployment(
            &pool,
            app_id,
            predecessor_a,
            "failed",
            Some("old-gen"),
            false,
        )
        .await;
        assert!(
            !no_other_generation_owns_provider_state(&pool, app_id, failed_a)
                .await
                .expect("check case A precondition"),
            "a superseded applying predecessor (failed with manifest_hash) blocks cleanup of a published failure"
        );

        // Case B: superseded `watching` predecessor — failed, hash already
        // cleared, but observing_since evidence remains.
        let failed_b = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_b, "failed", Some("new-gen"), false).await;
        let predecessor_b = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, predecessor_b, "failed", None, true).await;
        assert!(
            !no_other_generation_owns_provider_state(&pool, app_id, failed_b)
                .await
                .expect("check case B precondition"),
            "a superseded watching predecessor (failed with observing_since) blocks cleanup of a published failure"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn rolled_back_generation_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;
        insert_cleanup_deployment(&pool, app_id, Uuid::new_v4(), "rolled_back", None, false).await;

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a rolled_back generation is treated as having owned provider state"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn deleting_app_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;
        sqlx::query("UPDATE apps SET status = 'deleting'::app_status_enum WHERE id = $1")
            .bind(app_id)
            .execute(&pool)
            .await
            .expect("mark cleanup app deleting");

        let allowed = no_other_generation_owns_provider_state(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "the app delete path owns teardown while the app is deleting"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[test]
    fn route_hosts_mirror_apply_publication_including_tee_fallback() {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let app = crate::models::App {
            id: app_id,
            org_id,
            name: "demo".to_string(),
            namespace: "cap-demo".to_string(),
            instance_id: "demo-inst".to_string(),
            tenant_id: "tenant1".to_string(),
            service_account: "cap-demo-sa".to_string(),
            bootstrap_owner_pubkey_hash: "11".repeat(32),
            tenant_instance_identity_hash: "22".repeat(32),
            unlock_mode: crate::models::UnlockMode::Auto,
            domain: "demo.example.test".to_string(),
            // Null tee_domain: apply falls back to the platform domain for the
            // TEE route, so cleanup must remove that exact host too.
            tee_domain: None,
            custom_domain: Some(String::new()),
            status: crate::models::AppStatus::Creating,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            source_provider: None,
            source_repository: None,
            egress_allowlist: serde_json::from_str("[]").unwrap(),
            egress_mode: "restricted".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        let hosts = crate::deploy::app_route_hosts(&app);
        assert_eq!(
            hosts,
            vec![
                (
                    crate::edge::BackendTag::App,
                    "demo.example.test".to_string()
                ),
                (
                    crate::edge::BackendTag::Tee,
                    "demo.example.test".to_string()
                ),
            ],
            "TEE host must mirror the apply fallback to the platform domain, and an empty custom domain must be skipped"
        );
    }

    fn annotated_namespace(generation: i64) -> k8s_openapi::api::core::v1::Namespace {
        namespace_with_annotations(generation, true)
    }

    /// A live namespace carrying only the mutation-generation annotation of
    /// this generation but NO creation evidence: a pre-existing namespace
    /// this apply adopted.
    fn adopted_namespace(generation: i64) -> k8s_openapi::api::core::v1::Namespace {
        namespace_with_annotations(generation, false)
    }

    fn namespace_with_annotations(
        generation: i64,
        created_by_cap: bool,
    ) -> k8s_openapi::api::core::v1::Namespace {
        let mut annotations = std::collections::BTreeMap::from([(
            enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
            generation.to_string(),
        )]);
        if created_by_cap {
            annotations.insert(
                enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                generation.to_string(),
            );
        }
        // CAP-created namespaces carry the creation annotation inside
        // an enclava-platform managed-fields entry (the create POST's
        // field-manager ownership); adopted ones have no such entry.
        let managed_fields = created_by_cap.then(|| {
            vec![k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry {
                manager: Some("enclava-platform".to_string()),
                fields_v1: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::FieldsV1(
                    serde_json::json!({
                        "f:metadata": {
                            "f:annotations": {
                                format!("f:{}", enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION): {}
                            }
                        }
                    }),
                )),
                ..Default::default()
            }]
        });
        k8s_openapi::api::core::v1::Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                annotations: Some(annotations),
                managed_fields,
                uid: Some("00000000-0000-0000-0000-000000000001".to_string()),
                creation_timestamp: Some(k8s_time("2026-10-01T00:00:00Z")),
                resource_version: Some("42".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn api_error(code: u16) -> kube::Error {
        kube::Error::Api(Box::new(
            kube::core::Status::failure("classified", "Probe").with_code(code),
        ))
    }

    #[test]
    fn initial_ownership_classifies_live_annotation_outcomes() {
        let generation = enclava_engine::apply::generation::MutationGeneration::new(7)
            .expect("valid generation");
        assert!(matches!(
            classify_ns_get(&Ok(annotated_namespace(7)), generation),
            InitialNamespaceOwnership::Owned { .. }
        ));
        assert!(matches!(
            classify_ns_get(&Ok(annotated_namespace(6)), generation),
            InitialNamespaceOwnership::Foreign
        ));
        // A missing annotation (or an unparseable one) is foreign, not owned:
        // `delete_resource` would otherwise treat it as generation 0.
        assert!(matches!(
            classify_ns_get(
                &Ok(k8s_openapi::api::core::v1::Namespace::default()),
                generation
            ),
            InitialNamespaceOwnership::Foreign
        ));
        // Codex P1: this generation's mutation annotation alone is only a
        // last-writer proof. Without creation evidence the namespace
        // pre-existed and was adopted — it must never be deleted.
        assert!(matches!(
            classify_ns_get(&Ok(adopted_namespace(7)), generation),
            InitialNamespaceOwnership::Adopted
        ));
        // Codex e4Z: a tenant-authored creation marker (value present,
        // but no CAP field-manager provenance) must not authenticate
        // ownership — SSA omission cannot remove a tenant-owned
        // annotation, so value-only checks would delete the foreign
        // namespace after CAP stamped the mutation generation.
        let mut forged = adopted_namespace(7);
        forged
            .metadata
            .annotations
            .as_mut()
            .expect("annotations")
            .insert(
                enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION.to_string(),
                "7".to_string(),
            );
        assert!(matches!(
            classify_ns_get(&Ok(forged), generation),
            InitialNamespaceOwnership::Adopted
        ));
        // Creation evidence written by an earlier generation (the namespace
        // was CAP-created, then re-applied by this generation which
        // preserved it) still reads as foreign for THIS generation's
        // mutation annotation mismatch — handled above — but the exact
        // match with preserved evidence is Owned.
        let mut recreated = annotated_namespace(5);
        recreated
            .metadata
            .annotations
            .as_mut()
            .expect("annotations")
            .insert(
                enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
                "7".to_string(),
            );
        assert!(matches!(
            classify_ns_get(&Ok(recreated), generation),
            InitialNamespaceOwnership::Owned { .. }
        ));
    }

    fn object_meta_with_annotations(pairs: &[(&str, i64)]) -> kube::api::DynamicObject {
        sweep_leftover_object(pairs, true)
    }

    /// A sweep target object with the given annotations; when
    /// `cap_provenance` is set, the creation annotation is owned by an
    /// enclava-platform managed-fields entry (as the create POST leaves
    /// it). Without it, the marker is tenant-authored.
    fn sweep_leftover_object(
        pairs: &[(&str, i64)],
        cap_provenance: bool,
    ) -> kube::api::DynamicObject {
        let annotations = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        let has_creation = pairs.iter().any(|(key, _)| {
            *key == enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION
        });
        let managed_fields = (cap_provenance && has_creation).then(|| {
            vec![k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry {
                manager: Some("enclava-platform".to_string()),
                fields_v1: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::FieldsV1(
                    serde_json::json!({
                        "f:metadata": {
                            "f:annotations": {
                                format!("f:{}", enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION): {}
                            }
                        }
                    }),
                )),
                ..Default::default()
            }]
        });
        kube::api::DynamicObject {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                annotations: Some(annotations),
                managed_fields,
                creation_timestamp: Some(k8s_time("2026-10-01T00:00:00Z")),
                ..Default::default()
            },
            types: None,
            data: serde_json::Value::Null,
        }
    }

    fn unparseable_mutation_object() -> kube::api::DynamicObject {
        // Build WITH CAP managed-fields creation proof (the pairs carry the
        // creation annotation), then garble the generation marker.
        let mut object = sweep_leftover_object(
            &[(
                enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION,
                7,
            )],
            true,
        );
        object.metadata.annotations = Some(std::collections::BTreeMap::from([
            (
                enclava_engine::apply::generation::RESOURCE_CREATED_BY_ANNOTATION.to_string(),
                "7".to_string(),
            ),
            (
                enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION.to_string(),
                "junk".to_string(),
            ),
        ]));
        object
    }

    #[test]
    fn sweep_requires_creation_evidence_not_last_writer_proof() {
        use enclava_engine::apply::generation as generation_annotations;
        // A CAP-created object of this failed generation: both annotations.
        assert!(is_cap_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 7),
            ]),
            7
        ));
        // An older CAP-created leftover (an earlier failed apply's object)
        // whose last writer is still an older generation: sweep it.
        assert!(is_cap_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 3),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 3),
            ]),
            7
        ));
        // Codex P1: SSA-patched pre-existing object — mutation annotation
        // from this apply, but NO creation evidence. Must never be deleted.
        assert!(!is_cap_leftover(
            &object_meta_with_annotations(&[(
                generation_annotations::MUTATION_GENERATION_ANNOTATION,
                7
            )]),
            7
        ));
        // A newer generation's publication: not this failure's partial state.
        assert!(!is_cap_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 9),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 9),
            ]),
            7
        ));
        // Foreign object: no annotations at all.
        assert!(!is_cap_leftover(&sweep_leftover_object(&[], false), 7));
        // Codex tGA: tenant-authored creation marker (value present, no
        // CAP managed-fields provenance) must not authorize deletion.
        assert!(!is_cap_leftover(
            &sweep_leftover_object(
                &[
                    (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                    (generation_annotations::MUTATION_GENERATION_ANNOTATION, 7),
                ],
                false
            ),
            7
        ));
        // Creation evidence alone with an unparseable mutation annotation:
        // undecidable last-writer — never a leftover (no deletion), and the
        // sweep treats it as UNRESOLVED (MarkerLost, fail closed), not
        // foreign-skip.
        assert!(!is_cap_leftover(&unparseable_mutation_object(), 7));
    }

    /// Codex P2: valid CAP creation evidence paired with an absent or
    /// unparseable mutation-generation marker is UNRESOLVED ownership —
    /// an admission webhook can drop or rewrite the marker on update and
    /// the update path's `verify_applied_generation` then fails without
    /// compensation. The sweep must neither delete the still-live object
    /// (it may be another generation's adopted object) nor silently skip
    /// it as foreign (the caller would declare the sweep complete and
    /// clear cleanup evidence over a partially updated resource).
    #[test]
    fn lost_generation_marker_is_unresolved_not_foreign() {
        use enclava_engine::apply::generation as generation_annotations;
        // Creation evidence, marker ABSENT: unresolved.
        assert!(matches!(
            classify_leftover(
                &sweep_leftover_object(
                    &[(generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7)],
                    true
                ),
                7
            ),
            GenerationLeftover::MarkerLost
        ));
        // Creation evidence, marker present but UNPARSEABLE: unresolved.
        assert!(matches!(
            classify_leftover(&unparseable_mutation_object(), 7),
            GenerationLeftover::MarkerLost
        ));
        // Creation evidence, marker garbage-but-parseable (0): unresolved.
        assert!(matches!(
            classify_leftover(
                &object_meta_with_annotations(&[
                    (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                    (generation_annotations::MUTATION_GENERATION_ANNOTATION, 0),
                ]),
                7
            ),
            GenerationLeftover::MarkerLost
        ));
        // The settled cases keep their attributions.
        assert!(matches!(
            classify_leftover(
                &object_meta_with_annotations(&[
                    (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                    (generation_annotations::MUTATION_GENERATION_ANNOTATION, 7),
                ]),
                7
            ),
            GenerationLeftover::Leftover
        ));
        assert!(matches!(
            classify_leftover(
                &object_meta_with_annotations(&[
                    (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 9),
                    (generation_annotations::MUTATION_GENERATION_ANNOTATION, 9),
                ]),
                7
            ),
            GenerationLeftover::Foreign
        ));
    }

    /// Owner deletion must not turn forged refs into GC deletion authority.
    #[tokio::test]
    async fn adopted_sweep_orphans_owner_and_retains_forged_dependents() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use std::sync::{Arc, Mutex};
        use tower::service_fn;

        let delete_options = Arc::new(Mutex::new(None));
        let observed = delete_options.clone();
        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let observed = observed.clone();
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let bytes = request.into_body().collect().await.unwrap().to_bytes();
                    let (status, body) = if method == "DELETE" {
                        assert!(
                            path.ends_with("/statefulsets/demo"),
                            "must not delete Pods/PVCs"
                        );
                        let options: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        *observed.lock().unwrap() = Some(options.clone());
                        // Model GC's key security consequence: cascading owner
                        // deletion would remove the forged claim before inspection.
                        (
                            200,
                            serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Success"}),
                        )
                    } else if path.ends_with("/persistentvolumeclaims") {
                        let options = observed
                            .lock()
                            .unwrap()
                            .clone()
                            .expect("owner deleted first");
                        let items = if options["propagationPolicy"] == "Orphan" {
                            vec![
                                serde_json::json!({"apiVersion":"v1", "kind":"PersistentVolumeClaim",
                            "metadata":{"name":"state-demo-999", "uid":"tenant-claim",
                                "ownerReferences":[{"apiVersion":"apps/v1", "kind":"StatefulSet",
                                    "name":"demo", "uid":"sts-uid", "controller":true}]}}),
                            ]
                        } else {
                            vec![]
                        };
                        (
                            200,
                            serde_json::json!({"apiVersion":"v1", "kind":"PersistentVolumeClaimList", "items":items}),
                        )
                    } else if path.ends_with("/pods") {
                        // Already-orphaned Pod: retry discovery cannot rely on refs.
                        (
                            200,
                            serde_json::json!({"apiVersion":"v1", "kind":"PodList", "items":[
                                {"metadata":{"name":"demo-0"}},
                                {"metadata":{"name":"other-0"}},
                                {"metadata":{"name":"demo-extra-0"}}
                            ]}),
                        )
                    } else {
                        assert!(path.ends_with("/statefulsets/demo"));
                        (
                            404,
                            serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "code":404}),
                        )
                    };
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let api: kube::Api<k8s_openapi::api::apps::v1::StatefulSet> =
            kube::Api::namespaced(client.clone(), "cap-demo");
        api.delete(
            "demo",
            &adopted_sweep_delete_params(kube::api::Preconditions {
                uid: Some("sts-uid".into()),
                resource_version: Some("42".into()),
            }),
        )
        .await
        .unwrap();
        let deadline = tokio::time::Instant::now() + SWEEP_DEADLINE;
        assert_eq!(
            wait_for_sweep_absence(&api, "demo", deadline).await,
            SweepAbsence::Absent
        );
        for _ in 0..2 {
            assert_eq!(
                sweep_statefulset_dependents(&client, "cap-demo", "demo", deadline).await,
                2,
                "owner 404 must not clear evidence over a forged PVC or an orphaned Pod, including retries"
            );
        }
        let options = delete_options.lock().unwrap().clone().unwrap();
        assert_eq!(options["propagationPolicy"], "Orphan");
        assert_eq!(options["preconditions"]["uid"], "sts-uid");
        assert_eq!(options["preconditions"]["resourceVersion"], "42");
    }

    #[tokio::test]
    async fn orphaned_pod_inspection_fails_closed() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;
        for pod_list_fails in [false, true] {
            let client = kube::Client::new(
                service_fn(move |request: Request<Body>| async move {
                    let is_pod = request.uri().path().ends_with("/pods");
                    let _ = request.into_body().collect().await;
                    let (status, body) = if is_pod && pod_list_fails {
                        (
                            500,
                            serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "message":"unavailable", "code":500}),
                        )
                    } else {
                        (
                            200,
                            serde_json::json!({"apiVersion":"v1", "kind":if is_pod {"PodList"} else {"PersistentVolumeClaimList"}, "items":[]}),
                        )
                    };
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(status)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    )
                }),
                "default",
            );
            assert_eq!(
                sweep_statefulset_dependents(
                    &client,
                    "cap-demo",
                    "demo",
                    tokio::time::Instant::now() + SWEEP_DEADLINE
                )
                .await,
                usize::from(pod_list_fails)
            );
        }
    }

    /// #273 regression: in an adopted namespace the tenant can read the
    /// live StatefulSet's UID (namespace-readable) and write
    /// `ownerReferences` on their own PVCs (tenant-writable), so a forged
    /// predictable-name claim carrying a StatefulSet-kind ownerRef pinning
    /// that UID — even one matching apiVersion/kind/name/controller/uid
    /// exactly, i.e. everything the interim hardening would have required
    /// — must NOT be deleted by the sweep. No PVC delete request may be
    /// issued at all: every name-matching claim is retained and counted,
    /// keeping the sweep incomplete (evidence and the storage-size guard
    /// survive; resolution paths per #251). The owner-delete propagation
    /// is covered separately by the orphan-propagation regression.
    #[tokio::test]
    async fn forged_owner_ref_claims_are_retained_and_sweep_stays_incomplete() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tower::service_fn;

        let namespace = "cap-demo".to_string();
        let statefulset = "demo".to_string();
        // The UID of the live, proven-window StatefulSet — readable by the
        // namespace tenant, so forgeable into their own claims' refs.
        let live_sts_uid = "11111111-2222-3333-4444-555555555555".to_string();
        let deletes = Arc::new(AtomicUsize::new(0));
        let deletes_for_closure = deletes.clone();
        let namespace_for_closure = namespace.clone();
        let live_sts_uid_for_closure = live_sts_uid.clone();
        let client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let deletes = deletes_for_closure.clone();
                let namespace = namespace_for_closure.clone();
                let live_sts_uid = live_sts_uid_for_closure.clone();
                async move {
                    let method = request.method().clone();
                    let path = request.uri().path().to_string();
                    let _ = request.into_body().collect().await;
                    if method == "DELETE" && path.contains("/persistentvolumeclaims/") {
                        deletes.fetch_add(1, Ordering::SeqCst);
                    }
                    // The claim set a tenant prepares: a forged
                    // out-of-replica-ordinal claim AND a controller-exact
                    // legitimate-looking one, both pinning the live
                    // (proven-window) StatefulSet UID. Under the old
                    // classifier both classified `Proven` and were deleted.
                    let body = serde_json::json!({
                        "apiVersion": "v1",
                        "kind": "PersistentVolumeClaimList",
                        "metadata": {},
                        "items": [
                            {
                                "apiVersion": "v1",
                                "kind": "PersistentVolumeClaim",
                                "metadata": {
                                    "name": "state-demo-999",
                                    "namespace": namespace,
                                    "uid": "forged-claim-uid",
                                    "resourceVersion": "10",
                                    "creationTimestamp": "2026-10-17T00:00:00Z",
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "StatefulSet",
                                        "name": "demo",
                                        "uid": live_sts_uid,
                                        "controller": true,
                                        "blockOwnerDeletion": true,
                                    }],
                                },
                            },
                            {
                                "apiVersion": "v1",
                                "kind": "PersistentVolumeClaim",
                                "metadata": {
                                    "name": "tls-state-demo-0",
                                    "namespace": namespace,
                                    "uid": "legit-looking-claim-uid",
                                    "resourceVersion": "11",
                                    "creationTimestamp": "2026-10-17T00:00:01Z",
                                    "ownerReferences": [{
                                        "apiVersion": "apps/v1",
                                        "kind": "StatefulSet",
                                        "name": "demo",
                                        "uid": live_sts_uid,
                                        "controller": true,
                                        "blockOwnerDeletion": true,
                                    }],
                                },
                            },
                            // Ownerless name-matching claim: the Retain/Retain
                            // common path (the controller stamps no
                            // ownerReferences). A later filter that only
                            // counted ownerRef-bearing claims would pass an
                            // ownerRef-only fixture and silently exempt this
                            // one — it must count too.
                            {
                                "apiVersion": "v1",
                                "kind": "PersistentVolumeClaim",
                                "metadata": {
                                    "name": "state-demo-0",
                                    "namespace": namespace,
                                    "uid": "ownerless-claim-uid",
                                    "resourceVersion": "12",
                                    "creationTimestamp": "2026-10-17T00:00:02Z",
                                },
                            },
                        ],
                    });
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(200)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );

        let failures = sweep_statefulset_pvcs(
            &client,
            &namespace,
            &statefulset,
            tokio::time::Instant::now() + SWEEP_DEADLINE,
        )
        .await;
        assert_eq!(
            failures, 3,
            "every name-matching claim (forged, legitimate-looking, or ownerless) must keep the sweep incomplete"
        );
        assert_eq!(
            deletes.load(Ordering::SeqCst),
            0,
            "no PVC delete request may be issued: in an adopted namespace tenant-writable ownerReferences are never deletion authority (#273)"
        );
    }

    #[tokio::test]
    async fn sweep_claim_count_fail_closed_arms() {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        let namespace = "cap-demo".to_string();
        let statefulset = "demo".to_string();

        // Arm 1: a PVC list error must count as one failure, never as a
        // complete sweep — returning 0 over an uninspected claim set is
        // how a later edit would clear manifest evidence silently.
        let error_client = kube::Client::new(
            service_fn(move |request: Request<Body>| async move {
                let _ = request.into_body().collect().await;
                Ok::<_, std::io::Error>(
                    Response::builder()
                        .status(500)
                        .body(Body::from(
                            br#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"boom","code":500}"#.to_vec(),
                        ))
                        .unwrap(),
                )
            }),
            "default",
        );
        let failures = sweep_statefulset_pvcs(
            &error_client,
            &namespace,
            &statefulset,
            tokio::time::Instant::now() + SWEEP_DEADLINE,
        )
        .await;
        assert_eq!(
            failures, 1,
            "a PVC list error must keep the sweep incomplete"
        );

        // Arm 2: only non-matching names (foreign set, non-canonical
        // ordinal, no name at all) is an empty match set: complete (0),
        // proving the filter does not count every PVC. (The
        // name-matching lock — including ownerless claims — is the forged
        // fixture above.)
        let body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaimList",
            "metadata": {},
            "items": [
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                 "metadata": {"name": "state-other-0"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                 "metadata": {"name": "state-demo-00"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                 "metadata": {"name": "unrelated"}},
                {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                 "metadata": {}},
            ],
        });
        let filter_client = kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let body = body.clone();
                async move {
                    let _ = request.into_body().collect().await;
                    Ok::<_, std::io::Error>(
                        Response::builder()
                            .status(200)
                            .body(Body::from(serde_json::to_vec(&body).unwrap()))
                            .unwrap(),
                    )
                }
            }),
            "default",
        );
        let failures = sweep_statefulset_pvcs(
            &filter_client,
            &namespace,
            &statefulset,
            tokio::time::Instant::now() + SWEEP_DEADLINE,
        )
        .await;
        assert_eq!(
            failures, 0,
            "claims that do not match the canonical CAP name shape must not count"
        );
    }

    /// Codex P1 (legacy unmarked rows): evidence rows published before the
    /// `apply_started_at` column existed (manifest_hash set, apply_started_at
    /// NULL — both written by the same atomic UPDATE) can only be pre-release
    /// rows; their objects can never carry creation evidence, so live
    /// unmarked targets under them must count as sweep failures, not skips.
    #[test]
    fn unmarked_target_is_unresolved_covers_both_arms() {
        // Plain case: no legacy rows, no evidence loss — unmarked is foreign.
        assert!(!unmarked_target_is_unresolved(false, false, false));
        // Legacy arm: a legacy evidence row is in scope.
        assert!(unmarked_target_is_unresolved(true, false, false));
        // ...unless the object provably predates every legacy row.
        assert!(!unmarked_target_is_unresolved(true, true, false));
        // Codex P2 arm: a creation_evidence_lost row is in scope. The
        // legacy temporal carve-out must NOT neutralize it — the
        // webhook-stripped object is typically old (created by an earlier
        // generation, updated by the failed one).
        assert!(unmarked_target_is_unresolved(false, false, true));
        assert!(unmarked_target_is_unresolved(true, true, true));
    }

    #[test]
    fn earliest_legacy_row_started_at_selects_earliest_legacy_row() {
        let t0 = chrono_time("2026-10-14T10:00:00Z");
        let t1 = chrono_time("2026-10-14T11:00:00Z");
        let t2 = chrono_time("2026-10-14T12:00:00Z");
        // Single legacy row: its row creation is the bound.
        assert_eq!(
            earliest_legacy_row_started_at([(Some("abc123"), None, t1)].into_iter()),
            Some(t1)
        );
        // Modern rows: no legacy bound.
        assert_eq!(
            earliest_legacy_row_started_at([(Some("abc123"), Some(t0), t1)].into_iter()),
            None
        );
        // No evidence at all: not a legacy evidence row.
        assert_eq!(
            earliest_legacy_row_started_at([(None, None, t1)].into_iter()),
            None
        );
        // Mixed set: the EARLIEST legacy row's created_at wins — an object
        // created strictly before it provably predates every legacy row.
        assert_eq!(
            earliest_legacy_row_started_at(
                [
                    (Some("new-gen"), Some(t0), t0),
                    (Some("old-gen"), None, t2),
                    (Some("oldest-gen"), None, t1),
                    (None, None, t0),
                ]
                .into_iter()
            ),
            Some(t1)
        );
        // The temporal carve-out predicate: only strictly-before counts as
        // provably pre-existing (ties at second precision stay unresolved).
        let bound = earliest_legacy_row_started_at([(Some("old-gen"), None, t1)].into_iter())
            .expect("legacy row present");
        assert!(chrono_time("2026-10-14T10:59:59Z") < bound);
        assert!(!(chrono_time("2026-10-14T11:00:00Z") < bound));
        assert!(!(chrono_time("2026-10-14T11:00:01Z") < bound));
    }

    fn chrono_time(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .expect("parse bound")
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn initial_ownership_classifies_pre_delete_absence_and_inspect_errors() {
        let generation = enclava_engine::apply::generation::MutationGeneration::new(7)
            .expect("valid generation");
        // An initial 404 must NOT read as an owning-then-vanished outcome:
        // it classifies as AbsentBeforeDelete, whose caller compensates this
        // generation's routes (a 404 cannot prove the apply never published
        // them — it can publish routes and then fail, with the namespace
        // deleted externally before this probe) but never issues a namespace
        // delete. (devin 🔍 follow-up: the old "NotOurs → skip route
        // removal" rollout note described superseded round-3 behavior.)
        assert!(matches!(
            classify_ns_get(&Err(api_error(404)), generation),
            InitialNamespaceOwnership::AbsentBeforeDelete
        ));
        // Any non-404 inspect failure is undecided ownership (Uninspectable):
        // no provider state may be touched at all.
        assert!(matches!(
            classify_ns_get(&Err(api_error(500)), generation),
            InitialNamespaceOwnership::Uninspectable
        ));
        assert!(matches!(
            classify_ns_get(
                &Err(kube::Error::Service("transport unavailable".into())),
                generation
            ),
            InitialNamespaceOwnership::Uninspectable
        ));
    }

    // ------------------------------------------------------------------
    // cap#272: creation-ledger provenance
    // ------------------------------------------------------------------

    fn k8s_time(rfc3339: &str) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
        k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
            rfc3339.parse().expect("parse fixture timestamp"),
        )
    }

    fn empty_ledger() -> enclava_engine::apply::creation_ledger::CreationLedgerBuffer {
        // Legacy fixtures explicitly opt into their historical trust boundary;
        // production's default remains strict and no process env is mutated.
        enclava_engine::apply::creation_ledger::CreationLedgerBuffer::with_legacy_cutover(
            "2026-10-17T00:00:00Z",
            "2026-10-17T00:00:00Z".parse().unwrap(),
        )
        .expect("fixture activation cutoff")
    }

    /// Legacy-signature forwarders: these tests exercise the grandfathered
    /// (pre-cutover) semantics with an empty ledger, so they keep calling
    /// the classifiers without spelling the ledger out at every site.
    fn classify_leftover<K: kube::Resource>(
        resource: &K,
        failed_generation: i64,
    ) -> GenerationLeftover {
        classify_generation_leftover(resource, failed_generation, &empty_ledger())
    }

    fn is_cap_leftover<K: kube::Resource>(resource: &K, failed_generation: i64) -> bool {
        is_cap_created_generation_leftover(resource, failed_generation, &empty_ledger())
    }

    fn classify_ns_get(
        result: &Result<k8s_openapi::api::core::v1::Namespace, kube::Error>,
        generation: enclava_engine::apply::generation::MutationGeneration,
    ) -> InitialNamespaceOwnership {
        classify_initial_namespace_get(result, generation, &empty_ledger())
    }

    /// The tenant-forged shape of cap#272: a pre-created, target-named
    /// object whose creation annotation is owned by a managed-fields entry
    /// submitted with `fieldManager=enclava-platform`, created AFTER the
    /// ledger cutover. Every legacy check (annotation value, manager
    /// ownership, generation marker) passes; only the missing ledger row
    /// distinguishes it from CAP's own creation.
    fn forged_post_cutover_object() -> kube::api::DynamicObject {
        use enclava_engine::apply::generation as generation_annotations;
        let mut forged = sweep_leftover_object(
            &[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 7),
            ],
            true,
        );
        forged.metadata.name = Some("cap-demo-pull".to_string());
        forged.metadata.uid = Some("uid-forged".to_string());
        forged.metadata.creation_timestamp = Some(k8s_time("2026-10-18T00:00:00Z"));
        forged
    }

    /// cap#272 regression: a tenant pre-creates a target-shaped object with
    /// the forged creation annotation + `fieldManager=enclava-platform`; a
    /// failed apply targeting the same name must NOT gain deletion
    /// authority over it. Post-cutover, deletion additionally requires a
    /// server-recorded (name, uid) creation row observed at CAP's own
    /// create POST; the forged shape stays UNRESOLVED (fail closed,
    /// retryable) instead of Leftover.
    #[test]
    fn forged_post_cutover_stamp_is_not_deletion_authority() {
        let forged = forged_post_cutover_object();
        assert!(matches!(
            classify_generation_leftover(&forged, 7, &empty_ledger()),
            GenerationLeftover::ProvenanceUnproven
        ));
        assert!(!is_cap_created_generation_leftover(
            &forged,
            7,
            &empty_ledger()
        ));
        // The identical object whose creation CAP's POST actually observed
        // (a durable ledger row matches its UID): a provable leftover,
        // deletable under the sweep's other gates.
        let recorded = enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new();
        recorded.preload([(
            "Secret".to_string(),
            "cap-demo-pull".to_string(),
            "uid-forged".to_string(),
        )]);
        assert!(matches!(
            classify_generation_leftover(&forged, 7, &recorded),
            GenerationLeftover::Leftover
        ));
        // Pre-cutover creation with no row: bounded one-time migration
        // trust keeps the legacy annotation+manager authority.
        let mut legacy = forged_post_cutover_object();
        legacy.metadata.creation_timestamp = Some(k8s_time("2026-10-13T00:00:00Z"));
        assert!(matches!(
            classify_generation_leftover(&legacy, 7, &empty_ledger()),
            GenerationLeftover::Leftover
        ));
    }

    #[test]
    fn legacy_cleanup_requires_explicit_activation_and_uses_full_instants() {
        use enclava_engine::apply::creation_ledger::CreationLedgerBuffer;
        let mut object = forged_post_cutover_object();
        object.metadata.creation_timestamp = Some(k8s_time("2026-10-17T11:59:59Z"));
        // No configured activation: even an otherwise legacy-shaped object
        // cannot become destructive authority solely because it is old.
        assert!(matches!(
            classify_generation_leftover(&object, 7, &CreationLedgerBuffer::new()),
            GenerationLeftover::ProvenanceUnproven
        ));
        let migration = CreationLedgerBuffer::with_legacy_cutover(
            "2026-10-17T12:00:00Z",
            "2026-10-17T12:00:00Z".parse().unwrap(),
        )
        .unwrap();
        // Old binaries may have created CAP objects after the former midnight
        // boundary. The explicit actual activation includes that rollout gap.
        assert!(matches!(
            classify_generation_leftover(&object, 7, &migration),
            GenerationLeftover::Leftover
        ));
        object.metadata.creation_timestamp = Some(k8s_time("2026-10-17T12:00:00.000000001Z"));
        assert!(matches!(
            classify_generation_leftover(&object, 7, &migration),
            GenerationLeftover::ProvenanceUnproven
        ));
    }

    /// cap#272, namespace arm: the same forged stamp on a namespace a
    /// tenant created post-cutover must classify ADOPTED (no namespace
    /// delete), and a recorded creation row must keep it Owned.
    #[test]
    fn forged_post_cutover_namespace_is_adopted_not_owned() {
        let generation = enclava_engine::apply::generation::MutationGeneration::new(7)
            .expect("valid generation");
        let mut forged = annotated_namespace(7);
        forged.metadata.name = Some("cap-demo".to_string());
        forged.metadata.creation_timestamp = Some(k8s_time("2026-10-18T00:00:00Z"));
        let empty = empty_ledger();
        assert!(matches!(
            classify_initial_namespace_get(&Ok(forged.clone()), generation, &empty),
            InitialNamespaceOwnership::Adopted
        ));
        let recorded = enclava_engine::apply::creation_ledger::CreationLedgerBuffer::new();
        recorded.preload([(
            "Namespace".to_string(),
            "cap-demo".to_string(),
            "00000000-0000-0000-0000-000000000001".to_string(),
        )]);
        assert!(matches!(
            classify_initial_namespace_get(&Ok(forged), generation, &recorded),
            InitialNamespaceOwnership::Owned { .. }
        ));
    }

    /// cap#272 durability: creation records persist idempotently per
    /// (app_id, uid) and load back as matchable lineage.
    #[tokio::test]
    async fn creation_ledger_roundtrip_is_idempotent_per_uid() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let deployment_id = Uuid::new_v4();
        let record = enclava_engine::apply::creation_ledger::CreationRecord {
            kind: "Secret".to_string(),
            name: "cap-demo-pull".to_string(),
            namespace: Some("cap-demo".to_string()),
            uid: "uid-roundtrip".to_string(),
            mutation_generation: 7,
        };
        persist_creation_records(&pool, app_id, deployment_id, std::slice::from_ref(&record))
            .await
            .expect("persist creation record");
        // A retried apply re-observing the same creation: same uid, newer
        // generation label — must not error or duplicate.
        let mut reobserved = record.clone();
        reobserved.mutation_generation = 8;
        persist_creation_records(&pool, app_id, deployment_id, &[reobserved])
            .await
            .expect("persist re-observed creation record");
        let ledger = load_creation_ledger(&pool, app_id)
            .await
            .expect("load creation ledger");
        assert!(ledger.contains("Secret", "cap-demo-pull", "uid-roundtrip"));
        assert!(!ledger.contains("Secret", "cap-demo-pull", "uid-other"));
        assert!(ledger.contains_name_uid("cap-demo-pull", "uid-roundtrip"));
        let rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM resource_creation_ledger WHERE app_id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("count creation rows");
        assert_eq!(rows, 1, "one row per (app_id, uid)");
        delete_cleanup_fixture(&pool, app_id).await;
    }
}
