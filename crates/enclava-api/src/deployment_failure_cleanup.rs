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
pub(crate) async fn sweep_published_objects_from_adopted_namespace(
    state: &crate::state::AppState,
    app: &App,
    failed_deployment_id: Uuid,
    generation: enclava_engine::apply::generation::MutationGeneration,
    _apply_started_at: Option<chrono::DateTime<chrono::Utc>>,
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
    // The durable PROVEN lineage windows (Codex P1): the server-reported
    // StatefulSet creation time, UID, and — once a sweep of the row issued
    // the sts delete — deletion time of this row and every still-incomplete
    // sibling (a completed sweep cleared those siblings' evidence — their
    // claims were converged). A sts creation time is only a LOWER bound on
    // CAP lineage, never proof that a later matching claim is ours: a claim
    // is deletable only on claim-specific evidence — creation strictly
    // inside a CLOSED window [sts_created_at, sts_observed_deleted_at], or
    // a controller ownerReference pinning a proven UID. Loaded fail-closed:
    // a query failure counts as sweep failure (retryable), not as "no
    // window" (which would silently skip claims then clear evidence
    // over them).
    let (sts_proven_windows, reached_sts_step_without_window, legacy_unmarked_row) = match sqlx::query_as::<
        _,
        (
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
            Option<chrono::DateTime<chrono::Utc>>,
        ),
    >(
        "SELECT sts_uid, sts_created_at, sts_observed_deleted_at, sts_apply_started_at,
                manifest_hash, apply_started_at
           FROM deployments
          WHERE app_id = $1
            AND (id = $2 OR cleanup_sweep_incomplete)",
    )
    .bind(app.id)
    .bind(failed_deployment_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(rows) => (
            rows.iter()
                .filter_map(|(uid, created_at, deleted_confirmed_at, _, _, _)| {
                    created_at.map(|created_at| StsProvenanceWindow {
                        uid: uid.clone(),
                        created_at,
                        deleted_confirmed_at: *deleted_confirmed_at,
                    })
                })
                .collect::<Vec<_>>(),
            // A row that reached the StatefulSet step but recorded no
            // server-reported provenance (the apply response's provenance
            // write failed): its claims are unprovable — an out-of-window
            // matching claim may still be that row's, so "foreign" skips
            // must not let the sweep complete over it.
            rows.iter().any(|(_, created_at, _, apply_started, _, _)| {
                apply_started.is_some() && created_at.is_none()
            }),
            any_legacy_evidence_row(
                rows.iter()
                    .map(|(_, _, _, _, manifest_hash, apply_started)| {
                        (manifest_hash.as_deref(), *apply_started)
                    }),
            ),
        ),
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                error = %error,
                "adopted-namespace sweep cannot load the proven sts lineage windows; counting the sweep as failed for retry"
            );
            return usize::MAX;
        }
    };
    let mut failures = 0usize;
    for target in adopted_namespace_sweep_targets(app) {
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
        let mut statefulset_uid: Option<String> = None;
        let mut statefulset_created_at: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut sts_observed_deleted_at: Option<chrono::DateTime<chrono::Utc>> = None;
        let mut sts_deleted_edge_persisted = false;
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
                // Absent. For the StatefulSet this may be a RETRY after a
                // previous sweep deleted it but could not finish its PVC
                // sweep: run the claim sweep now under the retry-time
                // claim-specific provenance rules — closed lineage windows
                // and UID-pinned controller refs only (Codex P1).
                if target.kind == "StatefulSet" {
                    failures += sweep_statefulset_pvcs(
                        &client,
                        &app.namespace,
                        &target.name,
                        sweep_deadline,
                        // Retry sweep after a previous sweep deleted the
                        // sts: only the durable PROVEN lineage windows
                        // (uid + [created_at, observed_deleted_at] of this
                        // row and still-incomplete siblings) may authorize
                        // deletion — Codex P1: the sts creation time alone
                        // is only a lower bound, never proof that a later
                        // matching claim is CAP lineage.
                        &sts_proven_windows,
                        None,
                        reached_sts_step_without_window,
                    )
                    .await;
                }
                break; // never created, or already deleted
            };
            if !is_cap_created_generation_leftover(&live, generation.get()) {
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
                if legacy_unmarked_row {
                    tracing::warn!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        kind = target.kind,
                        name = %target.name,
                        "adopted-namespace sweep cannot attribute live unmarked object (legacy evidence row in scope); counting the sweep incomplete"
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
                }
                break;
            }
            let preconditions = kube::api::Preconditions {
                uid: live.metadata.uid.clone(),
                resource_version: live.metadata.resource_version.clone(),
            };
            if target.kind == "StatefulSet" {
                statefulset_uid = live.metadata.uid.clone();
                // Capture the StatefulSet's creation timestamp to use as the
                // evidence-bound for PVC deletion. Using the StatefulSet's own
                // creation time rather than apply_started_at ensures we only
                // delete PVCs created by THIS StatefulSet, not ones a tenant
                // created between apply_started_at and when CAP reached the
                // StatefulSet step.
                let observed_created_at =
                    live.metadata.creation_timestamp.as_ref().and_then(|ts| {
                        ts.0.to_string()
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .ok()
                    });
                statefulset_created_at = observed_created_at;
                // Persist the proven window edges BEFORE the delete (Codex
                // P1): the sts creation provenance (uid + server-reported
                // creationTimestamp) and the deletion edge stamped now, so
                // a sweep that deletes the sts but cannot finish the claim
                // sweep leaves a CLOSED lineage window
                // [sts_created_at, sts_observed_deleted_at] that retry
                // sweeps (sts absent) can require — "created after the sts"
                // alone was only a lower bound, never claim-specific proof.
                let deleted_edge = chrono::Utc::now();
                if let (Some(uid), Some(created)) =
                    (live.metadata.uid.as_deref(), observed_created_at)
                    && let Err(error) = sqlx::query(
                        "UPDATE deployments
                            SET sts_uid = COALESCE(sts_uid, $3),
                                sts_created_at = COALESCE(sts_created_at, $4),
                                sts_observed_deleted_at = COALESCE(sts_observed_deleted_at, $5)
                          WHERE app_id = $1 AND id = $2",
                    )
                    .bind(app.id)
                    .bind(failed_deployment_id)
                    .bind(uid)
                    .bind(created)
                    .bind(deleted_edge)
                    .execute(&state.db)
                    .await
                {
                    tracing::warn!(
                        app_id = %app.id,
                        deployment_id = %failed_deployment_id,
                        error = %error,
                        "adopted-namespace sweep could not persist the observed sts provenance; retry sweeps stay fail-closed"
                    );
                    // Best-effort write failed: the durable window may stay
                    // OPEN (no deletion edge) — retry sweeps must then fail
                    // closed on post-birth claims rather than accept them.
                    sts_deleted_edge_persisted = false;
                } else {
                    sts_deleted_edge_persisted = true;
                }
                sts_observed_deleted_at = Some(deleted_edge);
            }
            match bounded_sweep_read(
                sweep_deadline,
                api.delete(
                    &target.name,
                    &kube::api::DeleteParams {
                        preconditions: Some(preconditions),
                        // Foreground propagation: the owner must not vanish
                        // while its Pods or other dependents are still live
                        // (background cascading deletion would let the 404
                        // confirmation here run ahead of the collector).
                        propagation_policy: Some(kube::api::PropagationPolicy::Foreground),
                        ..kube::api::DeleteParams::default()
                    },
                ),
            )
            .await
            {
                Ok(_) => {
                    // Accepted DELETE is not absence: a finalizer can hold
                    // the object in Terminating indefinitely. Re-read and
                    // confirm 404 before counting the target complete.
                    match bounded_sweep_read(sweep_deadline, api.get_opt(&target.name)).await {
                        Ok(None) => {
                            deleted = true;
                            break;
                        }
                        Ok(Some(_)) => {
                            // Terminating or finalizer-stuck: the sweep
                            // must not report completion while the object
                            // may survive.
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                kind = target.kind,
                                name = %target.name,
                                "adopted-namespace sweep delete accepted but object still live (finalizer?); counting as incomplete"
                            );
                            failures += 1;
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                kind = target.kind,
                                name = %target.name,
                                error = %error,
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
        if deleted && target.kind == "StatefulSet" {
            // A deleted StatefulSet leaves its PVCs behind (the manifest's
            // retention policy is Retain): sweep the CAP-created claims
            // too, or a later resized workload would silently reuse the
            // old-size volumes while the cleared manifest_hash had
            // disabled the storage-size guard.
            failures += sweep_statefulset_pvcs(
                &client,
                &app.namespace,
                &target.name,
                sweep_deadline,
                // The durable proven windows of this row and its
                // still-incomplete siblings (retry evidence).
                &sts_proven_windows,
                // The sts was proven live and just deleted by THIS sweep:
                // its own window [creationTimestamp, pre-delete stamp] is
                // this instance's lineage bound — server-reported
                // creation, CAP-issued deletion. Only pass it as CLOSED
                // when the pre-delete stamp was durably persisted (a
                // failed best-effort write would leave retry sweeps with
                // an open window, which they treat fail-closed).
                statefulset_created_at.map(|created_at| StsProvenanceWindow {
                    uid: statefulset_uid.clone(),
                    created_at,
                    deleted_confirmed_at: if sts_deleted_edge_persisted {
                        sts_observed_deleted_at
                    } else {
                        None
                    },
                }),
                reached_sts_step_without_window,
            )
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
fn is_cap_created_generation_leftover<K>(resource: &K, failed_generation: i64) -> bool
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
        return false;
    };
    if !(created_by > 0) {
        return false;
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
        return false;
    }
    let live_generation =
        annotation(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION);
    live_generation.is_some_and(|live| live > 0 && live <= failed_generation)
}

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
fn any_legacy_evidence_row<'a>(
    mut rows: impl Iterator<Item = (Option<&'a str>, Option<chrono::DateTime<chrono::Utc>>)>,
) -> bool {
    rows.any(|(manifest_hash, apply_started)| {
        manifest_hash.is_some() && apply_started.is_none()
    })
}

/// Bounded re-read retry budget for preconditioned sweep deletes.
const SWEEP_DELETE_RETRIES: usize = 3;

/// Classify a claim's creation against the proven StatefulSet-step bound
/// at Kubernetes timestamp precision. `metav1.Time` serializes as RFC 3339
/// with SECOND precision (no sub-second digits), and the StatefulSet
/// controller routinely creates the ordinal claims within the same second
/// the StatefulSet itself was created — so a claim that is `==` the bound
/// is a NORMAL outcome, not an exceptional clock race. Both sides are
/// compared as instants: the chrono bound is rendered RFC 3339 and parsed
/// into a jiff `Timestamp` (the string forms of the two libraries differ
/// and misorder near-equal times), so the ordering is truly chronological
/// before the three-way decision is made.
#[derive(Debug, PartialEq, Eq)]
enum ClaimBoundOrdering {
    /// Created strictly after the bound (a later second): within this
    /// workload's lineage window — sweep-eligible.
    AfterBound,
    /// The SAME second as the bound: at second precision this is
    /// undecidable — the claim may be the controller's own same-second
    /// creation or a tenant's race. Ownership is unresolved: retain the
    /// claim (never delete) and count it as a failure so the sweep
    /// reports INCOMPLETE and the caller keeps provider-state evidence
    /// instead of silently clearing it over a retained claim.
    SameSecondUnresolved,
    /// Created strictly before the bound: a tenant's or a predecessor's
    /// claim. Never swept, and not a failure.
    BeforeBound,
}

fn classify_claim_creation(
    created: &k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
    bound: chrono::DateTime<chrono::Utc>,
) -> ClaimBoundOrdering {
    // Compare as the SAME type: the chrono threshold is parsed into a
    // jiff Timestamp (both render/parse RFC 3339), so the ordering is
    // truly chronological — string forms of the two libraries differ and
    // misorder near-equal times. An unparseable bound proves nothing:
    // treat it as undecidable (fail closed) rather than as "after".
    let Ok(threshold) = bound.to_rfc3339().parse::<k8s_openapi::jiff::Timestamp>() else {
        return ClaimBoundOrdering::SameSecondUnresolved;
    };
    if created.0 > threshold {
        ClaimBoundOrdering::AfterBound
    } else if created.0 < threshold {
        ClaimBoundOrdering::BeforeBound
    } else {
        ClaimBoundOrdering::SameSecondUnresolved
    }
}

/// A proven StatefulSet lineage window: server-reported evidence about a
/// StatefulSet a CAP apply created (or a sweep observed live and deleted).
/// `created_at` is the sts's own creationTimestamp; `deleted_confirmed_at`
/// is the time a sweep stamped BEFORE issuing the sts delete (so a crash
/// between stamp and delete still leaves a CLOSED window behind — an open
/// one could never be closed again, wedging retry sweeps). `uid` is the
/// sts's immutable Kubernetes identity.
#[derive(Debug, Clone)]
pub(crate) struct StsProvenanceWindow {
    uid: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    deleted_confirmed_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Claim-specific lineage verdict for a name-matching PVC.
#[derive(Debug, PartialEq, Eq)]
enum ClaimLineage {
    /// Proven CAP lineage — safe to delete: a controller ownerReference
    /// pinning a proven sts UID (immutable server identity), or creation
    /// strictly inside a CLOSED proven window (the exact-name claim was
    /// created while CAP's sts held the name and before CAP's delete of
    /// it was issued).
    Proven,
    /// Proven foreign — predates every proven sts birth, or postdates a
    /// closed window's deletion edge: a tenant's or predecessor's claim
    /// that CAP's StatefulSets can never have created. Skipped silently.
    Foreign,
    /// Cannot be proven either way — RETAINED, and counted as a failure so
    /// the sweep stays incomplete (same-second edges, open windows, rows
    /// that reached the sts step without recorded provenance, controller
    /// references pinning an unknown UID). Fail closed: never delete, and
    /// never let the caller clear evidence over the retained claim.
    Unproven,
}

/// Codex P1 (claim-specific provenance): a StatefulSet creation time is
/// only a LOWER bound on CAP lineage — it is not proof that every later
/// name-matching claim came from that StatefulSet. After an incomplete
/// sweep deletes the sts, a tenant can create an ownerless
/// `<vct>-<sts>-<ordinal>` claim (or park a foreign same-named sts's
/// claim); a retry sweep must NOT accept "postdates the old bound" as
/// lineage. Deletion now requires immutable claim-specific evidence:
/// a controller ownerReference pinning a proven sts UID, or creation
/// strictly INSIDE a closed window [sts_created_at,
/// sts_observed_deleted_at] — anything created after the window's
/// deletion edge is foreign by construction (the name was un-held from
/// that moment). Same-second boundary cases are UNRESOLVED at Kubernetes'
/// second-precision timestamps and fail closed.
fn classify_claim_lineage(
    created: &k8s_openapi::apimachinery::pkg::apis::meta::v1::Time,
    controller_ref_uid: Option<&str>,
    windows: &[StsProvenanceWindow],
    unproven_sts_step: bool,
) -> ClaimLineage {
    // A StatefulSet controller ownerReference is the strongest possible
    // evidence — but only when the pinned UID is one CAP recorded (the
    // persisted sts_uid was never loaded for retry sweeps before; a
    // foreign same-NAMED sts has a different, unknown UID). A ref
    // pinning an UNKNOWN uid is positive evidence AGAINST this
    // workload's lineage (a foreign sts held the claim name) — even
    // inside a temporal window — and fails closed.
    if let Some(uid) = controller_ref_uid {
        return if windows.iter().any(|w| w.uid.as_deref() == Some(uid)) {
            ClaimLineage::Proven
        } else {
            ClaimLineage::Unproven
        };
    }
    let mut covered_by_open_window = unproven_sts_step;
    for w in windows {
        match classify_claim_creation(created, w.created_at) {
            // Same second as the sts's birth: the controller's own claim
            // and a tenant's race are indistinguishable — fail closed.
            ClaimBoundOrdering::SameSecondUnresolved => return ClaimLineage::Unproven,
            // Predates this sts: this window says nothing about the claim.
            ClaimBoundOrdering::BeforeBound => continue,
            ClaimBoundOrdering::AfterBound => match w.deleted_confirmed_at {
                // Closed window, strictly before its deletion edge: the
                // claim was created while CAP's sts provably held this
                // exact claim name.
                Some(deleted_at) => match classify_claim_creation(created, deleted_at) {
                    ClaimBoundOrdering::BeforeBound => return ClaimLineage::Proven,
                    ClaimBoundOrdering::SameSecondUnresolved => return ClaimLineage::Unproven,
                    // Created after the delete was issued: the name was
                    // no longer held by CAP — foreign unless another
                    // window covers it.
                    ClaimBoundOrdering::AfterBound => continue,
                },
                // Open window (sts proven created, deletion never stamped):
                // no upper bound exists — an "after the lower bound" claim
                // is exactly the attacker shape. Fail closed.
                None => covered_by_open_window = true,
            },
        }
    }
    if covered_by_open_window {
        ClaimLineage::Unproven
    } else {
        ClaimLineage::Foreign
    }
}

/// Delete the PVCs this failed generation's StatefulSet created in an
/// adopted namespace. A claim is deleted only on CLAIM-SPECIFIC evidence
/// of CAP lineage (Codex P1 — see `classify_claim_lineage`):
///
/// * its name matches the exact `<vct>-<statefulset>-<ordinal>` shape for
///   a CAP-rendered VCT name, AND
/// * it carries a controller ownerReference pinning a proven sts UID, OR
///   was created strictly inside a CLOSED proven window
///   [sts_created_at, sts_observed_deleted_at] — the live sts's own
///   window when this sweep deleted it (deleted edge = the pre-delete
///   stamp), else the durable recorded windows of this row and its
///   still-incomplete siblings for a retry sweep after the sts is gone.
///
/// When the StatefulSet is absent and NO proven window exists, matching
/// claims cannot be proven either way: none are touched, but the sweep
/// reports INCOMPLETE (non-zero) as long as name-matching claims remain —
/// reporting zero would let the caller clear manifest evidence over
/// unproven, retained claims (Codex P2 / devin). With no matching claims
/// there is nothing to converge and the sweep is complete.
///
/// PVCs created by the controller from `spec.volumeClaimTemplates` never
/// carry CAP annotations (VCT metadata is immutable — adding the
/// annotation would break every redeploy of an existing StatefulSet with
/// 422), and under the default Retain/Retain policy the controller
/// attaches no PVC ownerReferences either, so closed lineage windows are
/// the sound discriminator for controller-created claims and UID-pinned
/// ownerReferences the hard proof when one is present.
pub(crate) async fn sweep_statefulset_pvcs(
    client: &kube::Client,
    namespace: &str,
    statefulset: &str,
    sweep_deadline: tokio::time::Instant,
    sts_proven_windows: &[StsProvenanceWindow],
    sts_live_window: Option<StsProvenanceWindow>,
    unproven_sts_step: bool,
) -> usize {
    const CAP_VCT_NAMES: [&str; 2] = ["state", "tls-state"];
    let mut all_windows: Vec<_> = sts_proven_windows.to_vec();
    if let Some(live) = sts_live_window {
        all_windows.push(live);
    }
    let api: kube::Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
        kube::Api::namespaced(client.clone(), namespace);
    let list = match bounded_sweep_read(sweep_deadline, api.list(&kube::api::ListParams::default()))
        .await
    {
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
    // Inspect only name-matching claims, and decide the no-window outcome
    // from what is actually retained rather than up front: an empty
    // match set is a complete sweep even with no provenance, while any
    // retained matching claim without a proven window keeps the sweep
    // incomplete (retryable) instead of silently complete.
    let matching_claims: Vec<_> = list
        .items
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
    if all_windows.is_empty() {
        // Codex P2 / devin: matching claims are retained but NO proven
        // StatefulSet lineage window exists (e.g. a previous sweep
        // deleted the sts and its best-effort provenance write failed).
        // Touch nothing, but do NOT report the sweep complete: returning
        // zero here would let the caller clear manifest_hash and the
        // cleanup marker over claims that were never inspected, leaving
        // them silently reusable by a later resized deployment.
        tracing::warn!(
            namespace = %namespace,
            statefulset = %statefulset,
            claims = matching_claims.len(),
            "adopted-namespace PVC sweep retains name-matching claims with no proven StatefulSet lineage window; counting the sweep incomplete for retry"
        );
        return 1;
    }
    let mut failures = 0usize;
    for pvc in matching_claims {
        let Some(name) = pvc.metadata.name.clone() else {
            continue;
        };
        let Some(created) = pvc.metadata.creation_timestamp.as_ref() else {
            continue;
        };
        let controller_ref_uid = pvc
            .metadata
            .owner_references
            .as_ref()
            .and_then(|owners| {
                owners
                    .iter()
                    .find(|owner| owner.kind == "StatefulSet" && owner.controller == Some(true))
            })
            .map(|owner| owner.uid.clone());
        match classify_claim_lineage(
            created,
            controller_ref_uid.as_deref(),
            &all_windows,
            unproven_sts_step,
        ) {
            ClaimLineage::Proven => {}
            ClaimLineage::Foreign => {
                // Count this as a failure: a foreign claim means the sweep
                // cannot prove the namespace is clean of tenant data. A tenant
                // could have created a same-named claim after CAP's STS was
                // deleted, and clearing evidence would let a later deployment
                // resize into that tenant claim. Retain evidence and keep the
                // row retryable so a future sweep can re-inspect.
                tracing::warn!(
                    namespace = %namespace,
                    pvc = %name,
                    "adopted-namespace PVC sweep counts foreign claim as failure; evidence retained for retry"
                );
                failures += 1;
                continue;
            }
            ClaimLineage::Unproven => {
                // Retain the claim and count a failure so the sweep
                // stays INCOMPLETE: the skip must not let the caller
                // clear manifest_hash / the cleanup marker while the
                // claim remains (the silent-reuse hazard).
                tracing::warn!(
                    namespace = %namespace,
                    pvc = %name,
                    "adopted-namespace PVC sweep cannot prove claim lineage from claim-specific evidence; retaining the claim and counting the sweep incomplete"
                );
                failures += 1;
                continue;
            }
        }
        let preconditions = kube::api::Preconditions {
            uid: pvc.metadata.uid.clone(),
            resource_version: pvc.metadata.resource_version.clone(),
        };
        if tokio::time::Instant::now() >= sweep_deadline {
            tracing::warn!(
                namespace = %namespace,
                pvc = %name,
                "adopted-namespace PVC sweep hit the overall deadline; counting remaining claims as failures"
            );
            failures += 1;
            continue;
        }
        match bounded_sweep_read(
            sweep_deadline,
            api.delete(
                &name,
                &kube::api::DeleteParams {
                    preconditions: Some(preconditions),
                    ..kube::api::DeleteParams::default()
                },
            ),
        )
        .await
        {
            Err(kube::Error::Api(error)) if error.code == 404 => {
                // Already gone: successful cleanup, not a failure.
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    namespace = %namespace,
                    pvc = %name,
                    error = %error,
                    "adopted-namespace sweep could not delete this generation's PVC; will retry via reconciliation"
                );
                failures += 1;
            }
            Ok(_) => {
                // Accepted is not absent (Longhorn finalizers can hold a
                // claim in Terminating): confirm 404, else the sweep is
                // incomplete and retains provider-state evidence.
                match bounded_sweep_read(sweep_deadline, api.get_opt(&name)).await {
                    Ok(None) => {}
                    Ok(Some(_)) => {
                        tracing::warn!(
                            namespace = %namespace,
                            pvc = %name,
                            "adopted-namespace sweep PVC delete accepted but claim still live (finalizer?); counting as incomplete"
                        );
                        failures += 1;
                    }
                    Err(error) => {
                        tracing::warn!(
                            namespace = %namespace,
                            pvc = %name,
                            error = %error,
                            "adopted-namespace sweep cannot confirm PVC absence; counting as incomplete"
                        );
                        failures += 1;
                    }
                }
            }
        }
    }
    failures
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
/// `enclava-engine`'s apply modules.
fn sweep_api_resource(kind: &str) -> kube::api::ApiResource {
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
        _ => unreachable!("statically enumerated kinds"),
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

/// Best-effort compensating cleanup for a deployment whose apply failed
/// terminally. `app` is the immutable payload snapshot of the failed
/// generation; `mutation` still owns that generation's provider fences.
pub(crate) async fn cleanup_after_terminal_apply_failure(
    state: &AppState,
    app: &App,
    failed_deployment_id: Uuid,
    mutation: &AppMutationLease,
) -> CleanupFenceOutcome {
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
    // this generation published provider state at all. Only when it owns the
    // namespace does route removal make sense — `ensure_haproxy_routes` runs
    // strictly after `apply_namespace` inside the same provider phase, so a
    // generation that never owned the namespace never published routes.
    //
    // The classification GET and the teardown run as separate guarded
    // provider steps: a lease lost during the classification (or the
    // adopted-namespace sweep) released nothing harmful — no namespace
    // delete can have been issued — so the fence must NOT be retained (an
    // adopted namespace never 404s, and the retained-fence reconciler only
    // releases on an observed 404; retaining would wedge every later
    // deployment of this app on permanent Busy). Only a lease lost while a
    // CAP-created namespace delete may be in flight retains the fence.
    let ownership = match mutation
        .guard_provider(classify_failed_generation_namespace(
            app,
            namespace_generation,
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
        } => match mutation
            .guard_provider(delete_owned_namespace(
                app,
                namespace_generation,
                uid,
                resource_version,
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                // Lease heartbeat lost with a namespace delete possibly in
                // flight: fail closed on the namespace fence.
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace cleanup lost its mutation lease; retaining the namespace fence for reconciliation"
                );
                return CleanupFenceOutcome::RetainNamespaceFence;
            }
        },
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
            // The claim bound is the earliest StatefulSet-step start across
            // THIS row AND every still-incomplete sibling row (a completed
            // sweep clears those siblings' evidence — their shared-name
            // objects, including retained claims, were converged — so
            // their older claims must be within this sweep's deletion
            // window). sts_apply_started_at is stamped immediately before
            // the StatefulSet step, so a tenant claim created after
            // apply_started_at but before that step predates the bound
            // and can never be swept. Rows whose applies never reached
            // the StatefulSet step (NULL sts stamp, incl. legacy rows
            // predating the column) fall back to apply_started_at /
            // observing_since / created_at.
            let apply_started_at = match sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
                "SELECT MIN(COALESCE(sts_apply_started_at, apply_started_at, observing_since, created_at)) FROM deployments WHERE app_id = $1 AND (id = $2 OR cleanup_sweep_incomplete)",
            )
            .bind(app.id)
            .bind(failed_deployment_id)
            .fetch_one(&state.db)
            .await
            {
                Ok(bound) => Some(bound),
                Err(error) => {
                    // The PVC ownership bound is load-bearing, not optional:
                    // treating a transient query failure as "no bound"
                    // would make sweep_statefulset_pvcs skip every claim
                    // (created_after_apply_start false) while still
                    // reporting zero failures — the sweep would then
                    // declare itself complete and clear provider evidence
                    // over retained claims. Fail the sweep instead.
                    tracing::warn!(
                        app_id = %app.id,
                        deployment_id = %failed_deployment_id,
                        error = %error,
                        "failed-apply cleanup cannot load the PVC ownership bound; marking the sweep incomplete for a later retry"
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
                    return CleanupFenceOutcome::ReleaseNormally;
                }
            };
            match mutation
                .guard_provider(sweep_published_objects_from_adopted_namespace(
                    state,
                    app,
                    failed_deployment_id,
                    namespace_generation,
                    apply_started_at,
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
            // release: the retained-fence reconciler requires a namespace
            // 404 — which never happens for an adopted namespace, nor for
            // a proven-owned one no delete was issued against (and this
            // generation is no longer authorized to delete). Marking the
            // row cleanup_sweep_incomplete keeps later failed generations
            // cleanup-eligible so their sweeps converge the leftovers.
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
/// delete; every other outcome — including an initial 404 — is
/// [`NamespaceTeardown::NotOurs`]. A generation that never owned the live
/// namespace never published routes (`ensure_haproxy_routes` runs strictly
/// after `apply_namespace`), so route removal must be skipped for these
/// outcomes rather than run against the shared HAProxy ConfigMap.
/// [`NamespaceTeardown::ConfirmedAbsent`] is reserved for a namespace that
/// was observed under this generation's annotation and only later returned
/// 404 (between the owning GET and the delete, or during the convergence
/// wait).
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
    /// GET returned 404 before any delete was issued. This generation never
    /// published the namespace, so it never published routes either.
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
    classify_initial_namespace_get(&probed, generation)
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
                        classify_initial_namespace_get(&Ok(live.clone()), generation),
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
            classify_initial_namespace_get(&Ok(annotated_namespace(7)), generation),
            InitialNamespaceOwnership::Owned { .. }
        ));
        assert!(matches!(
            classify_initial_namespace_get(&Ok(annotated_namespace(6)), generation),
            InitialNamespaceOwnership::Foreign
        ));
        // A missing annotation (or an unparseable one) is foreign, not owned:
        // `delete_resource` would otherwise treat it as generation 0.
        assert!(matches!(
            classify_initial_namespace_get(
                &Ok(k8s_openapi::api::core::v1::Namespace::default()),
                generation
            ),
            InitialNamespaceOwnership::Foreign
        ));
        // Codex P1: this generation's mutation annotation alone is only a
        // last-writer proof. Without creation evidence the namespace
        // pre-existed and was adopted — it must never be deleted.
        assert!(matches!(
            classify_initial_namespace_get(&Ok(adopted_namespace(7)), generation),
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
            classify_initial_namespace_get(&Ok(forged), generation),
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
            classify_initial_namespace_get(&Ok(recreated), generation),
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
                ..Default::default()
            },
            types: None,
            data: serde_json::Value::Null,
        }
    }

    fn unparseable_mutation_object() -> kube::api::DynamicObject {
        let mut object = sweep_leftover_object(&[], true);
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
        assert!(is_cap_created_generation_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 7),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 7),
            ]),
            7
        ));
        // An older CAP-created leftover (an earlier failed apply's object)
        // whose last writer is still an older generation: sweep it.
        assert!(is_cap_created_generation_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 3),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 3),
            ]),
            7
        ));
        // Codex P1: SSA-patched pre-existing object — mutation annotation
        // from this apply, but NO creation evidence. Must never be deleted.
        assert!(!is_cap_created_generation_leftover(
            &object_meta_with_annotations(&[(
                generation_annotations::MUTATION_GENERATION_ANNOTATION,
                7
            )]),
            7
        ));
        // A newer generation's publication: not this failure's partial state.
        assert!(!is_cap_created_generation_leftover(
            &object_meta_with_annotations(&[
                (generation_annotations::RESOURCE_CREATED_BY_ANNOTATION, 9),
                (generation_annotations::MUTATION_GENERATION_ANNOTATION, 9),
            ]),
            7
        ));
        // Foreign object: no annotations at all.
        assert!(!is_cap_created_generation_leftover(
            &sweep_leftover_object(&[], false),
            7
        ));
        // Codex tGA: tenant-authored creation marker (value present, no
        // CAP managed-fields provenance) must not authorize deletion.
        assert!(!is_cap_created_generation_leftover(
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
        // undecidable last-writer, skip.
        assert!(!is_cap_created_generation_leftover(
            &unparseable_mutation_object(),
            7
        ));
    }

    fn k8s_time(rfc3339: &str) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::Time {
        rfc3339
            .parse::<k8s_openapi::jiff::Timestamp>()
            .map(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time)
            .unwrap_or_else(|_| panic!("parse {rfc3339} as jiff Timestamp"))
    }

    /// Codex P1 (same-second PVC claims): metav1.Time is second-precision,
    /// and the StatefulSet controller routinely creates the ordinal claims
    /// in the same second as the StatefulSet itself. A strict `>` rejects
    /// those claims AND (worse) lets the sweep complete while they remain.
    /// The classifier must treat equality as UNRESOLVED and before as
    /// foreign; only strictly-after claims are sweep-eligible.
    #[test]
    fn claim_creation_classification_is_three_way_at_second_precision() {
        let bound = chrono::DateTime::parse_from_rfc3339("2026-10-14T10:00:04Z")
            .expect("parse bound")
            .with_timezone(&chrono::Utc);
        // Strictly after: the controller's claim in a later second.
        assert_eq!(
            classify_claim_creation(&k8s_time("2026-10-14T10:00:05Z"), bound),
            ClaimBoundOrdering::AfterBound
        );
        // SAME second as the bound: undecidable at Kubernetes precision —
        // the exact case the strict `>` misclassified as "too old" while
        // still letting the sweep complete over the retained claim.
        assert_eq!(
            classify_claim_creation(&k8s_time("2026-10-14T10:00:04Z"), bound),
            ClaimBoundOrdering::SameSecondUnresolved
        );
        // Strictly before: a tenant's or predecessor's claim.
        assert_eq!(
            classify_claim_creation(&k8s_time("2026-10-14T10:00:03Z"), bound),
            ClaimBoundOrdering::BeforeBound
        );
        // Cross-second-boundary sanity: instants, not string prefixes.
        assert_eq!(
            classify_claim_creation(&k8s_time("2026-10-14T09:59:59Z"), bound),
            ClaimBoundOrdering::BeforeBound
        );
        assert_eq!(
            classify_claim_creation(&k8s_time("2026-10-14T10:00:04.500Z"), bound),
            ClaimBoundOrdering::AfterBound,
            "a sub-second claim after the second-bound is strictly after as an instant"
        );
    }

    /// Codex P1 (legacy unmarked rows): evidence rows published before the
    /// `apply_started_at` column existed (manifest_hash set, apply_started_at
    /// NULL — both written by the same atomic UPDATE) can only be pre-release
    /// rows; their objects can never carry creation evidence, so live
    /// unmarked targets under them must count as sweep failures, not skips.
    #[test]
    fn legacy_evidence_row_detection() {
        let t = chrono_time("2026-10-14T10:00:00Z");
        // Legacy row: evidence without apply_started_at.
        assert!(any_legacy_evidence_row(
            [(Some("abc123"), None)].into_iter()
        ));
        // Modern row: both stamped.
        assert!(!any_legacy_evidence_row(
            [(Some("abc123"), Some(t))].into_iter()
        ));
        // No evidence at all: not a legacy evidence row.
        assert!(!any_legacy_evidence_row([(None, None)].into_iter()));
        // Mixed set: one legacy row among modern ones still flags.
        assert!(any_legacy_evidence_row(
            [
                (Some("new-gen"), Some(t)),
                (Some("old-gen"), None),
                (None, None),
            ]
            .into_iter()
        ));
    }

    fn chrono_time(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .expect("parse bound")
            .with_timezone(&chrono::Utc)
    }

    fn provenance_window(
        uid: Option<&str>,
        created: &str,
        deleted: Option<&str>,
    ) -> StsProvenanceWindow {
        StsProvenanceWindow {
            uid: uid.map(str::to_string),
            created_at: chrono_time(created),
            deleted_confirmed_at: deleted.map(chrono_time),
        }
    }

    /// Codex P1 (claim-specific provenance): "created after the sts's
    /// creation time" is only a lower bound, never proof of CAP lineage.
    /// After an incomplete sweep deletes the sts, a tenant can create an
    /// ownerless matching claim (or park a foreign same-named sts's
    /// claim); the retry sweep must not delete either. Deletion requires
    /// immutable claim-specific evidence: a UID-pinned controller ref, or
    /// creation strictly INSIDE a closed window.
    #[test]
    fn claim_lineage_requires_claim_specific_provenance() {
        let closed = provenance_window(
            Some("uid-cap-1"),
            "2026-10-14T10:00:04Z",
            Some("2026-10-14T10:05:00Z"),
        );
        // Controller's own claim inside the closed window: proven.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:05Z"),
                None,
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Proven
        );
        // Tenant claim created AFTER the sweep deleted the sts: the exact
        // attack — postdates the old lower bound, but the name was no
        // longer held by CAP. Foreign, never deleted.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T11:00:00Z"),
                None,
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Foreign
        );
        // Foreign same-named sts's claim: controller ref pinning an
        // UNKNOWN uid — postdates the bound but is not CAP lineage.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:05Z"),
                Some("uid-foreign-sts"),
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Unproven
        );
        // Same evidence, ref pinning the PROVEN uid: hard proof.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T11:00:00Z"),
                Some("uid-cap-1"),
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Proven
        );
        // OPEN window (deletion never stamped — best-effort write lost):
        // an after-birth claim cannot be proven and must fail closed.
        let open = provenance_window(Some("uid-cap-1"), "2026-10-14T10:00:04Z", None);
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:05Z"),
                None,
                std::slice::from_ref(&open),
                false,
            ),
            ClaimLineage::Unproven
        );
        // OPEN window, but a UID-pinned controller ref still proves it.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:05Z"),
                Some("uid-cap-1"),
                std::slice::from_ref(&open),
                false,
            ),
            ClaimLineage::Proven
        );
        // Claim predating every proven sts birth: foreign (tenant's or
        // predecessor's), skipped silently.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T09:00:00Z"),
                None,
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Foreign
        );
        // Same-second edges at both window boundaries stay unresolved.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:04Z"),
                None,
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Unproven
        );
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:05:00Z"),
                None,
                std::slice::from_ref(&closed),
                false,
            ),
            ClaimLineage::Unproven
        );
        // A sibling generation's window covers a claim this row's window
        // does not (converging older incomplete siblings' claims).
        let sibling = provenance_window(
            Some("uid-cap-0"),
            "2026-10-14T09:30:00Z",
            Some("2026-10-14T09:35:00Z"),
        );
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T09:30:30Z"),
                None,
                &[closed.clone(), sibling],
                false,
            ),
            ClaimLineage::Proven
        );
        // A row that reached the sts step but recorded no provenance: its
        // claims could exist anywhere after that step, so an OUT-of-window
        // claim is unprovable — fail closed, not foreign.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T11:00:00Z"),
                None,
                std::slice::from_ref(&closed),
                true,
            ),
            ClaimLineage::Unproven
        );
        // Same flag, but the claim sits INSIDE a proven closed window:
        // the window's evidence decides — proven.
        assert_eq!(
            classify_claim_lineage(
                &k8s_time("2026-10-14T10:00:05Z"),
                None,
                std::slice::from_ref(&closed),
                true,
            ),
            ClaimLineage::Proven
        );
    }

    #[test]
    fn initial_ownership_treats_pre_delete_absence_and_errors_as_not_ours() {
        let generation = enclava_engine::apply::generation::MutationGeneration::new(7)
            .expect("valid generation");
        // The round-3 regression: an initial 404 must NOT read as
        // ConfirmedAbsent — this generation never published the namespace or
        // its routes, so route removal against the shared HAProxy ConfigMap
        // must be skipped (NotOurs), not run.
        assert!(matches!(
            classify_initial_namespace_get(&Err(api_error(404)), generation),
            InitialNamespaceOwnership::AbsentBeforeDelete
        ));
        // Any non-404 inspect failure is equally undecided ownership.
        assert!(matches!(
            classify_initial_namespace_get(&Err(api_error(500)), generation),
            InitialNamespaceOwnership::Uninspectable
        ));
        assert!(matches!(
            classify_initial_namespace_get(
                &Err(kube::Error::Service("transport unavailable".into())),
                generation
            ),
            InitialNamespaceOwnership::Uninspectable
        ));
    }
}
