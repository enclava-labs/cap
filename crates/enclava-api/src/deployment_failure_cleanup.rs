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
    // sensitive object; its name comes from the same env-derived default
    // as `deploy.rs`.
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

/// Bound a single sweep read. Returns Err on both transport failure and
/// deadline expiry: both mean the target's state is undecidable within the
/// sweep's budget.
async fn bounded_sweep_read<F, T>(future: F) -> Result<T, kube::Error>
where
    F: std::future::Future<Output = Result<T, kube::Error>>,
{
    match tokio::time::timeout(SWEEP_READ_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err(kube::Error::Service(
            "adopted-namespace sweep read exceeded its 30s per-request budget".into(),
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
    app: &App,
    generation: enclava_engine::apply::generation::MutationGeneration,
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
        for attempt in 0..SWEEP_DELETE_RETRIES {
            let live = match bounded_sweep_read(api.get_opt(&target.name)).await {
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
                break; // never created, or already deleted
            };
            if !is_cap_created_generation_leftover(&live.metadata, generation.get()) {
                // Foreign (no creation evidence — includes objects CAP
                // merely SSA-patched), or a newer generation's publication:
                // never delete on name alone.
                tracing::info!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    kind = target.kind,
                    name = %target.name,
                    "adopted-namespace sweep skips object not created by a CAP failed apply"
                );
                break;
            }
            let preconditions = kube::api::Preconditions {
                uid: live.metadata.uid.clone(),
                resource_version: live.metadata.resource_version.clone(),
            };
            match api
                .delete(
                    &target.name,
                    &kube::api::DeleteParams {
                        preconditions: Some(preconditions),
                        ..kube::api::DeleteParams::default()
                    },
                )
                .await
            {
                Ok(_) => {
                    deleted = true;
                    break;
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
            failures += sweep_statefulset_pvcs(&client, &app.namespace, &target.name).await;
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
fn is_cap_created_generation_leftover(
    metadata: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
    failed_generation: i64,
) -> bool {
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
    let live_generation =
        annotation(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION);
    created_by > 0 && live_generation.is_some_and(|live| live > 0 && live <= failed_generation)
}

/// Bounded re-read retry budget for preconditioned sweep deletes.
const SWEEP_DELETE_RETRIES: usize = 3;

/// Delete the PVCs this failed generation's StatefulSet created in an
/// adopted namespace. Only claims whose name matches the exact
/// `<vct>-<statefulset>-<ordinal>` shape for a CAP-rendered VCT name are
/// deleted, with UID/resourceVersion preconditions. PVCs created by the
/// Kubernetes StatefulSet controller from `spec.volumeClaimTemplates`
/// never carry CAP annotations (VCT metadata is immutable — adding the
/// annotation would break every redeploy of an existing StatefulSet with
/// 422), so ownership is derived from the claim-name shape after the
/// StatefulSet itself was proven CAP-created and deleted by this sweep.
/// A pre-existing unannotated claim — including one from a foreign
/// StatefulSet with the same name — is never touched.
pub(crate) async fn sweep_statefulset_pvcs(
    client: &kube::Client,
    namespace: &str,
    statefulset: &str,
) -> usize {
    const CAP_VCT_NAMES: [&str; 2] = ["state", "tls-state"];
    let api: kube::Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
        kube::Api::namespaced(client.clone(), namespace);
    let list = match bounded_sweep_read(api.list(&kube::api::ListParams::default())).await {
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
    let mut failures = 0usize;
    for pvc in list.items {
        let Some(name) = pvc.metadata.name.clone() else {
            continue;
        };
        if !is_cap_claim_name(&name, statefulset, &CAP_VCT_NAMES) {
            continue;
        }
        let preconditions = kube::api::Preconditions {
            uid: pvc.metadata.uid.clone(),
            resource_version: pvc.metadata.resource_version.clone(),
        };
        if let Err(error) = api
            .delete(
                &name,
                &kube::api::DeleteParams {
                    preconditions: Some(preconditions),
                    ..kube::api::DeleteParams::default()
                },
            )
            .await
        {
            if matches!(&error, kube::Error::Api(error) if error.code == 404) {
                // Already gone: successful cleanup, not a failure.
                continue;
            }
            tracing::warn!(
                namespace = %namespace,
                pvc = %name,
                error = %error,
                "adopted-namespace sweep could not delete this generation's PVC; will retry via reconciliation"
            );
            failures += 1;
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
    /// Nothing this generation owns: the live namespace carries another
    /// generation's (or no) mutation annotation, or it could not even be
    /// inspected. No delete was issued through this path.
    NotOurs,
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
    let teardown = match mutation
        .guard_provider(delete_failed_generation_namespace(
            app,
            namespace_generation,
        ))
        .await
    {
        Ok(outcome) => outcome,
        Err(error) => {
            // Lease heartbeat lost with the provider state uncertain: fail
            // closed on the namespace fence.
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply namespace cleanup lost its mutation lease; retaining the namespace fence for reconciliation"
            );
            return CleanupFenceOutcome::RetainNamespaceFence;
        }
    };

    if matches!(teardown, NamespaceTeardown::NotOurs) {
        tracing::info!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed apply never owned the live namespace; skipping route removal"
        );
        return CleanupFenceOutcome::ReleaseNormally;
    }

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
            if let Err(error) = sqlx::query(
                "UPDATE deployments
                 SET manifest_hash = NULL, observing_since = NULL
                 WHERE id = $1 AND app_id = $2 AND status = 'failed'",
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
        NamespaceTeardown::AdoptedIncomplete => {
            // Evidence kept (storage guard + ownership gates), fences
            // release: the namespace was never CAP's, so the
            // retained-fence reconciler (which requires a namespace 404)
            // would never release a retained fence here.
            CleanupFenceOutcome::ReleaseNormally
        }
        NamespaceTeardown::DeleteIncomplete => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply namespace deletion is not confirmed complete; retaining the pre-armed namespace fence for reconciliation"
            );
            CleanupFenceOutcome::RetainNamespaceFence
        }
        NamespaceTeardown::NotOurs => unreachable!("handled above"),
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
        "SELECT NOT EXISTS (
             SELECT 1 FROM deployments
              WHERE app_id = $1
                AND id <> $2
                AND (
                    manifest_hash IS NOT NULL
                    OR observing_since IS NOT NULL
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
enum InitialNamespaceOwnership {
    /// Live object carries this generation's annotation AND creation
    /// evidence (`enclava.dev/cap-namespace-created-by-generation`): CAP
    /// created it and this generation was the last writer — safe to delete.
    /// Carries the exact UID/resourceVersion of the object that passed the
    /// ownership check: the DELETE must target THAT object, never whatever
    /// a fresh GET would return (a same-named replacement would sail
    /// through the annotation checks as generation zero).
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

fn classify_initial_namespace_get(
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
                let created_by_cap = annotations
                    .and_then(|annotations| {
                        annotations
                            .get(enclava_engine::apply::generation::NAMESPACE_CREATED_BY_ANNOTATION)
                    })
                    .and_then(|raw| raw.parse::<i64>().ok())
                    .is_some_and(|value| value > 0);
                if !created_by_cap {
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

/// Delete the failed generation's namespace — which removes the image-pull
/// secret, network policy, Gateway API resources, and StatefulSet with it —
/// but only when the live namespace carries this exact generation's
/// mutation-generation annotation. `delete_resource` alone would accept any
/// live generation <= ours (a missing annotation counts as 0), which could
/// destroy a namespace another generation created; the exact-annotation check
/// closes that, and it doubles as the proof this generation itself ran
/// `apply_namespace` (the deployment row's `manifest_hash` is written before
/// any provider call and proves nothing).
///
/// A 404 before any delete is issued is [`NamespaceTeardown::NotOurs`]: the
/// generation never published the namespace (a pre-publish failure), so it
/// never published routes either, and the caller must not touch the shared
/// HAProxy ConfigMap. Once a delete is issued under a proven-owning GET, the
/// bounded convergence wait must observe 404; otherwise the outcome is
/// `DeleteIncomplete` and the caller retains the pre-armed fence (fail
/// closed, mirroring app delete) rather than converting it to the bounded
/// reclaim quarantine while the namespace may still be Terminating.
async fn delete_failed_generation_namespace(
    app: &App,
    generation: enclava_engine::apply::generation::MutationGeneration,
) -> NamespaceTeardown {
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
            return NamespaceTeardown::NotOurs;
        }
    };
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);

    let (owned_uid, owned_resource_version) = match classify_initial_namespace_get(
        &api.get(&app.namespace).await,
        generation,
    ) {
        InitialNamespaceOwnership::Owned {
            uid,
            resource_version,
        } => (uid, resource_version),
        InitialNamespaceOwnership::AbsentBeforeDelete => {
            tracing::info!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply cleanup found no live namespace before any delete; this generation never published it (or its routes)"
            );
            return NamespaceTeardown::NotOurs;
        }
        InitialNamespaceOwnership::Adopted => {
            // Pre-existing namespace this apply adopted: not CAP's to
            // destroy. Delete only the objects this generation published
            // (generation-gated), then compensate routes; fences release
            // normally because the namespace outlives the failed
            // generation.
            tracing::info!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply cleanup sweeps published objects from adopted namespace (no creation evidence; namespace not deleted)"
            );
            let failures = sweep_published_objects_from_adopted_namespace(app, generation).await;
            if failures > 0 {
                // Incomplete sweep. The namespace fence must NOT be
                // retained: the retained-fence reconciler releases only on
                // an observed namespace 404, which never happens for an
                // adopted namespace — retaining would reintroduce the
                // permanent-Busy bug this change fixes. Leftovers converge
                // deterministically instead: the next apply of this app
                // SSA-overwrites every swept name with a newer generation,
                // and app deletion tears down whatever remains.
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    failures,
                    error_code = "adopted_namespace_sweep_incomplete",
                    "adopted-namespace sweep left objects behind; the next apply or app deletion converges them"
                );
                return NamespaceTeardown::AdoptedIncomplete;
            }
            return NamespaceTeardown::Adopted;
        }
        InitialNamespaceOwnership::Foreign => {
            // The namespace was created or last written by another
            // generation (or predates generation annotations): it is not
            // this apply's partial state. Leave it alone.
            tracing::info!(
                app_id = %app.id,
                namespace = %app.namespace,
                expected_generation = generation.get(),
                "failed-apply cleanup skips namespace: it does not carry this generation's mutation annotation"
            );
            return NamespaceTeardown::NotOurs;
        }
        InitialNamespaceOwnership::Uninspectable => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                "failed-apply cleanup cannot inspect the namespace; skipping deletion"
            );
            // No delete issued through this path.
            return NamespaceTeardown::NotOurs;
        }
    };

    // The DELETE carries the UID/resourceVersion of the EXACT object that
    // passed the ownership classification above — not whatever a fresh GET
    // inside a generic delete helper would return. If an external actor
    // deletes the CAP-owned namespace and recreates a foreign same-named
    // one between our reads, the stale resourceVersion precondition fails
    // with 409 instead of authorizing deletion of the replacement.
    let deleted = match api
        .delete(
            &app.namespace,
            &kube::api::DeleteParams {
                preconditions: Some(kube::api::Preconditions {
                    uid: Some(owned_uid),
                    resource_version: Some(owned_resource_version),
                }),
                ..kube::api::DeleteParams::default()
            },
        )
        .await
    {
        Ok(_) => true,
        Err(kube::Error::Api(error)) if error.code == 404 => {
            // Vanished between the owning GET and the delete: complete.
            false
        }
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply namespace deletion failed; retaining the namespace fence for reconciliation"
            );
            // The delete request may have reached the API server
            // before the error surfaced: treat as incomplete.
            return NamespaceTeardown::DeleteIncomplete;
        }
    };
    if !deleted {
        // Vanished between get and delete: complete.
        return NamespaceTeardown::ConfirmedAbsent;
    }
    // The delete was accepted. Bound the convergence wait; if it
    // elapses without a 404 the caller must retain the fence. Each
    // GET is itself bounded by the remaining deadline: a stalled
    // API server must not hold this apply's shared fences past the
    // advertised convergence budget via the client's ~295s read
    // timeout.
    let deadline = tokio::time::Instant::now() + NAMESPACE_CONVERGENCE_TIMEOUT;
    loop {
        match tokio::time::timeout_at(deadline, api.get(&app.namespace)).await {
            Ok(Err(kube::Error::Api(error))) if error.code == 404 => {
                return NamespaceTeardown::ConfirmedAbsent;
            }
            Ok(Ok(_)) => {
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
        k8s_openapi::api::core::v1::Namespace {
            metadata: k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                annotations: Some(annotations),
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

    fn object_meta_with_annotations(
        pairs: &[(&str, i64)],
    ) -> k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
        let annotations = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
            annotations: Some(annotations),
            ..Default::default()
        }
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
            &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta::default(),
            7
        ));
        // Creation evidence alone with an unparseable mutation annotation:
        // undecidable last-writer, skip.
        assert!(!is_cap_created_generation_leftover(
            &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta {
                annotations: Some(std::collections::BTreeMap::from([
                    (
                        generation_annotations::RESOURCE_CREATED_BY_ANNOTATION.to_string(),
                        "7".to_string()
                    ),
                    (
                        generation_annotations::MUTATION_GENERATION_ANNOTATION.to_string(),
                        "junk".to_string()
                    ),
                ])),
                ..Default::default()
            },
            7
        ));
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
