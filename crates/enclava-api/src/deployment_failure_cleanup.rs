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
//!   StatefulSet). Deleting the namespace is sufficient cleanup: every object
//!   the apply creates is namespaced and dies with it.
//!
//! Cleanup is strictly conservative. It runs only when durable evidence says
//! this failed generation itself published provider state (`manifest_hash`)
//! and no OTHER generation of the app ever did — a superseded `watching`
//! predecessor that already applied manifests keeps its namespace (and its
//! PVCs, whose StatefulSet retention the namespace cascade would bypass) and
//! its shared generation-independent routes. Namespace deletion additionally
//! requires the live namespace to carry this exact generation's
//! mutation-generation annotation, so a namespace created or last written by
//! any other generation is never touched.
//!
//! Cleanup runs while the failing worker still owns the durable mutation
//! fences (`edge_config`, `kubernetes_namespace/<ns>`), under
//! `guard_provider`, so a concurrently accepted redeploy cannot mutate the
//! same providers until this worker releases them, and a lost lease heartbeat
//! cancels the provider calls the same way apply does. Every step is bounded
//! and best-effort: a failure or timeout is logged and the caller's bounded
//! reclaim quarantine retains the fences; the periodic reconcilers converge
//! the remainder. A crash before cleanup simply leaves the pre-existing
//! (slower) convergence behavior — never a worse one.

use uuid::Uuid;

use crate::models::App;
use crate::mutation_leases::{AppMutationLease, ResourceFence};
use crate::state::AppState;

/// Mirrors the app-delete namespace teardown envelope so the two loops cannot
/// drift: bounded convergence wait inside a hard bound over the whole
/// provider operation (inspect + delete + wait), fail-closed on timeout.
const NAMESPACE_CONVERGENCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const CLEANUP_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Best-effort compensating cleanup for a deployment whose apply failed
/// terminally. `app` is the immutable payload snapshot of the failed
/// generation; `mutation` still owns that generation's provider fences and is
/// released by the caller (through bounded reclaim quarantine) afterwards.
pub(crate) async fn cleanup_after_terminal_apply_failure(
    state: &AppState,
    app: &App,
    failed_deployment_id: Uuid,
    mutation: &AppMutationLease,
) {
    // Evidence gate: this generation must itself have published provider
    // state, and no other generation of this app may ever have. The failed
    // deployment's own row is excluded from the "other" check.
    match app_lifecycle_allows_cleanup(&state.db, app.id, failed_deployment_id).await {
        Ok(false) => {
            tracing::info!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                "skipping failed-apply compensating cleanup: another generation owns or previously owned the provider state"
            );
            return;
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
            return;
        }
    }

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

    if let Some(namespace_generation) =
        mutation.resource_generation(&ResourceFence::new("kubernetes_namespace", &app.namespace))
    {
        // `resource_generation` returns the raw durable i64; the provider
        // calls require a validated MutationGeneration.
        let namespace_generation = match enclava_engine::apply::generation::MutationGeneration::new(
            namespace_generation,
        ) {
            Ok(generation) => generation,
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply cleanup cannot validate kubernetes_namespace generation; skipping namespace deletion"
                );
                return;
            }
        };
        let deleted = mutation
            .guard_provider(delete_failed_generation_namespace(
                app,
                namespace_generation,
            ))
            .await;
        if let Err(error) = deleted {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply namespace cleanup did not complete under the mutation lease; the caller's bounded reclaim quarantine retains the fence for reconciliation"
            );
        }
    } else {
        tracing::info!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed-apply cleanup holds no kubernetes_namespace generation; skipping namespace deletion"
        );
    }
}

/// Cleanup may only run when BOTH hold:
///
/// * the failed deployment itself reached provider publication
///   (`manifest_hash` IS NOT NULL) — otherwise it created nothing and there
///   is nothing of its own to clean;
/// * no OTHER deployment of this app ever published provider state
///   (`manifest_hash` or `observing_since` set, or any non-failed status
///   including `rolled_back`), and the app is not being deleted.
///
/// The second condition deliberately treats a superseded `watching`/
/// `applying` predecessor — terminalized to `failed` by
/// `supersede_incomplete_deployments` — as still owning its namespace, PVCs,
/// and shared routes: its evidence columns remain set even though its status
/// flipped to `failed`, so this failed row cannot destroy another
/// generation's live data.
async fn app_lifecycle_allows_cleanup(
    pool: &sqlx::PgPool,
    app_id: Uuid,
    failed_deployment_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT
             -- this generation itself reached provider publication
             EXISTS (
                 SELECT 1 FROM deployments
                  WHERE id = $2 AND app_id = $1 AND manifest_hash IS NOT NULL
             )
             -- no other generation ever published provider state
             AND NOT EXISTS (
                 SELECT 1 FROM deployments
                  WHERE app_id = $1
                    AND id <> $2
                    AND (
                        manifest_hash IS NOT NULL
                        OR observing_since IS NOT NULL
                        OR status::text IN ('pending', 'applying', 'watching', 'healthy', 'rolled_back')
                    )
             )
             -- the app delete path owns teardown while deleting
             AND NOT EXISTS (
                 SELECT 1 FROM apps
                  WHERE id = $1 AND status = 'deleting'::app_status_enum
             )",
    )
    .bind(app_id)
    .bind(failed_deployment_id)
    .fetch_one(pool)
    .await
}

/// The SNI hostnames this generation's apply published, mirroring
/// `apply_deployment_manifests` exactly (including the TEE fallback to the
/// platform domain when `tee_domain` is null/empty, and the empty-custom-
/// domain skip) so cleanup can never diverge from what was published.
fn failed_generation_route_hosts(app: &App) -> Vec<(crate::edge::BackendTag, String)> {
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

/// Remove the SNI routes this failed generation's domains route through.
/// Backend names are generation-independent (derived from org/app slug), so
/// removal is only safe once the lifecycle precondition confirmed no other
/// generation ever published routes.
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
    for (tag, host) in failed_generation_route_hosts(app) {
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

/// Delete the failed generation's namespace — which removes the image-pull
/// secret, network policy, Gateway API resources, and StatefulSet with it —
/// but only when the live namespace carries this exact generation's
/// mutation-generation annotation. `delete_resource` alone would accept any
/// live generation <= ours (a missing annotation counts as 0), which could
/// destroy a namespace another generation created; the exact-annotation check
/// closes that. Absence (404) is success. The whole operation is bounded and
/// fails closed, mirroring the app-delete teardown envelope.
async fn delete_failed_generation_namespace(
    app: &App,
    generation: enclava_engine::apply::generation::MutationGeneration,
) {
    let client = match kube::Client::try_default().await {
        Ok(client) => client,
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply cleanup cannot reach Kubernetes; skipping namespace deletion"
            );
            return;
        }
    };
    let api: kube::Api<k8s_openapi::api::core::v1::Namespace> = kube::Api::all(client);

    let delete_and_wait = async {
        match api.get(&app.namespace).await {
            Ok(namespace) => {
                let live = namespace
                    .metadata
                    .annotations
                    .as_ref()
                    .and_then(|annotations| {
                        annotations
                            .get(enclava_engine::apply::generation::MUTATION_GENERATION_ANNOTATION)
                    })
                    .and_then(|raw| raw.parse::<i64>().ok());
                if live != Some(generation.get()) {
                    // The namespace was created or last written by another
                    // generation (or predates generation annotations): it is
                    // not this apply's partial state. Leave it alone.
                    tracing::info!(
                        app_id = %app.id,
                        namespace = %app.namespace,
                        expected_generation = generation.get(),
                        live_generation = ?live,
                        "failed-apply cleanup skips namespace: it does not carry this generation's mutation annotation"
                    );
                    return;
                }
                let deleted = match enclava_engine::apply::generation::delete_resource(
                    &api,
                    &app.namespace,
                    generation,
                    kube::api::DeleteParams::default(),
                )
                .await
                {
                    Ok(deleted) => deleted,
                    Err(error) => {
                        tracing::warn!(
                            app_id = %app.id,
                            namespace = %app.namespace,
                            error = %error,
                            "failed-apply namespace deletion failed; reconciliation will converge"
                        );
                        return;
                    }
                };
                if !deleted {
                    return;
                }
                let deadline = tokio::time::Instant::now() + NAMESPACE_CONVERGENCE_TIMEOUT;
                loop {
                    match api.get(&app.namespace).await {
                        Err(kube::Error::Api(error)) if error.code == 404 => return,
                        Ok(_) if tokio::time::Instant::now() < deadline => {
                            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        }
                        Ok(_) => {
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                "failed-apply namespace deletion did not converge within the bounded wait; reconciliation will finish it"
                            );
                            return;
                        }
                        Err(error) => {
                            tracing::warn!(
                                app_id = %app.id,
                                namespace = %app.namespace,
                                error = %error,
                                "failed-apply namespace deletion wait failed; reconciliation will finish it"
                            );
                            return;
                        }
                    }
                }
            }
            Err(kube::Error::Api(error)) if error.code == 404 => {
                // Already absent: nothing this apply left behind.
            }
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply cleanup cannot inspect the namespace; skipping deletion"
                );
            }
        }
    };

    // Bound the entire provider operation so this path fails closed (the
    // caller's bounded reclaim quarantine then retains the namespace fence)
    // instead of pinning the worker and its fences indefinitely.
    if tokio::time::timeout(CLEANUP_OPERATION_TIMEOUT, delete_and_wait)
        .await
        .is_err()
    {
        tracing::warn!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed-apply namespace cleanup exceeded its operation budget; the caller's bounded reclaim quarantine retains the fence for reconciliation"
        );
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
    async fn published_failed_apply_allows_cleanup_when_no_other_generation_exists() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", Some("abc123"), false).await;

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            allowed,
            "a failed apply that published manifests, with no other generation, must allow compensating cleanup"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn unpublished_failed_apply_skips_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        // Failed before any manifest hash was recorded (e.g. validation or
        // KBS failure before apply_namespace): it created nothing.
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", None, false).await;

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a failed apply that never published must not run provider cleanup"
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

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
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

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a newer watching generation must not have its namespace deleted underneath it"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn superseded_watching_predecessor_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        // The critical regression from review: a predecessor that reached
        // `watching` (namespace, PVCs, and routes published) and was then
        // terminalized to `failed` by supersede_incomplete_deployments when a
        // newer generation was accepted. Its status is `failed` but its
        // manifest_hash/observing_since evidence remains.
        let predecessor_id = Uuid::new_v4();
        insert_cleanup_deployment(
            &pool,
            app_id,
            predecessor_id,
            "failed",
            Some("old-gen"),
            true,
        )
        .await;
        // The newer generation fails before publishing anything.
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed", None, false).await;

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            !allowed,
            "a superseded watching predecessor (failed but published) keeps its namespace, PVCs, and routes"
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

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
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

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
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

        let hosts = failed_generation_route_hosts(&app);
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
}
