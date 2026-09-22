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
//! Cleanup runs while the failing worker still owns the durable mutation
//! fences (`edge_config`, `kubernetes_namespace/<ns>`), so a concurrently
//! accepted redeploy cannot mutate the same providers until this worker
//! releases them. It is strictly best-effort: a failure is logged and the
//! fences stay quarantined for operator/periodic reconciliation, and a crash
//! before cleanup simply leaves the pre-existing (slower) convergence
//! behavior — never a worse one.

use uuid::Uuid;

use crate::models::App;
use crate::mutation_leases::{AppMutationLease, ResourceFence};
use crate::state::AppState;

/// Every cleanup provider step is bounded so a wedged Kubernetes or edge
/// operation cannot pin the worker (and its mutation fences) indefinitely.
const CLEANUP_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// Best-effort compensating cleanup for a deployment whose apply failed
/// terminally. `app` is the immutable payload snapshot of the failed
/// generation; `mutation` still owns that generation's provider fences and is
/// released by the caller (through reclaim quarantine) afterwards.
pub(crate) async fn cleanup_after_terminal_apply_failure(
    state: &AppState,
    app: &App,
    failed_deployment_id: Uuid,
    mutation: &AppMutationLease,
) {
    // Skip cleanup entirely when a newer generation is in flight or the app is
    // being deleted: the namespace and routes may still belong to that other
    // generation, and the delete path performs its own bounded teardown.
    match app_lifecycle_allows_cleanup(&state.db, app.id, failed_deployment_id).await {
        Ok(false) => {
            tracing::info!(
                app_id = %app.id,
                deployment_id = %failed_deployment_id,
                "skipping failed-apply compensating cleanup: newer deployment activity owns the provider state"
            );
            return;
        }
        Ok(true) => {}
        Err(error) => {
            // Uncertain durable state: do not guess. The quarantined fences
            // keep the slower pre-existing convergence behavior.
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
        if let Err(error) = tokio::time::timeout(
            CLEANUP_STEP_TIMEOUT,
            remove_failed_generation_edge_routes(state, app, edge_config_generation),
        )
        .await
        {
            tracing::warn!(
                app_id = %app.id,
                error = %error,
                "failed-apply HAProxy route cleanup timed out; periodic edge reconciliation will converge"
            );
        }
    } else {
        tracing::warn!(
            app_id = %app.id,
            "failed-apply cleanup cannot determine edge_config generation; skipping route removal"
        );
    }

    if let Some(namespace_generation) =
        mutation.resource_generation(&ResourceFence::new("kubernetes_namespace", &app.namespace))
    {
        // `resource_generation` returns the raw durable i64; delete_resource
        // requires a validated MutationGeneration (rejects stale writers).
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
        if let Err(error) = tokio::time::timeout(
            CLEANUP_STEP_TIMEOUT,
            delete_failed_generation_namespace(app, namespace_generation),
        )
        .await
        {
            tracing::warn!(
                app_id = %app.id,
                namespace = %app.namespace,
                error = %error,
                "failed-apply namespace cleanup timed out; namespace fence remains quarantined for reconciliation"
            );
        }
    } else {
        tracing::warn!(
            app_id = %app.id,
            namespace = %app.namespace,
            "failed-apply cleanup cannot determine kubernetes_namespace generation; skipping namespace deletion"
        );
    }
}

/// Cleanup may only run when no *other* deployment of this app is active and
/// the app is not being deleted. The failed deployment itself is excluded.
async fn app_lifecycle_allows_cleanup(
    pool: &sqlx::PgPool,
    app_id: Uuid,
    failed_deployment_id: Uuid,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT NOT EXISTS (
             SELECT 1
               FROM deployments AS deployment
              WHERE deployment.app_id = $1
                AND deployment.id <> $2
                AND deployment.status::text IN ('pending', 'applying', 'watching', 'healthy')
         ) AND NOT EXISTS (
             SELECT 1 FROM apps WHERE id = $1 AND status = 'deleting'::app_status_enum
         )",
    )
    .bind(app_id)
    .bind(failed_deployment_id)
    .fetch_one(pool)
    .await
}

/// Remove the SNI routes this failed generation's domains route through.
/// Backend names are generation-independent (derived from org/app slug), so
/// removal is only safe once the lifecycle precondition confirmed no other
/// generation of this app owns traffic on them.
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

    let backends = (
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::App),
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::Tee),
    );
    let (Ok(app_backend), Ok(tee_backend)) = backends else {
        tracing::warn!(
            app_id = %app.id,
            "failed-apply cleanup cannot derive backend names; skipping route removal"
        );
        return;
    };

    let mut routes_to_remove = vec![(app_backend.clone(), app.domain.clone())];
    if let Some(tee_domain) = app.tee_domain.as_deref() {
        routes_to_remove.push((tee_backend.clone(), tee_domain.to_string()));
    }
    if let Some(custom_domain) = app.custom_domain.as_deref()
        && !custom_domain.is_empty()
    {
        routes_to_remove.push((app_backend.clone(), custom_domain.to_string()));
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
/// and wait bounded for the namespace to disappear, so a redeploy accepted
/// right after fence release never applies into a `Terminating` namespace.
/// Absence (404) is success.
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
                "failed-apply namespace deletion failed; namespace fence remains quarantined for reconciliation"
            );
            return;
        }
    };
    if !deleted {
        return;
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(120);
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
                    "failed-apply namespace deletion did not converge; fence remains quarantined for reconciliation"
                );
                return;
            }
            Err(error) => {
                tracing::warn!(
                    app_id = %app.id,
                    namespace = %app.namespace,
                    error = %error,
                    "failed-apply namespace deletion wait failed; fence remains quarantined for reconciliation"
                );
                return;
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
            "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
             VALUES ($1, $2, $3, $4::deploy_status_enum, '{}'::jsonb)",
        )
        .bind(deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(status)
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
    async fn failed_apply_allows_cleanup_when_no_other_generation_is_active() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed").await;

        let allowed = app_lifecycle_allows_cleanup(&pool, app_id, failed_id)
            .await
            .expect("check cleanup precondition");
        assert!(
            allowed,
            "a terminally failed apply with no other generation must allow compensating cleanup"
        );

        delete_cleanup_fixture(&pool, app_id).await;
    }

    #[tokio::test]
    async fn prior_healthy_generation_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed").await;
        insert_cleanup_deployment(&pool, app_id, Uuid::new_v4(), "healthy").await;

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
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed").await;
        insert_cleanup_deployment(&pool, app_id, Uuid::new_v4(), "watching").await;

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
    async fn deleting_app_blocks_cleanup() {
        let pool = cleanup_test_pool().await;
        let app_id = insert_cleanup_app_fixture(&pool).await;
        let failed_id = Uuid::new_v4();
        insert_cleanup_deployment(&pool, app_id, failed_id, "failed").await;
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
}
