//! Projection queries backing CAP's internal `/internal/paas/*` endpoints.
//!
//! These shapes are PaaS-specific (field selection, ordering, and wrappers
//! differ from the public route projections): each consumer is an
//! `enclava-paas` server module that translates or forwards the response.
//! Route handlers keep JSON shaping; only the SQL lives here.

use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub struct PaaSAppRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub domain: String,
    pub tee_domain: Option<String>,
}

/// Apps of one CAP org, newest first, for the enclava-paas
/// `proxy_cap_apps` read proxy (`GET /internal/paas/orgs/{id}/apps`).
pub async fn list_paas_org_apps_pool(
    pool: &PgPool,
    cap_org_id: Uuid,
) -> Result<Vec<PaaSAppRow>, sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT id,
               name,
               status::text AS status,
               domain,
               tee_domain
          FROM apps
         WHERE org_id = $1
         ORDER BY created_at DESC, id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(pool)
    .await
}

#[derive(sqlx::FromRow)]
pub struct PaaSMemberRow {
    pub user_id: Uuid,
    pub display_name: String,
    pub role: String,
    pub active: bool,
}

/// Memberships (including removed) of one CAP org for the enclava-paas
/// `proxy_cap_members` read proxy (`GET /internal/paas/orgs/{id}/members`).
pub async fn list_paas_org_members_pool(
    pool: &PgPool,
    cap_org_id: Uuid,
) -> Result<Vec<PaaSMemberRow>, sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT u.id AS user_id,
               u.display_name,
               m.role::text AS role,
               m.removed_at IS NULL AS active
          FROM memberships m
          JOIN users u ON u.id = m.user_id
         WHERE m.org_id = $1
         ORDER BY u.display_name, u.id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(pool)
    .await
}

#[derive(sqlx::FromRow)]
pub struct PaaSDeploymentRow {
    pub deployment_id: Uuid,
    pub app_id: Uuid,
    pub app_name: String,
    pub status: String,
    pub spec_snapshot: serde_json::Value,
    pub image_digest: Option<String>,
    pub error_message: Option<String>,
}

/// Deployments of one CAP org, newest first, for the enclava-paas
/// `proxy_cap_deployments` read proxy
/// (`GET /internal/paas/orgs/{id}/deployments`).
pub async fn list_paas_org_deployments_pool(
    pool: &PgPool,
    cap_org_id: Uuid,
) -> Result<Vec<PaaSDeploymentRow>, sqlx::Error> {
    sqlx::query_as(
        r#"
        SELECT d.id AS deployment_id,
               d.app_id,
               a.name AS app_name,
               d.status::text AS status,
               d.spec_snapshot,
               d.image_digest,
               d.error_message
          FROM deployments d
          JOIN apps a ON a.id = d.app_id
         WHERE d.org_id = $1
         ORDER BY d.created_at DESC, d.id
        "#,
    )
    .bind(cap_org_id)
    .fetch_all(pool)
    .await
}

#[derive(sqlx::FromRow)]
pub struct PaaSStatusRow {
    pub app_id: Uuid,
    pub app_name: String,
    pub namespace: String,
    pub app_status: String,
    pub domain: String,
    pub tee_domain: Option<String>,
    pub deployment_id: Option<Uuid>,
    pub deployment_status: Option<String>,
    pub image_digest: Option<String>,
    pub error_message: Option<String>,
}

/// The latest-deployment subquery shared by the org-scoped and cluster-wide
/// status projections: the deployment of record is the one owned by the
/// newest apply generation, else the most recently created row.
const LATEST_DEPLOYMENT_LATERAL: &str = "
          LEFT JOIN LATERAL (
              SELECT d.id,
                     d.status::text AS status,
                     d.image_digest,
                     d.error_message
                FROM deployments d
                LEFT JOIN deployment_apply_jobs apply_job
                  ON apply_job.deployment_id = d.id
               WHERE d.app_id = a.id
               ORDER BY (apply_job.generation IS NOT NULL) DESC,
                        apply_job.generation DESC NULLS LAST,
                        d.created_at DESC,
                        d.id DESC
               LIMIT 1
          ) latest ON TRUE";

/// Apps of one CAP org with their latest deployment, newest app first, for
/// the enclava-paas `fetch_cluster_org_inventory` /
/// `proxy_cap_status` callers (`GET /internal/paas/orgs/{id}/status`).
/// Live observation is layered on by the route, not here.
pub async fn list_paas_org_status_pool(
    pool: &PgPool,
    cap_org_id: Uuid,
) -> Result<Vec<PaaSStatusRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"
        SELECT a.id AS app_id,
               a.name AS app_name,
               a.namespace,
               a.status::text AS app_status,
               a.domain,
               a.tee_domain,
               latest.id AS deployment_id,
               latest.status AS deployment_status,
               latest.image_digest,
               latest.error_message
          FROM apps a
          {LATEST_DEPLOYMENT_LATERAL}
         WHERE a.org_id = $1
         ORDER BY a.created_at DESC, a.id
        "#
    ))
    .bind(cap_org_id)
    .fetch_all(pool)
    .await
}

#[derive(sqlx::FromRow)]
pub struct PaaSClusterStatusRow {
    pub paas_org_id: String,
    pub cap_org_id: Uuid,
    pub cap_org_name: String,
    pub cap_org_display_name: Option<String>,
    pub app_id: Uuid,
    pub app_name: String,
    pub namespace: String,
    pub app_status: String,
    pub domain: String,
    pub tee_domain: Option<String>,
    pub deployment_id: Option<Uuid>,
    pub deployment_status: Option<String>,
    pub image_digest: Option<String>,
    pub error_message: Option<String>,
}

/// Every PaaS-mapped org's apps with their latest deployment, newest app
/// first, for the enclava-paas `fetch_global_cluster_inventory` caller
/// (`GET /internal/paas/status`). Live observation is layered on by the
/// route, not here.
pub async fn list_paas_cluster_status_pool(
    pool: &PgPool,
) -> Result<Vec<PaaSClusterStatusRow>, sqlx::Error> {
    sqlx::query_as(&format!(
        r#"
        SELECT m.paas_external_id AS paas_org_id,
               o.id AS cap_org_id,
               o.name AS cap_org_name,
               o.display_name AS cap_org_display_name,
               a.id AS app_id,
               a.name AS app_name,
               a.namespace,
               a.status::text AS app_status,
               a.domain,
               a.tee_domain,
               latest.id AS deployment_id,
               latest.status AS deployment_status,
               latest.image_digest,
               latest.error_message
          FROM apps a
          JOIN organizations o ON o.id = a.org_id
          JOIN paas_external_mappings m
            ON m.org_id = o.id
           AND m.resource_type = 'organization'
          {LATEST_DEPLOYMENT_LATERAL}
         ORDER BY a.created_at DESC, a.id
        "#
    ))
    .fetch_all(pool)
    .await
}
