//! One-shot operator tool: cut existing apps over to the D1 two-hostname
//! model.
//!
//! For every row in `apps`:
//!   - Compute the new `<app>.<orgSlug>.<platform_domain>` and
//!     `<app>.<orgSlug>.<tee_domain_suffix>`.
//!   - Idempotently create the A/AAAA records in Cloudflare (skip if a row
//!     already exists in `dns_records`).
//!   - Idempotently insert HAProxy SNI map entries for both hostnames.
//!   - Update the `apps.domain` and `apps.tee_domain` columns to the new
//!     hostnames.
//!
//! Old hostnames are NOT removed — operators are expected to keep them
//! live for one release cycle and remove via a follow-up cleanup tool
//! once clients have migrated.
//!
//! Usage: `cargo run -p enclava-api --bin migrate-two-hostnames`
//!
//! Env: DATABASE_URL, PLATFORM_DOMAIN, TEE_DOMAIN_SUFFIX,
//!      CLOUDFLARE_API_TOKEN, TENANT_DNS_TARGET, CLOUDFLARE_ZONE_NAME.

use enclava_api::dns::DnsConfig;
use enclava_api::edge::{
    BackendTag, EdgeRouteConfig, SniRoute, backend_name_for, ensure_haproxy_routes,
};
use enclava_api::models::App;
use enclava_engine::types::AttestationConfig;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
struct AppRow {
    id: Uuid,
    name: String,
    namespace: String,
    domain: String,
    tee_domain: Option<String>,
    cust_slug: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")?;
    let platform_domain =
        std::env::var("PLATFORM_DOMAIN").unwrap_or_else(|_| "enclava.dev".to_string());
    let tee_domain_suffix =
        std::env::var("TEE_DOMAIN_SUFFIX").unwrap_or_else(|_| format!("tee.{platform_domain}"));

    let pool = PgPool::connect(&database_url).await?;
    let http = reqwest::Client::new();

    let dns = match (
        std::env::var("CLOUDFLARE_API_TOKEN"),
        std::env::var("TENANT_DNS_TARGET"),
    ) {
        (Ok(t), Ok(target)) if !t.is_empty() && !target.is_empty() => Some(DnsConfig {
            cloudflare_api_token: t,
            cloudflare_zone_id: std::env::var("CLOUDFLARE_ZONE_ID")
                .ok()
                .filter(|v| !v.is_empty()),
            cloudflare_zone_name: std::env::var("CLOUDFLARE_ZONE_NAME")
                .unwrap_or_else(|_| platform_domain.clone()),
            target,
            required: true,
        }),
        _ => {
            tracing::warn!("CLOUDFLARE_API_TOKEN/TENANT_DNS_TARGET not set; running DRY-RUN");
            None
        }
    };

    let edge = EdgeRouteConfig::from_env();

    let rows: Vec<AppRow> = sqlx::query_as(
        "SELECT a.id, a.name, a.namespace, a.domain, a.tee_domain, o.cust_slug
         FROM apps a JOIN organizations o ON o.id = a.org_id
         ORDER BY a.created_at ASC",
    )
    .fetch_all(&pool)
    .await?;

    tracing::info!(count = rows.len(), "iterating apps");

    let attestation = load_attestation_for_migration();
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost".to_string());
    let api_signing_pubkey = std::env::var("API_SIGNING_PUBKEY_BASE64").unwrap_or_default();

    let mut succeeded: u64 = 0;
    let mut failed: u64 = 0;

    for app in rows {
        let app_host =
            enclava_common::hostnames::app_hostname(&app.name, &app.cust_slug, &platform_domain)?;
        let tee_host =
            enclava_common::hostnames::tee_hostname(&app.name, &app.cust_slug, &tee_domain_suffix)?;

        tracing::info!(app = %app.name, app_host, tee_host, "migrating");

        if let Some(cfg) = dns.as_ref() {
            // Idempotent: ensure_dns_record updates existing row by hostname.
            enclava_api::dns::ensure_dns_record(&pool, &http, Some(cfg), app.id, &app_host, false)
                .await?;
            enclava_api::dns::ensure_dns_record(&pool, &http, Some(cfg), app.id, &tee_host, false)
                .await?;
        }

        // HAProxy: insert (idempotent) two SNI entries.
        let app_target =
            enclava_api::edge::resolve_backend_target(&app.name, &app.namespace, 443).await?;
        let tee_target =
            enclava_api::edge::resolve_backend_target(&app.name, &app.namespace, 8081).await?;
        let app_backend = backend_name_for(&app.cust_slug, &app.name, BackendTag::App)?;
        let tee_backend = backend_name_for(&app.cust_slug, &app.name, BackendTag::Tee)?;
        let routes = vec![
            SniRoute::new(&app_host, &app_backend, &app_target)?,
            SniRoute::new(&tee_host, &tee_backend, &tee_target)?,
        ];
        ensure_haproxy_routes(&pool, &edge, &routes).await?;

        // Update DB row to point at the new hostnames.
        sqlx::query(
            "UPDATE apps SET domain = $1, tee_domain = $2, updated_at = now() WHERE id = $3",
        )
        .bind(&app_host)
        .bind(&tee_host)
        .bind(app.id)
        .execute(&pool)
        .await?;

        if app.domain != app_host {
            tracing::info!(old = %app.domain, new = %app_host, "rewrote app.domain");
        }
        if app.tee_domain.as_deref() != Some(tee_host.as_str()) {
            tracing::info!(new = %tee_host, "set app.tee_domain");
        }

        // Re-render and SSA-apply the tenant-ingress ConfigMap so Caddy serves
        // the new hostname pair. The helper also restarts the tenant
        // StatefulSet and waits for the replacement pod to become ready.
        match attestation.as_ref() {
            Some(att) => {
                match reapply_one(&pool, app.id, att, &api_signing_pubkey, &api_url).await {
                    Ok(()) => {
                        succeeded += 1;
                    }
                    Err(e) => {
                        failed += 1;
                        tracing::error!(
                            app_id = %app.id,
                            app = %app.name,
                            error = %e,
                            "failed to re-render tenant ingress; redeploy this app manually"
                        );
                    }
                }
            }
            None => {
                failed += 1;
                tracing::error!(
                    app = %app.name,
                    "ATTESTATION_PROXY_IMAGE/CADDY_INGRESS_IMAGE unset; tenant ingress NOT regenerated"
                );
            }
        }
    }

    tracing::info!(succeeded, failed, "done");
    if failed > 0 {
        std::process::exit(2);
    }
    Ok(())
}

fn load_attestation_for_migration() -> Option<AttestationConfig> {
    use enclava_common::image::ImageRef;

    let proxy = std::env::var("ATTESTATION_PROXY_IMAGE").ok()?;
    let caddy = std::env::var("CADDY_INGRESS_IMAGE").ok()?;
    let proxy_image = ImageRef::parse(&proxy).ok()?;
    let caddy_image = ImageRef::parse(&caddy).ok()?;
    proxy_image.require_digest().ok()?;
    caddy_image.require_digest().ok()?;
    Some(AttestationConfig {
        proxy_image,
        caddy_image,
        acme_ca_url: std::env::var("TENANT_CADDY_ACME_CA")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(enclava_engine::types::default_acme_ca_url),
        trustee_policy_read_available: false,
        workload_artifacts_url: None,
        trustee_policy_url: None,
        local_workload_artifacts_json: None,
        local_trustee_policy_json: None,
        platform_trustee_policy_pubkey_hex: None,
        signing_service_pubkey_hex: None,
    })
}

async fn reapply_one(
    pool: &PgPool,
    app_id: Uuid,
    attestation: &AttestationConfig,
    api_signing_pubkey: &str,
    api_url: &str,
) -> anyhow::Result<()> {
    let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(pool)
        .await?;
    enclava_api::deploy::reapply_tenant_ingress(
        pool,
        &app,
        Some(attestation),
        api_signing_pubkey,
        api_url,
    )
    .await?;
    Ok(())
}
