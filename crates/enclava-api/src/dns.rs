use reqwest::StatusCode;
use serde::Deserialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub cloudflare_api_token: String,
    pub cloudflare_zone_id: Option<String>,
    pub cloudflare_zone_name: String,
    pub target: String,
    pub required: bool,
}

impl DnsConfig {
    pub fn record_type(&self) -> &'static str {
        if self.target.contains(':') {
            "AAAA"
        } else {
            "A"
        }
    }

    pub fn manages_hostname(&self, hostname: &str) -> bool {
        let zone = self
            .cloudflare_zone_name
            .trim_start_matches('.')
            .to_lowercase();
        let hostname = hostname.trim_end_matches('.').to_lowercase();
        hostname == zone || hostname.ends_with(&format!(".{zone}"))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS management is required but not configured")]
    NotConfigured,
    #[error("hostname '{0}' is outside managed Cloudflare zone")]
    OutsideManagedZone(String),
    #[error("hostname '{hostname}' is already assigned to another app")]
    HostnameInUse { hostname: String },
    #[error("Cloudflare API error: {0}")]
    Cloudflare(String),
    #[error("Cloudflare request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

#[derive(Debug, Deserialize)]
struct CloudflareList<T> {
    success: bool,
    result: Vec<T>,
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareSingle<T> {
    success: bool,
    result: Option<T>,
    errors: Vec<CloudflareApiError>,
}

#[derive(Debug, Deserialize)]
struct CloudflareApiError {
    code: Option<i64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareRecord {
    id: String,
}

fn cloudflare_error(errors: &[CloudflareApiError]) -> String {
    if errors.is_empty() {
        return "unknown error".to_string();
    }

    errors
        .iter()
        .map(|e| match e.code {
            Some(code) => format!("{code}: {}", e.message),
            None => e.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

async fn resolve_zone_id(client: &reqwest::Client, config: &DnsConfig) -> Result<String, DnsError> {
    if let Some(zone_id) = config.cloudflare_zone_id.as_ref() {
        return Ok(zone_id.clone());
    }

    let response = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            config.cloudflare_zone_name
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DnsError::Cloudflare(format!(
            "zone lookup returned HTTP {}",
            response.status()
        )));
    }

    let body: CloudflareList<CloudflareZone> = response.json().await?;
    if !body.success {
        return Err(DnsError::Cloudflare(cloudflare_error(&body.errors)));
    }

    body.result
        .into_iter()
        .next()
        .map(|zone| zone.id)
        .ok_or_else(|| {
            DnsError::Cloudflare(format!(
                "zone '{}' was not found",
                config.cloudflare_zone_name
            ))
        })
}

async fn find_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    hostname: &str,
) -> Result<Option<CloudflareRecord>, DnsError> {
    let record_type = config.record_type();
    let response = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={hostname}&per_page=100"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DnsError::Cloudflare(format!(
            "record lookup for '{hostname}' returned HTTP {}",
            response.status()
        )));
    }

    let body: CloudflareList<CloudflareRecord> = response.json().await?;
    if !body.success {
        return Err(DnsError::Cloudflare(cloudflare_error(&body.errors)));
    }

    Ok(body.result.into_iter().next())
}

async fn find_record_by_type(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    record_type: &str,
    hostname: &str,
) -> Result<Option<CloudflareRecord>, DnsError> {
    let response = client
        .get(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records?type={record_type}&name={hostname}&per_page=100"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(DnsError::Cloudflare(format!(
            "record lookup for '{hostname}' returned HTTP {}",
            response.status()
        )));
    }

    let body: CloudflareList<CloudflareRecord> = response.json().await?;
    if !body.success {
        return Err(DnsError::Cloudflare(cloudflare_error(&body.errors)));
    }

    Ok(body.result.into_iter().next())
}

async fn create_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    hostname: &str,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": config.record_type(),
            "name": hostname,
            "content": config.target,
            "ttl": 300,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "create record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("create record response had no result".to_string()))
}

async fn create_record_by_type(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    record_type: &str,
    hostname: &str,
    content: &str,
    ttl: u32,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .post(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": ttl,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "create record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("create record response had no result".to_string()))
}

async fn update_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    record_id: &str,
    hostname: &str,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .put(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": config.record_type(),
            "name": hostname,
            "content": config.target,
            "ttl": 300,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "update record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("update record response had no result".to_string()))
}

async fn update_record_by_type(
    client: &reqwest::Client,
    config: &DnsConfig,
    zone_id: &str,
    record_id: &str,
    record_type: &str,
    hostname: &str,
    content: &str,
    ttl: u32,
) -> Result<CloudflareRecord, DnsError> {
    let response = client
        .put(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .json(&serde_json::json!({
            "type": record_type,
            "name": hostname,
            "content": content,
            "ttl": ttl,
            "proxied": false,
        }))
        .send()
        .await?;

    let status = response.status();
    let body: CloudflareSingle<CloudflareRecord> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "update record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }

    body.result
        .ok_or_else(|| DnsError::Cloudflare("update record response had no result".to_string()))
}

pub async fn ensure_txt_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    hostname: &str,
    content: &str,
) -> Result<(), DnsError> {
    if !config.manages_hostname(hostname) {
        return Err(DnsError::OutsideManagedZone(hostname.to_string()));
    }
    let zone_id = resolve_zone_id(client, config).await?;
    let existing = find_record_by_type(client, config, &zone_id, "TXT", hostname).await?;
    match existing {
        Some(record) => {
            update_record_by_type(
                client, config, &zone_id, &record.id, "TXT", hostname, content, 60,
            )
            .await?;
        }
        None => {
            create_record_by_type(client, config, &zone_id, "TXT", hostname, content, 60).await?;
        }
    }
    Ok(())
}

pub async fn delete_txt_record(
    client: &reqwest::Client,
    config: &DnsConfig,
    hostname: &str,
    _content: &str,
) -> Result<(), DnsError> {
    if !config.manages_hostname(hostname) {
        return Err(DnsError::OutsideManagedZone(hostname.to_string()));
    }
    let zone_id = resolve_zone_id(client, config).await?;
    let Some(record) = find_record_by_type(client, config, &zone_id, "TXT", hostname).await? else {
        return Ok(());
    };
    let response = client
        .delete(format!(
            "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{}",
            record.id
        ))
        .bearer_auth(&config.cloudflare_api_token)
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND {
        return Ok(());
    }
    let status = response.status();
    let body: CloudflareSingle<serde_json::Value> = response.json().await?;
    if !status.is_success() || !body.success {
        return Err(DnsError::Cloudflare(format!(
            "delete record for '{hostname}' failed: {}",
            cloudflare_error(&body.errors)
        )));
    }
    Ok(())
}

pub async fn ensure_dns_record(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
    hostname: &str,
    is_custom: bool,
) -> Result<(), DnsError> {
    let Some(config) = config else {
        return Ok(());
    };

    if !config.manages_hostname(hostname) {
        return Err(DnsError::OutsideManagedZone(hostname.to_string()));
    }

    let zone_id = resolve_zone_id(client, config).await?;
    let existing = find_record(client, config, &zone_id, hostname).await?;
    let record = match existing {
        Some(record) => update_record(client, config, &zone_id, &record.id, hostname).await?,
        None => create_record(client, config, &zone_id, hostname).await?,
    };

    sqlx::query(
        "INSERT INTO dns_records (id, app_id, hostname, zone_id, record_id, record_type, target, is_custom)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         ON CONFLICT (hostname) DO UPDATE SET
             app_id = EXCLUDED.app_id,
             zone_id = EXCLUDED.zone_id,
             record_id = EXCLUDED.record_id,
             record_type = EXCLUDED.record_type,
             target = EXCLUDED.target,
             is_custom = EXCLUDED.is_custom,
             updated_at = now()",
    )
    .bind(Uuid::new_v4())
    .bind(app_id)
    .bind(hostname)
    .bind(&zone_id)
    .bind(&record.id)
    .bind(config.record_type())
    .bind(&config.target)
    .bind(is_custom)
    .execute(pool)
    .await?;

    tracing::info!(
        app_id = %app_id,
        hostname = %hostname,
        target = %config.target,
        record_id = %record.id,
        "DNS record ensured"
    );

    Ok(())
}

pub async fn delete_dns_record(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
    hostname: &str,
) -> Result<(), DnsError> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT zone_id, record_id FROM dns_records WHERE app_id = $1 AND hostname = $2",
    )
    .bind(app_id)
    .bind(hostname)
    .fetch_optional(pool)
    .await?;

    let Some((zone_id, record_id)) = row else {
        return Ok(());
    };

    // Custom (user-owned) rows have no Cloudflare handle; delete the local row
    // only. Platform-zone rows need a Cloudflare delete first.
    if let (Some(zone_id), Some(record_id)) = (zone_id.as_deref(), record_id.as_deref()) {
        let Some(config) = config else {
            return Ok(());
        };

        let response = client
            .delete(format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            ))
            .bearer_auth(&config.cloudflare_api_token)
            .send()
            .await?;

        if response.status() != StatusCode::NOT_FOUND {
            let status = response.status();
            let body: CloudflareSingle<serde_json::Value> = response.json().await?;
            if !status.is_success() || !body.success {
                return Err(DnsError::Cloudflare(format!(
                    "delete record for '{hostname}' failed: {}",
                    cloudflare_error(&body.errors)
                )));
            }
        }

        tracing::info!(
            app_id = %app_id,
            hostname = %hostname,
            record_id = %record_id,
            "DNS record deleted"
        );
    } else {
        tracing::info!(
            app_id = %app_id,
            hostname = %hostname,
            "custom DNS record forgotten (user-owned, no cloudflare delete)"
        );
    }

    sqlx::query("DELETE FROM dns_records WHERE app_id = $1 AND hostname = $2")
        .bind(app_id)
        .bind(hostname)
        .execute(pool)
        .await?;

    Ok(())
}

/// Record a user-owned custom domain in `dns_records` without touching
/// Cloudflare. The user controls this DNS, so we only track it for cleanup
/// and audit. Idempotent for the same app, but refuses to transfer a hostname
/// away from another app because the old app may still have DB and HAProxy
/// state for that domain.
pub async fn record_custom_domain(
    pool: &PgPool,
    app_id: Uuid,
    hostname: &str,
) -> Result<(), DnsError> {
    let row: Option<(Uuid,)> = sqlx::query_as(
        "INSERT INTO dns_records (id, app_id, hostname, zone_id, record_id, record_type, target, is_custom, provider)
         VALUES ($1, $2, $3, NULL, NULL, 'CUSTOM', '', true, 'user')
         ON CONFLICT (hostname) DO UPDATE SET
             app_id = EXCLUDED.app_id,
             zone_id = NULL,
             record_id = NULL,
             record_type = EXCLUDED.record_type,
             target = EXCLUDED.target,
             is_custom = EXCLUDED.is_custom,
             provider = EXCLUDED.provider,
             updated_at = now()
         WHERE dns_records.app_id = EXCLUDED.app_id
         RETURNING app_id",
    )
    .bind(Uuid::new_v4())
    .bind(app_id)
    .bind(hostname)
    .fetch_optional(pool)
    .await?;

    if row.is_none() {
        return Err(DnsError::HostnameInUse {
            hostname: hostname.to_string(),
        });
    }

    tracing::info!(
        app_id = %app_id,
        hostname = %hostname,
        "custom DNS hostname tracked (user-owned)"
    );

    Ok(())
}

/// Atomically ensure DNS records for both the user-facing app hostname and
/// the TEE hostname. If any record creation fails, the records that were
/// successfully created in this call are deleted before returning the error
/// (best-effort rollback). Existing records (created in a prior successful
/// call) are not touched on failure -- the operation is idempotent so a
/// retry will reconcile.
pub async fn ensure_dns_pair(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
    app_host: &str,
    tee_host: &str,
) -> Result<(), DnsError> {
    if config.is_none() {
        return Ok(());
    }

    let mut created: Vec<String> = Vec::new();

    // Track whether each hostname existed already so that rollback only
    // removes records that this call created.
    let app_existed = dns_record_exists(pool, app_id, app_host).await?;
    ensure_dns_record(pool, client, config, app_id, app_host, false).await?;
    if !app_existed {
        created.push(app_host.to_string());
    }

    let tee_existed = dns_record_exists(pool, app_id, tee_host).await?;
    if let Err(e) = ensure_dns_record(pool, client, config, app_id, tee_host, false).await {
        for host in created {
            if let Err(rb_err) = delete_dns_record(pool, client, config, app_id, &host).await {
                tracing::error!(
                    app_id = %app_id,
                    hostname = %host,
                    error = %rb_err,
                    "rollback delete failed during ensure_dns_pair"
                );
            }
        }
        return Err(e);
    }
    if !tee_existed {
        created.push(tee_host.to_string());
    }

    Ok(())
}

async fn dns_record_exists(pool: &PgPool, app_id: Uuid, hostname: &str) -> Result<bool, DnsError> {
    let row: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM dns_records WHERE app_id = $1 AND hostname = $2")
            .bind(app_id)
            .bind(hostname)
            .fetch_optional(pool)
            .await?;
    Ok(row.is_some())
}

pub async fn delete_all_dns_records_for_app(
    pool: &PgPool,
    client: &reqwest::Client,
    config: Option<&DnsConfig>,
    app_id: Uuid,
) -> Result<(), DnsError> {
    let hostnames: Vec<String> =
        sqlx::query_scalar("SELECT hostname FROM dns_records WHERE app_id = $1 ORDER BY hostname")
            .bind(app_id)
            .fetch_all(pool)
            .await?;

    for hostname in hostnames {
        delete_dns_record(pool, client, config, app_id, &hostname).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::DnsConfig;

    fn config() -> DnsConfig {
        DnsConfig {
            cloudflare_api_token: "token".to_string(),
            cloudflare_zone_id: None,
            cloudflare_zone_name: "enclava.dev".to_string(),
            target: "95.217.56.248".to_string(),
            required: true,
        }
    }

    #[test]
    fn record_type_uses_a_for_ipv4() {
        assert_eq!(config().record_type(), "A");
    }

    #[test]
    fn record_type_uses_aaaa_for_ipv6() {
        let mut config = config();
        config.target = "2001:db8::1".to_string();
        assert_eq!(config.record_type(), "AAAA");
    }

    #[test]
    fn manages_only_configured_zone() {
        let config = config();
        assert!(config.manages_hostname("app.enclava.dev"));
        assert!(config.manages_hostname("enclava.dev"));
        assert!(!config.manages_hostname("app.example.com"));
    }
}
