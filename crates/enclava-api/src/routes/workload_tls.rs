use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, response::IntoResponse};
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::state::AppState;

const CERTIFICATE_CACHE_MAX_AGE_DAYS: i64 = 60;
const CERTIFICATE_ISSUANCE_WINDOW_DAYS: i64 = 7;
const MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW: i64 = 3;
const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str = "https://acme-v02.api.letsencrypt.org/directory";

#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    hostnames: Vec<String>,
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CertificateCacheKey {
    directory_url: String,
    hostnames_key: String,
    csr_sha256: Vec<u8>,
}

#[derive(Debug, sqlx::FromRow)]
struct DescriptorRow {
    descriptor_payload: Value,
}

pub async fn dns01_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CertificateRequest>,
) -> impl IntoResponse {
    let Some(token) = crate::routes::workload::attestation_bearer(&headers) else {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "attestation_token_required"})),
        )
            .into_response();
    };
    let Some(verify_url) = state.trustee_attestation_verify_url.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "trustee_attestation_verify_unconfigured"})),
        )
            .into_response();
    };
    let Some(dns_config) = state.dns.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dns_management_unconfigured"})),
        )
            .into_response();
    };
    let Some(acme_config) = state.acme.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "acme_unconfigured"})),
        )
            .into_response();
    };

    let claims = match verify_attestation(&state, verify_url, token).await {
        Ok(claims) => claims,
        Err(response) => return response,
    };
    let Some(descriptor_core_hash) = crate::routes::workload::extract_descriptor_core_hash(&claims)
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "descriptor_core_hash_missing"})),
        )
            .into_response();
    };
    let Some(init_data_hash) = attested_or_declared_init_data_hash(&claims, &body) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "init_data_hash_missing"})),
        )
            .into_response();
    };

    let row = match sqlx::query_as::<_, DescriptorRow>(
        "SELECT descriptor_payload
         FROM workload_artifacts
         WHERE descriptor_core_hash = $1",
    )
    .bind(&descriptor_core_hash)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "workload_artifacts_not_found"})),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    json!({"error": "workload_artifacts_query_failed", "detail": err.to_string()}),
                ),
            )
                .into_response();
        }
    };

    if !descriptor_init_hash_matches(&row.descriptor_payload, &init_data_hash) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "attested_init_data_hash_mismatch"})),
        )
            .into_response();
    }
    if let Err(err) = validate_requested_hostnames(&row.descriptor_payload, &body.hostnames) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": err}))).into_response();
    }
    let csr_der = match base64::engine::general_purpose::STANDARD.decode(&body.csr_der_base64) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "csr_empty"}))).into_response();
        }
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "csr_base64_invalid", "detail": err.to_string()})),
            )
                .into_response();
        }
    };
    let certificate_cache_key =
        certificate_cache_key(&acme_config.directory_url, &body.hostnames, &csr_der);
    match find_cached_certificate(&state.db, &certificate_cache_key).await {
        Ok(Some(certificate_chain_pem)) => {
            tracing::info!(
                hostnames = %certificate_cache_key.hostnames_key,
                csr_sha256 = %hex::encode(&certificate_cache_key.csr_sha256),
                "returning cached workload TLS certificate chain"
            );
            return (
                StatusCode::OK,
                Json(CertificateResponse {
                    certificate_chain_pem,
                }),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "certificate_cache_query_failed",
                    "detail": err.to_string(),
                })),
            )
                .into_response();
        }
    }
    match count_recent_distinct_csrs(&state.db, &certificate_cache_key).await {
        Ok(distinct_csrs)
            if production_acme_budget_exhausted(
                &certificate_cache_key.directory_url,
                distinct_csrs,
            ) =>
        {
            tracing::warn!(
                hostnames = %certificate_cache_key.hostnames_key,
                distinct_csrs,
                limit = MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW,
                window_days = CERTIFICATE_ISSUANCE_WINDOW_DAYS,
                "blocking production ACME issuance before external rate limit is exhausted"
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({
                    "error": "acme_internal_issuance_limit",
                    "detail": "too many distinct TLS CSRs for this hostname set; cached certificates still work, but new private keys are blocked to protect production ACME quota",
                    "distinct_csrs": distinct_csrs,
                    "limit": MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW,
                    "window_days": CERTIFICATE_ISSUANCE_WINDOW_DAYS,
                })),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "certificate_issuance_budget_query_failed",
                    "detail": err.to_string(),
                })),
            )
                .into_response();
        }
    }
    let rate_limit_key =
        crate::acme::AcmeRateLimitKey::new(&acme_config.directory_url, &body.hostnames);
    if let Some(retry_after) = state
        .acme_rate_limits
        .active_retry_after(&rate_limit_key, chrono::Utc::now())
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "acme_rate_limited",
                "retry_after": retry_after.to_rfc3339(),
            })),
        )
            .into_response();
    }

    match crate::acme::issue_dns01_certificate(
        &state.http_client,
        dns_config,
        acme_config,
        &body.hostnames,
        &csr_der,
    )
    .await
    {
        Ok(certificate_chain_pem) => {
            if let Err(err) = remember_cached_certificate(
                &state.db,
                &certificate_cache_key,
                &certificate_chain_pem,
                &descriptor_core_hash,
            )
            .await
            {
                tracing::error!(
                    error = %err,
                    hostnames = %certificate_cache_key.hostnames_key,
                    csr_sha256 = %hex::encode(&certificate_cache_key.csr_sha256),
                    "failed to cache workload TLS certificate chain after ACME issuance"
                );
            }
            (
                StatusCode::OK,
                Json(CertificateResponse {
                    certificate_chain_pem,
                }),
            )
                .into_response()
        }
        Err(err) => {
            let detail = err.to_string();
            if let Some(retry_after) = crate::acme::rate_limit_retry_after(&detail) {
                state.acme_rate_limits.record(rate_limit_key, retry_after);
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({
                        "error": "acme_rate_limited",
                        "detail": detail,
                        "retry_after": retry_after.to_rfc3339(),
                    })),
                )
                    .into_response();
            }
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "acme_certificate_issuance_failed", "detail": detail})),
            )
                .into_response()
        }
    }
}

fn certificate_cache_key(
    directory_url: &str,
    hostnames: &[String],
    csr_der: &[u8],
) -> CertificateCacheKey {
    CertificateCacheKey {
        directory_url: directory_url.to_string(),
        hostnames_key: normalized_hostnames_key(hostnames),
        csr_sha256: Sha256::digest(csr_der).to_vec(),
    }
}

fn normalized_hostnames_key(hostnames: &[String]) -> String {
    let mut hostnames = hostnames.to_vec();
    hostnames.sort();
    hostnames.dedup();
    hostnames.join("\n")
}

async fn find_cached_certificate(
    pool: &PgPool,
    key: &CertificateCacheKey,
) -> Result<Option<String>, sqlx::Error> {
    let cutoff = Utc::now() - Duration::days(CERTIFICATE_CACHE_MAX_AGE_DAYS);
    sqlx::query_scalar::<_, String>(
        "SELECT certificate_chain_pem
           FROM workload_tls_certificate_cache
          WHERE acme_directory_url = $1
            AND hostnames_key = $2
            AND csr_sha256 = $3
            AND updated_at > $4
          LIMIT 1",
    )
    .bind(&key.directory_url)
    .bind(&key.hostnames_key)
    .bind(&key.csr_sha256)
    .bind(cutoff)
    .fetch_optional(pool)
    .await
}

async fn remember_cached_certificate(
    pool: &PgPool,
    key: &CertificateCacheKey,
    certificate_chain_pem: &str,
    descriptor_core_hash: &[u8],
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO workload_tls_certificate_cache (
             acme_directory_url,
             hostnames_key,
             csr_sha256,
             certificate_chain_pem,
             last_descriptor_core_hash
         )
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (acme_directory_url, hostnames_key, csr_sha256)
         DO UPDATE SET
             certificate_chain_pem = EXCLUDED.certificate_chain_pem,
             last_descriptor_core_hash = EXCLUDED.last_descriptor_core_hash,
             updated_at = now()",
    )
    .bind(&key.directory_url)
    .bind(&key.hostnames_key)
    .bind(&key.csr_sha256)
    .bind(certificate_chain_pem)
    .bind(descriptor_core_hash)
    .execute(pool)
    .await?;
    Ok(())
}

async fn count_recent_distinct_csrs(
    pool: &PgPool,
    key: &CertificateCacheKey,
) -> Result<i64, sqlx::Error> {
    let cutoff = Utc::now() - Duration::days(CERTIFICATE_ISSUANCE_WINDOW_DAYS);
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(DISTINCT csr_sha256)::bigint
           FROM workload_tls_certificate_cache
          WHERE acme_directory_url = $1
            AND hostnames_key = $2
            AND created_at > $3",
    )
    .bind(&key.directory_url)
    .bind(&key.hostnames_key)
    .bind(cutoff)
    .fetch_one(pool)
    .await
}

fn production_acme_budget_exhausted(directory_url: &str, distinct_csrs: i64) -> bool {
    directory_url == LETS_ENCRYPT_PRODUCTION_DIRECTORY
        && distinct_csrs >= MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW
}

fn attested_or_declared_init_data_hash(
    claims: &Value,
    body: &CertificateRequest,
) -> Option<Vec<u8>> {
    crate::routes::workload::extract_init_data_hash(claims).or_else(|| {
        body.cc_init_data_hash
            .as_deref()
            .and_then(crate::routes::workload::parse_hex32)
    })
}

async fn verify_attestation(
    state: &AppState,
    verify_url: &str,
    token: &str,
) -> Result<Value, axum::response::Response> {
    let verify_response = match crate::routes::workload::trustee_attestation_verify_request(
        &state.trustee_http_client,
        verify_url,
        token,
        state.trustee_attestation_verify_bearer_token.as_deref(),
    )
    .send()
    .await
    {
        Ok(response) => response,
        Err(err) => {
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "trustee_attestation_verify_failed", "detail": err.to_string()})),
            )
                .into_response());
        }
    };

    if !verify_response.status().is_success() {
        let status = verify_response.status().as_u16();
        let body = verify_response.text().await.unwrap_or_default();
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "attestation_denied",
                "upstream_status": status,
                "upstream_body": body,
            })),
        )
            .into_response());
    }

    verify_response.json().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": "attestation_claims_invalid", "detail": err.to_string()})),
        )
            .into_response()
    })
}

fn descriptor_init_hash_matches(descriptor: &Value, attested_init_data_hash: &[u8]) -> bool {
    descriptor
        .get("expected_cc_init_data_hash")
        .and_then(Value::as_str)
        .and_then(crate::routes::workload::parse_hex32)
        .as_deref()
        == Some(attested_init_data_hash)
}

fn validate_requested_hostnames(descriptor: &Value, requested: &[String]) -> Result<(), String> {
    if requested.is_empty() {
        return Err("hostnames_empty".into());
    }
    let allowed = allowed_certificate_hostnames(descriptor);
    if allowed.is_empty() {
        return Err("descriptor_has_no_certificate_hostnames".into());
    }
    for hostname in requested {
        if !allowed.iter().any(|allowed| allowed == hostname) {
            return Err("hostname_not_attested".into());
        }
    }
    Ok(())
}

fn allowed_certificate_hostnames(descriptor: &Value) -> Vec<String> {
    let mut hostnames = Vec::new();
    if let Some(hostname) = descriptor.get("app_domain").and_then(Value::as_str)
        && !hostname.is_empty()
    {
        hostnames.push(hostname.to_string());
    }
    if let Some(custom) = descriptor.get("custom_domains").and_then(Value::as_array) {
        for hostname in custom.iter().filter_map(Value::as_str) {
            if !hostname.is_empty() && !hostnames.iter().any(|existing| existing == hostname) {
                hostnames.push(hostname.to_string());
            }
        }
    }
    hostnames
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certificate_hostnames_are_limited_to_attested_descriptor_domains() {
        let descriptor = json!({
            "app_domain": "app.enclava.dev",
            "tee_domain": "app.tee.enclava.dev",
            "custom_domains": ["custom.example.test"]
        });

        assert!(validate_requested_hostnames(&descriptor, &["app.enclava.dev".into()]).is_ok());
        assert!(validate_requested_hostnames(&descriptor, &["custom.example.test".into()]).is_ok());
        assert_eq!(
            validate_requested_hostnames(&descriptor, &["other.example.test".into()]).unwrap_err(),
            "hostname_not_attested"
        );
    }

    #[test]
    fn broker_accepts_declared_cc_init_data_hash_when_kbs_token_omits_it() {
        let body = CertificateRequest {
            hostnames: vec!["app.enclava.dev".into()],
            csr_der_base64: "AA==".into(),
            cc_init_data_hash: Some("ab".repeat(32)),
        };

        assert_eq!(
            attested_or_declared_init_data_hash(&json!({}), &body),
            Some(vec![0xab; 32])
        );
    }

    #[test]
    fn certificate_cache_key_normalizes_hostnames_and_binds_csr() {
        let first = certificate_cache_key(
            "https://acme-v02.api.letsencrypt.org/directory",
            &[
                "b.example.test".to_string(),
                "a.example.test".to_string(),
                "a.example.test".to_string(),
            ],
            b"csr-one",
        );
        let reordered = certificate_cache_key(
            "https://acme-v02.api.letsencrypt.org/directory",
            &["a.example.test".to_string(), "b.example.test".to_string()],
            b"csr-one",
        );
        let different_csr = certificate_cache_key(
            "https://acme-v02.api.letsencrypt.org/directory",
            &["a.example.test".to_string(), "b.example.test".to_string()],
            b"csr-two",
        );

        assert_eq!(first.hostnames_key, "a.example.test\nb.example.test");
        assert_eq!(first, reordered);
        assert_ne!(first, different_csr);
    }

    #[test]
    fn cached_certificate_is_checked_before_acme_rate_limit_gate() {
        let source = include_str!("workload_tls.rs");
        let cache_lookup = source
            .find("find_cached_certificate")
            .expect("workload TLS route checks certificate cache");
        let rate_limit_gate = source
            .find("active_retry_after")
            .expect("workload TLS route checks ACME rate limit cache");

        assert!(
            cache_lookup < rate_limit_gate,
            "cached public certificate chains must be reusable even while a production ACME exact-set rate limit is active"
        );
    }

    #[test]
    fn production_acme_budget_blocks_new_csrs_before_external_rate_limit() {
        assert!(!production_acme_budget_exhausted(
            "https://acme-staging-v02.api.letsencrypt.org/directory",
            100,
        ));
        assert!(!production_acme_budget_exhausted(
            "https://acme-v02.api.letsencrypt.org/directory",
            MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW - 1,
        ));
        assert!(production_acme_budget_exhausted(
            "https://acme-v02.api.letsencrypt.org/directory",
            MAX_DISTINCT_CSRS_PER_HOSTNAME_WINDOW,
        ));
    }
}
