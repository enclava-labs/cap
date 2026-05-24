//! Custom-domain routes (D5 / Phase 4 mitigations).
//!
//! Flow:
//! 1. `POST /apps/{name}/domains` — caller proposes a custom domain. We
//!    validate the FQDN, reject anything inside the platform `enclava.dev`
//!    zone, mint a one-shot challenge token, and return the TXT record the
//!    caller must publish on `_enclava-challenge.<domain>`.
//! 2. `POST /apps/{name}/domains/{domain}/verify` — caller asks us to
//!    verify the proof. We resolve the TXT record (via `hickory-resolver`
//!    so the operator-side cache cannot lie to us), match the live TXT
//!    against the stored token in constant time, and only on success track the
//!    user-owned hostname, regenerate tenant ingress, publish HAProxy routing,
//!    and update the app row.
//! 3. `DELETE /apps/{name}/domains/{domain}` — remove a custom domain.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::Engine;
use chrono::{Duration, Utc};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::auth::scopes;
use crate::models::App;
use crate::state::AppState;

const CHALLENGE_LIFETIME_HOURS: i64 = 24;
const CHALLENGE_PREFIX: &str = "_enclava-challenge.";

fn dns_error_response(error: crate::dns::DnsError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match &error {
        crate::dns::DnsError::OutsideManagedZone(_) => StatusCode::BAD_REQUEST,
        crate::dns::DnsError::HostnameInUse { .. } => StatusCode::CONFLICT,
        crate::dns::DnsError::NotConfigured => StatusCode::INTERNAL_SERVER_ERROR,
        crate::dns::DnsError::Cloudflare(_)
        | crate::dns::DnsError::Http(_)
        | crate::dns::DnsError::Db(_) => StatusCode::BAD_GATEWAY,
    };
    (
        status,
        Json(serde_json::json!({"error": error.to_string()})),
    )
}

fn internal_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("domain must be outside the platform-managed zone {0}")]
    InsidePlatformZone(String),
    #[error("DNS lookup failed: {0}")]
    Lookup(String),
    #[error("TXT record at {0} did not match stored challenge")]
    MismatchedToken(String),
    #[error("no challenge for this domain")]
    NoChallenge,
    #[error("challenge has expired")]
    Expired,
}

impl DomainError {
    fn status(&self) -> StatusCode {
        match self {
            DomainError::InvalidDomain(_) | DomainError::InsidePlatformZone(_) => {
                StatusCode::BAD_REQUEST
            }
            DomainError::NoChallenge | DomainError::Expired => StatusCode::CONFLICT,
            DomainError::MismatchedToken(_) => StatusCode::PRECONDITION_FAILED,
            DomainError::Lookup(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

/// Fail any candidate that ends with one of the platform-managed zones. The
/// platform zone list is conservative on purpose -- we'd rather over-reject
/// than allow an FQDN inside our zone to be smuggled in as a "custom"
/// domain.
fn validate_custom_domain(
    candidate: &str,
    platform_domain: &str,
    tee_domain_suffix: &str,
) -> Result<String, DomainError> {
    enclava_common::validate::validate_fqdn(candidate)
        .map_err(|e| DomainError::InvalidDomain(e.to_string()))?;
    let lower = candidate.to_ascii_lowercase();

    for forbidden in [platform_domain, tee_domain_suffix] {
        let forbidden = forbidden.trim_end_matches('.').to_ascii_lowercase();
        if lower == forbidden || lower.ends_with(&format!(".{forbidden}")) {
            return Err(DomainError::InsidePlatformZone(forbidden));
        }
    }

    Ok(lower)
}

fn mint_challenge_token() -> String {
    let mut buf = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[derive(Debug, Deserialize)]
pub struct CreateChallengeRequest {
    pub domain: String,
}

#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub domain: String,
    pub txt_record_name: String,
    pub txt_record_value: String,
    pub expires_at: chrono::DateTime<Utc>,
    pub instructions: String,
}

/// POST /apps/{name}/domains -- create a verification challenge.
pub async fn create_challenge(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<CreateChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let domain = validate_custom_domain(
        &body.domain,
        &state.platform_domain,
        &state.tee_domain_suffix,
    )
    .map_err(|e| {
        (
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    let token = mint_challenge_token();
    let expires_at = Utc::now() + Duration::hours(CHALLENGE_LIFETIME_HOURS);
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO custom_domain_challenges (id, app_id, domain, challenge_token, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(app.id)
    .bind(&domain)
    .bind(&token)
    .bind(expires_at)
    .execute(&state.db)
    .await
    .map_err(|_| internal_error())?;

    Ok(Json(ChallengeResponse {
        txt_record_name: format!("{}{}", CHALLENGE_PREFIX, domain),
        txt_record_value: format!("enclava-domain-verification={token}"),
        domain,
        expires_at,
        instructions: format!(
            "Publish a TXT record at the listed name with the listed value, then call POST /apps/{app_name}/domains/<domain>/verify",
        ),
    }))
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub domain: String,
    pub verified_at: chrono::DateTime<Utc>,
}

/// POST /apps/{name}/domains/{domain}/verify -- verify a published TXT record.
pub async fn verify_challenge(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((app_name, domain)): Path<(String, String)>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let domain = validate_custom_domain(&domain, &state.platform_domain, &state.tee_domain_suffix)
        .map_err(|e| {
            (
                e.status(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    type ChallengeRow = (
        Uuid,
        String,
        chrono::DateTime<Utc>,
        Option<chrono::DateTime<Utc>>,
    );
    let row: Option<ChallengeRow> = sqlx::query_as(
        "SELECT id, challenge_token, expires_at, verified_at
             FROM custom_domain_challenges
             WHERE app_id = $1 AND domain = $2
             ORDER BY created_at DESC
             LIMIT 1",
    )
    .bind(app.id)
    .bind(&domain)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| internal_error())?;

    let (challenge_id, token, expires_at, _) = row.ok_or_else(|| {
        let e = DomainError::NoChallenge;
        (
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    if Utc::now() > expires_at {
        let e = DomainError::Expired;
        return Err((
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }

    let txt_name = format!("{}{}", CHALLENGE_PREFIX, domain);
    let expected = format!("enclava-domain-verification={token}");

    let live = lookup_txt(&txt_name).await.map_err(|e| {
        let de = DomainError::Lookup(e.to_string());
        (
            de.status(),
            Json(serde_json::json!({"error": de.to_string()})),
        )
    })?;

    let mut matched = false;
    for value in &live {
        if value.as_bytes().ct_eq(expected.as_bytes()).into() {
            matched = true;
            break;
        }
    }
    if !matched {
        let e = DomainError::MismatchedToken(txt_name);
        return Err((
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }

    let verified_at = Utc::now();
    sqlx::query("UPDATE custom_domain_challenges SET verified_at = $1 WHERE id = $2")
        .bind(verified_at)
        .bind(challenge_id)
        .execute(&state.db)
        .await
        .map_err(|_| internal_error())?;

    let previous_custom = app.custom_domain.clone();

    crate::dns::record_custom_domain(&state.db, app.id, &domain)
        .await
        .map_err(dns_error_response)?;

    // Re-render the tenant-ingress ConfigMap before publishing the HAProxy
    // route. Caddy does not watch its ConfigMap, so reapply_tenant_ingress
    // also restarts the StatefulSet and waits for the new pod to become ready.
    // If the app has not been deployed yet, persist the verified custom domain
    // and let the first deploy publish the route.
    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let next_app = App {
        custom_domain: Some(domain.clone()),
        ..app.clone()
    };
    let ingress_ready = match crate::deploy::reapply_tenant_ingress(
        &state.db,
        &next_app,
        state.attestation.as_ref(),
        &api_signing_pubkey,
        &state.api_url,
    )
    .await
    {
        Ok(()) => true,
        Err(crate::deploy::DeployError::NoContainers)
        | Err(crate::deploy::DeployError::NotDeployed(_)) => {
            tracing::info!(
                app_id = %app.id,
                %domain,
                "tenant ingress regeneration skipped: app not yet deployed"
            );
            false
        }
        Err(e) => {
            tracing::error!(
                app_id = %app.id,
                %domain,
                error = %e,
                "failed to regenerate tenant ingress for verified custom domain"
            );
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("tenant ingress update failed: {e}")})),
            ));
        }
    };

    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(auth.org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| internal_error())?;
    let app_backend =
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::App).map_err(
            |e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("invalid app name: {e}")})),
                )
            },
        )?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();

    sqlx::query("UPDATE apps SET custom_domain = $1, updated_at = now() WHERE id = $2")
        .bind(&domain)
        .bind(app.id)
        .execute(&state.db)
        .await
        .map_err(|_| internal_error())?;

    if ingress_ready {
        let app_target = crate::edge::resolve_backend_target(&app.name, &app.namespace, 443)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("resolve backend: {e}")})),
                )
            })?;
        let route =
            crate::edge::SniRoute::new(&domain, &app_backend, &app_target).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("sni route: {e}")})),
                )
            })?;
        crate::edge::ensure_haproxy_routes(&state.db, &edge_config, &[route])
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("haproxy update: {e}")})),
                )
            })?;
    }

    if let Some(old) = previous_custom.as_deref()
        && old != domain
    {
        if let Err(e) = crate::dns::delete_dns_record(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            app.id,
            old,
        )
        .await
        {
            tracing::warn!(error = %e, old_domain = %old, "failed to clean up previous custom domain DNS record");
        }
        if let Err(e) = crate::edge::remove_haproxy_routes(
            &state.db,
            &edge_config,
            &[(app_backend.clone(), old.to_string())],
        )
        .await
        {
            tracing::warn!(error = %e, old_domain = %old, "failed to remove previous custom domain HAProxy route");
        }
    }

    Ok(Json(VerifyResponse {
        domain,
        verified_at,
    }))
}

/// DELETE /apps/{name}/domains/{domain} -- remove the custom domain.
pub async fn remove_custom_domain(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((app_name, domain)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_admin(&auth)?;
    scopes::require_scope(&auth, "apps:write")?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let domain = validate_custom_domain(&domain, &state.platform_domain, &state.tee_domain_suffix)
        .map_err(|e| {
            (
                e.status(),
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;

    crate::dns::delete_dns_record(
        &state.db,
        &state.http_client,
        state.dns.as_ref(),
        app.id,
        &domain,
    )
    .await
    .map_err(dns_error_response)?;

    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(auth.org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| internal_error())?;
    let app_backend =
        crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::App).map_err(
            |e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("invalid app name: {e}")})),
                )
            },
        )?;
    let edge_config = crate::edge::EdgeRouteConfig::from_env();
    if let Err(e) = crate::edge::remove_haproxy_routes(
        &state.db,
        &edge_config,
        &[(app_backend, domain.clone())],
    )
    .await
    {
        tracing::warn!(error = %e, %domain, "failed to remove custom domain HAProxy route");
    }

    sqlx::query("UPDATE apps SET custom_domain = NULL, updated_at = now() WHERE id = $1 AND custom_domain = $2")
        .bind(app.id)
        .bind(&domain)
        .execute(&state.db)
        .await
        .map_err(|_| internal_error())?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct DomainResponse {
    pub platform_domain: String,
    pub tee_domain: Option<String>,
    pub custom_domain: Option<String>,
}

/// GET /apps/{name}/domain -- domain summary.
pub async fn get_domain(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<DomainResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| internal_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    Ok(Json(DomainResponse {
        platform_domain: app.domain,
        tee_domain: app.tee_domain,
        custom_domain: app.custom_domain,
    }))
}

async fn lookup_txt(name: &str) -> Result<Vec<String>, String> {
    // Use the system resolver if configured; otherwise fall back to public
    // resolvers (Cloudflare 1.1.1.1, Google 8.8.8.8). Either way the live
    // record is fetched fresh -- not from any operator-side cache.
    let resolver = match TokioResolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(r) => r,
        Err(_) => TokioResolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .with_options(ResolverOpts::default())
        .build()
        .map_err(|e| e.to_string())?,
    };
    let response = resolver.txt_lookup(name).await.map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for record in response.answers() {
        let RData::TXT(rdata) = &record.data else {
            continue;
        };
        for chunk in rdata.txt_data.iter() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                out.push(s.to_string());
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_inside_platform_zone() {
        assert!(matches!(
            validate_custom_domain("foo.enclava.dev", "enclava.dev", "tee.enclava.dev"),
            Err(DomainError::InsidePlatformZone(_))
        ));
        assert!(matches!(
            validate_custom_domain("foo.tee.enclava.dev", "enclava.dev", "tee.enclava.dev"),
            Err(DomainError::InsidePlatformZone(_))
        ));
        assert!(matches!(
            validate_custom_domain("enclava.dev", "enclava.dev", "tee.enclava.dev"),
            Err(DomainError::InsidePlatformZone(_))
        ));
    }

    #[test]
    fn accepts_third_party_domain() {
        let d =
            validate_custom_domain("app.example.com", "enclava.dev", "tee.enclava.dev").unwrap();
        assert_eq!(d, "app.example.com");
    }

    #[test]
    fn rejects_invalid_fqdn() {
        for bad in ["", "a..b.com", "App.Example.com", "xn--bad.com", "a b.com"] {
            assert!(
                matches!(
                    validate_custom_domain(bad, "enclava.dev", "tee.enclava.dev"),
                    Err(DomainError::InvalidDomain(_))
                ),
                "expected invalid for {bad:?}"
            );
        }
    }
}
