//! Custom-domain routes (D5 / Phase 4 mitigations).
//!
//! Flow:
//! 1. `POST /apps/{name}/domains` — caller proposes a custom domain. We
//!    validate the FQDN, reject anything inside the platform `enclava.dev`
//!    zone, mint a one-shot challenge token, and return the TXT record the
//!    caller must publish on `_enclava-challenge.<domain>`.
//! 2. `POST /apps/{name}/domains/{domain}/verify` — look up the live TXT and
//!    compare it against the stored token in constant time. On success, track
//!    the user-owned hostname, regenerate ingress when changed, publish routing,
//!    and update the app row. A live StatefulSet may only be restarted after
//!    live cluster state proves both volume claims initialized (exact Ready
//!    ordinal-0 pod); terminal deployment rows are not proof. Apps with no
//!    StatefulSet keep the DNS-only predeploy path.
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
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::acme::DnsLookupError;
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

/// Typed, code-shaped backend-unavailable error (cap#422): no provider
/// text, no bare 500.
fn edge_route_unavailable() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({"error": "edge_route_backend_unavailable"})),
    )
}

/// Release the claimed mutation leases durably, in the release's OWN
/// transaction, under the app deployment lane lock (the same discipline
/// `AppMutationLease::finish` uses): the caller's lane may be aborted (a
/// failed statement makes every later query on it fail) or may carry
/// staged business writes that must NOT be committed by an error path, so
/// it is rolled back first.
async fn release_mutation(
    state: &AppState,
    mutation: &mut crate::mutation_leases::AppMutationLease,
    app_id: Uuid,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut release_lane = state.db.begin().await.map_err(|_| internal_error())?;
    crate::deploy::lock_app_deployment_lane(&mut release_lane, app_id)
        .await
        .map_err(|_| internal_error())?;
    mutation
        .finish_in_tx(&mut release_lane)
        .await
        .map_err(|_| internal_error())?;
    release_lane.commit().await.map_err(|_| internal_error())?;
    Ok(())
}

/// cap#422: the error-path release. The pre-fix code dropped `app_lane`
/// uncommitted — no staged business write (the proof timestamp, the
/// custom-domain assignment) may survive a failed verify — so the lane is
/// ROLLED BACK first, and only then are the claimed rows released
/// durably (a PostgreSQL statement abort in the lane would make
/// finish_in_tx fail inside it, so the release runs in its own
/// transaction). This closes every post-claim error path with a SETTLED
/// outcome: a stranded lease reported `idempotency_request_in_progress`
/// until `reclaim_after` on dev.
async fn release_mutation_and_rollback_lane(
    state: &AppState,
    mutation: &mut crate::mutation_leases::AppMutationLease,
    app_id: Uuid,
    app_lane: sqlx::Transaction<'static, sqlx::Postgres>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    app_lane.rollback().await.map_err(|_| internal_error())?;
    release_mutation(state, mutation, app_id).await
}

/// cap#422: renewal lost mid-provider-call — the provider write's outcome
/// is UNRESOLVED: `guard_provider` drops the local future, but a request
/// already issued to Kubernetes or the DNS provider can still complete on
/// the server, and a missing ConfigMap create has no existing version to
/// fence it. The reclaim quarantine (RECLAIM_QUARANTINE_SECONDS) exists
/// to keep the next durable generation off these resources during exactly
/// that window, so the fences are deliberately NOT released: the business
/// lane is rolled back (no staged write survives) and the leases stay
/// quarantined until reclaim, which frees them only after the quarantine
/// bound. Used only on the guard's renewal-loss arms; provider failures
/// that RETURNED (settled) release normally.
async fn quarantine_mutation_and_rollback_lane(
    // The mutation is accepted for call-site symmetry with the releasing
    // variant and deliberately untouched: every claimed row, the shared
    // edge_config fence included, stays quarantined until reclaim_after.
    _mutation: &crate::mutation_leases::AppMutationLease,
    app_lane: sqlx::Transaction<'static, sqlx::Postgres>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    app_lane.rollback().await.map_err(|_| internal_error())?;
    Ok(())
}

/// cap#422 R2 (review T1 + round 3): the no-edge-write arms of the
/// renewal-loss path. The provider write in flight touches Postgres or
/// the DNS provider only (the DNS-tracking record, a Cloudflare record
/// deletion) -- no HAProxy/ConfigMap request was ever issued, so no
/// later reconcile can adopt a poisoned base from it. The global
/// `edge_config` fence is cross-app (deployment apply for UNRELATED apps
/// needs it), so it is RELEASED here instead of idling through the
/// reclaim quarantine. The app's own fences stay quarantined until
/// reclaim_after. The edge-write arms (route publish, ingress ConfigMap,
/// route removal) deliberately keep using
/// `quarantine_mutation_and_rollback_lane`: an in-flight ConfigMap write
/// can still land, and a freed edge_config fence would let an unrelated
/// deployment's reconcile adopt the post-write config as its base.
async fn quarantine_mutation_and_rollback_lane_releasing_edge_config(
    mutation: &crate::mutation_leases::AppMutationLease,
    app_lane: sqlx::Transaction<'static, sqlx::Postgres>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    app_lane.rollback().await.map_err(|_| internal_error())?;
    if let Err(error) = mutation
        .release_fences_quarantined(&[crate::mutation_leases::ResourceFence::edge_config()])
        .await
    {
        // Fail toward the old behavior: the fence stays quarantined
        // (bounded by reclaim_after) rather than blocking this path's
        // error return on a second failure.
        tracing::warn!(
            error = %error,
            "cross-app fence release after renewal loss failed; the edge_config fence stays quarantined until reclaim"
        );
    }
    Ok(())
}

/// The same-domain re-verification's decision on the app's backend
/// resolution (cap#422): deploy the route, skip the publish (the
/// first-verification rule — the app was never deployed), or surface a
/// typed backend-unavailable failure.
#[derive(Debug, PartialEq, Eq)]
enum SameDomainBackend {
    Deployed,
    NotDeployed,
    Unavailable,
}

/// cap#422: Kubernetes NotFound on the Service lookup means "not
/// deployed" — skip the route publish (the first deploy publishes it),
/// mirroring the first-verification rule. Every OTHER backend error is
/// a real failure: typed and code-shaped, never a bare 500.
fn same_domain_backend_verdict(
    resolution: &Result<String, crate::edge::EdgeRouteError>,
) -> SameDomainBackend {
    match resolution {
        Ok(_) => SameDomainBackend::Deployed,
        Err(error) if crate::edge::is_kube_not_found(error) => SameDomainBackend::NotDeployed,
        Err(_) => SameDomainBackend::Unavailable,
    }
}

fn internal_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "internal server error"})),
    )
}

async fn ensure_custom_domain_haproxy_route(
    state: &AppState,
    org_id: Uuid,
    app: &App,
    domain: &str,
    edge_config_generation: i64,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let org_slug: String = sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
        .bind(org_id)
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
    let app_target =
        crate::edge::resolve_backend_target(&state.kube_client, &app.name, &app.namespace, 443)
            .await
            .map_err(|e| {
                // cap#422: typed and code-shaped, never a bare 500 with
                // provider text (the cause is logged by the caller).
                tracing::error!(error = %e, "backend resolution failed for custom domain route");
                edge_route_unavailable()
            })?;
    let route = crate::edge::SniRoute::new(domain, &app_backend, &app_target).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("sni route: {e}")})),
        )
    })?;
    crate::edge::ensure_haproxy_routes(
        &state.kube_client,
        &state.db,
        &crate::edge::EdgeRouteConfig::from_env(),
        Some(edge_config_generation),
        &[route],
    )
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("haproxy update: {e}")})),
        )
    })?;
    Ok(app_backend)
}

#[derive(Debug, thiserror::Error)]
pub enum DomainError {
    #[error("invalid domain: {0}")]
    InvalidDomain(String),
    #[error("domain must be outside the platform-managed zone {0}")]
    InsidePlatformZone(String),
    #[error("DNS lookup failed: {0}")]
    Lookup(String),
    #[error(
        "TXT record at {0} was not found or did not match the stored challenge; DNS changes can take a few minutes to become visible"
    )]
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
    /// The CNAME record a tenant must ALSO publish when the domain is
    /// outside the platform's managed DNS zone, so ACME DNS-01 challenges
    /// can be answered through delegation. `null` for in-zone domains
    /// (they are answered directly and need no delegation).
    pub acme_cname_name: Option<String>,
    /// The in-zone target `acme_cname_name` must point at
    /// (`<domain>.acme.<zone>`). `null` for in-zone domains.
    pub acme_cname_target: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
    pub instructions: String,
}

/// The ACME delegation record pair for a custom domain, or `(None, None)`
/// when no pair applies: in-zone domains (answered directly), and
/// deployments where the DNS-01 certificate broker is not the issuer (no
/// broker configured -- e.g. Caddy TLS-ALPN mode -- or no managed DNS
/// provider, where no DNS-01 certificate can be issued either). Demanding
/// the CNAME there would block domains a TLS-ALPN deployment serves
/// without it.
fn acme_cname_fields(
    dns: Option<&crate::dns::DnsConfig>,
    broker: Option<&crate::acme::AcmeConfig>,
    domain: &str,
) -> (Option<String>, Option<String>) {
    match (dns, broker) {
        (Some(dns), Some(_)) if !dns.manages_hostname(domain) => {
            let (name, target) =
                crate::acme::expected_acme_cname_pair(domain, &dns.cloudflare_zone_name);
            (Some(name), Some(target))
        }
        _ => (None, None),
    }
}

/// The 422 body for a missing ACME delegation on verify: the actionable
/// expected record pair travels with the error code. Provider text and
/// resolver details never appear.
fn delegation_missing_response(
    acme_cname_name: &str,
    acme_cname_target: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({
            "error": "acme_delegation_missing",
            "acme_cname_name": acme_cname_name,
            "acme_cname_target": acme_cname_target,
        })),
    )
}

/// POST /apps/{name}/domains -- create a verification challenge.
pub async fn create_challenge(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<CreateChallengeRequest>,
) -> Result<Json<ChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

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

    let (acme_cname_name, acme_cname_target) =
        acme_cname_fields(state.dns.as_ref(), state.acme.as_ref(), &domain);
    let instructions = match (&acme_cname_name, &acme_cname_target) {
        (Some(cname_name), Some(cname_target)) => format!(
            "Publish BOTH records at your DNS provider: the ownership TXT record at the listed name with the listed value, and a CNAME record named {cname_name} pointing at {cname_target}, then call POST /apps/{app_name}/domains/<domain>/verify",
        ),
        _ => format!(
            "Publish a TXT record at the listed name with the listed value, then call POST /apps/{app_name}/domains/<domain>/verify",
        ),
    };
    Ok(Json(ChallengeResponse {
        txt_record_name: format!("{CHALLENGE_PREFIX}{domain}"),
        txt_record_value: format!("enclava-domain-verification={token}"),
        acme_cname_name,
        acme_cname_target,
        domain,
        expires_at,
        instructions,
    }))
}

/// Total-time bound for the same-domain re-verify readiness probe. The
/// kube client carries no default total timeout, and the receipt must not
/// be delayed behind one hung StatefulSet GET (the residual the finite
/// lease + reconciler already bound; this keeps the request path fast
/// too).
const VERIFY_ROLLOUT_PROBE_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// Map a rollout-settled probe outcome to the verify receipt's
/// `ingress_ready`, failing closed on every shape but a positively
/// settled rollout: probe error, missing workload (None), an in-flight
/// rollout (Some(false)), and a probe that exceeds `bound` all read as
/// not-ready.
async fn ingress_ready_from_probe<F>(probe: F, bound: std::time::Duration) -> bool
where
    F: std::future::Future<Output = Result<Option<bool>, crate::deploy::DeployError>>,
{
    match tokio::time::timeout(bound, probe).await {
        Ok(Ok(Some(true))) => true,
        Ok(Ok(Some(false))) | Ok(Ok(None)) | Ok(Err(_)) | Err(_) => false,
    }
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub domain: String,
    pub verified_at: chrono::DateTime<Utc>,
    /// Whether the tenant ingress is provably serving this domain. `false`
    /// after a verify that SCHEDULED the restart (the pod converges on its
    /// own clock — in password mode only after the owner's unlock), for an
    /// app not yet deployed, and on same-domain re-verification while the
    /// live StatefulSet rollout has not settled. Clients learn convergence
    /// from the app's readiness surfaces (a re-verify consults the live
    /// rollout; a deploy re-renders the signed descriptor); this field is
    /// the verify-time snapshot, not a subscription.
    pub ingress_ready: bool,
}

/// Refuse the verify when this app's apply is still in progress: restarting
/// a live first-boot volume initialization can leave an unrecoverable
/// partial volume. Evaluated inside the caller's deployment-lane
/// transaction so a concurrently committing 'watching' transition cannot
/// slip past it. 'pending' deployments have produced no provider objects
/// yet and keep the predeploy verify path. Terminal rows pass THIS guard
/// only: changing the domain still requires live initialization proof before
/// restarting; same-domain DNS/edge re-verification does not restart the pod.
async fn ensure_no_apply_in_progress(
    app_lane: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let apply_in_progress: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM deployments
              WHERE app_id = $1
                AND status IN ('applying'::deploy_status_enum, 'watching'::deploy_status_enum)
         )",
    )
    .bind(app_id)
    .fetch_one(&mut **app_lane)
    .await
    .map_err(|_| internal_error())?;
    if apply_in_progress {
        Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "deployment_in_progress",
                "message": "app deployment in progress"
            })),
        ))
    } else {
        Ok(())
    }
}

/// POST /apps/{name}/domains/{domain}/verify -- verify a published TXT record.
pub async fn verify_challenge(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((app_name, domain)): Path<(String, String)>,
) -> Result<Json<VerifyResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    let mut app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
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

    let (challenge_id, token, expires_at, verified_at) = row.ok_or_else(|| {
        let e = DomainError::NoChallenge;
        (
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;

    // Expiry is absolute: a challenge past `expires_at` is refused whether or
    // not ownership was previously proven (migration 0014: "`expires_at` bounds
    // the window for the proof"). The live TXT lookup is not run, so an expired
    // challenge never re-contacts DNS.
    if Utc::now() > expires_at {
        let e = DomainError::Expired;
        return Err((
            e.status(),
            Json(serde_json::json!({"error": e.to_string()})),
        ));
    }

    // Every verify re-proves current DNS control with a live TXT lookup -- a
    // captured `verified_at` does not bypass it. The lookup runs before the
    // app-mutation lease is claimed so the lease is never held across DNS; a
    // lookup failure returns without ever claiming it. `verified_at` is not
    // persisted here -- it is written inside the apply transaction below, after
    // the CAS guard, so persist + apply commit or roll back together.
    let txt_name = format!("{CHALLENGE_PREFIX}{domain}");
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

    // Every verify also re-proves the ACME CNAME delegation for out-of-zone
    // domains with a live lookup (the same shared predicate the certificate
    // pre-flight uses, so the proof and issuance cannot drift). The check
    // applies only where the DNS-01 broker is the certificate issuer:
    // in-zone domains (answered directly), broker-less deployments (e.g.
    // Caddy TLS-ALPN, which never queries _acme-challenge), and
    // deployments with no managed DNS provider are unaffected.
    if let (Some(dns), Some(acme_config)) = (state.dns.as_ref(), state.acme.as_ref())
        && !dns.manages_hostname(&domain)
        && crate::acme::verify_acme_delegation(
            &domain,
            &dns.cloudflare_zone_name,
            &crate::acme::live_cname_lookup(Some(acme_config)),
        )
        .await
        .is_err()
    {
        // Mirror the issuance path's bounded warn so an operator can see
        // refused verifies in diagnostics; no hostname or provider text.
        tracing::warn!(
            code = "acme_delegation_missing",
            "custom domain verify refused: ACME CNAME delegation missing"
        );
        // Out-of-zone with the broker configured always derives a pair;
        // the match keeps the invariant explicit instead of defaulting.
        match acme_cname_fields(Some(dns), Some(acme_config), &domain) {
            (Some(name), Some(target)) => return Err(delegation_missing_response(&name, &target)),
            _ => return Err(internal_error()),
        }
    }
    // Reuse the captured timestamp or stage a new one; it is persisted inside
    // the apply transaction below.
    let (verified_at, needs_persist) = match verified_at {
        Some(verified_at) => (verified_at, false),
        None => (Utc::now(), true),
    };

    // Domain mutation follows the same queue order as deployment apply:
    // apply-specific capacity, shared side-effect admission, then DB lanes.
    let apply_permit = state
        .deployment_apply_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| internal_error())?;
    let engine = if app.custom_domain.as_deref() != Some(domain.as_str()) {
        Some(enclava_engine::apply::engine::ApplyEngine::new(
            state.kube_client.clone(),
            enclava_engine::apply::types::ApplyConfig::default(),
        ))
    } else {
        None
    };
    let previous_custom = app.custom_domain.clone();
    let expected_namespace = app.namespace.clone();
    let mut resources = vec![
        crate::mutation_leases::ResourceFence::dns(&domain),
        crate::mutation_leases::ResourceFence::edge(&domain),
        crate::mutation_leases::ResourceFence::edge_config(),
        crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
    ];
    if let Some(old) = previous_custom.as_deref() {
        resources.push(crate::mutation_leases::ResourceFence::dns(old));
        resources.push(crate::mutation_leases::ResourceFence::edge(old));
    }
    let mutation = crate::mutation_leases::claim(
        &state,
        app.id,
        crate::mutation_leases::CUSTOM_DOMAIN_SET_OPERATION,
        challenge_id,
        false,
        resources.clone(),
    )
    .await;
    let mut mutation = match mutation {
        Ok(mutation) => mutation,
        Err(crate::mutation_leases::MutationLeaseError::Busy) => {
            return Err(crate::routes::apps::app_mutation_busy_error(
                &state.db, app.id, &resources,
            )
            .await);
        }
        Err(_) => return Err(internal_error()),
    };
    // cap#422: every error path from here on releases the claimed rows —
    // a stranded lease reports as idempotency_request_in_progress until
    // reclaim_after (observed 9 minutes on dev).
    let edge_config_generation =
        match mutation.resource_generation(&crate::mutation_leases::ResourceFence::edge_config()) {
            Some(generation) => generation,
            None => {
                release_mutation(&state, &mut mutation, app.id).await?;
                return Err(internal_error());
            }
        };
    let kubernetes_mutation_generation = match mutation.resource_generation(
        &crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
    ) {
        Some(generation) => generation,
        None => {
            release_mutation(&state, &mut mutation, app.id).await?;
            return Err(internal_error());
        }
    };

    let mut app_lane = state.db.begin().await.map_err(|_| internal_error())?;
    if crate::entitlements::lock_org_entitlement_lane(&mut app_lane, auth.org_id)
        .await
        .is_err()
    {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(internal_error());
    }
    let current_role = match crate::auth::scopes::lock_and_read_active_membership_role_in_tx(
        &mut app_lane,
        auth.org_id,
        auth.user_id,
    )
    .await
    {
        Ok(role) => role,
        Err(response) => {
            release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
            return Err(response);
        }
    };
    if let Err(response) = crate::auth::scopes::require_admin_role(current_role) {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(response);
    }
    if crate::deploy::lock_app_deployment_lane(&mut app_lane, app.id)
        .await
        .is_err()
    {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(internal_error());
    }
    let current_app: Option<App> = match sqlx::query_as(
        "SELECT * FROM apps
          WHERE id = $1
            AND org_id = $2
            AND status <> 'deleting'::app_status_enum
            AND custom_domain IS NOT DISTINCT FROM $3
            AND namespace = $4",
    )
    .bind(app.id)
    .bind(auth.org_id)
    .bind(previous_custom.as_deref())
    .bind(&expected_namespace)
    .fetch_optional(&mut *app_lane)
    .await
    {
        Ok(app) => app,
        Err(_) => {
            release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
            return Err(internal_error());
        }
    };
    let Some(current_app) = current_app else {
        mutation
            .finish_in_tx(&mut app_lane)
            .await
            .map_err(|_| internal_error())?;
        app_lane.commit().await.map_err(|_| internal_error())?;
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "app authority changed"})),
        ));
    };
    app = current_app;

    if let Err(conflict) = ensure_no_apply_in_progress(&mut app_lane, app.id).await {
        mutation
            .finish_in_tx(&mut app_lane)
            .await
            .map_err(|_| internal_error())?;
        app_lane.commit().await.map_err(|_| internal_error())?;
        return Err(conflict);
    }

    // Re-verification repairs DNS/edge only; changing the domain restarts the pod.
    if let Some(engine) = engine.as_ref() {
        let refuse = match crate::deploy::ingress_restart_verdict(engine, &app.namespace, &app.name)
            .await
        {
            Ok(crate::deploy::IngressRestartVerdict::NotDeployed)
            | Ok(crate::deploy::IngressRestartVerdict::Ready) => None,
            Ok(crate::deploy::IngressRestartVerdict::Unproven) => {
                // The strict whole-second rule exists to defend the
                // size-floor waiver against a pod predating a REPLACED
                // claim; as restart admission it refuses the FIRST domain
                // verify of every fresh app, because a StatefulSet's
                // ordinal-0 pod is normally created in the same whole
                // second as its claims (observed on dev). Adding the first
                // domain admits on the timestamp-agnostic proof instead: a
                // Ready pod that mounts both claims completed first-boot on
                // these volumes, and the residual same-second replacement
                // ambiguity is healed by the very rollout restart this
                // admits. Domain CHANGES keep the strict rule.
                if previous_custom.is_none()
                    && enclava_engine::apply::orchestrator::inspect_ready_pod_mounts_all_claims(
                        engine,
                        &app.namespace,
                        &app.name,
                    )
                    .await
                    .unwrap_or(false)
                {
                    None
                } else {
                    Some((
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "volume_init_unproven",
                            "message": "volume initialization has not proven complete; recover the deployment before changing domains"
                        })),
                    ))
                }
            }
            Err(error) => {
                tracing::error!(
                    app_id = %app.id,
                    %error,
                    "domain restart admission probe failed"
                );
                Some(internal_error())
            }
        };
        if let Some(conflict) = refuse {
            mutation
                .finish_in_tx(&mut app_lane)
                .await
                .map_err(|_| internal_error())?;
            app_lane.commit().await.map_err(|_| internal_error())?;
            return Err(conflict);
        }
    }

    // Commit proof and domain assignment together, only after restart admission.
    if needs_persist
        && sqlx::query("UPDATE custom_domain_challenges SET verified_at = $1 WHERE id = $2")
            .bind(verified_at)
            .bind(challenge_id)
            .execute(&mut *app_lane)
            .await
            .is_err()
    {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(internal_error());
    }

    let dns_record = match mutation
        .guard_provider(crate::dns::record_custom_domain(&state.db, app.id, &domain))
        .await
    {
        Ok(result) => result,
        Err(_) => {
            // Renewal lost mid-DNS-write: the request may still land
            // server-side, so the app's fences stay quarantined
            // (cap#422). No edge request was issued on this arm, so the
            // cross-app edge_config fence is released instead of idling
            // through the reclaim quarantine.
            quarantine_mutation_and_rollback_lane_releasing_edge_config(&mutation, app_lane)
                .await?;
            return Err(internal_error());
        }
    };
    if let Err(dns_error) = dns_record {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(dns_error_response(dns_error));
    }

    if app.custom_domain.as_deref() == Some(domain.as_str()) {
        // cap#422: same-domain re-verification used to publish the HAProxy
        // route unconditionally, which resolves the app Service — with no
        // live workload the lookup 500s AND (pre-fix) the just-claimed
        // mutation leases were never released. Apply the first-verification
        // rule instead: a missing Service (Kubernetes NotFound) skips the
        // route publish — the first deploy publishes it — and the verify
        // returns 200 with ingress_ready=false. Any OTHER backend error
        // stays a typed, code-shaped 502, with the mutation released.
        let backend_resolution =
            crate::edge::resolve_backend_target(&state.kube_client, &app.name, &app.namespace, 443)
                .await;
        let backend_deployed = match same_domain_backend_verdict(&backend_resolution) {
            SameDomainBackend::Deployed => true,
            SameDomainBackend::NotDeployed => {
                tracing::info!(
                    app_id = %app.id,
                    %domain,
                    "same-domain re-verification skipped the edge route publish: app not yet deployed"
                );
                false
            }
            SameDomainBackend::Unavailable => {
                tracing::error!(
                    app_id = %app.id,
                    %domain,
                    error = %backend_resolution.as_ref().expect_err("the verdict guarantees an error"),
                    "same-domain re-verification backend resolution failed"
                );
                release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
                return Err(edge_route_unavailable());
            }
        };
        if backend_deployed {
            let route_publish = match mutation
                .guard_provider(ensure_custom_domain_haproxy_route(
                    &state,
                    auth.org_id,
                    &app,
                    &domain,
                    edge_config_generation,
                ))
                .await
            {
                Ok(result) => result,
                Err(_) => {
                    // Durable renewal was lost mid-publish: the HAProxy
                    // write may still land, so the fences stay quarantined
                    // (cap#422).
                    quarantine_mutation_and_rollback_lane(&mutation, app_lane).await?;
                    return Err(internal_error());
                }
            };
            if let Err(response) = route_publish {
                release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
                return Err(response);
            }
        }
        mutation
            .finish_in_tx(&mut app_lane)
            .await
            .map_err(|_| internal_error())?;
        app_lane.commit().await.map_err(|_| internal_error())?;
        drop(apply_permit);
        if !backend_deployed {
            return Ok(Json(VerifyResponse {
                domain,
                verified_at,
                ingress_ready: false,
            }));
        }
        // Same-domain re-verification repairs DNS/edge only — but the
        // ingress is only provably serving when the live StatefulSet has
        // converged (a restart scheduled by an earlier verify may still be
        // replacing a locked password-mode pod). Fail closed on probe
        // errors, a missing workload, or an in-flight rollout.
        let engine = enclava_engine::apply::engine::ApplyEngine::new(
            state.kube_client.clone(),
            enclava_engine::apply::types::ApplyConfig::default(),
        );
        let probe = crate::deploy::workload_rollout_settled(&engine, &app.namespace, &app.name);
        let ingress_ready = ingress_ready_from_probe(probe, VERIFY_ROLLOUT_PROBE_BOUND).await;
        return Ok(Json(VerifyResponse {
            domain,
            verified_at,
            ingress_ready,
        }));
    }

    let previous_custom = app.custom_domain.clone();

    // Re-render the tenant-ingress ConfigMap before publishing the HAProxy
    // route. Caddy does not watch its ConfigMap, so reapply_tenant_ingress
    // also restarts the StatefulSet; the restart is scheduled, not waited
    // on — the pod becomes Ready on its own clock (in password mode only
    // after the owner's unlock), and the request returns well inside the
    // hosted proxy timeout. If the app has not been deployed yet, persist
    // the verified custom domain and let the first deploy publish the route.
    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let next_app = App {
        custom_domain: Some(domain.clone()),
        ..app.clone()
    };
    // `false` for the scheduled-restart and not-deployed paths: the custom
    // domain is verified and routed, but the serving ingress converges on
    // the pod's own readiness clock (the route below still publishes — the
    // backend exists in both cases; only the not-deployed path defers it).
    let mut ingress_scheduled = false;
    let tenant_ingress = match mutation
        .guard_provider(crate::deploy::reapply_tenant_ingress(
            &state.kube_client,
            &state.db,
            &next_app,
            state.attestation.as_ref(),
            &api_signing_pubkey,
            &state.api_url,
            &mutation,
            kubernetes_mutation_generation,
        ))
        .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            // cap#422 R2 round 4 (review 4703156939): durable renewal was
            // lost mid-reapply. The tenant-ingress write is APP-SCOPED
            // state -- reapply_tenant_ingress SSA-applies the app's own
            // ConfigMap in its namespace (deploy.rs:6961-6962) and patches
            // its StatefulSet restart annotation; the shared route
            // publish starts only after this step returns, so no edge
            // request is in flight and the cross-app edge_config fence is
            // released. The app's own fences (its namespace, dns/edge for
            // its domains) stay quarantined: the uncertain ConfigMap
            // write may still land server-side and a missing-object
            // create has no version to fence it.
            quarantine_mutation_and_rollback_lane_releasing_edge_config(&mutation, app_lane)
                .await?;
            return Err(internal_error());
        }
    };
    match tenant_ingress {
        Ok(()) => {
            ingress_scheduled = true;
        }
        Err(crate::deploy::DeployError::NoContainers)
        | Err(crate::deploy::DeployError::NotDeployed(_)) => {
            tracing::info!(
                app_id = %app.id,
                %domain,
                "tenant ingress regeneration skipped: app not yet deployed"
            );
        }
        Err(e) => {
            // Codex P2: an ingress reapply whose accepted write lost CAP
            // creation evidence must durably mark the app — this path has
            // no deployment job, so without the marker a later failed
            // apply's sweep would treat the stripped object as foreign and
            // clear cleanup evidence over it.
            if matches!(
                e,
                crate::deploy::DeployError::Apply(
                    enclava_engine::apply::engine::ApplyError::CreationEvidenceLost { .. }
                )
            ) && !crate::deployment_failure_cleanup::persist_creation_evidence_loss(
                &state.db, app.id,
            )
            .await
            {
                // The marker is the only durable signal for later sweeps;
                // surface its loss distinctly instead of silently
                // continuing (the request already failed).
                tracing::error!(
                    app_id = %app.id,
                    "creation-evidence-loss marker could not be persisted; later sweeps will not know unmarked targets may be CAP-created"
                );
            }
            tracing::error!(
                app_id = %app.id,
                %domain,
                error = %e,
                "failed to regenerate tenant ingress for verified custom domain"
            );
            release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                // Code-shaped, provider-text-free (the DeployError display
                // carries internals); the full cause is in the log line above.
                Json(serde_json::json!({"error": "tenant_ingress_update_failed"})),
            ));
        }
    };
    let app_backend = if ingress_scheduled {
        // The restart is scheduled: the edge route publishes now (the
        // backend exists and serves once the rollout converges), while the
        // response's ingress_ready stays false so the client knows serving
        // is converging rather than established.
        match mutation
            .guard_provider(ensure_custom_domain_haproxy_route(
                &state,
                auth.org_id,
                &app,
                &domain,
                edge_config_generation,
            ))
            .await
        {
            Ok(Ok(backend)) => backend,
            Ok(Err(response)) => {
                release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
                return Err(response);
            }
            Err(_) => {
                // Renewal lost mid-publish: the write may still land, so
                // the fences stay quarantined (cap#422).
                quarantine_mutation_and_rollback_lane(&mutation, app_lane).await?;
                return Err(internal_error());
            }
        }
    } else {
        let org_slug: String =
            match sqlx::query_scalar("SELECT cust_slug FROM organizations WHERE id = $1")
                .bind(auth.org_id)
                .fetch_one(&state.db)
                .await
            {
                Ok(slug) => slug,
                Err(_) => {
                    release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane)
                        .await?;
                    return Err(internal_error());
                }
            };
        match crate::edge::backend_name_for(&org_slug, &app.name, crate::edge::BackendTag::App) {
            Ok(backend) => backend,
            Err(e) => {
                release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("invalid app name: {e}")})),
                ));
            }
        }
    };

    if sqlx::query("UPDATE apps SET custom_domain = $1, updated_at = now() WHERE id = $2")
        .bind(&domain)
        .bind(app.id)
        .execute(&mut *app_lane)
        .await
        .is_err()
    {
        release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
        return Err(internal_error());
    }

    if let Some(old) = previous_custom.as_deref()
        && old != domain
    {
        let dns_delete = match mutation
            .guard_provider(crate::dns::delete_dns_record(
                &state.db,
                &state.http_client,
                state.dns.as_ref(),
                app.id,
                old,
            ))
            .await
        {
            Ok(result) => result,
            Err(_) => {
                // Renewal lost mid-delete: the Cloudflare deletion may
                // still land, so the app's fences stay quarantined
                // (cap#422). No edge request was issued on this arm, so
                // the cross-app edge_config fence is released instead of
                // idling through the reclaim quarantine.
                quarantine_mutation_and_rollback_lane_releasing_edge_config(&mutation, app_lane)
                    .await?;
                return Err(internal_error());
            }
        };
        if let Err(dns_error) = dns_delete {
            release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
            return Err(dns_error_response(dns_error));
        }
        let edge_removal = match mutation
            .guard_provider(crate::edge::remove_haproxy_routes(
                &state.kube_client,
                &state.db,
                &crate::edge::EdgeRouteConfig::from_env(),
                Some(edge_config_generation),
                &[(app_backend.clone(), old.to_string())],
            ))
            .await
        {
            Ok(result) => result,
            Err(_) => {
                // Renewal lost mid-removal: the route removal may still
                // land, so the fences stay quarantined (cap#422).
                quarantine_mutation_and_rollback_lane(&mutation, app_lane).await?;
                return Err(internal_error());
            }
        };
        if edge_removal.is_err() {
            release_mutation_and_rollback_lane(&state, &mut mutation, app.id, app_lane).await?;
            return Err((
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "previous edge route reconciliation failed"})),
            ));
        }
    }

    mutation
        .finish_in_tx(&mut app_lane)
        .await
        .map_err(|_| internal_error())?;
    app_lane.commit().await.map_err(|_| internal_error())?;
    drop(apply_permit);

    Ok(Json(VerifyResponse {
        domain,
        verified_at,
        // Scheduled restart (or not-yet-deployed): verified and routed, but
        // serving converges with the rollout.
        ingress_ready: false,
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
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

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

    let resources = vec![
        crate::mutation_leases::ResourceFence::dns(&domain),
        crate::mutation_leases::ResourceFence::edge(&domain),
        crate::mutation_leases::ResourceFence::edge_config(),
    ];
    let mutation = crate::mutation_leases::claim(
        &state,
        app.id,
        "custom_domain_remove",
        Uuid::new_v4(),
        false,
        resources.clone(),
    )
    .await;
    let mut mutation = match mutation {
        Ok(mutation) => mutation,
        Err(crate::mutation_leases::MutationLeaseError::Busy) => {
            return Err(crate::routes::apps::app_mutation_busy_error(
                &state.db, app.id, &resources,
            )
            .await);
        }
        Err(_) => return Err(internal_error()),
    };
    let edge_config_generation = mutation
        .resource_generation(&crate::mutation_leases::ResourceFence::edge_config())
        .ok_or_else(internal_error)?;
    let mut app_lane = state.db.begin().await.map_err(|_| internal_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut app_lane, auth.org_id)
        .await
        .map_err(|_| internal_error())?;
    crate::deploy::lock_app_deployment_lane(&mut app_lane, app.id)
        .await
        .map_err(|_| internal_error())?;
    let current_role = crate::auth::scopes::lock_and_read_active_membership_role_in_tx(
        &mut app_lane,
        auth.org_id,
        auth.user_id,
    )
    .await?;
    crate::auth::scopes::require_admin_role(current_role)?;
    let current: bool = sqlx::query_scalar(
        "SELECT EXISTS(
             SELECT 1 FROM apps
              WHERE id = $1
                AND org_id = $2
                AND status <> 'deleting'::app_status_enum
                AND custom_domain = $3
         )",
    )
    .bind(app.id)
    .bind(auth.org_id)
    .bind(&domain)
    .fetch_one(&mut *app_lane)
    .await
    .map_err(|_| internal_error())?;
    if !current {
        mutation
            .finish_in_tx(&mut app_lane)
            .await
            .map_err(|_| internal_error())?;
        app_lane.commit().await.map_err(|_| internal_error())?;
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "custom domain authority changed"})),
        ));
    }

    mutation
        .guard_provider(crate::dns::delete_dns_record(
            &state.db,
            &state.http_client,
            state.dns.as_ref(),
            app.id,
            &domain,
        ))
        .await
        .map_err(|_| internal_error())?
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
    if mutation
        .guard_provider(crate::edge::remove_haproxy_routes(
            &state.kube_client,
            &state.db,
            &edge_config,
            Some(edge_config_generation),
            &[(app_backend, domain.clone())],
        ))
        .await
        .map_err(|_| internal_error())?
        .is_err()
    {
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({"error": "edge route reconciliation failed"})),
        ));
    }

    sqlx::query("UPDATE apps SET custom_domain = NULL, updated_at = now() WHERE id = $1 AND custom_domain = $2")
        .bind(app.id)
        .bind(&domain)
        .execute(&mut *app_lane)
        .await
        .map_err(|_| internal_error())?;

    mutation
        .finish_in_tx(&mut app_lane)
        .await
        .map_err(|_| internal_error())?;
    app_lane.commit().await.map_err(|_| internal_error())?;

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
    // Test seam: hermetic tests pin the TXT answer for a name instead of
    // resolving live (the production path below is untouched). Keyed by
    // name so only the registering test's own lookups are affected.
    #[cfg(test)]
    {
        let map = TXT_TEST_ANSWERS.lock().expect("txt test answers lock");
        if let Some(values) = map.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()) {
            return Ok(values);
        }
    }
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
    let response = match resolver.txt_lookup(name).await {
        Ok(response) => response,
        // A name with no TXT record yet is the ordinary "not published or
        // not propagated" case, not a resolver failure: report it as an
        // empty answer so verify refuses with the precise 412 instead of a
        // 502 the idempotency layer turns into `idempotency_recovery_required`.
        Err(e) => return absent_txt_or_lookup_error(e),
    };
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

/// Hermetic TXT answers for `lookup_txt` (tests only). Registered by
/// name so concurrent tests do not interfere; every entry must be
/// removed by the registering test before it returns.
#[cfg(test)]
static TXT_TEST_ANSWERS: std::sync::Mutex<Vec<(String, Vec<String>)>> =
    std::sync::Mutex::new(Vec::new());

/// NXDOMAIN and NODATA mean "no TXT record here" and become an empty answer;
/// every other resolver error (SERVFAIL, timeout, transport) stays a failure.
fn absent_txt_or_lookup_error(error: NetError) -> Result<Vec<String>, String> {
    let error = DnsLookupError::from(error);
    if error.is_record_absent() {
        Ok(Vec::new())
    } else {
        Err(error.into_message())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_lookup_treats_absent_records_as_empty_and_failures_as_errors() {
        use hickory_resolver::net::{DnsError, NoRecords};
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};
        let query = Query::query(
            Name::from_ascii("_enclava-challenge.example.com.").unwrap(),
            RecordType::TXT,
        );
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let error = NetError::from(NoRecords::new(query.clone(), code));
            assert_eq!(absent_txt_or_lookup_error(error), Ok(Vec::new()));
        }
        for error in [
            NetError::from(NoRecords::new(query, ResponseCode::ServFail)),
            NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
            NetError::Timeout,
            NetError::NoConnections,
        ] {
            assert!(absent_txt_or_lookup_error(error).is_err());
        }
    }

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

    async fn insert_guard_app(pool: &sqlx::PgPool, status: &str) -> (Uuid, Uuid) {
        let (app, deployment_id, _, _) =
            crate::deployment_jobs::tests::insert_job_fixture(pool).await;
        sqlx::query("UPDATE deployments SET status = $2::deploy_status_enum WHERE id = $1")
            .bind(deployment_id)
            .bind(status)
            .execute(pool)
            .await
            .expect("set guard deployment phase");
        (app.org_id, app.id)
    }

    async fn guard_verdict(
        pool: &sqlx::PgPool,
        app_id: Uuid,
    ) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
        let mut tx = pool.begin().await.expect("begin guard transaction");
        ensure_no_apply_in_progress(&mut tx, app_id).await
    }

    #[tokio::test]
    async fn in_progress_apply_blocks_domain_verify() {
        // An 'applying' or 'watching' deployment means a workload mutation —
        // possibly a first-boot volume format — is live; verification must
        // conflict instead of restarting the pod mid-initialization.
        let pool = crate::test_support::database_test_pool().await;
        for status in ["applying", "watching"] {
            let (org_id, app_id) = insert_guard_app(&pool, status).await;
            let Err((code, _)) = guard_verdict(&pool, app_id).await else {
                panic!("{status} deployment must conflict with domain verify");
            };
            assert_eq!(code, StatusCode::CONFLICT);
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn queued_or_finished_apply_allows_domain_verify() {
        // 'pending' rows produced no provider objects (the predeploy path
        // still works) and terminal rows no longer mutate anything.
        let pool = crate::test_support::database_test_pool().await;
        for status in ["pending", "healthy", "failed"] {
            let (org_id, app_id) = insert_guard_app(&pool, status).await;
            guard_verdict(&pool, app_id)
                .await
                .unwrap_or_else(|_| panic!("{status} deployment must not block domain verify"));
            sqlx::query("DELETE FROM organizations WHERE id = $1")
                .bind(org_id)
                .execute(&pool)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn other_apps_in_progress_apply_does_not_block_verify() {
        let pool = crate::test_support::database_test_pool().await;
        let (org_id, app_id) = insert_guard_app(&pool, "pending").await;
        let (other_org, _) = insert_guard_app(&pool, "watching").await;
        guard_verdict(&pool, app_id)
            .await
            .expect("unrelated app's in-progress apply must not block verify");
        sqlx::query("DELETE FROM organizations WHERE id IN ($1, $2)")
            .bind(org_id)
            .bind(other_org)
            .execute(&pool)
            .await
            .unwrap();
    }

    // --- cap#412: ACME delegation response shapes ---

    fn test_dns_config(zone: &str) -> crate::dns::DnsConfig {
        crate::dns::DnsConfig {
            cloudflare_api_token: "token".to_string(),
            cloudflare_api_base_url: "https://synthetic.invalid".to_string(),
            cloudflare_zone_id: None,
            cloudflare_zone_name: zone.to_string(),
            target: "192.0.2.10".to_string(),
            required: true,
        }
    }

    fn test_acme_config() -> crate::acme::AcmeConfig {
        crate::acme::AcmeConfig {
            directory_url: "https://synthetic.invalid/dir".to_string(),
            account_credentials_path: None,
            dns_propagation_wait: std::time::Duration::from_secs(30),
            dns_lookup_prefer_system: false,
            dns_lookup_timeout: None,
        }
    }

    #[test]
    fn acme_cname_fields_pair_by_zone_membership() {
        let dns = test_dns_config("managed.test");
        let acme = test_acme_config();
        let (name, target) = acme_cname_fields(Some(&dns), Some(&acme), "app.example.com");
        assert_eq!(name.as_deref(), Some("_acme-challenge.app.example.com"));
        assert_eq!(target.as_deref(), Some("app.example.com.acme.managed.test"));

        // In-zone domains (exact or suffix) need no delegation: null pair.
        for in_zone in ["managed.test", "app.managed.test"] {
            let (name, target) = acme_cname_fields(Some(&dns), Some(&acme), in_zone);
            assert!(name.is_none(), "{in_zone}");
            assert!(target.is_none(), "{in_zone}");
        }

        // No DNS provider configured: pair stays null (no certificate can
        // be issued there either).
        let (name, target) = acme_cname_fields(None, Some(&acme), "app.example.com");
        assert!(name.is_none());
        assert!(target.is_none());

        // Broker not configured (e.g. Caddy TLS-ALPN deployments): no
        // CNAME is demanded of the tenant even with managed DNS -- the
        // ownership TXT alone remains the proof, matching that mode's
        // certificate path, which never queries _acme-challenge.
        let (name, target) = acme_cname_fields(Some(&dns), None, "app.example.com");
        assert!(name.is_none(), "TLS-ALPN mode must not demand a CNAME");
        assert!(target.is_none());
    }

    #[test]
    fn delegation_targets_strip_dotted_zone_names() {
        // A zone configured with leading/trailing dots (tolerated by
        // manages_hostname) must still derive a publishable target.
        for zone in [".managed.test", "managed.test.", ".managed.test."] {
            let (name, target) = crate::acme::expected_acme_cname_pair("app.example.com", zone);
            assert_eq!(name, "_acme-challenge.app.example.com", "{zone}");
            assert_eq!(target, "app.example.com.acme.managed.test", "{zone}");
            assert!(!target.contains(".."), "{zone}");
        }
    }

    #[test]
    fn challenge_response_serializes_the_delegation_pair_as_null_in_zone() {
        let dns = test_dns_config("managed.test");
        let acme = test_acme_config();
        let in_zone = ChallengeResponse {
            domain: "app.managed.test".to_string(),
            txt_record_name: "_enclava-challenge.app.managed.test".to_string(),
            txt_record_value: "enclava-domain-verification=tok".to_string(),
            acme_cname_name: acme_cname_fields(Some(&dns), Some(&acme), "app.managed.test").0,
            acme_cname_target: acme_cname_fields(Some(&dns), Some(&acme), "app.managed.test").1,
            expires_at: Utc::now(),
            instructions: "publish".to_string(),
        };
        let value = serde_json::to_value(&in_zone).unwrap();
        // Keys are always present; in-zone values are null, not omitted.
        assert_eq!(value["acme_cname_name"], serde_json::json!(null));
        assert_eq!(value["acme_cname_target"], serde_json::json!(null));

        let (name, target) = acme_cname_fields(Some(&dns), Some(&acme), "app.example.com");
        let out_zone = ChallengeResponse {
            domain: "app.example.com".to_string(),
            txt_record_name: "_enclava-challenge.app.example.com".to_string(),
            txt_record_value: "enclava-domain-verification=tok".to_string(),
            acme_cname_name: name.clone(),
            acme_cname_target: target.clone(),
            expires_at: Utc::now(),
            instructions: "publish".to_string(),
        };
        let value = serde_json::to_value(&out_zone).unwrap();
        assert_eq!(
            value["acme_cname_name"],
            serde_json::json!(*name.as_deref().unwrap())
        );
        assert_eq!(
            value["acme_cname_target"],
            serde_json::json!(*target.as_deref().unwrap())
        );
    }

    #[test]
    fn delegation_missing_response_carries_the_actionable_pair() {
        let (status, Json(body)) = delegation_missing_response(
            "_acme-challenge.app.example.com",
            "app.example.com.acme.managed.test",
        );
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], serde_json::json!("acme_delegation_missing"));
        assert_eq!(
            body["acme_cname_name"],
            serde_json::json!("_acme-challenge.app.example.com")
        );
        assert_eq!(
            body["acme_cname_target"],
            serde_json::json!("app.example.com.acme.managed.test")
        );
        // Bounded shape: no detail/reason fields ever.
        let serialized = body.to_string();
        assert!(!serialized.contains("detail"));
        assert!(!serialized.contains("reason"));
    }

    // The verify receipt's ingress_ready contract (review MUST-FIX 2):
    // fail closed on every probe shape but a positively settled rollout,
    // including a probe that exceeds its bound. Run with
    // --test-threads=1 (the repo's ci.yml convention for DB-backed
    // suites; these are pure but keep the convention).
    #[tokio::test]
    async fn ingress_ready_is_true_only_for_a_settled_rollout() {
        use crate::deploy::DeployError;

        let settled = std::future::ready(Ok(Some(true)));
        assert!(ingress_ready_from_probe(settled, VERIFY_ROLLOUT_PROBE_BOUND).await);

        for not_ready in [
            std::future::ready(Ok(Some(false))),
            std::future::ready(Ok(None)),
            std::future::ready(Err(DeployError::MissingAttestationConfig)),
        ] {
            assert!(
                !ingress_ready_from_probe(not_ready, VERIFY_ROLLOUT_PROBE_BOUND).await,
                "unsettled / missing / errored probes must read not-ready"
            );
        }

        // A probe that never resolves is cut off by the bound: not-ready,
        // and the helper returns within it.
        let hung = tokio::time::timeout(
            VERIFY_ROLLOUT_PROBE_BOUND + std::time::Duration::from_secs(5),
            ingress_ready_from_probe(std::future::pending(), std::time::Duration::from_millis(20)),
        )
        .await
        .expect("the bound cuts the hung probe off");
        assert!(!hung);
    }

    /// cap#422: the NotFound classifier that separates "app not deployed"
    /// (skip the route publish, first-verification rule) from real backend
    /// failures.
    fn kube_err(code: u16, reason: &str) -> crate::edge::EdgeRouteError {
        crate::edge::EdgeRouteError::Kube(kube::Error::Api(Box::new(kube::core::Status {
            code,
            reason: reason.to_string(),
            message: "test".to_string(),
            ..Default::default()
        })))
    }

    #[test]
    fn is_kube_not_found_separates_missing_from_other_backend_errors() {
        let not_found = kube_err(404, "NotFound");
        assert!(crate::edge::is_kube_not_found(&not_found));
        let forbidden = kube_err(403, "Forbidden");
        assert!(!crate::edge::is_kube_not_found(&forbidden));
        // A database error must never read as NotFound.
        let database = crate::edge::EdgeRouteError::Database(sqlx::Error::RowNotFound);
        assert!(!crate::edge::is_kube_not_found(&database));
    }

    /// cap#422: the same-domain re-verification decision — a resolved
    /// backend deploys the route, Kubernetes NotFound skips the publish
    /// (the first-verification rule), every other backend error is a
    /// typed failure, never a bare 500.
    #[test]
    fn same_domain_backend_verdict_deploys_skips_or_fails() {
        assert_eq!(
            same_domain_backend_verdict(&Ok("10.0.0.1:443".to_string())),
            SameDomainBackend::Deployed
        );
        assert_eq!(
            same_domain_backend_verdict(&Err(kube_err(404, "NotFound"))),
            SameDomainBackend::NotDeployed
        );
        for other in [
            kube_err(403, "Forbidden"),
            kube_err(500, "InternalError"),
            crate::edge::EdgeRouteError::Database(sqlx::Error::RowNotFound),
        ] {
            assert_eq!(
                same_domain_backend_verdict(&Err(other)),
                SameDomainBackend::Unavailable,
                "only Kubernetes NotFound may skip the route publish"
            );
        }
    }

    /// cap#422: the error-path release — `release_mutation_and_rollback_lane`
    /// — must BOTH discard the lane's staged business writes (the pre-fix
    /// code dropped the lane uncommitted: no proof timestamp, no domain
    /// assignment may survive a failed verify) AND clear the claimed lease
    /// rows (the bug: stranded leases reported
    /// `idempotency_request_in_progress` until `reclaim_after`).
    #[sqlx::test]
    async fn release_rolls_back_staged_writes_and_clears_claimed_rows(pool: sqlx::PgPool) {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        // Reuse the deployment-jobs fixture for a schema-accurate app row.
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let app_id = app.id;
        let domain = "release-test.example.com";
        let operation_id = Uuid::new_v4();
        let resources = vec![
            crate::mutation_leases::ResourceFence::dns(domain),
            crate::mutation_leases::ResourceFence::edge(domain),
            crate::mutation_leases::ResourceFence::edge_config(),
            crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
        ];
        let mut mutation = crate::mutation_leases::claim(
            &state,
            app_id,
            crate::mutation_leases::CUSTOM_DOMAIN_SET_OPERATION,
            operation_id,
            false,
            resources.clone(),
        )
        .await
        .expect("claim the domain mutation");
        // Verify the rows are owned before the release (the claim owns one
        // row per fence: dns_hostname, edge_route, edge_config and the
        // namespace fence).
        let owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows");
        assert!(owned >= 4, "the claim must own the fence rows first");
        let mut lane = state.db.begin().await.expect("begin lane");
        crate::entitlements::lock_org_entitlement_lane(&mut lane, app.org_id)
            .await
            .expect("lock entitlement lane");
        crate::deploy::lock_app_deployment_lane(&mut lane, app_id)
            .await
            .expect("lock deployment lane");
        // Stage a business write in the lane, exactly as verify_challenge
        // does before its provider calls (the proof UPDATE, the apps
        // assignment UPDATE).
        sqlx::query("UPDATE apps SET custom_domain = $1, updated_at = now() WHERE id = $2")
            .bind("staged.example.com")
            .bind(app_id)
            .execute(&mut *lane)
            .await
            .expect("stage the domain assignment");
        release_mutation_and_rollback_lane(&state, &mut mutation, app_id, lane)
            .await
            .expect("release on the error path");
        // The staged write is rolled back, not committed by the release.
        let staged: Option<String> =
            sqlx::query_scalar("SELECT custom_domain FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("read the app row");
        assert_eq!(
            staged, None,
            "no staged business write survives the release"
        );
        let still_owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows after release");
        assert_eq!(still_owned, 0, "no fence rows remain owned after release");
        let app_lease_free: bool = sqlx::query_scalar(
            "SELECT owner_token IS NULL FROM app_mutation_leases WHERE app_id = $1",
        )
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("read the app mutation lease");
        assert!(app_lease_free, "the app mutation lease is released too");
    }

    /// cap#422: a statement that ABORTS the lane must not block the
    /// release — `finish_in_tx` cannot run inside an aborted transaction,
    /// so the release rolls the lane back and finishes in its own.
    #[sqlx::test]
    async fn release_survives_an_aborted_lane(pool: sqlx::PgPool) {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        // Reuse the deployment-jobs fixture for a schema-accurate app row.
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let app_id = app.id;
        let domain = "aborted-lane.example.com";
        let operation_id = Uuid::new_v4();
        let resources = vec![
            crate::mutation_leases::ResourceFence::dns(domain),
            crate::mutation_leases::ResourceFence::edge(domain),
            crate::mutation_leases::ResourceFence::edge_config(),
            crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
        ];
        let mut mutation = crate::mutation_leases::claim(
            &state,
            app_id,
            crate::mutation_leases::CUSTOM_DOMAIN_SET_OPERATION,
            operation_id,
            false,
            resources.clone(),
        )
        .await
        .expect("claim the domain mutation");
        let owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows");
        assert!(owned >= 4, "the claim must own the fence rows first");
        let mut lane = state.db.begin().await.expect("begin lane");
        crate::entitlements::lock_org_entitlement_lane(&mut lane, app.org_id)
            .await
            .expect("lock entitlement lane");
        crate::deploy::lock_app_deployment_lane(&mut lane, app_id)
            .await
            .expect("lock deployment lane");
        // A failing statement puts the transaction into the aborted state:
        // every later query on it would fail, so finish_in_tx could not
        // release the leases inside it.
        let aborted = sqlx::query("SELECT 1/0").execute(&mut *lane).await;
        assert!(aborted.is_err(), "1/0 must abort the lane");
        release_mutation_and_rollback_lane(&state, &mut mutation, app_id, lane)
            .await
            .expect("release on the aborted-lane error path");
        let still_owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows after release");
        assert_eq!(still_owned, 0, "the leases are released despite the abort");
        let app_lease_free: bool = sqlx::query_scalar(
            "SELECT owner_token IS NULL FROM app_mutation_leases WHERE app_id = $1",
        )
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("read the app mutation lease");
        assert!(app_lease_free, "the app mutation lease is released too");
    }

    /// cap#422: renewal lost mid-provider-call — the provider write's
    /// outcome is UNRESOLVED, so the fences must stay quarantined until
    /// reclaim (RECLAIM_QUARANTINE_SECONDS) instead of being released
    /// while a Kubernetes/DNS request can still land server-side. The
    /// staged business writes are still rolled back.
    /// cap#422 R2 round 4 (review 4703156939): renewal lost mid
    /// tenant-ingress reapply, on the REAL verify path. The tenant-ingress
    /// write is the APP's OWN ConfigMap (deploy.rs:6961-6962: SSA-applied
    /// in the app's namespace) plus its StatefulSet restart annotation --
    /// not edge state; the shared route publish starts only after that
    /// step returns (domains.rs:1064-1079). So this arm releases the
    /// cross-app edge_config fence while the app-scoped ones (its
    /// namespace, dns/edge for BOTH the old and the new domain) stay
    /// quarantined until reclaim_after.
    #[sqlx::test]
    async fn tenant_ingress_renewal_loss_releases_the_cross_app_fence(pool: sqlx::PgPool) {
        use crate::auth::middleware::ManagementOrigin;
        use crate::models::Role;

        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let (kube, _kube_task) = hanging_ingress_kube(&app.name).await;
        state.kube_client = kube;

        let old_domain = "tenant-ingress-old.example-test.com";
        let domain = "tenant-ingress-new.example-test.com";
        // A CHANGED domain: the restart-admission engine is Some (its
        // kube gate passes against the fake), and the re-verify reaches
        // the tenant-ingress reapply.
        sqlx::query("UPDATE apps SET custom_domain = $1 WHERE id = $2")
            .bind(old_domain)
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("pin the app to the old domain");
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'ingress-loss tester')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert the verifying user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("insert the owner membership");
        let token = "tenant-ingress-loss-token";
        let challenge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO custom_domain_challenges
                 (id, app_id, domain, challenge_token, expires_at)
             VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
        )
        .bind(challenge_id)
        .bind(app.id)
        .bind(domain)
        .bind(token)
        .execute(&pool)
        .await
        .expect("insert the domain challenge");
        let txt_name = format!("{CHALLENGE_PREFIX}{domain}");
        TXT_TEST_ANSWERS.lock().expect("txt answers lock").push((
            txt_name.clone(),
            vec![format!("enclava-domain-verification={token}")],
        ));

        let auth = AuthContext {
            user_id,
            org_id: app.org_id,
            org_name: format!("durable-{}", app.org_id),
            role: Role::Owner,
            api_key: None,
            management_origin: ManagementOrigin::Public,
        };
        let app_name = app.name.clone();
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            crate::routes::domains::verify_challenge(
                auth,
                State(task_state),
                Path((app_name, domain.to_string())),
            )
            .await
        });

        // Wait for the handler to claim the mutation (it then runs the
        // DNS-tracking write, passes admission against the fake kube, and
        // hangs in the tenant-ingress ConfigMap apply).
        let claim_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut task = task;
        loop {
            tokio::select! {
                settled = &mut task => {
                    panic!("the verify settled before the renewal loss: {settled:?}");
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            let claimed: bool = sqlx::query_scalar(
                "SELECT owner_token IS NOT NULL FROM app_mutation_leases WHERE app_id = $1",
            )
            .bind(app.id)
            .fetch_optional(&pool)
            .await
            .expect("poll the app mutation lease")
            .unwrap_or(false);
            if claimed {
                break;
            }
            assert!(
                std::time::Instant::now() < claim_deadline,
                "the verify never claimed the mutation"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Block the heartbeat's renewal on the app lease row past the 2s
        // test renew timeout while the ConfigMap apply is in flight.
        {
            let mut renewal_blocker = pool.begin().await.expect("begin the renewal blocker");
            sqlx::query("UPDATE app_mutation_leases SET updated_at = updated_at WHERE app_id = $1")
                .bind(app.id)
                .execute(&mut *renewal_blocker)
                .await
                .expect("lock the app mutation lease row");
            tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
            renewal_blocker
                .rollback()
                .await
                .expect("release the renewal blocker");
        }

        // The guard aborted (renewal lost mid-tenant-ingress) and the arm
        // ran. The join is deadline-bounded.
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), task)
            .await
            .expect("the verify must settle within the test deadline")
            .expect("the verify task must join")
            .expect_err("the renewal loss must fail the verify");
        assert_eq!(response.0, StatusCode::INTERNAL_SERVER_ERROR);

        // The lane rolled back: the staged verified_at write is gone.
        let verified_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT verified_at FROM custom_domain_challenges WHERE id = $1")
                .bind(challenge_id)
                .fetch_one(&pool)
                .await
                .expect("read the challenge row");
        assert!(
            verified_at.is_none(),
            "the staged verified_at write must roll back with the lane"
        );

        // The APP-SCOPED fences stay quarantined until reclaim_after: the
        // app's own namespace and dns/edge for BOTH the old and the new
        // domain (the uncertain ConfigMap write and the old domain's
        // cleanup are exactly what they guard).
        for (scope, key) in [
            ("kubernetes_namespace", app.namespace.clone()),
            ("dns_hostname", old_domain.to_string()),
            ("edge_route", old_domain.to_string()),
            ("dns_hostname", domain.to_string()),
            ("edge_route", domain.to_string()),
        ] {
            let owner: Option<Uuid> = sqlx::query_scalar(
                "SELECT owner_token FROM external_resource_mutation_leases
                  WHERE resource_scope = $1 AND resource_key = $2",
            )
            .bind(scope)
            .bind(&key)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("read the {scope}/{key} fence row"));
            assert!(
                owner.is_some(),
                "{scope}/{key} must stay quarantined until reclaim_after"
            );
        }

        // THE ROUND-4 PROPERTY: the tenant-ingress write is app-scoped
        // state, so the cross-app edge_config fence is RELEASED here too.
        let edge_owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT owner_token FROM external_resource_mutation_leases
              WHERE resource_scope = 'edge_config' AND resource_key = 'global'",
        )
        .fetch_one(&pool)
        .await
        .expect("read the edge_config fence row");
        assert!(
            edge_owner.is_none(),
            "the cross-app edge_config fence must be released after the tenant-ingress renewal loss"
        );
        match crate::mutation_leases::claim_resources(
            &state,
            "deployment-apply-test",
            Uuid::new_v4(),
            vec![crate::mutation_leases::ResourceFence::edge_config()],
        )
        .await
        {
            Ok(_lease) => {}
            Err(error) => panic!(
                "an unrelated app's deployment apply must be able to claim edge_config now: {error}"
            ),
        }

        TXT_TEST_ANSWERS
            .lock()
            .expect("txt answers lock")
            .retain(|(name, _)| name != &txt_name);
    }

    /// cap#422 R2 round 4 (review 4703157106): the EDGE-WRITE arm —
    /// renewal lost mid HAProxy route PUBLISH, on the REAL verify path.
    /// The route publish writes the SHARED edge config (the edge
    /// namespace's HAProxy ConfigMap); the request is in flight when the
    /// renewal dies, and a freed edge_config fence would let an unrelated
    /// deployment's reconcile claim the next generation and adopt the
    /// post-write config as its base — so THIS arm keeps the full
    /// quarantine, edge_config included, and an unrelated deployment
    /// apply requeues instead of proceeding.
    #[sqlx::test]
    async fn route_publish_renewal_loss_keeps_the_shared_edge_fence(pool: sqlx::PgPool) {
        use crate::auth::middleware::ManagementOrigin;
        use crate::models::Role;

        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let (kube, _kube_task) = hanging_ingress_kube(&app.name).await;
        state.kube_client = kube;
        let domain = "route-publish-loss.example-test.com";
        sqlx::query("UPDATE apps SET custom_domain = $1 WHERE id = $2")
            .bind(domain)
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("pin the app to the same domain");
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'publish-loss tester')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert the verifying user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("insert the owner membership");
        let token = "route-publish-loss-token";
        let challenge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO custom_domain_challenges
                 (id, app_id, domain, challenge_token, expires_at)
             VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
        )
        .bind(challenge_id)
        .bind(app.id)
        .bind(domain)
        .bind(token)
        .execute(&pool)
        .await
        .expect("insert the domain challenge");
        let txt_name = format!("{CHALLENGE_PREFIX}{domain}");
        TXT_TEST_ANSWERS.lock().expect("txt answers lock").push((
            txt_name.clone(),
            vec![format!("enclava-domain-verification={token}")],
        ));

        let auth = AuthContext {
            user_id,
            org_id: app.org_id,
            org_name: format!("durable-{}", app.org_id),
            role: Role::Owner,
            api_key: None,
            management_origin: ManagementOrigin::Public,
        };
        let app_name = app.name.clone();
        let task_state = state.clone();
        let mut task = tokio::spawn(async move {
            crate::routes::domains::verify_challenge(
                auth,
                State(task_state),
                Path((app_name, domain.to_string())),
            )
            .await
        });

        // Wait for the claim; the handler then runs the DNS-tracking
        // write, resolves the app Service against the fake (Deployed) and
        // hangs inside the route publish's edge ConfigMap write.
        let claim_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            tokio::select! {
                settled = &mut task => {
                    panic!("the verify settled before the renewal loss: {settled:?}");
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
            }
            let claimed: bool = sqlx::query_scalar(
                "SELECT owner_token IS NOT NULL FROM app_mutation_leases WHERE app_id = $1",
            )
            .bind(app.id)
            .fetch_optional(&pool)
            .await
            .expect("poll the app mutation lease")
            .unwrap_or(false);
            if claimed {
                break;
            }
            assert!(
                std::time::Instant::now() < claim_deadline,
                "the verify never claimed the mutation"
            );
        }

        // Block the heartbeat's renewal past the 2s test renew timeout
        // while the edge ConfigMap write is in flight.
        {
            let mut renewal_blocker = pool.begin().await.expect("begin the renewal blocker");
            sqlx::query("UPDATE app_mutation_leases SET updated_at = updated_at WHERE app_id = $1")
                .bind(app.id)
                .execute(&mut *renewal_blocker)
                .await
                .expect("lock the app mutation lease row");
            tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
            renewal_blocker
                .rollback()
                .await
                .expect("release the renewal blocker");
        }

        let response = tokio::time::timeout(std::time::Duration::from_secs(30), task)
            .await
            .expect("the verify must settle within the test deadline")
            .expect("the verify task must join")
            .expect_err("the renewal loss must fail the verify");
        assert_eq!(response.0, StatusCode::INTERNAL_SERVER_ERROR);

        // The lane rolled back: the staged verified_at write is gone.
        let verified_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT verified_at FROM custom_domain_challenges WHERE id = $1")
                .bind(challenge_id)
                .fetch_one(&pool)
                .await
                .expect("read the challenge row");
        assert!(
            verified_at.is_none(),
            "the staged verified_at write must roll back with the lane"
        );

        // THE ROUND-4 KEEP PROPERTY: the edge write is in flight, so the
        // cross-app edge_config fence STAYS quarantined until
        // reclaim_after — an unrelated deployment apply must NOT be able
        // to claim it (it requeues, exactly as deployment apply does
        // against a held fence).
        let edge_owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT owner_token FROM external_resource_mutation_leases
              WHERE resource_scope = 'edge_config' AND resource_key = 'global'",
        )
        .fetch_one(&pool)
        .await
        .expect("read the edge_config fence row");
        assert!(
            edge_owner.is_some(),
            "the edge_config fence must stay quarantined while the route publish is unresolved"
        );
        match crate::mutation_leases::claim_resources(
            &state,
            "deployment-apply-test",
            Uuid::new_v4(),
            vec![crate::mutation_leases::ResourceFence::edge_config()],
        )
        .await
        {
            Ok(_lease) => panic!(
                "an unrelated deployment apply must NOT claim edge_config while the route publish is unresolved"
            ),
            Err(crate::mutation_leases::MutationLeaseError::Busy) => {}
            Err(error) => panic!("the unrelated claim should be Busy, got {error}"),
        }

        TXT_TEST_ANSWERS
            .lock()
            .expect("txt answers lock")
            .retain(|(name, _)| name != &txt_name);
    }

    /// cap#422 R2 round 3: the EDGE-WRITE arms keep the full quarantine —
    /// an in-flight ConfigMap write can still land, and a freed
    /// edge_config fence would let an unrelated deployment's reconcile
    /// adopt the post-write config as its base (review 4702593725). The
    /// plain helper leaves every claimed row quarantined, edge_config
    /// included.
    #[sqlx::test]
    async fn edge_write_quarantine_keeps_the_shared_edge_config_fence(pool: sqlx::PgPool) {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let domain = "edge-quarantine.example.com";
        let operation_id = Uuid::new_v4();
        let resources = vec![
            crate::mutation_leases::ResourceFence::dns(domain),
            crate::mutation_leases::ResourceFence::edge(domain),
            crate::mutation_leases::ResourceFence::edge_config(),
            crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
        ];
        let mutation = crate::mutation_leases::claim(
            &state,
            app.id,
            crate::mutation_leases::CUSTOM_DOMAIN_SET_OPERATION,
            operation_id,
            false,
            resources.clone(),
        )
        .await
        .expect("claim the domain mutation");
        let mut lane = state.db.begin().await.expect("begin lane");
        crate::entitlements::lock_org_entitlement_lane(&mut lane, app.org_id)
            .await
            .expect("lock entitlement lane");
        crate::deploy::lock_app_deployment_lane(&mut lane, app.id)
            .await
            .expect("lock deployment lane");
        quarantine_mutation_and_rollback_lane(&mutation, lane)
            .await
            .expect("roll the lane back on the edge-write arm");
        drop(mutation);
        let still_owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows after quarantine");
        assert_eq!(
            still_owned, 4,
            "every fence stays quarantined on an edge-write arm, edge_config included"
        );
    }

    /// A minimal kube API stand-in for driving the REAL verify path past
    /// the restart-admission gate and INTO a provider call (round 4): the
    /// StatefulSet GET answers 200 (admission verdict: Ready), the PVC
    /// list answers empty, and the tenant-ingress ConfigMap apply is
    /// never answered -- the provider future hangs mid-write, exactly
    /// where a lost renewal must abort it.
    async fn hanging_ingress_kube(workload: &str) -> (kube::Client, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the fake kube listener");
        let port = listener.local_addr().unwrap().port();
        let workload = workload.to_string();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let workload = workload.clone();
                tokio::spawn(async move {
                    let mut stream = stream;
                    loop {
                        // Read one request head (and its body) so routing
                        // can look at the method and path.
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        loop {
                            match stream.readable().await {
                                Ok(()) => {}
                                Err(_) => return,
                            }
                            match stream.try_read(&mut byte) {
                                Ok(0) => return,
                                Ok(1) => {
                                    head.push(byte[0]);
                                    if head.ends_with(b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Ok(_) => {}
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    continue;
                                }
                                Err(_) => return,
                            }
                        }
                        let head_text = String::from_utf8_lossy(&head).to_string();
                        let mut lines = head_text.lines();
                        let request_line = lines.next().unwrap_or_default().to_string();
                        let mut content_length = 0usize;
                        for line in lines {
                            if let Some(value) =
                                line.to_ascii_lowercase().strip_prefix("content-length:")
                            {
                                content_length = value.trim().parse().unwrap_or(0);
                            }
                        }
                        let mut body = vec![0u8; content_length];
                        if content_length > 0 {
                            use tokio::io::AsyncReadExt;
                            let _ = stream.read_exact(&mut body).await;
                        }
                        let parts: Vec<&str> = request_line.split_whitespace().collect();
                        let method = parts.first().copied().unwrap_or("");
                        let path = parts.get(1).copied().unwrap_or("");
                        fn respond(status: &str, body: &str) -> String {
                            format!(
                                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: keep-alive\r\ncontent-length: {}\r\n\r\n{body}",
                                body.len()
                            )
                        }
                        let response = if path.contains("statefulsets") && method == "GET" {
                            Some(respond(
                                "200 OK",
                                "{\"apiVersion\":\"apps/v1\",\"kind\":\"StatefulSet\",\"metadata\":{\"name\":\"app\"},\"spec\":{},\"status\":{}}",
                            ))
                        } else if path.contains("persistentvolumeclaims") && method == "GET" {
                            // A provisioned claim older than the pod below,
                            // so the pod proves it initialized (admission
                            // verdict: Ready).
                            Some(respond(
                                "200 OK",
                                "{\"apiVersion\":\"v1\",\"kind\":\"PersistentVolumeClaim\",\"metadata\":{\"name\":\"claim\",\"creationTimestamp\":\"2020-01-01T00:00:00Z\"}}",
                            ))
                        } else if path.contains("pods") {
                            let claim = enclava_engine::manifest::volumes::provisioned_claim_name(
                                "state", &workload,
                            );
                            let tls_claim =
                                enclava_engine::manifest::volumes::provisioned_claim_name(
                                    "tls-state",
                                    &workload,
                                );
                            let pod = format!(
                                "{{\"apiVersion\":\"v1\",\"kind\":\"PodList\",\"metadata\":{{}},\"items\":[{{\"apiVersion\":\"v1\",\"kind\":\"Pod\",\"metadata\":{{\"name\":\"pod\",\"creationTimestamp\":\"2021-01-01T00:00:00Z\"}},\"spec\":{{\"volumes\":[{{\"name\":\"v0\",\"persistentVolumeClaim\":{{\"claimName\":\"{claim}\"}}}},{{\"name\":\"v1\",\"persistentVolumeClaim\":{{\"claimName\":\"{tls_claim}\"}}}}]}},\"status\":{{\"conditions\":[{{\"type\":\"Ready\",\"status\":\"True\"}}]}}}}]}}"
                            );
                            Some(respond("200 OK", &pod))
                        } else if path.contains("configmaps")
                            && method == "GET"
                            && path.contains("tenant-envoy")
                        {
                            // The SHARED edge config exists and parses as
                            // an empty HAProxy config; the route publish's
                            // write to it is what hangs below.
                            Some(respond(
                                "200 OK",
                                "{\"apiVersion\":\"v1\",\"kind\":\"ConfigMap\",\"metadata\":{\"name\":\"haproxy-tenant\",\"namespace\":\"tenant-envoy\"},\"data\":{\"haproxy.cfg\":\"global\\n\"}}",
                            ))
                        } else if path.contains("configmaps") && method == "GET" {
                            Some(respond(
                                "404 Not Found",
                                "{\"apiVersion\":\"v1\",\"kind\":\"Status\",\"status\":\"Failure\",\"reason\":\"NotFound\",\"code\":404,\"message\":\"not found\"}",
                            ))
                        } else if path.contains("configmaps") {
                            // The tenant-ingress ConfigMap SSA apply: never
                            // answer. The provider future stays in flight
                            // until the renewal loss aborts it.
                            None
                        } else {
                            Some(respond("200 OK", "{}"))
                        };
                        match response {
                            Some(response) => {
                                use tokio::io::AsyncWriteExt;
                                if stream.write_all(response.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                            None => {
                                // Hold the connection open without
                                // responding until the client goes away.
                                loop {
                                    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
                                }
                            }
                        }
                    }
                });
            }
        });
        let client = kube::Client::try_from(kube::Config::new(
            format!("http://127.0.0.1:{port}").parse().unwrap(),
        ))
        .expect("build the fake kube client");
        (client, task)
    }

    /// cap#422 R2 (review T1 + T2): drives the REAL verify path
    /// (verify_challenge) with a renewal loss injected INSIDE the
    /// DNS-tracking step (record_custom_domain). The dns_records row is
    /// row-locked so the guard's provider future blocks mid-write; the
    /// app mutation lease row is then held under a no-op write lock past
    /// the heartbeat's renew timeout (the test build runs a 1s heartbeat
    /// with a 2s renew timeout), which is the production renewal-loss
    /// condition reached on the real path. RED on the pre-R2 head
    /// (48bc819): the global edge_config fence stayed quarantined until
    /// reclaim, so the unrelated deployment-apply claim below returned
    /// Busy and the fence-owner assertion failed.
    #[sqlx::test]
    async fn renewal_loss_mid_verification_releases_the_cross_app_fence(pool: sqlx::PgPool) {
        use crate::auth::middleware::ManagementOrigin;
        use crate::models::Role;

        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let domain = "renewal-loss.example-test.com";
        // Same-domain re-verification: the restart-admission engine is
        // None on this path, so the black-hole test kube client is never
        // touched before the DNS-tracking step.
        sqlx::query("UPDATE apps SET custom_domain = $1 WHERE id = $2")
            .bind(domain)
            .bind(app.id)
            .execute(&pool)
            .await
            .expect("pin the app to the same domain");
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'renewal-loss tester')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert the verifying user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(app.org_id)
            .execute(&pool)
            .await
            .expect("insert the owner membership");
        // The challenge is unexpired and unverified: needs_persist stages
        // the verified_at write in the lane the arm must roll back.
        let token = "renewal-loss-challenge-token";
        let challenge_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO custom_domain_challenges
                 (id, app_id, domain, challenge_token, expires_at)
             VALUES ($1, $2, $3, $4, now() + interval '1 hour')",
        )
        .bind(challenge_id)
        .bind(app.id)
        .bind(domain)
        .bind(token)
        .execute(&pool)
        .await
        .expect("insert the domain challenge");
        let txt_name = format!("{CHALLENGE_PREFIX}{domain}");
        TXT_TEST_ANSWERS.lock().expect("txt answers lock").push((
            txt_name.clone(),
            vec![format!("enclava-domain-verification={token}")],
        ));
        // A pre-existing dns_records row for the hostname, row-locked by a
        // held transaction: record_custom_domain's upsert blocks on it.
        let dns_row = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO dns_records
                 (id, app_id, hostname, record_type, target, is_custom, provider)
             VALUES ($1, $2, $3, 'CUSTOM', '', true, 'user')",
        )
        .bind(dns_row)
        .bind(app.id)
        .bind(domain)
        .execute(&pool)
        .await
        .expect("seed the tracked dns record");
        let mut blocker = pool.begin().await.expect("begin the dns blocker");
        sqlx::query("SELECT id FROM dns_records WHERE id = $1 FOR UPDATE")
            .bind(dns_row)
            .execute(&mut *blocker)
            .await
            .expect("lock the tracked dns record");

        let auth = AuthContext {
            user_id,
            org_id: app.org_id,
            org_name: format!("durable-{}", app.org_id),
            role: Role::Owner,
            api_key: None,
            management_origin: ManagementOrigin::Public,
        };
        let app_name = app.name.clone();
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            crate::routes::domains::verify_challenge(
                auth,
                State(task_state),
                Path((app_name, domain.to_string())),
            )
            .await
        });

        // Wait for the handler to claim the mutation (it then blocks in
        // record_custom_domain on the locked dns_records row).
        let claim_deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let claimed: bool = sqlx::query_scalar(
                "SELECT owner_token IS NOT NULL FROM app_mutation_leases WHERE app_id = $1",
            )
            .bind(app.id)
            .fetch_optional(&pool)
            .await
            .expect("poll the app mutation lease")
            .unwrap_or(false);
            if claimed {
                break;
            }
            assert!(
                std::time::Instant::now() < claim_deadline,
                "the verify never claimed the mutation"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        // Block the heartbeat's renewal on the app lease row: a no-op
        // UPDATE holds the row write lock past the 2s test renew timeout,
        // so the heartbeat declares the lease lost while the provider
        // future is still blocked mid-DNS-write.
        {
            let mut renewal_blocker = pool.begin().await.expect("begin the renewal blocker");
            sqlx::query("UPDATE app_mutation_leases SET updated_at = updated_at WHERE app_id = $1")
                .bind(app.id)
                .execute(&mut *renewal_blocker)
                .await
                .expect("lock the app mutation lease row");
            tokio::time::sleep(std::time::Duration::from_millis(3500)).await;
            renewal_blocker
                .rollback()
                .await
                .expect("release the renewal blocker");
        }

        // The guard aborted (renewal lost mid-DNS-write) and the arm ran.
        // The join is deadline-bounded (review round 3): if the fixed
        // sleep ever misses the heartbeat timeout, the test fails here
        // instead of waiting on the still-held DNS lock forever.
        let response = tokio::time::timeout(std::time::Duration::from_secs(30), task)
            .await
            .expect("the verify must settle within the test deadline")
            .expect("the verify task must join")
            .expect_err("the renewal loss must fail the verify");
        assert_eq!(response.0, StatusCode::INTERNAL_SERVER_ERROR);

        // The lane rolled back: the staged verified_at write is gone.
        let verified_at: Option<chrono::DateTime<Utc>> =
            sqlx::query_scalar("SELECT verified_at FROM custom_domain_challenges WHERE id = $1")
                .bind(challenge_id)
                .fetch_one(&pool)
                .await
                .expect("read the challenge row");
        assert!(
            verified_at.is_none(),
            "the staged verified_at write must roll back with the lane"
        );

        // The APP-SCOPED fences stay quarantined until reclaim_after.
        for (scope, key) in [
            ("dns_hostname", domain.to_string()),
            ("edge_route", domain.to_string()),
            ("kubernetes_namespace", app.namespace.clone()),
        ] {
            let owner: Option<Uuid> = sqlx::query_scalar(
                "SELECT owner_token FROM external_resource_mutation_leases
                  WHERE resource_scope = $1 AND resource_key = $2",
            )
            .bind(scope)
            .bind(&key)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|_| panic!("read the {scope}/{key} fence row"));
            assert!(
                owner.is_some(),
                "{scope}/{key} must stay quarantined until reclaim_after"
            );
        }

        // THE R2 PROPERTY (review T1): the cross-app edge_config fence is
        // RELEASED on this arm — an unrelated app's deployment apply can
        // claim it immediately instead of waiting out the quarantine.
        let edge_owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT owner_token FROM external_resource_mutation_leases
              WHERE resource_scope = 'edge_config' AND resource_key = 'global'",
        )
        .fetch_one(&pool)
        .await
        .expect("read the edge_config fence row");
        assert!(
            edge_owner.is_none(),
            "the cross-app edge_config fence must be released after the renewal loss"
        );
        match crate::mutation_leases::claim_resources(
            &state,
            "deployment-apply-test",
            Uuid::new_v4(),
            vec![crate::mutation_leases::ResourceFence::edge_config()],
        )
        .await
        {
            Ok(_lease) => {}
            Err(error) => panic!(
                "an unrelated app's deployment apply must be able to claim edge_config now: {error}"
            ),
        }

        blocker.rollback().await.expect("release the dns blocker");
        TXT_TEST_ANSWERS
            .lock()
            .expect("txt answers lock")
            .retain(|(name, _)| name != &txt_name);
    }

    #[sqlx::test]
    async fn quarantine_on_renewal_loss_keeps_the_fences_and_rolls_back(pool: sqlx::PgPool) {
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        let (app, _deployment_id, _lease, _payload) =
            crate::deployment_jobs::tests::insert_job_fixture(&pool).await;
        let app_id = app.id;
        let domain = "quarantine-test.example.com";
        let operation_id = Uuid::new_v4();
        let resources = vec![
            crate::mutation_leases::ResourceFence::dns(domain),
            crate::mutation_leases::ResourceFence::edge(domain),
            crate::mutation_leases::ResourceFence::edge_config(),
            crate::mutation_leases::ResourceFence::new("kubernetes_namespace", &app.namespace),
        ];
        let mutation = crate::mutation_leases::claim(
            &state,
            app_id,
            crate::mutation_leases::CUSTOM_DOMAIN_SET_OPERATION,
            operation_id,
            false,
            resources.clone(),
        )
        .await
        .expect("claim the domain mutation");
        let mut lane = state.db.begin().await.expect("begin lane");
        crate::entitlements::lock_org_entitlement_lane(&mut lane, app.org_id)
            .await
            .expect("lock entitlement lane");
        crate::deploy::lock_app_deployment_lane(&mut lane, app_id)
            .await
            .expect("lock deployment lane");
        // Stage a business write in the lane, then simulate the renewal-loss
        // error path: the lane is rolled back, the fences stay quarantined.
        sqlx::query("UPDATE apps SET custom_domain = $1, updated_at = now() WHERE id = $2")
            .bind("quarantined.example.com")
            .bind(app_id)
            .execute(&mut *lane)
            .await
            .expect("stage the domain assignment");
        quarantine_mutation_and_rollback_lane_releasing_edge_config(&mutation, lane)
            .await
            .expect("roll the lane back on renewal loss");
        drop(mutation);
        let staged: Option<String> =
            sqlx::query_scalar("SELECT custom_domain FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("read the app row");
        assert_eq!(staged, None, "no staged business write survives");
        // The APP-SCOPED fences stay owned: a newer mutation cannot claim
        // the namespace while the unresolved write may still land. The
        // global edge_config fence is RELEASED (cap#422 R2, review T1):
        // it is cross-app, and unrelated apps' deployment apply needs it.
        let still_owned: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1",
        )
        .bind(operation_id)
        .fetch_one(&pool)
        .await
        .expect("count owned rows after quarantine");
        assert!(
            still_owned >= 3,
            "the app-scoped fences stay quarantined, not released"
        );
        let edge_config_released: Option<Uuid> = sqlx::query_scalar(
            "SELECT owner_token FROM external_resource_mutation_leases
              WHERE resource_scope = 'edge_config' AND resource_key = 'global'",
        )
        .fetch_one(&pool)
        .await
        .expect("read the edge_config fence row");
        assert!(
            edge_config_released.is_none(),
            "the cross-app edge_config fence must be released on a renewal-loss quarantine"
        );
        let app_lease_held: bool = sqlx::query_scalar(
            "SELECT owner_token IS NOT NULL FROM app_mutation_leases WHERE app_id = $1",
        )
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("read the app mutation lease");
        assert!(app_lease_held, "the app mutation lease stays quarantined");
    }
}
