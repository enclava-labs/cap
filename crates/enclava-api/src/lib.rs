pub mod acme;
pub mod auth;
pub mod clients;
pub mod cosign;
pub mod db;
pub mod deploy;
pub mod deployment_failure_cleanup;
pub mod deployment_jobs;
pub mod dns;
pub mod edge;
pub mod egress_proxy;
pub mod entitlements;
pub mod env_gates;
pub mod kbs;
pub mod models;
pub mod mutation_leases;
pub mod platform_release;
pub mod ratelimit;
pub mod registry;
pub mod routes;
pub mod signing_service;
pub mod source_provider;
pub mod state;
mod tee_attestation;
mod workload_tls_timing;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::ratelimit::TrustedProxyKeyExtractor;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    build_router_inner(state, true)
}

fn build_router_inner(state: AppState, enable_rate_limits: bool) -> Router {
    build_router_inner_with_trace(state, enable_rate_limits, TraceLayer::new_for_http())
}

/// Build the production router with a configurable request-tracing layer.
/// Production always passes `TraceLayer::new_for_http()`; tests inject a
/// recording trace layer to assert that governor 429 rejections and gate
/// short-circuits pass through the (outermost) tracing layer.
#[allow(clippy::type_complexity)]
fn build_router_inner_with_trace<T>(
    state: AppState,
    enable_rate_limits: bool,
    trace_layer: T,
) -> Router
where
    T: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
    T::Service: tower::Service<Request> + Clone + Send + Sync + 'static,
    <T::Service as tower::Service<Request>>::Response: IntoResponse + 'static,
    <T::Service as tower::Service<Request>>::Error: Into<std::convert::Infallible> + 'static,
    <T::Service as tower::Service<Request>>::Future: Send + 'static,
{
    let key_extractor = TrustedProxyKeyExtractor::from_env();
    // The device-start route carries its own tight governor and is merged
    // OUTSIDE the generic API governor below: if it ran inside, a flood of
    // starts would charge the shared burst-100 bucket before the tight
    // governor rejects them, starving /auth/device/poll, /auth/device/approve
    // and every other route keyed to the same peer. The tight governor
    // (1 r/s, burst 10) is strictly tighter than the generic one for the
    // same key, so excluding start from the shared bucket loses nothing.
    let device_start = device_start_routes(enable_rate_limits, key_extractor.clone());
    let api_routes = build_api_routes(enable_rate_limits, key_extractor.clone());
    let api_routes = if enable_rate_limits {
        api_routes.layer(GovernorLayer::new(
            GovernorConfigBuilder::default()
                .per_second(1)
                .burst_size(100)
                .key_extractor(key_extractor.clone())
                .finish()
                .expect("api governor config"),
        ))
    } else {
        api_routes
    };

    let mut router = Router::new()
        .merge(with_tracing(
            with_operational_gates(&state, api_routes),
            &trace_layer,
        ))
        // Device-start rides its own tight governor (see the split note
        // above) and gets the same gates + tracing as every other group.
        .merge(with_tracing(
            with_operational_gates(&state, device_start),
            &trace_layer,
        ));

    // Health and internal PaaS governors are layered OUTSIDE the operational
    // gates (startup gate, dispatch freeze): requests short-circuited by
    // those gates must still consume rate-limit tokens, otherwise the very
    // surfaces this router bounds stay unbounded exactly while a gate is
    // tripped (review feedback on enclava-labs/cap#170).
    //
    // TraceLayer conversely sits OUTERMOST in every group (see
    // `with_tracing`) so governor rejections and gate short-circuits remain
    // observable in HTTP traces.
    let health_routes = with_operational_gates(&state, health_routes());
    let health_routes = if enable_rate_limits {
        health_routes.layer(GovernorLayer::new(
            GovernorConfigBuilder::default()
                // Kubelet probes run at ~1/s per node. Probes from many nodes
                // can arrive without a per-node X-Forwarded-For (only trusted
                // proxies are honoured), so buckets key on the observed probe
                // source; 5 req/s with a burst of 100 bounds amplification
                // (issue #135) while leaving headroom for shared probe
                // sources. If probes ever exceed this, raise the budget or
                // widen TRUSTED_PROXY_CIDRS so probes key per node.
                //
                // NOTE: tower_governor's `per_second(n)` sets the token
                // replenishment *period* to n seconds (one token per n
                // seconds), not n requests per second. The intended rate is
                // therefore expressed as a period: 200ms/token = 5 req/s.
                .per_millisecond(200)
                .burst_size(100)
                .key_extractor(key_extractor.clone())
                .finish()
                .expect("health governor config"),
        ))
    } else {
        health_routes
    };
    router = router.merge(with_tracing(health_routes, &trace_layer));

    if state.management_mode.internal_paas_routes_enabled() {
        let internal_routes = with_operational_gates(&state, internal_routes());
        let internal_routes = if enable_rate_limits {
            internal_routes.layer(GovernorLayer::new(
                GovernorConfigBuilder::default()
                    // The PaaS control plane is the only consumer of this
                    // surface and egresses from a single IP: 100 req/s with a
                    // burst of 1000 leaves headroom for proxied end-user
                    // traffic while bounding call rates (issue #135).
                    // enclava-paas treats 429 as retryable, so bursts degrade
                    // gracefully. If the PaaS ever scales to multiple egress
                    // IPs, revisit the keying.
                    //
                    // NOTE: tower_governor's `per_second(n)` sets the token
                    // replenishment *period* to n seconds (one token per n
                    // seconds), not n requests per second. The intended rate
                    // is therefore expressed as a period: 10ms/token =
                    // 100 req/s.
                    .per_millisecond(10)
                    .burst_size(1000)
                    .key_extractor(key_extractor)
                    .finish()
                    .expect("internal paas governor config"),
            ))
        } else {
            internal_routes
        };
        router = router.merge(with_tracing(internal_routes, &trace_layer));
    }

    router
        // Explicit global request-body bound (#128): signing blobs get
        // additional per-field caps in signing_service, but keep the router
        // limit pinned so a future extractor change cannot silently lift it.
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(build_cors_layer())
        .with_state(state)
}

/// Wrap a route group in request tracing. Applied OUTERMOST in every group
/// (above the group governors and operational gates) so that governor 429
/// rejections and gate short-circuits are still recorded in HTTP traces —
/// without this, the traffic that trips a rate limit is invisible.
fn with_tracing<T>(routes: Router<AppState>, trace_layer: &T) -> Router<AppState>
where
    T: tower::Layer<axum::routing::Route> + Clone + Send + Sync + 'static,
    T::Service: tower::Service<Request> + Clone + Send + Sync + 'static,
    <T::Service as tower::Service<Request>>::Response: IntoResponse + 'static,
    <T::Service as tower::Service<Request>>::Error: Into<std::convert::Infallible> + 'static,
    <T::Service as tower::Service<Request>>::Future: Send + 'static,
{
    routes.layer(trace_layer.clone())
}

/// Wrap a route group in the operational middleware shared by every group:
/// the dispatch-freeze and startup gates. Applied per group (rather than
/// once on the merged router) so group-level governors can be layered above
/// these short-circuiting middlewares.
fn with_operational_gates(state: &AppState, routes: Router<AppState>) -> Router<AppState> {
    routes
        .layer(middleware::from_fn_with_state(
            state.clone(),
            freeze_workload_authority_mutations,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_startup_ready,
        ))
}

async fn require_startup_ready(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    if request.uri().path() == "/livez" || state.startup_is_ready() {
        return next.run(request).await;
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        "startup reconciliation in progress",
    )
        .into_response()
}

async fn freeze_workload_authority_mutations(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let matched_path = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map_or("", |path| path.as_str());
    if state.deployment_dispatch_is_enabled()
        || !is_workload_authority_mutation(request.method(), matched_path)
    {
        return next.run(request).await;
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({
            "error": "deploy_blocked",
            "reason": "deployment_dispatch_disabled",
            "message": "tenant workload mutation is disabled by the deployment activation gate",
        })),
    )
        .into_response()
}

/// Only explicitly allowed method/route pairs bypass the deployment freeze.
/// Axum's matched pattern prevents new static routes, encoded parameters, or
/// renamed routes from inheriting a raw-path prefix exemption.
fn is_workload_authority_mutation(method: &Method, matched_path: &str) -> bool {
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return false;
    }

    let control_plane_write = match *method {
        Method::POST => matches!(
            matched_path,
            "/auth/signup"
                | "/auth/login"
                | "/auth/device/start"
                | "/auth/device/poll"
                | "/auth/device/approve"
                | "/auth/api-keys"
                | "/orgs"
                | "/orgs/{name}/invite"
        ),
        Method::DELETE => matches!(
            matched_path,
            "/auth/api-keys/{id}"
                | "/apps/{name}"
                | "/orgs/{name}/members/{id}"
                | "/internal/paas/orgs/{paas_org_id}/apps/{app_name}"
        ),
        Method::PUT => matches!(
            matched_path,
            "/internal/paas/orgs/{paas_org_id}"
                | "/internal/paas/orgs/{paas_org_id}/entitlements"
                | "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}"
        ),
        _ => false,
    };
    !control_plane_write
}

fn internal_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/internal/paas/status",
            axum::routing::get(routes::internal::list_paas_cluster_status),
        )
        .route(
            "/internal/paas/platform/deployment-context",
            axum::routing::get(routes::internal::paas_deployment_context),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}",
            axum::routing::put(routes::internal::upsert_paas_org),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}",
            axum::routing::put(routes::internal::sync_paas_member),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/entitlements",
            axum::routing::put(routes::internal::sync_paas_entitlement),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps",
            axum::routing::get(routes::internal::list_paas_apps)
                .post(routes::internal::create_paas_app),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}",
            axum::routing::delete(routes::internal::delete_paas_app),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/desired-state",
            axum::routing::put(routes::internal::put_paas_app_desired_state),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/logs",
            axum::routing::get(routes::internal::get_paas_app_logs),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/proof-bundle",
            axum::routing::get(routes::internal::get_paas_proof_bundle),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/members",
            axum::routing::get(routes::internal::list_paas_members),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/deployments",
            axum::routing::get(routes::internal::list_paas_deployments)
                .post(routes::internal::create_paas_generic_deployment),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/status",
            axum::routing::get(routes::internal::list_paas_status),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/deploy",
            axum::routing::post(routes::internal::deploy_paas_app),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/agent-policy",
            axum::routing::post(routes::internal::generate_paas_agent_policy),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/users/me/public-keys",
            axum::routing::post(routes::internal::register_paas_public_key),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/keyring",
            axum::routing::get(routes::internal::get_paas_keyring)
                .put(routes::internal::put_paas_keyring),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/signing-readiness",
            axum::routing::get(routes::internal::get_paas_signing_readiness),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/keyring/bootstrap-signing-service",
            axum::routing::post(routes::internal::bootstrap_paas_keyring_signing_service),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/keyring/rotate-owner",
            axum::routing::post(routes::internal::rotate_paas_keyring_owner),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer/rotation-token",
            axum::routing::post(routes::internal::issue_paas_signer_rotation_token),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer",
            axum::routing::patch(routes::internal::rotate_paas_signer),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domain",
            axum::routing::get(routes::internal::get_paas_app_domain),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains",
            axum::routing::post(routes::internal::create_paas_domain_challenge),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}/verify",
            axum::routing::post(routes::internal::verify_paas_domain_challenge),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}",
            axum::routing::delete(routes::internal::remove_paas_custom_domain),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config",
            axum::routing::get(routes::internal::list_paas_config_keys),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token",
            axum::routing::post(routes::internal::issue_paas_config_token),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/sync",
            axum::routing::post(routes::internal::sync_paas_config_metadata),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/{key_name}/meta",
            axum::routing::delete(routes::internal::delete_paas_config_metadata),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/rollback",
            axum::routing::post(routes::internal::rollback_paas_app),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}",
            axum::routing::get(routes::internal::get_paas_generic_deployment),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/config-token",
            axum::routing::post(routes::internal::issue_paas_generic_config_token),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/customer-config-released",
            axum::routing::post(routes::internal::release_paas_customer_config_roll),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/status",
            axum::routing::get(routes::internal::get_paas_unlock_status),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/endpoint",
            axum::routing::get(routes::internal::get_paas_unlock_endpoint),
        )
        .route(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/mode",
            axum::routing::put(routes::internal::update_paas_unlock_mode),
        )
}

fn build_api_routes(
    enable_rate_limits: bool,
    key_extractor: TrustedProxyKeyExtractor,
) -> Router<AppState> {
    Router::new()
        .merge(auth_routes())
        .merge(user_routes())
        .merge(platform_routes())
        .merge(org_routes())
        .merge(app_routes())
        .merge(deploy_routes())
        .merge(config_routes())
        .merge(domain_routes())
        .merge(status_routes())
        .merge(unlock_routes(enable_rate_limits, key_extractor))
        .merge(workload_routes())
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/signup", axum::routing::post(routes::auth::signup))
        .route("/auth/login", axum::routing::post(routes::auth::login))
        .route(
            "/auth/api-keys",
            axum::routing::post(routes::auth::create_api_key_route),
        )
        .route(
            "/auth/api-keys/{id}",
            axum::routing::delete(routes::auth::revoke_api_key_route),
        )
        .merge(device_auth_routes())
}

/// The `/auth/device/start` router with its tight per-IP governor. Kept
/// separate from `device_auth_routes` so `build_router_inner` can merge it
/// OUTSIDE the generic burst-100 API governor — see the comment there.
fn device_start_routes(
    enable_rate_limits: bool,
    key_extractor: TrustedProxyKeyExtractor,
) -> Router<AppState> {
    // The device-login surface is reachable before authentication, and
    // /auth/device/start inserts a session row per call, so only the start
    // route gets the tight per-IP budget. Poll and approve deliberately
    // stay out of this bucket: CLIs poll at the advertised 5-second
    // interval, so a shared 1 r/s budget would throttle any group of
    // users behind one public IP, and an unauthenticated start flood must
    // not be able to starve authenticated approvals. Both remain covered
    // by the generic per-IP API governor.
    //
    // Same-NAT note: keying by IP means users sharing one public egress IP
    // (corporate NAT, CI runners) share the 1 start/s burst-10 budget.
    // `start` is rare per user (once per login), so even ~10 concurrent
    // logins behind one NAT fit inside the burst; if a hosted-tenant NAT
    // ever trips this, key by IP + requested org instead.
    //
    // Per-replica note: tower-governor counters live in-process, so each
    // API replica keeps an independent budget — with N replicas one client
    // effectively gets N × (1 r/s, burst 10). That approximation is
    // deliberate for this route: `start` is a cheap, single INSERT and the
    // budget exists to stop unbounded session-row floods, not to enforce an
    // exact global rate. The exact aggregate cap belongs at the ingress
    // tier (nginx `limit-rps`); see runbooks/cap-api-network-policy-rollout.md
    // §5 for the rollout check.
    let start = Router::new().route(
        "/auth/device/start",
        axum::routing::post(routes::auth::start_device_login),
    );

    if enable_rate_limits {
        start.layer(GovernorLayer::new(
            GovernorConfigBuilder::default()
                .per_second(1)
                .burst_size(10)
                .key_extractor(key_extractor)
                .finish()
                .expect("device auth governor config"),
        ))
    } else {
        start
    }
}

fn device_auth_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/auth/device/poll",
            axum::routing::post(routes::auth::poll_device_login),
        )
        .route(
            "/auth/device/approve",
            axum::routing::post(routes::auth::approve_device_login),
        )
}

fn user_routes() -> Router<AppState> {
    Router::new()
        .route("/users/me", axum::routing::get(routes::users::current_user))
        .route(
            "/users/me/public-keys",
            axum::routing::post(routes::users::register_public_key),
        )
}

fn platform_routes() -> Router<AppState> {
    Router::new().route(
        "/platform/deployment-context",
        axum::routing::get(routes::platform::deployment_context),
    )
}

fn org_routes() -> Router<AppState> {
    Router::new()
        .route("/orgs", axum::routing::post(routes::orgs::create_org))
        .route("/orgs", axum::routing::get(routes::orgs::list_orgs))
        .route(
            "/orgs/{name}/invite",
            axum::routing::post(routes::orgs::invite_member),
        )
        .route(
            "/orgs/{name}/members",
            axum::routing::get(routes::orgs::list_members),
        )
        .route(
            "/orgs/{name}/members/{id}",
            axum::routing::delete(routes::orgs::remove_member),
        )
        .route(
            "/orgs/{name}/keyring",
            axum::routing::get(routes::orgs::get_keyring).put(routes::orgs::put_keyring),
        )
        .route(
            "/orgs/{name}/keyring/bootstrap-signing-service",
            axum::routing::post(routes::orgs::bootstrap_signing_service_owner),
        )
        .route(
            "/orgs/{name}/keyring/rotate-owner",
            axum::routing::post(routes::orgs::rotate_org_owner),
        )
}

fn app_routes() -> Router<AppState> {
    Router::new()
        .route("/apps", axum::routing::post(routes::apps::create_app))
        .route("/apps", axum::routing::get(routes::apps::list_apps))
        .route("/apps/{name}", axum::routing::get(routes::apps::get_app))
        .route(
            "/apps/{name}",
            axum::routing::delete(routes::apps::delete_app),
        )
        .route(
            "/apps/{name}/signer",
            axum::routing::patch(routes::apps::rotate_signer),
        )
        .route(
            "/apps/{name}/signer/rotation-token",
            axum::routing::post(routes::apps::issue_signer_rotation_token_route),
        )
}

fn deploy_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/deployments",
            axum::routing::post(routes::deployments::create_generic_deployment),
        )
        .route(
            "/deployments/{deployment_id}",
            axum::routing::get(routes::deployments::get_generic_deployment),
        )
        .route(
            "/deployments/{deployment_id}/config-token",
            axum::routing::post(routes::deployments::generic_config_token),
        )
        .route(
            "/apps/{name}/deploy",
            axum::routing::post(routes::deployments::deploy),
        )
        .route(
            "/apps/{name}/agent-policy",
            axum::routing::post(routes::deployments::generate_agent_policy),
        )
        .route(
            "/apps/{name}/deployments",
            axum::routing::get(routes::deployments::deployment_history),
        )
        .route(
            "/apps/{name}/rollback",
            axum::routing::post(routes::deployments::rollback),
        )
}

fn config_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/apps/{name}/config-token",
            axum::routing::post(routes::config::issue_config_token_route),
        )
        .route(
            "/apps/{name}/config",
            axum::routing::get(routes::config::list_config_keys),
        )
        .route(
            "/apps/{name}/config/sync",
            axum::routing::post(routes::config::config_sync),
        )
        .route(
            "/apps/{name}/config/{key}/meta",
            axum::routing::delete(routes::config::delete_config_meta),
        )
}

fn domain_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/apps/{name}/domain",
            axum::routing::get(routes::domains::get_domain),
        )
        .route(
            "/apps/{name}/domains",
            axum::routing::post(routes::domains::create_challenge),
        )
        .route(
            "/apps/{name}/domains/{domain}/verify",
            axum::routing::post(routes::domains::verify_challenge),
        )
        .route(
            "/apps/{name}/domains/{domain}",
            axum::routing::delete(routes::domains::remove_custom_domain),
        )
}

fn status_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/apps/{name}/status",
            axum::routing::get(routes::status::app_status),
        )
        .route(
            "/apps/{name}/deployment/diagnostics",
            axum::routing::get(routes::diagnostics::get_deployment_diagnostics),
        )
        .route(
            "/apps/{name}/logs",
            axum::routing::get(routes::status::app_logs),
        )
}

fn unlock_routes(
    enable_rate_limits: bool,
    key_extractor: TrustedProxyKeyExtractor,
) -> Router<AppState> {
    let routes = Router::new()
        .route(
            "/apps/{name}/unlock/status",
            axum::routing::get(routes::unlock::unlock_status),
        )
        .route(
            "/apps/{name}/unlock/endpoint",
            axum::routing::get(routes::unlock::unlock_endpoint),
        )
        .route(
            "/apps/{name}/unlock/mode",
            axum::routing::put(routes::unlock::update_unlock_mode),
        );

    if enable_rate_limits {
        routes.layer(GovernorLayer::new(
            GovernorConfigBuilder::default()
                .per_second(1)
                .burst_size(120)
                .key_extractor(key_extractor)
                .finish()
                .expect("unlock governor config"),
        ))
    } else {
        routes
    }
}

fn workload_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/workload/artifacts",
            axum::routing::get(routes::workload::artifacts),
        )
        .route(
            "/api/v1/workload/tls/dns01-certificate",
            axum::routing::post(routes::workload_tls::dns01_certificate),
        )
        .route(
            "/workload/artifacts",
            axum::routing::get(routes::workload::artifacts),
        )
        .route(
            "/workload/tls/dns01-certificate",
            axum::routing::post(routes::workload_tls::dns01_certificate),
        )
}

fn health_routes() -> Router<AppState> {
    Router::new()
        .route("/livez", axum::routing::get(|| async { "ok" }))
        .route("/readyz", axum::routing::get(|| async { "ok" }))
        .route("/health", axum::routing::get(|| async { "ok" }))
}

/// Build the CORS layer from `CORS_ALLOWED_ORIGINS` (comma-separated).
/// Production default: empty (no cross-origin). Debug default: localhost.
pub fn build_cors_layer() -> CorsLayer {
    let raw = std::env::var("CORS_ALLOWED_ORIGINS").ok();
    let origins: Vec<HeaderValue> = match raw.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<HeaderValue>().ok())
            .collect(),
        _ if cfg!(debug_assertions) => vec![
            HeaderValue::from_static("http://localhost"),
            HeaderValue::from_static("http://localhost:3000"),
            HeaderValue::from_static("http://localhost:5173"),
            HeaderValue::from_static("http://127.0.0.1:3000"),
        ],
        _ => Vec::new(),
    };

    let methods = [
        Method::GET,
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];
    let headers = [
        header::AUTHORIZATION,
        header::CONTENT_TYPE,
        header::ACCEPT,
        header::HeaderName::from_static("x-api-key"),
        header::HeaderName::from_static("x-enclava-org"),
    ];

    if origins.is_empty() {
        // No allowed origins -> no Access-Control-Allow-Origin header.
        // Build an empty layer; tower-http will not echo origins back.
        CorsLayer::new()
    } else {
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods(methods)
            .allow_headers(headers)
    }
}

/// Expose build_router for testing.
#[doc(hidden)]
pub fn test_router(state: AppState) -> Router {
    build_router_inner(state, false)
}

#[cfg(test)]
mod runtime_gate_tests {
    use super::{
        build_router_inner, build_router_inner_with_trace, is_workload_authority_mutation,
        test_router,
    };
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{HeaderValue, Method, Request, StatusCode, header},
        middleware::{self, Next},
        response::Response,
    };
    use http_body_util::BodyExt;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn request_with_peer(peer: &str, method: Method, uri: &str) -> Request<Body> {
        let peer: SocketAddr = format!("{peer}:42000").parse().unwrap();
        Request::builder()
            .method(method)
            .uri(uri)
            .extension(ConnectInfo(peer))
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn health_routes_are_rate_limited_on_the_production_router() {
        // Regression test for enclava-labs/cap#135: `/livez`, `/readyz` and
        // `/health` used to be merged without a GovernorLayer, so a single
        // peer could request them at an unbounded rate. Each path is probed
        // from its own peer address so the three loops do not drain one
        // another's bucket before the 429 assertion.
        let state = crate::test_support::lazy_state();
        let app = build_router_inner(state, true);

        for (i, uri) in ["/livez", "/readyz", "/health"].into_iter().enumerate() {
            let peer = format!("198.51.{}.7", i + 1);
            let mut saw_ok = false;
            let mut saw_limit = None;
            for _ in 0..250 {
                let response = app
                    .clone()
                    .oneshot(request_with_peer(&peer, Method::GET, uri))
                    .await
                    .unwrap();
                if response.status() == StatusCode::OK {
                    saw_ok = true;
                } else {
                    saw_limit = Some(response.status());
                }
            }
            assert!(saw_ok, "{uri} probe must succeed below the burst budget");
            assert_eq!(
                saw_limit,
                Some(StatusCode::TOO_MANY_REQUESTS),
                "{uri} must share a per-peer request bucket"
            );
        }
    }

    #[tokio::test]
    async fn gate_rejected_health_probes_still_consume_rate_limit_tokens() {
        // Review feedback on enclava-labs/cap#170: while startup
        // reconciliation is in progress, /readyz is short-circuited by
        // require_startup_ready with a 503. Those rejected probes must still
        // pass through (and drain) the health governor, otherwise the health
        // surface is unbounded exactly when the service is not ready.
        let state = crate::test_support::lazy_state();
        state
            .startup_ready
            .store(false, std::sync::atomic::Ordering::Release);
        let app = build_router_inner(state, true);

        let mut saw_gate_rejection = false;
        let mut saw_limit = None;
        for _ in 0..250 {
            let response = app
                .clone()
                .oneshot(request_with_peer("203.0.113.7", Method::GET, "/readyz"))
                .await
                .unwrap();
            match response.status() {
                StatusCode::SERVICE_UNAVAILABLE => saw_gate_rejection = true,
                StatusCode::TOO_MANY_REQUESTS => saw_limit = Some(response.status()),
                other => panic!("unexpected status while not ready: {other}"),
            }
        }
        assert!(
            saw_gate_rejection,
            "startup gate must still reject /readyz while not ready"
        );
        assert_eq!(
            saw_limit,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "gate-rejected probes must still consume governor tokens"
        );
    }

    #[tokio::test]
    async fn internal_paas_routes_are_rate_limited_on_the_production_router() {
        // Regression test for enclava-labs/cap#135: the internal PaaS surface
        // used to be merged without a GovernorLayer, so internal-route call
        // rates were unbounded. The request below is rejected by InternalAuth
        // long before the database is touched; the governor still counts it.
        let mut state = crate::test_support::lazy_state();
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        let app = build_router_inner(state, true);

        let mut saw_reachable = false;
        let mut saw_limit = None;
        for _ in 0..1500 {
            let response = app
                .clone()
                .oneshot(request_with_peer(
                    "198.51.100.7",
                    Method::GET,
                    "/internal/paas/status",
                ))
                .await
                .unwrap();
            match response.status() {
                // 401 = InternalAuth rejected the request, 503 = internal
                // auth is not configured (lazy_state sets internal_auth to
                // None and startup_ready to true, so no other middleware
                // can produce a 503 for this GET); either way the route
                // itself was reached and the governor counted the request.
                StatusCode::UNAUTHORIZED | StatusCode::SERVICE_UNAVAILABLE => {
                    saw_reachable = true;
                }
                StatusCode::TOO_MANY_REQUESTS => saw_limit = Some(response.status()),
                other => panic!("unexpected status from internal route: {other}"),
            }
        }
        assert!(
            saw_reachable,
            "internal routes must still be reachable behind InternalAuth"
        );
        assert_eq!(
            saw_limit,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "internal PaaS routes must share a per-peer request bucket"
        );
    }

    #[test]
    fn workload_gate_is_fail_closed_for_current_and_future_writes() {
        for (method, path) in [
            (Method::POST, "/apps"),
            (Method::DELETE, "/apps/demo/domains/example.test"),
            (Method::POST, "/internal/paas/orgs/org-1/deployments"),
            (Method::POST, "/internal/paas/future-workload-authority"),
            (Method::POST, "/api/v2/workload/future"),
        ] {
            assert!(is_workload_authority_mutation(&method, path));
        }

        for (method, path) in [
            (Method::GET, "/apps"),
            (Method::DELETE, "/apps/{name}"),
            (Method::POST, "/auth/login"),
            (Method::POST, "/orgs"),
            (Method::DELETE, "/orgs/{name}/members/{id}"),
            (
                Method::PUT,
                "/internal/paas/orgs/{paas_org_id}/entitlements",
            ),
            (
                Method::DELETE,
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}",
            ),
        ] {
            assert!(!is_workload_authority_mutation(&method, path));
        }
    }

    #[tokio::test]
    async fn freeze_blocks_new_writes_without_a_route_inventory_entry() {
        let state = crate::test_support::lazy_state();
        state.set_deployment_dispatch_enabled(false);
        state.mark_startup_ready();
        for path in [
            "/auth/future-workload-authority",
            "/auth/api-keys/future-workload-authority",
            "/orgs/acme/members/future-workload-authority",
        ] {
            let app = super::with_operational_gates(
                &state,
                Router::new().route(path, axum::routing::any(|| async { StatusCode::OK })),
            )
            .with_state(state.clone());
            for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
                let request = || {
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap()
                };
                state.set_deployment_dispatch_enabled(false);
                let response = app.clone().oneshot(request()).await.unwrap();
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                state.set_deployment_dispatch_enabled(true);
                let response = app.clone().oneshot(request()).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
            }
        }
    }

    #[tokio::test]
    async fn workload_gate_classification_agrees_with_axum_dispatch() {
        // Parameter contents must not change which route's admission policy applies.
        // The production matcher supplies identity; this case table is not authority.
        const MATCHED_PATH_HEADER: header::HeaderName =
            header::HeaderName::from_static("x-enclava-test-matched-path");
        const FALLBACK_SENTINEL: &str = "(fallback)";

        async fn echo_matched_path(
            matched: Option<axum::extract::MatchedPath>,
            request: Request<Body>,
            next: Next,
        ) -> Response {
            let mut response = next.run(request).await;
            response.headers_mut().insert(
                MATCHED_PATH_HEADER,
                HeaderValue::from_str(
                    matched
                        .as_ref()
                        .map(|path| path.as_str())
                        .unwrap_or(FALLBACK_SENTINEL),
                )
                .expect("route patterns are valid header values"),
            );
            response
        }

        const ALLOW: bool = true;
        const MUTATION: bool = false;
        let route_table: &[(&str, &[(&str, bool)])] = &[
            // health
            ("/livez", &[("GET", ALLOW)]),
            ("/readyz", &[("GET", ALLOW)]),
            ("/health", &[("GET", ALLOW)]),
            // auth
            ("/auth/signup", &[("POST", ALLOW)]),
            ("/auth/login", &[("POST", ALLOW)]),
            ("/auth/device/start", &[("POST", ALLOW)]),
            ("/auth/device/poll", &[("POST", ALLOW)]),
            ("/auth/device/approve", &[("POST", ALLOW)]),
            ("/auth/api-keys", &[("POST", ALLOW)]),
            ("/auth/api-keys/{id}", &[("DELETE", ALLOW)]),
            // users
            ("/users/me", &[("GET", ALLOW)]),
            ("/users/me/public-keys", &[("POST", MUTATION)]),
            // platform
            ("/platform/deployment-context", &[("GET", ALLOW)]),
            // orgs
            ("/orgs", &[("GET", ALLOW), ("POST", ALLOW)]),
            ("/orgs/{name}/invite", &[("POST", ALLOW)]),
            ("/orgs/{name}/members", &[("GET", ALLOW)]),
            ("/orgs/{name}/members/{id}", &[("DELETE", ALLOW)]),
            ("/orgs/{name}/keyring", &[("GET", ALLOW), ("PUT", MUTATION)]),
            (
                "/orgs/{name}/keyring/bootstrap-signing-service",
                &[("POST", MUTATION)],
            ),
            ("/orgs/{name}/keyring/rotate-owner", &[("POST", MUTATION)]),
            // apps
            ("/apps", &[("GET", ALLOW), ("POST", MUTATION)]),
            ("/apps/{name}", &[("GET", ALLOW), ("DELETE", ALLOW)]),
            ("/apps/{name}/signer", &[("PATCH", MUTATION)]),
            ("/apps/{name}/signer/rotation-token", &[("POST", MUTATION)]),
            // deployments
            ("/deployments", &[("POST", MUTATION)]),
            ("/deployments/{deployment_id}", &[("GET", ALLOW)]),
            (
                "/deployments/{deployment_id}/config-token",
                &[("POST", MUTATION)],
            ),
            ("/apps/{name}/deploy", &[("POST", MUTATION)]),
            ("/apps/{name}/agent-policy", &[("POST", MUTATION)]),
            ("/apps/{name}/deployments", &[("GET", ALLOW)]),
            ("/apps/{name}/rollback", &[("POST", MUTATION)]),
            // config
            ("/apps/{name}/config-token", &[("POST", MUTATION)]),
            ("/apps/{name}/config", &[("GET", ALLOW)]),
            ("/apps/{name}/config/sync", &[("POST", MUTATION)]),
            ("/apps/{name}/config/{key}/meta", &[("DELETE", MUTATION)]),
            // domains
            ("/apps/{name}/domain", &[("GET", ALLOW)]),
            ("/apps/{name}/domains", &[("POST", MUTATION)]),
            (
                "/apps/{name}/domains/{domain}/verify",
                &[("POST", MUTATION)],
            ),
            ("/apps/{name}/domains/{domain}", &[("DELETE", MUTATION)]),
            // status
            ("/apps/{name}/status", &[("GET", ALLOW)]),
            ("/apps/{name}/deployment/diagnostics", &[("GET", ALLOW)]),
            ("/apps/{name}/logs", &[("GET", ALLOW)]),
            // unlock
            ("/apps/{name}/unlock/status", &[("GET", ALLOW)]),
            ("/apps/{name}/unlock/endpoint", &[("GET", ALLOW)]),
            ("/apps/{name}/unlock/mode", &[("PUT", MUTATION)]),
            // workload
            ("/api/v1/workload/artifacts", &[("GET", ALLOW)]),
            (
                "/api/v1/workload/tls/dns01-certificate",
                &[("POST", MUTATION)],
            ),
            ("/workload/artifacts", &[("GET", ALLOW)]),
            ("/workload/tls/dns01-certificate", &[("POST", MUTATION)]),
            // internal (PaasManaged)
            ("/internal/paas/status", &[("GET", ALLOW)]),
            (
                "/internal/paas/platform/deployment-context",
                &[("GET", ALLOW)],
            ),
            ("/internal/paas/orgs/{paas_org_id}", &[("PUT", ALLOW)]),
            (
                "/internal/paas/orgs/{paas_org_id}/members/{paas_user_id}",
                &[("PUT", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/entitlements",
                &[("PUT", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps",
                &[("GET", ALLOW), ("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}",
                &[("DELETE", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/desired-state",
                &[("PUT", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/logs",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/proof-bundle",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/members",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/deployments",
                &[("GET", ALLOW), ("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/status",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/deploy",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/agent-policy",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/users/me/public-keys",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/keyring",
                &[("GET", ALLOW), ("PUT", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/signing-readiness",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/keyring/bootstrap-signing-service",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/keyring/rotate-owner",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer/rotation-token",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/signer",
                &[("PATCH", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domain",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}/verify",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/domains/{domain}",
                &[("DELETE", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/sync",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config/{key_name}/meta",
                &[("DELETE", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/rollback",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/config-token",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/customer-config-released",
                &[("POST", MUTATION)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/status",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/endpoint",
                &[("GET", ALLOW)],
            ),
            (
                "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/unlock/mode",
                &[("PUT", MUTATION)],
            ),
        ];

        // PaasManaged so the internal PaaS routes are mounted; dispatch
        // stays enabled so every annotated route is reachable (the freeze
        // gate itself is exercised end-to-end by the other tests in this
        // module). The echo layer sits outside the operational gates, so
        // even a gate short-circuit still reports the matched pattern.
        let mut state = crate::test_support::lazy_state();
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        let app = build_router_inner(state, false).layer(middleware::from_fn(echo_matched_path));

        // The pattern axum dispatched this request to, or `None` when no
        // route matched (the sentinel the echo layer emits for fallback).
        async fn dispatched_pattern(app: &Router, method: Method, path: &str) -> Option<String> {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let observed = response
                .headers()
                .get(MATCHED_PATH_HEADER)
                .expect("echo layer must report dispatch outcome")
                .to_str()
                .expect("matched pattern is ASCII")
                .to_string();
            (observed != FALLBACK_SENTINEL).then_some(observed)
        }

        // Replace every {param} in a pattern with the given raw value.
        fn instantiate(pattern: &str, value: &str) -> String {
            let mut out = String::new();
            let mut rest = pattern;
            while let Some(open) = rest.find('{') {
                out.push_str(&rest[..open]);
                let close = rest[open..].find('}').expect("unclosed param") + open;
                out.push_str(value);
                rest = &rest[close + 1..];
            }
            out.push_str(rest);
            out
        }

        // Replace {param}s in a pattern positionally: the parameter at
        // `poison_at` (0-based) takes `poison`, every other parameter takes
        // the ordinary value "org-1".
        fn instantiate_mixed(pattern: &str, poison: &str, poison_at: usize) -> String {
            let mut out = String::new();
            let mut rest = pattern;
            let mut position = 0usize;
            while let Some(open) = rest.find('{') {
                out.push_str(&rest[..open]);
                let close = rest[open..].find('}').expect("unclosed param") + open;
                out.push_str(if position == poison_at {
                    poison
                } else {
                    "org-1"
                });
                position += 1;
                rest = &rest[close + 1..];
            }
            out.push_str(rest);
            out
        }

        fn parameter_count(pattern: &str) -> usize {
            pattern.matches('{').count()
        }

        let poison_values = [
            "demo",
            "org-1",
            "",
            ".",
            "..",
            "%2e%2e",
            "%2F",
            "%2f",
            "x%2F..%2F..%2Fauth%2Flogin",
            "org%2F1",
        ];

        // Assert one instantiated path: the router must dispatch it to the
        // pattern it was built from — except a trailing empty parameter,
        // which yields a trailing '/' no route may match — and the gate
        // classification of every method the pattern serves must equal the
        // annotation.
        async fn assert_dispatch_agrees(
            app: &Router,
            pattern: &str,
            served: &[(&str, bool)],
            path: &str,
            expect_miss: bool,
        ) {
            let method = Method::from_bytes(served[0].0.as_bytes()).unwrap();
            match dispatched_pattern(app, method, path).await {
                Some(observed) => {
                    assert!(
                        !expect_miss,
                        "{path}: the router must not match a trailing '/' \
                         (no route serves it; pattern {pattern})"
                    );
                    assert_eq!(
                        observed, pattern,
                        "{path} instantiated from {pattern} dispatched to {observed}"
                    );
                    for (method_name, is_allow) in served.iter() {
                        let method = Method::from_bytes(method_name.as_bytes()).unwrap();
                        let gate = is_workload_authority_mutation(&method, &observed);
                        assert_eq!(
                            gate,
                            !*is_allow,
                            "{method} {path} (from {pattern}): gate says {}, \
                             annotation says {}",
                            if gate { "mutation" } else { "allowed" },
                            if *is_allow { "allow" } else { "mutation" },
                        );
                    }
                }
                None => {
                    assert!(
                        expect_miss,
                        "{path} instantiated from {pattern} must dispatch"
                    );
                }
            }
        }

        // (1) Exhaustive per-pattern poison instantiation.
        for (pattern, served) in route_table.iter() {
            for value in poison_values {
                let path = instantiate(pattern, value);
                let trailing_empty = value.is_empty() && pattern.ends_with('}');
                assert_dispatch_agrees(&app, pattern, served, &path, trailing_empty).await;
            }
        }

        // (1b) Mixed parameters: poison each parameter position on every
        // multi-parameter pattern while the others stay ordinary. A
        // poisoned segment beside plain segments (for example a poisoned
        // `{paas_org_id}` next to an ordinary `{deployment_id}` on the
        // `customer-config-released` route) must still dispatch to its own
        // pattern with the same gate classification — uniform-poison runs
        // alone would miss a matcher or gate that only misbehaves on mixed
        // input.
        for (pattern, served) in route_table.iter() {
            if parameter_count(pattern) < 2 {
                continue;
            }
            for poison_at in 0..parameter_count(pattern) {
                for poison in poison_values {
                    let path = instantiate_mixed(pattern, poison, poison_at);
                    let trailing_empty = poison.is_empty()
                        && poison_at == parameter_count(pattern) - 1
                        && pattern.ends_with('}');
                    assert_dispatch_agrees(&app, pattern, served, &path, trailing_empty).await;
                }
            }
        }

        // (2) Enumerated raw variants: explicit dispatch pins for the
        // shapes the other tests reason about.
        let dispatch_pins: &[(Method, &str)] = &[
            // Interior empty segment is a parameter value: dispatched to
            // the keyring handler (a mutation), never collapsed onto the
            // org-upsert allow rule.
            (Method::PUT, "/internal/paas/orgs//keyring"),
            // The issue's central case: %2F/.. poisoned parameter is
            // dispatched to the deploy handler (mutation) — a decoding
            // matcher would retarget it and fail this pin.
            (Method::POST, "/apps/x%2F..%2F..%2Fauth%2Flogin/deploy"),
            (Method::POST, "/apps/demo/deploy"),
            // Encoded bytes inside a parameter of an allow-listed route.
            (Method::PUT, "/internal/paas/orgs/org%2F1/entitlements"),
            (Method::PUT, "/internal/paas/orgs//members/u"),
            (Method::PUT, "/internal/paas/orgs//entitlements"),
            (Method::DELETE, "/internal/paas/orgs//apps/demo"),
            (Method::POST, "/orgs//invite"),
            (Method::DELETE, "/orgs//members/user-1"),
        ];
        for (method, path) in dispatch_pins {
            let observed = dispatched_pattern(&app, method.clone(), path)
                .await
                .unwrap_or_else(|| {
                    panic!("{method} {path} must dispatch under current router semantics")
                });
            let (pattern, served) = route_table
                .iter()
                .find(|(p, _)| *p == observed)
                .unwrap_or_else(|| {
                    panic!("{method} {path} dispatched to unannotated route {observed}")
                });
            let (_, is_allow) = served
                .iter()
                .find(|(m, _)| *m == method.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{method} {path} dispatched to {pattern} which does \
                         not serve that method"
                    )
                });
            assert_eq!(
                is_workload_authority_mutation(method, &observed),
                !*is_allow,
                "{method} {path} dispatched to {pattern}: gate and annotation \
                 disagree"
            );
        }
        let miss_pins = [
            "/apps%2Fdemo/deploy",
            "/apps%2fdemo/deploy",
            "/apps/demo/deploy/",
            "/apps/./demo/deploy",
            "/apps/x/../demo/deploy",
            "//apps//demo//deploy",
            "/auth/%2e%2e/apps/demo/deploy",
            "/internal/paas/orgs/",
            "/internal%2Fpaas/orgs/org-1/deployments",
            "/auth%2Flogin",
        ];
        for path in miss_pins {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} must NOT dispatch under current router semantics \
                 (raw bytes are not decoded, dot segments are not resolved, \
                 trailing slashes and leading empties do not match)"
            );
        }
    }

    #[tokio::test]
    async fn router_freeze_gate_blocks_encoded_and_dot_segment_variants() {
        // End-to-end through the real router middleware: while dispatch is
        // disabled, every raw variant of a workload mutation must receive
        // 503 deploy_blocked, never reach a handler. The poisoned-parameter
        // cases are the ones a percent-decoding normalizer would wrongly
        // allow: the router dispatches them to mutation handlers while a
        // decoded/dot-resolved view collapses them into an allow pattern.
        let state = crate::test_support::lazy_state();
        state.set_deployment_dispatch_enabled(false);
        state.mark_startup_ready();
        let app = test_router(state);

        for (method, path) in [
            (Method::POST, "/apps/demo/deploy"),
            (Method::POST, "/auth/%2e%2e/apps/demo/deploy"),
            (
                Method::POST,
                "/internal/paas/orgs/org-1/deployments/deployment-1/customer-config-released",
            ),
            (Method::POST, "/apps%2Fdemo/deploy"),
            (Method::POST, "//apps//demo//deploy"),
            (Method::POST, "/apps/demo/deploy/"),
            (Method::POST, "/apps/./demo/deploy"),
            (Method::POST, "/apps/x%2F..%2F..%2Fauth%2Flogin/deploy"),
            (Method::POST, "/apps/x%2f..%2f..%2fauth/deploy"),
            (Method::DELETE, "/apps/demo/domains/.."),
            (Method::DELETE, "/apps/demo/domains/%2e%2e"),
            (Method::DELETE, "/apps/demo/domains/x%2F..%2F.."),
            (Method::DELETE, "/apps/demo/config/x%2F..%2F..%2Fauth/meta"),
            // Interior empty segment as a poisoned paas_org_id: matchit
            // dispatches this to the keyring handler, so the freeze gate —
            // not the handler — must answer while dispatch is disabled.
            (Method::PUT, "/internal/paas/orgs//keyring"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{method} {path} must be blocked by the freeze gate"
            );
            // The 503 must be the freeze gate itself, not some other
            // middleware that happens to return 503.
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(
                body["error"], "deploy_blocked",
                "{method} {path} must carry the freeze-gate error body"
            );
            assert_eq!(
                body["reason"], "deployment_dispatch_disabled",
                "{method} {path} must carry the freeze-gate reason"
            );
        }

        // In PaasManaged mode the internal keyring route is actually
        // mounted; the poisoned-parameter request must still be answered
        // by the gate (503 deploy_blocked), never by the handler (which
        // would 400 on the empty org id after InternalAuth).
        let mut paas_state = crate::test_support::lazy_state();
        paas_state.management_mode = crate::state::CapManagementMode::PaasManaged;
        paas_state.set_deployment_dispatch_enabled(false);
        paas_state.mark_startup_ready();
        let paas_app = test_router(paas_state);
        let response = paas_app
            .oneshot(
                Request::put("/internal/paas/orgs//keyring")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"], "deploy_blocked");
        assert_eq!(body["reason"], "deployment_dispatch_disabled");

        // Control-plane writes are still served (they fail downstream auth,
        // not at the gate) — the gate must not over-block the allow list.
        for (method, path) in [
            (Method::POST, "/auth/login"),
            (Method::POST, "/orgs"),
            (Method::DELETE, "/apps/demo"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_ne!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{method} {path} must not be blocked by the freeze gate"
            );
        }
    }

    #[tokio::test]
    async fn internal_routes_rate_limited_while_dispatch_gate_is_frozen() {
        // Review feedback on enclava-labs/cap#170: with
        // CAP_DEPLOYMENT_DISPATCH_ENABLED=false, POSTs to internal PaaS
        // workload-authority routes are short-circuited by
        // freeze_workload_authority_mutations with a 503 before any handler
        // (or auth) runs. Those gate-rejected requests must still drain the
        // internal governor, otherwise the internal surface is unbounded
        // exactly while the dispatch gate is tripped.
        let mut state = crate::test_support::lazy_state();
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        state.set_deployment_dispatch_enabled(false);
        let app = build_router_inner(state, true);

        let mut saw_gate_rejection = false;
        let mut saw_limit = None;
        for _ in 0..1500 {
            let response = app
                .clone()
                .oneshot(request_with_peer(
                    "203.0.113.9",
                    Method::POST,
                    "/internal/paas/orgs/org-1/apps",
                ))
                .await
                .unwrap();
            match response.status() {
                StatusCode::SERVICE_UNAVAILABLE => saw_gate_rejection = true,
                StatusCode::TOO_MANY_REQUESTS => saw_limit = Some(response.status()),
                other => panic!("unexpected status while dispatch frozen: {other}"),
            }
        }
        assert!(
            saw_gate_rejection,
            "dispatch freeze must still reject internal workload mutations"
        );
        assert_eq!(
            saw_limit,
            Some(StatusCode::TOO_MANY_REQUESTS),
            "gate-rejected internal requests must still consume governor tokens"
        );
    }

    #[tokio::test]
    async fn unregistered_writes_still_hit_dispatch_gate_with_rate_limits_on() {
        // Review feedback on enclava-labs/cap#170 (Codex): merging
        // individually wrapped route groups could fall back to an ungated
        // 404 for unregistered workload-authority writes instead of the
        // freeze gate's fail-closed 503. In axum, layers applied with
        // `.layer()` wrap each group's fallback, so merged groups keep the
        // api group's gated fallback. This test pins that behavior on the
        // production router (rate limits enabled, three-way merge).
        let mut state = crate::test_support::lazy_state();
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        state.set_deployment_dispatch_enabled(false);
        state.mark_startup_ready();
        let app = build_router_inner(state, true);

        for uri in [
            "/future-workload-authority",
            "/internal/paas/future-workload-authority",
        ] {
            let response = app
                .clone()
                .oneshot(request_with_peer("203.0.113.99", Method::POST, uri))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "unregistered write to {uri} must be fail-closed by the dispatch gate, not 404"
            );
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(body["error"], "deploy_blocked");
            assert_eq!(body["reason"], "deployment_dispatch_disabled");
        }
    }

    #[tokio::test]
    async fn rate_limit_rejections_are_recorded_in_http_traces() {
        // Review feedback on enclava-labs/cap#170 (Devin + Codex): the health
        // and internal governors sit outside the operational gates, so a
        // 429 rejection must not bypass request tracing — otherwise the
        // traffic that trips a rate limit is invisible in traces. This test
        // injects a recording trace layer through the real router assembly
        // (no global tracing subscriber, so it is robust under parallel test
        // execution) and asserts 429 responses pass through it.
        use std::sync::Arc;
        use tower_http::trace::{OnResponse, TraceLayer};

        #[derive(Clone, Default)]
        struct RecordStatuses(Arc<std::sync::Mutex<Vec<u16>>>);

        impl<B> OnResponse<B> for RecordStatuses {
            fn on_response(
                self,
                response: &axum::http::Response<B>,
                _latency: std::time::Duration,
                _span: &tracing::Span,
            ) {
                self.0.lock().unwrap().push(response.status().as_u16());
            }
        }

        let recorder = RecordStatuses::default();
        let trace_layer = TraceLayer::new_for_http().on_response(recorder.clone());
        let state = crate::test_support::lazy_state();
        let app = build_router_inner_with_trace(state, true, trace_layer);

        // Drain the health bucket until the governor rejects with 429s.
        let mut saw_limit = false;
        for _ in 0..250 {
            let response = app
                .clone()
                .oneshot(request_with_peer("203.0.113.77", Method::GET, "/readyz"))
                .await
                .unwrap();
            if response.status() == StatusCode::TOO_MANY_REQUESTS {
                saw_limit = true;
                break;
            }
        }
        assert!(saw_limit, "governor must reject the probe loop with 429");

        let statuses = recorder.0.lock().unwrap().clone();
        assert!(
            statuses.contains(&429),
            "governor 429 rejections must pass through the tracing layer; saw {statuses:?}"
        );
    }

    #[tokio::test]
    async fn router_exposes_only_liveness_until_ready_then_enforces_dispatch_gate() {
        let state = crate::test_support::lazy_state();
        state.set_deployment_dispatch_enabled(false);
        state
            .startup_ready
            .store(false, std::sync::atomic::Ordering::Release);
        let app = test_router(state.clone());

        let live = app
            .clone()
            .oneshot(Request::get("/livez").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(live.status(), StatusCode::OK);

        let not_ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(not_ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(not_ready.headers()[header::CACHE_CONTROL], "no-store");

        state.mark_startup_ready();
        let ready = app
            .clone()
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);

        let frozen = app
            .clone()
            .oneshot(
                Request::post("/future-workload-authority")
                    .header(header::ORIGIN, "http://localhost:5173")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(frozen.status(), StatusCode::SERVICE_UNAVAILABLE);
        let allow_origin = &frozen.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN];
        assert_eq!(allow_origin, "http://localhost:5173");
        let body = frozen.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["reason"], "deployment_dispatch_disabled");

        let cleanup = app
            .oneshot(Request::delete("/apps/demo").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(cleanup.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Serializes tests that mutate or assert on the global
    /// `kbs_signed_policy_reconciliation` singleton row: cargo runs lib
    /// tests in parallel against one shared database, so unsynchronized
    /// generation bumps from one test would corrupt another's assertions.
    pub(crate) static SIGNED_POLICY_SINGLETON_LOCK: tokio::sync::Mutex<()> =
        tokio::sync::Mutex::const_new(());

    use crate::auth::api_key::ValidatedApiKey;
    use crate::auth::middleware::{AuthContext, ManagementOrigin};
    use crate::clients::{AllowList, ClientConfig, RegistryClient};
    use crate::models::Role;
    use crate::state::AppState;
    use ed25519_dalek::SigningKey;
    use enclava_common::image::ImageRef;
    use enclava_engine::types::AttestationConfig;
    use rand::rngs::OsRng;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;
    use uuid::Uuid;

    pub(crate) async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate test database");
        pool
    }

    pub(crate) fn auth_context(role: Role, scopes: &[&str]) -> AuthContext {
        AuthContext {
            user_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            org_name: "test-org".to_string(),
            role,
            api_key: if scopes.is_empty() {
                None
            } else {
                Some(ValidatedApiKey {
                    id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
                    org_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
                    created_by: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
                    scopes: scopes.iter().map(|scope| scope.to_string()).collect(),
                })
            },
            management_origin: ManagementOrigin::Public,
        }
    }

    pub(crate) fn lazy_state() -> AppState {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgresql://test:test@localhost:5432/test")
            .expect("lazy postgres URL should parse");
        let side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        AppState {
            db: pool,
            management_mode: crate::state::CapManagementMode::Standalone,
            deployment_dispatch_enabled: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            startup_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            signing_key: Arc::new(SigningKey::generate(&mut OsRng)),
            hmac_key: Arc::new([7u8; 32]),
            api_url: "https://api.example.test".to_string(),
            dashboard_url: Some("https://app.example.test".to_string()),
            platform_domain: "enclava.dev".to_string(),
            tee_domain_suffix: "tee.enclava.dev".to_string(),
            http_client: reqwest::Client::new(),
            outbound_body_limit: crate::clients::ClientConfig::from_env().body_limit_bytes,
            registry_client: RegistryClient::new(
                ClientConfig::from_env(),
                AllowList::from_env_or_default(None),
            )
            .unwrap(),
            cosign_egress: crate::clients::EgressGuard::from_env(),
            trustee_http_client: reqwest::Client::new(),
            tee_http_client: reqwest::Client::new(),
            recent_tee_probe_failures: std::sync::Arc::new(std::sync::Mutex::new(
                crate::state::TeeProbeFailureCache::default(),
            )),
            attestation: Some(AttestationConfig {
                proxy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/attestation-proxy@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                caddy_image: ImageRef::parse(
                    "ghcr.io/enclava-labs/caddy-ingress@sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                acme_ca_url: enclava_engine::types::default_acme_ca_url(),
                caddy_tls_mode: enclava_engine::types::CaddyTlsMode::Acme,
                trustee_policy_read_available: true,
                workload_artifacts_url: Some("https://api.example.test/workload/artifacts".into()),
                tls_certificate_broker_url: None,
                amd_kds_base_url: None,
                trustee_policy_url: Some("https://kbs.example.test/policy".into()),
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: Some("33".repeat(32)),
                signing_service_pubkey_hex: Some("11".repeat(32)),
                verification_material: None,
            }),
            platform_release_envelope: None,
            dns: None,
            acme: None,
            kbs_policy: None,
            trustee_attestation_verify_url: None,
            trustee_attestation_verify_bearer_token: None,
            signing_service: None,
            require_customer_signed_policy_artifact: true,
            deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            side_effect_admission,
            internal_auth: None,
        }
    }

    /// Route-level and reconciliation tests assert exact values on the global
    /// `kbs_signed_policy_reconciliation` singleton.  The shared test
    /// database is mutated concurrently by hundreds of other tests (and by
    /// sibling pipeline worktrees), any of which can bump the generation
    /// mid-assertion.  A dedicated database makes these tests deterministic.
    ///
    /// The database name is suffixed with the current process id: sibling CI
    /// worktrees share one PostgreSQL server, and a fixed name would let two
    /// processes mutate the same singleton row concurrently.  The database is
    /// created fresh (a stale leftover from a crashed run is dropped first).
    ///
    /// The pool must be returned to [`drop_isolated_database`] when the test
    /// body finishes; that closes the pool and drops the database so repeated
    /// CI runs do not accumulate fully migrated databases on the shared
    /// PostgreSQL server (the pid suffix means a later run's initial
    /// DROP IF EXISTS never matches an earlier run's leftover).
    ///
    /// The returned [`IsolatedDatabaseCleanup`] guard is the panic-path
    /// backstop: the explicit drop runs only on the happy path, but a failing
    /// assertion (or any panic) would otherwise leak the fully migrated
    /// per-process database forever.  The guard drops the database during
    /// unwind as well; its final `DROP IF EXISTS` is idempotent with the
    /// explicit drop.
    pub(crate) async fn isolated_database_test_pool(
        name: &str,
    ) -> (IsolatedDatabaseCleanup, sqlx::PgPool) {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let db_name = format!("{name}_{}", std::process::id());
        let cleanup = IsolatedDatabaseCleanup {
            db_name: db_name.clone(),
            base_url: base_url.clone(),
        };
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base_url)
            .await
            .expect("connect isolated keyring database admin");
        // A leftover database from a crashed run would carry a stale
        // singleton generation; drop it so every run starts from scratch.
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
        ))
        .execute(&admin)
        .await
        .expect("drop stale isolated keyring database");
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await
            .expect("create isolated keyring database");
        admin.close().await;
        // Same connection settings with only the database replaced: parse
        // the URL instead of slicing it so query parameters (sslmode, a
        // Unix-socket `host`, `options`, ...) survive the swap.  String
        // slicing on the last '/' would drop the whole query string and a
        // socket-host URL can even place a '/' inside the query.
        let options = base_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse DATABASE_URL for isolated keyring database")
            .database(&db_name);
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect isolated keyring database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate isolated keyring database");
        (cleanup, pool)
    }

    /// Panic-path backstop for [`isolated_database_test_pool`]: drops the
    /// per-process database even when the test panics before reaching its
    /// explicit [`drop_isolated_database`] call.  Runs on a dedicated thread
    /// with its own short-lived runtime so it can block on the async driver
    /// from synchronous unwind code.
    pub(crate) struct IsolatedDatabaseCleanup {
        db_name: String,
        base_url: String,
    }

    impl Drop for IsolatedDatabaseCleanup {
        fn drop(&mut self) {
            let db_name = self.db_name.clone();
            let base_url = self.base_url.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build isolated database cleanup runtime");
                rt.block_on(async move {
                    let admin = PgPoolOptions::new()
                        .max_connections(1)
                        .connect(&base_url)
                        .await;
                    if let Ok(admin) = admin {
                        let _ = sqlx::query(&format!(
                            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
                        ))
                        .execute(&admin)
                        .await;
                        admin.close().await;
                    }
                });
            })
            .join()
            .expect("isolated database cleanup thread");
        }
    }

    /// Companion to [`isolated_database_test_pool`]: closes the pool and
    /// drops the per-process database.  Without this, every test run leaves
    /// a fully migrated database behind on the shared PostgreSQL server (the
    /// pid suffix means a later run's initial `DROP IF EXISTS` targets a
    /// different name and never reclaims it).
    pub(crate) async fn drop_isolated_database(name: &str, pool: sqlx::PgPool) {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let db_name = format!("{name}_{}", std::process::id());
        // All clones share one connection pool, so this closes every handle
        // the test (and its AppState clones) hold; DROP ... WITH (FORCE)
        // would terminate any stragglers regardless.
        pool.close().await;
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .connect(&base_url)
            .await
            .expect("connect isolated keyring database admin for drop");
        sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
        ))
        .execute(&admin)
        .await
        .expect("drop isolated keyring database");
        admin.close().await;
    }

    /// Stateful Kubernetes API double behind the fenced KBS reconciler: it
    /// stores the resource-policy ConfigMap and the Trustee deployment the
    /// way the API server would, so route regressions observe real
    /// publication (ConfigMap replace plus rollout confirmation) instead of
    /// a fabricated success.  `healthy = false` makes provider I/O fail.
    /// The seeded policy body keeps the empty legacy binding maps, so
    /// legacy Rego reconciliation finds its splice anchors too.
    pub(crate) struct KbsPolicyProvider {
        pub(crate) healthy: bool,
        pub(crate) configmap: serde_json::Value,
        pub(crate) deployment: serde_json::Value,
        pub(crate) configmap_replaces: usize,
        pub(crate) deployment_replaces: usize,
        pub(crate) deployment_put_failures: usize,
        pub(crate) deployment_gets_before_failure: Option<usize>,
        pub(crate) replace_configmap_on_next_deployment_get: Option<serde_json::Value>,
        pub(crate) configmap_put_hold: Option<(
            tokio::sync::oneshot::Sender<()>,
            tokio::sync::oneshot::Receiver<()>,
        )>,
    }

    impl KbsPolicyProvider {
        pub(crate) fn new(healthy: bool) -> Self {
            Self {
                healthy,
                configmap: serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": "resource-policy",
                        "namespace": "kbs-test",
                        "resourceVersion": "1",
                    },
                    "data": {
                        "policy.rego": "package policy\nresource_bindings := {}\nowner_resource_bindings := {}\n",
                    },
                }),
                deployment: serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": "trustee",
                        "namespace": "kbs-test",
                        "resourceVersion": "1",
                        "generation": 1,
                    },
                    "spec": {
                        "replicas": 1,
                        "template": {
                            "metadata": {},
                            "spec": {
                                "containers": [{"name": "trustee", "image": "trustee"}],
                            },
                        },
                    },
                    "status": {
                        "observedGeneration": 1_000_000,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "readyReplicas": 1,
                        "availableReplicas": 1,
                    },
                }),
                configmap_replaces: 0,
                deployment_replaces: 0,
                deployment_put_failures: 0,
                deployment_gets_before_failure: None,
                replace_configmap_on_next_deployment_get: None,
                configmap_put_hold: None,
            }
        }

        pub(crate) fn published_generation(&self) -> Option<i64> {
            self.configmap["metadata"]["annotations"]
                .as_object()?
                .get("enclava.dev/cap-policy-generation")?
                .as_str()?
                .parse()
                .ok()
        }
    }

    pub(crate) fn kbs_policy_kube_client(
        provider: std::sync::Arc<tokio::sync::Mutex<KbsPolicyProvider>>,
    ) -> kube::Client {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        fn respond(
            status: u16,
            value: &serde_json::Value,
        ) -> Result<Response<Body>, std::io::Error> {
            Ok(Response::builder()
                .status(status)
                .body(Body::from(
                    serde_json::to_vec(value).expect("serialize kube double response"),
                ))
                .expect("build kube double response"))
        }

        kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let provider = provider.clone();
                async move {
                    let method = request.method().as_str().to_string();
                    let path = request.uri().path().to_string();
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .expect("read Kubernetes request body")
                        .to_bytes();
                    let mut provider = provider.lock().await;
                    let mut object: serde_json::Value = if method == "PUT" {
                        serde_json::from_slice(&body)
                            .expect("kube double PUT requests carry a JSON body")
                    } else {
                        serde_json::json!({})
                    };
                    if !provider.healthy
                        || (method != "GET" && method != "PUT")
                        || (!path.contains("/configmaps/") && !path.contains("/deployments/"))
                    {
                        return respond(
                            404,
                            &serde_json::json!({
                                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                "reason": "NotFound", "message": "unavailable", "code": 404,
                            }),
                        );
                    }
                    if path.contains("/configmaps/") {
                        if method == "PUT" {
                            if let Some((reached, release)) = provider.configmap_put_hold.take() {
                                // Deterministic handshake: park this PUT,
                                // and the provider mutex it holds, until the
                                // test releases it, so a rotation can commit
                                // while a publication is mid-flight.
                                let _ = reached.send(());
                                let _ = release.await;
                            }
                            provider.configmap_replaces += 1;
                            if let Some(metadata) =
                                object.get_mut("metadata").and_then(|m| m.as_object_mut())
                            {
                                metadata.insert(
                                    "resourceVersion".to_string(),
                                    serde_json::json!(
                                        (provider.configmap_replaces + 1).to_string()
                                    ),
                                );
                            }
                            provider.configmap = object;
                        }
                        return respond(200, &provider.configmap);
                    }
                    if method == "PUT" {
                        if provider.deployment_put_failures > 0 {
                            provider.deployment_put_failures -= 1;
                            return respond(
                                500,
                                &serde_json::json!({
                                    "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                    "reason": "InternalError",
                                    "message": "injected deployment write failure",
                                    "code": 500,
                                }),
                            );
                        }
                        provider.deployment_replaces += 1;
                        provider.deployment = object;
                    } else {
                        if let Some(configmap) =
                            provider.replace_configmap_on_next_deployment_get.take()
                        {
                            provider.configmap = configmap;
                        }
                        if let Some(remaining) = provider.deployment_gets_before_failure {
                            if remaining == 0 {
                                provider.deployment_gets_before_failure = None;
                                return respond(
                                    500,
                                    &serde_json::json!({
                                        "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                        "reason": "InternalError",
                                        "message": "injected deployment readiness failure",
                                        "code": 500,
                                    }),
                                );
                            }
                            provider.deployment_gets_before_failure = Some(remaining - 1);
                        }
                    }
                    respond(200, &provider.deployment)
                }
            }),
            "default",
        )
    }
}
