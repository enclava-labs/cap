pub mod acme;
pub mod auth;
pub mod clients;
pub mod cosign;
pub mod db;
pub mod deploy;
pub mod deployment_jobs;
pub mod dns;
pub mod edge;
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
mod workload_tls_timing;

use axum::{
    Json, Router,
    extract::{Request, State},
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
    let key_extractor = TrustedProxyKeyExtractor::from_env();
    let api_routes = build_api_routes(enable_rate_limits, key_extractor);
    let api_routes = if enable_rate_limits {
        api_routes.layer(GovernorLayer::new(
            GovernorConfigBuilder::default()
                .per_second(1)
                .burst_size(100)
                .key_extractor(TrustedProxyKeyExtractor::from_env())
                .finish()
                .expect("api governor config"),
        ))
    } else {
        api_routes
    };

    let mut router = Router::new().merge(health_routes());
    if state.management_mode.internal_paas_routes_enabled() {
        router = router.merge(internal_routes());
    }

    router
        .merge(api_routes)
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            freeze_workload_authority_mutations,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_startup_ready,
        ))
        .layer(build_cors_layer())
        .with_state(state)
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
    if state.deployment_dispatch_enabled
        || !is_workload_authority_mutation(request.method(), request.uri().path())
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

/// Classify whether a request is a tenant workload-authority mutation that
/// the deployment freeze gate must block while dispatch is disabled.
///
/// Invariant: this function must classify the raw segments the router will
/// match — the only deliberate divergence is the leading/trailing slash
/// trim described below, which is fail-closed. Axum 0.8 dispatches through
/// matchit 0.8.x, which matches the raw
/// (still percent-encoded) URI path, splits parameters on a literal `/`
/// only, and never decodes `%2F` or resolves `.`/`..` segments (there is no
/// `NormalizePath` layer in `build_router_inner`). The gate therefore also
/// splits on literal `/` and compares raw segments: `%2F` inside a segment
/// is NOT a separator here, because it is not one to the router either.
///
/// The invariant is enforced by
/// `workload_gate_classification_agrees_with_matchit_dispatch`, which
/// mirrors this file's route table into a `matchit::Router` pinned to the
/// locked version and asserts gate classification ↔ dispatch agreement on
/// every pattern instantiated with poisoned parameter values (empty, dot
/// segments, %2F encodings), plus explicit match/miss pins for the raw
/// variants below: a matchit update that changes raw-path semantics
/// (decoding %2F, resolving dot segments, tolerating trailing slashes)
/// fails that test instead of silently breaking alignment. Because a
/// patch-level matchit release can change matching behavior, the pin must
/// be bumped deliberately — re-verify the semantics on ANY matchit bump,
/// not only majors.
///
/// A path that matches no allow pattern below is a mutation (deny-by-default),
/// so raw variants such as `/apps%2Fdemo/deploy`, `//apps//demo//deploy`,
/// `/apps/demo/deploy/`, or `/apps/./demo/deploy` are all blocked: the
/// router would not serve them as allow-listed control-plane writes.
///
/// Interior empty segments (`//`) are preserved, because matchit treats an
/// empty path parameter as a value: `PUT /internal/paas/orgs//keyring` is
/// dispatched to the keyring handler with an empty `paas_org_id`, so the
/// gate must see the five-segment shape (mutation), not a collapsed
/// four-segment shape that would hit the org-upsert allow rule. Only the
/// leading/trailing slashes are trimmed; that divergence from matchit is
/// fail-closed (a trailing slash can only make a path look like a shorter
/// allow pattern that matchit would not route, or leave it deny-by-default).
///
/// Do NOT "normalize" by percent-decoding or resolving dot segments before
/// matching: that rewrites the path into shapes the router never selected,
/// and can only move requests from the blocked set into the allowed set
/// (fail-open). For example, decoding `/apps/x%2F..%2F..%2Fauth%2Flogin/deploy`
/// — which the router dispatches to the deploy handler — would make it look
/// like an `auth`-prefixed control-plane write and let it through the gate.
fn is_workload_authority_mutation(method: &Method, path: &str) -> bool {
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        return false;
    }

    // Split on literal '/' with interior empty segments preserved (see the
    // invariant comment above): an empty segment is a parameter value to
    // matchit, not a separator to collapse.
    let segments = path.trim_matches('/').split('/').collect::<Vec<_>>();

    if method == Method::DELETE
        && matches!(
            segments.as_slice(),
            ["apps", _] | ["internal", "paas", "orgs", _, "apps", _]
        )
    {
        return false;
    }

    if matches!(segments.as_slice(), ["internal", "paas", ..]) {
        return !(method == Method::PUT
            && matches!(
                segments.as_slice(),
                ["internal", "paas", "orgs", _]
                    | ["internal", "paas", "orgs", _, "entitlements"]
                    | ["internal", "paas", "orgs", _, "members", _]
            ));
    }

    let control_plane_write = matches!(segments.first(), Some(&"auth"))
        || (method == Method::POST && matches!(segments.as_slice(), ["orgs"]))
        || (method == Method::POST && matches!(segments.as_slice(), ["orgs", _, "invite"]))
        || (method == Method::DELETE && matches!(segments.as_slice(), ["orgs", _, "members", _]));
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
            "/auth/device/start",
            axum::routing::post(routes::auth::start_device_login),
        )
        .route(
            "/auth/device/poll",
            axum::routing::post(routes::auth::poll_device_login),
        )
        .route(
            "/auth/device/approve",
            axum::routing::post(routes::auth::approve_device_login),
        )
        .route(
            "/auth/api-keys",
            axum::routing::post(routes::auth::create_api_key_route),
        )
        .route(
            "/auth/api-keys/{id}",
            axum::routing::delete(routes::auth::revoke_api_key_route),
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
    use super::{is_workload_authority_mutation, test_router};
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode, header},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;

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
            (Method::DELETE, "/apps/demo"),
            (Method::POST, "/auth/login"),
            (Method::POST, "/orgs"),
            (Method::DELETE, "/orgs/acme/members/user-1"),
            (Method::PUT, "/internal/paas/orgs/org-1/entitlements"),
            (Method::DELETE, "/internal/paas/orgs/org-1/apps/demo"),
        ] {
            assert!(!is_workload_authority_mutation(&method, path));
        }
    }

    #[test]
    fn workload_gate_classification_agrees_with_matchit_dispatch() {
        // Locks the gate/router alignment invariant to the exact matchit
        // in the lockfile, from four angles:
        //
        // 1. Mirror freshness: the annotated pattern set below must equal
        //    the route declarations in this file (scanned from the source
        //    at compile time), including each route's served methods, so
        //    adding a route or a method on an existing route without
        //    updating the table fails here instead of drifting silently.
        // 2. Single matcher: Cargo.lock must contain exactly one matchit
        //    package, pinned via the `=0.8.4` dev-dependency. If axum and
        //    this mirror ever resolve to different matchit copies, the
        //    mirror would test the wrong crate — fail instead.
        // 3. Exhaustive dispatch agreement: every pattern is instantiated
        //    with every poison value (empty, dot segments, %2F encodings)
        //    in every parameter, and the mirror must dispatch it to the
        //    same pattern (pinning that matchit never decodes %2F,
        //    resolves dot segments, or treats an interior empty segment as
        //    a separator) with the gate classification equal to the
        //    annotation. A trailing empty parameter produces a trailing
        //    '/', which matchit must NOT match (pinning the absence of
        //    trailing-slash tolerance); the gate's own trailing-slash
        //    trim stays fail-closed because no handler serves those
        //    shapes.
        // 4. Enumerated raw variants from the tests below are fed through
        //    the mirror with explicit match/miss pins.
        //
        // A matcher semantics change (percent-decoding, %2F/empty as
        // separators, dot resolution, trailing-slash tolerance) breaks 3
        // or 4 and fails CI instead of silently breaking alignment.
        // HEAD is dispatched by axum's method router to the GET handler
        // and always allowed by the gate, so GET annotations cover it.
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

        // (1) The route declarations of this file, scanned at compile
        // time, must match the annotated table exactly — both the set
        // of paths and, per path, the set of served methods (a path
        // may be declared twice with different methods or chained via
        // `.get(...).post(...)`). Adding a route or adding/changing a
        // method on an existing route fails here instead of drifting
        // silently. Only the router-construction section is scanned —
        // everything from the test module onward (including this
        // scanner's own source) is excluded.
        let source = include_str!("lib.rs");
        let source = &source[..source
            .find("mod runtime_gate_tests")
            .expect("test module must exist; the route scanner depends on its position")];
        const METHOD_VERBS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
        // Builder calls that may appear inside a route handler
        // expression without serving a method.
        const NON_METHOD_CALLS: [&str; 6] = [
            "layer",
            "route_layer",
            "with_state",
            "handle_error",
            "fallback",
            "fallback_service",
        ];

        // Blank string-literal bodies and comments with spaces (byte
        // positions preserved) so structural scans see only code.
        fn blank_noncode(src: &str) -> Vec<u8> {
            let b = src.as_bytes();
            let mut out = b.to_vec();
            let mut i = 0;
            let mut in_string = false;
            while i < b.len() {
                let c = b[i];
                if in_string {
                    out[i] = b' ';
                    if c == b'\\' && i + 1 < b.len() {
                        out[i + 1] = b' ';
                        i += 2;
                        continue;
                    }
                    if c == b'"' {
                        in_string = false;
                    }
                    i += 1;
                } else {
                    match c {
                        b'"' => {
                            in_string = true;
                            out[i] = b' ';
                            i += 1;
                        }
                        b'/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                            while i < b.len() && b[i] != b'\n' {
                                out[i] = b' ';
                                i += 1;
                            }
                        }
                        b'/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                            out[i] = b' ';
                            out[i + 1] = b' ';
                            i += 2;
                            while i < b.len() {
                                if b[i] == b'*' && i + 1 < b.len() && b[i + 1] == b'/' {
                                    out[i] = b' ';
                                    out[i + 1] = b' ';
                                    i += 2;
                                    break;
                                }
                                out[i] = b' ';
                                i += 1;
                            }
                        }
                        _ => i += 1,
                    }
                }
            }
            out
        }

        let blanked = blank_noncode(source);
        let code = std::str::from_utf8(&blanked).expect("blanking preserves UTF-8 validity");
        // (path, method verb) pairs, one per served method
        let mut declared: Vec<(&str, &str)> = Vec::new();
        let mut search_from = 0usize;
        while let Some(rel) = code[search_from..].find(".route(") {
            let pos = search_from + rel;
            // The .route(...) call is bounded by its matching paren —
            // never anything beyond it — so later code cannot be
            // misattributed to this route.
            let open = pos + ".route(".len() - 1;
            let mut depth = 0usize;
            let mut close = None;
            for (i, c) in code[open..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(open + i);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let close = close.expect("unbalanced .route( call");
            search_from = close + 1;
            let call = &code[pos..=close];
            // route paths are plain literals without escapes; look the
            // literal up in the original source (the blanked copy has
            // no quotes left)
            let src_call = &source[pos..=close];
            let q1 = src_call
                .find('"')
                .expect("route path must be a string literal");
            let q2 = src_call[q1 + 1..]
                .find('"')
                .expect("route path literal must close")
                + q1
                + 1;
            let path = &src_call[q1 + 1..q2];
            let comma = call[q2 + 1..]
                .find(',')
                .expect("route must have a handler argument")
                + q2
                + 1;
            let handler = &call[comma + 1..call.len() - 1];
            // Leading verb: `axum::routing::get(handler)` or `get(handler)`
            let trimmed = handler.trim_start();
            let paren = trimmed.find('(').expect("handler must be a call");
            let ident_path = trimmed[..paren].trim_end();
            let leading = ident_path.rsplit("::").next().unwrap();
            assert!(
                METHOD_VERBS.contains(&leading),
                "route {path}: unrecognized handler {ident_path:?}; the freshness \
                 scanner only understands verb calls (get/post/put/patch/delete, \
                 optionally module-qualified) — restructure the route or teach \
                 the scanner about it"
            );
            declared.push((path, leading));
            // Every dotted call chained on the handler must be a known
            // method verb or a known non-method builder. Anything else
            // (`.on(MethodFilter, ...)`, `.any(...)`, `.merge(...)`,
            // `get_service`-style forms, ...) may serve a method this
            // table cannot see — fail instead of tracking it wrongly.
            let mut scan = 0usize;
            while let Some(dot) = handler[scan..].find('.') {
                let at = scan + dot;
                scan = at + 1;
                let after = &handler[at + 1..];
                let name_len = after
                    .find(|c: char| !(c.is_ascii_alphabetic() || c == '_'))
                    .unwrap_or(after.len());
                if name_len == 0 || !handler[at + 1 + name_len..].starts_with('(') {
                    continue; // not a call
                }
                let name = &after[..name_len];
                if METHOD_VERBS.contains(&name) {
                    declared.push((path, name));
                } else if !NON_METHOD_CALLS.contains(&name) {
                    panic!(
                        "route {path}: chained call .{name}( is not a known method \
                         verb or non-method builder; it may serve a method the \
                         mirrored table cannot track — restructure the route or \
                         teach the scanner about it"
                    );
                }
            }
        }
        let mut declared_map: std::collections::BTreeMap<&str, std::collections::BTreeSet<String>> =
            std::collections::BTreeMap::new();
        for (path, verb) in declared {
            declared_map
                .entry(path)
                .or_default()
                .insert(verb.to_uppercase());
        }
        let mut table_map: std::collections::BTreeMap<&str, std::collections::BTreeSet<String>> =
            std::collections::BTreeMap::new();
        for (path, served) in route_table {
            table_map
                .entry(path)
                .or_default()
                .extend(served.iter().map(|(m, _)| m.to_string()));
        }
        assert_eq!(
            declared_map, table_map,
            "route table mirror (paths AND per-path method sets) drifted from the \
             route declarations in this file"
        );

        // (2) Exactly one matchit in the lockfile, and it is the pinned
        // version this test compiles against.
        let lock = include_str!("../../../Cargo.lock");
        let mut lock_lines = lock.lines().filter(|l| l.starts_with("name = \"matchit\""));
        let name_line = lock_lines
            .next()
            .expect("Cargo.lock must contain a matchit package");
        assert!(
            lock_lines.next().is_none(),
            "Cargo.lock contains more than one matchit package: the mirror would \
             test a different matcher than the router"
        );
        let _ = name_line;
        let pin_index = lock.find("name = \"matchit\"").unwrap();
        let version_line = lock[pin_index..]
            .lines()
            .find(|l| l.starts_with("version = "))
            .expect("matchit package must have a version");
        const PINNED_MATCHIT: &str = "0.8.4";
        assert_eq!(
            version_line,
            format!("version = \"{PINNED_MATCHIT}\""),
            "the matchit dev-dependency pin (=0.8.4) and Cargo.lock disagree; \
             re-verify matcher semantics (see the classifier invariant comment) \
             when bumping matchit — any bump, not only majors"
        );

        // Inserting must succeed: conflicting patterns would mean the
        // table itself is malformed.
        let mut mirror = matchit::Router::new();
        for (index, (pattern, _)) in route_table.iter().enumerate() {
            mirror
                .insert(*pattern, index)
                .unwrap_or_else(|e| panic!("mirror insert failed for {pattern}: {e}"));
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

        // (3) Exhaustive per-pattern poison instantiation.
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
        let patterns_needing_non_get = route_table
            .iter()
            .filter(|(_, served)| served.iter().any(|(m, _)| *m != "GET"))
            .count();
        let mut non_get_covered = std::collections::HashSet::new();
        for (index, (pattern, served)) in route_table.iter().enumerate() {
            for value in poison_values {
                let path = instantiate(pattern, value);
                // A trailing empty parameter yields a trailing '/', which
                // no pattern contains: matchit must not match it. All
                // other instantiations must dispatch to their own pattern
                // — pinning that %2F, dots, and interior empties are
                // ordinary parameter bytes to the matcher.
                let trailing_empty = value.is_empty() && pattern.ends_with('}');
                match mirror.at(&path) {
                    Ok(matched) => {
                        assert!(
                            !trailing_empty,
                            "{path}: matchit must not match a trailing '/' \
                             (no pattern serves it; pattern {pattern})"
                        );
                        assert_eq!(
                            *matched.value, index,
                            "{path} instantiated from {pattern} dispatched to {}",
                            route_table[*matched.value].0
                        );
                        for (method_name, is_allow) in served.iter() {
                            let method = Method::from_bytes(method_name.as_bytes()).unwrap();
                            let gate = is_workload_authority_mutation(&method, &path);
                            assert_eq!(
                                gate,
                                !*is_allow,
                                "{method} {path} (from {pattern}): gate says {}, \
                                 annotation says {}",
                                if gate { "mutation" } else { "allowed" },
                                if *is_allow { "allow" } else { "mutation" },
                            );
                            if method != Method::GET {
                                non_get_covered.insert(index);
                            }
                        }
                    }
                    Err(_) => {
                        assert!(
                            trailing_empty,
                            "{path} instantiated from {pattern} must dispatch"
                        );
                    }
                }
            }
        }
        assert_eq!(
            non_get_covered.len(),
            patterns_needing_non_get,
            "every pattern with a non-GET method must be asserted against \
             the mirror with at least one non-GET method"
        );

        // (4) Enumerated raw variants: explicit dispatch pins for the
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
            let matched = mirror.at(path).unwrap_or_else(|_| {
                panic!(
                    "{method} {path} must dispatch under \
                                          current matchit semantics"
                )
            });
            let (pattern, served) = route_table[*matched.value];
            let (_, is_allow) = served
                .iter()
                .find(|(m, _)| *m == method.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{method} {path} dispatched to {pattern} \
                                          which does not serve that method"
                    )
                });
            assert_eq!(
                is_workload_authority_mutation(method, path),
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
            assert!(
                mirror.at(path).is_err(),
                "{path} must NOT dispatch under current matchit semantics \
                 (raw bytes are not decoded, dot segments are not resolved, \
                 trailing slashes and leading empties do not match)"
            );
        }
    }

    #[test]
    fn workload_gate_classifies_raw_path_variants_fail_closed() {
        // Raw variants of workload mutations (encoded slashes, doubled
        // slashes, trailing slash, dot segments) must never fall through the
        // gate's allow patterns. The router (matchit 0.8) matches the raw
        // path with literal `/` separators only, so the gate must classify
        // these same raw bytes — and must classify every one of them as a
        // mutation.
        for (method, path) in [
            (Method::POST, "/apps%2Fdemo/deploy"),
            (Method::POST, "/apps%2fdemo/deploy"),
            (Method::POST, "//apps//demo//deploy"),
            (Method::POST, "/apps/demo/deploy/"),
            (Method::POST, "/apps/./demo/deploy"),
            (Method::POST, "/apps/x/../demo/deploy"),
            // A `%2F`/`..` poisoned path parameter on a route the router
            // still dispatches to a mutation handler.
            (Method::POST, "/apps/x%2F..%2F..%2Fauth%2Flogin/deploy"),
            (Method::POST, "/apps/x%2f..%2f..%2fauth/deploy"),
            (Method::DELETE, "/apps/demo/domains/.."),
            (Method::DELETE, "/apps/demo/domains/%2e%2e"),
            (Method::DELETE, "/apps/demo/domains/x%2F..%2F.."),
            (Method::DELETE, "/apps/demo/config/x%2F..%2F..%2Fauth/meta"),
            (Method::PUT, "/internal%2Fpaas/orgs/org-1/deployments"),
            (Method::POST, "/auth%2Flogin"),
            // Interior empty segment as a poisoned parameter: matchit
            // dispatches this to the keyring handler (empty paas_org_id),
            // so it must NOT collapse onto the org-upsert allow rule.
            (Method::PUT, "/internal/paas/orgs//keyring"),
        ] {
            assert!(
                is_workload_authority_mutation(&method, path),
                "{method} {path} must be classified as a workload authority mutation"
            );
        }

        // Allow-listed control-plane writes keep working, including when a
        // still-literal segment carries an encoded character.
        for (method, path) in [
            (Method::POST, "/auth/login"),
            (Method::PUT, "/internal/paas/orgs/org%2F1/entitlements"),
            (Method::PUT, "/internal/paas/orgs/org-1/members/user%2F1"),
            (Method::DELETE, "/internal/paas/orgs/org-1/apps/demo"),
            // Interior empty segments inside allow patterns: matchit
            // dispatches these to the allow-listed handlers (the empty
            // segment is the parameter value), so they must stay allowed —
            // an over-strict gate that rejects empty segments inside allow
            // rules would false-block control-plane writes.
            (Method::PUT, "/internal/paas/orgs//members/u"),
            (Method::PUT, "/internal/paas/orgs//entitlements"),
            (Method::DELETE, "/internal/paas/orgs//apps/demo"),
            (Method::POST, "/orgs//invite"),
            (Method::DELETE, "/orgs//members/user-1"),
        ] {
            assert!(
                !is_workload_authority_mutation(&method, path),
                "{method} {path} must not be classified as a workload authority mutation"
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
        let mut state = crate::test_support::lazy_state();
        state.deployment_dispatch_enabled = false;
        state.mark_startup_ready();
        let app = test_router(state);

        for (method, path) in [
            (Method::POST, "/apps/demo/deploy"),
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
        paas_state.deployment_dispatch_enabled = false;
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

        // Raw first segment `auth`, so the gate's control-plane allow list
        // matches it — but matchit has no such route, so the router must
        // 404 it. Asserting the 404 (not just "not 503") pins the router
        // agreement: if a future route table ever dispatches this shape to
        // a mutation handler, this test fails and forces a gate update.
        let response = app
            .oneshot(
                Request::post("/auth/%2e%2e/apps/demo/deploy")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn router_exposes_only_liveness_until_ready_then_enforces_dispatch_gate() {
        let mut state = crate::test_support::lazy_state();
        state.deployment_dispatch_enabled = false;
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
            deployment_dispatch_enabled: true,
            startup_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            signing_key: Arc::new(SigningKey::generate(&mut OsRng)),
            hmac_key: Arc::new([7u8; 32]),
            api_url: "https://api.example.test".to_string(),
            dashboard_url: Some("https://app.example.test".to_string()),
            platform_domain: "enclava.dev".to_string(),
            tee_domain_suffix: "tee.enclava.dev".to_string(),
            http_client: reqwest::Client::new(),
            registry_client: RegistryClient::new(
                ClientConfig::from_env(),
                AllowList::from_env_or_default(None),
            )
            .unwrap(),
            trustee_http_client: reqwest::Client::new(),
            tee_http_client: reqwest::Client::new(),
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
                platform_trustee_policy_pubkey_hex: Some("11".repeat(32)),
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
}
