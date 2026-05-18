pub mod acme;
pub mod auth;
pub mod billing;
pub mod clients;
pub mod cosign;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod edge;
pub mod env_gates;
pub mod kbs;
pub mod models;
pub mod platform_release;
pub mod ratelimit;
pub mod registry;
pub mod routes;
pub mod signing_service;
pub mod state;

use axum::Router;
use axum::http::{HeaderValue, Method, header};
use tower_governor::{GovernorLayer, governor::GovernorConfigBuilder};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::ratelimit::TrustedProxyKeyExtractor;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    let key_extractor = TrustedProxyKeyExtractor::from_env();

    let unlock_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(120)
        .key_extractor(key_extractor.clone())
        .finish()
        .expect("unlock governor config");

    let api_governor_conf = GovernorConfigBuilder::default()
        .per_second(1)
        .burst_size(100)
        .key_extractor(key_extractor)
        .finish()
        .expect("api governor config");

    // Auth routes (unauthenticated)
    let auth_routes = Router::new()
        .route("/auth/signup", axum::routing::post(routes::auth::signup))
        .route("/auth/login", axum::routing::post(routes::auth::login))
        .route(
            "/auth/api-keys",
            axum::routing::post(routes::auth::create_api_key_route),
        )
        .route(
            "/auth/api-keys/{id}",
            axum::routing::delete(routes::auth::revoke_api_key_route),
        );

    let user_routes = Router::new().route(
        "/users/me/public-keys",
        axum::routing::post(routes::users::register_public_key),
    );

    // Org routes (authenticated)
    let org_routes = Router::new()
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
        );

    // App routes (authenticated)
    let app_routes = Router::new()
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
        );

    // Deployment routes (authenticated)
    let deploy_routes = Router::new()
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
        );

    // Secret Agent hosted-Hermes compatibility routes. These wrap CAP's native
    // org/app/deploy/config-token model behind the small provisioning API used
    // by Secret Agent.
    let secret_agent_routes = Router::new()
        .route(
            "/v1/deployments",
            axum::routing::post(routes::secret_agent::create_deployment),
        )
        .route(
            "/v1/deployments/{deployment_id}/status",
            axum::routing::get(routes::secret_agent::deployment_status),
        )
        .route(
            "/v1/deployments/{deployment_id}/config-token",
            axum::routing::post(routes::secret_agent::config_token),
        );

    // Config routes (authenticated)
    let config_routes = Router::new()
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
        );

    // Domain routes (authenticated). Phase 4 introduces a TXT-based
    // verification flow before any A/AAAA record is created for a custom
    // domain; the legacy `PUT /domain` shortcut is gone.
    let domain_routes = Router::new()
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
        );

    // Status routes (authenticated)
    let status_routes = Router::new()
        .route(
            "/apps/{name}/status",
            axum::routing::get(routes::status::app_status),
        )
        .route(
            "/apps/{name}/logs",
            axum::routing::get(routes::status::app_logs),
        );

    // Unlock routes (authenticated, rate-limited)
    let unlock_routes = Router::new()
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
        )
        .layer(GovernorLayer::new(unlock_governor_conf));

    // Billing routes
    let billing_routes = Router::new()
        .route(
            "/billing/tiers",
            axum::routing::get(routes::billing::list_tiers),
        )
        .route(
            "/billing/upgrade",
            axum::routing::post(routes::billing::upgrade_tier),
        )
        .route(
            "/billing/status",
            axum::routing::get(routes::billing::subscription_status),
        )
        .route(
            "/billing/renew",
            axum::routing::post(routes::billing::renew_subscription),
        )
        .route(
            "/billing/webhook",
            axum::routing::post(routes::billing::btcpay_webhook),
        );

    // Health check (unauthenticated)
    let health = Router::new().route("/health", axum::routing::get(|| async { "ok" }));

    // Workload routes (attestation-authenticated through Trustee callback).
    let workload_routes = Router::new()
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
        );

    let api_routes = Router::new()
        .merge(auth_routes)
        .merge(user_routes)
        .merge(org_routes)
        .merge(app_routes)
        .merge(deploy_routes)
        .merge(secret_agent_routes)
        .merge(config_routes)
        .merge(domain_routes)
        .merge(status_routes)
        .merge(unlock_routes)
        .merge(workload_routes)
        .merge(billing_routes)
        .layer(GovernorLayer::new(api_governor_conf));

    Router::new()
        .merge(health)
        .merge(api_routes)
        .layer(TraceLayer::new_for_http())
        .layer(build_cors_layer())
        .with_state(state)
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
    build_router(state)
}
