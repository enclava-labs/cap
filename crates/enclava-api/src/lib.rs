pub mod acme;
pub mod auth;
pub mod clients;
pub mod cosign;
pub mod db;
pub mod deploy;
pub mod dns;
pub mod edge;
pub mod entitlements;
pub mod env_gates;
pub mod kbs;
pub mod models;
pub mod platform_release;
pub mod ratelimit;
pub mod registry;
pub mod routes;
pub mod signing_service;
pub mod source_provider;
pub mod state;

use axum::Router;
use axum::http::{HeaderValue, Method, header};
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
        .layer(build_cors_layer())
        .with_state(state)
}

fn internal_routes() -> Router<AppState> {
    Router::new()
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
            "/internal/paas/orgs/{paas_org_id}/keyring/bootstrap-signing-service",
            axum::routing::post(routes::internal::bootstrap_paas_keyring_signing_service),
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
    Router::new().route("/health", axum::routing::get(|| async { "ok" }))
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
        AppState {
            db: pool,
            management_mode: crate::state::CapManagementMode::Standalone,
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
                trustee_policy_url: Some("https://kbs.example.test/policy".into()),
                local_workload_artifacts_json: None,
                local_trustee_policy_json: None,
                platform_trustee_policy_pubkey_hex: Some("11".repeat(32)),
                signing_service_pubkey_hex: Some("11".repeat(32)),
            }),
            dns: None,
            acme: None,
            kbs_policy: None,
            trustee_attestation_verify_url: None,
            trustee_attestation_verify_bearer_token: None,
            signing_service: None,
            require_customer_signed_policy_artifact: true,
            deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(1)),
            internal_auth: None,
        }
    }
}
