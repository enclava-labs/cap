//! Platform metadata routes consumed by trusted CLIs.

use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use crate::auth::{middleware::AuthContext, scopes};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DeploymentContextResponse {
    pub api_signing_pubkey: String,
    pub tls_certificate_broker_url: Option<String>,
}

/// GET /platform/deployment-context -- runtime values needed for descriptor signing.
pub async fn deployment_context(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<DeploymentContextResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

    Ok(Json(DeploymentContextResponse {
        api_signing_pubkey: crate::auth::jwt::public_key_base64(&state.signing_key),
        tls_certificate_broker_url: state
            .attestation
            .as_ref()
            .and_then(|cfg| cfg.tls_certificate_broker_url.clone()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::public_key_base64;
    use crate::models::Role;
    use crate::test_support::{auth_context, lazy_state};
    use ed25519_dalek::SigningKey;
    use enclava_engine::types::CaddyTlsMode;
    use std::sync::Arc;

    #[tokio::test]
    async fn deployment_context_returns_runtime_signing_key_and_broker_url() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let expected_pubkey = public_key_base64(&signing_key);
        let mut state = lazy_state();
        state.signing_key = Arc::new(signing_key);
        let attestation = state.attestation.as_mut().expect("test attestation config");
        attestation.caddy_tls_mode = CaddyTlsMode::Dns01Broker;
        attestation.tls_certificate_broker_url = Some(
            "http://cap-api.cap-test01.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
                .to_string(),
        );

        let Json(response) = deployment_context(auth_context(Role::Admin, &[]), State(state))
            .await
            .expect("deployment context response");

        assert_eq!(response.api_signing_pubkey, expected_pubkey);
        assert_eq!(
            response.tls_certificate_broker_url.as_deref(),
            Some(
                "http://cap-api.cap-test01.svc.cluster.local/api/v1/workload/tls/dns01-certificate"
            )
        );
    }

    #[tokio::test]
    async fn deployment_context_requires_apps_write_scope_for_api_keys() {
        let err = deployment_context(
            auth_context(Role::Admin, &["apps:read"]),
            State(lazy_state()),
        )
        .await
        .expect_err("apps:write scope should be required");

        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }
}
