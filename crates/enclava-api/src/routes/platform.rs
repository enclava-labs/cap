//! Platform metadata routes consumed by trusted CLIs.

use axum::{Json, extract::State, http::StatusCode};
use serde::Serialize;

use crate::auth::{middleware::AuthContext, scopes};
use crate::platform_release::PlatformReleaseEnvelope;
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct DeploymentContextResponse {
    pub api_signing_pubkey: String,
    pub tls_certificate_broker_url: Option<String>,
    /// PEM trust anchors for workload TLS certificate validation, present
    /// only when the platform pins a non-public tenant ACME issuer. The
    /// signer installs the API's published value before hashing so both
    /// producers render identical cc_init_data bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_certificate_trust_anchors_pem: Option<String>,
    /// Whether this API's deployed enclava-init performs the log-spool
    /// state-PVC bind (cap#290 review): the API installs the gate from
    /// `ENCLAVA_LOG_SPOOL_STORAGE` at startup, so an absent or false flag
    /// tells signers to render claim-less cc_init_data. Deployment-context
    /// JSON tolerates unknown fields, so older CLIs ignore it.
    pub log_spool_state_bind_supported: bool,
    /// Contract v1 (policy-templates#23): this API deployment may
    /// discover and admit pod supplemental groups. An API DEPLOYMENT
    /// capability (cap#290 pattern): ops enables it atomically with the
    /// ENCLAVA_INIT_IMAGE pin whose descriptor parser tolerates the
    /// field — pre-change init rejects group-bearing descriptors with
    /// deny_unknown_fields, which would brick guest startup. Absent or
    /// false: signers keep the legacy single-call flow and admission
    /// rejects group-bearing descriptors.
    pub pod_supplemental_groups_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_platform_release_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform_release_envelope: Option<PlatformReleaseEnvelope>,
}

/// GET /platform/deployment-context -- runtime values needed for descriptor signing.
pub async fn deployment_context(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<DeploymentContextResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_write(&auth)?;

    Ok(Json(deployment_context_response(&state)))
}

/// Contract v1 (policy-templates#23): whether THIS API deployment may
/// discover and admit pod supplemental groups. An API DEPLOYMENT
/// capability, not a version constant — the cap#290
/// `log_spool_state_bind_supported` pattern: pre-change enclava-init
/// images parse the descriptor with `deny_unknown_fields`, so a
/// group-bearing descriptor would fail guest verification on every start
/// under an old ENCLAVA_INIT_IMAGE pin. Ops enables this gate atomically
/// with the field-tolerant init image pin (init-first rollout per
/// AGENTS.md); absent/false keeps signers on the legacy single-call flow
/// and admission rejects group-bearing descriptors.
pub(crate) fn pod_supplemental_groups_supported() -> bool {
    pod_supplemental_groups_supported_from(
        std::env::var("ENCLAVA_POD_SUPPLEMENTAL_GROUPS_SUPPORTED")
            .as_deref()
            .ok(),
    )
}

/// Pure parse so the gate's truth table is testable without env mutation.
pub(crate) fn pod_supplemental_groups_supported_from(value: Option<&str>) -> bool {
    match value {
        Some(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        None => false,
    }
}

pub(crate) fn deployment_context_response(state: &AppState) -> DeploymentContextResponse {
    DeploymentContextResponse {
        api_signing_pubkey: crate::auth::jwt::public_key_base64(&state.signing_key),
        tls_certificate_broker_url: state
            .attestation
            .as_ref()
            .and_then(|cfg| cfg.tls_certificate_broker_url.clone()),
        tls_certificate_trust_anchors_pem:
            enclava_engine::manifest::cc_init_data::tls_certificate_trust_anchors_pem(),
        log_spool_state_bind_supported:
            enclava_engine::manifest::cc_init_data::log_spool_bind_supported(),
        pod_supplemental_groups_supported: pod_supplemental_groups_supported(),
        current_platform_release_id: state
            .platform_release_envelope
            .as_ref()
            .map(|envelope| envelope.payload.platform_release_version.clone()),
        platform_release_envelope: state.platform_release_envelope.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::public_key_base64;
    use crate::models::Role;
    use crate::platform_release::PlatformReleaseEnvelope;
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
        assert_eq!(response.current_platform_release_id, None);
        assert!(
            response.tls_certificate_trust_anchors_pem.is_none(),
            "no installed anchors means the guest stays on the public root store"
        );
        assert!(response.platform_release_envelope.is_none());
        assert_eq!(
            response.log_spool_state_bind_supported,
            enclava_engine::manifest::cc_init_data::log_spool_bind_supported(),
            "the deployment-context gate must mirror the API's installed claim"
        );
        assert_eq!(
            response.pod_supplemental_groups_supported,
            pod_supplemental_groups_supported(),
            "the deployment-context gate must mirror the API's installed capability"
        );
    }

    #[test]
    fn pod_supplemental_groups_gate_defaults_off_and_parses_explicit_enablement() {
        // Off unless the deployment explicitly opts in: pre-change
        // enclava-init rejects group-bearing descriptors, so the default
        // must keep every signer on the legacy flow.
        assert!(!pod_supplemental_groups_supported_from(None));
        assert!(!pod_supplemental_groups_supported_from(Some("")));
        assert!(!pod_supplemental_groups_supported_from(Some("0")));
        assert!(!pod_supplemental_groups_supported_from(Some("false")));
        assert!(!pod_supplemental_groups_supported_from(Some("yes")));
        assert!(pod_supplemental_groups_supported_from(Some("1")));
        assert!(pod_supplemental_groups_supported_from(Some("true")));
        assert!(pod_supplemental_groups_supported_from(Some("TRUE")));
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

    #[tokio::test]
    async fn deployment_context_returns_signed_platform_release_envelope_when_loaded() {
        let mut state = lazy_state();
        state.platform_release_envelope =
            Some(PlatformReleaseEnvelope::load_verified().expect("test platform release"));

        let Json(response) = deployment_context(auth_context(Role::Admin, &[]), State(state))
            .await
            .expect("deployment context response");

        let envelope = response
            .platform_release_envelope
            .expect("platform release envelope");
        assert_eq!(
            response.current_platform_release_id.as_deref(),
            Some(envelope.payload.platform_release_version.as_str())
        );
        assert!(!envelope.signature.is_empty());
        assert!(!envelope.signing_pubkey.is_empty());
    }
}
