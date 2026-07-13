use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::{
    Json,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use serde_json::{Value, json};

use crate::state::AppState;

#[derive(Debug, sqlx::FromRow)]
struct WorkloadArtifactRow {
    descriptor_payload: Value,
    descriptor_signature: Vec<u8>,
    descriptor_signing_key_id: String,
    org_keyring_envelope: Value,
    signed_policy_artifact: Value,
    expected_init_data_hash: Vec<u8>,
    artifact_bundle_digest: Vec<u8>,
    authorization_bytes: Vec<u8>,
    authorization_digest: Vec<u8>,
    receipt_resource_path: String,
}

#[derive(Debug, Serialize)]
struct WorkloadArtifactsResponse {
    schema_version: &'static str,
    artifact_bundle_digest: String,
    authorization_digest: String,
    receipt_resource_path: String,
    descriptor_payload: Value,
    descriptor_signature: String,
    descriptor_signing_key_id: String,
    org_keyring_envelope: Value,
    signed_policy_artifact: Value,
}

/// GET /api/v1/workload/artifacts
///
/// Workloads present the same KBS attestation token they use for resource reads.
/// CAP delegates token verification to Trustee and uses the attested
/// descriptor_core_hash claim to select the artifact row. This keeps descriptor,
/// keyring, and signed policy artifacts out of unauthenticated cross-tenant
/// reach while avoiding Trustee admin credentials in the workload.
pub async fn artifacts(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let response = artifacts_inner(state, headers).await;
    let result = if response.status().is_success() {
        "success"
    } else if response.status().is_client_error() {
        "denied"
    } else {
        "error"
    };
    crate::metrics::artifact_fetch(result);
    response
}

async fn artifacts_inner(state: AppState, headers: HeaderMap) -> Response {
    let Some(token) = attestation_bearer(&headers) else {
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

    let verify_response = match trustee_attestation_verify_request(
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
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "trustee_attestation_verify_failed", "detail": err.to_string()})),
            )
                .into_response();
        }
    };

    if !verify_response.status().is_success() {
        let status = verify_response.status().as_u16();
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "attestation_denied",
                "upstream_status": status,
            })),
        )
            .into_response();
    }

    let claims: Value = match verify_response.json().await {
        Ok(value) => value,
        Err(err) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error": "attestation_claims_invalid", "detail": err.to_string()})),
            )
                .into_response();
        }
    };
    let descriptor_core_hash = match extract_unique_hex_claim(&claims, "descriptor_core_hash") {
        Ok(hash) => hash,
        Err(error) => {
            if error == ClaimExtractionError::Ambiguous {
                crate::metrics::claim_conflict();
            }
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": error.code("descriptor_core_hash")})),
            )
                .into_response();
        }
    };
    let attested_init_data_hash = match extract_unique_hex_claim(&claims, "init_data_hash") {
        Ok(hash) => hash,
        Err(error) => {
            if error == ClaimExtractionError::Ambiguous {
                crate::metrics::claim_conflict();
            }
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": error.code("init_data_hash")})),
            )
                .into_response();
        }
    };

    let row = match sqlx::query_as::<_, WorkloadArtifactRow>(
        "SELECT wa.descriptor_payload, wa.descriptor_signature,
                wa.descriptor_signing_key_id, wa.org_keyring_envelope,
                wa.signed_policy_artifact, wa.expected_init_data_hash,
                wa.artifact_bundle_digest, auth.authorization_bytes,
                auth.authorization_digest, auth.receipt_resource_path
         FROM workload_artifacts wa
         JOIN apps app ON app.id = wa.app_id
         JOIN workload_artifact_authorizations auth
           ON auth.descriptor_core_hash = wa.descriptor_core_hash
         WHERE wa.descriptor_core_hash = $1
           AND wa.terminally_revoked_at IS NULL
           AND app.status <> 'deleting'
           AND auth.publication_state = 'active'
           AND auth.terminally_revoked_at IS NULL
           AND (auth.expires_at IS NULL OR auth.expires_at > now())
           AND EXISTS (
               SELECT 1 FROM deployment_artifact_activations activation
               JOIN deployments deployment
                 ON deployment.id = activation.management_deployment_id
               WHERE activation.descriptor_core_hash = wa.descriptor_core_hash
                 AND activation.activation_state = 'active'
                 AND deployment.status IN ('applying', 'watching', 'healthy')
           )",
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

    if row.descriptor_signature.len() != 64
        || row.expected_init_data_hash.len() != 32
        || row.artifact_bundle_digest.len() != 32
        || row.authorization_digest.len() != 32
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored_artifact_signature_invalid"})),
        )
            .into_response();
    }
    let Some(expected_cc_init_data_hash) = row
        .descriptor_payload
        .get("expected_cc_init_data_hash")
        .and_then(Value::as_str)
        .and_then(parse_hex32)
    else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored_descriptor_missing_expected_cc_init_data_hash"})),
        )
            .into_response();
    };
    if expected_cc_init_data_hash != attested_init_data_hash {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "attested_init_data_hash_mismatch"})),
        )
            .into_response();
    }
    if row.expected_init_data_hash != attested_init_data_hash {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "attested_init_data_hash_mismatch"})),
        )
            .into_response();
    }

    let authorization =
        match enclava_common::kbs_authorization::DeploymentAuthorizationV1::parse_exact_json(
            &row.authorization_bytes,
        ) {
            Ok(authorization) => authorization,
            Err(_) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": "stored_authorization_invalid"})),
                )
                    .into_response();
            }
        };
    let authorization_pubkey = match authorization_pubkey_for_issuer(
        state
            .attestation
            .as_ref()
            .and_then(|config| config.signing_service_trusted_pubkeys_json.as_deref()),
        &authorization.issuer_key_id,
    ) {
        Ok(key) => key,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error": "authorization_trust_key_unconfigured"})),
            )
                .into_response();
        }
    };
    if authorization
        .verify_signature(&authorization_pubkey)
        .is_err()
        || authorization.validate_time(chrono::Utc::now()).is_err()
        || authorization.descriptor_core_hash.as_slice() != descriptor_core_hash
        || authorization.expected_init_data_hash.as_slice() != attested_init_data_hash
        || authorization.artifact_bundle_digest.as_slice() != row.artifact_bundle_digest
        || authorization.receipt_resource_path != row.receipt_resource_path
        || enclava_common::kbs_authorization::authorization_digest(&row.authorization_bytes)
            .as_slice()
            != row.authorization_digest
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored_authorization_binding_invalid"})),
        )
            .into_response();
    }
    let recomputed_bundle = match crate::signing_service::recompute_stored_bundle_digest(
        &row.descriptor_payload,
        &row.descriptor_signature,
        &row.descriptor_signing_key_id,
        &row.org_keyring_envelope,
        &row.signed_policy_artifact,
    ) {
        Ok(digest) => digest,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "stored_artifact_bundle_invalid"})),
            )
                .into_response();
        }
    };
    if recomputed_bundle.as_slice() != row.artifact_bundle_digest {
        crate::metrics::artifact_digest_mismatch();
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored_artifact_bundle_digest_mismatch"})),
        )
            .into_response();
    }

    let response = WorkloadArtifactsResponse {
        schema_version: "enclava-workload-artifact-bundle-v1",
        artifact_bundle_digest: hex::encode(&row.artifact_bundle_digest),
        authorization_digest: hex::encode(&row.authorization_digest),
        receipt_resource_path: row.receipt_resource_path,
        descriptor_payload: row.descriptor_payload,
        descriptor_signature: hex::encode(row.descriptor_signature),
        descriptor_signing_key_id: row.descriptor_signing_key_id,
        org_keyring_envelope: row.org_keyring_envelope,
        signed_policy_artifact: row.signed_policy_artifact,
    };
    let response_size = serde_json::to_vec(&response).map_or(usize::MAX, |bytes| bytes.len());
    if response_size > 2 * 1024 * 1024 {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "stored_artifact_bundle_too_large"})),
        )
            .into_response();
    }
    let mut response_headers = HeaderMap::new();
    response_headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    (StatusCode::OK, response_headers, Json(response)).into_response()
}

pub(crate) fn attestation_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Attestation ")
        .or_else(|| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

pub(crate) fn trustee_attestation_verify_request(
    client: &reqwest::Client,
    verify_url: &str,
    workload_token: &str,
    caller_bearer_token: Option<&str>,
) -> reqwest::RequestBuilder {
    let request = client
        .post(verify_url)
        .json(&json!({ "token": workload_token }));
    match caller_bearer_token {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

pub(crate) fn extract_descriptor_core_hash(value: &Value) -> Option<Vec<u8>> {
    extract_unique_hex_claim(value, "descriptor_core_hash").ok()
}

pub(crate) fn extract_init_data_hash(value: &Value) -> Option<Vec<u8>> {
    extract_unique_hex_claim(value, "init_data_hash").ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimExtractionError {
    Missing,
    Invalid,
    Ambiguous,
}

impl ClaimExtractionError {
    fn code(self, claim: &str) -> String {
        let suffix = match self {
            Self::Missing => "missing",
            Self::Invalid => "invalid",
            Self::Ambiguous => "ambiguous",
        };
        format!("{claim}_{suffix}")
    }
}

fn extract_unique_hex_claim(value: &Value, key: &str) -> Result<Vec<u8>, ClaimExtractionError> {
    let mut raw_values = Vec::new();
    collect_claim_values(value, key, &mut raw_values);
    if raw_values.is_empty() {
        return Err(ClaimExtractionError::Missing);
    }

    let mut parsed = Vec::with_capacity(raw_values.len());
    for value in raw_values {
        let Some(value) = value.as_str().and_then(parse_hex32) else {
            return Err(ClaimExtractionError::Invalid);
        };
        parsed.push(value);
    }
    if parsed.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(ClaimExtractionError::Ambiguous);
    }
    Ok(parsed.remove(0))
}

fn collect_claim_values<'a>(value: &'a Value, key: &str, found: &mut Vec<&'a Value>) {
    match value {
        Value::Object(map) => {
            if let Some(value) = map.get(key) {
                found.push(value);
            }
            for nested in map.values() {
                collect_claim_values(nested, key, found);
            }
        }
        Value::Array(values) => {
            for nested in values {
                collect_claim_values(nested, key, found);
            }
        }
        _ => {}
    }
}

pub(crate) fn parse_hex32(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() != 64
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    hex::decode(trimmed).ok()
}

fn authorization_pubkey_for_issuer(
    raw_trust_map: Option<&str>,
    issuer_key_id: &str,
) -> Result<[u8; 32], enclava_common::kbs_authorization::AuthorizationError> {
    let raw_trust_map = raw_trust_map.ok_or(
        enclava_common::kbs_authorization::AuthorizationError::InvalidTrustMap(
            "receipt mode requires an issuer trust map",
        ),
    )?;
    let trusted_keys =
        enclava_common::kbs_authorization::parse_authorization_trust_map(raw_trust_map)?;
    enclava_common::kbs_authorization::trusted_authorization_key(&trusted_keys, issuer_key_id)
        .copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_descriptor_core_hash_from_nested_claims() {
        let claims = json!({
            "claims": {
                "submods": {
                    "cpu0": {
                        "ear.veraison.annotated-evidence": {
                            "init_data_hash": "cd".repeat(32),
                            "init_data_claims": {
                                "descriptor_core_hash": "ab".repeat(32)
                            }
                        }
                    }
                }
            }
        });
        assert_eq!(
            extract_descriptor_core_hash(&claims).unwrap(),
            vec![0xab; 32]
        );
        assert_eq!(extract_init_data_hash(&claims).unwrap(), vec![0xcd; 32]);
    }

    #[test]
    fn rejects_missing_or_malformed_hex_claims() {
        assert!(extract_descriptor_core_hash(&json!({})).is_none());
        assert!(
            extract_descriptor_core_hash(&json!({
                "init_data_claims": { "descriptor_core_hash": "not-hex" }
            }))
            .is_none()
        );
        assert!(
            extract_init_data_hash(&json!({
                "init_data_hash": "not-hex"
            }))
            .is_none()
        );
    }

    #[test]
    fn rejects_conflicting_or_malformed_duplicate_claims() {
        let conflicting = json!({
            "descriptor_core_hash": "aa".repeat(32),
            "nested": { "descriptor_core_hash": "bb".repeat(32) }
        });
        assert_eq!(
            extract_unique_hex_claim(&conflicting, "descriptor_core_hash"),
            Err(ClaimExtractionError::Ambiguous)
        );

        let malformed_duplicate = json!({
            "descriptor_core_hash": "aa".repeat(32),
            "nested": { "descriptor_core_hash": "not-hex" }
        });
        assert_eq!(
            extract_unique_hex_claim(&malformed_duplicate, "descriptor_core_hash"),
            Err(ClaimExtractionError::Invalid)
        );

        let identical = json!({
            "descriptor_core_hash": "aa".repeat(32),
            "nested": { "descriptor_core_hash": "aa".repeat(32) }
        });
        assert_eq!(
            extract_unique_hex_claim(&identical, "descriptor_core_hash").unwrap(),
            vec![0xaa; 32]
        );
    }

    #[test]
    fn trustee_verify_request_attaches_internal_bearer_without_replacing_workload_token() {
        let request = trustee_attestation_verify_request(
            &reqwest::Client::new(),
            "https://kbs.example.test/kbs/v0/attestation/verify",
            "workload-attestation-token",
            Some("internal-cap-token"),
        )
        .build()
        .unwrap();

        assert_eq!(
            request
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("Bearer internal-cap-token")
        );
        let body = request
            .body()
            .and_then(|body| body.as_bytes())
            .expect("request body should be buffered JSON");
        assert_eq!(
            serde_json::from_slice::<Value>(body).unwrap(),
            json!({ "token": "workload-attestation-token" })
        );
    }

    #[test]
    fn authorization_key_lookup_rejects_unknown_issuer_without_scalar_fallback() {
        let current_key = "11".repeat(32);
        let trust_map = json!({"current": current_key}).to_string();

        assert_eq!(
            authorization_pubkey_for_issuer(Some(&trust_map), "current").unwrap(),
            [0x11; 32]
        );
        assert_eq!(
            authorization_pubkey_for_issuer(Some(&trust_map), "retired-or-unknown"),
            Err(enclava_common::kbs_authorization::AuthorizationError::UntrustedIssuerKeyId)
        );
        assert!(authorization_pubkey_for_issuer(None, "current").is_err());
    }
}
