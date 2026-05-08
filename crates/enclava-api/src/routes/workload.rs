use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::{Json, response::IntoResponse};
use serde::Serialize;
use serde_json::{Value, json};

use crate::state::AppState;

#[derive(Debug, sqlx::FromRow)]
struct WorkloadArtifactRow {
    descriptor_payload: Value,
    descriptor_signature: Vec<u8>,
    descriptor_signing_key_id: String,
    org_keyring_payload: Value,
    org_keyring_signature: Vec<u8>,
    signed_policy_artifact: Value,
}

#[derive(Debug, Serialize)]
struct WorkloadArtifactsResponse {
    descriptor_payload: Value,
    descriptor_signature: String,
    descriptor_signing_key_id: String,
    org_keyring_payload: Value,
    org_keyring_signature: String,
    signed_policy_artifact: Value,
}

/// GET /api/v1/workload/artifacts
///
/// Workloads present the same KBS attestation token they use for resource reads.
/// CAP delegates token verification to Trustee and uses the attested
/// descriptor_core_hash claim to select the artifact row. This keeps descriptor,
/// keyring, and signed policy artifacts out of unauthenticated cross-tenant
/// reach while avoiding Trustee admin credentials in the workload.
pub async fn artifacts(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
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

    let verify_response = match state
        .trustee_http_client
        .post(verify_url)
        .json(&json!({ "token": token }))
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
        let body = verify_response.text().await.unwrap_or_default();
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "attestation_denied",
                "upstream_status": status,
                "upstream_body": body,
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
    let Some(descriptor_core_hash) = extract_descriptor_core_hash(&claims) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "descriptor_core_hash_missing"})),
        )
            .into_response();
    };
    let Some(attested_init_data_hash) = extract_init_data_hash(&claims) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "init_data_hash_missing"})),
        )
            .into_response();
    };

    let row = match sqlx::query_as::<_, WorkloadArtifactRow>(
        "SELECT descriptor_payload, descriptor_signature, descriptor_signing_key_id,
                org_keyring_payload, org_keyring_signature, signed_policy_artifact
         FROM workload_artifacts
         WHERE descriptor_core_hash = $1",
    )
    .bind(descriptor_core_hash)
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

    if row.descriptor_signature.len() != 64 || row.org_keyring_signature.len() != 64 {
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

    (
        StatusCode::OK,
        Json(WorkloadArtifactsResponse {
            descriptor_payload: row.descriptor_payload,
            descriptor_signature: hex::encode(row.descriptor_signature),
            descriptor_signing_key_id: row.descriptor_signing_key_id,
            org_keyring_payload: row.org_keyring_payload,
            org_keyring_signature: hex::encode(row.org_keyring_signature),
            signed_policy_artifact: row.signed_policy_artifact,
        }),
    )
        .into_response()
}

fn attestation_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Attestation ")
        .or_else(|| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn extract_descriptor_core_hash(value: &Value) -> Option<Vec<u8>> {
    extract_hex_claim(value, "descriptor_core_hash")
}

fn extract_init_data_hash(value: &Value) -> Option<Vec<u8>> {
    extract_hex_claim(value, "init_data_hash")
}

fn extract_hex_claim(value: &Value, key: &str) -> Option<Vec<u8>> {
    match value {
        Value::Object(map) => {
            if let Some(hash) = map.get(key).and_then(Value::as_str).and_then(parse_hex32) {
                return Some(hash);
            }
            map.values()
                .find_map(|nested| extract_hex_claim(nested, key))
        }
        Value::Array(values) => values
            .iter()
            .find_map(|nested| extract_hex_claim(nested, key)),
        _ => None,
    }
}

fn parse_hex32(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(trimmed).ok()
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
}
