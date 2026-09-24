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

    let mut verify_response = match trustee_attestation_verify_request(
        &state.trustee_http_client,
        verify_url,
        token,
        state.trustee_attestation_verify_bearer_token.as_deref(),
    )
    .send()
    .await
    {
        Ok(response) => response,
        Err(err) => return trustee_verify_unreachable(&err).into_response(),
    };

    if !verify_response.status().is_success() {
        let status = verify_response.status().as_u16();
        let body = read_limited_upstream_body(&mut verify_response).await;
        return attestation_denied(status, &body).into_response();
    }

    let claims: Value = match verify_response.json().await {
        Ok(value) => value,
        Err(err) => return attestation_claims_invalid(&err).into_response(),
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
        Err(err) => return workload_artifacts_query_failed(&err).into_response(),
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

pub(crate) fn attestation_bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    value
        .strip_prefix("Attestation ")
        .or_else(|| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

/// Caps on upstream-body text retained from a failed Trustee verify: at
/// most UPSTREAM_READ_LIMIT bytes are read off the wire (the response has
/// no other consumer after this change, so an unbounded read is unjustified
/// exposure to a misbehaving upstream), and at most UPSTREAM_LOG_BODY_LIMIT
/// characters reach the log field. The raw body never reaches the client
/// response (#122).
const UPSTREAM_LOG_BODY_LIMIT: usize = 512;
const UPSTREAM_READ_LIMIT: usize = 2048;

fn truncate_for_log(value: &str) -> &str {
    match value.char_indices().nth(UPSTREAM_LOG_BODY_LIMIT) {
        Some((idx, _)) => &value[..idx],
        None => value,
    }
}

/// Formats an error together with its full `source()` chain. reqwest's
/// `Display` carries only the error kind and URL; the DNS failure, TLS
/// alert, or serde decode message operators need lives on the source
/// chain and would otherwise be lost (#122).
fn format_error_chain(err: &dyn std::error::Error) -> String {
    let mut chain = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        chain.push_str(": ");
        chain.push_str(&cause.to_string());
        source = cause.source();
    }
    chain
}

/// Reads at most [`UPSTREAM_READ_LIMIT`] bytes of a non-success Trustee
/// verify response for the server-side log. Read failures are logged and
/// yield whatever was retained so far instead of silently degrading to an
/// empty log field.
pub(crate) async fn read_limited_upstream_body(response: &mut reqwest::Response) -> String {
    let mut retained: Vec<u8> = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(bytes)) => {
                let remaining = UPSTREAM_READ_LIMIT - retained.len();
                if bytes.len() >= remaining {
                    retained.extend_from_slice(&bytes[..remaining]);
                    break;
                }
                retained.extend_from_slice(&bytes);
            }
            Ok(None) => break,
            Err(err) => {
                tracing::warn!(
                    error = %format_error_chain(&err),
                    "Trustee error body read failed before reaching the log cap"
                );
                break;
            }
        }
    }
    String::from_utf8_lossy(&retained).into_owned()
}

/// 502 for a transport failure reaching the Trustee attestation endpoint.
///
/// The reqwest error (with its source chain) can name internal hosts,
/// ports, and TLS detail; it is logged server-side only and the client
/// gets the fixed code (#122).
pub(crate) fn trustee_verify_unreachable(
    err: &(dyn std::error::Error + 'static),
) -> (StatusCode, Json<Value>) {
    tracing::warn!(
        error = format_error_chain(err),
        "Trustee attestation verify request failed to reach upstream"
    );
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": "trustee_attestation_verify_failed"})),
    )
}

/// 403 for a Trustee attestation rejection.
///
/// The upstream status and body can disclose Trustee internals (hostnames,
/// versions, policy detail); they are logged server-side — body truncated —
/// and the client gets only the fixed code (#122).
pub(crate) fn attestation_denied(
    upstream_status: u16,
    upstream_body: &str,
) -> (StatusCode, Json<Value>) {
    tracing::warn!(
        upstream_status,
        upstream_body = truncate_for_log(upstream_body),
        "Trustee attestation verification rejected the token"
    );
    (
        StatusCode::FORBIDDEN,
        Json(json!({"error": "attestation_denied"})),
    )
}

/// 502 when Trustee returns success but a non-JSON body.
///
/// The decode error can quote fragments of the upstream payload in its
/// source chain; it is logged server-side only and the client gets the
/// fixed code (#122).
pub(crate) fn attestation_claims_invalid(
    err: &(dyn std::error::Error + 'static),
) -> (StatusCode, Json<Value>) {
    tracing::warn!(
        error = format_error_chain(err),
        "Trustee attestation verify response did not decode as JSON claims"
    );
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({"error": "attestation_claims_invalid"})),
    )
}

/// 500 for a workload_artifacts database failure.
///
/// The sqlx error can carry connection strings, hostnames, and constraint
/// detail; it is logged server-side only and the client gets the fixed
/// code (#122).
pub(crate) fn workload_artifacts_query_failed(err: &sqlx::Error) -> (StatusCode, Json<Value>) {
    tracing::error!(
        error = format_error_chain(err),
        "workload_artifacts database query failed"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "workload_artifacts_query_failed"})),
    )
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
    extract_hex_claim(value, "descriptor_core_hash")
}

pub(crate) fn extract_init_data_hash(value: &Value) -> Option<Vec<u8>> {
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

pub(crate) fn parse_hex32(value: &str) -> Option<Vec<u8>> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(trimmed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal error with a source chain, standing in for a reqwest error
    /// whose `Display` alone would hide the underlying cause.
    #[derive(Debug)]
    struct ChainedError;
    impl std::fmt::Display for ChainedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "error sending request for url (https://trustee.internal.example.test:8443/attest)"
            )
        }
    }
    impl std::error::Error for ChainedError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&SourceError)
        }
    }
    #[derive(Debug)]
    struct SourceError;
    impl std::fmt::Display for SourceError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "dns failure: trustee.internal.example.test")
        }
    }
    impl std::error::Error for SourceError {}

    #[test]
    fn format_error_chain_includes_sources_display_hides() {
        let chain = format_error_chain(&ChainedError);
        assert!(chain.contains("error sending request"));
        assert!(chain.contains("dns failure: trustee.internal.example.test"));
    }

    #[test]
    fn trustee_error_responses_never_carry_upstream_or_internal_detail() {
        // Synthetic secrets stand in for the internal hostnames, connection
        // detail, and upstream body text that the legacy responses leaked.
        let transport = ChainedError;
        let transport_err: &(dyn std::error::Error + 'static) = &transport;

        let (status, Json(body)) = trustee_verify_unreachable(transport_err);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, json!({"error": "trustee_attestation_verify_failed"}));
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("trustee.internal.example.test"));
        assert!(!serialized.contains("detail"));

        let (status, Json(body)) = attestation_claims_invalid(transport_err);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body, json!({"error": "attestation_claims_invalid"}));
        assert!(!serde_json::to_string(&body).unwrap().contains("detail"));

        let upstream_body = "internal Trustee v4.2.1 at kbs-node-3.internal: connection refused";
        let (status, Json(body)) = attestation_denied(503, upstream_body);
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, json!({"error": "attestation_denied"}));
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("kbs-node-3"));
        assert!(!serialized.contains("upstream_body"));
        assert!(!serialized.contains("upstream_status"));

        let db = sqlx::Error::Protocol(
            "tenant-sensitive database detail at postgres.internal:5432".to_string(),
        );
        let (status, Json(body)) = workload_artifacts_query_failed(&db);
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, json!({"error": "workload_artifacts_query_failed"}));
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains("postgres.internal"));
        assert!(!serialized.contains("detail"));
    }

    #[test]
    fn upstream_log_body_is_truncated_on_multibyte_boundaries() {
        let long: String = "ä".repeat(600);
        assert_eq!(
            truncate_for_log(&long).chars().count(),
            UPSTREAM_LOG_BODY_LIMIT
        );
        let short = "small body";
        assert_eq!(truncate_for_log(short), short);
    }

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
}
