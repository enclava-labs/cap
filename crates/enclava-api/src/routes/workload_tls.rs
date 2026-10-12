use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::{Json, response::IntoResponse};
use base64::Engine;
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::acme::IssuanceFailure;
use crate::state::AppState;
use crate::workload_tls_timing::{Phase, RequestTiming};

#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    hostnames: Vec<String>,
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Serialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

#[derive(Debug, sqlx::FromRow)]
struct DescriptorRow {
    descriptor_payload: Value,
}

pub async fn dns01_certificate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CertificateRequest>,
) -> impl IntoResponse {
    let timing = RequestTiming::new();
    let mut total = timing.start(Phase::BrokerTotal);
    let response = dns01_certificate_inner(state, headers, body, timing)
        .await
        .into_response();
    total.finish(response.status().is_success());
    response
}

async fn dns01_certificate_inner(
    state: AppState,
    headers: HeaderMap,
    body: CertificateRequest,
    timing: RequestTiming,
) -> impl IntoResponse {
    let Some(token) = crate::routes::workload::attestation_bearer(&headers) else {
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
    let Some(dns_config) = state.dns.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "dns_management_unconfigured"})),
        )
            .into_response();
    };
    let Some(acme_config) = state.acme.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "acme_unconfigured"})),
        )
            .into_response();
    };

    let claims = match timing
        .measure(
            Phase::Attestation,
            verify_attestation(&state, verify_url, token),
        )
        .await
    {
        Ok(claims) => claims,
        Err(response) => return *response,
    };
    let Some(descriptor_core_hash) = crate::routes::workload::extract_descriptor_core_hash(&claims)
    else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "descriptor_core_hash_missing"})),
        )
            .into_response();
    };
    let Some(init_data_hash) = attested_or_declared_init_data_hash(&claims, &body) else {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "init_data_hash_missing"})),
        )
            .into_response();
    };

    let row = match timing
        .measure(
            Phase::ArtifactLookup,
            sqlx::query_as::<_, DescriptorRow>(
                "SELECT descriptor_payload
         FROM workload_artifacts
         WHERE descriptor_core_hash = $1",
            )
            .bind(descriptor_core_hash)
            .fetch_optional(&state.db),
        )
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
            let (status, body) = crate::routes::workload::workload_artifacts_query_failed(&err);
            return (status, body).into_response();
        }
    };

    if !descriptor_init_hash_matches(&row.descriptor_payload, &init_data_hash) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "attested_init_data_hash_mismatch"})),
        )
            .into_response();
    }
    if let Err(err) = validate_requested_hostnames(&row.descriptor_payload, &body.hostnames) {
        return (StatusCode::FORBIDDEN, Json(json!({"error": err}))).into_response();
    }
    let csr_der = match base64::engine::general_purpose::STANDARD.decode(&body.csr_der_base64) {
        Ok(bytes) if !bytes.is_empty() => bytes,
        Ok(_) => {
            return (StatusCode::BAD_REQUEST, Json(json!({"error": "csr_empty"}))).into_response();
        }
        Err(err) => return csr_base64_invalid_response(&err).into_response(),
    };

    match crate::acme::issue_dns01_certificate_timed(
        &state.http_client,
        dns_config,
        acme_config,
        &body.hostnames,
        &csr_der,
        timing,
    )
    .await
    {
        Ok(certificate_chain_pem) => (
            StatusCode::OK,
            Json(CertificateResponse {
                certificate_chain_pem,
            }),
        )
            .into_response(),
        Err(failure) => issuance_failure_response(&failure).into_response(),
    }
}

/// Bounded, provider-text-free response for a terminal ACME issuance failure.
///
/// The `error` field keeps the value clients recognize for generic failures
/// (`acme_certificate_issuance_failed`) and carries `acme_rate_limited` only
/// when the terminal ACME problem type was exactly
/// `urn:ietf:params:acme:error:rateLimited`. `terminal` marks that this
/// issuance attempt ended. `retry_after` is a validated UTC timestamp from
/// the failing response's `Retry-After` header, or null when the provider
/// did not supply a usable one. Problem details, hostnames, request URLs and
/// other provider text never appear here or in the log.
fn issuance_failure_response(failure: &IssuanceFailure) -> (StatusCode, Json<Value>) {
    let retry_after = failure.retry_after.map(format_retry_after);
    tracing::warn!(
        code = failure.code.as_str(),
        retry_after = retry_after.as_deref(),
        "ACME DNS-01 certificate issuance attempt failed"
    );
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({
            "error": failure.code.as_str(),
            "terminal": true,
            "retry_after": retry_after,
        })),
    )
}

fn format_retry_after(deadline: DateTime<Utc>) -> String {
    deadline.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// 400 for a CSR that is not valid base64.
///
/// The decode error is logged server-side only; the client gets the fixed
/// code (#122).
fn csr_base64_invalid_response(err: &base64::DecodeError) -> (StatusCode, Json<Value>) {
    tracing::warn!(error = %err, "certificate CSR base64 decode failed");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "csr_base64_invalid"})),
    )
}

fn attested_or_declared_init_data_hash(
    claims: &Value,
    body: &CertificateRequest,
) -> Option<Vec<u8>> {
    crate::routes::workload::extract_init_data_hash(claims).or_else(|| {
        body.cc_init_data_hash
            .as_deref()
            .and_then(crate::routes::workload::parse_hex32)
    })
}

async fn verify_attestation(
    state: &AppState,
    verify_url: &str,
    token: &str,
) -> Result<Value, Box<axum::response::Response>> {
    let mut verify_response = match crate::routes::workload::trustee_attestation_verify_request(
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
            let (status, body) = crate::routes::workload::trustee_verify_unreachable(&err);
            return Err((status, body).into_response().into());
        }
    };

    if !verify_response.status().is_success() {
        let status = verify_response.status().as_u16();
        let body = crate::routes::workload::read_limited_upstream_body(&mut verify_response).await;
        let (denied_status, denied_body) =
            crate::routes::workload::attestation_denied(status, &body);
        return Err((denied_status, denied_body).into_response().into());
    }

    verify_response.json().await.map_err(|err| {
        let (status, body) = crate::routes::workload::attestation_claims_invalid(&err);
        (status, body).into_response().into()
    })
}

fn descriptor_init_hash_matches(descriptor: &Value, attested_init_data_hash: &[u8]) -> bool {
    descriptor
        .get("expected_cc_init_data_hash")
        .and_then(Value::as_str)
        .and_then(crate::routes::workload::parse_hex32)
        .as_deref()
        == Some(attested_init_data_hash)
}

fn validate_requested_hostnames(descriptor: &Value, requested: &[String]) -> Result<(), String> {
    if requested.is_empty() {
        return Err("hostnames_empty".into());
    }
    let allowed = allowed_certificate_hostnames(descriptor);
    if allowed.is_empty() {
        return Err("descriptor_has_no_certificate_hostnames".into());
    }
    for hostname in requested {
        if !allowed.iter().any(|allowed| allowed == hostname) {
            return Err("hostname_not_attested".into());
        }
    }
    Ok(())
}

fn allowed_certificate_hostnames(descriptor: &Value) -> Vec<String> {
    let mut hostnames = Vec::new();
    if let Some(hostname) = descriptor.get("app_domain").and_then(Value::as_str)
        && !hostname.is_empty()
    {
        hostnames.push(hostname.to_string());
    }
    if let Some(custom) = descriptor.get("custom_domains").and_then(Value::as_array) {
        for hostname in custom.iter().filter_map(Value::as_str) {
            if !hostname.is_empty() && !hostnames.iter().any(|existing| existing == hostname) {
                hostnames.push(hostname.to_string());
            }
        }
    }
    hostnames
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme::IssuanceFailureCode;
    use chrono::{DateTime, Utc};

    #[test]
    fn csr_base64_error_response_is_a_fixed_code_without_detail() {
        // The legacy response carried the base64 decode error string in a
        // `detail` field; pin the bounded shape (#122).
        let err = base64::engine::general_purpose::STANDARD
            .decode("not!base64")
            .expect_err("invalid base64 must fail");
        let (status, Json(body)) = csr_base64_invalid_response(&err);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, json!({"error": "csr_base64_invalid"}));
        assert!(!serde_json::to_string(&body).unwrap().contains("detail"));
    }

    #[test]
    fn certificate_hostnames_are_limited_to_attested_descriptor_domains() {
        let descriptor = json!({
            "app_domain": "app.enclava.dev",
            "tee_domain": "app.tee.enclava.dev",
            "custom_domains": ["custom.example.test"]
        });

        assert!(validate_requested_hostnames(&descriptor, &["app.enclava.dev".into()]).is_ok());
        assert!(validate_requested_hostnames(&descriptor, &["custom.example.test".into()]).is_ok());
        assert_eq!(
            validate_requested_hostnames(&descriptor, &["other.example.test".into()]).unwrap_err(),
            "hostname_not_attested"
        );
    }

    #[test]
    fn broker_accepts_declared_cc_init_data_hash_when_kbs_token_omits_it() {
        let body = CertificateRequest {
            hostnames: vec!["app.enclava.dev".into()],
            csr_der_base64: "AA==".into(),
            cc_init_data_hash: Some("ab".repeat(32)),
        };

        assert_eq!(
            attested_or_declared_init_data_hash(&json!({}), &body),
            Some(vec![0xab; 32])
        );
    }

    #[test]
    fn issuance_failure_response_contract_is_bounded_and_terminal() {
        let deadline = DateTime::parse_from_rfc3339("2026-09-10T09:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let cases = [
            (
                IssuanceFailure {
                    code: IssuanceFailureCode::RateLimited,
                    retry_after: Some(deadline),
                },
                json!({
                    "error": "acme_rate_limited",
                    "terminal": true,
                    "retry_after": "2026-09-10T09:30:00Z",
                }),
            ),
            (
                IssuanceFailure {
                    code: IssuanceFailureCode::Failed,
                    retry_after: None,
                },
                // Generic failures keep the exact error value clients already
                // recognize; the leaking detail field is gone.
                json!({
                    "error": "acme_certificate_issuance_failed",
                    "terminal": true,
                    "retry_after": null,
                }),
            ),
        ];
        for (failure, expected) in cases {
            let (status, Json(body)) = issuance_failure_response(&failure);
            assert_eq!(status, StatusCode::BAD_GATEWAY);
            assert_eq!(body, expected);
            let serialized = serde_json::to_string(&body).unwrap();
            assert!(!serialized.contains("detail"));
        }
    }

    #[test]
    fn provider_secrets_never_reach_the_issuance_failure_response() {
        let secret = "SYNTHETIC-PROVIDER-SECRET-7f3a91c2";
        let problem = instant_acme::Problem {
            r#type: Some("urn:ietf:params:acme:error:rateLimited".into()),
            detail: Some(format!("quota window exceeded for {secret}")),
            status: Some(429),
            subproblems: Vec::new(),
        };
        let error = crate::acme::AcmeError::Acme(instant_acme::Error::Api(problem));
        // The legacy response leaked exactly this provider text.
        assert!(error.to_string().contains(secret));

        let failures = crate::acme::FailureHeaders::default();
        let mut headers = HeaderMap::new();
        headers.insert(
            "Retry-After",
            "120"
                .parse::<axum::http::HeaderValue>()
                .expect("header value"),
        );
        failures.observe_response(StatusCode::TOO_MANY_REQUESTS, &headers, Utc::now());

        let failure = IssuanceFailure::diagnose(&error, &failures);
        let (status, Json(body)) = issuance_failure_response(&failure);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "acme_rate_limited");
        assert_eq!(body["terminal"], true);
        assert!(body["retry_after"].is_string());
        let serialized = serde_json::to_string(&body).unwrap();
        assert!(!serialized.contains(secret));
    }
}
