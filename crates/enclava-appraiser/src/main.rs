use std::{collections::HashMap, env, sync::Arc, time::SystemTime};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signer as _, SigningKey};
use enclava_verifier::{
    AppraisalResponse, AppraisalResult, SignedReceipt, VerificationContext,
    appraisal_receipt_bytes, canonical_result_sha256, verify,
};
use serde::Deserialize;

const REQUEST_MEDIA_TYPE: &str = "application/vnd.enclava.appraisal-request.v1+json";
const RESPONSE_MEDIA_TYPE: &str = "application/vnd.enclava.appraisal-response.v1+json";
const MAX_REQUEST_BYTES: usize = 1_600_000;

#[derive(Clone, Default)]
struct AppState {
    policies: Arc<HashMap<String, Vec<u8>>>,
    signer: Option<Arc<ReceiptSigner>>,
}

struct ReceiptSigner {
    key_id: String,
    key: SigningKey,
    lifetime_seconds: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppraisalRequest {
    bundle_base64: String,
    policy_base64: Option<String>,
    policy_id: Option<String>,
    challenge_nonce_base64url: String,
    expected_target_origin: String,
}

#[tokio::main]
async fn main() {
    let state = AppState::from_env().expect("invalid appraiser configuration");
    let bind = env::var("ENCLAVA_APPRAISER_BIND").unwrap_or_else(|_| "0.0.0.0:8080".into());
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .expect("failed to bind appraiser");
    axum::serve(listener, router(state))
        .await
        .expect("appraiser server failed");
}

fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::NO_CONTENT }))
        .route("/v1/appraise", post(appraise))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

async fn appraise(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(request): Json<AppraisalRequest>,
) -> Result<Response, ApiError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        != Some(REQUEST_MEDIA_TYPE)
    {
        return Err(ApiError::UnsupportedMediaType);
    }
    let bundle = general_purpose::STANDARD
        .decode(request.bundle_base64)
        .map_err(|_| ApiError::InvalidRequest)?;
    let nonce: [u8; 32] = general_purpose::URL_SAFE_NO_PAD
        .decode(request.challenge_nonce_base64url)
        .map_err(|_| ApiError::InvalidRequest)?
        .try_into()
        .map_err(|_| ApiError::InvalidRequest)?;
    let policy = match (request.policy_base64, request.policy_id) {
        (Some(bytes), None) => general_purpose::STANDARD
            .decode(bytes)
            .map_err(|_| ApiError::InvalidRequest)?,
        (None, Some(id)) => state
            .policies
            .get(&id)
            .cloned()
            .ok_or(ApiError::UnknownPolicy)?,
        _ => return Err(ApiError::InvalidRequest),
    };
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| ApiError::Clock)?
        .as_secs();
    let result = verify(
        &bundle,
        &policy,
        VerificationContext {
            challenge_nonce: nonce,
            expected_target_origin: request.expected_target_origin,
            now_unix_seconds: now,
            observed_channel_spki_sha256: None,
        },
    );
    let result_hash = canonical_result_sha256(&result);
    let receipt = state
        .signer
        .as_ref()
        .map(|signer| signer.sign(&result, result_hash, now));
    let body = serde_json::to_vec(&AppraisalResponse {
        result,
        result_sha256: hex::encode(result_hash),
        receipt,
    })
    .map_err(|_| ApiError::Serialization)?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, RESPONSE_MEDIA_TYPE),
            (header::CACHE_CONTROL, "no-store"),
        ],
        Body::from(body),
    )
        .into_response())
}

impl ReceiptSigner {
    fn sign(&self, result: &AppraisalResult, result_hash: [u8; 32], now: u64) -> SignedReceipt {
        let expires = now.saturating_add(self.lifetime_seconds);
        let receipt = appraisal_receipt_bytes(result, result_hash, now, expires, &self.key_id);
        SignedReceipt {
            key_id: self.key_id.clone(),
            appraised_at: now,
            expires_at: expires,
            public_key_base64: general_purpose::STANDARD
                .encode(self.key.verifying_key().as_bytes()),
            signature_base64: general_purpose::STANDARD.encode(self.key.sign(&receipt).to_bytes()),
        }
    }
}

impl AppState {
    fn from_env() -> Result<Self, String> {
        let policies = env::var("ENCLAVA_APPRAISER_POLICIES_JSON")
            .ok()
            .map(|value| serde_json::from_str::<HashMap<String, String>>(&value))
            .transpose()
            .map_err(|error| error.to_string())?
            .unwrap_or_default()
            .into_iter()
            .map(|(id, encoded)| {
                general_purpose::STANDARD
                    .decode(encoded)
                    .map(|bytes| (id, bytes))
                    .map_err(|error| error.to_string())
            })
            .collect::<Result<_, _>>()?;
        let signer = match env::var("ENCLAVA_APPRAISER_SIGNING_KEY_BASE64").ok() {
            Some(encoded) => {
                let seed: [u8; 32] = general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|error| error.to_string())?
                    .try_into()
                    .map_err(|_| "signing key must be a 32-byte Ed25519 seed".to_string())?;
                let key_id = env::var("ENCLAVA_APPRAISER_KEY_ID")
                    .map_err(|_| "ENCLAVA_APPRAISER_KEY_ID is required with a signing key")?;
                let lifetime_seconds = env::var("ENCLAVA_APPRAISER_RECEIPT_LIFETIME_SECONDS")
                    .ok()
                    .map(|value| value.parse::<u64>())
                    .transpose()
                    .map_err(|error| error.to_string())?
                    .unwrap_or(300);
                Some(Arc::new(ReceiptSigner {
                    key_id,
                    key: SigningKey::from_bytes(&seed),
                    lifetime_seconds,
                }))
            }
            None => None,
        };
        Ok(Self {
            policies: Arc::new(policies),
            signer,
        })
    }
}

enum ApiError {
    UnsupportedMediaType,
    InvalidRequest,
    UnknownPolicy,
    Clock,
    Serialization,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::UnsupportedMediaType => {
                (StatusCode::UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE")
            }
            Self::InvalidRequest => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            Self::UnknownPolicy => (StatusCode::BAD_REQUEST, "UNKNOWN_POLICY"),
            Self::Clock | Self::Serialization => {
                (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR")
            }
        };
        (status, Json(serde_json::json!({ "error": code }))).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use ed25519_dalek::{Signature, Verifier as _};
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn rejects_implicit_or_ambiguous_policy_selection() {
        let app = router(AppState::default());
        for body in [
            r#"{"bundle_base64":"","challenge_nonce_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expected_target_origin":"https://example.com"}"#,
            r#"{"bundle_base64":"","policy_base64":"","policy_id":"default","challenge_nonce_base64url":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expected_target_origin":"https://example.com"}"#,
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::post("/v1/appraise")
                        .header(header::CONTENT_TYPE, REQUEST_MEDIA_TYPE)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }
    }

    #[test]
    fn receipt_signature_covers_result_context_and_expiry() {
        let signer = ReceiptSigner {
            key_id: "test-2026".into(),
            key: SigningKey::from_bytes(&[7; 32]),
            lifetime_seconds: 300,
        };
        let result = AppraisalResult {
            verdict: enclava_verifier::Verdict::Fail,
            bundle_sha256: "11".repeat(32),
            policy_sha256: "22".repeat(32),
            target_origin: "https://example.com".into(),
            challenge_nonce: "33".repeat(32),
            verified_at: 100,
            verifier_version: "0.1.0".into(),
            checks: vec![],
            warnings: vec![],
        };
        let hash = canonical_result_sha256(&result);
        let receipt = signer.sign(&result, hash, 100);
        let signature = Signature::from_slice(
            &general_purpose::STANDARD
                .decode(receipt.signature_base64)
                .unwrap(),
        )
        .unwrap();
        signer
            .key
            .verifying_key()
            .verify(
                &appraisal_receipt_bytes(&result, hash, 100, 400, "test-2026"),
                &signature,
            )
            .unwrap();
    }
}
