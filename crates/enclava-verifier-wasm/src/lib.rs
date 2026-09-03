use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct ContextInput {
    challenge_nonce: String,
    expected_target_origin: String,
    now_unix_seconds: u64,
    observed_channel_spki_sha256: Option<String>,
}

#[derive(Deserialize)]
struct ExpectedReceiptInput {
    policy_sha256: String,
    challenge_nonce: String,
    target_origin: String,
}

#[wasm_bindgen]
pub fn verify_bundle(bundle: &[u8], policy: &[u8], context_json: &str) -> Result<String, JsError> {
    Ok(serde_json::to_string(&verify_input(
        bundle,
        policy,
        context_json,
    )?)?)
}

#[wasm_bindgen]
pub fn verify_bundle_sha256(
    bundle: &[u8],
    policy: &[u8],
    context_json: &str,
) -> Result<String, JsError> {
    Ok(hex::encode(enclava_verifier::canonical_result_sha256(
        &verify_input(bundle, policy, context_json)?,
    )))
}

#[wasm_bindgen]
pub fn verify_appraisal_response_pinned(
    response: &[u8],
    appraiser_policy_json: &str,
    now_unix_seconds: u64,
    expected_json: &str,
) -> Result<String, JsError> {
    verify_appraisal_input(
        response,
        appraiser_policy_json,
        now_unix_seconds,
        expected_json,
    )
    .map_err(|error| JsError::new(&error))
}

fn verify_appraisal_input(
    response: &[u8],
    appraiser_policy_json: &str,
    now_unix_seconds: u64,
    expected_json: &str,
) -> Result<String, String> {
    let policy = serde_json::from_str(appraiser_policy_json).map_err(|error| error.to_string())?;
    let expected: ExpectedReceiptInput =
        serde_json::from_str(expected_json).map_err(|error| error.to_string())?;
    let verified = enclava_verifier::verify_appraisal_response_pinned(
        response,
        &policy,
        now_unix_seconds,
        &enclava_verifier::ExpectedReceipt {
            policy_sha256: &expected.policy_sha256,
            challenge_nonce: &expected.challenge_nonce,
            target_origin: &expected.target_origin,
        },
    )
    .map_err(|error| error.to_string())?;
    serde_json::to_string(&verified).map_err(|error| error.to_string())
}

fn verify_input(
    bundle: &[u8],
    policy: &[u8],
    context_json: &str,
) -> Result<enclava_verifier::AppraisalResult, JsError> {
    let context: ContextInput = serde_json::from_str(context_json)?;
    let challenge_nonce = decode_32(&context.challenge_nonce, "challenge_nonce")
        .map_err(|error| JsError::new(&error))?;
    let observed_channel_spki_sha256 = context
        .observed_channel_spki_sha256
        .as_deref()
        .map(|value| decode_32(value, "observed_channel_spki_sha256"))
        .transpose()
        .map_err(|error| JsError::new(&error))?;
    Ok(enclava_verifier::verify(
        bundle,
        policy,
        enclava_verifier::VerificationContext {
            challenge_nonce,
            expected_target_origin: context.expected_target_origin,
            now_unix_seconds: context.now_unix_seconds,
            observed_channel_spki_sha256,
        },
    ))
}

fn decode_32(value: &str, name: &str) -> Result<[u8; 32], String> {
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .filter(|_| value.bytes().all(|byte| !byte.is_ascii_uppercase()))
        .ok_or_else(|| format!("{name} must be 32-byte lowercase hex"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_context_before_verification() {
        assert!(decode_32("00", "challenge_nonce").is_err());
        assert!(decode_32(&"AA".repeat(32), "challenge_nonce").is_err());
    }

    #[test]
    fn appraisal_export_requires_every_relying_party_binding() {
        let error = verify_appraisal_input(
            b"{}",
            "{}",
            0,
            r#"{"policy_sha256":"00","challenge_nonce":"11"}"#,
        )
        .unwrap_err();
        assert!(error.contains("target_origin"));
    }
}
