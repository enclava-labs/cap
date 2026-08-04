use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
struct ContextInput {
    challenge_nonce: String,
    expected_target_origin: String,
    now_unix_seconds: u64,
    observed_channel_spki_sha256: Option<String>,
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
}
