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
    // Panic isolation (cap#141): the wasm module runs inside the relying
    // party's page — a panic must surface as a catchable JsError, not
    // abort the whole module (which would poison every later call in the
    // same JS context).
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        enclava_verifier::verify(
            bundle,
            policy,
            enclava_verifier::VerificationContext {
                challenge_nonce,
                expected_target_origin: context.expected_target_origin.clone(),
                now_unix_seconds: context.now_unix_seconds,
                observed_channel_spki_sha256,
            },
        )
    }))
    .map_err(|panic| {
        // Downcast the panic payload when possible so a hostile bundle
        // that trips a latent panic is diagnosable from the JS console
        // instead of surfacing as an opaque generic error (cap#141 review).
        let reason = panic
            .downcast_ref::<&str>()
            .map(|message| format!("verification panicked: {message}"))
            .or_else(|| {
                panic
                    .downcast_ref::<String>()
                    .map(|message| format!("verification panicked: {message}"))
            })
            .unwrap_or_else(|| "verification panicked on the supplied bundle".to_string());
        JsError::new(&reason)
    })
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
    fn mutated_bundles_never_panic_the_wasm_entry_point() {
        // Panic isolation (cap#141): push truncations and byte flips of
        // the live fixture through the same entry point the browser
        // calls. verify() must return a result (or a JsError) for every
        // input — an abort here would poison the whole JS context.
        let encoded: Vec<u8> = include_str!(
            "../../../crates/enclava-verifier/tests/fixtures/prove-it-live.bundle.b64"
        )
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
        let bundle = base64_decode_for_test(&encoded);
        let policy = include_bytes!(
            "../../../crates/enclava-verifier/tests/fixtures/prove-it-live.policy.json"
        );
        let context = serde_json::json!({
            "challenge_nonce": "01".repeat(32),
            "expected_target_origin":
                "https://prove-it-independent-dev.e72a13df.dev.enclava.work",
            "now_unix_seconds": 1_785_844_800_u64,
        })
        .to_string();
        let mut mutations: Vec<Vec<u8>> = Vec::new();
        for len in (0..bundle.len()).step_by(bundle.len() / 64 + 1) {
            mutations.push(bundle[..len].to_vec());
        }
        for offset in (0..bundle.len()).step_by(bundle.len() / 64 + 1) {
            let mut flipped = bundle.clone();
            flipped[offset] ^= 0xff;
            mutations.push(flipped);
        }
        for mutation in mutations {
            // Every mutation must produce a Result — the call itself must
            // not panic. unwrap both arms to that effect.
            let outcome = verify_input(&mutation, policy, &context);
            let _ = outcome.map(|_| ()).map_err(|_| ());
        }
    }

    fn base64_decode_for_test(encoded: &[u8]) -> Vec<u8> {
        // wasm crate has no base64 dependency; decode inline (standard
        // alphabet, padded) just for the fixture.
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut count = 0u32;
        let mut out = Vec::new();
        for &byte in encoded {
            let value = TABLE
                .iter()
                .position(|&c| c == byte)
                .expect("fixture base64 is standard alphabet") as u32;
            bits = (bits << 6) | value;
            count += 6;
            if count >= 8 {
                count -= 8;
                out.push((bits >> count) as u8);
            }
        }
        out
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
