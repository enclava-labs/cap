use base64::Engine as _;
use enclava_common::canonical::ce_v1_decode;
use enclava_verifier::{CheckOutcome, Verdict, VerificationContext, verify};

fn fixture() -> (Vec<u8>, Vec<u8>) {
    let encoded = include_str!("fixtures/prove-it-live.bundle.b64")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let bundle = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let policy = include_bytes!("fixtures/prove-it-live.policy.json").to_vec();
    (bundle, policy)
}

fn context() -> VerificationContext {
    VerificationContext {
        challenge_nonce: [1; 32],
        expected_target_origin: "https://prove-it-independent-dev.e72a13df.dev.enclava.work".into(),
        now_unix_seconds: 1_785_844_800,
        observed_channel_spki_sha256: None,
    }
}

#[test]
fn live_portable_fixture_passes_offline() {
    let (bundle, policy) = fixture();
    let result = verify(&bundle, &policy, context());
    assert_eq!(result.verdict, Verdict::Pass, "{:#?}", result.checks);
    assert!(
        result
            .checks
            .iter()
            .any(|check| { check.id == "amd.vcek_binding" && check.outcome == CheckOutcome::Pass })
    );
    assert!(result.checks.iter().any(|check| {
        check.id == "transport.tls_channel_spki" && check.outcome == CheckOutcome::Skipped
    }));
}

fn mutate_record(mut bundle: Vec<u8>, label: &str) -> Vec<u8> {
    let base = bundle.as_ptr() as usize;
    let offset = ce_v1_decode(&bundle)
        .unwrap()
        .into_iter()
        .find(|record| record.label == label)
        .unwrap()
        .value
        .as_ptr() as usize
        - base;
    bundle[offset] ^= 1;
    bundle
}

fn mutate_record_last(mut bundle: Vec<u8>, label: &str) -> Vec<u8> {
    let base = bundle.as_ptr() as usize;
    let record = ce_v1_decode(&bundle)
        .unwrap()
        .into_iter()
        .find(|record| record.label == label)
        .unwrap();
    let offset = record.value.as_ptr() as usize - base + record.value.len() - 1;
    bundle[offset] ^= 1;
    bundle
}

#[test]
fn every_security_critical_bundle_field_fails_after_one_byte_mutation() {
    let (bundle, policy) = fixture();
    for field in [
        "target_origin",
        "challenge_nonce",
        "snp_report",
        "tls_leaf_der",
        "proxy_receipt_public_key",
        "amd_endorsements",
        "cc_init_data_toml",
        "workload_artifacts_json",
        "trustee_policy_json",
        "sigstore_material",
        "provenance_oci_material",
    ] {
        let result = verify(&mutate_record(bundle.clone(), field), &policy, context());
        assert_eq!(result.verdict, Verdict::Fail, "mutation of {field} passed");
    }

    let diagnostic_only = mutate_record_last(bundle, "created_at_unix_seconds");
    assert_eq!(
        verify(&diagnostic_only, &policy, context()).verdict,
        Verdict::Pass
    );
}

fn rejected_policy(field: &str, value: serde_json::Value) -> Vec<u8> {
    let (_, policy) = fixture();
    let mut policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    policy
        .pointer_mut(field)
        .map(|field| *field = value)
        .unwrap();
    serde_json::to_vec(&policy).unwrap()
}

#[test]
fn independently_selected_policy_and_channel_context_fail_closed() {
    let (bundle, _) = fixture();
    for policy in [
        rejected_policy(
            "/amd/allowed_measurements",
            serde_json::json!(["00".repeat(48)]),
        ),
        rejected_policy(
            "/target/image_digests",
            serde_json::json!([format!("sha256:{}", "00".repeat(32))]),
        ),
        rejected_policy(
            "/target/origins",
            serde_json::json!(["https://attacker.example"]),
        ),
    ] {
        assert_eq!(verify(&bundle, &policy, context()).verdict, Verdict::Fail);
    }

    assert_eq!(
        verify(&bundle, &[], context()).verdict,
        Verdict::Inconclusive
    );
    let mut require_channel = rejected_policy(
        "/transport/require_tls_channel_spki",
        serde_json::json!(true),
    );
    assert_eq!(
        verify(&bundle, &require_channel, context()).verdict,
        Verdict::Inconclusive
    );
    let mut mismatched_channel = context();
    mismatched_channel.observed_channel_spki_sha256 = Some([0; 32]);
    require_channel = rejected_policy(
        "/transport/require_tls_channel_spki",
        serde_json::json!(false),
    );
    assert_eq!(
        verify(&bundle, &require_channel, mismatched_channel).verdict,
        Verdict::Fail
    );
}
