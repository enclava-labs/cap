use base64::Engine as _;
use enclava_common::canonical::ce_v1_decode;
use enclava_verifier::{
    CheckOutcome, TrustPolicy, Verdict, VerificationContext, canonical_result_sha256,
    parse_proof_bundle, verify,
};

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

fn rejected_measurement_policy() -> Vec<u8> {
    let (_, policy) = fixture();
    let parsed: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    let measurement = parsed["amd"]["allowed_measurements"][0].as_str().unwrap();
    String::from_utf8(policy)
        .unwrap()
        .replacen(measurement, &"00".repeat(48), 1)
        .into_bytes()
}

fn deployment_pinned_policy(deployment_ids: serde_json::Value) -> Vec<u8> {
    let (_, policy) = fixture();
    let mut policy: serde_json::Value = serde_json::from_slice(&policy).unwrap();
    policy["target"]["deployment_ids"] = deployment_ids;
    serde_json::to_vec(&policy).unwrap()
}

fn observed_deploy_id(bundle: &[u8]) -> String {
    let proof = parse_proof_bundle(bundle).unwrap();
    let artifacts: serde_json::Value =
        serde_json::from_slice(proof.workload_artifacts_json).unwrap();
    artifacts["descriptor_payload"]["deploy_id"]
        .as_str()
        .expect("fixture descriptor carries deploy_id")
        .into()
}

fn deployment_identity_check(
    result: &enclava_verifier::AppraisalResult,
) -> &enclava_verifier::CheckResult {
    result
        .checks
        .iter()
        .find(|check| check.id == "deployment.identity")
        .expect("deployment.identity check is always emitted for verified artifacts")
}

#[test]
fn pinned_deployment_id_admits_only_the_exact_retained_deployment() {
    let (bundle, _) = fixture();
    let deploy_id = observed_deploy_id(&bundle);

    let pinned = deployment_pinned_policy(serde_json::json!([deploy_id.clone()]));
    let parsed = TrustPolicy::parse(&pinned).expect("policy with deployment_ids parses");
    assert_eq!(parsed.target.deployment_ids, Some(vec![deploy_id.clone()]));
    let result = verify(&bundle, &pinned, context());
    assert_eq!(result.verdict, Verdict::Pass, "{:#?}", result.checks);
    let identity = deployment_identity_check(&result);
    assert_eq!(identity.outcome, CheckOutcome::Pass);
    assert_eq!(identity.reason_code, "OK");

    // Same organization, application, and image digest: only the pinned
    // signed deployment differs, and the allowlist must reject it.
    let other_deployment =
        deployment_pinned_policy(serde_json::json!(["11111111-2222-4333-8444-555555555555"]));
    let parsed = TrustPolicy::parse(&other_deployment).unwrap();
    assert_eq!(
        parsed.target.deployment_ids,
        Some(vec!["11111111-2222-4333-8444-555555555555".to_string()])
    );
    let result = verify(&bundle, &other_deployment, context());
    assert_eq!(result.verdict, Verdict::Fail, "{:#?}", result.checks);
    let identity = deployment_identity_check(&result);
    assert_eq!(identity.outcome, CheckOutcome::Fail);
    assert_eq!(identity.reason_code, "DEPLOYMENT_IDENTITY_REJECTED");
}

#[test]
fn empty_or_malformed_deployment_allowlists_reject_every_deployment() {
    let (bundle, _) = fixture();
    for ids in [
        serde_json::json!([]),
        serde_json::json!([""]),
        serde_json::json!(["not-a-uuid"]),
        serde_json::json!([observed_deploy_id(&bundle).to_uppercase()]),
    ] {
        let policy = deployment_pinned_policy(ids.clone());
        let parsed = TrustPolicy::parse(&policy)
            .unwrap_or_else(|| panic!("allowlist {ids} keeps the policy parseable"));
        let expected: Vec<String> = ids
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        assert_eq!(parsed.target.deployment_ids, Some(expected));
        let result = verify(&bundle, &policy, context());
        assert_eq!(result.verdict, Verdict::Fail, "allowlist {ids} passed");
        let identity = deployment_identity_check(&result);
        assert_eq!(identity.outcome, CheckOutcome::Fail);
        assert_eq!(identity.reason_code, "DEPLOYMENT_IDENTITY_REJECTED");
    }
}

#[test]
fn explicit_null_or_non_array_deployment_ids_is_malformed_policy() {
    let (bundle, _) = fixture();
    for ids in [
        serde_json::json!(null),
        serde_json::json!("013c5158-971a-49f0-98b2-00ae125c7aa5"),
        serde_json::json!(7),
        serde_json::json!({}),
        serde_json::json!([null]),
        serde_json::json!([42]),
    ] {
        let policy = deployment_pinned_policy(ids.clone());
        assert!(
            TrustPolicy::parse(&policy).is_none(),
            "deployment_ids {ids} must not parse"
        );
        let result = verify(&bundle, &policy, context());
        assert_eq!(
            result.verdict,
            Verdict::Fail,
            "deployment_ids {ids} accepted"
        );
        assert!(
            result
                .checks
                .iter()
                .any(|check| check.id == "policy.structure"
                    && check.outcome == CheckOutcome::Fail
                    && check.reason_code == "MALFORMED_POLICY"),
            "deployment_ids {ids} must fail policy.structure with MALFORMED_POLICY"
        );
    }
}

#[test]
fn absent_deployment_allowlist_preserves_the_broad_identity_contract() {
    let (bundle, policy) = fixture();
    let parsed = TrustPolicy::parse(&policy).expect("v1 policy without deployment_ids parses");
    assert!(parsed.target.deployment_ids.is_none());
    let result = verify(&bundle, &policy, context());
    assert_eq!(result.verdict, Verdict::Pass, "{:#?}", result.checks);
    assert_eq!(
        deployment_identity_check(&result).outcome,
        CheckOutcome::Pass
    );
}

#[test]
fn independently_selected_policy_and_channel_context_fail_closed() {
    let (bundle, policy) = fixture();
    let rejected_measurement = rejected_measurement_policy();
    let rejected = verify(&bundle, &rejected_measurement, context());
    assert_eq!(rejected.verdict, Verdict::Fail);
    assert!(
        rejected
            .checks
            .iter()
            .any(|check| check.reason_code == "SNP_MEASUREMENT_REJECTED")
    );
    assert_eq!(
        hex::encode(canonical_result_sha256(&rejected)),
        "63f02a375ad811f5c520d294720f49ee14a951ae01b34bd616101db6e5fe331b"
    );

    for (field, reason, hash) in [
        (
            "snp_report",
            "SNP_REPORT_SIGNATURE_INVALID",
            "5a0027525995ca9741194fc2c3ca439bef21d7838e1176447cd66ccf26c80c2a",
        ),
        (
            "sigstore_material",
            "SUPPLY_CHAIN_SIGNATURE_INVALID",
            "ce329c730ed95af1a3bade7239958c0f4ebb790a800e72c7d0afde8dfbfb85d4",
        ),
        (
            "provenance_oci_material",
            "SUPPLY_CHAIN_SIGNATURE_INVALID",
            "66b43fa8721a02bfc17481b386d1362da9549a86c3ba1b04ec1b48d28282f9a9",
        ),
    ] {
        let result = verify(&mutate_record(bundle.clone(), field), &policy, context());
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(
            result
                .checks
                .iter()
                .any(|check| check.reason_code == reason)
        );
        assert_eq!(hex::encode(canonical_result_sha256(&result)), hash);
    }

    for policy in [
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
    // The appraiser cannot observe the live TLS channel
    // (observed_channel_spki_sha256: None), so the
    // transport.tls_channel_spki check is Skipped. A policy that demands it
    // — via the transport flag or an explicit required_checks entry — must
    // fail closed (#127), not degrade to Inconclusive.
    let skipped_required = verify(&bundle, &require_channel, context());
    assert_eq!(skipped_required.verdict, Verdict::Fail);
    assert!(
        skipped_required
            .checks
            .iter()
            .any(|check| check.id == "transport.tls_channel_spki"
                && check.outcome == CheckOutcome::Skipped
                && check.reason_code == "CHANNEL_SPKI_UNAVAILABLE")
    );
    let listed_required = {
        let mut policy: serde_json::Value = serde_json::from_slice(&require_channel).unwrap();
        policy["transport"]["require_tls_channel_spki"] = serde_json::json!(false);
        policy["required_checks"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("transport.tls_channel_spki"));
        serde_json::to_vec(&policy).unwrap()
    };
    assert_eq!(
        verify(&bundle, &listed_required, context()).verdict,
        Verdict::Fail
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
