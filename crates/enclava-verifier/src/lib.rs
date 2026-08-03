//! Deterministic, I/O-free verification primitives shared by native and WASM adapters.

mod amd;
mod bundle;
mod result;
mod snp;

pub use amd::{AmdVerificationError, verify_amd_certificate_chain, verify_snp_signature};
pub use bundle::{BundleError, PROOF_BUNDLE_MEDIA_TYPE, ProofBundle, parse_proof_bundle};
pub use result::{
    AppraisalResult, CheckOutcome, CheckResult, Verdict, canonical_result_bytes,
    canonical_result_sha256,
};
use sha2::{Digest, Sha256};
pub use snp::{SNP_REPORT_BYTES, SnpReport, SnpReportError, parse_snp_report};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationContext {
    pub challenge_nonce: [u8; 32],
    pub expected_target_origin: String,
    pub now_unix_seconds: u64,
    pub observed_channel_spki_sha256: Option<[u8; 32]>,
}

pub fn verify(
    bundle_bytes: &[u8],
    policy_bytes: &[u8],
    context: VerificationContext,
) -> AppraisalResult {
    let bundle_sha256 = hex::encode(Sha256::digest(bundle_bytes));
    let policy_sha256 = hex::encode(Sha256::digest(policy_bytes));
    let challenge_nonce = hex::encode(context.challenge_nonce);
    let mut checks = Vec::new();
    let mut warnings = Vec::new();

    let bundle = match parse_proof_bundle(bundle_bytes) {
        Ok(bundle) => {
            checks.push(CheckResult {
                id: "bundle.structure".into(),
                outcome: CheckOutcome::Pass,
                observed: Some("enclava-proof-bundle-v1".into()),
                expected: Some("enclava-proof-bundle-v1".into()),
                reason_code: "OK".into(),
            });
            Some(bundle)
        }
        Err(error) => {
            checks.push(CheckResult {
                id: "bundle.structure".into(),
                outcome: CheckOutcome::Fail,
                observed: None,
                expected: Some("enclava-proof-bundle-v1".into()),
                reason_code: "MALFORMED_BUNDLE".into(),
            });
            warnings.push(error.to_string());
            None
        }
    };

    if let Some(bundle) = bundle {
        checks.push(equality_check(
            "binding.challenge_nonce",
            bundle.challenge_nonce == context.challenge_nonce,
            hex::encode(bundle.challenge_nonce),
            challenge_nonce.clone(),
            "NONCE_MISMATCH",
        ));
        checks.push(equality_check(
            "binding.target_origin",
            bundle.target_origin == context.expected_target_origin,
            bundle.target_origin.into(),
            context.expected_target_origin.clone(),
            "TARGET_ORIGIN_MISMATCH",
        ));
    }

    if policy_bytes.is_empty() {
        warnings.push("NO_POLICY_SUPPLIED".into());
    } else if serde_json::from_slice::<serde_json::Value>(policy_bytes)
        .ok()
        .and_then(|policy| {
            policy
                .get("schema_version")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
        .as_deref()
        != Some("enclava-trust-policy-v1")
    {
        checks.push(CheckResult {
            id: "policy.structure".into(),
            outcome: CheckOutcome::Fail,
            observed: None,
            expected: Some("enclava-trust-policy-v1".into()),
            reason_code: "MALFORMED_POLICY".into(),
        });
    } else {
        checks.push(CheckResult {
            id: "policy.structure".into(),
            outcome: CheckOutcome::Pass,
            observed: Some("enclava-trust-policy-v1".into()),
            expected: Some("enclava-trust-policy-v1".into()),
            reason_code: "OK".into(),
        });
        warnings.push("CRYPTOGRAPHIC_CHECKS_NOT_IMPLEMENTED".into());
    }

    let verdict = if checks
        .iter()
        .any(|check| check.outcome == CheckOutcome::Fail)
    {
        Verdict::Fail
    } else {
        Verdict::Inconclusive
    };
    AppraisalResult {
        verdict,
        bundle_sha256,
        policy_sha256,
        target_origin: context.expected_target_origin,
        challenge_nonce,
        verified_at: context.now_unix_seconds,
        verifier_version: env!("CARGO_PKG_VERSION").into(),
        checks,
        warnings,
    }
}

fn equality_check(
    id: &str,
    matches: bool,
    observed: String,
    expected: String,
    mismatch_reason: &str,
) -> CheckResult {
    CheckResult {
        id: id.into(),
        outcome: if matches {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        },
        observed: Some(observed),
        expected: Some(expected),
        reason_code: if matches { "OK" } else { mismatch_reason }.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclava_common::canonical::ce_v1_bytes;

    fn bundle(nonce: &[u8; 32]) -> Vec<u8> {
        ce_v1_bytes(&[
            ("purpose", b"enclava-proof-bundle"),
            ("schema_version", b"1"),
            ("target_origin", b"https://app.example"),
            ("challenge_nonce", nonce),
            ("created_at_unix_seconds", b"1770000000"),
            ("snp_report", b"report"),
            ("tls_leaf_der", b"certificate"),
            ("proxy_receipt_public_key", b"public-key"),
            ("amd_endorsements", b"endorsements"),
            ("cc_init_data_toml", b"cc-init"),
            ("workload_artifacts_json", b"artifacts"),
            ("trustee_policy_json", b"trustee-policy"),
            ("sigstore_material", b"sigstore"),
            ("provenance_oci_material", b"provenance"),
        ])
    }

    fn context(nonce: [u8; 32]) -> VerificationContext {
        VerificationContext {
            challenge_nonce: nonce,
            expected_target_origin: "https://app.example".into(),
            now_unix_seconds: 1_770_000_001,
            observed_channel_spki_sha256: None,
        }
    }

    #[test]
    fn never_passes_without_completed_security_checks() {
        assert_eq!(
            verify(
                &bundle(&[7; 32]),
                br#"{"schema_version":"enclava-trust-policy-v1"}"#,
                context([7; 32]),
            )
            .verdict,
            Verdict::Inconclusive
        );
    }

    #[test]
    fn nonce_mismatch_fails_closed() {
        let result = verify(&bundle(&[7; 32]), b"", context([8; 32]));
        assert_eq!(result.verdict, Verdict::Fail);
        assert!(result.checks.iter().any(|check| {
            check.id == "binding.challenge_nonce" && check.reason_code == "NONCE_MISMATCH"
        }));
    }
}
