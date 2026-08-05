//! Deterministic, I/O-free verification primitives shared by native and WASM adapters.

mod amd;
mod artifacts;
mod bundle;
mod evidence;
mod policy;
mod receipt;
mod result;
mod sigstore;
mod snp;
mod supply_chain;

#[cfg(feature = "fuzzing")]
pub use amd::verify_rsa_pss_sha384_for_fuzzing;
pub use amd::{
    AmdVerificationError, verify_amd_certificate_chain, verify_amd_revocation,
    verify_snp_signature, verify_vcek_report_binding,
};
pub use artifacts::{ArtifactError, VerifiedArtifacts, verify_workload_artifacts};
pub use bundle::{
    BundleError, MAX_PROOF_BUNDLE_BYTES, PROOF_BUNDLE_MEDIA_TYPE, ProofBundle, parse_proof_bundle,
};
pub use evidence::{
    AmdEndorsements, EvidenceError, expected_report_data, parse_amd_endorsements,
    report_data_matches, tls_leaf_spki_sha256,
};
pub use policy::{AppraiserKeyPolicy, AppraiserPolicy, SigstorePolicy, TrustPolicy};
pub use receipt::{
    AppraisalResponse, ReceiptError, SignedReceipt, appraisal_receipt_bytes,
    verify_appraisal_response,
};
pub use result::{
    AppraisalResult, CheckOutcome, CheckResult, Verdict, canonical_result_bytes,
    canonical_result_sha256,
};
use sha2::{Digest, Sha256};
pub use sigstore::{SigstoreError, verify_sigstore_and_provenance};
pub use snp::{SNP_REPORT_BYTES, SnpReport, SnpReportError, parse_snp_report};
pub use supply_chain::{SupplyChainError, verify_portable_material};

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

    if let Some(bundle) = bundle.as_ref() {
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

    let policy = if policy_bytes.is_empty() {
        warnings.push("NO_POLICY_SUPPLIED".into());
        None
    } else if let Some(policy) = policy::TrustPolicy::parse(policy_bytes) {
        checks.push(CheckResult {
            id: "policy.structure".into(),
            outcome: CheckOutcome::Pass,
            observed: Some("enclava-trust-policy-v1".into()),
            expected: Some("enclava-trust-policy-v1".into()),
            reason_code: "OK".into(),
        });
        Some(policy)
    } else {
        checks.push(CheckResult {
            id: "policy.structure".into(),
            outcome: CheckOutcome::Fail,
            observed: None,
            expected: Some("enclava-trust-policy-v1".into()),
            reason_code: "MALFORMED_POLICY".into(),
        });
        None
    };

    if let (Some(bundle), Some(policy)) = (bundle.as_ref(), policy.as_ref()) {
        verify_evidence(bundle, policy, &context, &mut checks, &mut warnings);
        for required in &policy.required_checks {
            if !checks.iter().any(|check| &check.id == required) {
                checks.push(CheckResult {
                    id: required.clone(),
                    outcome: CheckOutcome::Fail,
                    observed: None,
                    expected: Some("supported verifier check".into()),
                    reason_code: "UNSUPPORTED_REQUIRED_CHECK".into(),
                });
            }
        }
    }

    let verdict = if checks
        .iter()
        .any(|check| check.outcome == CheckOutcome::Fail)
    {
        Verdict::Fail
    } else if let Some(policy) = policy.as_ref()
        && policy.required_checks.iter().all(|required| {
            checks
                .iter()
                .any(|check| &check.id == required && check.outcome == CheckOutcome::Pass)
        })
        && (!policy.transport.require_tls_channel_spki
            || checks.iter().any(|check| {
                check.id == "transport.tls_channel_spki" && check.outcome == CheckOutcome::Pass
            }))
    {
        Verdict::Pass
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

fn verify_evidence(
    bundle: &ProofBundle<'_>,
    policy: &policy::TrustPolicy,
    context: &VerificationContext,
    checks: &mut Vec<CheckResult>,
    warnings: &mut Vec<String>,
) {
    let report = parse_snp_report(bundle.snp_report);
    checks.push(simple_check(
        "amd.report_structure",
        report.is_ok(),
        "INVALID_SNP_REPORT",
    ));
    let endorsements = parse_amd_endorsements(bundle.amd_endorsements);
    checks.push(simple_check(
        "amd.endorsements_structure",
        endorsements.is_ok(),
        "INVALID_AMD_ENDORSEMENTS",
    ));
    let leaf_spki = tls_leaf_spki_sha256(bundle.tls_leaf_der);
    checks.push(simple_check(
        "binding.tls_leaf_certificate",
        leaf_spki.is_ok(),
        "INVALID_TLS_LEAF_CERTIFICATE",
    ));

    if let (Ok(report), Ok(endorsements)) = (&report, &endorsements) {
        let chain_valid = policy.amd.trusted_ark_sha256.iter().any(|trusted| {
            policy::decode_32(trusted).is_some_and(|trusted| {
                verify_amd_certificate_chain(
                    endorsements.ark_der,
                    endorsements.ask_der,
                    endorsements.vcek_der,
                    &trusted,
                )
                .is_ok()
            })
        });
        checks.push(simple_check(
            "amd.certificate_chain",
            chain_valid,
            "AMD_CHAIN_INVALID_OR_UNTRUSTED",
        ));
        checks.push(simple_check(
            "amd.report_signature",
            verify_snp_signature(report, endorsements.vcek_der).is_ok(),
            "SNP_REPORT_SIGNATURE_INVALID",
        ));
        checks.push(simple_check(
            "amd.vcek_binding",
            verify_vcek_report_binding(report, endorsements.vcek_der).is_ok(),
            "VCEK_REPORT_BINDING_INVALID",
        ));
        let revocation = verify_amd_revocation(
            endorsements.ark_der,
            endorsements.ask_der,
            endorsements.vcek_der,
            endorsements.crl_der,
            context.now_unix_seconds,
            policy.amd.revocation_max_age_seconds,
        );
        checks.push(simple_check(
            "amd.revocation.freshness",
            revocation.is_ok(),
            match revocation {
                Err(AmdVerificationError::RevocationDataExpired) => "REVOCATION_DATA_EXPIRED",
                Err(AmdVerificationError::RevocationDataStale) => "REVOCATION_DATA_STALE",
                Err(AmdVerificationError::RevocationTimeMissing) => "REVOCATION_TIME_MISSING",
                Err(AmdVerificationError::AskRevoked) => "ASK_REVOKED",
                Err(AmdVerificationError::VcekRevoked) => "VCEK_REVOKED",
                _ => "AMD_REVOCATION_INVALID",
            },
        ));
        checks.push(simple_check(
            "amd.measurement",
            policy.amd.allowed_measurements.iter().any(|measurement| {
                policy::decode_48(measurement).as_ref() == Some(&report.measurement)
            }),
            "SNP_MEASUREMENT_REJECTED",
        ));
        checks.push(simple_check(
            "amd.tcb",
            policy::tcb_meets(report.reported_tcb, &policy.amd.minimum_tcb),
            "SNP_TCB_BELOW_MINIMUM",
        ));
        checks.push(simple_check(
            "amd.guest_policy",
            report.guest_policy & policy.amd.guest_policy_mask == policy.amd.guest_policy_value,
            "SNP_POLICY_REJECTED",
        ));
        if let Ok(leaf_spki) = leaf_spki {
            checks.push(simple_check(
                "binding.report_data",
                report_data_matches(
                    report,
                    bundle.target_origin,
                    &bundle.challenge_nonce,
                    &leaf_spki,
                    bundle.proxy_receipt_public_key,
                ),
                "REPORT_DATA_MISMATCH",
            ));
            match context.observed_channel_spki_sha256 {
                Some(observed) => checks.push(equality_check(
                    "transport.tls_channel_spki",
                    observed == leaf_spki,
                    hex::encode(observed),
                    hex::encode(leaf_spki),
                    "CHANNEL_SPKI_MISMATCH",
                )),
                None => {
                    checks.push(CheckResult {
                        id: "transport.tls_channel_spki".into(),
                        outcome: CheckOutcome::Skipped,
                        observed: None,
                        expected: Some(hex::encode(leaf_spki)),
                        reason_code: "CHANNEL_SPKI_UNAVAILABLE".into(),
                    });
                    warnings.push("LIVE_TLS_CHANNEL_BINDING_NOT_CHECKED".into());
                }
            }
        }
    }

    checks.push(simple_check(
        "policy.target_origin",
        policy
            .target
            .origins
            .iter()
            .any(|origin| origin == bundle.target_origin),
        "TARGET_ORIGIN_REJECTED",
    ));
    let artifacts = report
        .as_ref()
        .map_err(|_| ArtifactError::RelationshipMismatch)
        .and_then(|report| {
            verify_workload_artifacts(
                bundle.workload_artifacts_json,
                bundle.trustee_policy_json,
                bundle.cc_init_data_toml,
                &report.host_data,
                &policy.trusted_org_keyring_sha256,
                &policy.trusted_policy_signing_pubkeys,
            )
        });
    match artifacts {
        Ok(artifacts) => {
            checks.push(simple_check(
                "artifacts.signatures",
                true,
                "ARTIFACT_SIGNATURE_INVALID",
            ));
            checks.push(simple_check(
                "artifacts.relationships",
                true,
                "ARTIFACT_RELATIONSHIP_INVALID",
            ));
            checks.push(simple_check(
                "artifacts.descriptor_measurement",
                report.as_ref().is_ok_and(|report| {
                    artifacts
                        .descriptor
                        .expected_firmware_measurement
                        .matches_report(&report.measurement)
                }),
                "DESCRIPTOR_MEASUREMENT_MISMATCH",
            ));
            checks.push(simple_check(
                "supply_chain.image_policy",
                policy
                    .target
                    .image_digests
                    .iter()
                    .any(|digest| digest == &artifacts.descriptor.image_digest),
                "IMAGE_DIGEST_REJECTED",
            ));
            let descriptor = &artifacts.descriptor;
            checks.push(simple_check(
                "platform.runtime_class",
                policy
                    .target
                    .runtime_classes
                    .iter()
                    .any(|value| value == &descriptor.expected_runtime_class),
                "RUNTIME_CLASS_REJECTED",
            ));
            checks.push(simple_check(
                "platform.sidecars",
                policy
                    .target
                    .attestation_proxy_digests
                    .iter()
                    .any(|value| value == &descriptor.sidecars.attestation_proxy_digest)
                    && policy
                        .target
                        .caddy_digests
                        .iter()
                        .any(|value| value == &descriptor.sidecars.caddy_digest),
                "SIDECAR_DIGEST_REJECTED",
            ));
            checks.push(simple_check(
                "platform.release",
                policy
                    .target
                    .platform_release_versions
                    .iter()
                    .any(|value| value == &descriptor.platform_release_version),
                "PLATFORM_RELEASE_REJECTED",
            ));
            checks.push(simple_check(
                "deployment.identity",
                policy
                    .target
                    .organization_ids
                    .iter()
                    .any(|value| value == &descriptor.org_id.to_string())
                    && policy
                        .target
                        .application_ids
                        .iter()
                        .any(|value| value == &descriptor.app_id.to_string()),
                "DEPLOYMENT_IDENTITY_REJECTED",
            ));
            checks.push(simple_check(
                "supply_chain.portable_integrity",
                verify_portable_material(
                    bundle.sigstore_material,
                    bundle.provenance_oci_material,
                    &artifacts.descriptor.image_digest,
                )
                .is_ok(),
                "PORTABLE_SUPPLY_CHAIN_MATERIAL_INVALID",
            ));
            checks.push(simple_check(
                "supply_chain.signatures",
                verify_sigstore_and_provenance(
                    bundle.sigstore_material,
                    bundle.provenance_oci_material,
                    &artifacts.descriptor.image_digest,
                    &policy.sigstore,
                )
                .is_ok(),
                "SUPPLY_CHAIN_SIGNATURE_INVALID",
            ));
        }
        Err(error) => {
            warnings.push(error.to_string());
            checks.extend(artifact_failure_checks(&error));
        }
    }
}

fn artifact_failure_checks(error: &ArtifactError) -> [CheckResult; 2] {
    let (signature_outcome, signature_reason, relationship_outcome, relationship_reason) =
        match error {
            ArtifactError::RelationshipMismatch => (
                CheckOutcome::Skipped,
                "ARTIFACT_SIGNATURE_NOT_CHECKED",
                CheckOutcome::Fail,
                "ARTIFACT_RELATIONSHIP_INVALID",
            ),
            ArtifactError::Malformed => (
                CheckOutcome::Fail,
                "MALFORMED_WORKLOAD_ARTIFACTS",
                CheckOutcome::Skipped,
                "ARTIFACT_RELATIONSHIP_NOT_CHECKED",
            ),
            ArtifactError::InvalidCustomerSignature => (
                CheckOutcome::Fail,
                "CUSTOMER_SIGNATURE_INVALID",
                CheckOutcome::Skipped,
                "ARTIFACT_RELATIONSHIP_NOT_CHECKED",
            ),
            ArtifactError::UntrustedCustomerAuthority => (
                CheckOutcome::Fail,
                "CUSTOMER_AUTHORITY_UNTRUSTED",
                CheckOutcome::Skipped,
                "ARTIFACT_RELATIONSHIP_NOT_CHECKED",
            ),
            ArtifactError::InvalidPolicySignature => (
                CheckOutcome::Fail,
                "POLICY_ARTIFACT_SIGNATURE_INVALID",
                CheckOutcome::Skipped,
                "ARTIFACT_RELATIONSHIP_NOT_CHECKED",
            ),
            ArtifactError::UntrustedPolicySigner => (
                CheckOutcome::Fail,
                "POLICY_SIGNER_UNTRUSTED",
                CheckOutcome::Skipped,
                "ARTIFACT_RELATIONSHIP_NOT_CHECKED",
            ),
        };
    [
        CheckResult {
            id: "artifacts.signatures".into(),
            outcome: signature_outcome,
            observed: None,
            expected: None,
            reason_code: signature_reason.into(),
        },
        CheckResult {
            id: "artifacts.relationships".into(),
            outcome: relationship_outcome,
            observed: None,
            expected: None,
            reason_code: relationship_reason.into(),
        },
    ]
}

fn simple_check(id: &str, passes: bool, reason: &str) -> CheckResult {
    CheckResult {
        id: id.into(),
        outcome: if passes {
            CheckOutcome::Pass
        } else {
            CheckOutcome::Fail
        },
        observed: None,
        expected: None,
        reason_code: if passes { "OK" } else { reason }.into(),
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
    fn incomplete_policy_fails_closed() {
        assert_eq!(
            verify(
                &bundle(&[7; 32]),
                br#"{"schema_version":"enclava-trust-policy-v1"}"#,
                context([7; 32]),
            )
            .verdict,
            Verdict::Fail
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

    #[test]
    fn malformed_fixture_has_stable_cross_runtime_hash() {
        let result = verify(
            &[],
            &[],
            VerificationContext {
                challenge_nonce: [0; 32],
                expected_target_origin: "https://fixture.example".into(),
                now_unix_seconds: 1_700_000_000,
                observed_channel_spki_sha256: None,
            },
        );
        assert_eq!(
            hex::encode(canonical_result_sha256(&result)),
            "540e8973f6c70712f986c9bba3ece9e05b92f4765551020618ae08584b1d88f3"
        );
    }

    #[test]
    fn artifact_failures_identify_the_failed_check() {
        let relationship = artifact_failure_checks(&ArtifactError::RelationshipMismatch);
        assert_eq!(relationship[0].outcome, CheckOutcome::Skipped);
        assert_eq!(relationship[1].outcome, CheckOutcome::Fail);
        assert_eq!(relationship[1].reason_code, "ARTIFACT_RELATIONSHIP_INVALID");

        let signature = artifact_failure_checks(&ArtifactError::InvalidPolicySignature);
        assert_eq!(signature[0].outcome, CheckOutcome::Fail);
        assert_eq!(
            signature[0].reason_code,
            "POLICY_ARTIFACT_SIGNATURE_INVALID"
        );
        assert_eq!(signature[1].outcome, CheckOutcome::Skipped);
    }
}
