//! Local Phase 7 attestation verifier plumbing.
//!
//! Uses the `sev` crate to parse raw AMD SNP attestation reports and verify
//! AMD VCEK certificate chains when evidence carries the required DER certs.

use std::collections::BTreeMap;

use enclava_common::canonical::ce_v1_hash;
use sev::parser::ByteParser;
#[cfg(test)]
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::descriptor::{DeploymentDescriptor, SignerIdentity};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSnpReport {
    pub report_data: [u8; 64],
    pub host_data: [u8; 32],
    pub firmware_measurement: [u8; 48],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationBundle {
    /// Raw SNP report bytes retained for the future AMD chain verifier.
    pub snp_report_bytes: Vec<u8>,
    pub parsed_snp_report: ParsedSnpReport,
    pub cc_init_data_toml: Vec<u8>,
    /// DER-encoded SubjectPublicKeyInfo for the TEE TLS leaf certificate.
    pub tls_pubkey_spki_der: Vec<u8>,
    /// Raw 32-byte Ed25519 receipt signing public key.
    pub receipt_pubkey_raw: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
pub struct AttestationExpectations<'a> {
    pub domain: &'a str,
    pub nonce: [u8; 32],
    pub descriptor: &'a DeploymentDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub leaf_spki_sha256: [u8; 32],
    pub receipt_pubkey_sha256: [u8; 32],
    pub amd_chain_status: AmdSnpChainStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmdSnpChainStatus {
    Valid,
    CertChainUnavailable,
}

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error(
        "AMD SNP report parsing is not wired in this crate yet; inject ParsedSnpReport from a validated parser"
    )]
    AmdSnpParsingUnavailable,
    #[error("cc_init_data is not valid utf-8: {0}")]
    CcInitDataUtf8(#[from] std::str::Utf8Error),
    #[error("cc_init_data TOML parse failed: {0}")]
    CcInitDataToml(#[from] toml::de::Error),
    #[error("cc_init_data missing claim {0}")]
    MissingClaim(&'static str),
    #[error("cc_init_data claim {claim} mismatch")]
    ClaimMismatch { claim: &'static str },
    #[error("SNP report firmware measurement mismatch")]
    FirmwareMeasurementMismatch,
    #[error("SNP report HOST_DATA does not match sha256(cc_init_data_toml)")]
    HostDataMismatch,
    #[error("descriptor expected_cc_init_data_hash does not match attested cc_init_data hash")]
    DescriptorCcInitDataHashMismatch,
    #[error("SNP report_data[0..32] TLS transcript mismatch")]
    ReportDataTranscriptMismatch,
    #[error("SNP report_data[32..64] receipt pubkey hash mismatch")]
    ReceiptPubkeyHashMismatch,
    #[error("invalid hex claim {claim}: {message}")]
    InvalidHexClaim {
        claim: &'static str,
        message: String,
    },
    #[error("SNP report parse failed: {0}")]
    SnpReportParse(String),
    #[error("AMD SNP VCEK chain verification failed: {0}")]
    AmdChain(String),
    #[error("SNP guest policy allows DEBUG; refusing to trust a debuggable TEE")]
    DebugPolicy,
}

#[derive(Debug, Clone)]
pub struct CcInitDataClaims {
    pub image_digest: String,
    pub runtime_class: String,
    pub signer_identity: SignerIdentity,
    pub namespace: String,
    pub service_account: String,
    pub identity_hash: [u8; 32],
    pub sidecar_digests: BTreeMap<String, String>,
}

pub fn parse_validated_snp_report(
    snp_report_bytes: &[u8],
) -> Result<ParsedSnpReport, AttestationError> {
    let report = sev::firmware::guest::AttestationReport::from_bytes(snp_report_bytes)
        .map_err(|err| AttestationError::SnpReportParse(err.to_string()))?;
    Ok(parsed_report_from_sev(&report))
}

pub fn validate_snp_report_with_der_chain(
    snp_report_bytes: &[u8],
    ark_der: &[u8],
    ask_der: &[u8],
    vcek_der: &[u8],
) -> Result<ParsedSnpReport, AttestationError> {
    use sev::certs::snp::{Certificate, Chain, Verifiable, ca};
    let report = sev::firmware::guest::AttestationReport::from_bytes(snp_report_bytes)
        .map_err(|err| AttestationError::SnpReportParse(err.to_string()))?;
    let ark = Certificate::from_der(ark_der)
        .map_err(|err| AttestationError::AmdChain(format!("ARK DER: {err}")))?;
    let ask = Certificate::from_der(ask_der)
        .map_err(|err| AttestationError::AmdChain(format!("ASK DER: {err}")))?;
    let vek = Certificate::from_der(vcek_der)
        .map_err(|err| AttestationError::AmdChain(format!("VCEK DER: {err}")))?;
    let chain = Chain {
        ca: ca::Chain { ark, ask },
        vek,
    };
    (&chain, &report)
        .verify()
        .map_err(|err| AttestationError::AmdChain(err.to_string()))?;
    ensure_snp_report_production_policy(&report)?;
    Ok(parsed_report_from_sev(&report))
}

/// A SNP guest launched with the DEBUG policy bit admits debugger access to
/// its memory-encryption keys: it is never a trustworthy confidential
/// workload, regardless of how valid its attestation chain is.
pub fn ensure_snp_report_production_policy(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<(), AttestationError> {
    if report.policy.debug_allowed() {
        return Err(AttestationError::DebugPolicy);
    }
    Ok(())
}

fn parsed_report_from_sev(report: &sev::firmware::guest::AttestationReport) -> ParsedSnpReport {
    ParsedSnpReport {
        report_data: report.report_data,
        host_data: report.host_data,
        firmware_measurement: report.measurement,
    }
}

/// Offline bundle verifier for local Phase 7 tests. NOT wired into any live
/// CLI path: the live attestation verification runs in `tee_client` via
/// `validate_snp_report_with_der_chain` (which does full AMD chain
/// verification and is the only trustworthy path). This test-only verifier
/// cannot reach a DER chain, so its `amd_chain_status` is always
/// `CertChainUnavailable` -- kept solely as a regression fixture for the
/// claim/transcript binding logic, and compile-gated so it can never be
/// mistaken for (or silently wired into) a production verifier.
#[cfg(test)]
pub fn verify_attestation_bundle(
    bundle: &AttestationBundle,
    expectations: &AttestationExpectations<'_>,
) -> Result<VerifiedAttestation, AttestationError> {
    let report = &bundle.parsed_snp_report;
    let amd_chain_status = if !bundle.snp_report_bytes.is_empty() {
        let parsed = parse_validated_snp_report(&bundle.snp_report_bytes)?;
        if parsed.report_data[..32] != report.report_data[..32] {
            return Err(AttestationError::ReportDataTranscriptMismatch);
        }
        if parsed.report_data[32..] != report.report_data[32..] {
            return Err(AttestationError::ReceiptPubkeyHashMismatch);
        }
        require_eq32(
            parsed.host_data,
            report.host_data,
            AttestationError::HostDataMismatch,
        )?;
        AmdSnpChainStatus::CertChainUnavailable
    } else {
        AmdSnpChainStatus::CertChainUnavailable
    };
    let descriptor = expectations.descriptor;

    if !descriptor
        .expected_firmware_measurement
        .matches_report(&report.firmware_measurement)
    {
        return Err(AttestationError::FirmwareMeasurementMismatch);
    }

    let cc_init_data_hash: [u8; 32] = Sha256::digest(&bundle.cc_init_data_toml).into();
    require_eq32(
        report.host_data,
        cc_init_data_hash,
        AttestationError::HostDataMismatch,
    )?;
    require_eq32(
        descriptor.expected_cc_init_data_hash,
        cc_init_data_hash,
        AttestationError::DescriptorCcInitDataHashMismatch,
    )?;

    let claims = parse_cc_init_data_claims(&bundle.cc_init_data_toml)?;
    verify_claims(&claims, descriptor)?;

    let leaf_spki_sha256: [u8; 32] = Sha256::digest(&bundle.tls_pubkey_spki_der).into();
    let receipt_pubkey_sha256: [u8; 32] = Sha256::digest(bundle.receipt_pubkey_raw).into();
    let transcript =
        tee_tls_transcript_hash(expectations.domain, &expectations.nonce, &leaf_spki_sha256);

    let mut expected_report_data = [0u8; 64];
    expected_report_data[..32].copy_from_slice(&transcript);
    expected_report_data[32..].copy_from_slice(&receipt_pubkey_sha256);

    if report.report_data[..32] != expected_report_data[..32] {
        return Err(AttestationError::ReportDataTranscriptMismatch);
    }
    if report.report_data[32..] != expected_report_data[32..] {
        return Err(AttestationError::ReceiptPubkeyHashMismatch);
    }

    Ok(VerifiedAttestation {
        leaf_spki_sha256,
        receipt_pubkey_sha256,
        amd_chain_status,
    })
}

pub fn tee_tls_transcript_hash(
    domain: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
) -> [u8; 32] {
    ce_v1_hash(&[
        ("purpose", b"enclava-tee-tls-v1"),
        ("domain", domain.as_bytes()),
        ("nonce", nonce),
        ("leaf_spki_sha256", leaf_spki_sha256),
    ])
}

pub fn parse_cc_init_data_claims(toml_bytes: &[u8]) -> Result<CcInitDataClaims, AttestationError> {
    let raw = std::str::from_utf8(toml_bytes)?;
    let value: toml::Value = toml::from_str(raw)?;
    let data = value
        .get("data")
        .and_then(toml::Value::as_table)
        .ok_or(AttestationError::MissingClaim("data"))?;

    let policy_data = data
        .get("policy.rego")
        .and_then(toml::Value::as_str)
        .and_then(parse_policy_data_json);
    let annotations = policy_data
        .as_ref()
        .and_then(|policy| policy.pointer("/containers/0/OCI/Annotations"));

    let image_digest = string_claim(data, "image_digest")
        .or_else(|| {
            policy_data
                .as_ref()
                .and_then(|policy| policy.pointer("/containers/0/image_name"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| annotation_claim(annotations, "io.kubernetes.cri.image-name"))
        .ok_or(AttestationError::MissingClaim("image_digest"))?;

    let runtime_class = string_claim(data, "runtime_class")
        .ok_or(AttestationError::MissingClaim("runtime_class"))?;
    let namespace = string_claim(data, "namespace")
        .or_else(|| annotation_claim(annotations, "io.kubernetes.pod.namespace"))
        .ok_or(AttestationError::MissingClaim("namespace"))?;
    let service_account = string_claim(data, "service_account")
        .or_else(|| annotation_claim(annotations, "io.kubernetes.pod.service-account.name"))
        .ok_or(AttestationError::MissingClaim("service_account"))?;
    let identity_hash = parse_identity_hash(data)?;
    let signer_identity = parse_signer_identity(data)?;
    let sidecar_digests = parse_sidecar_digests(data)?;

    Ok(CcInitDataClaims {
        image_digest,
        runtime_class,
        signer_identity,
        namespace,
        service_account,
        identity_hash,
        sidecar_digests,
    })
}

#[cfg(test)]
fn verify_claims(
    claims: &CcInitDataClaims,
    descriptor: &DeploymentDescriptor,
) -> Result<(), AttestationError> {
    if !image_digest_matches(&claims.image_digest, &descriptor.image_digest) {
        return Err(AttestationError::ClaimMismatch {
            claim: "image_digest",
        });
    }
    if claims.runtime_class != descriptor.expected_runtime_class {
        return Err(AttestationError::ClaimMismatch {
            claim: "runtime_class",
        });
    }
    if claims.signer_identity.subject != descriptor.signer_identity.subject {
        return Err(AttestationError::ClaimMismatch {
            claim: "signer_identity.subject",
        });
    }
    if claims.signer_identity.issuer != descriptor.signer_identity.issuer {
        return Err(AttestationError::ClaimMismatch {
            claim: "signer_identity.issuer",
        });
    }
    if claims.namespace != descriptor.namespace {
        return Err(AttestationError::ClaimMismatch { claim: "namespace" });
    }
    if claims.service_account != descriptor.service_account {
        return Err(AttestationError::ClaimMismatch {
            claim: "service_account",
        });
    }
    if claims.identity_hash != descriptor.identity_hash {
        return Err(AttestationError::ClaimMismatch {
            claim: "identity_hash",
        });
    }
    if claims
        .sidecar_digests
        .get("attestation_proxy")
        .ok_or(AttestationError::MissingClaim(
            "sidecar_digests.attestation_proxy",
        ))?
        != &descriptor.sidecars.attestation_proxy_digest
    {
        return Err(AttestationError::ClaimMismatch {
            claim: "sidecar_digests.attestation_proxy",
        });
    }
    let caddy_digest = claims
        .sidecar_digests
        .get("caddy_ingress")
        .or_else(|| claims.sidecar_digests.get("caddy"))
        .ok_or(AttestationError::MissingClaim("sidecar_digests.caddy"))?;
    if caddy_digest != &descriptor.sidecars.caddy_digest {
        return Err(AttestationError::ClaimMismatch {
            claim: "sidecar_digests.caddy",
        });
    }
    Ok(())
}

fn parse_policy_data_json(policy_rego: &str) -> Option<serde_json::Value> {
    let json = policy_rego
        .lines()
        .find_map(|line| line.trim().strip_prefix("policy_data := "))?;
    serde_json::from_str(json).ok()
}

fn annotation_claim(annotations: Option<&serde_json::Value>, key: &str) -> Option<String> {
    annotations?
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

fn string_claim(data: &toml::map::Map<String, toml::Value>, key: &str) -> Option<String> {
    data.get(key)
        .and_then(toml::Value::as_str)
        .map(ToOwned::to_owned)
}

fn parse_signer_identity(
    data: &toml::map::Map<String, toml::Value>,
) -> Result<SignerIdentity, AttestationError> {
    if let Some(table) = data.get("signer_identity").and_then(toml::Value::as_table) {
        let subject = string_claim(table, "subject")
            .ok_or(AttestationError::MissingClaim("signer_identity.subject"))?;
        let issuer = string_claim(table, "issuer")
            .ok_or(AttestationError::MissingClaim("signer_identity.issuer"))?;
        return Ok(SignerIdentity { subject, issuer });
    }

    let subject = string_claim(data, "signer_identity_subject")
        .or_else(|| string_claim(data, "signer_subject"))
        .ok_or(AttestationError::MissingClaim("signer_identity_subject"))?;
    let issuer = string_claim(data, "signer_identity_issuer")
        .or_else(|| string_claim(data, "signer_issuer"))
        .ok_or(AttestationError::MissingClaim("signer_identity_issuer"))?;
    Ok(SignerIdentity { subject, issuer })
}

fn parse_identity_hash(
    data: &toml::map::Map<String, toml::Value>,
) -> Result<[u8; 32], AttestationError> {
    let claim = string_claim(data, "identity_hash")
        .or_else(|| string_claim(data, "tenant_instance_identity_hash"))
        .or_else(|| {
            data.get("identity.toml")
                .and_then(toml::Value::as_str)
                .and_then(|raw| toml::from_str::<toml::Value>(raw).ok())
                .and_then(|identity| {
                    identity
                        .get("tenant_instance_identity_hash")
                        .and_then(toml::Value::as_str)
                        .map(ToOwned::to_owned)
                })
        })
        .ok_or(AttestationError::MissingClaim("identity_hash"))?;
    parse_hex32("identity_hash", &claim)
}

fn parse_sidecar_digests(
    data: &toml::map::Map<String, toml::Value>,
) -> Result<BTreeMap<String, String>, AttestationError> {
    let value = data
        .get("sidecar_digests")
        .ok_or(AttestationError::MissingClaim("sidecar_digests"))?;

    if let Some(table) = value.as_table() {
        return Ok(table
            .iter()
            .filter_map(|(key, value)| {
                value
                    .as_str()
                    .map(|digest| (key.clone(), digest.to_string()))
            })
            .collect());
    }

    let Some(raw_json) = value.as_str() else {
        return Err(AttestationError::MissingClaim("sidecar_digests"));
    };
    let parsed: serde_json::Value = serde_json::from_str(raw_json)
        .map_err(|_| AttestationError::MissingClaim("sidecar_digests"))?;
    let object = parsed
        .as_object()
        .ok_or(AttestationError::MissingClaim("sidecar_digests"))?;

    Ok(object
        .iter()
        .filter_map(|(key, value)| {
            value
                .as_str()
                .map(|digest| (key.clone(), digest.to_string()))
        })
        .collect())
}

fn parse_hex32(claim: &'static str, value: &str) -> Result<[u8; 32], AttestationError> {
    let bytes = hex::decode(value.trim()).map_err(|err| AttestationError::InvalidHexClaim {
        claim,
        message: err.to_string(),
    })?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| AttestationError::InvalidHexClaim {
            claim,
            message: format!("expected 32 bytes, got {}", bytes.len()),
        })
}

#[cfg(test)]
fn image_digest_matches(claim: &str, expected_digest: &str) -> bool {
    claim == expected_digest || claim.ends_with(&format!("@{expected_digest}"))
}

#[cfg(test)]
fn require_eq32(
    actual: [u8; 32],
    expected: [u8; 32],
    err: AttestationError,
) -> Result<(), AttestationError> {
    if actual == expected { Ok(()) } else { Err(err) }
}

/// In-crate regression tests for the (test-only) offline bundle verifier.
/// They live here, not in `tests/`, precisely because
/// `verify_attestation_bundle` is `#[cfg(test)]`-gated: the gating only
/// means anything if no external integration test can reach the symbol.
#[cfg(test)]
mod tests {
    use super::{
        AmdSnpChainStatus, AttestationBundle, AttestationError, AttestationExpectations,
        ParsedSnpReport, tee_tls_transcript_hash, verify_attestation_bundle,
    };
    use crate::descriptor::{
        Capabilities, DeploymentDescriptor, EnvVar, OciRuntimeSpec, Port, Resources,
        SecurityContext, Sidecars, SignerIdentity,
    };
    use chrono::{TimeZone, Utc};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    fn fixed_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap(),
            nonce: [7; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec!["app.example.com".to_string()],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [9; 32],
            image_ref: "ghcr.io/enclava-labs/demo@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            image_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            signer_identity: SignerIdentity {
                subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/app".to_string()],
                args: vec!["--serve".to_string()],
                env: vec![EnvVar {
                    name: "A".to_string(),
                    value: "1".to_string(),
                }],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: "sha256:1111".to_string(),
                caddy_digest: "sha256:2222".to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            independent_verification: false,
            expected_firmware_measurement: [3; 32].into(),
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "platform-2026.04".to_string(),
            expected_agent_policy_hash: [7; 32],
            expected_cc_init_data_hash: [0; 32],
            expected_kbs_policy_hash: [6; 32],
        }
    }

    fn cc_init_data_toml(descriptor: &DeploymentDescriptor) -> Vec<u8> {
        format!(
            r#"version = "0.1.0"
algorithm = "sha256"

[data]
image_digest = "{}"
runtime_class = "{}"
namespace = "{}"
service_account = "{}"
identity_hash = "{}"
signer_identity_subject = "{}"
signer_identity_issuer = "{}"
sidecar_digests = '{{"attestation_proxy":"{}","caddy_ingress":"{}"}}'
"#,
            descriptor.image_digest,
            descriptor.expected_runtime_class,
            descriptor.namespace,
            descriptor.service_account,
            hex::encode(descriptor.identity_hash),
            descriptor.signer_identity.subject,
            descriptor.signer_identity.issuer,
            descriptor.sidecars.attestation_proxy_digest,
            descriptor.sidecars.caddy_digest
        )
        .into_bytes()
    }

    struct ValidCase {
        bundle: AttestationBundle,
        descriptor: DeploymentDescriptor,
        domain: &'static str,
        nonce: [u8; 32],
    }

    impl ValidCase {
        fn expectations(&self) -> AttestationExpectations<'_> {
            AttestationExpectations {
                domain: self.domain,
                nonce: self.nonce,
                descriptor: &self.descriptor,
            }
        }
    }

    fn valid_case() -> ValidCase {
        let mut descriptor = fixed_descriptor();
        let cc_init_data = cc_init_data_toml(&descriptor);
        descriptor.expected_cc_init_data_hash = Sha256::digest(&cc_init_data).into();

        let domain = "demo.abcd1234.tee.enclava.dev";
        let nonce = [8; 32];
        let tls_pubkey_spki_der = b"fake test spki der".to_vec();
        let receipt_pubkey_raw = [0x42; 32];
        let leaf_spki_hash: [u8; 32] = Sha256::digest(&tls_pubkey_spki_der).into();
        let receipt_pubkey_hash: [u8; 32] = Sha256::digest(receipt_pubkey_raw).into();
        let transcript = tee_tls_transcript_hash(domain, &nonce, &leaf_spki_hash);
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&transcript);
        report_data[32..].copy_from_slice(&receipt_pubkey_hash);

        let bundle = AttestationBundle {
            snp_report_bytes: Vec::new(),
            parsed_snp_report: ParsedSnpReport {
                report_data,
                host_data: Sha256::digest(&cc_init_data).into(),
                firmware_measurement: [3; 48],
            },
            cc_init_data_toml: cc_init_data,
            tls_pubkey_spki_der,
            receipt_pubkey_raw,
        };
        ValidCase {
            bundle,
            descriptor,
            domain,
            nonce,
        }
    }

    #[test]
    fn verifies_local_rev14_bindings() {
        let case = valid_case();
        let verified = verify_attestation_bundle(&case.bundle, &case.expectations()).unwrap();
        assert_eq!(
            verified.amd_chain_status,
            AmdSnpChainStatus::CertChainUnavailable
        );
    }

    #[test]
    fn rejects_host_data_mismatch() {
        let mut case = valid_case();
        case.bundle.parsed_snp_report.host_data[0] ^= 1;
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::HostDataMismatch)
        ));
    }

    #[test]
    fn rejects_descriptor_expected_cc_init_data_hash_mismatch() {
        let mut case = valid_case();
        case.descriptor.expected_cc_init_data_hash[0] ^= 1;
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::DescriptorCcInitDataHashMismatch)
        ));
    }

    #[test]
    fn rejects_report_data_spki_mismatch() {
        let mut case = valid_case();
        case.bundle.tls_pubkey_spki_der.push(0xff);
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::ReportDataTranscriptMismatch)
        ));
    }

    #[test]
    fn rejects_receipt_pubkey_mismatch() {
        let mut case = valid_case();
        case.bundle.receipt_pubkey_raw[0] ^= 1;
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::ReceiptPubkeyHashMismatch)
        ));
    }

    #[test]
    fn rejects_descriptor_claim_mismatch() {
        let mut case = valid_case();
        case.descriptor.namespace = "cap-other-demo".to_string();
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::ClaimMismatch { claim: "namespace" })
        ));
    }

    #[test]
    fn v2_rejects_mismatch_in_measurement_tail() {
        let mut case = valid_case();
        case.descriptor.schema_version = "v2".into();
        case.descriptor.expected_firmware_measurement = [3; 48].into();
        case.bundle.parsed_snp_report.firmware_measurement[47] ^= 1;
        assert!(matches!(
            verify_attestation_bundle(&case.bundle, &case.expectations()),
            Err(AttestationError::FirmwareMeasurementMismatch)
        ));
    }
}
