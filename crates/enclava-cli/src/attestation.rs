//! Local Phase 7 attestation verifier plumbing.
//!
//! Uses the `sev` crate to parse raw AMD SNP attestation reports and verify
//! AMD VCEK certificate chains when evidence carries the required DER certs.

use std::collections::BTreeMap;

use enclava_common::canonical::ce_v1_hash;
use sev::parser::ByteParser;
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

fn image_digest_matches(claim: &str, expected_digest: &str) -> bool {
    claim == expected_digest || claim.ends_with(&format!("@{expected_digest}"))
}

fn require_eq32(
    actual: [u8; 32],
    expected: [u8; 32],
    err: AttestationError,
) -> Result<(), AttestationError> {
    if actual == expected { Ok(()) } else { Err(err) }
}
