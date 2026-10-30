//! SNP-attested TLS channels to Enclava TEEs, shared by CAP and PaaS.
//!
//! [`attest_tee`] learns the TEE's per-boot TLS leaf, asks the guest for
//! nonce-bound SNP evidence over a channel pinned to that leaf, verifies the
//! evidence against builtin AMD roots, and returns the pinned TLS config with
//! the authenticated launch identity. The collateral policy is in README.md.

mod evidence;
mod kds;
#[cfg(test)]
mod test_fixtures;
mod tls;

use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE_NO_PAD},
};
use enclava_common::descriptor::LaunchIdentity;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use x509_cert::der::Decode;

use evidence::SnpDerChain;
pub use kds::{DEFAULT_AMD_KDS_BASE_URL, Kds};

/// Upper bound on the attestation response body; the TEE is unauthenticated
/// until SNP verification completes, so the body is never read unbounded.
const MAX_ATTESTATION_RESPONSE_BODY_BYTES: usize = 256 * 1024;

/// SHA-256 pins of the builtin AMD ARK roots (Milan, Genoa, Turin), byte
/// identical to the roots the platform CLI anchors SNP chains to. Only chains
/// whose ARK matches one of these are trusted.
pub const BUILTIN_AMD_ARK_SHA256_PINS: [[u8; 32]; 3] = [
    // sev 7.1.0 builtin milan ARK
    [
        0x69, 0xd0, 0x63, 0xb4, 0x53, 0x44, 0xd2, 0x6a, 0x2e, 0x94, 0xe1, 0xf4, 0x21, 0x0d, 0xe4,
        0x9e, 0xf5, 0x55, 0x30, 0x82, 0x87, 0xd4, 0xc1, 0x74, 0x44, 0x5c, 0x95, 0x63, 0x9a, 0x54,
        0x0b, 0xcd,
    ],
    // sev 7.1.0 builtin genoa ARK (matches the pinned ARK in the platform
    // verifier fixtures)
    [
        0x4c, 0x65, 0x98, 0xd1, 0x9c, 0x18, 0x71, 0x9c, 0x5d, 0xfd, 0x4a, 0x7d, 0x33, 0x5f, 0x67,
        0x4e, 0x5b, 0xfe, 0x1d, 0x8f, 0x80, 0x0c, 0xea, 0x2c, 0xf2, 0x70, 0xc1, 0x0d, 0x10, 0x3d,
        0xb2, 0xf1,
    ],
    // sev 7.1.0 builtin turin ARK
    [
        0x1f, 0x08, 0x41, 0x61, 0xa4, 0x4b, 0xb6, 0xd9, 0x37, 0x78, 0xa9, 0x04, 0x87, 0x7d, 0x48,
        0x19, 0xca, 0xfa, 0x5d, 0x05, 0xef, 0x41, 0x93, 0xb2, 0xde, 0xd9, 0xdd, 0x9c, 0x73, 0xdd,
        0x3f, 0x6a,
    ],
];

/// SNP guest policy bit 19 (DEBUG): when set, the PSP exposes the guest's
/// memory-encryption keys to a debugger, so the guest is never confidential
/// regardless of how valid its attestation chain is.
const SNP_GUEST_POLICY_DEBUG_BIT: u64 = 1 << 19;

pub fn snp_guest_policy_allows_debug(guest_policy: u64) -> bool {
    guest_policy & SNP_GUEST_POLICY_DEBUG_BIT != 0
}

/// Coarse, content-free failure class. Transport and TLS error strings can
/// interpolate tenant-controlled endpoints, so only static text leaves here.
#[derive(Debug)]
pub enum AttestError {
    /// TCP connect refused, reset or unresolvable: the resolved address did
    /// not serve, which callers may retry against another address.
    TcpConnect,
    Timeout,
    Transport,
    /// Fixed attestation/verification rejection.
    Attestation(&'static str),
}

impl AttestError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::TcpConnect => "connect",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Attestation(_) => "attestation",
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp connect failed",
            Self::Timeout => "request timed out",
            Self::Transport => "transport error",
            Self::Attestation(reason) => reason,
        }
    }
}

impl std::fmt::Display for AttestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for AttestError {}

fn map_reqwest_error(error: &reqwest::Error) -> AttestError {
    if error.is_timeout() {
        AttestError::Timeout
    } else if error.is_connect() {
        AttestError::TcpConnect
    } else {
        AttestError::Transport
    }
}

/// A TEE endpoint whose TLS key is bound to verified SNP evidence from an
/// admissible launch.
#[derive(Debug)]
pub struct AttestedTee {
    /// Lowercase host the evidence binds, and the port that served it.
    pub host: String,
    pub port: u16,
    /// Client config that only accepts the attested TLS leaf key.
    pub tls_config: rustls::ClientConfig,
    /// The guest attestation agent reported it could not obtain a KBS token.
    pub aa_token_error: bool,
}

/// Attest the TEE serving `url` (an `https` URL; only host and port are used)
/// and require its launch to be one of `admissible`.
///
/// `resolve_ip` pins the host to an address, e.g. an in-cluster Gateway.
pub async fn attest_tee(
    url: &str,
    resolve_ip: Option<IpAddr>,
    timeout: Duration,
    kds: &Kds<'_>,
    admissible: &[LaunchIdentity],
) -> Result<AttestedTee, AttestError> {
    // Any genuine SNP guest produces valid evidence; only the launch identity
    // tells the expected deployment apart, so never attest without one.
    if admissible.is_empty() {
        return Err(AttestError::Attestation(
            "no signed deployment identity to bind TEE evidence",
        ));
    }
    let session_id = ATTESTATION_SESSION.fetch_add(1, Ordering::Relaxed);
    let (host, port) = tee_endpoint(url)?;
    let resolve = resolve_ip.map(|ip| SocketAddr::new(ip, port));
    let leaf_cert_der = AttestationTiming::new(session_id, "tls_leaf")
        .measure(tls::fetch_leaf_cert_der(&host, port, resolve, timeout))
        .await?;
    let leaf_spki_sha256 = enclava_verifier::tls_leaf_spki_sha256(&leaf_cert_der)
        .map_err(|_| AttestError::Attestation("TEE leaf certificate is malformed"))?;
    let tls_config = tls::spki_pinned_config(leaf_spki_sha256)?;
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .use_preconfigured_tls(tls_config.clone());
    if let Some(socket) = resolve {
        builder = builder.resolve(&host, socket);
    }
    let client = builder.build().map_err(|error| map_reqwest_error(&error))?;

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let leaf_spki_hex = hex::encode(leaf_spki_sha256);
    let mut attestation_url = attestation_url(&host, port);
    attestation_url
        .query_pairs_mut()
        .append_pair("nonce", &nonce_b64)
        .append_pair("domain", &host)
        .append_pair("leaf_spki_sha256", &leaf_spki_hex);
    let attestation = fetch_attestation(&client, attestation_url, session_id).await?;
    // Fixed messages only: response content must never leak into errors
    // before SNP authentication completes.
    if attestation.nonce != nonce_b64 {
        return Err(AttestError::Attestation("nonce mismatch"));
    }
    if attestation.runtime_data_binding.domain != host {
        return Err(AttestError::Attestation("domain mismatch"));
    }
    if attestation.runtime_data_binding.leaf_spki_sha256 != leaf_spki_hex {
        return Err(AttestError::Attestation("leaf SPKI mismatch"));
    }
    let receipt_pubkey_sha256 =
        parse_hex32(&attestation.runtime_data_binding.receipt_pubkey_sha256)?;
    let expected_report_data = enclava_verifier::expected_report_data_with_pubkey_sha256(
        &format!("https://{host}"),
        &nonce,
        &leaf_spki_sha256,
        &receipt_pubkey_sha256,
    )
    .map_err(|_| AttestError::Attestation("report data derivation failed"))?;
    let evidence_bytes = B64_STANDARD
        .decode(attestation.evidence.payload_b64.as_bytes())
        .map_err(|_| AttestError::Attestation("evidence payload is not base64"))?;
    AttestationTiming::new(session_id, "evidence_verify")
        .measure(verify_snp_evidence(
            &attestation.evidence,
            &evidence_bytes,
            &expected_report_data,
            admissible,
            kds,
            session_id,
        ))
        .await?;
    Ok(AttestedTee {
        host,
        port,
        tls_config,
        aa_token_error: attestation.claims_meta.reports_aa_token_failure(),
    })
}

fn tee_endpoint(url: &str) -> Result<(String, u16), AttestError> {
    let url = reqwest::Url::parse(url).map_err(|_| AttestError::Attestation("invalid TEE URL"))?;
    if url.scheme() != "https" {
        return Err(AttestError::Attestation("TEE URL must be https"));
    }
    let host = url
        .host_str()
        .ok_or(AttestError::Attestation("TEE URL host missing"))?
        .to_ascii_lowercase();
    let port = url
        .port_or_known_default()
        .ok_or(AttestError::Attestation("TEE URL port missing"))?;
    Ok((host, port))
}

fn attestation_url(host: &str, port: u16) -> reqwest::Url {
    let mut url = reqwest::Url::parse("https://a.invalid/.well-known/confidential/attestation")
        .expect("static https URL must parse");
    // host and port came from a parsed https URL, so composing them back
    // cannot fail; a failure here would be a bug, not peer input.
    url.set_host(Some(host))
        .expect("attested TEE host must compose");
    url.set_port(Some(port))
        .expect("attested TEE port must compose");
    url
}

#[derive(serde::Deserialize)]
struct AttestationResponse {
    nonce: String,
    runtime_data_binding: RuntimeDataBinding,
    evidence: AttestationEvidence,
    #[serde(default)]
    claims_meta: ClaimsMeta,
}

#[derive(serde::Deserialize)]
struct RuntimeDataBinding {
    domain: String,
    leaf_spki_sha256: String,
    receipt_pubkey_sha256: String,
}

#[derive(serde::Deserialize)]
struct AttestationEvidence {
    payload_b64: String,
    #[serde(default)]
    json: Option<serde_json::Value>,
}

#[derive(Default, serde::Deserialize)]
struct ClaimsMeta {
    #[serde(default)]
    aa_token_error: Option<serde_json::Value>,
}

impl ClaimsMeta {
    /// Any non-empty diagnostic counts as a failure; its text is guest
    /// content and is never relayed.
    fn reports_aa_token_failure(&self) -> bool {
        match self.aa_token_error.as_ref() {
            None | Some(serde_json::Value::Null) => false,
            Some(serde_json::Value::String(error)) => !error.trim().is_empty(),
            Some(_) => true,
        }
    }
}

async fn fetch_attestation(
    client: &reqwest::Client,
    url: reqwest::Url,
    session_id: u64,
) -> Result<AttestationResponse, AttestError> {
    let mut timing = AttestationTiming::new(session_id, "attestation_get");
    let result = async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|error| map_reqwest_error(&error))?;
        timing.http_status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(AttestError::Attestation(
                "TEE attestation endpoint refused the request",
            ));
        }
        let body = read_body_capped(response, MAX_ATTESTATION_RESPONSE_BODY_BYTES)
            .await
            .map_err(|_| AttestError::Attestation("TEE attestation body exceeded bounds"))?;
        serde_json::from_slice(&body)
            .map_err(|_| AttestError::Attestation("attestation body is malformed"))
    }
    .await;
    timing.outcome = if result.is_ok() { "success" } else { "error" };
    result
}

enum BodyError {
    TooLarge,
    Read,
}

async fn read_body_capped(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, BodyError> {
    if response
        .content_length()
        .is_some_and(|size| size > max_bytes as u64)
    {
        return Err(BodyError::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| BodyError::Read)? {
        if chunk.len() > max_bytes - body.len() {
            return Err(BodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn parse_hex32(value: &str) -> Result<[u8; 32], AttestError> {
    // Fixed messages only: hex errors interpolate the offending bytes, and
    // this field is parsed before SNP authentication completes.
    let bytes = hex::decode(value.trim())
        .map_err(|_| AttestError::Attestation("receipt_pubkey_sha256 is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| AttestError::Attestation("receipt_pubkey_sha256 must be 32 bytes"))
}

/// Extract the raw report, authenticate it against a pinned-ARK chain
/// (evidence-embedded when it anchors to a builtin AMD root, otherwise AMD
/// KDS) and require its launch identity to be admissible.
async fn verify_snp_evidence(
    evidence: &AttestationEvidence,
    evidence_bytes: &[u8],
    expected_report_data: &[u8; 64],
    admissible: &[LaunchIdentity],
    kds: &Kds<'_>,
    session_id: u64,
) -> Result<(), AttestError> {
    let parsed_evidence;
    let evidence_json = match evidence.json.as_ref() {
        Some(json) => json,
        None => {
            parsed_evidence = serde_json::from_slice(evidence_bytes).map_err(|_| {
                AttestError::Attestation("attestation evidence is not parseable JSON")
            })?;
            &parsed_evidence
        }
    };
    let report_bytes = evidence::snp_report_bytes(evidence_json).ok_or(
        AttestError::Attestation("attestation evidence does not contain a raw AMD SNP report"),
    )?;
    let chain = match evidence::snp_der_chain(evidence_json) {
        Some(chain) if ark_is_pinned_to_builtin_root(&chain.ark_der) => chain,
        embedded => {
            if embedded.is_some() {
                // Signature checks on an unpinned ARK only prove internal
                // consistency, never AMD anchoring: attacker-controlled input.
                tracing::warn!(
                    code = "tee_attestation_unanchored_chain",
                    "attestation evidence carried an AMD chain not anchored to a builtin AMD root; falling back to AMD KDS"
                );
            }
            AttestationTiming::new(session_id, "kds_fetch")
                .measure(kds.chain_for_report(&report_bytes, session_id))
                .await?
        }
    };
    let (host_data, measurement) =
        verify_snp_report(&report_bytes, &chain, expected_report_data, unix_now()?)?;
    if !admissible
        .iter()
        .any(|identity| identity.matches_report(&host_data, &measurement))
    {
        return Err(AttestError::Attestation(
            "SNP launch identity does not bind a live deployment",
        ));
    }
    Ok(())
}

/// The full gate stack: pinned ARK anchor, ARK/ASK/VCEK signatures, the
/// certificates' validity windows, production guest policy, VCEK report
/// signature and chip/TCB binding, then the report_data binding.
fn verify_snp_report(
    report_bytes: &[u8],
    chain: &SnpDerChain,
    expected_report_data: &[u8; 64],
    now_unix_seconds: u64,
) -> Result<([u8; 32], [u8; 48]), AttestError> {
    if report_bytes.len() != enclava_verifier::SNP_REPORT_BYTES {
        return Err(AttestError::Attestation("SNP report has unexpected length"));
    }
    let ark_sha256: [u8; 32] = Sha256::digest(&chain.ark_der).into();
    if !BUILTIN_AMD_ARK_SHA256_PINS.contains(&ark_sha256) {
        return Err(AttestError::Attestation(
            "AMD chain is not anchored to a pinned root",
        ));
    }
    enclava_verifier::verify_amd_certificate_chain(
        &chain.ark_der,
        &chain.ask_der,
        &chain.vcek_der,
        &ark_sha256,
    )
    .map_err(|_| AttestError::Attestation("AMD certificate chain verification failed"))?;
    for der in [&chain.ark_der, &chain.ask_der, &chain.vcek_der] {
        if !certificate_validity(der).is_some_and(|(not_before, not_after)| {
            (not_before..=not_after).contains(&now_unix_seconds)
        }) {
            return Err(AttestError::Attestation(
                "AMD certificate is outside its validity period",
            ));
        }
    }
    let report = enclava_verifier::parse_snp_report(report_bytes)
        .map_err(|_| AttestError::Attestation("SNP report is malformed"))?;
    if snp_guest_policy_allows_debug(report.guest_policy) {
        return Err(AttestError::Attestation("SNP guest policy allows debug"));
    }
    enclava_verifier::verify_snp_signature(&report, &chain.vcek_der)
        .map_err(|_| AttestError::Attestation("SNP report signature invalid"))?;
    enclava_verifier::verify_vcek_report_binding(&report, &chain.vcek_der)
        .map_err(|_| AttestError::Attestation("VCEK does not bind the SNP report"))?;
    if &report.report_data != expected_report_data {
        return Err(AttestError::Attestation(
            "SNP report_data does not bind nonce, TLS leaf SPKI, and receipt key",
        ));
    }
    Ok((report.host_data, report.measurement))
}

fn ark_is_pinned_to_builtin_root(ark_der: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(ark_der).into();
    BUILTIN_AMD_ARK_SHA256_PINS.contains(&digest)
}

/// `(not_before, not_after)` in Unix seconds, or `None` if `der` is not a certificate.
fn certificate_validity(der: &[u8]) -> Option<(u64, u64)> {
    let validity = x509_cert::Certificate::from_der(der)
        .ok()?
        .tbs_certificate
        .validity;
    Some((
        validity.not_before.to_unix_duration().as_secs(),
        validity.not_after.to_unix_duration().as_secs(),
    ))
}

fn unix_now() -> Result<u64, AttestError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|now| now.as_secs())
        .map_err(|_| AttestError::Attestation("system clock predates UNIX epoch"))
}

static ATTESTATION_SESSION: AtomicU64 = AtomicU64::new(1);

/// One `attestation_timing` event per stage. Process-local correlation only:
/// never log a URL, chip ID, evidence or guest error.
struct AttestationTiming {
    session_id: u64,
    stage: &'static str,
    start: Instant,
    outcome: &'static str,
    attempt: usize,
    // Zero means no response status recorded, not HTTP 0.
    http_status: u16,
}

impl AttestationTiming {
    fn new(session_id: u64, stage: &'static str) -> Self {
        Self {
            session_id,
            stage,
            start: Instant::now(),
            outcome: "cancelled",
            attempt: 0,
            http_status: 0,
        }
    }

    async fn measure<T, E>(mut self, work: impl Future<Output = Result<T, E>>) -> Result<T, E> {
        let result = work.await;
        self.outcome = if result.is_ok() { "success" } else { "error" };
        result
    }
}

impl Drop for AttestationTiming {
    fn drop(&mut self) {
        tracing::info!(
            event = "attestation_timing",
            session_id = self.session_id,
            stage = self.stage,
            outcome = self.outcome,
            attempt = self.attempt,
            http_status = self.http_status,
            elapsed_ms = self.start.elapsed().as_secs_f64() * 1000.0
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use sev::parser::ByteParser;

    use super::*;
    use crate::test_fixtures::{FIXTURE_NOW, prove_it_live, quiet_subscriber, serve_every_path};

    fn evidence(json: serde_json::Value) -> AttestationEvidence {
        AttestationEvidence {
            payload_b64: String::new(),
            json: Some(json),
        }
    }

    /// Pinned embedded chains never reach KDS; a dead endpoint proves it.
    const UNREACHABLE_KDS: Kds<'static> = Kds {
        base_url: "https://127.0.0.1:9/vcek/v1",
        ca_bundle_path: None,
        max_attempts: 1,
    };

    #[tokio::test]
    async fn pinned_evidence_chain_verifies_an_admissible_launch() {
        let _quiet = quiet_subscriber();
        let fixture = prove_it_live();
        verify_snp_evidence(
            &evidence(fixture.evidence()),
            b"",
            &fixture.parsed().report_data,
            &[fixture.launch_identity()],
            &UNREACHABLE_KDS,
            1,
        )
        .await
        .expect("live Genoa evidence must verify offline");
    }

    #[tokio::test]
    async fn verified_evidence_from_an_unlisted_launch_is_rejected() {
        let _quiet = quiet_subscriber();
        let fixture = prove_it_live();
        let genuine = fixture.launch_identity();
        // A genuine SNP guest launched for another deployment, or the right
        // deployment under different firmware.
        let other_deployment = LaunchIdentity {
            expected_cc_init_data_hash: [0xaa; 32],
            ..genuine.clone()
        };
        let other_firmware = LaunchIdentity {
            expected_firmware_measurement: [0xab; 48].into(),
            ..genuine
        };
        let error = verify_snp_evidence(
            &evidence(fixture.evidence()),
            b"",
            &fixture.parsed().report_data,
            &[other_deployment, other_firmware],
            &UNREACHABLE_KDS,
            1,
        )
        .await
        .expect_err("valid evidence for an unlisted launch must be rejected");
        assert_eq!(
            error.reason(),
            "SNP launch identity does not bind a live deployment"
        );
    }

    #[tokio::test]
    async fn attest_tee_without_admissible_identity_fails_before_connecting() {
        let error = attest_tee(
            "https://127.0.0.1:9",
            None,
            Duration::from_secs(5),
            &UNREACHABLE_KDS,
            &[],
        )
        .await
        .expect_err("attestation without an expected launch must fail closed");
        assert_eq!(
            error.reason(),
            "no signed deployment identity to bind TEE evidence"
        );
    }

    /// CoCo guest components send the report as sev's structured JSON.
    #[tokio::test]
    async fn structured_coco_report_verifies_like_raw_bytes() {
        let _quiet = quiet_subscriber();
        let fixture = prove_it_live();
        let structured = serde_json::to_value(
            sev::firmware::guest::AttestationReport::from_bytes(&fixture.report).unwrap(),
        )
        .unwrap();
        let json = serde_json::json!({
            "attestation_report": structured,
            "cert_chain": fixture.evidence()["cert_chain"],
        });
        verify_snp_evidence(
            &evidence(json),
            b"",
            &fixture.parsed().report_data,
            &[fixture.launch_identity()],
            &UNREACHABLE_KDS,
            1,
        )
        .await
        .expect("structured report must verify");
    }

    #[tokio::test]
    async fn evidence_for_another_binding_is_rejected() {
        let _quiet = quiet_subscriber();
        let fixture = prove_it_live();
        let error = verify_snp_evidence(
            &evidence(fixture.evidence()),
            b"",
            &[0x42; 64],
            &[fixture.launch_identity()],
            &UNREACHABLE_KDS,
            1,
        )
        .await
        .expect_err("evidence for another nonce/domain/leaf must be rejected");
        assert_eq!(
            error.reason(),
            "SNP report_data does not bind nonce, TLS leaf SPKI, and receipt key"
        );
    }

    #[test]
    fn tampered_vcek_chain_is_rejected() {
        let fixture = prove_it_live();
        let mut chain = fixture.chain();
        // The last DER byte sits in the ASK's RSA-PSS signature over the VCEK.
        let last = chain.vcek_der.len() - 1;
        chain.vcek_der[last] ^= 0x01;
        let error = verify_snp_report(
            &fixture.report,
            &chain,
            &fixture.parsed().report_data,
            FIXTURE_NOW,
        )
        .unwrap_err();
        assert_eq!(error.category(), "attestation");
        assert_eq!(error.reason(), "AMD certificate chain verification failed");
    }

    #[test]
    fn gate_rejects_unpinned_roots_stale_collateral_and_debug_guests() {
        let fixture = prove_it_live();
        let report = fixture.parsed();
        let verify = |report_bytes: &[u8], chain: &SnpDerChain, now: u64| {
            verify_snp_report(report_bytes, chain, &report.report_data, now)
        };
        assert_eq!(
            verify(&fixture.report, &fixture.chain(), FIXTURE_NOW).unwrap(),
            (report.host_data, report.measurement)
        );

        let unpinned = SnpDerChain {
            ark_der: fixture.ask_der.clone(),
            ..fixture.chain()
        };
        assert_eq!(
            verify(&fixture.report, &unpinned, FIXTURE_NOW)
                .unwrap_err()
                .reason(),
            "AMD chain is not anchored to a pinned root"
        );

        let (not_before, not_after) = certificate_validity(&fixture.vcek_der).unwrap();
        for now in [not_before, not_after] {
            assert!(verify(&fixture.report, &fixture.chain(), now).is_ok());
        }
        for now in [not_before - 1, not_after + 1] {
            assert_eq!(
                verify(&fixture.report, &fixture.chain(), now)
                    .unwrap_err()
                    .reason(),
                "AMD certificate is outside its validity period"
            );
        }

        let mut debug = fixture.report.clone();
        debug[0x0a] |= 0x08; // bit 19 of the little-endian guest policy
        assert_eq!(
            verify(&debug, &fixture.chain(), FIXTURE_NOW)
                .unwrap_err()
                .reason(),
            "SNP guest policy allows debug"
        );

        let mut forged = fixture.report.clone();
        forged[0x50] ^= 1; // report_data is covered by the VCEK signature
        assert_eq!(
            verify(&forged, &fixture.chain(), FIXTURE_NOW)
                .unwrap_err()
                .reason(),
            "SNP report signature invalid"
        );
    }

    #[tokio::test]
    async fn unpinned_embedded_chain_falls_back_to_kds_and_builtin_roots() {
        let _quiet = quiet_subscriber();
        let fixture = prove_it_live();
        let (address, requests, server) = serve_every_path(200, fixture.vcek_der.clone()).await;
        let mut json = fixture.evidence();
        // An attacker-chosen ARK must never anchor the chain, even if the rest
        // of the embedded collateral is genuine.
        json["cert_chain"][0]["data"] = serde_json::json!(fixture.ask_der);
        let base_url = format!("http://{address}/vcek/v1");
        let kds = Kds {
            base_url: &base_url,
            ca_bundle_path: None,
            max_attempts: 1,
        };
        let report = fixture.parsed();
        verify_snp_evidence(
            &evidence(json),
            b"",
            &report.report_data,
            &[fixture.launch_identity()],
            &kds,
            1,
        )
        .await
        .expect("the KDS VCEK must chain to the builtin Genoa roots");
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        server.abort();
    }

    #[test]
    fn aa_token_failure_is_reported_without_relaying_guest_diagnostics() {
        let meta = |value: serde_json::Value| ClaimsMeta {
            aa_token_error: Some(value),
        };
        assert!(
            meta(serde_json::json!(
                "aa_token_fetch_failed:upstream diagnostics"
            ))
            .reports_aa_token_failure()
        );
        assert!(meta(serde_json::json!({"unexpected": "shape"})).reports_aa_token_failure());
        assert!(!meta(serde_json::Value::Null).reports_aa_token_failure());
        assert!(!meta(serde_json::json!("  ")).reports_aa_token_failure());
        assert!(!ClaimsMeta::default().reports_aa_token_failure());
    }

    /// Serves a fresh self-signed leaf; `respond` maps the request line and
    /// the leaf SPKI to a JSON body.
    async fn spawn_attestation_server(
        domain: &'static str,
        respond: impl Fn(&str, [u8; 32]) -> String + Send + Sync + 'static,
    ) -> SocketAddr {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
            .expect("self-signed certificate");
        let leaf_spki_sha256 =
            enclava_verifier::tls_leaf_spki_sha256(cert.cert.der().as_ref()).expect("leaf SPKI");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(
                    cert.cert.der().to_vec(),
                )],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .expect("TLS server config");
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let respond = std::sync::Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 2048];
                while let Ok(read) = stream.read(&mut buf).await {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                if request.is_empty() {
                    continue;
                }
                let request_line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let body = respond(&request_line, leaf_spki_sha256);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        address
    }

    fn query_param(request_line: &str, name: &str) -> Option<String> {
        let path = request_line.split_whitespace().nth(1)?;
        let (_, query) = path.split_once('?')?;
        query.split('&').find_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            (key == name).then(|| value.to_string())
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn self_signed_peer_without_hardware_evidence_is_rejected() {
        let _quiet = quiet_subscriber();
        let domain = "tee.app.example";
        let socket = spawn_attestation_server(domain, move |request_line, leaf_spki| {
            serde_json::json!({
                "nonce": query_param(request_line, "nonce").unwrap_or_default(),
                "runtime_data_binding": {
                    "domain": domain,
                    "leaf_spki_sha256": hex::encode(leaf_spki),
                    "receipt_pubkey_sha256": "00".repeat(32),
                },
                "evidence": {"payload_b64": "", "json": {"note": "no snp report"}},
            })
            .to_string()
        })
        .await;
        let error = attest_tee(
            &format!("https://{domain}:{}", socket.port()),
            Some(socket.ip()),
            Duration::from_secs(5),
            &UNREACHABLE_KDS,
            &[prove_it_live().launch_identity()],
        )
        .await
        .expect_err("mock evidence without a raw SNP report must fail closed");
        assert_eq!(
            error.reason(),
            "attestation evidence does not contain a raw AMD SNP report"
        );
    }

    #[tokio::test]
    async fn pinned_config_accepts_only_the_negotiated_tls_key() {
        let domain = "tee.app.example";
        let socket = spawn_attestation_server(domain, |_, _| "{}".to_string()).await;
        let timeout = Duration::from_secs(5);
        let leaf = tls::fetch_leaf_cert_der(domain, socket.port(), Some(socket), timeout)
            .await
            .expect("learn self-signed leaf");
        let spki = enclava_verifier::tls_leaf_spki_sha256(&leaf).expect("leaf SPKI");
        let url = format!("https://{domain}:{}/attestation", socket.port());
        let client = |spki| {
            reqwest::Client::builder()
                .use_preconfigured_tls(tls::spki_pinned_config(spki).unwrap())
                .resolve(domain, socket)
                .build()
                .unwrap()
        };
        assert_eq!(
            client(spki)
                .get(&url)
                .send()
                .await
                .expect("matching key")
                .status(),
            reqwest::StatusCode::OK
        );
        let mut foreign_spki = spki;
        foreign_spki[0] ^= 1;
        assert!(client(foreign_spki).get(&url).send().await.is_err());
    }
}
