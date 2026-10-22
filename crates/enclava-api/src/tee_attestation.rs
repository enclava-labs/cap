//! Authenticates per-boot TEE TLS keys with fresh SNP evidence and stored launch identities.
//! CRL freshness follows the CLI policy: required for unlock transitions, not ordinary attested operations.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use enclava_common::descriptor::{DeploymentDescriptor, FirmwareMeasurement};
use rand::{RngCore, rngs::OsRng};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sev::parser::ByteParser;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const DEFAULT_AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com/vcek/v1";
/// Upper bound on the attestation response body; the TEE is unauthenticated
/// until SNP verification completes, so the body is never read unbounded.
const MAX_ATTESTATION_RESPONSE_BODY_BYTES: u64 = 256 * 1024;
/// Maximum accepted size of a single evidence-carried AMD certificate DER.
/// Real ARK/ASK/VCEK certificates are under 2 KiB; anything larger is
/// rejected before X.509 parsing (same bound as the unlock transition gate).
const MAX_EVIDENCE_CERTIFICATE_DER_BYTES: usize = 16_384;

/// SHA-256 pins of the AMD ARK roots compiled into the `sev` crate the
/// platform CLI uses to anchor SNP chains (Milan, Genoa, Turin). The API
/// accepts only chains whose ARK byte-matches one of these roots, mirroring
/// the client-side `ark_is_pinned_to_builtin_root` trust anchor.
pub(crate) const BUILTIN_AMD_ARK_SHA256_PINS: [[u8; 32]; 3] = [
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

/// SNP guest policy bit 19 (DEBUG): when set, debugging the guest is
/// allowed and the PSP exposes the guest's memory-encryption keys to the
/// debugger. A guest launched with this bit is never confidential,
/// regardless of how valid its attestation chain is.
const SNP_GUEST_POLICY_DEBUG_BIT: u64 = 1 << 19;

/// Mirrors the CLI's `ensure_snp_report_production_policy`: reports from
/// debug-enabled guests must not be trusted as TEE-consent evidence.
pub(crate) fn snp_guest_policy_allows_debug(guest_policy: u64) -> bool {
    guest_policy & SNP_GUEST_POLICY_DEBUG_BIT != 0
}

/// Coarse, content-free failure class. Error Display strings from transport
/// and TLS layers can interpolate tenant-controlled endpoints, so only the
/// category reaches logs and responses.
#[derive(Debug)]
pub(crate) enum TeeAttestError {
    /// TCP connect refused/reset/dns failure; the only class that may retry
    /// against the public origin after a Gateway resolve miss.
    TcpConnect,
    Timeout,
    Transport,
    /// Fixed attestation/verification rejection. The label is a static
    /// string so diagnostics stay content-free.
    Attestation(&'static str),
    /// Authoritative deployment identity unavailable or malformed in
    /// storage; indistinguishable from a broken dependency to the caller.
    Storage,
}

impl TeeAttestError {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            Self::TcpConnect => "connect",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Attestation(_) => "attestation",
            Self::Storage => "storage",
        }
    }

    /// The static, content-free rejection reason. Safe for warn diagnostics:
    /// every value is a string literal authored in this module, never
    /// interpolated transport or response content.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp connect failed",
            Self::Timeout => "request timed out",
            Self::Transport => "transport error",
            Self::Attestation(reason) => reason,
            Self::Storage => "deployment identity storage unavailable",
        }
    }
}

fn map_reqwest_error(error: &reqwest::Error) -> TeeAttestError {
    if error.is_timeout() {
        TeeAttestError::Timeout
    } else if error.is_connect() {
        TeeAttestError::TcpConnect
    } else {
        TeeAttestError::Transport
    }
}

struct EndpointParts {
    host: String,
    port: u16,
}

impl EndpointParts {
    fn parse(base: &str) -> Result<Self, TeeAttestError> {
        let url = reqwest::Url::parse(base)
            .map_err(|_| TeeAttestError::Attestation("invalid TEE URL"))?;
        if url.scheme() != "https" {
            return Err(TeeAttestError::Attestation("TEE URL must be https"));
        }
        let host = url
            .host_str()
            .ok_or(TeeAttestError::Attestation("TEE URL host missing"))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or(TeeAttestError::Attestation("TEE URL port missing"))?;
        Ok(Self { host, port })
    }
}

#[derive(Debug)]
struct SpkiPinnedVerifier {
    expected_spki_sha256: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for SpkiPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki_sha256 =
            enclava_verifier::tls_leaf_spki_sha256(end_entity.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        if spki_sha256 == self.expected_spki_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn build_spki_pinned_client(
    expected_spki_sha256: [u8; 32],
    timeout: Duration,
    host: &str,
    resolve_ip: Option<SocketAddr>,
) -> Result<reqwest::Client, TeeAttestError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| TeeAttestError::Attestation("TLS versions invalid"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinnedVerifier {
            expected_spki_sha256,
            algorithms,
        }))
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .use_preconfigured_tls(tls);
    if let Some(socket) = resolve_ip {
        builder = builder.resolve(host, socket);
    }
    builder.build().map_err(|error| map_reqwest_error(&error))
}

/// Pass-through verifier for the leaf-learning handshake only. Its output is
/// never trusted: the leaf SPKI it yields only becomes authoritative once
/// nonce-bound SNP evidence binds it to the expected deployment.
#[derive(Debug)]
struct NoVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Complete one TLS handshake against the TEE endpoint and return the raw
/// DER of the presented leaf certificate.
async fn fetch_tls_leaf_cert_der(
    host: &str,
    port: u16,
    resolve_ip: Option<SocketAddr>,
    timeout: Duration,
) -> Result<Vec<u8>, TeeAttestError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| TeeAttestError::Attestation("TLS versions invalid"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier { algorithms }))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let connect = async {
        match resolve_ip {
            Some(socket) => TcpStream::connect(socket).await,
            None => TcpStream::connect((host, port)).await,
        }
    };
    let stream = tokio::time::timeout(timeout.min(Duration::from_secs(10)), connect)
        .await
        .map_err(|_| TeeAttestError::Timeout)?
        // Every TCP connect failure is the same retirable class as the CLI's
        // "TEE TCP connect" errors: refusal, reset, or DNS all mean the
        // resolved address did not serve, not that the endpoint is bad.
        .map_err(|_| TeeAttestError::TcpConnect)?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| TeeAttestError::Attestation("TEE host is not a valid DNS name"))?;
    let tls_stream = tokio::time::timeout(
        timeout.min(Duration::from_secs(10)),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| TeeAttestError::Timeout)?
    .map_err(|_| TeeAttestError::Attestation("TEE TLS handshake failed"))?;
    let certs = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .ok_or(TeeAttestError::Attestation(
            "TEE did not present a certificate",
        ))?;
    let leaf = certs.first().ok_or(TeeAttestError::Attestation(
        "TEE certificate chain is empty",
    ))?;
    Ok(leaf.as_ref().to_vec())
}

#[derive(Debug, serde::Deserialize)]
struct AttestationResponse {
    nonce: String,
    runtime_data_binding: RuntimeDataBinding,
    evidence: AttestationEvidence,
}

#[derive(Debug, serde::Deserialize)]
struct RuntimeDataBinding {
    domain: String,
    leaf_spki_sha256: String,
    receipt_pubkey_sha256: String,
}

#[derive(Debug, serde::Deserialize)]
struct AttestationEvidence {
    payload_b64: String,
    #[serde(default)]
    json: Option<serde_json::Value>,
}

/// Expected launch identity for one admissible live deployment, derived from
/// the signed deployment descriptor persisted at deploy time.
#[derive(Debug)]
pub(crate) struct TeardownIdentity {
    pub expected_cc_init_data_hash: [u8; 32],
    pub expected_firmware_measurement: FirmwareMeasurement,
}

#[derive(Debug, sqlx::FromRow)]
struct TeardownArtifactRow {
    deploy_id: uuid::Uuid,
    descriptor_payload: serde_json::Value,
}

/// Load the deployment identities the live TEE may legitimately attest to.
///
/// Authority is exactly the app's required KBS policy authority (kbs.rs): the
/// artifact of the latest admitted operation (a rollback's older source
/// artifact included), the prior healthy workload while a replacement is
/// unconfirmed, and every possibly-serving generation of a deleting app.
/// Held, withdrawn, removed-signer and artifact-less operations contribute
/// nothing, so a token is never minted for an identity KBS would not admit.
pub(crate) async fn load_teardown_identities(
    pool: &sqlx::PgPool,
    app: &crate::models::App,
) -> Result<Vec<TeardownIdentity>, TeeAttestError> {
    let artifacts = crate::kbs::load_required_app_artifacts(pool, app.id)
        .await
        .map_err(|_| TeeAttestError::Storage)?;
    if artifacts.is_empty() {
        return Err(TeeAttestError::Attestation(
            "no admitted workload authority",
        ));
    }
    let core_hashes = artifacts
        .iter()
        .map(|artifact| hex::decode(&artifact.metadata.descriptor_core_hash))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TeeAttestError::Storage)?;
    let rows = sqlx::query_as::<_, TeardownArtifactRow>(
        "SELECT deploy_id, descriptor_payload
           FROM workload_artifacts
          WHERE app_id = $1 AND descriptor_core_hash = ANY($2)",
    )
    .bind(app.id)
    .bind(&core_hashes)
    .fetch_all(pool)
    .await
    .map_err(|_| TeeAttestError::Storage)?;
    if rows.len() != core_hashes.len() {
        return Err(TeeAttestError::Storage);
    }

    let mut identities = Vec::with_capacity(rows.len());
    for row in rows {
        let descriptor: DeploymentDescriptor =
            serde_json::from_value(row.descriptor_payload).map_err(|_| TeeAttestError::Storage)?;
        // The stored artifact is already signature- and hash-validated at
        // deploy; these comparisons bind it to THIS delete's app row so a
        // cataloguing anomaly cannot attest another app's TEE into scope.
        if descriptor.app_id != app.id
            || descriptor.org_id != app.org_id
            || descriptor.deploy_id != row.deploy_id
        {
            return Err(TeeAttestError::Attestation(
                "stored deployment identity does not match the deleting app",
            ));
        }
        identities.push(TeardownIdentity {
            expected_cc_init_data_hash: descriptor.expected_cc_init_data_hash,
            expected_firmware_measurement: descriptor.expected_firmware_measurement,
        });
    }
    Ok(identities)
}

fn report_is_bound_to_deployment(
    host_data: &[u8; 32],
    measurement: &[u8; 48],
    identities: &[TeardownIdentity],
) -> bool {
    identities.iter().any(|identity| {
        *host_data == identity.expected_cc_init_data_hash
            && identity
                .expected_firmware_measurement
                .matches_report(measurement)
    })
}

/// Attest the TEE endpoint and return an SPKI-pinned HTTP client for it.
///
/// Tries the resolved tenant-Gateway address first (hairpin-blocked
/// deployments cannot reach their own external edge); a TCP-connect failure
/// there retries against the public origin exactly like the CLI's
/// `attest_receipt_key`. Every other failure class fails closed — there is
/// no unauthenticated fallback because the only caller sends a protected
/// bearer token over the returned channel.
pub(crate) async fn attest_teardown_channel(
    domain: &str,
    resolve_ip: Option<IpAddr>,
    identities: &[TeardownIdentity],
    kds_base_url: Option<&str>,
) -> Result<reqwest::Client, TeeAttestError> {
    if identities.is_empty() {
        return Err(TeeAttestError::Attestation(
            "no signed deployment identity to bind TEE evidence",
        ));
    }
    let endpoint = EndpointParts::parse(&format!("https://{domain}"))?;
    let socket = resolve_ip.map(|ip| SocketAddr::new(ip, endpoint.port));
    let result = attest_teardown_channel_once(&endpoint, socket, identities, kds_base_url).await;
    if matches!(result, Err(TeeAttestError::TcpConnect)) && resolve_ip.is_some() {
        return attest_teardown_channel_once(&endpoint, None, identities, kds_base_url).await;
    }
    result
}

async fn attest_teardown_channel_once(
    endpoint: &EndpointParts,
    resolve_ip: Option<SocketAddr>,
    identities: &[TeardownIdentity],
    kds_base_url: Option<&str>,
) -> Result<reqwest::Client, TeeAttestError> {
    let timeout = Duration::from_secs(30);
    let leaf_cert_der =
        fetch_tls_leaf_cert_der(&endpoint.host, endpoint.port, resolve_ip, timeout).await?;
    let leaf_spki_sha256 = enclava_verifier::tls_leaf_spki_sha256(&leaf_cert_der)
        .map_err(|_| TeeAttestError::Attestation("TEE leaf certificate is malformed"))?;
    let pinned_http =
        build_spki_pinned_client(leaf_spki_sha256, timeout, &endpoint.host, resolve_ip)?;

    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
    let leaf_spki_hex = hex::encode(leaf_spki_sha256);
    let mut attestation_url = endpoint.attestation_url();
    attestation_url
        .query_pairs_mut()
        .append_pair("nonce", nonce_b64.as_str())
        .append_pair("domain", endpoint.host.as_str())
        .append_pair("leaf_spki_sha256", leaf_spki_hex.as_str());
    let resp = pinned_http
        .get(attestation_url)
        .send()
        .await
        .map_err(|error| map_reqwest_error(&error))?;
    // Error and success bodies take the same bounded path: SPKI pinning only
    // proves continuity with the contacted peer until SNP verification
    // completes, so an unbounded body must never be consumed pre-auth.
    if !resp.status().is_success() {
        return Err(TeeAttestError::Attestation(
            "TEE attestation endpoint refused the request",
        ));
    }
    let body = crate::clients::read_body_capped(resp, MAX_ATTESTATION_RESPONSE_BODY_BYTES)
        .await
        .map_err(|_| TeeAttestError::Attestation("TEE attestation body exceeded bounds"))?;
    // Fixed messages only: response content must never leak into errors
    // before SNP authentication completes.
    let attestation: AttestationResponse = serde_json::from_slice(&body)
        .map_err(|_| TeeAttestError::Attestation("attestation body is malformed"))?;
    if attestation.nonce != nonce_b64 {
        return Err(TeeAttestError::Attestation("nonce mismatch"));
    }
    if attestation.runtime_data_binding.domain != endpoint.host {
        return Err(TeeAttestError::Attestation("domain mismatch"));
    }
    if attestation.runtime_data_binding.leaf_spki_sha256 != leaf_spki_hex {
        return Err(TeeAttestError::Attestation("leaf SPKI mismatch"));
    }
    let receipt_pubkey_sha256 =
        parse_hex32_field(&attestation.runtime_data_binding.receipt_pubkey_sha256)?;
    let expected_report_data = enclava_verifier::expected_report_data_with_pubkey_sha256(
        &format!("https://{}", endpoint.host),
        &nonce,
        &leaf_spki_sha256,
        &receipt_pubkey_sha256,
    )
    .map_err(|_| TeeAttestError::Attestation("report data derivation failed"))?;

    let evidence_bytes = B64_STANDARD
        .decode(attestation.evidence.payload_b64.as_bytes())
        .map_err(|_| TeeAttestError::Attestation("evidence payload is not base64"))?;
    verify_snp_evidence(
        &attestation.evidence,
        &evidence_bytes,
        &expected_report_data,
        identities,
        kds_base_url,
    )
    .await?;
    Ok(pinned_http)
}

impl EndpointParts {
    fn attestation_url(&self) -> reqwest::Url {
        let mut url =
            reqwest::Url::parse("https://a.invalid").expect("static https URL must parse");
        // host/port came from the same parsed https URL this struct was
        // built from; a failure here is impossible and would fail closed.
        url.set_host(Some(&self.host))
            .expect("attested TEE host must compose");
        url.set_port(Some(self.port))
            .expect("attested TEE port must compose");
        url.set_path("/.well-known/confidential/attestation");
        url
    }
}

fn parse_hex32_field(value: &str) -> Result<[u8; 32], TeeAttestError> {
    // Fixed messages only: hex errors interpolate the offending response
    // bytes, and this field is parsed before SNP authentication completes.
    let bytes = hex::decode(value.trim())
        .map_err(|_| TeeAttestError::Attestation("receipt_pubkey_sha256 is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| TeeAttestError::Attestation("receipt_pubkey_sha256 must be 32 bytes"))
}

/// Verify the SNP evidence envelope: extract the raw report, authenticate it
/// against a pinned-ARK DER chain (evidence-embedded when it anchors to a
/// builtin AMD root, otherwise AMD KDS), enforce production guest policy and
/// the report_data binding, then require the authenticated launch identity
/// ({HOST_DATA, firmware measurement}) to match a live deployment identity.
async fn verify_snp_evidence(
    evidence: &AttestationEvidence,
    evidence_bytes: &[u8],
    expected_report_data: &[u8; 64],
    identities: &[TeardownIdentity],
    kds_base_url: Option<&str>,
) -> Result<(), TeeAttestError> {
    let parsed_evidence;
    let evidence_json = match evidence.json.as_ref() {
        Some(json) => json,
        None => {
            parsed_evidence = serde_json::from_slice(evidence_bytes).map_err(|_| {
                TeeAttestError::Attestation("attestation evidence is not parseable JSON")
            })?;
            &parsed_evidence
        }
    };

    let snp_report_bytes = extract_snp_report_bytes(evidence_json).ok_or(
        TeeAttestError::Attestation("attestation evidence does not contain a raw AMD SNP report"),
    )?;
    let chain = match extract_snp_der_chain(evidence_json) {
        Some(chain) if ark_is_pinned_to_builtin_root(&chain.ark_der) => chain,
        Some(_) => {
            // An evidence-embedded chain whose ARK does not byte-match a
            // builtin AMD root is attacker-controlled input: `verify` would
            // only prove internal consistency, never AMD anchoring. Fall
            // back to the anchored KDS fetch; if that fails, fail closed.
            tracing::warn!(
                code = "tee_attestation_unanchored_chain",
                "attestation evidence carried an AMD chain not anchored to a builtin AMD root; falling back to AMD KDS"
            );
            fetch_snp_der_chain_from_kds(&snp_report_bytes, kds_base_url).await?
        }
        None => fetch_snp_der_chain_from_kds(&snp_report_bytes, kds_base_url).await?,
    };
    let (report_host_data, report_measurement) =
        verify_snp_report(&snp_report_bytes, &chain, expected_report_data)?;
    if !report_is_bound_to_deployment(&report_host_data, &report_measurement, identities) {
        return Err(TeeAttestError::Attestation(
            "SNP launch identity does not bind a live deployment",
        ));
    }
    Ok(())
}

/// Authenticate a raw SNP report end to end and return its launch identity.
/// Same gate stack as `verify_transition_snp_quote` minus the
/// caller-submitted CRL (see module docs): pinned ARK anchor, ARK/ASK/VCEK
/// chain, production guest policy, VCEK report signature and VCEK/report
/// chip+TCB binding, then the nonce/domain/leaf/receipt-key report_data
/// binding.
fn verify_snp_report(
    snp_report_bytes: &[u8],
    chain: &SnpDerChain,
    expected_report_data: &[u8; 64],
) -> Result<([u8; 32], [u8; 48]), TeeAttestError> {
    if snp_report_bytes.len() != enclava_verifier::SNP_REPORT_BYTES {
        return Err(TeeAttestError::Attestation(
            "SNP report has unexpected length",
        ));
    }
    let ark_sha256: [u8; 32] = Sha256::digest(&chain.ark_der).into();
    if !BUILTIN_AMD_ARK_SHA256_PINS.contains(&ark_sha256) {
        return Err(TeeAttestError::Attestation(
            "AMD chain is not anchored to a pinned root",
        ));
    }
    enclava_verifier::verify_amd_certificate_chain(
        &chain.ark_der,
        &chain.ask_der,
        &chain.vcek_der,
        &ark_sha256,
    )
    .map_err(|_| TeeAttestError::Attestation("AMD certificate chain verification failed"))?;
    let report = enclava_verifier::parse_snp_report(snp_report_bytes)
        .map_err(|_| TeeAttestError::Attestation("SNP report is malformed"))?;
    // A debug-enabled guest is not confidential (the PSP hands its keys to a
    // debugger), so its leaf key is untrusted even with a valid chain.
    if snp_guest_policy_allows_debug(report.guest_policy) {
        return Err(TeeAttestError::Attestation("SNP guest policy allows debug"));
    }
    enclava_verifier::verify_snp_signature(&report, &chain.vcek_der)
        .map_err(|_| TeeAttestError::Attestation("SNP report signature invalid"))?;
    enclava_verifier::verify_vcek_report_binding(&report, &chain.vcek_der)
        .map_err(|_| TeeAttestError::Attestation("VCEK does not bind the SNP report"))?;
    if &report.report_data != expected_report_data {
        return Err(TeeAttestError::Attestation(
            "SNP report_data does not bind nonce, TLS leaf SPKI, and receipt key",
        ));
    }
    Ok((report.host_data, report.measurement))
}

#[derive(Debug)]
struct SnpDerChain {
    ark_der: Vec<u8>,
    ask_der: Vec<u8>,
    vcek_der: Vec<u8>,
}

/// True only when `ark_der` byte-matches one of the built-in AMD ARK roots
/// (Milan, Genoa, Turin) whose SHA-256 pins anchor the API's quote gate.
/// Evidence-embedded chains are trusted exclusively through this anchor.
fn ark_is_pinned_to_builtin_root(ark_der: &[u8]) -> bool {
    let digest: [u8; 32] = Sha256::digest(ark_der).into();
    BUILTIN_AMD_ARK_SHA256_PINS.contains(&digest)
}

fn bounded_cert_der(field: &'static str, der: Vec<u8>) -> Result<Vec<u8>, TeeAttestError> {
    if der.is_empty() || der.len() > MAX_EVIDENCE_CERTIFICATE_DER_BYTES {
        return Err(TeeAttestError::Attestation(match field {
            "ark" => "evidence ARK certificate is out of bounds",
            "ask" => "evidence ASK certificate is out of bounds",
            _ => "evidence VCEK certificate is out of bounds",
        }));
    }
    Ok(der)
}

async fn fetch_snp_der_chain_from_kds(
    snp_report_bytes: &[u8],
    kds_base_url: Option<&str>,
) -> Result<SnpDerChain, TeeAttestError> {
    let report = sev::firmware::guest::AttestationReport::from_bytes(snp_report_bytes)
        .map_err(|_| TeeAttestError::Attestation("attestation evidence SNP report is malformed"))?;
    let (ark_der, ask_der) = builtin_snp_ca_der_chain(&report)?;
    let vcek_url = amd_kds_vcek_url(&report, kds_base_url.unwrap_or(DEFAULT_AMD_KDS_BASE_URL))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| map_reqwest_error(&error))?;
    let vcek_der = fetch_amd_kds_vcek_der(&client, &vcek_url).await?;
    Ok(SnpDerChain {
        ark_der,
        ask_der,
        vcek_der,
    })
}

fn builtin_snp_ca_der_chain(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<(Vec<u8>, Vec<u8>), TeeAttestError> {
    let generation = snp_report_generation(report)?;
    let (ark, ask) = match generation {
        sev::Generation::Milan => (
            sev::certs::snp::builtin::milan::ark(),
            sev::certs::snp::builtin::milan::ask(),
        ),
        sev::Generation::Genoa => (
            sev::certs::snp::builtin::genoa::ark(),
            sev::certs::snp::builtin::genoa::ask(),
        ),
        sev::Generation::Turin => (
            sev::certs::snp::builtin::turin::ark(),
            sev::certs::snp::builtin::turin::ask(),
        ),
    };
    let ark_der = ark
        .map_err(|_| TeeAttestError::Attestation("AMD ARK parse failed"))?
        .to_der()
        .map_err(|_| TeeAttestError::Attestation("AMD ARK DER encode failed"))?;
    let ask_der = ask
        .map_err(|_| TeeAttestError::Attestation("AMD ASK parse failed"))?
        .to_der()
        .map_err(|_| TeeAttestError::Attestation("AMD ASK DER encode failed"))?;
    Ok((ark_der, ask_der))
}

/// Error categories stay coarse: the request URL embeds the chip HWID and
/// must not reach logs or user-facing errors.
async fn fetch_amd_kds_vcek_der(
    client: &reqwest::Client,
    vcek_url: &str,
) -> Result<Vec<u8>, TeeAttestError> {
    let response = client
        .get(vcek_url)
        .send()
        .await
        .map_err(|error| map_reqwest_error(&error))?;
    if !response.status().is_success() {
        return Err(TeeAttestError::Attestation("AMD KDS VCEK fetch failed"));
    }
    read_vcek_body(response).await
}

/// Bounded VCEK body read: KDS or a relay must not stream unbounded bytes
/// into verifier memory. 64 KiB covers every real certificate with headroom.
async fn read_vcek_body(mut response: reqwest::Response) -> Result<Vec<u8>, TeeAttestError> {
    const MAX_DER_BYTES: u64 = 64 * 1024;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_DER_BYTES)
    {
        return Err(TeeAttestError::Attestation(
            "AMD KDS VCEK body exceeds bounds",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| TeeAttestError::Transport)?
    {
        if body.len() as u64 + chunk.len() as u64 > MAX_DER_BYTES {
            return Err(TeeAttestError::Attestation(
                "AMD KDS VCEK body exceeds bounds",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// AMD KDS spec 57230 identity for a report: the generation (from CPUID
/// family/model) plus the chip HWID used in the VCEK URL.
fn snp_report_kds_identity(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<(sev::Generation, String), TeeAttestError> {
    if report.chip_id == [0u8; 64] {
        return Err(TeeAttestError::Attestation(
            "SNP report masks chip_id; cannot fetch VCEK from AMD KDS",
        ));
    }
    if report.key_info.signing_key() != 0 {
        return Err(TeeAttestError::Attestation(
            "SNP report was not signed by VCEK; AMD KDS VCEK fallback is not applicable",
        ));
    }
    let generation = snp_report_generation(report)?;
    // AMD KDS spec 57230: Turin uses the first eight CHIP_ID bytes.
    let hw_id = if matches!(generation, sev::Generation::Turin) {
        if report.chip_id[8..].iter().any(|byte| *byte != 0) {
            return Err(TeeAttestError::Attestation("invalid Turin chip_id padding"));
        }
        hex::encode(&report.chip_id[..8])
    } else {
        hex::encode(report.chip_id)
    };
    Ok((generation, hw_id))
}

fn amd_kds_vcek_url(
    report: &sev::firmware::guest::AttestationReport,
    base_url: &str,
) -> Result<String, TeeAttestError> {
    let (generation, hw_id) = snp_report_kds_identity(report)?;
    let tcb = report.reported_tcb;
    let base = base_url.trim_end_matches('/');
    if matches!(generation, sev::Generation::Turin) {
        let fmc = tcb.fmc.ok_or(TeeAttestError::Attestation(
            "Turin SNP report missing fmc TCB value",
        ))?;
        Ok(format!(
            "{base}/{}/{hw_id}?fmcSPL={fmc:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            generation.titlecase(),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ))
    } else {
        Ok(format!(
            "{base}/{}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            generation.titlecase(),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ))
    }
}

fn snp_report_generation(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<sev::Generation, TeeAttestError> {
    let family = report.cpuid_fam_id.ok_or(TeeAttestError::Attestation(
        "SNP report missing CPUID family for VCEK lookup",
    ))?;
    let model = report.cpuid_mod_id.ok_or(TeeAttestError::Attestation(
        "SNP report missing CPUID model for VCEK lookup",
    ))?;
    sev::Generation::identify_cpu(family, model)
        .map_err(|_| TeeAttestError::Attestation("unknown SNP CPU generation"))
}

fn extract_structured_snp_report_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    if !value.is_object() {
        return None;
    }
    let report: sev::firmware::guest::AttestationReport =
        serde::Deserialize::deserialize(value).ok()?;
    let bytes = report.to_bytes().ok()?;
    Some(bytes.as_ref().to_vec())
}

fn extract_snp_report_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, candidate) in map {
                let normalized = normalize_json_key(key);
                let is_report_key = matches!(
                    normalized.as_str(),
                    "snpreport"
                        | "snpreportbytes"
                        | "rawsnpreport"
                        | "rawreport"
                        | "report"
                        | "quote"
                        | "attestationreport"
                        | "attestationreportbytes"
                );
                if is_report_key && let Some(bytes) = extract_structured_snp_report_bytes(candidate)
                {
                    return Some(bytes);
                }
                if is_report_key
                    && let Some(bytes) = parse_bytes_value(candidate)
                    && bytes.len() == enclava_verifier::SNP_REPORT_BYTES
                {
                    return Some(bytes);
                }
            }
            map.values().find_map(extract_snp_report_bytes)
        }
        serde_json::Value::Array(values) => parse_bytes_value(value)
            .filter(|bytes| bytes.len() == enclava_verifier::SNP_REPORT_BYTES)
            .or_else(|| values.iter().find_map(extract_snp_report_bytes)),
        _ => None,
    }
}

fn extract_snp_der_chain(value: &serde_json::Value) -> Option<SnpDerChain> {
    if let Some(chain) = extract_coco_cert_chain(value) {
        return Some(chain);
    }
    let ark_der = extract_named_bytes(value, &["ark", "arkder", "arkcert", "arkcertificate"])?;
    let ask_der = extract_named_bytes(value, &["ask", "askder", "askcert", "askcertificate"])?;
    let vcek_der = extract_named_bytes(value, &["vcek", "vcekder", "vcekcert", "vcekcertificate"])?;
    Some(SnpDerChain {
        ark_der: bounded_cert_der("ark", ark_der).ok()?,
        ask_der: bounded_cert_der("ask", ask_der).ok()?,
        vcek_der: bounded_cert_der("vcek", vcek_der).ok()?,
    })
}

fn extract_coco_cert_chain(value: &serde_json::Value) -> Option<SnpDerChain> {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(values) = map.get("cert_chain").and_then(serde_json::Value::as_array) {
                let mut ark_der = None;
                let mut ask_der = None;
                let mut vcek_der = None;

                for entry in values {
                    let cert_type = entry
                        .get("cert_type")
                        .and_then(serde_json::Value::as_str)
                        .map(normalize_json_key)?;
                    let data = entry.get("data").and_then(parse_bytes_value)?;
                    match cert_type.as_str() {
                        "ark" => ark_der = Some(data),
                        "ask" | "asvk" => ask_der = Some(data),
                        "vcek" | "vlek" => vcek_der = Some(data),
                        _ => {}
                    }
                }

                if ark_der.is_some() && ask_der.is_some() && vcek_der.is_some() {
                    return Some(SnpDerChain {
                        ark_der: bounded_cert_der("ark", ark_der?).ok()?,
                        ask_der: bounded_cert_der("ask", ask_der?).ok()?,
                        vcek_der: bounded_cert_der("vcek", vcek_der?).ok()?,
                    });
                }
            }
            map.values().find_map(extract_coco_cert_chain)
        }
        serde_json::Value::Array(values) => values.iter().find_map(extract_coco_cert_chain),
        _ => None,
    }
}

fn extract_named_bytes(value: &serde_json::Value, normalized_names: &[&str]) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, candidate) in map {
                let normalized = normalize_json_key(key);
                if normalized_names.iter().any(|name| normalized == *name)
                    && let Some(bytes) = parse_bytes_value(candidate)
                {
                    return Some(bytes);
                }
            }
            map.values()
                .find_map(|candidate| extract_named_bytes(candidate, normalized_names))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|candidate| extract_named_bytes(candidate, normalized_names)),
        _ => None,
    }
}

fn normalize_json_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn parse_bytes_value(value: &serde_json::Value) -> Option<Vec<u8>> {
    match value {
        serde_json::Value::String(raw) => parse_bytes_string(raw),
        serde_json::Value::Array(values) => values
            .iter()
            .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            .collect(),
        _ => None,
    }
}

fn parse_bytes_string(raw: &str) -> Option<Vec<u8>> {
    let value = raw
        .trim()
        .strip_prefix("0x")
        .or_else(|| raw.trim().strip_prefix("0X"))
        .unwrap_or_else(|| raw.trim());
    if value.contains("BEGIN CERTIFICATE") {
        let b64: String = value
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .map(str::trim)
            .collect();
        return B64_STANDARD.decode(b64.as_bytes()).ok();
    }
    if value.len().is_multiple_of(2) && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex::decode(value).ok();
    }
    B64_STANDARD
        .decode(value.as_bytes())
        .or_else(|_| URL_SAFE.decode(value.as_bytes()))
        .or_else(|_| URL_SAFE_NO_PAD.decode(value.as_bytes()))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanitized live Genoa bundle (see enclava-verifier fixtures README): real
    /// AMD chain and report, no secrets, verifiable fully offline.
    struct ProveItLiveFixture {
        snp_report: Vec<u8>,
        ark_der: Vec<u8>,
        ask_der: Vec<u8>,
        vcek_der: Vec<u8>,
    }

    fn prove_it_live_fixture() -> ProveItLiveFixture {
        let encoded =
            include_str!("../../enclava-verifier/tests/fixtures/prove-it-live.bundle.b64")
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
        let bundle = B64_STANDARD
            .decode(encoded)
            .expect("decode prove-it-live bundle");
        let records = enclava_common::canonical::ce_v1_decode(&bundle)
            .expect("parse prove-it-live bundle")
            .into_iter()
            .map(|record| (record.label.to_string(), record.value.to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let endorsement_records = enclava_common::canonical::ce_v1_decode(
            records
                .get("amd_endorsements")
                .expect("bundle endorsements"),
        )
        .expect("parse bundle endorsements")
        .into_iter()
        .map(|record| (record.label.to_string(), record.value.to_vec()))
        .collect::<std::collections::BTreeMap<_, _>>();
        let field = |name: &str| {
            endorsement_records
                .get(name)
                .expect("endorsement field")
                .clone()
        };
        ProveItLiveFixture {
            snp_report: records.get("snp_report").expect("bundle report").clone(),
            ark_der: field("ark_der"),
            ask_der: field("ask_der"),
            vcek_der: field("vcek_der"),
        }
    }

    fn fixture_evidence(fixture: &ProveItLiveFixture) -> serde_json::Value {
        serde_json::json!({
            "quote": fixture.snp_report,
            "cert_chain": [
                {"cert_type": "ARK", "data": fixture.ark_der},
                {"cert_type": "ASK", "data": fixture.ask_der},
                {"cert_type": "VCEK", "data": fixture.vcek_der},
            ],
        })
    }

    fn fixture_report_data(fixture: &ProveItLiveFixture) -> [u8; 64] {
        sev::firmware::guest::AttestationReport::from_bytes(&fixture.snp_report)
            .expect("parse fixture report")
            .report_data
    }

    fn fixture_identity(fixture: &ProveItLiveFixture) -> TeardownIdentity {
        let report =
            enclava_verifier::parse_snp_report(&fixture.snp_report).expect("parse fixture report");
        TeardownIdentity {
            expected_cc_init_data_hash: report.host_data,
            expected_firmware_measurement: FirmwareMeasurement::Full(report.measurement),
        }
    }

    #[test]
    fn configured_kds_vcek_prefix_is_not_duplicated() {
        let fixture = prove_it_live_fixture();
        let mut report = sev::firmware::guest::AttestationReport::from_bytes(&fixture.snp_report)
            .expect("fixture report");
        report.cpuid_fam_id = Some(0x19);
        report.cpuid_mod_id = Some(0x11);
        report.chip_id = [7; 64];
        let url = amd_kds_vcek_url(&report, "http://amd-kds-relay:8080/vcek/v1")
            .expect("configured relay URL");
        assert_eq!(
            reqwest::Url::parse(&url).expect("VCEK URL").path(),
            format!("/vcek/v1/Genoa/{}", hex::encode([7; 64]))
        );
    }

    #[tokio::test]
    async fn evidence_with_pinned_chain_and_bound_identity_verifies() {
        let fixture = prove_it_live_fixture();
        let evidence = AttestationEvidence {
            payload_b64: String::new(),
            json: Some(fixture_evidence(&fixture)),
        };
        verify_snp_evidence(
            &evidence,
            b"",
            &fixture_report_data(&fixture),
            &[fixture_identity(&fixture)],
            None,
        )
        .await
        .expect("correctly evidenced launch identity must verify offline");
    }

    #[tokio::test]
    async fn evidence_fails_closed_on_wrong_report_data_binding() {
        let fixture = prove_it_live_fixture();
        let evidence = AttestationEvidence {
            payload_b64: String::new(),
            json: Some(fixture_evidence(&fixture)),
        };
        let err = verify_snp_evidence(
            &evidence,
            b"",
            &[0x42; 64],
            &[fixture_identity(&fixture)],
            None,
        )
        .await
        .expect_err("evidence for another nonce/domain/leaf must be rejected");
        assert!(matches!(err, TeeAttestError::Attestation(_)));
    }

    #[tokio::test]
    async fn evidence_fails_closed_when_launch_identity_is_unbound() {
        let fixture = prove_it_live_fixture();
        let evidence = AttestationEvidence {
            payload_b64: String::new(),
            json: Some(fixture_evidence(&fixture)),
        };
        // A valid TEE launch whose HOST_DATA matches no admissible deployment
        // (wrong app, or a superseded deployment outside the live set).
        let foreign = TeardownIdentity {
            expected_cc_init_data_hash: [0xAA; 32],
            expected_firmware_measurement: fixture_identity(&fixture).expected_firmware_measurement,
        };
        let err = verify_snp_evidence(
            &evidence,
            b"",
            &fixture_report_data(&fixture),
            &[foreign],
            None,
        )
        .await
        .expect_err("evidence bound to no live deployment must be rejected");
        assert!(matches!(err, TeeAttestError::Attestation(_)));
    }

    #[tokio::test]
    async fn evidence_rejects_wrong_firmware_even_with_matching_app_host_data() {
        let fixture = prove_it_live_fixture();
        let evidence = AttestationEvidence {
            payload_b64: String::new(),
            json: Some(fixture_evidence(&fixture)),
        };
        let mut identity = fixture_identity(&fixture);
        identity.expected_firmware_measurement = FirmwareMeasurement::Full([0xAB; 48]);
        let error = verify_snp_evidence(
            &evidence,
            b"",
            &fixture_report_data(&fixture),
            &[identity],
            None,
        )
        .await
        .expect_err("a different measured firmware must not receive a teardown token");
        assert!(matches!(error, TeeAttestError::Attestation(_)));
    }

    #[tokio::test]
    async fn evidence_with_unanchored_ark_is_not_trusted() {
        let fixture = prove_it_live_fixture();
        let mut evidence_json = fixture_evidence(&fixture);
        // Swap the anchored ARK for an attacker-supplied certificate: even if
        // DER-valid it must never anchor the chain (KDS fallback would run,
        // but the pin check itself is the assertion target).
        evidence_json["cert_chain"] = serde_json::json!([
            {"cert_type": "ARK", "data": fixture.ask_der},
            {"cert_type": "ASK", "data": fixture.ask_der},
            {"cert_type": "VCEK", "data": fixture.vcek_der},
        ]);
        let chain = extract_snp_der_chain(&evidence_json).expect("chain extracted");
        assert!(!ark_is_pinned_to_builtin_root(&chain.ark_der));
        assert!(ark_is_pinned_to_builtin_root(&fixture.ark_der));
    }

    #[test]
    fn report_data_rejects_debug_guest_policy() {
        // The same bit the CLI's production-policy check and the unlock
        // transition gate enforce.
        assert!(snp_guest_policy_allows_debug(1 << 19));
        assert!(!snp_guest_policy_allows_debug(0));
    }

    /// Serves a fresh self-signed leaf for real TLS verification tests.
    async fn spawn_attestation_server(
        domain: &'static str,
        respond: impl Fn(&str, [u8; 32]) -> String + Send + Sync + 'static,
    ) -> SocketAddr {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_rustls::TlsAcceptor;

        let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec![domain.to_string()])
            .expect("self-signed certificate");
        let leaf_spki_sha256 = enclava_verifier::tls_leaf_spki_sha256(cert.cert.der().as_ref())
            .expect("test leaf SPKI");
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    cert.cert.der().to_vec(),
                )],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.signing_key.serialize_der().into(),
                ),
            )
            .expect("TLS server config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
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
                let response_body = respond(&request_line, leaf_spki_sha256);
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        address
    }

    fn query_param(request_line: &str, name: &str) -> Option<String> {
        let path = request_line.split_whitespace().nth(1)?;
        let (_, query) = path.split_once('?')?;
        for pair in query.split('&') {
            let (key, value) = pair.split_once('=')?;
            if key == name {
                return Some(value.to_string());
            }
        }
        None
    }

    fn attestation_body(
        domain: &str,
        nonce: String,
        leaf_spki_sha256: [u8; 32],
        evidence_json: serde_json::Value,
    ) -> String {
        serde_json::json!({
            "nonce": nonce,
            "runtime_data_binding": {
                "domain": domain,
                "leaf_spki_sha256": hex::encode(leaf_spki_sha256),
                "receipt_pubkey_sha256": "00".repeat(32),
            },
            "evidence": {
                "payload_b64": "",
                "json": evidence_json,
            },
        })
        .to_string()
    }

    fn teardown_test_identity() -> TeardownIdentity {
        TeardownIdentity {
            expected_cc_init_data_hash: [7; 32],
            expected_firmware_measurement: FirmwareMeasurement::Full([9; 48]),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn self_signed_peer_without_hardware_evidence_is_rejected() {
        let domain = "tee.app.example";
        let socket = spawn_attestation_server(domain, move |request_line, leaf_spki| {
            attestation_body(
                domain,
                query_param(request_line, "nonce").unwrap_or_default(),
                leaf_spki,
                serde_json::json!({"note": "no snp report"}),
            )
        })
        .await;

        let error = attest_teardown_channel(
            &format!("{domain}:{}", socket.port()),
            Some(socket.ip()),
            &[teardown_test_identity()],
            None,
        )
        .await
        .expect_err("mock evidence without a raw SNP report must fail closed");
        assert!(matches!(error, TeeAttestError::Attestation(_)));
    }

    #[tokio::test]
    async fn pinned_client_accepts_only_the_negotiated_tls_key() {
        let domain = "tee.app.example";
        let socket = spawn_attestation_server(domain, |_, _| "{}".to_string()).await;
        let timeout = Duration::from_secs(5);
        let leaf = fetch_tls_leaf_cert_der(domain, socket.port(), Some(socket), timeout)
            .await
            .expect("learn self-signed leaf");
        let spki = enclava_verifier::tls_leaf_spki_sha256(&leaf).expect("leaf SPKI");
        let url = format!("https://{domain}:{}/attestation", socket.port());
        let client =
            build_spki_pinned_client(spki, timeout, domain, Some(socket)).expect("pinned client");
        assert_eq!(
            client
                .get(&url)
                .send()
                .await
                .expect("matching key")
                .status(),
            reqwest::StatusCode::OK
        );
        let mut foreign_spki = spki;
        foreign_spki[0] ^= 1;
        let foreign = build_spki_pinned_client(foreign_spki, timeout, domain, Some(socket))
            .expect("foreign-key client");
        assert!(foreign.get(&url).send().await.is_err());
    }
}
