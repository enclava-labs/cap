use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64_STANDARD, URL_SAFE, URL_SAFE_NO_PAD},
};
use rand::{RngCore, rngs::OsRng};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::Deserialize;
use sev::parser::ByteParser;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::{Decode, Encode};

use enclava_common::canonical::ce_v1_hash;

use crate::api_types::{SignedReceiptResponse, TransitionReceiptAttestation};
use crate::attestation::{tee_tls_transcript_hash, validate_snp_report_with_der_chain};

const AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com";
const AMD_KDS_VCEK_MAX_ATTEMPTS: usize = 8;
pub const DEFAULT_TEE_REQUEST_TIMEOUT_SECONDS: u64 = 180;
pub const OWNERSHIP_TEE_REQUEST_TIMEOUT_SECONDS: u64 = 900;
pub const OWNERSHIP_TEE_PROBE_TIMEOUT_SECONDS: u64 = 15;

/// Direct HTTPS client for the attestation proxy running inside a TEE.
/// All requests go to https://{app-domain}/.well-known/confidential/...
pub struct TeeClient {
    confidential_base_url: String,
    http: reqwest::Client,
    timeout: std::time::Duration,
    resolve_ip: Option<IpAddr>,
}

fn accepts_invalid_tee_certs() -> bool {
    std::env::var("ENCLAVA_TEE_TLS_MODE")
        .map(|mode| matches!(mode.as_str(), "staging" | "insecure"))
        .unwrap_or(false)
        || std::env::var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("TEE error ({status}): {message}")]
    Tee { status: u16, message: String },
    #[error("invalid TEE request header: {0}")]
    InvalidHeader(#[from] reqwest::header::InvalidHeaderValue),
    #[error("TEE attestation error: {0}")]
    Attestation(String),
}

#[derive(Debug, Deserialize)]
struct AttestationResponse {
    nonce: String,
    runtime_data_binding: RuntimeDataBinding,
    evidence: AttestationEvidence,
}

#[derive(Debug, Deserialize)]
struct RuntimeDataBinding {
    domain: String,
    leaf_spki_sha256: String,
    receipt_pubkey_sha256: String,
}

#[derive(Debug, Deserialize)]
struct AttestationEvidence {
    payload_b64: String,
    #[serde(default)]
    json: Option<serde_json::Value>,
}

/// Response from the bootstrap challenge endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    #[serde(
        alias = "expires_in_seconds",
        deserialize_with = "deserialize_seconds_as_u64"
    )]
    pub ttl_seconds: u64,
}

/// Response from the claim endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct ClaimResponse {
    pub status: String,
    /// BIP39 mnemonic backup (shown to user once, never stored by CLI)
    pub mnemonic: Option<String>,
}

/// Response from status endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct TeeStatusResponse {
    pub ownership_state: String,
    pub unlock_state: String,
    pub auto_unlock_enabled: bool,
}

fn deserialize_seconds_as_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Number(number) => {
            if let Some(seconds) = number.as_u64() {
                return Ok(seconds);
            }
            number
                .as_f64()
                .filter(|seconds| seconds.is_finite() && *seconds >= 0.0)
                .map(|seconds| seconds as u64)
                .ok_or_else(|| serde::de::Error::custom("invalid seconds value"))
        }
        other => Err(serde::de::Error::custom(format!(
            "expected seconds number, got {other}"
        ))),
    }
}

impl TeeClient {
    /// Create a TEE client for the given app domain.
    /// The domain is the HTTPS endpoint of the app (e.g., "myapp.enclava.dev").
    pub fn new(app_domain: &str) -> Self {
        Self::new_with_timeout_and_resolve_ip(
            app_domain,
            std::time::Duration::from_secs(DEFAULT_TEE_REQUEST_TIMEOUT_SECONDS),
            None,
        )
    }

    pub fn new_with_resolve_ip(app_domain: &str, resolve_ip: Option<IpAddr>) -> Self {
        Self::new_with_timeout_and_resolve_ip(
            app_domain,
            std::time::Duration::from_secs(DEFAULT_TEE_REQUEST_TIMEOUT_SECONDS),
            resolve_ip,
        )
    }

    /// Create a TEE client for ownership claim/unlock requests.
    pub fn new_for_ownership(app_domain: &str) -> Self {
        Self::new_with_timeout_and_resolve_ip(
            app_domain,
            std::time::Duration::from_secs(OWNERSHIP_TEE_REQUEST_TIMEOUT_SECONDS),
            None,
        )
    }

    pub fn new_for_ownership_with_resolve_ip(app_domain: &str, resolve_ip: Option<IpAddr>) -> Self {
        Self::new_with_timeout_and_resolve_ip(
            app_domain,
            std::time::Duration::from_secs(OWNERSHIP_TEE_REQUEST_TIMEOUT_SECONDS),
            resolve_ip,
        )
    }

    pub fn new_for_ownership_probe_with_resolve_ip(
        app_domain: &str,
        resolve_ip: Option<IpAddr>,
    ) -> Self {
        Self::new_with_timeout_and_resolve_ip(
            app_domain,
            std::time::Duration::from_secs(OWNERSHIP_TEE_PROBE_TIMEOUT_SECONDS),
            resolve_ip,
        )
    }

    /// Create a TEE client with a custom request timeout.
    pub fn new_with_timeout(app_domain: &str, timeout: std::time::Duration) -> Self {
        Self::new_with_timeout_and_resolve_ip(app_domain, timeout, None)
    }

    fn new_with_timeout_and_resolve_ip(
        app_domain: &str,
        timeout: std::time::Duration,
        resolve_ip: Option<IpAddr>,
    ) -> Self {
        let base_url = if app_domain.starts_with("https://") || app_domain.starts_with("http://") {
            app_domain.trim_end_matches('/').to_string()
        } else {
            format!("https://{}", app_domain.trim_end_matches('/'))
        };
        let confidential_base_url = if base_url.ends_with("/.well-known/confidential") {
            base_url
        } else {
            format!("{base_url}/.well-known/confidential")
        };
        let http = build_tee_http_client(&confidential_base_url, timeout, resolve_ip)
            .expect("failed to build HTTP client");

        Self {
            confidential_base_url,
            http,
            timeout,
            resolve_ip,
        }
    }

    pub fn from_config_url(config_url: &str) -> Self {
        Self::from_config_url_with_resolve_ip(config_url, None)
    }

    pub fn from_config_url_with_resolve_ip(config_url: &str, resolve_ip: Option<IpAddr>) -> Self {
        let trimmed = config_url.trim_end_matches('/');
        let base = trimmed.strip_suffix("/config").unwrap_or(trimmed);
        Self::new_with_resolve_ip(base, resolve_ip)
    }

    fn with_http(&self, http: reqwest::Client) -> Self {
        Self {
            confidential_base_url: self.confidential_base_url.clone(),
            http,
            timeout: self.timeout,
            resolve_ip: self.resolve_ip,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.confidential_base_url, path)
    }

    async fn check_response(&self, resp: reqwest::Response) -> Result<reqwest::Response, TeeError> {
        let status = resp.status();
        if status.is_success() {
            Ok(resp)
        } else {
            let status_code = status.as_u16();
            let message = resp
                .text()
                .await
                .unwrap_or_else(|_| format!("HTTP {status_code}"));
            Err(TeeError::Tee {
                status: status_code,
                message,
            })
        }
    }

    // --- Config operations (require API-issued JWT) ---

    fn config_bearer_header(config_token: &str) -> Result<HeaderValue, TeeError> {
        Ok(HeaderValue::from_str(&format!("Bearer {config_token}"))?)
    }

    /// Set a config key/value pair on the TEE's encrypted filesystem.
    pub async fn config_set(
        &self,
        key: &str,
        value: &str,
        config_token: &str,
    ) -> Result<(), TeeError> {
        let resp = self
            .http
            .put(self.url(&format!("/config/{key}")))
            .header(AUTHORIZATION, Self::config_bearer_header(config_token)?)
            .header(CONTENT_TYPE, "text/plain")
            .body(value.to_string())
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Delete a config key from the TEE's encrypted filesystem.
    pub async fn config_unset(&self, key: &str, config_token: &str) -> Result<(), TeeError> {
        let resp = self
            .http
            .delete(self.url(&format!("/config/{key}")))
            .header(AUTHORIZATION, Self::config_bearer_header(config_token)?)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    // --- Status ---

    /// Get the TEE's ownership and unlock status.
    pub async fn status(&self) -> Result<TeeStatusResponse, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    pub async fn status_json(&self) -> Result<serde_json::Value, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Return whether the TEE status shows ownership has already been claimed.
    ///
    /// The claim endpoint can commit ownership and then close the connection
    /// before the client receives the response. Callers use this as an
    /// idempotence check after an indeterminate claim transport error.
    pub async fn claim_state_is_successful(&self) -> Result<bool, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        let body = resp.json::<serde_json::Value>().await?;
        Ok(claim_state_json_is_successful(&body))
    }

    // --- Ownership operations (direct to TEE, no API token) ---

    /// Request a bootstrap challenge for first-time ownership claim.
    pub async fn bootstrap_challenge(&self) -> Result<ChallengeResponse, TeeError> {
        let resp = self
            .http
            .post(self.url("/bootstrap/challenge"))
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Claim ownership of the app (first-time setup, password mode).
    pub async fn bootstrap_claim(
        &self,
        challenge_nonce: &str,
        bootstrap_pubkey: &str,
        signature: &str,
        password: &str,
    ) -> Result<ClaimResponse, TeeError> {
        let body = serde_json::json!({
            "challenge": challenge_nonce,
            "bootstrap_pubkey": bootstrap_pubkey,
            "signature": signature,
            "password": password,
        });
        let resp = self
            .http
            .post(self.url("/bootstrap/claim"))
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        Ok(resp.json().await?)
    }

    /// Unlock storage with password (subsequent restarts, password mode).
    pub async fn unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Recover with BIP39 mnemonic and set a new password.
    pub async fn recover(&self, mnemonic: &str, new_password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({
            "mnemonic": mnemonic,
            "new_password": new_password,
        });
        let resp = self
            .http
            .post(self.url("/recover"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Change the unlock password.
    pub async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), TeeError> {
        let body = change_password_body(current_password, new_password);
        let resp = self
            .http
            .post(self.url("/change-password"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Enable auto-unlock (seal owner seed with VMPCK).
    pub async fn enable_auto_unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/enable-auto-unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Disable auto-unlock (remove sealed seed).
    pub async fn disable_auto_unlock(&self, password: &str) -> Result<(), TeeError> {
        let body = serde_json::json!({ "password": password });
        let resp = self
            .http
            .post(self.url("/disable-auto-unlock"))
            .json(&body)
            .send()
            .await?;
        self.check_response(resp).await?;
        Ok(())
    }

    /// Sign an unlock-mode transition receipt with the in-TEE receipt key.
    pub async fn sign_unlock_mode_transition(
        &self,
        app_id: &str,
        from_mode: &str,
        to_mode: &str,
        attestation: &TransitionReceiptAttestation,
    ) -> Result<SignedReceiptResponse, TeeError> {
        let body = serde_json::json!({
            "receipt_type": "unlock_mode_transition",
            "app_id": app_id,
            "from_mode": normalize_unlock_mode(from_mode),
            "to_mode": normalize_unlock_mode(to_mode),
            "attestation_quote_sha256": attestation.attestation_evidence_sha256,
        });
        let resp = self
            .http
            .post(self.url("/receipts/sign"))
            .json(&body)
            .send()
            .await?;
        let resp = self.check_response(resp).await?;
        let receipt: SignedReceiptResponse = resp.json().await?;
        verify_receipt_matches_attestation(&receipt, attestation)?;
        Ok(receipt)
    }

    /// Fetch SNP evidence for the current TEE TLS leaf and return a client pinned to that leaf.
    pub async fn attest_receipt_key(
        &self,
    ) -> Result<(TransitionReceiptAttestation, TeeClient), TeeError> {
        let endpoint = EndpointParts::parse(&self.confidential_base_url)?;
        let leaf_spki_der =
            fetch_tls_leaf_spki_der(&endpoint.host, endpoint.port, self.resolve_ip).await?;
        let leaf_spki_sha256: [u8; 32] = Sha256::digest(&leaf_spki_der).into();
        let pinned_http = build_spki_pinned_client(
            leaf_spki_sha256,
            self.timeout,
            &endpoint.host,
            endpoint.port,
            self.resolve_ip,
        )?;

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce);
        let leaf_spki_hex = hex::encode(leaf_spki_sha256);
        let mut attestation_url = reqwest::Url::parse(&self.url("/attestation"))
            .map_err(|err| TeeError::Attestation(format!("invalid attestation URL: {err}")))?;
        attestation_url
            .query_pairs_mut()
            .append_pair("nonce", nonce_b64.as_str())
            .append_pair("domain", endpoint.host.as_str())
            .append_pair("leaf_spki_sha256", leaf_spki_hex.as_str());
        let resp = pinned_http.get(attestation_url).send().await?;
        let resp = self.check_response(resp).await?;
        let attestation: AttestationResponse = resp.json().await?;
        if attestation.nonce != nonce_b64 {
            return Err(TeeError::Attestation("nonce mismatch".to_string()));
        }
        if attestation.runtime_data_binding.domain != endpoint.host {
            return Err(TeeError::Attestation("domain mismatch".to_string()));
        }
        if attestation.runtime_data_binding.leaf_spki_sha256 != leaf_spki_hex {
            return Err(TeeError::Attestation("leaf SPKI mismatch".to_string()));
        }
        let receipt_pubkey_sha256 = parse_hex32_field(
            "runtime_data_binding.receipt_pubkey_sha256",
            &attestation.runtime_data_binding.receipt_pubkey_sha256,
        )?;
        let expected_report_data = tee_tls_report_data(
            &endpoint.host,
            &nonce,
            &leaf_spki_sha256,
            &receipt_pubkey_sha256,
        );

        let evidence = B64_STANDARD
            .decode(attestation.evidence.payload_b64.as_bytes())
            .map_err(|_| TeeError::Attestation("evidence payload is not base64".to_string()))?;
        verify_evidence_report_data(&attestation.evidence, &evidence, &expected_report_data)
            .await?;
        let evidence_sha256 = hex::encode(Sha256::digest(evidence));
        let transition_attestation = TransitionReceiptAttestation {
            tee_domain: endpoint.host,
            nonce: nonce_b64,
            leaf_spki_sha256: leaf_spki_hex,
            receipt_pubkey_sha256: attestation.runtime_data_binding.receipt_pubkey_sha256,
            attestation_evidence_sha256: evidence_sha256,
        };
        Ok((transition_attestation, self.with_http(pinned_http)))
    }
}

fn build_tee_http_client(
    confidential_base_url: &str,
    timeout: std::time::Duration,
    resolve_ip: Option<IpAddr>,
) -> Result<reqwest::Client, TeeError> {
    let accept_invalid_certs = accepts_invalid_tee_certs();
    let mut builder = reqwest::Client::builder()
        .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .danger_accept_invalid_certs(accept_invalid_certs)
        .https_only(true);
    if let Some(resolve_ip) = resolve_ip {
        let endpoint = EndpointParts::parse(confidential_base_url)?;
        builder = builder.resolve(
            endpoint.host.as_str(),
            SocketAddr::new(resolve_ip, endpoint.port),
        );
    }
    builder.build().map_err(TeeError::Http)
}

fn claim_state_json_is_successful(body: &serde_json::Value) -> bool {
    let ownership_state = body.get("ownership_state").and_then(|value| value.as_str());
    let legacy_state = body.get("state").and_then(|value| value.as_str());

    matches!(ownership_state, Some("claimed"))
        || (ownership_state.is_none() && matches!(legacy_state, Some("claimed")))
}

fn change_password_body(current_password: &str, new_password: &str) -> serde_json::Value {
    serde_json::json!({
        "old_password": current_password,
        "new_password": new_password,
    })
}

fn normalize_unlock_mode(mode: &str) -> &str {
    match mode {
        "auto" | "auto-unlock" => "auto",
        "password" => "password",
        other => other,
    }
}

fn tee_tls_report_data(
    domain: &str,
    nonce: &[u8; 32],
    leaf_spki_sha256: &[u8; 32],
    receipt_pubkey_sha256: &[u8; 32],
) -> [u8; 64] {
    let transcript_hash = tee_tls_transcript_hash(domain, nonce, leaf_spki_sha256);
    let binding_hash = ce_v1_hash(&[
        ("purpose", b"enclava-tee-report-data-v1"),
        ("transcript_hash", &transcript_hash),
        ("receipt_pubkey_sha256", receipt_pubkey_sha256),
    ]);
    let binding_hex = hex::encode(binding_hash);
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(binding_hex.as_bytes());
    report_data
}

fn verify_receipt_matches_attestation(
    receipt: &SignedReceiptResponse,
    attestation: &TransitionReceiptAttestation,
) -> Result<(), TeeError> {
    let pubkey = base64::engine::general_purpose::STANDARD
        .decode(receipt.receipt.pubkey.as_bytes())
        .map_err(|_| TeeError::Attestation("receipt pubkey is not base64".to_string()))?;
    let pubkey_hash = hex::encode(Sha256::digest(pubkey));
    if pubkey_hash != receipt.receipt.pubkey_sha256 {
        return Err(TeeError::Attestation(
            "receipt pubkey hash is inconsistent".to_string(),
        ));
    }
    if pubkey_hash != attestation.receipt_pubkey_sha256 {
        return Err(TeeError::Attestation(
            "receipt pubkey was not the attested TEE receipt key".to_string(),
        ));
    }
    if receipt.payload.attestation_quote_sha256.as_deref()
        != Some(attestation.attestation_evidence_sha256.as_str())
    {
        return Err(TeeError::Attestation(
            "receipt does not bind the attestation evidence hash".to_string(),
        ));
    }
    Ok(())
}

async fn verify_evidence_report_data(
    evidence: &AttestationEvidence,
    evidence_bytes: &[u8],
    expected_report_data: &[u8; 64],
) -> Result<(), TeeError> {
    verify_evidence_report_data_with_json_fallback(
        evidence,
        evidence_bytes,
        expected_report_data,
        allows_json_report_data_only(),
    )
    .await
}

async fn verify_evidence_report_data_with_json_fallback(
    evidence: &AttestationEvidence,
    evidence_bytes: &[u8],
    expected_report_data: &[u8; 64],
    allow_json_report_data_only: bool,
) -> Result<(), TeeError> {
    let evidence_json = evidence
        .json
        .as_ref()
        .cloned()
        .or_else(|| serde_json::from_slice(evidence_bytes).ok());
    let Some(evidence_json) = evidence_json else {
        return Err(TeeError::Attestation(
            "attestation evidence is not parseable JSON".to_string(),
        ));
    };

    if let Some(snp_report_bytes) = extract_snp_report_bytes(&evidence_json) {
        let chain = match extract_snp_der_chain(&evidence_json) {
            Some(chain) => chain,
            None => fetch_snp_der_chain_from_kds(&snp_report_bytes).await?,
        };
        let report = validate_snp_report_with_der_chain(
            &snp_report_bytes,
            &chain.ark_der,
            &chain.ask_der,
            &chain.vcek_der,
        )
        .map_err(|err| TeeError::Attestation(err.to_string()))?;
        if &report.report_data != expected_report_data {
            return Err(TeeError::Attestation(
                "SNP report_data does not bind nonce, TLS leaf SPKI, and receipt key".to_string(),
            ));
        }
        return Ok(());
    }

    if !allow_json_report_data_only {
        return Err(TeeError::Attestation(
            "attestation evidence does not contain a raw AMD SNP report".to_string(),
        ));
    }

    let report_data = extract_report_data(&evidence_json).ok_or_else(|| {
        TeeError::Attestation("attestation evidence does not contain SNP report_data".to_string())
    })?;
    if &report_data != expected_report_data {
        return Err(TeeError::Attestation(
            "SNP report_data does not bind nonce, TLS leaf SPKI, and receipt key".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct SnpDerChain {
    ark_der: Vec<u8>,
    ask_der: Vec<u8>,
    vcek_der: Vec<u8>,
}

fn allows_json_report_data_only() -> bool {
    #[cfg(debug_assertions)]
    {
        std::env::var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
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
                    && bytes.len() == 1184
                {
                    return Some(bytes);
                }
            }
            map.values().find_map(extract_snp_report_bytes)
        }
        serde_json::Value::Array(values) => parse_bytes_value(value)
            .filter(|bytes| bytes.len() == 1184)
            .or_else(|| values.iter().find_map(extract_snp_report_bytes)),
        _ => None,
    }
}

fn extract_snp_der_chain(value: &serde_json::Value) -> Option<SnpDerChain> {
    if let Some(chain) = extract_coco_cert_chain(value) {
        return Some(chain);
    }
    Some(SnpDerChain {
        ark_der: extract_named_bytes(value, &["ark", "arkder", "arkcert", "arkcertificate"])?,
        ask_der: extract_named_bytes(value, &["ask", "askder", "askcert", "askcertificate"])?,
        vcek_der: extract_named_bytes(value, &["vcek", "vcekder", "vcekcert", "vcekcertificate"])?,
    })
}

async fn fetch_snp_der_chain_from_kds(snp_report_bytes: &[u8]) -> Result<SnpDerChain, TeeError> {
    let report = sev::firmware::guest::AttestationReport::from_bytes(snp_report_bytes)
        .map_err(|err| TeeError::Attestation(format!("SNP report parse failed: {err}")))?;
    let (ark_der, ask_der) = builtin_snp_ca_der_chain(&report)?;
    let vcek_url = amd_kds_vcek_url(&report, AMD_KDS_BASE_URL)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let vcek_der = fetch_amd_kds_vcek_der(&client, &vcek_url).await?;

    Ok(SnpDerChain {
        ark_der,
        ask_der,
        vcek_der,
    })
}

fn amd_kds_vcek_should_retry(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn amd_kds_vcek_retry_delay(attempt_index: usize) -> std::time::Duration {
    let seconds = match attempt_index {
        0 => 2,
        1 => 5,
        2 => 10,
        3 => 20,
        _ => 30,
    };
    std::time::Duration::from_secs(seconds)
}

async fn fetch_amd_kds_vcek_der(
    client: &reqwest::Client,
    vcek_url: &str,
) -> Result<Vec<u8>, TeeError> {
    let mut last_error = None;

    for attempt in 0..AMD_KDS_VCEK_MAX_ATTEMPTS {
        match client.get(vcek_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                if !status.is_success() {
                    if amd_kds_vcek_should_retry(status) && attempt + 1 < AMD_KDS_VCEK_MAX_ATTEMPTS
                    {
                        tokio::time::sleep(amd_kds_vcek_retry_delay(attempt)).await;
                        continue;
                    }
                    return Err(TeeError::Attestation(format!(
                        "AMD KDS VCEK fetch failed: HTTP status {status} for url ({vcek_url})"
                    )));
                }

                return resp
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .map_err(|err| {
                        TeeError::Attestation(format!("AMD KDS VCEK body read failed: {err}"))
                    });
            }
            Err(err) => {
                let message = err.to_string();
                if attempt + 1 < AMD_KDS_VCEK_MAX_ATTEMPTS {
                    last_error = Some(message);
                    tokio::time::sleep(amd_kds_vcek_retry_delay(attempt)).await;
                    continue;
                }
                return Err(TeeError::Attestation(format!(
                    "AMD KDS VCEK request failed: {message}"
                )));
            }
        }
    }

    Err(TeeError::Attestation(format!(
        "AMD KDS VCEK request failed after retries: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )))
}

fn builtin_snp_ca_der_chain(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<(Vec<u8>, Vec<u8>), TeeError> {
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
        .map_err(|err| TeeError::Attestation(format!("AMD ARK parse failed: {err}")))?
        .to_der()
        .map_err(|err| TeeError::Attestation(format!("AMD ARK DER encode failed: {err}")))?;
    let ask_der = ask
        .map_err(|err| TeeError::Attestation(format!("AMD ASK parse failed: {err}")))?
        .to_der()
        .map_err(|err| TeeError::Attestation(format!("AMD ASK DER encode failed: {err}")))?;
    Ok((ark_der, ask_der))
}

fn amd_kds_vcek_url(
    report: &sev::firmware::guest::AttestationReport,
    base_url: &str,
) -> Result<String, TeeError> {
    if report.chip_id == [0u8; 64] {
        return Err(TeeError::Attestation(
            "SNP report masks chip_id; cannot fetch VCEK from AMD KDS".to_string(),
        ));
    }
    if report.key_info.signing_key() != 0 {
        return Err(TeeError::Attestation(
            "SNP report was not signed by VCEK; AMD KDS VCEK fallback is not applicable"
                .to_string(),
        ));
    }

    let generation = snp_report_generation(report)?;
    let tcb = report.reported_tcb;
    let hw_id = hex::encode(report.chip_id);
    let base = base_url.trim_end_matches('/');
    if matches!(generation, sev::Generation::Turin) {
        let fmc = tcb.fmc.ok_or_else(|| {
            TeeError::Attestation("Turin SNP report missing fmc TCB value".to_string())
        })?;
        Ok(format!(
            "{base}/vcek/v1/{}/{hw_id}?fmcSPL={fmc:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            generation.titlecase(),
            tcb.bootloader,
            tcb.tee,
            tcb.snp,
            tcb.microcode
        ))
    } else {
        Ok(format!(
            "{base}/vcek/v1/{}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
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
) -> Result<sev::Generation, TeeError> {
    let family = report.cpuid_fam_id.ok_or_else(|| {
        TeeError::Attestation("SNP report missing CPUID family for VCEK lookup".to_string())
    })?;
    let model = report.cpuid_mod_id.ok_or_else(|| {
        TeeError::Attestation("SNP report missing CPUID model for VCEK lookup".to_string())
    })?;
    sev::Generation::identify_cpu(family, model)
        .map_err(|err| TeeError::Attestation(format!("unknown SNP CPU generation: {err}")))
}

fn extract_structured_snp_report_bytes(value: &serde_json::Value) -> Option<Vec<u8>> {
    if !value.is_object() {
        return None;
    }
    let report: sev::firmware::guest::AttestationReport =
        serde_json::from_value(value.clone()).ok()?;
    let bytes = report.to_bytes().ok()?;
    Some(bytes.as_ref().to_vec())
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
                        ark_der: ark_der?,
                        ask_der: ask_der?,
                        vcek_der: vcek_der?,
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

fn extract_report_data(value: &serde_json::Value) -> Option<[u8; 64]> {
    match value {
        serde_json::Value::Object(map) => {
            for key in [
                "report_data",
                "reportData",
                "report-data",
                "REPORT_DATA",
                "runtime_data",
                "runtimeData",
            ] {
                if let Some(bytes) = map.get(key).and_then(parse_bytes64_value) {
                    return Some(bytes);
                }
            }
            map.values().find_map(extract_report_data)
        }
        serde_json::Value::Array(values) => {
            parse_bytes64_value(value).or_else(|| values.iter().find_map(extract_report_data))
        }
        _ => None,
    }
}

fn parse_bytes64_value(value: &serde_json::Value) -> Option<[u8; 64]> {
    parse_bytes_value(value)?.try_into().ok()
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

fn parse_hex32_field(field: &str, value: &str) -> Result<[u8; 32], TeeError> {
    let bytes = hex::decode(value.trim())
        .map_err(|err| TeeError::Attestation(format!("{field} is not hex: {err}")))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        TeeError::Attestation(format!("{field} must be 32 bytes, got {}", bytes.len()))
    })
}

mod tls;
use tls::{EndpointParts, build_spki_pinned_client, fetch_tls_leaf_spki_der};

#[cfg(test)]
#[path = "tee_client/tests/mod.rs"]
mod tests;
