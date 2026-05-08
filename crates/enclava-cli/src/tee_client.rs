use std::sync::Arc;

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
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_cert::der::{Decode, Encode};

use enclava_common::canonical::ce_v1_hash;

use crate::api_types::{SignedReceiptResponse, TransitionReceiptAttestation};
use crate::attestation::{tee_tls_transcript_hash, validate_snp_report_with_der_chain};

/// Direct HTTPS client for the attestation proxy running inside a TEE.
/// All requests go to https://{app-domain}/.well-known/confidential/...
pub struct TeeClient {
    confidential_base_url: String,
    http: reqwest::Client,
    timeout: std::time::Duration,
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
        Self::new_with_timeout(app_domain, std::time::Duration::from_secs(180))
    }

    /// Create a TEE client with a custom request timeout.
    pub fn new_with_timeout(app_domain: &str, timeout: std::time::Duration) -> Self {
        let accept_invalid_certs = accepts_invalid_tee_certs();
        let http = reqwest::Client::builder()
            .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .danger_accept_invalid_certs(accept_invalid_certs)
            .https_only(true) // Enforce HTTPS
            .build()
            .expect("failed to build HTTP client");

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

        Self {
            confidential_base_url,
            http,
            timeout,
        }
    }

    fn with_http(&self, http: reqwest::Client) -> Self {
        Self {
            confidential_base_url: self.confidential_base_url.clone(),
            http,
            timeout: self.timeout,
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
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {config_token}")).unwrap(),
            )
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
            .header(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {config_token}")).unwrap(),
            )
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

    /// Return whether the TEE status shows ownership has already been claimed.
    ///
    /// The claim endpoint can commit ownership and then close the connection
    /// before the client receives the response. Callers use this as an
    /// idempotence check after an indeterminate claim transport error.
    pub async fn claim_state_is_successful(&self) -> Result<bool, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        let resp = self.check_response(resp).await?;
        let body = resp.json::<serde_json::Value>().await?;
        let state = body
            .get("ownership_state")
            .or_else(|| body.get("state"))
            .and_then(|value| value.as_str());
        let unlock_state = body.get("unlock_state").and_then(|value| value.as_str());

        Ok(matches!(state, Some("claimed" | "unlocked"))
            || matches!(unlock_state, Some("unlocked")))
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
        let leaf_spki_der = fetch_tls_leaf_spki_der(&endpoint.host, endpoint.port).await?;
        let leaf_spki_sha256: [u8; 32] = Sha256::digest(&leaf_spki_der).into();
        let pinned_http = build_spki_pinned_client(leaf_spki_sha256, self.timeout)?;

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
        verify_evidence_report_data(&attestation.evidence, &evidence, &expected_report_data)?;
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

fn verify_evidence_report_data(
    evidence: &AttestationEvidence,
    evidence_bytes: &[u8],
    expected_report_data: &[u8; 64],
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
        let chain = extract_snp_der_chain(&evidence_json).ok_or_else(|| {
            TeeError::Attestation(
                "SNP evidence contains a raw report but is missing ARK/ASK/VCEK DER certificates"
                    .to_string(),
            )
        })?;
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

    if !allows_json_report_data_only() {
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
    Some(SnpDerChain {
        ark_der: extract_named_bytes(value, &["ark", "arkder", "arkcert", "arkcertificate"])?,
        ask_der: extract_named_bytes(value, &["ask", "askder", "askcert", "askcertificate"])?,
        vcek_der: extract_named_bytes(value, &["vcek", "vcekder", "vcekcert", "vcekcertificate"])?,
    })
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

struct EndpointParts {
    host: String,
    port: u16,
}

impl EndpointParts {
    fn parse(base: &str) -> Result<Self, TeeError> {
        let url = reqwest::Url::parse(base)
            .map_err(|err| TeeError::Attestation(format!("invalid TEE URL: {err}")))?;
        if url.scheme() != "https" {
            return Err(TeeError::Attestation("TEE URL must be https".to_string()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| TeeError::Attestation("TEE URL host missing".to_string()))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TeeError::Attestation("TEE URL port missing".to_string()))?;
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
        let spki = leaf_spki_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let actual: [u8; 32] = Sha256::digest(spki).into();
        if actual == self.expected_spki_sha256 {
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
    timeout: std::time::Duration,
) -> Result<reqwest::Client, TeeError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|err| TeeError::Attestation(format!("TLS versions invalid: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinnedVerifier {
            expected_spki_sha256,
            algorithms,
        }))
        .with_no_client_auth();
    reqwest::Client::builder()
        .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .https_only(true)
        .use_preconfigured_tls(tls)
        .build()
        .map_err(TeeError::Http)
}

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

async fn fetch_tls_leaf_spki_der(host: &str, port: u16) -> Result<Vec<u8>, TeeError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|err| TeeError::Attestation(format!("TLS versions invalid: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier { algorithms }))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|err| TeeError::Attestation(format!("TEE TCP connect failed: {err}")))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| TeeError::Attestation("TEE host is not a valid DNS name".to_string()))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| TeeError::Attestation(format!("TEE TLS handshake failed: {err}")))?;
    let certs =
        tls_stream.get_ref().1.peer_certificates().ok_or_else(|| {
            TeeError::Attestation("TEE did not present a certificate".to_string())
        })?;
    let leaf = certs
        .first()
        .ok_or_else(|| TeeError::Attestation("TEE certificate chain is empty".to_string()))?;
    leaf_spki_der(leaf.as_ref())
}

fn leaf_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, TeeError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|err| TeeError::Attestation(format!("certificate parse failed: {err}")))?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| TeeError::Attestation(format!("certificate SPKI encode failed: {err}")))
}

#[cfg(test)]
mod tests {
    use super::{TeeClient, accepts_invalid_tee_certs, normalize_unlock_mode};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn normalizes_plain_domain_to_confidential_base() {
        let tee = TeeClient::new("app.enclava.dev");
        assert_eq!(
            tee.url("/status"),
            "https://app.enclava.dev/.well-known/confidential/status"
        );
    }

    #[test]
    fn accepts_api_returned_confidential_base() {
        let tee = TeeClient::new("https://app.enclava.dev/.well-known/confidential");
        assert_eq!(
            tee.url("/bootstrap/challenge"),
            "https://app.enclava.dev/.well-known/confidential/bootstrap/challenge"
        );
    }

    #[test]
    fn challenge_response_accepts_live_proxy_shape() {
        let parsed: super::ChallengeResponse = serde_json::from_value(serde_json::json!({
            "challenge": "abc",
            "nonce": "abc",
            "expires_in_seconds": 300.0
        }))
        .expect("parse challenge");
        assert_eq!(parsed.nonce, "abc");
        assert_eq!(parsed.ttl_seconds, 300);
    }

    #[test]
    fn staging_tls_mode_accepts_invalid_tee_certs() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("ENCLAVA_TEE_TLS_MODE", "staging");
            std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
        }
        assert!(accepts_invalid_tee_certs());
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
        }
    }

    #[test]
    fn default_tls_mode_requires_valid_tee_certs() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_TLS_MODE");
            std::env::remove_var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS");
        }
        assert!(!accepts_invalid_tee_certs());
    }

    #[test]
    fn change_password_body_matches_attestation_proxy_contract() {
        assert_eq!(
            super::change_password_body("old", "new"),
            serde_json::json!({
                "old_password": "old",
                "new_password": "new",
            })
        );
    }

    #[test]
    fn unlock_mode_receipt_modes_are_stable() {
        assert_eq!(normalize_unlock_mode("password"), "password");
        assert_eq!(normalize_unlock_mode("auto-unlock"), "auto");
        assert_eq!(normalize_unlock_mode("auto"), "auto");
    }

    #[test]
    fn verifies_attestation_evidence_report_data_binding() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY", "true");
        }
        let expected = [0x42; 64];
        let evidence = super::AttestationEvidence {
            payload_b64: String::new(),
            json: Some(serde_json::json!({
                "attestation_report": {
                    "report_data": hex::encode(expected),
                }
            })),
        };

        super::verify_evidence_report_data(&evidence, b"", &expected).unwrap();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY");
        }
    }

    #[test]
    fn rejects_attestation_evidence_report_data_mismatch() {
        let _guard = env_lock();
        unsafe {
            std::env::set_var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY", "true");
        }
        let expected = [0x42; 64];
        let evidence = super::AttestationEvidence {
            payload_b64: String::new(),
            json: Some(serde_json::json!({
                "attestation_report": {
                    "report_data": hex::encode([0x24; 64]),
                }
            })),
        };

        assert!(super::verify_evidence_report_data(&evidence, b"", &expected).is_err());
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY");
        }
    }

    #[test]
    fn rejects_json_only_attestation_evidence_by_default() {
        let _guard = env_lock();
        unsafe {
            std::env::remove_var("ENCLAVA_TEE_DEV_ALLOW_JSON_REPORT_DATA_ONLY");
        }
        let expected = [0x42; 64];
        let evidence = super::AttestationEvidence {
            payload_b64: String::new(),
            json: Some(serde_json::json!({
                "attestation_report": {
                    "report_data": hex::encode(expected),
                }
            })),
        };

        let err = super::verify_evidence_report_data(&evidence, b"", &expected).unwrap_err();
        assert!(err.to_string().contains("raw AMD SNP report"));
    }
}
