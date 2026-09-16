use std::{
    collections::HashMap,
    io::{ErrorKind, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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

use chrono::{DateTime, Utc};

use crate::api_types::{SignedReceiptResponse, TransitionReceiptAttestation};
use crate::attestation::{tee_tls_transcript_hash, validate_snp_report_with_der_chain};

const AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com";
const AMD_KDS_VCEK_MAX_ATTEMPTS: usize = 8;
/// Cached VCEK bytes are collateral, not a verdict: the TTL only bounds reuse
/// of certificate material that every attestation still re-validates end to
/// end. Fresh SNP reports, nonce bindings, TLS bindings, and chain checks are
/// unaffected by the cache.
const AMD_KDS_VCEK_CACHE_TTL: Duration = Duration::from_secs(3600);
const AMD_KDS_VCEK_CACHE_MAX_ENTRIES: usize = 256;
const AMD_KDS_VCEK_DISK_CACHE_MAX_ENTRIES: usize = 512;
/// Cross-process fills serialize on a fixed pool of lock files selected by
/// hashing the normalized cache key. A fixed slot count keeps `.lock` inode
/// usage bounded no matter how many distinct identities are attempted —
/// including identities whose fills always fail and therefore never write a
/// `.der` entry. Same-key processes always contend on the same slot;
/// distinct keys contend only on a digest-mod-slots collision.
const AMD_KDS_VCEK_LOCK_POOL_SLOTS: u64 = 64;
/// A `Retry-After` hint is honored only up to this cap; an oversized or absent
/// value falls back to the bounded jittered schedule.
const AMD_KDS_VCEK_RETRY_AFTER_CAP: Duration = Duration::from_secs(120);
/// Cross-process single-flight waits on a per-key file lock. A live fill is
/// bounded by the retry budget, so waiting longer means the lock is stale.
const AMD_KDS_VCEK_LOCK_WAIT_CAP: Duration = Duration::from_secs(600);
const AMD_KDS_VCEK_LOCK_POLL: Duration = Duration::from_millis(50);
/// Override the AMD KDS host root (scheme://authority, no path), e.g. to point
/// at a reachable caching relay. Workstation defaults stay direct AMD.
const AMD_KDS_BASE_URL_ENV: &str = "ENCLAVA_AMD_KDS_BASE_URL";
/// Override the on-disk VCEK cache directory (tests and offline isolation).
const AMD_KDS_CACHE_DIR_ENV: &str = "ENCLAVA_KDS_CACHE_DIR";
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
    /// Launch identity (SNP HOST_DATA plus authenticated firmware
    /// measurement) verified by this client's attestation. Present only on
    /// the SPKI-pinned client returned by `attest_receipt_key()` after the
    /// AMD chain, nonce, TLS leaf SPKI, and report data all verified; it
    /// binds every later `/status` read on this client to the TEE whose
    /// launch produced that identity.
    verified_launch_identity: Option<VerifiedSnpLaunchIdentity>,
}

/// Whether TEE TLS verification is relaxed for staging-type environments.
/// Only honored in debug builds; release builds always verify TLS.
pub fn accepts_invalid_tee_certs() -> bool {
    // Release builds never honor TLS-bypass env vars: the gate must hold for
    // library consumers too, not only for the `enclava` binary's startup
    // checks in main.rs.
    #[cfg(debug_assertions)]
    {
        std::env::var("ENCLAVA_TEE_TLS_MODE")
            .map(|mode| matches!(mode.as_str(), "staging" | "insecure"))
            .unwrap_or(false)
            || std::env::var("ENCLAVA_TEE_ACCEPT_INVALID_CERTS")
                .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                .unwrap_or(false)
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
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
    /// BIP39 mnemonic backup (emitted exactly once; persisted to the protected
    /// local keystore after a successful claim — never printed; deliberate
    /// export happens via `enclava key backup`). The TEE emits this under the
    /// `owner_seed_mnemonic` key.
    #[serde(rename = "owner_seed_mnemonic")]
    pub mnemonic: Option<String>,
}

/// Response from status endpoint.
#[derive(Debug, serde::Deserialize)]
pub struct TeeStatusResponse {
    pub ownership_state: String,
    pub unlock_state: String,
    pub auto_unlock_enabled: bool,
}

/// Stable, recognized terminal bootstrap failure codes the attestation proxy
/// may report under `/status`'s optional `bootstrap_error` field.
pub const TERMINAL_BOOTSTRAP_ERROR_CODES: [&str; 3] = [
    "acme_rate_limited",
    "acme_certificate_issuance_failed",
    "enclava_init_failed",
];

/// Upper bound on `/status` bodies accepted by the safe bootstrap-status read.
const MAX_BOOTSTRAP_STATUS_BODY_BYTES: usize = 64 * 1024;

/// Upper bound on `/attestation` response bodies, read before SNP verification
/// authenticates the peer (SPKI pinning only proves continuity with the
/// contacted endpoint). Ample for an SNP report plus an embedded DER chain.
const MAX_ATTESTATION_RESPONSE_BODY_BYTES: usize = 256 * 1024;

/// Matches the attestation-proxy broker bound: a `retry_after` deadline more
/// than 365 days past the observation is not a bounded deadline, and the
/// whole diagnostic is treated as unrecognized.
const TERMINAL_BOOTSTRAP_RETRY_AFTER_MAX_FUTURE_SECONDS: i64 = 365 * 24 * 60 * 60;

/// A terminal bootstrap failure diagnostic recognized in the TEE's `/status`
/// response.
///
/// Carries only the stable error code and an optional validated retry
/// deadline -- never arbitrary provider detail. A `retry_after` that has
/// already elapsed is preserved: it means a retry may now be attempted
/// separately, not that the terminal failure is erased.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalBootstrapError {
    code: &'static str,
    retry_after: Option<DateTime<Utc>>,
}

impl TerminalBootstrapError {
    pub fn code(&self) -> &'static str {
        self.code
    }

    pub fn retry_after(&self) -> Option<DateTime<Utc>> {
        self.retry_after
    }

    /// Stable, safe-to-print summary: the recognized code plus the validated
    /// deadline, re-serialized as UTC RFC3339 seconds (`Z`) rather than echoed
    /// from the response body.
    pub fn stable_summary(&self) -> String {
        match self.retry_after {
            Some(deadline) => format!(
                "{} (retry_after {})",
                self.code,
                deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
            None => self.code.to_string(),
        }
    }
}

/// One safe, bounded `/status` read for bootstrap waits: whether ownership is
/// already claimed, and whether the attestation proxy reported a recognized
/// terminal bootstrap failure. Both signals come from the same body, so a
/// claimed state can never mask a terminal diagnostic (and callers decide
/// which signal outranks the other for their flow).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeBootstrapStatus {
    pub claimed: bool,
    pub terminal_bootstrap_error: Option<TerminalBootstrapError>,
}

/// The single parser for the optional `/status` `bootstrap_error` field.
///
/// Recognizes a diagnostic only when the `error` code is exactly one of
/// [`TERMINAL_BOOTSTRAP_ERROR_CODES`], `terminal` is exactly `true`, and
/// `retry_after` is absent, `null`, or a strictly valid UTC RFC3339 deadline
/// within the broker's 365-day bound. Absent, unknown, or malformed fields
/// yield no diagnostic, so pre-existing retry deadlines keep governing and no
/// raw response text ever reaches the console.
pub fn parse_terminal_bootstrap_error(body: &serde_json::Value) -> Option<TerminalBootstrapError> {
    let field = body.get("bootstrap_error")?;
    if !field.is_object() {
        return None;
    }
    let code = field.get("error").and_then(|value| value.as_str())?;
    let code = TERMINAL_BOOTSTRAP_ERROR_CODES
        .iter()
        .find(|known| **known == code)?;
    match field.get("terminal") {
        Some(serde_json::Value::Bool(true)) => {}
        _ => return None,
    }
    let retry_after = match field.get("retry_after") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(raw)) => {
            let deadline = parse_utc_rfc3339_deadline(raw)?;
            let horizon = Utc::now()
                + chrono::Duration::seconds(TERMINAL_BOOTSTRAP_RETRY_AFTER_MAX_FUTURE_SECONDS);
            if deadline > horizon {
                return None;
            }
            Some(deadline)
        }
        _ => return None,
    };
    Some(TerminalBootstrapError { code, retry_after })
}

/// Launch identity verified during attestation: the SNP HOST_DATA (launch
/// input measurement) together with the authenticated firmware measurement,
/// both verified by the same AMD chain that authenticated report data.
/// HOST_DATA alone is hypervisor-supplied launch input and does not
/// authenticate the executed firmware, so the measurement is required
/// alongside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedSnpLaunchIdentity {
    pub host_data: [u8; 32],
    pub firmware_measurement: [u8; 48],
}

/// Deployment binding for terminal diagnostics: the launch identity verified
/// over a client's attestation must match BOTH the locally trusted expected
/// cc-init-data hash of the deployment being waited on AND the existing
/// expected firmware measurement. CAP validates the signed descriptor's hash
/// when rendering the deployment and revalidates it at apply, and the
/// firmware measurement authenticates which code the TEE actually executes;
/// the SPKI-pinned channel then guarantees the `/status` read reaches that
/// same TEE. Missing verified identity (unattested client, or development
/// JSON evidence) never binds, and neither does a matching HOST_DATA with a
/// mismatched measurement.
pub fn launch_identity_binds_deployment(
    verified: Option<&VerifiedSnpLaunchIdentity>,
    expected_cc_init_data_hash: &[u8; 32],
    expected_firmware_measurement: &enclava_common::descriptor::FirmwareMeasurement,
) -> bool {
    let Some(verified) = verified else {
        return false;
    };
    verified.host_data == *expected_cc_init_data_hash
        && expected_firmware_measurement.matches_report(&verified.firmware_measurement)
}

/// Strictly UTC RFC3339 (`Z` or zero offset); every other shape is rejected.
fn parse_utc_rfc3339_deadline(raw: &str) -> Option<DateTime<Utc>> {
    let deadline = DateTime::parse_from_rfc3339(raw).ok()?;
    if deadline.offset().local_minus_utc() != 0 {
        return None;
    }
    Some(deadline.with_timezone(&Utc))
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
            verified_launch_identity: None,
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
            verified_launch_identity: self.verified_launch_identity,
        }
    }

    /// The launch identity (SNP HOST_DATA plus authenticated firmware
    /// measurement) verified by this client's attestation, when this client
    /// came from `attest_receipt_key()`.
    pub fn verified_launch_identity(&self) -> Option<VerifiedSnpLaunchIdentity> {
        self.verified_launch_identity
    }

    /// Unit-test-only (lib tests): pin a synthetic verified launch identity
    /// onto a client, standing in for a completed `attest_receipt_key()`
    /// verification. Compiled only under `cfg(test)`, so no production build
    /// -- debug or release -- can construct synthetic trust; only
    /// `attest_receipt_key()` produces a trustworthy identity outside tests.
    #[cfg(test)]
    pub(crate) fn with_verified_launch_identity_for_tests(
        mut self,
        host_data: [u8; 32],
        firmware_measurement: [u8; 48],
    ) -> Self {
        self.verified_launch_identity = Some(VerifiedSnpLaunchIdentity {
            host_data,
            firmware_measurement,
        });
        self
    }

    /// Record the launch identity verified during attestation. `None` (the
    /// development JSON evidence path) leaves the client without deployment
    /// binding evidence, so terminal diagnostics fail closed.
    fn with_verified_launch_identity_checked(
        mut self,
        identity: Option<VerifiedSnpLaunchIdentity>,
    ) -> Self {
        self.verified_launch_identity = identity;
        self
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

    /// One safe, bounded `/status` read combining the ownership-claim fallback
    /// check with the terminal bootstrap diagnostic.
    ///
    /// Meaningful only on the SPKI-pinned client returned by
    /// [`TeeClient::attest_receipt_key`]: a `/status` response received over
    /// any unverified channel can never authorize a terminal decision. Reads
    /// are bounded and transport failures surface as `Err`, which callers
    /// treat as "no trusted diagnostic" so existing retry deadlines govern.
    pub async fn bootstrap_status(&self) -> Result<TeeBootstrapStatus, TeeError> {
        let body = self.bounded_status_json().await?;
        Ok(bootstrap_status_from_json(&body))
    }

    /// [`TeeClient::bootstrap_status`] under a hard budget, so a
    /// terminal-classifying status read can never outlive the enclosing
    /// wait. A budget expiry surfaces as `Err`, which callers treat as "no
    /// status".
    pub async fn bootstrap_status_within(
        &self,
        budget: std::time::Duration,
    ) -> Result<TeeBootstrapStatus, TeeError> {
        let body = self.bounded_status_json_within(budget).await?;
        Ok(bootstrap_status_from_json(&body))
    }

    /// The one safe `/status` read shared by every bootstrap-diagnostics
    /// caller. Successful bodies are capped at
    /// `MAX_BOOTSTRAP_STATUS_BODY_BYTES` (checked against `content-length`
    /// and again while chunking), and non-success responses are rejected by
    /// status code alone without reading the body, so neither a success body
    /// nor an error body can stream unbounded data or leak raw provider
    /// detail. Transport failures surface as `Err`, which callers treat as
    /// "no trusted diagnostic" so existing retry deadlines govern.
    pub async fn bounded_status_json(&self) -> Result<serde_json::Value, TeeError> {
        let resp = self.http.get(self.url("/status")).send().await?;
        reject_error_status(resp.status(), "TEE status")?;
        let body =
            read_bounded_response_body(resp, MAX_BOOTSTRAP_STATUS_BODY_BYTES, "TEE status body")
                .await?;
        parse_status_body(&body)
    }

    /// [`TeeClient::bounded_status_json`] under a hard budget: the complete
    /// read (connection, status code, bounded body) is cut when the budget
    /// elapses, so a stalled endpoint cannot hold a wait past its deadline
    /// via a status read.
    pub async fn bounded_status_json_within(
        &self,
        budget: std::time::Duration,
    ) -> Result<serde_json::Value, TeeError> {
        tokio::time::timeout(budget, self.bounded_status_json())
            .await
            .map_err(|_| TeeError::Attestation("TEE status read exceeded its budget".to_string()))?
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

    /// Enable auto-unlock (KBS-attestation-gated seed wrap, not VMPCK sealing).
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

    /// Disable auto-unlock (remove the KBS-gated seed wrap).
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
        match self.attest_receipt_key_once().await {
            Err(error) if self.resolve_ip.is_some() && is_tee_tcp_connect_error(&error) => {
                Self::new_with_timeout_and_resolve_ip(
                    &self.confidential_base_url,
                    self.timeout,
                    None,
                )
                .attest_receipt_key_once()
                .await
            }
            result => result,
        }
    }

    async fn attest_receipt_key_once(
        &self,
    ) -> Result<(TransitionReceiptAttestation, TeeClient), TeeError> {
        let endpoint = EndpointParts::parse(&self.confidential_base_url)?;
        let leaf_spki_der =
            fetch_tls_leaf_spki_der(&endpoint.host, endpoint.port, self.resolve_ip, self.timeout)
                .await?;
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
        // Read the attestation response through the bounded safe path for both
        // success and failure responses: at this point SPKI pinning only
        // proves continuity with the contacted peer, and SNP verification has
        // not yet authenticated it, so an unbounded body (or error body) must
        // not be consumed before authentication completes.
        reject_error_status(resp.status(), "TEE attestation")?;
        let body = read_bounded_response_body(
            resp,
            MAX_ATTESTATION_RESPONSE_BODY_BYTES,
            "TEE attestation body",
        )
        .await?;
        // Fixed messages only: serde errors can interpolate response content,
        // which must never leak before SNP authentication completes.
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| TeeError::Attestation("attestation body is not valid JSON".to_string()))?;
        let attestation: AttestationResponse = serde_json::from_value(value)
            .map_err(|_| TeeError::Attestation("attestation body is malformed".to_string()))?;
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
        let verified_launch_identity =
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
        let attested_client = self
            .with_http(pinned_http)
            .with_verified_launch_identity_checked(verified_launch_identity);
        Ok((transition_attestation, attested_client))
    }
}

fn is_tee_tcp_connect_error(error: &TeeError) -> bool {
    matches!(error, TeeError::Attestation(message) if message.starts_with("TEE TCP connect "))
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

/// Reject a non-success response by status code alone. Deliberately no body
/// read: the fixed message never carries arbitrary response content.
fn reject_error_status(status: reqwest::StatusCode, subject: &str) -> Result<(), TeeError> {
    if status.is_success() {
        return Ok(());
    }
    Err(TeeError::Tee {
        status: status.as_u16(),
        message: format!("{subject} request failed"),
    })
}

/// Shared bounded streaming reader: caps the body against the declared
/// `content-length` and again per chunk, so streaming bodies without a
/// declared length cannot bypass the limit.
async fn read_bounded_response_body(
    mut resp: reqwest::Response,
    max_bytes: usize,
    subject: &str,
) -> Result<Vec<u8>, TeeError> {
    let too_large = || {
        TeeError::Attestation(format!(
            "{subject} exceeds the {max_bytes}-byte bounded read limit"
        ))
    };
    if resp
        .content_length()
        .is_some_and(|length| length as usize > max_bytes)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > max_bytes {
            return Err(too_large());
        }
    }
    Ok(body)
}

fn too_large_status_body_error() -> TeeError {
    TeeError::Attestation(format!(
        "TEE status body exceeds the {}-byte bounded read limit",
        MAX_BOOTSTRAP_STATUS_BODY_BYTES
    ))
}

/// Parse a bounded `/status` body. Bodies above the bounded read limit are
/// rejected before parsing.
fn parse_status_body(body: &[u8]) -> Result<serde_json::Value, TeeError> {
    if body.len() > MAX_BOOTSTRAP_STATUS_BODY_BYTES {
        return Err(too_large_status_body_error());
    }
    serde_json::from_slice(body)
        .map_err(|_| TeeError::Attestation("TEE status body is not valid JSON".to_string()))
}

/// Bounded-body variant of the safe terminal-diagnostic parser.
#[cfg(test)]
pub(crate) fn parse_terminal_bootstrap_error_body(body: &[u8]) -> Option<TerminalBootstrapError> {
    parse_status_body(body)
        .ok()
        .and_then(|value| parse_terminal_bootstrap_error(&value))
}

/// Composition of one `/status` body into the safe bootstrap status: both the
/// ownership-claim fallback and the terminal diagnostic come from the same
/// body so neither can mask the other.
fn bootstrap_status_from_json(body: &serde_json::Value) -> TeeBootstrapStatus {
    TeeBootstrapStatus {
        claimed: claim_state_json_is_successful(body),
        terminal_bootstrap_error: parse_terminal_bootstrap_error(body),
    }
}

fn claim_state_json_is_successful(body: &serde_json::Value) -> bool {
    let ownership_state = body.get("ownership_state").and_then(|value| value.as_str());
    let legacy_state = body.get("state").and_then(|value| value.as_str());

    // The attestation-proxy's OwnershipState enum has no "claimed" variant -- it emits
    // "unclaimed"/"locked"/"unlocking"/"unlocked"/"error". Treat the post-claim states as
    // claimed; the prior match on "claimed" was dead code, so already-claimed password-mode
    // redeploys looped to the claim-wait timeout (notably via `template deploy`, which lacks
    // the `deploy_needs_initial_claim` pre-check the standalone `deploy` path has).
    fn is_claimed(state: Option<&str>) -> bool {
        matches!(state, Some("locked" | "unlocking" | "unlocked"))
    }
    is_claimed(ownership_state) || (ownership_state.is_none() && is_claimed(legacy_state))
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
) -> Result<Option<VerifiedSnpLaunchIdentity>, TeeError> {
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
) -> Result<Option<VerifiedSnpLaunchIdentity>, TeeError> {
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
            Some(chain) if ark_is_pinned_to_builtin_root(&chain.ark_der) => chain,
            Some(_) => {
                // An evidence-embedded chain whose ARK does not byte-match a
                // builtin AMD root is attacker-controlled input: `Chain`'s
                // verify() only proves internal consistency (ARK self-signed,
                // ARK->ASK->VCEK->report), never anchoring to AMD. Fall back
                // to the anchored KDS fetch; if that fails, fail closed.
                tracing::warn!(
                    "attestation evidence carried an AMD chain not anchored to a builtin AMD root; falling back to AMD KDS"
                );
                fetch_snp_der_chain_from_kds(&snp_report_bytes).await?
            }
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
        // HOST_DATA and the firmware measurement were verified together with
        // the same AMD chain that authenticated report_data: preserve both as
        // the launch identity of exactly this endpoint.
        return Ok(Some(VerifiedSnpLaunchIdentity {
            host_data: report.host_data,
            firmware_measurement: report.firmware_measurement,
        }));
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
    // The development JSON path carries no raw SNP report, so no trusted
    // launch identity exists: callers fail closed on deployment binding.
    Ok(None)
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
    let report =
        sev::firmware::guest::AttestationReport::from_bytes(snp_report_bytes).map_err(|_| {
            TeeError::Attestation("attestation evidence SNP report is malformed".to_string())
        })?;
    let (ark_der, ask_der) = builtin_snp_ca_der_chain(&report)?;
    let vcek_url = amd_kds_vcek_url(&report, &amd_kds_base_url())?;
    let key = vcek_cache_key(&report)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(30))
        .build()?;
    let vcek_der = fetch_amd_kds_vcek_der_cached(&client, &vcek_url, &key, kds_cache_dir())
        .await?
        .as_ref()
        .clone();

    Ok(SnpDerChain {
        ark_der,
        ask_der,
        vcek_der,
    })
}

fn amd_kds_vcek_should_retry(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn amd_kds_vcek_retry_delay(attempt_index: usize) -> Duration {
    let seconds = match attempt_index {
        0 => 2,
        1 => 5,
        2 => 10,
        3 => 20,
        _ => 30,
    };
    Duration::from_secs(seconds)
}

/// A valid `Retry-After` delta-seconds value is honored up to a fixed cap;
/// otherwise the backoff schedule is jittered to [50%, 150%) so callers
/// released together do not retry in lockstep. The outer attempt bound in
/// `fetch_amd_kds_vcek_der` is unchanged, and no nested loop may multiply it.
fn amd_kds_vcek_sleep_duration(attempt: usize, retry_after: Option<Duration>) -> Duration {
    if let Some(delay) = retry_after {
        return delay.min(AMD_KDS_VCEK_RETRY_AFTER_CAP);
    }
    let jitter = (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    amd_kds_vcek_retry_delay(attempt).mul_f64(0.5 + jitter)
}

/// `Retry-After` in delta-seconds only. An HTTP-date or malformed value falls
/// back to the jittered schedule rather than being trusted.
fn parse_retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let seconds: u64 = value?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

/// Error strings deliberately carry only the HTTP status or a coarse transport
/// class: the request URL embeds the chip HWID and must not reach logs or
/// user-facing errors.
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
                    let retry_after =
                        parse_retry_after(resp.headers().get(reqwest::header::RETRY_AFTER));
                    if amd_kds_vcek_should_retry(status) && attempt + 1 < AMD_KDS_VCEK_MAX_ATTEMPTS
                    {
                        tokio::time::sleep(amd_kds_vcek_sleep_duration(attempt, retry_after)).await;
                        continue;
                    }
                    return Err(TeeError::Attestation(format!(
                        "AMD KDS VCEK fetch failed: HTTP status {status}"
                    )));
                }

                return read_vcek_body(resp).await;
            }
            Err(err) => {
                // Coarse class only: `reqwest::Error` strings embed the full
                // request URL, including the HWID.
                let class = if err.is_timeout() {
                    "timeout"
                } else {
                    "transport"
                };
                if attempt + 1 < AMD_KDS_VCEK_MAX_ATTEMPTS {
                    last_error = Some(class);
                    tokio::time::sleep(amd_kds_vcek_sleep_duration(attempt, None)).await;
                    continue;
                }
                return Err(TeeError::Attestation(format!(
                    "AMD KDS VCEK request failed: {class}"
                )));
            }
        }
    }

    Err(TeeError::Attestation(format!(
        "AMD KDS VCEK request failed after retries: {}",
        last_error.unwrap_or("unknown error")
    )))
}

/// Bounded VCEK body read: a KDS or relay must not stream unbounded bytes
/// into verifier memory. 64 KiB covers every real certificate with headroom.
async fn read_vcek_body(mut response: reqwest::Response) -> Result<Vec<u8>, TeeError> {
    const MAX_DER_BYTES: usize = 64 * 1024;
    let too_large = || TeeError::Attestation("AMD KDS VCEK body exceeds 64 KiB".to_string());
    if response
        .content_length()
        .is_some_and(|size| size > MAX_DER_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| TeeError::Attestation("AMD KDS VCEK body read failed".to_string()))?
    {
        if chunk.len() > MAX_DER_BYTES - body.len() {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Cache key for VCEK collateral: normalized product generation, hardware
/// identity, and the complete reported TCB tuple (including Turin's `fmc`).
/// Any firmware/TCB change produces a different key, so cached bytes can never
/// satisfy a report that needed a different certificate.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct VcekCacheKey {
    product: String,
    hw_id: String,
    fmc: Option<u8>,
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl VcekCacheKey {
    /// Stable filename-safe form; hashed so the HWID never lands on disk or in
    /// file names.
    fn digest(&self) -> String {
        let canonical = format!(
            "{}|{}|{}|{:02}|{:02}|{:02}|{:02}",
            self.product,
            self.hw_id,
            self.fmc.map(|v| format!("{v:02}")).unwrap_or_default(),
            self.bootloader,
            self.tee,
            self.snp,
            self.microcode,
        );
        hex::encode(Sha256::digest(canonical.as_bytes()))
    }
}

fn vcek_cache_key(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<VcekCacheKey, TeeError> {
    let (generation, hw_id) = snp_report_kds_identity(report)?;
    let tcb = report.reported_tcb;
    Ok(VcekCacheKey {
        product: generation.titlecase(),
        hw_id,
        fmc: tcb.fmc,
        bootloader: tcb.bootloader,
        tee: tcb.tee,
        snp: tcb.snp,
        microcode: tcb.microcode,
    })
}

struct CachedVcek {
    der: Arc<Vec<u8>>,
    expires_at: Instant,
}

fn vcek_cache() -> &'static Mutex<HashMap<VcekCacheKey, CachedVcek>> {
    static CACHE: OnceLock<Mutex<HashMap<VcekCacheKey, CachedVcek>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn vcek_fill_locks() -> &'static Mutex<HashMap<VcekCacheKey, Arc<tokio::sync::Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<VcekCacheKey, Arc<tokio::sync::Mutex<()>>>>> =
        OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn vcek_cache_get(key: &VcekCacheKey) -> Option<Arc<Vec<u8>>> {
    let mut cache = vcek_cache().lock().expect("VCEK cache mutex poisoned");
    match cache.get(key) {
        Some(entry) if entry.expires_at > Instant::now() => Some(entry.der.clone()),
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

fn vcek_cache_insert(key: VcekCacheKey, der: Arc<Vec<u8>>, expires_at: Instant) {
    let mut cache = vcek_cache().lock().expect("VCEK cache mutex poisoned");
    if cache.len() >= AMD_KDS_VCEK_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
    }
    while cache.len() >= AMD_KDS_VCEK_CACHE_MAX_ENTRIES {
        let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.expires_at)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        cache.remove(&oldest);
    }
    cache.insert(key, CachedVcek { der, expires_at });
}

/// Per-key in-process fill lock for single-flight collapse. Bounded map; once
/// full, unknown keys share a process-wide fallback lock, which still
/// collapses concurrent fills for the same missing key.
// ponytail: cold keys serialize after 256 identities; evict idle locks if this matters.
fn vcek_fill_lock(key: &VcekCacheKey) -> Arc<tokio::sync::Mutex<()>> {
    static FALLBACK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();
    let mut locks = vcek_fill_locks()
        .lock()
        .expect("VCEK fill-lock map poisoned");
    if let Some(lock) = locks.get(key) {
        return lock.clone();
    }
    if locks.len() >= AMD_KDS_VCEK_CACHE_MAX_ENTRIES {
        return FALLBACK
            .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
    }
    locks
        .entry(key.clone())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Parse the fetched VCEK and compute its cache expiry: the earlier of the
/// certificate's own `not_after` and the bounded cache TTL. A body that is not
/// a certificate currently inside its validity window is rejected and never
/// cached, so a 429/error body can never become cached "certificate" bytes.
fn vcek_der_expiry(der: &[u8]) -> Result<Instant, TeeError> {
    let certificate = x509_cert::Certificate::from_der(der).map_err(|_| {
        TeeError::Attestation("AMD KDS VCEK response is not a certificate".to_string())
    })?;
    let validity = certificate.tbs_certificate.validity;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TeeError::Attestation("system clock predates UNIX epoch".to_string()))?;
    let not_before = validity.not_before.to_unix_duration();
    let not_after = validity.not_after.to_unix_duration();
    if now < not_before || now >= not_after {
        return Err(TeeError::Attestation(
            "AMD KDS VCEK is outside its validity period".to_string(),
        ));
    }
    Ok(Instant::now() + (not_after - now).min(AMD_KDS_VCEK_CACHE_TTL))
}

/// On-disk cache shared by concurrent `enclava` invocations: a short-lived
/// process alone cannot collapse same-key fetches across processes. Entries
/// are `vcek-<sha256(key)>.der`; cross-process single-flight uses one of
/// `AMD_KDS_VCEK_LOCK_POOL_SLOTS` pooled `vcek-lock-<NN>.lock` files. The
/// digest keeps the HWID out of file names.
fn kds_cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var(AMD_KDS_CACHE_DIR_ENV) {
        let dir = dir.trim();
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    dirs::cache_dir().map(|base| base.join("enclava").join("kds-vcek"))
}

fn vcek_disk_paths(dir: &Path, key: &VcekCacheKey) -> (PathBuf, PathBuf) {
    let digest = key.digest();
    (
        dir.join(format!("vcek-{digest}.der")),
        vcek_disk_lock_path(dir, &digest),
    )
}

/// The pooled cross-process fill lock for a normalized key digest. Pool
/// files are permanent shared infrastructure: they are never evicted and
/// are never treated as orphans by the sweep below.
fn vcek_disk_lock_path(dir: &Path, key_digest: &str) -> PathBuf {
    let slot =
        u64::from_str_radix(&key_digest[..16], 16).unwrap_or(0) % AMD_KDS_VCEK_LOCK_POOL_SLOTS;
    dir.join(format!("vcek-lock-{slot:02}.lock"))
}

/// Read a disk-cached VCEK only if it is fresh, parseable, and still inside
/// its certificate validity window. Corrupt or expired entries are removed
/// and reported as a miss.
fn vcek_disk_get(dir: &Path, key: &VcekCacheKey) -> Option<Vec<u8>> {
    let (der_path, _) = vcek_disk_paths(dir, key);
    let metadata = std::fs::metadata(&der_path).ok()?;
    if !metadata.is_file() {
        return None;
    }
    let fetched_at = metadata.modified().ok()?;
    if fetched_at.elapsed().ok()? > AMD_KDS_VCEK_CACHE_TTL {
        let _ = std::fs::remove_file(&der_path);
        return None;
    }
    let mut der = Vec::new();
    std::fs::File::open(&der_path)
        .ok()?
        .take(64 * 1024 + 1)
        .read_to_end(&mut der)
        .ok()?;
    if der.is_empty() || der.len() > 64 * 1024 || vcek_der_expiry(&der).is_err() {
        let _ = std::fs::remove_file(&der_path);
        return None;
    }
    Some(der)
}

/// Best-effort atomic write plus oldest-first eviction. The caller has already
/// validated the DER; failures only lose sharing, never correctness.
fn vcek_disk_put(dir: &Path, key: &VcekCacheKey, der: &[u8]) {
    let (der_path, _) = vcek_disk_paths(dir, key);
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = der_path.with_extension(format!("{}.tmp", std::process::id()));
    if std::fs::write(&tmp, der).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    if std::fs::rename(&tmp, &der_path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return;
    }
    evict_vcek_disk_cache(dir);
}

fn evict_vcek_disk_cache(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut cached: Vec<(SystemTime, PathBuf)> = entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let name = entry.file_name();
            let name = name.to_str()?;
            if !name.starts_with("vcek-") || !name.ends_with(".der") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    if cached.len() <= AMD_KDS_VCEK_DISK_CACHE_MAX_ENTRIES {
        return;
    }
    cached.sort_by_key(|(modified, _)| *modified);
    let excess = cached.len() - AMD_KDS_VCEK_DISK_CACHE_MAX_ENTRIES;
    for (_, path) in cached.into_iter().take(excess) {
        let _ = std::fs::remove_file(path);
    }
}

/// Remove leftover per-key `vcek-<digest>.lock` files from before the pooled
/// lock scheme — and any future orphan `.lock` file — when no matching
/// `.der` entry exists. A file is only unlinked while this process holds
/// its flock, which proves no live filler is serialized on that inode. A
/// concurrent opener that has not yet locked can still observe the stale
/// path briefly; the worst case is one lost single-flight collapse for an
/// orphan key, never a freshness or correctness change.
fn sweep_orphan_vcek_locks(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        // Pool slots are shared infrastructure, never orphans.
        if name.starts_with("vcek-lock-") || !name.starts_with("vcek-") || !name.ends_with(".lock")
        {
            continue;
        }
        let der = dir.join(format!("{}.der", &name[..name.len() - ".lock".len()]));
        if der.exists() {
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(entry.path())
        else {
            continue;
        };
        let mut lock = fd_lock::RwLock::new(file);
        let Ok(_guard) = lock.try_write() else {
            continue;
        };
        let _ = std::fs::remove_file(entry.path());
    }
}

/// Single-flight VCEK fetch. In-process, callers for the same product/HWID/TCB
/// key share one fill through a per-key mutex; across `enclava` invocations a
/// per-key file lock plays the same role. A warm memory or disk entry is
/// reused without an upstream request. The cached value is only DER
/// certificate bytes; chain/identity/validity verification runs on every
/// attestation regardless of the cache.
async fn fetch_amd_kds_vcek_der_cached(
    client: &reqwest::Client,
    vcek_url: &str,
    key: &VcekCacheKey,
    cache_dir: Option<PathBuf>,
) -> Result<Arc<Vec<u8>>, TeeError> {
    if let Some(der) = vcek_cache_get(key) {
        return Ok(der);
    }
    let fill = vcek_fill_lock(key);
    let _guard = fill.lock().await;
    // A concurrent caller may have filled this key while we queued on it.
    if let Some(der) = vcek_cache_get(key) {
        return Ok(der);
    }
    vcek_fill_from_upstream(client, vcek_url, key, cache_dir).await
}

/// The disk-cache layer of a fill: warm on-disk entries are reused, and the
/// per-key file lock serializes fills across concurrent `enclava` processes.
async fn vcek_fill_from_upstream(
    client: &reqwest::Client,
    vcek_url: &str,
    key: &VcekCacheKey,
    cache_dir: Option<PathBuf>,
) -> Result<Arc<Vec<u8>>, TeeError> {
    if let Some(dir) = cache_dir.as_deref()
        && let Some(der) = vcek_disk_get(dir, key)
    {
        let expires_at = vcek_der_expiry(&der)?;
        let der = Arc::new(der);
        vcek_cache_insert(key.clone(), der.clone(), expires_at);
        return Ok(der);
    }

    // Cross-process single-flight: hold the key's pooled lock slot while
    // filling. Missing lock support only loses cross-process collapse, never
    // freshness.
    let mut file_lock = cache_dir.as_deref().and_then(|dir| {
        let (_, lock_path) = vcek_disk_paths(dir, key);
        std::fs::create_dir_all(dir).ok()?;
        let file = std::fs::File::create(lock_path).ok()?;
        Some(fd_lock::RwLock::new(file))
    });
    let _file_guard = match file_lock.as_mut() {
        Some(lock) => {
            let deadline = Instant::now() + AMD_KDS_VCEK_LOCK_WAIT_CAP;
            loop {
                match lock.try_write() {
                    Ok(guard) => break Some(guard),
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        if Instant::now() >= deadline {
                            return Err(TeeError::Attestation(
                                "AMD KDS VCEK cache lock wait exceeded".to_string(),
                            ));
                        }
                        tokio::time::sleep(AMD_KDS_VCEK_LOCK_POLL).await;
                    }
                    // Unexpected lock errors disable cross-process collapse
                    // for this fill rather than blocking verification.
                    Err(_) => break None,
                }
            }
        }
        None => None,
    };
    // Another process may have filled the key while we waited on the lock.
    if let Some(dir) = cache_dir.as_deref()
        && let Some(der) = vcek_disk_get(dir, key)
    {
        let expires_at = vcek_der_expiry(&der)?;
        let der = Arc::new(der);
        vcek_cache_insert(key.clone(), der.clone(), expires_at);
        return Ok(der);
    }

    // Best-effort sweep of orphaned per-key lock files while this fill is
    // already serialized on its slot. Sweeps are idempotent and never
    // remove pool slots or in-use locks.
    if let Some(dir) = cache_dir.as_deref() {
        sweep_orphan_vcek_locks(dir);
    }

    let der = Arc::new(fetch_amd_kds_vcek_der(client, vcek_url).await?);
    let expires_at = vcek_der_expiry(&der)?;
    if let Some(dir) = cache_dir.as_deref() {
        vcek_disk_put(dir, key, &der);
    }
    vcek_cache_insert(key.clone(), der.clone(), expires_at);
    Ok(der)
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

/// True only when `ark_der` byte-matches one of the built-in AMD ARK roots
/// compiled into the `sev` crate (Milan, Genoa, Turin). Evidence-embedded
/// chains are trusted exclusively through this anchor.
fn ark_is_pinned_to_builtin_root(ark_der: &[u8]) -> bool {
    static PINNED_ARKS: std::sync::OnceLock<Vec<Vec<u8>>> = std::sync::OnceLock::new();
    let pinned = PINNED_ARKS.get_or_init(|| {
        let mut roots = Vec::new();
        for ark in [
            sev::certs::snp::builtin::milan::ark(),
            sev::certs::snp::builtin::genoa::ark(),
            sev::certs::snp::builtin::turin::ark(),
        ] {
            if let Ok(cert) = ark
                && let Ok(der) = cert.to_der()
            {
                roots.push(der);
            }
        }
        roots
    });
    pinned.iter().any(|root| root == ark_der)
}

fn amd_kds_base_url() -> String {
    std::env::var(AMD_KDS_BASE_URL_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| AMD_KDS_BASE_URL.to_string())
}

/// Normalized KDS lookup identity for a report: the processor generation
/// (product) plus the product-correct hardware-ID encoding. Every check here
/// is a precondition for a KDS lookup, so the cache key shares it with the URL
/// to keep both on identical normalization.
fn snp_report_kds_identity(
    report: &sev::firmware::guest::AttestationReport,
) -> Result<(sev::Generation, String), TeeError> {
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
    // AMD KDS spec 57230: Turin uses the first eight CHIP_ID bytes.
    let hw_id = if matches!(generation, sev::Generation::Turin) {
        if report.chip_id[8..].iter().any(|byte| *byte != 0) {
            return Err(TeeError::Attestation(
                "invalid Turin chip_id padding".to_string(),
            ));
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
) -> Result<String, TeeError> {
    let (generation, hw_id) = snp_report_kds_identity(report)?;
    let tcb = report.reported_tcb;
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

fn parse_hex32_field(field: &'static str, value: &str) -> Result<[u8; 32], TeeError> {
    // Fixed messages only: hex errors interpolate the offending response
    // bytes, and this field is parsed before SNP authentication completes.
    let bytes = hex::decode(value.trim())
        .map_err(|_| TeeError::Attestation(format!("{field} is not valid hex")))?;
    bytes
        .try_into()
        .map_err(|_| TeeError::Attestation(format!("{field} must be 32 bytes")))
}

mod tls;
use tls::{EndpointParts, build_spki_pinned_client, fetch_tls_leaf_spki_der};

#[cfg(test)]
#[path = "tee_client/tests/mod.rs"]
pub(crate) mod tests;
