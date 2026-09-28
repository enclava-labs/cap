//! Static TLS certificate provisioning through the workload-attested broker.
//!
//! Trust model (review fix on top of the retained-state validation):
//!
//! * Every chain — retained on disk or freshly returned by the broker — is
//!   validated with webpki [`EndEntityCert::verify_for_usage`] for
//!   `serverAuth` against the independently trusted public root store
//!   (`webpki-roots`, the Mozilla CA certificate programme). Only that store
//!   is trusted in production; there is no configuration switch that adds,
//!   downloads, or extends roots.
//! * Certificates carried inside a chain never extend the trust store: a
//!   trailing self-signed root, a root sent in the same broker response, or a
//!   leaf-only chain all fail closed unless the chain independently leads to
//!   a configured trust anchor. Signature linkage, issuer validity windows,
//!   CA basic constraints/path lengths, name constraints, and serverAuth EKU
//!   are all enforced by webpki during path building.
//! * The public store deliberately does not contain the Let's Encrypt
//!   *staging* roots, so staging-issued chains are rejected by default. A
//!   future staging deployment needs explicit, separately reviewed trust
//!   support; it is never inferred from URLs, chain contents, or broker
//!   responses (see `TLS_CERTIFICATE_VALIDATION.md`).
//!
//! Retained-state policy: reuse is only permitted when the retained
//! certificate and key are regular files and the full anchored validation
//! passes. Anything else — non-regular files, symlinks (including dangling
//! ones), unreadable state, malformed/expired/untrusted chains, key
//! mismatches — aborts provisioning without ordering a replacement
//! certificate and without replacing the retained private key. Only an
//! actually absent certificate (ENOENT) starts issuance; a certificate-less
//! retained key is reused for the new CSR so an interrupted first issuance
//! retries with the same key.
//!
//! Failure contract: broker responses are consumed with a bounded body
//! read, and terminal issuance failures are reduced to the broker's safe
//! bounded contract (`{"error","terminal","retry_after"}`) carried in the
//! typed [`TlsBrokerFailure`] error. Raw response bytes, HTTP detail, and
//! provider prose never enter any error, log, or file; unknown, malformed,
//! or unbounded bodies degrade to the generic safe issuance failure.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use chrono::{DateTime, Utc};
use rcgen::{CertificateParams, DistinguishedName, KeyPair, SigningKey};
use rustls_pki_types::{
    CertificateDer, ServerName, SignatureVerificationAlgorithm, TrustAnchor, UnixTime,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage};
use webpki_roots::TLS_SERVER_ROOTS;

use crate::config::Config;
use crate::safe_diagnostics::{SafeBootstrapDiagnostic, SafeDiagnosticCode};
use crate::{trustee_verify, writes};

pub const CERT_RELATIVE_PATH: &str = "certificates/tls.crt";
pub const KEY_RELATIVE_PATH: &str = "certificates/tls.key";

/// Signature algorithms accepted during chain validation. Covers the
/// algorithm families used by public WebPKI issuers (and therefore by the
/// broker's ACME provider).
const SUPPORTED_SIG_ALGS: &[&dyn SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P256_SHA256,
    webpki::ring::ECDSA_P256_SHA384,
    webpki::ring::ECDSA_P384_SHA256,
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::ED25519,
    webpki::ring::RSA_PKCS1_2048_8192_SHA256,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA512,
];

/// Reuse clock tolerance for `notBefore`: broker-issued certificates can
/// carry an issuance timestamp slightly ahead of the workload clock. When a
/// chain is not valid yet by at most this much, path validation is retried
/// at the certificate's own `notBefore` time; expiry stays strict.
const NOT_BEFORE_TOLERANCE_SECS: u64 = 300;

/// Fixed message signed with the retained/generated TLS private key to prove
/// the certificate leaf was issued for exactly that key.
const TLS_KEY_BINDING_PROBE: &[u8] = b"enclava-init tls certificate key binding probe";

/// Maximum TLS certificate broker response body bytes ever buffered, for
/// failures and successes alike. Successful PEM chains are a few KiB and
/// the terminal-failure contract is far smaller; anything larger is
/// treated as an unbounded (malformed) body and never read into memory.
const MAX_BROKER_RESPONSE_BYTES: usize = 64 * 1024;

/// Farthest a single honored ACME `retry_after` deadline may lie in the
/// future. A broker deadline beyond this is not waited on: provisioning
/// fails terminally with the preserved diagnostic instead of parking the
/// bootstrap for an operator-invisible span. Four hours comfortably covers
/// the Let's Encrypt rate-limit windows observed in production telemetry
/// (~40-minute order spacing) while still bounding the certificate phase.
const ACME_RETRY_MAX_WAIT_SECS: i64 = 4 * 60 * 60;

/// Most rate-limit waits honored per provisioning call. A provider that
/// keeps answering `acme_rate_limited` cannot hold the workload in the
/// certificate phase forever.
const ACME_RETRY_MAX_ROUNDS: u32 = 12;

/// Location of the persisted rate-limit deadline relative to the
/// confidential persistent root, next to the retained key. Surviving a pod
/// restart is the whole point: a restarted init resumes the honored wait
/// instead of submitting a fresh ACME order and compounding the limit.
const ACME_RETRY_RELATIVE_PATH: &str = "certificates/acme-retry.json";

/// Bound on the persisted marker size; the marker is a three-field JSON
/// document and anything larger is treated as corrupt.
const MAX_ACME_RETRY_MARKER_BYTES: u64 = 4 * 1024;

/// Clock/sleep seam for the ACME rate-limit wait. Production uses the
/// real clock and thread sleep; tests inject a deterministic fake so the
/// wait logic is exercised without wall-clock delays.
pub(crate) struct AcmeWait {
    /// Runtime marker file the attestation proxy polls so a certificate
    /// cooldown never degrades into an `unlock_timeout` ownership error.
    /// Best-effort: observability only, never a provisioning failure.
    pub cooldown_file: PathBuf,
    pub now: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    pub sleep_until: Box<dyn Fn(DateTime<Utc>) + Send + Sync>,
}

impl AcmeWait {
    fn production(cooldown_file: &Path) -> Self {
        Self {
            cooldown_file: cooldown_file.to_path_buf(),
            now: Box::new(Utc::now),
            sleep_until: Box::new(|deadline| {
                loop {
                    let remaining = deadline - Utc::now();
                    let Ok(remaining) = remaining.to_std() else {
                        return;
                    };
                    // Chunk the wait so clock adjustments settle and shutdown
                    // signals are observed reasonably promptly.
                    std::thread::sleep(remaining.min(Duration::from_secs(60)));
                }
            }),
        }
    }
}

/// Persisted rate-limit deadline, bound to the exact request it was
/// issued for so stale markers never suppress a different request's
/// issuance. The fingerprint hashes the retained key and the configured
/// hostnames — not the CSR DER, whose signature is not deterministic
/// across serializations.
#[derive(Debug, Serialize, Deserialize)]
struct AcmeRetryMarker {
    version: u32,
    request_sha256: String,
    retry_after: String,
}

/// Stable fingerprint of the issuance request a persisted deadline
/// applies to: the private key PEM and the exact configured hostname list.
fn acme_request_fingerprint(key_pem: &str, hostnames: &[String]) -> String {
    let mut input = key_pem.as_bytes().to_vec();
    input.push(0);
    for hostname in hostnames {
        input.extend_from_slice(hostname.as_bytes());
        input.push(0);
    }
    hex::encode(Sha256::digest(&input))
}

fn acme_retry_marker_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(ACME_RETRY_RELATIVE_PATH)
}

/// Read the persisted cooldown deadline for this CSR, honoring the same
/// bounds as a live broker response: UTC-only RFC 3339, horizon-limited,
/// and no farther out than a single honored wait. Corrupt, oversized,
/// mismatched, or expired markers are removed and ignored — a fresh order
/// is then the correct recovery.
fn persisted_retry_deadline(
    persistent_root: &Path,
    request_sha256: &str,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let path = acme_retry_marker_path(persistent_root);
    let drop_marker = |why: &str| {
        if let Err(err) = std::fs::remove_file(&path) {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                reason = why,
                "failed to remove unusable persisted ACME retry marker"
            );
        }
        None
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return drop_marker("unreadable"),
    };
    if !metadata.is_file() || metadata.len() > MAX_ACME_RETRY_MARKER_BYTES {
        return drop_marker("invalid");
    }
    let body = match std::fs::read_to_string(&path) {
        Ok(body) => body,
        Err(_) => return drop_marker("unreadable"),
    };
    let marker = match serde_json::from_str::<AcmeRetryMarker>(&body) {
        Ok(marker) => marker,
        Err(_) => return drop_marker("malformed"),
    };
    if marker.version != 1 || marker.request_sha256 != request_sha256 {
        return drop_marker("mismatched");
    }
    let deadline = SafeBootstrapDiagnostic::parse_retry_after(&marker.retry_after, now)
        .filter(|deadline| *deadline > now)
        .filter(|deadline| (*deadline - now).num_seconds() <= ACME_RETRY_MAX_WAIT_SECS);
    match deadline {
        Some(deadline) => Some(deadline),
        None => drop_marker("expired-or-out-of-bounds"),
    }
}

fn persist_retry_deadline(
    persistent_root: &Path,
    request_sha256: &str,
    deadline: DateTime<Utc>,
) -> Result<()> {
    let marker = AcmeRetryMarker {
        version: 1,
        request_sha256: request_sha256.to_string(),
        retry_after: deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    };
    let body = serde_json::to_vec(&marker).context("encoding ACME retry marker")?;
    writes::atomic_write(&acme_retry_marker_path(persistent_root), &body, 0o600)
        .context("persisting ACME retry deadline")
}

fn clear_persisted_retry_deadline(persistent_root: &Path) {
    let path = acme_retry_marker_path(persistent_root);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(
            path = %path.display(),
            error = %err,
            "failed to clear persisted ACME retry deadline"
        ),
    }
}

/// Publish the non-terminal cooldown marker consumed by the attestation
/// proxy's init-ready watch: `{"error":"acme_rate_limited","terminal":false,
/// "retry_after":<UTC>,"retry_after_unix":<secs>}`. The proxy uses the
/// integer deadline to extend its wait instead of degrading the
/// certificate cooldown into a terminal ownership error, and surfaces the
/// RFC 3339 field on the attested status endpoint for operators.
fn write_acme_cooldown_marker(path: &Path, deadline: DateTime<Utc>) {
    let body = serde_json::json!({
        "error": "acme_rate_limited",
        "terminal": false,
        "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "retry_after_unix": deadline.timestamp(),
    })
    .to_string();
    if let Err(err) = writes::atomic_write(path, format!("{body}\n").as_bytes(), 0o644) {
        tracing::warn!(
            path = %path.display(),
            error = %err,
            "failed to write ACME cooldown marker"
        );
    }
}

fn clear_acme_cooldown_marker(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => tracing::warn!(
            path = %path.display(),
            error = %err,
            "failed to clear ACME cooldown marker"
        ),
    }
}

/// A broker diagnostic is a waitable rate-limit cooldown only when it is
/// the exact typed code carrying a validated deadline that is still in the
/// future and within the single-wait bound. Missing, elapsed, or
/// over-horizon deadlines stay terminal.
fn waitable_rate_limit(
    diagnostic: &SafeBootstrapDiagnostic,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    if diagnostic.code != SafeDiagnosticCode::AcmeRateLimited {
        return None;
    }
    diagnostic
        .retry_after
        .filter(|deadline| *deadline > now)
        .filter(|deadline| (*deadline - now).num_seconds() <= ACME_RETRY_MAX_WAIT_SECS)
}

/// Typed terminal TLS broker failure carrying only the safe, bounded
/// diagnostic — never raw response text, HTTP detail, or provider prose.
///
/// The type propagates unchanged through the contextual anyhow wrappers
/// between here and the init binary's failure reporting, which recovers it
/// by typed downcast (`anyhow::Error::downcast_ref`), not string scraping.
/// Its `Display` text is itself safe: it renders only the diagnostic code
/// and the validated deadline.
#[derive(Debug, thiserror::Error)]
#[error(
    "TLS certificate broker issuance failed: code {}, retry_after {}",
    diagnostic.code.as_str(),
    diagnostic.retry_after_rfc3339().as_deref().unwrap_or("null")
)]
pub struct TlsBrokerFailure {
    pub diagnostic: SafeBootstrapDiagnostic,
}

#[derive(Debug, Serialize)]
struct CertificateRequest<'a> {
    hostnames: &'a [String],
    csr_der_base64: String,
    cc_init_data_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertificateResponse {
    certificate_chain_pem: String,
}

/// Wire shape of the broker's bounded terminal-failure contract:
/// `{"error":"acme_rate_limited"|"acme_certificate_issuance_failed",
/// "terminal":true,"retry_after":null|RFC3339 UTC}`. Unknown fields are
/// ignored and never echoed anywhere.
#[derive(Debug, Deserialize)]
struct BrokerFailureBody {
    error: String,
    terminal: bool,
    retry_after: Option<String>,
}

/// Consume a broker failure body into the safe diagnostic.
///
/// Only the exact recognized contract is honored: a known code with
/// `terminal: true` keeps its code and its validated UTC deadline. Unknown
/// codes, malformed JSON, non-terminal bodies, and absent/malformed/
/// out-of-bounds deadlines all degrade to the generic safe terminal
/// `acme_certificate_issuance_failed` with a null deadline. The body bytes
/// are never included in any error, log, or returned value.
fn broker_failure_diagnostic(body: &[u8], now: DateTime<Utc>) -> SafeBootstrapDiagnostic {
    let Ok(parsed) = serde_json::from_slice::<BrokerFailureBody>(body) else {
        return SafeBootstrapDiagnostic::acme_failed();
    };
    if !parsed.terminal {
        return SafeBootstrapDiagnostic::acme_failed();
    }
    let Some(code) = SafeDiagnosticCode::from_broker_code(&parsed.error) else {
        return SafeBootstrapDiagnostic::acme_failed();
    };
    SafeBootstrapDiagnostic {
        code,
        retry_after: parsed
            .retry_after
            .as_deref()
            .and_then(|value| SafeBootstrapDiagnostic::parse_retry_after(value, now)),
    }
}

/// Read at most `limit` bytes of a blocking response body. Returns `None`
/// when the body is larger than the limit or cannot be read, so unbounded
/// bodies are never buffered.
fn read_response_body_bounded(
    response: &mut reqwest::blocking::Response,
    limit: usize,
) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let read = response.read(&mut chunk).ok()?;
        if read == 0 {
            return Some(body);
        }
        if body.len() + read > limit {
            return None;
        }
        body.extend_from_slice(&chunk[..read]);
    }
}

/// Provision the static TLS certificate, waiting through bounded ACME
/// rate-limit cooldowns instead of failing terminally on the first
/// `acme_rate_limited` response.
///
/// `cooldown_file` is the runtime marker the attestation proxy polls
/// (e.g. `/run/enclava/init-acme-cooldown`): while a rate-limit wait is in
/// progress it carries `{"error":"acme_rate_limited","terminal":false,
/// "retry_after":...}` so the proxy's init-ready watch extends its own
/// deadline instead of degrading the wait into an ownership error, and the
/// attested status endpoint can surface the pending retry to operators.
pub fn provision_static_tls_certificate(
    cfg: &Config,
    persistent_root: &Path,
    cooldown_file: &Path,
) -> Result<()> {
    provision_with_policy(
        cfg,
        persistent_root,
        TLS_SERVER_ROOTS,
        &AcmeWait::production(cooldown_file),
    )
}

/// Same as [`provision_static_tls_certificate`], with the trust anchor set
/// injected by the in-module tests (synthetic independently trusted
/// anchors) and a wait policy that panics if code under test tries to
/// sleep — tests exercising the retry path call
/// [`provision_with_policy`] with a fake clock instead. Production callers
/// reach this only through [`provision_static_tls_certificate`], which
/// always passes the public `webpki-roots` store; there is no
/// configuration path that alters anchors.
#[cfg(test)]
fn provision_with_trust_anchors(
    cfg: &Config,
    persistent_root: &Path,
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    provision_with_policy(
        cfg,
        persistent_root,
        trust_anchors,
        &AcmeWait {
            cooldown_file: persistent_root.join("init-acme-cooldown"),
            now: Box::new(Utc::now),
            sleep_until: Box::new(|deadline| {
                panic!("unexpected ACME rate-limit wait for {deadline}")
            }),
        },
    )
}

fn provision_with_policy(
    cfg: &Config,
    persistent_root: &Path,
    trust_anchors: &[TrustAnchor<'_>],
    wait: &AcmeWait,
) -> Result<()> {
    let Some(broker_url) = cfg.tls_certificate_broker_url.as_deref() else {
        return Ok(());
    };
    if cfg.tls_certificate_hostnames.is_empty() {
        return Err(anyhow!(
            "tls-certificate-broker-url requires tls-certificate-hostnames"
        ));
    }

    let cert_path = cert_path(persistent_root);
    let key_path = key_path(persistent_root);
    if retained_path_is_regular_file(&cert_path)
        .with_context(|| format!("checking retained TLS certificate {}", cert_path.display()))?
    {
        // Fail closed on retained state: an incomplete, malformed, expired,
        // untrusted, or mismatched certificate never triggers a new broker
        // order and the retained private key is never replaced. An operator
        // must remove the stale certificate explicitly to force reissuance.
        if !retained_path_is_regular_file(&key_path)
            .with_context(|| format!("checking retained TLS private key {}", key_path.display()))?
        {
            return Err(anyhow!(
                "retained TLS certificate {} exists but private key {} is missing; \
                 refusing to order a replacement certificate or replace the private key",
                cert_path.display(),
                key_path.display()
            ));
        }
        validate_retained_tls_state(
            trust_anchors,
            &cfg.tls_certificate_hostnames,
            &cert_path,
            &key_path,
        )
        .context("validating retained static TLS certificate")?;
        tracing::info!(
            cert = %cert_path.display(),
            key = %key_path.display(),
            "retained static TLS certificate validated; skipping issuance"
        );
        return Ok(());
    }

    let key_pair = load_or_generate_key(&key_path)?;
    let csr_der = build_csr_der(&cfg.tls_certificate_hostnames, &key_pair)?;
    let request_sha256 =
        acme_request_fingerprint(&key_pair.serialize_pem(), &cfg.tls_certificate_hostnames);

    // A restart while an earlier cooldown was being honored resumes the
    // wait before submitting a new order — every broker POST is itself an
    // ACME order and would compound the rate limit.
    if let Some(deadline) = persisted_retry_deadline(persistent_root, &request_sha256, (wait.now)())
    {
        tracing::info!(
            retry_after = %deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "resuming persisted ACME rate-limit cooldown"
        );
        write_acme_cooldown_marker(&wait.cooldown_file, deadline);
        (wait.sleep_until)(deadline);
    } else {
        // A container restart inside the same pod keeps /run/enclava; a
        // cooldown marker left by a previous run whose persisted deadline
        // is gone or unusable must not keep extending the proxy's watch.
        clear_acme_cooldown_marker(&wait.cooldown_file);
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(180))
        .build()
        .context("building TLS certificate broker client")?;
    let request = CertificateRequest {
        hostnames: &cfg.tls_certificate_hostnames,
        csr_der_base64: base64::engine::general_purpose::STANDARD.encode(&csr_der),
        cc_init_data_hash: local_cc_init_data_hash(cfg)?,
    };
    let mut rate_limit_rounds = 0u32;
    let body = loop {
        // The attestation token is resolved per attempt: it can expire
        // while a cooldown is being waited out.
        let token = trustee_verify::resolve_kbs_attestation_token(
            crate::env_override("KBS_ATTESTATION_TOKEN").as_deref(),
            &cfg.kbs_attestation_token_url,
            Duration::from_secs(15),
        )
        .context("resolving KBS attestation token for TLS certificate broker")?;
        let mut response = client
            .post(broker_url)
            .header("Authorization", format!("Attestation {token}"))
            .json(&request)
            .send()
            .context("requesting TLS certificate from broker")?;
        let status = response.status();
        let body = read_response_body_bounded(&mut response, MAX_BROKER_RESPONSE_BYTES);
        if status.is_success() {
            break body;
        }
        // Broker failure: consume the bounded body as the safe contract.
        // Unknown, malformed, or unbounded bodies degrade to the generic
        // safe issuance failure; the raw body, the HTTP status, and any
        // provider detail never enter the error, the log, or the typed
        // diagnostic.
        let diagnostic = match body.as_deref() {
            Some(bytes) => broker_failure_diagnostic(bytes, (wait.now)()),
            None => SafeBootstrapDiagnostic::acme_failed(),
        };
        let now = (wait.now)();
        let cooldown = waitable_rate_limit(&diagnostic, now)
            .filter(|_| rate_limit_rounds < ACME_RETRY_MAX_ROUNDS);
        let Some(deadline) = cooldown else {
            clear_acme_cooldown_marker(&wait.cooldown_file);
            tracing::warn!(
                error = diagnostic.code.as_str(),
                terminal = true,
                retry_after = diagnostic.retry_after_rfc3339().as_deref(),
                "static TLS certificate broker issuance attempt failed"
            );
            return Err(anyhow::Error::new(TlsBrokerFailure { diagnostic }));
        };
        // Waitable cooldown: persist the deadline so a pod restart resumes
        // it instead of burning another order, publish the non-terminal
        // marker the proxy's init-ready watch honors, then wait.
        rate_limit_rounds += 1;
        persist_retry_deadline(persistent_root, &request_sha256, deadline)
            .context("recording ACME rate-limit cooldown")?;
        write_acme_cooldown_marker(&wait.cooldown_file, deadline);
        tracing::warn!(
            error = diagnostic.code.as_str(),
            terminal = false,
            retry_after = %deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            round = rate_limit_rounds,
            "ACME rate limit honored; waiting before certificate issuance retry"
        );
        (wait.sleep_until)(deadline);
    };
    clear_acme_cooldown_marker(&wait.cooldown_file);
    clear_persisted_retry_deadline(persistent_root);
    // A success status still has to decode as the bounded certificate
    // response; an unbounded or malformed body is a failed issuance.
    let body: CertificateResponse = body
        .as_deref()
        .and_then(|bytes| serde_json::from_slice(bytes).ok())
        .ok_or_else(|| {
            anyhow::Error::new(TlsBrokerFailure {
                diagnostic: SafeBootstrapDiagnostic::acme_failed(),
            })
        })?;
    validate_certificate_chain(
        &body.certificate_chain_pem,
        &key_pair,
        &cfg.tls_certificate_hostnames,
        trust_anchors,
    )
    .context("validating TLS certificate broker response")?;
    writes::atomic_write(&cert_path, body.certificate_chain_pem.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", cert_path.display()))?;
    Ok(())
}

pub fn cert_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(CERT_RELATIVE_PATH)
}

pub fn key_path(persistent_root: &Path) -> PathBuf {
    persistent_root.join(KEY_RELATIVE_PATH)
}

/// Classify retained TLS state fail-closed: `Ok(true)` for a regular file,
/// `Ok(false)` only for a confirmed missing path (ENOENT). Directories,
/// symlinks (including dangling ones and links to regular files), other
/// non-regular inodes, and stat errors are hard errors — none of them may
/// silently start issuance or be overwritten.
fn retained_path_is_regular_file(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(anyhow!(
                    "{} is a symbolic link; refusing to use or replace it as retained TLS state",
                    path.display()
                ));
            }
            if !file_type.is_file() {
                return Err(anyhow!(
                    "{} is not a regular file; refusing to use or replace it as retained TLS state",
                    path.display()
                ));
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(anyhow!("reading metadata of {}: {error}", path.display())),
    }
}

/// Validate retained TLS state read from the confidential encrypted volume.
fn validate_retained_tls_state(
    trust_anchors: &[TrustAnchor<'_>],
    hostnames: &[String],
    cert_path: &Path,
    key_path: &Path,
) -> Result<()> {
    let chain_pem = std::fs::read_to_string(cert_path)
        .with_context(|| format!("reading retained TLS certificate {}", cert_path.display()))?;
    let key_pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("reading retained TLS private key {}", key_path.display()))?;
    let key_pair = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parsing retained TLS private key {}", key_path.display()))?;
    validate_certificate_chain(&chain_pem, &key_pair, hostnames, trust_anchors)
}

/// Validate a PEM certificate chain against the retained private key, the
/// configured hostnames, and the given trust anchors.
///
/// Checks: PEM blocks are all certificates; the leaf is issued for exactly
/// the retained private key (signature probe verified with the leaf's public
/// key); the leaf covers every configured hostname; and the full chain is
/// anchored via webpki `verify_for_usage` for `serverAuth`, which enforces
/// per-certificate signature verification, issuer validity windows, CA basic
/// constraints and path lengths, name constraints, and serverAuth EKU.
/// Trust derives exclusively from `trust_anchors`; certificates inside the
/// chain (including any trailing self-signed root) never add trust.
fn validate_certificate_chain(
    chain_pem: &str,
    key_pair: &KeyPair,
    hostnames: &[String],
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    let pems = pem::parse_many(chain_pem).context("parsing TLS certificate chain PEM")?;
    if pems.is_empty() {
        return Err(anyhow!("TLS certificate chain contains no PEM blocks"));
    }
    for (index, block) in pems.iter().enumerate() {
        if block.tag() != "CERTIFICATE" {
            return Err(anyhow!(
                "unexpected PEM block {:?} at position {index} in TLS certificate chain",
                block.tag()
            ));
        }
    }
    let certs: Vec<CertificateDer<'static>> = pems
        .iter()
        .map(|block| CertificateDer::from(block.contents().to_vec()))
        .collect();
    let intermediates = &certs[1..];
    let leaf = &certs[0];

    let end_entity = EndEntityCert::try_from(leaf)
        .map_err(|error| anyhow!("parsing TLS leaf certificate: {error}"))?;

    // Leaf/key binding: a signature made with the retained private key must
    // verify under the leaf's public key.
    let signature = key_pair
        .sign(TLS_KEY_BINDING_PROBE)
        .map_err(|error| anyhow!("signing TLS key binding probe: {error}"))?;
    end_entity
        .verify_signature(
            verification_algorithm_for_key(key_pair)?,
            TLS_KEY_BINDING_PROBE,
            &signature,
        )
        .map_err(|_| {
            anyhow!("TLS certificate chain leaf does not match the retained TLS private key")
        })?;

    for hostname in hostnames {
        let server_name = ServerName::try_from(hostname.as_str())
            .with_context(|| format!("interpreting configured TLS hostname {hostname:?}"))?;
        end_entity
            .verify_is_valid_for_subject_name(&server_name)
            .with_context(|| {
                format!("TLS certificate does not cover configured hostname {hostname}")
            })?;
    }

    verify_anchored_path(&end_entity, intermediates, trust_anchors)
}

/// Anchored path validation with a bounded `notBefore` clock-skew retry.
fn verify_anchored_path(
    end_entity: &EndEntityCert<'_>,
    intermediates: &[CertificateDer<'static>],
    trust_anchors: &[TrustAnchor<'_>],
) -> Result<()> {
    let now = UnixTime::now();
    match end_entity.verify_for_usage(
        SUPPORTED_SIG_ALGS,
        trust_anchors,
        intermediates,
        now,
        KeyUsage::server_auth(),
        None,
        None,
    ) {
        Ok(_) => Ok(()),
        // Bounded clock-skew tolerance: if the chain becomes valid within
        // NOT_BEFORE_TOLERANCE_SECS, re-run validation at the certificate's
        // own notBefore time. Expiry remains strict at the current time.
        Err(webpki::Error::CertNotValidYet { not_before, .. })
            if now.as_secs().saturating_add(NOT_BEFORE_TOLERANCE_SECS) >= not_before.as_secs() =>
        {
            end_entity
                .verify_for_usage(
                    SUPPORTED_SIG_ALGS,
                    trust_anchors,
                    intermediates,
                    not_before,
                    KeyUsage::server_auth(),
                    None,
                    None,
                )
                .map(|_| ())
                .map_err(|_| {
                    anyhow!(
                        "TLS certificate is not valid before unix time {}",
                        not_before.as_secs()
                    )
                })
        }
        Err(webpki::Error::CertExpired { not_after, .. }) => Err(anyhow!(
            "TLS certificate chain expired at unix time {}",
            not_after.as_secs()
        )),
        Err(error) => Err(anyhow!(
            "anchored TLS certificate chain validation failed: {error}"
        )),
    }
}

/// Map the retained TLS key's signature algorithm to a webpki verification
/// algorithm for the key-binding probe. Only algorithms rcgen itself can
/// sign with are accepted; every other key family fails closed.
fn verification_algorithm_for_key(
    key_pair: &KeyPair,
) -> Result<&'static dyn SignatureVerificationAlgorithm> {
    let algorithm = key_pair.algorithm();
    if algorithm == &rcgen::PKCS_ED25519 {
        Ok(webpki::ring::ED25519)
    } else if algorithm == &rcgen::PKCS_ECDSA_P256_SHA256 {
        Ok(webpki::ring::ECDSA_P256_SHA256)
    } else if algorithm == &rcgen::PKCS_ECDSA_P384_SHA384 {
        Ok(webpki::ring::ECDSA_P384_SHA384)
    } else {
        Err(anyhow!(
            "unsupported TLS private key signature algorithm {algorithm:?}"
        ))
    }
}

fn load_or_generate_key(path: &Path) -> Result<KeyPair> {
    if retained_path_is_regular_file(path)
        .with_context(|| format!("checking TLS private key {}", path.display()))?
    {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("reading TLS private key {}", path.display()))?;
        return KeyPair::from_pem(&pem)
            .with_context(|| format!("parsing TLS private key {}", path.display()));
    }
    let key_pair = KeyPair::generate().context("generating TLS private key")?;
    writes::atomic_write(path, key_pair.serialize_pem().as_bytes(), 0o600)
        .with_context(|| format!("writing TLS private key {}", path.display()))?;
    Ok(key_pair)
}

fn build_csr_der(hostnames: &[String], key_pair: &KeyPair) -> Result<Vec<u8>> {
    let mut params =
        CertificateParams::new(hostnames.to_vec()).context("building TLS CSR parameters")?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(key_pair)
        .context("serializing TLS CSR")?;
    Ok(csr.der().as_ref().to_vec())
}

fn local_cc_init_data_hash(cfg: &Config) -> Result<Option<String>> {
    let Some(path) = cfg.cc_init_data_path.as_deref() else {
        return Ok(None);
    };
    let bytes = std::fs::read(path).with_context(|| format!("reading cc_init_data from {path}"))?;
    Ok(Some(hex::encode(Sha256::digest(&bytes))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeDelta;
    use rcgen::{BasicConstraints, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer};
    use serde_json::json;
    use std::io::Write as _;
    use std::net::TcpListener;
    use tempfile::tempdir;

    const TEST_HOSTNAMES: &[&str] = &["app.example.test", "www.example.test"];
    /// Synthetic provider secret planted in raw/malformed broker bodies; it
    /// must never reach any error chain, log field, or written file.
    const SYNTHETIC_PROVIDER_SENTINEL: &str = "SYNTHETIC-PROVIDER-SECRET";

    struct TestRoot {
        params: CertificateParams,
        key: KeyPair,
        cert: rcgen::Certificate,
        der: CertificateDer<'static>,
    }

    impl TestRoot {
        fn anchor(&self) -> TrustAnchor<'_> {
            webpki::anchor_from_trusted_cert(&self.der)
                .expect("synthetic root parses as trust anchor")
        }
    }

    fn mint_root(name: &str) -> TestRoot {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let der = CertificateDer::from(cert.der().to_vec());
        TestRoot {
            params,
            key,
            cert,
            der,
        }
    }

    struct TestChain {
        chain_pem: String,
        leaf_key_pem: String,
    }

    fn mint_leaf(
        issuer_params: &CertificateParams,
        issuer_key: &KeyPair,
        hostnames: &[&str],
        tweak_leaf: impl FnOnce(&mut CertificateParams),
    ) -> TestChain {
        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params =
            CertificateParams::new(hostnames.iter().map(|h| h.to_string()).collect::<Vec<_>>())
                .unwrap();
        tweak_leaf(&mut leaf_params);
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &Issuer::from_params(issuer_params, issuer_key))
            .unwrap();
        TestChain {
            chain_pem: leaf_cert.pem(),
            leaf_key_pem: leaf_key.serialize_pem(),
        }
    }

    fn mint_test_chain(
        hostnames: &[&str],
        tweak_leaf: impl FnOnce(&mut CertificateParams),
    ) -> (TestRoot, TestChain) {
        let root = mint_root("Enclava Test Root CA");
        let chain = mint_leaf(&root.params, &root.key, hostnames, tweak_leaf);
        (root, chain)
    }

    fn broker_config(dir: &Path, hostnames: &[&str]) -> Config {
        broker_config_with_endpoints(
            dir,
            hostnames,
            "http://127.0.0.1:9/",
            "http://127.0.0.1:8006/aa/token?token_type=kbs",
        )
    }

    /// Broker config whose attestation-token and broker endpoints both
    /// point at a local test server, so provisioning reaches the real HTTP
    /// response handling without any external service.
    fn broker_config_with_endpoints(
        dir: &Path,
        hostnames: &[&str],
        broker_url: &str,
        token_url: &str,
    ) -> Config {
        let cfg_path = dir.join("config.toml");
        let hostnames_list = hostnames
            .iter()
            .map(|h| format!("\"{h}\""))
            .collect::<Vec<_>>()
            .join(", ");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
mode = "autounlock"
tls-certificate-broker-url = "{broker_url}"
tls-certificate-hostnames = [{hostnames_list}]
kbs-attestation-token-url = "{token_url}"

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#
            ),
        )
        .unwrap();
        Config::load(&cfg_path).unwrap()
    }

    /// Minimal local HTTP server: `GET .../kbs-token` serves an attestation
    /// token, every other request (the broker POST) gets the given status
    /// line and body. Handles one connection at a time until the test
    /// process drops it.
    fn spawn_local_broker(
        token_status_line: &str,
        broker_status_line: &str,
        broker_body: String,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let token_status_line = token_status_line.to_string();
        let broker_status_line = broker_status_line.to_string();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => head.push(byte[0]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let content_length = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0u8; content_length];
                if content_length > 0 {
                    stream.read_exact(&mut request_body).ok();
                }
                let (status_line, body) = if head.starts_with("GET /kbs-token") {
                    (
                        token_status_line.clone(),
                        "{\"token\":\"test-token\"}".to_string(),
                    )
                } else {
                    (broker_status_line.clone(), broker_body.clone())
                };
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).ok();
                stream.flush().ok();
            }
        });
        (base, handle)
    }

    fn write_retained_state(dir: &Path, chain_pem: &str, key_pem: &str) -> PathBuf {
        let persistent = dir.join("persistent");
        writes::atomic_write(&cert_path(&persistent), chain_pem.as_bytes(), 0o644).unwrap();
        writes::atomic_write(&key_path(&persistent), key_pem.as_bytes(), 0o600).unwrap();
        persistent
    }

    /// Full leaf -> (optional intermediate) -> root chain PEM, including the
    /// root itself, exactly like ACME providers deliver chains.
    fn full_chain_pem(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn certificate_paths_match_caddyfile_static_tls_paths() {
        let root = Path::new("/state/tls-state/tenant-ingress");
        assert_eq!(
            cert_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.crt")
        );
        assert_eq!(
            key_path(root),
            PathBuf::from("/state/tls-state/tenant-ingress/certificates/tls.key")
        );
    }

    #[test]
    fn generated_key_is_persisted_and_reused_for_csrs() {
        let dir = tempdir().unwrap();
        let key_path = key_path(dir.path());
        let hosts = vec!["app.example.test".to_string()];

        let first_key = load_or_generate_key(&key_path).unwrap();
        let first_pem = std::fs::read_to_string(&key_path).unwrap();
        let first_csr = build_csr_der(&hosts, &first_key).unwrap();
        let second_key = load_or_generate_key(&key_path).unwrap();
        let second_pem = std::fs::read_to_string(&key_path).unwrap();
        let second_csr = build_csr_der(&hosts, &second_key).unwrap();

        assert!(KeyPair::from_pem(&first_pem).is_ok());
        assert_eq!(first_pem, second_pem);
        assert!(!first_csr.is_empty());
        assert!(!second_csr.is_empty());
    }

    #[test]
    fn local_cc_init_data_hash_reads_signed_runtime_toml() {
        let dir = tempdir().unwrap();
        let cc_path = dir.path().join("cc-init-data.toml");
        std::fs::write(&cc_path, b"descriptor_core_hash = \"abc\"\n").unwrap();
        let cfg_path = dir.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            format!(
                r#"
mode = "autounlock"
cc-init-data-path = "{}"

[state]
device = "/dev/csi0"
mapping-name = "cap-state"
mount-path = "/state/app-data"
hkdf-info = "state-luks-key"

[tls-state]
device = "/dev/csi1"
mapping-name = "cap-tls-state"
mount-path = "/state/tls-state"
hkdf-info = "tls-state-luks-key"
"#,
                cc_path.display()
            ),
        )
        .unwrap();
        let cfg = Config::load(&cfg_path).unwrap();

        assert_eq!(
            local_cc_init_data_hash(&cfg).unwrap(),
            Some(hex::encode(Sha256::digest(
                b"descriptor_core_hash = \"abc\"\n"
            )))
        );
    }

    #[test]
    fn retained_valid_anchored_certificate_is_reused_repeatedly_without_broker_calls() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        // The broker URL points at an unroutable address: any broker contact
        // makes provisioning fail, so two clean runs prove zero broker calls.
        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();
        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();

        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_valid_chain_with_intermediate_and_root_validates_anchored() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &intermediate_cert.pem(), &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap();
    }

    #[test]
    fn retained_expired_certificate_fails_closed_without_reissue_or_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("expired"), "unexpected error: {message}");
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_not_yet_valid_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.not_before = rcgen::date_time_ymd(3000, 1, 1);
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed") || message.contains("not valid"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_key_mismatch_fails_closed_without_key_replacement() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let unrelated_key_pem = KeyPair::generate().unwrap().serialize_pem();
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &unrelated_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();
        let key_before = std::fs::read(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("does not match the retained TLS private key"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
        assert_eq!(std::fs::read(key_path(&persistent)).unwrap(), key_before);
    }

    #[test]
    fn retained_hostname_mismatch_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), &["app.example.test"]);
        let (root, chain) = mint_test_chain(&["other.example.test"], |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("does not cover configured hostname app.example.test"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_leaf_only_chain_missing_intermediate_fails_closed() {
        // A lone leaf whose issuer (an intermediate) is not delivered cannot
        // reach a trust anchor on its own; the old adjacency loop accepted
        // leaf-only chains without any issuer verification.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        // Chain delivers the leaf only, without the issuing intermediate.
        let persistent = write_retained_state(dir.path(), &chain.chain_pem, &chain.leaf_key_pem);
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_self_signed_leaf_chain_fails_closed() {
        // A self-signed leaf is its own issuer; without the issuing key being
        // a configured anchor this must fail closed.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, _) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];

        let self_signed_key = KeyPair::generate().unwrap();
        let params = CertificateParams::new(
            TEST_HOSTNAMES
                .iter()
                .map(|h| h.to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let self_signed = params.self_signed(&self_signed_key).unwrap();
        let persistent = write_retained_state(
            dir.path(),
            &self_signed.pem(),
            &self_signed_key.serialize_pem(),
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_chain_from_untrusted_root_fails_closed() {
        // Chain is fully valid internally but rooted at a CA that is not in
        // the configured anchor set: no trust, no reuse.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (trusted_root, _) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let (untrusted_root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [trusted_root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &untrusted_root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_chain_missing_its_intermediate_fails_closed() {
        // Leaf issued by an intermediate, chain carries the root but not the
        // intermediate: the gap must not be bridged by trusting the chain's
        // own last certificate.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        // Chain delivers leaf + root, skipping the issuing intermediate.
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_expired_intermediate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);

        let root = mint_root("Enclava Test Root CA");
        let intermediate_key = KeyPair::generate().unwrap();
        let mut intermediate_params = CertificateParams::default();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        intermediate_params.not_after = rcgen::date_time_ymd(2000, 1, 1);
        let intermediate_cert = intermediate_params
            .signed_by(
                &intermediate_key,
                &Issuer::from_params(&root.params, &root.key),
            )
            .unwrap();
        let chain = mint_leaf(
            &intermediate_params,
            &intermediate_key,
            TEST_HOSTNAMES,
            |_| {},
        );
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &intermediate_cert.pem(), &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("expired"), "unexpected error: {message}");
    }

    #[test]
    fn retained_wrong_eku_leaf_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |params| {
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        });
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn production_public_roots_reject_synthetic_and_staging_like_chains() {
        // The production entry has no anchor parameter: it always validates
        // against the public webpki-roots store. Any chain not leading to a
        // public root — including synthetic CAs and, by the same mechanism,
        // Let's Encrypt staging chains whose roots are absent from the
        // public store — is rejected by default.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (synthetic_root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let synthetic_chain = full_chain_pem(&[&chain.chain_pem, &synthetic_root.cert.pem()]);
        let persistent = write_retained_state(dir.path(), &synthetic_chain, &chain.leaf_key_pem);

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("validation failed"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn retained_certificate_without_private_key_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = dir.path().join("persistent");
        writes::atomic_write(
            &cert_path(&persistent),
            full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]).as_bytes(),
            0o644,
        )
        .unwrap();
        let cert_before = std::fs::read(cert_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("private key") && message.contains("missing"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
        assert_eq!(std::fs::read(cert_path(&persistent)).unwrap(), cert_before);
    }

    #[test]
    fn retained_malformed_certificate_chain_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, valid_chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let full = full_chain_pem(&[&valid_chain.chain_pem, &root.cert.pem()]);

        for malformed in [
            "not a pem certificate".to_string(),
            format!(
                "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
                base64::engine::general_purpose::STANDARD.encode(b"junk not der")
            ),
            String::new(),
            full[..full.find("-----END CERTIFICATE-----").unwrap()].to_string(),
        ] {
            let persistent =
                write_retained_state(dir.path(), &malformed, &valid_chain.leaf_key_pem);
            assert!(
                provision_with_trust_anchors(&cfg, &persistent, &anchors).is_err(),
                "expected failure for malformed chain: {malformed}"
            );
        }
    }

    #[test]
    fn directory_at_cert_path_never_reaches_broker() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not a regular file"),
            "unexpected error: {message}"
        );
        // No issuance side effects: the key was never generated.
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn dangling_symlink_at_cert_path_never_reaches_broker() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(
            persistent.join("does-not-exist.crt"),
            cert_path(&persistent),
        )
        .unwrap();

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn symlink_to_regular_certificate_is_rejected() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let real = dir.path().join("real.crt");
        std::fs::write(&real, full_chain_pem(&[&chain.chain_pem, &root.cert.pem()])).unwrap();
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(cert_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&real, cert_path(&persistent)).unwrap();

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
        assert!(!key_path(&persistent).exists());
    }

    #[test]
    fn directory_at_key_path_with_retained_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        std::fs::remove_file(key_path(&persistent)).unwrap();
        std::fs::create_dir_all(key_path(&persistent)).unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("not a regular file"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn dangling_symlink_at_key_path_with_retained_certificate_fails_closed() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let (root, chain) = mint_test_chain(TEST_HOSTNAMES, |_| {});
        let anchors = [root.anchor()];
        let persistent = write_retained_state(
            dir.path(),
            &full_chain_pem(&[&chain.chain_pem, &root.cert.pem()]),
            &chain.leaf_key_pem,
        );
        std::fs::remove_file(key_path(&persistent)).unwrap();
        std::os::unix::fs::symlink(persistent.join("does-not-exist.key"), key_path(&persistent))
            .unwrap();

        let error = provision_with_trust_anchors(&cfg, &persistent, &anchors).unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn missing_cert_with_retained_key_retries_issuance_with_same_key() {
        // Interrupted-initial-issuance semantics: only a genuinely missing
        // certificate (ENOENT) starts issuance, and the retained key is
        // reused for the new CSR. No KBS runs locally and the broker URL is
        // unroutable, so the issuance attempt surfaces at the attestation
        // token step — after the CSR was built from the retained key — and
        // the key file is provably unchanged.
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let key_pem = KeyPair::generate().unwrap().serialize_pem();
        let persistent = dir.path().join("persistent");
        writes::atomic_write(&key_path(&persistent), key_pem.as_bytes(), 0o600).unwrap();

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("KBS attestation token"),
            "unexpected error: {message}"
        );
        assert_eq!(
            std::fs::read_to_string(key_path(&persistent)).unwrap(),
            key_pem
        );
        assert!(!cert_path(&persistent).exists());
    }

    #[test]
    fn symlink_at_key_path_blocks_issuance_before_broker_contact() {
        let dir = tempdir().unwrap();
        let cfg = broker_config(dir.path(), TEST_HOSTNAMES);
        let persistent = dir.path().join("persistent");
        std::fs::create_dir_all(key_path(&persistent).parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(persistent.join("does-not-exist.key"), key_path(&persistent))
            .unwrap();

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("symbolic link"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn broker_failure_contract_keeps_rate_limit_code_and_validated_deadline() {
        let now = chrono::SubsecRound::trunc_subsecs(Utc::now(), 0);
        let deadline = now + TimeDelta::hours(3);
        let body = json!({
            "error": "acme_rate_limited",
            "terminal": true,
            "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
        .to_string();

        let diagnostic = broker_failure_diagnostic(body.as_bytes(), now);

        assert_eq!(diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(diagnostic.retry_after, Some(deadline));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&diagnostic.render_json()).unwrap(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
        );
    }

    #[test]
    fn elapsed_broker_deadline_keeps_terminal_rate_limit_failure() {
        // Contract coordination: an elapsed (past) bounded deadline does not
        // erase the terminal failure — the code and timestamp are preserved
        // and rendered, and no automatic certificate retry happens here.
        let now = chrono::SubsecRound::trunc_subsecs(Utc::now(), 0);
        let elapsed = now - TimeDelta::hours(2);
        let body = json!({
            "error": "acme_rate_limited",
            "terminal": true,
            "retry_after": elapsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
        .to_string();

        let diagnostic = broker_failure_diagnostic(body.as_bytes(), now);

        assert_eq!(diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(diagnostic.retry_after, Some(elapsed));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&diagnostic.render_json()).unwrap(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": elapsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
        );
    }

    #[test]
    fn broker_failure_contract_generic_code_has_null_deadline() {
        let now = Utc::now();
        for body in [
            json!({
                "error": "acme_certificate_issuance_failed",
                "terminal": true,
                "retry_after": null,
            })
            .to_string(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": null,
            })
            .to_string(),
        ] {
            let diagnostic = broker_failure_diagnostic(body.as_bytes(), now);
            assert_eq!(diagnostic.retry_after, None);
        }
    }

    #[test]
    fn unknown_malformed_and_secret_bearing_broker_bodies_fail_safe() {
        let now = Utc::now();
        let valid_deadline =
            (now + TimeDelta::hours(1)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        // Bodies that must degrade to the generic safe terminal failure.
        for body in [
            // Raw provider prose instead of the contract.
            format!("provider said {SYNTHETIC_PROVIDER_SENTINEL}: quota exhausted"),
            // Unknown error code carrying provider detail.
            json!({
                "error": "brand_new_provider_code",
                "terminal": true,
                "detail": SYNTHETIC_PROVIDER_SENTINEL,
            })
            .to_string(),
            // Recognized code but non-terminal contract.
            json!({
                "error": "acme_rate_limited",
                "terminal": false,
                "retry_after": valid_deadline,
            })
            .to_string(),
            // Missing terminal field.
            json!({
                "error": "acme_rate_limited",
                "retry_after": valid_deadline,
            })
            .to_string(),
            // Wrong-typed fields.
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": 42,
            })
            .to_string(),
            // Not JSON at all / empty.
            String::new(),
            "<<html>502</html>".to_string(),
        ] {
            let diagnostic = broker_failure_diagnostic(body.as_bytes(), now);
            assert_eq!(
                diagnostic.code,
                SafeDiagnosticCode::AcmeCertificateIssuanceFailed,
                "unknown/malformed body must degrade to the safe terminal issuance failure: {body}"
            );
            assert_eq!(diagnostic.retry_after, None, "no deadline from: {body}");
            let rendered = diagnostic.render_json();
            assert!(
                !rendered.contains(SYNTHETIC_PROVIDER_SENTINEL),
                "rendered diagnostic leaked provider text: {rendered}"
            );
        }

        // Recognized codes with an absent, malformed, non-UTC, or
        // out-of-bounds deadline keep their code and lose the deadline.
        for body in [
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": SYNTHETIC_PROVIDER_SENTINEL,
            })
            .to_string(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": "2026-09-10T09:30:00+02:00",
            })
            .to_string(),
            json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": "9999-12-31T23:59:59Z",
            })
            .to_string(),
            json!({
                "error": "acme_certificate_issuance_failed",
                "terminal": true,
                "retry_after": "not-a-date",
            })
            .to_string(),
        ] {
            let diagnostic = broker_failure_diagnostic(body.as_bytes(), now);
            assert_eq!(
                diagnostic.retry_after, None,
                "unusable deadline must be absent: {body}"
            );
            let rendered = diagnostic.render_json();
            assert!(
                !rendered.contains(SYNTHETIC_PROVIDER_SENTINEL),
                "rendered diagnostic leaked provider text: {rendered}"
            );
        }
    }

    #[test]
    fn broker_terminal_failure_reaches_provisioning_error_as_typed_diagnostic() {
        let dir = tempdir().unwrap();
        // Beyond the honored single-wait bound: the diagnostic is preserved
        // but the production wait policy must not actually sleep here.
        let deadline = Utc::now() + TimeDelta::seconds(ACME_RETRY_MAX_WAIT_SECS + 3600);
        let deadline_rfc3339 = deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let body = json!({
            "error": "acme_rate_limited",
            "terminal": true,
            "retry_after": deadline_rfc3339,
            // Unknown contract fields must never surface anywhere.
            "detail": SYNTHETIC_PROVIDER_SENTINEL,
        })
        .to_string();
        let (base, _server) = spawn_local_broker("200 OK", "502 Bad Gateway", body);
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();

        let failure = error
            .downcast_ref::<TlsBrokerFailure>()
            .expect("terminal broker failure must be the typed error");
        assert_eq!(failure.diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(
            failure
                .diagnostic
                .retry_after
                .map(|deadline| deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            Some(deadline_rfc3339)
        );
        // Even the full anyhow chain (what failure reporting used to print)
        // carries no provider detail.
        let chain = format!("{error:#}");
        assert!(!chain.contains(SYNTHETIC_PROVIDER_SENTINEL));
        assert!(!cert_path(&persistent).exists());
    }

    #[test]
    fn broker_raw_failure_text_never_reaches_error_or_files() {
        let dir = tempdir().unwrap();
        let body = format!("upstream ACME problem: {SYNTHETIC_PROVIDER_SENTINEL}");
        let (base, _server) = spawn_local_broker("200 OK", "502 Bad Gateway", body);
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();

        let failure = error
            .downcast_ref::<TlsBrokerFailure>()
            .expect("terminal broker failure must be the typed error");
        assert_eq!(
            failure.diagnostic.code,
            SafeDiagnosticCode::AcmeCertificateIssuanceFailed
        );
        assert_eq!(failure.diagnostic.retry_after, None);
        let chain = format!("{error:#}");
        assert!(!chain.contains(SYNTHETIC_PROVIDER_SENTINEL));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&failure.diagnostic.render_json()).unwrap(),
            json!({
                "error": "acme_certificate_issuance_failed",
                "terminal": true,
                "retry_after": null,
            })
        );
    }

    #[test]
    fn broker_success_status_with_malformed_body_is_safe_terminal_failure() {
        let dir = tempdir().unwrap();
        let body = format!("not json {SYNTHETIC_PROVIDER_SENTINEL}");
        let (base, _server) = spawn_local_broker("200 OK", "200 OK", body);
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();

        let failure = error
            .downcast_ref::<TlsBrokerFailure>()
            .expect("malformed success body must be a typed broker failure");
        assert_eq!(
            failure.diagnostic.code,
            SafeDiagnosticCode::AcmeCertificateIssuanceFailed
        );
        assert_eq!(failure.diagnostic.retry_after, None);
        assert!(!format!("{error:#}").contains(SYNTHETIC_PROVIDER_SENTINEL));
        assert!(!cert_path(&persistent).exists());
    }

    #[test]
    fn oversized_broker_body_is_rejected_before_buffering_or_surfacing() {
        let dir = tempdir().unwrap();
        let mut body = format!("{{\"error\":\"{SYNTHETIC_PROVIDER_SENTINEL}\"");
        body.push_str(&"x".repeat(MAX_BROKER_RESPONSE_BYTES));
        let (base, _server) = spawn_local_broker("200 OK", "502 Bad Gateway", body);
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");

        let error = provision_static_tls_certificate(
            &cfg,
            &persistent,
            &dir.path().join("init-acme-cooldown"),
        )
        .unwrap_err();

        let failure = error
            .downcast_ref::<TlsBrokerFailure>()
            .expect("unbounded body must be a typed broker failure");
        assert_eq!(
            failure.diagnostic.code,
            SafeDiagnosticCode::AcmeCertificateIssuanceFailed
        );
        assert_eq!(failure.diagnostic.retry_after, None);
        assert!(!format!("{error:#}").contains(SYNTHETIC_PROVIDER_SENTINEL));
    }

    /// Scripted variant of [`spawn_local_broker`]: `GET /kbs-token` always
    /// serves a token; every other request (broker POST) pops the next
    /// `(status_line, body)` response, repeating the last one when the
    /// script is exhausted. `events` records `"post"` for each broker POST
    /// so tests can assert ordering against waits.
    fn spawn_scripted_broker(
        broker_script: Vec<(String, String)>,
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let script = std::sync::Arc::new(std::sync::Mutex::new(
            broker_script
                .into_iter()
                .collect::<std::collections::VecDeque<_>>(),
        ));
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => head.push(byte[0]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let content_length = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0u8; content_length];
                if content_length > 0 {
                    stream.read_exact(&mut request_body).ok();
                }
                let (status_line, body) = if head.starts_with("GET /kbs-token") {
                    (
                        "200 OK".to_string(),
                        "{\"token\":\"test-token\"}".to_string(),
                    )
                } else {
                    events.lock().unwrap().push("post".to_string());
                    let mut script = script.lock().unwrap();
                    match script.len() {
                        0 => panic!("broker script exhausted"),
                        1 => script.front().unwrap().clone(),
                        _ => script.pop_front().unwrap(),
                    }
                };
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).ok();
                stream.flush().ok();
            }
        });
        (base, handle)
    }

    /// Mint a leaf for an explicitly supplied key — needed when the broker
    /// success response must validate against the retained workload key.
    fn mint_leaf_for_key(
        issuer_params: &CertificateParams,
        issuer_key: &KeyPair,
        leaf_key: &KeyPair,
        hostnames: &[&str],
    ) -> String {
        let leaf_params =
            CertificateParams::new(hostnames.iter().map(|h| h.to_string()).collect::<Vec<_>>())
                .unwrap();
        leaf_params
            .signed_by(leaf_key, &Issuer::from_params(issuer_params, issuer_key))
            .unwrap()
            .pem()
    }

    /// Deterministic ACME wait: a fake clock that `sleep_until` advances
    /// to the deadline, recording each requested wake time and an event.
    struct FakeClock {
        now: std::sync::Mutex<DateTime<Utc>>,
        sleeps: std::sync::Mutex<Vec<DateTime<Utc>>>,
    }

    fn fake_wait(
        cooldown_file: PathBuf,
        start: DateTime<Utc>,
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (AcmeWait, std::sync::Arc<FakeClock>) {
        let clock = std::sync::Arc::new(FakeClock {
            now: std::sync::Mutex::new(start),
            sleeps: std::sync::Mutex::new(Vec::new()),
        });
        let now_clock = clock.clone();
        let sleep_clock = clock.clone();
        (
            AcmeWait {
                cooldown_file,
                now: Box::new(move || *now_clock.now.lock().unwrap()),
                sleep_until: Box::new(move |deadline| {
                    events.lock().unwrap().push("sleep".to_string());
                    sleep_clock.sleeps.lock().unwrap().push(deadline);
                    *sleep_clock.now.lock().unwrap() = deadline;
                }),
            },
            clock,
        )
    }

    fn rate_limited_body(retry_after: Option<DateTime<Utc>>) -> String {
        json!({
            "error": "acme_rate_limited",
            "terminal": true,
            "retry_after": retry_after
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        })
        .to_string()
    }

    /// Workload key + a valid anchored chain minted for it, with only the
    /// key retained on the persistent root (interrupted-first-issuance
    /// state): issuance must POST and then succeed with the chain.
    fn seed_retained_key_and_chain(dir: &Path, hostnames: &[&str]) -> (TestRoot, String, PathBuf) {
        let root = mint_root("Enclava Test Root CA");
        let leaf_key = KeyPair::generate().unwrap();
        let chain_pem = mint_leaf_for_key(&root.params, &root.key, &leaf_key, hostnames);
        let persistent = dir.join("persistent");
        writes::atomic_write(
            &key_path(&persistent),
            leaf_key.serialize_pem().as_bytes(),
            0o600,
        )
        .unwrap();
        let full_chain = full_chain_pem(&[&chain_pem, &root.cert.pem()]);
        (root, full_chain, persistent)
    }

    #[test]
    fn rate_limited_cooldown_waits_then_retries_to_success() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        let deadline = start + TimeDelta::minutes(30);
        let (root, chain_pem, persistent) = seed_retained_key_and_chain(dir.path(), TEST_HOSTNAMES);
        let anchors = [root.anchor()];
        let success_body = json!({"certificate_chain_pem": chain_pem}).to_string();
        let (base, _server) = spawn_scripted_broker(
            vec![
                (
                    "503 Service Unavailable".to_string(),
                    rate_limited_body(Some(deadline)),
                ),
                ("200 OK".to_string(), success_body),
            ],
            events.clone(),
        );
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let cooldown = dir.path().join("init-acme-cooldown");
        let (wait, clock) = fake_wait(cooldown.clone(), start, events.clone());

        provision_with_policy(&cfg, &persistent, &anchors, &wait).unwrap();

        assert_eq!(*clock.sleeps.lock().unwrap(), vec![deadline]);
        assert_eq!(*events.lock().unwrap(), vec!["post", "sleep", "post"]);
        // The certificate landed and both markers were cleared.
        assert!(cert_path(&persistent).exists());
        assert!(!acme_retry_marker_path(&persistent).exists());
        assert!(!cooldown.exists());
    }

    #[test]
    fn rate_limited_without_deadline_stays_terminal_without_waiting() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (base, _server) = spawn_scripted_broker(
            vec![(
                "503 Service Unavailable".to_string(),
                rate_limited_body(None),
            )],
            events,
        );
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");
        // The cfg(test) seam panics on any attempted wait — a regression
        // that turns this into a cooldown fails loudly.
        let root = mint_root("R");
        let error = provision_with_trust_anchors(&cfg, &persistent, &[root.anchor()]).unwrap_err();
        let failure = error.downcast_ref::<TlsBrokerFailure>().unwrap();
        assert_eq!(failure.diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(failure.diagnostic.retry_after, None);
    }

    #[test]
    fn rate_limited_beyond_wait_bound_stays_terminal() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        // One second past the single-wait bound.
        let deadline = start + TimeDelta::seconds(ACME_RETRY_MAX_WAIT_SECS + 1);
        let (base, _server) = spawn_scripted_broker(
            vec![(
                "503 Service Unavailable".to_string(),
                rate_limited_body(Some(deadline)),
            )],
            events.clone(),
        );
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");
        let (wait, clock) = fake_wait(dir.path().join("init-acme-cooldown"), start, events.clone());
        let root = mint_root("R");
        let anchors = [root.anchor()];

        let error = provision_with_policy(&cfg, &persistent, &anchors, &wait).unwrap_err();

        let failure = error.downcast_ref::<TlsBrokerFailure>().unwrap();
        assert_eq!(failure.diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(failure.diagnostic.retry_after, Some(deadline));
        assert!(clock.sleeps.lock().unwrap().is_empty());
        assert_eq!(*events.lock().unwrap(), vec!["post"]);
    }

    /// Broker that answers every POST with `acme_rate_limited` carrying a
    /// deadline `period_secs` ahead of the injected clock — used to prove
    /// the retry-rounds bound against a provider that never stops
    /// rate-limiting.
    fn spawn_rate_limited_broker(
        now: std::sync::Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
        period_secs: i64,
        events: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) => break,
                        Ok(_) => head.push(byte[0]),
                        Err(_) => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let content_length = head
                    .to_ascii_lowercase()
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut request_body = vec![0u8; content_length];
                if content_length > 0 {
                    stream.read_exact(&mut request_body).ok();
                }
                let (status_line, body) = if head.starts_with("GET /kbs-token") {
                    (
                        "200 OK".to_string(),
                        "{\"token\":\"test-token\"}".to_string(),
                    )
                } else {
                    events.lock().unwrap().push("post".to_string());
                    let deadline = now() + TimeDelta::seconds(period_secs);
                    (
                        "503 Service Unavailable".to_string(),
                        rate_limited_body(Some(deadline)),
                    )
                };
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).ok();
                stream.flush().ok();
            }
        });
        (base, handle)
    }

    #[test]
    fn rate_limited_rounds_are_bounded_then_terminal() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        let persistent = dir.path().join("persistent");
        let (wait, clock) = fake_wait(dir.path().join("init-acme-cooldown"), start, events.clone());
        let now_fn = {
            let clock = clock.clone();
            move || *clock.now.lock().unwrap()
        };
        let (base, _server) =
            spawn_rate_limited_broker(std::sync::Arc::new(now_fn), 1800, events.clone());
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let root = mint_root("R");
        let anchors = [root.anchor()];

        let error = provision_with_policy(&cfg, &persistent, &anchors, &wait).unwrap_err();

        // Every round is honored, then the cap converts the last
        // diagnostic into a terminal failure — the provider can never
        // hold the certificate phase open forever.
        let failure = error.downcast_ref::<TlsBrokerFailure>().unwrap();
        assert_eq!(failure.diagnostic.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(
            clock.sleeps.lock().unwrap().len() as u32,
            ACME_RETRY_MAX_ROUNDS
        );
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|e| *e == "post")
                .count() as u32,
            ACME_RETRY_MAX_ROUNDS + 1
        );
        // The final diagnostic keeps the provider's last deadline.
        assert_eq!(
            failure.diagnostic.retry_after,
            Some(start + TimeDelta::seconds(1800 * (ACME_RETRY_MAX_ROUNDS as i64 + 1)))
        );
    }

    #[test]
    fn waitable_rate_limit_predicate_is_exact() {
        let now = DateTime::from_timestamp(1789000000, 0).unwrap();
        let fresh = SafeBootstrapDiagnostic {
            code: SafeDiagnosticCode::AcmeRateLimited,
            retry_after: Some(now + TimeDelta::minutes(30)),
        };
        assert_eq!(
            waitable_rate_limit(&fresh, now),
            Some(now + TimeDelta::minutes(30))
        );
        // Elapsed, absent, and out-of-bounds deadlines are not waitable.
        for retry_after in [
            Some(now - TimeDelta::minutes(1)),
            None,
            Some(now + TimeDelta::seconds(ACME_RETRY_MAX_WAIT_SECS + 1)),
        ] {
            let diagnostic = SafeBootstrapDiagnostic {
                code: SafeDiagnosticCode::AcmeRateLimited,
                retry_after,
            };
            assert_eq!(waitable_rate_limit(&diagnostic, now), None);
        }
        // Non-rate-limit codes are never waitable.
        let other = SafeBootstrapDiagnostic::acme_failed();
        assert_eq!(waitable_rate_limit(&other, now), None);
    }

    #[test]
    fn persisted_deadline_resumes_wait_before_new_order() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        let deadline = start + TimeDelta::minutes(45);
        let (root, chain_pem, persistent) = seed_retained_key_and_chain(dir.path(), TEST_HOSTNAMES);
        let anchors = [root.anchor()];
        // Bind the persisted marker to the exact request the retained key
        // and configured hostnames produce.
        let hosts: Vec<String> = TEST_HOSTNAMES.iter().map(|h| h.to_string()).collect();
        let fingerprint = acme_request_fingerprint(
            &std::fs::read_to_string(key_path(&persistent)).unwrap(),
            &hosts,
        );
        persist_retry_deadline(&persistent, &fingerprint, deadline).unwrap();
        let success_body = json!({"certificate_chain_pem": chain_pem}).to_string();
        let (base, _server) =
            spawn_scripted_broker(vec![("200 OK".to_string(), success_body)], events.clone());
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let (wait, clock) = fake_wait(dir.path().join("init-acme-cooldown"), start, events.clone());

        provision_with_policy(&cfg, &persistent, &anchors, &wait).unwrap();

        // The wait resumed before any broker POST: no order was burned.
        assert_eq!(*clock.sleeps.lock().unwrap(), vec![deadline]);
        assert_eq!(*events.lock().unwrap(), vec!["sleep", "post"]);
        assert!(cert_path(&persistent).exists());
        assert!(!acme_retry_marker_path(&persistent).exists());
    }

    #[test]
    fn mismatched_persisted_deadline_is_dropped_and_ignored() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        let deadline = start + TimeDelta::minutes(45);
        let (root, chain_pem, persistent) = seed_retained_key_and_chain(dir.path(), TEST_HOSTNAMES);
        let anchors = [root.anchor()];
        // A marker bound to a different CSR must not suppress issuance.
        persist_retry_deadline(&persistent, &"00".repeat(32), deadline).unwrap();
        let success_body = json!({"certificate_chain_pem": chain_pem}).to_string();
        let (base, _server) =
            spawn_scripted_broker(vec![("200 OK".to_string(), success_body)], events.clone());
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let (wait, clock) = fake_wait(dir.path().join("init-acme-cooldown"), start, events.clone());

        provision_with_policy(&cfg, &persistent, &anchors, &wait).unwrap();

        assert!(clock.sleeps.lock().unwrap().is_empty());
        assert_eq!(*events.lock().unwrap(), vec!["post"]);
        assert!(!acme_retry_marker_path(&persistent).exists());
    }

    #[test]
    fn cooldown_marker_carries_non_terminal_safe_contract() {
        let dir = tempdir().unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let start = DateTime::from_timestamp(1789000000, 0).unwrap();
        let deadline = start + TimeDelta::minutes(30);
        let cooldown = dir.path().join("init-acme-cooldown");
        // Observed marker content while the wait is in progress.
        let observed = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
        let (base, _server) = spawn_scripted_broker(
            vec![(
                "503 Service Unavailable".to_string(),
                rate_limited_body(Some(deadline)),
            )],
            events,
        );
        let cfg = broker_config_with_endpoints(
            dir.path(),
            TEST_HOSTNAMES,
            &format!("{base}/broker"),
            &format!("{base}/kbs-token"),
        );
        let persistent = dir.path().join("persistent");
        let clock = std::sync::Arc::new(FakeClock {
            now: std::sync::Mutex::new(start),
            sleeps: std::sync::Mutex::new(Vec::new()),
        });
        let observed_in_sleep = observed.clone();
        let cooldown_in_sleep = cooldown.clone();
        let now_clock = clock.clone();
        let sleep_clock = clock.clone();
        let wait = AcmeWait {
            cooldown_file: cooldown.clone(),
            now: Box::new(move || *now_clock.now.lock().unwrap()),
            sleep_until: Box::new(move |d| {
                *observed_in_sleep.lock().unwrap() =
                    std::fs::read_to_string(&cooldown_in_sleep).ok();
                sleep_clock.sleeps.lock().unwrap().push(d);
                *sleep_clock.now.lock().unwrap() = d;
            }),
        };
        let root = mint_root("R");
        let anchors = [root.anchor()];

        // The wait happens; the second POST is an unroutable-address
        // failure only if the script breaks — the marker was observed
        // during the wait, which is what this test asserts.
        let _ = provision_with_policy(&cfg, &persistent, &anchors, &wait);

        let marker = observed
            .lock()
            .unwrap()
            .clone()
            .expect("cooldown marker must exist while waiting");
        let parsed: serde_json::Value = serde_json::from_str(&marker).unwrap();
        assert_eq!(
            parsed,
            json!({
                "error": "acme_rate_limited",
                "terminal": false,
                "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "retry_after_unix": deadline.timestamp(),
            })
        );
    }
}
