//! AMD KDS collateral for reports whose evidence carries no anchored chain.

use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, LazyLock, Mutex, Weak},
    time::{Duration, Instant},
};

use rand::{RngCore, rngs::OsRng};
use sev::parser::ByteParser;

use crate::{
    AttestError, AttestationTiming, BodyError, certificate_validity,
    evidence::{self, SnpDerChain},
    map_reqwest_error, read_body_capped, unix_now,
};

pub const DEFAULT_AMD_KDS_BASE_URL: &str = "https://kdsintf.amd.com/vcek/v1";

/// How long fetched VCEK DER bytes may be reused by this process. The
/// certificate is fully re-verified on every use; this only bounds how long
/// the bytes sit in the cache, further capped by the certificate's not_after.
const VCEK_CACHE_TTL: Duration = Duration::from_secs(3600);
const VCEK_CACHE_MAX_ENTRIES: usize = 256;
/// Ceiling on an upstream `Retry-After` so one response cannot park a fill
/// beyond the bounded retry schedule's scale.
const RETRY_AFTER_CAP: Duration = Duration::from_secs(120);
/// KDS or a relay must not stream unbounded bytes into verifier memory; 64 KiB
/// covers every real certificate with headroom.
const MAX_VCEK_DER_BYTES: usize = 64 * 1024;
const MAX_CA_BUNDLE_BYTES: u64 = 64 * 1024;

/// Where VCEKs come from when evidence carries no chain anchored to a builtin
/// AMD root.
#[derive(Clone, Copy, Debug)]
pub struct Kds<'a> {
    /// AMD KDS `/vcek/v1` endpoint, or a relay serving the same paths.
    pub base_url: &'a str,
    /// PEM bundle that replaces the platform roots, for a relay with a private CA.
    pub ca_bundle_path: Option<&'a Path>,
    /// Upstream requests per VCEK fill; 429 and 5xx are retried with backoff.
    pub max_attempts: usize,
}

impl Kds<'_> {
    pub(crate) async fn chain_for_report(
        &self,
        report_bytes: &[u8],
        session_id: u64,
    ) -> Result<SnpDerChain, AttestError> {
        let report =
            sev::firmware::guest::AttestationReport::from_bytes(report_bytes).map_err(|_| {
                AttestError::Attestation("attestation evidence SNP report is malformed")
            })?;
        let (generation, key) = VcekKey::for_report(&report)?;
        let (ark_der, ask_der) = builtin_ca_der_chain(generation)?;
        let client = http_client(self.ca_bundle_path)?;
        let vcek_der = cached_vcek_der(
            &client,
            &key.url(self.base_url),
            &key,
            self.max_attempts,
            session_id,
        )
        .await?;
        Ok(SnpDerChain {
            ark_der,
            ask_der,
            vcek_der: vcek_der.as_ref().clone(),
        })
    }
}

/// AMD KDS spec 57230 lookup identity: product, product-correct HWID and the
/// complete reported TCB. A changed firmware/TCB is a different key, so stale
/// collateral cannot be replayed across a TCB update. `hw_id` identifies
/// hardware: it must never appear in logs or errors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct VcekKey {
    product: String,
    hw_id: String,
    fmc: Option<u8>,
    bootloader: u8,
    tee: u8,
    snp: u8,
    microcode: u8,
}

impl VcekKey {
    fn for_report(
        report: &sev::firmware::guest::AttestationReport,
    ) -> Result<(sev::Generation, Self), AttestError> {
        if report.chip_id == [0u8; 64] {
            return Err(AttestError::Attestation(
                "SNP report masks chip_id; cannot fetch VCEK from AMD KDS",
            ));
        }
        if report.key_info.signing_key() != 0 {
            return Err(AttestError::Attestation(
                "SNP report was not signed by VCEK; AMD KDS VCEK fallback is not applicable",
            ));
        }
        let family = report.cpuid_fam_id.ok_or(AttestError::Attestation(
            "SNP report missing CPUID family for VCEK lookup",
        ))?;
        let model = report.cpuid_mod_id.ok_or(AttestError::Attestation(
            "SNP report missing CPUID model for VCEK lookup",
        ))?;
        let generation = sev::Generation::identify_cpu(family, model)
            .map_err(|_| AttestError::Attestation("unknown SNP CPU generation"))?;
        let tcb = report.reported_tcb;
        let (hw_id, fmc) = if matches!(generation, sev::Generation::Turin) {
            // Turin uses the first eight CHIP_ID bytes and an fmc SPL.
            if report.chip_id[8..].iter().any(|byte| *byte != 0) {
                return Err(AttestError::Attestation("invalid Turin chip_id padding"));
            }
            let fmc = tcb.fmc.ok_or(AttestError::Attestation(
                "Turin SNP report missing fmc TCB value",
            ))?;
            (hex::encode(&report.chip_id[..8]), Some(fmc))
        } else {
            (hex::encode(report.chip_id), None)
        };
        Ok((
            generation,
            Self {
                product: generation.titlecase(),
                hw_id,
                fmc,
                bootloader: tcb.bootloader,
                tee: tcb.tee,
                snp: tcb.snp,
                microcode: tcb.microcode,
            },
        ))
    }

    fn url(&self, base_url: &str) -> String {
        let base = base_url.trim_end_matches('/');
        let fmc = self
            .fmc
            .map(|fmc| format!("fmcSPL={fmc:02}&"))
            .unwrap_or_default();
        format!(
            "{base}/{}/{}?{fmc}blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
            self.product, self.hw_id, self.bootloader, self.tee, self.snp, self.microcode
        )
    }
}

/// The ARK/ASK pair for `generation`, as shipped by sev 7.1.0's builtin roots.
fn builtin_ca_der_chain(generation: sev::Generation) -> Result<(Vec<u8>, Vec<u8>), AttestError> {
    let (ark, ask) = match generation {
        sev::Generation::Milan => (
            include_str!("../certs/milan_ark.pem"),
            include_str!("../certs/milan_ask.pem"),
        ),
        sev::Generation::Genoa => (
            include_str!("../certs/genoa_ark.pem"),
            include_str!("../certs/genoa_ask.pem"),
        ),
        sev::Generation::Turin => (
            include_str!("../certs/turin_ark.pem"),
            include_str!("../certs/turin_ask.pem"),
        ),
    };
    let der = |pem| {
        evidence::bytes_string(pem).ok_or(AttestError::Attestation(
            "builtin AMD certificate is malformed",
        ))
    };
    Ok((der(ark)?, der(ask)?))
}

fn http_client(ca_bundle_path: Option<&Path>) -> Result<reqwest::Client, AttestError> {
    let roots = match ca_bundle_path {
        // Public CA material only, scoped to this client and re-read for rotation.
        Some(path) => {
            read_ca_bundle(path).ok_or(AttestError::Attestation("invalid KDS CA bundle"))?
        }
        // Mozilla roots bundled at build time: KDS trust must not depend on
        // whether the image ships a CA store (the PaaS image does not).
        None => webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .filter_map(|der| reqwest::Certificate::from_der(der).ok())
            .collect(),
    };
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .tls_certs_only(roots)
        .build()
        .map_err(|error| map_reqwest_error(&error))
}

fn read_ca_bundle(path: &Path) -> Option<Vec<reqwest::Certificate>> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut pem = Vec::new();
    file.take(MAX_CA_BUNDLE_BYTES + 1)
        .read_to_end(&mut pem)
        .ok()?;
    if pem.len() as u64 > MAX_CA_BUNDLE_BYTES {
        return None;
    }
    let roots = reqwest::Certificate::from_pem_bundle(&pem).ok()?;
    (!roots.is_empty()).then_some(roots)
}

struct CachedVcek {
    der: Arc<Vec<u8>>,
    expires_at: Instant,
}

static VCEK_CACHE: LazyLock<Mutex<HashMap<VcekKey, CachedVcek>>> = LazyLock::new(Default::default);
static VCEK_FILL_LOCKS: LazyLock<Mutex<HashMap<VcekKey, Weak<tokio::sync::Mutex<()>>>>> =
    LazyLock::new(Default::default);

fn vcek_cache_get(key: &VcekKey) -> Option<Arc<Vec<u8>>> {
    let mut cache = VCEK_CACHE.lock().expect("VCEK cache mutex poisoned");
    match cache.get(key) {
        Some(entry) if entry.expires_at > Instant::now() => Some(entry.der.clone()),
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}

fn vcek_cache_insert(key: VcekKey, der: Arc<Vec<u8>>, expires_at: Instant) {
    let mut cache = VCEK_CACHE.lock().expect("VCEK cache mutex poisoned");
    if cache.len() >= VCEK_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
    }
    while cache.len() >= VCEK_CACHE_MAX_ENTRIES {
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

/// Per-key fill lock for single-flight collapse. Entries are weak, so a lock
/// whose callers have all retired is reclaimed on the next lookup instead of
/// pinning the key, while a lock with a live caller can never be dropped from
/// under a queued waiter. At saturation a new key still gets its own lock
/// rather than serializing behind an unrelated identity.
fn vcek_fill_lock(key: &VcekKey) -> Arc<tokio::sync::Mutex<()>> {
    let mut locks = VCEK_FILL_LOCKS.lock().expect("VCEK fill-lock map poisoned");
    if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
        return lock;
    }
    locks.remove(key);
    if locks.len() >= VCEK_CACHE_MAX_ENTRIES {
        locks.retain(|_, weak| weak.strong_count() > 0);
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key.clone(), Arc::downgrade(&lock));
    lock
}

/// The earlier of the certificate's own not_after and the cache TTL. A body
/// that is not a certificate inside its validity window is rejected and never
/// cached, so a 429/error body can never become cached "certificate" bytes.
fn vcek_cache_expiry(der: &[u8]) -> Result<Instant, AttestError> {
    let (not_before, not_after) = certificate_validity(der).ok_or(AttestError::Attestation(
        "AMD KDS VCEK response is not a certificate",
    ))?;
    let now = unix_now()?;
    if now < not_before || now >= not_after {
        return Err(AttestError::Attestation(
            "AMD KDS VCEK is outside its validity period",
        ));
    }
    Ok(Instant::now() + Duration::from_secs(not_after - now).min(VCEK_CACHE_TTL))
}

/// Single-flight VCEK fetch: concurrent callers for one key share one fill and
/// a warm entry is reused without an upstream request.
async fn cached_vcek_der(
    client: &reqwest::Client,
    url: &str,
    key: &VcekKey,
    max_attempts: usize,
    session_id: u64,
) -> Result<Arc<Vec<u8>>, AttestError> {
    if let Some(der) = vcek_cache_get(key) {
        return Ok(der);
    }
    let fill = vcek_fill_lock(key);
    let _guard = fill.lock().await;
    // A concurrent caller may have filled this key while we queued on it.
    if let Some(der) = vcek_cache_get(key) {
        return Ok(der);
    }
    let der = Arc::new(fetch_vcek_der(client, url, max_attempts, session_id).await?);
    let expires_at = vcek_cache_expiry(&der)?;
    vcek_cache_insert(key.clone(), der.clone(), expires_at);
    Ok(der)
}

/// Errors stay coarse: the URL embeds the chip HWID and must not reach logs
/// or errors; timing events carry the HTTP status instead.
async fn fetch_vcek_der(
    client: &reqwest::Client,
    url: &str,
    max_attempts: usize,
    session_id: u64,
) -> Result<Vec<u8>, AttestError> {
    let attempts = max_attempts.max(1);
    let mut attempt = 0;
    loop {
        let retries_left = attempt + 1 < attempts;
        let mut timing = AttestationTiming::new(session_id, "kds_attempt");
        timing.attempt = attempt + 1;
        let response = match client.get(url).send().await {
            Ok(response) => response,
            Err(error) => {
                timing.outcome = if error.is_timeout() {
                    "timeout"
                } else {
                    "transport"
                };
                drop(timing);
                if retries_left {
                    retry_sleep(session_id, attempt, sleep_duration(attempt, None)).await;
                    attempt += 1;
                    continue;
                }
                return Err(map_reqwest_error(&error));
            }
        };
        let status = response.status();
        timing.http_status = status.as_u16();
        if !status.is_success() {
            timing.outcome = "http_error";
            let retry_after =
                parse_retry_after(response.headers().get(reqwest::header::RETRY_AFTER));
            drop(timing);
            if should_retry(status) && retries_left {
                retry_sleep(session_id, attempt, sleep_duration(attempt, retry_after)).await;
                attempt += 1;
                continue;
            }
            return Err(AttestError::Attestation("AMD KDS VCEK fetch failed"));
        }
        let body = read_body_capped(response, MAX_VCEK_DER_BYTES).await;
        timing.outcome = if body.is_ok() {
            "success"
        } else {
            "body_error"
        };
        return body.map_err(|error| match error {
            BodyError::TooLarge => AttestError::Attestation("AMD KDS VCEK body exceeds bounds"),
            BodyError::Read => AttestError::Transport,
        });
    }
}

async fn retry_sleep(session_id: u64, attempt: usize, delay: Duration) {
    let mut timing = AttestationTiming::new(session_id, "kds_retry_sleep");
    timing.attempt = attempt + 1;
    tokio::time::sleep(delay).await;
    timing.outcome = "success";
}

fn should_retry(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn retry_delay(attempt: usize) -> Duration {
    Duration::from_secs(match attempt {
        0 => 2,
        1 => 5,
        2 => 10,
        3 => 20,
        _ => 30,
    })
}

/// A valid `Retry-After` is honored up to a cap; otherwise the schedule is
/// jittered to [50%, 150%) so callers released together do not retry in
/// lockstep.
fn sleep_duration(attempt: usize, retry_after: Option<Duration>) -> Duration {
    if let Some(delay) = retry_after {
        return delay.min(RETRY_AFTER_CAP);
    }
    let jitter = (OsRng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
    retry_delay(attempt).mul_f64(0.5 + jitter)
}

/// Delta-seconds only; an HTTP-date or malformed value falls back to the
/// jittered schedule rather than being trusted.
fn parse_retry_after(value: Option<&reqwest::header::HeaderValue>) -> Option<Duration> {
    let seconds: u64 = value?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use sha2::{Digest, Sha256};
    use x509_cert::der::{Decode, Encode};

    use super::*;
    use crate::BUILTIN_AMD_ARK_SHA256_PINS;
    use crate::test_fixtures::{prove_it_live, quiet_subscriber, serve_every_path};

    const PAAS_ATTEMPTS: usize = 8;

    fn test_key(suffix: u8) -> VcekKey {
        VcekKey {
            product: "Genoa".to_string(),
            hw_id: hex::encode([suffix; 64]),
            fmc: None,
            bootloader: 2,
            tee: 3,
            snp: 4,
            microcode: 5,
        }
    }

    #[test]
    fn builtin_roots_match_the_pins_and_sign_their_ask() {
        let mut pins = Vec::new();
        for generation in [
            sev::Generation::Milan,
            sev::Generation::Genoa,
            sev::Generation::Turin,
        ] {
            let (ark, ask) = builtin_ca_der_chain(generation).unwrap();
            let pin: [u8; 32] = Sha256::digest(&ark).into();
            // (ark, ark, ask) checks the ARK self-signature and the ASK under the ARK.
            enclava_verifier::verify_amd_certificate_chain(&ark, &ark, &ask, &pin).unwrap();
            pins.push(pin);
        }
        assert_eq!(pins, BUILTIN_AMD_ARK_SHA256_PINS);
    }

    #[test]
    fn vcek_lookup_preserves_product_hardware_and_tcb() {
        let mut report = sev::firmware::guest::AttestationReport {
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            chip_id: [1; 64],
            ..Default::default()
        };
        report.reported_tcb.bootloader = 2;
        report.reported_tcb.tee = 3;
        report.reported_tcb.snp = 4;
        report.reported_tcb.microcode = 5;
        let relay = "http://relay.platform.svc.cluster.local:8080/vcek/v1";
        let url = |report: &sev::firmware::guest::AttestationReport| {
            VcekKey::for_report(report).map(|(_, key)| key.url(&format!("{relay}/")))
        };
        assert_eq!(
            url(&report).unwrap(),
            format!(
                "{relay}/Milan/{}?blSPL=02&teeSPL=03&snpSPL=04&ucodeSPL=05",
                "01".repeat(64)
            )
        );
        report.cpuid_fam_id = Some(0x1a);
        report.cpuid_mod_id = Some(0x02);
        report.reported_tcb.fmc = Some(6);
        report.chip_id[8..].fill(0);
        assert_eq!(
            url(&report).unwrap(),
            format!(
                "{relay}/Turin/{}?fmcSPL=06&blSPL=02&teeSPL=03&snpSPL=04&ucodeSPL=05",
                "01".repeat(8)
            )
        );
        report.chip_id[63] = 1;
        assert_eq!(
            url(&report).unwrap_err().reason(),
            "invalid Turin chip_id padding"
        );
        report.chip_id = [0; 64];
        assert_eq!(
            url(&report).unwrap_err().reason(),
            "SNP report masks chip_id; cannot fetch VCEK from AMD KDS"
        );
    }

    #[tokio::test]
    async fn vcek_body_limit_covers_fixed_and_chunked_responses() {
        let _quiet = quiet_subscriber();
        use axum::{
            Router,
            body::{Body, Bytes},
            routing::get,
        };
        let app = Router::new()
            .route(
                "/fixed",
                get(|| async { vec![0u8; MAX_VCEK_DER_BYTES + 1] }),
            )
            .route(
                "/chunked",
                get(|| async {
                    Body::from_stream(futures::stream::iter([
                        Ok::<_, std::io::Error>(Bytes::from(vec![0u8; 32768])),
                        Ok(Bytes::from(vec![0u8; 32769])),
                    ]))
                }),
            )
            .route("/limit", get(|| async { vec![0u8; MAX_VCEK_DER_BYTES] }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = reqwest::Client::new();
        for path in ["fixed", "chunked"] {
            let error = fetch_vcek_der(&client, &format!("http://{address}/{path}"), 1, 1)
                .await
                .unwrap_err();
            assert_eq!(error.reason(), "AMD KDS VCEK body exceeds bounds");
        }
        assert_eq!(
            fetch_vcek_der(&client, &format!("http://{address}/limit"), 1, 1)
                .await
                .unwrap()
                .len(),
            MAX_VCEK_DER_BYTES
        );
        server.abort();
    }

    #[tokio::test]
    async fn configured_kds_client_trusts_only_its_ca_and_never_follows_redirects() {
        let _quiet = quiet_subscriber();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Ephemeral test-only certificates: no live CA material.
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = |expired: bool| {
            let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
            if expired {
                params.not_before = rcgen::date_time_ymd(2020, 1, 1);
                params.not_after = rcgen::date_time_ymd(2021, 1, 1);
            }
            params.signed_by(&leaf_key, &issuer).unwrap().der().to_vec()
        };

        async fn serve_tls(
            cert: Vec<u8>,
            key: Vec<u8>,
        ) -> (
            u16,
            Arc<std::sync::atomic::AtomicUsize>,
            tokio::task::JoinHandle<()>,
        ) {
            let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert)],
                rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
            )
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = requests.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    let count = count.clone();
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut request = [0; 8192];
                        let Ok(n) = stream.read(&mut request).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        count.fetch_add(1, Ordering::SeqCst);
                        let response: &[u8] = if request[..n].starts_with(b"GET /ok ") {
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nDER"
                        } else {
                            b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://localhost/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        };
                        let _ = stream.write_all(response).await;
                        let _ = stream.shutdown().await;
                    });
                }
            });
            (port, requests, task)
        }

        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("ca.pem");
        std::fs::write(&ca, ca_pem).unwrap();
        let (port, requests, server) = serve_tls(leaf(false), leaf_key.serialize_der()).await;
        let client = http_client(Some(&ca)).unwrap();
        let url = format!("https://localhost:{port}/ok");
        let body = client
            .get(&url)
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(body.as_ref(), b"DER");
        assert!(
            http_client(None).unwrap().get(&url).send().await.is_err(),
            "untrusted CA accepted"
        );
        assert!(
            client
                .get(format!("https://127.0.0.1:{port}/ok"))
                .send()
                .await
                .is_err(),
            "wrong TLS name accepted"
        );
        let error = fetch_vcek_der(
            &client,
            &format!("https://localhost:{port}/SENSITIVE_HWID?token=SENSITIVE"),
            1,
            1,
        )
        .await
        .unwrap_err();
        assert_eq!(error.reason(), "AMD KDS VCEK fetch failed");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "a redirect was followed or a rejected TLS peer received a request"
        );
        let (expired_port, expired_requests, expired_server) =
            serve_tls(leaf(true), leaf_key.serialize_der()).await;
        assert!(
            client
                .get(format!("https://localhost:{expired_port}/ok"))
                .send()
                .await
                .is_err(),
            "expired TLS certificate accepted"
        );
        assert_eq!(expired_requests.load(Ordering::SeqCst), 0);
        server.abort();
        expired_server.abort();

        let bad_ca = directory.path().join("bad-ca.pem");
        for value in [Vec::new(), b"NOT-PEM".to_vec(), vec![b'A'; 65537]] {
            std::fs::write(&bad_ca, value).unwrap();
            assert_eq!(
                http_client(Some(&bad_ca)).unwrap_err().reason(),
                "invalid KDS CA bundle"
            );
        }
        assert!(http_client(Some(directory.path())).is_err());
    }

    #[tokio::test]
    async fn kds_timings_record_status_retries_and_cancellation_without_urls() {
        use axum::{Router, routing::get};
        use std::sync::atomic::AtomicUsize;
        use tracing::instrument::WithSubscriber;

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let app = Router::new()
            .route(
                "/retry/private-chip-id",
                get(move || {
                    let counter = counter.clone();
                    async move {
                        if counter.fetch_add(1, Ordering::Relaxed) == 0 {
                            (reqwest::StatusCode::TOO_MANY_REQUESTS, "private diagnostic")
                        } else {
                            (reqwest::StatusCode::OK, "certificate bytes")
                        }
                    }
                }),
            )
            .route(
                "/missing/private-chip-id",
                get(|| async { (reqwest::StatusCode::NOT_FOUND, "private diagnostic") }),
            )
            .route(
                "/unavailable/private-chip-id",
                get(|| async {
                    (
                        reqwest::StatusCode::SERVICE_UNAVAILABLE,
                        "private diagnostic",
                    )
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let output = Arc::new(Mutex::new(Vec::<u8>::new()));
        let writer = Capture(output.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        async {
            // Callsite interest is process-global: recompute it with this
            // subscriber active so events registered by other tests count.
            tracing::callsite::rebuild_interest_cache();
            let client = reqwest::Client::new();
            let retry_url = format!("http://{address}/retry/private-chip-id");
            assert_eq!(
                fetch_vcek_der(&client, &retry_url, PAAS_ATTEMPTS, 1)
                    .await
                    .unwrap(),
                b"certificate bytes"
            );
            assert_eq!(requests.load(Ordering::Relaxed), 2);
            let missing_url = format!("http://{address}/missing/private-chip-id");
            assert_eq!(
                fetch_vcek_der(&client, &missing_url, PAAS_ATTEMPTS, 2)
                    .await
                    .unwrap_err()
                    .reason(),
                "AMD KDS VCEK fetch failed"
            );
            assert!(
                crate::fetch_attestation(&client, missing_url.parse().unwrap(), 4)
                    .await
                    .is_err()
            );
            // A 200 with an invalid JSON body still records status 200.
            assert!(
                crate::fetch_attestation(&client, retry_url.parse().unwrap(), 5)
                    .await
                    .is_err()
            );
            let unavailable_url = format!("http://{address}/unavailable/private-chip-id");
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(100),
                    fetch_vcek_der(&client, &unavailable_url, PAAS_ATTEMPTS, 3)
                )
                .await
                .is_err()
            );
        }
        .with_subscriber(subscriber)
        .await;
        server.abort();
        let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
        for status in ["429", "404", "503"] {
            assert!(logs.contains(&format!("http_status={status}")));
        }
        for status in ["404", "200"] {
            assert!(
                logs.lines()
                    .any(|line| line.contains("stage=\"attestation_get\"")
                        && line.contains("outcome=\"error\"")
                        && line.contains(&format!("http_status={status}")))
            );
        }
        assert!(logs.contains("stage=\"kds_retry_sleep\" outcome=\"cancelled\""));
        assert!(logs.contains("stage=\"kds_attempt\" outcome=\"success\" attempt=2"));
        for secret in [
            "private-chip-id",
            "private diagnostic",
            "certificate bytes",
            "http://",
        ] {
            assert!(!logs.contains(secret), "timing must contain metadata only");
        }
    }

    #[test]
    fn kds_retry_policy_is_bounded_and_unchanged() {
        for status in [429, 500, 503, 599] {
            assert!(should_retry(reqwest::StatusCode::from_u16(status).unwrap()));
        }
        for status in [200, 301, 400, 401, 403, 404] {
            assert!(!should_retry(
                reqwest::StatusCode::from_u16(status).unwrap()
            ));
        }
        assert_eq!(
            (0..8)
                .map(|attempt| retry_delay(attempt).as_secs())
                .collect::<Vec<_>>(),
            [2, 5, 10, 20, 30, 30, 30, 30]
        );
    }

    #[test]
    fn kds_retry_delay_honors_bounded_retry_after_and_jitter() {
        use reqwest::header::HeaderValue;
        assert_eq!(
            parse_retry_after(Some(&HeaderValue::from_static("7"))),
            Some(Duration::from_secs(7))
        );
        assert_eq!(
            sleep_duration(0, Some(Duration::from_secs(7))),
            Duration::from_secs(7)
        );
        assert_eq!(
            sleep_duration(2, Some(Duration::from_secs(86_400))),
            RETRY_AFTER_CAP
        );
        for bad in ["soon", "Wed, 21 Oct 2065 07:28:00 GMT", "-5", ""] {
            assert_eq!(
                parse_retry_after(Some(&HeaderValue::from_str(bad).unwrap())),
                None
            );
        }
        for attempt in 0..8 {
            let delay = sleep_duration(attempt, None);
            let base = retry_delay(attempt);
            assert!(delay >= base / 2 && delay < base + base / 2);
        }
    }

    #[tokio::test]
    async fn vcek_cache_collapses_concurrent_same_key_fills_and_serves_warm_hits() {
        let _quiet = quiet_subscriber();
        let (address, requests, server) = serve_every_path(200, prove_it_live().vcek_der).await;
        let client = reqwest::Client::new();
        let url = format!("http://{address}/vcek");
        let key = test_key(0xc1);

        let results =
            futures::future::join_all((0..8).map(|_| cached_vcek_der(&client, &url, &key, 1, 1)))
                .await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(requests.load(Ordering::Relaxed), 1);

        for _ in 0..4 {
            cached_vcek_der(&client, &url, &key, 1, 2).await.unwrap();
        }
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        server.abort();
    }

    #[tokio::test]
    async fn vcek_cache_keeps_different_hwid_tcb_and_product_keys_separate() {
        let _quiet = quiet_subscriber();
        let (address, requests, server) = serve_every_path(200, prove_it_live().vcek_der).await;
        let client = reqwest::Client::new();
        let url = format!("http://{address}/vcek");
        let mut different_hwid = test_key(0xd1);
        different_hwid.hw_id = hex::encode([0xd2; 64]);
        let mut different_tcb = test_key(0xd1);
        different_tcb.microcode += 1;
        let mut different_product = test_key(0xd1);
        different_product.product = "Turin".to_string();
        for key in [&different_hwid, &different_tcb, &different_product] {
            cached_vcek_der(&client, &url, key, 1, 1).await.unwrap();
            cached_vcek_der(&client, &url, key, 1, 1).await.unwrap();
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        server.abort();
    }

    #[tokio::test]
    async fn vcek_fill_lock_reclaims_idle_entries_and_keeps_distinct_keys_independent() {
        let key_with_index = |index: usize| {
            let mut key = test_key(0xf1);
            let mut hw_id = [0u8; 64];
            hw_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            key.hw_id = hex::encode(hw_id);
            key
        };
        // Saturate the lock map with identities whose callers have retired.
        for index in 0..VCEK_CACHE_MAX_ENTRIES {
            drop(vcek_fill_lock(&key_with_index(index)));
        }

        let key_a = key_with_index(VCEK_CACHE_MAX_ENTRIES);
        let key_b = key_with_index(VCEK_CACHE_MAX_ENTRIES + 1);
        let lock_a = vcek_fill_lock(&key_a);
        let lock_b = vcek_fill_lock(&key_b);
        assert!(
            !Arc::ptr_eq(&lock_a, &lock_b),
            "unrelated fills must not serialize on a shared lock"
        );
        let guard_a = lock_a.lock().await;
        let guard_b = tokio::time::timeout(Duration::from_secs(5), lock_b.lock())
            .await
            .expect("a distinct-key fill must not wait behind another identity");
        drop(guard_b);
        drop(guard_a);

        assert!(
            Arc::ptr_eq(&lock_a, &vcek_fill_lock(&key_a)),
            "same-key fills must keep single-flight collapse"
        );
        let map_len = VCEK_FILL_LOCKS.lock().unwrap().len();
        assert!(
            map_len <= VCEK_CACHE_MAX_ENTRIES + 32,
            "idle lock entries must be reclaimed at saturation, got {map_len}"
        );
    }

    #[tokio::test]
    async fn vcek_cache_never_stores_noncertificate_or_expired_bodies() {
        let _quiet = quiet_subscriber();
        let client = reqwest::Client::new();
        let (address, requests, server) = serve_every_path(200, b"error page bytes".to_vec()).await;
        let key = test_key(0xe1);
        for _ in 0..3 {
            let error = cached_vcek_der(&client, &format!("http://{address}/vcek"), &key, 1, 1)
                .await
                .unwrap_err();
            assert_eq!(error.reason(), "AMD KDS VCEK response is not a certificate");
        }
        assert_eq!(requests.load(Ordering::Relaxed), 3);
        server.abort();

        let mut expired = x509_cert::Certificate::from_der(&prove_it_live().vcek_der).unwrap();
        expired.tbs_certificate.validity.not_after = expired.tbs_certificate.validity.not_before;
        let (address, requests, server) = serve_every_path(200, expired.to_der().unwrap()).await;
        let key = test_key(0xe2);
        for _ in 0..2 {
            let error = cached_vcek_der(&client, &format!("http://{address}/vcek"), &key, 1, 1)
                .await
                .unwrap_err();
            assert_eq!(
                error.reason(),
                "AMD KDS VCEK is outside its validity period"
            );
        }
        assert_eq!(requests.load(Ordering::Relaxed), 2);
        server.abort();
    }

    #[tokio::test]
    async fn vcek_fill_is_bounded_cancellable_and_error_responses_are_uncached() {
        let _quiet = quiet_subscriber();
        use axum::Router;
        use std::sync::atomic::AtomicUsize;

        let throttled = |retry_after: &'static str| {
            let requests = Arc::new(AtomicUsize::new(0));
            let counter = requests.clone();
            let app = Router::new().fallback(move || {
                let counter = counter.clone();
                async move {
                    counter.fetch_add(1, Ordering::Relaxed);
                    (
                        reqwest::StatusCode::TOO_MANY_REQUESTS,
                        [(reqwest::header::RETRY_AFTER, retry_after)],
                        "throttled",
                    )
                }
            });
            (app, requests)
        };
        let client = reqwest::Client::new();

        // The retry budget is exactly max_attempts upstream hits, and a 429
        // body is never served back as a certificate or cached.
        let (app, requests) = throttled("0");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/vcek", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let key = test_key(0xf3);
        let error = cached_vcek_der(&client, &url, &key, PAAS_ATTEMPTS, 1)
            .await
            .unwrap_err();
        assert_eq!(error.reason(), "AMD KDS VCEK fetch failed");
        assert_eq!(requests.load(Ordering::Relaxed), PAAS_ATTEMPTS);
        assert!(
            cached_vcek_der(&client, &url, &key, PAAS_ATTEMPTS, 2)
                .await
                .is_err()
        );
        assert_eq!(requests.load(Ordering::Relaxed), 2 * PAAS_ATTEMPTS);
        server.abort();

        // A Retry-After parks the fill inside its sleep; dropping the future
        // cancels it and releases the key's fill lock.
        let (app, requests) = throttled("60");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/vcek", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let key = test_key(0xf4);
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            cached_vcek_der(&client, &url, &key, PAAS_ATTEMPTS, 3),
        )
        .await;
        assert!(result.is_err(), "Retry-After fill must be cancellable");
        assert_eq!(requests.load(Ordering::Relaxed), 1);
        assert!(vcek_fill_lock(&key).try_lock().is_ok());
        server.abort();
    }
}
