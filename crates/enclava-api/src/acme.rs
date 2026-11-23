use std::collections::BTreeMap;
use std::future::Future;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::dns::{self, DnsConfig};
use crate::workload_tls_timing::{DnsErrorCategory, Phase, RequestTiming};
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{RData, RecordType};
use http::header::RETRY_AFTER;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub account_credentials_path: Option<PathBuf>,
    pub dns_propagation_wait: Duration,
    pub dns_lookup_prefer_system: bool,
    pub dns_lookup_timeout: Option<Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME account load failed: {0}")]
    AccountLoad(String),
    #[error("ACME failed: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("DNS challenge failed: {0}")]
    Dns(#[from] dns::DnsError),
    #[error("invalid CSR DER base64: {0}")]
    Csr(String),
    #[error("unexpected ACME authorization status: {0:?}")]
    AuthorizationStatus(AuthorizationStatus),
    #[error("unexpected ACME order status: {0:?}")]
    OrderStatus(OrderStatus),
    #[error("DNS challenge TXT did not propagate for {record_name}")]
    DnsPropagation { record_name: String },
    #[error("ACME DNS delegation missing")]
    DelegationMissing,
    #[error("account credential persistence failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("account credential serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

/// The exact ACME problem type that maps to the broker's rate-limit
/// diagnostic. Classification is byte-exact; any other value (including
/// prefixed or suffixed lookalikes) stays a generic failure.
const RATE_LIMITED_PROBLEM_TYPE: &str = "urn:ietf:params:acme:error:rateLimited";

/// Largest `Retry-After` offset accepted from an ACME provider. Larger (or
/// otherwise unusable) values produce no retry deadline instead of an
/// unbounded timestamp.
const MAX_RETRY_AFTER_SECONDS: i64 = 365 * 24 * 60 * 60;

/// Bounded, provider-text-free diagnostic code for a terminal issuance
/// failure. Never carries ACME problem details, CSRs, hostnames, request
/// URLs, or any other provider-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuanceFailureCode {
    /// The terminal ACME API problem type was exactly
    /// `urn:ietf:params:acme:error:rateLimited`.
    RateLimited,
    /// A requested hostname outside the managed DNS zone had no usable
    /// CNAME delegation (`_acme-challenge.<hostname>` did not resolve,
    /// through CNAME hops only, to `<hostname>.acme.<zone>`). Refused at
    /// pre-flight, before any ACME or DNS provider write.
    DelegationMissing,
    /// Every other terminal issuance failure: transport errors, DNS
    /// failures, unexpected statuses, and non-rate-limited or untyped ACME
    /// problems.
    Failed,
}

impl IssuanceFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "acme_rate_limited",
            Self::DelegationMissing => "acme_delegation_missing",
            Self::Failed => "acme_certificate_issuance_failed",
        }
    }
}

/// Safe terminal diagnostics for one failed certificate issuance attempt.
///
/// Every field is bounded and safe for API responses and logs; the raw
/// [`AcmeError`] is deliberately not preserved.
#[derive(Debug, Clone)]
pub struct IssuanceFailure {
    /// Bounded diagnostic code for the failure.
    pub code: IssuanceFailureCode,
    /// Validated UTC instant after which a new issuance attempt may be
    /// retried, captured from the issuance's most recent transport exchange
    /// when that exchange was an ACME API failure response. `None` when the
    /// header was absent, malformed, out of bounds, or the exchange was a
    /// success or transport failure.
    pub retry_after: Option<DateTime<Utc>>,
}

impl IssuanceFailure {
    /// Build the safe diagnostic for a terminal issuance error and the
    /// issuance-local failure-header capture.
    pub(crate) fn diagnose(error: &AcmeError, failures: &FailureHeaders) -> Self {
        let code = match error {
            AcmeError::Acme(instant_acme::Error::Api(problem))
                if problem.r#type.as_deref() == Some(RATE_LIMITED_PROBLEM_TYPE) =>
            {
                IssuanceFailureCode::RateLimited
            }
            AcmeError::DelegationMissing => IssuanceFailureCode::DelegationMissing,
            _ => IssuanceFailureCode::Failed,
        };
        Self {
            code,
            retry_after: failures.retry_after(),
        }
    }
}

/// Issuance-local capture of the `Retry-After` value from ACME API failure
/// responses.
///
/// The capture tracks exactly one transport exchange — the most recent one —
/// so a stored deadline can only ever describe the response that produced
/// the terminal failure. Successful responses and transport failures clear
/// it, which keeps a recovered badNonce retry's header (instant-acme retries
/// badNonce internally) from leaking into a later DNS failure, transport
/// failure, or API problem embedded in a successful order body. One capture
/// belongs to exactly one issuance attempt; concurrent issuances never share
/// it, so unrelated polling headers cannot become a retry deadline either.
#[derive(Clone, Default)]
pub(crate) struct FailureHeaders {
    inner: Arc<FailureHeadersInner>,
}

#[derive(Default)]
struct FailureHeadersInner {
    retry_after: Mutex<Option<DateTime<Utc>>>,
}

impl FailureHeaders {
    /// Record the outcome of one transport exchange. A failure response
    /// stores its own validated `Retry-After` (clearing when the header is
    /// absent or unusable, so the last failure stays authoritative); any
    /// other response clears, because its headers cannot describe a later
    /// terminal failure.
    pub(crate) fn observe_response(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) {
        let retry_after = (status.is_client_error() || status.is_server_error())
            .then(|| {
                headers
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| parse_retry_after(value, now))
            })
            .flatten();
        *self.lock() = retry_after;
    }

    /// A transport-level failure carries no response headers; clear so no
    /// earlier exchange's deadline can describe it.
    pub(crate) fn observe_transport_failure(&self) {
        *self.lock() = None;
    }

    pub(crate) fn retry_after(&self) -> Option<DateTime<Utc>> {
        *self.lock()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<DateTime<Utc>>> {
        self.inner
            .retry_after
            .lock()
            .expect("retry-after capture lock poisoned")
    }
}

/// Parse and validate a `Retry-After` header value (delta-seconds or
/// HTTP-date) into a bounded future UTC deadline.
///
/// Returns `None` for malformed, non-future, or out-of-bound values;
/// provider prose is never interpreted as a deadline.
fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let value = value.trim();
    // RFC 9110 delta-seconds is 1*DIGIT; signs, fractions, or other text
    // are not accepted as a delta.
    let delta_seconds = !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    if delta_seconds {
        let seconds = value.parse::<u64>().ok()?;
        if seconds > MAX_RETRY_AFTER_SECONDS as u64 {
            return None;
        }
        let deadline = now.checked_add_signed(TimeDelta::seconds(seconds as i64))?;
        return (deadline > now).then_some(deadline);
    }
    let deadline = DateTime::<Utc>::from(httpdate::parse_http_date(value).ok()?);
    let horizon = now.checked_add_signed(TimeDelta::seconds(MAX_RETRY_AFTER_SECONDS))?;
    if deadline <= now || deadline > horizon {
        return None;
    }
    Some(deadline)
}

/// The instant-acme HTTP transport for one issuance attempt.
///
/// Forwards every request to the caller-provided reqwest client — in
/// production the SSRF-guarded shared client (HTTPS-only, redirects
/// disabled, guarded resolver; `crate::clients::build_guarded_client`) —
/// adding no client policy of its own, and records the `Retry-After` header
/// of failure responses into the issuance-local capture. The default
/// instant-acme client discards response headers on API failures, so the
/// capture happens here, on the transport, before the error is surfaced.
struct IssuanceHttpClient {
    client: reqwest::Client,
    failures: FailureHeaders,
}

impl instant_acme::HttpClient for IssuanceHttpClient {
    fn request(
        &self,
        req: Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> Pin<
        Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>,
    > {
        let client = self.client.clone();
        let failures = self.failures.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let body = match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(infallible) => match infallible {},
            };
            let request = match client
                .request(parts.method, parts.uri.to_string())
                .headers(parts.headers)
                .body(body)
                .build()
            {
                Ok(request) => request,
                Err(err) => {
                    failures.observe_transport_failure();
                    return Err(instant_acme::Error::Other(Box::new(err)));
                }
            };
            let response = match client.execute(request).await {
                Ok(response) => response,
                Err(err) => {
                    failures.observe_transport_failure();
                    return Err(instant_acme::Error::Other(Box::new(err)));
                }
            };
            let status = response.status();
            let headers = response.headers().clone();
            failures.observe_response(status, &headers, Utc::now());
            let forwarded = <http::Response<reqwest::Body>>::from(response);
            Ok(instant_acme::BytesResponse::from(forwarded))
        })
    }
}

/// Maximum CNAME hops the delegation check follows from
/// `_acme-challenge.<hostname>` before refusing. Eight is the classic
/// resolver bound (RFC 1034 resolver algorithm); a longer chain is a loop
/// or a misconfiguration, and every hop must itself be a CNAME.
const DELEGATION_MAX_HOPS: usize = 8;

/// Total attempts (first try plus one retry) before the delegation check
/// refuses. The retry rides transient resolver flakes only: DNS
/// propagation is not waited for here, and the refusal is total either
/// way.
const DELEGATION_ATTEMPTS: u32 = 2;

/// Pause between delegation attempts.
const DELEGATION_RETRY_DELAY: Duration = Duration::from_secs(1);

/// The CNAME record a tenant must publish for an out-of-zone `hostname`,
/// and the in-zone target it must point at:
/// `_acme-challenge.<hostname>` -> `<hostname>.acme.<zone>`.
pub(crate) fn expected_acme_cname_pair(hostname: &str, zone: &str) -> (String, String) {
    // A configured zone name may carry leading (or trailing) dots that
    // zone-membership checks tolerate; the derived target must be a
    // publishable DNS name, so the dots are stripped here just as
    // `manages_hostname` strips them.
    let zone = zone.trim_matches('.');
    (
        format!("_acme-challenge.{hostname}"),
        format!("{hostname}.acme.{zone}"),
    )
}

/// Case-insensitive, trailing-dot-insensitive comparison form for DNS
/// names on both sides of the delegation check.
fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

/// Follow the CNAME chain for `_acme-challenge.<hostname>` and decide
/// whether it terminates at exactly the delegated target.
///
/// `cname_of` answers one CNAME query: `Ok(None)` is a definitive "no
/// CNAME here" (including NXDOMAIN/NODATA), `Err` any lookup failure, and
/// `Ok(Some(target))` a CNAME record whose target is returned verbatim.
/// Every hop must be a CNAME, the chain may not exceed
/// [`DELEGATION_MAX_HOPS`] hops, and the terminal target must equal
/// `<hostname>.acme.<zone>` after normalization. Anything else -- no
/// CNAME, a wrong target, a chain that ends early, an over-long chain, or
/// a lookup error mid-chain -- is a refusal.
async fn delegation_chain_valid_with<F, Fut>(hostname: &str, zone: &str, mut cname_of: F) -> bool
where
    F: FnMut(&str) -> Fut,
    Fut: Future<Output = Result<Option<String>, DnsLookupError>>,
{
    let (start, target) = expected_acme_cname_pair(hostname, zone);
    let target = normalize_dns_name(&target);
    let mut current = normalize_dns_name(&start);
    for _ in 0..DELEGATION_MAX_HOPS {
        match cname_of(&current).await {
            Ok(Some(next)) => {
                let next = normalize_dns_name(&next);
                if next == target {
                    return true;
                }
                current = next;
            }
            Ok(None) => return false,
            Err(_) => return false,
        }
    }
    false
}

/// Injectable CNAME lookup: tests drive the delegation check without a
/// real resolver; production uses [`lookup_cname`].
pub(crate) type CnameLookupFn = std::sync::Arc<
    dyn Fn(&str) -> Pin<Box<dyn Future<Output = Result<Option<String>, DnsLookupError>> + Send>>
        + Send
        + Sync,
>;

/// Build the live CNAME lookup honouring the ACME resolver policy when
/// one is configured (preferred resolver order and per-lookup timeout,
/// the same knobs `lookup_txt` honours). Without a config (the domains
/// verify route on a deployment without the broker) external-first with
/// the resolver family's own default timeouts applies.
pub(crate) fn live_cname_lookup(config: Option<&AcmeConfig>) -> CnameLookupFn {
    let config = config.cloned();
    std::sync::Arc::new(move |name: &str| {
        let name = name.to_string();
        let config = config.clone();
        Box::pin(async move { lookup_cname(&name, config.as_ref()).await })
    })
}

/// Prove the CNAME delegation for one out-of-zone hostname, retrying once
/// on resolver flakes. The refusal is total: `Err(AcmeError::DelegationMissing)`
/// carries no hostname and no provider text.
pub(crate) async fn verify_acme_delegation(
    hostname: &str,
    zone: &str,
    lookup: &CnameLookupFn,
) -> Result<(), AcmeError> {
    for attempt in 0..DELEGATION_ATTEMPTS {
        if attempt > 0 {
            tokio::time::sleep(DELEGATION_RETRY_DELAY).await;
        }
        if delegation_chain_valid_with(hostname, zone, |name| lookup(name)).await {
            return Ok(());
        }
    }
    Err(AcmeError::DelegationMissing)
}

fn first_cname(lookup: hickory_resolver::lookup::Lookup) -> Option<String> {
    lookup
        .answers()
        .iter()
        .find_map(|record| match &record.data {
            RData::CNAME(cname) => Some(cname.0.to_string()),
            _ => None,
        })
}

/// Query the CNAME (if any) at `name`, external-first with a system
/// fallback (or the configured order), each attempt bounded by the
/// configured lookup timeout when one is set. A successful
/// no-such-record answer is `Ok(None)`, not an error: the refusal total
/// does not depend on which resolver answered.
/// One bounded resolver attempt: a timeout becomes this resolver's error
/// answer (so the caller's fallback loop still runs) rather than ending
/// the whole lookup.
async fn bounded_cname_attempt<F>(
    attempt: F,
    timeout: Option<Duration>,
) -> Result<Option<String>, DnsLookupError>
where
    F: Future<Output = Result<Option<String>, DnsLookupError>>,
{
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, attempt)
            .await
            .unwrap_or_else(|_| {
                Err(DnsLookupError {
                    message: "DNS CNAME lookup timed out".to_string(),
                    category: DnsErrorCategory::Timeout,
                })
            }),
        None => attempt.await,
    }
}

async fn lookup_cname(
    name: &str,
    config: Option<&AcmeConfig>,
) -> Result<Option<String>, DnsLookupError> {
    let prefer_system = config.map(|c| c.dns_lookup_prefer_system).unwrap_or(false);
    let order: Vec<bool> = vec![prefer_system, !prefer_system];
    let mut last = None;
    for system in order {
        let attempt = async {
            if system {
                lookup_cname_system(name).await
            } else {
                lookup_cname_external(name).await
            }
        };
        // A timed-out preferred resolver must NOT end the lookup: the
        // timeout becomes that resolver's error answer so the fallback
        // gets its own full budget (same shape as the TXT path).
        let result =
            bounded_cname_attempt(attempt, config.and_then(|c| c.dns_lookup_timeout)).await;
        match result {
            Ok(value) => return Ok(value),
            Err(error) => last = Some(error),
        }
    }
    Err(last.unwrap_or_else(|| DnsLookupError {
        message: "no DNS resolver available".to_string(),
        category: DnsErrorCategory::Other,
    }))
}

async fn lookup_cname_external(name: &str) -> Result<Option<String>, DnsLookupError> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
    .map_err(DnsLookupError::from)?;
    cname_query_result(resolver.lookup(name, RecordType::CNAME).await)
}

async fn lookup_cname_system(name: &str) -> Result<Option<String>, DnsLookupError> {
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(DnsLookupError::from)?;
    cname_query_result(resolver.lookup(name, RecordType::CNAME).await)
}

fn cname_query_result(
    result: Result<hickory_resolver::lookup::Lookup, NetError>,
) -> Result<Option<String>, DnsLookupError> {
    match result {
        Ok(lookup) => Ok(first_cname(lookup)),
        Err(NetError::Dns(DnsError::NoRecordsFound(_))) => Ok(None),
        Err(error) => Err(DnsLookupError::from(error)),
    }
}

pub async fn issue_dns01_certificate(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
) -> Result<String, IssuanceFailure> {
    issue_dns01_certificate_timed(
        http_client,
        dns_config,
        acme_config,
        hostnames,
        csr_der,
        RequestTiming::new(),
    )
    .await
}

pub(crate) async fn issue_dns01_certificate_timed(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
    timing: RequestTiming,
) -> Result<String, IssuanceFailure> {
    // The failure-header capture is issuance-local: it exists only for this
    // attempt's transport and error handling, so concurrent issuances (or
    // accounts) can never exchange retry metadata.
    let failures = FailureHeaders::default();
    let acme_http: Box<dyn instant_acme::HttpClient> = Box::new(IssuanceHttpClient {
        client: http_client.clone(),
        failures: failures.clone(),
    });
    issue_dns01_certificate_attempt(
        http_client,
        acme_http,
        dns_config,
        acme_config,
        hostnames,
        csr_der,
        timing,
        live_cname_lookup(Some(acme_config)),
    )
    .await
    .map_err(|error| IssuanceFailure::diagnose(&error, &failures))
}

// Eight arguments, all distinct concerns the issuance attempt owns; the
// alternative (a params struct) would churn PR #367's overlapping diff
// further for no behavioural gain.
#[allow(clippy::too_many_arguments)]
async fn issue_dns01_certificate_attempt(
    http_client: &reqwest::Client,
    acme_http: Box<dyn instant_acme::HttpClient>,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
    timing: RequestTiming,
    delegation_lookup: CnameLookupFn,
) -> Result<String, AcmeError> {
    // Delegation pre-flight: refuse the WHOLE request before any ACME
    // account, order, or DNS provider write when an out-of-zone hostname
    // lacks its `_acme-challenge.<hostname>` CNAME delegation into the
    // managed zone. In-zone hostnames write their TXT records directly and
    // are not checked here.
    for hostname in hostnames {
        if !dns_config.manages_hostname(hostname) {
            verify_acme_delegation(
                hostname,
                &dns_config.cloudflare_zone_name,
                &delegation_lookup,
            )
            .await?;
        }
    }

    let account = timing
        .measure(
            Phase::AcmeAccount,
            load_or_create_account(acme_config, acme_http),
        )
        .await?;
    let identifiers = hostnames
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let mut order = timing
        .measure(
            Phase::AcmeOrder,
            account.new_order(&NewOrder::new(&identifiers)),
        )
        .await?;

    // One cleanup guard over the whole post-create body: every exit after
    // the first TXT record is created -- a later create, the propagation
    // wait, set_ready, poll_ready, finalize, or poll_certificate -- runs
    // the same cleanup over the records created so far, as does success.
    let mut challenges = ChallengeCleanup::arm(http_client.clone(), dns_config.clone());
    let outcome = async {
        {
            let mut authorizations = order.authorizations();
            loop {
                let mut authorization = timing.start(Phase::AcmeAuthorization);
                let result = authorizations.next().await;
                authorization.finish(result.as_ref().is_none_or(Result::is_ok));
                drop(authorization);
                let Some(result) = result else {
                    break;
                };
                let mut authz = result?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => return Err(AcmeError::AuthorizationStatus(other)),
                }
                let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                    AcmeError::AccountLoad("ACME order has no DNS-01 challenge".into())
                })?;
                let hostname = challenge.identifier().to_string();
                // Out-of-zone hostnames write their challenge TXT at the
                // delegated in-zone target (`<hostname>.acme.<zone>`, proven by
                // the pre-flight above); in-zone hostnames keep the direct
                // `_acme-challenge.<hostname>` name. Either way the record is
                // in-zone by construction and dns::create_txt_record is
                // unchanged. The propagation wait polls the same name it wrote.
                let record_name = if dns_config.manages_hostname(&hostname) {
                    format!("_acme-challenge.{hostname}")
                } else {
                    let (_, target) =
                        expected_acme_cname_pair(&hostname, &dns_config.cloudflare_zone_name);
                    target
                };
                let record_value = challenge.key_authorization().dns_value();
                let record = timing
                    .measure(
                        Phase::DnsCreate,
                        dns::create_txt_record(
                            http_client,
                            dns_config,
                            &record_name,
                            &record_value,
                        ),
                    )
                    .await?;
                challenges.push(record);
                await_propagation_then_ready(
                    wait_for_txt_record(&record_name, &record_value, acme_config, timing),
                    || async { challenge.set_ready().await },
                    || async { challenges.cleanup(timing).await },
                    timing,
                )
                .await?;
            }
        }

        let status = timing
            .measure(
                Phase::AcmeOrderReady,
                order.poll_ready(&RetryPolicy::default()),
            )
            .await?;
        if status != OrderStatus::Ready {
            return Err(AcmeError::OrderStatus(status));
        }

        timing
            .measure(Phase::AcmeFinalize, order.finalize_csr(csr_der))
            .await?;
        let cert_chain = timing
            .measure(
                Phase::AcmeCertificate,
                order.poll_certificate(&RetryPolicy::default()),
            )
            .await?;
        Ok(cert_chain)
    }
    .await;
    challenges.cleanup(timing).await;
    outcome
}

/// The single ACME DNS-01 cleanup guard: armed before the first TXT record
/// is created, it deletes every record created so far (draining them, so a
/// cleanup triggered by an inner error path cannot double-delete) whenever
/// it is called -- and [`issue_dns01_certificate_attempt`] calls it on
/// every exit, error or success.
struct ChallengeCleanup {
    http_client: reqwest::Client,
    dns_config: DnsConfig,
    records: Vec<dns::DnsRecordHandle>,
}

impl ChallengeCleanup {
    fn arm(http_client: reqwest::Client, dns_config: DnsConfig) -> Self {
        Self {
            http_client,
            dns_config,
            records: Vec::new(),
        }
    }

    fn push(&mut self, record: dns::DnsRecordHandle) {
        self.records.push(record);
    }

    async fn cleanup(&mut self, timing: RequestTiming) {
        for record in std::mem::take(&mut self.records) {
            if timing
                .measure(
                    Phase::DnsCleanup,
                    dns::delete_txt_record(&self.http_client, &self.dns_config, &record),
                )
                .await
                .is_err()
            {
                // DNS provider error details and challenge record names stay out
                // of broker diagnostics.
                tracing::warn!("failed to clean up ACME DNS-01 TXT record");
            }
        }
    }
}

async fn wait_for_txt_record(
    record_name: &str,
    expected_value: &str,
    config: &AcmeConfig,
    timing: RequestTiming,
) -> Result<(), AcmeError> {
    if config.dns_propagation_wait.is_zero() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + config.dns_propagation_wait;
    loop {
        match lookup_txt(record_name, config, timing).await {
            Ok(values) if values.iter().any(|value| value == expected_value) => return Ok(()),
            Ok(_) => tracing::info!("waiting for ACME DNS-01 TXT propagation"),
            Err(_) => tracing::info!("waiting for ACME DNS-01 TXT lookup"),
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::DnsPropagation {
                record_name: record_name.to_string(),
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

// Construct the CA operation only after DNS propagation succeeds.
async fn await_propagation_then_ready<PropagateFut, ReadyFut, CleanupFut, E>(
    propagate: PropagateFut,
    ready: impl FnOnce() -> ReadyFut,
    cleanup: impl FnOnce() -> CleanupFut,
    timing: RequestTiming,
) -> Result<(), AcmeError>
where
    PropagateFut: Future<Output = Result<(), AcmeError>>,
    ReadyFut: Future<Output = Result<(), E>>,
    CleanupFut: Future<Output = ()>,
    E: Into<AcmeError>,
{
    if let Err(err) = timing.measure(Phase::DnsVisibility, propagate).await {
        cleanup().await;
        return Err(err);
    }
    timing
        .measure(Phase::AcmeChallengeReady, ready())
        .await
        .map_err(Into::into)
}

async fn lookup_txt(
    name: &str,
    config: &AcmeConfig,
    timing: RequestTiming,
) -> Result<Vec<String>, String> {
    lookup_txt_with_resolvers(config, timing, |system| async move {
        if system {
            lookup_txt_system(name).await
        } else {
            lookup_txt_external(name).await
        }
    })
    .await
}

#[derive(Clone, Debug)]
pub(crate) struct DnsLookupError {
    message: String,
    category: DnsErrorCategory,
}

impl From<NetError> for DnsLookupError {
    fn from(error: NetError) -> Self {
        let category = match &error {
            NetError::Dns(DnsError::NoRecordsFound(records)) => match records.response_code {
                ResponseCode::NXDomain => DnsErrorCategory::NxDomain,
                ResponseCode::NoError => DnsErrorCategory::NoData,
                _ => DnsErrorCategory::Other,
            },
            NetError::Timeout => DnsErrorCategory::Timeout,
            NetError::Io(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                DnsErrorCategory::Timeout
            }
            NetError::Io(_) | NetError::NoConnections => DnsErrorCategory::Transport,
            _ => DnsErrorCategory::Other,
        };
        Self {
            message: error.to_string(),
            category,
        }
    }
}

impl From<String> for DnsLookupError {
    fn from(message: String) -> Self {
        Self {
            message,
            category: DnsErrorCategory::Other,
        }
    }
}

#[cfg(test)]
impl From<&str> for DnsLookupError {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

async fn lookup_txt_with_resolvers<
    F: std::future::Future<Output = Result<Vec<String>, DnsLookupError>>,
>(
    config: &AcmeConfig,
    timing: RequestTiming,
    mut lookup: impl FnMut(bool) -> F,
) -> Result<Vec<String>, String> {
    let mut last_error = String::new();
    for system in [
        config.dns_lookup_prefer_system,
        !config.dns_lookup_prefer_system,
    ] {
        let phase = if system {
            Phase::DnsSystemLookup
        } else {
            Phase::DnsExternalLookup
        };
        let result = {
            let mut stage = timing.start(phase);
            let result = async {
                let work = lookup(system);
                match config.dns_lookup_timeout {
                    Some(timeout) => {
                        tokio::time::timeout(timeout, work)
                            .await
                            .map_err(|_| DnsLookupError {
                                message: "DNS TXT lookup timed out".to_string(),
                                category: DnsErrorCategory::Timeout,
                            })?
                    }
                    None => work.await,
                }
            }
            .await;
            match &result {
                Ok(_) => stage.finish(true),
                Err(error) => stage.finish_dns_error(error.category),
            }
            result
        };
        match result {
            // Empty or nonmatching answers still belong to this resolver. The
            // propagation loop, not the fallback, checks the exact challenge.
            Ok(values) => return Ok(values),
            Err(err) => last_error = err.message,
        }
        if system == config.dns_lookup_prefer_system {
            let message = if system {
                "system DNS lookup failed; falling back to external resolver"
            } else {
                "external DNS lookup failed; falling back to system resolver"
            };
            tracing::warn!("{message}");
        }
    }
    Err(last_error)
}

async fn lookup_txt_external(name: &str) -> Result<Vec<String>, DnsLookupError> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
    .map_err(DnsLookupError::from)?;
    collect_txt_values(
        resolver
            .txt_lookup(name)
            .await
            .map_err(DnsLookupError::from)?,
    )
    .map_err(DnsLookupError::from)
}

async fn lookup_txt_system(name: &str) -> Result<Vec<String>, DnsLookupError> {
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(DnsLookupError::from)?;
    collect_txt_values(
        resolver
            .txt_lookup(name)
            .await
            .map_err(DnsLookupError::from)?,
    )
    .map_err(DnsLookupError::from)
}

fn collect_txt_values(response: hickory_resolver::lookup::Lookup) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for record in response.answers() {
        let RData::TXT(rdata) = &record.data else {
            continue;
        };
        for chunk in rdata.txt_data.iter() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                out.push(s.to_string());
            }
        }
    }
    Ok(out)
}

/// Process-wide single-flight for ACME account registration. Let's Encrypt
/// allows only a handful of new accounts per IP per window, so concurrent
/// first issuances must not each register their own account: the first
/// caller registers and persists the credentials under this lock, and
/// waiters re-load the file instead of registering again.
static ACCOUNT_REGISTRATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// In-memory fallback when no credentials file is configured: the registered
/// account's serialized credentials keyed by ACME directory URL, kept for the
/// process lifetime. `Account` objects are never cached — failure headers are
/// deliberately issuance-local — so each caller rebuilds an `Account` from
/// the shared credentials with its own HTTP client.
static MEMORY_ACCOUNT_CREDENTIALS: tokio::sync::Mutex<BTreeMap<String, Vec<u8>>> =
    tokio::sync::Mutex::const_new(BTreeMap::new());

async fn load_or_create_account(
    config: &AcmeConfig,
    http: Box<dyn instant_acme::HttpClient>,
) -> Result<Account, AcmeError> {
    match config.account_credentials_path.as_ref() {
        Some(path) if path.is_file() => return load_account(path, http).await,
        Some(_) => {}
        None => {
            if let Some(bytes) = MEMORY_ACCOUNT_CREDENTIALS
                .lock()
                .await
                .get(&config.directory_url)
                .cloned()
            {
                return account_from_credentials_bytes(http, &bytes).await;
            }
        }
    }

    let _registration = ACCOUNT_REGISTRATION_LOCK.lock().await;
    match config.account_credentials_path.as_ref() {
        Some(path) if path.is_file() => load_account(path, http).await,
        Some(path) => {
            let (account, credentials) = register_account(config, http).await?;
            write_account_credentials(path, &credentials)?;
            Ok(account)
        }
        None => {
            let bytes = MEMORY_ACCOUNT_CREDENTIALS
                .lock()
                .await
                .get(&config.directory_url)
                .cloned();
            if let Some(bytes) = bytes {
                return account_from_credentials_bytes(http, &bytes).await;
            }
            let (account, credentials) = register_account(config, http).await?;
            let bytes = serde_json::to_vec(&credentials)?;
            MEMORY_ACCOUNT_CREDENTIALS
                .lock()
                .await
                .insert(config.directory_url.clone(), bytes);
            Ok(account)
        }
    }
}

async fn account_from_credentials_bytes(
    http: Box<dyn instant_acme::HttpClient>,
    bytes: &[u8],
) -> Result<Account, AcmeError> {
    let credentials: AccountCredentials = serde_json::from_slice(bytes)?;
    Account::builder_with_http(http)
        .from_credentials(credentials)
        .await
        .map_err(AcmeError::Acme)
}

async fn load_account(
    path: &std::path::Path,
    http: Box<dyn instant_acme::HttpClient>,
) -> Result<Account, AcmeError> {
    let bytes = std::fs::read(path)?;
    account_from_credentials_bytes(http, &bytes).await
}

async fn register_account(
    config: &AcmeConfig,
    http: Box<dyn instant_acme::HttpClient>,
) -> Result<(Account, AccountCredentials), AcmeError> {
    Account::builder_with_http(http)
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url.clone(),
            None,
        )
        .await
        .map_err(AcmeError::Acme)
}

/// Persist account credentials atomically with owner-only permissions: a
/// temporary sibling file is written, fsynced, then renamed so a concurrent
/// reader (or a crash mid-write) never observes a partial credentials file.
fn write_account_credentials(
    path: &std::path::Path,
    credentials: &AccountCredentials,
) -> Result<(), AcmeError> {
    let dir = credentials_dir(path);
    std::fs::create_dir_all(dir)?;
    // Never follow or reuse a pre-existing temp path: create a uniquely-named
    // sibling exclusively and only ever remove the file we created. The name
    // is short and independent of the destination so a long (but valid)
    // destination file name cannot overflow the 255-byte component limit.
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut file = None;
    let mut tmp = dir.to_path_buf();
    for attempt in 0..8u32 {
        tmp = dir.join(format!(".acme-account.{pid}.{nanos}.{attempt}.tmp"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(opened) => {
                file = Some(opened);
                break;
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err.into()),
        }
    }
    let Some(mut file) = file else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not create a unique account credentials temp file",
        )
        .into());
    };
    let persisted = (|| -> Result<(), AcmeError> {
        std::io::Write::write_all(&mut file, &serde_json::to_vec(credentials)?)?;
        file.sync_all()?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if let Err(err) = persisted {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    // fsync the parent directory so the rename itself survives a crash.
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Directory the credentials file and its temp sibling live in. A bare
/// relative file name like `account.json` has `parent() == Some("")`; an
/// empty parent fails to open as a directory and would break the temp
/// sibling create and the post-rename fsync, so it resolves to `"."`.
fn credentials_dir(path: &std::path::Path) -> &std::path::Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => std::path::Path::new("."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_dns_error_categories_do_not_change_error_messages() {
        use hickory_resolver::net::NoRecords;
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::{Name, RecordType};
        let query = Query::query(
            Name::from_ascii("private-name.invalid.").unwrap(),
            RecordType::TXT,
        );
        let cases = [
            (
                NetError::from(NoRecords::new(query.clone(), ResponseCode::NXDomain)),
                DnsErrorCategory::NxDomain,
            ),
            (
                NetError::from(NoRecords::new(query.clone(), ResponseCode::NoError)),
                DnsErrorCategory::NoData,
            ),
            (
                NetError::from(NoRecords::new(query, ResponseCode::ServFail)),
                DnsErrorCategory::Other,
            ),
            (
                NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail)),
                DnsErrorCategory::Other,
            ),
            (
                NetError::Dns(DnsError::ResponseCode(ResponseCode::Refused)),
                DnsErrorCategory::Other,
            ),
            (NetError::Timeout, DnsErrorCategory::Timeout),
            (
                NetError::Io(
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "private-error").into(),
                ),
                DnsErrorCategory::Timeout,
            ),
            (
                NetError::Io(
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "private-error")
                        .into(),
                ),
                DnsErrorCategory::Transport,
            ),
            (NetError::NoConnections, DnsErrorCategory::Transport),
            (NetError::QueryCaseMismatch, DnsErrorCategory::Other),
            (
                NetError::Msg("private-error".into()),
                DnsErrorCategory::Other,
            ),
        ];
        for (error, expected) in cases {
            let message = error.to_string();
            let classified = DnsLookupError::from(error);
            assert_eq!(classified.category, expected);
            assert_eq!(classified.message, message);
        }
    }

    fn config(system: bool, timeout: Option<Duration>) -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme.invalid/directory".into(),
            account_credentials_path: None,
            dns_propagation_wait: Duration::from_secs(30),
            dns_lookup_prefer_system: system,
            dns_lookup_timeout: timeout,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_timings_follow_actual_order_and_do_not_log_answers_or_errors() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for system in [false, true] {
            use hickory_resolver::net::NoRecords;
            use hickory_resolver::proto::op::Query;
            use hickory_resolver::proto::rr::{Name, RecordType};
            let query = Query::query(
                Name::from_ascii("private-name.invalid.").unwrap(),
                RecordType::TXT,
            );
            for (error, label) in [
                (
                    Some(NetError::from(NoRecords::new(
                        query.clone(),
                        ResponseCode::NXDomain,
                    ))),
                    "nxdomain",
                ),
                (
                    Some(NetError::from(NoRecords::new(query, ResponseCode::NoError))),
                    "nodata",
                ),
                (Some(NetError::Timeout), "timeout"),
                (Some(NetError::NoConnections), "transport"),
                (Some(NetError::Msg("private-error".into())), "other"),
                (None, "timeout"),
            ] {
                let logs = Arc::new(Mutex::new(Vec::new()));
                let output = logs.clone();
                let subscriber = tracing_subscriber::fmt()
                    .without_time()
                    .with_ansi(false)
                    .with_env_filter("enclava_api=debug,cap::workload_tls_timing=debug")
                    .with_writer(move || Writer(output.clone()))
                    .finish();
                let _guard = tracing::subscriber::set_default(subscriber);
                lookup_txt_with_resolvers(
                    &config(system, Some(Duration::from_millis(10))),
                    RequestTiming::new(),
                    |resolver| {
                        let error = error.clone();
                        async move {
                            if resolver == system {
                                match error {
                                    Some(error) => Err(DnsLookupError::from(error)),
                                    None => std::future::pending().await,
                                }
                            } else {
                                Ok(vec!["private-answer".into()])
                            }
                        }
                    },
                )
                .await
                .unwrap();
                let text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
                assert!(!text.contains("private-"));
                let lines: Vec<_> = text
                    .lines()
                    .filter(|line| line.contains("event=\"workload_tls_timing\""))
                    .collect();
                assert_eq!(lines.len(), 2);
                let phases = if system {
                    ["dns_system_lookup", "dns_external_lookup"]
                } else {
                    ["dns_external_lookup", "dns_system_lookup"]
                };
                for (line, phase) in lines.iter().zip(phases) {
                    assert!(line.contains(&format!("phase=\"{phase}\"")));
                }
                assert!(lines[0].contains("outcome=\"error\""));
                assert!(lines[0].contains(&format!("error_category=\"{label}\"")));
                assert!(lines[1].contains("outcome=\"success\""));
                assert!(!lines[1].contains("error_category="));
                let seq = |line: &str| {
                    line.split_whitespace()
                        .find(|field| field.starts_with("request_seq="))
                        .unwrap()
                        .to_owned()
                };
                assert_eq!(seq(lines[0]), seq(lines[1]));
            }
        }
    }

    #[tokio::test]
    async fn resolver_success_including_negative_answers_never_falls_back() {
        for system in [false, true] {
            for values in [vec![], vec!["wrong".into()], vec!["expected".into()]] {
                let mut calls = Vec::new();
                let result = lookup_txt_with_resolvers(
                    &config(system, None),
                    RequestTiming::new(),
                    |resolver| {
                        calls.push(resolver);
                        std::future::ready(Ok(values.clone()))
                    },
                )
                .await
                .unwrap();
                assert_eq!(result, values);
                assert_eq!(calls, vec![system]);
            }
        }
    }

    #[tokio::test]
    async fn resolver_errors_fall_back_in_configured_order() {
        for system in [false, true] {
            for fallback in [Ok(vec!["expected".into()]), Err("secondary failed".into())] {
                let mut calls = Vec::new();
                let result = lookup_txt_with_resolvers(
                    &config(system, None),
                    RequestTiming::new(),
                    |resolver| {
                        calls.push(resolver);
                        std::future::ready(if resolver == system {
                            Err("primary failed".into())
                        } else {
                            fallback.clone()
                        })
                    },
                )
                .await;
                assert_eq!(
                    result,
                    fallback.map_err(|error: DnsLookupError| error.message)
                );
                assert_eq!(calls, vec![system, !system]);
            }
        }
    }

    struct DropFlag<'a>(&'a std::cell::Cell<bool>);
    impl Drop for DropFlag<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[tokio::test]
    async fn timeout_drops_primary_before_fallback_and_bounds_secondary() {
        for system in [false, true] {
            for secondary_stalls in [false, true] {
                let dropped = std::cell::Cell::new(false);
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    lookup_txt_with_resolvers(
                        &config(system, Some(Duration::from_millis(10))),
                        RequestTiming::new(),
                        |resolver| {
                            let dropped = &dropped;
                            async move {
                                if resolver == system {
                                    let _guard = DropFlag(dropped);
                                    std::future::pending::<()>().await;
                                } else {
                                    assert!(dropped.get());
                                    if secondary_stalls {
                                        std::future::pending::<()>().await;
                                    }
                                }
                                Ok(vec!["expected".into()])
                            }
                        },
                    ),
                )
                .await
                .expect("both attempts must be bounded");
                assert!(dropped.get());
                if secondary_stalls {
                    assert_eq!(result.unwrap_err(), "DNS TXT lookup timed out");
                } else {
                    assert_eq!(result.unwrap(), vec!["expected"]);
                }
            }
        }
    }

    #[tokio::test]
    async fn unset_timeout_preserves_native_wait_and_outer_cancellation_drops_work() {
        let dropped = std::cell::Cell::new(false);
        let calls = std::cell::Cell::new(0);
        let result = tokio::time::timeout(
            Duration::from_millis(30),
            lookup_txt_with_resolvers(&config(false, None), RequestTiming::new(), |_| async {
                calls.set(calls.get() + 1);
                let _guard = DropFlag(&dropped);
                std::future::pending::<Result<Vec<String>, DnsLookupError>>().await
            }),
        )
        .await;
        assert!(result.is_err());
        assert!(dropped.get());
        assert_eq!(calls.get(), 1);
    }

    const SYNTHETIC_PROVIDER_SECRET: &str = "SYNTHETIC-PROVIDER-SECRET-7f3a91c2";

    fn api_problem(r#type: Option<&str>, detail: Option<&str>) -> instant_acme::Problem {
        instant_acme::Problem {
            r#type: r#type.map(str::to_string),
            detail: detail.map(str::to_string),
            status: Some(429),
            subproblems: Vec::new(),
        }
    }

    fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
                http::HeaderValue::from_str(value).expect("header value"),
            );
        }
        headers
    }

    #[test]
    fn rate_limit_classification_requires_exact_problem_type() {
        let cases = [
            (
                Some("urn:ietf:params:acme:error:rateLimited"),
                IssuanceFailureCode::RateLimited,
            ),
            (
                Some("urn:ietf:params:acme:error:rateLimited/"),
                IssuanceFailureCode::Failed,
            ),
            (
                Some("urn:ietf:params:acme:error:rateLimitedX"),
                IssuanceFailureCode::Failed,
            ),
            (
                Some("xurn:ietf:params:acme:error:rateLimited"),
                IssuanceFailureCode::Failed,
            ),
            (
                Some("URN:IETF:PARAMS:ACME:ERROR:RATELIMITED"),
                IssuanceFailureCode::Failed,
            ),
            (
                Some("urn:ietf:params:acme:error:unauthorized"),
                IssuanceFailureCode::Failed,
            ),
            (Some(""), IssuanceFailureCode::Failed),
            (None, IssuanceFailureCode::Failed),
        ];
        for (r#type, expected) in cases {
            let error = AcmeError::Acme(instant_acme::Error::Api(api_problem(
                r#type,
                Some(SYNTHETIC_PROVIDER_SECRET),
            )));
            let diagnostic = IssuanceFailure::diagnose(&error, &FailureHeaders::default());
            assert_eq!(diagnostic.code, expected, "problem type {type:?}");
            assert_eq!(diagnostic.retry_after, None);
        }

        let non_api_errors = [
            AcmeError::Acme(instant_acme::Error::Crypto),
            AcmeError::OrderStatus(OrderStatus::Invalid),
            AcmeError::AuthorizationStatus(AuthorizationStatus::Invalid),
            AcmeError::Csr(SYNTHETIC_PROVIDER_SECRET.into()),
            AcmeError::AccountLoad("no DNS-01 challenge".into()),
            AcmeError::Io(std::io::Error::other(SYNTHETIC_PROVIDER_SECRET)),
        ];
        for error in &non_api_errors {
            assert_eq!(
                IssuanceFailure::diagnose(error, &FailureHeaders::default()).code,
                IssuanceFailureCode::Failed
            );
        }
    }

    #[test]
    fn issuance_diagnostics_never_contain_provider_detail_text() {
        let error = AcmeError::Acme(instant_acme::Error::Api(api_problem(
            Some("urn:ietf:params:acme:error:rateLimited"),
            Some(&format!(
                "quota window exceeded for {SYNTHETIC_PROVIDER_SECRET}"
            )),
        )));
        // The legacy detail field did leak this provider text.
        assert!(error.to_string().contains(SYNTHETIC_PROVIDER_SECRET));

        let failures = FailureHeaders::default();
        failures.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "60")]),
            Utc::now(),
        );
        let diagnostic = IssuanceFailure::diagnose(&error, &failures);
        let rendered = format!(
            "{diagnostic:?}|{}|{:?}",
            diagnostic.code.as_str(),
            diagnostic.retry_after
        );
        assert!(!rendered.contains(SYNTHETIC_PROVIDER_SECRET));
        assert_eq!(diagnostic.code.as_str(), "acme_rate_limited");
        assert!(diagnostic.retry_after.is_some());
    }

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-09-09T12:00:00Z")
            .expect("fixed test instant")
            .with_timezone(&Utc)
    }

    #[test]
    fn retry_after_delta_seconds_are_parsed_and_bounded() {
        let now = fixed_now();
        assert_eq!(
            parse_retry_after("3600", now),
            Some(now + TimeDelta::hours(1))
        );
        assert_eq!(
            parse_retry_after("  3600 ", now),
            Some(now + TimeDelta::hours(1))
        );
        // Not a future deadline.
        assert_eq!(parse_retry_after("0", now), None);
        // The horizon is inclusive.
        assert_eq!(
            parse_retry_after(&MAX_RETRY_AFTER_SECONDS.to_string(), now),
            Some(now + TimeDelta::seconds(MAX_RETRY_AFTER_SECONDS))
        );
        // Beyond the horizon, or beyond u64 entirely: no deadline.
        assert_eq!(
            parse_retry_after(&(MAX_RETRY_AFTER_SECONDS + 1).to_string(), now),
            None
        );
        assert_eq!(parse_retry_after("99999999999999999999999999", now), None);
        assert_eq!(parse_retry_after(&u64::MAX.to_string(), now), None);
    }

    #[test]
    fn retry_after_http_dates_are_parsed_and_bounded() {
        let now = fixed_now();
        let future = now + TimeDelta::hours(6);
        let rendered = httpdate::fmt_http_date(future.into());
        assert_eq!(parse_retry_after(&rendered, now), Some(future));

        let past = now - TimeDelta::hours(1);
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(past.into()), now),
            None
        );

        let horizon = now + TimeDelta::seconds(MAX_RETRY_AFTER_SECONDS);
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(horizon.into()), now),
            Some(horizon)
        );
        let beyond = now + TimeDelta::seconds(MAX_RETRY_AFTER_SECONDS + 1);
        assert_eq!(
            parse_retry_after(&httpdate::fmt_http_date(beyond.into()), now),
            None
        );
    }

    #[test]
    fn retry_after_malformed_values_are_rejected() {
        let now = fixed_now();
        let malformed = [
            "",
            "   ",
            "abc",
            "-1",
            "1.5",
            "+60",
            "60seconds",
            "60 60",
            "\u{0669}\u{0669}",
            "Sep 9 2026",
            "Wed, 99 Zzz 2026 00:00:00 GMT",
            "999999999999999999999",
        ];
        for value in malformed {
            assert_eq!(parse_retry_after(value, now), None, "value {value:?}");
        }
    }

    #[test]
    fn failure_capture_tracks_only_the_latest_exchange() {
        let capture = FailureHeaders::default();
        let now = fixed_now();

        // Successful responses — including ones carrying Retry-After, and
        // redirects — clear: their headers cannot describe a later failure.
        capture.observe_response(StatusCode::OK, &header_map(&[("Retry-After", "999")]), now);
        assert_eq!(capture.retry_after(), None);
        capture.observe_response(
            StatusCode::FOUND,
            &header_map(&[("Retry-After", "999")]),
            now,
        );
        assert_eq!(capture.retry_after(), None);

        capture.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "120")]),
            now,
        );
        assert_eq!(capture.retry_after(), Some(now + TimeDelta::minutes(2)));

        // A later success clears the stored failure deadline.
        capture.observe_response(StatusCode::OK, &header_map(&[]), now);
        assert_eq!(capture.retry_after(), None);

        // A failure without a usable header is authoritative for that
        // failure: it clears any earlier value.
        capture.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "120")]),
            now,
        );
        capture.observe_response(StatusCode::BAD_GATEWAY, &header_map(&[]), now);
        assert_eq!(capture.retry_after(), None);
        capture.observe_response(
            StatusCode::SERVICE_UNAVAILABLE,
            &header_map(&[("Retry-After", "not-a-date")]),
            now,
        );
        assert_eq!(capture.retry_after(), None);

        // Transport-level failures carry no headers and clear too.
        capture.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "120")]),
            now,
        );
        capture.observe_transport_failure();
        assert_eq!(capture.retry_after(), None);
    }

    #[test]
    fn concurrent_issuance_captures_are_independent() {
        let first = FailureHeaders::default();
        let second = FailureHeaders::default();
        let now = fixed_now();

        first.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "100")]),
            now,
        );
        second.observe_response(
            StatusCode::TOO_MANY_REQUESTS,
            &header_map(&[("Retry-After", "86400")]),
            now,
        );
        // A later failure of the first issuance does not touch the second.
        first.observe_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            &header_map(&[("Retry-After", "garbage")]),
            now,
        );

        assert_eq!(first.retry_after(), None);
        assert_eq!(second.retry_after(), Some(now + TimeDelta::hours(24)));
    }

    /// Serve requests on `listener` until it is dropped. `respond` maps a
    /// request path to a `(status, headers, body)` reply; for HEAD requests
    /// the computed body is suppressed. Request bodies are consumed so
    /// keep-alive connections stay usable.
    async fn serve_test_acme_server(
        listener: tokio::net::TcpListener,
        respond: impl Fn(&str) -> (u16, HeaderMap, String) + Send + Sync + 'static,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let respond = Arc::new(respond);
        while let Ok((mut stream, _)) = listener.accept().await {
            let respond = Arc::clone(&respond);
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    let head_end = loop {
                        if let Some(position) =
                            buffer.windows(4).position(|window| window == b"\r\n\r\n")
                        {
                            break Some(position);
                        }
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => break None,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    };
                    let Some(head_end) = head_end else { return };
                    let head = String::from_utf8_lossy(&buffer[..head_end]).into_owned();
                    buffer.drain(..head_end + 4);
                    let method = head.split_whitespace().next().unwrap_or("").to_string();
                    let path = head
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("/")
                        .split('?')
                        .next()
                        .unwrap_or("/")
                        .to_string();
                    let content_length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    while buffer.len() < content_length {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buffer.extend_from_slice(&chunk[..read]),
                        }
                    }
                    buffer.drain(..content_length);
                    let (status, headers, body) = respond(&path);
                    let reason = StatusCode::from_u16(status)
                        .ok()
                        .and_then(|status| status.canonical_reason())
                        .unwrap_or("Status");
                    let mut response = format!("HTTP/1.1 {status} {reason}\r\n");
                    for (name, value) in headers.iter() {
                        if let Ok(value) = value.to_str() {
                            response.push_str(&format!("{name}: {value}\r\n"));
                        }
                    }
                    let (length, body) = if method == "HEAD" {
                        (0, String::new())
                    } else {
                        (body.len(), body)
                    };
                    response.push_str(&format!(
                        "Content-Length: {length}\r\nConnection: keep-alive\r\n\r\n"
                    ));
                    response.push_str(&body);
                    if stream.write_all(response.as_bytes()).await.is_err() {
                        return;
                    }
                }
            });
        }
    }

    async fn spawn_test_acme_server(
        respond: impl Fn(&str) -> (u16, HeaderMap, String) + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("loopback address");
        tokio::spawn(serve_test_acme_server(listener, respond));
        addr
    }

    fn test_acme_request(
        addr: &std::net::SocketAddr,
        path: &str,
    ) -> Request<instant_acme::BodyWrapper<Bytes>> {
        Request::get(format!("http://{addr}{path}"))
            .body(instant_acme::BodyWrapper::default())
            .expect("static test request")
    }

    /// Loopback test client mirroring the production guarded client's
    /// no-redirect policy (`crate::clients::build_guarded_client`:
    /// HTTPS-only, redirects disabled, guarded resolver). HTTPS-only and the
    /// guarded resolver cannot apply to loopback http; production gets them
    /// from the shared client the transport forwards to unchanged.
    fn test_loopback_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("test loopback client")
    }

    #[tokio::test]
    async fn issuance_transport_forwards_traffic_and_captures_failure_retry_after() {
        let addr = spawn_test_acme_server(|path| match path {
            "/ok" => (
                200,
                header_map(&[("Retry-After", "999")]),
                "{\"ok\":true}".to_string(),
            ),
            _ => (
                429,
                header_map(&[("Retry-After", "120")]),
                "{\"type\":\"urn:ietf:params:acme:error:rateLimited\"}".to_string(),
            ),
        })
        .await;
        let failures = FailureHeaders::default();
        let transport = IssuanceHttpClient {
            client: test_loopback_client(),
            failures: failures.clone(),
        };

        // A successful poll carrying Retry-After must be forwarded but not
        // captured.
        let mut response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(&transport, test_acme_request(&addr, "/ok")),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::OK);
        let body = response.body.into_bytes().await.expect("forwarded body");
        assert_eq!(body, Bytes::from_static(b"{\"ok\":true}"));
        assert_eq!(failures.retry_after(), None);

        // A failure response with Retry-After is forwarded and captured.
        let before = Utc::now();
        let mut response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(
                &transport,
                test_acme_request(&addr, "/rate-limited"),
            ),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        let after = Utc::now();
        assert_eq!(response.parts.status, StatusCode::TOO_MANY_REQUESTS);
        let body = response.body.into_bytes().await.expect("forwarded body");
        assert!(body.starts_with(b"{\"type\""));
        let deadline = failures.retry_after().expect("failure deadline captured");
        assert!(deadline > before + TimeDelta::seconds(118));
        assert!(deadline < after + TimeDelta::seconds(122));
    }

    #[tokio::test]
    async fn concurrent_issuances_share_transport_but_not_retry_metadata() {
        let addr = spawn_test_acme_server(|path| match path {
            "/first" => (429, header_map(&[("Retry-After", "100")]), "{}".to_string()),
            "/second" => (
                429,
                header_map(&[("Retry-After", "86400")]),
                "{}".to_string(),
            ),
            _ => (200, header_map(&[("Retry-After", "999")]), "{}".to_string()),
        })
        .await;
        let shared = test_loopback_client();
        let first = FailureHeaders::default();
        let second = FailureHeaders::default();
        let first_transport = IssuanceHttpClient {
            client: shared.clone(),
            failures: first.clone(),
        };
        let second_transport = IssuanceHttpClient {
            client: shared.clone(),
            failures: second.clone(),
        };

        let before = Utc::now();
        let (first_response, second_response) = tokio::join!(
            tokio::time::timeout(
                Duration::from_secs(10),
                instant_acme::HttpClient::request(
                    &first_transport,
                    test_acme_request(&addr, "/first"),
                ),
            ),
            tokio::time::timeout(
                Duration::from_secs(10),
                instant_acme::HttpClient::request(
                    &second_transport,
                    test_acme_request(&addr, "/second"),
                ),
            ),
        );
        let after = Utc::now();
        for response in [first_response, second_response] {
            assert_eq!(
                response
                    .expect("bounded loopback request")
                    .expect("forwarded request")
                    .parts
                    .status,
                StatusCode::TOO_MANY_REQUESTS
            );
        }

        let first_deadline = first.retry_after().expect("first issuance deadline");
        let second_deadline = second.retry_after().expect("second issuance deadline");
        assert!(first_deadline > before + TimeDelta::seconds(98));
        assert!(first_deadline < after + TimeDelta::seconds(102));
        assert!(second_deadline > before + TimeDelta::hours(24) - TimeDelta::seconds(2));
        assert!(second_deadline < after + TimeDelta::hours(24) + TimeDelta::seconds(2));

        // A later unrelated success on the shared transport clears the
        // first issuance's own capture (its last exchange was a success)
        // and leaves the untouched second issuance's deadline in place.
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(
                &first_transport,
                test_acme_request(&addr, "/unrelated"),
            ),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::OK);
        assert_eq!(first.retry_after(), None);
        assert_eq!(second.retry_after(), Some(second_deadline));
    }

    #[tokio::test]
    async fn recovered_bad_nonce_header_never_describes_later_failures() {
        // instant-acme retries badNonce internally: a 400 with Retry-After
        // is followed by a retried request that succeeds. The recovered
        // header must not survive into any later, unrelated failure.
        let challenge_visits = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let addr = spawn_test_acme_server(move |path| match path {
            "/challenge" => {
                if challenge_visits.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    (
                        400,
                        header_map(&[("Retry-After", "999")]),
                        "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}".to_string(),
                    )
                } else {
                    (200, HeaderMap::new(), "{}".to_string())
                }
            }
            "/redirect" => (302, header_map(&[("Retry-After", "999")]), String::new()),
            "/rate-limited" => (
                429,
                header_map(&[("Retry-After", "120")]),
                "{\"type\":\"urn:ietf:params:acme:error:rateLimited\"}".to_string(),
            ),
            _ => (200, HeaderMap::new(), "{}".to_string()),
        })
        .await;
        let failures = FailureHeaders::default();
        let transport = IssuanceHttpClient {
            client: test_loopback_client(),
            failures: failures.clone(),
        };

        // The recovered badNonce exchange: failure first, retry succeeds.
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(&transport, test_acme_request(&addr, "/challenge")),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::BAD_REQUEST);
        assert!(failures.retry_after().is_some());
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(&transport, test_acme_request(&addr, "/challenge")),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::OK);
        assert_eq!(
            failures.retry_after(),
            None,
            "recovered failure header cleared"
        );

        // A later DNS failure must not inherit the recovered deadline.
        let dns_error = AcmeError::DnsPropagation {
            record_name: "_acme-challenge.app.example.test".to_string(),
        };
        let diagnostic = IssuanceFailure::diagnose(&dns_error, &failures);
        assert_eq!(diagnostic.code, IssuanceFailureCode::Failed);
        assert_eq!(diagnostic.retry_after, None);

        // An API problem embedded in a successful order body classifies by
        // type but carries no deadline (its exchange was a success).
        let embedded = AcmeError::Acme(instant_acme::Error::Api(api_problem(
            Some("urn:ietf:params:acme:error:rateLimited"),
            Some(SYNTHETIC_PROVIDER_SECRET),
        )));
        let diagnostic = IssuanceFailure::diagnose(&embedded, &failures);
        assert_eq!(diagnostic.code, IssuanceFailureCode::RateLimited);
        assert_eq!(diagnostic.retry_after, None);

        // Redirects stay terminal at the transport (production policy:
        // redirects disabled) and never capture.
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(&transport, test_acme_request(&addr, "/redirect")),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::FOUND);
        assert_eq!(failures.retry_after(), None);

        // A transport-level failure clears: first re-arm the capture with a
        // failing response, then hit an unreachable address.
        let response = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(
                &transport,
                test_acme_request(&addr, "/rate-limited"),
            ),
        )
        .await
        .expect("bounded loopback request")
        .expect("forwarded request");
        assert_eq!(response.parts.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(failures.retry_after().is_some());
        let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let dead_addr = dead.local_addr().expect("loopback address");
        drop(dead);
        let transport_error = tokio::time::timeout(
            Duration::from_secs(10),
            instant_acme::HttpClient::request(&transport, test_acme_request(&dead_addr, "/")),
        )
        .await
        .expect("bounded loopback request");
        assert!(transport_error.is_err(), "unreachable address must fail");
        assert_eq!(failures.retry_after(), None, "transport failure cleared");
        let diagnostic = IssuanceFailure::diagnose(
            &AcmeError::Acme(instant_acme::Error::Other(Box::new(std::io::Error::other(
                "transport",
            )))),
            &failures,
        );
        assert_eq!(diagnostic.code, IssuanceFailureCode::Failed);
        assert_eq!(diagnostic.retry_after, None);
    }

    #[tokio::test(start_paused = true)]
    async fn ca_ready_signal_waits_for_dns_propagation_to_finish() {
        let signaled = std::cell::Cell::new(false);
        let result = tokio::time::timeout(
            Duration::from_secs(60),
            await_propagation_then_ready(
                std::future::pending::<Result<(), AcmeError>>(),
                || {
                    signaled.set(true);
                    std::future::ready(Ok::<(), AcmeError>(()))
                },
                || async {},
                RequestTiming::new(),
            ),
        )
        .await;
        assert!(result.is_err());
        assert!(!signaled.get());
    }

    #[tokio::test]
    async fn propagation_failure_cleans_up_and_never_signals_ready() {
        let signaled = std::cell::Cell::new(false);
        let cleaned = std::cell::Cell::new(false);
        let error = await_propagation_then_ready(
            std::future::ready(Err(AcmeError::DnsPropagation {
                record_name: "_acme-challenge.app.example.test".to_string(),
            })),
            || {
                signaled.set(true);
                std::future::ready(Ok::<(), AcmeError>(()))
            },
            || async { cleaned.set(true) },
            RequestTiming::new(),
        )
        .await
        .expect_err("propagation failure must propagate");
        assert!(matches!(error, AcmeError::DnsPropagation { .. }));
        assert!(cleaned.get());
        assert!(!signaled.get());
    }

    #[tokio::test]
    async fn successful_propagation_signals_ready_only_afterward() {
        let propagated = std::cell::Cell::new(false);
        let signaled = std::cell::Cell::new(false);
        await_propagation_then_ready(
            async {
                propagated.set(true);
                Ok(())
            },
            || {
                assert!(propagated.get());
                signaled.set(true);
                std::future::ready(Ok::<(), AcmeError>(()))
            },
            || async { panic!("successful propagation must retain challenge records") },
            RequestTiming::new(),
        )
        .await
        .expect("propagation success must reach readiness");
        assert!(signaled.get());
    }

    #[tokio::test]
    async fn concurrent_first_issuances_register_one_account() {
        let new_accounts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("loopback address");
        let base = format!("http://{addr}");
        let count = new_accounts.clone();
        let directory = base.clone();
        tokio::spawn(serve_test_acme_server(listener, move |path| match path {
            "/dir" => (
                200,
                HeaderMap::new(),
                format!(
                    "{{\"newNonce\":\"{directory}/nonce\",\"newAccount\":\"{directory}/new-acct\",\"newOrder\":\"{directory}/new-order\"}}"
                ),
            ),
            "/nonce" => (200, header_map(&[("Replay-Nonce", "nonce")]), String::new()),
            "/new-acct" => {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::LOCATION,
                    format!("{directory}/accounts/1").parse().unwrap(),
                );
                (201, headers, String::new())
            }
            _ => (404, HeaderMap::new(), String::new()),
        }));

        let dir = tempfile::tempdir().expect("tempdir");
        let credentials_path = dir.path().join("credentials.json");
        let client = test_loopback_client();
        let config = AcmeConfig {
            directory_url: format!("{base}/dir"),
            account_credentials_path: Some(credentials_path.clone()),
            dns_propagation_wait: Duration::ZERO,
            dns_lookup_prefer_system: false,
            dns_lookup_timeout: None,
        };
        let mut handles = Vec::new();
        for _ in 0..8 {
            let config = config.clone();
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                load_or_create_account(
                    &config,
                    Box::new(IssuanceHttpClient {
                        client,
                        failures: FailureHeaders::default(),
                    }),
                )
                .await
            }));
        }
        for handle in handles {
            handle.await.expect("task panicked").expect("account load");
        }
        assert_eq!(
            new_accounts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one ACME account must be registered"
        );
        assert!(credentials_path.is_file());
    }

    #[tokio::test]
    async fn concurrent_first_issuances_without_credentials_file_register_one_account() {
        let new_accounts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("loopback address");
        let base = format!("http://{addr}");
        let count = new_accounts.clone();
        let directory = base.clone();
        tokio::spawn(serve_test_acme_server(listener, move |path| match path {
            "/dir" => (
                200,
                HeaderMap::new(),
                format!(
                    "{{\"newNonce\":\"{directory}/nonce\",\"newAccount\":\"{directory}/new-acct\",\"newOrder\":\"{directory}/new-order\"}}"
                ),
            ),
            "/nonce" => (200, header_map(&[("Replay-Nonce", "nonce")]), String::new()),
            "/new-acct" => {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut headers = HeaderMap::new();
                headers.insert(
                    http::header::LOCATION,
                    format!("{directory}/accounts/1").parse().unwrap(),
                );
                (201, headers, String::new())
            }
            _ => (404, HeaderMap::new(), String::new()),
        }));

        let client = test_loopback_client();
        let config = AcmeConfig {
            directory_url: format!("{base}/dir"),
            account_credentials_path: None,
            dns_propagation_wait: Duration::ZERO,
            dns_lookup_prefer_system: false,
            dns_lookup_timeout: None,
        };
        let mut handles = Vec::new();
        for _ in 0..8 {
            let config = config.clone();
            let client = client.clone();
            handles.push(tokio::spawn(async move {
                load_or_create_account(
                    &config,
                    Box::new(IssuanceHttpClient {
                        client,
                        failures: FailureHeaders::default(),
                    }),
                )
                .await
            }));
        }
        for handle in handles {
            handle.await.expect("task panicked").expect("account load");
        }
        // Sequential re-issuance must reuse the cached account as well.
        load_or_create_account(
            &config,
            Box::new(IssuanceHttpClient {
                client,
                failures: FailureHeaders::default(),
            }),
        )
        .await
        .expect("account load");
        assert_eq!(
            new_accounts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "exactly one ACME account must be registered"
        );
    }

    #[test]
    fn credentials_dir_resolves_bare_file_names_to_current_dir() {
        assert_eq!(
            credentials_dir(std::path::Path::new("account.json")),
            std::path::Path::new(".")
        );
        assert_eq!(
            credentials_dir(std::path::Path::new("./account.json")),
            std::path::Path::new(".")
        );
        assert_eq!(
            credentials_dir(std::path::Path::new("/etc/ssl/account.json")),
            std::path::Path::new("/etc/ssl")
        );
        assert_eq!(
            credentials_dir(std::path::Path::new("nested/account.json")),
            std::path::Path::new("nested")
        );
        // No parent at all: still usable for temp creation and fsync.
        assert_eq!(
            credentials_dir(std::path::Path::new("")),
            std::path::Path::new(".")
        );
    }

    // --- cap#412: ACME DNS-01 CNAME delegation ---

    #[test]
    fn delegation_pair_derivation() {
        let (name, target) = expected_acme_cname_pair("app.example.com", "managed.test");
        assert_eq!(name, "_acme-challenge.app.example.com");
        assert_eq!(target, "app.example.com.acme.managed.test");
        // Multi-label hostnames are delegated whole; every hostname maps to
        // its own unique target.
        let (other_name, other_target) =
            expected_acme_cname_pair("a.b.example.com", "managed.test");
        assert_eq!(other_name, "_acme-challenge.a.b.example.com");
        assert_eq!(other_target, "a.b.example.com.acme.managed.test");
        assert_ne!(target, other_target);
    }

    fn chain_lookup<'a>(
        map: &'a [(&'a str, &'a str)],
    ) -> impl FnMut(&str) -> std::future::Ready<Result<Option<String>, DnsLookupError>> + 'a {
        move |query| {
            std::future::ready(match map.iter().find(|(from, _)| *from == query) {
                Some((_, to)) => Ok(Some(to.to_string())),
                None => Ok(None),
            })
        }
    }

    #[tokio::test]
    async fn delegation_chain_accepts_direct_and_multi_hop_target_matches() {
        let zone = "managed.test";
        let ok = chain_lookup(&[(
            "_acme-challenge.app.example.com",
            "app.example.com.acme.managed.test",
        )]);
        assert!(delegation_chain_valid_with("app.example.com", zone, ok).await);

        // Two and three correct hops (a tenant-side alias chain).
        let two = chain_lookup(&[
            ("_acme-challenge.app.example.com", "alias.customer.net"),
            ("alias.customer.net", "app.example.com.acme.managed.test"),
        ]);
        assert!(delegation_chain_valid_with("app.example.com", zone, two).await);

        let three = chain_lookup(&[
            ("_acme-challenge.app.example.com", "one.customer.net"),
            ("one.customer.net", "two.customer.net"),
            ("two.customer.net", "APP.Example.COM.ACME.Managed.Test."),
        ]);
        assert!(delegation_chain_valid_with("app.example.com", zone, three).await);
    }

    #[tokio::test]
    async fn delegation_chain_rejects_missing_wrong_and_overlong_chains() {
        let zone = "managed.test";

        // No CNAME at all.
        let none = chain_lookup(&[]);
        assert!(!delegation_chain_valid_with("app.example.com", zone, none).await);

        // Wrong terminal target.
        let wrong = chain_lookup(&[("_acme-challenge.app.example.com", "decoy.example.net")]);
        assert!(!delegation_chain_valid_with("app.example.com", zone, wrong).await);

        // Chain ends mid-way (no record at the last hop).
        let truncated = chain_lookup(&[("_acme-challenge.app.example.com", "alias.customer.net")]);
        assert!(!delegation_chain_valid_with("app.example.com", zone, truncated).await);

        // A lookup error mid-chain (resolver failure, including NXDOMAIN at a
        // hop that must be a CNAME) is a refusal.
        let erroring = |_q: &str| {
            std::future::ready::<Result<Option<String>, DnsLookupError>>(Err(DnsLookupError::from(
                NetError::Timeout,
            )))
        };
        assert!(!delegation_chain_valid_with("app.example.com", zone, erroring).await);

        // A name whose record is a TXT (not a CNAME) answers as no-CNAME
        // and is a refusal.
        let txt_not_cname = chain_lookup(&[]);
        assert!(!delegation_chain_valid_with("app.example.com", zone, txt_not_cname).await);

        // More hops than the budget (the target only reachable past it) is
        // covered by delegation_chain_allows_exactly_the_hop_budget.
    }

    #[tokio::test]
    async fn delegation_chain_allows_exactly_the_hop_budget() {
        let zone = "managed.test";
        let target = "app.example.com.acme.managed.test";
        // start -> h1 -> ... -> h7 -> target is exactly DELEGATION_MAX_HOPS
        // (8) lookups and must pass; one more intermediate hop exceeds the
        // budget and must fail.
        fn refs(map: &[(String, String)]) -> Vec<(&str, &str)> {
            map.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect()
        }
        fn chain(last: usize, target: &str) -> Vec<(String, String)> {
            let mut map = vec![(
                "_acme-challenge.app.example.com".to_string(),
                "h1.example.net".to_string(),
            )];
            for i in 1..last {
                map.push((
                    format!("h{i}.example.net"),
                    format!("h{}.example.net", i + 1),
                ));
            }
            map.push((format!("h{last}.example.net"), target.to_string()));
            map
        }
        let exact_chain = chain(DELEGATION_MAX_HOPS - 1, target);
        let exact = refs(&exact_chain);
        assert!(delegation_chain_valid_with("app.example.com", zone, chain_lookup(&exact)).await);

        let over_chain = chain(DELEGATION_MAX_HOPS, target);
        let over = refs(&over_chain);
        assert!(!delegation_chain_valid_with("app.example.com", zone, chain_lookup(&over)).await);
    }

    #[derive(Clone, Copy, PartialEq)]
    enum DelegationMode {
        Ok,
        Missing,
        WrongTarget,
    }

    fn mock_cname_lookup(mode: DelegationMode, zone: &'static str) -> CnameLookupFn {
        std::sync::Arc::new(move |name: &str| {
            let answer = match mode {
                DelegationMode::Missing => Ok(None),
                DelegationMode::WrongTarget => Ok(Some("decoy.example.net".to_string())),
                DelegationMode::Ok => {
                    let host = name.strip_prefix("_acme-challenge.").unwrap_or(name);
                    Ok(Some(format!("{host}.acme.{zone}")))
                }
            };
            Box::pin(async move { answer })
        })
    }

    /// What the fake ACME/Cloudflare doubles observed.
    #[derive(Default)]
    struct IssuanceCalls {
        chal_posts: std::sync::atomic::AtomicUsize,
        finalize_posts: std::sync::atomic::AtomicUsize,
        order_lookups: std::sync::atomic::AtomicUsize,
        new_order_posts: std::sync::atomic::AtomicUsize,
        cf_zone_lookups: std::sync::atomic::AtomicUsize,
        cf_creates: std::sync::Mutex<Vec<(String, String)>>,
        cf_deletes: std::sync::atomic::AtomicUsize,
    }

    macro_rules! bump {
        ($calls:expr, $field:ident) => {
            $calls
                .$field
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        };
    }

    macro_rules! tally {
        ($calls:expr, $field:ident) => {
            $calls.$field.load(std::sync::atomic::Ordering::SeqCst)
        };
    }

    #[derive(Clone, Copy, PartialEq)]
    enum FailPoint {
        None,
        CreateSecond,
        SetReady,
        Finalize,
        CertFetch,
    }

    /// Loopback ACME CA + fake Cloudflare for one issuance attempt.
    ///
    /// The order covers two hostnames: `name1.managed.test` (in-zone) and
    /// `app.example.com` (out-of-zone, delegated). `fail` selects the leg
    /// that returns 500 to prove the cleanup guard.
    async fn spawn_issuance_doubles(
        fail: FailPoint,
    ) -> (
        DnsConfig,
        AcmeConfig,
        reqwest::Client,
        std::sync::Arc<IssuanceCalls>,
    ) {
        use axum::extract::{Path, Query};
        use axum::routing::{delete, get, post};
        use std::collections::HashMap;

        let calls = std::sync::Arc::new(IssuanceCalls::default());

        // --- fake Cloudflare ---
        let cf_calls = calls.clone();
        let fail_here = fail;
        let zones = move |_q: Query<HashMap<String, String>>| {
            let calls = cf_calls.clone();
            async move {
                bump!(calls, cf_zone_lookups);
                axum::Json(serde_json::json!({
                    "success": true,
                    "result": [{"id": "zone-1"}],
                    "errors": []
                }))
            }
        };
        let cf_calls = calls.clone();
        let create = move |payload: axum::Json<serde_json::Value>| {
            let calls = cf_calls.clone();
            async move {
                let name = payload
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let content = payload
                    .get("content")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let mut created = calls.cf_creates.lock().unwrap();
                if fail_here == FailPoint::CreateSecond && created.len() == 1 {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        axum::Json(serde_json::json!({
                            "success": false,
                            "result": null,
                            "errors": [{"code": 500, "message": "synthetic provider failure"}]
                        })),
                    );
                }
                created.push((name, content));
                let id = format!("record-{}", created.len());
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "success": true,
                        "result": {"id": id},
                        "errors": []
                    })),
                )
            }
        };
        let cf_calls = calls.clone();
        let delete_record = move |_p: Path<(String, String)>| {
            let calls = cf_calls.clone();
            async move {
                bump!(calls, cf_deletes);
                (
                    StatusCode::OK,
                    axum::Json(serde_json::json!({
                        "success": true,
                        "result": {},
                        "errors": []
                    })),
                )
            }
        };
        let cf_app = axum::Router::new()
            .route("/zones", get(zones))
            .route("/zones/{zone_id}/dns_records", post(create))
            .route(
                "/zones/{zone_id}/dns_records/{record_id}",
                delete(delete_record),
            );
        let cf_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake cloudflare");
        let cf_addr = cf_listener.local_addr().expect("fake cloudflare addr");
        tokio::spawn(async move {
            axum::serve(cf_listener, cf_app)
                .await
                .expect("serve fake cloudflare");
        });

        let dns_config = DnsConfig {
            cloudflare_api_token: "token".to_string(),
            cloudflare_api_base_url: format!("http://{cf_addr}"),
            cloudflare_zone_id: None,
            cloudflare_zone_name: "managed.test".to_string(),
            target: "192.0.2.10".to_string(),
            required: true,
        };

        // --- loopback ACME CA ---
        let acme_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake acme");
        let acme_addr = acme_listener.local_addr().expect("fake acme addr");
        let base = format!("http://{acme_addr}");
        let cert_pem = {
            let key = rcgen::KeyPair::generate().expect("test key");
            let params = rcgen::CertificateParams::new(vec!["name1.managed.test".to_string()])
                .expect("test params");
            params.self_signed(&key).expect("test cert").pem()
        };
        let calls_state = calls.clone();
        let directory = base.clone();
        tokio::spawn(serve_test_acme_server(acme_listener, {
            let calls = calls_state.clone();
            let directory = directory.clone();
            move |path: &str| {
                let calls = calls.clone();
                let base = directory.clone();
                let cert_pem = cert_pem.clone();
                let chal_json = |n: u8| {
                    format!(
                        r#"{{"type":"dns-01","url":"{base}/chal/{n}","token":"token-{n}","status":"valid","error":null}}"#
                    )
                };
                let authz_json = |host: &str, n: u8| {
                    format!(
                        r#"{{"identifier":{{"type":"dns","value":"{host}"}}, "status":"pending", "challenges":[{}], "wildcard":false}}"#,
                        chal_json(n)
                    )
                };
                let order_body = |status: &str, certificate: Option<String>| {
                    format!(
                        r#"{{"status":"{status}","authorizations":["{base}/authz/1","{base}/authz/2"],"finalize":"{base}/finalize","certificate":{},"error":null}}"#,
                        certificate
                            .map(|url| format!(r#""{url}""#))
                            .unwrap_or_else(|| "null".to_string())
                    )
                };
                let reply = |status: u16, headers: HeaderMap, body: String| (status, headers, body);
                match path {
                    "/dir" => reply(
                        200,
                        HeaderMap::new(),
                        format!(
                            r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/new-acct","newOrder":"{base}/new-order"}}"#
                        ),
                    ),
                    "/nonce" => reply(200, header_map(&[("Replay-Nonce", "nonce")]), String::new()),
                    "/new-acct" => {
                        let mut headers = HeaderMap::new();
                        headers.insert(
                            http::header::LOCATION,
                            format!("{base}/accounts/1").parse().unwrap(),
                        );
                        reply(201, headers, String::new())
                    }
                    "/new-order" => {
                        bump!(calls, new_order_posts);
                        let mut headers = header_map(&[("Replay-Nonce", "nonce")]);
                        headers.insert(
                            http::header::LOCATION,
                            format!("{base}/order/1").parse().unwrap(),
                        );
                        reply(201, headers, order_body("pending", None))
                    }
                    "/authz/1" => reply(200, HeaderMap::new(), authz_json("name1.managed.test", 1)),
                    "/authz/2" => reply(200, HeaderMap::new(), authz_json("app.example.com", 2)),
                    "/chal/1" | "/chal/2" => {
                        bump!(calls, chal_posts);
                        if fail == FailPoint::SetReady && tally!(calls, chal_posts) == 2 {
                            return reply(
                                    500,
                                    HeaderMap::new(),
                                    r#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"synthetic"}"#.to_string(),
                                );
                        }
                        reply(200, HeaderMap::new(), chal_json(1))
                    }
                    "/order/1" => {
                        bump!(calls, order_lookups);
                        if tally!(calls, finalize_posts) > 0 {
                            reply(
                                200,
                                HeaderMap::new(),
                                order_body("valid", Some(format!("{base}/cert"))),
                            )
                        } else if tally!(calls, chal_posts) >= 2 {
                            reply(200, HeaderMap::new(), order_body("ready", None))
                        } else {
                            reply(200, HeaderMap::new(), order_body("pending", None))
                        }
                    }
                    "/finalize" => {
                        bump!(calls, finalize_posts);
                        if fail == FailPoint::Finalize {
                            return reply(
                                    500,
                                    HeaderMap::new(),
                                    r#"{"type":"urn:ietf:params:acme:error:serverInternal","detail":"synthetic"}"#.to_string(),
                                );
                        }
                        reply(
                            200,
                            HeaderMap::new(),
                            order_body("valid", Some(format!("{base}/cert"))),
                        )
                    }
                    "/cert" => {
                        if fail == FailPoint::CertFetch {
                            return reply(500, HeaderMap::new(), String::new());
                        }
                        reply(200, HeaderMap::new(), cert_pem)
                    }
                    _ => reply(404, HeaderMap::new(), String::new()),
                }
            }
        }));

        let config = AcmeConfig {
            directory_url: format!("http://{acme_addr}/dir"),
            account_credentials_path: None,
            dns_propagation_wait: Duration::ZERO,
            dns_lookup_prefer_system: false,
            dns_lookup_timeout: None,
        };
        let client = test_loopback_client();
        (dns_config, config, client, calls)
    }

    fn issuance_hostnames() -> Vec<String> {
        vec![
            "name1.managed.test".to_string(),
            "app.example.com".to_string(),
        ]
    }

    async fn run_attempt(
        dns_config: &DnsConfig,
        config: &AcmeConfig,
        client: &reqwest::Client,
        hostnames: &[String],
        delegation: DelegationMode,
    ) -> Result<String, AcmeError> {
        issue_dns01_certificate_attempt(
            client,
            Box::new(IssuanceHttpClient {
                client: client.clone(),
                failures: FailureHeaders::default(),
            }),
            dns_config,
            config,
            hostnames,
            &[0u8; 16],
            RequestTiming::new(),
            mock_cname_lookup(delegation, "managed.test"),
        )
        .await
    }

    fn assert_cleanup(calls: &IssuanceCalls) {
        let created = calls.cf_creates.lock().unwrap().clone();
        assert_eq!(
            tally!(calls, cf_deletes),
            created.len(),
            "every created TXT record must be cleaned up (created {created:?})"
        );
    }

    #[tokio::test]
    async fn delegated_issuance_writes_txt_at_target_and_cleans_up() {
        let (dns_config, config, client, calls) = spawn_issuance_doubles(FailPoint::None).await;
        let cert = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::Ok,
        )
        .await
        .expect("delegated issuance must succeed");
        assert!(cert.starts_with("-----BEGIN CERTIFICATE-----"));

        let created = calls.cf_creates.lock().unwrap().clone();
        assert_eq!(created.len(), 2, "one TXT per hostname: {created:?}");
        // The in-zone hostname writes its record directly...
        assert!(
            created
                .iter()
                .any(|(name, _)| name == "_acme-challenge.name1.managed.test")
        );
        // ...and the delegated hostname writes at the in-zone TARGET, not at
        // _acme-challenge.<hostname>.
        assert!(
            created
                .iter()
                .any(|(name, _)| name == "app.example.com.acme.managed.test")
        );
        assert!(
            !created
                .iter()
                .any(|(name, _)| name == "_acme-challenge.app.example.com")
        );
        for (_, value) in &created {
            assert_eq!(value.len(), 43, "base64url key authorization: {value}");
        }
        assert_cleanup(&calls);
    }

    #[tokio::test]
    async fn missing_delegation_fails_preflight_with_zero_provider_writes() {
        let (dns_config, config, client, calls) = spawn_issuance_doubles(FailPoint::None).await;
        let error = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::Missing,
        )
        .await
        .expect_err("missing delegation must refuse the whole request");
        assert!(matches!(error, AcmeError::DelegationMissing));
        assert_eq!(error.to_string(), "ACME DNS delegation missing");
        assert_eq!(tally!(calls, new_order_posts), 0, "no ACME order");
        assert!(calls.cf_creates.lock().unwrap().is_empty(), "no TXT writes");
        assert_eq!(tally!(calls, cf_zone_lookups), 0, "not even a zone lookup");
        assert_eq!(tally!(calls, cf_deletes), 0);

        // The surfaced diagnostic for the refusal is the bounded code: no
        // provider text, no retry deadline. (Asserted on diagnose() so this
        // test never contacts a real resolver through the live lookup.)
        let surfaced =
            IssuanceFailure::diagnose(&AcmeError::DelegationMissing, &FailureHeaders::default());
        assert_eq!(surfaced.code, IssuanceFailureCode::DelegationMissing);
        assert_eq!(surfaced.code.as_str(), "acme_delegation_missing");
        assert_eq!(surfaced.retry_after, None);
    }

    #[tokio::test]
    async fn wrong_delegation_target_fails_preflight_with_zero_provider_writes() {
        let (dns_config, config, client, calls) = spawn_issuance_doubles(FailPoint::None).await;
        let error = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::WrongTarget,
        )
        .await
        .expect_err("wrong target must refuse");
        assert!(matches!(error, AcmeError::DelegationMissing));
        assert_eq!(tally!(calls, new_order_posts), 0);
        assert!(calls.cf_creates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn second_create_failure_cleans_up_the_first_record() {
        let (dns_config, config, client, calls) =
            spawn_issuance_doubles(FailPoint::CreateSecond).await;
        let error = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::Ok,
        )
        .await
        .expect_err("second create failure must fail issuance");
        assert!(matches!(error, AcmeError::Dns(_)));
        let created = calls.cf_creates.lock().unwrap().clone();
        assert_eq!(created.len(), 1, "only the in-zone record was created");
        assert_eq!(created[0].0, "_acme-challenge.name1.managed.test");
        assert_eq!(
            tally!(calls, cf_deletes),
            1,
            "the created record is deleted"
        );
    }

    #[tokio::test]
    async fn set_ready_failure_cleans_up_all_created_records() {
        let (dns_config, config, client, calls) = spawn_issuance_doubles(FailPoint::SetReady).await;
        let error = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::Ok,
        )
        .await
        .expect_err("set_ready failure must fail issuance");
        assert!(matches!(error, AcmeError::Acme(_)));
        assert_eq!(calls.cf_creates.lock().unwrap().len(), 2);
        assert_cleanup(&calls);
    }

    #[tokio::test]
    async fn finalize_failure_cleans_up_all_created_records() {
        let (dns_config, config, client, calls) = spawn_issuance_doubles(FailPoint::Finalize).await;
        let error = run_attempt(
            &dns_config,
            &config,
            &client,
            &issuance_hostnames(),
            DelegationMode::Ok,
        )
        .await
        .expect_err("finalize failure must fail issuance");
        assert!(matches!(error, AcmeError::Acme(_)));
        assert_eq!(calls.cf_creates.lock().unwrap().len(), 2);
        assert_cleanup(&calls);
    }

    #[tokio::test]
    async fn certificate_fetch_failure_cleans_up_all_created_records() {
        let (dns_config, config, client, calls) =
            spawn_issuance_doubles(FailPoint::CertFetch).await;
        let error = tokio::time::timeout(
            Duration::from_secs(120),
            run_attempt(
                &dns_config,
                &config,
                &client,
                &issuance_hostnames(),
                DelegationMode::Ok,
            ),
        )
        .await
        .expect("bounded despite retries")
        .expect_err("certificate fetch failure must fail issuance");
        assert!(matches!(error, AcmeError::Acme(_)));
        assert_eq!(calls.cf_creates.lock().unwrap().len(), 2);
        assert_cleanup(&calls);
    }

    #[tokio::test]
    async fn cname_timeout_is_one_resolvers_answer_not_the_lookup_end() {
        // A stalled preferred resolver yields a classified Timeout error
        // from ONE attempt -- the value the fallback loop consumes --
        // rather than ending the whole lookup.
        let stalled = std::future::pending::<Result<Option<String>, DnsLookupError>>();
        let timed_out = bounded_cname_attempt(stalled, Some(Duration::from_millis(10)))
            .await
            .unwrap_err();
        assert!(matches!(timed_out.category, DnsErrorCategory::Timeout));
        assert_eq!(timed_out.message, "DNS CNAME lookup timed out");

        // The fallback's own budget is independent: a slow-but-successful
        // answer within its window is returned, not punished for the
        // preferred resolver's earlier stall.
        let slow_ok = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(Some("app.example.com.acme.managed.test".to_string()))
        };
        let answer = bounded_cname_attempt(slow_ok, Some(Duration::from_millis(200)))
            .await
            .unwrap();
        assert_eq!(answer.as_deref(), Some("app.example.com.acme.managed.test"));

        // No configured timeout preserves the native wait.
        let native = async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok(None)
        };
        assert_eq!(bounded_cname_attempt(native, None).await.unwrap(), None);
    }
}
