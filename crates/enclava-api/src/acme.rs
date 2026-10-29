use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::dns::{self, DnsConfig};
use crate::workload_tls_timing::{DnsErrorCategory, Phase, RequestTiming};
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Utc};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
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
    /// Every other terminal issuance failure: transport errors, DNS
    /// failures, unexpected statuses, and non-rate-limited or untyped ACME
    /// problems.
    Failed,
}

impl IssuanceFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RateLimited => "acme_rate_limited",
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
    )
    .await
    .map_err(|error| IssuanceFailure::diagnose(&error, &failures))
}

async fn issue_dns01_certificate_attempt(
    http_client: &reqwest::Client,
    acme_http: Box<dyn instant_acme::HttpClient>,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
    timing: RequestTiming,
) -> Result<String, AcmeError> {
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

    let mut challenge_records = Vec::new();
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
            let record_name = format!("_acme-challenge.{hostname}");
            let record_value = challenge.key_authorization().dns_value();
            let record = timing
                .measure(
                    Phase::DnsCreate,
                    dns::create_txt_record(http_client, dns_config, &record_name, &record_value),
                )
                .await?;
            challenge_records.push(record);
            if let Err(err) = timing
                .measure(
                    Phase::DnsVisibility,
                    wait_for_txt_record(&record_name, &record_value, acme_config, timing),
                )
                .await
            {
                cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
                return Err(err);
            }
            timing
                .measure(Phase::AcmeChallengeReady, challenge.set_ready())
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
        cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
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
    cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
    Ok(cert_chain)
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
struct DnsLookupError {
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

async fn cleanup_challenges(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    records: &[dns::DnsRecordHandle],
    timing: RequestTiming,
) {
    for record in records {
        if timing
            .measure(
                Phase::DnsCleanup,
                dns::delete_txt_record(http_client, dns_config, record),
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

async fn load_or_create_account(
    config: &AcmeConfig,
    http: Box<dyn instant_acme::HttpClient>,
) -> Result<Account, AcmeError> {
    if let Some(path) = config.account_credentials_path.as_ref()
        && path.is_file()
    {
        let bytes = std::fs::read(path)?;
        let credentials: AccountCredentials = serde_json::from_slice(&bytes)?;
        return Account::builder_with_http(http)
            .from_credentials(credentials)
            .await
            .map_err(AcmeError::Acme);
    }

    let (account, credentials) = Account::builder_with_http(http)
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url.clone(),
            None,
        )
        .await?;
    if let Some(path) = config.account_credentials_path.as_ref() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec(&credentials)?)?;
    }
    Ok(account)
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

    async fn spawn_test_acme_server(
        respond: impl Fn(&str) -> (u16, Option<&'static str>, String) + Send + Sync + 'static,
    ) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback bind");
        let addr = listener.local_addr().expect("loopback address");
        let respond = Arc::new(respond);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let respond = Arc::clone(&respond);
                tokio::spawn(async move {
                    let mut buffer = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        // Test requests carry no body, so a complete head
                        // delimits each request.
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
                        let path = head
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("/")
                            .split('?')
                            .next()
                            .unwrap_or("/")
                            .to_string();
                        let (status, retry_after, body) = respond(&path);
                        let reason = StatusCode::from_u16(status)
                            .ok()
                            .and_then(|status| status.canonical_reason())
                            .unwrap_or("Status");
                        let mut response = format!(
                            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n",
                            body.len()
                        );
                        if let Some(value) = retry_after {
                            response.push_str("Retry-After: ");
                            response.push_str(value);
                            response.push_str("\r\n");
                        }
                        response.push_str("Connection: keep-alive\r\n\r\n");
                        response.push_str(&body);
                        if stream.write_all(response.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
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
            "/ok" => (200, Some("999"), "{\"ok\":true}".to_string()),
            _ => (
                429,
                Some("120"),
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
            "/first" => (429, Some("100"), "{}".to_string()),
            "/second" => (429, Some("86400"), "{}".to_string()),
            _ => (200, Some("999"), "{}".to_string()),
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
                        Some("999"),
                        "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}".to_string(),
                    )
                } else {
                    (200, None, "{}".to_string())
                }
            }
            "/redirect" => (302, Some("999"), String::new()),
            "/rate-limited" => (
                429,
                Some("120"),
                "{\"type\":\"urn:ietf:params:acme:error:rateLimited\"}".to_string(),
            ),
            _ => (200, None, "{}".to_string()),
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
}
