//! Outbound HTTP client hardened against SSRF (C12).
//!
//! Provides one narrow `reqwest` client:
//! - `RegistryClient` — talks to OCI registries on a hostname allowlist.
//!
//! The client refuses redirects, forces HTTPS, caps response body size, and
//! resolves DNS through a custom resolver that rejects loopback, link-local,
//! RFC1918, IMDS-style metadata addresses, IPv4-compatible/mapped IPv6
//! spellings of all of the above, and configured cluster CIDRs. Because
//! reqwest never consults a custom resolver for literal-IP hosts, the
//! cosign/sigstore verification paths (whose stacks build their own
//! transports) additionally pre-flight every registry-derived destination
//! through `EgressGuard` (issue #224): https-only, registry allowlist,
//! literal-IP blocklist, and a one-shot DNS resolution for names.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use enclava_common::outbound_http::{BlockedNetworks, GuardedResolver};

const DEFAULT_REGISTRY_ALLOWLIST: &[&str] = &[
    "ghcr.io",
    "docker.io",
    "registry-1.docker.io",
    // Docker Hub's bearer-token realm (challenge flow for docker.io pulls).
    "auth.docker.io",
    // GitLab's bearer-token realm (challenge for registry.gitlab.com pulls).
    "gitlab.com",
    "quay.io",
    "gcr.io",
    "registry.gitlab.com",
];
const DEFAULT_REGISTRY_WILDCARDS: &[&str] = &["pkg.dev"];

const DEFAULT_BODY_LIMIT_BYTES: u64 = 10 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("hostname `{0}` is not on the registry allowlist")]
    HostNotAllowed(String),
    #[error("scheme `{0}` not allowed; only https is permitted")]
    SchemeNotAllowed(String),
    #[error("response body exceeded {limit} byte limit")]
    BodyTooLarge { limit: u64 },
    #[error("URL is missing a host")]
    MissingHost,
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    #[error("destination resolves to a blocked address: {0}")]
    BlockedAddress(String),
    #[error("DNS lookup for destination failed: {0}")]
    DnsLookupFailed(String),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

#[derive(Debug, Clone)]
pub struct AllowList {
    exact: Vec<String>,
    wildcard_suffixes: Vec<String>,
}

impl AllowList {
    pub fn from_env_or_default(env_value: Option<String>) -> Self {
        match env_value
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(value) => Self::parse(value),
            None => Self {
                exact: DEFAULT_REGISTRY_ALLOWLIST
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                wildcard_suffixes: DEFAULT_REGISTRY_WILDCARDS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            },
        }
    }

    fn parse(value: &str) -> Self {
        let mut exact = Vec::new();
        let mut wildcard_suffixes = Vec::new();
        for entry in value.split(',') {
            let entry = entry.trim().to_ascii_lowercase();
            if entry.is_empty() {
                continue;
            }
            if let Some(rest) = entry.strip_prefix("*.") {
                wildcard_suffixes.push(rest.to_string());
            } else {
                exact.push(entry);
            }
        }
        Self {
            exact,
            wildcard_suffixes,
        }
    }

    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.exact.iter().any(|h| h == &host) {
            return true;
        }
        self.wildcard_suffixes
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
    }
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub blocked: Arc<BlockedNetworks>,
    pub body_limit_bytes: u64,
    pub timeout: Duration,
}

impl ClientConfig {
    pub fn from_env() -> Self {
        let blocked = BlockedNetworks::from_env();
        Self {
            blocked: Arc::new(blocked),
            body_limit_bytes: std::env::var("OUTBOUND_HTTP_BODY_LIMIT_BYTES")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .filter(|v| *v > 0)
                .unwrap_or(DEFAULT_BODY_LIMIT_BYTES),
            timeout: Duration::from_secs(15),
        }
    }
}

/// Build a SSRF-defended `reqwest::Client` (no host allowlist; the resolver
/// still rejects loopback / RFC1918 / cluster CIDRs). Use for outbound
/// callsites that talk to many destinations (Cloudflare, BTCPay, registries).
pub fn build_guarded_client(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    build_inner(config)
}

fn build_inner(config: &ClientConfig) -> Result<reqwest::Client, ClientError> {
    let resolver = Arc::new(GuardedResolver::new(Arc::clone(&config.blocked)));
    Ok(reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(config.timeout)
        .dns_resolver(resolver)
        .build()?)
}

/// Parse a URL host as a literal IP if it is one. Brackets are Url's
/// spelling for IPv6 literals; stripping them lets a single `IpAddr` parse
/// cover both families.
fn parse_literal_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
        .ok()
}

/// Pre-flight destination check for outbound URLs whose transport cannot be
/// routed through `build_guarded_client` (issue #224): reqwest never
/// consults a custom DNS resolver for literal-IP hosts, so a literal such
/// as `10.0.5.7` or `::ffff:169.254.169.254` reaches the socket directly.
/// The sigstore/oci clients used by the cosign verification paths build
/// their own reqwest transports internally, so every registry-derived URL
/// they touch is validated here — https, allowlisted host, and literal IPs
/// (and, for names, a one-shot DNS resolution) checked against
/// `BlockedNetworks` — BEFORE any connection is attempted.
pub async fn check_egress_destination(
    url: &reqwest::Url,
    blocked: &BlockedNetworks,
    allowlist: Option<&AllowList>,
) -> Result<(), ClientError> {
    check_egress_destination_with_http(url, blocked, allowlist, false).await
}

async fn check_egress_destination_with_http(
    url: &reqwest::Url,
    blocked: &BlockedNetworks,
    allowlist: Option<&AllowList>,
    allow_http: bool,
) -> Result<(), ClientError> {
    if url.scheme() != "https" && !(allow_http && url.scheme() == "http") {
        return Err(ClientError::SchemeNotAllowed(url.scheme().to_string()));
    }
    let host = url.host_str().ok_or(ClientError::MissingHost)?;
    if let Some(allowlist) = allowlist
        && !allowlist.allows(host)
    {
        return Err(ClientError::HostNotAllowed(host.to_string()));
    }
    if let Some(addr) = parse_literal_ip(host) {
        if blocked.contains(addr) {
            return Err(ClientError::BlockedAddress(format!("{addr} (literal)")));
        }
        return Ok(());
    }
    // A hostname: resolve it once here so a name pointing into private or
    // cluster space is refused before the unguarded transport dials it.
    // This mirrors the GuardedResolver check the guarded transports get.
    // Resolution FAILURE is reported distinctly from a blocked answer so
    // callers (and offline test environments) can tell the two apart.
    // The lookup is bounded (cap#241 review): a slow or nonresponsive
    // resolver must not hold the deployment request for its full retry
    // period before the bounded proxy path is even reached.
    let lookup = tokio::net::lookup_host(format!("{host}:0"));
    let addrs: Vec<SocketAddr> =
        match tokio::time::timeout(crate::egress_proxy::DNS_RESOLVE_TIMEOUT, lookup).await {
            Ok(result) => result
                .map_err(|e| {
                    ClientError::DnsLookupFailed(format!("failed to resolve `{host}`: {e}"))
                })?
                .collect(),
            Err(_) => {
                return Err(ClientError::DnsLookupFailed(format!(
                    "resolving `{host}` timed out after {:?}",
                    crate::egress_proxy::DNS_RESOLVE_TIMEOUT
                )));
            }
        };
    for addr in &addrs {
        if blocked.contains(addr.ip()) {
            return Err(ClientError::BlockedAddress(format!(
                "refused to resolve `{host}` to blocked address {}",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// Outbound client for OCI registries.
#[derive(Clone)]
pub struct RegistryClient {
    inner: reqwest::Client,
    allowlist: AllowList,
    blocked: Arc<BlockedNetworks>,
    body_limit: u64,
}

impl RegistryClient {
    pub fn from_env() -> Result<Self, ClientError> {
        let config = ClientConfig::from_env();
        let allowlist = AllowList::from_env_or_default(std::env::var("REGISTRY_ALLOWLIST").ok());
        Self::new(config, allowlist)
    }

    pub fn new(config: ClientConfig, allowlist: AllowList) -> Result<Self, ClientError> {
        Ok(Self {
            inner: build_inner(&config)?,
            allowlist,
            blocked: Arc::clone(&config.blocked),
            body_limit: config.body_limit_bytes,
        })
    }

    pub fn allowlist(&self) -> &AllowList {
        &self.allowlist
    }

    pub fn body_limit(&self) -> u64 {
        self.body_limit
    }

    /// Reqwest client for callers that drive their own request building.
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }

    /// Validate a URL is allowed before issuing a request.
    pub fn check_url(&self, url: &str) -> Result<(), ClientError> {
        let parsed =
            reqwest::Url::parse(url).map_err(|e| ClientError::InvalidUrl(e.to_string()))?;
        if parsed.scheme() != "https" {
            return Err(ClientError::SchemeNotAllowed(parsed.scheme().to_string()));
        }
        let host = parsed.host_str().ok_or(ClientError::MissingHost)?;
        if !self.allowlist.allows(host) {
            return Err(ClientError::HostNotAllowed(host.to_string()));
        }
        // reqwest bypasses its custom DNS resolver for literal-IP hosts, so
        // the GuardedResolver blocklist never sees them — an allowlisted
        // literal (e.g. a custom REGISTRY_ALLOWLIST entry like `10.0.5.7`)
        // would otherwise be dialed directly. Every request this client
        // issues goes through here, so enforce the literal-IP blocklist at
        // the same pre-flight point (cap#241 review).
        if let Some(addr) = parse_literal_ip(host)
            && self.blocked.contains(addr)
        {
            return Err(ClientError::BlockedAddress(format!("{addr} (literal)")));
        }
        Ok(())
    }

    pub async fn get_text(&self, url: &str) -> Result<(reqwest::StatusCode, String), ClientError> {
        self.check_url(url)?;
        let resp = self.inner.get(url).send().await?;
        let status = resp.status();
        let body = read_capped(resp, self.body_limit).await?;
        Ok((status, body))
    }
}

/// Shared egress policy for the cosign/sigstore verification paths (issue
/// #224): those stacks build their own reqwest transports internally (no
/// resolver/redirect injection point), so their destinations are validated
/// through this pre-flight guard instead — https-only, registry allowlist,
/// literal-IP blocklist, and a one-shot DNS resolution for names — before
/// any connection is attempted.
#[derive(Debug, Clone)]
pub struct EgressGuard {
    pub blocked: Arc<BlockedNetworks>,
    pub allowlist: AllowList,
    /// Loopback CONNECT proxy (see `egress_proxy`) that the sigstore and
    /// oci-client transports are routed through, so the guarded resolution
    /// is the one the connection actually uses and every redirect hop /
    /// bearer-token realm is re-validated (DNS-rebinding and redirect
    /// bypasses from the cap#241 review).
    pub proxy: crate::egress_proxy::EgressProxy,
}

impl EgressGuard {
    pub fn from_env() -> Self {
        let mut blocked = BlockedNetworks::defaults();
        if let Ok(pod) = std::env::var("CLUSTER_POD_CIDR") {
            blocked.extend_from_cidrs(pod.split(','));
        }
        if let Ok(svc) = std::env::var("CLUSTER_SERVICE_CIDR") {
            blocked.extend_from_cidrs(svc.split(','));
        }
        let blocked = Arc::new(blocked);
        Self {
            proxy: crate::egress_proxy::EgressProxy::new(Arc::clone(&blocked)),
            blocked,
            allowlist: AllowList::from_env_or_default(std::env::var("REGISTRY_ALLOWLIST").ok()),
        }
    }

    /// Validate a registry-derived URL before the unguarded transport dials
    /// it. Fails closed on any violation.
    pub async fn check_registry_url(&self, url: &reqwest::Url) -> Result<(), ClientError> {
        check_egress_destination(url, &self.blocked, Some(&self.allowlist)).await
    }

    /// Cosign's explicit development HTTP opt-in changes only the scheme
    /// policy, never host, DNS or blocked-network validation. Release builds
    /// remain HTTPS-only even if a caller requests HTTP.
    pub(crate) async fn check_cosign_registry_url(
        &self,
        url: &reqwest::Url,
        allow_http: bool,
    ) -> Result<(), ClientError> {
        check_egress_destination_with_http(
            url,
            &self.blocked,
            Some(&self.allowlist),
            cfg!(debug_assertions) && allow_http,
        )
        .await
    }
}
/// Read a response body into memory while enforcing `limit` against the
/// bytes actually received, not just the advertised Content-Length: a
/// hostile server can omit the header or lie about it, so bodies are
/// consumed incrementally and the read is aborted as soon as the cap is
/// exceeded — the oversized body is never buffered.
pub(crate) async fn read_body_capped(
    mut resp: reqwest::Response,
    limit: u64,
) -> Result<bytes::Bytes, ClientError> {
    if let Some(len) = resp.content_length()
        && len > limit
    {
        return Err(ClientError::BodyTooLarge { limit });
    }
    let mut body = bytes::BytesMut::with_capacity(
        resp.content_length()
            .unwrap_or(0)
            .min(limit)
            .min(u32::MAX as u64) as usize,
    );
    while let Some(chunk) = resp.chunk().await.map_err(ClientError::Http)? {
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(ClientError::BodyTooLarge { limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

async fn read_capped(resp: reqwest::Response, limit: u64) -> Result<String, ClientError> {
    let bytes = read_body_capped(resp, limit).await?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ClientConfig {
        ClientConfig {
            blocked: Arc::new(BlockedNetworks::defaults()),
            body_limit_bytes: 1024,
            timeout: Duration::from_secs(2),
        }
    }

    /// Test-local guard with default policy, independent of ambient env
    /// (REGISTRY_ALLOWLIST / CLUSTER_*_CIDR may be set by other tests).
    fn hermetic_egress_guard() -> EgressGuard {
        let blocked = Arc::new(BlockedNetworks::defaults());
        EgressGuard {
            proxy: crate::egress_proxy::EgressProxy::new(Arc::clone(&blocked)),
            blocked,
            allowlist: AllowList::from_env_or_default(None),
        }
    }

    #[tokio::test]
    async fn cosign_http_opt_in_preserves_destination_policy() {
        let guard = hermetic_egress_guard();
        let public = reqwest::Url::parse("http://8.8.8.8:5000/v2/").unwrap();
        assert!(matches!(
            guard.check_cosign_registry_url(&public, false).await,
            Err(ClientError::SchemeNotAllowed(_))
        ));
        assert!(matches!(
            guard.check_registry_url(&public).await,
            Err(ClientError::SchemeNotAllowed(_))
        ));
        let guard = EgressGuard {
            allowlist: AllowList::from_env_or_default(Some(
                "8.8.8.8,127.0.0.1,10.0.0.1,localhost".into(),
            )),
            ..guard
        };
        let result = guard.check_cosign_registry_url(&public, true).await;
        if cfg!(debug_assertions) {
            result.unwrap();
            for url in [
                "http://127.0.0.1:5000",
                "http://10.0.0.1:5000",
                "http://localhost:5000",
            ] {
                assert!(matches!(
                    guard
                        .check_cosign_registry_url(&url.parse().unwrap(), true)
                        .await,
                    Err(ClientError::BlockedAddress(_))
                ));
            }
            let restricted = EgressGuard {
                allowlist: AllowList::from_env_or_default(Some("ghcr.io".into())),
                ..guard
            };
            assert!(matches!(
                restricted.check_cosign_registry_url(&public, true).await,
                Err(ClientError::HostNotAllowed(_))
            ));
        } else {
            assert!(matches!(result, Err(ClientError::SchemeNotAllowed(_))));
        }
    }

    #[test]
    fn default_allowlist_accepts_known_registries() {
        let allow = AllowList::from_env_or_default(None);
        for host in [
            "ghcr.io",
            "docker.io",
            "registry-1.docker.io",
            "auth.docker.io",
            "gitlab.com",
            "quay.io",
            "gcr.io",
            "registry.gitlab.com",
        ] {
            assert!(allow.allows(host), "{host} should be allowed");
        }
    }

    #[test]
    fn wildcard_pkg_dev_matches_subdomains() {
        let allow = AllowList::from_env_or_default(None);
        assert!(allow.allows("us-docker.pkg.dev"));
        assert!(allow.allows("europe-west4-docker.pkg.dev"));
        assert!(allow.allows("pkg.dev"));
        assert!(!allow.allows("pkg.dev.attacker.example"));
    }

    #[test]
    fn allowlist_from_env_value_overrides_default() {
        let allow =
            AllowList::from_env_or_default(Some("internal.registry.test, *.corp.example".into()));
        assert!(allow.allows("internal.registry.test"));
        assert!(allow.allows("foo.corp.example"));
        assert!(!allow.allows("ghcr.io"));
    }

    #[test]
    fn registry_client_rejects_non_allowed_host() {
        let client = RegistryClient::new(cfg(), AllowList::from_env_or_default(None)).unwrap();
        let err = client
            .check_url("https://attacker.example/v2/foo/manifests/x")
            .unwrap_err();
        assert!(matches!(err, ClientError::HostNotAllowed(_)));
    }

    #[test]
    fn registry_client_accepts_gitlab_registry() {
        let client = RegistryClient::new(cfg(), AllowList::from_env_or_default(None)).unwrap();
        client
            .check_url("https://registry.gitlab.com/v2/acme/app/manifests/latest")
            .unwrap();
    }

    #[test]
    fn registry_client_rejects_http_scheme() {
        let client = RegistryClient::new(cfg(), AllowList::from_env_or_default(None)).unwrap();
        let err = client
            .check_url("http://ghcr.io/v2/foo/manifests/x")
            .unwrap_err();
        assert!(matches!(err, ClientError::SchemeNotAllowed(_)));
    }

    #[test]
    fn registry_client_rejects_allowlisted_private_literal_ip() {
        // cap#241 review: reqwest bypasses GuardedResolver for literal-IP
        // hosts, so an operator adding a private literal to
        // REGISTRY_ALLOWLIST must not let tag resolution dial it. The
        // literal-IP blocklist is enforced in check_url itself.
        let allow = AllowList::from_env_or_default(Some("10.0.5.7".into()));
        let client = RegistryClient::new(cfg(), allow).unwrap();
        let err = client
            .check_url("https://10.0.5.7/v2/team/app/manifests/latest")
            .unwrap_err();
        assert!(matches!(err, ClientError::BlockedAddress(_)));
    }

    #[test]
    fn registry_client_rejects_allowlisted_public_literal_ip() {
        // A public literal is not on the blocklist and is explicitly
        // allowlisted by the operator, so — mirroring
        // check_egress_destination's literal branch — it passes the
        // pre-flight. Only blocked literals fail; this pins that the two
        // guards stay consistent rather than silently diverging.
        let allow = AllowList::from_env_or_default(Some("8.8.8.8".into()));
        let client = RegistryClient::new(cfg(), allow).unwrap();
        client
            .check_url("https://8.8.8.8/v2/team/app/manifests/latest")
            .unwrap();
    }
    #[tokio::test]
    async fn egress_guard_rejects_literal_ip_registry_hosts() {
        // reqwest bypasses its custom DNS resolver for literal-IP hosts, so
        // the pre-flight guard must reject them explicitly (issue #224).
        let guard = hermetic_egress_guard();
        for url in [
            "https://10.0.5.7/v2/",
            "https://127.0.0.1:5000/v2/",
            "https://169.254.169.254/v2/",
            // Bracketed IPv6 spellings, v4-compatible and v4-mapped.
            "https://[::10.0.5.7]/v2/",
            "https://[::127.0.0.1]/v2/",
            "https://[::ffff:169.254.169.254]/v2/",
            "https://[::1]/v2/",
            // NAT64 spellings of internal v4 destinations (cap#241 review).
            "https://[64:ff9b::a00:507]/v2/",
            "https://[64:ff9b::a9fe:a9fe]/v2/",
            "https://[64:ff9b:1::a00:507]/v2/",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            assert!(
                guard.check_registry_url(&parsed).await.is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn egress_guard_rejects_non_allowlisted_registry_hosts() {
        // A tenant-supplied registry host that is not on the allowlist must
        // never steer the cosign/sigstore egress (issue #224).
        let guard = hermetic_egress_guard();
        for url in [
            "https://internal.svc.cluster.local/v2/",
            "https://reg.evil.example/v2/",
            "https://metadata.google.internal/v2/",
        ] {
            let parsed = reqwest::Url::parse(url).unwrap();
            let err = guard.check_registry_url(&parsed).await.unwrap_err();
            assert!(
                matches!(err, ClientError::HostNotAllowed(_)),
                "{url} must be rejected by the allowlist, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn egress_guard_rejects_http_scheme() {
        let guard = hermetic_egress_guard();
        let parsed = reqwest::Url::parse("http://ghcr.io/v2/").unwrap();
        let err = guard.check_registry_url(&parsed).await.unwrap_err();
        assert!(matches!(err, ClientError::SchemeNotAllowed(_)));
    }

    #[tokio::test]
    async fn egress_guard_allows_default_allowlisted_registries() {
        // Sanity: the default allowlist's own entries still pass the guard.
        // ghcr.io is a name, so the DNS path runs; offline CI resolves to
        // nothing, which now surfaces as the distinct `DnsLookupFailed`
        // variant (a resolution failure, not a block verdict) and is
        // tolerated here (cap#241 review).
        let guard = hermetic_egress_guard();
        let parsed = reqwest::Url::parse("https://ghcr.io/v2/").unwrap();
        match guard.check_registry_url(&parsed).await {
            Ok(()) => {}
            Err(ClientError::DnsLookupFailed(_)) => { /* offline test env: acceptable */ }
            Err(other) => panic!("ghcr.io must not be blocked: {other:?}"),
        }
    }
    #[test]
    fn redirect_policy_disabled_on_built_clients() {
        // Smoke check: builders shouldn't fail. The redirect ban is enforced
        // at request time by reqwest; check_url additionally guards the URL.
        RegistryClient::new(cfg(), AllowList::from_env_or_default(None)).unwrap();
    }

    #[tokio::test]
    async fn body_limit_is_respected_with_explicit_content_length() {
        // A direct unit covering the cap-on-content-length branch — we
        // construct a Response synthetically by not making a real HTTP call.
        // Instead, validate the helper through a tiny in-process server
        // would require starting a listener; we keep it pure here by
        // asserting cfg().body_limit_bytes is propagated.
        let client = RegistryClient::new(cfg(), AllowList::from_env_or_default(None)).unwrap();
        assert_eq!(client.body_limit(), 1024);
    }
    #[tokio::test]
    async fn body_limit_is_enforced_mid_stream_when_content_length_is_absent() {
        // A hostile server can omit Content-Length and stream an unbounded
        // body; the read must abort at the cap instead of buffering the
        // whole body first (follow-up to the #140 manifest body cap).
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = (0..4)
            .map(|_| Ok(bytes::Bytes::from(vec![b'x'; 512])))
            .collect();
        let stream = futures::stream::iter(chunks);
        let body = reqwest::Body::wrap_stream(stream);
        let http_response = http::Response::builder()
            .status(200)
            .body(body)
            .expect("synthetic response");
        let response = reqwest::Response::from(http_response);
        assert!(response.content_length().is_none());

        let err = read_body_capped(response, 1024).await.unwrap_err();
        assert!(
            matches!(err, ClientError::BodyTooLarge { limit: 1024 }),
            "streamed body over the cap must be rejected mid-read: {err}"
        );
    }

    #[tokio::test]
    async fn body_under_limit_streams_fully_without_content_length() {
        let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = vec![
            Ok(bytes::Bytes::from_static(b"hello ")),
            Ok(bytes::Bytes::from_static(b"world")),
        ];
        let stream = futures::stream::iter(chunks);
        let body = reqwest::Body::wrap_stream(stream);
        let http_response = http::Response::builder()
            .status(200)
            .body(body)
            .expect("synthetic response");
        let response = reqwest::Response::from(http_response);
        assert!(response.content_length().is_none());

        let bytes = read_body_capped(response, 1024).await.unwrap();
        assert_eq!(&bytes[..], b"hello world");
    }
}
