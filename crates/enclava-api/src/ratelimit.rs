//! Rate-limiter key extractor that only honours client-address headers
//! from configured trusted proxy CIDRs — and, when a shared proxy secret
//! is configured, only from peers that also present that secret.
//!
//! Untrusted peers fall back to the direct TCP peer address; spoofed XFF
//! headers from the open internet cannot move another tenant's bucket.
//! The secret requirement exists because the trusted CIDR (the cluster
//! pod network) also contains workloads that may connect to the API
//! directly (tenant enclava-init pods, admitted by the API NetworkPolicy):
//! without it, such a caller could rotate `X-Real-IP`/XFF per request and
//! receive a fresh rate-limit bucket each time. ingress-nginx overwrites
//! the secret header via its `proxy-set-headers` ConfigMap, so public
//! clients cannot supply it. When no secret is configured (local dev),
//! CIDR membership alone grants header trust.
//!
//! For a trusted peer the key is derived, in order of preference, from:
//!
//! 1. `X-Real-IP` — ingress-nginx rewrites this with the address that
//!    actually connected to it (default `use-forwarded-headers=false`), so
//!    no client — public or on the trusted pod network — can seed it.
//!    This is the verified-proxy-metadata source and takes precedence
//!    whenever the peer is trusted (not only when XFF is absent).
//! 2. A rightmost-untrusted walk over `X-Forwarded-For` — for proxies that
//!    only append to XFF. The public client may put arbitrary leftmost
//!    entries in the header, but the rightmost entries are appended by
//!    proxies we trust. If every entry is trusted, the rightmost entry
//!    (written by the proxy closest to us) is used — the leftmost entry is
//!    fully client-controlled and must never become a key.
//! 3. The direct TCP peer address.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::Request;
use std::net::SocketAddr;
use tower_governor::GovernorError;
use tower_governor::key_extractor::KeyExtractor;

use crate::clients::BlockedNetworks; // re-uses the CIDR matcher logic only

#[derive(Debug, Clone)]
pub struct TrustedProxyKeyExtractor {
    trusted: Arc<TrustedProxyMatcher>,
}

#[derive(Debug, Clone, Default)]
pub struct TrustedProxyMatcher {
    cidrs: Vec<(IpAddr, u8)>,
    /// Shared secret that a peer must present (in addition to sitting in a
    /// trusted CIDR) for its forwarding headers to be honoured. Injected by
    /// the ingress controllers via proxy-set-headers; see module docs.
    proxy_secret_sha256: Option<[u8; 32]>,
}

/// Header the ingress controllers carry the shared proxy secret in.
const PROXY_SECRET_HEADER: &str = "x-enclava-proxy-secret";

fn sha256_hex(value: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(value.trim().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

impl TrustedProxyMatcher {
    pub fn from_env() -> Self {
        let raw = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
        let secret = std::env::var("TRUSTED_PROXY_SECRET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self::from_csv(&raw).with_proxy_secret(secret.as_deref())
    }

    pub fn from_csv(raw: &str) -> Self {
        let mut cidrs = Vec::new();
        for entry in raw.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((addr, bits)) = entry.split_once('/') {
                if let (Ok(ip), Ok(bits)) =
                    (addr.trim().parse::<IpAddr>(), bits.trim().parse::<u8>())
                {
                    cidrs.push((ip, bits));
                    continue;
                }
            } else if let Ok(ip) = entry.parse::<IpAddr>() {
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                cidrs.push((ip, bits));
                continue;
            }
            tracing::warn!("ignoring invalid TRUSTED_PROXY_CIDRS entry: {}", entry);
        }
        Self {
            cidrs,
            proxy_secret_sha256: None,
        }
    }

    /// Require peers to present this shared secret (via the
    /// `x-enclava-proxy-secret` header) before their forwarding headers are
    /// honoured. `None` restores CIDR-only trust.
    pub fn with_proxy_secret(mut self, secret: Option<&str>) -> Self {
        self.proxy_secret_sha256 = secret
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(sha256_hex);
        self
    }

    pub fn is_trusted(&self, addr: IpAddr) -> bool {
        self.cidrs
            .iter()
            .any(|(net, bits)| ip_in_cidr(addr, *net, *bits))
    }

    /// True when the request carries the configured proxy secret (constant
    /// time when a secret is set). When no secret is configured, CIDR
    /// membership alone is sufficient (local/dev deployments).
    fn presents_proxy_secret<B>(&self, req: &Request<B>) -> bool {
        let Some(expected) = self.proxy_secret_sha256.as_ref() else {
            return true;
        };
        let Some(value) = req
            .headers()
            .get(PROXY_SECRET_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        else {
            return false;
        };
        use subtle::ConstantTimeEq;
        expected.ct_eq(&sha256_hex(value)).into()
    }
}

fn ip_in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            if bits == 0 {
                return true;
            }
            if bits > 32 {
                return false;
            }
            let mask: u32 = !0u32 << (32 - bits);
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            if bits == 0 {
                return true;
            }
            if bits > 128 {
                return false;
            }
            let mask: u128 = !0u128 << (128 - bits);
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

impl TrustedProxyKeyExtractor {
    pub fn from_env() -> Self {
        Self {
            trusted: Arc::new(TrustedProxyMatcher::from_env()),
        }
    }

    pub fn new(trusted: TrustedProxyMatcher) -> Self {
        Self {
            trusted: Arc::new(trusted),
        }
    }

    fn peer_addr<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(s)| s.ip())
    }

    /// Parse the comma-separated `X-Forwarded-For` list, right to left.
    fn forwarded_list<B>(&self, req: &Request<B>) -> Vec<IpAddr> {
        let Some(value) = req.headers().get("x-forwarded-for") else {
            return Vec::new();
        };
        let Ok(s) = value.to_str() else {
            return Vec::new();
        };
        s.split(',')
            .filter_map(|entry| entry.trim().parse::<IpAddr>().ok())
            .collect()
    }

    /// `X-Real-IP` from a trusted peer. Preferred source whenever the peer
    /// is trusted (not only when XFF is absent): ingress-nginx rewrites the
    /// header with the address that actually connected to it.
    fn real_ip<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        req.headers()
            .get("x-real-ip")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }

    /// Rightmost-untrusted walk over `X-Forwarded-For`.
    ///
    /// Only called when the direct peer is a trusted proxy. Each trusted
    /// proxy appends the address it received the request from, so the
    /// rightmost entries were written by proxies closest to us and can be
    /// consumed while they are trusted; the rightmost address that is NOT a
    /// trusted proxy is the originating client. Spoofed leftmost entries
    /// appended by the public client are skipped like any other untrusted
    /// hop. If every entry is trusted (e.g. an internal probe through two
    /// layers of proxy), fall back to the rightmost entry: it was written
    /// by the proxy closest to us, whereas the leftmost entry is fully
    /// client-controlled and must never become a rate-limit key.
    fn client_ip_from_forwarded<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        let chain = self.forwarded_list(req);
        if chain.is_empty() {
            return None;
        }
        let client = chain
            .iter()
            .rev()
            .find(|ip| !self.trusted.is_trusted(**ip))
            .copied();
        client.or_else(|| chain.last().copied())
    }

    pub fn extract_ip<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        let peer = self.peer_addr(req);
        let peer_is_trusted = peer.map(|ip| self.trusted.is_trusted(ip)).unwrap_or(false);
        // Header trust requires BOTH CIDR membership and (when configured)
        // the shared proxy secret. The secret is what stops a tenant or PaaS
        // pod — which the NetworkPolicy admits directly and whose IPs sit
        // inside the trusted pod-network CIDR — from rotating X-Real-IP/XFF
        // to mint a fresh rate-limit bucket per request. Only the ingress
        // controllers, which overwrite the header via proxy-set-headers,
        // present it.
        let peer_is_trusted = peer_is_trusted && self.trusted.presents_proxy_secret(req);
        if peer_is_trusted {
            // Preferred source: X-Real-IP as rewritten by ingress-nginx with
            // the address that actually connected to it. Unlike XFF (which
            // proxies append to), this header is overwritten, so a client
            // on the trusted pod network cannot seed it via the ingress to
            // rotate rate-limit keys.
            if let Some(real_ip) = self.real_ip(req) {
                return Some(real_ip);
            }
            // Fallback for trusted proxies that only set XFF.
            if let Some(client) = self.client_ip_from_forwarded(req) {
                return Some(client);
            }
        }
        peer
    }
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<B>(&self, req: &Request<B>) -> Result<Self::Key, GovernorError> {
        self.extract_ip(req)
            .ok_or(GovernorError::UnableToExtractKey)
    }
}

// `BlockedNetworks` is a small re-export touchpoint to keep the crate's
// internal API surface from drifting. The trusted-proxy code does not depend
// on it at runtime, but downstream code that builds both modules together
// expects the symbol path to remain stable.
#[allow(dead_code)]
fn _link_blocked_networks(_: &BlockedNetworks) {}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;

    fn req_with(peer: &str, xff: Option<&str>) -> Request<()> {
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = format!("{peer}:54321").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        if let Some(xff) = xff {
            req.headers_mut()
                .insert("x-forwarded-for", xff.parse().unwrap());
        }
        req
    }

    #[test]
    fn untrusted_peer_xff_is_ignored() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("203.0.113.5", Some("198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.5");
    }

    #[test]
    fn trusted_proxy_xff_is_used() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn empty_trusted_list_means_no_xff_trust() {
        let extractor = TrustedProxyKeyExtractor::new(TrustedProxyMatcher::default());
        let req = req_with("127.0.0.1", Some("198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "127.0.0.1");
    }

    #[test]
    fn invalid_xff_falls_back_to_peer() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.0.1", Some("not-an-ip"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "10.10.0.1");
    }

    #[test]
    fn single_address_trusted_entry() {
        let extractor = TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.0.0.5"));
        assert!(extractor.trusted.is_trusted("10.0.0.5".parse().unwrap()));
        assert!(!extractor.trusted.is_trusted("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn spoofed_leftmost_xff_cannot_choose_bucket() {
        // A public client sends its own XFF header; the ingress appends the
        // client's real address. The leftmost spoofed entry must be ignored
        // and the real client IP (rightmost untrusted) used as the key.
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("1.2.3.4, 5.6.7.8, 198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn spoofed_trusted_range_leftmost_xff_is_skipped() {
        // Spoofing a trusted-range address as the leftmost entry must not
        // let the client impersonate an internal caller either.
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("10.10.9.9, 198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn all_trusted_chain_falls_back_to_rightmost() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("10.10.1.1, 10.10.2.2"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "10.10.2.2");
    }

    #[test]
    fn unparseable_xff_entries_are_skipped() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("garbage, 198.51.100.7"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn x_real_ip_fallback_when_xff_absent() {
        // When X-Forwarded-For is absent but X-Real-IP is present from a
        // trusted proxy, use the real IP as the client.
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = "10.10.5.5:54321".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        req.headers_mut()
            .insert("x-real-ip", "198.51.100.7".parse().unwrap());
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn x_real_ip_preferred_and_unspoofable_through_ingress() {
        // Codex PR #172 finding: a pod on the trusted pod network (10/8)
        // calls the public ingress with a spoofed XFF; ingress-nginx
        // appends the pod's (trusted) address to XFF but OVERWRITES
        // X-Real-IP with the address that actually connected to it. Since
        // the key comes from X-Real-IP, the spoofed XFF entries are
        // ignored and the pod cannot rotate rate-limit keys.
        let extractor = TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.0.0.0/8"));
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = "10.10.5.5:54321".parse().unwrap(); // ingress controller
        req.extensions_mut().insert(ConnectInfo(socket));
        req.headers_mut().insert(
            "x-forwarded-for",
            "1.2.3.4, 5.6.7.8, 10.20.30.40".parse().unwrap(),
        );
        // ingress-nginx rewrote X-Real-IP to the pod's true address
        req.headers_mut()
            .insert("x-real-ip", "10.20.30.40".parse().unwrap());
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "10.20.30.40");
    }

    #[test]
    fn x_real_ip_ignored_when_peer_untrusted() {
        // When the direct peer is not trusted, fall back to peer IP even if
        // X-Real-IP is present (prevents a compromised proxy from setting it).
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = "203.0.113.5:54321".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        req.headers_mut()
            .insert("x-real-ip", "198.51.100.7".parse().unwrap());
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "203.0.113.5");
    }

    fn req_with_headers(peer: &str, headers: &[(&str, String)]) -> Request<()> {
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = format!("{peer}:54321").parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        for (name, value) in headers {
            let name =
                axum::http::HeaderName::from_lowercase(name.as_bytes()).expect("valid header name");
            let value = value
                .parse::<axum::http::HeaderValue>()
                .expect("valid header value");
            req.headers_mut().insert(name, value);
        }
        req
    }

    #[test]
    fn proxy_secret_required_for_header_trust_when_configured() {
        // Self-check Critical finding: tenant/PaaS pods sit inside the
        // trusted pod-network CIDR and the NetworkPolicy admits them
        // directly, so CIDR membership alone must not grant header trust.
        // Without the shared proxy secret, headers are ignored and the
        // caller is keyed by its peer (pod) IP.
        let extractor = TrustedProxyKeyExtractor::new(
            TrustedProxyMatcher::from_csv("10.0.0.0/8").with_proxy_secret(Some("ingress-secret")),
        );
        // Tenant pod calls the ClusterIP directly, rotating X-Real-IP and
        // XFF per request without knowing the secret.
        let req = req_with_headers(
            "10.42.7.7",
            &[
                ("x-real-ip", "198.51.100.7".to_string()),
                ("x-forwarded-for", "1.2.3.4, 203.0.113.9".to_string()),
            ],
        );
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(
            ip.to_string(),
            "10.42.7.7",
            "secret-less trusted-CIDR peer must be keyed by peer IP"
        );

        // Same pod presents a wrong secret: still keyed by peer IP.
        let req = req_with_headers(
            "10.42.7.7",
            &[
                ("x-enclava-proxy-secret", "wrong".to_string()),
                ("x-real-ip", "198.51.100.7".to_string()),
            ],
        );
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "10.42.7.7");
    }

    #[test]
    fn proxy_secret_grants_header_trust_to_ingress() {
        // The ingress controller (trusted CIDR + correct secret) still gets
        // per-client keys from X-Real-IP.
        let extractor = TrustedProxyKeyExtractor::new(
            TrustedProxyMatcher::from_csv("10.0.0.0/8").with_proxy_secret(Some("ingress-secret")),
        );
        let req = req_with_headers(
            "10.10.5.5",
            &[
                ("x-enclava-proxy-secret", "ingress-secret".to_string()),
                ("x-real-ip", "198.51.100.7".to_string()),
            ],
        );
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }

    #[test]
    fn proxy_secret_absent_config_restores_cidr_only_trust() {
        // No secret configured (local dev): CIDR membership alone grants
        // header trust, as before this gate existed.
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with_headers("10.10.5.5", &[("x-real-ip", "198.51.100.7".to_string())]);
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
    }
}
