//! Rate-limiter key extractor that only honours `X-Forwarded-For` /
//! `Forwarded` headers from configured trusted proxy CIDRs.
//!
//! Untrusted peers fall back to the direct TCP peer address; spoofed XFF
//! headers from the open internet cannot move another tenant's bucket.
//! Within a trusted proxy chain the client IP is resolved with the standard
//! rightmost-untrusted walk: the public client may append arbitrary leftmost
//! entries, but it cannot forge the rightmost entries appended by proxies
//! we trust, so it cannot choose its own rate-limit key.

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
}

impl TrustedProxyMatcher {
    pub fn from_env() -> Self {
        let raw = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
        Self::from_csv(&raw)
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
        Self { cidrs }
    }

    pub fn is_trusted(&self, addr: IpAddr) -> bool {
        self.cidrs
            .iter()
            .any(|(net, bits)| ip_in_cidr(addr, *net, *bits))
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

    /// Fallback to `X-Real-IP` when `X-Forwarded-For` is absent.
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
    /// layers of proxy), fall back to the leftmost entry.
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
        client.or_else(|| chain.first().copied())
    }

    pub fn extract_ip<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        let peer = self.peer_addr(req);
        if let Some(peer_ip) = peer
            && self.trusted.is_trusted(peer_ip)
            && let Some(client) = self.client_ip_from_forwarded(req)
        {
            return Some(client);
        }
        // Fall back to X-Real-IP if peer is trusted but X-Forwarded-For is absent/unusable.
        if let Some(peer_ip) = peer
            && self.trusted.is_trusted(peer_ip)
            && let Some(real_ip) = self.real_ip(req)
        {
            return Some(real_ip);
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
    fn all_trusted_chain_falls_back_to_leftmost() {
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let req = req_with("10.10.5.5", Some("10.10.1.1, 10.10.2.2"));
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "10.10.1.1");
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
    fn xff_preferred_over_x_real_ip() {
        // When both XFF and X-Real-IP are present, XFF takes precedence.
        let extractor =
            TrustedProxyKeyExtractor::new(TrustedProxyMatcher::from_csv("10.10.0.0/16"));
        let mut req = Request::builder().uri("/").body(()).unwrap();
        let socket: SocketAddr = "10.10.5.5:54321".parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(socket));
        req.headers_mut()
            .insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        req.headers_mut()
            .insert("x-real-ip", "203.0.113.99".parse().unwrap());
        let ip = extractor.extract_ip(&req).unwrap();
        assert_eq!(ip.to_string(), "198.51.100.7");
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
}
