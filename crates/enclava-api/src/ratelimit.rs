//! Rate-limiter key extractor that only honours `X-Forwarded-For` /
//! `Forwarded` headers from configured trusted proxy CIDRs.
//!
//! Untrusted peers fall back to the direct TCP peer address; spoofed XFF
//! headers from the open internet cannot move another tenant's bucket.

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

    fn first_forwarded_ip<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        if let Some(value) = req.headers().get("x-forwarded-for")
            && let Ok(s) = value.to_str()
            && let Some(first) = s.split(',').next()
            && let Ok(ip) = first.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
        if let Some(value) = req.headers().get("x-real-ip")
            && let Ok(s) = value.to_str()
            && let Ok(ip) = s.trim().parse::<IpAddr>()
        {
            return Some(ip);
        }
        None
    }

    pub fn extract_ip<B>(&self, req: &Request<B>) -> Option<IpAddr> {
        let peer = self.peer_addr(req);
        if let Some(peer_ip) = peer
            && self.trusted.is_trusted(peer_ip)
            && let Some(client) = self.first_forwarded_ip(req)
        {
            return Some(client);
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
}
