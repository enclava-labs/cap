//! Shared SSRF guard for outbound HTTP clients.
//!
//! `BlockedNetworks` is the set of CIDR ranges outbound HTTP must never
//! touch (loopback, link-local, RFC1918, IMDS, configured cluster CIDRs).
//! `GuardedResolver` is a `reqwest` DNS resolver that refuses any name whose
//! answer set contains a blocked address. Callers must also validate URL
//! literals against the same blocklist: literals bypass DNS resolution.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};

/// CIDR ranges that outbound HTTP must never touch.
#[derive(Debug, Clone)]
pub struct BlockedNetworks {
    v4: Vec<(Ipv4Addr, u8)>,
    v6: Vec<(Ipv6Addr, u8)>,
}

impl BlockedNetworks {
    pub fn defaults() -> Self {
        let v4 = vec![
            (Ipv4Addr::new(127, 0, 0, 0), 8),
            (Ipv4Addr::new(169, 254, 0, 0), 16),
            (Ipv4Addr::new(10, 0, 0, 0), 8),
            (Ipv4Addr::new(172, 16, 0, 0), 12),
            (Ipv4Addr::new(192, 168, 0, 0), 16),
            (Ipv4Addr::new(0, 0, 0, 0), 8),
            // CGNAT includes metadata endpoints used by some cloud providers.
            (Ipv4Addr::new(100, 64, 0, 0), 10),
        ];
        let v6 = vec![
            (Ipv6Addr::LOCALHOST, 128),
            (Ipv6Addr::UNSPECIFIED, 128),
            (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            (Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7), // ULA
        ];
        Self { v4, v6 }
    }

    /// Defaults plus any cluster CIDRs from the environment. Both vars hold
    /// comma-separated CIDRs; absent vars and malformed entries are skipped.
    pub fn from_env() -> Self {
        let mut blocked = Self::defaults();
        for var in ["CLUSTER_POD_CIDR", "CLUSTER_SERVICE_CIDR"] {
            if let Ok(cidrs) = std::env::var(var) {
                blocked.extend_from_cidrs(cidrs.split(','));
            }
        }
        blocked
    }

    /// Add CIDR strings of the form `10.0.0.0/8`. Invalid entries are skipped
    /// with a warning so config typos don't take down the process.
    pub fn extend_from_cidrs<I: IntoIterator<Item = S>, S: AsRef<str>>(&mut self, cidrs: I) {
        for cidr in cidrs {
            match parse_cidr(cidr.as_ref()) {
                Some(Cidr::V4(net, bits)) => self.v4.push((net, bits)),
                Some(Cidr::V6(net, bits)) => self.v6.push((net, bits)),
                None => tracing::warn!(
                    "ignoring invalid CIDR in cluster blocklist: {}",
                    cidr.as_ref()
                ),
            }
        }
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => self.v4.iter().any(|(net, bits)| in_v4(ip, *net, *bits)),
            IpAddr::V6(ip) => {
                if let Some(v4) = ip.to_ipv4()
                    && self.v4.iter().any(|(net, bits)| in_v4(v4, *net, *bits))
                {
                    return true;
                }
                self.v6.iter().any(|(net, bits)| in_v6(ip, *net, *bits))
            }
        }
    }
}

fn first_blocked(addrs: &[SocketAddr], blocked: &BlockedNetworks) -> Option<IpAddr> {
    addrs
        .iter()
        .map(SocketAddr::ip)
        .find(|ip| blocked.contains(*ip))
}

enum Cidr {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

fn parse_cidr(s: &str) -> Option<Cidr> {
    let (addr, bits) = s.split_once('/')?;
    let bits: u8 = bits.trim().parse().ok()?;
    let ip: IpAddr = addr.trim().parse().ok()?;
    match ip {
        IpAddr::V4(v4) if bits <= 32 => Some(Cidr::V4(v4, bits)),
        IpAddr::V6(v6) if bits <= 128 => Some(Cidr::V6(v6, bits)),
        _ => None,
    }
}

fn in_v4(ip: Ipv4Addr, net: Ipv4Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let mask: u32 = !0u32 << (32 - bits);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn in_v6(ip: Ipv6Addr, net: Ipv6Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let ip_bits = u128::from(ip);
    let net_bits = u128::from(net);
    let mask: u128 = !0u128 << (128 - bits);
    (ip_bits & mask) == (net_bits & mask)
}

/// DNS resolver that rejects any name resolving to a blocked IP.
#[derive(Debug)]
pub struct GuardedResolver {
    blocked: Arc<BlockedNetworks>,
}

impl GuardedResolver {
    pub fn new(blocked: Arc<BlockedNetworks>) -> Self {
        Self { blocked }
    }
}

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let blocked = Arc::clone(&self.blocked);
        Box::pin(async move {
            // Vet the real answer set the client will connect to; a separate
            // preflight lookup could be re-resolved to different addresses.
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
                .collect();

            if let Some(ip) = first_blocked(&addrs, &blocked) {
                return Err(format!("refused to resolve `{host}` to blocked address {ip}").into());
            }

            let iter: Addrs = Box::new(addrs.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_networks_reject_private_v4() {
        let blocked = BlockedNetworks::defaults();
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.6",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // IMDS
            "0.0.0.0",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(blocked.contains(parsed), "{ip} should be blocked");
        }
    }

    #[test]
    fn blocked_networks_accept_public_v4() {
        let blocked = BlockedNetworks::defaults();
        for ip in ["140.82.121.4", "1.1.1.1", "8.8.8.8"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!blocked.contains(parsed), "{ip} should be permitted");
        }
    }

    #[test]
    fn blocked_networks_reject_loopback_v6_and_link_local() {
        let blocked = BlockedNetworks::defaults();
        for ip in ["::1", "fe80::1", "fd00::1"] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(blocked.contains(parsed), "{ip} should be blocked");
        }
    }

    #[test]
    fn embedded_ipv4_v6_checked_against_v4_ranges() {
        let blocked = BlockedNetworks::defaults();
        // IPv4-compatible and mapped forms must obey the same IPv4 policy.
        assert!(blocked.contains("::ffff:10.1.2.3".parse().unwrap()));
        assert!(blocked.contains("::ffff:127.0.0.1".parse().unwrap()));
        assert!(blocked.contains("::10.1.2.3".parse().unwrap()));
        assert!(blocked.contains("::127.0.0.1".parse().unwrap()));
        assert!(blocked.contains("::169.254.169.254".parse().unwrap()));
        assert!(!blocked.contains("::ffff:8.8.8.8".parse().unwrap()));
        assert!(!blocked.contains("::8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn cluster_cidr_boundaries_are_deterministic() {
        let mut blocked = BlockedNetworks::defaults();
        blocked.extend_from_cidrs(["203.0.113.0/24", "2001:db8:1234::/48"]);
        // Public cluster ranges block inside the range only: the boundary
        // and first-outside addresses must fall on the right sides.
        assert!(blocked.contains("203.0.113.0".parse().unwrap()));
        assert!(blocked.contains("203.0.113.255".parse().unwrap()));
        assert!(!blocked.contains("203.0.114.0".parse().unwrap()));
        assert!(!blocked.contains("203.0.112.255".parse().unwrap()));

        assert!(blocked.contains("2001:db8:1234::".parse().unwrap()));
        assert!(blocked.contains("2001:db8:1234:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!blocked.contains("2001:db8:1235::".parse().unwrap()));
        // A v4-mapped literal inside a configured public v4 range is blocked.
        assert!(blocked.contains("::ffff:203.0.113.7".parse().unwrap()));
        assert!(blocked.contains("::203.0.113.7".parse().unwrap()));
    }

    #[test]
    fn mixed_answer_set_is_rejected_when_any_address_is_blocked() {
        let blocked = BlockedNetworks::defaults();
        let public: SocketAddr = "8.8.8.8:443".parse().unwrap();
        let private: SocketAddr = "10.1.2.3:443".parse().unwrap();

        let mixed = [public, private];
        assert_eq!(
            first_blocked(&mixed, &blocked),
            Some(private.ip()),
            "one blocked answer must poison the whole set"
        );
        assert_eq!(first_blocked(&[public], &blocked), None);
        // Ordering does not matter: private-first sets reject the same way.
        assert_eq!(
            first_blocked(&[private, public], &blocked),
            Some(private.ip())
        );
    }
}
