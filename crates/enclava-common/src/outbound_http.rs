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
    /// Fail closed on the RFC 8215 local-use NAT64 prefix
    /// `64:ff9b:1::/48`: the prefix is a container for operator-chosen
    /// longer prefixes, so the embedded IPv4 position cannot be decoded
    /// from the address alone and any fixed-offset decode can be evaded.
    /// True for every guarded list — `defaults()` and any list extended
    /// with explicit CIDRs. False only for `empty()`, whose documented
    /// contract is "every destination allowed" for explicitly unguarded
    /// paths.
    block_local_use_nat64: bool,
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
        Self {
            v4,
            v6,
            block_local_use_nat64: true,
        }
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

    /// An empty blocklist — every destination allowed. For tests and for
    /// explicitly unguarded internal paths only.
    pub fn empty() -> Self {
        Self {
            v4: Vec::new(),
            v6: Vec::new(),
            block_local_use_nat64: false,
        }
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
        // An explicitly extended list is a guarded list: fail closed on the
        // undecodable RFC 8215 local-use NAT64 prefix.
        self.block_local_use_nat64 = true;
    }

    pub fn contains(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(ip) => self.v4.iter().any(|(net, bits)| in_v4(ip, *net, *bits)),
            IpAddr::V6(ip) => {
                // Several IPv6 spellings are an IPv4 destination in disguise
                // and must be checked against the v4 ranges, or they fall
                // through to a v6 list with no covering entry:
                //   - IPv4-mapped ::ffff:0:0/96 and IPv4-compatible ::/96
                //     (to_ipv4() covers both and returns None for any address
                //     with nonzero upper bits),
                //   - RFC 6052 NAT64: on a NAT64-enabled network the kernel
                //     translator routes e.g. 64:ff9b::a00:507 to 10.0.5.7, so
                //     the embedded IPv4 address is the real dial destination
                //     and must pass the v4 blocklist. The well-known /96
                //     embeds IPv4 unambiguously in the low 32 bits; the RFC
                //     8215 local-use /48 is a container for operator-chosen
                //     longer prefixes, so its addresses are blocked whole —
                //     but only on guarded lists; empty() must honor its
                //     allow-everything contract.
                if self.block_local_use_nat64 && nat64_local_use_prefix(ip) {
                    return true;
                }
                if let Some(v4) = ip.to_ipv4().or_else(|| nat64_embedded_ipv4(ip))
                    && self.v4.iter().any(|(net, bits)| in_v4(v4, *net, *bits))
                {
                    return true;
                }
                self.v6.iter().any(|(net, bits)| in_v6(ip, *net, *bits))
            }
        }
    }
}

/// Decode the IPv4 destination embedded in an RFC 6052 well-known-prefix
/// NAT64 address `64:ff9b::/96` (IPv4 in the low 32 bits, bits 32..96
/// zero). Returns None for anything else, so ordinary global unicast IPv6
/// is unaffected.
fn nat64_embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    let o = ip.octets();
    if o[..4] == [0x00, 0x64, 0xff, 0x9b] && o[4..12].iter().all(|&b| b == 0) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// RFC 8215 local-use NAT64 prefix `64:ff9b:1::/48`. Unlike the well-known
/// /96, this prefix is a container from which operators pick longer
/// network-specific prefixes (RFC 6052 permits /64, /96, ... embedding
/// layouts), so the position of the embedded IPv4 address cannot be known
/// from the address alone. Every address inside it is a
/// translator-mediated IPv4 destination, so the guard fails closed and
/// blocks the whole prefix.
fn nat64_local_use_prefix(ip: Ipv6Addr) -> bool {
    let o = ip.octets();
    o[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
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

    #[test]
    fn blocked_networks_reject_nat64_literals_with_private_v4() {
        // RFC 6052 well-known prefix 64:ff9b::/96: on a NAT64-enabled host
        // the translator dials the embedded IPv4 address, so the v4
        // blocklist must apply.
        let blocked = BlockedNetworks::defaults();
        for ip in [
            "64:ff9b::a00:507",   // -> 10.0.5.7
            "64:ff9b::7f00:1",    // -> 127.0.0.1
            "64:ff9b::a9fe:a9fe", // -> 169.254.169.254
            "64:ff9b::c0a8:101",  // -> 192.168.1.1
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(blocked.contains(parsed), "{ip} should be blocked");
        }
    }

    #[test]
    fn blocked_networks_fail_closed_on_rfc8215_local_use_nat64() {
        // RFC 8215's 64:ff9b:1::/48 is a container for operator-chosen
        // longer prefixes (/64, /96, ... layouts per RFC 6052), so the
        // embedded IPv4 position is not derivable from the address alone.
        // A /96 instance inside the prefix can bury 169.254.169.254 in
        // bits a fixed-offset decode never reads; the guard therefore
        // blocks the whole /48.
        let blocked = BlockedNetworks::defaults();
        for ip in [
            "64:ff9b:1::a00:507",
            "64:ff9b:1::a9fe:a9fe",
            // /96 instance at subnet id 0x0102: translator dials
            // 169.254.169.254 via 64:ff9b:1:102::a9fe:a9fe.
            "64:ff9b:1:102::a9fe:a9fe",
            // /64 instance at subnet id 0x0100: translator dials
            // 169.254.169.254 via 64:ff9b:1:100:a9:fea9:fe00::.
            "64:ff9b:1:100:a9:fea9:fe00::",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(blocked.contains(parsed), "{ip} should be blocked");
        }
    }

    #[test]
    fn blocked_networks_empty_allows_every_destination() {
        // empty()'s documented contract is "every destination allowed" —
        // including NAT64 spellings. It is reserved for explicitly
        // unguarded paths, where the caller takes responsibility for the
        // destination, so no heuristics may reject anything.
        let blocked = BlockedNetworks::empty();
        for ip in [
            "10.0.5.7",
            "127.0.0.1",
            "169.254.169.254",
            "::1",
            "64:ff9b::a00:507",
            "64:ff9b:1::a00:507",
            "64:ff9b:1:102::a9fe:a9fe",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!blocked.contains(parsed), "{ip} should be allowed");
        }
    }

    #[test]
    fn extended_empty_blocklist_still_fails_closed_on_local_use_nat64() {
        // extend_from_cidrs marks the list as explicitly guarded: even if
        // the added CIDRs cover nothing inside 64:ff9b:1::/48, the
        // undecodable local-use NAT64 prefix keeps being blocked whole.
        let mut blocked = BlockedNetworks::empty();
        blocked.extend_from_cidrs(["203.0.113.0/24"]);
        let nat64: IpAddr = "64:ff9b:1::a9fe:a9fe".parse().unwrap();
        assert!(
            blocked.contains(nat64),
            "extended list must fail closed on local-use NAT64"
        );
    }

    #[test]
    fn blocked_networks_still_allow_ordinary_public_v6() {
        // The ::/96 and NAT64 decodings must not over-block ordinary global
        // unicast v6: to_ipv4 returns None for any address with nonzero
        // upper bits, and NAT64 literals with a public embedded IPv4
        // address (e.g. 64:ff9b::8.8.8.8) are legitimate destinations.
        let blocked = BlockedNetworks::defaults();
        for ip in [
            "2600::1",
            "2001:db8::1",
            "64:ff9b::8.8.8.8",
            "64:ff9b::808:808",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!blocked.contains(parsed), "{ip} should not be blocked");
        }
    }

    #[test]
    fn cluster_cidrs_extend_blocklist() {
        let mut blocked = BlockedNetworks::defaults();
        blocked.extend_from_cidrs(["10.244.0.0/16", "10.96.0.0/12"]);
        let pod_ip: IpAddr = "10.244.5.7".parse().unwrap();
        let svc_ip: IpAddr = "10.96.0.10".parse().unwrap();
        assert!(blocked.contains(pod_ip));
        assert!(blocked.contains(svc_ip));
    }
}
