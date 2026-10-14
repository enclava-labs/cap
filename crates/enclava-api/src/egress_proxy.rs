//! Loopback CONNECT proxy that binds egress validation to the actual
//! connection (issue #224 review follow-up).
//!
//! The sigstore and oci-client stacks build their own internal `reqwest`
//! clients: `sigstore::cosign::ClientBuilder::build()` hardcodes
//! `oci_client::client::Client::new(..)`, which exposes no DNS-resolver or
//! redirect-policy injection point. A pre-flight check alone therefore
//! leaves two gaps:
//!
//! 1. **DNS rebinding** — the pre-flight resolves the hostname, discards the
//!    answers, and the transport's own resolver performs a second, unguarded
//!    lookup moments later.
//! 2. **Follow-up destinations** — registries redirect manifest/blob
//!    requests and point bearer-token challenges at new hosts that the
//!    pre-flight never saw.
//!
//! Both `sigstore::registry::ClientConfig` and
//! `oci_client::client::ClientConfig` DO expose `https_proxy`, and reqwest
//! routes HTTPS requests through a proxy with CONNECT. Routing those
//! transports through this loopback proxy closes both gaps at once: every
//! CONNECT target (initial registry host, each redirect hop, each token
//! realm) is resolved HERE, every answer is checked against
//! `BlockedNetworks`, and the proxy itself dials the validated address —
//! there is no second resolution to race.
//!
//! Scope notes:
//! - Only CONNECT is served. Plain-HTTP proxy-style requests are refused,
//!   matching the https-only egress policy.
//! - The registry allowlist is NOT re-enforced here: a custom allowlisted
//!   registry may legitimately run its token realm on a different host.
//!   The allowlist still gates the initial registry URL in
//!   `EgressGuard::check_registry_url`; this proxy enforces the SSRF
//!   network blocklist for every dialed destination.
//! - Any port is accepted for CONNECT: the destination NETWORK is the SSRF
//!   boundary, TLS is always performed by the client regardless of port,
//!   and HTTPS registries on non-443 ports must keep working.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use crate::clients::{BlockedNetworks, ClientError};

/// Maximum bytes accepted for a CONNECT request head. Anything larger is a
/// malformed (or hostile) client and gets refused.
const MAX_REQUEST_HEAD_BYTES: usize = 8192;

#[derive(Debug, Clone)]
pub struct EgressProxy {
    blocked: Arc<BlockedNetworks>,
    bound: Arc<Mutex<Option<String>>>,
}

impl EgressProxy {
    pub fn new(blocked: Arc<BlockedNetworks>) -> Self {
        Self {
            blocked,
            bound: Arc::new(Mutex::new(None)),
        }
    }

    /// Return the proxy URL, binding the loopback listener on first use.
    ///
    /// The listener is created lazily so guards constructed in tests (or
    /// processes that never run the cosign paths) hold no sockets. Fails
    /// closed: if the listener cannot be bound, the error propagates and
    /// callers must abort the guarded operation rather than proceed with a
    /// direct (unguarded) connection.
    pub fn url(&self) -> Result<String, ClientError> {
        let mut bound = self.bound.lock().expect("egress proxy bind mutex poisoned");
        if let Some(url) = bound.as_ref() {
            return Ok(url.clone());
        }
        // Bind synchronously (std) and hand the socket to tokio: `url()` is
        // called from async contexts but stays a plain fn, and a loopback
        // bind never blocks meaningfully.
        let std_listener = std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
            ClientError::InvalidUrl(format!("failed to bind loopback egress proxy: {e}"))
        })?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| ClientError::InvalidUrl(format!("egress proxy nonblocking: {e}")))?;
        let listener = tokio::net::TcpListener::from_std(std_listener).map_err(|e| {
            ClientError::InvalidUrl(format!("egress proxy register with runtime: {e}"))
        })?;
        let addr = listener
            .local_addr()
            .map_err(|e| ClientError::InvalidUrl(format!("egress proxy local addr: {e}")))?;
        let blocked = Arc::clone(&self.blocked);
        tokio::spawn(async move {
            accept_loop(listener, blocked).await;
        });
        let url = format!("http://{addr}");
        *bound = Some(url.clone());
        Ok(url)
    }
}

async fn accept_loop(listener: TcpListener, blocked: Arc<BlockedNetworks>) {
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let blocked = Arc::clone(&blocked);
                tokio::spawn(async move {
                    handle_conn(stream, blocked).await;
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "egress proxy accept failed; stopping listener");
                return;
            }
        }
    }
}

async fn handle_conn(mut stream: TcpStream, blocked: Arc<BlockedNetworks>) {
    let head = match read_request_head(&mut stream).await {
        Some(head) => head,
        None => {
            let _ = write_forbidden(&mut stream).await;
            return;
        }
    };
    let first_line = head.lines().next().unwrap_or("");
    let Some(target) = parse_connect_target(first_line) else {
        // Not a valid CONNECT (includes plain proxy-style GET/POST, which
        // the https-only policy refuses).
        tracing::warn!(line = %first_line, "egress proxy refused non-CONNECT request");
        let _ = write_forbidden(&mut stream).await;
        return;
    };

    match resolve_tunnel_destination(&target, &blocked).await {
        Ok(destination) => {
            // Dial only addresses that were validated above: for hostnames
            // `resolve_tunnel_destination` returns the checked answers
            // themselves, so there is no second, unguarded resolution.
            let upstream = match TcpStream::connect(destination.as_slice()).await {
                Ok(upstream) => upstream,
                Err(e) => {
                    tracing::warn!(error = %e, target = %target.host, "egress proxy dial failed");
                    let _ = write_forbidden(&mut stream).await;
                    return;
                }
            };
            if stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            let mut upstream = upstream;
            // Errors here just tear down one tunnel; the proxy stays up.
            let _ = copy_bidirectional(&mut stream, &mut upstream).await;
        }
        Err(reason) => {
            tracing::warn!(reason = %reason, target = %target.host, "egress proxy refused CONNECT");
            let _ = write_forbidden(&mut stream).await;
        }
    }
}

/// Read up to the end of the HTTP request head (`\r\n\r\n`), bounded by
/// `MAX_REQUEST_HEAD_BYTES`. The CONNECT client waits for the proxy
/// response before sending anything else, so the head cannot be followed
/// by tunnel payload in the same read.
async fn read_request_head(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.ends_with(b"\r\n\r\n") {
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
        if buf.len() > MAX_REQUEST_HEAD_BYTES {
            return None;
        }
    }
}

struct ConnectTarget {
    host: String,
    port: u16,
}

/// Parse a `CONNECT host:port HTTP/1.1` request line. Accepts bracketed
/// IPv6 literals; rejects anything carrying a path or userinfo, and
/// requires an explicit `HTTP/` version token (a bare `CONNECT host:port`
/// is malformed).
fn parse_connect_target(line: &str) -> Option<ConnectTarget> {
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    // Parse as a URL to borrow reqwest's authority grammar; then require a
    // bare authority (no path, no userinfo) and an explicit port.
    let url = reqwest::Url::parse(&format!("http://{target}")).ok()?;
    if url.path() != "/" || !url.username().is_empty() {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port()?;
    Some(ConnectTarget { host, port })
}

/// Resolve a CONNECT target to dialable, already-validated addresses.
///
/// Literal IPs are checked against the blocklist directly. Hostnames are
/// resolved HERE — the answers returned are exactly the addresses the
/// proxy will dial, closing the rebinding window between check and
/// connect. Every answer must be clean; any blocked answer refuses the
/// whole tunnel (an attacker must not be able to flood the answer set with
/// one public and one private address).
async fn resolve_tunnel_destination(
    target: &ConnectTarget,
    blocked: &BlockedNetworks,
) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = target
        .host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        if blocked.contains(addr) {
            return Err(format!("literal destination {addr} is blocked"));
        }
        return Ok(vec![SocketAddr::new(addr, target.port)]);
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| format!("DNS lookup for `{}` failed: {e}", target.host))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("`{}` resolved to no addresses", target.host));
    }
    for addr in &addrs {
        if blocked.contains(addr.ip()) {
            return Err(format!(
                "refused to resolve `{}` to blocked address {}",
                target.host,
                addr.ip()
            ));
        }
    }
    Ok(addrs)
}

async fn write_forbidden(stream: &mut TcpStream) -> std::io::Result<()> {
    stream
        .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn connect_raw(proxy_url: &str) -> TcpStream {
        let url = reqwest::Url::parse(proxy_url).unwrap();
        let addr = url
            .socket_addrs(|| None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        TcpStream::connect(addr).await.unwrap()
    }

    async fn roundtrip(proxy_url: &str, request: &str) -> String {
        let mut stream = connect_raw(proxy_url).await;
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        // Read whatever comes back first (status line + headers).
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..n]);
            if response.ends_with(b"\r\n\r\n") || response.len() > 4096 {
                // For 403 the proxy closes; give it one extra read's grace.
                let _ = stream.read(&mut chunk).await;
                break;
            }
        }
        String::from_utf8_lossy(&response).into_owned()
    }

    #[tokio::test]
    async fn url_is_stable_across_calls() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let first = proxy.url().unwrap();
        let second = proxy.url().unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("http://127.0.0.1:"));
    }

    #[tokio::test]
    async fn rejects_connect_to_blocked_literal() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        let response = roundtrip(
            &url,
            "CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "loopback CONNECT must be refused, got: {response}"
        );

        let response = roundtrip(
            &url,
            "CONNECT [::ffff:169.254.169.254]:443 HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "IPv4-mapped metadata address must be refused, got: {response}"
        );
    }

    #[tokio::test]
    async fn rejects_plain_http_proxy_requests() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        let response = roundtrip(
            &url,
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "non-CONNECT requests must be refused, got: {response}"
        );
    }

    #[tokio::test]
    async fn rejects_malformed_request_lines() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        for request in [
            "CONNECT not a request line\r\n\r\n",
            "CONNECT host:443/path HTTP/1.1\r\nHost: host\r\n\r\n",
            "CONNECT user@host:443 HTTP/1.1\r\nHost: host\r\n\r\n",
            "CONNECT host HTTP/1.1\r\nHost: host\r\n\r\n",
        ] {
            let response = roundtrip(&url, request).await;
            assert!(
                response.starts_with("HTTP/1.1 403") || response.is_empty(),
                "malformed CONNECT must be refused, got: {response}"
            );
        }
    }

    #[tokio::test]
    async fn tunnels_allowed_destinations() {
        // End-to-end: parse, validate, dial, and pipe both directions.
        let echo = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = echo.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = sock.read(&mut buf).await {
                    let _ = sock.write_all(&buf[..n]).await;
                }
            }
        });

        // The default blocklist refuses loopback, so run this test with an
        // empty blocklist: validation passes and the pipe must work.
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::empty()));
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        stream
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n == 1, "proxy closed before completing the handshake");
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head);
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "allowed CONNECT must succeed, got: {head}"
        );

        stream.write_all(b"ping-through-tunnel").await.unwrap();
        let mut echoed = [0u8; 64];
        let n = stream.read(&mut echoed).await.unwrap();
        assert_eq!(&echoed[..n], b"ping-through-tunnel");
    }

    #[test]
    fn parse_connect_target_accepts_authority_forms() {
        let t = parse_connect_target("CONNECT ghcr.io:443 HTTP/1.1").unwrap();
        assert_eq!(t.host, "ghcr.io");
        assert_eq!(t.port, 443);

        let t = parse_connect_target("CONNECT [2001:db8::1]:8443 HTTP/1.1").unwrap();
        // reqwest's host_str keeps the brackets; the resolver strips them.
        assert_eq!(t.host, "[2001:db8::1]");
        assert_eq!(t.port, 8443);

        assert!(parse_connect_target("GET http://x/ HTTP/1.1").is_none());
        assert!(parse_connect_target("CONNECT host:443").is_none()); // no version
    }
}
