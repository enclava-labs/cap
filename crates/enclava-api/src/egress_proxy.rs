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
//! - CONNECT is served for HTTPS destinations (the production path). The
//!   debug-only `COSIGN_ALLOW_HTTP_REGISTRY` flag routes cleartext registry
//!   traffic as absolute-form proxy requests; those are served too, but the
//!   destination is resolved and blocklist-checked here exactly like a
//!   CONNECT target and the cleartext request is forwarded verbatim to the
//!   validated address only (cap#241 review). Everything else — including
//!   `https://` absolute-form (a cleartext request cannot carry TLS) and
//!   origin-form requests — is refused.
//! - The registry allowlist is NOT re-enforced here: a custom allowlisted
//!   registry may legitimately run its token realm on a different host, and
//!   manifest/blob redirects to CDN hosts are normal registry behavior.
//!   The allowlist still gates the initial registry URL in
//!   `EgressGuard::check_registry_url`; this proxy enforces the SSRF
//!   network blocklist for every dialed destination (see the cap#241
//!   review discussion for why per-hop hostname checks would break
//!   legitimate registries without adding security).
//! - Any port is accepted for CONNECT: the destination NETWORK is the SSRF
//!   boundary, TLS is always performed by the client regardless of port,
//!   and HTTPS registries on non-443 ports (including HTTPS-on-80, whose
//!   authority keeps its explicit `:80` — parsed straight from the CONNECT
//!   authority because URL normalization would strip a scheme-default
//!   port) must keep working.
//! - Resource bounds (cap#241 review): a connection that sends no request
//!   head within `REQUEST_HEAD_IDLE_TIMEOUT` is refused and closed, so a
//!   local client cannot park unbounded idle tasks/sockets on the API;
//!   tunnels and forwarded exchanges silent for `TUNNEL_IDLE_TIMEOUT`
//!   (measured per-progress — an ACTIVE transfer never hits it, only a
//!   silent one does) are torn down; at most
//!   `MAX_PROXY_CONNECTIONS` connections are served concurrently, so even
//!   a never-idle local client cannot accumulate unbounded tasks/sockets;
//!   a single DNS resolution or upstream dial is bounded by
//!   `DNS_RESOLVE_TIMEOUT`/`HTTP_UPSTREAM_CONNECT_TIMEOUT` so a slow
//!   resolver or unresponsive destination cannot hold a permit
//!   indefinitely; and the accept loop retries transient accept failures
//!   (e.g. temporary FD exhaustion) with a bounded backoff instead of
//!   dying while callers keep the cached URL.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::clients::{BlockedNetworks, ClientError};

/// Maximum bytes accepted for a CONNECT request head. Anything larger is a
/// malformed (or hostile) client and gets refused.
const MAX_REQUEST_HEAD_BYTES: usize = 8192;

/// A connection must send its request head within this window or it is
/// refused and closed. Bounds the task/socket cost of idle connections.
#[cfg(test)]
const REQUEST_HEAD_IDLE_TIMEOUT: Duration = Duration::from_millis(750);
#[cfg(not(test))]
const REQUEST_HEAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// An established CONNECT tunnel (or forwarded cleartext exchange) that
/// transfers no data in either direction for this long is torn down.
#[cfg(test)]
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Backoff (min and max) for transient `accept()` failures; the listener is
/// retained and retried forever with exponential growth capped here.
const ACCEPT_BACKOFF_START: Duration = Duration::from_millis(100);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Timeout for dialing an upstream (CONNECT tunnel or cleartext forward).
const HTTP_UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Timeout for a single DNS resolution of a tunnel/forward destination.
/// A slow or nonresponsive resolver must not hold a connection slot (and
/// thus one of the `MAX_PROXY_CONNECTIONS` permits) indefinitely
/// (cap#241 review).
pub(crate) const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum concurrent client connections served at once. Each in-flight
/// connection (head read, tunnel, or forward) holds one slot for its whole
/// lifetime; when none remain, further connections are refused and closed
/// immediately. Bounds the worst case a local client can impose even when
/// it never goes idle (cap#241 review).
#[cfg(test)]
const MAX_PROXY_CONNECTIONS: usize = 4;
#[cfg(not(test))]
const MAX_PROXY_CONNECTIONS: usize = 64;

#[derive(Debug, Clone)]
pub struct EgressProxy {
    blocked: Arc<BlockedNetworks>,
    bound: Arc<Mutex<Option<String>>>,
    /// Whether absolute-form cleartext (`http://`) forwarding is served at
    /// all. Bound to the debug-only `COSIGN_ALLOW_HTTP_REGISTRY` escape
    /// hatch at construction so the production HTTPS path (flag unset)
    /// cannot be downgraded to cleartext by an `http://` redirect or
    /// token realm advertised by a registry (cap#241 review).
    allow_http_forwarding: bool,
}

impl EgressProxy {
    pub fn new(blocked: Arc<BlockedNetworks>) -> Self {
        Self::with_http_forwarding(
            blocked,
            crate::env_gates::flag_is_truthy(
                &std::env::var("COSIGN_ALLOW_HTTP_REGISTRY").unwrap_or_default(),
            ),
        )
    }

    /// Test/explicit constructor: opt in or out of cleartext forwarding.
    pub fn with_http_forwarding(blocked: Arc<BlockedNetworks>, allow: bool) -> Self {
        Self {
            blocked,
            bound: Arc::new(Mutex::new(None)),
            allow_http_forwarding: allow,
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
        let allow_http_forwarding = self.allow_http_forwarding;
        tokio::spawn(async move {
            accept_loop(listener, blocked, allow_http_forwarding).await;
        });
        let url = format!("http://{addr}");
        *bound = Some(url.clone());
        Ok(url)
    }
}

async fn accept_loop(
    listener: TcpListener,
    blocked: Arc<BlockedNetworks>,
    allow_http_forwarding: bool,
) {
    let mut backoff = ACCEPT_BACKOFF_START;
    // One permit per in-flight connection: head read, tunnel, or forward.
    // Acquired BEFORE spawn so the slot is held from the moment the socket
    // is accepted (no gap a connection could slip through), released when
    // the handler finishes. `MAX_PROXY_CONNECTIONS` bounds the worst case
    // even against a client that never goes idle (cap#241 review).
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_PROXY_CONNECTIONS));
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                backoff = ACCEPT_BACKOFF_START;
                let permit = match slots.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        // At capacity: refuse and close immediately rather
                        // than queueing (queueing would reintroduce the
                        // unbounded task/socket cost the cap exists to
                        // bound).
                        tracing::warn!("egress proxy at connection cap; refusing");
                        drop(stream);
                        continue;
                    }
                };
                let blocked = Arc::clone(&blocked);
                let allow_http = allow_http_forwarding;
                tokio::spawn(async move {
                    handle_conn(stream, blocked, allow_http).await;
                    drop(permit);
                });
            }
            Err(e) => {
                // Transient accept failures (e.g. temporary FD exhaustion)
                // must not kill the listener while `EgressProxy::url` keeps
                // handing out its address: retry with a bounded backoff
                // instead of returning (cap#241 review). Fatal listener
                // errors surface again on the next accept attempt; the
                // loop never exits silently.
                tracing::warn!(error = %e, backoff_ms = backoff.as_millis() as u64, "egress proxy accept failed; retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
            }
        }
    }
}

async fn handle_conn(
    mut stream: TcpStream,
    blocked: Arc<BlockedNetworks>,
    allow_http_forwarding: bool,
) {
    let (head, body_prefix) = match read_request_head(&mut stream).await {
        Some(parts) => parts,
        None => {
            // Includes idle-timeout: a client that never sends a request
            // head is refused and closed, bounding the connection cost.
            let _ = write_forbidden(&mut stream).await;
            return;
        }
    };
    let first_line = head.lines().next().unwrap_or("");
    if first_line.to_ascii_uppercase().starts_with("CONNECT") {
        let Some(target) = parse_connect_target(first_line) else {
            tracing::warn!(line = %first_line, "egress proxy refused malformed CONNECT");
            let _ = write_forbidden(&mut stream).await;
            return;
        };
        match resolve_tunnel_destination(&target, &blocked).await {
            Ok(destination) => {
                // Dial only addresses that were validated above: for hostnames
                // `resolve_tunnel_destination` returns the checked answers
                // themselves, so there is no second, unguarded resolution.
                let upstream = match tokio::time::timeout(
                    HTTP_UPSTREAM_CONNECT_TIMEOUT,
                    TcpStream::connect(destination.as_slice()),
                )
                .await
                {
                    Ok(Ok(upstream)) => upstream,
                    _ => {
                        tracing::warn!(target = %target.host, "egress proxy dial failed");
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
                let _ = idle_bounded_copy(&mut stream, &mut upstream).await;
            }
            Err(reason) => {
                tracing::warn!(reason = %reason, target = %target.host, "egress proxy refused CONNECT");
                let _ = write_forbidden(&mut stream).await;
            }
        }
        return;
    }
    // Not a CONNECT: the only other accepted form is the absolute-form
    // `GET/... http://host:port/... HTTP/1.1` used when the debug-only
    // `COSIGN_ALLOW_HTTP_REGISTRY` flag routes cleartext registry traffic
    // through `http_proxy` (cap#241 review). The forwarding path is gated
    // on that flag (bound at construction): with the flag unset — the
    // production HTTPS configuration — an `http://` redirect or bearer
    // realm advertised by a registry is refused, so nothing can downgrade
    // the production path to cleartext. The destination is validated
    // exactly like a CONNECT target and the request is forwarded to the
    // validated address only; redirects are NOT followed by this proxy —
    // the client re-issues them through the proxy, re-validating each hop.
    if let Some(target) = parse_absolute_form_http_target(first_line) {
        if !allow_http_forwarding {
            tracing::warn!(
                line = %first_line,
                "egress proxy refused absolute-form http request (COSIGN_ALLOW_HTTP_REGISTRY not enabled)"
            );
            let _ = write_forbidden(&mut stream).await;
            return;
        }
        match resolve_tunnel_destination(&target, &blocked).await {
            Ok(destination) => {
                let upstream = match tokio::time::timeout(
                    HTTP_UPSTREAM_CONNECT_TIMEOUT,
                    TcpStream::connect(destination.as_slice()),
                )
                .await
                {
                    Ok(Ok(upstream)) => upstream,
                    _ => {
                        tracing::warn!(target = %target.host, "egress proxy dial failed");
                        let _ = write_forbidden(&mut stream).await;
                        return;
                    }
                };
                let mut upstream = upstream;
                // Replay the full request head verbatim, followed by any
                // body bytes that arrived in the same TCP read as the
                // head (coalesced head+body); anything after that still
                // sits in the socket and flows through the pipe below.
                if upstream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                if !body_prefix.is_empty() && upstream.write_all(&body_prefix).await.is_err() {
                    return;
                }
                // ...then pipe bidirectionally (remaining request body +
                // response), torn down when the exchange goes idle.
                let _ = idle_bounded_copy(&mut stream, &mut upstream).await;
            }
            Err(reason) => {
                tracing::warn!(reason = %reason, target = %target.host, "egress proxy refused HTTP forward");
                let _ = write_forbidden(&mut stream).await;
            }
        }
        return;
    }
    tracing::warn!(line = %first_line, "egress proxy refused non-CONNECT request");
    let _ = write_forbidden(&mut stream).await;
}

/// Read up to the end of the HTTP request head (first `\r\n\r\n`),
/// bounded by `MAX_REQUEST_HEAD_BYTES` and `REQUEST_HEAD_IDLE_TIMEOUT`.
/// The CONNECT client waits for the proxy response before sending
/// anything else, but a cleartext proxy request may carry a body whose
/// first bytes arrive in the same TCP read as the head: the terminator
/// is matched ANYWHERE in the buffer (not just at its end) and any
/// bytes after it are returned as the body prefix for forwarding
/// (cap#241 review). A connection that stays silent past the idle
/// timeout is refused, so a local client cannot park unbounded idle
/// tasks/sockets on the API.
async fn read_request_head(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 1024];
    let read = async {
        loop {
            let n = stream.read(&mut chunk).await.ok()?;
            if n == 0 {
                return None;
            }
            buf.extend_from_slice(&chunk[..n]);
            // Head terminator can land mid-buffer (coalesced head+body).
            if let Some(pos) = find_head_end(&buf) {
                // The head includes its terminating CRLFCRLF: the replayed
                // request must be a complete, well-formed head.
                let head = String::from_utf8_lossy(&buf[..pos + 4]).into_owned();
                let body = buf[pos + 4..].to_vec();
                return Some((head, body));
            }
            if buf.len() > MAX_REQUEST_HEAD_BYTES {
                return None;
            }
        }
    };
    tokio::time::timeout(REQUEST_HEAD_IDLE_TIMEOUT, read)
        .await
        .ok()?
}

/// Offset of the first `\r\n\r\n` head terminator, if present.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Bidirectional copy torn down only after `TUNNEL_IDLE_TIMEOUT` elapses
/// with NO traffic in either direction, and only after BOTH directions
/// have finished. Implemented as a chunked loop (not
/// `timeout(copy_bidirectional)`, which would cap the TOTAL duration and
/// cut healthy long transfers at exactly the deadline): each loop
/// iteration races the still-open directions' next read against the
/// remaining idle budget, and any progress resets the deadline.
/// EOF is tracked per direction and only the peer's WRITE half is shut
/// down when one side finishes: a half-closing client (request sent,
/// write side closed) must still receive the upstream's reply
/// (cap#241 review).
async fn idle_bounded_copy(a: &mut TcpStream, b: &mut TcpStream) -> std::io::Result<()> {
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];
    let mut budget = TUNNEL_IDLE_TIMEOUT;
    // EOF seen on `a` (a is done sending) / on `b`. A closed direction is
    // no longer polled; the opposite direction keeps flowing until it too
    // EOFs or the idle budget expires.
    let mut eof_a = false;
    let mut eof_b = false;
    loop {
        if eof_a && eof_b {
            return Ok(());
        }
        // Race whichever directions are still open against the budget
        // (branch futures are not evaluated when the precondition is
        // false, so `a`/`b` are only borrowed by live reads). The futures
        // (and their borrows) end when the `select!` does, before the
        // shutdown/write below.
        let outcome = tokio::select! {
            res = a.read(&mut buf_a), if !eof_a => Some((true, res?)),
            res = b.read(&mut buf_b), if !eof_b => Some((false, res?)),
            _ = tokio::time::sleep(budget) => None,
        };
        let (from_a, n) = match outcome {
            Some(x) => x,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "egress proxy tunnel idle",
                ));
            }
        };
        if n == 0 {
            // EOF on one side: propagate it as a write-half shutdown of
            // the peer (so the upstream or client sees end-of-request)
            // and keep forwarding the OTHER direction — the reply to a
            // half-closed request must still be delivered.
            if from_a {
                eof_a = true;
                let _ = b.shutdown().await;
            } else {
                eof_b = true;
                let _ = a.shutdown().await;
            }
            // EOF is not traffic: the idle budget is NOT reset here.
            continue;
        }
        let data: Vec<u8> = if from_a {
            buf_a[..n].to_vec()
        } else {
            buf_b[..n].to_vec()
        };
        let dst = if from_a { &mut *b } else { &mut *a };
        // Forward the chunk with the idle budget enforced per WRITE, not
        // per chunk: a peer that drains a full socket SLOWLY makes
        // partial progress (each positive write resets the deadline, so
        // a live transfer is never cut), while a peer that stops reading
        // entirely cannot hold the tunnel — and its proxy slot — past
        // one idle window (cap#241 review).
        budget = TUNNEL_IDLE_TIMEOUT;
        let mut off = 0;
        while off < data.len() {
            match tokio::time::timeout(budget, dst.write(&data[off..])).await {
                Ok(Ok(0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "egress proxy peer closed mid-write",
                    ));
                }
                Ok(Ok(written)) => {
                    off += written;
                    budget = TUNNEL_IDLE_TIMEOUT; // write progress resets the clock
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "egress proxy tunnel idle (stalled forward write)",
                    ));
                }
            }
        }
    }
}

struct ConnectTarget {
    host: String,
    port: u16,
}

/// Split an authority-form host into (host, explicit port). Handles
/// bracketed IPv6 literals (`[2001:db8::1]:443`) without URL parsing, so
/// a scheme-default port (80 over `http://`, 443 over `https://`) cannot
/// be normalized away — a CONNECT to an HTTPS-on-port-80 registry must
/// keep its explicit `:80` (cap#241 review).
fn split_authority_port(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // Bracketed IPv6 literal: the closing bracket must be followed by
        // `:port`.
        let (literal, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?.parse::<u16>().ok()?;
        return Some((format!("[{literal}]"), port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host.contains(':') {
        // Unbracketed IPv6 — malformed for an authority with a port.
        return None;
    }
    Some((host.to_string(), port.parse::<u16>().ok()?))
}

/// Parse a `CONNECT host:port HTTP/1.1` request line. Accepts bracketed
/// IPv6 literals; rejects anything carrying a path or userinfo, and
/// requires an explicit `HTTP/` version token (a bare `CONNECT host:port`
/// is malformed). The port comes straight from the authority — URL
/// normalization would drop a scheme-default port like `:80`.
fn parse_connect_target(line: &str) -> Option<ConnectTarget> {
    let mut parts = line.split_whitespace();
    if !parts.next()?.eq_ignore_ascii_case("CONNECT") {
        return None;
    }
    let target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let (host, port) = split_authority_port(target)?;
    // Validate the host spelling via URL grammar (rejects userinfo,
    // paths, and other garbage an authority must not carry).
    let url = reqwest::Url::parse(&format!("http://{target}")).ok()?;
    if url.path() != "/" || !url.username().is_empty() {
        return None;
    }
    if url.host_str()? != host {
        return None;
    }
    Some(ConnectTarget { host, port })
}

/// Parse an absolute-form proxy request line
/// `GET http://host:port/path HTTP/1.1` (also HEAD/POST/PUT/DELETE/PATCH,
/// the verbs an OCI client uses). Only cleartext `http://` URLs are
/// accepted: reqwest sends absolute-form requests to `http_proxy` for
/// plain-HTTP destinations when the debug-only
/// `COSIGN_ALLOW_HTTP_REGISTRY` flag is enabled (cap#241 review), while
/// HTTPS destinations always use CONNECT. An `https://` absolute-form
/// request cannot be served — the proxy has no TLS material — and is
/// refused.
fn parse_absolute_form_http_target(line: &str) -> Option<ConnectTarget> {
    let mut parts = line.split_whitespace();
    let method = parts.next()?;
    if !matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH"
    ) {
        return None;
    }
    let target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/") {
        return None;
    }
    let url = reqwest::Url::parse(target).ok()?;
    if url.scheme() != "http" {
        return None;
    }
    let host = url.host_str()?.to_string();
    let port = url.port_or_known_default()?;
    if !url.username().is_empty() {
        return None;
    }
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
    let lookup = tokio::net::lookup_host((target.host.as_str(), target.port));
    let addrs: Vec<SocketAddr> = match tokio::time::timeout(DNS_RESOLVE_TIMEOUT, lookup).await {
        Ok(result) => result
            .map_err(|e| format!("DNS lookup for `{}` failed: {e}", target.host))?
            .collect(),
        // A slow/nonresponsive resolver must not hold a connection slot
        // (one of the MAX_PROXY_CONNECTIONS permits) indefinitely
        // (cap#241 review).
        Err(_) => {
            return Err(format!(
                "DNS lookup for `{}` timed out after {DNS_RESOLVE_TIMEOUT:?}",
                target.host
            ));
        }
    };
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
    async fn rejects_plain_https_proxy_requests() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        // https:// absolute-form cannot be served: the proxy has no TLS
        // material, HTTPS must go through CONNECT.
        let response = roundtrip(
            &url,
            "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "https absolute-form must be refused, got: {response}"
        );
    }

    #[tokio::test]
    async fn rejects_origin_form_requests() {
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        let response = roundtrip(&url, "GET /v2/ HTTP/1.1\r\nHost: example.com\r\n\r\n").await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "origin-form requests must be refused, got: {response}"
        );
    }

    #[tokio::test]
    async fn idle_connections_are_refused() {
        // A connection that never sends a request head must be closed
        // within the (test-shortened) idle window instead of parking a
        // task and socket forever.
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        let mut chunk = [0u8; 64];
        let start = std::time::Instant::now();
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
            .await
            .expect("proxy must respond within the idle window")
            .unwrap_or(0);
        assert!(
            n == 0 || chunk[..n].starts_with(b"HTTP/1.1 403"),
            "idle connection must be refused, got: {n} bytes"
        );
        assert!(
            start.elapsed() >= REQUEST_HEAD_IDLE_TIMEOUT,
            "refusal must come from the idle timeout, not instantly"
        );
    }

    #[tokio::test]
    async fn connection_cap_refuses_beyond_limit() {
        // `MAX_PROXY_CONNECTIONS` (4 under cfg(test)) connections may be
        // in flight; the next one must be refused immediately (closed or
        // 403) rather than accepted into an unbounded set.
        let proxy = EgressProxy::new(Arc::new(BlockedNetworks::defaults()));
        let url = proxy.url().unwrap();
        // Hold the cap open with connections that send nothing (each
        // occupies a slot until its idle timeout fires).
        let mut holders = Vec::new();
        for _ in 0..MAX_PROXY_CONNECTIONS {
            holders.push(connect_raw(&url).await);
        }
        // Give the accept loop a moment to register the holders, then the
        // over-cap connection must be refused right away: either closed
        // with no bytes or served a 403 — never left hanging.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut extra = connect_raw(&url).await;
        let mut chunk = [0u8; 64];
        let n = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut chunk))
            .await
            .expect("over-cap connection must not hang")
            .unwrap_or(0);
        assert!(
            n == 0 || chunk[..n].starts_with(b"HTTP/1.1 403"),
            "over-cap connection must be refused, got {n} bytes: {}",
            String::from_utf8_lossy(&chunk[..n])
        );
    }

    #[tokio::test]
    async fn forwards_absolute_form_http_to_validated_destination() {
        // The debug HTTP-registry path: an absolute-form request is
        // resolved + blocklist-checked and forwarded to the validated
        // address only (cap#241 review).
        let echo = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = echo.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                // Read the forwarded request head, then answer.
                while !buf.ends_with(b"\r\n\r\n") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });

        // Default blocklist refuses loopback, so run with an empty one;
        // a companion test below proves loopback is refused with the
        // default policy. Forwarding requires the debug flag (cap#241
        // review), so enable it via the explicit constructor.
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let url = proxy.url().unwrap();
        let response = roundtrip(
            &url,
            &format!("GET http://{echo_addr}/v2/ HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n"),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("ok"),
            "validated absolute-form request must be forwarded, got: {response}"
        );
    }

    #[tokio::test]
    async fn refuses_absolute_form_http_to_blocked_destination() {
        // Forwarding enabled, default blocklist: the BLOCKLIST must be
        // what refuses (the flag gate is covered by its own test below).
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::defaults()), true);
        let url = proxy.url().unwrap();
        let response = roundtrip(
            &url,
            "GET http://127.0.0.1:5000/v2/ HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "absolute-form request to blocked destination must be refused, got: {response}"
        );
    }

    #[tokio::test]
    async fn refuses_absolute_form_http_without_debug_flag() {
        // Flag unset (production HTTPS configuration): an `http://`
        // absolute-form request — e.g. from a registry redirect or bearer
        // realm — must be refused, not forwarded in cleartext (cap#241
        // review). Even an empty blocklist must not save it.
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), false);
        let url = proxy.url().unwrap();
        let response = roundtrip(
            &url,
            "GET http://example.com/v2/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 403"),
            "absolute-form http must be refused without COSIGN_ALLOW_HTTP_REGISTRY, got: {response}"
        );
    }

    #[tokio::test]
    async fn forwards_coalesced_head_and_body() {
        // A POST whose head and body arrive in ONE TCP write: the head
        // reader must split at the FIRST terminator and the body prefix
        // must reach the upstream verbatim, before any pipe traffic
        // (cap#241 review).
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured = Arc::clone(&received);
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream.accept().await {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                // Read until the full request (head + 3-byte body) is in.
                while !buf.ends_with(b"abc") {
                    match sock.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                *captured.lock().unwrap() = buf.clone();
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        // Single write: head + body coalesced.
        stream
            .write_all(
                format!(
                    "POST http://{upstream_addr}/v2/ HTTP/1.1\r\nHost: {upstream_addr}\r\nContent-Length: 3\r\n\r\nabc"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("coalesced forward must not stall")
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            response.extend_from_slice(&chunk[..n]);
            if response.ends_with(b"ok") {
                break;
            }
        }
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200") && response.ends_with("ok"),
            "coalesced head+body must be forwarded, got: {response}"
        );
        let received = received.lock().unwrap().clone();
        let received = String::from_utf8_lossy(&received);
        assert!(
            received.contains("Content-Length: 3") && received.ends_with("abc"),
            "upstream must receive head followed by body prefix verbatim, got: {received}"
        );
    }

    #[tokio::test]
    async fn active_transfer_survives_beyond_idle_timeout() {
        // TUNNEL_IDLE_TIMEOUT is 5s under cfg(test). A tunnel that keeps
        // transferring data must NEVER be torn down by it — only a silent
        // one may be. Stream chunks across >2x the idle window and verify
        // they all arrive (cap#241 review).
        let echo = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = echo.accept().await {
                // Echo whatever arrives, for as long as it arrives.
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        stream
            .write_all(
                format!("CONNECT {echo_addr} HTTP/1.1\r\nHost: {echo_addr}\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        // Consume the 200.
        let mut byte = [0u8; 1];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n == 1, "proxy closed before completing the handshake");
            head.push(byte[0]);
        }
        assert!(String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"));

        // Keep the tunnel busy for well past the (test) idle timeout:
        // 4 rounds of sleep(idle/2) + echo, total ~2x the idle window.
        for i in 0..4 {
            tokio::time::sleep(TUNNEL_IDLE_TIMEOUT / 2).await;
            let payload = format!("round-{i}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            let mut echoed = [0u8; 64];
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut echoed))
                .await
                .expect("active tunnel must not be torn down by the idle timeout")
                .expect("echo read failed");
            assert_eq!(
                &echoed[..n],
                payload.as_bytes(),
                "round {i} must round-trip"
            );
        }
    }

    #[tokio::test]
    async fn half_closed_client_still_receives_upstream_reply() {
        // A client that sends its request and half-closes its write side
        // must still receive the upstream's reply through the tunnel
        // (cap#241 review): EOF is propagated as a write-half shutdown
        // of the peer, and the reverse direction keeps flowing.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream.accept().await {
                // Read the request until the client's EOF...
                let mut buf = [0u8; 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                // ...then reply AFTER having seen the EOF: proves the
                // proxy kept the reverse direction open.
                let _ = sock
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    .await;
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        stream
            .write_all(
                format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        // Consume the 200 Connection established.
        let mut byte = [0u8; 1];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n == 1, "proxy closed before completing the handshake");
            head.push(byte[0]);
        }
        // Send a request, then half-close our write side.
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();
        // The reply must still arrive.
        let mut reply = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .expect("reply must arrive after half-close, not hang")
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&chunk[..n]);
            if reply.ends_with(b"ok") {
                break;
            }
        }
        let reply = String::from_utf8_lossy(&reply);
        assert!(
            reply.starts_with("HTTP/1.1 200") && reply.ends_with("ok"),
            "half-closed client must receive the upstream reply, got: {reply}"
        );
    }

    #[tokio::test]
    async fn stalled_upstream_write_is_torn_down() {
        // An upstream that accepts the connection but never READS parks
        // the proxy's forward write under TCP backpressure. The write is
        // bounded by one idle window: the tunnel (and its proxy slot)
        // must be released rather than held forever (cap#241 review).
        // Note the upstream also never sends anything, so after the
        // client's payload fills both sockets' buffers the proxy must
        // hit the stalled-write timeout (TUNNEL_IDLE_TIMEOUT = 5s in
        // tests) and close the client side.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let gate = Arc::clone(&release);
        tokio::spawn(async move {
            if let Ok((sock, _)) = upstream.accept().await {
                // Accept but never read; hold the socket open until the
                // test signals completion.
                gate.notified().await;
                drop(sock);
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let url = proxy.url().unwrap();
        let mut stream = connect_raw(&url).await;
        stream
            .write_all(
                format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        // Consume the 200 Connection established.
        let mut byte = [0u8; 1];
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n == 1, "proxy closed before completing the handshake");
            head.push(byte[0]);
        }
        // Upload more than the sockets' combined buffers so the proxy's
        // forward write blocks on the non-reading upstream. The client's
        // own write is deadline-bounded too: if a regression makes the
        // proxy stop reading, the test must fail fast, not hang.
        let big = vec![b'x'; 4 * 1024 * 1024];
        let start = std::time::Instant::now();
        let write_err = tokio::time::timeout(TUNNEL_IDLE_TIMEOUT * 3, stream.write_all(&big))
            .await
            .expect("client write must not hang forever");
        // The client's own write may error first (proxy tore the tunnel
        // down) or succeed partially — what matters is the proxy side
        // releases the slot. Wait for the close.
        let mut chunk = [0u8; 256];
        let n = tokio::time::timeout(TUNNEL_IDLE_TIMEOUT * 3, stream.read(&mut chunk))
            .await
            .expect("proxy must tear the stalled tunnel down, not hang")
            .unwrap_or(0);
        release.notify_waiters();
        assert!(
            n == 0 || write_err.is_err(),
            "stalled tunnel must be closed by the idle bound, got {n} bytes"
        );
        assert!(
            start.elapsed() >= TUNNEL_IDLE_TIMEOUT,
            "teardown must come from the stalled-write bound, not instantly"
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

        // HTTPS-on-port-80 registry: the explicit `:80` must survive even
        // though it is http's scheme-default port (URL normalization would
        // strip it — cap#241 review).
        let t = parse_connect_target("CONNECT registry.example:80 HTTP/1.1").unwrap();
        assert_eq!(t.host, "registry.example");
        assert_eq!(t.port, 80);

        assert!(parse_connect_target("GET http://x/ HTTP/1.1").is_none());
        assert!(parse_connect_target("CONNECT host:443").is_none()); // no version
        assert!(parse_connect_target("CONNECT host HTTP/1.1").is_none()); // no port
        assert!(parse_connect_target("CONNECT [2001:db8::1] HTTP/1.1").is_none()); // bare bracketed, no port
    }

    #[test]
    fn parse_absolute_form_http_target_forms() {
        let t = parse_absolute_form_http_target("GET http://registry.example:5000/v2/ HTTP/1.1")
            .unwrap();
        assert_eq!(t.host, "registry.example");
        assert_eq!(t.port, 5000);

        let t =
            parse_absolute_form_http_target("POST http://registry.example/v2/ HTTP/1.1").unwrap();
        assert_eq!(t.host, "registry.example");
        assert_eq!(t.port, 80); // scheme default

        // https:// absolute-form cannot be forwarded by a cleartext proxy.
        assert!(parse_absolute_form_http_target("GET https://x/ HTTP/1.1").is_none());
        // Origin-form is not a proxy request.
        assert!(parse_absolute_form_http_target("GET /v2/ HTTP/1.1").is_none());
        // Userinfo must not sneak a host through.
        assert!(
            parse_absolute_form_http_target("GET http://u:p@x/ HTTP/1.1").is_none(),
            "userinfo must be rejected"
        );
    }
}
