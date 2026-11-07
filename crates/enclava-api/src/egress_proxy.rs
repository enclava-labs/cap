//! Loopback CONNECT proxy that binds egress validation to the actual
//! connection (issue #224 review follow-up).
//!
//! The oci-client stack builds its own internal `reqwest` clients (the
//! cosign verifier drives `oci_client::client::Client` directly since the
//! sigstore-rust 0.15 migration), and `Client::try_from(ClientConfig)`
//! exposes no DNS-resolver or redirect-policy injection point. A pre-flight
//! check alone therefore leaves two gaps:
//!
//! 1. **DNS rebinding** — the pre-flight resolves the hostname, discards the
//!    answers, and the transport's own resolver performs a second, unguarded
//!    lookup moments later.
//! 2. **Follow-up destinations** — registries redirect manifest/blob
//!    requests and point bearer-token challenges at new hosts that the
//!    pre-flight never saw.
//!
//! Both the cosign verifier's `oci_client::client::ClientConfig` instances
//! expose `https_proxy`, and reqwest
//! routes HTTPS requests through a proxy with CONNECT. Routing that
//! transport through this loopback proxy closes both gaps at once: every
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
//!   CONNECT target and the cleartext request is forwarded to the
//!   validated address only, minus hop-by-hop `Proxy-Authorization`
//!   (the process-local tenant credential must not leave the proxy;
//!   cap#241 review, cap#266). Everything else — including
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
//!   that global budget is further partitioned by authenticated principal
//!   (`MAX_PER_TENANT_CONNECTIONS`) so one tenant cannot occupy every
//!   permit (cap#266); a single DNS resolution or upstream dial is bounded
//!   by `DNS_RESOLVE_TIMEOUT`/`HTTP_UPSTREAM_CONNECT_TIMEOUT` so a slow
//!   resolver or unresponsive destination cannot hold a permit
//!   indefinitely; a tunnel that only trickles (below
//!   `MIN_PROGRESS_BYTES` per `TUNNEL_PROGRESS_WINDOW`) or that outlives
//!   `TUNNEL_MAX_LIFETIME` is torn down even though any byte still resets
//!   the idle clock — a floor-meeting transfer is not cut at the idle
//!   window (cap#241); and the accept loop retries transient accept
//!   failures (e.g. temporary FD exhaustion) with a bounded backoff
//!   instead of dying while callers keep the cached URL.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use enclava_common::outbound_http::BlockedNetworks;

use crate::clients::ClientError;

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

/// Per-principal share of the proxy budget (cap#266). The global cap stays
/// the backstop; this partition is what stops one tenant from starving
/// every other tenant's verification fetches. Anonymous clients (no
/// `Proxy-Authorization`) share one bucket of the same size, so a path
/// that forgets to present identity cannot fill the global budget either.
#[cfg(test)]
const MAX_PER_TENANT_CONNECTIONS: usize = 2;
#[cfg(not(test))]
const MAX_PER_TENANT_CONNECTIONS: usize = 16;

/// Window in which a tunnel must forward at least `MIN_PROGRESS_BYTES`.
/// Sub-floor traffic does not move this deadline (unlike the idle clock,
/// which any byte resets). A transfer that meets the floor refreshes the
/// window and may continue, so a healthy long pull is not cut merely for
/// having run past `TUNNEL_IDLE_TIMEOUT` (cap#241).
#[cfg(test)]
const TUNNEL_PROGRESS_WINDOW: Duration = Duration::from_secs(5);
#[cfg(not(test))]
const TUNNEL_PROGRESS_WINDOW: Duration = Duration::from_secs(300);

/// Minimum bytes that must be *forwarded* (written to the peer, not merely
/// read) in each `TUNNEL_PROGRESS_WINDOW`. A 1-byte drip resets the idle
/// clock and still loses the permit when the window ends.
#[cfg(test)]
const MIN_PROGRESS_BYTES: u64 = 4096;
#[cfg(not(test))]
const MIN_PROGRESS_BYTES: u64 = 64 * 1024;

/// Absolute occupancy ceiling from tunnel start. Independent of throughput,
/// so a stream calibrated to just meet the progress floor cannot hold a
/// permit forever. Far longer than the 5-minute total cap cap#241 removed:
/// an actively streaming transfer is not cut at the idle window, only after
/// this backstop. The test value stays above
/// `active_transfer_survives_beyond_idle_timeout`.
#[cfg(test)]
const TUNNEL_MAX_LIFETIME: Duration = Duration::from_secs(20);
#[cfg(not(test))]
const TUNNEL_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

/// Partition key for platform-owned fetches (sidecar startup verification)
/// that must not be charged to a customer org.
pub const PLATFORM_EGRESS_PRINCIPAL: &str = "platform";

/// Bucket key for connections that present no proxy credentials. Not a
/// valid caller principal (`valid_principal` rejects the NUL), so a client
/// cannot join this bucket by choosing its name.
const ANONYMOUS_PRINCIPAL: &str = "\0anonymous";

#[derive(Clone)]
pub struct EgressProxy {
    blocked: Arc<BlockedNetworks>,
    bound: Arc<Mutex<Option<String>>>,
    /// Whether absolute-form cleartext (`http://`) forwarding is served at
    /// all. Bound to the debug-only `COSIGN_ALLOW_HTTP_REGISTRY` escape
    /// hatch at construction so the production HTTPS path (flag unset)
    /// cannot be downgraded to cleartext by an `http://` redirect or
    /// token realm advertised by a registry (cap#241 review).
    allow_http_forwarding: bool,
    /// Process-local admission state shared with the listener spawned by
    /// `url()`. The credential is redacted from `Debug`.
    admission: Arc<Admission>,
}

impl fmt::Debug for EgressProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgressProxy")
            .field("allow_http_forwarding", &self.allow_http_forwarding)
            .field("bound", &self.bound)
            .finish_non_exhaustive()
    }
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
            admission: Arc::new(Admission::generate()),
        }
    }

    /// Return the credential-less proxy URL, binding the loopback listener
    /// on first use.
    ///
    /// Connections that present no `Proxy-Authorization` share one anonymous
    /// bucket of `MAX_PER_TENANT_CONNECTIONS` (cap#266). Production callers
    /// must use [`Self::url_for_principal`] so a tenant is charged to its own
    /// bucket. This URL is for tests and for binding the listener.
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
        let admission = Arc::clone(&self.admission);
        tokio::spawn(async move {
            accept_loop(listener, blocked, allow_http_forwarding, admission).await;
        });
        let url = format!("http://{addr}");
        *bound = Some(url.clone());
        Ok(url)
    }

    /// Proxy URL that attributes connections to `principal`.
    ///
    /// reqwest / hyper-util turn the userinfo into `Proxy-Authorization:
    /// Basic`. The password is a process-local secret so a local process
    /// that discovers the ephemeral port cannot mint extra tenant buckets
    /// and bypass the per-tenant cap. Do not log the returned URL.
    ///
    /// `principal` is the partition key — an org id rendered by
    /// [`org_egress_principal`], or [`PLATFORM_EGRESS_PRINCIPAL`].
    pub fn url_for_principal(&self, principal: &str) -> Result<String, ClientError> {
        if !valid_principal(principal) {
            return Err(ClientError::InvalidUrl(
                "egress principal must be 1-128 chars of [A-Za-z0-9._-]".into(),
            ));
        }
        let mut url = reqwest::Url::parse(&self.url()?)
            .map_err(|e| ClientError::InvalidUrl(format!("egress proxy url: {e}")))?;
        url.set_username(principal).map_err(|_| {
            ClientError::InvalidUrl("egress principal rejected by URL grammar".into())
        })?;
        url.set_password(Some(&self.admission.secret_hex))
            .map_err(|_| {
                ClientError::InvalidUrl("egress proxy credential rejected by URL grammar".into())
            })?;
        Ok(url.to_string())
    }

    /// `Proxy-Authorization` header value for raw-TCP tests. Same credential
    /// `url_for_principal` embeds. Production callers use the proxy URL.
    #[cfg(test)]
    pub(crate) fn authorization_header(&self, principal: &str) -> String {
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{principal}:{}", self.admission.secret_hex));
        format!("Proxy-Authorization: Basic {token}")
    }
}

/// Partition key for an authenticated org. Hyphens only — a colon would
/// split userinfo into username/password before percent-encoding.
pub fn org_egress_principal(org_id: &impl fmt::Display) -> String {
    format!("org-{org_id}")
}

async fn accept_loop(
    listener: TcpListener,
    blocked: Arc<BlockedNetworks>,
    allow_http_forwarding: bool,
    admission: Arc<Admission>,
) {
    let mut backoff = ACCEPT_BACKOFF_START;
    // One permit per in-flight connection: head read, tunnel, or forward.
    // Acquired BEFORE spawn so the slot is held from the moment the socket
    // is accepted (no gap a connection could slip through), released when
    // the handler finishes. `MAX_PROXY_CONNECTIONS` bounds the worst case
    // even against a client that never goes idle (cap#241 review).
    // Per-tenant permits are acquired later, once the request head has
    // named a principal (cap#266).
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
                let admission = Arc::clone(&admission);
                tokio::spawn(async move {
                    handle_conn(stream, blocked, allow_http, admission).await;
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
    admission: Arc<Admission>,
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
    // Attribute the connection before spending a dial or a tunnel on it.
    // Invalid credentials are refused outright (not folded into the
    // anonymous bucket) so a wrong secret cannot be used to probe.
    let principal = match classify_principal(&head, &admission.secret_hex) {
        PrincipalDecision::Invalid => {
            tracing::warn!("egress proxy refused invalid proxy authorization");
            let _ = write_forbidden(&mut stream).await;
            return;
        }
        PrincipalDecision::Anonymous => ANONYMOUS_PRINCIPAL.to_string(),
        PrincipalDecision::Named(principal) => principal,
    };
    let _tenant_permit = match admission.tenants.try_acquire(&principal) {
        Some(permit) => permit,
        None => {
            tracing::warn!(
                principal = principal_label(&principal),
                "egress proxy per-tenant connection cap; refusing"
            );
            let _ = write_unavailable(&mut stream).await;
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
                // Replay the request head, minus hop-by-hop proxy
                // credentials. `Proxy-Authorization` carries the
                // process-local tenant secret (cap#266); forwarding it
                // would hand that secret to the destination.
                let forwarded = head_for_upstream(&head);
                if upstream.write_all(forwarded.as_bytes()).await.is_err() {
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

/// Bidirectional copy torn down when:
/// - both directions have finished, or
/// - `TUNNEL_IDLE_TIMEOUT` elapses with no traffic in either direction, or
/// - a `TUNNEL_PROGRESS_WINDOW` elapses without `MIN_PROGRESS_BYTES`
///   actually forwarded (a slow drip resets the idle clock and still loses
///   the permit — cap#266), or
/// - `TUNNEL_MAX_LIFETIME` elapses from tunnel start, even if the progress
///   floor is being met.
///
/// Implemented as a chunked loop (not `timeout(copy_bidirectional)`, which
/// would cap the TOTAL duration at the idle window and cut healthy long
/// transfers): each iteration races the still-open directions' next read
/// against the earliest of the three deadlines. Any read or forwarded byte
/// resets the *idle* clock. Only a full progress-floor of forwarded bytes
/// resets the progress window. The lifetime deadline never moves, so a
/// floor-meeting transfer can run far past the idle window (cap#241) and
/// still cannot occupy a permit forever (cap#266).
/// EOF is tracked per direction and only the peer's WRITE half is shut
/// down when one side finishes: a half-closing client (request sent,
/// write side closed) must still receive the upstream's reply
/// (cap#241 review). EOF does not refresh any deadline.
async fn idle_bounded_copy(a: &mut TcpStream, b: &mut TcpStream) -> std::io::Result<()> {
    let mut buf_a = [0u8; 8192];
    let mut buf_b = [0u8; 8192];
    let mut budget = TunnelBudget::new();
    // EOF seen on `a` (a is done sending) / on `b`. A closed direction is
    // no longer polled; the opposite direction keeps flowing until it too
    // EOFs or a deadline expires.
    let mut eof_a = false;
    let mut eof_b = false;
    loop {
        if eof_a && eof_b {
            return Ok(());
        }
        // Race whichever directions are still open against the earliest
        // deadline (branch futures are not evaluated when the precondition
        // is false, so `a`/`b` are only borrowed by live reads). The
        // futures (and their borrows) end when the `select!` does, before
        // the shutdown/write below.
        let outcome = tokio::select! {
            res = a.read(&mut buf_a), if !eof_a => Some((true, res?)),
            res = b.read(&mut buf_b), if !eof_b => Some((false, res?)),
            _ = tokio::time::sleep_until(budget.effective_deadline()) => None,
        };
        let (from_a, n) = match outcome {
            Some(x) => x,
            None => return Err(budget.tear_down()),
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
            // EOF is not traffic: no deadline moves.
            continue;
        }
        // A completed read is idle-liveness only. It does not count toward
        // the progress floor until those bytes are actually written — a
        // peer that accepts the read side and drains the write side slowly
        // must not be able to refresh the progress window (cap#266).
        budget.on_read_liveness();
        let data: Vec<u8> = if from_a {
            buf_a[..n].to_vec()
        } else {
            buf_b[..n].to_vec()
        };
        let dst = if from_a { &mut *b } else { &mut *a };
        let mut off = 0;
        while off < data.len() {
            // Recomputed each partial write. A sub-floor write refreshes
            // idle but not the progress window or the lifetime, so the
            // effective deadline stays put for a slow drain.
            let deadline = budget.effective_deadline();
            match tokio::time::timeout_at(deadline, dst.write(&data[off..])).await {
                Ok(Ok(0)) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "egress proxy peer closed mid-write",
                    ));
                }
                Ok(Ok(written)) => {
                    off += written;
                    budget.on_forwarded(written);
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(budget.tear_down()),
            }
        }
    }
}

/// Deadlines for one tunnel. Idle moves on any read or forwarded byte.
/// The progress window moves only when the byte floor is met. Lifetime
/// never moves.
struct TunnelBudget {
    started: tokio::time::Instant,
    idle_deadline: tokio::time::Instant,
    window_start: tokio::time::Instant,
    window_bytes: u64,
}

impl TunnelBudget {
    fn new() -> Self {
        let now = tokio::time::Instant::now();
        Self {
            started: now,
            idle_deadline: now + TUNNEL_IDLE_TIMEOUT,
            window_start: now,
            window_bytes: 0,
        }
    }

    fn effective_deadline(&self) -> tokio::time::Instant {
        self.idle_deadline
            .min(self.window_start + TUNNEL_PROGRESS_WINDOW)
            .min(self.started + TUNNEL_MAX_LIFETIME)
    }

    fn on_read_liveness(&mut self) {
        self.idle_deadline = tokio::time::Instant::now() + TUNNEL_IDLE_TIMEOUT;
    }

    /// `n` is bytes successfully written to the peer.
    fn on_forwarded(&mut self, n: usize) {
        if n == 0 {
            return;
        }
        let now = tokio::time::Instant::now();
        self.idle_deadline = now + TUNNEL_IDLE_TIMEOUT;
        self.window_bytes = self.window_bytes.saturating_add(n as u64);
        if self.window_bytes >= MIN_PROGRESS_BYTES {
            self.window_start = now;
            self.window_bytes = 0;
        }
    }

    fn tear_down(&self) -> std::io::Error {
        let now = tokio::time::Instant::now();
        let msg = if now >= self.started + TUNNEL_MAX_LIFETIME {
            "egress proxy tunnel lifetime exceeded"
        } else if now >= self.window_start + TUNNEL_PROGRESS_WINDOW {
            "egress proxy tunnel below minimum progress"
        } else {
            "egress proxy tunnel idle"
        };
        if msg != "egress proxy tunnel idle" {
            tracing::info!(reason = msg, "egress proxy tunnel torn down");
        }
        std::io::Error::new(std::io::ErrorKind::TimedOut, msg)
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

async fn write_unavailable(stream: &mut TcpStream) -> std::io::Result<()> {
    stream
        .write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
}

/// Process-local credential plus the per-principal counters. Shared by
/// every clone of an `EgressProxy` and by the listener it spawns.
struct Admission {
    secret_hex: String,
    tenants: Arc<TenantBudget>,
}

impl Admission {
    fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            secret_hex: hex::encode(bytes),
            tenants: Arc::new(TenantBudget::default()),
        }
    }
}

#[derive(Default)]
struct TenantBudget {
    counts: Mutex<HashMap<String, usize>>,
}

struct TenantPermit {
    key: String,
    budget: Arc<TenantBudget>,
}

impl TenantBudget {
    fn try_acquire(self: &Arc<Self>, key: &str) -> Option<TenantPermit> {
        let mut counts = self
            .counts
            .lock()
            .expect("egress tenant budget mutex poisoned");
        let n = counts.entry(key.to_string()).or_insert(0);
        if *n >= MAX_PER_TENANT_CONNECTIONS {
            return None;
        }
        *n += 1;
        drop(counts);
        Some(TenantPermit {
            key: key.to_string(),
            budget: Arc::clone(self),
        })
    }
}

impl Drop for TenantPermit {
    fn drop(&mut self) {
        let mut counts = self
            .budget
            .counts
            .lock()
            .expect("egress tenant budget mutex poisoned");
        if let Some(n) = counts.get_mut(&self.key) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

enum PrincipalDecision {
    Anonymous,
    Named(String),
    Invalid,
}

fn valid_principal(principal: &str) -> bool {
    let n = principal.len();
    (1..=128).contains(&n)
        && principal.bytes().all(|b| {
            matches!(
                b,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'
            )
        })
}

fn principal_label(key: &str) -> &str {
    if key == ANONYMOUS_PRINCIPAL {
        "anonymous"
    } else {
        key
    }
}

fn secrets_equal(presented: &[u8], expected: &[u8]) -> bool {
    let n = presented.len().min(expected.len());
    let prefix_eq = presented[..n].ct_eq(&expected[..n]);
    presented.len() == expected.len() && bool::from(prefix_eq)
}

/// `None` when the header is absent (anonymous). `Some(Err)` when it is
/// present but not a usable Basic credential.
fn proxy_basic_userinfo(head: &str) -> Option<Result<(String, String), ()>> {
    let value = head.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        let (name, rest) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("Proxy-Authorization") {
            Some(rest.trim())
        } else {
            None
        }
    })?;
    let encoded = match value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    {
        Some(encoded) => encoded,
        None => return Some(Err(())),
    };
    let bytes =
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded.trim()) {
            Ok(bytes) => bytes,
            Err(_) => return Some(Err(())),
        };
    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return Some(Err(())),
    };
    match text.split_once(':') {
        Some((user, pass)) => Some(Ok((user.to_string(), pass.to_string()))),
        None => Some(Err(())),
    }
}

fn head_for_upstream(head: &str) -> String {
    let mut out = String::with_capacity(head.len());
    for line in head.split_inclusive('\n') {
        let name = line.split(':').next().unwrap_or("");
        let name = name.trim();
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        out.push_str(line);
    }
    out
}

fn classify_principal(head: &str, secret_hex: &str) -> PrincipalDecision {
    match proxy_basic_userinfo(head) {
        None => PrincipalDecision::Anonymous,
        Some(Err(())) => PrincipalDecision::Invalid,
        Some(Ok((user, pass))) => {
            if !secrets_equal(pass.as_bytes(), secret_hex.as_bytes()) || !valid_principal(&user) {
                PrincipalDecision::Invalid
            } else {
                PrincipalDecision::Named(user)
            }
        }
    }
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

        // Keep the tunnel busy for well past the (test) idle timeout and
        // past one progress window: each round forwards at least
        // MIN_PROGRESS_BYTES, so the floor is met and the tunnel must NOT
        // be cut (cap#241: an active transfer survives; cap#266: only a
        // sub-floor drip is cut by the progress window). 4 rounds of
        // sleep(idle/2) total ~2x the idle window, still under
        // TUNNEL_MAX_LIFETIME.
        for i in 0..4 {
            tokio::time::sleep(TUNNEL_IDLE_TIMEOUT / 2).await;
            let mut payload = vec![b'a' + (i as u8); MIN_PROGRESS_BYTES as usize];
            payload[0] = i as u8;
            stream.write_all(&payload).await.unwrap();
            let mut echoed = vec![0u8; payload.len()];
            let mut off = 0;
            while off < echoed.len() {
                let n =
                    tokio::time::timeout(Duration::from_secs(5), stream.read(&mut echoed[off..]))
                        .await
                        .expect("active tunnel must not be torn down by the idle timeout")
                        .expect("echo read failed");
                assert!(n > 0, "active tunnel closed mid-echo on round {i}");
                off += n;
            }
            assert_eq!(echoed, payload, "round {i} must round-trip");
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

    async fn read_status_head(stream: &mut TcpStream) -> String {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut byte))
                .await
                .expect("proxy response must not hang")
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") || head.len() > 4096 {
                break;
            }
        }
        String::from_utf8_lossy(&head).into_owned()
    }

    async fn connect_request(proxy: &EgressProxy, request: &str) -> TcpStream {
        let mut stream = connect_raw(&proxy.url().unwrap()).await;
        stream.write_all(request.as_bytes()).await.unwrap();
        stream
    }

    fn spawn_discard_upstream() -> SocketAddr {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let listener = TcpListener::from_std(listener).unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 8192];
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
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn drip_tunnel_loses_permit_within_progress_window() {
        // Traffic arrives well inside the idle window, so the idle clock
        // keeps resetting. The bytes are below the progress floor, so the
        // tunnel (and its permit) must still die when the progress window
        // ends — not at the absolute lifetime.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream.accept().await {
                loop {
                    if sock.write_all(b"x").await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(400)).await;
                }
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut stream = connect_request(
            &proxy,
            &format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"),
        )
        .await;
        let head = read_status_head(&mut stream).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "drip setup must tunnel, got: {head}"
        );

        let start = std::time::Instant::now();
        let mut buf = [0u8; 16];
        // One deadline for the whole drip, not per read: a byte every 400ms
        // would otherwise refresh a per-read timeout forever and the test
        // would hang on the pre-fix idle-only clock instead of failing.
        let closed = tokio::time::timeout(TUNNEL_PROGRESS_WINDOW + Duration::from_secs(6), async {
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => continue,
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "drip tunnel still open after {:?}",
            start.elapsed()
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed + Duration::from_secs(1) >= TUNNEL_PROGRESS_WINDOW,
            "drip teardown at {elapsed:?} was too fast to be the progress window"
        );
        assert!(
            elapsed < TUNNEL_MAX_LIFETIME,
            "drip tunnel lived {elapsed:?}; expected the progress window, not the lifetime"
        );
    }

    #[tokio::test]
    async fn slow_draining_write_loses_permit_under_same_budget() {
        // Upstream accepts writes but drains far below the progress floor.
        // Partial writes reset the idle clock; they must not refresh the
        // progress window (cap#266).
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = upstream.accept().await {
                let mut one = [0u8; 1];
                // Drain one byte at a time, pausing between reads, so the
                // proxy's forward write makes partial progress well below
                // the byte floor. Exit when the proxy tears the socket down.
                loop {
                    match sock.read(&mut one).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut stream = connect_request(
            &proxy,
            &format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"),
        )
        .await;
        let head = read_status_head(&mut stream).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "slow-drain setup must tunnel, got: {head}"
        );

        let big = vec![b'x'; 4 * 1024 * 1024];
        let start = std::time::Instant::now();
        let write_result =
            tokio::time::timeout(TUNNEL_PROGRESS_WINDOW * 4, stream.write_all(&big)).await;
        let mut chunk = [0u8; 64];
        let n = tokio::time::timeout(TUNNEL_PROGRESS_WINDOW * 2, stream.read(&mut chunk))
            .await
            .expect("slow-draining tunnel must be torn down, not hang")
            .unwrap_or(0);
        assert!(
            n == 0 || write_result.unwrap_or(Ok(())).is_err(),
            "slow-draining write must lose the tunnel, got {n} bytes"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed + Duration::from_secs(1) >= TUNNEL_PROGRESS_WINDOW,
            "teardown at {elapsed:?} was too fast to be the progress budget"
        );
        assert!(
            elapsed < TUNNEL_MAX_LIFETIME,
            "slow drain lived {elapsed:?}; expected the progress budget, not the lifetime"
        );
    }

    #[tokio::test]
    async fn floor_meeting_tunnel_still_dies_at_absolute_lifetime() {
        // A transfer that keeps meeting the progress floor must survive
        // the idle window (covered by active_transfer_survives_beyond_idle_timeout)
        // and still lose its permit at TUNNEL_MAX_LIFETIME.
        let upstream_addr = spawn_discard_upstream();
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut stream = connect_request(
            &proxy,
            &format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n"),
        )
        .await;
        let head = read_status_head(&mut stream).await;
        assert!(
            head.starts_with("HTTP/1.1 200"),
            "lifetime setup must tunnel, got: {head}"
        );
        let payload = vec![b'z'; MIN_PROGRESS_BYTES as usize];
        let start = std::time::Instant::now();
        // Write continuously. A 2s pause between rounds plus a slow echo
        // can miss the 5s test progress window and die early, which is a
        // flake rather than a lifetime failure (review).
        let closed = tokio::time::timeout(TUNNEL_MAX_LIFETIME + Duration::from_secs(8), async {
            loop {
                if stream.write_all(&payload).await.is_err() {
                    return;
                }
                let mut echoed = vec![0u8; payload.len()];
                let mut off = 0;
                while off < echoed.len() {
                    match stream.read(&mut echoed[off..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => off += n,
                    }
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "floor-meeting tunnel must be cut at the absolute lifetime"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed + Duration::from_secs(4) >= TUNNEL_MAX_LIFETIME,
            "lifetime teardown at {elapsed:?} was too fast"
        );
    }

    #[tokio::test]
    async fn per_tenant_cap_refuses_saturated_tenant_and_admits_another() {
        let upstream_addr = spawn_discard_upstream();
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut holders = Vec::new();
        for _ in 0..MAX_PER_TENANT_CONNECTIONS {
            let auth = proxy.authorization_header("tenant-a");
            let mut stream = connect_request(
                &proxy,
                &format!(
                    "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n{auth}\r\n\r\n"
                ),
            )
            .await;
            let head = read_status_head(&mut stream).await;
            assert!(
                head.starts_with("HTTP/1.1 200"),
                "holder must be admitted, got: {head}"
            );
            holders.push(stream);
        }

        let auth = proxy.authorization_header("tenant-a");
        let mut refused = connect_request(
            &proxy,
            &format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n{auth}\r\n\r\n"),
        )
        .await;
        let refused_head = read_status_head(&mut refused).await;
        assert!(
            refused_head.starts_with("HTTP/1.1 503"),
            "tenant at its cap must be refused, got: {refused_head}"
        );

        let auth_b = proxy.authorization_header("tenant-b");
        let mut other = connect_request(
            &proxy,
            &format!(
                "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n{auth_b}\r\n\r\n"
            ),
        )
        .await;
        let other_head = read_status_head(&mut other).await;
        assert!(
            other_head.starts_with("HTTP/1.1 200"),
            "another tenant must still be admitted under the global budget, got: {other_head}"
        );
        other.write_all(b"ping").await.unwrap();
        let mut echoed = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(3), other.read(&mut echoed))
            .await
            .expect("other tenant's fetch must succeed")
            .unwrap();
        assert_eq!(&echoed[..n], b"ping");
        drop(holders);
    }

    #[tokio::test]
    async fn credentialed_proxy_url_is_charged_to_that_principal() {
        // The production path (oci-client / reqwest) learns the principal
        // from proxy-URL userinfo, not from a header we add by hand.
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = upstream.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        match sock.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });

        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut holders = Vec::new();
        for _ in 0..MAX_PER_TENANT_CONNECTIONS {
            let auth = proxy.authorization_header("tenant-b");
            let mut stream = connect_request(
                &proxy,
                &format!(
                    "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n{auth}\r\n\r\n"
                ),
            )
            .await;
            let head = read_status_head(&mut stream).await;
            assert!(head.starts_with("HTTP/1.1 200"), "holder: {head}");
            holders.push(stream);
        }

        let saturated = proxy.url_for_principal("tenant-b").unwrap();
        let saturated_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&saturated).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let denied = saturated_client
            .get(format!("http://{upstream_addr}/v2/"))
            .send()
            .await;
        // reqwest returns `Ok(503)` when the proxy answers; a reset is also
        // a refusal. Either way the saturated principal must not get a 200.
        match denied {
            Err(_) => {}
            Ok(resp) => assert_eq!(
                resp.status(),
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "credentialed URL for a saturated principal must be refused"
            ),
        }

        let other = proxy.url_for_principal("tenant-c").unwrap();
        let other_client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&other).unwrap())
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ok = other_client
            .get(format!("http://{upstream_addr}/v2/"))
            .send()
            .await
            .expect("another principal must still fetch through the global budget");
        assert_eq!(ok.status(), reqwest::StatusCode::OK);
        drop(holders);
    }

    #[tokio::test]
    async fn invalid_proxy_authorization_is_refused_without_taking_a_slot() {
        let upstream_addr = spawn_discard_upstream();
        let proxy = EgressProxy::with_http_forwarding(Arc::new(BlockedNetworks::empty()), true);
        let mut bad = connect_request(
            &proxy,
            &format!(
                "CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: Basic bm90LXZhbGlk\r\n\r\n"
            ),
        )
        .await;
        let head = read_status_head(&mut bad).await;
        assert!(
            head.starts_with("HTTP/1.1 403"),
            "bad credentials must be refused, got: {head}"
        );

        let auth = proxy.authorization_header("tenant-a");
        let mut ok = connect_request(
            &proxy,
            &format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n{auth}\r\n\r\n"),
        )
        .await;
        let ok_head = read_status_head(&mut ok).await;
        assert!(
            ok_head.starts_with("HTTP/1.1 200"),
            "a valid principal must still be admitted after a bad credential, got: {ok_head}"
        );
    }

    #[test]
    fn org_principal_is_url_safe_and_distinct() {
        let a = org_egress_principal(&"11111111-1111-1111-1111-111111111111");
        let b = org_egress_principal(&"22222222-2222-2222-2222-222222222222");
        assert_ne!(a, b);
        assert!(valid_principal(&a), "{a}");
        assert!(valid_principal(PLATFORM_EGRESS_PRINCIPAL));
        assert!(!a.contains(':'));
    }
}
