//! The forward proxy.
//!
//! The workload connects with `CONNECT host:port`. Three outcomes:
//!
//! - the origin has a connection: the tunnel is terminated here with a leaf
//!   from the vault CA, each request goes through [`substitute::rewrite`],
//!   and is forwarded over a new TLS connection that is verified against
//!   the configured roots;
//! - the origin is on the pass-through list: bytes are relayed untouched;
//! - anything else is refused.
//!
//! Every outbound dial resolves the name here and refuses the destination
//! if any answer is in a blocked network, so there is no second lookup to
//! race. Only CONNECT is served: credentials never travel over cleartext
//! proxying.

use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use enclava_common::outbound_http::BlockedNetworks;
use http::header::{CONNECTION, HeaderMap, HeaderName, HeaderValue, TE, UPGRADE};
use http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection as HyperConnection};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::ServerName;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::ca::VaultCa;
use crate::connection::{Origin, Snapshot};
use crate::store::{Store, StoreError};
use crate::substitute;

type BoxError = Box<dyn StdError + Send + Sync>;
type Body = BoxBody<Bytes, BoxError>;

const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Headers that describe one hop and must not be forwarded.
const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "proxy-connection",
    "keep-alive",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authorization",
    "proxy-authenticate",
];

pub struct ProxyConfig {
    /// Origins relayed without interception.
    pub passthrough: Vec<Origin>,
    /// Networks no outbound connection may reach.
    pub blocked: BlockedNetworks,
    /// Roots that upstream certificates are verified against.
    pub upstream_roots: RootCertStore,
    /// Connections served at once; further ones are dropped at accept.
    pub max_connections: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            passthrough: Vec::new(),
            blocked: BlockedNetworks::defaults(),
            upstream_roots: RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ),
            max_connections: 256,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("TLS configuration failed: {0}")]
    Tls(#[from] rustls::Error),
}

pub struct Proxy {
    inner: Arc<Inner>,
}

struct Inner {
    ca: VaultCa,
    store: Store,
    /// Store generation the cached snapshot was loaded at.
    cached: RwLock<(String, Arc<Snapshot>)>,
    passthrough: Vec<Origin>,
    blocked: Arc<BlockedNetworks>,
    client: Client<UpstreamConnector, Incoming>,
    permits: Arc<Semaphore>,
}

impl Proxy {
    pub fn new(store: Store, ca: VaultCa, config: ProxyConfig) -> Result<Self, ProxyError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut tls = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(config.upstream_roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let blocked = Arc::new(config.blocked);
        let connector = UpstreamConnector {
            tls: TlsConnector::from(Arc::new(tls)),
            blocked: blocked.clone(),
        };
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            .pool_timer(TokioTimer::new())
            .build(connector);

        let generation = store.generation().map_err(StoreError::from)?;
        let snapshot = Arc::new(store.snapshot()?);
        Ok(Self {
            inner: Arc::new(Inner {
                ca,
                store,
                cached: RwLock::new((generation, snapshot)),
                passthrough: config.passthrough,
                blocked,
                client,
                permits: Arc::new(Semaphore::new(config.max_connections)),
            }),
        })
    }

    /// Serves until the listener fails.
    pub async fn serve(self, listener: TcpListener) -> io::Result<()> {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permit) = self.inner.permits.clone().try_acquire_owned() else {
                tracing::warn!("connection limit reached; dropping connection");
                continue;
            };
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let permit = Arc::new(permit);
                let service = service_fn(move |request| {
                    let inner = inner.clone();
                    let permit = permit.clone();
                    async move { Ok::<_, Infallible>(inner.handle_connect(request, permit).await) }
                });
                let served = hyper::server::conn::http1::Builder::new()
                    .timer(TokioTimer::new())
                    .header_read_timeout(HEAD_TIMEOUT)
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
                if let Err(e) = served {
                    tracing::debug!(error = %e, "proxy connection ended with an error");
                }
            });
        }
    }
}

impl Inner {
    /// The current connections, reloaded when the store has changed.
    fn snapshot(&self) -> Result<Arc<Snapshot>, StoreError> {
        let generation = self.store.generation()?;
        {
            let cached = self.cached.read().unwrap_or_else(|e| e.into_inner());
            if cached.0 == generation {
                return Ok(cached.1.clone());
            }
        }
        let snapshot = Arc::new(self.store.snapshot()?);
        let mut cached = self.cached.write().unwrap_or_else(|e| e.into_inner());
        *cached = (generation, snapshot.clone());
        Ok(snapshot)
    }

    async fn handle_connect(
        self: Arc<Self>,
        request: Request<Incoming>,
        permit: Arc<OwnedSemaphorePermit>,
    ) -> Response<Body> {
        if request.method() != Method::CONNECT {
            return refusal(StatusCode::METHOD_NOT_ALLOWED, "connect_only");
        }
        let Some(origin) = connect_origin(request.uri()) else {
            return refusal(StatusCode::BAD_REQUEST, "bad_connect_target");
        };
        let snapshot = match self.snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                tracing::error!(error = %e, "connection store is unreadable");
                return refusal(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable");
            }
        };

        if snapshot.has_origin(&origin) {
            let config = match self.ca.server_config(origin.host()) {
                Ok(config) => config,
                Err(e) => {
                    tracing::error!(error = %e, origin = %origin, "leaf certificate failed");
                    return refusal(StatusCode::INTERNAL_SERVER_ERROR, "certificate_unavailable");
                }
            };
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(e) = self.intercept(request, origin.clone(), config).await {
                    tracing::debug!(error = %e, origin = %origin, "intercepted tunnel ended");
                }
            });
            return Response::new(empty());
        }

        if self.passthrough.contains(&origin) {
            let mut upstream =
                match guarded_connect(origin.host(), origin.port(), &self.blocked).await {
                    Ok(upstream) => upstream,
                    Err(e) => return dial_refusal(&origin, &e),
                };
            tokio::spawn(async move {
                let _permit = permit;
                if let Ok(upgraded) = hyper::upgrade::on(request).await {
                    let mut client = TokioIo::new(upgraded);
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
            return Response::new(empty());
        }

        tracing::warn!(origin = %origin, "refused CONNECT to an origin that is not connected");
        refusal(StatusCode::FORBIDDEN, "origin_not_connected")
    }

    async fn intercept(
        self: Arc<Self>,
        request: Request<Incoming>,
        origin: Origin,
        config: Arc<rustls::ServerConfig>,
    ) -> Result<(), BoxError> {
        let upgraded = hyper::upgrade::on(request).await?;
        let tls = TlsAcceptor::from(config)
            .accept(TokioIo::new(upgraded))
            .await?;
        let service = service_fn(move |request| {
            let inner = self.clone();
            let origin = origin.clone();
            async move { Ok::<_, Infallible>(inner.forward(&origin, request).await) }
        });
        let mut server = auto::Builder::new(TokioExecutor::new());
        server
            .http1()
            .timer(TokioTimer::new())
            .header_read_timeout(HEAD_TIMEOUT);
        server.http2().timer(TokioTimer::new());
        server.serve_connection(TokioIo::new(tls), service).await
    }

    async fn forward(&self, origin: &Origin, request: Request<Incoming>) -> Response<Body> {
        // An upgraded stream would carry bytes this proxy cannot check.
        if request.method() == Method::CONNECT || request.headers().contains_key(UPGRADE) {
            return refusal(StatusCode::NOT_IMPLEMENTED, "upgrade_unsupported");
        }
        let snapshot = match self.snapshot() {
            Ok(snapshot) => snapshot,
            Err(e) => {
                tracing::error!(error = %e, "connection store is unreadable");
                return refusal(StatusCode::SERVICE_UNAVAILABLE, "store_unavailable");
            }
        };

        let (mut parts, body) = request.into_parts();
        let outcome = match substitute::rewrite(&mut parts, origin, &snapshot) {
            Ok(outcome) => outcome,
            Err(e) => {
                tracing::warn!(
                    origin = %origin,
                    connection = e.connection().unwrap_or("-"),
                    reason = e.code(),
                    "refused request"
                );
                return refusal(StatusCode::FORBIDDEN, e.code());
            }
        };

        // The destination is always the tunnel's origin, whatever the
        // request claimed; `rewrite` has already refused a mismatch.
        let path_and_query = parts.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let uri = Uri::builder()
            .scheme("https")
            .authority(origin.authority())
            .path_and_query(path_and_query)
            .build();
        let Ok(uri) = uri else {
            return refusal(StatusCode::BAD_REQUEST, "malformed_request");
        };
        strip_hop_by_hop(&mut parts.headers);
        parts.headers.remove(http::header::HOST);
        parts.uri = uri;
        parts.version = http::Version::HTTP_11;
        let method = parts.method.clone();

        match self.client.request(Request::from_parts(parts, body)).await {
            Ok(response) => {
                tracing::info!(
                    origin = %origin,
                    method = %method,
                    status = response.status().as_u16(),
                    substituted = ?outcome.substituted,
                    "forwarded request"
                );
                let (mut parts, body) = response.into_parts();
                strip_hop_by_hop(&mut parts.headers);
                Response::from_parts(parts, body.map_err(BoxError::from).boxed())
            }
            Err(e) => match find_io_error(&e) {
                Some(io) => dial_refusal(origin, io),
                None => {
                    tracing::warn!(origin = %origin, error = %e, "upstream request failed");
                    refusal(StatusCode::BAD_GATEWAY, "upstream_unreachable")
                }
            },
        }
    }
}

/// Parses the authority-form target of a CONNECT request.
fn connect_origin(uri: &Uri) -> Option<Origin> {
    let authority = uri.authority()?;
    Origin::from_host_port(authority.host(), authority.port_u16().unwrap_or(443)).ok()
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let listed: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect();
    for name in listed {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    // `TE: trailers` is the one TE value that is meaningful end to end.
    if headers.get(TE).is_some_and(|value| value != "trailers") {
        headers.remove(TE);
    }
}

fn empty() -> Body {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn refusal(status: StatusCode, reason: &'static str) -> Response<Body> {
    let body = format!("{{\"error\":\"enclava_vault_refused\",\"reason\":\"{reason}\"}}\n");
    let mut response = Response::new(
        Full::new(Bytes::from(body))
            .map_err(|never| match never {})
            .boxed(),
    );
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert("x-enclava-vault", HeaderValue::from_static(reason));
    response
}

fn dial_refusal(origin: &Origin, error: &io::Error) -> Response<Body> {
    if error.kind() == io::ErrorKind::PermissionDenied {
        tracing::warn!(origin = %origin, "refused a destination in a blocked network");
        refusal(StatusCode::FORBIDDEN, "destination_blocked")
    } else {
        tracing::warn!(origin = %origin, error = %error, "upstream dial failed");
        refusal(StatusCode::BAD_GATEWAY, "upstream_unreachable")
    }
}

fn find_io_error<'a>(error: &'a (dyn StdError + 'static)) -> Option<&'a io::Error> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(io) = error.downcast_ref::<io::Error>() {
            return Some(io);
        }
        current = error.source();
    }
    None
}

/// Resolves `host` and connects to it, refusing the destination outright if
/// any resolved address is in a blocked network.
async fn guarded_connect(
    host: &str,
    port: u16,
    blocked: &BlockedNetworks,
) -> io::Result<TcpStream> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    if addresses.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "no addresses"));
    }
    if addresses
        .iter()
        .any(|address| blocked.contains(address.ip()))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "destination resolves to a blocked network",
        ));
    }
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no addresses");
    for address in addresses {
        match tokio::time::timeout(DIAL_TIMEOUT, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last = e,
            Err(_) => last = io::Error::new(io::ErrorKind::TimedOut, "connect timed out"),
        }
    }
    Err(last)
}

/// Connector for the upstream client: guarded dial, then verified TLS.
#[derive(Clone)]
struct UpstreamConnector {
    tls: TlsConnector,
    blocked: Arc<BlockedNetworks>,
}

impl tower_service::Service<Uri> for UpstreamConnector {
    type Response = UpstreamIo;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<UpstreamIo>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let tls = self.tls.clone();
        let blocked = self.blocked.clone();
        Box::pin(async move {
            let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
            if uri.scheme_str() != Some("https") {
                return Err(invalid("upstream must be https"));
            }
            let host = uri
                .host()
                .ok_or_else(|| invalid("upstream has no host"))?
                .to_owned();
            let port = uri.port_u16().unwrap_or(443);
            let tcp = guarded_connect(&host, port, &blocked).await?;
            let name = ServerName::try_from(host)
                .map_err(|_| invalid("upstream host is not a DNS name"))?;
            let stream = tls.connect(name, tcp).await?;
            Ok(UpstreamIo(TokioIo::new(stream)))
        })
    }
}

struct UpstreamIo(TokioIo<tokio_rustls::client::TlsStream<TcpStream>>);

impl HyperConnection for UpstreamIo {
    fn connected(&self) -> Connected {
        let (_, session) = self.0.inner().get_ref();
        if session.alpn_protocol() == Some(b"h2") {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
    }
}

impl hyper::rt::Read for UpstreamIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl hyper::rt::Write for UpstreamIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_removed_and_te_trailers_kept() {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("connection", "keep-alive, x-per-hop"),
            ("x-per-hop", "1"),
            ("keep-alive", "timeout=5"),
            ("proxy-authorization", "Basic abc"),
            ("transfer-encoding", "chunked"),
            ("te", "trailers"),
            ("accept", "*/*"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        strip_hop_by_hop(&mut headers);
        let mut left: Vec<_> = headers.keys().map(|name| name.as_str()).collect();
        left.sort_unstable();
        assert_eq!(left, ["accept", "te"]);

        headers.insert("te", HeaderValue::from_static("gzip"));
        strip_hop_by_hop(&mut headers);
        assert!(!headers.contains_key("te"));
    }

    #[test]
    fn connect_target_must_be_a_dns_name() {
        let origin = |target: &str| connect_origin(&target.parse::<Uri>().unwrap());
        assert_eq!(
            origin("api.example.com:443").unwrap().authority(),
            "api.example.com"
        );
        assert_eq!(
            origin("API.example.com:8443").unwrap().authority(),
            "api.example.com:8443"
        );
        assert!(origin("127.0.0.1:443").is_none());
        assert!(origin("[::1]:443").is_none());
    }

    #[tokio::test]
    async fn guarded_connect_refuses_blocked_networks_before_dialing() {
        let error = guarded_connect("localhost", 9, &BlockedNetworks::defaults())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
}
