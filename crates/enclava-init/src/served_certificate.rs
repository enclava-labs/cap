//! Probe the certificate tenant-ingress actually serves.
//!
//! Readiness must reflect what caddy puts on the wire, not what a file
//! says: after a renewal there is a window where the runtime `tls.crt` is
//! already new while caddy still serves the old certificate, and a
//! listener that accepts TCP but fails TLS is still not serving. A full
//! rustls client handshake against the tenant-ingress listener — chain
//! anchored to the same public root store the broker-response validation
//! uses, hostname, and validity windows — succeeds only when a client
//! could actually be served. Every failure is reported: refused
//! connection, timeout, TLS alert, untrusted, expired, or wrong name.

use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

/// TLS handshake against `127.0.0.1:port` with SNI `host`, validating the
/// presented chain against `roots` (chain signatures, validity windows,
/// and the server name — a real client would accept what this accepts).
/// `timeout` bounds the TCP connect and every handshake read/write so a
/// wedged listener cannot stall the readiness tick. `Ok(())` only when
/// the handshake completes; no application data is ever sent.
pub fn served_https_usable(
    host: &str,
    port: u16,
    roots: Arc<RootCertStore>,
    timeout: Duration,
) -> Result<()> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow::anyhow!("invalid TLS server name {host:?}"))?;
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .context("building TLS client protocol configuration")?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("initializing TLS client connection")?;
    let mut stream =
        TcpStream::connect_timeout(&std::net::SocketAddr::from(([127, 0, 0, 1], port)), timeout)
            .with_context(|| format!("connecting to 127.0.0.1:{port}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .context("setting TLS read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("setting TLS write timeout")?;
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)
            .context("completing TLS handshake")?;
    }
    Ok(())
}
