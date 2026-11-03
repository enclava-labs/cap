//! Fetch the certificate tenant-ingress actually serves.
//!
//! Readiness must reflect what caddy puts on the wire, not what a file
//! says: after a renewal there is a window where the runtime `tls.crt` is
//! already new while caddy still serves the old certificate. A short TLS
//! handshake against the tenant-ingress listener records exactly the
//! end-entity certificate caddy presents — the verifier accepts anything
//! (this is an observation, not authentication; trust is established
//! separately by the brokered-issuance checks in `tls_certificate.rs`) so
//! an expired or untrusted-but-served chain is reported faithfully.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme};

/// Server-certificate verifier that accepts any chain and records the
/// end-entity certificate the peer presents. Signature verifications are
/// asserted valid unconditionally: the handshake is aborted as soon as
/// the leaf is captured, so nothing here authenticates a peer for I/O.
#[derive(Debug)]
struct CaptureVerifier {
    leaf: Mutex<Option<CertificateDer<'static>>>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        *self.leaf.lock().unwrap() = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

/// TLS handshake against `127.0.0.1:port` with SNI `host`, returning the
/// end-entity certificate the server presented. `timeout` bounds the TCP
/// connect and every handshake read so a wedged listener cannot stall the
/// readiness tick. Any failure — refused connection, timeout, or a
/// handshake the server never completes — is an error; the leaf is only
/// returned once the handshake actually completes.
pub fn fetch_served_certificate(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<CertificateDer<'static>> {
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid TLS server name {host:?}"))?;
    let verifier = Arc::new(CaptureVerifier {
        leaf: Mutex::new(None),
    });
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .context("building TLS client protocol configuration")?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
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
    // The handshake is done: the recorded leaf is what caddy serves right
    // now. No application data is ever sent.
    verifier
        .leaf
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| anyhow!("TLS handshake completed without a server certificate"))
}
