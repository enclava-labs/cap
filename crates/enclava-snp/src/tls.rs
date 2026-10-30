//! TLS legs of the attestation handshake: learn the per-boot leaf, then pin it.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::AttestError;

/// Client config that completes a handshake only when the leaf's SPKI hashes
/// to `expected_spki_sha256`.
pub(crate) fn spki_pinned_config(
    expected_spki_sha256: [u8; 32],
) -> Result<ClientConfig, AttestError> {
    client_config(Some(expected_spki_sha256))
}

/// `pin: None` is the leaf-learning handshake only. Its result is never
/// trusted on its own: the leaf SPKI it yields becomes authoritative only
/// once nonce-bound SNP evidence binds it.
fn client_config(pin: Option<[u8; 32]>) -> Result<ClientConfig, AttestError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    Ok(ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|_| AttestError::Attestation("TLS versions invalid"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(LeafVerifier { pin, algorithms }))
        .with_no_client_auth())
}

#[derive(Debug)]
struct LeafVerifier {
    pin: Option<[u8; 32]>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for LeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(expected) = self.pin else {
            return Ok(ServerCertVerified::assertion());
        };
        let actual = enclava_verifier::tls_leaf_spki_sha256(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if actual == expected {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

/// Complete one TLS handshake with the TEE and return its leaf certificate DER.
pub(crate) async fn fetch_leaf_cert_der(
    host: &str,
    port: u16,
    resolve: Option<SocketAddr>,
    timeout: Duration,
) -> Result<Vec<u8>, AttestError> {
    let connector = TlsConnector::from(Arc::new(client_config(None)?));
    let step_timeout = timeout.min(Duration::from_secs(10));
    let connect = async {
        match resolve {
            Some(socket) => TcpStream::connect(socket).await,
            None => TcpStream::connect((host, port)).await,
        }
    };
    let stream = tokio::time::timeout(step_timeout, connect)
        .await
        .map_err(|_| AttestError::Timeout)?
        // Refusal, reset and DNS failure all mean the address did not serve,
        // not that the endpoint is bad.
        .map_err(|_| AttestError::TcpConnect)?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| AttestError::Attestation("TEE host is not a valid DNS name"))?;
    let tls_stream = tokio::time::timeout(step_timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| AttestError::Timeout)?
        .map_err(|_| AttestError::Attestation("TEE TLS handshake failed"))?;
    let leaf = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .ok_or(AttestError::Attestation(
            "TEE did not present a certificate",
        ))?;
    Ok(leaf.as_ref().to_vec())
}
