use super::*;

pub(super) struct EndpointParts {
    pub(super) host: String,
    pub(super) port: u16,
}

impl EndpointParts {
    pub(super) fn parse(base: &str) -> Result<Self, TeeError> {
        let url = reqwest::Url::parse(base)
            .map_err(|err| TeeError::Attestation(format!("invalid TEE URL: {err}")))?;
        if url.scheme() != "https" {
            return Err(TeeError::Attestation("TEE URL must be https".to_string()));
        }
        let host = url
            .host_str()
            .ok_or_else(|| TeeError::Attestation("TEE URL host missing".to_string()))?
            .to_ascii_lowercase();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TeeError::Attestation("TEE URL port missing".to_string()))?;
        Ok(Self { host, port })
    }
}

#[derive(Debug)]
struct SpkiPinnedVerifier {
    expected_spki_sha256: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for SpkiPinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = leaf_spki_der(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let actual: [u8; 32] = Sha256::digest(spki).into();
        if actual == self.expected_spki_sha256 {
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

pub(super) fn build_spki_pinned_client(
    expected_spki_sha256: [u8; 32],
    timeout: std::time::Duration,
    resolve_override: Option<(&str, &[SocketAddr])>,
) -> Result<reqwest::Client, TeeError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|err| TeeError::Attestation(format!("TLS versions invalid: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SpkiPinnedVerifier {
            expected_spki_sha256,
            algorithms,
        }))
        .with_no_client_auth();
    let mut builder = reqwest::Client::builder()
        .user_agent(format!("enclava-cli/{}", env!("CARGO_PKG_VERSION")))
        .timeout(timeout)
        .https_only(true)
        .use_preconfigured_tls(tls);
    if let Some((domain, addrs)) = resolve_override {
        builder = builder.resolve_to_addrs(domain, addrs);
    }
    builder.build().map_err(TeeError::Http)
}

#[derive(Debug)]
struct NoVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
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

pub(super) async fn fetch_tls_leaf_spki_der(
    host: &str,
    port: u16,
    connect_override: Option<&TeeConnectOverride>,
) -> Result<Vec<u8>, TeeError> {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let algorithms = provider.signature_verification_algorithms;
    let tls = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .map_err(|err| TeeError::Attestation(format!("TLS versions invalid: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier { algorithms }))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let (connect_host, connect_port) = connect_override
        .map(|connect| (connect.host.as_str(), connect.port))
        .unwrap_or((host, port));
    let stream = TcpStream::connect((connect_host, connect_port))
        .await
        .map_err(|err| TeeError::Attestation(format!("TEE TCP connect failed: {err}")))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| TeeError::Attestation("TEE host is not a valid DNS name".to_string()))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|err| TeeError::Attestation(format!("TEE TLS handshake failed: {err}")))?;
    let certs =
        tls_stream.get_ref().1.peer_certificates().ok_or_else(|| {
            TeeError::Attestation("TEE did not present a certificate".to_string())
        })?;
    let leaf = certs
        .first()
        .ok_or_else(|| TeeError::Attestation("TEE certificate chain is empty".to_string()))?;
    leaf_spki_der(leaf.as_ref())
}

pub(super) fn leaf_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, TeeError> {
    let cert = x509_cert::Certificate::from_der(cert_der)
        .map_err(|err| TeeError::Attestation(format!("certificate parse failed: {err}")))?;
    cert.tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|err| TeeError::Attestation(format!("certificate SPKI encode failed: {err}")))
}
