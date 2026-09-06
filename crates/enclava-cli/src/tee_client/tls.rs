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
    host: &str,
    port: u16,
    resolve_ip: Option<IpAddr>,
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
    if let Some(resolve_ip) = resolve_ip {
        builder = builder.resolve(host, SocketAddr::new(resolve_ip, port));
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
    resolve_ip: Option<IpAddr>,
    timeout: std::time::Duration,
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
    let connect = async {
        match resolve_ip {
            Some(ip) => TcpStream::connect(SocketAddr::new(ip, port)).await,
            None => TcpStream::connect((host, port)).await,
        }
    };
    let stream = tokio::time::timeout(timeout.min(std::time::Duration::from_secs(10)), connect)
        .await
        .map_err(|_| TeeError::Attestation("TEE TCP connect timed out".to_string()))?
        .map_err(|err| TeeError::Attestation(format!("TEE TCP connect failed: {err}")))?;
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|_| TeeError::Attestation("TEE host is not a valid DNS name".to_string()))?;
    let tls_stream = tokio::time::timeout(
        timeout.min(std::time::Duration::from_secs(10)),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| TeeError::Attestation("TEE TLS handshake timed out".to_string()))?
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tls_leaf_fetch_preserves_successful_handshake_spki() {
        // Public synthetic localhost fixture, used only for this TLS transport test.
        let certificate = B64_STANDARD.decode("MIIBfzCCASWgAwIBAgIUDvNchz/4kjYNIUZPbhErYcJcQEkwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkwNjE1NTgyM1oYDzIxMjYwODEzMTU1ODIzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASTrTE27CrHezsrQig5SJS3khO5zrEB7SYnpJj05SOwGHPQCBpYHg38VRS9fdnyKI2JdkuAePfnhVJULAcTmrkuo1MwUTAdBgNVHQ4EFgQUW41obMczsiH/amwMRntTfO2u2g0wHwYDVR0jBBgwFoAUW41obMczsiH/amwMRntTfO2u2g0wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiBFGRlU//+3JyhVqXNcpWw7QR9N6pEoiRVpgFc0Dxk+uwIhAIO8kzgeVzlTSTS7/2jE2EuVXtAxL3Mcbd62YjrqNtaG").unwrap();
        let key = B64_STANDARD.decode("MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1eONjcC4FaH2HqTDcwYCUym2nm332NQ/GN4WxJafrU+hRANCAASTrTE27CrHezsrQig5SJS3khO5zrEB7SYnpJj05SOwGHPQCBpYHg38VRS9fdnyKI2JdkuAePfnhVJULAcTmrku").unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_protocol_versions(rustls::DEFAULT_VERSIONS)
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(certificate.clone())],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
        });
        let spki = fetch_tls_leaf_spki_der(
            "localhost",
            address.port(),
            Some(address.ip()),
            std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        assert_eq!(spki, leaf_spki_der(&certificate).unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_leaf_fetch_times_out_when_peer_stalls_handshake() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            fetch_tls_leaf_spki_der(
                "localhost",
                address.port(),
                Some(address.ip()),
                std::time::Duration::from_millis(50),
            ),
        )
        .await;
        server.abort();
        let error = result
            .expect("TLS handshake must honor the configured timeout")
            .unwrap_err();
        assert!(
            matches!(error, TeeError::Attestation(message) if message == "TEE TLS handshake timed out")
        );
    }

    #[test]
    fn parse_accepts_https_with_explicit_port() {
        let p = EndpointParts::parse("https://Example.COM:8443/path").unwrap();
        assert_eq!(p.host, "example.com");
        assert_eq!(p.port, 8443);
    }

    #[test]
    fn parse_accepts_https_default_port() {
        let p = EndpointParts::parse("https://tee.example.dev").unwrap();
        assert_eq!(p.host, "tee.example.dev");
        assert_eq!(p.port, 443);
    }

    #[test]
    fn parse_rejects_non_https_scheme() {
        match EndpointParts::parse("http://tee.example.dev:8443") {
            Err(e) => assert!(e.to_string().contains("https")),
            Ok(_) => panic!("expected non-https scheme to be rejected"),
        }
    }

    #[test]
    fn parse_rejects_empty_host() {
        assert!(EndpointParts::parse("https://:8443/").is_err());
    }

    #[test]
    fn parse_rejects_invalid_url() {
        assert!(EndpointParts::parse("not a url at all").is_err());
    }
}
