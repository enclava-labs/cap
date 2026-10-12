use super::*;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::atomic::{AtomicUsize, Ordering};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
};
use openssl::x509::{X509, X509NameBuilder};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

struct TestServer {
    addr: SocketAddr,
    root: Option<reqwest::Certificate>,
    requests: Arc<Mutex<Vec<String>>>,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl TestServer {
    async fn start(tls: bool, handler: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (acceptor, root) = if tls {
            let (acceptor, root) = tls_config();
            (Some(acceptor), Some(root))
        } else {
            (None, None)
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let connections = Arc::new(AtomicUsize::new(0));
        let connected = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                connected.fetch_add(1, Ordering::SeqCst);
                if let Some(acceptor) = &acceptor {
                    let stream = acceptor.accept(stream).await.unwrap();
                    serve_request(stream, &captured, &handler).await;
                } else {
                    serve_request(stream, &captured, &handler).await;
                }
            }
        });
        Self {
            addr,
            root,
            requests,
            connections,
            task,
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().clone()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_request(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    requests: &Mutex<Vec<String>>,
    handler: &impl Fn(&str) -> String,
) {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        bytes.push(byte);
        assert!(bytes.len() <= 16 * 1024);
    }
    let request = String::from_utf8(bytes).unwrap();
    requests.lock().push(request.clone());
    stream
        .write_all(handler(&request).as_bytes())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
}

fn response(status: &str, headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn tls_config() -> (TlsAcceptor, reqwest::Certificate) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let ca_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let leaf_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "Registry regression CA")
        .unwrap();
    let name = name.build();
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();

    let mut ca = X509::builder().unwrap();
    ca.set_version(2).unwrap();
    ca.set_serial_number(&BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    ca.set_subject_name(&name).unwrap();
    ca.set_issuer_name(&name).unwrap();
    ca.set_pubkey(&ca_key).unwrap();
    ca.set_not_before(&not_before).unwrap();
    ca.set_not_after(&not_after).unwrap();
    ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
        .unwrap();
    ca.append_extension(KeyUsage::new().critical().key_cert_sign().build().unwrap())
        .unwrap();
    ca.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca = ca.build();

    let mut leaf = X509::builder().unwrap();
    leaf.set_version(2).unwrap();
    leaf.set_serial_number(&BigNum::from_u32(2).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    leaf.set_subject_name(&name).unwrap();
    leaf.set_issuer_name(ca.subject_name()).unwrap();
    leaf.set_pubkey(&leaf_key).unwrap();
    leaf.set_not_before(&not_before).unwrap();
    leaf.set_not_after(&not_after).unwrap();
    leaf.append_extension(BasicConstraints::new().critical().build().unwrap())
        .unwrap();
    leaf.append_extension(
        KeyUsage::new()
            .critical()
            .digital_signature()
            .build()
            .unwrap(),
    )
    .unwrap();
    leaf.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
        .unwrap();
    let san = SubjectAlternativeName::new()
        .dns("registry.example")
        .dns("other.example")
        .ip("127.0.0.1")
        .build(&leaf.x509v3_context(Some(&ca), None))
        .unwrap();
    leaf.append_extension(san).unwrap();
    leaf.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let leaf = leaf.build();

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(rustls::DEFAULT_VERSIONS)
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(
            leaf.to_der().unwrap(),
        )],
        rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.private_key_to_pkcs8().unwrap())
            .into(),
    )
    .unwrap();
    (
        TlsAcceptor::from(Arc::new(config)),
        reqwest::Certificate::from_pem(&ca.to_pem().unwrap()).unwrap(),
    )
}

fn test_client(blocked: Arc<BlockedNetworks>, servers: &[&TestServer]) -> reqwest::Client {
    let roots = servers.iter().filter_map(|server| server.root.clone());
    let mut builder = registry_client_builder(blocked).tls_certs_only(roots);
    // Only the fixture's public hostname is mapped locally; production DNS
    // rejection is exercised separately without a reqwest resolution override.
    for (host, server) in ["registry.example", "other.example"]
        .into_iter()
        .zip(servers)
    {
        builder = builder.resolve(host, server.addr);
    }
    builder.build().unwrap()
}

#[test]
fn destination_guard_blocks_literal_ips_including_url_normalization() {
    let mut blocked = BlockedNetworks::defaults();
    blocked.extend_from_cidrs(["203.0.113.0/24", "2001:db8:1234::/48"]);
    for host in [
        "127.0.0.1",
        "127.1",
        "2130706433",
        "0x7f000001",
        "10.2.3.4",
        "172.16.0.1",
        "192.168.1.2",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "[::1]",
        "[::]",
        "[fe80::1]",
        "[fd00::1]",
        "[::ffff:127.0.0.1]",
        "[::ffff:169.254.169.254]",
        "203.0.113.7",
        "[2001:db8:1234::1]",
    ] {
        let url = reqwest::Url::parse(&format!("https://{host}:8443/token")).unwrap();
        assert!(validate_destination(&url, &blocked).is_err(), "{url}");
    }
    for host in ["1.1.1.1", "[2606:4700:4700::1111]", "registry.example"] {
        let url = reqwest::Url::parse(&format!("https://{host}:8443/token")).unwrap();
        assert_eq!(validate_destination(&url, &blocked), Ok(()));
    }
    let url = reqwest::Url::parse("http://registry.example/token").unwrap();
    assert!(validate_destination(&url, &blocked).is_err());
}

#[tokio::test]
async fn production_resolver_blocks_loopback_literals_and_dns_before_connecting() {
    let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    for host in ["127.0.0.1", "localhost."] {
        let image = ImageRef::parse(&format!("{host}:{port}/victim/repo:latest")).unwrap();
        assert!(resolve_image_digest(&image).await.is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    let pinned = ImageRef::parse(&format!(
        "127.0.0.1:{port}/victim/repo@sha256:{}",
        "a".repeat(64)
    ))
    .unwrap();
    assert_eq!(
        resolve_image_digest(&pinned).await.unwrap(),
        pinned.digest()
    );
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn manifest_redirects_never_contact_another_destination() {
    for (scheme, tls) in [("http", false), ("https", true)] {
        let target = TestServer::start(tls, |_| {
            response("200 OK", "", r#"{"access_token":"INTERNAL_SECRET"}"#)
        })
        .await;
        let location = format!(
            "{scheme}://127.0.0.1:{}/metadata/credentials",
            target.addr.port()
        );
        let registry = TestServer::start(true, move |_| {
            response("302 Found", &format!("Location: {location}\r\n"), "")
        })
        .await;
        let blocked = Arc::new(BlockedNetworks::defaults());
        let client = test_client(Arc::clone(&blocked), &[&registry, &target]);
        let image = ImageRef::parse(&format!(
            "registry.example:{}/victim/repo:latest",
            registry.addr.port()
        ))
        .unwrap();
        assert!(resolve_tag(&image, &client, &blocked).await.is_err());
        assert_eq!(registry.requests().len(), 1);
        assert_eq!(target.connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bearer_redirects_cannot_read_or_replay_internal_tokens() {
    for (scheme, tls, host) in [
        ("http", false, "127.0.0.1"),
        ("https", true, "127.0.0.1"),
        ("https", true, "other.example"),
    ] {
        let target = TestServer::start(tls, |_| {
            response("200 OK", "", r#"{"access_token":"INTERNAL_SECRET"}"#)
        })
        .await;
        let location = format!(
            "{scheme}://{host}:{}/metadata/credentials",
            target.addr.port()
        );
        let registry = TestServer::start(true, move |request| {
            if request.starts_with("GET /token?") {
                response("302 Found", &format!("Location: {location}\r\n"), "")
            } else if request.to_ascii_lowercase().contains("authorization:") {
                response("200 OK", "", "stolen-token manifest")
            } else {
                let host = request
                    .lines()
                    .find_map(|line| line.strip_prefix("host: "))
                    .unwrap();
                response(
                    "401 Unauthorized",
                    &format!("WWW-Authenticate: Bearer realm=\"https://{host}/token\"\r\n"),
                    "",
                )
            }
        })
        .await;
        let blocked = Arc::new(BlockedNetworks::defaults());
        let client = test_client(Arc::clone(&blocked), &[&registry, &target]);
        let image = ImageRef::parse(&format!(
            "registry.example:{}/victim/repo:latest",
            registry.addr.port()
        ))
        .unwrap();
        assert!(resolve_tag(&image, &client, &blocked).await.is_err());
        let requests = registry.requests();
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("GET /v2/victim/repo/manifests/latest "));
        assert!(
            requests
                .iter()
                .all(|request| !request.to_ascii_lowercase().contains("authorization:"))
        );
        assert_eq!(target.connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn bearer_private_literals_and_dns_with_custom_ports_are_rejected_before_connecting() {
    let target = TestServer::start(true, |_| {
        response("200 OK", "", r#"{"token":"INTERNAL_SECRET"}"#)
    })
    .await;
    let blocked = Arc::new(BlockedNetworks::defaults());
    let client = registry_client_builder(Arc::clone(&blocked))
        .build()
        .unwrap();
    for host in ["127.0.0.1", "localhost."] {
        let base = format!("https://{host}:{}", target.addr.port());
        let challenge = enclava_common::registry::BearerChallenge {
            realm: format!("{base}/token"),
            service: None,
            scope: None,
        };
        assert!(
            fetch_bearer_token(&client, challenge, &base, "victim/repo", &blocked)
                .await
                .is_err()
        );
        assert_eq!(target.connections.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn registry_transport_refuses_http_before_connecting() {
    let target = TestServer::start(false, |_| response("200 OK", "", "http response")).await;
    let blocked = Arc::new(BlockedNetworks::defaults());
    let client = test_client(blocked, &[&target]);
    let url = format!("http://registry.example:{}/token", target.addr.port());
    assert!(client.get(url).send().await.is_err());
    assert_eq!(target.connections.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn permitted_https_bearer_flow_resolves_and_hashes_manifest() {
    let manifest =
        r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
    let registry = TestServer::start(true, move |request| {
        if request.starts_with("GET /token?") {
            response("200 OK", "", r#"{"access_token":"REGISTRY_TOKEN"}"#)
        } else if request.to_ascii_lowercase().contains("authorization: bearer registry_token\r\n") {
            response("200 OK", &format!("Docker-Content-Digest: {}\r\n", manifest_digest(manifest.as_bytes())), manifest)
        } else {
            let host = request.lines().find_map(|line| line.strip_prefix("host: ")).unwrap();
            response("401 Unauthorized", &format!("WWW-Authenticate: Bearer realm=\"https://{host}/token\",service=\"registry.example\"\r\n"), "")
        }
    }).await;
    let blocked = Arc::new(BlockedNetworks::defaults());
    let client = test_client(Arc::clone(&blocked), &[&registry]);
    let image = ImageRef::parse(&format!(
        "registry.example:{}/victim/repo:latest",
        registry.addr.port()
    ))
    .unwrap();
    assert_eq!(
        resolve_tag(&image, &client, &blocked).await.unwrap(),
        manifest_digest(manifest.as_bytes())
    );
    let requests = registry.requests();
    assert_eq!(requests.len(), 3);
    assert!(
        requests[2]
            .to_ascii_lowercase()
            .contains("authorization: bearer registry_token\r\n")
    );
}
