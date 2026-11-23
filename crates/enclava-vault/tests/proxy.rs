//! End-to-end: a real HTTPS client talks through the vault to a real TLS
//! upstream, and the tests assert on what the upstream actually received.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use enclava_common::outbound_http::BlockedNetworks;
use enclava_vault::{ConnectionSpec, Origin, Position, Proxy, ProxyConfig, Store, VaultCa};
use http::{HeaderMap, Request, Response, StatusCode, Version};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

const SECRET: &str = "real-credential-9f2c";

#[derive(Debug, Clone)]
struct Seen {
    target: String,
    headers: HeaderMap,
    body: Bytes,
    version: Version,
}

/// A TLS server for `localhost` that records every request it receives.
struct Upstream {
    port: u16,
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Upstream {
    async fn spawn() -> Self {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der.clone()],
                PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let recorder = recorder.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let recorder = recorder.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body.collect().await.unwrap().to_bytes();
                            let reply = format!("upstream saw {} bytes", body.len());
                            recorder.lock().unwrap().push(Seen {
                                target: parts.uri.path_and_query().unwrap().to_string(),
                                headers: parts.headers,
                                body,
                                version: parts.version,
                            });
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(reply))))
                        }
                    });
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self {
            port,
            cert_pem: cert.cert.pem(),
            cert_der,
            seen,
        }
    }

    fn origin(&self) -> Origin {
        Origin::parse(&format!("https://localhost:{}", self.port)).unwrap()
    }

    fn url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.port)
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

struct Vault {
    proxy_url: String,
    ca_pem: String,
    store: Store,
    _dir: tempfile::TempDir,
}

struct VaultOptions {
    passthrough: Vec<Origin>,
    blocked: BlockedNetworks,
}

impl Default for VaultOptions {
    fn default() -> Self {
        Self {
            passthrough: Vec::new(),
            // The upstreams live on loopback, which the production default
            // blocks; one test below keeps the default on purpose.
            blocked: BlockedNetworks::empty(),
        }
    }
}

impl Vault {
    /// Starts a vault that trusts `upstreams` and holds no connections yet.
    async fn spawn(upstreams: &[&Upstream], options: VaultOptions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let ca = VaultCa::load_or_generate(store.dir()).unwrap();
        let ca_pem = ca.cert_pem().to_owned();
        let mut roots = RootCertStore::empty();
        for upstream in upstreams {
            roots.add(upstream.cert_der.clone()).unwrap();
        }
        let proxy = Proxy::new(
            store.clone(),
            ca,
            ProxyConfig {
                passthrough: options.passthrough,
                blocked: options.blocked,
                upstream_roots: roots,
                max_connections: 64,
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(proxy.serve(listener));
        Self {
            proxy_url,
            ca_pem,
            store,
            _dir: dir,
        }
    }

    /// Adds a header connection for `upstream` and returns its placeholder.
    fn connect(&self, name: &str, upstream: &Upstream, prefix: &str) -> String {
        let spec = ConnectionSpec {
            name: name.into(),
            origin: upstream.origin(),
            path_prefix: prefix.into(),
            position: Position::Header {
                name: "authorization".into(),
            },
            expose_as: None,
        };
        self.store.put(spec, SECRET).unwrap().placeholder
    }

    /// A client that reaches the world only through the vault and trusts
    /// only `trusted_pem`.
    fn client(&self, trusted_pem: &str, http1_only: bool) -> reqwest::Client {
        let certificate = reqwest::Certificate::from_pem(trusted_pem.as_bytes()).unwrap();
        let mut builder = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&self.proxy_url).unwrap())
            .tls_certs_only([certificate]);
        if http1_only {
            builder = builder.http1_only();
        }
        builder.build().unwrap()
    }
}

async fn refusal_reason(response: reqwest::Response) -> String {
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    response
        .headers()
        .get("x-enclava-vault")
        .expect("vault refusal header")
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn placeholder_is_swapped_over_http1() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;
    let placeholder = vault.connect("api", &upstream, "/");

    let response = vault
        .client(&vault.ca_pem, true)
        .post(upstream.url("/v1/items?page=2"))
        .bearer_auth(&placeholder)
        .body("hello upstream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "upstream saw 14 bytes");

    let seen = upstream.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].target, "/v1/items?page=2");
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(seen[0].body, "hello upstream");
    assert!(!seen[0].headers.contains_key("proxy-connection"));
}

#[tokio::test]
async fn placeholder_is_swapped_over_http2_on_both_legs() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;
    let placeholder = vault.connect("api", &upstream, "/");

    let response = vault
        .client(&vault.ca_pem, false)
        .get(upstream.url("/v1/me"))
        .bearer_auth(&placeholder)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_2);

    let seen = upstream.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].version, Version::HTTP_2);
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {SECRET}"));
}

#[tokio::test]
async fn request_without_a_placeholder_passes_unchanged() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;
    vault.connect("api", &upstream, "/");

    let response = vault
        .client(&vault.ca_pem, true)
        .get(upstream.url("/public"))
        .bearer_auth("the-apps-own-token")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        upstream.seen()[0].headers["authorization"],
        "Bearer the-apps-own-token"
    );
}

#[tokio::test]
async fn misplaced_placeholder_is_refused_and_never_reaches_the_upstream() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;
    let placeholder = vault.connect("api", &upstream, "/v1");
    let client = vault.client(&vault.ca_pem, true);

    let wrong_header = client
        .get(upstream.url("/v1/me"))
        .header("x-debug", &placeholder)
        .send()
        .await
        .unwrap();
    assert_eq!(refusal_reason(wrong_header).await, "placeholder_misplaced");

    let in_query = client
        .get(upstream.url(&format!("/v1/me?token={placeholder}")))
        .send()
        .await
        .unwrap();
    assert_eq!(refusal_reason(in_query).await, "placeholder_misplaced");

    let outside_prefix = client
        .get(upstream.url("/v2/me"))
        .bearer_auth(&placeholder)
        .send()
        .await
        .unwrap();
    assert_eq!(refusal_reason(outside_prefix).await, "path_not_allowed");

    assert!(upstream.seen().is_empty());
}

#[tokio::test]
async fn placeholder_is_refused_at_another_connected_origin() {
    let api = Upstream::spawn().await;
    let other = Upstream::spawn().await;
    let vault = Vault::spawn(&[&api, &other], VaultOptions::default()).await;
    let api_placeholder = vault.connect("api", &api, "/");
    vault.connect("other", &other, "/");

    let response = vault
        .client(&vault.ca_pem, true)
        .get(other.url("/collect"))
        .bearer_auth(&api_placeholder)
        .send()
        .await
        .unwrap();
    assert_eq!(refusal_reason(response).await, "placeholder_wrong_origin");
    assert!(api.seen().is_empty());
    assert!(other.seen().is_empty());
}

#[tokio::test]
async fn origin_that_is_not_connected_is_refused_at_connect() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;

    let result = vault
        .client(&upstream.cert_pem, true)
        .get(upstream.url("/"))
        .send()
        .await;
    assert!(result.is_err(), "CONNECT should have been refused");
    assert!(upstream.seen().is_empty());
}

#[tokio::test]
async fn passthrough_origin_is_relayed_without_interception() {
    let upstream = Upstream::spawn().await;
    let options = VaultOptions {
        passthrough: vec![upstream.origin()],
        ..VaultOptions::default()
    };
    let vault = Vault::spawn(&[&upstream], options).await;

    // The client trusts the upstream's own certificate and not the vault
    // CA, so this only succeeds if the vault did not terminate TLS.
    let response = vault
        .client(&upstream.cert_pem, true)
        .get(upstream.url("/plain"))
        .bearer_auth("encv_api_00000000000000000000000000000000")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        upstream.seen()[0].headers["authorization"],
        "Bearer encv_api_00000000000000000000000000000000"
    );
}

#[tokio::test]
async fn blocked_network_is_refused_for_intercepted_and_passthrough_origins() {
    let connected = Upstream::spawn().await;
    let relayed = Upstream::spawn().await;
    let options = VaultOptions {
        passthrough: vec![relayed.origin()],
        blocked: BlockedNetworks::defaults(),
    };
    let vault = Vault::spawn(&[&connected, &relayed], options).await;
    let placeholder = vault.connect("api", &connected, "/");

    let intercepted = vault
        .client(&vault.ca_pem, true)
        .get(connected.url("/v1/me"))
        .bearer_auth(&placeholder)
        .send()
        .await
        .unwrap();
    assert_eq!(refusal_reason(intercepted).await, "destination_blocked");

    let tunnelled = vault
        .client(&relayed.cert_pem, true)
        .get(relayed.url("/"))
        .send()
        .await;
    assert!(tunnelled.is_err(), "CONNECT should have been refused");

    assert!(connected.seen().is_empty());
    assert!(relayed.seen().is_empty());
}

#[tokio::test]
async fn rotation_and_removal_take_effect_without_a_restart() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;
    let placeholder = vault.connect("api", &upstream, "/");
    let client = vault.client(&vault.ca_pem, true);
    let call = || {
        client
            .get(upstream.url("/v1/me"))
            .bearer_auth(&placeholder)
            .send()
    };

    assert_eq!(call().await.unwrap().status(), StatusCode::OK);

    let rotated = ConnectionSpec {
        name: "api".into(),
        origin: upstream.origin(),
        path_prefix: "/".into(),
        position: Position::Header {
            name: "authorization".into(),
        },
        expose_as: None,
    };
    assert_eq!(
        vault
            .store
            .put(rotated, "rotated-credential")
            .unwrap()
            .placeholder,
        placeholder
    );
    assert_eq!(call().await.unwrap().status(), StatusCode::OK);

    let seen = upstream.seen();
    assert_eq!(seen[0].headers["authorization"], format!("Bearer {SECRET}"));
    assert_eq!(
        seen[1].headers["authorization"],
        "Bearer rotated-credential"
    );

    // Once the last connection for an origin is gone, a new tunnel to it
    // is refused. A fresh client is used so no pooled tunnel is reused.
    assert!(vault.store.remove("api").unwrap());
    let fresh = vault.client(&vault.ca_pem, true);
    let after_removal = fresh
        .get(upstream.url("/v1/me"))
        .bearer_auth(&placeholder)
        .send()
        .await;
    assert!(after_removal.is_err(), "CONNECT should have been refused");
    assert_eq!(upstream.seen().len(), 2);
}

#[tokio::test]
async fn plain_http_proxying_is_refused() {
    let upstream = Upstream::spawn().await;
    let vault = Vault::spawn(&[&upstream], VaultOptions::default()).await;

    let response = vault
        .client(&vault.ca_pem, true)
        .get(format!("http://localhost:{}/", upstream.port))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(response.headers()["x-enclava-vault"], "connect_only");
}
