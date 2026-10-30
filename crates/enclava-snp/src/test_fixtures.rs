use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::evidence::SnpDerChain;

/// A time inside every certificate's validity window in the live fixture.
pub(crate) const FIXTURE_NOW: u64 = 1_798_761_600; // 2027-01-01

/// Sanitized live Genoa bundle (see enclava-verifier fixtures README): real
/// AMD chain and report, no secrets, verifiable fully offline.
pub(crate) struct ProveItLive {
    pub(crate) report: Vec<u8>,
    pub(crate) ark_der: Vec<u8>,
    pub(crate) ask_der: Vec<u8>,
    pub(crate) vcek_der: Vec<u8>,
}

pub(crate) fn prove_it_live() -> ProveItLive {
    let encoded = include_str!("../../enclava-verifier/tests/fixtures/prove-it-live.bundle.b64")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    let bundle = STANDARD
        .decode(encoded)
        .expect("decode prove-it-live bundle");
    let bundle = records(&bundle);
    let endorsements = records(&bundle["amd_endorsements"]);
    ProveItLive {
        report: bundle["snp_report"].clone(),
        ark_der: endorsements["ark_der"].clone(),
        ask_der: endorsements["ask_der"].clone(),
        vcek_der: endorsements["vcek_der"].clone(),
    }
}

fn records(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    enclava_common::canonical::ce_v1_decode(bytes)
        .expect("CE-v1 records")
        .into_iter()
        .map(|record| (record.label.to_string(), record.value.to_vec()))
        .collect()
}

impl ProveItLive {
    pub(crate) fn chain(&self) -> SnpDerChain {
        SnpDerChain {
            ark_der: self.ark_der.clone(),
            ask_der: self.ask_der.clone(),
            vcek_der: self.vcek_der.clone(),
        }
    }

    pub(crate) fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "quote": self.report,
            "cert_chain": [
                {"cert_type": "ARK", "data": self.ark_der},
                {"cert_type": "ASK", "data": self.ask_der},
                {"cert_type": "VCEK", "data": self.vcek_der},
            ],
        })
    }

    pub(crate) fn parsed(&self) -> enclava_verifier::SnpReport<'_> {
        enclava_verifier::parse_snp_report(&self.report).expect("fixture report parses")
    }
}

/// Timing events share process-global callsites: a first registration on a
/// thread without a subscriber can cache `Interest::never` and drop events in
/// the log-capturing test. A scoped sink subscriber keeps interest live.
pub(crate) fn quiet_subscriber() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(std::io::sink)
            .finish(),
    )
}

/// Serve `body` (with `status`) on every path; returns the address and a
/// request counter.
pub(crate) async fn serve_every_path(
    status: u16,
    body: Vec<u8>,
) -> (
    std::net::SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    use std::sync::{Arc, atomic::AtomicUsize, atomic::Ordering};
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let status = axum::http::StatusCode::from_u16(status).expect("test status");
    let app = axum::Router::new().fallback(move || {
        let counter = counter.clone();
        let body = body.clone();
        async move {
            counter.fetch_add(1, Ordering::Relaxed);
            (status, body)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, requests, server)
}
