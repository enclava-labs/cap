//! Opt-in, content-free TLS broker timings. Never pass request data or errors here.
//! Enable only `cap::workload_tls_timing=debug` in the existing log filter.
//! Group by process/pod and request_seq; nested stages must not be added to totals.
//! Success means that operation returned Ok, not that subsequent validation passed.
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) struct RequestTiming(u64);

#[derive(Clone, Copy)]
pub(crate) enum Phase {
    BrokerTotal,
    Attestation,
    ArtifactLookup,
    AcmeAccount,
    AcmeOrder,
    AcmeAuthorization,
    DnsCreate,
    DnsVisibility,
    DnsExternalLookup,
    DnsSystemLookup,
    AcmeChallengeReady,
    AcmeOrderReady,
    AcmeFinalize,
    AcmeCertificate,
    DnsCleanup,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Self::BrokerTotal => "broker_total",
            Self::Attestation => "attestation",
            Self::ArtifactLookup => "artifact_lookup",
            Self::AcmeAccount => "acme_account",
            Self::AcmeOrder => "acme_order",
            Self::AcmeAuthorization => "acme_authorization",
            Self::DnsCreate => "dns_create",
            Self::DnsVisibility => "dns_visibility",
            Self::DnsExternalLookup => "dns_external_lookup",
            Self::DnsSystemLookup => "dns_system_lookup",
            Self::AcmeChallengeReady => "acme_challenge_ready",
            Self::AcmeOrderReady => "acme_order_ready",
            Self::AcmeFinalize => "acme_finalize",
            Self::AcmeCertificate => "acme_certificate",
            Self::DnsCleanup => "dns_cleanup",
        }
    }
}

impl RequestTiming {
    pub(crate) fn new() -> Self {
        loop {
            let seq = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
            if seq != 0 {
                return Self(seq);
            }
        }
    }

    pub(crate) fn start(self, phase: Phase) -> StageTiming {
        StageTiming {
            request: self,
            phase,
            started: tracing::enabled!(target: "cap::workload_tls_timing", tracing::Level::DEBUG)
                .then(Instant::now),
            outcome: "cancelled",
        }
    }

    pub(crate) async fn measure<T, E>(
        self,
        phase: Phase,
        work: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        let mut stage = self.start(phase);
        let result = work.await;
        stage.finish(result.is_ok());
        result
    }
}

pub(crate) struct StageTiming {
    request: RequestTiming,
    phase: Phase,
    started: Option<Instant>,
    outcome: &'static str,
}

impl StageTiming {
    pub(crate) fn finish(&mut self, success: bool) {
        self.outcome = if success { "success" } else { "error" };
    }
}

impl Drop for StageTiming {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            tracing::debug!(
                target: "cap::workload_tls_timing",
                parent: None,
                event = "workload_tls_timing",
                request_seq = self.request.0,
                phase = self.phase.label(),
                outcome = self.outcome,
                elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timing_is_opt_in_closed_schema_and_never_formats_values_or_errors() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let make_writer = || {
            let logs = logs.clone();
            move || Writer(logs.clone())
        };
        let disabled = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_env_filter("enclava_api=debug")
            .with_writer(make_writer())
            .finish();
        {
            let _guard = tracing::subscriber::set_default(disabled);
            let mut timer = RequestTiming::new().start(Phase::BrokerTotal);
            timer.finish(true);
        }
        assert!(logs.lock().unwrap().is_empty());
        let enabled = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_env_filter("off,cap::workload_tls_timing=debug")
            .with_writer(make_writer())
            .finish();
        let _guard = tracing::subscriber::set_default(enabled);
        let span = tracing::debug_span!(target: "cap::workload_tls_timing", "private_request", private = "private-host-token-csr-error");
        let _entered = span.enter();
        let request = RequestTiming::new();
        assert!(request.0 > 0);
        assert_ne!(request.0, RequestTiming::new().0);
        let secret = "private-host-token-csr-error";
        assert_eq!(
            request
                .measure(Phase::DnsCreate, async { Ok::<_, &str>(secret) })
                .await,
            Ok(secret)
        );
        assert_eq!(
            request
                .measure(Phase::DnsVisibility, async { Err::<(), _>(secret) })
                .await,
            Err(secret)
        );
        let mut future = Box::pin(request.measure(
            Phase::AcmeCertificate,
            std::future::pending::<Result<(), &str>>(),
        ));
        assert!(futures::poll!(&mut future).is_pending());
        drop(future);
        let text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert!(!text.contains(secret));
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        for (line, (phase, outcome)) in lines.iter().zip([
            ("dns_create", "success"),
            ("dns_visibility", "error"),
            ("acme_certificate", "cancelled"),
        ]) {
            let fields: Vec<_> = line.split_whitespace().collect();
            assert_eq!(fields.len(), 7, "unexpected telemetry field: {line}");
            assert_eq!(fields[0], "DEBUG");
            assert_eq!(fields[1], "cap::workload_tls_timing:");
            assert_eq!(fields[2], "event=\"workload_tls_timing\"");
            assert_eq!(fields[3], format!("request_seq={}", request.0));
            assert_eq!(fields[4], format!("phase=\"{phase}\""));
            assert_eq!(fields[5], format!("outcome=\"{outcome}\""));
            fields[6]
                .strip_prefix("elapsed_ms=")
                .unwrap()
                .parse::<u64>()
                .unwrap();
        }
    }
}
