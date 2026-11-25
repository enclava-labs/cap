//! cap#425-adjacent (cd plain-deploy 409, 2026-11-25): the signing-path
//! server errors that the idempotency layer masks as 409 must be visible
//! in the api log, with the signing service's own refusal text for
//! Upstream responses.

use super::signing_error_response;
use crate::signing_service::SigningServiceError;
use axum::http::StatusCode;
use std::io::Write;
use std::sync::{Arc, Mutex};

struct CapturedWarnWriter(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedWarnWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("captured log mutex").extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn captured_warn_logs() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer({
            let logs = Arc::clone(&logs);
            move || CapturedWarnWriter(Arc::clone(&logs))
        })
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (logs, guard)
}

fn captured_warn_text(logs: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8(logs.lock().expect("captured log mutex").clone())
        .expect("captured logs are UTF-8")
}

#[test]
fn signing_service_5xx_responses_log_the_refusal_body() {
    // The exact shape of the 2026-11-25 outage: the service refused /sign
    // before generation (descriptor signature verification failed against
    // its canonical bytes), CAP masked the 422 as 502
    // signing_service_unavailable, and the idempotency layer turned that
    // into 409 idempotency_recovery_required. The WARN is the only place
    // the service's refusal body survives.
    let (logs, _guard) = captured_warn_logs();
    let (status, body) = signing_error_response(SigningServiceError::Upstream {
        status: reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        body: "descriptor signature verification failed: ed25519 signature".to_string(),
    });
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body.0["error"], "signing_service_unavailable");
    let text = captured_warn_text(&logs);
    assert!(
        text.contains("signing_service_unavailable"),
        "the code is logged: {text}"
    );
    assert!(
        text.contains("descriptor signature verification failed"),
        "the service's refusal body is logged: {text}"
    );
    assert!(
        text.contains("idempotency_recovery_required"),
        "the masking is named so the operator knows to look here: {text}"
    );
}

#[test]
fn signing_service_database_and_serialization_errors_log_too() {
    for error in [
        SigningServiceError::Db(sqlx::Error::RowNotFound),
        SigningServiceError::Serde(
            serde_json::from_str::<serde_json::Value>("{")
                .expect_err("a malformed body must fail to parse"),
        ),
    ] {
        let (logs, _guard) = captured_warn_logs();
        let (status, _) = signing_error_response(error);
        assert!(status.is_server_error());
        assert!(
            !captured_warn_text(&logs).is_empty(),
            "every 5xx signing error logs a WARN"
        );
    }
}

#[test]
fn typed_4xx_signing_errors_do_not_log() {
    // Mismatch/InvalidSignature are typed 4xx the CLI prints verbatim;
    // they are not masked and must not add log noise.
    for error in [
        SigningServiceError::Mismatch("artifact.metadata.app_id".into()),
        SigningServiceError::InvalidSignature,
    ] {
        let (logs, _guard) = captured_warn_logs();
        let (status, _) = signing_error_response(error);
        assert!(!status.is_server_error());
        assert!(
            captured_warn_text(&logs).is_empty(),
            "4xx signing errors stay unlogged"
        );
    }
}
