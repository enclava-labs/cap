//! Safe, bounded bootstrap-failure diagnostics shared by every failure
//! surface of enclava-init (init-error file, termination log, stderr, and
//! tracing).
//!
//! Failure reporting never carries raw provider text or the raw anyhow
//! chain: the TLS certificate broker's terminal issuance failures are
//! consumed as the broker's bounded, provider-text-free contract
//! (`{"error","terminal","retry_after"}`) and carried here as a typed
//! [`SafeBootstrapDiagnostic`]; every other bootstrap failure is reported
//! as the generic `enclava_init_failed` code with no retry deadline. The
//! anyhow chain (which may contain paths, URLs, or provider detail) is
//! deliberately never rendered in the failure path — see the init binary's
//! failure reporting, which renders only the fields below.
//!
//! Contract shared with the attestation proxy worker and CLI consumers:
//!
//! ```json
//! {"error":"acme_rate_limited"|"acme_certificate_issuance_failed"|"enclava_init_failed",
//!  "terminal":true,"retry_after":null|"2026-09-10T09:30:00Z"}
//! ```
//!
//! Only exact recognized codes and a validated UTC deadline are ever
//! emitted; unknown, malformed, or out-of-bounds input degrades to the
//! generic failure with a null deadline.

use anyhow;
use chrono::{DateTime, TimeDelta, Utc};

/// Largest `retry_after` deadline accepted from the broker's safe contract,
/// mirroring the broker's own bound (365 days). A deadline farther out —
/// or a malformed timestamp — is reported as `null` instead of becoming an
/// unbounded retry-suppression window.
pub(crate) const MAX_RETRY_AFTER_HORIZON_SECS: i64 = 365 * 24 * 60 * 60;

/// Longest `retry_after` string ever parsed. RFC 3339 timestamps fit far
/// below this; anything longer is treated as malformed without parsing.
const MAX_RETRY_AFTER_LEN: usize = 64;

/// Bounded, provider-text-free diagnostic code for a bootstrap failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeDiagnosticCode {
    /// Terminal ACME rate limit reported by the TLS certificate broker
    /// (exact code `acme_rate_limited`).
    AcmeRateLimited,
    /// Terminal ACME issuance failure reported by the TLS certificate
    /// broker (exact code `acme_certificate_issuance_failed`); also the
    /// safe degradation for unknown, malformed, or unbounded broker
    /// responses.
    AcmeCertificateIssuanceFailed,
    /// Every other bootstrap failure (IO, LUKS, KBS, trustee policy, ...).
    EnclavaInitFailed,
}

impl SafeDiagnosticCode {
    /// Recognize only the exact broker contract codes. Classification is
    /// byte-exact; lookalikes, prefixed values, and anything else stay
    /// unrecognized so callers degrade them to the generic safe failure.
    pub fn from_broker_code(code: &str) -> Option<Self> {
        match code {
            "acme_rate_limited" => Some(Self::AcmeRateLimited),
            "acme_certificate_issuance_failed" => Some(Self::AcmeCertificateIssuanceFailed),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AcmeRateLimited => "acme_rate_limited",
            Self::AcmeCertificateIssuanceFailed => "acme_certificate_issuance_failed",
            Self::EnclavaInitFailed => "enclava_init_failed",
        }
    }
}

/// Safe, bounded diagnostic for one failed bootstrap run.
///
/// Every field is safe for ordinary logs and the init-error/termination
/// files: a fixed-vocabulary code and an optional validated UTC deadline.
/// No provider text, raw response bytes, paths, or anyhow chain ever enter
/// this type.
#[derive(Debug, Clone)]
pub struct SafeBootstrapDiagnostic {
    /// Bounded diagnostic code for the failure.
    pub code: SafeDiagnosticCode,
    /// Validated UTC instant after which the bootstrap may be retried, or
    /// `None` when no usable deadline exists.
    pub retry_after: Option<DateTime<Utc>>,
}

impl SafeBootstrapDiagnostic {
    /// The safe degradation for terminal ACME issuance failures without a
    /// usable deadline: unknown, malformed, or unbounded broker bodies.
    pub fn acme_failed() -> Self {
        Self {
            code: SafeDiagnosticCode::AcmeCertificateIssuanceFailed,
            retry_after: None,
        }
    }

    /// The generic safe failure for every non-broker bootstrap error.
    pub fn generic() -> Self {
        Self {
            code: SafeDiagnosticCode::EnclavaInitFailed,
            retry_after: None,
        }
    }

    /// Derive the safe diagnostic for a failed bootstrap run.
    ///
    /// The TLS broker's typed terminal failure is recovered by typed
    /// downcast through any contextual anyhow wrappers (never string
    /// scraping); every other error — including wrapped IO, config, or
    /// validation failures — degrades to the generic safe failure, keeping
    /// its possibly path-bearing chain out of all output.
    pub fn diagnose(error: &anyhow::Error) -> Self {
        error
            .downcast_ref::<crate::tls_certificate::TlsBrokerFailure>()
            .map(|failure| failure.diagnostic.clone())
            .unwrap_or_else(Self::generic)
    }

    /// Parse and validate a broker-supplied `retry_after` value into a
    /// bounded UTC deadline.
    ///
    /// Accepts RFC 3339 timestamps with a UTC offset (`Z` or `+00:00`)
    /// within [`MAX_RETRY_AFTER_HORIZON_SECS`] of `now` in either
    /// direction (the broker only emits future deadlines; the past
    /// tolerance only absorbs bounded clock skew). Returns `None` for
    /// absent, malformed, non-UTC, overlong, or out-of-bounds values —
    /// provider prose is never interpreted as a deadline.
    pub fn parse_retry_after(value: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let value = value.trim();
        if value.is_empty() || value.len() > MAX_RETRY_AFTER_LEN {
            return None;
        }
        let deadline = DateTime::parse_from_rfc3339(value).ok()?;
        if deadline.offset().local_minus_utc() != 0 {
            return None;
        }
        let deadline = deadline.with_timezone(&Utc);
        let horizon = now.checked_add_signed(TimeDelta::seconds(MAX_RETRY_AFTER_HORIZON_SECS))?;
        let floor = now.checked_sub_signed(TimeDelta::seconds(MAX_RETRY_AFTER_HORIZON_SECS))?;
        if deadline > horizon || deadline < floor {
            return None;
        }
        Some(deadline)
    }

    /// The validated retry deadline as an RFC 3339 UTC string, exactly as
    /// rendered in the JSON contract.
    pub fn retry_after_rfc3339(&self) -> Option<String> {
        self.retry_after
            .map(|deadline| deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
    }

    /// Render the single-line safe JSON contract used by the init-error
    /// file, the termination log, stderr, and tracing.
    ///
    /// `stage` is an optional exact vocabulary phrase already validated by
    /// the caller. It is omitted when absent. The stage file is overwritten
    /// on the next boot, so the termination log is the surface that survives
    /// a restart; unknown or caller-supplied text must never be passed here.
    pub fn render_json_with_stage(&self, stage: Option<&str>) -> String {
        let mut value = serde_json::json!({
            "error": self.code.as_str(),
            "terminal": true,
            "retry_after": self.retry_after_rfc3339(),
        });
        if let Some(stage) = stage {
            value["stage"] = serde_json::Value::String(stage.to_string());
        }
        value.to_string()
    }

    pub fn render_json(&self) -> String {
        self.render_json_with_stage(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use chrono::TimeDelta;

    fn now() -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp(1789000000, 0).unwrap()
    }

    #[test]
    fn generic_failure_renders_exact_safe_contract() {
        let rendered = SafeBootstrapDiagnostic::generic().render_json();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
            serde_json::json!({
                "error": "enclava_init_failed",
                "terminal": true,
                "retry_after": null,
            })
        );
        assert!(!rendered.contains('\n'));
        assert_eq!(
            SafeDiagnosticCode::from_broker_code("enclava_init_failed"),
            None
        );
    }

    #[test]
    fn rate_limited_failure_renders_validated_deadline() {
        let deadline = now() + TimeDelta::hours(3);
        let diagnostic = SafeBootstrapDiagnostic {
            code: SafeDiagnosticCode::AcmeRateLimited,
            retry_after: Some(deadline),
        };
        let rendered = diagnostic.render_json();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
            serde_json::json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            })
        );
        assert!(rendered.contains(&deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)));
    }

    #[test]
    fn broker_code_classification_is_byte_exact() {
        assert_eq!(
            SafeDiagnosticCode::from_broker_code("acme_rate_limited"),
            Some(SafeDiagnosticCode::AcmeRateLimited)
        );
        assert_eq!(
            SafeDiagnosticCode::from_broker_code("acme_certificate_issuance_failed"),
            Some(SafeDiagnosticCode::AcmeCertificateIssuanceFailed)
        );
        for lookalike in [
            "",
            "acme_rate_limited ",
            " acme_rate_limited",
            "ACME_RATE_LIMITED",
            "acme_rate_limited2",
            "acme-rate-limited",
            "urn:ietf:params:acme:error:rateLimited",
            "acme_certificate_issuance_failed\0",
        ] {
            assert_eq!(
                SafeDiagnosticCode::from_broker_code(lookalike),
                None,
                "lookalike must stay unrecognized: {lookalike:?}"
            );
        }
    }

    #[test]
    fn typed_broker_failure_survives_contextual_anyhow_wrappers() {
        let deadline = now() + TimeDelta::minutes(30);
        let diagnostic = SafeBootstrapDiagnostic {
            code: SafeDiagnosticCode::AcmeRateLimited,
            retry_after: Some(deadline),
        };
        let error = anyhow::Error::new(crate::tls_certificate::TlsBrokerFailure { diagnostic })
            .context("provisioning static TLS certificate")
            .context("outer context with SYNTHETIC-CHAIN-SENTINEL text");

        let diagnosed = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnosed.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(diagnosed.retry_after, Some(deadline));
        // The rendered output carries only the safe fields, never the chain.
        let rendered = diagnosed.render_json();
        assert!(!rendered.contains("SYNTHETIC-CHAIN-SENTINEL"));
        assert!(!rendered.contains("outer context"));
    }

    #[test]
    fn unknown_errors_degrade_to_generic_without_chain_text() {
        let error = anyhow!("reading supplied value /state/secret-path: SYNTHETIC-IO-SENTINEL")
            .context("opening luks volumes");
        let diagnosed = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnosed.code, SafeDiagnosticCode::EnclavaInitFailed);
        assert_eq!(diagnosed.retry_after, None);
        let rendered = diagnosed.render_json();
        assert!(!rendered.contains("SYNTHETIC-IO-SENTINEL"));
        assert!(!rendered.contains("/state/secret-path"));
    }

    #[test]
    fn retry_after_parsing_accepts_only_bounded_utc_rfc3339() {
        let now = now();
        let valid = "2026-09-10T09:30:00Z";
        assert_eq!(
            SafeBootstrapDiagnostic::parse_retry_after(valid, now),
            DateTime::parse_from_rfc3339(valid)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        );
        assert_eq!(
            SafeBootstrapDiagnostic::parse_retry_after("2026-09-10T09:30:00+00:00", now)
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
            Some("2026-09-10T09:30:00Z".to_string())
        );

        for malformed in [
            "",
            "   ",
            "null",
            "soon",
            "2026-09-10T09:30:00",             // no offset
            "2026-09-10T09:30:00+02:00",       // not UTC
            "9999-12-31T23:59:59Z",            // far out of bounds
            "1900-01-01T00:00:00Z",            // far out of bounds
            "2026-09-10T09:30:00Z extra text", // trailing prose
            &"9".repeat(MAX_RETRY_AFTER_LEN + 1),
        ] {
            assert_eq!(
                SafeBootstrapDiagnostic::parse_retry_after(malformed, now),
                None,
                "malformed deadline must be absent: {malformed:?}"
            );
        }
        // RFC 3339 permits a space separator (its NOTE on section 5.6);
        // chrono accepts it and the rendered deadline is normalized to `T`.
        assert!(SafeBootstrapDiagnostic::parse_retry_after("2026-09-10 09:30:00Z", now).is_some());
    }

    #[test]
    fn retry_after_horizon_is_bounded_in_both_directions() {
        let now = now();
        let inside = now + TimeDelta::seconds(MAX_RETRY_AFTER_HORIZON_SECS - 60);
        let outside = now + TimeDelta::seconds(MAX_RETRY_AFTER_HORIZON_SECS + 60);
        assert!(
            SafeBootstrapDiagnostic::parse_retry_after(
                &inside.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                now
            )
            .is_some()
        );
        assert_eq!(
            SafeBootstrapDiagnostic::parse_retry_after(
                &outside.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                now
            ),
            None
        );
    }

    #[test]
    fn elapsed_retry_after_is_preserved_not_erased() {
        // Contract coordination: an elapsed deadline does not erase the
        // terminal failure — it only means a retry may be attempted
        // separately. The bounded timestamp stays preserved verbatim (the
        // past tolerance also absorbs guest/broker clock skew) and is
        // never nulled.
        let now = now();
        let elapsed = now - TimeDelta::hours(2);
        assert_eq!(
            SafeBootstrapDiagnostic::parse_retry_after(
                &elapsed.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                now
            ),
            Some(elapsed)
        );
    }
}
