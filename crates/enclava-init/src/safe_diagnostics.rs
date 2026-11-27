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
//!  "terminal":true,"retry_after":null|"2026-09-10T09:30:00Z",
//!  "failed_stage":null|"binding workload mount namespaces",
//!  "failed_step":null|"tls_decode_failed"|"tls_validate_failed"|"tls_write_failed"|
//!                "tls_handoff_failed"|"bind_sentinel_failed"|"bind_source_failed"|
//!                "bind_target_create_failed"|"bind_mount_failed"}
//! ```
//!
//! `failed_step` is a sibling of the code, never a replacement for it: the
//! `error` code set is fixed (the proxy and the CLI enumerate it), so the
//! failing step rides its own allowlisted field and every old consumer
//! that reads by key keeps working unchanged. It is `null` whenever the
//! failing site is not instrumented.
//!
//! Only exact recognized codes and a validated UTC deadline are ever
//! emitted; unknown, malformed, or out-of-bounds input degrades to the
//! generic failure with a null deadline. `failed_stage` names the fixed
//! init-stage vocabulary phrase the failed run had reached, so the payload
//! stays self-describing even when the stage file has moved on (a later
//! boot attempt) — it is `null` only when no stage was recorded.

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

/// Stage this process has reached. The binary's `record_stage` is the only
/// production writer; [`SafeBootstrapDiagnostic::diagnose`] is the only
/// reader that copies it onto a diagnostic. A caller of `diagnose` cannot
/// pass a different string.
static LAST_STAGE: std::sync::Mutex<Option<&'static str>> = std::sync::Mutex::new(None);

/// Record the fixed-vocabulary stage the current run has reached.
///
/// Production code writes this only from `record_stage`. Tests reset it so
/// a previous case cannot leak a stage into the next failure report.
pub fn set_last_stage(stage: Option<&'static str>) {
    *LAST_STAGE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = stage;
}

/// The stage [`set_last_stage`] last recorded, if any.
pub fn last_stage() -> Option<&'static str> {
    *LAST_STAGE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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

/// The fixed failing-step vocabulary, one entry per instrumented site in
/// the certificate and bind stages (cap#428). Content-free by the same
/// discipline as [`SafeDiagnosticCode`]: no provider text, paths, errno
/// strings, or secrets — only this table's literals ever leave the init
/// binary on the `failed_step` key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitFailedStep {
    /// Reading or parsing retained TLS certificate/key state.
    TlsDecodeFailed,
    /// Anchored validation of a retained or broker-issued certificate chain.
    TlsValidateFailed,
    /// Persisting the certificate or key, and the ownership handoff loop.
    TlsWriteFailed,
    /// Publishing the public certificate for the proxy handoff.
    TlsHandoffFailed,
    /// Waiting for workload container start sentinels, including timeout.
    BindSentinelFailed,
    /// Building the bind plan or inspecting the source mount tree.
    BindSourceFailed,
    /// Creating the bind target inside the workload namespace.
    BindTargetCreateFailed,
    /// Entering the namespace or performing the mount itself.
    BindMountFailed,
}

impl InitFailedStep {
    /// The exact `failed_step` literal for this step.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TlsDecodeFailed => "tls_decode_failed",
            Self::TlsValidateFailed => "tls_validate_failed",
            Self::TlsWriteFailed => "tls_write_failed",
            Self::TlsHandoffFailed => "tls_handoff_failed",
            Self::BindSentinelFailed => "bind_sentinel_failed",
            Self::BindSourceFailed => "bind_source_failed",
            Self::BindTargetCreateFailed => "bind_target_create_failed",
            Self::BindMountFailed => "bind_mount_failed",
        }
    }

    /// Recognize only exact step literals: classification is byte-exact, so
    /// lookalikes, prefixed values, and anything else stay unrecognized.
    pub fn parse_str(value: &str) -> Option<Self> {
        match value {
            "tls_decode_failed" => Some(Self::TlsDecodeFailed),
            "tls_validate_failed" => Some(Self::TlsValidateFailed),
            "tls_write_failed" => Some(Self::TlsWriteFailed),
            "tls_handoff_failed" => Some(Self::TlsHandoffFailed),
            "bind_sentinel_failed" => Some(Self::BindSentinelFailed),
            "bind_source_failed" => Some(Self::BindSourceFailed),
            "bind_target_create_failed" => Some(Self::BindTargetCreateFailed),
            "bind_mount_failed" => Some(Self::BindMountFailed),
            _ => None,
        }
    }

    /// The fixed exit-code table the bind child shares with its parent.
    /// Only the three steps a bind child can hit are mapped (below 128 on
    /// purpose: a signal death has no code); every other step stays `None`
    /// and the child exits 1 like any untyped failure.
    pub fn child_exit_code(self) -> Option<u8> {
        match self {
            Self::BindSourceFailed => Some(3),
            Self::BindTargetCreateFailed => Some(4),
            Self::BindMountFailed => Some(5),
            _ => None,
        }
    }

    /// The receiving half of the child exit-code table.
    pub fn from_child_exit_code(code: i32) -> Option<Self> {
        match code {
            3 => Some(Self::BindSourceFailed),
            4 => Some(Self::BindTargetCreateFailed),
            5 => Some(Self::BindMountFailed),
            _ => None,
        }
    }
}

/// The typed wrapper that carries an [`InitFailedStep`] through the anyhow
/// chain as a context frame, so [`SafeBootstrapDiagnostic::diagnose`] can
/// recover it by typed downcast — never by string scraping. The display
/// text is content-free by the same rule as the diagnostic itself.
#[derive(Debug)]
pub struct InitStepError(pub InitFailedStep);

impl std::fmt::Display for InitStepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "init step {}", self.0.as_str())
    }
}

impl std::error::Error for InitStepError {}

/// Safe, bounded diagnostic for one failed bootstrap run.
///
/// Every field is safe for ordinary logs and the init-error/termination
/// files: a fixed-vocabulary code and an optional validated UTC deadline.
/// No provider text, raw response bytes, paths, or anyhow chain ever enter
/// this type.
#[derive(Debug, Clone)]
pub struct SafeBootstrapDiagnostic {
    /// The instrumented failing step, when the error chain carried a typed
    /// [`InitStepError`] (a broker failure never carries one).
    step: Option<InitFailedStep>,
    /// Bounded diagnostic code for the failure.
    pub code: SafeDiagnosticCode,
    /// Validated UTC instant after which the bootstrap may be retried, or
    /// `None` when no usable deadline exists.
    pub retry_after: Option<DateTime<Utc>>,
    /// The fixed-vocabulary init stage the failed run had reached (one of
    /// the `record_stage` literals), or `None` when no stage was recorded.
    /// Safe like every other field: never free-form text. Private, and set
    /// only by [`Self::diagnose`] from the stage tracker `record_stage`
    /// writes — a caller cannot pass a different string (#402).
    stage: Option<&'static str>,
}

impl SafeBootstrapDiagnostic {
    /// A stage-less diagnostic for a known code and validated deadline.
    /// [`Self::diagnose`] attaches the stage the run has reached; nothing
    /// else may name one.
    pub fn new(code: SafeDiagnosticCode, retry_after: Option<DateTime<Utc>>) -> Self {
        Self {
            step: None,
            code,
            retry_after,
            stage: None,
        }
    }

    /// The stage [`Self::diagnose`] attached, if the run had reached one.
    pub fn stage(&self) -> Option<&'static str> {
        self.stage
    }

    /// The instrumented failing step [`Self::diagnose`] recovered from the
    /// typed context frame, if any.
    pub fn step(&self) -> Option<InitFailedStep> {
        self.step
    }

    /// Attach the stage the tracker currently holds. Not a caller-supplied
    /// string: the only production writer is `record_stage`.
    fn with_recorded_stage(mut self) -> Self {
        self.stage = last_stage();
        self
    }

    /// The safe degradation for terminal ACME issuance failures without a
    /// usable deadline: unknown, malformed, or unbounded broker bodies.
    pub fn acme_failed() -> Self {
        Self {
            step: None,
            code: SafeDiagnosticCode::AcmeCertificateIssuanceFailed,
            retry_after: None,
            stage: None,
        }
    }

    /// The generic safe failure for every non-broker bootstrap error.
    pub fn generic() -> Self {
        Self {
            step: None,
            code: SafeDiagnosticCode::EnclavaInitFailed,
            retry_after: None,
            stage: None,
        }
    }

    /// Derive the safe diagnostic for a failed bootstrap run.
    ///
    /// The stage is read from the tracker `record_stage` writes, at
    /// construction time — never from a caller-supplied string and never by
    /// a later field write (#402).
    ///
    /// The TLS broker's typed terminal failure is recovered by typed
    /// downcast through any contextual anyhow wrappers (never string
    /// scraping); every other error — including wrapped IO, config, or
    /// validation failures — degrades to the generic safe failure, keeping
    /// its possibly path-bearing chain out of all output.
    pub fn diagnose(error: &anyhow::Error) -> Self {
        match error.downcast_ref::<crate::tls_certificate::TlsBrokerFailure>() {
            // A broker failure keeps its acme code and carries no step —
            // the broker's typed contract already classifies it.
            Some(failure) => failure.diagnostic.clone().with_recorded_stage(),
            None => {
                let mut diagnostic = Self::generic();
                diagnostic.step = error
                    .downcast_ref::<InitStepError>()
                    .map(|wrapper| wrapper.0);
                diagnostic.with_recorded_stage()
            }
        }
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
    pub fn render_json(&self) -> String {
        serde_json::json!({
            "error": self.code.as_str(),
            "terminal": true,
            "retry_after": self.retry_after_rfc3339(),
            "failed_stage": self.stage,
            "failed_step": self.step.map(InitFailedStep::as_str),
        })
        .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use chrono::TimeDelta;

    /// Serializes tests that read or write the process-global stage tracker.
    static STAGE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

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
                "failed_step": serde_json::Value::Null,
                "failed_stage": null,
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
            step: None,
            code: SafeDiagnosticCode::AcmeRateLimited,
            retry_after: Some(deadline),
            stage: Some("provisioning static tls certificate"),
        };
        let rendered = diagnostic.render_json();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&rendered).unwrap(),
            serde_json::json!({
                "error": "acme_rate_limited",
                "terminal": true,
                "retry_after": deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "failed_step": serde_json::Value::Null,
                "failed_stage": "provisioning static tls certificate",
            })
        );
        assert!(rendered.contains(&deadline.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)));
    }

    #[test]
    fn step_vocabulary_round_trips_byte_exactly() {
        for step in [
            InitFailedStep::TlsDecodeFailed,
            InitFailedStep::TlsValidateFailed,
            InitFailedStep::TlsWriteFailed,
            InitFailedStep::TlsHandoffFailed,
            InitFailedStep::BindSentinelFailed,
            InitFailedStep::BindSourceFailed,
            InitFailedStep::BindTargetCreateFailed,
            InitFailedStep::BindMountFailed,
        ] {
            assert_eq!(InitFailedStep::parse_str(step.as_str()), Some(step));
        }
        for lookalike in [
            "",
            " tls_decode_failed",
            "tls_decode_failed ",
            "TLS_DECODE_FAILED",
            "tls_decode_failed2",
            "tls-decode-failed",
            "tls_decode",
            "enclava_init_failed",
            "failed_step:tls_write_failed",
            "tls_handoff_failed tls_handoff_failed",
        ] {
            assert_eq!(
                InitFailedStep::parse_str(lookalike),
                None,
                "lookalike must stay unrecognized: {lookalike:?}"
            );
        }
    }

    #[test]
    fn child_exit_code_table_round_trips() {
        // The bind child's fixed table: only the three child-eligible
        // steps map (below 128 on purpose), and only those codes map back.
        for (step, code) in [
            (InitFailedStep::BindSourceFailed, 3u8),
            (InitFailedStep::BindTargetCreateFailed, 4),
            (InitFailedStep::BindMountFailed, 5),
        ] {
            assert_eq!(step.child_exit_code(), Some(code));
            assert_eq!(
                InitFailedStep::from_child_exit_code(code as i32),
                Some(step)
            );
        }
        // Every other step stays untyped on the child boundary.
        for step in [
            InitFailedStep::TlsDecodeFailed,
            InitFailedStep::TlsValidateFailed,
            InitFailedStep::TlsWriteFailed,
            InitFailedStep::TlsHandoffFailed,
            InitFailedStep::BindSentinelFailed,
        ] {
            assert_eq!(step.child_exit_code(), None);
        }
        // exit 1, 2, 6, 0, negative, and signal-range codes stay untyped.
        for code in [0, 1, 2, 6, 127, 130, -1] {
            assert_eq!(
                InitFailedStep::from_child_exit_code(code),
                None,
                "code {code} must stay untyped"
            );
        }
    }

    #[test]
    fn diagnose_recovers_a_typed_step_and_renders_the_literal_contract() {
        let _stage = STAGE_LOCK.lock().unwrap();
        set_last_stage(None);
        let error = anyhow!("mkdir /data: Read-only file system")
            .context(InitStepError(InitFailedStep::BindTargetCreateFailed));
        let diagnostic = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnostic.code, SafeDiagnosticCode::EnclavaInitFailed);
        assert_eq!(
            diagnostic.step(),
            Some(InitFailedStep::BindTargetCreateFailed)
        );
        let rendered = diagnostic.render_json();
        // The whole rendered string, compared against the rebuilt literal
        // contract: no path, no errno text, no provider text ever rides it.
        assert_eq!(
            rendered,
            "{\"error\":\"enclava_init_failed\",\"failed_stage\":null,\"failed_step\":\"bind_target_create_failed\",\"retry_after\":null,\"terminal\":true}"
        );
    }

    #[test]
    fn diagnose_keeps_failed_step_null_for_uninstrumented_failures() {
        let _stage = STAGE_LOCK.lock().unwrap();
        set_last_stage(None);
        let error = anyhow!("opening /some/path failed: Permission denied (os error 13)");
        let diagnostic = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnostic.code, SafeDiagnosticCode::EnclavaInitFailed);
        assert_eq!(diagnostic.step(), None);
        assert!(
            !diagnostic.render_json().contains("failed_step\":\""),
            "no step literal may appear: {}",
            diagnostic.render_json()
        );
    }

    #[test]
    fn a_broker_failure_keeps_its_acme_code_and_carries_no_step() {
        let _stage = STAGE_LOCK.lock().unwrap();
        set_last_stage(None);
        // Even a step context wrapped around a broker failure must not
        // attach a step: the broker's typed contract classifies it.
        let error = anyhow::Error::new(crate::tls_certificate::TlsBrokerFailure {
            diagnostic: SafeBootstrapDiagnostic::acme_failed(),
        })
        .context(InitStepError(InitFailedStep::TlsValidateFailed));
        let diagnostic = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(
            diagnostic.code,
            SafeDiagnosticCode::AcmeCertificateIssuanceFailed
        );
        assert_eq!(diagnostic.step(), None);
        assert!(
            !diagnostic.render_json().contains("failed_step\":\""),
            "broker failures carry no step: {}",
            diagnostic.render_json()
        );
    }

    #[test]
    fn init_step_error_display_is_content_free() {
        assert_eq!(
            InitStepError(InitFailedStep::TlsDecodeFailed).to_string(),
            "init step tls_decode_failed"
        );
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
        let _stage = STAGE_LOCK.lock().unwrap();
        set_last_stage(Some("provisioning static tls certificate"));
        let deadline = now() + TimeDelta::minutes(30);
        let diagnostic = SafeBootstrapDiagnostic {
            step: None,
            code: SafeDiagnosticCode::AcmeRateLimited,
            retry_after: Some(deadline),
            stage: None,
        };
        let error = anyhow::Error::new(crate::tls_certificate::TlsBrokerFailure { diagnostic })
            .context("provisioning static TLS certificate")
            .context("outer context with SYNTHETIC-CHAIN-SENTINEL text");

        let diagnosed = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnosed.code, SafeDiagnosticCode::AcmeRateLimited);
        assert_eq!(diagnosed.retry_after, Some(deadline));
        // The stage comes from the tracker record_stage writes, not a
        // diagnose argument. A caller cannot pass a different string.
        assert_eq!(
            diagnosed.stage(),
            Some("provisioning static tls certificate")
        );
        // The rendered output carries only the safe fields, never the chain.
        let rendered = diagnosed.render_json();
        assert!(!rendered.contains("SYNTHETIC-CHAIN-SENTINEL"));
        assert!(!rendered.contains("outer context"));
        set_last_stage(None);
    }

    #[test]
    fn unknown_errors_degrade_to_generic_without_chain_text() {
        let _stage = STAGE_LOCK.lock().unwrap();
        set_last_stage(None);
        let error = anyhow!("reading supplied value /state/secret-path: SYNTHETIC-IO-SENTINEL")
            .context("opening luks volumes");
        let diagnosed = SafeBootstrapDiagnostic::diagnose(&error);
        assert_eq!(diagnosed.code, SafeDiagnosticCode::EnclavaInitFailed);
        assert_eq!(diagnosed.retry_after, None);
        assert_eq!(diagnosed.stage(), None);
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
