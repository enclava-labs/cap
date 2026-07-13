use std::sync::LazyLock;

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use prometheus::{Counter, CounterVec, Encoder, Gauge, IntGauge, Opts, Registry, TextEncoder};

use crate::state::AppState;

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let registry = Registry::new();
    registry
        .register(Box::new(KBS_AUTHORIZATION_OUTBOX_PENDING.clone()))
        .unwrap();
    registry
        .register(Box::new(KBS_AUTHORIZATION_PUBLICATION_TOTAL.clone()))
        .unwrap();
    registry
        .register(Box::new(KBS_AUTHORIZATION_PUBLICATION_LAG_SECONDS.clone()))
        .unwrap();
    registry
        .register(Box::new(KBS_AUTHORIZATION_RECONCILIATION_TOTAL.clone()))
        .unwrap();
    registry
        .register(Box::new(ARTIFACT_BUNDLE_FETCH_TOTAL.clone()))
        .unwrap();
    registry
        .register(Box::new(ARTIFACT_BUNDLE_DIGEST_MISMATCH_TOTAL.clone()))
        .unwrap();
    registry
        .register(Box::new(ATTESTATION_CLAIM_CONFLICT_TOTAL.clone()))
        .unwrap();
    registry
        .register(Box::new(LEGACY_KBS_POLICY_FORMAT_SEEN_TOTAL.clone()))
        .unwrap();
    registry
});

static KBS_AUTHORIZATION_OUTBOX_PENDING: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::with_opts(Opts::new(
        "kbs_authorization_outbox_pending",
        "Pending or failed KBS authorization outbox operations",
    ))
    .unwrap()
});

static KBS_AUTHORIZATION_PUBLICATION_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "kbs_authorization_publication_total",
            "KBS authorization publication outcomes",
        ),
        &["result"],
    )
    .unwrap()
});

static KBS_AUTHORIZATION_PUBLICATION_LAG_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    Gauge::with_opts(Opts::new(
        "kbs_authorization_publication_lag_seconds",
        "Age of the oldest pending or failed KBS authorization outbox event",
    ))
    .unwrap()
});

static KBS_AUTHORIZATION_RECONCILIATION_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "kbs_authorization_reconciliation_total",
            "Active KBS authorization read-back reconciliation outcomes",
        ),
        &["result"],
    )
    .unwrap()
});

static ARTIFACT_BUNDLE_FETCH_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    CounterVec::new(
        Opts::new(
            "artifact_bundle_fetch_total",
            "Attested workload artifact bundle fetch outcomes",
        ),
        &["result"],
    )
    .unwrap()
});

static ARTIFACT_BUNDLE_DIGEST_MISMATCH_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    Counter::with_opts(Opts::new(
        "artifact_bundle_digest_mismatch_total",
        "Stored or returned artifact bundle digest mismatches",
    ))
    .unwrap()
});

static ATTESTATION_CLAIM_CONFLICT_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    Counter::with_opts(Opts::new(
        "attestation_claim_conflict_total",
        "Attestation tokens denied for conflicting recognized claim values",
    ))
    .unwrap()
});

static LEGACY_KBS_POLICY_FORMAT_SEEN_TOTAL: LazyLock<Counter> = LazyLock::new(|| {
    Counter::with_opts(Opts::new(
        "legacy_kbs_policy_format_seen_total",
        "Runtime encounters with legacy dynamic KBS policy formats",
    ))
    .unwrap()
});

pub fn publication(result: &'static str) {
    KBS_AUTHORIZATION_PUBLICATION_TOTAL
        .with_label_values(&[result])
        .inc();
}

pub fn authorization_reconciliation(result: &'static str) {
    KBS_AUTHORIZATION_RECONCILIATION_TOTAL
        .with_label_values(&[result])
        .inc();
}

pub fn artifact_fetch(result: &'static str) {
    ARTIFACT_BUNDLE_FETCH_TOTAL
        .with_label_values(&[result])
        .inc();
}

pub fn artifact_digest_mismatch() {
    ARTIFACT_BUNDLE_DIGEST_MISMATCH_TOTAL.inc();
}

pub fn claim_conflict() {
    ATTESTATION_CLAIM_CONFLICT_TOTAL.inc();
}

pub fn legacy_policy_seen() {
    LEGACY_KBS_POLICY_FORMAT_SEEN_TOTAL.inc();
}

pub async fn refresh_outbox(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    let (pending, oldest_lag): (i64, Option<f64>) = sqlx::query_as(
        "SELECT count(*),
                EXTRACT(EPOCH FROM now() - min(created_at))::double precision
         FROM kbs_authorization_outbox
         WHERE state IN ('pending', 'failed')",
    )
    .fetch_one(pool)
    .await?;
    KBS_AUTHORIZATION_OUTBOX_PENDING.set(pending);
    KBS_AUTHORIZATION_PUBLICATION_LAG_SECONDS.set(oldest_lag.unwrap_or(0.0).max(0.0));
    Ok(())
}

pub async fn handler(State(state): State<AppState>) -> impl IntoResponse {
    if refresh_outbox(&state.db).await.is_err() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "metrics database query failed",
        )
            .into_response();
    }
    let families = REGISTRY.gather();
    let mut body = Vec::new();
    if TextEncoder::new().encode(&families, &mut body).is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "metrics encoding failed").into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, TextEncoder::new().format_type())],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_metric_names_are_registered() {
        publication("test");
        authorization_reconciliation("exact");
        artifact_fetch("test");
        artifact_digest_mismatch();
        claim_conflict();
        legacy_policy_seen();
        let mut body = Vec::new();
        TextEncoder::new()
            .encode(&REGISTRY.gather(), &mut body)
            .unwrap();
        let text = String::from_utf8(body).unwrap();
        for name in [
            "kbs_authorization_outbox_pending",
            "kbs_authorization_publication_total",
            "kbs_authorization_publication_lag_seconds",
            "kbs_authorization_reconciliation_total",
            "artifact_bundle_fetch_total",
            "artifact_bundle_digest_mismatch_total",
            "attestation_claim_conflict_total",
            "legacy_kbs_policy_format_seen_total",
        ] {
            assert!(text.contains(name), "missing metric {name}");
        }
    }
}
