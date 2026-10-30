//! Binds SNP-attested TEE channels (`enclava-snp`) to the app's stored launch identities.
//! CRL freshness follows the CLI policy: required for unlock transitions, not ordinary attested operations.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use enclava_common::descriptor::{DeploymentDescriptor, FirmwareMeasurement};
use enclava_snp::AttestError;

/// Coarse, content-free failure class (see [`AttestError`]).
#[derive(Debug)]
pub(crate) enum TeeAttestError {
    Attest(AttestError),
    /// Authoritative deployment identity unavailable or malformed in
    /// storage; indistinguishable from a broken dependency to the caller.
    Storage,
}

impl TeeAttestError {
    pub(crate) fn category(&self) -> &'static str {
        match self {
            Self::Attest(error) => error.category(),
            Self::Storage => "storage",
        }
    }

    /// The static, content-free rejection reason; safe for warn diagnostics.
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::Attest(error) => error.reason(),
            Self::Storage => "deployment identity storage unavailable",
        }
    }
}

impl From<AttestError> for TeeAttestError {
    fn from(error: AttestError) -> Self {
        Self::Attest(error)
    }
}

fn rejected(reason: &'static str) -> TeeAttestError {
    TeeAttestError::Attest(AttestError::Attestation(reason))
}

/// Expected launch identity for one admissible live deployment, derived from
/// the signed deployment descriptor persisted at deploy time.
#[derive(Debug)]
pub(crate) struct TeardownIdentity {
    pub expected_cc_init_data_hash: [u8; 32],
    pub expected_firmware_measurement: FirmwareMeasurement,
}

#[derive(Debug, sqlx::FromRow)]
struct TeardownArtifactRow {
    deploy_id: uuid::Uuid,
    descriptor_payload: serde_json::Value,
}

/// Load the deployment identities the live TEE may legitimately attest to.
///
/// Authority is exactly the app's required KBS policy authority (kbs.rs): the
/// artifact of the latest admitted operation (a rollback's older source
/// artifact included), the prior healthy workload while a replacement is
/// unconfirmed, and every possibly-serving generation of a deleting app.
/// Held, withdrawn, removed-signer and artifact-less operations contribute
/// nothing, so a token is never minted for an identity KBS would not admit.
pub(crate) async fn load_teardown_identities(
    pool: &sqlx::PgPool,
    app: &crate::models::App,
) -> Result<Vec<TeardownIdentity>, TeeAttestError> {
    let artifacts = crate::kbs::load_required_app_artifacts(pool, app.id)
        .await
        .map_err(|_| TeeAttestError::Storage)?;
    if artifacts.is_empty() {
        return Err(rejected("no admitted workload authority"));
    }
    let core_hashes = artifacts
        .iter()
        .map(|artifact| hex::decode(&artifact.metadata.descriptor_core_hash))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TeeAttestError::Storage)?;
    let rows = sqlx::query_as::<_, TeardownArtifactRow>(
        "SELECT deploy_id, descriptor_payload
           FROM workload_artifacts
          WHERE app_id = $1 AND descriptor_core_hash = ANY($2)",
    )
    .bind(app.id)
    .bind(&core_hashes)
    .fetch_all(pool)
    .await
    .map_err(|_| TeeAttestError::Storage)?;
    if rows.len() != core_hashes.len() {
        return Err(TeeAttestError::Storage);
    }

    let mut identities = Vec::with_capacity(rows.len());
    for row in rows {
        let descriptor: DeploymentDescriptor =
            serde_json::from_value(row.descriptor_payload).map_err(|_| TeeAttestError::Storage)?;
        // The stored artifact is already signature- and hash-validated at
        // deploy; these comparisons bind it to THIS delete's app row so a
        // cataloguing anomaly cannot attest another app's TEE into scope.
        if descriptor.app_id != app.id
            || descriptor.org_id != app.org_id
            || descriptor.deploy_id != row.deploy_id
        {
            return Err(rejected(
                "stored deployment identity does not match the deleting app",
            ));
        }
        identities.push(TeardownIdentity {
            expected_cc_init_data_hash: descriptor.expected_cc_init_data_hash,
            expected_firmware_measurement: descriptor.expected_firmware_measurement,
        });
    }
    Ok(identities)
}

fn report_is_bound_to_deployment(
    host_data: &[u8; 32],
    measurement: &[u8; 48],
    identities: &[TeardownIdentity],
) -> bool {
    identities.iter().any(|identity| {
        *host_data == identity.expected_cc_init_data_hash
            && identity
                .expected_firmware_measurement
                .matches_report(measurement)
    })
}

/// Attest the TEE endpoint and return an SPKI-pinned HTTP client for it.
///
/// Tries the resolved tenant-Gateway address first (hairpin-blocked
/// deployments cannot reach their own external edge); a TCP-connect failure
/// there retries against the public origin exactly like the CLI's
/// `attest_receipt_key`. Every other failure class fails closed — there is
/// no unauthenticated fallback because the only caller sends a protected
/// bearer token over the returned channel.
pub(crate) async fn attest_teardown_channel(
    domain: &str,
    resolve_ip: Option<IpAddr>,
    identities: &[TeardownIdentity],
    kds_base_url: Option<&str>,
) -> Result<reqwest::Client, TeeAttestError> {
    if identities.is_empty() {
        return Err(rejected(
            "no signed deployment identity to bind TEE evidence",
        ));
    }
    let url = format!("https://{domain}");
    let timeout = Duration::from_secs(30);
    // One KDS attempt: retry backoff must not outlast the teardown deadline.
    let kds = enclava_snp::Kds {
        base_url: kds_base_url.unwrap_or(enclava_snp::DEFAULT_AMD_KDS_BASE_URL),
        ca_bundle_path: None,
        max_attempts: 1,
    };
    let (attested, resolve_ip) =
        match enclava_snp::attest_tee(&url, resolve_ip, timeout, &kds).await {
            Err(AttestError::TcpConnect) if resolve_ip.is_some() => (
                enclava_snp::attest_tee(&url, None, timeout, &kds).await?,
                None,
            ),
            result => (result?, resolve_ip),
        };
    if !report_is_bound_to_deployment(&attested.host_data, &attested.measurement, identities) {
        return Err(rejected(
            "SNP launch identity does not bind a live deployment",
        ));
    }
    let mut builder = reqwest::Client::builder()
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .use_preconfigured_tls(attested.tls_config);
    if let Some(ip) = resolve_ip {
        builder = builder.resolve(&attested.host, SocketAddr::new(ip, attested.port));
    }
    builder
        .build()
        .map_err(|_| TeeAttestError::Attest(AttestError::Transport))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST_DATA: [u8; 32] = [7; 32];
    const MEASUREMENT: [u8; 48] = [9; 48];

    fn identity(host_data: [u8; 32], measurement: FirmwareMeasurement) -> TeardownIdentity {
        TeardownIdentity {
            expected_cc_init_data_hash: host_data,
            expected_firmware_measurement: measurement,
        }
    }

    #[test]
    fn launch_identity_must_match_a_live_deployment_host_data_and_firmware() {
        let bound = identity(HOST_DATA, FirmwareMeasurement::Full(MEASUREMENT));
        assert!(report_is_bound_to_deployment(
            &HOST_DATA,
            &MEASUREMENT,
            &[bound]
        ));

        // A valid TEE launch whose HOST_DATA matches no admissible deployment
        // (wrong app, or a superseded deployment outside the live set).
        let foreign = identity([0xAA; 32], FirmwareMeasurement::Full(MEASUREMENT));
        assert!(!report_is_bound_to_deployment(
            &HOST_DATA,
            &MEASUREMENT,
            &[foreign]
        ));

        // A different measured firmware must not receive a teardown token.
        let other_firmware = identity(HOST_DATA, FirmwareMeasurement::Full([0xAB; 48]));
        assert!(!report_is_bound_to_deployment(
            &HOST_DATA,
            &MEASUREMENT,
            &[other_firmware]
        ));
        assert!(!report_is_bound_to_deployment(
            &HOST_DATA,
            &MEASUREMENT,
            &[]
        ));
    }
}
