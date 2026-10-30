//! Loads the launch identities a tenant TEE may attest to, and binds SNP-attested channels (`enclava-snp`) to them.
//! CRL freshness follows the CLI policy: required for unlock transitions, not ordinary attested operations.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use enclava_common::descriptor::{DeploymentDescriptor, LaunchIdentity};
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

#[derive(Debug, sqlx::FromRow)]
struct AdmittedArtifactRow {
    deploy_id: uuid::Uuid,
    descriptor_payload: serde_json::Value,
}

/// Load the launch identities the app's live TEE may legitimately attest to.
/// Empty when no workload is admitted.
///
/// Authority is exactly the app's required KBS policy authority (kbs.rs): the
/// artifact of the latest admitted operation (a rollback's older source
/// artifact included), the prior healthy workload while a replacement is
/// unconfirmed, and every possibly-serving generation of a deleting app.
/// Held, withdrawn, removed-signer and artifact-less operations contribute
/// nothing, so nothing is sent to a TEE KBS would not admit.
pub(crate) async fn load_admissible_launch_identities(
    pool: &sqlx::PgPool,
    app: &crate::models::App,
) -> Result<Vec<LaunchIdentity>, TeeAttestError> {
    let artifacts = crate::kbs::load_required_app_artifacts(pool, app.id)
        .await
        .map_err(|_| TeeAttestError::Storage)?;
    if artifacts.is_empty() {
        return Ok(Vec::new());
    }
    let core_hashes = artifacts
        .iter()
        .map(|artifact| hex::decode(&artifact.metadata.descriptor_core_hash))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TeeAttestError::Storage)?;
    let rows = sqlx::query_as::<_, AdmittedArtifactRow>(
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
        // deploy; these comparisons bind it to THIS app row so a cataloguing
        // anomaly cannot attest another app's TEE into scope.
        if descriptor.app_id != app.id
            || descriptor.org_id != app.org_id
            || descriptor.deploy_id != row.deploy_id
        {
            return Err(rejected(
                "stored deployment identity does not match the app",
            ));
        }
        identities.push(descriptor.launch_identity());
    }
    Ok(identities)
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
    identities: &[LaunchIdentity],
    kds_base_url: Option<&str>,
) -> Result<reqwest::Client, TeeAttestError> {
    let url = format!("https://{domain}");
    let timeout = Duration::from_secs(30);
    // One KDS attempt: retry backoff must not outlast the teardown deadline.
    let kds = enclava_snp::Kds {
        base_url: kds_base_url.unwrap_or(enclava_snp::DEFAULT_AMD_KDS_BASE_URL),
        ca_bundle_path: None,
        max_attempts: 1,
    };
    let (attested, resolve_ip) =
        match enclava_snp::attest_tee(&url, resolve_ip, timeout, &kds, identities).await {
            Err(AttestError::TcpConnect) if resolve_ip.is_some() => (
                enclava_snp::attest_tee(&url, None, timeout, &kds, identities).await?,
                None,
            ),
            result => (result?, resolve_ip),
        };
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
