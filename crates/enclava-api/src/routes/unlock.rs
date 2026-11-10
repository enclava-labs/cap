//! Unlock metadata routes.
//!
//! The actual unlock happens CLI -> TEE direct. These routes provide metadata.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use enclava_common::canonical::ce_v1_bytes;
use enclava_engine::types::LogEncryptionConfig;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::auth::scopes;
use crate::models::{App, UnlockMode};
use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct UnlockStatusResponse {
    pub unlock_mode: String,
    pub tee_url: String,
    pub ownership_state: Option<String>,
    /// The generation `update_unlock_mode` locks, plus the stored primary
    /// shape that may be signed. Hosted `GET /apps/{name}/deployments` is a
    /// different table and must not be substituted for this object.
    pub locked_generation: UnlockLockedGeneration,
}

/// Wire marker. A hosted deployment row does not carry this source.
pub const LOCKED_GENERATION_SOURCE: &str = "apply_job_generation";

const LATEST_APPLY_GENERATION_SQL: &str = "SELECT deployment.id, deployment.status::text, \
     deployment.image_digest, deployment.spec_snapshot \
     FROM deployments AS deployment \
     JOIN deployment_apply_jobs AS apply_job \
       ON apply_job.deployment_id = deployment.id \
     WHERE deployment.app_id = $1 \
     ORDER BY apply_job.generation DESC \
     LIMIT 1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlockLockedGenerationResources {
    pub cpu: String,
    pub memory: String,
    pub storage: String,
    pub tls_storage: String,
}

/// CAP app identity `validate_deployment_inputs` compares. A hosted app
/// projection is not this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlockLockedGenerationApp {
    pub id: Uuid,
    pub name: String,
    pub namespace: String,
    pub service_account: String,
    pub domain: String,
    pub tee_domain: String,
    pub custom_domain: Option<String>,
    pub tenant_instance_identity_hash: String,
    pub bootstrap_owner_pubkey_hash: String,
    pub signer_identity_subject: String,
    pub signer_identity_issuer: String,
}

/// Signable view of the row the unlock handler locks.
///
/// `acceptable` is true only when that handler's generation predicate passes
/// and the stored primary can be signed without inventing port, command,
/// storage paths, or a digest. Refused generations omit the signable fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnlockLockedGeneration {
    pub source: String,
    pub acceptable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_security_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<UnlockLockedGenerationResources>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app: Option<UnlockLockedGenerationApp>,
    /// Generation `spec_snapshot.log_encryption`. Null is an explicit
    /// no-recipient generation. A refused snapshot also serializes null; clients
    /// must use `acceptable`, not this field, to decide whether to sign.
    pub log_encryption: Option<enclava_engine::types::LogEncryptionConfig>,
}

type ApplyGenerationRow = (Uuid, String, Option<String>, serde_json::Value);

fn refused_generation(
    deployment_id: Option<Uuid>,
    status: Option<String>,
    reason: &str,
) -> UnlockLockedGeneration {
    UnlockLockedGeneration {
        source: LOCKED_GENERATION_SOURCE.to_string(),
        acceptable: false,
        refusal: Some(reason.to_string()),
        deployment_id,
        status,
        image_digest: None,
        image_ref: None,
        container_name: None,
        port: None,
        command: None,
        storage_paths: None,
        workload_security_profile: None,
        resources: None,
        app: None,
        log_encryption: None,
    }
}

/// An unlock-mode redeploy must not pin the legacy omit-claim render when the
/// locked generation has a log recipient. A proxy that rewrites that field to
/// null would otherwise commit encrypted logging off after the wrap is gone.
fn reject_omitted_log_recipient(
    omit_log_encryption_claim: bool,
    log_encryption: Option<&enclava_engine::types::LogEncryptionConfig>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if log_encryption.is_some() && omit_log_encryption_claim {
        return Err(unlock_transition_conflict(
            "signed descriptor omitted the locked generation log recipient",
        ));
    }
    Ok(())
}

/// The predicate `update_unlock_mode` enforces after it has a primary and a
/// latest apply-job generation. `None` means that handler will not reject
/// the generation itself.
#[allow(clippy::too_many_arguments)]
fn generation_conflict_reason(
    status: &str,
    generation_digest: Option<&str>,
    primary_digest: Option<&str>,
    spec_snapshot: &serde_json::Value,
    cpu: &str,
    memory: &str,
    storage: &str,
    tls_storage: &str,
    primary_profile: &str,
) -> Option<&'static str> {
    if matches!(status, "pending" | "applying" | "watching") {
        return Some("current deployment generation is still in progress");
    }
    if generation_digest != primary_digest {
        return Some("current runtime does not match its deployment generation");
    }
    let Some(resolved) = spec_snapshot.get("resolved_resources") else {
        return Some(
            "current deployment predates exact resource snapshots; deploy a current generation first",
        );
    };
    let exact = |field: &str, expected: &str| {
        resolved.get(field).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !exact("cpu", cpu)
        || !exact("memory", memory)
        || !exact("storage", storage)
        || !exact("tls_storage", tls_storage)
    {
        return Some("current resource authority does not match its deployment generation");
    }
    if spec_snapshot
        .get("workload_security_profile")
        .and_then(serde_json::Value::as_str)
        != Some(primary_profile)
    {
        return Some("current workload security profile does not match its deployment generation");
    }
    None
}

fn signable_port(port: Option<i32>) -> Option<u16> {
    u16::try_from(port?).ok().filter(|port| *port > 0)
}

fn signable_command(raw: Option<&str>) -> Option<Vec<String>> {
    let argv = serde_json::from_str::<Vec<String>>(raw?.trim()).ok()?;
    if argv.is_empty() || argv.iter().any(|arg| arg.is_empty()) {
        return None;
    }
    Some(argv)
}

fn signable_storage_paths(paths: Option<&[String]>) -> Result<Vec<String>, &'static str> {
    let Some(paths) = paths else {
        return Err("stored primary storage paths are missing");
    };
    if paths.iter().any(|path| path.is_empty()) {
        return Err("stored primary storage paths contain an empty path");
    }
    // Match descriptor_storage_paths: the platform /state mount is not a
    // user path, and an empty remainder is a valid no-extra-mount workload.
    Ok(paths
        .iter()
        .filter(|path| path.as_str() != "/state")
        .cloned()
        .collect())
}

/// The locked primary in the form a signed unlock render uses: JSON argv,
/// port > 0, and user storage paths with `/state` removed. Persisting this
/// form, not the raw column and not the raw descriptor, is what keeps the
/// apply job's cc_init hash equal to the commit-time pin.
fn normalized_locked_workload(
    primary: &crate::models::AppContainer,
) -> Result<(String, i32, Vec<String>), &'static str> {
    let command = signable_command(primary.command.as_deref())
        .ok_or("stored primary command is missing or not a JSON argv")?;
    let command_json = serde_json::to_string(&command)
        .map_err(|_| "stored primary command is missing or not a JSON argv")?;
    let port = i32::from(
        signable_port(primary.port)
            .ok_or("stored primary omitted port; refusing to assume 8080")?,
    );
    let storage_paths = signable_storage_paths(primary.storage_paths.as_deref())?;
    Ok((command_json, port, storage_paths))
}

/// The signed OCI spec also carries the primary name and CPU/memory limits.
/// Command, port, and storage paths are checked separately. A proxy that
/// rewrites the name or limits in both status reads would otherwise pass
/// this preview, then have the apply job render the locked rows under a
/// policy that describes the rewritten shape.
fn signed_identity_matches_locked_runtime(
    primary: &crate::models::AppContainer,
    resources: &crate::models::AppResources,
    env: &[enclava_common::descriptor::EnvVar],
    limits: &[enclava_common::descriptor::EnvVar],
) -> Result<(), &'static str> {
    let signed_name = env
        .iter()
        .find(|var| var.name == "ENCLAVA_CONTAINER_NAME")
        .map(|var| var.value.as_str())
        .filter(|value| !value.is_empty());
    let Some(signed_name) = signed_name else {
        return Err("signed descriptor omitted ENCLAVA_CONTAINER_NAME");
    };
    if signed_name != primary.name {
        return Err("signed descriptor container name does not match the locked primary");
    }
    let limit = |name: &str| {
        limits
            .iter()
            .find(|var| var.name == name)
            .map(|var| var.value.as_str())
            .filter(|value| !value.is_empty())
    };
    let Some(cpu) = limit("cpu") else {
        return Err("signed descriptor omitted cpu limit");
    };
    let Some(memory) = limit("memory") else {
        return Err("signed descriptor omitted memory limit");
    };
    if cpu != resources.cpu_limit {
        return Err("signed descriptor cpu limit does not match the locked resources");
    }
    if memory != resources.memory_limit {
        return Err("signed descriptor memory limit does not match the locked resources");
    }
    Ok(())
}

/// The CLI signs the status object's command, port, and storage paths. A
/// proxy that rewrites both status reads can still present a different
/// descriptor at PUT, and `require_same_locked_generation` will not catch
/// it. Compare those fields to the locked primary before any container
/// write, using [`normalized_locked_workload`]. A raw equality check against
/// a `/state`-only column would refuse the honest empty list. A match is
/// then stored in that normalized form so the apply job does not render a
/// different cc_init than the one the commit pin checked.
fn signed_workload_matches_locked_primary(
    primary: &crate::models::AppContainer,
    signed_command: Option<&str>,
    signed_port: Option<i32>,
    signed_paths: Option<&[String]>,
) -> Result<(), &'static str> {
    if signed_command.is_none() && signed_port.is_none() && signed_paths.is_none() {
        return Ok(());
    }
    let (Some(signed_command), Some(signed_port), Some(signed_paths)) =
        (signed_command, signed_port, signed_paths)
    else {
        return Err("signed descriptor omitted command, port, or storage paths");
    };
    let (locked_command_json, locked_port, locked_paths) = normalized_locked_workload(primary)?;
    let locked_command = signable_command(Some(&locked_command_json))
        .ok_or("stored primary command is missing or not a JSON argv")?;
    let signed_argv = signable_command(Some(signed_command))
        .ok_or("signed descriptor command is missing or not a JSON argv")?;
    if signed_argv != locked_command {
        return Err("signed descriptor command does not match the locked primary");
    }
    let Some(normalized_signed_port) = signable_port(Some(signed_port)) else {
        return Err("signed descriptor port does not match the locked primary");
    };
    if i32::from(normalized_signed_port) != locked_port {
        return Err("signed descriptor port does not match the locked primary");
    }
    let signed_normalized = signable_storage_paths(Some(signed_paths))?;
    if signed_normalized != locked_paths {
        return Err("signed descriptor storage paths do not match the locked primary");
    }
    Ok(())
}

fn signable_image_ref(image_ref: &str, digest: &str) -> bool {
    let Some(repository) = image_ref.strip_suffix(&format!("@{digest}")) else {
        return false;
    };
    !repository.is_empty()
        && !repository.ends_with('@')
        && enclava_common::validate::validate_image_digest(digest).is_ok()
}

/// Build the status object from the same rows the handler locks.
///
/// A missing generation is not filled in from the primary container. Callers
/// that cannot see this object must not remove the guest wrap.
fn locked_generation_snapshot(
    generation: Option<&ApplyGenerationRow>,
    primary: Option<&crate::models::AppContainer>,
    resources: Option<&crate::models::AppResources>,
    app: &crate::models::App,
) -> UnlockLockedGeneration {
    let Some(primary) = primary else {
        return refused_generation(None, None, "app has no primary container");
    };
    let Some(resources) = resources else {
        return refused_generation(None, None, "app has no resource record");
    };
    let Some(generation) = generation else {
        return refused_generation(None, None, "app has no deployment generation");
    };
    let profile = primary
        .workload_security_profile
        .clone()
        .unwrap_or_else(|| "restricted".to_string());
    if let Some(reason) = generation_conflict_reason(
        &generation.1,
        generation.2.as_deref(),
        primary.image_digest.as_deref(),
        &generation.3,
        &resources.cpu_limit,
        &resources.memory_limit,
        &resources.app_data_size,
        &resources.tls_data_size,
        &profile,
    ) {
        return refused_generation(Some(generation.0), Some(generation.1.clone()), reason);
    }
    let Some(digest) = primary.image_digest.clone() else {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored primary has no image digest",
        );
    };
    if !signable_image_ref(&primary.image_ref, &digest) {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored primary image is not digest-pinned to the locked generation",
        );
    }
    let Some(port) = signable_port(primary.port) else {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored primary omitted port; refusing to assume 8080",
        );
    };
    let Some(command) = signable_command(primary.command.as_deref()) else {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored primary command is missing or not a JSON argv",
        );
    };
    let storage_paths = match signable_storage_paths(primary.storage_paths.as_deref()) {
        Ok(paths) => paths,
        Err(reason) => {
            return refused_generation(Some(generation.0), Some(generation.1.clone()), reason);
        }
    };
    if profile
        .parse::<enclava_engine::types::WorkloadSecurityProfile>()
        .is_err()
    {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored workload security profile is invalid",
        );
    }
    if primary.name.trim().is_empty() {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored primary container name is empty",
        );
    }
    let Some(subject) = app
        .signer_identity_subject
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored app has no signer subject",
        );
    };
    let Some(issuer) = app
        .signer_identity_issuer
        .as_deref()
        .filter(|value| !value.is_empty())
    else {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored app has no signer issuer",
        );
    };
    if app.name.is_empty()
        || app.namespace.is_empty()
        || app.service_account.is_empty()
        || app.domain.is_empty()
        || app.tenant_instance_identity_hash.is_empty()
        || app.bootstrap_owner_pubkey_hash.is_empty()
    {
        return refused_generation(
            Some(generation.0),
            Some(generation.1.clone()),
            "stored app identity is incomplete",
        );
    }
    if let Some(reason) = crate::routes::deployments::runtime_reapply_status_error(app.status) {
        return refused_generation(Some(generation.0), Some(generation.1.clone()), reason);
    }
    let log_encryption =
        match serde_json::from_value::<Option<enclava_engine::types::LogEncryptionConfig>>(
            generation
                .3
                .get("log_encryption")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        ) {
            Ok(value) => value,
            Err(_) => {
                return refused_generation(
                    Some(generation.0),
                    Some(generation.1.clone()),
                    "stored log encryption metadata is invalid",
                );
            }
        };
    UnlockLockedGeneration {
        source: LOCKED_GENERATION_SOURCE.to_string(),
        acceptable: true,
        refusal: None,
        deployment_id: Some(generation.0),
        status: Some(generation.1.clone()),
        image_digest: Some(digest),
        image_ref: Some(primary.image_ref.clone()),
        container_name: Some(primary.name.clone()),
        port: Some(port),
        command: Some(command),
        storage_paths: Some(storage_paths),
        workload_security_profile: Some(profile),
        resources: Some(UnlockLockedGenerationResources {
            cpu: resources.cpu_limit.clone(),
            memory: resources.memory_limit.clone(),
            storage: resources.app_data_size.clone(),
            tls_storage: resources.tls_data_size.clone(),
        }),
        app: Some(UnlockLockedGenerationApp {
            id: app.id,
            name: app.name.clone(),
            namespace: app.namespace.clone(),
            service_account: app.service_account.clone(),
            domain: app.domain.clone(),
            tee_domain: app.tee_domain.clone().unwrap_or_else(|| app.domain.clone()),
            custom_domain: app.custom_domain.clone(),
            tenant_instance_identity_hash: app.tenant_instance_identity_hash.clone(),
            bootstrap_owner_pubkey_hash: app.bootstrap_owner_pubkey_hash.clone(),
            signer_identity_subject: subject.to_string(),
            signer_identity_issuer: issuer.to_string(),
        }),
        log_encryption,
    }
}

async fn load_unlock_locked_generation(
    db: &sqlx::PgPool,
    app: &crate::models::App,
) -> Result<UnlockLockedGeneration, (StatusCode, Json<serde_json::Value>)> {
    let primary: Option<crate::models::AppContainer> = sqlx::query_as(
        "SELECT * FROM app_containers WHERE app_id = $1 AND is_primary = true ORDER BY id LIMIT 1",
    )
    .bind(app.id)
    .fetch_optional(db)
    .await
    .map_err(|_| unlock_database_error())?;
    let resources: Option<crate::models::AppResources> =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app.id)
            .fetch_optional(db)
            .await
            .map_err(|_| unlock_database_error())?;
    let generation: Option<ApplyGenerationRow> = sqlx::query_as(LATEST_APPLY_GENERATION_SQL)
        .bind(app.id)
        .fetch_optional(db)
        .await
        .map_err(|_| unlock_database_error())?;
    let mut snapshot = locked_generation_snapshot(
        generation.as_ref(),
        primary.as_ref(),
        resources.as_ref(),
        app,
    );
    if snapshot.acceptable {
        let mut tx = db.begin().await.map_err(|_| unlock_database_error())?;
        let busy = crate::mutation_leases::desired_state_mutation_in_progress(&mut tx, app.id)
            .await
            .map_err(|_| unlock_database_error())?;
        tx.rollback().await.map_err(|_| unlock_database_error())?;
        if busy {
            snapshot = refused_generation(
                snapshot.deployment_id,
                snapshot.status,
                "app mutation already in progress",
            );
        }
    }
    Ok(snapshot)
}

#[derive(Debug, Deserialize)]
pub struct UpdateUnlockModeRequest {
    pub mode: String,
    pub transition_receipt: Option<SignedReceiptResponse>,
    pub transition_attestation: Option<TransitionReceiptAttestation>,
    #[serde(default)]
    pub customer_descriptor_blob: Option<String>,
    #[serde(default)]
    pub org_keyring_blob: Option<String>,
    #[serde(default)]
    pub signed_policy_artifact: Option<String>,
    /// Compare the signed descriptor to the locked primary and return without
    /// a receipt or a commit. The CLI calls this before it removes the guest
    /// wrap, so a rewritten status cannot strand the TEE.
    #[serde(default)]
    pub validate_only: bool,
}

#[derive(Debug, Serialize)]
pub struct UpdateUnlockModeResponse {
    pub app_name: String,
    pub unlock_mode: String,
    pub deployment_id: Option<Uuid>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedReceiptResponse {
    pub operation: String,
    pub payload: ReceiptPayloadView,
    pub receipt: ReceiptEnvelope,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReceiptPayloadView {
    pub purpose: String,
    pub app_id: String,
    pub resource_path: Option<String>,
    pub from_mode: Option<String>,
    pub to_mode: Option<String>,
    pub attestation_quote_sha256: Option<String>,
    pub new_value_sha256: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReceiptEnvelope {
    pub pubkey: String,
    pub pubkey_sha256: String,
    pub payload_canonical_bytes: String,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransitionReceiptAttestation {
    pub tee_domain: String,
    pub nonce: String,
    pub leaf_spki_sha256: String,
    pub receipt_pubkey_sha256: String,
    pub attestation_evidence_sha256: String,
    /// Raw AMD SNP quote and the DER certificate chain the client verified,
    /// so the API can independently verify the TEE launch evidence instead of
    /// trusting caller-supplied hash consistency.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quote: Option<TransitionSnpQuote>,
}

/// Raw SNP launch evidence for an unlock-mode transition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransitionSnpQuote {
    /// Raw 1184-byte AMD SNP attestation report, standard base64.
    pub report_b64: String,
    /// ARK certificate DER, standard base64. Must anchor to a pinned AMD root.
    pub ark_der_b64: String,
    /// ASK certificate DER, standard base64.
    pub ask_der_b64: String,
    /// VCEK certificate DER, standard base64.
    pub vcek_der_b64: String,
    /// ARK-signed AMD product CRL DER, standard base64, fetched from AMD
    /// KDS by the CLI. The API enforces certificate validity intervals,
    /// CRL signature/freshness, and the revoked-serial walk against it, so
    /// a retired ASK or VCEK can no longer certify a transition.
    pub crl_der_b64: String,
}

/// SHA-256 pins of the AMD ARK roots compiled into the `sev` crate the
/// platform CLI uses to anchor SNP chains (Milan, Genoa, Turin): the shared
/// anchor set lives in [`enclava_snp`].
use enclava_snp::{BUILTIN_AMD_ARK_SHA256_PINS, snp_guest_policy_allows_debug};

/// Maximum accepted size of a single submitted AMD certificate DER. Real
/// ARK/ASK/VCEK certificates are under 2 KiB; anything larger is rejected
/// before X.509 parsing.
const MAX_QUOTE_CERTIFICATE_DER_BYTES: usize = 16_384;

/// Maximum accepted AMD product CRL DER, in bytes. Deliberately larger
/// than the certificate bound: a mass ASK/VCEK revocation event — exactly
/// when this gate matters most — is the scenario where AMD's product CRL
/// grows, and rejecting an oversized (but ARK-signed, valid) CRL would
/// fail every transition platform-wide. Matches the CLI's KDS body-read
/// bound, so anything the CLI can submit the API can evaluate.
const MAX_QUOTE_CRL_DER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestedUnlockMode {
    Auto,
    Password,
}

impl RequestedUnlockMode {
    fn parse(mode: &str) -> Result<Self, String> {
        match mode {
            "auto" | "auto-unlock" => Ok(Self::Auto),
            "password" => Ok(Self::Password),
            _ => Err("invalid unlock mode: expected 'password' or 'auto-unlock'".to_string()),
        }
    }

    fn db_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Password => "password",
        }
    }

    fn api_value(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Password => "password",
        }
    }

    fn model_value(self) -> UnlockMode {
        match self {
            Self::Auto => UnlockMode::Auto,
            Self::Password => UnlockMode::Password,
        }
    }
}

fn current_mode(app: &App) -> RequestedUnlockMode {
    match app.unlock_mode {
        UnlockMode::Auto => RequestedUnlockMode::Auto,
        UnlockMode::Password => RequestedUnlockMode::Password,
    }
}

fn validate_transition(current: RequestedUnlockMode, requested: RequestedUnlockMode) -> bool {
    current == requested
        || matches!(
            (current, requested),
            (RequestedUnlockMode::Password, RequestedUnlockMode::Auto)
                | (RequestedUnlockMode::Auto, RequestedUnlockMode::Password)
        )
}

fn verify_transition_receipt(
    receipt: &SignedReceiptResponse,
    app: &App,
    current: RequestedUnlockMode,
    requested: RequestedUnlockMode,
) -> Result<VerifiedTransitionReceipt, String> {
    if receipt.operation != "unlock_mode_transition" {
        return Err("transition_receipt.operation".to_string());
    }
    if receipt.payload.purpose != "enclava-unlock-receipt-v1" {
        return Err("transition_receipt.payload.purpose".to_string());
    }
    if receipt.payload.app_id != app.id.to_string() {
        return Err("transition_receipt.payload.app_id".to_string());
    }
    if receipt.payload.resource_path.is_some() {
        return Err("transition_receipt.payload.resource_path".to_string());
    }
    if receipt.payload.from_mode.as_deref() != Some(current.api_value()) {
        return Err("transition_receipt.payload.from_mode".to_string());
    }
    if receipt.payload.to_mode.as_deref() != Some(requested.api_value()) {
        return Err("transition_receipt.payload.to_mode".to_string());
    }
    let attestation_quote_sha256_text = receipt
        .payload
        .attestation_quote_sha256
        .as_deref()
        .ok_or_else(|| "transition_receipt.payload.attestation_quote_sha256".to_string())?;
    let attestation_quote_sha256 = parse_hex32(
        "transition_receipt.payload.attestation_quote_sha256",
        attestation_quote_sha256_text,
    )?;
    if receipt.payload.new_value_sha256.is_some() {
        return Err("transition_receipt.payload.new_value_sha256".to_string());
    }
    let receipt_timestamp = DateTime::parse_from_rfc3339(&receipt.payload.timestamp)
        .map_err(|_| "transition_receipt.payload.timestamp".to_string())?
        .with_timezone(&Utc);

    let expected_payload = ce_v1_bytes(&[
        ("purpose", receipt.payload.purpose.as_bytes()),
        ("app_id", app.id.as_bytes()),
        ("from_mode", current.api_value().as_bytes()),
        ("to_mode", requested.api_value().as_bytes()),
        (
            "attestation_quote_sha256",
            attestation_quote_sha256.as_slice(),
        ),
        ("timestamp", receipt.payload.timestamp.as_bytes()),
    ]);
    let payload_bytes = B64
        .decode(&receipt.receipt.payload_canonical_bytes)
        .map_err(|_| "transition_receipt.payload_canonical_bytes".to_string())?;
    if payload_bytes != expected_payload {
        return Err("transition_receipt.payload_canonical_bytes".to_string());
    }

    let pubkey_vec = B64
        .decode(&receipt.receipt.pubkey)
        .map_err(|_| "transition_receipt.pubkey".to_string())?;
    let pubkey_bytes: [u8; 32] = pubkey_vec
        .try_into()
        .map_err(|_| "transition_receipt.pubkey".to_string())?;
    let pubkey_sha256 = hex::encode(Sha256::digest(pubkey_bytes));
    if receipt.receipt.pubkey_sha256 != pubkey_sha256 {
        return Err("transition_receipt.pubkey_sha256".to_string());
    }
    let pubkey_sha256_bytes = Sha256::digest(pubkey_bytes).to_vec();

    let signature_vec = B64
        .decode(&receipt.receipt.signature)
        .map_err(|_| "transition_receipt.signature".to_string())?;
    let signature_bytes: [u8; 64] = signature_vec
        .try_into()
        .map_err(|_| "transition_receipt.signature".to_string())?;
    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|_| "transition_receipt.pubkey".to_string())?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&payload_bytes, &signature)
        .map_err(|_| "transition_receipt.signature".to_string())?;

    Ok(VerifiedTransitionReceipt {
        receipt_timestamp,
        pubkey_sha256_bytes,
        attestation_quote_sha256,
    })
}

#[derive(Debug)]
struct VerifiedTransitionReceipt {
    receipt_timestamp: DateTime<Utc>,
    pubkey_sha256_bytes: Vec<u8>,
    attestation_quote_sha256: Vec<u8>,
}

fn parse_hex32(field: &'static str, value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(field.to_string());
    }
    hex::decode(trimmed).map_err(|_| field.to_string())
}

fn verify_transition_attestation(
    attestation: &TransitionReceiptAttestation,
    app: &App,
    verified_receipt: &VerifiedTransitionReceipt,
) -> Result<(), String> {
    let expected_domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    if attestation.tee_domain != expected_domain {
        return Err("transition_attestation.tee_domain".to_string());
    }

    let nonce = URL_SAFE_NO_PAD
        .decode(&attestation.nonce)
        .or_else(|_| B64.decode(&attestation.nonce))
        .map_err(|_| "transition_attestation.nonce".to_string())?;
    if nonce.len() != 32 {
        return Err("transition_attestation.nonce".to_string());
    }

    parse_hex32(
        "transition_attestation.leaf_spki_sha256",
        &attestation.leaf_spki_sha256,
    )?;
    let attested_receipt_key = parse_hex32(
        "transition_attestation.receipt_pubkey_sha256",
        &attestation.receipt_pubkey_sha256,
    )?;
    if attested_receipt_key != verified_receipt.pubkey_sha256_bytes {
        return Err("transition_attestation.receipt_pubkey_sha256".to_string());
    }

    let evidence_hash = parse_hex32(
        "transition_attestation.attestation_evidence_sha256",
        &attestation.attestation_evidence_sha256,
    )?;
    if evidence_hash != verified_receipt.attestation_quote_sha256 {
        return Err("transition_attestation.attestation_evidence_sha256".to_string());
    }

    Ok(())
}

/// Error type for API-side SNP quote verification on unlock-mode
/// transitions. The variants deliberately carry no caller-controlled detail.
#[derive(Debug, PartialEq, Eq)]
enum TransitionQuoteError {
    /// The request did not include the raw SNP quote.
    Missing,
    /// A submitted field failed decoding or a structural bound.
    Malformed,
    /// The AMD chain did not anchor to a pinned AMD root.
    UntrustedAnchor,
    /// Report signature / VCEK binding / report_data binding failed.
    InvalidEvidence,
    /// The quote does not match the evidence hash the receipt signed.
    EvidenceMismatch,
    /// The report's guest policy allows debug: not a confidential workload.
    DebugPolicy,
    /// Revocation/validity collateral was missing, malformed, stale, or it
    /// revoked the ASK/VCEK.
    RevocationRejected,
}

impl TransitionQuoteError {
    fn reason(&self) -> &'static str {
        match self {
            Self::Missing => "transition_attestation.quote required for unlock mode change",
            Self::Malformed => "transition_attestation.quote is malformed",
            Self::UntrustedAnchor => {
                "transition_attestation.quote chain is not anchored to a trusted AMD root"
            }
            Self::InvalidEvidence => "transition_attestation.quote failed SNP verification",
            Self::EvidenceMismatch => {
                "transition_attestation.quote does not match the receipt-signed evidence hash"
            }
            Self::DebugPolicy => {
                "transition_attestation.quote guest policy allows debug; not a confidential workload"
            }
            Self::RevocationRejected => {
                "transition_attestation.quote failed AMD revocation/validity checking"
            }
        }
    }
}

/// A transition receipt older than this is rejected. Without a window,
/// quote/receipt replay is bounded only by per-app receipt-timestamp
/// monotonicity and the unique receipt index, both of which permit a
/// first reuse of captured evidence.
const TRANSITION_RECEIPT_MAX_AGE_SECONDS: i64 = 15 * 60;

/// Maximum accepted age of the submitted AMD product CRL, in seconds.
/// Matches the appraiser policy bound (`revocation_max_age_seconds`) and
/// AMD's ~45-day CRL publication cadence; an older (or nextUpdate-lapsed)
/// CRL fails the transition closed.
const TRANSITION_REVOCATION_MAX_AGE_SECONDS: u64 = 3_888_000;

/// Trusted time for quote revocation math. Wall-clock now, clamped to a
/// floor: the CRL freshness window already bounds how old accepted
/// collateral can be, and a zero/negative reading (clock not yet set on a
/// freshly booted host) must reject rather than panic in u64 conversions.
fn quote_verification_now() -> u64 {
    let now = Utc::now();
    if now.timestamp() <= 0 {
        return 1;
    }
    now.timestamp() as u64
}

/// Tolerance for clock skew between the signing TEE and the API on
/// future-dated receipt timestamps.
const TRANSITION_RECEIPT_MAX_FUTURE_SKEW_SECONDS: i64 = 5 * 60;

/// Server-side freshness window for a transition receipt: the receipt must
/// have been signed within [`TRANSITION_RECEIPT_MAX_AGE_SECONDS`] of now
/// (and not be dated further ahead than the allowed skew).
fn transition_receipt_is_fresh(receipt_timestamp: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    // age = now - ts: a recent receipt has a small positive age; a slightly
    // future-dated one (clock skew) has a small negative age.
    let age_seconds = now.signed_duration_since(receipt_timestamp).num_seconds();
    (-TRANSITION_RECEIPT_MAX_FUTURE_SKEW_SECONDS..=TRANSITION_RECEIPT_MAX_AGE_SECONDS)
        .contains(&age_seconds)
}

/// Standard base64 of at most `max_der_bytes` bytes is exactly
/// `4 * ceil(max/3)` characters (padding included), so a longer string can
/// never decode to an in-bounds value. Checking the string length first
/// bounds the decode allocation: `base64::decode` allocates output
/// proportional to its input, and oversized caller-submitted quote fields
/// must be rejected by a length comparison, not by allocating for them
/// first.
fn decode_bounded_quote_b64(field: &str, max_der_bytes: usize) -> Option<Vec<u8>> {
    let max_b64_len = max_der_bytes.div_ceil(3) * 4;
    if field.len() > max_b64_len {
        return None;
    }
    B64.decode(field).ok()
}

/// Independently verify the raw AMD SNP quote bound to an unlock-mode
/// transition:
///
/// - the SHA-256 of the submitted report bytes equals the
///   `attestation_quote_sha256` the receipt signature covers, so the API
///   verifies exactly the evidence the receipt identified,
/// - the ARK/ASK/VCEK chain is internally consistent and anchored to one of
///   the pinned builtin AMD roots (the same anchor set the platform CLI
///   uses),
/// - the certificate validity intervals hold at `now_unix_seconds` and the
///   submitted ARK-signed product CRL is signature-valid, fresh, and does
///   not revoke the ASK or VCEK (`verify_amd_revocation`, the same
///   revocation gate the appraiser applies),
/// - the report's guest policy disables debug (a debug-enabled guest is
///   not confidential, mirroring the CLI's
///   `ensure_snp_report_production_policy`),
/// - the report is signed by the VCEK and the VCEK binds to the report's
///   chipID and reported TCB, and
/// - the guest-committed `report_data` binds the TEE domain, the caller
///   nonce, the observed TLS leaf SPKI, and the TEE receipt key -- the same
///   values `verify_transition_receipt`/`verify_transition_attestation`
///   validated, so a self-consistent package fabricated without a genuine
///   TEE cannot satisfy this check.
fn verify_transition_snp_quote(
    attestation: &TransitionReceiptAttestation,
    receipt: &SignedReceiptResponse,
    now_unix_seconds: u64,
) -> Result<(), TransitionQuoteError> {
    use enclava_verifier::{
        expected_report_data, parse_snp_report, verify_amd_certificate_chain,
        verify_amd_revocation, verify_snp_signature, verify_vcek_report_binding,
    };

    let quote = attestation
        .quote
        .as_ref()
        .ok_or(TransitionQuoteError::Missing)?;
    // Pre-decode length gate: base64 decoding allocates proportionally to
    // the submitted string, so bound the string length BEFORE decoding.
    // This keeps a repeated oversized submission from consuming memory and
    // CPU ahead of its inevitable rejection. The exact DER/report length
    // bounds are still enforced after decoding, below.
    let report_bytes =
        decode_bounded_quote_b64(&quote.report_b64, enclava_verifier::SNP_REPORT_BYTES)
            .ok_or(TransitionQuoteError::Malformed)?;
    if report_bytes.len() != enclava_verifier::SNP_REPORT_BYTES {
        return Err(TransitionQuoteError::Malformed);
    }
    // Bind the submitted quote bytes to the evidence hash the receipt
    // signed. The receipt's signature covers attestation_quote_sha256, so
    // this closes the gap where the caller submits evidence hash X in the
    // receipt while the API verifies an unrelated (genuine but different)
    // quote.
    let signed_evidence_hash = parse_hex32(
        "transition_receipt.payload.attestation_quote_sha256",
        receipt
            .payload
            .attestation_quote_sha256
            .as_deref()
            .unwrap_or(""),
    )
    .map_err(|_| TransitionQuoteError::Malformed)?;
    if Sha256::digest(&report_bytes).as_slice() != signed_evidence_hash.as_slice() {
        return Err(TransitionQuoteError::EvidenceMismatch);
    }

    let decode_cert = |field: &String| -> Result<Vec<u8>, TransitionQuoteError> {
        // Same pre-decode bound as the report: cap the b64 string length
        // before allocating decode output for it.
        let der = decode_bounded_quote_b64(field, MAX_QUOTE_CERTIFICATE_DER_BYTES)
            .ok_or(TransitionQuoteError::Malformed)?;
        if der.is_empty() || der.len() > MAX_QUOTE_CERTIFICATE_DER_BYTES {
            return Err(TransitionQuoteError::Malformed);
        }
        Ok(der)
    };
    let ark_der = decode_cert(&quote.ark_der_b64)?;
    let ask_der = decode_cert(&quote.ask_der_b64)?;
    let vcek_der = decode_cert(&quote.vcek_der_b64)?;

    // Anchor: only builtin AMD roots may authenticate the chain.
    let ark_sha256: [u8; 32] = Sha256::digest(&ark_der).into();
    if !BUILTIN_AMD_ARK_SHA256_PINS.contains(&ark_sha256) {
        return Err(TransitionQuoteError::UntrustedAnchor);
    }
    verify_amd_certificate_chain(&ark_der, &ask_der, &vcek_der, &ark_sha256)
        .map_err(|_| TransitionQuoteError::InvalidEvidence)?;

    // Revocation/validity gate (#115 follow-up): the chain being
    // well-signed is not sufficient when AMD has retired an ASK/VCEK or a
    // certificate has expired. The caller-submitted CRL must itself be
    // ARK-signed and fresh; `verify_amd_revocation` re-checks the ARK pin
    // before any RSA math, enforces the ARK/ASK/VCEK validity intervals at
    // `now_unix_seconds`, verifies the CRL signature and this/nextUpdate
    // window, and walks the revoked serials for the exact ASK and VCEK
    // under verification. Missing or stale collateral fails closed.
    let crl_der = decode_bounded_quote_b64(&quote.crl_der_b64, MAX_QUOTE_CRL_DER_BYTES)
        .ok_or(TransitionQuoteError::Malformed)?;
    if crl_der.is_empty() || crl_der.len() > MAX_QUOTE_CRL_DER_BYTES {
        return Err(TransitionQuoteError::Malformed);
    }
    verify_amd_revocation(
        &ark_der,
        &ask_der,
        &vcek_der,
        &crl_der,
        now_unix_seconds,
        TRANSITION_REVOCATION_MAX_AGE_SECONDS,
        &BUILTIN_AMD_ARK_SHA256_PINS,
    )
    .map_err(|_| TransitionQuoteError::RevocationRejected)?;

    let report = parse_snp_report(&report_bytes).map_err(|_| TransitionQuoteError::Malformed)?;
    // A debug-enabled guest is not confidential (the PSP hands its keys to a
    // debugger), so its receipt key is untrusted even with a valid chain.
    if snp_guest_policy_allows_debug(report.guest_policy) {
        return Err(TransitionQuoteError::DebugPolicy);
    }
    verify_snp_signature(&report, &vcek_der).map_err(|_| TransitionQuoteError::InvalidEvidence)?;
    verify_vcek_report_binding(&report, &vcek_der)
        .map_err(|_| TransitionQuoteError::InvalidEvidence)?;

    // The report_data binding reproduces the client-side
    // `tee_tls_report_data` contract: transcript hash over domain, nonce,
    // leaf SPKI, then a binding hash including the receipt key hash. The
    // verifier helper hashes the raw receipt public key itself, so decode it
    // from the signature-verified receipt envelope.
    let nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&attestation.nonce)
        .or_else(|_| B64.decode(&attestation.nonce))
        .map_err(|_| TransitionQuoteError::Malformed)?
        .try_into()
        .map_err(|_| TransitionQuoteError::Malformed)?;
    let leaf_spki_sha256 = parse_hex32("leaf_spki_sha256", &attestation.leaf_spki_sha256)
        .map_err(|_| TransitionQuoteError::Malformed)?
        .try_into()
        .map_err(|_| TransitionQuoteError::Malformed)?;
    let receipt_pubkey: [u8; 32] = B64
        .decode(&receipt.receipt.pubkey)
        .map_err(|_| TransitionQuoteError::Malformed)?
        .try_into()
        .map_err(|_| TransitionQuoteError::Malformed)?;
    let origin = format!("https://{}", attestation.tee_domain);
    let expected = expected_report_data(&origin, &nonce, &leaf_spki_sha256, &receipt_pubkey)
        .map_err(|_| TransitionQuoteError::Malformed)?;
    if report.report_data != expected {
        return Err(TransitionQuoteError::InvalidEvidence);
    }

    Ok(())
}

type UnlockModeError = (StatusCode, Json<serde_json::Value>);

fn unlock_database_error() -> UnlockModeError {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "database error"})),
    )
}

fn unlock_transition_conflict(message: &'static str) -> UnlockModeError {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": message})),
    )
}

fn auto_unlock_disabled_error() -> UnlockModeError {
    crate::routes::apps::auto_unlock_disabled_response()
}

async fn reject_replayed_transition_receipt(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    app_id: Uuid,
    receipt_timestamp: DateTime<Utc>,
) -> Result<(), UnlockModeError> {
    let latest: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(receipt_timestamp) FROM unlock_transition_receipts WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(|_| unlock_database_error())?;

    if latest.is_some_and(|latest| receipt_timestamp <= latest) {
        return Err(unlock_transition_conflict("replayed transition_receipt"));
    }
    Ok(())
}

struct UnlockModeCommitRequest<'a> {
    org_id: Uuid,
    user_id: Uuid,
    app_name: &'a str,
    observed_authority: &'a crate::deploy::ExistingAppAuthoritySnapshot,
    source_deployment_id: Uuid,
    requested: RequestedUnlockMode,
    receipt: &'a SignedReceiptResponse,
    transition_attestation: &'a TransitionReceiptAttestation,
    verified_receipt: &'a VerifiedTransitionReceipt,
    receipt_json: &'a serde_json::Value,
    deploy_id: Uuid,
    image_digest: Option<&'a str>,
    signed_workload_command: Option<&'a str>,
    signed_container_port: Option<i32>,
    signed_storage_paths: Option<&'a Vec<String>>,
    signing_artifacts: Option<&'a crate::signing_service::DeploymentSigningArtifacts>,
    signed_policy_artifact: Option<&'a crate::signing_service::SignedPolicyArtifact>,
    descriptor_platform_binding: &'a crate::signing_service::DescriptorPlatformBinding,
    log_encryption: Option<&'a LogEncryptionConfig>,
    api_signing_pubkey: &'a str,
    api_url: &'a str,
    attestation_config: Option<&'a enclava_engine::types::AttestationConfig>,
    signing_service_pubkey_hex: Option<&'a str>,
    signed_required: bool,
    fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims,
}

#[derive(Debug)]
struct CommittedUnlockModeTransition {
    app: App,
}

/// Lock and revalidate the accepted transition, then persist every
/// authoritative row as one unit.  The external signing work deliberately
/// happens before this helper so no network request holds the application row
/// lock; everything that can make the transition visible happens here.
async fn commit_unlock_mode_transition(
    pool: &sqlx::PgPool,
    request: UnlockModeCommitRequest<'_>,
) -> Result<CommittedUnlockModeTransition, UnlockModeError> {
    // Backstop under the deployment lane: even if admission above raced with
    // another writer, an auto target can never reach the committed rows.
    if request.requested == RequestedUnlockMode::Auto {
        return Err(auto_unlock_disabled_error());
    }
    let mut tx = pool.begin().await.map_err(|_| unlock_database_error())?;

    // Match every hosted authority writer's global lock order. The caller's
    // owner role, customer signing authority and app/runtime generation are
    // all re-read only after their respective lanes are held.
    crate::entitlements::lock_org_entitlement_lane(&mut tx, request.org_id)
        .await
        .map_err(|_| unlock_database_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, request.org_id)
        .await
        .map_err(|_| unlock_database_error())?;
    let current_role = crate::auth::scopes::lock_and_read_active_membership_role_in_tx(
        &mut tx,
        request.org_id,
        request.user_id,
    )
    .await?;
    crate::auth::scopes::require_owner_role(current_role)?;
    crate::deploy::lock_app_deployment_lane(&mut tx, request.observed_authority.app_id())
        .await
        .map_err(|_| unlock_database_error())?;

    // Check replay while holding the app lane but before comparing the
    // observed runtime snapshot. A concurrent successful transition changes
    // that snapshot, but a duplicate receipt should still have one stable,
    // bounded outcome: replay conflict.
    reject_replayed_transition_receipt(
        &mut tx,
        request.observed_authority.app_id(),
        request.verified_receipt.receipt_timestamp,
    )
    .await?;
    if !crate::deploy::lock_and_verify_existing_app_authority(
        &mut tx,
        request.observed_authority.app_id(),
        request.observed_authority,
    )
    .await
    .map_err(|_| unlock_database_error())?
    {
        return Err(unlock_transition_conflict(
            "app changed while unlock mode transition was validating; retry",
        ));
    }

    let locked_app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(request.observed_authority.app_id())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| unlock_database_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;
    if locked_app.org_id != request.org_id || locked_app.name != request.app_name {
        return Err(unlock_transition_conflict(
            "app changed while unlock mode transition was validating; retry",
        ));
    }
    if let Some(error) = crate::routes::deployments::runtime_reapply_status_error(locked_app.status)
    {
        return Err(unlock_transition_conflict(error));
    }
    if crate::mutation_leases::desired_state_mutation_in_progress(
        &mut tx,
        request.observed_authority.app_id(),
    )
    .await
    .map_err(|_| unlock_database_error())?
    {
        return Err(unlock_transition_conflict(
            "app mutation already in progress",
        ));
    }

    let locked_current = current_mode(&locked_app);
    if !validate_transition(locked_current, request.requested) {
        return Err(unlock_transition_conflict("invalid unlock mode transition"));
    }
    let reverified = verify_transition_receipt(
        request.receipt,
        &locked_app,
        locked_current,
        request.requested,
    )
    .map_err(|_| {
        unlock_transition_conflict("app changed while unlock mode transition was validating; retry")
    })?;
    verify_transition_attestation(request.transition_attestation, &locked_app, &reverified)
        .map_err(|_| {
            unlock_transition_conflict(
                "app changed while unlock mode transition was validating; retry",
            )
        })?;

    let locked_containers: Vec<crate::models::AppContainer> = sqlx::query_as(
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
    )
    .bind(locked_app.id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| unlock_database_error())?;
    let locked_primary = locked_containers
        .iter()
        .find(|container| container.is_primary)
        .ok_or_else(|| unlock_transition_conflict("app has no primary container"))?;
    if locked_primary.image_digest.as_deref() != request.image_digest {
        return Err(unlock_transition_conflict(
            "app runtime changed while unlock mode transition was validating; retry",
        ));
    }
    // Reject a rewritten command, port, or mount list before either UPDATE.
    // Artifacts without these fields would still pin via the descriptor
    // overlay and then apply the raw column.
    if request.signing_artifacts.is_some()
        && (request.signed_workload_command.is_none()
            || request.signed_container_port.is_none()
            || request.signed_storage_paths.is_none())
    {
        return Err(unlock_transition_conflict(
            "signed descriptor omitted command, port, or storage paths",
        ));
    }
    if let Err(reason) = signed_workload_matches_locked_primary(
        locked_primary,
        request.signed_workload_command,
        request.signed_container_port,
        request.signed_storage_paths.map(Vec::as_slice),
    ) {
        return Err(unlock_transition_conflict(reason));
    }

    // Lock resources too so the apply snapshot is exactly the state accepted
    // by this transaction rather than a later concurrent edit.
    let resources: crate::models::AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(locked_app.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| unlock_database_error())?;
    if let Some(artifacts) = request.signing_artifacts
        && let Err(reason) = signed_identity_matches_locked_runtime(
            locked_primary,
            &resources,
            &artifacts.descriptor.oci_runtime_spec.env,
            &artifacts.descriptor.oci_runtime_spec.resources.limits,
        )
    {
        return Err(unlock_transition_conflict(reason));
    }
    crate::routes::deployments::enforce_authoritative_entitlement(
        &mut tx,
        request.org_id,
        &resources,
        false,
        // Revalidation of PERSISTED resources against live claim evidence:
        // a surviving sub-floor claim keeps operating (its LUKS header
        // exists), a missing/terminating one is a fresh format and must
        // meet the floor.
        request.fresh_volume_claims,
    )
    .await?;

    let source: ApplyGenerationRow = sqlx::query_as(LATEST_APPLY_GENERATION_SQL)
        .bind(locked_app.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| unlock_database_error())?
        .ok_or_else(|| unlock_transition_conflict("app has no deployment generation"))?;
    if source.0 != request.source_deployment_id
        || matches!(source.1.as_str(), "pending" | "applying" | "watching")
        || source.2.as_deref() != request.image_digest
        || source
            .3
            .get("log_encryption")
            .cloned()
            .unwrap_or(serde_json::Value::Null)
            != serde_json::to_value(request.log_encryption).map_err(|_| unlock_database_error())?
    {
        return Err(unlock_transition_conflict(
            "deployment generation changed while unlock mode transition was validating; retry",
        ));
    }

    if request.signed_required && request.signing_artifacts.is_none() {
        return Err(unlock_transition_conflict(
            "current deployment authority requires signed artifacts",
        ));
    }
    if request.signing_artifacts.is_some() != request.signed_policy_artifact.is_some() {
        return Err(unlock_transition_conflict(
            "signed deployment authority is incomplete",
        ));
    }

    if let (Some(artifacts), Some(signed_policy_artifact)) =
        (request.signing_artifacts, request.signed_policy_artifact)
    {
        let image_digest = request.image_digest.ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed unlock-mode redeployment requires an existing digest-pinned primary image"
            })),
        ))?;
        let mut signed_locked_app = locked_app.clone();
        signed_locked_app.unlock_mode = request.requested.model_value();
        artifacts
            .validate_deployment_inputs(
                &signed_locked_app,
                image_digest,
                request.api_signing_pubkey,
                request.descriptor_platform_binding,
            )
            .map_err(crate::routes::deployments::signing_error_response)?;
        artifacts
            .validate_customer_authority_in_tx(&mut tx)
            .await
            .map_err(crate::routes::deployments::signing_error_response)?;
        // Policy artifacts are produced by the off-cluster signing service,
        // so its key is the acceptance authority (cap#118 note: the trustee
        // policy key is a separate in-TEE authority, not a /sign producer).
        let policy_authority_pubkey_hex = request.signing_service_pubkey_hex.ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "platform signing-service pubkey required for signed deployment verification"
            })),
        ))?;
        artifacts
            .validate_signed_artifact(signed_policy_artifact, policy_authority_pubkey_hex)
            .map_err(crate::routes::deployments::signing_error_response)?;

        let locked_profile = locked_primary
            .workload_security_profile
            .as_deref()
            .unwrap_or("restricted")
            .parse::<enclava_engine::types::WorkloadSecurityProfile>()
            .map_err(|_| {
                unlock_transition_conflict("stored workload security profile is invalid")
            })?;
        let signed_profile =
            crate::routes::deployments::signed_descriptor_profile(&artifacts.descriptor)
                .ok_or_else(|| {
                    crate::routes::deployments::signing_error_response(
                        crate::signing_service::SigningServiceError::Mismatch(
                            "workload_security_profile".to_string(),
                        ),
                    )
                })?;
        if signed_profile != locked_profile {
            return Err(crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".to_string(),
                ),
            ));
        }
    }

    let result = sqlx::query(
        "UPDATE apps SET unlock_mode = $1::unlock_enum, updated_at = now() WHERE id = $2",
    )
    .bind(request.requested.db_value())
    .bind(locked_app.id)
    .execute(&mut *tx)
    .await
    .map_err(|_| unlock_database_error())?;
    if result.rows_affected() != 1 {
        return Err(unlock_database_error());
    }

    // Store the normalized locked workload, not the raw descriptor and not
    // the raw column. `set_primary_descriptor_runtime` drops `/state` before
    // the commit pin; `validate_signed_render` and `apply_deployment_manifests`
    // rebuild cc_init from this snapshot and do not overlay the descriptor.
    // Leaving `/state` in the column makes those renders hash differently
    // and the job fails Artifact after the guest wrap is already gone.
    if request.signed_workload_command.is_some() {
        let (command_json, port, storage_paths) =
            normalized_locked_workload(locked_primary).map_err(unlock_transition_conflict)?;
        let result = sqlx::query(
            "UPDATE app_containers
             SET command = $1, port = $2, storage_paths = $3
             WHERE app_id = $4 AND is_primary = true",
        )
        .bind(command_json)
        .bind(port)
        .bind(&storage_paths)
        .bind(locked_app.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| unlock_database_error())?;
        if result.rows_affected() != 1 {
            return Err(unlock_database_error());
        }
    }

    let updated_app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(locked_app.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| unlock_database_error())?;
    let containers: Vec<crate::models::AppContainer> = sqlx::query_as(
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
    )
    .bind(locked_app.id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|_| unlock_database_error())?;

    // Repeat the signed cc-init render from the exact locked rows that will be
    // stored in the durable job. This is the final validation before any
    // unlock transition row becomes commit-visible.
    if let (Some(artifacts), Some(signed_policy_artifact)) =
        (request.signing_artifacts, request.signed_policy_artifact)
    {
        let attestation = request.attestation_config.ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "attestation runtime configuration required for signed deployment"
            })),
        ))?;
        let mut app_spec = crate::deploy::build_confidential_app_from_rows(
            &updated_app,
            request.deploy_id,
            attestation,
            request.api_signing_pubkey,
            request.api_url,
            &containers,
            &resources,
        )
        .map_err(|_| unlock_transition_conflict("stored workload runtime is invalid"))?;
        crate::deploy::set_primary_descriptor_runtime(&mut app_spec, &artifacts.descriptor);
        app_spec.workload_artifact_binding = Some(artifacts.binding());
        app_spec.log_encryption = request.log_encryption.cloned();
        crate::routes::deployments::select_local_signed_artifact_delivery(
            &mut app_spec.attestation,
        );
        app_spec.generated_agent_policy = Some(
            artifacts
                .generated_agent_policy(signed_policy_artifact)
                .map_err(crate::routes::deployments::signing_error_response)?,
        );
        // Accept either the modern render (with the log_encryption_json claim)
        // or, for artifacts signed before the claim existed, the legacy render
        // without it; a legacy match pins the app to the legacy byte layout.
        artifacts
            .validate_and_pin_cc_init_data_render(&mut app_spec)
            .map_err(crate::routes::deployments::signing_error_response)?;
        reject_omitted_log_recipient(
            app_spec
                .workload_artifact_binding
                .as_ref()
                .is_some_and(|binding| binding.omit_log_encryption_claim),
            request.log_encryption,
        )?;
    }

    let primary = containers
        .iter()
        .find(|container| container.is_primary)
        .ok_or_else(|| unlock_transition_conflict("app has no primary container"))?;
    let workload_security_profile = primary
        .workload_security_profile
        .as_deref()
        .unwrap_or("restricted");

    let spec_snapshot = serde_json::json!({
        "app_name": &updated_app.name,
        "namespace": &updated_app.namespace,
        "instance_id": &updated_app.instance_id,
        "unlock_mode": request.requested.api_value(),
        "source_generation": request.source_deployment_id,
        "image": &primary.image_ref,
        "image_digest": request.image_digest,
        "resolved_resources": {
            "cpu": &resources.cpu_limit,
            "memory": &resources.memory_limit,
            "storage": &resources.app_data_size,
            "tls_storage": &resources.tls_data_size,
        },
        "workload_security_profile": workload_security_profile,
        "transition": {
            "from": locked_current.api_value(),
            "to": request.requested.api_value(),
        },
        "signed_descriptor_core_hash": request
            .signing_artifacts
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
        "log_encryption": request.log_encryption,
        "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
    });

    crate::deploy::supersede_incomplete_deployments(&mut tx, locked_app.id)
        .await
        .map_err(|error| match error {
            crate::deploy::SupersedeDeploymentError::Busy => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "deployment mutation is still in progress"})),
            ),
            crate::deploy::SupersedeDeploymentError::Database(_) => unlock_database_error(),
        })?;
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest)
         VALUES ($1, $2, $3, 'api', $4, $5)",
    )
    .bind(request.deploy_id)
    .bind(request.org_id)
    .bind(locked_app.id)
    .bind(&spec_snapshot)
    .bind(request.image_digest)
    .execute(&mut *tx)
    .await
    .map_err(|_| unlock_database_error())?;

    let insert_receipt = sqlx::query(
        "INSERT INTO unlock_transition_receipts
            (app_id, deployment_id, from_mode, to_mode, receipt,
             receipt_pubkey_sha256, receipt_timestamp)
         VALUES ($1, $2, $3::unlock_enum, $4::unlock_enum, $5, $6, $7)",
    )
    .bind(locked_app.id)
    .bind(request.deploy_id)
    .bind(locked_current.db_value())
    .bind(request.requested.db_value())
    .bind(request.receipt_json)
    .bind(&reverified.pubkey_sha256_bytes)
    .bind(reverified.receipt_timestamp)
    .execute(&mut *tx)
    .await;
    if let Err(error) = insert_receipt {
        if error
            .as_database_error()
            .and_then(|error| error.code())
            .as_deref()
            == Some("23505")
        {
            return Err(unlock_transition_conflict("replayed transition_receipt"));
        }
        return Err(unlock_database_error());
    }

    if let (Some(artifacts), Some(signed)) =
        (request.signing_artifacts, request.signed_policy_artifact)
    {
        crate::signing_service::accept_signed_workload_artifacts(
            &mut tx,
            locked_app.id,
            request.deploy_id,
            artifacts,
            signed,
        )
        .await
        .map_err(|_| unlock_database_error())?;
    } else {
        crate::kbs::enqueue_signed_policy_revocation_if_active(&mut tx)
            .await
            .map_err(|_| unlock_database_error())?;
    }

    let apply_payload = crate::deployment_jobs::DeploymentApplyJobPayload::new(
        updated_app.clone(),
        crate::deploy::DeploymentApplySnapshot::new(containers.clone(), resources.clone()),
        request.attestation_config.cloned(),
        request.api_signing_pubkey.to_string(),
        request.api_url.to_string(),
        request.signing_artifacts.map(|_| request.deploy_id),
        request
            .signing_artifacts
            .map(|artifacts| artifacts.descriptor_core_hash),
        request.log_encryption.cloned(),
        false,
    );
    crate::deployment_jobs::insert_ready_job(
        &mut tx,
        request.deploy_id,
        request.deploy_id,
        &apply_payload,
        request.signed_required,
    )
    .await
    .map_err(|_| unlock_database_error())?;

    // Audit is part of acceptance, not best effort. Any audit failure aborts
    // the mode, receipt, runtime, deployment and artifact writes above.
    sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail)
         VALUES ($1, $2, $3, 'app.unlock_mode.update', $4)",
    )
    .bind(request.org_id)
    .bind(locked_app.id)
    .bind(request.user_id)
    .bind(serde_json::json!({
        "from": locked_current.api_value(),
        "to": request.requested.api_value(),
        "deployment_id": request.deploy_id,
    }))
    .execute(&mut *tx)
    .await
    .map_err(|_| unlock_database_error())?;

    tx.commit().await.map_err(|_| unlock_database_error())?;

    Ok(CommittedUnlockModeTransition { app: updated_app })
}

/// GET /apps/{name}/unlock/status -- ownership state (queried from TEE).
pub async fn unlock_status(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<UnlockStatusResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    let tee_url = format!("https://{domain}/.well-known/confidential");

    // Tenant TEE endpoints serve self-signed RA-TLS leaves; only the
    // SNP-attested, SPKI-pinned channel authenticates them. Any failure is
    // reported as `ownership_state: null` — never an unauthenticated read.
    let tee_client = match crate::tee_attestation::attested_tee_channel(
        &app,
        &state.db,
        &state.kube_client,
        state
            .attestation
            .as_ref()
            .and_then(|config| config.amd_kds_base_url.as_deref()),
    )
    .await
    {
        Ok(client) => Some(client),
        Err(error) => {
            tracing::warn!(
                app_id = %app.id,
                category = error.category(),
                reason = error.reason(),
                code = "unlock_status_attestation",
                "unlock status TEE channel failed attestation"
            );
            None
        }
    };
    let ownership_state = match tee_client {
        Some(client) => tee_ownership_state(&client, domain).await,
        None => None,
    };
    let locked_generation = load_unlock_locked_generation(&state.db, &app).await?;

    Ok(Json(UnlockStatusResponse {
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        tee_url,
        ownership_state,
        locked_generation,
    }))
}

/// Fetch and parse the guest `ownership_state` over an attested channel.
/// Returns `None` on transport, non-2xx, or malformed responses.
async fn tee_ownership_state(client: &reqwest::Client, domain: &str) -> Option<String> {
    let status_url = format!("https://{domain}/.well-known/confidential/status");
    match client.get(&status_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<serde_json::Value>().await {
            Ok(v) => tee_ownership_state_from_value(&v),
            Err(_) => {
                tracing::warn!(
                    code = "unlock_status_malformed",
                    "unlock status TEE response was not JSON"
                );
                None
            }
        },
        Ok(resp) => {
            tracing::warn!(
                status = %resp.status(),
                code = "unlock_status_http",
                "unlock status TEE returned non-success status"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                code = "unlock_status_transport",
                "unlock status TEE request failed"
            );
            None
        }
    }
}

fn tee_ownership_state_from_value(value: &serde_json::Value) -> Option<String> {
    value
        .get("ownership_state")
        .or_else(|| value.get("state"))
        .and_then(|s| s.as_str())
        .map(String::from)
}

#[derive(Debug, Serialize)]
pub struct UnlockEndpointResponse {
    pub tee_url: String,
    pub unlock_endpoint: String,
    pub claim_endpoint: String,
}

/// GET /apps/{name}/unlock/endpoint -- returns TEE URLs for direct unlock/claim.
pub async fn unlock_endpoint(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
) -> Result<Json<UnlockEndpointResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_app_read(&auth)?;

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;

    let domain = app.tee_domain.as_deref().unwrap_or(&app.domain);
    let base = format!("https://{domain}/.well-known/confidential");

    Ok(Json(UnlockEndpointResponse {
        tee_url: base.clone(),
        unlock_endpoint: format!("{base}/unlock"),
        claim_endpoint: format!("{base}/bootstrap/claim"),
    }))
}

/// Entitlement and fresh-claim gates `commit_unlock_mode_transition` enforces
/// after the guest wrap is gone. Preview must fail the same way, without
/// writing mode or deployment rows, or the CLI removes the wrap and the
/// commit leaves CAP in auto mode. The commit repeats the checks under its
/// own locks for changes between the two requests.
async fn preview_unlock_commit_gates(
    state: &AppState,
    org_id: Uuid,
    app: &crate::models::App,
    resources: &crate::models::AppResources,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let fresh_volume_claims =
        crate::routes::deployments::fresh_volume_claims(&state.kube_client, app, resources)
            .await
            .map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(serde_json::json!({
                        "error": "volume provisioning state could not be verified; retry"
                    })),
                )
            })?;
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|_| unlock_database_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, org_id)
        .await
        .map_err(|_| unlock_database_error())?;
    crate::routes::deployments::enforce_authoritative_entitlement(
        &mut tx,
        org_id,
        resources,
        false,
        fresh_volume_claims,
    )
    .await?;
    tx.rollback().await.map_err(|_| unlock_database_error())?;
    Ok(())
}

/// PUT /apps/{name}/unlock/mode -- update CAP-owned unlock mode and re-apply manifests.
///
/// The owner password must never pass through this route. The CLI calls the
/// tenant TEE endpoint first to create/remove the sealed seed, then calls this
/// route with only the desired CAP deployment mode.
pub async fn update_unlock_mode(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(app_name): Path<String>,
    Json(body): Json<UpdateUnlockModeRequest>,
) -> Result<Json<UpdateUnlockModeResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_owner(&auth)?;
    scopes::require_scope(&auth, "apps:write")?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    let requested = RequestedUnlockMode::parse(&body.mode).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        )
    })?;
    // Auto-unlock is hard-disabled: refuse any auto target before app reads,
    // receipt verification, or attestation work. Auto->password transitions
    // (legacy migration) remain fully functional.
    if requested == RequestedUnlockMode::Auto {
        return Err(auto_unlock_disabled_error());
    }

    let app: App = sqlx::query_as("SELECT * FROM apps WHERE org_id = $1 AND name = $2")
        .bind(auth.org_id)
        .bind(&app_name)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "app not found"})),
        ))?;
    if let Some(error) = crate::routes::deployments::runtime_reapply_status_error(app.status) {
        return Err(unlock_transition_conflict(error));
    }

    let current = current_mode(&app);
    if !validate_transition(current, requested) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "invalid unlock mode transition"})),
        ));
    }

    if current == requested && !body.validate_only {
        return Ok(Json(UpdateUnlockModeResponse {
            app_name: app.name,
            unlock_mode: requested.api_value().to_string(),
            deployment_id: None,
            status: "unchanged".to_string(),
        }));
    }

    // A preview has no TEE receipt yet. It exists so the CLI can learn that
    // CAP will reject the signed descriptor before the guest wrap is removed.
    let receipt_gate = if body.validate_only {
        None
    } else {
        let receipt = body.transition_receipt.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "transition_receipt required for unlock mode change"
            })),
        ))?;
        let verified_receipt = verify_transition_receipt(receipt, &app, current, requested)
            .map_err(|field| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid transition_receipt",
                        "field": field,
                    })),
                )
            })?;
        let transition_attestation = body.transition_attestation.as_ref().ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "transition_attestation required for unlock mode change"
            })),
        ))?;
        verify_transition_attestation(transition_attestation, &app, &verified_receipt).map_err(
            |field| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid transition_attestation",
                        "field": field,
                    })),
                )
            },
        )?;
        verify_transition_snp_quote(transition_attestation, receipt, quote_verification_now())
            .map_err(|error| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid transition_attestation",
                        "field": "transition_attestation.quote",
                        "reason": error.reason(),
                    })),
                )
            })?;
        // Server-side freshness window: without it, captured quote/receipt
        // pairs can be replayed once (monotonicity and the unique receipt
        // index only block reuse after the first consumption).
        if !transition_receipt_is_fresh(verified_receipt.receipt_timestamp, Utc::now()) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid transition_receipt",
                    "field": "transition_receipt.payload.timestamp",
                    "reason": "transition receipt outside freshness window",
                })),
            ));
        }
        Some((receipt, verified_receipt, transition_attestation))
    };

    let signing_artifacts = crate::signing_service::decode_optional_blobs(
        body.customer_descriptor_blob.clone(),
        body.org_keyring_blob.clone(),
    )
    .map_err(crate::routes::deployments::signing_error_response)?;
    if body.signed_policy_artifact.is_some() && signing_artifacts.is_none() {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::ArtifactWithoutBlobs,
        ));
    }
    let signed_required = crate::routes::deployments::customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    );
    if signed_required && signing_artifacts.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed unlock-mode redeployments require customer_descriptor_blob and org_keyring_blob; use a current enclava CLI to sign the updated deployment descriptor"
            })),
        ));
    }

    let observed_containers: Vec<crate::models::AppContainer> = sqlx::query_as(
        "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
    )
    .bind(app.id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| unlock_database_error())?;
    let primary = observed_containers
        .iter()
        .find(|container| container.is_primary)
        .ok_or_else(|| unlock_transition_conflict("app has no primary container"))?
        .clone();
    let image_digest = primary.image_digest.clone();
    let current_profile = primary
        .workload_security_profile
        .clone()
        .unwrap_or_else(|| "restricted".to_string());
    let observed_resources: crate::models::AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(app.id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| unlock_database_error())?;
    let observed_authority = crate::deploy::ExistingAppAuthoritySnapshot::new(
        app.updated_at,
        observed_containers,
        observed_resources.clone(),
    );
    let source: ApplyGenerationRow = sqlx::query_as(LATEST_APPLY_GENERATION_SQL)
        .bind(app.id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| unlock_database_error())?
        .ok_or_else(|| unlock_transition_conflict("app has no deployment generation"))?;
    if let Some(reason) = generation_conflict_reason(
        &source.1,
        source.2.as_deref(),
        image_digest.as_deref(),
        &source.3,
        &observed_resources.cpu_limit,
        &observed_resources.memory_limit,
        &observed_resources.app_data_size,
        &observed_resources.tls_data_size,
        current_profile.as_str(),
    ) {
        return Err(unlock_transition_conflict(reason));
    }
    let log_encryption: Option<LogEncryptionConfig> = serde_json::from_value(
        source
            .3
            .get("log_encryption")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    )
    .map_err(|_| unlock_transition_conflict("stored log encryption metadata is invalid"))?;
    let source_deployment_id = source.0;

    let mut signed_app = app.clone();
    signed_app.unlock_mode = requested.model_value();
    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
    let mut signed_policy_artifact = None;
    let mut signed_workload_command = None;
    let mut signed_container_port = None;
    let mut signed_storage_paths = None;
    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    if let Some(artifacts) = signing_artifacts.as_ref() {
        let image_digest_ref = image_digest.as_deref().ok_or((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed unlock-mode redeployment requires an existing digest-pinned primary image"
            })),
        ))?;
        artifacts
            .validate_deployment_inputs(
                &signed_app,
                image_digest_ref,
                &api_signing_pubkey,
                &crate::signing_service::descriptor_platform_binding_for(
                    &state,
                    &observed_resources.memory_limit,
                )
                .map_err(crate::routes::deployments::signing_error_response)?,
            )
            .map_err(crate::routes::deployments::signing_error_response)?;
        let workload_command = artifacts.descriptor.oci_runtime_spec.args.clone();
        signed_workload_command = crate::deploy::serialize_workload_command(&workload_command)
            .map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "command serialization error"})),
                )
            })?;
        signed_container_port = crate::deploy::descriptor_primary_port(&artifacts.descriptor);
        signed_storage_paths = Some(crate::deploy::descriptor_storage_paths(
            &artifacts.descriptor,
        ));
        // Fail before the signing service sees a descriptor that would change
        // the stored primary. The commit re-checks the locked row.
        if let Err(reason) = signed_workload_matches_locked_primary(
            &primary,
            signed_workload_command.as_deref(),
            signed_container_port,
            signed_storage_paths.as_deref(),
        ) {
            return Err(unlock_transition_conflict(reason));
        }
        if let Err(reason) = signed_identity_matches_locked_runtime(
            &primary,
            &observed_resources,
            &artifacts.descriptor.oci_runtime_spec.env,
            &artifacts.descriptor.oci_runtime_spec.resources.limits,
        ) {
            return Err(unlock_transition_conflict(reason));
        }
        // The cc_init pin does not separate the two uid-0 profiles. The commit
        // rejects that swap; the preview must too, or the wrap is removed and
        // the mode stays auto.
        let signed_profile =
            crate::routes::deployments::signed_descriptor_profile(&artifacts.descriptor)
                .ok_or_else(|| {
                    crate::routes::deployments::signing_error_response(
                        crate::signing_service::SigningServiceError::Mismatch(
                            "workload_security_profile".to_string(),
                        ),
                    )
                })?;
        let locked_profile = current_profile
            .parse::<enclava_engine::types::WorkloadSecurityProfile>()
            .map_err(|_| {
                unlock_transition_conflict("stored workload security profile is invalid")
            })?;
        if signed_profile != locked_profile {
            return Err(crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::Mismatch(
                    "workload_security_profile".to_string(),
                ),
            ));
        }
        let attestation = state.attestation.as_ref().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": "signed deployment artifacts require attestation runtime configuration"
            })),
        ))?;
        let signing_service_pubkey_hex = attestation.signing_service_pubkey_hex.as_deref();
        let mut app_spec = crate::deploy::build_confidential_app(
            &state.db,
            &signed_app,
            deploy_id,
            attestation,
            &api_signing_pubkey,
            &state.api_url,
        )
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "stored workload runtime is invalid"})),
            )
        })?;
        crate::deploy::set_primary_descriptor_runtime(&mut app_spec, &artifacts.descriptor);
        let binding = artifacts.binding();
        app_spec.workload_artifact_binding = Some(binding.clone());
        app_spec.log_encryption = log_encryption.clone();

        let signed = crate::routes::deployments::resolve_signed_policy_artifact(
            &state,
            artifacts,
            body.signed_policy_artifact.clone(),
            signing_service_pubkey_hex,
            log_encryption.clone(),
            true,
        )
        .await?;
        app_spec.generated_agent_policy = Some(
            artifacts
                .generated_agent_policy(&signed)
                .map_err(crate::routes::deployments::signing_error_response)?,
        );
        crate::routes::deployments::select_local_signed_artifact_delivery(
            &mut app_spec.attestation,
        );
        // Accept either the modern render (with the log_encryption_json claim)
        // or, for artifacts signed before the claim existed, the legacy render
        // without it; a legacy match pins the app to the legacy byte layout.
        artifacts
            .validate_and_pin_cc_init_data_render(&mut app_spec)
            .map_err(crate::routes::deployments::signing_error_response)?;
        reject_omitted_log_recipient(
            app_spec
                .workload_artifact_binding
                .as_ref()
                .is_some_and(|binding| binding.omit_log_encryption_claim),
            log_encryption.as_ref(),
        )?;
        signed_policy_artifact = Some(signed);
    }

    if body.validate_only {
        // An already-applied mode returns unchanged and never reaches the
        // commit gates. Only a real transition can remove the wrap and then
        // be rejected, so only that preview is refused here.
        if current != requested {
            preview_unlock_commit_gates(&state, auth.org_id, &app, &observed_resources).await?;
        }
        return Ok(Json(UpdateUnlockModeResponse {
            app_name: app.name,
            unlock_mode: current.api_value().to_string(),
            deployment_id: None,
            status: "validated".to_string(),
        }));
    }
    let (receipt, verified_receipt, transition_attestation) =
        receipt_gate.expect("unlock mode change without validate_only has a verified receipt");

    let descriptor_platform_binding = crate::signing_service::descriptor_platform_binding_for(
        &state,
        &observed_resources.memory_limit,
    )
    .map_err(crate::routes::deployments::signing_error_response)?;
    let receipt_json = serde_json::to_value(receipt).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "receipt serialization error"})),
        )
    })?;
    // Live claim evidence for the persisted resource sizes, computed
    // outside the commit transaction (no kube I/O under the lanes; none at
    // all for at/above-floor sizes). If app state changed since the read
    // that produced `observed_resources`, the commit's authority check
    // forces a retry that recomputes this.
    let fresh_volume_claims = crate::routes::deployments::fresh_volume_claims(
        &state.kube_client,
        &app,
        &observed_resources,
    )
    .await
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "volume provisioning state could not be verified; retry"})),
        )
    })?;

    let committed = commit_unlock_mode_transition(
        &state.db,
        UnlockModeCommitRequest {
            org_id: auth.org_id,
            user_id: auth.user_id,
            app_name: &app_name,
            observed_authority: &observed_authority,
            source_deployment_id,
            requested,
            receipt,
            transition_attestation,
            verified_receipt: &verified_receipt,
            receipt_json: &receipt_json,
            deploy_id,
            image_digest: image_digest.as_deref(),
            signed_workload_command: signed_workload_command.as_deref(),
            signed_container_port,
            signed_storage_paths: signed_storage_paths.as_ref(),
            signing_artifacts: signing_artifacts.as_ref(),
            signed_policy_artifact: signed_policy_artifact.as_ref(),
            descriptor_platform_binding: &descriptor_platform_binding,
            log_encryption: log_encryption.as_ref(),
            api_signing_pubkey: &api_signing_pubkey,
            api_url: &state.api_url,
            attestation_config: state.attestation.as_ref(),
            signing_service_pubkey_hex: state
                .attestation
                .as_ref()
                .and_then(|config| config.signing_service_pubkey_hex.as_deref()),
            signed_required,
            fresh_volume_claims,
        },
    )
    .await?;

    Ok(Json(UpdateUnlockModeResponse {
        app_name: committed.app.name,
        unlock_mode: requested.api_value().to_string(),
        deployment_id: Some(deploy_id),
        status: "deploying".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use base64::{
        Engine as _,
        engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD},
    };
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    /// Tests run without a platform release or attestation sidecar config, so
    /// the descriptor platform binding enforces only the canonical KBS path.
    static EMPTY_PLATFORM_BINDING: crate::signing_service::DescriptorPlatformBinding =
        crate::signing_service::DescriptorPlatformBinding::EMPTY;

    use super::{
        BUILTIN_AMD_ARK_SHA256_PINS, LOCKED_GENERATION_SOURCE, ReceiptEnvelope, ReceiptPayloadView,
        RequestedUnlockMode, SignedReceiptResponse, TransitionQuoteError,
        TransitionReceiptAttestation, TransitionSnpQuote, UnlockModeCommitRequest,
        auto_unlock_disabled_error, commit_unlock_mode_transition, locked_generation_snapshot,
        snp_guest_policy_allows_debug, tee_ownership_state_from_value, transition_receipt_is_fresh,
        unlock_status, validate_transition, verify_transition_attestation,
        verify_transition_receipt, verify_transition_snp_quote,
    };
    use crate::models::{App, AppContainer, AppStatus, UnlockMode};

    fn test_app() -> App {
        App {
            id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            name: "demo".to_string(),
            namespace: "cap-demo".to_string(),
            instance_id: "instance-test-01".to_string(),
            tenant_id: "tenant-test".to_string(),
            service_account: "cap-demo-sa".to_string(),
            bootstrap_owner_pubkey_hash: "00".repeat(32),
            tenant_instance_identity_hash: "11".repeat(32),
            unlock_mode: UnlockMode::Password,
            domain: "demo.enclava.dev".to_string(),
            tee_domain: Some("demo.tee.enclava.dev".to_string()),
            custom_domain: None,
            status: AppStatus::Running,
            signer_identity_subject: None,
            signer_identity_issuer: None,
            signer_identity_set_at: None,
            signer_rotation_generation: 0,
            source_provider: None,
            source_repository: None,
            egress_allowlist: sqlx::types::Json(Vec::new()),
            egress_mode: "restricted".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn signed_transition_receipt(
        from_mode: &str,
        to_mode: &str,
        attestation_quote_sha256: &str,
        signing_key: &SigningKey,
    ) -> SignedReceiptResponse {
        signed_transition_receipt_for_app(
            test_app().id,
            "2026-04-28T12:00:00Z",
            from_mode,
            to_mode,
            attestation_quote_sha256,
            signing_key,
        )
    }

    fn signed_transition_receipt_for_app(
        app_id: Uuid,
        timestamp: &str,
        from_mode: &str,
        to_mode: &str,
        attestation_quote_sha256: &str,
        signing_key: &SigningKey,
    ) -> SignedReceiptResponse {
        let payload = ReceiptPayloadView {
            purpose: "enclava-unlock-receipt-v1".to_string(),
            app_id: app_id.to_string(),
            resource_path: None,
            from_mode: Some(from_mode.to_string()),
            to_mode: Some(to_mode.to_string()),
            attestation_quote_sha256: Some(attestation_quote_sha256.to_string()),
            new_value_sha256: None,
            timestamp: timestamp.to_string(),
        };
        let quote_hash_bytes = hex::decode(attestation_quote_sha256).unwrap();
        let payload_canonical_bytes = enclava_common::canonical::ce_v1_bytes(&[
            ("purpose", payload.purpose.as_bytes()),
            (
                "app_id",
                uuid::Uuid::parse_str(&payload.app_id).unwrap().as_bytes(),
            ),
            ("from_mode", from_mode.as_bytes()),
            ("to_mode", to_mode.as_bytes()),
            ("attestation_quote_sha256", quote_hash_bytes.as_slice()),
            ("timestamp", payload.timestamp.as_bytes()),
        ]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let signature = signing_key.sign(&payload_canonical_bytes);
        SignedReceiptResponse {
            operation: "unlock_mode_transition".to_string(),
            payload,
            receipt: ReceiptEnvelope {
                pubkey: B64.encode(pubkey),
                pubkey_sha256: hex::encode(Sha256::digest(pubkey)),
                payload_canonical_bytes: B64.encode(payload_canonical_bytes),
                signature: B64.encode(signature.to_bytes()),
            },
        }
    }

    fn transition_attestation(
        signing_key: &SigningKey,
        quote_hash: &str,
    ) -> TransitionReceiptAttestation {
        transition_attestation_for_domain("demo.tee.enclava.dev", signing_key, quote_hash)
    }

    fn transition_attestation_for_domain(
        tee_domain: &str,
        signing_key: &SigningKey,
        quote_hash: &str,
    ) -> TransitionReceiptAttestation {
        TransitionReceiptAttestation {
            tee_domain: tee_domain.to_string(),
            nonce: B64.encode([0x99; 32]),
            leaf_spki_sha256: "aa".repeat(32),
            receipt_pubkey_sha256: hex::encode(Sha256::digest(
                signing_key.verifying_key().to_bytes(),
            )),
            attestation_evidence_sha256: quote_hash.to_string(),
            quote: None,
        }
    }

    async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect unlock regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate unlock regression database");
        pool
    }

    struct UnlockTestFixture {
        app: App,
        user_id: Uuid,
        source_deployment_id: Uuid,
        authority: crate::deploy::ExistingAppAuthoritySnapshot,
    }

    async fn insert_unlock_test_app(pool: &sqlx::PgPool) -> UnlockTestFixture {
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let app_name = format!("unlock-{}", &suffix[..12]);
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("unlock-test-{suffix}"))
        .bind(&suffix[..8])
        .execute(pool)
        .await
        .expect("insert unlock test organization");
        sqlx::query(
            "INSERT INTO apps (
                id, org_id, name, namespace, instance_id, tenant_id,
                service_account, bootstrap_owner_pubkey_hash,
                tenant_instance_identity_hash, unlock_mode, domain, tee_domain,
                status
             )
             VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                'auto'::unlock_enum, $10, $11, 'running'::app_status_enum
             )",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(&app_name)
        .bind(format!("cap-{app_name}"))
        .bind(format!("instance-{suffix}"))
        .bind(&suffix[..8])
        .bind(format!("cap-{app_name}-sa"))
        .bind("11".repeat(32))
        .bind("22".repeat(32))
        .bind(format!("{app_name}.{}.enclava.dev", &suffix[..8]))
        .bind(format!("{app_name}.{}.tee.enclava.dev", &suffix[..8]))
        .execute(pool)
        .await
        .expect("insert unlock test app");
        sqlx::query(
            "INSERT INTO app_containers (
                id, app_id, name, image_ref, image_digest, command, port,
                storage_paths, is_primary
             )
             VALUES ($1, $2, 'web', $3, $4, $5, 8080, $6, true)",
        )
        .bind(Uuid::new_v4())
        .bind(app_id)
        .bind("ghcr.io/enclava-labs/test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .bind("[\"/bin/old\"]")
        .bind(vec!["/data".to_string()])
        .execute(pool)
        .await
        .expect("insert unlock test container");
        sqlx::query("INSERT INTO app_resources (app_id) VALUES ($1)")
            .bind(app_id)
            .execute(pool)
            .await
            .expect("insert unlock test resources");
        let app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await
            .expect("load unlock test app");
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'unlock actor')")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("insert unlock test actor");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner'::role_enum)",
        )
        .bind(user_id)
        .bind(org_id)
        .execute(pool)
        .await
        .expect("insert unlock test owner membership");
        let containers: Vec<crate::models::AppContainer> = sqlx::query_as(
            "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
        )
        .bind(app_id)
        .fetch_all(pool)
        .await
        .expect("load unlock test containers");
        let resources: crate::models::AppResources =
            sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
                .bind(app_id)
                .fetch_one(pool)
                .await
                .expect("load unlock test resources");
        let source_deployment_id = Uuid::new_v4();
        let image_digest = containers[0]
            .image_digest
            .clone()
            .expect("unlock test digest");
        let mut tx = pool.begin().await.expect("begin unlock source generation");
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, spec_snapshot, image_digest
             ) VALUES ($1, $2, $3, 'api', $4, $5)",
        )
        .bind(source_deployment_id)
        .bind(org_id)
        .bind(app_id)
        .bind(serde_json::json!({
            "image": &containers[0].image_ref,
            "image_digest": &image_digest,
            "resolved_resources": {
                "cpu": &resources.cpu_limit,
                "memory": &resources.memory_limit,
                "storage": &resources.app_data_size,
                "tls_storage": &resources.tls_data_size,
            },
            "workload_security_profile": "restricted",
            "signed_descriptor_core_hash": null,
            "log_encryption": null,
            "setup_state": crate::deployment_jobs::DEPLOYMENT_SETUP_ACCEPTED,
        }))
        .bind(&image_digest)
        .execute(&mut *tx)
        .await
        .expect("insert unlock source deployment");
        let payload = crate::deployment_jobs::DeploymentApplyJobPayload::new(
            app.clone(),
            crate::deploy::DeploymentApplySnapshot::new(containers.clone(), resources.clone()),
            None,
            "test-api-key".to_string(),
            "https://api.example.test".to_string(),
            None,
            None,
            None,
            false,
        );
        crate::deployment_jobs::insert_ready_job(
            &mut tx,
            source_deployment_id,
            source_deployment_id,
            &payload,
            false,
        )
        .await
        .expect("insert unlock source job");
        sqlx::query(
            "UPDATE deployments
                SET status = 'healthy'::deploy_status_enum,
                    completed_at = clock_timestamp()
              WHERE id = $1",
        )
        .bind(source_deployment_id)
        .execute(&mut *tx)
        .await
        .expect("complete unlock source deployment");
        sqlx::query(
            "UPDATE deployment_apply_jobs
                SET state = 'completed', updated_at = clock_timestamp()
              WHERE deployment_id = $1",
        )
        .bind(source_deployment_id)
        .execute(&mut *tx)
        .await
        .expect("complete unlock source job");
        tx.commit().await.expect("commit unlock source generation");
        let authority =
            crate::deploy::ExistingAppAuthoritySnapshot::new(app.updated_at, containers, resources);
        UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        }
    }

    async fn delete_unlock_test_org(pool: &sqlx::PgPool, org_id: Uuid) {
        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(pool)
            .await
            .expect("delete unlock test audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(pool)
            .await
            .expect("delete unlock test organization");
    }

    fn test_signing_artifacts(
        app: &App,
        deploy_id: Uuid,
        image_digest: &str,
        api_signing_pubkey: &str,
    ) -> (
        crate::signing_service::DeploymentSigningArtifacts,
        crate::signing_service::SignedPolicyArtifact,
    ) {
        let descriptor = serde_json::json!({
            "schema_version": "v1",
            "org_id": app.org_id,
            "org_slug": app.tenant_id,
            "app_id": app.id,
            "app_name": app.name,
            "deploy_id": deploy_id,
            "created_at": Utc::now(),
            "nonce": "01".repeat(32),
            "app_domain": app.domain,
            "tee_domain": app.tee_domain.as_deref().unwrap_or(&app.domain),
            "custom_domains": [],
            "namespace": app.namespace,
            "service_account": app.service_account,
            "identity_hash": app.tenant_instance_identity_hash,
            "image_ref": format!("ghcr.io/enclava-labs/test@{image_digest}"),
            "image_digest": image_digest,
            "signer_identity": {
                "subject": app.signer_identity_subject.as_deref().unwrap_or_default(),
                "issuer": app.signer_identity_issuer.as_deref().unwrap_or_default(),
            },
            "oci_runtime_spec": {
                "command": [enclava_engine::manifest::containers::ENCLAVA_WAIT_EXEC_PATH],
                "args": ["/usr/local/bin/test"],
                "env": [],
                "ports": [{"container_port": 8080, "protocol": "TCP"}],
                "mounts": [],
                "capabilities": {"add": [], "drop": []},
                "security_context": {
                    "run_as_user": 1000,
                    "run_as_group": 1000,
                    "read_only_root_fs": true,
                    "allow_privilege_escalation": false,
                    "privileged": false,
                },
                "resources": {"requests": [], "limits": []},
            },
            "sidecars": {
                "attestation_proxy_digest": format!("sha256:{}", "11".repeat(32)),
                "caddy_digest": format!("sha256:{}", "22".repeat(32)),
            },
            "api_signing_pubkey": api_signing_pubkey,
            "expected_firmware_measurement": "03".repeat(32),
            "expected_runtime_class": "kata-qemu-snp",
            "kbs_resource_path": format!(
                "default/{}-{}-owner/seed-encrypted",
                app.namespace, app.name
            ),
            "unlock_mode": "auto",
            "policy_template_id": "enclava-kbs-policy-v1",
            "policy_template_sha256": "04".repeat(32),
            "platform_release_version": "cap-test",
            "expected_agent_policy_hash": "05".repeat(32),
            "expected_cc_init_data_hash": "06".repeat(32),
            "expected_kbs_policy_hash": "07".repeat(32),
        });
        // #128: decode_optional_blobs verifies customer signatures, so the
        // fixture signs both envelopes with a real test key.
        let deployer_key = ed25519_dalek::SigningKey::from_bytes(&[0x09; 32]);
        let owner_key = ed25519_dalek::SigningKey::from_bytes(&[0x0b; 32]);
        let descriptor_typed: enclava_common::descriptor::DeploymentDescriptor =
            serde_json::from_value(descriptor.clone()).expect("descriptor fixture");
        let keyring = crate::signing_service::TestOrgKeyring {
            org_id: app.org_id,
            version: 1,
            members: vec![
                crate::signing_service::TestKeyringMember {
                    user_id: Uuid::new_v4(),
                    pubkey: deployer_key.verifying_key().to_bytes(),
                    role: crate::signing_service::TestKeyringRole::Deployer,
                    added_at: Utc::now(),
                },
                // The keyring envelope must be signed by an Owner member
                // (#128: decode_optional_blobs verifies signatures at decode
                // time, including the owner-role check on the signing pubkey).
                crate::signing_service::TestKeyringMember {
                    user_id: Uuid::new_v4(),
                    pubkey: owner_key.verifying_key().to_bytes(),
                    role: crate::signing_service::TestKeyringRole::Owner,
                    added_at: Utc::now(),
                },
            ],
            updated_at: Utc::now(),
        };
        let descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": hex::encode(
                deployer_key
                    .sign(&enclava_common::descriptor::descriptor_canonical_bytes(
                        &descriptor_typed
                    ))
                    .to_bytes()
            ),
            "signing_key_id": "test-deployer-key",
            "signing_pubkey": hex::encode(deployer_key.verifying_key().to_bytes()),
        })
        .to_string();
        let keyring_blob = serde_json::json!({
            "keyring": serde_json::to_value(&keyring).expect("keyring fixture"),
            "signature": hex::encode(
                owner_key
                    .sign(&crate::signing_service::canonical_keyring_bytes_test(&keyring))
                    .to_bytes()
            ),
            "signing_pubkey": hex::encode(owner_key.verifying_key().to_bytes()),
        })
        .to_string();
        let artifacts = crate::signing_service::decode_optional_blobs(
            Some(descriptor_blob),
            Some(keyring_blob),
        )
        .expect("decode test signing artifacts")
        .expect("test signing artifacts present");
        let signed = serde_json::from_value(serde_json::json!({
            "metadata": {
                "app_id": app.id.to_string(),
                "deploy_id": deploy_id.to_string(),
                "descriptor_core_hash": hex::encode(artifacts.descriptor_core_hash),
                "descriptor_signing_pubkey": hex::encode(artifacts.descriptor_signing_pubkey),
                "platform_release_version": "cap-test",
                "policy_template_id": "enclava-kbs-policy-v1",
                "policy_template_sha256": "04".repeat(32),
                "agent_policy_sha256": "05".repeat(32),
                "genpolicy_version_pin": "test",
                "signed_at": Utc::now().to_rfc3339(),
                "key_id": "test",
            },
            "rego_text": "package test",
            "rego_sha256": "0c".repeat(32),
            "agent_policy_text": "{}",
            "agent_policy_sha256": "05".repeat(32),
            "signature": B64.encode([0x0d; 64]),
            "verify_pubkey_b64": B64.encode([0x0e; 32]),
        }))
        .expect("decode test signed policy artifact");
        (artifacts, signed)
    }

    #[test]
    fn parses_public_unlock_mode_names() {
        assert_eq!(
            RequestedUnlockMode::parse("auto-unlock").unwrap(),
            RequestedUnlockMode::Auto
        );
        assert_eq!(
            RequestedUnlockMode::parse("auto").unwrap(),
            RequestedUnlockMode::Auto
        );
        assert_eq!(
            RequestedUnlockMode::parse("password").unwrap(),
            RequestedUnlockMode::Password
        );
        assert!(RequestedUnlockMode::parse("manual").is_err());
    }

    #[test]
    fn permits_only_supported_unlock_mode_transitions() {
        assert!(validate_transition(
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Auto
        ));
        assert!(validate_transition(
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Password
        ));
    }

    #[test]
    fn verifies_unlock_mode_transition_receipt_signature_and_payload() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let quote_hash = "ab".repeat(32);
        let receipt = signed_transition_receipt("password", "auto", &quote_hash, &signing_key);
        let verified = verify_transition_receipt(
            &receipt,
            &test_app(),
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto,
        )
        .expect("receipt verifies");
        assert_eq!(
            verified.pubkey_sha256_bytes,
            Sha256::digest(signing_key.verifying_key().to_bytes()).to_vec()
        );
        let attestation = transition_attestation(&signing_key, &quote_hash);
        verify_transition_attestation(&attestation, &test_app(), &verified).unwrap();
    }

    #[test]
    fn rejects_unlock_mode_transition_receipt_for_wrong_mode() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let receipt = signed_transition_receipt("auto", "password", &"ab".repeat(32), &signing_key);
        assert_eq!(
            verify_transition_receipt(
                &receipt,
                &test_app(),
                RequestedUnlockMode::Password,
                RequestedUnlockMode::Auto,
            )
            .unwrap_err(),
            "transition_receipt.payload.from_mode"
        );
    }

    #[test]
    fn rejects_unlock_mode_transition_receipt_bad_signature() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let mut receipt =
            signed_transition_receipt("password", "auto", &"ab".repeat(32), &signing_key);
        receipt.receipt.signature = B64.encode([0x55; 64]);
        assert_eq!(
            verify_transition_receipt(
                &receipt,
                &test_app(),
                RequestedUnlockMode::Password,
                RequestedUnlockMode::Auto,
            )
            .unwrap_err(),
            "transition_receipt.signature"
        );
    }

    #[test]
    fn rejects_transition_attestation_for_wrong_receipt_key() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let other_key = SigningKey::from_bytes(&[8; 32]);
        let quote_hash = "ab".repeat(32);
        let receipt = signed_transition_receipt("password", "auto", &quote_hash, &signing_key);
        let verified = verify_transition_receipt(
            &receipt,
            &test_app(),
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto,
        )
        .unwrap();
        let attestation = transition_attestation(&other_key, &quote_hash);
        assert_eq!(
            verify_transition_attestation(&attestation, &test_app(), &verified).unwrap_err(),
            "transition_attestation.receipt_pubkey_sha256"
        );
    }

    /// Decoded fields of the prove-it-live fixture bundle: a real VCEK-signed
    /// Genoa SNP report, its AMD chain (ARK byte-matches the builtin Genoa
    /// root the CLI pins), the recorded nonce, TLS leaf SPKI hash, and the
    /// attested receipt key.
    struct LiveQuoteFixture {
        report: Vec<u8>,
        ark_der: Vec<u8>,
        ask_der: Vec<u8>,
        vcek_der: Vec<u8>,
        crl_der: Vec<u8>,
        nonce: [u8; 32],
        leaf_spki_sha256: [u8; 32],
        receipt_pubkey: [u8; 32],
        tee_domain: String,
    }

    fn live_quote_fixture() -> LiveQuoteFixture {
        let encoded =
            include_str!("../../../enclava-verifier/tests/fixtures/prove-it-live.bundle.b64")
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect::<Vec<_>>();
        let bundle = B64.decode(encoded).expect("decode prove-it-live bundle");
        let records = enclava_common::canonical::ce_v1_decode(&bundle)
            .expect("parse prove-it-live bundle")
            .into_iter()
            .map(|record| (record.label.to_string(), record.value.to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let snp_report = records
            .get("snp_report")
            .expect("bundle snp report")
            .clone();
        let endorsements = records
            .get("amd_endorsements")
            .expect("bundle endorsements")
            .clone();
        let endorsement_records = enclava_common::canonical::ce_v1_decode(&endorsements)
            .expect("parse bundle endorsements")
            .into_iter()
            .map(|record| (record.label.to_string(), record.value.to_vec()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let field = |name: &str| {
            endorsement_records
                .get(name)
                .expect("endorsement field")
                .clone()
        };
        let leaf_spki_sha256 = enclava_verifier::tls_leaf_spki_sha256(
            records.get("tls_leaf_der").expect("bundle TLS leaf"),
        )
        .expect("bundle TLS leaf SPKI hash");

        LiveQuoteFixture {
            report: snp_report,
            ark_der: field("ark_der"),
            ask_der: field("ask_der"),
            vcek_der: field("vcek_der"),
            crl_der: field("crl_der"),
            nonce: records
                .get("challenge_nonce")
                .expect("bundle nonce")
                .as_slice()
                .try_into()
                .expect("32-byte nonce"),
            leaf_spki_sha256,
            receipt_pubkey: records
                .get("proxy_receipt_public_key")
                .expect("bundle receipt key")
                .as_slice()
                .try_into()
                .expect("32-byte receipt key"),
            tee_domain: "prove-it-independent-dev.e72a13df.dev.enclava.work".to_string(),
        }
    }

    fn live_quote_attestation(fixture: &LiveQuoteFixture) -> TransitionReceiptAttestation {
        TransitionReceiptAttestation {
            tee_domain: fixture.tee_domain.clone(),
            nonce: URL_SAFE_NO_PAD.encode(fixture.nonce),
            leaf_spki_sha256: hex::encode(fixture.leaf_spki_sha256),
            receipt_pubkey_sha256: hex::encode(Sha256::digest(fixture.receipt_pubkey)),
            attestation_evidence_sha256: hex::encode(Sha256::digest(&fixture.report)),
            quote: Some(TransitionSnpQuote {
                report_b64: B64.encode(&fixture.report),
                ark_der_b64: B64.encode(&fixture.ark_der),
                ask_der_b64: B64.encode(&fixture.ask_der),
                vcek_der_b64: B64.encode(&fixture.vcek_der),
                crl_der_b64: B64.encode(&fixture.crl_der),
            }),
        }
    }

    fn live_quote_receipt(fixture: &LiveQuoteFixture) -> SignedReceiptResponse {
        // A receipt whose envelope carries exactly the attested TEE receipt
        // key. `verify_transition_snp_quote` binds report_data to this key,
        // so the envelope must hold the fixture's public key bytes (deriving
        // a SigningKey from them would produce an unrelated key).
        SignedReceiptResponse {
            operation: "unlock_mode_transition".to_string(),
            payload: ReceiptPayloadView {
                purpose: "enclava-unlock-receipt-v1".to_string(),
                app_id: test_app().id.to_string(),
                resource_path: None,
                from_mode: Some("password".to_string()),
                to_mode: Some("auto".to_string()),
                attestation_quote_sha256: Some(hex::encode(Sha256::digest(&fixture.report))),
                new_value_sha256: None,
                timestamp: "2026-04-28T12:00:00Z".to_string(),
            },
            receipt: ReceiptEnvelope {
                pubkey: B64.encode(fixture.receipt_pubkey),
                pubkey_sha256: hex::encode(Sha256::digest(fixture.receipt_pubkey)),
                payload_canonical_bytes: B64.encode([0u8; 64]),
                signature: B64.encode([0u8; 64]),
            },
        }
    }

    /// Trusted time for the prove-it-live fixture: the capture time
    /// recorded by `enclava-verifier`'s `live_bundle.rs` (2026-08-04
    /// 12:00:00 UTC), inside the bundle CRL's this/nextUpdate window.
    const LIVE_QUOTE_TRUSTED_TIME_UNIX: u64 = 1_785_844_800;

    #[test]
    fn verifies_transition_snp_quote_from_live_vcek_signed_report() {
        let fixture = live_quote_fixture();
        let attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
            .expect("live VCEK-signed SNP quote with matching binding verifies");
    }

    /// Combined check against a fully valid signed receipt: the route's
    /// ordering (receipt signature first, then the SNP quote gate) applied
    /// to a receipt that passes `verify_transition_receipt` and a quote
    /// that fails only the quote gate. A positive end-to-end pass of both
    /// the signed-receipt and quote checks is impossible with the
    /// prove-it-live fixture: the fixture deliberately contains only the
    /// TEE receipt key's public half, so no signature valid under
    /// `verify_transition_receipt` can also bind the fixture quote's
    /// report_data (which commits that same public key). This test pins
    /// the next-best thing: a receipt that clears every signed check and a
    /// live VCEK-signed quote, rejected solely by the quote binding.
    #[test]
    fn signed_receipt_with_foreign_quote_is_rejected_by_quote_gate() {
        let fixture = live_quote_fixture();
        let attestation = live_quote_attestation(&fixture);
        // A genuine, correctly signed transition receipt under an
        // unrelated Ed25519 key: passes verify_transition_receipt when
        // paired with a matching attestation, but its key is not the key
        // the live quote commits, so the quote gate must reject.
        let signing_key = SigningKey::from_bytes(&[0x2a; 32]);
        let quote_hash = hex::encode(Sha256::digest(&fixture.report));
        let receipt = signed_transition_receipt("password", "auto", &quote_hash, &signing_key);
        verify_transition_receipt(
            &receipt,
            &test_app(),
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto,
        )
        .expect("receipt passes every signature/payload check on its own");
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::InvalidEvidence
        );
    }

    #[test]
    fn rejects_transition_snp_quote_that_differs_from_receipt_signed_evidence_hash() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let mut receipt = live_quote_receipt(&fixture);
        // Receipt signs evidence hash X (here: SHA256 of the TLS leaf),
        // while a genuinely valid quote of the report bytes verifies --
        // previously accepted, now must fail closed.
        let foreign_hash = hex::encode(fixture.leaf_spki_sha256);
        receipt.payload.attestation_quote_sha256 = Some(foreign_hash.clone());
        attestation.attestation_evidence_sha256 = foreign_hash;
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::EvidenceMismatch
        );
    }

    #[test]
    fn rejects_transition_snp_quote_from_debug_enabled_guest() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let mut receipt = live_quote_receipt(&fixture);
        // Set the guest policy DEBUG bit (bit 19) in the raw report bytes.
        // The debug gate runs before VCEK signature verification, so the
        // rejection is deterministically DebugPolicy even though the
        // tampered bytes would also break the signature.
        let mut report = fixture.report.clone();
        let policy = u64::from_le_bytes(report[0x08..0x10].try_into().unwrap());
        assert!(
            !snp_guest_policy_allows_debug(policy),
            "fixture policy must not have debug set"
        );
        report[0x0a] |= 0x08; // set bit 19 of the LE u64 policy
        let tampered_policy = u64::from_le_bytes(report[0x08..0x10].try_into().unwrap());
        assert!(snp_guest_policy_allows_debug(tampered_policy));
        attestation.quote = Some(TransitionSnpQuote {
            report_b64: B64.encode(&report),
            ..attestation.quote.clone().expect("quote present")
        });
        // Keep the receipt-signed evidence hash consistent with the
        // tampered bytes so the earlier hash gate passes and the debug
        // gate is the rejection reason under test.
        let tampered_hash = hex::encode(Sha256::digest(&report));
        receipt.payload.attestation_quote_sha256 = Some(tampered_hash.clone());
        attestation.attestation_evidence_sha256 = tampered_hash;
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::DebugPolicy
        );
    }

    #[test]
    fn transition_receipt_freshness_window_bounds_replay() {
        let now = Utc::now();
        assert!(transition_receipt_is_fresh(now, now));
        assert!(transition_receipt_is_fresh(
            now - chrono::Duration::seconds(14 * 60),
            now
        ));
        // Just inside the future-skew bound.
        assert!(transition_receipt_is_fresh(
            now + chrono::Duration::seconds(4 * 60),
            now
        ));
        // Too old and too far in the future are both rejected.
        assert!(!transition_receipt_is_fresh(
            now - chrono::Duration::seconds(16 * 60),
            now
        ));
        assert!(!transition_receipt_is_fresh(
            now + chrono::Duration::seconds(6 * 60),
            now
        ));
    }

    #[test]
    fn rejects_transition_snp_quote_when_report_data_is_tampered() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let mut receipt = live_quote_receipt(&fixture);
        let mut report = fixture.report.clone();
        report[0x50] ^= 1; // flip one report_data byte
        attestation.quote = Some(TransitionSnpQuote {
            report_b64: B64.encode(&report),
            ..attestation.quote.clone().expect("quote present")
        });
        // Re-sync the receipt-signed evidence hash to the tampered bytes so
        // the earlier hash gate passes and the rejection demonstrably comes
        // from SNP verification itself. The signature no longer covers the
        // mutated bytes, so the quote must fail closed -- exactly the
        // fabricated-self-consistent-package case from the issue.
        let tampered_hash = hex::encode(Sha256::digest(&report));
        receipt.payload.attestation_quote_sha256 = Some(tampered_hash.clone());
        attestation.attestation_evidence_sha256 = tampered_hash;
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::InvalidEvidence
        );
    }

    #[test]
    fn rejects_transition_snp_quote_for_wrong_tee_domain() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        attestation.tee_domain = "attacker.example".to_string();
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::InvalidEvidence
        );
    }

    #[test]
    fn rejects_transition_snp_quote_with_unanchored_chain() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        // Replace the ARK with the (pinned) Milan root: a real AMD root, but
        // not the one that signed this chain, so anchoring must reject it.
        let milan_ark_der = milan_builtin_ark_der();
        attestation.quote = Some(TransitionSnpQuote {
            ark_der_b64: B64.encode(&milan_ark_der),
            ..attestation.quote.clone().expect("quote present")
        });
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::InvalidEvidence
        );
    }

    #[test]
    fn rejects_transition_snp_quote_when_missing() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        attestation.quote = None;
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::Missing
        );
    }

    #[test]
    fn rejects_transition_snp_quote_without_revocation_collateral() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        // Drop the CRL entirely: a chain that internally verifies but has no
        // revocation collateral must fail closed, not pass on signature
        // alone.
        attestation.quote = Some(TransitionSnpQuote {
            crl_der_b64: String::new(),
            ..attestation.quote.clone().expect("quote present")
        });
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::Malformed
        );
    }

    #[test]
    fn rejects_transition_snp_quote_with_stale_crl() {
        let fixture = live_quote_fixture();
        let attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        // Same bundle verified at a time past the CRL's nextUpdate
        // (2026-09-09): the revocation gate must treat the collateral as
        // expired. 2027-01-01T00:00:00Z.
        const PAST_NEXT_UPDATE: u64 = 1_792_761_600;
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, PAST_NEXT_UPDATE).unwrap_err(),
            TransitionQuoteError::RevocationRejected
        );
    }

    #[test]
    fn rejects_transition_snp_quote_with_oversized_fields_before_decoding() {
        // Base64 decoding allocates proportionally to the submitted string:
        // an oversized field must be rejected by a length comparison before
        // any decode allocation, not by allocating for it first.
        let fixture = live_quote_fixture();
        let receipt = live_quote_receipt(&fixture);
        // A multi-megabyte base64 blob: without the pre-decode length gate
        // this allocates the full decoded buffer before rejection.
        let oversized_b64 = "A".repeat(8 * 1024 * 1024);
        for oversized in [
            TransitionSnpQuote {
                report_b64: oversized_b64.clone(),
                ..live_quote_attestation(&fixture)
                    .quote
                    .clone()
                    .expect("quote present")
            },
            TransitionSnpQuote {
                ark_der_b64: oversized_b64.clone(),
                ..live_quote_attestation(&fixture)
                    .quote
                    .clone()
                    .expect("quote present")
            },
            TransitionSnpQuote {
                crl_der_b64: oversized_b64,
                ..live_quote_attestation(&fixture)
                    .quote
                    .clone()
                    .expect("quote present")
            },
        ] {
            let mut attestation = live_quote_attestation(&fixture);
            attestation.quote = Some(oversized);
            assert_eq!(
                verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                    .unwrap_err(),
                TransitionQuoteError::Malformed
            );
        }
    }

    #[test]
    fn rejects_transition_snp_quote_with_tampered_crl() {
        let fixture = live_quote_fixture();
        let mut attestation = live_quote_attestation(&fixture);
        let receipt = live_quote_receipt(&fixture);
        // Flip one byte of the ARK-signed CRL: the RSA-PSS signature check
        // must reject the forged revocation list.
        let mut crl = fixture.crl_der.clone();
        let last = crl.len() - 1;
        crl[last] ^= 0xff;
        attestation.quote = Some(TransitionSnpQuote {
            crl_der_b64: B64.encode(&crl),
            ..attestation.quote.clone().expect("quote present")
        });
        assert_eq!(
            verify_transition_snp_quote(&attestation, &receipt, LIVE_QUOTE_TRUSTED_TIME_UNIX)
                .unwrap_err(),
            TransitionQuoteError::RevocationRejected
        );
    }

    /// The builtin Milan ARK DER, as `sev::certs::snp::builtin::milan::ark()`
    /// delivers it. Hash-pinned here so a `sev` bump that changes the root
    /// is caught: it is one of the API's accepted anchors.
    fn milan_builtin_ark_der() -> Vec<u8> {
        let der = B64
            .decode(
                include_str!("../../../enclava-verifier/tests/fixtures/milan-builtin-ark.der.b64")
                    .trim(),
            )
            .expect("decode Milan builtin ARK fixture");
        assert_eq!(
            hex::encode(Sha256::digest(&der)),
            "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd",
            "Milan builtin ARK pin must match BUILTIN_AMD_ARK_SHA256_PINS[0]"
        );
        der
    }

    /// Sync guard against sev root rotation: every ARK the sev crate ships
    /// as a builtin must be pinned in BUILTIN_AMD_ARK_SHA256_PINS, and the
    /// pin set must not contain roots sev no longer ships. Without this a
    /// sev upgrade that rotates a root would leave the API rejecting every
    /// unlock transition (UntrustedAnchor) while the CLI happily verifies
    /// the new chain client-side.
    #[test]
    fn ark_pin_set_matches_sev_builtin_roots() {
        let mut sev_roots: Vec<String> = Vec::new();
        for ark in [
            sev::certs::snp::builtin::milan::ark(),
            sev::certs::snp::builtin::genoa::ark(),
            sev::certs::snp::builtin::turin::ark(),
        ] {
            let ark = ark.expect("load sev builtin ARK");
            let der = ark.to_der().expect("serialize sev builtin ARK to DER");
            sev_roots.push(hex::encode(Sha256::digest(&der)));
        }
        let pinned: Vec<String> = BUILTIN_AMD_ARK_SHA256_PINS
            .iter()
            .map(hex::encode)
            .collect();
        for root in &sev_roots {
            assert!(
                pinned.contains(root),
                "sev builtin ARK {root} is not pinned; a sev bump rotated the root set"
            );
        }
        assert_eq!(
            sev_roots.len(),
            pinned.len(),
            "pin set and sev builtin root set have drifted"
        );
    }

    async fn commit_signed_workload<'a>(
        pool: &sqlx::PgPool,
        fixture: &'a UnlockTestFixture,
        command: Option<&'a str>,
        port: Option<i32>,
        paths: Option<&'a Vec<String>>,
        timestamp: &str,
        key_byte: u8,
    ) -> Result<super::CommittedUnlockModeTransition, (StatusCode, Json<serde_json::Value>)> {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let quote_hash = hex::encode([key_byte; 32]);
        let receipt = signed_transition_receipt_for_app(
            fixture.app.id,
            timestamp,
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &fixture.app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify signed-workload receipt");
        let attestation = transition_attestation_for_domain(
            fixture.app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        commit_unlock_mode_transition(
            pool,
            UnlockModeCommitRequest {
                org_id: fixture.app.org_id,
                user_id: fixture.user_id,
                app_name: &fixture.app.name,
                observed_authority: &fixture.authority,
                source_deployment_id: fixture.source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id: Uuid::new_v4(),
                image_digest: Some(image_digest),
                signed_workload_command: command,
                signed_container_port: port,
                signed_storage_paths: paths,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await
    }

    #[tokio::test]
    async fn rewritten_signed_command_is_rejected_before_primary_update() {
        let pool = database_test_pool().await;
        let fixture = insert_unlock_test_app(&pool).await;
        let paths = vec!["/data".to_string()];
        let result = commit_signed_workload(
            &pool,
            &fixture,
            Some("[\"/bin/rewritten\"]"),
            Some(8080),
            Some(&paths),
            "2026-07-17T11:10:00Z",
            23,
        )
        .await;
        let (status, body) = result.expect_err("rewritten command must not commit");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            body.0["error"],
            "signed descriptor command does not match the locked primary"
        );

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(fixture.app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after rewritten command");
        assert_eq!(persisted_mode, "auto");
        let persisted: AppContainer =
            sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 AND is_primary = true")
                .bind(fixture.app.id)
                .fetch_one(&pool)
                .await
                .expect("load primary after rewritten command");
        assert_eq!(persisted.command.as_deref(), Some("[\"/bin/old\"]"));
        assert_eq!(persisted.port, Some(8080));
        assert_eq!(persisted.storage_paths, Some(vec!["/data".to_string()]));
        delete_unlock_test_org(&pool, fixture.app.org_id).await;
    }

    #[tokio::test]
    async fn state_only_primary_is_stored_as_the_normalized_signed_paths() {
        let pool = database_test_pool().await;
        let mut fixture = insert_unlock_test_app(&pool).await;
        sqlx::query(
            "UPDATE app_containers SET storage_paths = $1 WHERE app_id = $2 AND is_primary = true",
        )
        .bind(vec!["/state".to_string()])
        .bind(fixture.app.id)
        .execute(&pool)
        .await
        .expect("set state-only storage paths");
        let containers: Vec<AppContainer> = sqlx::query_as(
            "SELECT * FROM app_containers WHERE app_id = $1 ORDER BY is_primary DESC, id",
        )
        .bind(fixture.app.id)
        .fetch_all(&pool)
        .await
        .expect("reload state-only containers");
        let resources: crate::models::AppResources =
            sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
                .bind(fixture.app.id)
                .fetch_one(&pool)
                .await
                .expect("reload state-only resources");
        fixture.authority = crate::deploy::ExistingAppAuthoritySnapshot::new(
            fixture.app.updated_at,
            containers,
            resources,
        );
        let paths = Vec::<String>::new();
        let result = commit_signed_workload(
            &pool,
            &fixture,
            Some("[\"/bin/old\"]"),
            Some(8080),
            Some(&paths),
            "2026-07-17T11:20:00Z",
            24,
        )
        .await;
        assert!(
            result.is_ok(),
            "empty signed paths must match a /state-only column, got {result:?}"
        );

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(fixture.app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after empty-path transition");
        assert_eq!(persisted_mode, "password");
        let persisted: AppContainer =
            sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 AND is_primary = true")
                .bind(fixture.app.id)
                .fetch_one(&pool)
                .await
                .expect("load primary after empty-path transition");
        assert_eq!(persisted.command.as_deref(), Some("[\"/bin/old\"]"));
        assert_eq!(persisted.port, Some(8080));
        assert_eq!(
            persisted.storage_paths,
            Some(Vec::<String>::new()),
            "the stored primary must drop /state so the apply snapshot matches the signed render"
        );
        let payload: serde_json::Value = sqlx::query_scalar(
            "SELECT payload FROM deployment_apply_jobs WHERE app_id = $1 AND deployment_id <> $2",
        )
        .bind(fixture.app.id)
        .bind(fixture.source_deployment_id)
        .fetch_one(&pool)
        .await
        .expect("load apply payload");
        assert_eq!(
            payload["snapshot"]["containers"][0]["storage_paths"],
            serde_json::json!([]),
            "validate_signed_render and apply_deployment_manifests render this snapshot, not the raw column"
        );
        delete_unlock_test_org(&pool, fixture.app.org_id).await;
    }

    #[tokio::test]
    async fn audit_failure_rolls_back_unlock_mode_runtime_receipt_and_deployment() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[17; 32]);
        let quote_hash = "ab".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T10:00:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify test transition receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let deploy_id = Uuid::new_v4();
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        // The stored primary. A rewritten command is rejected before this
        // transaction reaches the audit insert, so the rollback fixture has
        // to present the workload the handler locks.
        let new_command = "[\"/bin/old\"]";
        let new_storage_paths = vec!["/data".to_string()];

        let suffix = app.id.simple().to_string();
        let function_name = format!("cap_test_block_unlock_audit_{suffix}");
        let trigger_name = format!("cap_test_block_unlock_audit_trigger_{suffix}");
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.app_id = '{}'::uuid THEN
                 RAISE EXCEPTION 'forced unlock audit failure';
               END IF;
               RETURN NEW;
             END
             $$",
            app.id
        ))
        .execute(&pool)
        .await
        .expect("create unlock audit failure function");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE INSERT ON audit_log
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .expect("create unlock audit failure trigger");

        let result = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: Some(new_command),
                signed_container_port: Some(8080),
                signed_storage_paths: Some(&new_storage_paths),
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await;
        let (status, _) = result.expect_err("mandatory audit failure rejects transition");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load rolled-back unlock mode");
        assert_eq!(persisted_mode, "auto");
        let persisted_container: AppContainer =
            sqlx::query_as("SELECT * FROM app_containers WHERE app_id = $1 AND is_primary = true")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load rolled-back primary container");
        assert_eq!(
            persisted_container.command.as_deref(),
            Some("[\"/bin/old\"]")
        );
        assert_eq!(persisted_container.port, Some(8080));
        assert_eq!(
            persisted_container.storage_paths,
            Some(vec!["/data".to_string()])
        );
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count rolled-back receipts");
        assert_eq!(receipt_count, 0);
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE id = $1")
                .bind(deploy_id)
                .fetch_one(&pool)
                .await
                .expect("count rolled-back deployment");
        assert_eq!(deployment_count, 0);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.unlock_mode.update'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count rolled-back audit rows");
        assert_eq!(audit_count, 0);

        sqlx::query(&format!("DROP TRIGGER {trigger_name} ON audit_log"))
            .execute(&pool)
            .await
            .expect("drop unlock audit failure trigger");
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .expect("drop unlock audit failure function");
        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn deployment_insert_failure_rolls_back_unlock_mode_and_receipt() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[19; 32]);
        let quote_hash = "bc".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T10:30:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify deployment failure receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let deploy_id = Uuid::new_v4();
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        sqlx::query(
            "INSERT INTO deployments (
                 id, org_id, app_id, trigger, status, spec_snapshot, image_digest
             ) VALUES ($1, $2, $3, 'api', 'failed'::deploy_status_enum, '{}'::jsonb, $4)",
        )
        .bind(deploy_id)
        .bind(app.org_id)
        .bind(app.id)
        .bind(image_digest)
        .execute(&pool)
        .await
        .expect("reserve duplicate deployment id");

        let result = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await;
        let (status, _) = result.expect_err("deployment insert failure rejects transition");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after deployment failure");
        assert_eq!(persisted_mode, "auto");
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count receipts after deployment failure");
        assert_eq!(receipt_count, 0);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.unlock_mode.update'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count audits after deployment failure");
        assert_eq!(audit_count, 0);

        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn durable_job_insert_failure_rolls_back_entire_unlock_transition() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[20; 32]);
        let quote_hash = "be".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T10:40:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify durable-job failure receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let deploy_id = Uuid::new_v4();
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let suffix = app.id.simple().to_string();
        let function_name = format!("cap_test_block_unlock_job_{suffix}");
        let trigger_name = format!("cap_test_block_unlock_job_trigger_{suffix}");
        sqlx::query(&format!(
            "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.deployment_id = '{deploy_id}'::uuid THEN
                 RAISE EXCEPTION 'forced unlock durable job failure';
               END IF;
               RETURN NEW;
             END
             $$"
        ))
        .execute(&pool)
        .await
        .expect("create durable-job failure function");
        sqlx::query(&format!(
            "CREATE TRIGGER {trigger_name}
             BEFORE INSERT ON deployment_apply_jobs
             FOR EACH ROW EXECUTE FUNCTION {function_name}()"
        ))
        .execute(&pool)
        .await
        .expect("create durable-job failure trigger");

        let result = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await;
        let (status, _) = result.expect_err("durable job failure rejects transition");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after durable-job failure");
        assert_eq!(persisted_mode, "auto");
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count receipts after durable-job failure");
        assert_eq!(receipt_count, 0);
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE id = $1")
                .bind(deploy_id)
                .fetch_one(&pool)
                .await
                .expect("count deployment after durable-job failure");
        assert_eq!(deployment_count, 0);
        let job_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM deployment_apply_jobs WHERE deployment_id = $1",
        )
        .bind(deploy_id)
        .fetch_one(&pool)
        .await
        .expect("count job after durable-job failure");
        assert_eq!(job_count, 0);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.unlock_mode.update'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count audit after durable-job failure");
        assert_eq!(audit_count, 0);

        sqlx::query(&format!(
            "DROP TRIGGER {trigger_name} ON deployment_apply_jobs"
        ))
        .execute(&pool)
        .await
        .expect("drop durable-job failure trigger");
        sqlx::query(&format!("DROP FUNCTION {function_name}()"))
            .execute(&pool)
            .await
            .expect("drop durable-job failure function");
        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn invalid_artifact_authority_rejects_unlock_atomically() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[21; 32]);
        let quote_hash = "bd".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T10:45:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify artifact failure receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let deploy_id = Uuid::new_v4();
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let api_signing_pubkey = "test-api-signing-key";
        let (artifacts, signed) =
            test_signing_artifacts(&app, deploy_id, image_digest, api_signing_pubkey);
        let stored_command = "[\"/bin/old\"]";
        let stored_paths = vec!["/data".to_string()];

        let result = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: Some(stored_command),
                signed_container_port: Some(8080),
                signed_storage_paths: Some(&stored_paths),
                signing_artifacts: Some(&artifacts),
                signed_policy_artifact: Some(&signed),
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey,
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await;
        let (status, _) = result.expect_err("invalid artifact authority rejects transition");
        assert!(
            matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::SERVICE_UNAVAILABLE
            ),
            "invalid signed authority must fail before persistence, got {status}"
        );

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after artifact failure");
        assert_eq!(persisted_mode, "auto");
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count receipts after artifact failure");
        assert_eq!(receipt_count, 0);
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE id = $1")
                .bind(deploy_id)
                .fetch_one(&pool)
                .await
                .expect("count deployment after artifact failure");
        assert_eq!(deployment_count, 0);
        let artifact_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM workload_artifacts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count artifacts after artifact failure");
        assert_eq!(artifact_count, 0);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.unlock_mode.update'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count audits after artifact failure");
        assert_eq!(audit_count, 0);

        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn concurrent_duplicate_transition_receipt_commits_exactly_once() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[23; 32]);
        let quote_hash = "cd".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T11:00:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify duplicate test receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let first_deploy_id = Uuid::new_v4();
        let second_deploy_id = Uuid::new_v4();
        let first = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id: first_deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        );
        let second = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id: second_deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        );

        let (first, second) = tokio::join!(first, second);
        let mut success_count = 0;
        let mut replay_conflict_count = 0;
        for result in [first, second] {
            match result {
                Ok(_) => success_count += 1,
                Err((status, body)) => {
                    assert_eq!(status, StatusCode::CONFLICT);
                    assert_eq!(body.0["error"], "replayed transition_receipt");
                    replay_conflict_count += 1;
                }
            }
        }
        assert_eq!(success_count, 1);
        assert_eq!(replay_conflict_count, 1);

        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load committed unlock mode");
        assert_eq!(persisted_mode, "password");
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count committed transition receipts");
        assert_eq!(receipt_count, 1);
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE id IN ($1, $2)")
                .bind(first_deploy_id)
                .bind(second_deploy_id)
                .fetch_one(&pool)
                .await
                .expect("count committed unlock deployments");
        assert_eq!(deployment_count, 1);
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.unlock_mode.update'",
        )
        .bind(app.id)
        .fetch_one(&pool)
        .await
        .expect("count committed unlock audits");
        assert_eq!(audit_count, 1);
        let receipt_index_is_unique: bool = sqlx::query_scalar(
            "SELECT indisunique
               FROM pg_index
              WHERE indexrelid = 'idx_unlock_transition_receipts_app_timestamp'::regclass",
        )
        .fetch_one(&pool)
        .await
        .expect("load receipt replay index metadata");
        assert!(receipt_index_is_unique);

        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn unlock_mode_transition_rejects_while_app_mutation_lease_is_live() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[24; 32]);
        let quote_hash = "ef".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T11:20:00Z",
            "auto",
            "password",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Auto,
            RequestedUnlockMode::Password,
        )
        .expect("verify busy-fence test receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let image_digest =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let org_id = app.org_id;
        let app_name = app.name.clone();

        // Simulate a desired-state stop converging with the deployment lane
        // released: the mutation lease row is live and heartbeated (#95).
        // Accepting authority-snapshotted work now would let the stop's
        // terminal publish invalidate it, so acceptance must fail busy.
        sqlx::query(
            "INSERT INTO app_mutation_leases (app_id) VALUES ($1)
             ON CONFLICT (app_id) DO NOTHING",
        )
        .bind(app.id)
        .execute(&pool)
        .await
        .expect("seed app mutation lease row");
        sqlx::query(
            "UPDATE app_mutation_leases
                SET owner_token = $2,
                    operation_kind = 'app_desired_state',
                    operation_id = $3,
                    locked_until = clock_timestamp() + interval '30 seconds',
                    reclaim_after = clock_timestamp() + interval '60 seconds'
              WHERE app_id = $1",
        )
        .bind(app.id)
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("hold app mutation lease");

        let (status, body) = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id,
                user_id,
                app_name: &app_name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id: Uuid::new_v4(),
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await
        .expect_err("live mutation lease fences acceptance");
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body.0["error"], "app mutation already in progress");

        sqlx::query(
            "UPDATE app_mutation_leases
                SET owner_token = NULL,
                    operation_kind = NULL,
                    operation_id = NULL,
                    locked_until = NULL,
                    reclaim_after = NULL
              WHERE app_id = $1",
        )
        .bind(app.id)
        .execute(&pool)
        .await
        .expect("release app mutation lease");
        commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id,
                user_id,
                app_name: &app_name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Password,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id: Uuid::new_v4(),
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await
        .expect("released mutation lease admits the transition");

        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[tokio::test]
    async fn commit_authority_rejects_auto_target_before_any_persistence() {
        let pool = database_test_pool().await;
        let UnlockTestFixture {
            app,
            user_id,
            source_deployment_id,
            authority,
        } = insert_unlock_test_app(&pool).await;
        let signing_key = SigningKey::from_bytes(&[25; 32]);
        let quote_hash = "fa".repeat(32);
        let receipt = signed_transition_receipt_for_app(
            app.id,
            "2026-07-17T11:30:00Z",
            "password",
            "auto",
            &quote_hash,
            &signing_key,
        );
        let verified_receipt = verify_transition_receipt(
            &receipt,
            &app,
            RequestedUnlockMode::Password,
            RequestedUnlockMode::Auto,
        )
        .expect("verify backstop test receipt");
        let attestation = transition_attestation_for_domain(
            app.tee_domain.as_deref().expect("test TEE domain"),
            &signing_key,
            &quote_hash,
        );
        let receipt_json = serde_json::to_value(&receipt).expect("serialize receipt");
        let deploy_id = Uuid::new_v4();

        let (status, body) = commit_unlock_mode_transition(
            &pool,
            UnlockModeCommitRequest {
                org_id: app.org_id,
                user_id,
                app_name: &app.name,
                observed_authority: &authority,
                source_deployment_id,
                requested: RequestedUnlockMode::Auto,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: None,
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: None,
                signed_policy_artifact: None,
                descriptor_platform_binding: &EMPTY_PLATFORM_BINDING,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
                fresh_volume_claims: enclava_engine::apply::orchestrator::FreshVolumeClaims::ALL,
            },
        )
        .await
        .expect_err("auto target must never commit");
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.0["error"], "auto_unlock_disabled");

        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE id = $1")
                .bind(deploy_id)
                .fetch_one(&pool)
                .await
                .expect("count deployments after auto rejection");
        assert_eq!(deployment_count, 0);
        let receipt_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM unlock_transition_receipts WHERE app_id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("count receipts after auto rejection");
        assert_eq!(receipt_count, 0);
        let persisted_mode: String =
            sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
                .bind(app.id)
                .fetch_one(&pool)
                .await
                .expect("load mode after auto rejection");
        assert_eq!(persisted_mode, "auto");

        delete_unlock_test_org(&pool, app.org_id).await;
    }

    #[test]
    fn auto_unlock_disabled_rejection_is_forbidden_with_stable_code() {
        let (status, body) = auto_unlock_disabled_error();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body.0["error"], "auto_unlock_disabled");
    }

    #[test]
    fn tee_ownership_state_parses_guest_status_fields() {
        assert_eq!(
            tee_ownership_state_from_value(&serde_json::json!({"ownership_state": "locked"})),
            Some("locked".to_string())
        );
        assert_eq!(
            tee_ownership_state_from_value(&serde_json::json!({"state": "unlocked"})),
            Some("unlocked".to_string())
        );
        assert_eq!(
            tee_ownership_state_from_value(&serde_json::json!({"ownership_state": 7})),
            None
        );
        assert_eq!(tee_ownership_state_from_value(&serde_json::json!({})), None);
    }

    fn generation_fixture(
        status: &str,
        generation_digest: &str,
        port: Option<i32>,
        profile: Option<&str>,
        snapshot_profile: &str,
    ) -> (
        super::ApplyGenerationRow,
        crate::models::AppContainer,
        crate::models::AppResources,
    ) {
        let digest = generation_digest.to_string();
        let generation = (
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            status.to_string(),
            Some(digest.clone()),
            serde_json::json!({
                "resolved_resources": {
                    "cpu": "1",
                    "memory": "1Gi",
                    "storage": "5Gi",
                    "tls_storage": "2Gi"
                },
                "workload_security_profile": snapshot_profile
            }),
        );
        let primary = crate::models::AppContainer {
            id: Uuid::nil(),
            app_id: Uuid::nil(),
            name: "app".to_string(),
            image_ref: format!("ghcr.io/acme/app@{digest}"),
            image_digest: Some(digest),
            port,
            command: Some("[\"/bin/app\"]".to_string()),
            storage_paths: Some(vec!["/data".to_string()]),
            workload_security_profile: profile.map(str::to_string),
            is_primary: true,
        };
        let resources = crate::models::AppResources {
            app_id: Uuid::nil(),
            cpu_limit: "1".to_string(),
            memory_limit: "1Gi".to_string(),
            app_data_size: "5Gi".to_string(),
            tls_data_size: "2Gi".to_string(),
        };
        (generation, primary, resources)
    }

    #[test]
    fn omit_claim_pin_is_rejected_when_the_generation_has_a_recipient() {
        let recipient = enclava_engine::types::LogEncryptionConfig {
            algorithm: "x25519-hpke-v1".to_string(),
            key_id: "log-key".to_string(),
            public_key_base64url: "pubkey".to_string(),
            public_key_sha256: "hash".to_string(),
        };
        assert!(super::reject_omitted_log_recipient(true, Some(&recipient)).is_err());
        assert!(super::reject_omitted_log_recipient(false, Some(&recipient)).is_ok());
        assert!(super::reject_omitted_log_recipient(true, None).is_ok());
    }

    #[test]
    fn signed_workload_match_drops_state_and_rejects_a_rewritten_primary() {
        let primary = crate::models::AppContainer {
            id: Uuid::nil(),
            app_id: Uuid::nil(),
            name: "app".to_string(),
            image_ref: "ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            image_digest: None,
            port: Some(8080),
            command: Some("[\"/bin/old\"]".to_string()),
            storage_paths: Some(vec!["/data".to_string(), "/state".to_string()]),
            workload_security_profile: None,
            is_primary: true,
        };
        let data = vec!["/data".to_string()];
        assert!(
            super::signed_workload_matches_locked_primary(
                &primary,
                Some("[\"/bin/old\"]"),
                Some(8080),
                Some(&data),
            )
            .is_ok()
        );
        assert_eq!(
            super::signed_workload_matches_locked_primary(
                &primary,
                Some("[\"/bin/rewritten\"]"),
                Some(8080),
                Some(&data),
            )
            .unwrap_err(),
            "signed descriptor command does not match the locked primary"
        );
        assert_eq!(
            super::signed_workload_matches_locked_primary(
                &primary,
                Some("[\"/bin/old\"]"),
                Some(9090),
                Some(&data),
            )
            .unwrap_err(),
            "signed descriptor port does not match the locked primary"
        );
        let rewritten = vec!["/other".to_string()];
        assert_eq!(
            super::signed_workload_matches_locked_primary(
                &primary,
                Some("[\"/bin/old\"]"),
                Some(8080),
                Some(&rewritten),
            )
            .unwrap_err(),
            "signed descriptor storage paths do not match the locked primary"
        );
        let mut state_only = primary.clone();
        state_only.storage_paths = Some(vec!["/state".to_string()]);
        let empty = Vec::<String>::new();
        assert!(
            super::signed_workload_matches_locked_primary(
                &state_only,
                Some("[\"/bin/old\"]"),
                Some(8080),
                Some(&empty),
            )
            .is_ok(),
            "a /state-only column is the honest empty user-path list"
        );
        assert!(super::signed_workload_matches_locked_primary(&primary, None, None, None).is_ok());
        assert_eq!(
            super::signed_workload_matches_locked_primary(
                &primary,
                Some("[\"/bin/old\"]"),
                None,
                Some(&data),
            )
            .unwrap_err(),
            "signed descriptor omitted command, port, or storage paths"
        );
    }

    #[test]
    fn signed_identity_rejects_a_rewritten_name_or_limit() {
        use enclava_common::descriptor::EnvVar;
        let primary = crate::models::AppContainer {
            id: Uuid::nil(),
            app_id: Uuid::nil(),
            name: "app".to_string(),
            image_ref: "ghcr.io/acme/app:latest".to_string(),
            image_digest: None,
            port: Some(8080),
            command: None,
            storage_paths: None,
            workload_security_profile: None,
            is_primary: true,
        };
        let resources = crate::models::AppResources {
            app_id: Uuid::nil(),
            cpu_limit: "1".to_string(),
            memory_limit: "1Gi".to_string(),
            app_data_size: "5Gi".to_string(),
            tls_data_size: "2Gi".to_string(),
        };
        let env = |name: &str| {
            vec![EnvVar {
                name: "ENCLAVA_CONTAINER_NAME".to_string(),
                value: name.to_string(),
            }]
        };
        let limits = |cpu: &str, memory: &str| {
            vec![
                EnvVar {
                    name: "cpu".to_string(),
                    value: cpu.to_string(),
                },
                EnvVar {
                    name: "memory".to_string(),
                    value: memory.to_string(),
                },
            ]
        };
        assert!(
            super::signed_identity_matches_locked_runtime(
                &primary,
                &resources,
                &env("app"),
                &limits("1", "1Gi"),
            )
            .is_ok()
        );
        assert_eq!(
            super::signed_identity_matches_locked_runtime(
                &primary,
                &resources,
                &env("rewritten"),
                &limits("1", "1Gi"),
            )
            .unwrap_err(),
            "signed descriptor container name does not match the locked primary"
        );
        assert_eq!(
            super::signed_identity_matches_locked_runtime(
                &primary,
                &resources,
                &env("app"),
                &limits("2", "1Gi"),
            )
            .unwrap_err(),
            "signed descriptor cpu limit does not match the locked resources"
        );
        assert_eq!(
            super::signed_identity_matches_locked_runtime(
                &primary,
                &resources,
                &env("app"),
                &limits("1", "2Gi"),
            )
            .unwrap_err(),
            "signed descriptor memory limit does not match the locked resources"
        );
    }

    #[test]
    fn locked_generation_is_the_apply_job_row_not_a_healthy_container() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut app = test_app();
        app.signer_identity_subject = Some("cosign-subject".to_string());
        app.signer_identity_issuer =
            Some("https://token.actions.githubusercontent.com".to_string());
        let (generation, primary, resources) = generation_fixture(
            "healthy",
            digest,
            Some(9090),
            Some("rootful-sudo"),
            "rootful-sudo",
        );
        let ok =
            locked_generation_snapshot(Some(&generation), Some(&primary), Some(&resources), &app);
        assert!(ok.acceptable, "{ok:?}");
        assert_eq!(ok.source, LOCKED_GENERATION_SOURCE);
        assert_eq!(ok.port, Some(9090));
        assert_eq!(ok.container_name.as_deref(), Some("app"));
        assert_eq!(
            ok.workload_security_profile.as_deref(),
            Some("rootful-sudo")
        );
        assert_eq!(ok.image_ref.as_deref(), Some(primary.image_ref.as_str()));
        assert_eq!(ok.app.as_ref().map(|identity| identity.id), Some(app.id));
        assert!(ok.app.as_ref().unwrap().signer_identity_subject == "cosign-subject");
        assert!(ok.log_encryption.is_none());
        let wire = serde_json::to_value(&ok).expect("serialize locked generation");
        assert!(
            wire.get("log_encryption")
                .is_some_and(|value| value.is_null()),
            "a no-recipient generation must emit explicit null, not omit the field: {wire}"
        );

        let mut stopped = app.clone();
        stopped.status = AppStatus::Stopped;
        let stopped = locked_generation_snapshot(
            Some(&generation),
            Some(&primary),
            Some(&resources),
            &stopped,
        );
        assert_eq!(
            stopped.refusal.as_deref(),
            Some("start the stopped app before deploying")
        );

        let mut empty_paths = primary.clone();
        empty_paths.storage_paths = Some(vec!["/state".to_string()]);
        let empty = locked_generation_snapshot(
            Some(&generation),
            Some(&empty_paths),
            Some(&resources),
            &app,
        );
        assert!(empty.acceptable, "{empty:?}");
        assert_eq!(empty.storage_paths.as_deref(), Some(&[][..]));

        let mut deleting = app.clone();
        deleting.status = AppStatus::Deleting;
        let deleting = locked_generation_snapshot(
            Some(&generation),
            Some(&primary),
            Some(&resources),
            &deleting,
        );
        assert_eq!(
            deleting.refusal.as_deref(),
            Some("app deletion is in progress")
        );

        let (pending, primary, resources) = generation_fixture(
            "pending",
            digest,
            Some(9090),
            Some("restricted"),
            "restricted",
        );
        let refused =
            locked_generation_snapshot(Some(&pending), Some(&primary), Some(&resources), &app);
        assert!(!refused.acceptable);
        assert!(refused.image_ref.is_none());
        assert_eq!(
            refused.refusal.as_deref(),
            Some("current deployment generation is still in progress")
        );

        let (watching, primary, resources) = generation_fixture(
            "watching",
            digest,
            Some(9090),
            Some("restricted"),
            "restricted",
        );
        assert!(
            !locked_generation_snapshot(Some(&watching), Some(&primary), Some(&resources), &app)
                .acceptable
        );

        let (healthy, mut drifted, resources) = generation_fixture(
            "healthy",
            digest,
            Some(9090),
            Some("restricted"),
            "restricted",
        );
        drifted.image_digest = Some(format!("sha256:{}", "b".repeat(64)));
        let drifted =
            locked_generation_snapshot(Some(&healthy), Some(&drifted), Some(&resources), &app);
        assert_eq!(
            drifted.refusal.as_deref(),
            Some("current runtime does not match its deployment generation")
        );

        let (healthy, mut omitted_port, resources) =
            generation_fixture("healthy", digest, None, Some("restricted"), "restricted");
        omitted_port.port = None;
        let omitted =
            locked_generation_snapshot(Some(&healthy), Some(&omitted_port), Some(&resources), &app);
        assert_eq!(
            omitted.refusal.as_deref(),
            Some("stored primary omitted port; refusing to assume 8080")
        );
        assert!(omitted.port.is_none());

        let missing = locked_generation_snapshot(None, Some(&primary), Some(&resources), &app);
        assert_eq!(
            missing.refusal.as_deref(),
            Some("app has no deployment generation")
        );
        assert_eq!(missing.source, LOCKED_GENERATION_SOURCE);
    }

    /// With no admissible launch identity the attested channel fails closed:
    /// `ownership_state` must be null even though the unverified
    /// `state.tee_http_client` is wired to a live TLS endpoint that would
    /// happily answer `{"ownership_state":"unlocked"}` — any fallback to it
    /// is observable as `Some("unlocked")` and fails this test.
    #[tokio::test]
    async fn unlock_status_reports_null_when_attestation_fails() {
        use std::net::SocketAddr;
        use std::sync::Once;
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        use tokio_rustls::TlsAcceptor;

        static INSTALL_PROVIDER: Once = Once::new();
        INSTALL_PROVIDER.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        // Self-signed HTTPS double answering the guest status endpoint the
        // way a real (unlocked) guest would — over a certificate no CA chain
        // trusts, exactly like the production RA-TLS leaf.
        let cert =
            rcgen::generate_simple_self_signed(vec!["status-double.example.test".to_string()])
                .expect("self-signed certificate");
        let tls_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![tokio_rustls::rustls::pki_types::CertificateDer::from(
                    cert.cert.der().to_vec(),
                )],
                tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
                    cert.signing_key.serialize_der().into(),
                ),
            )
            .expect("TLS server config");
        let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let double_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(read) = stream.read(&mut buf).await {
                    if read == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..read]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let body = r#"{"ownership_state":"unlocked"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });

        let pool = database_test_pool().await;
        let fixture = insert_unlock_test_app(&pool).await;
        let app_name = fixture.app.name.clone();
        let tee_domain = fixture.app.tee_domain.clone().expect("fixture tee_domain");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        // The unverified channel, pointed at the live double: if any code
        // path falls back to it, the test observes "unlocked".
        state.tee_http_client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .resolve(
                &tee_domain,
                SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    double_addr.port(),
                ),
            )
            .https_only(true)
            .no_proxy()
            .build()
            .expect("build unverified trap client");

        let auth = crate::auth::middleware::AuthContext {
            user_id: fixture.user_id,
            org_id: fixture.app.org_id,
            org_name: "unlock-status-test".to_string(),
            role: crate::models::Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };

        let Json(body) = unlock_status(auth, State(state), Path(app_name.clone()))
            .await
            .expect("unlock status must succeed");
        assert_eq!(body.ownership_state, None);
        assert_eq!(body.unlock_mode, "auto");
        assert!(body.tee_url.ends_with("/.well-known/confidential"));
        // The fixture has a primary and no apply-job row. A container is not
        // the generation the handler locks, so the field must refuse rather
        // than look acceptable.
        assert_eq!(body.locked_generation.source, LOCKED_GENERATION_SOURCE);
        assert!(!body.locked_generation.acceptable);
        // The fixture has a generation and a primary, but no signer. That is
        // not a signable identity, and the refusal must not expose a digest.
        assert_eq!(
            body.locked_generation.refusal.as_deref(),
            Some("stored app has no signer subject")
        );
        assert!(body.locked_generation.image_digest.is_none());
        assert!(body.locked_generation.port.is_none());

        delete_unlock_test_org(&pool, fixture.app.org_id).await;
    }

    #[tokio::test]
    async fn disable_preview_rejects_the_entitlement_gates_the_commit_enforces() {
        let pool = database_test_pool().await;
        let fixture = insert_unlock_test_app(&pool).await;
        let mut state = crate::test_support::lazy_state();
        state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
        state.db = pool.clone();
        // The fixture has no signed blobs. Turn the signed-artifact requirement
        // off so this test reaches the entitlement gate instead of the
        // missing-blob refusal.
        state.attestation = None;
        state.signing_service = None;
        state.require_customer_signed_policy_artifact = false;
        let auth = crate::auth::middleware::AuthContext {
            user_id: fixture.user_id,
            org_id: fixture.app.org_id,
            org_name: "unlock-preview-test".to_string(),
            role: crate::models::Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let request = super::UpdateUnlockModeRequest {
            mode: "password".to_string(),
            transition_receipt: None,
            transition_attestation: None,
            customer_descriptor_blob: None,
            org_keyring_blob: None,
            signed_policy_artifact: None,
            validate_only: true,
        };

        let Json(accepted) = super::update_unlock_mode(
            auth.clone(),
            State(state.clone()),
            Path(fixture.app.name.clone()),
            Json(request),
        )
        .await
        .expect("an allowed org must pass the disable preview");
        assert_eq!(accepted.status, "validated");
        let mode: String = sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
            .bind(fixture.app.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, "auto", "preview must not write the mode");

        let paas_org_id = format!("paas-{}", fixture.app.org_id.simple());
        sqlx::query(
            "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
        )
        .bind(fixture.app.org_id)
        .bind(&paas_org_id)
        .execute(&pool)
        .await
        .expect("mark preview org PaaS managed");
        sqlx::query(
            "INSERT INTO organization_entitlements (
                 org_id, version, deploy_allowed, block_reason, limits
             ) VALUES ($1, 1, false, 'entitlement_blocked', $2)",
        )
        .bind(fixture.app.org_id)
        .bind(serde_json::json!({
            "name": "test",
            "max_apps": 10,
            "max_cpu": "4",
            "max_memory": "8Gi",
            "max_storage": "20Gi"
        }))
        .execute(&pool)
        .await
        .expect("block preview org deploys");

        let blocked = super::update_unlock_mode(
            auth.clone(),
            State(state.clone()),
            Path(fixture.app.name.clone()),
            Json(super::UpdateUnlockModeRequest {
                mode: "password".to_string(),
                transition_receipt: None,
                transition_attestation: None,
                customer_descriptor_blob: None,
                org_keyring_blob: None,
                signed_policy_artifact: None,
                validate_only: true,
            }),
        )
        .await
        .expect_err("a blocked entitlement must fail the preview");
        assert_eq!(blocked.0, StatusCode::FORBIDDEN);
        assert_eq!(blocked.1.0["error"], "deploy_blocked");
        assert_eq!(blocked.1.0["reason"], "entitlement_blocked");
        let mode: String = sqlx::query_scalar("SELECT unlock_mode::text FROM apps WHERE id = $1")
            .bind(fixture.app.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, "auto");

        sqlx::query(
            "UPDATE organization_entitlements
                SET deploy_allowed = true, block_reason = NULL, limits = $2
              WHERE org_id = $1",
        )
        .bind(fixture.app.org_id)
        .bind(serde_json::json!({
            "name": "test",
            "max_apps": 10,
            "max_cpu": "4",
            "max_memory": "8Gi",
            "max_storage": "1Gi"
        }))
        .execute(&pool)
        .await
        .expect("shrink preview org storage limit");
        let over_limit = super::update_unlock_mode(
            auth,
            State(state),
            Path(fixture.app.name.clone()),
            Json(super::UpdateUnlockModeRequest {
                mode: "password".to_string(),
                transition_receipt: None,
                transition_attestation: None,
                customer_descriptor_blob: None,
                org_keyring_blob: None,
                signed_policy_artifact: None,
                validate_only: true,
            }),
        )
        .await
        .expect_err("a persisted size over the live limit must fail the preview");
        assert_eq!(over_limit.0, StatusCode::FORBIDDEN);
        assert_eq!(over_limit.1.0["reason"], "entitlement_storage_limit");

        delete_unlock_test_org(&pool, fixture.app.org_id).await;
    }
}
