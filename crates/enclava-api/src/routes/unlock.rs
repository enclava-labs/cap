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
}

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
    log_encryption: Option<&'a LogEncryptionConfig>,
    api_signing_pubkey: &'a str,
    api_url: &'a str,
    attestation_config: Option<&'a enclava_engine::types::AttestationConfig>,
    signing_service_pubkey_hex: Option<&'a str>,
    signed_required: bool,
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
    let current_role =
        crate::auth::scopes::active_membership_role_in_tx(&mut tx, request.org_id, request.user_id)
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
    if locked_app.status == crate::models::AppStatus::Deleting {
        return Err(unlock_transition_conflict("app deletion is in progress"));
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

    // Lock resources too so the apply snapshot is exactly the state accepted
    // by this transaction rather than a later concurrent edit.
    let resources: crate::models::AppResources =
        sqlx::query_as("SELECT * FROM app_resources WHERE app_id = $1")
            .bind(locked_app.id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| unlock_database_error())?;
    crate::routes::deployments::enforce_authoritative_entitlement(
        &mut tx,
        request.org_id,
        &resources,
        false,
    )
    .await?;

    let source: (Uuid, String, Option<String>, serde_json::Value) = sqlx::query_as(
        "SELECT deployment.id, deployment.status::text,
                deployment.image_digest, deployment.spec_snapshot
           FROM deployments AS deployment
           JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
          ORDER BY apply_job.generation DESC
          LIMIT 1",
    )
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
            )
            .map_err(crate::routes::deployments::signing_error_response)?;
        artifacts
            .validate_customer_authority_in_tx(&mut tx)
            .await
            .map_err(crate::routes::deployments::signing_error_response)?;
        let signing_service_pubkey_hex = request.signing_service_pubkey_hex.ok_or((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "platform signing-service pubkey required for signed deployment verification"
            })),
        ))?;
        artifacts
            .validate_signed_artifact(signed_policy_artifact, signing_service_pubkey_hex)
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

    if request.signed_workload_command.is_some()
        || request.signed_container_port.is_some()
        || request.signed_storage_paths.is_some()
    {
        let result = sqlx::query(
            "UPDATE app_containers
             SET command = COALESCE($1, command),
                 port = COALESCE($2, port),
                 storage_paths = COALESCE($3, storage_paths)
             WHERE app_id = $4 AND is_primary = true",
        )
        .bind(request.signed_workload_command)
        .bind(request.signed_container_port)
        .bind(request.signed_storage_paths)
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
        let (_encoded, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        artifacts
            .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
            .map_err(crate::routes::deployments::signing_error_response)?;
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
        .map_err(|_| unlock_database_error())?;
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
        crate::signing_service::persist_workload_artifacts(
            &mut *tx,
            locked_app.id,
            request.deploy_id,
            artifacts,
            signed,
        )
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

    let status_url = format!("https://{domain}/.well-known/confidential/status");
    let ownership_state = match state.tee_http_client.get(&status_url).send().await {
        Ok(resp) if resp.status().is_success() => {
            resp.json::<serde_json::Value>().await.ok().and_then(|v| {
                v.get("ownership_state")
                    .or_else(|| v.get("state"))
                    .and_then(|s| s.as_str())
                    .map(String::from)
            })
        }
        _ => None,
    };

    Ok(Json(UnlockStatusResponse {
        unlock_mode: format!("{:?}", app.unlock_mode).to_lowercase(),
        tee_url,
        ownership_state,
    }))
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

    let current = current_mode(&app);
    if !validate_transition(current, requested) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "invalid unlock mode transition"})),
        ));
    }

    if current == requested {
        return Ok(Json(UpdateUnlockModeResponse {
            app_name: app.name,
            unlock_mode: requested.api_value().to_string(),
            deployment_id: None,
            status: "unchanged".to_string(),
        }));
    }

    let receipt = body.transition_receipt.as_ref().ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": "transition_receipt required for unlock mode change"
        })),
    ))?;
    let verified_receipt =
        verify_transition_receipt(receipt, &app, current, requested).map_err(|field| {
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
        .ok_or_else(|| unlock_transition_conflict("app has no primary container"))?;
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
    let source: (Uuid, String, Option<String>, serde_json::Value) = sqlx::query_as(
        "SELECT deployment.id, deployment.status::text,
                deployment.image_digest, deployment.spec_snapshot
           FROM deployments AS deployment
           JOIN deployment_apply_jobs AS apply_job
             ON apply_job.deployment_id = deployment.id
          WHERE deployment.app_id = $1
          ORDER BY apply_job.generation DESC
          LIMIT 1",
    )
    .bind(app.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| unlock_database_error())?
    .ok_or_else(|| unlock_transition_conflict("app has no deployment generation"))?;
    if matches!(source.1.as_str(), "pending" | "applying" | "watching") {
        return Err(unlock_transition_conflict(
            "current deployment generation is still in progress",
        ));
    }
    if source.2.as_deref() != image_digest.as_deref() {
        return Err(unlock_transition_conflict(
            "current runtime does not match its deployment generation",
        ));
    }
    let resolved = source.3.get("resolved_resources").ok_or_else(|| {
        unlock_transition_conflict(
            "current deployment predates exact resource snapshots; deploy a current generation first",
        )
    })?;
    let exact_resource = |field: &str, expected: &str| {
        resolved.get(field).and_then(serde_json::Value::as_str) == Some(expected)
    };
    if !exact_resource("cpu", &observed_resources.cpu_limit)
        || !exact_resource("memory", &observed_resources.memory_limit)
        || !exact_resource("storage", &observed_resources.app_data_size)
        || !exact_resource("tls_storage", &observed_resources.tls_data_size)
    {
        return Err(unlock_transition_conflict(
            "current resource authority does not match its deployment generation",
        ));
    }
    if source
        .3
        .get("workload_security_profile")
        .and_then(serde_json::Value::as_str)
        != Some(current_profile.as_str())
    {
        return Err(unlock_transition_conflict(
            "current workload security profile does not match its deployment generation",
        ));
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
            .validate_deployment_inputs(&signed_app, image_digest_ref, &api_signing_pubkey)
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
        let (_encoded, cc_init_data_hash) =
            enclava_engine::manifest::cc_init_data::compute_cc_init_data(&app_spec);
        artifacts
            .validate_rendered_cc_init_data_hash(&cc_init_data_hash)
            .map_err(crate::routes::deployments::signing_error_response)?;
        signed_policy_artifact = Some(signed);
    }

    let receipt_json = serde_json::to_value(receipt).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "receipt serialization error"})),
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
            log_encryption: log_encryption.as_ref(),
            api_signing_pubkey: &api_signing_pubkey,
            api_url: &state.api_url,
            attestation_config: state.attestation.as_ref(),
            signing_service_pubkey_hex: state
                .attestation
                .as_ref()
                .and_then(|config| config.signing_service_pubkey_hex.as_deref()),
            signed_required,
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
    use axum::http::StatusCode;
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        ReceiptEnvelope, ReceiptPayloadView, RequestedUnlockMode, SignedReceiptResponse,
        TransitionReceiptAttestation, UnlockModeCommitRequest, commit_unlock_mode_transition,
        validate_transition, verify_transition_attestation, verify_transition_receipt,
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
                'password'::unlock_enum, $10, $11, 'running'::app_status_enum
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
            "kbs_resource_path": format!("default/{}-owner", app.name),
            "unlock_mode": "auto",
            "policy_template_id": "enclava-kbs-policy-v1",
            "policy_template_sha256": "04".repeat(32),
            "platform_release_version": "cap-test",
            "expected_agent_policy_hash": "05".repeat(32),
            "expected_cc_init_data_hash": "06".repeat(32),
            "expected_kbs_policy_hash": "07".repeat(32),
        });
        let descriptor_blob = serde_json::json!({
            "descriptor": descriptor,
            "signature": "08".repeat(64),
            "signing_key_id": "test-deployer-key",
            "signing_pubkey": "09".repeat(32),
        })
        .to_string();
        let keyring_blob = serde_json::json!({
            "keyring": {
                "org_id": app.org_id,
                "version": 1,
                "members": [],
                "updated_at": Utc::now(),
            },
            "signature": "0a".repeat(64),
            "signing_pubkey": "0b".repeat(32),
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
    fn unlock_mode_hash_validation_uses_local_artifact_delivery_mode() {
        let source = include_str!("unlock.rs");
        let fn_start = source
            .find("pub async fn update_unlock_mode")
            .expect("update_unlock_mode exists");
        let fn_end = source[fn_start..]
            .find("let receipt_json")
            .expect("receipt persistence follows signing validation")
            + fn_start;
        let body = &source[fn_start..fn_end];

        let select = body
            .find("select_local_signed_artifact_delivery")
            .expect("unlock-mode signing validation must use local artifact delivery mode");
        let compute = body
            .find("compute_cc_init_data")
            .expect("unlock-mode signing validation computes cc_init_data hash");
        assert!(
            select < compute,
            "unlock-mode redeploy hash validation must match normal deploy's signed-artifact delivery mode"
        );
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
        let new_command = "[\"/bin/new\"]";
        let new_storage_paths = vec!["/new-data".to_string()];

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
                requested: RequestedUnlockMode::Auto,
                receipt: &receipt,
                transition_attestation: &attestation,
                verified_receipt: &verified_receipt,
                receipt_json: &receipt_json,
                deploy_id,
                image_digest: Some(image_digest),
                signed_workload_command: Some(new_command),
                signed_container_port: Some(9090),
                signed_storage_paths: Some(&new_storage_paths),
                signing_artifacts: None,
                signed_policy_artifact: None,
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
        assert_eq!(persisted_mode, "password");
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
                requested: RequestedUnlockMode::Auto,
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
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
        assert_eq!(persisted_mode, "password");
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
                requested: RequestedUnlockMode::Auto,
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
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
        assert_eq!(persisted_mode, "password");
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

        let result = commit_unlock_mode_transition(
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
                image_digest: Some(image_digest),
                signed_workload_command: None,
                signed_container_port: None,
                signed_storage_paths: None,
                signing_artifacts: Some(&artifacts),
                signed_policy_artifact: Some(&signed),
                log_encryption: None,
                api_signing_pubkey,
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
        assert_eq!(persisted_mode, "password");
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
                requested: RequestedUnlockMode::Auto,
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
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
                requested: RequestedUnlockMode::Auto,
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
                log_encryption: None,
                api_signing_pubkey: "unused-without-signing-artifacts",
                api_url: "https://api.example.test",
                attestation_config: None,
                signing_service_pubkey_hex: None,
                signed_required: false,
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
        assert_eq!(persisted_mode, "auto");
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
}
