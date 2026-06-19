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
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
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
            _ => Err(format!(
                "invalid unlock mode '{mode}': expected 'password' or 'auto-unlock'"
            )),
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

async fn reject_replayed_transition_receipt(
    pool: &PgPool,
    app_id: Uuid,
    receipt_timestamp: DateTime<Utc>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let latest: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT max(receipt_timestamp) FROM unlock_transition_receipts WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(pool)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    if latest.is_some_and(|latest| receipt_timestamp <= latest) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "replayed transition_receipt"})),
        ));
    }
    Ok(())
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
    let tee_url = format!("https://{}/.well-known/confidential", domain);

    let status_url = format!("https://{}/.well-known/confidential/status", domain);
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
    let base = format!("https://{}/.well-known/confidential", domain);

    Ok(Json(UnlockEndpointResponse {
        tee_url: base.clone(),
        unlock_endpoint: format!("{}/unlock", base),
        claim_endpoint: format!("{}/bootstrap/claim", base),
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
    reject_replayed_transition_receipt(&state.db, app.id, verified_receipt.receipt_timestamp)
        .await?;

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
    if crate::routes::deployments::customer_signed_deploy_required(
        state.attestation.as_ref(),
        state.signing_service.is_some() || state.require_customer_signed_policy_artifact,
    ) && signing_artifacts.is_none()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "signed unlock-mode redeployments require customer_descriptor_blob and org_keyring_blob; use a current enclava CLI to sign the updated deployment descriptor"
            })),
        ));
    }

    let image_digest: Option<String> = sqlx::query_scalar(
        "SELECT image_digest FROM app_containers WHERE app_id = $1 AND is_primary = true LIMIT 1",
    )
    .bind(app.id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?
    .flatten();

    let mut signed_app = app.clone();
    signed_app.unlock_mode = requested.model_value();
    let mut workload_artifact_binding = None;
    let mut signed_policy_artifact = None;
    let mut signed_workload_command = None;
    let mut signed_container_port = None;
    let mut signed_storage_paths = None;
    if let Some(artifacts) = signing_artifacts.as_ref() {
        let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
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
            attestation,
            &api_signing_pubkey,
            &state.api_url,
        )
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
        crate::deploy::set_primary_descriptor_runtime(&mut app_spec, &artifacts.descriptor);
        let binding = artifacts.binding();
        app_spec.workload_artifact_binding = Some(binding.clone());

        let signed = crate::routes::deployments::resolve_signed_policy_artifact(
            &state,
            artifacts,
            body.signed_policy_artifact.clone(),
            signing_service_pubkey_hex,
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
        workload_artifact_binding = Some(binding);
        signed_policy_artifact = Some(signed);
    }

    let receipt_json = serde_json::to_value(receipt).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "receipt serialization error"})),
        )
    })?;

    let mut tx = state.db.begin().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    sqlx::query("UPDATE apps SET unlock_mode = $1::unlock_enum, updated_at = now() WHERE id = $2")
        .bind(requested.db_value())
        .bind(app.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    if signed_workload_command.is_some()
        || signed_container_port.is_some()
        || signed_storage_paths.is_some()
    {
        sqlx::query(
            "UPDATE app_containers
             SET command = COALESCE($1, command),
                 port = COALESCE($2, port),
                 storage_paths = COALESCE($3, storage_paths)
             WHERE app_id = $4 AND is_primary = true",
        )
        .bind(signed_workload_command.as_ref())
        .bind(signed_container_port)
        .bind(signed_storage_paths.as_ref())
        .bind(app.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;
    }

    sqlx::query(
        "INSERT INTO unlock_transition_receipts
            (app_id, from_mode, to_mode, receipt, receipt_pubkey_sha256, receipt_timestamp)
         VALUES ($1, $2::unlock_enum, $3::unlock_enum, $4, $5, $6)",
    )
    .bind(app.id)
    .bind(current.db_value())
    .bind(requested.db_value())
    .bind(receipt_json)
    .bind(verified_receipt.pubkey_sha256_bytes)
    .bind(verified_receipt.receipt_timestamp)
    .execute(&mut *tx)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    tx.commit().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    let updated_app: App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app.id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    let deploy_id = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.deploy_id)
        .unwrap_or_else(Uuid::new_v4);
    let spec_snapshot = serde_json::json!({
        "app_name": updated_app.name,
        "namespace": updated_app.namespace,
        "instance_id": updated_app.instance_id,
        "unlock_mode": requested.api_value(),
        "transition": {
            "from": current.api_value(),
            "to": requested.api_value(),
        },
        "signed_descriptor_core_hash": signing_artifacts
            .as_ref()
            .map(|artifacts| hex::encode(artifacts.descriptor_core_hash)),
    });

    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, spec_snapshot, image_digest)
         VALUES ($1, $2, $3, 'api', $4, $5)",
    )
    .bind(deploy_id)
    .bind(auth.org_id)
    .bind(app.id)
    .bind(&spec_snapshot)
    .bind(&image_digest)
    .execute(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    if let (Some(artifacts), Some(signed)) =
        (signing_artifacts.as_ref(), signed_policy_artifact.as_ref())
    {
        crate::signing_service::persist_workload_artifacts(
            &state.db, app.id, deploy_id, artifacts, signed,
        )
        .await
        .map_err(crate::routes::deployments::signing_error_response)?;
    }

    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, app_id, user_id, action, detail)
         VALUES ($1, $2, $3, 'app.unlock_mode.update', $4)",
    )
    .bind(auth.org_id)
    .bind(app.id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "from": current.api_value(),
        "to": requested.api_value(),
        "deployment_id": deploy_id,
    }))
    .execute(&state.db)
    .await;

    let api_signing_pubkey = crate::auth::jwt::public_key_base64(&state.signing_key);
    let local_verification_artifacts =
        match (signing_artifacts.as_ref(), signed_policy_artifact.as_ref()) {
            (Some(artifacts), Some(signed)) => Some((
                crate::signing_service::workload_artifacts_json(artifacts, signed)
                    .map_err(crate::routes::deployments::signing_error_response)?,
                crate::signing_service::trustee_policy_json(signed)
                    .map_err(crate::routes::deployments::signing_error_response)?,
            )),
            _ => None,
        };
    let db = state.db.clone();
    let attestation = state.attestation.clone();
    let kbs_policy = state.kbs_policy.clone();
    let api_url = state.api_url.clone();
    let apply_app = updated_app.clone();
    let apply_permits = state.deployment_apply_permits.clone();
    let (local_workload_artifacts_json, local_trustee_policy_json) =
        local_verification_artifacts.unzip();
    let signed_descriptor = signing_artifacts
        .as_ref()
        .map(|artifacts| artifacts.descriptor.clone());
    tokio::spawn(async move {
        let _apply_permit = match apply_permits.acquire_owned().await {
            Ok(permit) => permit,
            Err(e) => {
                let error_message = format!("deployment apply limiter closed: {}", e);
                let _ = crate::deploy::set_deployment_status(
                    &db,
                    deploy_id,
                    "failed",
                    None,
                    Some(&error_message),
                    true,
                )
                .await;
                let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
                tracing::error!(
                    app_id = %apply_app.id,
                    deployment_id = %deploy_id,
                    error = %error_message,
                    "failed to acquire unlock-mode apply permit"
                );
                return;
            }
        };

        if let Err(e) = crate::deploy::apply_deployment_manifests(
            crate::deploy::ApplyDeploymentManifestsRequest {
                pool: db.clone(),
                app: apply_app.clone(),
                deployment_id: deploy_id,
                attestation_config: attestation,
                kbs_policy_config: kbs_policy,
                api_signing_pubkey,
                api_url,
                workload_artifact_binding,
                signed_policy_artifact,
                signed_descriptor,
                local_workload_artifacts_json,
                local_trustee_policy_json,
                workload_security_profile: None,
            },
        )
        .await
        {
            let error_message = e.to_string();
            let _ = crate::deploy::set_deployment_status(
                &db,
                deploy_id,
                "failed",
                None,
                Some(&error_message),
                true,
            )
            .await;
            let _ = crate::deploy::set_app_status(&db, apply_app.id, "failed").await;
            tracing::error!(
                app_id = %apply_app.id,
                deployment_id = %deploy_id,
                error = %error_message,
                "failed to apply unlock-mode manifests"
            );
        }
    });

    Ok(Json(UpdateUnlockModeResponse {
        app_name: updated_app.name,
        unlock_mode: requested.api_value().to_string(),
        deployment_id: Some(deploy_id),
        status: "deploying".to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    use chrono::Utc;
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use super::{
        ReceiptEnvelope, ReceiptPayloadView, RequestedUnlockMode, SignedReceiptResponse,
        TransitionReceiptAttestation, validate_transition, verify_transition_attestation,
        verify_transition_receipt,
    };
    use crate::models::{App, AppStatus, UnlockMode};

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
            egress_allowlist: serde_json::json!([]),
            health_path: "/health".to_string(),
            health_interval_seconds: 30,
            health_timeout_seconds: 5,
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
        let timestamp = "2026-04-28T12:00:00Z";
        let payload = ReceiptPayloadView {
            purpose: "enclava-unlock-receipt-v1".to_string(),
            app_id: "11111111-1111-1111-1111-111111111111".to_string(),
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
        TransitionReceiptAttestation {
            tee_domain: "demo.tee.enclava.dev".to_string(),
            nonce: B64.encode([0x99; 32]),
            leaf_spki_sha256: "aa".repeat(32),
            receipt_pubkey_sha256: hex::encode(Sha256::digest(
                signing_key.verifying_key().to_bytes(),
            )),
            attestation_evidence_sha256: quote_hash.to_string(),
        }
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
}
