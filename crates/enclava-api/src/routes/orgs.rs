use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
use enclava_common::crypto::owner_rotation_directive_bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::auth::scopes;
use crate::models::{Organization, Role};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CreateOrgRequest {
    pub name: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OrgResponse {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub entitlement_class: String,
    pub is_personal: bool,
}

impl From<Organization> for OrgResponse {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id,
            name: o.name,
            display_name: o.display_name,
            entitlement_class: o.entitlement_class,
            is_personal: o.is_personal,
        }
    }
}

/// POST /orgs -- create a new organization (non-personal).
pub async fn create_org(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<CreateOrgRequest>,
) -> Result<(StatusCode, Json<OrgResponse>), (StatusCode, Json<serde_json::Value>)> {
    // PaaS-managed instances provision orgs exclusively through the
    // authenticated /internal/paas routes; a public signup must not be able
    // to create (or name-squat) orgs on them.
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;
    if enclava_common::validate::validate_dns_label(&body.name).is_err() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_org_name",
                "message": "name must be a DNS-safe lowercase organization name ([a-z0-9-], max 63 chars)"
            })),
        ));
    }
    let org_id = Uuid::new_v4();

    if let Err(e) = crate::db::orgs::insert_org_pool(
        &state.db,
        org_id,
        &body.name,
        body.display_name.as_deref(),
        false,
    )
    .await
    {
        if e.to_string().contains("duplicate key") || e.to_string().contains("unique") {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "organization name already taken"})),
            ));
        }
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        ));
    }

    // Add creator as owner
    sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
        .bind(auth.user_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    let org: Organization = sqlx::query_as("SELECT * FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_one(&state.db)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "database error"})),
            )
        })?;

    // Audit
    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, user_id, action, detail) VALUES ($1, $2, 'org.create', $3)",
    )
    .bind(org_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({"name": &body.name}))
    .execute(&state.db)
    .await;

    Ok((StatusCode::CREATED, Json(org.into())))
}

fn list_orgs_api_key_org_filter(auth: &AuthContext) -> Option<Uuid> {
    auth.api_key.as_ref().map(|_| auth.org_id)
}

/// GET /orgs -- list user's organizations.
pub async fn list_orgs(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<OrgResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let orgs: Vec<Organization> = sqlx::query_as(
        "SELECT o.* FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1
           AND m.removed_at IS NULL
           AND ($2::uuid IS NULL OR o.id = $2)
         ORDER BY o.name",
    )
    .bind(auth.user_id)
    .bind(list_orgs_api_key_org_filter(&auth))
    .fetch_all(&state.db)
    .await
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "database error"})),
        )
    })?;

    Ok(Json(orgs.into_iter().map(Into::into).collect()))
}

#[derive(Debug, Deserialize)]
pub struct InviteRequest {
    pub email: String,
    pub role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct PutOrgKeyringRequest {
    pub version: i64,
    pub keyring_payload: serde_json::Value,
    pub signature: String,
    pub signing_pubkey: String,
}

#[derive(Debug, Serialize)]
pub struct OrgKeyringResponse {
    pub org_id: Uuid,
    pub version: i64,
    pub keyring_payload: serde_json::Value,
    pub signature: String,
    pub signing_pubkey: String,
    pub fingerprint: String,
}

#[derive(Debug, Deserialize)]
pub struct BootstrapSigningServiceRequest {
    pub owner_pubkey_hex: String,
}

#[derive(Debug, Serialize)]
pub struct BootstrapSigningServiceResponse {
    pub org_id: Uuid,
    pub state: String,
    pub owner_pubkey_fingerprint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RotateOrgOwnerRequest {
    pub version: i64,
    pub keyring_payload: serde_json::Value,
    pub signature: String,
    pub replacement_signing_pubkey: String,
    pub current_signing_pubkey: String,
    pub signed_at: DateTime<Utc>,
    pub reason: String,
    pub rotation_signature: String,
}

#[derive(Debug, Serialize)]
pub struct RotateOrgOwnerResponse {
    pub org_id: Uuid,
    pub state: &'static str,
    pub keyring_version: i64,
    pub owner_fingerprint: String,
}

#[derive(Debug, Serialize)]
pub struct SigningReadinessResponse {
    pub org_id: Uuid,
    pub state: &'static str,
    pub keyring_version: Option<i64>,
    pub keyring_fingerprint: Option<String>,
    pub owner_fingerprint: Option<String>,
    pub last_changed_at: Option<DateTime<Utc>>,
    pub authorized_signers: Vec<AuthorizedSignerResponse>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizedSignerResponse {
    pub user_id: Uuid,
    pub role: &'static str,
    pub fingerprint: String,
}

type KeyringRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Debug, Deserialize)]
struct SignedOrgKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<SignedOrgKeyringMember>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct SignedOrgKeyringMember {
    user_id: Uuid,
    #[serde(deserialize_with = "deserialize_pubkey")]
    pubkey: [u8; 32],
    role: SignedOrgKeyringRole,
    added_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum SignedOrgKeyringRole {
    Owner,
    Admin,
    Deployer,
}

impl SignedOrgKeyringRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Deployer => "deployer",
        }
    }
}

fn deserialize_pubkey<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let value = String::deserialize(deserializer)?;
    let bytes = hex::decode(value).map_err(D::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| D::Error::custom("pubkey must decode to 32 bytes"))
}

fn canonical_member_hash(member: &SignedOrgKeyringMember) -> [u8; 32] {
    let role = member.role.as_str().as_bytes().to_vec();
    let added_at = member.added_at.to_rfc3339().into_bytes();
    ce_v1_hash(&[
        ("user_id", member.user_id.as_bytes().as_slice()),
        ("pubkey", member.pubkey.as_slice()),
        ("role", &role),
        ("added_at", &added_at),
    ])
}

fn canonical_members_hash(members: &[SignedOrgKeyringMember]) -> [u8; 32] {
    let mut sorted: Vec<&SignedOrgKeyringMember> = members.iter().collect();
    sorted.sort_by_key(|member| member.user_id);
    let per_member: Vec<(String, [u8; 32])> = sorted
        .iter()
        .map(|member| (member.user_id.to_string(), canonical_member_hash(member)))
        .collect();
    let records: Vec<(&str, &[u8])> = per_member
        .iter()
        .map(|(label, hash)| (label.as_str(), hash.as_slice()))
        .collect();
    ce_v1_hash(&records)
}

fn canonical_keyring_bytes(keyring: &SignedOrgKeyring) -> Vec<u8> {
    let members_hash = canonical_members_hash(&keyring.members);
    let version_be = keyring.version.to_be_bytes();
    let updated_at = keyring.updated_at.to_rfc3339().into_bytes();
    ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", keyring.org_id.as_bytes().as_slice()),
        ("version", &version_be),
        ("members", &members_hash),
        ("updated_at", &updated_at),
    ])
}

fn db_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "database error"})),
    )
}

fn bad_request(message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": message})),
    )
}

fn decode_hex_len(
    name: &'static str,
    value: &str,
    len: usize,
) -> Result<Vec<u8>, (StatusCode, Json<serde_json::Value>)> {
    let bytes =
        hex::decode(value.trim()).map_err(|_| bad_request(&format!("{name} is not hex")))?;
    if bytes.len() != len {
        return Err(bad_request(&format!(
            "{name} must decode to {len} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn require_api_key_org(
    auth: &AuthContext,
    org_id: Uuid,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if auth.api_key.is_some() && auth.org_id != org_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "API key is restricted to its organization"
            })),
        ));
    }
    Ok(())
}

async fn active_membership(
    state: &AppState,
    auth: &AuthContext,
    org_name: &str,
) -> Result<(Uuid, Role), (StatusCode, Json<serde_json::Value>)> {
    let (org_id, role) = sqlx::query_as(
        "SELECT o.id, m.role as \"role: _\"
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
    )
    .bind(org_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "organization not found"})),
    ))?;
    require_api_key_org(auth, org_id)?;
    Ok((org_id, role))
}

pub async fn put_keyring(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
    Json(body): Json<PutOrgKeyringRequest>,
) -> Result<(StatusCode, Json<OrgKeyringResponse>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;
    let (org_id, caller_role) = active_membership(&state, &auth, &org_name).await?;
    scopes::require_owner_role(caller_role)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    if body.version < 1 {
        return Err(bad_request("version must be positive"));
    }
    let signature = decode_hex_len("signature", &body.signature, 64)?;
    let signing_pubkey = decode_hex_len("signing_pubkey", &body.signing_pubkey, 32)?;
    let keyring_org_id = body
        .keyring_payload
        .get("org_id")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| bad_request("keyring_payload.org_id is required"))?;
    let keyring_version = body
        .keyring_payload
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| bad_request("keyring_payload.version is required"))?;
    if keyring_org_id != org_id || keyring_version != body.version as u64 {
        return Err(bad_request("keyring payload does not match org/version"));
    }

    let keyring: SignedOrgKeyring =
        serde_json::from_value(body.keyring_payload.clone()).map_err(|err| {
            bad_request(&format!(
                "keyring_payload is not a valid signed org keyring: {err}"
            ))
        })?;
    if keyring.members.is_empty() {
        return Err(bad_request("keyring must contain at least one member"));
    }
    if !keyring.members.iter().any(|member| {
        member.pubkey.as_slice() == signing_pubkey.as_slice()
            && member.role == SignedOrgKeyringRole::Owner
    }) {
        return Err(bad_request(
            "signing_pubkey must be present in the keyring with owner role",
        ));
    }

    let signing_pubkey_arr: [u8; 32] = signing_pubkey
        .clone()
        .try_into()
        .map_err(|_| bad_request("signing_pubkey must decode to 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&signing_pubkey_arr)
        .map_err(|_| bad_request("signing_pubkey is not a valid Ed25519 key"))?;
    let signature_arr: [u8; 64] = signature
        .clone()
        .try_into()
        .map_err(|_| bad_request("signature must decode to 64 bytes"))?;
    let signature_obj = Signature::from_bytes(&signature_arr);
    let canonical_bytes = canonical_keyring_bytes(&keyring);
    verifying_key
        .verify(&canonical_bytes, &signature_obj)
        .map_err(|_| bad_request("keyring signature verification failed"))?;

    let keyring_payload_bytes = serde_json::to_vec(&body.keyring_payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "serialization error"})),
        )
    })?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;

    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;

    // Re-read key registration and latest keyring only after acquiring the
    // shared signing-authority lane. Rotation and signed acceptance therefore
    // linearize on one exact owner authority generation.
    let signing_key_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM user_signing_keys
         WHERE user_id = $1 AND pubkey = $2 AND revoked_at IS NULL",
    )
    .bind(auth.user_id)
    .bind(&signing_pubkey)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad_request("signing_pubkey is not registered for this user"))?;

    type LatestKeyringAuthority = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
    let latest: Option<LatestKeyringAuthority> = sqlx::query_as(
        "SELECT ok.version, ok.keyring_payload, ok.signature, usk.pubkey
         FROM org_keyrings ok
         JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
         WHERE ok.org_id = $1
         ORDER BY ok.version DESC
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    let mut insert_new_version = true;
    if let Some((latest_version, latest_payload, latest_signature, latest_signing_pubkey)) = latest
    {
        if body.version < latest_version {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "keyring version is stale"})),
            ));
        }
        if body.version == latest_version
            && (latest_payload != keyring_payload_bytes
                || latest_signature != signature
                || latest_signing_pubkey != signing_pubkey)
        {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "keyring version already exists with different content"
                })),
            ));
        }
        if body.version == latest_version {
            insert_new_version = false;
        }
        let next_version = latest_version
            .checked_add(1)
            .ok_or_else(|| bad_request("keyring version cannot be incremented"))?;
        if body.version > next_version {
            return Err(bad_request("keyring version must increment by one"));
        }
        if body.version == next_version {
            if latest_signing_pubkey != signing_pubkey {
                return Err(bad_request(
                    "keyring signing owner does not match the current pinned owner",
                ));
            }
            let latest_signing_pubkey: [u8; 32] = latest_signing_pubkey
                .as_slice()
                .try_into()
                .map_err(|_| db_error())?;
            let latest_owner =
                VerifyingKey::from_bytes(&latest_signing_pubkey).map_err(|_| db_error())?;
            latest_owner
                .verify(&canonical_bytes, &signature_obj)
                .map_err(|_| {
                    bad_request("keyring signature verification failed under current pinned owner")
                })?;
        }
    } else if body.version != 1 {
        return Err(bad_request("first keyring version must be one"));
    }

    if insert_new_version {
        sqlx::query(
            "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(body.version)
        .bind(&keyring_payload_bytes)
        .bind(&signature)
        .bind(signing_key_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;

        sqlx::query(
            "INSERT INTO audit_log (org_id, user_id, action, detail)
             VALUES ($1, $2, 'org.keyring.put', $3)",
        )
        .bind(org_id)
        .bind(auth.user_id)
        .bind(serde_json::json!({
            "version": body.version,
            "signing_pubkey": body.signing_pubkey,
        }))
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    }

    tx.commit().await.map_err(|_| db_error())?;

    let fingerprint = hex::encode(Sha256::digest(&canonical_bytes));
    Ok((
        StatusCode::OK,
        Json(OrgKeyringResponse {
            org_id,
            version: body.version,
            keyring_payload: body.keyring_payload,
            signature: body.signature,
            signing_pubkey: body.signing_pubkey,
            fingerprint,
        }),
    ))
}

pub async fn get_keyring(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
) -> Result<Json<OrgKeyringResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_member(&auth)?;
    let (org_id, _) = active_membership(&state, &auth, &org_name).await?;

    let row: Option<KeyringRow> = sqlx::query_as(
        "SELECT ok.version, ok.keyring_payload, ok.signature, usk.pubkey
         FROM org_keyrings ok
         JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
         WHERE ok.org_id = $1
         ORDER BY ok.version DESC
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let Some((version, payload_bytes, signature, signing_pubkey)) = row else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "org keyring not found"})),
        ));
    };
    let keyring_payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).map_err(|_| db_error())?;
    let keyring: SignedOrgKeyring =
        serde_json::from_value(keyring_payload.clone()).map_err(|_| db_error())?;
    let fingerprint = hex::encode(Sha256::digest(canonical_keyring_bytes(&keyring)));
    Ok(Json(OrgKeyringResponse {
        org_id,
        version,
        keyring_payload,
        signature: hex::encode(signature),
        signing_pubkey: hex::encode(signing_pubkey),
        fingerprint,
    }))
}

pub async fn get_signing_readiness(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
) -> Result<Json<SigningReadinessResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_member(&auth)?;
    let (org_id, _) = active_membership(&state, &auth, &org_name).await?;
    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;

    let row: Option<KeyringRow> = sqlx::query_as(
        "SELECT ok.version, ok.keyring_payload, ok.signature, usk.pubkey
         FROM org_keyrings ok
         JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
         WHERE ok.org_id = $1
         ORDER BY ok.version DESC
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let owner_status = signing_service
        .owner_status(org_id)
        .await
        .map_err(crate::routes::deployments::signing_error_response)?;
    let owner_state_consistent = matches!(
        (
            owner_status.state.as_str(),
            owner_status.owner_pubkey_hex.as_ref()
        ),
        ("not_configured", None) | ("ready", Some(_))
    );
    if owner_status.org_id != org_id || !owner_state_consistent {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "owner status does not match the requested organization".to_string(),
            ),
        ));
    }
    let service_owner = owner_status
        .owner_pubkey_hex
        .as_deref()
        .map(|raw| decode_hex_len("owner_pubkey_hex", raw, 32))
        .transpose()
        .map_err(|_| {
            crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::AuthorityStatus(
                    "owner status contains an invalid public key".to_string(),
                ),
            )
        })?;

    let Some((version, payload_bytes, _signature, signing_pubkey)) = row else {
        return Ok(Json(SigningReadinessResponse {
            org_id,
            state: signing_readiness_state(None, service_owner.as_deref()),
            keyring_version: None,
            keyring_fingerprint: None,
            owner_fingerprint: owner_status
                .owner_pubkey_hex
                .as_deref()
                .and_then(owner_key_fingerprint),
            last_changed_at: owner_status.last_changed_at,
            authorized_signers: Vec::new(),
        }));
    };

    let keyring: SignedOrgKeyring =
        serde_json::from_slice(&payload_bytes).map_err(|_| db_error())?;
    let keyring_fingerprint = hex::encode(Sha256::digest(canonical_keyring_bytes(&keyring)));
    let authorized_signers = keyring
        .members
        .iter()
        .map(|member| AuthorizedSignerResponse {
            user_id: member.user_id,
            role: member.role.as_str(),
            fingerprint: hex::encode(Sha256::digest(member.pubkey)),
        })
        .collect();
    let state_name = signing_readiness_state(Some(&signing_pubkey), service_owner.as_deref());

    Ok(Json(SigningReadinessResponse {
        org_id,
        state: state_name,
        keyring_version: Some(version),
        keyring_fingerprint: Some(keyring_fingerprint),
        owner_fingerprint: owner_status
            .owner_pubkey_hex
            .as_deref()
            .and_then(owner_key_fingerprint),
        last_changed_at: owner_status.last_changed_at,
        authorized_signers,
    }))
}

fn owner_key_fingerprint(owner_pubkey_hex: &str) -> Option<String> {
    let bytes = hex::decode(owner_pubkey_hex).ok()?;
    (bytes.len() == 32).then(|| hex::encode(Sha256::digest(bytes)))
}

fn signing_readiness_state(
    keyring_owner: Option<&[u8]>,
    service_owner: Option<&[u8]>,
) -> &'static str {
    match (keyring_owner, service_owner) {
        (None, None) => "not_configured",
        (Some(keyring), Some(service)) if keyring == service => "ready",
        (Some(_), Some(_)) => "drifted",
        _ => "recovery_required",
    }
}

fn validate_rotated_members(
    current: &SignedOrgKeyring,
    replacement: &SignedOrgKeyring,
    current_owner: &[u8; 32],
    replacement_owner: &[u8; 32],
) -> Result<(), &'static str> {
    if current.members.len() != replacement.members.len() {
        return Err("owner rotation must preserve every keyring member");
    }
    let mut replaced = 0;
    for member in &current.members {
        let next = replacement
            .members
            .iter()
            .filter(|candidate| candidate.user_id == member.user_id)
            .collect::<Vec<_>>();
        if next.len() != 1 {
            return Err("owner rotation requires one member entry per user");
        }
        let next = next[0];
        if member.pubkey == *current_owner && member.role == SignedOrgKeyringRole::Owner {
            replaced += 1;
            if next.pubkey != *replacement_owner
                || next.role != SignedOrgKeyringRole::Owner
                || next.added_at != member.added_at
            {
                return Err("owner rotation may only replace the current owner public key");
            }
        } else if next.pubkey != member.pubkey
            || next.role != member.role
            || next.added_at != member.added_at
        {
            return Err("owner rotation must preserve non-owner keyring members");
        }
    }
    if replaced != 1 {
        return Err("current keyring must contain exactly one matching owner entry");
    }
    Ok(())
}

pub async fn bootstrap_signing_service_owner(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
    Json(body): Json<BootstrapSigningServiceRequest>,
) -> Result<Json<BootstrapSigningServiceResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;
    let (org_id, caller_role) = active_membership(&state, &auth, &org_name).await?;
    scopes::require_admin_role(caller_role)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    let owner_pubkey = decode_hex_len("owner_pubkey_hex", &body.owner_pubkey_hex, 32)?;
    let latest_signing_pubkey: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT usk.pubkey
         FROM org_keyrings ok
         JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
         WHERE ok.org_id = $1
         ORDER BY ok.version DESC
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;
    let latest_signing_pubkey =
        latest_signing_pubkey.ok_or_else(|| bad_request("org keyring must be uploaded first"))?;
    if latest_signing_pubkey != owner_pubkey {
        return Err(bad_request(
            "owner_pubkey_hex must match the latest org keyring signing owner",
        ));
    }

    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;
    let response = signing_service
        .bootstrap_org(&crate::signing_service::BootstrapOrgRequest {
            org_id,
            owner_pubkey_hex: hex::encode(owner_pubkey),
        })
        .await
        .map_err(crate::routes::deployments::signing_error_response)?;

    Ok(Json(BootstrapSigningServiceResponse {
        org_id: response.org_id,
        state: response.state,
        owner_pubkey_fingerprint: response.owner_pubkey_fingerprint,
    }))
}

pub async fn rotate_org_owner(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
    Json(body): Json<RotateOrgOwnerRequest>,
) -> Result<Json<RotateOrgOwnerResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;
    let (org_id, caller_role) = active_membership(&state, &auth, &org_name).await?;
    scopes::require_owner_role(caller_role)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;
    if body.reason.trim().is_empty() {
        return Err(bad_request("rotation reason is required"));
    }
    if body.version < 2 {
        return Err(bad_request("rotated keyring version must be at least two"));
    }

    let current_owner: [u8; 32] =
        decode_hex_len("current_signing_pubkey", &body.current_signing_pubkey, 32)?
            .try_into()
            .map_err(|_| bad_request("current_signing_pubkey must decode to 32 bytes"))?;
    let replacement_owner: [u8; 32] = decode_hex_len(
        "replacement_signing_pubkey",
        &body.replacement_signing_pubkey,
        32,
    )?
    .try_into()
    .map_err(|_| bad_request("replacement_signing_pubkey must decode to 32 bytes"))?;
    if current_owner == replacement_owner {
        return Err(bad_request(
            "replacement owner public key must differ from current owner",
        ));
    }
    let keyring_signature: [u8; 64] = decode_hex_len("signature", &body.signature, 64)?
        .try_into()
        .map_err(|_| bad_request("signature must decode to 64 bytes"))?;
    let rotation_signature: [u8; 64] =
        decode_hex_len("rotation_signature", &body.rotation_signature, 64)?
            .try_into()
            .map_err(|_| bad_request("rotation_signature must decode to 64 bytes"))?;
    let replacement_key = VerifyingKey::from_bytes(&replacement_owner)
        .map_err(|_| bad_request("replacement owner is not a valid Ed25519 key"))?;
    let current_key = VerifyingKey::from_bytes(&current_owner)
        .map_err(|_| bad_request("current owner is not a valid Ed25519 key"))?;
    let replacement_keyring: SignedOrgKeyring =
        serde_json::from_value(body.keyring_payload.clone()).map_err(|err| {
            bad_request(&format!(
                "keyring_payload is not a valid signed org keyring: {err}"
            ))
        })?;
    if replacement_keyring.org_id != org_id || replacement_keyring.version != body.version as u64 {
        return Err(bad_request("keyring payload does not match org/version"));
    }
    if !replacement_keyring.members.iter().any(|member| {
        member.pubkey == replacement_owner && member.role == SignedOrgKeyringRole::Owner
    }) {
        return Err(bad_request(
            "replacement owner must be present in the keyring with owner role",
        ));
    }
    let canonical_bytes = canonical_keyring_bytes(&replacement_keyring);
    replacement_key
        .verify(&canonical_bytes, &Signature::from_bytes(&keyring_signature))
        .map_err(|_| bad_request("replacement keyring signature verification failed"))?;
    // Freshness and replay binding for the rotation directive (issue #120).
    // The directive's CE-v1 bytes are a cross-repo contract with the platform
    // signing service (policy-templates re-derives them verbatim), so the
    // binding is enforced by the authoritative verifier in CAP:
    // - when a rotation creates a new keyring version, signed_at must be
    //   neither in the future (no skew allowance: a pre-creation capture
    //   must not pass as newer than the version it rotates) nor older
    //   than the current keyring version's creation, both measured
    //   against the authoritative clock observed after the
    //   signing-authority lane is acquired (queueing on the lane can
    //   outlast any window captured before the lock).
    // - the signed_at max-age is a first-use bound, enforced only when the
    //   rotation creates a new keyring version: a captured directive is not
    //   a standing bearer token for the (current -> replacement) pair. A
    //   retry of an already-applied rotation must stay idempotent at any
    //   age (response-loss recovery, pre-ledger rotations from before this
    //   deployment) and is instead proven by the byte-identical stored
    //   keyring content, signatures, and pinned-owner checks below. The
    //   bound carries a recovery exception bound to a durable
    //   presentation record (org_rotation_intents, migration 0053):
    //   every authenticated, signature-verified presentation commits
    //   the exact (directive digest, keyring payload digest) pair with
    //   its first-presentation timestamp on its own connection BEFORE
    //   this handler opens the signing-authority lane transaction. If
    //   the upstream rotation succeeded but the CAP transaction rolled
    //   back (service pinned to the replacement, no keyring version or
    //   ledger row), retrying that exact request is allowed through at
    //   any age only when the committed record proves this directive
    //   caused the drift: it was first presented while still fresh,
    //   that presentation preceded the service's current owner (the
    //   owner snapshot's last_changed_at), and no other directive was
    //   presented in between -- an intent row alone proves a request
    //   reached this handler, not that its rotate_owner succeeded (PR
    //   #185 review). Under the waiver the upstream rotation already
    //   happened, so rotate_owner is not re-issued (the service already
    //   holds the replacement), the pinned-owner, content, and
    //   signature checks still bind the stored version to the
    //   replacement owner, and the ledger still consumes the digest
    //   (single use). A different directive or keyring over the same
    //   pair gets no waiver.
    // - when the rotation creates a new keyring version, signed_at may not
    //   predate the creation of the keyring version whose owner signed it.
    // - each directive accepted on the insert-new-version path is consumed
    //   exactly once (ledger below). The already-applied path is idempotent
    //   for any valid directive over the same completed rotation (see the
    //   else branch) and consumes nothing.
    const MAX_DIRECTIVE_AGE_SECONDS: i64 = 900;
    /// Skew allowance when comparing the intent row's created_at (CAP's
    /// database clock) against the signing service's owner snapshot
    /// last_changed_at (an independent service clock). Only the
    /// presentation-preceded-rotation bound uses it; every other freshness
    /// comparison stays on a single clock.
    const OWNER_SNAPSHOT_SKEW_SECONDS: i64 = 30;
    let directive = owner_rotation_directive_bytes(
        org_id,
        &current_owner,
        &replacement_owner,
        body.signed_at,
        body.reason.trim(),
    );
    current_key
        .verify(&directive, &Signature::from_bytes(&rotation_signature))
        .map_err(|_| bad_request("owner rotation signature verification failed"))?;

    let payload_bytes = serde_json::to_vec(&body.keyring_payload).map_err(|_| db_error())?;
    let directive_digest = Sha256::digest(&directive);

    // Snapshot the signing-service owner authority and durably record this
    // presentation BEFORE opening the signing-authority lane transaction
    // (PR #185 review, codex P2): this handler must never wait on a second
    // pool connection while holding the lane transaction's connection --
    // with the pool capped, N concurrent rotations holding their lane
    // connections could all block here waiting for an (N+1)th connection
    // and time out as a cluster. Pre-lane is also the correct observation
    // point: the max-age waiver compares the intent row's presentation
    // timestamp against the service owner's last_changed_at, and both are
    // only comparable while no competing rotation can slip between them
    // under the lane -- the read precedes the write's lane segment, and
    // no upstream effect can happen before the lane is taken, so moving
    // the snapshot earlier does not reorder any side effect.
    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;
    let owner_status = signing_service
        .owner_status(org_id)
        .await
        .map_err(crate::routes::deployments::signing_error_response)?;
    let service_owner = owner_status
        .owner_pubkey_hex
        .as_deref()
        .and_then(|raw| hex::decode(raw).ok());
    if owner_status.org_id != org_id || owner_status.state != "ready" {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "owner status does not match requested authority".to_string(),
            ),
        ));
    }

    // Durable presentation record (migration 0053), committed on its own
    // short-lived pool connection BEFORE this handler opens the
    // signing-authority lane transaction and thus before any upstream
    // rotate-owner effect can happen. Every authenticated,
    // signature-verified presentation of a new-version rotation directive
    // lands here with its first-presentation timestamp -- including
    // presentations that later fail the freshness bounds or the ledger:
    // the row is a presentation record, not an approval. If the upstream
    // rotation succeeds but this handler's transaction rolls back, this
    // committed row is what later authorizes the max-age waiver for
    // retrying this exact (directive, keyring) pair. Idempotent:
    // re-presenting the same request rewrites nothing (the first
    // presentation timestamp is what the waiver checks).
    let intent_digest = Sha256::digest(&payload_bytes);
    sqlx::query(
        "INSERT INTO org_rotation_intents (org_id, directive_sha256, keyring_sha256)
         VALUES ($1, $2, $3)
         ON CONFLICT ON CONSTRAINT org_rotation_intents_pkey DO NOTHING",
    )
    .bind(org_id)
    .bind(directive_digest.as_slice())
    .bind(intent_digest.as_slice())
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    // The signing-authority lane is a blocking advisory lock and this
    // handler performs signing-service requests while holding it, so
    // queue time behind other writers can outlast any freshness window.
    // All freshness bounds therefore use the reference time observed
    // strictly after the lane is acquired, on the same database clock
    // that witnesses org_keyrings.created_at (migration 0051).
    let lane_now = crate::signing_service::lock_org_signing_authority_lane_now(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;

    type AuthorityRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, DateTime<Utc>);
    let latest: AuthorityRow = sqlx::query_as(
        "SELECT ok.version, ok.keyring_payload, ok.signature, usk.pubkey, ok.created_at
           FROM org_keyrings ok
           JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
          WHERE ok.org_id = $1
          ORDER BY ok.version DESC
          LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad_request("org keyring must be uploaded before owner rotation"))?;

    let (base_payload, expected_current_owner, insert_new_version) = if body.version == latest.0 {
        if latest.1 != payload_bytes
            || latest.2 != keyring_signature
            || latest.3 != replacement_owner
        {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "keyring version already exists with different content"
                })),
            ));
        }
        let previous: (Vec<u8>, Vec<u8>) = sqlx::query_as(
            "SELECT ok.keyring_payload, usk.pubkey
                   FROM org_keyrings ok
                   JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
                  WHERE ok.org_id = $1 AND ok.version = $2",
        )
        .bind(org_id)
        .bind(body.version - 1)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?
        .ok_or_else(|| bad_request("previous keyring authority is unavailable"))?;
        (previous.0, previous.1, false)
    } else if body.version == latest.0 + 1 {
        (latest.1, latest.3, true)
    } else if body.version < latest.0 {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "keyring version is stale"})),
        ));
    } else {
        return Err(bad_request("keyring version must increment by one"));
    };
    if expected_current_owner != current_owner {
        return Err(bad_request(
            "rotation signer does not match the current pinned owner",
        ));
    }
    // Consume-once + version binding for the rotation directive (issue #120).
    // A directive that creates a new keyring version must be younger than the
    // version it rotates (no skew allowance: a pre-creation capture must fail),
    // must fall inside the first-use max-age window (a captured directive is
    // not a standing bearer token), and must never have been accepted for
    // this org before. The comparison uses the version row's created_at,
    // whose default is clock_timestamp() (migration 0051): the actual
    // insertion time, not the start of the inserting transaction -- uploads
    // and rotations queue on the shared signing-authority lane before
    // inserting, so a transaction-start timestamp could predate the insert
    // by the full lock wait and would accept directives signed inside that
    // lag. The already-applied path below proves a retry by the byte-
    // identical stored keyring content, signatures, and pinned-owner checks
    // instead of the ledger, so retries of rotations performed before this
    // ledger existed (or whose response was lost and retried past the
    // window) stay idempotent at any age.
    if insert_new_version {
        if body.signed_at > lane_now {
            return Err(bad_request(
                "owner rotation directive signed_at is in the future",
            ));
        }
        if body.signed_at < lane_now - chrono::Duration::seconds(MAX_DIRECTIVE_AGE_SECONDS) {
            // Recovery exception (PR #185 review, codex P1): when the
            // upstream rotate-owner already succeeded and only the CAP
            // transaction rolled back, the signing service is pinned to
            // the replacement owner while no keyring version or ledger
            // row exists. The exact lost request can be retried past the
            // window -- but only when the committed presentation record
            // (org_rotation_intents, migration 0053) proves THIS
            // directive caused the drift, not merely that it was
            // presented at some point:
            // 1. same directive digest AND keyring payload digest (a
            //    different directive or keyring over the same
            //    (current -> replacement) pair gets no waiver);
            // 2. first presented while still inside the freshness
            //    window (created_at - signed_at <= MAX_DIRECTIVE_AGE):
            //    a directive first presented already-expired cannot
            //    mint its own waiver evidence in the drift state;
            // 3. that presentation preceded the service's current owner
            //    (intent created_at <= owner snapshot's last_changed_at
            //    + a small skew allowance for independent clocks);
            // 4. no OTHER directive was presented for this org between
            //    this one and the rotation that pinned the service (no
            //    other row's created_at falls in (this row's created_at,
            //    last_changed_at + skew]). Without this, an earlier
            //    failed presentation D1 whose rotate_owner never
            //    succeeded could be replayed after a later D2 over the
            //    same owner pair rotated upstream and CAP rolled back --
            //    D1's intent row would match a drift it did not cause.
            //    Presentations after the rotation are excluded: they
            //    cannot have caused it and must not wedge recovery.
            let waiver: Option<DateTime<Utc>> = sqlx::query_scalar(
                "SELECT i.created_at FROM org_rotation_intents i
                  WHERE i.org_id = $1
                    AND i.directive_sha256 = $2
                    AND i.keyring_sha256 = $3
                    AND i.created_at <= $4::timestamptz + make_interval(secs => $5)
                    AND ($6::timestamptz IS NULL
                         OR i.created_at <= $6::timestamptz + make_interval(secs => $7))
                    AND NOT EXISTS (
                        SELECT 1 FROM org_rotation_intents o
                         WHERE o.org_id = i.org_id
                           AND (o.directive_sha256, o.keyring_sha256)
                               <> (i.directive_sha256, i.keyring_sha256)
                           AND o.created_at > i.created_at
                           AND ($6::timestamptz IS NULL
                                OR o.created_at
                                   <= $6::timestamptz + make_interval(secs => $7)))",
            )
            .bind(org_id)
            .bind(directive_digest.as_slice())
            .bind(intent_digest.as_slice())
            .bind(body.signed_at)
            .bind(MAX_DIRECTIVE_AGE_SECONDS as f64)
            .bind(owner_status.last_changed_at)
            .bind(OWNER_SNAPSHOT_SKEW_SECONDS as f64)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|_| db_error())?;
            let service_holds_replacement =
                service_owner.as_deref() == Some(replacement_owner.as_slice());
            if !(waiver.is_some() && service_holds_replacement) {
                return Err(bad_request("owner rotation directive signed_at is too old"));
            }
        }
        if body.signed_at < latest.4 {
            return Err(bad_request(
                "owner rotation directive predates the current keyring version",
            ));
        }
        let consumed = sqlx::query(
            "INSERT INTO org_rotation_directives (org_id, directive_sha256)
             VALUES ($1, $2)
             ON CONFLICT ON CONSTRAINT org_rotation_directives_pkey DO NOTHING",
        )
        .bind(org_id)
        .bind(directive_digest.as_slice())
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?
        .rows_affected();
        if consumed == 0 {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "owner rotation directive was already used"
                })),
            ));
        }
    } else {
        // Already-applied rotation: the byte-identical stored version
        // content, the verified keyring and directive signatures, and the
        // pinned-owner checks above prove this is a retry of the completed
        // rotation (main's pre-ledger idempotency contract). Any valid
        // directive over the same completed (current -> replacement) pair
        // passes here, not only the consumed one; that stays safe because
        // nothing is consumed on this path (such a directive can never
        // authorize a later insert, which independently enforces the time
        // bounds and the ledger) and no CAP rows are mutated. The signing
        // service may still receive the pre-existing rotate-owner recovery
        // call when it still holds the directive's signer, but the
        // replacement is pinned by the stored keyring, so no new owner key
        // can be introduced (residual exposure tracked in #188).
    }
    let current_keyring: SignedOrgKeyring =
        serde_json::from_slice(&base_payload).map_err(|_| db_error())?;
    if !current_keyring
        .members
        .iter()
        .any(|member| member.pubkey == current_owner && member.role == SignedOrgKeyringRole::Owner)
    {
        return Err(bad_request(
            "current pinned owner key is not an owner in the keyring",
        ));
    }
    validate_rotated_members(
        &current_keyring,
        &replacement_keyring,
        &current_owner,
        &replacement_owner,
    )
    .map_err(bad_request)?;

    let replacement_signing_key_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM user_signing_keys
          WHERE user_id = $1 AND pubkey = $2 AND revoked_at IS NULL",
    )
    .bind(auth.user_id)
    .bind(replacement_owner.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad_request("replacement owner key is not registered for this user"))?;

    if service_owner.as_deref() == Some(current_owner.as_slice()) {
        let rotated = signing_service
            .rotate_owner(&crate::signing_service::RotateOwnerRequest {
                org_id,
                replacement_owner_pubkey_b64: B64.encode(replacement_owner),
                signed_at: body.signed_at,
                reason: body.reason.trim().to_string(),
                signing_pubkey_b64: B64.encode(current_owner),
                signature_b64: B64.encode(rotation_signature),
            })
            .await
            .map_err(crate::routes::deployments::signing_error_response)?;
        // `owner_pubkey_fingerprint` is hex(raw pubkey) by cross-repo contract
        // (see SigningServiceClient response docs) — not a digest.
        if rotated.org_id != org_id
            || rotated.owner_pubkey_fingerprint != hex::encode(replacement_owner)
        {
            return Err(crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::AuthorityStatus(
                    "owner rotation response does not match requested authority".to_string(),
                ),
            ));
        }
    } else if service_owner.as_deref() != Some(replacement_owner.as_slice()) {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "signing service owner matches neither rotation key".to_string(),
            ),
        ));
    }

    if insert_new_version {
        sqlx::query(
            "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(body.version)
        .bind(&payload_bytes)
        .bind(keyring_signature.as_slice())
        .bind(replacement_signing_key_id)
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
        sqlx::query(
            "INSERT INTO audit_log (org_id, user_id, action, detail)
             VALUES ($1, $2, 'org.keyring.owner.rotate', $3)",
        )
        .bind(org_id)
        .bind(auth.user_id)
        .bind(serde_json::json!({"version": body.version, "reason": body.reason.trim()}))
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?;
    }
    tx.commit().await.map_err(|_| db_error())?;

    Ok(Json(RotateOrgOwnerResponse {
        org_id,
        state: "ready",
        keyring_version: body.version,
        owner_fingerprint: hex::encode(Sha256::digest(replacement_owner)),
    }))
}

/// POST /orgs/{name}/invite -- invite a member (must be owner or admin).
pub async fn invite_member(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
    Json(body): Json<InviteRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;

    // Verify caller is an active owner or admin of the target org.
    let membership: Option<(Uuid, Role)> = sqlx::query_as(
        "SELECT o.id, m.role as \"role: _\"
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
    )
    .bind(&org_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let (org_id, caller_role) = membership.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "organization not found"})),
    ))?;
    require_api_key_org(&auth, org_id)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    scopes::require_admin_role(caller_role)?;

    // Find user by email
    let invitee: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM user_identities WHERE provider = 'email' AND identifier = $1",
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let (invitee_id,) = invitee.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "user not found"})),
    ))?;

    let requested_role = scopes::parse_role(body.role.as_deref().unwrap_or("member"))?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_caller_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_admin_role(current_caller_role)?;

    let existing_role: Option<Role> = sqlx::query_scalar(
        "SELECT role as \"role: _\"
         FROM memberships
         WHERE user_id = $1 AND org_id = $2 AND removed_at IS NULL
         FOR UPDATE",
    )
    .bind(invitee_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    scopes::require_owner_to_modify_privileged_role(
        current_caller_role,
        existing_role,
        Some(requested_role),
        invitee_id == auth.user_id,
    )?;

    if existing_role == Some(Role::Owner) && requested_role != Role::Owner {
        scopes::ensure_last_owner_invariant(&mut tx, org_id, invitee_id, Some(requested_role))
            .await?;
    }

    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, removed_at)
         VALUES ($1, $2, $3::role_enum, NULL)
         ON CONFLICT (user_id, org_id)
         DO UPDATE SET role = $3::role_enum, removed_at = NULL",
    )
    .bind(invitee_id)
    .bind(org_id)
    .bind(scopes::role_name(requested_role))
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    tx.commit().await.map_err(|_| db_error())?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({"status": "invited"})),
    ))
}

/// GET /orgs/{name}/members -- list members of an org.
pub async fn list_members(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
) -> Result<Json<Vec<MemberResponse>>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_member(&auth)?;

    // Verify caller is an active member.
    let org_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT o.id FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
    )
    .bind(&org_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let org_id = org_id.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "organization not found"})),
    ))?;
    require_api_key_org(&auth, org_id)?;

    let members: Vec<(Uuid, String, Role)> = sqlx::query_as(
        "SELECT u.id, u.display_name, m.role as \"role: _\"
         FROM users u
         JOIN memberships m ON m.user_id = u.id
         WHERE m.org_id = $1 AND m.removed_at IS NULL
         ORDER BY m.role, u.display_name",
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;

    let result: Vec<MemberResponse> = members
        .into_iter()
        .map(|(user_id, display_name, role)| MemberResponse {
            user_id,
            display_name,
            role: format!("{role:?}").to_lowercase(),
        })
        .collect();

    Ok(Json(result))
}

/// DELETE /orgs/{name}/members/{id} -- remove a member.
pub async fn remove_member(
    auth: AuthContext,
    State(state): State<AppState>,
    Path((org_name, member_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;

    // Verify caller is an active owner or admin.
    let membership: Option<(Uuid, Role)> = sqlx::query_as(
        "SELECT o.id, m.role as \"role: _\"
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE o.name = $1 AND m.user_id = $2 AND m.removed_at IS NULL",
    )
    .bind(&org_name)
    .bind(auth.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    let (org_id, caller_role) = membership.ok_or((
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({"error": "organization not found"})),
    ))?;
    require_api_key_org(&auth, org_id)?;
    crate::routes::apps::ensure_management_write_allowed(&state, &auth).await?;

    scopes::require_admin_role(caller_role)?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::entitlements::lock_org_entitlement_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_caller_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_admin_role(current_caller_role)?;
    let target_role: Option<Role> = sqlx::query_scalar(
        "SELECT role as \"role: _\"
         FROM memberships
         WHERE user_id = $1 AND org_id = $2 AND removed_at IS NULL
         FOR UPDATE",
    )
    .bind(member_id)
    .bind(org_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    scopes::require_owner_to_modify_privileged_role(
        current_caller_role,
        target_role,
        None,
        member_id == auth.user_id,
    )?;

    if target_role == Some(Role::Owner) {
        scopes::ensure_last_owner_invariant(&mut tx, org_id, member_id, None).await?;
    }

    sqlx::query(
        "UPDATE memberships
         SET removed_at = now()
         WHERE user_id = $1 AND org_id = $2 AND removed_at IS NULL",
    )
    .bind(member_id)
    .bind(org_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    sqlx::query(
        "UPDATE api_keys
         SET expires_at = CASE
             WHEN expires_at IS NULL OR expires_at > now() THEN now()
             ELSE expires_at
         END
         WHERE org_id = $1 AND created_by = $2",
    )
    .bind(org_id)
    .bind(member_id)
    .execute(&mut *tx)
    .await
    .map_err(|_| db_error())?;

    tx.commit().await.map_err(|_| db_error())?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::api_key::ValidatedApiKey;
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::sync::Arc;

    #[tokio::test]
    async fn create_org_rejects_non_dns_safe_names_before_database_access() {
        let state = crate::test_support::lazy_state();
        let auth = crate::test_support::auth_context(Role::Owner, &[]);
        for bad_name in ["Acme", "acme corp", "acme_", "-acme", "acme-", ""] {
            let err = create_org(
                auth.clone(),
                State(state.clone()),
                Json(CreateOrgRequest {
                    name: bad_name.to_string(),
                    display_name: None,
                }),
            )
            .await
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST, "name {bad_name:?}");
        }
    }

    #[tokio::test]
    async fn create_org_refuses_public_signups_on_paas_managed_instances() {
        let mut state = crate::test_support::lazy_state();
        state.management_mode = crate::state::CapManagementMode::PaasManaged;
        let auth = crate::test_support::auth_context(Role::Owner, &[]);
        let err = create_org(
            auth,
            State(state),
            Json(CreateOrgRequest {
                name: "acme".to_string(),
                display_name: None,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::FORBIDDEN);
    }

    #[test]
    fn signing_readiness_requires_both_authorities_to_agree() {
        let owner = [0x11; 32];
        let other = [0x22; 32];
        assert_eq!(signing_readiness_state(None, None), "not_configured");
        assert_eq!(signing_readiness_state(Some(&owner), Some(&owner)), "ready");
        assert_eq!(
            signing_readiness_state(Some(&owner), Some(&other)),
            "drifted"
        );
        assert_eq!(
            signing_readiness_state(Some(&owner), None),
            "recovery_required"
        );
        assert_eq!(
            signing_readiness_state(None, Some(&owner)),
            "recovery_required"
        );
    }

    #[test]
    fn owner_fingerprint_is_a_digest_not_the_public_key() {
        let owner = [0x11; 32];
        let public_key = hex::encode(owner);
        let fingerprint = owner_key_fingerprint(&public_key).expect("valid owner key");
        assert_ne!(fingerprint, public_key);
        assert_eq!(fingerprint, hex::encode(Sha256::digest(owner)));
        assert_eq!(owner_key_fingerprint("not-hex"), None);
    }

    #[test]
    fn owner_rotation_preserves_every_member_except_owner_public_key() {
        let org_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let deployer_id = Uuid::new_v4();
        let added_at = Utc.with_ymd_and_hms(2026, 8, 12, 0, 0, 0).unwrap();
        let current_owner = [0x11; 32];
        let replacement_owner = [0x22; 32];
        let current = SignedOrgKeyring {
            org_id,
            version: 1,
            members: vec![
                SignedOrgKeyringMember {
                    user_id: owner_id,
                    pubkey: current_owner,
                    role: SignedOrgKeyringRole::Owner,
                    added_at,
                },
                SignedOrgKeyringMember {
                    user_id: deployer_id,
                    pubkey: [0x33; 32],
                    role: SignedOrgKeyringRole::Deployer,
                    added_at,
                },
            ],
            updated_at: added_at,
        };
        let replacement = SignedOrgKeyring {
            org_id,
            version: 2,
            members: vec![
                SignedOrgKeyringMember {
                    user_id: owner_id,
                    pubkey: replacement_owner,
                    role: SignedOrgKeyringRole::Owner,
                    added_at,
                },
                SignedOrgKeyringMember {
                    user_id: deployer_id,
                    pubkey: [0x33; 32],
                    role: SignedOrgKeyringRole::Deployer,
                    added_at,
                },
            ],
            updated_at: added_at,
        };

        assert!(
            validate_rotated_members(&current, &replacement, &current_owner, &replacement_owner)
                .is_ok()
        );

        let mut tampered = replacement;
        tampered.members[1].role = SignedOrgKeyringRole::Admin;
        assert_eq!(
            validate_rotated_members(&current, &tampered, &current_owner, &replacement_owner),
            Err("owner rotation must preserve non-owner keyring members")
        );
    }

    async fn database_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect keyring regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate keyring regression database");
        pool
    }

    async fn named_database_test_pool(application_name: &str) -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let options = database_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse keyring regression database URL")
            .application_name(application_name);
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .expect("connect named keyring regression pool")
    }

    async fn wait_for_named_lock_waiter(pool: &sqlx::PgPool, application_name: &str) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (
                         SELECT 1
                           FROM pg_stat_activity
                          WHERE datname = current_database()
                            AND application_name = $1
                            AND wait_event_type = 'Lock'
                     )",
                )
                .bind(application_name)
                .fetch_one(pool)
                .await
                .expect("inspect named keyring writer lock state");
                if waiting {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("keyring writer did not block on membership authority removal");
    }

    fn signed_keyring_request(
        org_id: Uuid,
        user_id: Uuid,
        key: &SigningKey,
        version: i64,
        second: u32,
    ) -> PutOrgKeyringRequest {
        let added_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let updated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, second).unwrap();
        let member = SignedOrgKeyringMember {
            user_id,
            pubkey: key.verifying_key().to_bytes(),
            role: SignedOrgKeyringRole::Owner,
            added_at,
        };
        let keyring = SignedOrgKeyring {
            org_id,
            version: version as u64,
            members: vec![member],
            updated_at,
        };
        let signature = key.sign(&canonical_keyring_bytes(&keyring));
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        PutOrgKeyringRequest {
            version,
            keyring_payload: serde_json::json!({
                "org_id": org_id,
                "version": version,
                "members": [{
                    "user_id": user_id,
                    "pubkey": pubkey,
                    "role": "owner",
                    "added_at": added_at,
                }],
                "updated_at": updated_at,
            }),
            signature: hex::encode(signature.to_bytes()),
            signing_pubkey: pubkey,
        }
    }

    fn auth_context(api_key: Option<ValidatedApiKey>) -> AuthContext {
        AuthContext {
            user_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            org_name: "personal".to_string(),
            role: Role::Owner,
            api_key,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        }
    }

    /// Minimal in-process stand-in for the platform signing service's owner
    /// authority surface: `GET /orgs/{id}/owner` and `POST /rotate-owner`.
    async fn mock_signing_service_owner_api(org_id: Uuid, initial_owner: [u8; 32]) -> String {
        mock_signing_service_owner_api_with_changed_at(org_id, initial_owner, Utc::now()).await
    }

    /// Variant whose owner status reports a fixed initial `last_changed_at`,
    /// standing in for a rotation that happened at a specific past instant
    /// (the max-age recovery waiver compares presentation records against
    /// that timestamp).
    async fn mock_signing_service_owner_api_with_changed_at(
        org_id: Uuid,
        initial_owner: [u8; 32],
        initial_changed_at: DateTime<Utc>,
    ) -> String {
        let owner = Arc::new(std::sync::Mutex::new((initial_owner, initial_changed_at)));
        let status_owner = owner.clone();
        let rotate_owner = owner;
        let app = axum::Router::new()
            .route(
                &format!("/orgs/{org_id}/owner"),
                axum::routing::get(move || async move {
                    let (current, changed_at) = *status_owner.lock().expect("mock owner lock");
                    axum::Json(serde_json::json!({
                        "org_id": org_id,
                        "state": "ready",
                        "version": 1,
                        "owner_pubkey_hex": hex::encode(current),
                        "last_changed_at": changed_at,
                    }))
                }),
            )
            .route(
                "/rotate-owner",
                axum::routing::post(
                    move |axum::Json(req): axum::Json<serde_json::Value>| async move {
                        let replacement: [u8; 32] = B64
                            .decode(req["replacement_owner_pubkey_b64"].as_str().unwrap_or(""))
                            .expect("mock replacement owner decodes")
                            .try_into()
                            .expect("mock replacement owner is 32 bytes");
                        *rotate_owner.lock().expect("mock owner lock") = (replacement, Utc::now());
                        axum::Json(serde_json::json!({
                            "org_id": req["org_id"].clone(),
                            "version": 1,
                            "owner_pubkey_fingerprint": hex::encode(replacement),
                            "rotated_at": Utc::now(),
                        }))
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock signing service");
        let address = listener.local_addr().expect("mock signing service address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve mock signing service");
        });
        format!("http://{address}/")
    }

    #[allow(clippy::too_many_arguments)]
    fn rotation_request(
        org_id: Uuid,
        user_id: Uuid,
        current: &SigningKey,
        replacement: &SigningKey,
        version: i64,
        second: u32,
        signed_at: DateTime<Utc>,
        reason: &str,
    ) -> RotateOrgOwnerRequest {
        let added_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let updated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, second).unwrap();
        let keyring = SignedOrgKeyring {
            org_id,
            version: version as u64,
            members: vec![SignedOrgKeyringMember {
                user_id,
                pubkey: replacement.verifying_key().to_bytes(),
                role: SignedOrgKeyringRole::Owner,
                added_at,
            }],
            updated_at,
        };
        let signature = replacement.sign(&canonical_keyring_bytes(&keyring));
        let directive = owner_rotation_directive_bytes(
            org_id,
            &current.verifying_key().to_bytes(),
            &replacement.verifying_key().to_bytes(),
            signed_at,
            reason,
        );
        RotateOrgOwnerRequest {
            version,
            keyring_payload: serde_json::json!({
                "org_id": org_id,
                "version": version,
                "members": [{
                    "user_id": user_id,
                    "pubkey": hex::encode(replacement.verifying_key().to_bytes()),
                    "role": "owner",
                    "added_at": added_at,
                }],
                "updated_at": updated_at,
            }),
            signature: hex::encode(signature.to_bytes()),
            replacement_signing_pubkey: hex::encode(replacement.verifying_key().to_bytes()),
            current_signing_pubkey: hex::encode(current.verifying_key().to_bytes()),
            signed_at,
            reason: reason.to_string(),
            rotation_signature: hex::encode(current.sign(&directive).to_bytes()),
        }
    }

    #[tokio::test]
    async fn owner_rotation_directive_is_fresh_bound_and_single_use() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-directive-replay-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert directive replay org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Directive Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert directive owner user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert directive owner membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert directive owner signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, current_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");

        // A directive whose signed_at predates the current keyring version
        // (while still inside the TTL window) must be rejected even though
        // the signature itself is perfectly valid.
        let stale = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::minutes(10),
            "regression",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(stale),
        )
        .await
        .expect_err("stale rotation directive must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive predates the current keyring version"
        );

        // A directive dated unreasonably far in the future is rejected: on
        // the insert-new-version path there is no skew allowance, because
        // signed_at is attacker-chosen at signing time and a future-dated
        // directive could otherwise compare as newer than a keyring version
        // that already existed when it was captured (PR #185 review).
        let future = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() + chrono::Duration::minutes(30),
            "regression",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(future),
        )
        .await
        .expect_err("future-dated rotation directive must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive signed_at is in the future"
        );

        // The issue's core replay: a directive signed while the current
        // keyring version was already in force (so it clears the
        // predates-version check) but submitted only after the max-age
        // window has elapsed. Signature still valid, pair still valid,
        // never consumed -- the TTL must reject it on first use.
        let aged = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::minutes(30),
            "regression",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(aged),
        )
        .await
        .expect_err("aged rotation directive must be rejected on first use");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive signed_at is too old"
        );

        // A fresh directive rotates normally...
        let first_signed_at = Utc::now();
        let forward = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            first_signed_at,
            "regression",
        );
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(forward.clone()),
        )
        .await
        .expect("fresh directive rotates the owner");
        // ...and an exact retry of the same, already-applied request stays
        // idempotent (same version, byte-identical payload, signatures, and
        // directive).
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(forward),
        )
        .await
        .expect("exact retry of an applied rotation is idempotent");

        // A DIFFERENT valid directive (fresh signed_at) presented against the
        // already-applied version is indistinguishable from an original
        // request whose response was lost: main's idempotency contract
        // accepts it (the stored version content, signatures, and pinned
        // owner all match) and nothing is mutated. It is NOT recorded in the
        // ledger, so it can never authorize a later new-version rotation.
        let different = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now(),
            "regression-second-signature",
        );
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(different),
        )
        .await
        .expect("different valid directive on the applied path is an idempotent no-op");

        // Rotate back so the original pair is valid again: the pinned owner
        // is once more the key that signed the first directive.
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(rotation_request(
                org_id,
                user_id,
                &replacement_key,
                &current_key,
                3,
                3,
                Utc::now(),
                "regression-back",
            )),
        )
        .await
        .expect("rotate owner back to the original key");

        // Replaying the captured first directive now targets a fresh keyring
        // version (v4) with a still-valid signature and a still-valid pair.
        // The predates-current-version bound rejects it here; the TTL and the
        // consume-once ledger additionally reject in-window and clock-skew
        // replays (a directive whose signed_at is older than every rollback
        // version can never grant authority again).
        let replay = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            4,
            4,
            first_signed_at,
            "regression",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(replay),
        )
        .await
        .expect_err("replayed rotation directive must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive predates the current keyring version"
        );

        let directive_rows: i64 =
            sqlx::query_scalar("SELECT count(*) FROM org_rotation_directives WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("count consumed rotation directives");
        assert_eq!(directive_rows, 2, "only the two applied directives consume");

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete directive replay audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete directive replay org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete directive replay user");
    }

    #[tokio::test]
    async fn owner_rotation_rejects_future_dated_directive_despite_version_recency() {
        // Regression (PR #185 review): the old +300s clock-skew allowance
        // made the version-recency bound bypassable. signed_at is chosen by
        // the signer, not the server: a directive captured at 12:00 with
        // signed_at = 12:04 compares as newer than a v2 uploaded at 12:01
        // and still passes the future-skew check when submitted at 12:05,
        // even though it predates v2. On the insert-new-version path
        // signed_at must not be in the future at all (measured after the
        // signing-authority lane is acquired).
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-future-dated-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert future-dated org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Future Dated Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert future-dated user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert future-dated membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert future-dated signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, current_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");

        // The directive is captured now but claims to be signed four
        // minutes in the future -- inside the old +300s skew allowance.
        let directive_signed_at = Utc::now() + chrono::Duration::minutes(4);
        // A v2 upload lands while the directive's claimed timestamp is
        // still in the future.
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 2, 2)),
        )
        .await
        .expect("publish v2 keyring");
        // Submit the directive for v3 while its claimed signed_at is still
        // four minutes in the future -- squarely inside the old +300s skew
        // allowance. Under the old code it would sail through every check:
        // inside the skew allowance, inside the TTL, and newer than v2's
        // created_at, despite having been captured before v2 existed. The
        // no-skew bound rejects it: signed_at is still in the future
        // measured against the lane clock at submission.
        let replay = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            3,
            3,
            directive_signed_at,
            "future-dated",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(replay),
        )
        .await
        .expect_err("directive submitted before its claimed signed_at must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive signed_at is in the future"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete future-dated audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete future-dated org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete future-dated user");
    }

    #[tokio::test]
    async fn owner_rotation_consumed_directive_conflict_is_rejected() {
        // Coverage (grok-4.7 self-check of the PR #185 follow-up): the
        // rows_affected == 0 branch of the ledger insert is the only
        // backstop for an already-consumed directive whose signed_at still
        // clears the time bounds (the #188 scenario once the directive has
        // been used). Seed the digest directly, keep signed_at inside the
        // window and not before the current version's created_at, and
        // expect 409 "already used" rather than any time-bound rejection.
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-consumed-conflict-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert consumed-conflict org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Consumed Conflict Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert consumed-conflict user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert consumed-conflict membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert consumed-conflict signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, current_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");

        // A directive that is otherwise perfectly valid on the
        // insert-new-version path: fresh, not future-dated, not before
        // v1's created_at -- but its digest was already consumed.
        let signed_at = Utc::now();
        let request = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            signed_at,
            "consumed-conflict",
        );
        let directive = owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            signed_at,
            "consumed-conflict",
        );
        sqlx::query(
            "INSERT INTO org_rotation_directives (org_id, directive_sha256) VALUES ($1, $2)",
        )
        .bind(org_id)
        .bind(Sha256::digest(&directive).as_slice())
        .execute(&pool)
        .await
        .expect("pre-consume directive digest");

        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(request),
        )
        .await
        .expect_err("already-consumed directive must be rejected");
        assert_eq!(rejected.0, StatusCode::CONFLICT);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive was already used"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete consumed-conflict audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete consumed-conflict org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete consumed-conflict user");
    }

    #[tokio::test]
    async fn owner_rotation_recovers_when_service_already_holds_replacement() {
        // Regression (PR #185 review, codex P1/P2): if the upstream
        // rotate-owner succeeds but the CAP transaction rolls back, the
        // signing service is pinned to the replacement while no keyring
        // version or ledger row exists. Retrying the exact request after
        // the 15-minute first-use window must still reconcile: the
        // owner_status check observes the pinned replacement and the
        // max-age bound must not reject the recovery retry on age alone
        // (completing the insert introduces no new owner key -- the
        // pinned-owner, byte-identical content, and signature checks
        // still bind the stored version to what upstream already
        // accepted). Contrast with
        // owner_rotation_expired_exact_retry_stays_idempotent, which
        // covers the already-applied (committed v2) path.
        //
        // The waiver is granted only when the committed presentation
        // record proves THIS directive caused the drift: first presented
        // while fresh, before the service's current owner was pinned,
        // with no other directive presented in between. The negative
        // cases below cover each leg of that proof.
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-service-recovery-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert service-recovery org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Service Recovery Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert service-recovery user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert service-recovery membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert service-recovery signing keys");

        // Drift timeline (PR #185 review, codex P1): the lost attempt
        // presented D2 while fresh; the upstream rotation that pinned the
        // service happened after that presentation. An earlier failed
        // directive D1 (whose rotate_owner never succeeded) was presented
        // before D2. All sub-cases below share this clock.
        let presented_d1_at = Utc::now() - chrono::Duration::minutes(25);
        let signed_d1_at = Utc::now() - chrono::Duration::minutes(26);
        let presented_d2_at = Utc::now() - chrono::Duration::minutes(20);
        let drift_at = Utc::now() - chrono::Duration::minutes(19);

        // The signing service starts pinned to the replacement owner with
        // last_changed_at = drift_at: the upstream rotate-owner of the
        // lost first attempt already succeeded and CAP's transaction
        // rolled back.
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api_with_changed_at(
                    org_id,
                    replacement_key.verifying_key().to_bytes(),
                    drift_at,
                )
                .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");
        // Backdate v1 so the 20-minute-old directive below still passes
        // the "not older than the current version's creation" bound; only
        // the first-use max-age window is exceeded.
        sqlx::query("UPDATE org_keyrings SET created_at = $2 WHERE org_id = $1 AND version = 1")
            .bind(org_id)
            .bind(Utc::now() - chrono::Duration::minutes(30))
            .execute(&pool)
            .await
            .expect("backdate v1 creation");

        // Negative case 1 (a different directive over the same pair gets
        // no waiver): a DIFFERENT directive over the same
        // (current -> replacement) pair -- here a different reason,
        // equally expired. Its presentation lands in org_rotation_intents
        // (created_at = now, long past the drift), but that cannot satisfy
        // the waiver: it was not presented while fresh, and it postdates
        // the rotation that pinned the service. The drift state must not
        // let a captured directive mint a version past the window.
        let imposter = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::minutes(20),
            "service-recovery-imposter",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(imposter),
        )
        .await
        .expect_err("unpresented expired directive must not get the waiver");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive signed_at is too old"
        );

        // The recovery retry: the same directive D2 the lost attempt used,
        // now past the 15-minute window. No v2 row, no ledger row exists --
        // but the lost attempt's separately-committed intent row does,
        // first presented (presented_d2_at) while the directive was fresh
        // and before the service rotation (drift_at) that pinned the
        // replacement. An earlier failed directive D1 (reason
        // "service-recovery-lost-first", signed at signed_d1_at, presented
        // at presented_d1_at, whose upstream rotate_owner never succeeded)
        // also has a committed row -- it must NOT be enough for D1 itself.
        let recovery_signed_at = Utc::now() - chrono::Duration::minutes(20);
        let recovery = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            recovery_signed_at,
            "service-recovery",
        );
        let recovery_directive = owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            recovery_signed_at,
            "service-recovery",
        );
        let d1 = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            signed_d1_at,
            "service-recovery-lost-first",
        );
        let d1_directive = owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            signed_d1_at,
            "service-recovery-lost-first",
        );
        let seed_row = |directive: &[u8],
                        payload: serde_json::Value,
                        presented_at: DateTime<Utc>| {
            let pool = pool.clone();
            let directive = Sha256::digest(directive);
            let keyring = Sha256::digest(serde_json::to_vec(&payload).expect("serialize payload"));
            async move {
                sqlx::query(
                    "INSERT INTO org_rotation_intents
                         (org_id, directive_sha256, keyring_sha256, created_at)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT ON CONSTRAINT org_rotation_intents_pkey DO NOTHING",
                )
                .bind(org_id)
                .bind(directive.as_slice())
                .bind(keyring.as_slice())
                .bind(presented_at)
                .execute(&pool)
                .await
                .expect("seed committed intent row");
            }
        };
        seed_row(&d1_directive, d1.keyring_payload.clone(), presented_d1_at).await;
        seed_row(
            &recovery_directive,
            recovery.keyring_payload.clone(),
            presented_d2_at,
        )
        .await;

        // Negative case 2 (codex P1, D1 did not cause the drift): D1 was
        // presented while fresh and before the rotation that pinned the
        // service, and its own rotate_owner never succeeded (the drift was
        // caused by the later D2 attempt). Replaying expired D1 must NOT
        // mint D1's keyring version: another directive (D2) was presented
        // between D1's presentation and the rotation, so D1's row does not
        // prove its rotation put the service into the drift state.
        let rejected_d1 = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(d1),
        )
        .await
        .expect_err("earlier failed directive must not inherit the drift");
        assert_eq!(rejected_d1.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected_d1.1.0["error"],
            "owner rotation directive signed_at is too old"
        );

        // Note: negative case 1 also proves the waiver cannot be
        // self-seeded -- the imposter's own presentation records an intent
        // row before the check runs, and the check still rejects it (first
        // presentation not fresh, postdates the rotation).

        let recovered = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(recovery),
        )
        .await
        .expect("recovery retry past the window reconciles the lost rotation");
        assert_eq!(recovered.keyring_version, 2);
        assert_eq!(
            recovered.owner_fingerprint,
            hex::encode(Sha256::digest(replacement_key.verifying_key().to_bytes()))
        );
        let stored_version: i64 = sqlx::query_scalar(
            "SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("read back latest version");
        assert_eq!(stored_version, 2);

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete service-recovery audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete service-recovery org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete service-recovery user");
    }

    #[tokio::test]
    async fn owner_rotation_expired_exact_retry_stays_idempotent() {
        // Regression (PR #185 review): the signed_at max-age is a first-use
        // bound. If a rotation commits but its response is lost, a caller
        // retrying the byte-identical request after the 15-minute window
        // must still get the documented idempotent success: the consume-once
        // ledger proves the exact directive authorized the completed
        // rotation. The mock signing service starts with the replacement
        // owner already pinned, standing in for the committed first attempt.
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-expired-retry-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert expired retry org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Expired Retry Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert expired retry user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert expired retry membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert expired retry signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, replacement_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");

        // The "committed first attempt": v2 exists with the replacement
        // owner pinned. No org_rotation_directives row exists, standing in
        // for a rotation performed before the ledger deployment (or a
        // crash-recovered commit) -- the retry must still be idempotent.
        let applied_signed_at = Utc::now() - chrono::Duration::minutes(30);
        let applied = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            applied_signed_at,
            "expired-retry",
        );
        sqlx::query(
            "INSERT INTO org_keyrings (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, 2, $2, $3,
                     (SELECT id FROM user_signing_keys
                       WHERE user_id = $4 AND pubkey = $5 AND revoked_at IS NULL))",
        )
        .bind(org_id)
        .bind(serde_json::to_vec(&applied.keyring_payload).expect("serialize applied payload"))
        .bind(hex::decode(&applied.signature).expect("decode applied signature"))
        .bind(user_id)
        .bind(replacement_key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("insert committed v2 keyring row");

        // Byte-identical retry past the max-age window: idempotent success.
        let retried = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(applied),
        )
        .await
        .expect("expired exact retry of an applied rotation is idempotent");
        assert_eq!(retried.keyring_version, 2);
        assert_eq!(
            retried.owner_fingerprint,
            hex::encode(Sha256::digest(replacement_key.verifying_key().to_bytes()))
        );

        // A never-applied directive older than the window is still rejected:
        // the max-age bound holds on first use. The pinned owner is now the
        // replacement key, so the would-be v3 rotation is signed by it.
        let stale = rotation_request(
            org_id,
            user_id,
            &replacement_key,
            &current_key,
            3,
            3,
            Utc::now() - chrono::Duration::minutes(30),
            "expired-first-use",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(stale),
        )
        .await
        .expect_err("expired first-use directive must still be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive signed_at is too old"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete expired retry audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete expired retry org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete expired retry user");
    }

    #[tokio::test]
    async fn owner_rotation_version_bound_uses_actual_keyring_insertion_time() {
        // Regression (PR #185 review): org_keyrings.created_at must witness
        // the moment a version row is actually inserted, not the start of the
        // inserting transaction. A keyring upload that queues on the shared
        // signing-authority lane pins now() == transaction_timestamp() at
        // BEGIN; a directive captured after BEGIN but before the queued
        // version lands would then compare as "newer than the version" and be
        // accepted, defeating the pre-creation replay bound. Migration 0051
        // switches the default to clock_timestamp() and this test fails
        // against the old transaction-start semantics.
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-lane-lag-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert lane lag org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Lane Lag Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert lane lag user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert lane lag membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert lane lag signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, current_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build mock signing service client"),
        );
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 1, 1)),
        )
        .await
        .expect("publish v1 keyring");

        // Hold the org's signing-authority lane so a v2 upload queues behind
        // this transaction, exactly like any concurrent signing-authority
        // writer would.
        let mut lane_blocker = pool.begin().await.expect("begin lane blocker");
        sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
            .bind(crate::signing_service::ORG_SIGNING_AUTHORITY_LANE_DOMAIN)
            .bind(crate::signing_service::org_signing_advisory_key(org_id))
            .execute(&mut *lane_blocker)
            .await
            .expect("hold signing authority lane");

        let writer_application = format!("keyring-lane-lag-writer-{suffix}");
        let mut writer_state = crate::test_support::lazy_state();
        writer_state.db = named_database_test_pool(&writer_application).await;
        writer_state.signing_service = state.signing_service.clone();
        let writer = tokio::spawn(put_keyring(
            auth.clone(),
            State(writer_state),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 2, 2)),
        ));
        wait_for_named_lock_waiter(&pool, &writer_application).await;

        // The upload transaction has begun and is queued on the lane. Capture
        // the directive timestamp now: after the writer's BEGIN, before the
        // v2 row can possibly be inserted. Under the old now() default this
        // predates v2's created_at and the directive is accepted as "newer".
        let directive_signed_at = Utc::now();
        lane_blocker
            .rollback()
            .await
            .expect("release signing authority lane");
        let _ = writer
            .await
            .expect("join queued keyring upload")
            .expect("queued v2 keyring upload commits");

        // The stored witness must be the true insertion time: strictly after
        // the directive captured while the upload was still queued.
        let v2_created_at: DateTime<Utc> = sqlx::query_scalar(
            "SELECT created_at FROM org_keyrings WHERE org_id = $1 AND version = 2",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("read v2 insertion witness");
        assert!(
            v2_created_at > directive_signed_at,
            "v2 created_at must be the actual insertion time (clock_timestamp), \
             not the queued transaction's start time"
        );

        // The directive predates v2's actual creation and must be rejected on
        // the insert-new-version path (v3) even though it is inside the TTL
        // window, freshly signed, and never consumed.
        let replay = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            3,
            3,
            directive_signed_at,
            "lane-lag",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(replay),
        )
        .await
        .expect_err("directive captured during lane lag must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive predates the current keyring version"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete lane lag audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete lane lag org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete lane lag user");
    }

    #[test]
    fn list_orgs_session_includes_all_user_orgs() {
        let auth = auth_context(None);

        assert_eq!(list_orgs_api_key_org_filter(&auth), None);
    }

    #[test]
    fn list_orgs_api_key_is_limited_to_bound_org() {
        let org_id = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        let auth = auth_context(Some(ValidatedApiKey {
            id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            org_id,
            created_by: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            scopes: vec!["apps:read".to_string()],
        }));

        assert_eq!(list_orgs_api_key_org_filter(&auth), Some(org_id));
    }

    #[tokio::test]
    async fn keyring_acceptance_waits_for_membership_removal_and_rejects() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let remover_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-removal-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring removal org");
        sqlx::query(
            "INSERT INTO users (id, display_name)
             VALUES ($1, 'Removed Owner'), ($2, 'Remaining Owner')",
        )
        .bind(user_id)
        .bind(remover_id)
        .execute(&pool)
        .await
        .expect("insert keyring removal owners");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $3, 'owner'), ($2, $3, 'owner')",
        )
        .bind(user_id)
        .bind(remover_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("insert keyring removal memberships");
        let key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert keyring removal signing key");

        let removal_application = format!("member-removal-{suffix}");
        let keyring_application = format!("keyring-after-removal-{suffix}");
        let mut removal_state = crate::test_support::lazy_state();
        removal_state.db = named_database_test_pool(&removal_application).await;
        let mut keyring_state = crate::test_support::lazy_state();
        keyring_state.db = named_database_test_pool(&keyring_application).await;
        let keyring_auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let remover_auth = AuthContext {
            user_id: remover_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };

        let mut row_blocker = pool.begin().await.expect("begin membership row blocker");
        sqlx::query(
            "SELECT 1 FROM memberships
              WHERE org_id = $1 AND user_id = $2
              FOR UPDATE",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&mut *row_blocker)
        .await
        .expect("block target membership row");

        let removal_org_name = org_name.clone();
        let removal = tokio::spawn(remove_member(
            remover_auth,
            State(removal_state),
            Path((removal_org_name, user_id)),
        ));
        wait_for_named_lock_waiter(&pool, &removal_application).await;

        let writer = tokio::spawn(put_keyring(
            keyring_auth,
            State(keyring_state),
            Path(org_name),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        ));
        wait_for_named_lock_waiter(&pool, &keyring_application).await;
        row_blocker
            .rollback()
            .await
            .expect("release target membership row");
        assert_eq!(
            removal
                .await
                .expect("join public membership removal")
                .expect("public membership removal succeeds"),
            StatusCode::NO_CONTENT
        );

        let rejected = writer
            .await
            .expect("join blocked keyring writer")
            .expect_err("removed owner cannot publish a keyring");
        assert_eq!(rejected.0, StatusCode::FORBIDDEN);
        assert_eq!(
            rejected.1.0["error"],
            "active organization membership required"
        );
        let authority_rows: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put')",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rejected keyring authority rows");
        assert_eq!(authority_rows, (0, 0));
    }

    #[tokio::test]
    async fn keyring_rotation_preserves_pinned_owner_and_one_immutable_v2_winner() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let attacker_user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-race-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring race org");
        sqlx::query(
            "INSERT INTO users (id, display_name)
             VALUES ($1, 'Keyring Owner'), ($2, 'Unpinned Owner')",
        )
        .bind(user_id)
        .bind(attacker_user_id)
        .execute(&pool)
        .await
        .expect("insert keyring owners");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $3, 'owner'), ($2, $3, 'owner')",
        )
        .bind(user_id)
        .bind(attacker_user_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("insert owner memberships");
        let key = SigningKey::generate(&mut OsRng);
        let attacker_key = SigningKey::generate(&mut OsRng);
        sqlx::query(
            "INSERT INTO user_signing_keys (user_id, pubkey)
             VALUES ($1, $3), ($2, $4)",
        )
        .bind(user_id)
        .bind(attacker_user_id)
        .bind(key.verifying_key().to_bytes().to_vec())
        .bind(attacker_key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("insert owner signing keys");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let auth = AuthContext {
            user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        )
        .await
        .expect("insert v1 keyring");

        let attacker_auth = AuthContext {
            user_id: attacker_user_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let takeover = put_keyring(
            attacker_auth,
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                attacker_user_id,
                &attacker_key,
                2,
                2,
            )),
        )
        .await
        .expect_err("an unpinned CAP owner cannot self-authorize keyring v2");
        assert_eq!(takeover.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            takeover.1.0["error"],
            "keyring signing owner does not match the current pinned owner"
        );
        let post_takeover_counts: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put')",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rows after rejected owner takeover");
        assert_eq!(
            post_takeover_counts,
            (1, 1),
            "rejected owner takeover must not mutate keyring or audit authority"
        );

        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(3));
        let spawn_writer = |request: PutOrgKeyringRequest| {
            let barrier = barrier.clone();
            let auth = auth.clone();
            let state = state.clone();
            let org_name = org_name.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                put_keyring(auth, State(state), Path(org_name), Json(request)).await
            })
        };
        let writer_a = spawn_writer(signed_keyring_request(org_id, user_id, &key, 2, 2));
        let writer_b = spawn_writer(signed_keyring_request(org_id, user_id, &key, 2, 3));
        barrier.wait().await;
        let results = [
            writer_a.await.expect("join keyring writer A"),
            writer_b.await.expect("join keyring writer B"),
        ];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let conflicts: Vec<_> = results
            .iter()
            .filter_map(|result| result.as_ref().err())
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].0, StatusCode::CONFLICT);
        assert_eq!(
            conflicts[0].1.0["error"],
            "keyring version already exists with different content"
        );

        let versions: Vec<(i64, Vec<u8>)> = sqlx::query_as(
            "SELECT version, keyring_payload FROM org_keyrings
             WHERE org_id = $1 ORDER BY version",
        )
        .bind(org_id)
        .fetch_all(&pool)
        .await
        .expect("load immutable keyring versions");
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].0, 1);
        assert_eq!(versions[1].0, 2);
        let v2_payload: serde_json::Value =
            serde_json::from_slice(&versions[1].1).expect("decode winning v2 payload");
        assert!(
            matches!(v2_payload["updated_at"].as_str(), Some(value) if value.ends_with("02Z") || value.ends_with("03Z"))
        );
        let winning_second = if v2_payload["updated_at"]
            .as_str()
            .is_some_and(|value| value.ends_with("02Z"))
        {
            2
        } else {
            3
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                user_id,
                &key,
                2,
                winning_second,
            )),
        )
        .await
        .expect("exact same-owner v2 replay is idempotent");
        let latest_signing_pubkey: Vec<u8> = sqlx::query_scalar(
            "SELECT usk.pubkey
               FROM org_keyrings ok
               JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
              WHERE ok.org_id = $1
              ORDER BY ok.version DESC
              LIMIT 1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load pinned v2 signing owner");
        assert_eq!(latest_signing_pubkey, key.verifying_key().to_bytes());
        let audit_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log
             WHERE org_id = $1 AND action = 'org.keyring.put'",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count mandatory keyring audit rows");
        assert_eq!(
            audit_count, 2,
            "only v1 and the single winning same-owner v2 are audited"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete keyring race audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete keyring race org");
        sqlx::query("DELETE FROM users WHERE id IN ($1, $2)")
            .bind(user_id)
            .bind(attacker_user_id)
            .execute(&pool)
            .await
            .expect("delete keyring race users");
    }

    fn membership_test_auth(
        user_id: Uuid,
        org_id: Uuid,
        org_name: &str,
        role: Role,
    ) -> AuthContext {
        AuthContext {
            user_id,
            org_id,
            org_name: org_name.to_string(),
            role,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        }
    }

    #[tokio::test]
    async fn membership_privileged_role_changes_require_owner() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();
        let victim_admin_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("member-escalation-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert member escalation org");
        sqlx::query(
            "INSERT INTO users (id, display_name)
             VALUES ($1, 'Escalation Owner'), ($2, 'Escalation Admin'),
                    ($3, 'Victim Admin'), ($4, 'Plain Member')",
        )
        .bind(owner_id)
        .bind(admin_id)
        .bind(victim_admin_id)
        .bind(member_id)
        .execute(&pool)
        .await
        .expect("insert member escalation users");
        sqlx::query(
            "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $5, 'owner'), ($2, $5, 'admin'),
                    ($3, $5, 'admin'), ($4, $5, 'member')",
        )
        .bind(owner_id)
        .bind(admin_id)
        .bind(victim_admin_id)
        .bind(member_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("insert member escalation memberships");
        let victim_email = format!("victim-admin-{suffix}@example.test");
        let member_email = format!("plain-member-{suffix}@example.test");
        let admin_email = format!("self-admin-{suffix}@example.test");
        sqlx::query(
            "INSERT INTO user_identities (id, user_id, provider, identifier)
             VALUES ($1, $4, 'email', $7), ($2, $5, 'email', $8), ($3, $6, 'email', $9)",
        )
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(Uuid::new_v4())
        .bind(victim_admin_id)
        .bind(member_id)
        .bind(admin_id)
        .bind(&victim_email)
        .bind(&member_email)
        .bind(&admin_email)
        .execute(&pool)
        .await
        .expect("insert member escalation identities");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        let admin_auth = membership_test_auth(admin_id, org_id, &org_name, Role::Admin);
        let owner_auth = membership_test_auth(owner_id, org_id, &org_name, Role::Owner);

        // Admin cannot promote a plain member to admin (invite path).
        let promote = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: member_email.clone(),
                role: Some("admin".to_string()),
            }),
        )
        .await
        .expect_err("admin must not promote a member to admin");
        assert_eq!(promote.0, StatusCode::FORBIDDEN);

        // Admin cannot remove an existing admin.
        let remove_admin = remove_member(
            admin_auth.clone(),
            State(state.clone()),
            Path((org_name.clone(), victim_admin_id)),
        )
        .await
        .expect_err("admin must not remove another admin");
        assert_eq!(remove_admin.0, StatusCode::FORBIDDEN);

        // Admin cannot demote an existing admin by re-inviting as member.
        let demote = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: victim_email.clone(),
                role: Some("member".to_string()),
            }),
        )
        .await
        .expect_err("admin must not demote another admin");
        assert_eq!(demote.0, StatusCode::FORBIDDEN);
        let victim_role: String = sqlx::query_scalar(
            "SELECT role::text FROM memberships
              WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL",
        )
        .bind(org_id)
        .bind(victim_admin_id)
        .fetch_one(&pool)
        .await
        .expect("victim admin role unchanged after rejected demotion");
        assert_eq!(victim_role, "admin");

        // Admin can still manage plain members (invite as member, remove).
        let invite_member_ok = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: member_email.clone(),
                role: Some("member".to_string()),
            }),
        )
        .await
        .expect("admin can re-invite a plain member as member");
        assert_eq!(invite_member_ok.0, StatusCode::OK);
        let remove_member_ok = remove_member(
            admin_auth.clone(),
            State(state.clone()),
            Path((org_name.clone(), member_id)),
        )
        .await
        .expect("admin can remove a plain member");
        assert_eq!(remove_member_ok, StatusCode::NO_CONTENT);

        // Self-service: the admin cannot re-invite themselves as admin
        // (keeping the privileged role), but CAN demote themselves to
        // member — the self-release exemption.
        let self_keep = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: admin_email.clone(),
                role: Some("admin".to_string()),
            }),
        )
        .await
        .expect_err("admin must not re-grant their own admin role");
        assert_eq!(self_keep.0, StatusCode::FORBIDDEN);
        let self_demote = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: admin_email.clone(),
                role: Some("member".to_string()),
            }),
        )
        .await
        .expect("admin can demote themselves to member");
        assert_eq!(self_demote.0, StatusCode::OK);
        let self_role: String = sqlx::query_scalar(
            "SELECT role::text FROM memberships
              WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL",
        )
        .bind(org_id)
        .bind(admin_id)
        .fetch_one(&pool)
        .await
        .expect("admin role after self-demotion");
        assert_eq!(self_role, "member");

        // After self-demotion the caller is a plain member: the org:admin
        // scope gate now rejects further privileged management attempts.
        let demoted_promote = invite_member(
            admin_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: member_email.clone(),
                role: Some("admin".to_string()),
            }),
        )
        .await
        .expect_err("demoted admin must not promote anyone");
        assert_eq!(demoted_promote.0, StatusCode::FORBIDDEN);

        // Owner can still promote to admin and remove an admin.
        let owner_promote = invite_member(
            owner_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: member_email.clone(),
                role: Some("admin".to_string()),
            }),
        )
        .await
        .expect("owner can promote a member to admin");
        assert_eq!(owner_promote.0, StatusCode::OK);
        let owner_remove = remove_member(
            owner_auth.clone(),
            State(state.clone()),
            Path((org_name.clone(), victim_admin_id)),
        )
        .await
        .expect("owner can remove an admin");
        assert_eq!(owner_remove, StatusCode::NO_CONTENT);

        // The rejected admin mutations must not have altered memberships:
        // the victim admin is only gone because the owner removed them, the
        // plain member is an admin only because the owner promoted them, and
        // the acting admin is a member only because they demoted themselves.
        let roles: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT user_id, role::text FROM memberships
              WHERE org_id = $1 AND removed_at IS NULL ORDER BY user_id",
        )
        .bind(org_id)
        .fetch_all(&pool)
        .await
        .expect("load post-escalation-attempt memberships");
        let role_of = |uid: Uuid| {
            roles
                .iter()
                .find(|(id, _)| *id == uid)
                .map(|(_, role)| role.as_str())
                .unwrap_or("removed")
        };
        assert_eq!(role_of(owner_id), "owner");
        assert_eq!(role_of(admin_id), "member");
        assert_eq!(role_of(victim_admin_id), "removed");
        assert_eq!(role_of(member_id), "admin");

        // Self-removal via DELETE: owner re-promotes the acting admin, then
        // the admin removes themselves without an owner present. The
        // self-release exemption must waive the owner gate (target is caller,
        // requested role None, both reads say admin) and the row must end up
        // removed in the database.
        let owner_repromote = invite_member(
            owner_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(InviteRequest {
                email: admin_email.clone(),
                role: Some("admin".to_string()),
            }),
        )
        .await
        .expect("owner re-promotes admin for self-removal case");
        assert_eq!(owner_repromote.0, StatusCode::OK);
        let self_remove = remove_member(admin_auth, State(state), Path((org_name, admin_id)))
            .await
            .expect("admin can remove themselves without an owner");
        assert_eq!(self_remove, StatusCode::NO_CONTENT);
        let removed_role: Option<String> = sqlx::query_scalar(
            "SELECT role::text FROM memberships
              WHERE org_id = $1 AND user_id = $2 AND removed_at IS NOT NULL",
        )
        .bind(org_id)
        .bind(admin_id)
        .fetch_optional(&pool)
        .await
        .expect("load admin row after self-removal");
        assert!(
            removed_role.is_some(),
            "self-removed admin row must be tombstoned, still active"
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete member escalation org");
        sqlx::query("DELETE FROM users WHERE id IN ($1, $2, $3, $4)")
            .bind(owner_id)
            .bind(admin_id)
            .bind(victim_admin_id)
            .bind(member_id)
            .execute(&pool)
            .await
            .expect("delete member escalation users");
    }
}
