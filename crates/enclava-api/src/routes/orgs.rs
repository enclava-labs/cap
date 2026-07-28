use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_common::canonical::{ce_v1_bytes, ce_v1_hash};
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
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;
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

    let current_role = scopes::active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
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

pub async fn bootstrap_signing_service_owner(
    auth: AuthContext,
    State(state): State<AppState>,
    Path(org_name): Path<String>,
    Json(body): Json<BootstrapSigningServiceRequest>,
) -> Result<Json<BootstrapSigningServiceResponse>, (StatusCode, Json<serde_json::Value>)> {
    scopes::require_scope(&auth, "org:admin")?;
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;
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
        scopes::active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
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

    scopes::require_owner_to_modify_owner(
        current_caller_role,
        existing_role,
        Some(requested_role),
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
        scopes::active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
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

    scopes::require_owner_to_modify_owner(current_caller_role, target_role, None)?;

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
}
