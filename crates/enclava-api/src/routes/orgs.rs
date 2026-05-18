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
    pub tier: String,
    pub is_personal: bool,
}

impl From<Organization> for OrgResponse {
    fn from(o: Organization) -> Self {
        Self {
            id: o.id,
            name: o.name,
            display_name: o.display_name,
            tier: format!("{:?}", o.tier).to_lowercase(),
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

/// GET /orgs -- list user's organizations (excludes personal orgs).
pub async fn list_orgs(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<OrgResponse>>, (StatusCode, Json<serde_json::Value>)> {
    let orgs: Vec<Organization> = sqlx::query_as(
        "SELECT o.* FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1 AND o.is_personal = false AND m.removed_at IS NULL
         ORDER BY o.name",
    )
    .bind(auth.user_id)
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
    let (org_id, caller_role) = active_membership(&state, &auth, &org_name).await?;
    scopes::require_owner_role(caller_role)?;

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

    let signing_key_id: Uuid = sqlx::query_scalar(
        "SELECT id FROM user_signing_keys
         WHERE user_id = $1 AND pubkey = $2 AND revoked_at IS NULL",
    )
    .bind(auth.user_id)
    .bind(&signing_pubkey)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad_request("signing_pubkey is not registered for this user"))?;

    let keyring_payload_bytes = serde_json::to_vec(&body.keyring_payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "serialization error"})),
        )
    })?;

    let latest: Option<(i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT version, keyring_payload, signature
         FROM org_keyrings
         WHERE org_id = $1
         ORDER BY version DESC
         LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    if let Some((latest_version, latest_payload, latest_signature)) = latest {
        if body.version < latest_version {
            return Err(bad_request("keyring version is stale"));
        }
        if body.version == latest_version
            && (latest_payload != keyring_payload_bytes || latest_signature != signature)
        {
            return Err(bad_request(
                "keyring version already exists with different content",
            ));
        }
        if body.version > latest_version + 1 {
            return Err(bad_request("keyring version must increment by one"));
        }
    }

    sqlx::query(
        "INSERT INTO org_keyrings
             (org_id, version, keyring_payload, signature, signing_key_id)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (org_id, version)
         DO UPDATE SET keyring_payload = EXCLUDED.keyring_payload,
                       signature = EXCLUDED.signature,
                       signing_key_id = EXCLUDED.signing_key_id",
    )
    .bind(org_id)
    .bind(body.version)
    .bind(&keyring_payload_bytes)
    .bind(&signature)
    .bind(signing_key_id)
    .execute(&state.db)
    .await
    .map_err(|_| db_error())?;

    let _ = sqlx::query(
        "INSERT INTO audit_log (org_id, user_id, action, detail)
         VALUES ($1, $2, 'org.keyring.put', $3)",
    )
    .bind(org_id)
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "version": body.version,
        "signing_pubkey": body.signing_pubkey,
    }))
    .execute(&state.db)
    .await;

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
    let (org_id, caller_role) = active_membership(&state, &auth, &org_name).await?;
    scopes::require_admin_role(caller_role)?;

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

    scopes::require_owner_to_modify_owner(caller_role, existing_role, Some(requested_role))?;

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
            role: format!("{:?}", role).to_lowercase(),
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

    scopes::require_admin_role(caller_role)?;

    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
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

    scopes::require_owner_to_modify_owner(caller_role, target_role, None)?;

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
