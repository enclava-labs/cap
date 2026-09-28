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

/// keyring payloads are persisted as UTF-8 JSON that PostgreSQL must be able
/// to re-parse as jsonb (migration 0058's shape CHECK, and the candidate
/// selector's cast).  serde_json is stricter than jsonb in exactly one
/// practical way: it accepts `\u0000` escapes that jsonb cannot represent.
/// The writers persist the client-supplied payload verbatim while
/// `SignedOrgKeyring` ignores unknown fields, so an extra field carrying a
/// NUL would pass signature verification and then fail the INSERT with a
/// database error (500).  Reject it as a 400 up front.  (A NUL cannot appear
/// in a signature-verified known field: pubkeys are hex, ids/roles/timestamps
/// are typed, so this scan only ever fires on client-supplied extras.)
fn reject_jsonb_unrepresentable_payload(
    payload: &serde_json::Value,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    fn contains_nul(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(s) => s.contains('\u{0000}'),
            serde_json::Value::Array(items) => items.iter().any(contains_nul),
            serde_json::Value::Object(map) => {
                map.keys().any(|key| key.contains('\u{0000}')) || map.values().any(contains_nul)
            }
            _ => false,
        }
    }
    if contains_nul(payload) {
        return Err(bad_request(
            "keyring_payload contains a \\u0000 escape, which PostgreSQL jsonb \
             cannot represent",
        ));
    }
    Ok(())
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

/// The keyring is already committed, so publication failure must remain
/// retryable without repeating the mutation.
async fn confirm_keyring_kbs_publication(
    state: &AppState,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Err(error) = crate::kbs::confirm_keyring_kbs_publication(state).await {
        tracing::warn!(
            %error,
            error_code = "keyring_policy_reconciliation_pending",
            "keyring committed; KBS policy reconciliation pending"
        );
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "keyring committed; KBS policy reconciliation pending",
                "code": "keyring_policy_reconciliation_pending",
            })),
        ));
    }
    Ok(())
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
    reject_jsonb_unrepresentable_payload(&body.keyring_payload)?;
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
        if body.version == latest_version {
            // Semantic replay check (PR #187 review): the stored payload may
            // carry unsigned extra JSON fields (e.g. a client's "memo") that
            // a typed rebuild drops before resubmitting.  The signature is
            // over the canonical keyring bytes, so comparing those (plus the
            // signature and signing key) instead of raw payload bytes keeps
            // an exact-version replay idempotent for semantically identical
            // payloads while still rejecting any genuinely different
            // content.  A stored payload that no longer parses fails closed
            // as a conflict.
            let latest_keyring: SignedOrgKeyring = serde_json::from_slice(&latest_payload)
                .map_err(|_| {
                    (
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "keyring version already exists with different content"
                        })),
                    )
                })?;
            if latest_signature != signature
                || latest_signing_pubkey != signing_pubkey
                || canonical_keyring_bytes(&latest_keyring) != canonical_bytes
            {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "keyring version already exists with different content"
                    })),
                ));
            }
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
        // A new keyring generation can revoke the signer of retained signed
        // policy artifacts; the owed generation bump is deferred to
        // migration 0058's INSERT trigger (durable selector debt) and
        // consumed only after the filtered policy body is published, never
        // bumped directly here.
    }

    tx.commit().await.map_err(|_| db_error())?;
    confirm_keyring_kbs_publication(&state).await?;

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

async fn ready_service_owner(
    state: &AppState,
    org_id: Uuid,
) -> Result<
    (
        &crate::signing_service::SigningServiceClient,
        Option<Vec<u8>>,
    ),
    (StatusCode, Json<serde_json::Value>),
> {
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
    Ok((signing_service, service_owner))
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
    reject_jsonb_unrepresentable_payload(&body.keyring_payload)?;

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
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    crate::signing_service::lock_org_signing_authority_lane(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;

    type AuthorityRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>);
    let latest: AuthorityRow = sqlx::query_as(
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
        // Exact replay of an already-committed rotation; the predecessor row
        // may legitimately be gone (pruned by migration 0058's repair pass),
        // so the committed authority alone must confirm it.
        let previous: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT ok.keyring_payload, usk.pubkey
                   FROM org_keyrings ok
                   JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
                  WHERE ok.org_id = $1 AND ok.version = $2",
        )
        .bind(org_id)
        .bind(body.version - 1)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?;
        let Some(previous) = previous else {
            // The pruned predecessor was already validated at commit time;
            // confirm replay against the live signing-service authority
            // without rotating again.
            let (_, service_owner) = ready_service_owner(&state, org_id).await?;
            if service_owner.as_deref() != Some(replacement_owner.as_slice()) {
                return Err(crate::routes::deployments::signing_error_response(
                    crate::signing_service::SigningServiceError::AuthorityStatus(
                        "signing service owner does not match the requested replacement owner"
                            .to_string(),
                    ),
                ));
            }
            // The replay is read-only: release the org signing-authority
            // lane before claiming the global KBS fence for publication.
            tx.rollback().await.map_err(|_| db_error())?;
            confirm_keyring_kbs_publication(&state).await?;
            return Ok(Json(RotateOrgOwnerResponse {
                org_id,
                state: "ready",
                keyring_version: body.version,
                owner_fingerprint: hex::encode(Sha256::digest(replacement_owner)),
            }));
        };
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
    let (signing_service, service_owner) = ready_service_owner(&state, org_id).await?;
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
        // As with put_keyring, the owed selector bump is deferred to
        // migration 0058's INSERT trigger and published only after the
        // filtered policy body is live, never bumped directly here.
    }
    tx.commit().await.map_err(|_| db_error())?;
    confirm_keyring_kbs_publication(&state).await?;

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
    use crate::test_support::{drop_isolated_database, isolated_database_test_pool};
    use chrono::{TimeZone, Utc};
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

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

    async fn keyring_enqueue_guard() -> tokio::sync::MutexGuard<'static, ()> {
        crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
            .lock()
            .await
    }

    fn test_kbs_policy_config() -> crate::kbs::KbsPolicyConfig {
        crate::kbs::KbsPolicyConfig {
            namespace: "kbs-test".to_string(),
            configmap_name: "resource-policy".to_string(),
            policy_key: "policy.rego".to_string(),
            deployment_name: "trustee".to_string(),
            required: true,
            signed_policy_retention: 6,
            signed_policy_max_bytes: 900 * 1024,
        }
    }

    /// Stateful Kubernetes API double behind the fenced KBS reconciler: it
    /// stores the resource-policy ConfigMap and the Trustee deployment the
    /// way the API server would, so route regressions observe real
    /// publication (ConfigMap replace plus rollout confirmation) instead of
    /// a fabricated success.  `healthy = false` makes provider I/O fail.
    struct KbsPolicyProvider {
        healthy: bool,
        configmap: serde_json::Value,
        deployment: serde_json::Value,
        configmap_replaces: usize,
    }

    impl KbsPolicyProvider {
        fn new(healthy: bool) -> Self {
            Self {
                healthy,
                configmap: serde_json::json!({
                    "apiVersion": "v1",
                    "kind": "ConfigMap",
                    "metadata": {
                        "name": "resource-policy",
                        "namespace": "kbs-test",
                        "resourceVersion": "1",
                    },
                    "data": {
                        "policy.rego": "package policy\n\n# legacy unsigned policy\n",
                    },
                }),
                deployment: serde_json::json!({
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "name": "trustee",
                        "namespace": "kbs-test",
                        "resourceVersion": "1",
                        "generation": 1,
                    },
                    "spec": {
                        "replicas": 1,
                        "template": {
                            "metadata": {},
                            "spec": {
                                "containers": [{"name": "trustee", "image": "trustee"}],
                            },
                        },
                    },
                    "status": {
                        "observedGeneration": 1_000_000,
                        "replicas": 1,
                        "updatedReplicas": 1,
                        "readyReplicas": 1,
                        "availableReplicas": 1,
                    },
                }),
                configmap_replaces: 0,
            }
        }

        fn published_generation(&self) -> Option<i64> {
            self.configmap["metadata"]["annotations"]
                .as_object()?
                .get("enclava.dev/cap-policy-generation")?
                .as_str()?
                .parse()
                .ok()
        }
    }

    fn kbs_policy_kube_client(
        provider: std::sync::Arc<tokio::sync::Mutex<KbsPolicyProvider>>,
    ) -> kube::Client {
        use axum::http::{Request, Response};
        use http_body_util::BodyExt;
        use kube::client::Body;
        use tower::service_fn;

        fn respond(
            status: u16,
            value: &serde_json::Value,
        ) -> Result<Response<Body>, std::io::Error> {
            Ok(Response::builder()
                .status(status)
                .body(Body::from(
                    serde_json::to_vec(value).expect("serialize kube double response"),
                ))
                .expect("build kube double response"))
        }

        kube::Client::new(
            service_fn(move |request: Request<Body>| {
                let provider = provider.clone();
                async move {
                    let method = request.method().as_str().to_string();
                    let path = request.uri().path().to_string();
                    let body = request
                        .into_body()
                        .collect()
                        .await
                        .expect("read Kubernetes request body")
                        .to_bytes();
                    let mut provider = provider.lock().await;
                    let mut object: serde_json::Value = if method == "PUT" {
                        serde_json::from_slice(&body)
                            .expect("kube double PUT requests carry a JSON body")
                    } else {
                        serde_json::json!({})
                    };
                    if !provider.healthy
                        || (method != "GET" && method != "PUT")
                        || (!path.contains("/configmaps/") && !path.contains("/deployments/"))
                    {
                        return respond(
                            404,
                            &serde_json::json!({
                                "apiVersion": "v1", "kind": "Status", "status": "Failure",
                                "reason": "NotFound", "message": "unavailable", "code": 404,
                            }),
                        );
                    }
                    if path.contains("/configmaps/") {
                        if method == "PUT" {
                            provider.configmap_replaces += 1;
                            if let Some(metadata) =
                                object.get_mut("metadata").and_then(|m| m.as_object_mut())
                            {
                                metadata.insert(
                                    "resourceVersion".to_string(),
                                    serde_json::json!(
                                        (provider.configmap_replaces + 1).to_string()
                                    ),
                                );
                            }
                            provider.configmap = object;
                        }
                        return respond(200, &provider.configmap);
                    }
                    if method == "PUT" {
                        provider.deployment = object;
                    }
                    respond(200, &provider.deployment)
                }
            }),
            "default",
        )
    }

    #[tokio::test]
    async fn put_keyring_reports_success_only_after_kbs_publication() {
        let _singleton = keyring_enqueue_guard().await;
        let (_db_cleanup, pool) = isolated_database_test_pool("cap130_keyring_enqueue_put").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-enqueue-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring enqueue org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Keyring Enqueuer')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert keyring enqueue user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert keyring enqueue membership");
        let key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert keyring enqueue signing key");

        // Active signed mode, seeded at a nonzero desired generation: the
        // keyring insert must owe exactly one selector bump through
        // migration 0058's trigger (never a direct desired_generation bump),
        // and the route must not report success until the owed generation is
        // live in the KBS.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .expect("seed signed-policy generation");

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

        // Active signed mode without KBS configuration fails closed; the
        // committed mutation stays durable exactly once.
        let misconfigured = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        )
        .await
        .expect_err("active signed mode without KBS configuration must fail closed");
        assert_eq!(misconfigured.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            misconfigured.1.0["error"],
            "keyring committed; KBS policy reconciliation pending"
        );
        assert_eq!(
            misconfigured.1.0["code"],
            "keyring_policy_reconciliation_pending"
        );

        // Configure the KBS against a failing provider: publication cannot
        // be confirmed, so the route still must not report success.
        state.kbs_policy = Some(test_kbs_policy_config());
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(false)));
        crate::kbs::TEST_KUBE_CLIENT.scope(kbs_policy_kube_client(provider.clone()), async {
        let blocked = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        )
        .await
        .expect_err("blocked publication must not report success");
        assert_eq!(blocked.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            blocked.1.0["code"],
            "keyring_policy_reconciliation_pending"
        );
        let authority: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put'),
                 (SELECT desired_generation FROM kbs_signed_policy_reconciliation
                   WHERE singleton),
                 (SELECT selector_bumps_owed FROM kbs_signed_policy_reconciliation
                   WHERE singleton)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("read durable keyring authority after blocked publication");
        assert_eq!(
            authority, (1, 1, 5, 1),
            "the committed keyring, audit row, and owed selector bump must remain exactly once"
        );

        // Healthy provider: exact replay retries publication without another
        // keyring version or audit row, and succeeds only once the filtered
        // policy set is live.
        {
            let mut provider = provider.lock().await;
            provider.healthy = true;
        }
        // Failed provider calls retain their fence until its reclaim deadline.
        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE resource_scope = 'kbs_policy' AND resource_key = 'global'",
        )
        .execute(&pool)
        .await
        .expect("expire failed publication fence");
        let published = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        )
        .await
        .expect("replay must succeed once publication is confirmed");
        assert_eq!(published.1.0.version, 1);
        {
            let provider = provider.lock().await;
            assert_eq!(
                provider.published_generation(),
                Some(6),
                "the owed generation must be live before success is reported"
            );
            assert_eq!(provider.configmap_replaces, 1);
        }
        let reconciled: (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put'),
                 (SELECT desired_generation FROM kbs_signed_policy_reconciliation
                   WHERE singleton),
                 (SELECT selector_bumps_owed FROM kbs_signed_policy_reconciliation
                   WHERE singleton)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("read durable keyring authority after publication");
        assert_eq!(
            reconciled, (1, 1, 6, 0),
            "the debt must be consumed exactly once, never re-owed by replay"
        );
        let applied: i64 = sqlx::query_scalar(
            "SELECT applied_generation FROM kbs_signed_policy_reconciliation
              WHERE singleton",
        )
        .fetch_one(&pool)
        .await
        .expect("read applied generation after publication");
        assert_eq!(applied, 6, "publication must be observed before success");

        // Once current, replay stays idempotent: no re-publication churn.
        let replayed = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
        )
        .await
        .expect("idempotent replay succeeds while publication is current");
        assert_eq!(replayed.1.0.version, 1);
        {
            let provider = provider.lock().await;
            assert_eq!(
                provider.configmap_replaces, 1,
                "a current publication must not be replaced again"
            );
        }

        }).await;
        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete keyring enqueue audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete keyring enqueue org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete keyring enqueue user");
        drop_isolated_database("cap130_keyring_enqueue_put", pool).await;
    }

    /// Review follow-up: a `\u0000` escape in an unknown field passes
    /// SignedOrgKeyring deserialization (unknown fields ignored) and would be
    /// persisted verbatim, but jsonb cannot represent it -- the INSERT would
    /// surface as a database error (500) once migration 0058's CHECK exists.
    /// The handler must reject it as a 400 before any signature work, and
    /// must never leave a row behind.
    #[tokio::test]
    async fn put_keyring_rejects_jsonb_unrepresentable_payload() {
        let mut request = signed_keyring_request(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &SigningKey::from_bytes(&[7u8; 32]),
            1,
            0,
        );
        if let serde_json::Value::Object(map) = &mut request.keyring_payload {
            map.insert(
                "memo".to_string(),
                serde_json::Value::String("bad \u{0} nul".to_string()),
            );
        } else {
            panic!("signed_keyring_request payload must be an object");
        }
        let err = reject_jsonb_unrepresentable_payload(&request.keyring_payload)
            .expect_err("NUL escape in an extra field must be rejected");
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // Nested positions must be caught too, and clean payloads pass.
        let mut nested = serde_json::json!({"outer": ["fine", "x\u{0}y"]});
        if let serde_json::Value::Object(map) = &mut nested {
            map.insert(
                "org_id".into(),
                serde_json::Value::String(Uuid::new_v4().to_string()),
            );
        }
        assert!(reject_jsonb_unrepresentable_payload(&nested).is_err());
        // A NUL inside an object KEY must be caught too (self-review C1):
        // serde_json parses it, serde_json::to_vec round-trips it verbatim,
        // and jsonb rejects it just like a NUL in a value.
        let mut nul_key = serde_json::Map::new();
        nul_key.insert(
            "a\u{0}b".to_string(),
            serde_json::Value::String("value is fine".to_string()),
        );
        assert!(reject_jsonb_unrepresentable_payload(&serde_json::Value::Object(nul_key)).is_err());
        assert!(
            reject_jsonb_unrepresentable_payload(&serde_json::json!({
                "org_id": Uuid::new_v4(),
                "members": [],
                "memo": "no nul here"
            }))
            .is_ok()
        );
    }

    #[tokio::test]
    async fn rotate_owner_reports_success_only_after_kbs_publication() {
        let _singleton = keyring_enqueue_guard().await;
        let (_db_cleanup, pool) =
            isolated_database_test_pool("cap130_keyring_enqueue_rotate").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-rotate-enqueue-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert rotate enqueue org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Rotate Enqueuer')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert rotate enqueue user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert rotate enqueue membership");
        let key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        // Both the current and the replacement owner keys must be registered
        // for the rotating user: the handler resolves signing_key_id from
        // user_signing_keys inside the lane-locked transaction.
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert rotate enqueue signing keys");

        // Active signed mode: every committed keyring insert (the v1 put
        // and the rotation v2) must owe exactly one selector bump through
        // migration 0058's trigger, and the route must not report success
        // until the owed generation is live in the KBS.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .expect("seed signed-policy generation");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.kbs_policy = Some(test_kbs_policy_config());
        let provider = std::sync::Arc::new(tokio::sync::Mutex::new(KbsPolicyProvider::new(true)));
        crate::kbs::TEST_KUBE_CLIENT
            .scope(kbs_policy_kube_client(provider.clone()), async {
                let auth = AuthContext {
                    user_id,
                    org_id,
                    org_name: org_name.clone(),
                    role: Role::Owner,
                    api_key: None,
                    management_origin: crate::auth::middleware::ManagementOrigin::Public,
                };

                // Publish v1 as the current owner; its owed selector bump must be
                // published before the route reports success.
                let _ = put_keyring(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(signed_keyring_request(org_id, user_id, &key, 1, 1)),
                )
                .await
                .expect("seed keyring v1");
                let (desired, owed, applied): (i64, i64, i64) = sqlx::query_as(
                    "SELECT desired_generation, selector_bumps_owed, applied_generation
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
                )
                .fetch_one(&pool)
                .await
                .expect("read reconciliation state after v1 publication");
                assert_eq!((desired, owed, applied), (6, 0, 6));

                // The signing service owner already matches the replacement key, so
                // the handler takes the no-remote-rotation branch and commits the
                // keyring v2 insert (and its trigger-owed selector bump) locally.
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind signing service mock");
                let address = listener.local_addr().expect("mock signing service address");
                let replacement_hex = hex::encode(replacement_key.verifying_key().to_bytes());
                let org_id_for_mock = org_id;
                let owner_status_response =
                    std::sync::Arc::new(std::sync::Mutex::new(serde_json::json!({
                        "org_id": org_id_for_mock,
                        "state": "ready",
                        "version": 2,
                        "owner_pubkey_hex": replacement_hex.clone(),
                        "last_changed_at": null,
                    })));
                let rotate_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let status_for_mock = owner_status_response.clone();
                let rotate_calls_for_mock = rotate_calls.clone();
                let mock = tokio::spawn(async move {
                    use axum::{
                        Json,
                        routing::{get, post},
                    };
                    let app = axum::Router::new()
                        .route(
                            "/orgs/{org_id}/owner",
                            get(move || {
                                let body = status_for_mock
                                    .lock()
                                    .expect("owner status mock lock")
                                    .clone();
                                async move { Json(body) }
                            }),
                        )
                        .route(
                            "/rotate-owner",
                            post(move || {
                                let calls = rotate_calls_for_mock.clone();
                                let rotated_org_id = org_id_for_mock;
                                let fingerprint = replacement_hex.clone();
                                async move {
                                    calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    Json(serde_json::json!({
                                        "org_id": rotated_org_id,
                                        "version": 2,
                                        "owner_pubkey_fingerprint": fingerprint,
                                        "rotated_at": "2026-01-01T00:00:00Z",
                                    }))
                                }
                            }),
                        );
                    axum::serve(listener, app).await.expect("serve mock");
                });
                state.signing_service = Some(
                    crate::signing_service::SigningServiceClient::new(
                        format!("http://{address}"),
                        None,
                    )
                    .expect("mock signing service client"),
                );

                let added_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
                let updated_at = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 30).unwrap();
                let replacement_pubkey = replacement_key.verifying_key().to_bytes();
                let keyring = SignedOrgKeyring {
                    org_id,
                    version: 2,
                    members: vec![SignedOrgKeyringMember {
                        user_id,
                        pubkey: replacement_pubkey,
                        role: SignedOrgKeyringRole::Owner,
                        added_at,
                    }],
                    updated_at,
                };
                let keyring_payload = serde_json::json!({
                    "org_id": org_id,
                    "version": 2,
                    "members": [{
                        "user_id": user_id,
                        "pubkey": hex::encode(replacement_pubkey),
                        "role": "owner",
                        "added_at": added_at,
                    }],
                    "updated_at": updated_at,
                });
                let keyring_signature = replacement_key.sign(&canonical_keyring_bytes(&keyring));
                let signed_at = Utc::now();
                let reason = "owner key compromised";
                let directive = owner_rotation_directive_bytes(
                    org_id,
                    &key.verifying_key().to_bytes(),
                    &replacement_pubkey,
                    signed_at,
                    reason,
                );
                let rotation_signature = key.sign(&directive);
                let rotation_request = RotateOrgOwnerRequest {
                    version: 2,
                    keyring_payload: keyring_payload.clone(),
                    signature: hex::encode(keyring_signature.to_bytes()),
                    replacement_signing_pubkey: hex::encode(replacement_pubkey),
                    current_signing_pubkey: hex::encode(key.verifying_key().to_bytes()),
                    signed_at,
                    reason: reason.to_string(),
                    rotation_signature: hex::encode(rotation_signature.to_bytes()),
                };
                let rotated = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect("owner rotation must confirm KBS publication");

                // The rotation consumed the v2 insert's owed selector bump exactly
                // once and never bumped desired_generation directly.
                let (desired, owed, applied): (i64, i64, i64) = sqlx::query_as(
                    "SELECT desired_generation, selector_bumps_owed, applied_generation
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
                )
                .fetch_one(&pool)
                .await
                .expect("read reconciliation state after rotation");
                assert_eq!(
                    (desired, owed, applied),
                    (7, 0, 7),
                    "the v1 and v2 selector bumps must be consumed exactly once each"
                );
                let latest_version: i64 =
                    sqlx::query_scalar("SELECT max(version) FROM org_keyrings WHERE org_id = $1")
                        .bind(org_id)
                        .fetch_one(&pool)
                        .await
                        .expect("read latest keyring version");
                assert_eq!(latest_version, 2);
                assert_eq!(rotated.0.state, "ready");
                {
                    let provider = provider.lock().await;
                    assert_eq!(
                        provider.published_generation(),
                        Some(7),
                        "the rotated generation must be live before success is reported"
                    );
                }

                // The v1 predecessor row can be pruned by migration 0058's repair
                // pass while the committed v2 rotation stays intact.  Replaying the
                // identical request after that prune must still confirm the
                // rotation, not fail with "previous keyring authority is
                // unavailable".
                sqlx::query("DELETE FROM org_keyrings WHERE org_id = $1 AND version = 1")
                    .bind(org_id)
                    .execute(&pool)
                    .await
                    .expect("prune predecessor keyring row");
                let replayed = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect("replay after predecessor prune must confirm the rotation");
                assert_eq!(replayed.0.state, "ready");
                assert_eq!(replayed.0.keyring_version, 2);
                let versions_after_replay: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM org_keyrings WHERE org_id = $1")
                        .bind(org_id)
                        .fetch_one(&pool)
                        .await
                        .expect("count keyring rows after replay");
                assert_eq!(
                    versions_after_replay, 1,
                    "replay must not insert a duplicate row"
                );

                *owner_status_response
                    .lock()
                    .expect("owner status mock lock") = serde_json::json!({
                    "org_id": org_id,
                    "state": "ready",
                    "version": 2,
                    "owner_pubkey_hex": hex::encode(key.verifying_key().to_bytes()),
                    "last_changed_at": null,
                });
                let drifted = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect_err("pruned replay must fail when the service reports a different owner");
                assert_eq!(drifted.0, StatusCode::BAD_GATEWAY);
                assert_eq!(drifted.1.0["error"], "signing_authority_status_invalid");

                *owner_status_response
                    .lock()
                    .expect("owner status mock lock") = serde_json::json!({
                    "org_id": org_id,
                    "state": "pending",
                    "version": 2,
                    "owner_pubkey_hex": hex::encode(replacement_key.verifying_key().to_bytes()),
                    "last_changed_at": null,
                });
                let not_ready = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect_err("pruned replay must fail when the service is not ready");
                assert_eq!(not_ready.0, StatusCode::BAD_GATEWAY);
                assert_eq!(not_ready.1.0["error"], "signing_authority_status_invalid");

                let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind dead signing service address");
                let dead_address = dead.local_addr().expect("dead signing service address");
                drop(dead);
                state.signing_service = Some(
                    crate::signing_service::SigningServiceClient::new(
                        format!("http://{dead_address}"),
                        None,
                    )
                    .expect("dead signing service client"),
                );
                let unavailable = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect_err("pruned replay must fail when the signing service is unreachable");
                assert_eq!(unavailable.0, StatusCode::BAD_GATEWAY);
                assert_eq!(unavailable.1.0["error"], "signing_service_unavailable");

                // Replay still requires KBS reconciliation: with the signing
                // service healthy again but publication blocked, the replay must
                // defer instead of reporting success.
                state.signing_service = Some(
                    crate::signing_service::SigningServiceClient::new(
                        format!("http://{address}"),
                        None,
                    )
                    .expect("mock signing service client"),
                );
                *owner_status_response
                    .lock()
                    .expect("owner status mock lock") = serde_json::json!({
                    "org_id": org_id,
                    "state": "ready",
                    "version": 2,
                    "owner_pubkey_hex": hex::encode(replacement_key.verifying_key().to_bytes()),
                    "last_changed_at": null,
                });
                {
                    let mut provider = provider.lock().await;
                    provider.healthy = false;
                }
                let pending = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect_err("replay must not report success while publication is blocked");
                assert_eq!(pending.0, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(pending.1.0["code"], "keyring_policy_reconciliation_pending");
                let (desired, owed, applied): (i64, i64, i64) = sqlx::query_as(
                    "SELECT desired_generation, selector_bumps_owed, applied_generation
               FROM kbs_signed_policy_reconciliation
              WHERE singleton",
                )
                .fetch_one(&pool)
                .await
                .expect("read reconciliation state after blocked replay");
                assert_eq!(
                    (desired, owed, applied),
                    (7, 0, 7),
                    "a blocked replay must not churn the durable rotation state"
                );
                {
                    let mut provider = provider.lock().await;
                    provider.healthy = true;
                }
                sqlx::query(
                    "UPDATE external_resource_mutation_leases
                SET locked_until = clock_timestamp() - interval '2 seconds',
                    reclaim_after = clock_timestamp() - interval '1 second'
              WHERE resource_scope = 'kbs_policy' AND resource_key = 'global'",
                )
                .execute(&pool)
                .await
                .expect("expire failed publication fence");
                let recovered = rotate_org_owner(
                    auth.clone(),
                    State(state.clone()),
                    Path(org_name.clone()),
                    Json(rotation_request.clone()),
                )
                .await
                .expect("replay must confirm the rotation once publication recovers");
                assert_eq!(recovered.0.state, "ready");
                assert_eq!(recovered.0.keyring_version, 2);

                assert_eq!(
                    rotate_calls.load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "pruned replays must never re-drive the signing service rotation"
                );
                let rotate_audit_rows: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'",
                )
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("count owner-rotation audit rows after replays");
                assert_eq!(rotate_audit_rows, 1);
                let versions_after_failures: i64 =
                    sqlx::query_scalar("SELECT count(*) FROM org_keyrings WHERE org_id = $1")
                        .bind(org_id)
                        .fetch_one(&pool)
                        .await
                        .expect("count keyring rows after failed replays");
                assert_eq!(versions_after_failures, 1);

                mock.abort();
            })
            .await;
        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete rotate enqueue audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete rotate enqueue org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete rotate enqueue user");
        drop_isolated_database("cap130_keyring_enqueue_rotate", pool).await;
    }

    #[tokio::test]
    async fn put_keyring_replay_ignores_unsigned_extra_payload_fields() {
        // PR #187 review: a client (e.g. the CLI's owner-recovery retry)
        // fetches a committed keyring, rebuilds it through the typed
        // envelope -- dropping unsigned extra JSON fields like "memo" --
        // and PUTs the same version back. The replay must be idempotent:
        // the signature is over the canonical keyring bytes, so comparing
        // those instead of raw payload bytes accepts the semantically
        // identical payload while still rejecting genuinely different
        // content. Unsigned-only mode keeps KBS publication out of scope.
        let (_db_cleanup, pool) = isolated_database_test_pool("cap187_keyring_replay_extra").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-replay-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring replay org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Keyring Replayer')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert keyring replay user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert keyring replay membership");
        let key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert keyring replay signing key");

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

        // Initial put carries an unsigned extra field the typed keyring
        // does not know about.
        let mut request = signed_keyring_request(org_id, user_id, &key, 1, 1);
        request
            .keyring_payload
            .as_object_mut()
            .expect("keyring payload is an object")
            .insert("memo".to_string(), serde_json::json!("rotation"));
        let created = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(request),
        )
        .await
        .expect("initial put with an extra field must succeed");
        assert_eq!(created.1.version, 1);

        // The CLI-style replay drops the extra field before resubmitting
        // the same version: semantically identical, so idempotent.
        let stripped = signed_keyring_request(org_id, user_id, &key, 1, 1);
        let replayed = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(stripped),
        )
        .await
        .expect("typed rebuild replay of the same version must be idempotent");
        assert_eq!(replayed.1.version, 1);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM org_keyrings WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("count keyring rows after replay");
        assert_eq!(rows, 1, "the replay must not insert a duplicate row");

        // Genuinely different content at the same version still conflicts:
        // a different updated_at changes the canonical bytes, and this
        // payload carries its own valid signature over those bytes.
        let conflicting = signed_keyring_request(org_id, user_id, &key, 1, 2);
        let rejected = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(conflicting),
        )
        .await
        .expect_err("same-version replay with different canonical content must conflict");
        assert_eq!(rejected.0, StatusCode::CONFLICT);

        drop_isolated_database("cap187_keyring_replay_extra", pool).await;
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
        // Holds the singleton lock: this test's committed put_keyring calls
        // bump the shared signed-policy generation whenever it is nonzero,
        // which would corrupt concurrent tests asserting exact values.
        let _singleton = keyring_enqueue_guard().await;
        let pool = database_test_pool().await;
        // Run as an unsigned install: this test asserts keyring authority,
        // not KBS publication, and the shared database's singleton row must
        // stay out of active signed mode for the whole flow.
        sqlx::query(
            "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 0,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
        )
        .execute(&pool)
        .await
        .expect("reset shared signed-policy singleton to unsigned mode");
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
