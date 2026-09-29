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

#[derive(Debug, Deserialize, Serialize)]
struct SignedOrgKeyring {
    org_id: Uuid,
    version: u64,
    members: Vec<SignedOrgKeyringMember>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize, Serialize)]
struct SignedOrgKeyringMember {
    user_id: Uuid,
    #[serde(
        deserialize_with = "deserialize_pubkey",
        serialize_with = "serialize_pubkey"
    )]
    pubkey: [u8; 32],
    role: SignedOrgKeyringRole,
    added_at: DateTime<Utc>,
}

fn serialize_pubkey<S: serde::Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(b))
}

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
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
        Json(serde_json::json!({ "error": "database error" })),
    )
}

// Legacy rows can differ in unsigned fields while carrying identical signed content.
fn keyring_replay_conflicts(
    stored_payload: &[u8],
    stored_signature: &[u8],
    stored_signing_pubkey: &[u8],
    canonical_bytes: &[u8],
    signature: &[u8],
    signing_pubkey: &[u8],
) -> bool {
    let Ok(stored_keyring) = serde_json::from_slice::<SignedOrgKeyring>(stored_payload) else {
        return true;
    };
    canonical_keyring_bytes(&stored_keyring).as_slice() != canonical_bytes
        || stored_signature != signature
        || stored_signing_pubkey != signing_pubkey
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

    // Store the normalized typed keyring (dropping unsigned extra fields)
    // with the same encoding rotate_org_owner uses, so replay equality is
    // canonical on both paths.
    let normalized_keyring_payload = serde_json::to_value(&keyring).map_err(|_| db_error())?;
    let keyring_payload_bytes = serde_json::to_vec(&normalized_keyring_payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "serialization error"})),
        )
    })?;
    // #128 review follow-up (P1): reject keyrings whose CLI envelope would
    // exceed the deploy-time org_keyring_blob cap, so accepted authority
    // stays deployable instead of failing every signed deployment at
    // decode_optional_blobs.
    crate::signing_service::validate_org_keyring_registration_budget(
        keyring_payload_bytes.len(),
        &signature,
        &signing_pubkey,
    )
    .map_err(crate::routes::deployments::signing_error_response)?;

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
            && keyring_replay_conflicts(
                &latest_payload,
                &latest_signature,
                &latest_signing_pubkey,
                &canonical_bytes,
                &signature,
                &signing_pubkey,
            )
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
            fence_successor_keyring_version(&state, &mut tx, org_id, &latest_signing_pubkey)
                .await?;
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
            keyring_payload: normalized_keyring_payload,
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
    let keyring: SignedOrgKeyring =
        serde_json::from_slice(&payload_bytes).map_err(|_| db_error())?;
    let fingerprint = hex::encode(Sha256::digest(canonical_keyring_bytes(&keyring)));
    // Legacy unsigned extensions must not leak into strict deployment envelopes.
    let normalized_keyring_payload = serde_json::to_value(&keyring).map_err(|_| db_error())?;
    Ok(Json(OrgKeyringResponse {
        org_id,
        version,
        keyring_payload: normalized_keyring_payload,
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

type RotationAuthorityRow = (i64, Vec<u8>, Vec<u8>, Vec<u8>, DateTime<Utc>);

/// Latest keyring version plus the signed_at floor for the directive
/// version-recency bound. Pre-0054 rows keep legacy transaction-start
/// created_at semantics, so their stored timestamp is floored at the
/// watermark recorded when 0054 committed.
async fn read_rotation_authority(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
) -> Result<(RotationAuthorityRow, DateTime<Utc>), (StatusCode, Json<serde_json::Value>)> {
    let latest: RotationAuthorityRow = sqlx::query_as(
        "SELECT ok.version, ok.keyring_payload, ok.signature, usk.pubkey, ok.created_at
           FROM org_keyrings ok
           JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
          WHERE ok.org_id = $1
          ORDER BY ok.version DESC
          LIMIT 1",
    )
    .bind(org_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| db_error())?
    .ok_or_else(|| bad_request("org keyring must be uploaded before owner rotation"))?;
    let created_at_watermark: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT watermarked_at FROM org_keyrings_created_at_watermark")
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| db_error())?;
    let version_created_at_floor = created_at_watermark.unwrap_or(latest.4).max(latest.4);
    Ok((latest, version_created_at_floor))
}

/// A matching committed version may outlive its pruned predecessor.
/// None permits only read-only replay after confirming the live replacement owner.
async fn derive_rotation_path(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    body_version: i64,
    latest: RotationAuthorityRow,
    canonical_bytes: &[u8],
    keyring_signature: &[u8; 64],
    replacement_owner: &[u8; 32],
) -> Result<Option<(Vec<u8>, Vec<u8>, bool)>, (StatusCode, Json<serde_json::Value>)> {
    if body_version == latest.0 {
        if keyring_replay_conflicts(
            &latest.1,
            &latest.2,
            &latest.3,
            canonical_bytes,
            keyring_signature,
            replacement_owner,
        ) {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "keyring version already exists with different content"
                })),
            ));
        }
        let previous: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
            "SELECT ok.keyring_payload, usk.pubkey
               FROM org_keyrings ok
               JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
              WHERE ok.org_id = $1 AND ok.version = $2",
        )
        .bind(org_id)
        .bind(body_version - 1)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| db_error())?;
        Ok(previous.map(|(payload, owner)| (payload, owner, false)))
    } else if latest
        .0
        .checked_add(1)
        .is_some_and(|successor| body_version == successor)
    {
        Ok(Some((latest.1, latest.3, true)))
    } else if body_version < latest.0 {
        Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "keyring version is stale"})),
        ))
    } else {
        Err(bad_request("keyring version must increment by one"))
    }
}

fn service_owner_pubkey(
    owner_status: &crate::signing_service::OwnerStatusResponse,
) -> Option<Vec<u8>> {
    owner_status
        .owner_pubkey_hex
        .as_deref()
        .and_then(|raw| hex::decode(raw).ok())
}

/// Read the signing-service owner strictly after the signing-authority
/// lane is acquired: queue time behind other lane writers can outlast any
/// freshness window, so a pre-lane snapshot is stale for every decision
/// that follows.
async fn read_live_service_owner(
    signing_service: &crate::signing_service::SigningServiceClient,
    org_id: Uuid,
) -> Result<crate::signing_service::OwnerStatusResponse, (StatusCode, Json<serde_json::Value>)> {
    let owner_status = signing_service
        .owner_status(org_id)
        .await
        .map_err(crate::routes::deployments::signing_error_response)?;

    if owner_status.org_id != org_id || owner_status.state != "ready" {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "owner status does not match requested authority".to_string(),
            ),
        ));
    }
    Ok(owner_status)
}

/// A prior rotation may have changed upstream authority without a CAP commit.
/// Missing or unreadable authority cannot make its successor version available
/// to the old pinned owner.
async fn fence_successor_keyring_version(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    pinned_owner: &[u8],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let Some(signing_service) = state.signing_service.as_ref() else {
        let rotation_history: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM org_rotation_intents WHERE org_id = $1 LIMIT 1")
                .bind(org_id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|_| db_error())?;
        if rotation_history.is_some() {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "platform signing service is not configured"
                })),
            ));
        }
        return Ok(());
    };
    let owner_status = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        signing_service.owner_status(org_id),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "signing_service_unavailable"})),
        )
    })?
    .map_err(crate::routes::deployments::signing_error_response)?;
    let state_consistent = matches!(
        (
            owner_status.state.as_str(),
            owner_status.owner_pubkey_hex.as_ref()
        ),
        ("not_configured", None) | ("ready", Some(_))
    );
    if owner_status.org_id != org_id || !state_consistent {
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
    if service_owner.is_some_and(|owner| owner.as_slice() != pinned_owner) {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "signing service owner does not match the current pinned owner (owner rotation in progress)"
            })),
        ));
    }
    Ok(())
}

/// Validate a rotate-owner response before it can mint a receipt: it must
/// be for this org, pin the raw replacement pubkey (the "fingerprint"
/// field is hex(raw pubkey) by cross-repo contract, not a digest), and
/// carry a positive version representable in the receipt's bigint column.
fn validated_rotate_owner_response(
    rotated: &crate::signing_service::RotateOwnerResponse,
    org_id: Uuid,
    replacement_owner: &[u8; 32],
) -> Result<i64, (StatusCode, Json<serde_json::Value>)> {
    if rotated.org_id != org_id
        || rotated.owner_pubkey_fingerprint != hex::encode(replacement_owner)
    {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "owner rotation response does not match requested authority".to_string(),
            ),
        ));
    }
    if rotated.version == 0 || rotated.version > i64::MAX as u64 {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "owner rotation response version is not representable".to_string(),
            ),
        ));
    }
    Ok(rotated.version as i64)
}

async fn rotate_service_owner(
    signing_service: &crate::signing_service::SigningServiceClient,
    org_id: Uuid,
    current_owner: &[u8; 32],
    replacement_owner: &[u8; 32],
    signed_at: DateTime<Utc>,
    reason: &str,
    rotation_signature: &[u8; 64],
) -> Result<crate::signing_service::RotateOwnerResponse, (StatusCode, Json<serde_json::Value>)> {
    signing_service
        .rotate_owner(&crate::signing_service::RotateOwnerRequest {
            org_id,
            replacement_owner_pubkey_b64: B64.encode(replacement_owner.as_slice()),
            signed_at,
            reason: reason.to_string(),
            signing_pubkey_b64: B64.encode(current_owner.as_slice()),
            signature_b64: B64.encode(rotation_signature.as_slice()),
        })
        .await
        .map_err(crate::routes::deployments::signing_error_response)
}

/// The only acceptable proof that this directive caused the upstream state
/// is a receipt minted from this request's own successful,
/// response-validated rotate-owner RPC that still matches the service's
/// current owner (replacement pubkey, version, last_changed_at), so no
/// later upstream rotation can have superseded it. The expired-retry
/// freshness waiver relies on this, and so does receipt-bound recovery:
/// it is the sole condition under which an owner other than the
/// initiating caller may complete this exact, already-executed transition.
/// The version and timestamp equality run in SQL on PostgreSQL's
/// microsecond timestamptz representation; Rust-side nanosecond equality
/// would mismatch after the service's JSON roundtrip.
async fn upstream_receipt_matches_live_service(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    directive_digest: &[u8],
    keyring_digest: &[u8],
    owner_status: &crate::signing_service::OwnerStatusResponse,
    replacement_owner: &[u8; 32],
) -> Result<bool, (StatusCode, Json<serde_json::Value>)> {
    let matched: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM org_rotation_upstream_receipts
          WHERE org_id = $1
            AND directive_sha256 = $2
            AND keyring_sha256 = $3
            AND upstream_owner_version = $4
            AND upstream_rotated_at = $5::timestamptz",
    )
    .bind(org_id)
    .bind(directive_digest)
    .bind(keyring_digest)
    .bind(owner_status.version)
    .bind(owner_status.last_changed_at)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| db_error())?;
    Ok(matched.is_some()
        && service_owner_pubkey(owner_status).as_deref() == Some(replacement_owner.as_slice()))
}

/// Fresh rotations require the caller's active replacement-key registration.
/// Exact receipt-bound recovery may reuse another active registration of that
/// same key, so removing the initiator does not strand the completed RPC.
async fn validate_rotation_successor(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    base_payload: &[u8],
    replacement_keyring: &SignedOrgKeyring,
    current_owner: &[u8; 32],
    replacement_owner: &[u8; 32],
    user_id: Uuid,
    receipt_bound_recovery: bool,
) -> Result<Uuid, (StatusCode, Json<serde_json::Value>)> {
    let current_keyring: SignedOrgKeyring =
        serde_json::from_slice(base_payload).map_err(|_| db_error())?;
    if !current_keyring
        .members
        .iter()
        .any(|member| member.pubkey == *current_owner && member.role == SignedOrgKeyringRole::Owner)
    {
        return Err(bad_request(
            "current pinned owner key is not an owner in the keyring",
        ));
    }
    validate_rotated_members(
        &current_keyring,
        replacement_keyring,
        current_owner,
        replacement_owner,
    )
    .map_err(bad_request)?;
    let mut registration: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM user_signing_keys
          WHERE user_id = $1 AND pubkey = $2 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .bind(replacement_owner.as_slice())
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| db_error())?;
    if registration.is_none() && receipt_bound_recovery {
        // Execution provenance comes from the receipt, not registration ownership.
        // Select a deterministic active registration of the already-executed key.
        registration = sqlx::query_scalar(
            "SELECT id FROM user_signing_keys
              WHERE pubkey = $1 AND revoked_at IS NULL
              ORDER BY id
              LIMIT 1",
        )
        .bind(replacement_owner.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(|_| db_error())?;
    }
    registration.ok_or_else(|| bad_request("replacement owner key is not registered for this user"))
}

// Release the org lane before calling: publication takes the global KBS fence.
async fn confirm_owner_rotation_publication(
    state: &AppState,
    org_id: Uuid,
    keyring_version: i64,
    replacement_owner: &[u8; 32],
) -> Result<Json<RotateOrgOwnerResponse>, (StatusCode, Json<serde_json::Value>)> {
    confirm_keyring_kbs_publication(state).await?;
    Ok(Json(RotateOrgOwnerResponse {
        org_id,
        state: "ready",
        keyring_version,
        owner_fingerprint: hex::encode(Sha256::digest(replacement_owner)),
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

    // Freshness, replay binding, and recovery for the rotation directive.
    // When a rotation creates a new keyring version, signed_at must be
    // neither in the future nor older than the current keyring version's
    // creation (both measured against the authoritative clock observed
    // after the signing-authority lane is acquired, because queueing on
    // the lane can outlast any window captured before the lock), must
    // fall inside the first-use max-age window, and the directive is
    // consumed exactly once. The max-age window carries one recovery
    // exception: an expired retry is accepted only when an upstream
    // receipt (org_rotation_upstream_receipts, migration 0059) proves this
    // exact request's rotate-owner RPC succeeded and the service's current
    // owner state still matches that receipt. An already-applied rotation
    // is idempotent at any age, proven by the byte-identical stored
    // keyring content, signatures, and pinned-owner checks, and consumes
    // nothing.
    const MAX_DIRECTIVE_AGE_SECONDS: i64 = 900;
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

    // The intent digest, the keyring-version insert, and the stored
    // replay-equality bytes all use the normalized JSON-value encoding
    // registration uses (the typed struct re-serialized, dropping unsigned
    // extra fields), never the raw request bytes; the encoding is fixed at
    // first recording and existing ledger rows are never rewritten.
    let normalized_payload = serde_json::to_value(&replacement_keyring).map_err(|_| db_error())?;
    let payload_bytes = serde_json::to_vec(&normalized_payload).map_err(|_| db_error())?;
    crate::signing_service::validate_org_keyring_registration_budget(
        payload_bytes.len(),
        &keyring_signature,
        &replacement_owner,
    )
    .map_err(crate::routes::deployments::signing_error_response)?;
    let directive_digest = Sha256::digest(&directive);
    let intent_digest = Sha256::digest(&payload_bytes);

    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;

    // Durable presentation record (migration 0053), committed on its own
    // short-lived connection BEFORE the lane transaction opens: with the
    // pool capped, waiting on a second connection while holding the lane
    // transaction's connection could starve the whole cluster. The row
    // records that an authenticated, signature-verified presentation
    // reached this handler; it authorizes nothing by itself.
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

    // Phase 1: short lane transaction. Validate the request against live
    // lane state and perform at most one upstream rotate-owner RPC,
    // committing only the receipt minted from that RPC's validated
    // response. The directive is not consumed and no keyring or audit row
    // is written before that receipt-only commit: if the upstream rotation
    // succeeded but the CAP writes rolled back, the receipt is what later
    // waives the max-age window for retrying the exact lost request -- an
    // intent row alone proves no such thing.
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    let lane_now = crate::signing_service::lock_org_signing_authority_lane_now(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;
    let (latest, version_created_at_floor) = read_rotation_authority(&mut tx, org_id).await?;
    let rotation_path = derive_rotation_path(
        &mut tx,
        org_id,
        body.version,
        latest,
        &canonical_bytes,
        &keyring_signature,
        &replacement_owner,
    )
    .await?;

    let owner_status = read_live_service_owner(signing_service, org_id).await?;
    let service_owner = service_owner_pubkey(&owner_status);
    let Some((base_payload, expected_current_owner, insert_new_version)) = rotation_path else {
        if service_owner.as_deref() != Some(replacement_owner.as_slice()) {
            return Err(crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::AuthorityStatus(
                    "signing service owner does not hold the replacement owner".to_string(),
                ),
            ));
        }
        tx.rollback().await.map_err(|_| db_error())?;
        return confirm_owner_rotation_publication(
            &state,
            org_id,
            body.version,
            &replacement_owner,
        )
        .await;
    };
    if expected_current_owner.as_slice() != current_owner.as_slice() {
        return Err(bad_request(
            "rotation signer does not match the current pinned owner",
        ));
    }

    if insert_new_version {
        if body.signed_at > lane_now {
            return Err(bad_request(
                "owner rotation directive signed_at is in the future",
            ));
        }
        if body.signed_at < lane_now - chrono::Duration::seconds(MAX_DIRECTIVE_AGE_SECONDS)
            && !upstream_receipt_matches_live_service(
                &mut tx,
                org_id,
                directive_digest.as_slice(),
                intent_digest.as_slice(),
                &owner_status,
                &replacement_owner,
            )
            .await?
        {
            return Err(bad_request("owner rotation directive signed_at is too old"));
        }
        if body.signed_at < version_created_at_floor {
            return Err(bad_request(
                "owner rotation directive predates the current keyring version",
            ));
        }
        // Consume-once detection before any upstream side effect; the
        // final phase's unique insertion remains the authoritative guard.
        let already_consumed: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM org_rotation_directives
              WHERE org_id = $1 AND directive_sha256 = $2",
        )
        .bind(org_id)
        .bind(directive_digest.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?;
        if already_consumed.is_some() {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "owner rotation directive was already used"
                })),
            ));
        }
    }
    // Another owner may finish only an exact, already-executed transition.
    let receipt_bound_recovery = service_owner.as_deref() == Some(replacement_owner.as_slice())
        && upstream_receipt_matches_live_service(
            &mut tx,
            org_id,
            directive_digest.as_slice(),
            intent_digest.as_slice(),
            &owner_status,
            &replacement_owner,
        )
        .await?;

    validate_rotation_successor(
        &mut tx,
        &base_payload,
        &replacement_keyring,
        &current_owner,
        &replacement_owner,
        auth.user_id,
        receipt_bound_recovery,
    )
    .await?;

    if !insert_new_version {
        // Already applied: the byte-identical stored version content, the
        // verified keyring and directive signatures, and the pinned-owner
        // checks prove a retry of the completed rotation; nothing is
        // consumed and no CAP row is mutated. The service may still hold
        // the directive's signer, so the pre-existing recovery call pins
        // it to the replacement already fixed by the stored version; no
        // new owner key can be introduced, and no receipt is minted
        // because no CAP write follows that could roll back into drift.
        if service_owner.as_deref() == Some(current_owner.as_slice()) {
            let rotated = rotate_service_owner(
                signing_service,
                org_id,
                &current_owner,
                &replacement_owner,
                body.signed_at,
                body.reason.trim(),
                &rotation_signature,
            )
            .await?;
            validated_rotate_owner_response(&rotated, org_id, &replacement_owner)?;
        } else if service_owner.as_deref() != Some(replacement_owner.as_slice()) {
            return Err(crate::routes::deployments::signing_error_response(
                crate::signing_service::SigningServiceError::AuthorityStatus(
                    "signing service owner matches neither rotation key".to_string(),
                ),
            ));
        }
        tx.commit().await.map_err(|_| db_error())?;
        return confirm_owner_rotation_publication(
            &state,
            org_id,
            body.version,
            &replacement_owner,
        )
        .await;
    }

    if service_owner.as_deref() == Some(current_owner.as_slice()) {
        let rotated = rotate_service_owner(
            signing_service,
            org_id,
            &current_owner,
            &replacement_owner,
            body.signed_at,
            body.reason.trim(),
            &rotation_signature,
        )
        .await?;
        let upstream_owner_version =
            validated_rotate_owner_response(&rotated, org_id, &replacement_owner)?;
        // Receipt-only commit: durable proof that this request's RPC
        // succeeded, binding the exact directive and normalized keyring
        // digests to the response's owner version and rotated_at. A
        // conflicting receipt for the same owner version with different
        // bound contents fails closed and is never overwritten.
        let receipt_rows = sqlx::query(
            "INSERT INTO org_rotation_upstream_receipts
                 (org_id, directive_sha256, keyring_sha256, upstream_owner_version, upstream_rotated_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (org_id, upstream_owner_version) DO NOTHING",
        )
        .bind(org_id)
        .bind(directive_digest.as_slice())
        .bind(intent_digest.as_slice())
        .bind(upstream_owner_version)
        .bind(rotated.rotated_at)
        .execute(&mut *tx)
        .await
        .map_err(|_| db_error())?
        .rows_affected();
        if receipt_rows == 0 {
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (
                    SELECT 1 FROM org_rotation_upstream_receipts
                     WHERE org_id = $1 AND upstream_owner_version = $2
                       AND directive_sha256 = $3 AND keyring_sha256 = $4
                       AND upstream_rotated_at = $5::timestamptz
                )",
            )
            .bind(org_id)
            .bind(upstream_owner_version)
            .bind(directive_digest.as_slice())
            .bind(intent_digest.as_slice())
            .bind(rotated.rotated_at)
            .fetch_one(&mut *tx)
            .await
            .map_err(|_| db_error())?;
            if !matches {
                return Err((
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": "upstream rotation receipt conflicts with an existing receipt"
                    })),
                ));
            }
        }
        tx.commit().await.map_err(|_| db_error())?;
    } else if service_owner.as_deref() == Some(replacement_owner.as_slice()) {
        // The service already holds the replacement (a prior attempt or
        // a concurrent retry pinned it): no RPC, and no receipt -- only
        // a response-validated RPC can mint one. Committing ends the
        // read-only phase.
        tx.commit().await.map_err(|_| db_error())?;
    } else {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "signing service owner matches neither rotation key".to_string(),
            ),
        ));
    }

    // Phase 2: final lane transaction. The lane was released after the
    // receipt-only commit, so competing keyring changes may have landed;
    // membership, keyring, service owner, and freshness are re-read and
    // re-derived here. This phase never issues an upstream RPC (at most
    // one per request, spent or deliberately skipped in phase 1): the
    // service must already hold the replacement owner before any CAP
    // write, so the stored keyring authority and the service stay pinned
    // to the same owner.
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    let lane_now = crate::signing_service::lock_org_signing_authority_lane_now(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;
    let (latest, version_created_at_floor) = read_rotation_authority(&mut tx, org_id).await?;
    let rotation_path = derive_rotation_path(
        &mut tx,
        org_id,
        body.version,
        latest,
        &canonical_bytes,
        &keyring_signature,
        &replacement_owner,
    )
    .await?;

    let owner_status = read_live_service_owner(signing_service, org_id).await?;
    let service_owner = service_owner_pubkey(&owner_status);
    if service_owner.as_deref() != Some(replacement_owner.as_slice()) {
        return Err(crate::routes::deployments::signing_error_response(
            crate::signing_service::SigningServiceError::AuthorityStatus(
                "signing service owner does not hold the replacement owner".to_string(),
            ),
        ));
    }
    let Some((base_payload, expected_current_owner, insert_new_version)) = rotation_path else {
        tx.rollback().await.map_err(|_| db_error())?;
        return confirm_owner_rotation_publication(
            &state,
            org_id,
            body.version,
            &replacement_owner,
        )
        .await;
    };
    if expected_current_owner.as_slice() != current_owner.as_slice() {
        return Err(bad_request(
            "rotation signer does not match the current pinned owner",
        ));
    }
    if !insert_new_version {
        // A concurrent retry of this exact rotation completed the write
        // between the phases; the byte-identical stored version proves
        // it. Idempotent success, nothing consumed or written here.
        tx.commit().await.map_err(|_| db_error())?;
        return confirm_owner_rotation_publication(
            &state,
            org_id,
            body.version,
            &replacement_owner,
        )
        .await;
    }

    if body.signed_at > lane_now {
        return Err(bad_request(
            "owner rotation directive signed_at is in the future",
        ));
    }
    if body.signed_at < lane_now - chrono::Duration::seconds(MAX_DIRECTIVE_AGE_SECONDS)
        && !upstream_receipt_matches_live_service(
            &mut tx,
            org_id,
            directive_digest.as_slice(),
            intent_digest.as_slice(),
            &owner_status,
            &replacement_owner,
        )
        .await?
    {
        return Err(bad_request("owner rotation directive signed_at is too old"));
    }
    if body.signed_at < version_created_at_floor {
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
    // Revalidate recovery provenance after the lane gap. Fresh requests keep
    // caller-bound registration checks even if their RPC just minted a receipt.
    let receipt_bound_recovery = receipt_bound_recovery
        && upstream_receipt_matches_live_service(
            &mut tx,
            org_id,
            directive_digest.as_slice(),
            intent_digest.as_slice(),
            &owner_status,
            &replacement_owner,
        )
        .await?;

    let replacement_signing_key_id = validate_rotation_successor(
        &mut tx,
        &base_payload,
        &replacement_keyring,
        &current_owner,
        &replacement_owner,
        auth.user_id,
        receipt_bound_recovery,
    )
    .await?;

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
    tx.commit().await.map_err(|_| db_error())?;
    confirm_owner_rotation_publication(&state, org_id, body.version, &replacement_owner).await
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

    /// In-process stand-in for the platform signing service's owner authority
    /// surface (`GET /orgs/{id}/owner`, `POST /rotate-owner`), carrying the
    /// state receipt-aware rotations depend on: the current owner, its
    /// upstream version, when it last changed, and how many rotate-owner
    /// RPCs have been accepted. Rotate calls signed by anyone other than the
    /// current owner are rejected, mirroring the real service's authority
    /// check, so a stale owner snapshot that re-sends an already-completed
    /// rotation surfaces as a rejected RPC instead of silently rotating
    /// twice.
    struct MockSigningServiceOwner {
        owner: [u8; 32],
        changed_at: DateTime<Utc>,
        version: i64,
        rotate_calls: usize,
    }

    /// Spawn the mock owner-authority service and return its base URL plus
    /// the shared state handle tests mutate and assert on.
    async fn spawn_mock_signing_service_owner(
        org_id: Uuid,
        initial: MockSigningServiceOwner,
    ) -> (String, Arc<std::sync::Mutex<MockSigningServiceOwner>>) {
        let owner = Arc::new(std::sync::Mutex::new(initial));
        let status_owner = owner.clone();
        let rotate_owner = owner.clone();
        let app = axum::Router::new()
            .route(
                &format!("/orgs/{org_id}/owner"),
                axum::routing::get(move || async move {
                    let state = status_owner.lock().expect("mock owner lock");
                    axum::Json(serde_json::json!({
                        "org_id": org_id,
                        "state": "ready",
                        "version": state.version,
                        "owner_pubkey_hex": hex::encode(state.owner),
                        "last_changed_at": state.changed_at,
                    }))
                }),
            )
            .route(
                "/rotate-owner",
                axum::routing::post(
                    move |axum::Json(req): axum::Json<serde_json::Value>| async move {
                        let mut state = rotate_owner.lock().expect("mock owner lock");
                        let signer = req["signing_pubkey_b64"]
                            .as_str()
                            .and_then(|raw| B64.decode(raw).ok())
                            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
                        if signer != Some(state.owner) {
                            return (
                                StatusCode::CONFLICT,
                                axum::Json(serde_json::json!({
                                    "error": "rotation signer does not match the current owner"
                                })),
                            );
                        }
                        let replacement: [u8; 32] = B64
                            .decode(req["replacement_owner_pubkey_b64"].as_str().unwrap_or(""))
                            .expect("mock replacement owner decodes")
                            .try_into()
                            .expect("mock replacement owner is 32 bytes");
                        state.owner = replacement;
                        state.changed_at = Utc::now();
                        state.version += 1;
                        state.rotate_calls += 1;
                        (
                            StatusCode::OK,
                            axum::Json(serde_json::json!({
                                "org_id": req["org_id"].clone(),
                                "version": state.version,
                                "owner_pubkey_fingerprint": hex::encode(replacement),
                                "rotated_at": state.changed_at,
                            })),
                        )
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
        (format!("http://{address}/"), owner)
    }

    /// Minimal in-process stand-in for the platform signing service's owner
    /// authority surface: `GET /orgs/{id}/owner` and `POST /rotate-owner`.
    async fn mock_signing_service_owner_api(org_id: Uuid, initial_owner: [u8; 32]) -> String {
        spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: initial_owner,
                changed_at: Utc::now(),
                version: 1,
                rotate_calls: 0,
            },
        )
        .await
        .0
    }

    /// The normalized typed-JSON keyring encoding both put_keyring and owner
    /// rotation must store and digest: the `SignedOrgKeyring` struct
    /// re-serialized, dropping unsigned extra fields. Mirrors what
    /// `rotation_request` builds so tests can compute the exact digests the
    /// handlers record.
    fn normalized_keyring_bytes(
        org_id: Uuid,
        user_id: Uuid,
        owner: [u8; 32],
        version: i64,
        second: u32,
    ) -> Vec<u8> {
        let keyring = SignedOrgKeyring {
            org_id,
            version: version as u64,
            members: vec![SignedOrgKeyringMember {
                user_id,
                pubkey: owner,
                role: SignedOrgKeyringRole::Owner,
                added_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            }],
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, second).unwrap(),
        };
        serde_json::to_vec(&serde_json::to_value(&keyring).expect("serialize keyring value"))
            .expect("serialize normalized keyring bytes")
    }

    /// Single-connection pool into an isolated fixture database: the receipt
    /// checkpoint must never need a second pool connection while a lane
    /// transaction holds the first (pool-exhaustion deadlock). The short
    /// acquire timeout turns that bug into a fast error instead of a hang.
    async fn isolated_single_connection_pool(name: &str) -> sqlx::PgPool {
        let base_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let options = base_url
            .parse::<sqlx::postgres::PgConnectOptions>()
            .expect("parse isolated database URL")
            .database(&format!("{name}_{}", std::process::id()));
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(10))
            .connect_with(options)
            .await
            .expect("connect single-connection isolated pool")
    }

    /// Seed a committed presentation row exactly as the pre-lane intent
    /// insert would have recorded it, for presentations that happened
    /// before the test began.
    async fn seed_rotation_presentation(
        pool: &sqlx::PgPool,
        org_id: Uuid,
        directive_sha256: &[u8],
        keyring_sha256: &[u8],
        presented_at: DateTime<Utc>,
    ) {
        sqlx::query(
            "INSERT INTO org_rotation_intents
                 (org_id, directive_sha256, keyring_sha256, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT ON CONSTRAINT org_rotation_intents_pkey DO NOTHING",
        )
        .bind(org_id)
        .bind(directive_sha256)
        .bind(keyring_sha256)
        .bind(presented_at)
        .execute(pool)
        .await
        .expect("seed committed intent row");
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
        // that already existed when it was captured.
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

    // Unsigned fields must not change recovery identity or break legacy replay.
    #[tokio::test]
    async fn owner_rotation_intent_digest_uses_registration_normalized_encoding() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-intent-encoding-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert intent encoding org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Intent Encoding Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert intent encoding user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert intent encoding membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert intent encoding signing keys");

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

        // Rotation request whose raw JSON carries an unsigned extra field:
        // the typed parse ignores it, but the durable intent digest and the
        // stored keyring bytes must be computed over the normalized typed
        // serialization, exactly like registration after #182.
        let mut request = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now(),
            "intent-encoding",
        );
        request.keyring_payload["future_extension"] = serde_json::json!("unsigned-extra");
        let normalized_bytes = serde_json::to_vec(
            &serde_json::to_value(&SignedOrgKeyring {
                org_id,
                version: 2,
                members: vec![SignedOrgKeyringMember {
                    user_id,
                    pubkey: replacement_key.verifying_key().to_bytes(),
                    role: SignedOrgKeyringRole::Owner,
                    added_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
                }],
                updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 2).unwrap(),
            })
            .expect("serialize normalized keyring"),
        )
        .expect("serialize normalized keyring bytes");
        let _response = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(request),
        )
        .await
        .expect("normalized rotation succeeds");

        // The stored keyring version is the normalized encoding, not the
        // raw request bytes carrying the extra field.
        let stored: Vec<u8> = sqlx::query_scalar(
            "SELECT keyring_payload FROM org_keyrings WHERE org_id = $1 AND version = 2",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load stored rotated keyring");
        assert_eq!(stored, normalized_bytes, "stored bytes must be normalized");

        // The intent row's keyring digest is sha256 of the same normalized
        // bytes registration would store, not sha256 of the raw request.
        let expected_digest: Vec<u8> = Sha256::digest(&normalized_bytes).to_vec();
        let intent_digest: Vec<u8> =
            sqlx::query_scalar("SELECT keyring_sha256 FROM org_rotation_intents WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("load recorded intent digest");
        assert_eq!(
            intent_digest, expected_digest,
            "intent digest must match the registration encoding"
        );

        // Legacy replay compatibility: rewrite the stored v2 row to the raw
        // pre-#182 encoding (extra field re-added) and retry the exact
        // rotation -- it must still be recognized as an already-applied
        // rotation and succeed idempotently at any directive age.
        let mut legacy_value: serde_json::Value =
            serde_json::from_slice(&normalized_bytes).expect("parse normalized bytes");
        legacy_value["future_extension"] = serde_json::json!("unsigned-extra");
        let legacy_raw = serde_json::to_vec(&legacy_value).expect("serialize legacy raw bytes");
        sqlx::query(
            "UPDATE org_keyrings SET keyring_payload = $1 WHERE org_id = $2 AND version = 2",
        )
        .bind(&legacy_raw)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("rewrite stored row to legacy encoding");
        let mut retry = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::hours(1),
            "intent-encoding",
        );
        retry.keyring_payload["future_extension"] = serde_json::json!("unsigned-extra");
        let _response = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(retry),
        )
        .await
        .expect("legacy-encoded replay must stay idempotent");

        // Equivalent valid representations of the same typed keyring -- a
        // millisecond-precision timestamp and an uppercase-hex pubkey --
        // carry identical signed content: replay equality compares the
        // canonical typed encoding, not the stored text.
        let mut equivalent: serde_json::Value =
            serde_json::from_slice(&legacy_raw).expect("parse legacy bytes");
        equivalent["updated_at"] = serde_json::json!("2026-01-01T00:00:02.000Z");
        equivalent["members"][0]["pubkey"] = serde_json::json!(
            hex::encode(replacement_key.verifying_key().to_bytes()).to_uppercase()
        );
        let equivalent_raw = serde_json::to_vec(&equivalent).expect("serialize equivalent bytes");
        sqlx::query(
            "UPDATE org_keyrings SET keyring_payload = $1 WHERE org_id = $2 AND version = 2",
        )
        .bind(&equivalent_raw)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("rewrite stored row to an equivalent representation");
        let mut equivalent_retry = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::hours(1),
            "intent-encoding",
        );
        equivalent_retry.keyring_payload["future_extension"] = serde_json::json!("unsigned-extra");
        let _response = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(equivalent_retry),
        )
        .await
        .expect("equivalent valid representations must stay replay-equal");

        // The upload path shares the same normalization: a put_keyring
        // carrying an unsigned extra field stores the normalized typed
        // bytes and replays idempotently.
        let upload = || {
            let mut request = signed_keyring_request(org_id, user_id, &replacement_key, 3, 3);
            request.keyring_payload["future_extension"] = serde_json::json!("unsigned-extra");
            request
        };
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(upload()),
        )
        .await
        .expect("upload v3 with an unsigned extra field");
        let stored_v3: Vec<u8> = sqlx::query_scalar(
            "SELECT keyring_payload FROM org_keyrings WHERE org_id = $1 AND version = 3",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load stored uploaded v3 keyring");
        assert_eq!(
            stored_v3,
            normalized_keyring_bytes(
                org_id,
                user_id,
                replacement_key.verifying_key().to_bytes(),
                3,
                3
            ),
            "upload must store the normalized typed encoding"
        );
        let _ = put_keyring(auth, State(state), Path(org_name), Json(upload()))
            .await
            .expect("exact upload replay stays idempotent");
    }

    #[tokio::test]
    async fn owner_rotation_rejects_future_dated_directive_despite_version_recency() {
        // A +300s clock-skew allowance
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
    async fn owner_rotation_version_bound_floors_legacy_rows_at_migration_watermark() {
        // A keyring version committed before the migration can retain a
        // transaction-start created_at that can predate its real
        // insertion by the full signing-authority lane wait. Without the
        // migration-0054 watermark floor, a directive signed while the
        // legacy upload sat queued on the lane compares as "newer than
        // the version" and is accepted during the post-rollout first-use
        // window even though it predates the version's real insertion.
        // Model the legacy row exactly: v1's stored created_at is moved
        // into the past (what a transaction-start default recorded),
        // while the watermark stays at migration time. The directive is
        // signed "now" -- after v1's stored timestamp, inside the
        // first-use window, never consumed -- and must be rejected by
        // the watermark floor rather than compared against the stale
        // legacy timestamp.
        // The org_keyrings_created_at_watermark row is shared global state
        // that this test backdates; pinning it inside an isolated database
        // keeps the shared fixture's floor intact for concurrently running
        // tests.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap185_watermark_floor").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-legacy-watermark-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert legacy watermark org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Legacy Watermark Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert legacy watermark user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert legacy watermark membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert legacy watermark signing keys");

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

        // Legacy semantics: the stored created_at predates the row's real
        // insertion (transaction-start clock). Pin the watermark explicitly
        // (as it would be minutes after rollout) so the scenario does not
        // depend on when this test database was migrated.
        sqlx::query("UPDATE org_keyrings SET created_at = $2 WHERE org_id = $1 AND version = 1")
            .bind(org_id)
            .bind(Utc::now() - chrono::Duration::minutes(10))
            .execute(&pool)
            .await
            .expect("backdate v1 to legacy transaction-start timestamp");
        sqlx::query("UPDATE org_keyrings_created_at_watermark SET watermarked_at = $1")
            .bind(Utc::now() - chrono::Duration::minutes(6))
            .execute(&pool)
            .await
            .expect("pin watermark to rollout time");

        // A directive signed 8 minutes ago: after v1's stored legacy
        // timestamp (now-10m), inside the first-use window, never consumed
        // -- but before the watermark (now-6m), hence before the version's
        // earliest provable insertion semantics. Against the stale stored
        // value it would pass; against the watermark floor it must fail.
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(rotation_request(
                org_id,
                user_id,
                &current_key,
                &replacement_key,
                2,
                2,
                Utc::now() - chrono::Duration::minutes(8),
                "legacy-watermark",
            )),
        )
        .await
        .expect_err("directive signed inside a legacy created_at lag must be rejected");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            rejected.1.0["error"],
            "owner rotation directive predates the current keyring version"
        );

        // Control: once the org has a post-watermark version (uploaded
        // after migration 0054, created_at = clock_timestamp()), a
        // directive signed after that insertion rotates normally -- the
        // floor does not wedge forward rotations.
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 2, 2)),
        )
        .await
        .expect("publish v2 keyring under post-migration semantics");
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(rotation_request(
                org_id,
                user_id,
                &current_key,
                &replacement_key,
                3,
                3,
                Utc::now(),
                "legacy-watermark-forward",
            )),
        )
        .await
        .expect("post-watermark directive rotates normally");

        crate::test_support::drop_isolated_database("cap185_watermark_floor", pool).await;
    }

    #[tokio::test]
    async fn owner_rotation_expired_recovery_requires_matching_upstream_receipt() {
        // Presentation order differs from execution order. Unrelated intents must not
        // block the exact receipt; a changed upstream snapshot must reject it.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap185_receipt_recovery").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-receipt-recovery-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert receipt recovery org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Receipt Recovery Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert receipt recovery user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert receipt recovery membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert receipt recovery signing keys");

        // D2 presented first but executed after D1 failed under the lane.
        // Presentation order must not let D1 borrow D2's upstream change.
        let drift_at = Utc::now() - chrono::Duration::minutes(19);
        let presented_d2_at = drift_at - chrono::Duration::minutes(1);
        let presented_d1_at = drift_at - chrono::Duration::seconds(30);

        let (mock_url, mock) = spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: replacement_key.verifying_key().to_bytes(),
                changed_at: drift_at,
                version: 2,
                rotate_calls: 0,
            },
        )
        .await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(mock_url, None)
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
        // Backdate v1 and the migration watermark so the 20-minute-old
        // directives below pass the version-recency floor and only the
        // first-use max-age window is exceeded. This mutates the shared
        // org_keyrings_created_at_watermark row, which is why this test
        // runs against an isolated database.
        sqlx::query("UPDATE org_keyrings SET created_at = $2 WHERE org_id = $1 AND version = 1")
            .bind(org_id)
            .bind(Utc::now() - chrono::Duration::minutes(30))
            .execute(&pool)
            .await
            .expect("backdate v1 creation");
        sqlx::query("UPDATE org_keyrings_created_at_watermark SET watermarked_at = $1")
            .bind(Utc::now() - chrono::Duration::minutes(30))
            .execute(&pool)
            .await
            .expect("backdate created_at watermark");

        let recovery_signed_at = presented_d2_at - chrono::Duration::seconds(1);
        let d1_signed_at = presented_d1_at - chrono::Duration::seconds(1);
        let recovery = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            recovery_signed_at,
            "receipt-recovery",
        );
        let recovery_directive = Sha256::digest(owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            recovery_signed_at,
            "receipt-recovery",
        ))
        .to_vec();
        // Both D1 and D2 rotate the same member set, so their keyring
        // digests are identical; only the directives differ.
        let shared_keyring_digest = Sha256::digest(normalized_keyring_bytes(
            org_id,
            user_id,
            replacement_key.verifying_key().to_bytes(),
            2,
            2,
        ))
        .to_vec();
        let d1 = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            d1_signed_at,
            "receipt-recovery-lost-first",
        );
        let d1_directive = Sha256::digest(owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            d1_signed_at,
            "receipt-recovery-lost-first",
        ))
        .to_vec();

        // Only D2's successful upstream execution produced a receipt.
        seed_rotation_presentation(
            &pool,
            org_id,
            &d1_directive,
            &shared_keyring_digest,
            presented_d1_at,
        )
        .await;
        seed_rotation_presentation(
            &pool,
            org_id,
            &recovery_directive,
            &shared_keyring_digest,
            presented_d2_at,
        )
        .await;
        sqlx::query(
            "INSERT INTO org_rotation_upstream_receipts
                 (org_id, directive_sha256, keyring_sha256, upstream_owner_version, upstream_rotated_at)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(&recovery_directive)
        .bind(&shared_keyring_digest)
        .bind(2_i64)
        .bind(drift_at)
        .execute(&pool)
        .await
        .expect("seed upstream receipt for the lost attempt");

        // A different directive over the same owner pair, presented now --
        // long past the drift: it has no receipt, and a presentation record
        // cannot borrow another directive's receipt. Its own presentation
        // lands in org_rotation_intents before the check runs, so it also
        // stands for every unactioned presentation recorded after the
        // drift: none of them may block the valid receipt recovery below.
        let imposter = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now() - chrono::Duration::minutes(20),
            "receipt-recovery-imposter",
        );
        let rejected = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(imposter),
        )
        .await
        .expect_err("a different directive cannot borrow the upstream receipt");
        assert_eq!(rejected.0, StatusCode::BAD_REQUEST);

        // D1 was presented while fresh, but never completed upstream.
        let rejected_d1 = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(d1),
        )
        .await
        .expect_err("an unactioned directive cannot borrow another request's upstream change");
        assert_eq!(rejected_d1.0, StatusCode::BAD_REQUEST);

        // The live signing service must still hold the exact rotation the
        // receipt records. A higher upstream version means the service
        // rotated again since the receipt: the older receipt must not
        // authorize recovery against the newer owner state.
        mock.lock().expect("mock owner lock").version = 3;
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(recovery.clone()),
        )
        .await
        .expect_err("a receipt older than the live upstream owner must be rejected");
        // Likewise a last_changed_at that no longer matches the receipt's
        // upstream_rotated_at (the owner state moved on without a version
        // the receipt knows about) must fail closed.
        {
            let mut service = mock.lock().expect("mock owner lock");
            service.version = 2;
            service.changed_at = drift_at + chrono::Duration::minutes(5);
        }
        let _ = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(recovery.clone()),
        )
        .await
        .expect_err("receipt rotated_at must match the live owner last_changed_at");
        let still_v1: i64 =
            sqlx::query_scalar("SELECT max(version) FROM org_keyrings WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("load latest version after rejected recoveries");
        assert_eq!(
            still_v1, 1,
            "no rejected recovery may mint a keyring version"
        );

        // The exact expired retry with the matching receipt: recovery
        // completes without any new upstream rotation -- the receipt is
        // the proof the remote already rotated.
        mock.lock().expect("mock owner lock").changed_at = drift_at;
        let recovered = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(recovery),
        )
        .await
        .expect("expired retry with a matching receipt recovers the lost rotation");
        assert_eq!(recovered.keyring_version, 2);
        assert_eq!(
            recovered.owner_fingerprint,
            hex::encode(Sha256::digest(replacement_key.verifying_key().to_bytes()))
        );
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            0,
            "receipt recovery must not repeat the upstream rotation"
        );
        let stored_version: i64 = sqlx::query_scalar(
            "SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version DESC LIMIT 1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("read back latest version");
        assert_eq!(stored_version, 2);

        crate::test_support::drop_isolated_database("cap185_receipt_recovery", pool).await;
    }

    #[tokio::test]
    async fn owner_rotation_receipt_survives_failed_final_commit_and_replays_once() {
        // The receipt must survive a failed final transaction without another RPC.
        // One pool connection exposes any nested-acquisition deadlock.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap185_receipt_checkpoint").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-receipt-checkpoint-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert receipt checkpoint org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Receipt Checkpoint Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert receipt checkpoint user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert receipt checkpoint membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        let third_key = SigningKey::generate(&mut OsRng);
        sqlx::query(
            "INSERT INTO user_signing_keys (user_id, pubkey)
             VALUES ($1, $2), ($1, $3), ($1, $4)",
        )
        .bind(user_id)
        .bind(current_key.verifying_key().to_bytes().to_vec())
        .bind(replacement_key.verifying_key().to_bytes().to_vec())
        .bind(third_key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("insert receipt checkpoint signing keys");

        // Scoped failure injection: while the switch row exists, inserts
        // into org_keyrings for this org raise, aborting only the final CAP
        // transaction. The receipt table is untouched, so the checkpoint
        // commit survives.
        sqlx::query("CREATE TABLE cap185_receipt_fail_switch (org_id uuid PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("create final-commit failure switch");
        sqlx::query(
            "CREATE OR REPLACE FUNCTION cap185_fail_keyring_insert() RETURNS trigger
             LANGUAGE plpgsql AS $$
             BEGIN
                 IF EXISTS (SELECT 1 FROM cap185_receipt_fail_switch WHERE org_id = NEW.org_id) THEN
                     RAISE EXCEPTION 'induced final keyring insert failure';
                 END IF;
                 RETURN NEW;
             END $$",
        )
        .execute(&pool)
        .await
        .expect("create final-commit failure function");
        sqlx::query(
            "CREATE TRIGGER cap185_fail_keyring_insert_trigger
             BEFORE INSERT ON org_keyrings
             FOR EACH ROW EXECUTE FUNCTION cap185_fail_keyring_insert()",
        )
        .execute(&pool)
        .await
        .expect("create final-commit failure trigger");

        let (mock_url, mock) = spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: current_key.verifying_key().to_bytes(),
                changed_at: Utc::now(),
                version: 1,
                rotate_calls: 0,
            },
        )
        .await;
        let unrouted_url = format!("{mock_url}unrouted/");
        let mut state = crate::test_support::lazy_state();
        state.db = isolated_single_connection_pool("cap185_receipt_checkpoint").await;
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(mock_url, None)
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

        let test_started_at = Utc::now();

        // Fresh rotation v2: exactly one upstream RPC, and the receipt it
        // produced binds the directive and normalized keyring digests to
        // the upstream version the rotation reported.
        let v2_signed_at = Utc::now();
        let v2_request = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            v2_signed_at,
            "receipt-checkpoint",
        );
        let rotated = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v2_request),
        )
        .await
        .expect("fresh rotation performs the upstream rotation");
        assert_eq!(rotated.keyring_version, 2);
        assert_eq!(mock.lock().expect("mock owner lock").rotate_calls, 1);
        let v2_directive = Sha256::digest(owner_rotation_directive_bytes(
            org_id,
            &current_key.verifying_key().to_bytes(),
            &replacement_key.verifying_key().to_bytes(),
            v2_signed_at,
            "receipt-checkpoint",
        ));
        let v2_keyring = Sha256::digest(normalized_keyring_bytes(
            org_id,
            user_id,
            replacement_key.verifying_key().to_bytes(),
            2,
            2,
        ));
        let v2_receipt: (Vec<u8>, Vec<u8>, i64, DateTime<Utc>) = sqlx::query_as(
            "SELECT directive_sha256, keyring_sha256, upstream_owner_version, upstream_rotated_at
               FROM org_rotation_upstream_receipts
              WHERE org_id = $1 AND upstream_owner_version = 2",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load v2 upstream receipt");
        assert_eq!(v2_receipt.0, v2_directive.as_slice().to_vec());
        assert_eq!(v2_receipt.1, v2_keyring.as_slice().to_vec());
        assert_eq!(v2_receipt.2, 2, "the receipt records the upstream version");
        assert!(
            v2_receipt.3 >= test_started_at,
            "upstream_rotated_at is the RPC time, not the directive time"
        );

        // Force the FINAL CAP transaction of the next rotation to fail
        // after its upstream rotation succeeded: only the receipt survives.
        sqlx::query("INSERT INTO cap185_receipt_fail_switch (org_id) VALUES ($1)")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("arm final-commit failure");
        let v3_signed_at = Utc::now();
        let v3_request = rotation_request(
            org_id,
            user_id,
            &replacement_key,
            &third_key,
            3,
            3,
            v3_signed_at,
            "receipt-checkpoint-failure",
        );
        let failed = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v3_request.clone()),
        )
        .await;
        assert!(
            failed.is_err(),
            "forced final persistence failure must surface as an error"
        );
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            2,
            "the upstream rotation happened exactly once before the failed commit"
        );
        let v3_directive = Sha256::digest(owner_rotation_directive_bytes(
            org_id,
            &replacement_key.verifying_key().to_bytes(),
            &third_key.verifying_key().to_bytes(),
            v3_signed_at,
            "receipt-checkpoint-failure",
        ));
        let v3_keyring = Sha256::digest(normalized_keyring_bytes(
            org_id,
            user_id,
            third_key.verifying_key().to_bytes(),
            3,
            3,
        ));
        let v3_receipts: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM org_rotation_upstream_receipts
              WHERE org_id = $1 AND directive_sha256 = $2 AND keyring_sha256 = $3
                AND upstream_owner_version = 3",
        )
        .bind(org_id)
        .bind(v3_directive.as_slice())
        .bind(v3_keyring.as_slice())
        .fetch_one(&pool)
        .await
        .expect("count v3 upstream receipts");
        assert_eq!(
            v3_receipts, 1,
            "the failed final commit must leave the receipt durable"
        );
        let checkpoint_state: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'),
                    (SELECT count(*) FROM org_rotation_directives WHERE org_id = $1)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count CAP-side rows after the failed final commit");
        assert_eq!(
            checkpoint_state,
            (2, 1, 1),
            "only the receipt checkpoint persists: no v3 keyring, audit, or directive consumption"
        );

        sqlx::query("DELETE FROM cap185_receipt_fail_switch WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("disarm final-commit failure");

        // The failed rotation already moved the service from B to C, so B
        // must not claim its successor even when authority becomes unreadable.
        let stale_put = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                user_id,
                &replacement_key,
                3,
                3,
            )),
        )
        .await
        .expect_err("the old pinned owner must not claim the successor version");
        assert_eq!(stale_put.0, StatusCode::CONFLICT);

        // Missing client: this org has recorded rotation history, so the
        // absence of configuration cannot stand in for the live authority.
        let mut no_client_state = state.clone();
        no_client_state.signing_service = None;
        let unconfigured = put_keyring(
            auth.clone(),
            State(no_client_state),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                user_id,
                &replacement_key,
                3,
                3,
            )),
        )
        .await
        .expect_err("rotation history requires restored service configuration");
        assert_eq!(unconfigured.0, StatusCode::SERVICE_UNAVAILABLE);

        // Unreadable authority: the same mock listener under a prefix it
        // does not route answers every request with a deterministic 404.
        let mut unrouted_state = state.clone();
        unrouted_state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(unrouted_url, None)
                .expect("build unrouted signing service client"),
        );
        let unreachable = put_keyring(
            auth.clone(),
            State(unrouted_state),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                user_id,
                &replacement_key,
                3,
                3,
            )),
        )
        .await
        .expect_err("an unreadable authority must fail closed");
        assert_eq!(unreachable.0, StatusCode::BAD_GATEWAY);
        assert_eq!(unreachable.1.0["error"], "signing_service_unavailable");

        let fenced_v3_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM org_keyrings WHERE org_id = $1 AND version = 3",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count v3 keyrings after the fenced puts");
        assert_eq!(
            fenced_v3_rows, 0,
            "every fenced put must reject before inserting a v3 row"
        );

        // Exact retry: the receipt proves the upstream rotation already
        // happened, so CAP completes without calling the remote again.
        let replayed = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v3_request),
        )
        .await
        .expect("retry after the failed final commit replays the receipt");
        assert_eq!(replayed.keyring_version, 3);
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            2,
            "the retry must not repeat the upstream rotation"
        );
        let replayed_state: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'),
                    (SELECT count(*) FROM org_rotation_directives WHERE org_id = $1)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count CAP-side rows after the receipt replay");
        assert_eq!(
            replayed_state,
            (3, 2, 2),
            "exactly one v3 keyring, audit row, and directive consumption"
        );
        let receipt_rows: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM org_rotation_upstream_receipts WHERE org_id = $1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count upstream receipts after replay");
        assert_eq!(
            receipt_rows, 2,
            "the retry reuses the existing receipt instead of recording a second one"
        );

        crate::test_support::drop_isolated_database("cap185_receipt_checkpoint", pool).await;
    }

    #[tokio::test]
    async fn owner_rotation_receipt_bound_recovery_by_remaining_owner() {
        // Phase 1 committed the receipt and moved the service to the
        // replacement owner, then the final CAP commit failed and the
        // initiating owner was demoted. A demoted actor must never
        // finalize; a remaining owner must recover the exact
        // receipt-bound request without another upstream RPC; unrelated
        // or mutated requests must stay denied.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap185_receipt_handoff").await;
        let org_id = Uuid::new_v4();
        let initiator_id = Uuid::new_v4();
        let remaining_owner_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-receipt-handoff-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert receipt handoff org");
        for (member_id, display_name) in [
            (initiator_id, "Receipt Handoff Initiator"),
            (remaining_owner_id, "Receipt Handoff Remaining Owner"),
        ] {
            sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, $2)")
                .bind(member_id)
                .bind(display_name)
                .execute(&pool)
                .await
                .expect("insert receipt handoff user");
            sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
                .bind(member_id)
                .bind(org_id)
                .execute(&pool)
                .await
                .expect("insert receipt handoff membership");
        }
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        let third_key = SigningKey::generate(&mut OsRng);
        // Only the initiator holds key registrations: the remaining owner
        // authorizes purely through role and the receipt, never through
        // key ownership.
        sqlx::query(
            "INSERT INTO user_signing_keys (user_id, pubkey)
             VALUES ($1, $2), ($1, $3), ($1, $4)",
        )
        .bind(initiator_id)
        .bind(current_key.verifying_key().to_bytes().to_vec())
        .bind(replacement_key.verifying_key().to_bytes().to_vec())
        .bind(third_key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("insert receipt handoff signing keys");

        // Scoped failure injection: while the switch row exists, inserts
        // into org_keyrings for this org raise, aborting only the final
        // CAP transaction; the receipt table is untouched.
        sqlx::query("CREATE TABLE cap185_handoff_fail_switch (org_id uuid PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("create handoff failure switch");
        sqlx::query(
            "CREATE OR REPLACE FUNCTION cap185_handoff_fail_insert() RETURNS trigger
             LANGUAGE plpgsql AS $$
             BEGIN
                 IF EXISTS (SELECT 1 FROM cap185_handoff_fail_switch WHERE org_id = NEW.org_id) THEN
                     RAISE EXCEPTION 'induced final keyring insert failure';
                 END IF;
                 RETURN NEW;
             END $$",
        )
        .execute(&pool)
        .await
        .expect("create handoff failure function");
        sqlx::query(
            "CREATE TRIGGER cap185_handoff_fail_insert_trigger
             BEFORE INSERT ON org_keyrings
             FOR EACH ROW EXECUTE FUNCTION cap185_handoff_fail_insert()",
        )
        .execute(&pool)
        .await
        .expect("create handoff failure trigger");

        let (mock_url, mock) = spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: current_key.verifying_key().to_bytes(),
                changed_at: Utc::now(),
                version: 1,
                rotate_calls: 0,
            },
        )
        .await;
        let mut state = crate::test_support::lazy_state();
        state.db = isolated_single_connection_pool("cap185_receipt_handoff").await;
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(mock_url, None)
                .expect("build mock signing service client"),
        );
        let initiator_auth = AuthContext {
            user_id: initiator_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let remaining_auth = AuthContext {
            user_id: remaining_owner_id,
            org_id,
            org_name: org_name.clone(),
            role: Role::Owner,
            api_key: None,
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        };
        let _ = put_keyring(
            initiator_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(
                org_id,
                initiator_id,
                &current_key,
                1,
                1,
            )),
        )
        .await
        .expect("publish v1 keyring");

        // The initiating owner's rotation executes the upstream RPC and
        // commits the receipt, then the final CAP commit is forced to
        // fail.
        sqlx::query("INSERT INTO cap185_handoff_fail_switch (org_id) VALUES ($1)")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("arm final-commit failure");
        let v2_signed_at = Utc::now();
        let v2_request = rotation_request(
            org_id,
            initiator_id,
            &current_key,
            &replacement_key,
            2,
            2,
            v2_signed_at,
            "handoff",
        );
        let failed = rotate_org_owner(
            initiator_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v2_request.clone()),
        )
        .await;
        assert!(
            failed.is_err(),
            "forced final persistence failure must surface as an error"
        );
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            1,
            "the upstream rotation happened exactly once before the failed commit"
        );
        let checkpoint: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                    (SELECT count(*) FROM org_rotation_directives WHERE org_id = $1),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id = $1 AND action = 'org.keyring.owner.rotate')",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count CAP-side rows after the failed final commit");
        assert_eq!(
            checkpoint,
            (1, 0, 0),
            "only the receipt survived the failed final commit"
        );

        sqlx::query("UPDATE memberships SET role = 'admin' WHERE user_id = $1 AND org_id = $2")
            .bind(initiator_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("demote the initiating owner");

        let demoted_error = rotate_org_owner(
            initiator_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v2_request.clone()),
        )
        .await
        .expect_err("a demoted actor must never finalize a rotation");
        assert_eq!(demoted_error.0, StatusCode::FORBIDDEN);

        // Mutated keyring content under the same directive: the receipt
        // binds the exact keyring digest, so the mutation forfeits the
        // recovery.
        let mutated = rotation_request(
            org_id,
            initiator_id,
            &current_key,
            &replacement_key,
            2,
            3,
            v2_signed_at,
            "handoff",
        );
        let mutated_error = rotate_org_owner(
            remaining_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(mutated),
        )
        .await
        .expect_err("a mutated request must not inherit the receipt");
        assert_eq!(mutated_error.0, StatusCode::BAD_REQUEST);

        // Unrelated directive with the initiator's key: no receipt exists
        // for it, so the remaining owner cannot borrow the registration.
        let unrelated = rotation_request(
            org_id,
            initiator_id,
            &current_key,
            &replacement_key,
            2,
            2,
            v2_signed_at,
            "handoff-unrelated",
        );
        let unrelated_error = rotate_org_owner(
            remaining_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(unrelated),
        )
        .await
        .expect_err("an unrelated directive must not inherit the receipt");
        assert_eq!(unrelated_error.0, StatusCode::BAD_REQUEST);

        sqlx::query("DELETE FROM cap185_handoff_fail_switch WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("disarm the final-commit failure");

        let recovered = rotate_org_owner(
            remaining_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(v2_request),
        )
        .await
        .expect("a remaining owner recovers the exact receipt-bound request");
        assert_eq!(recovered.keyring_version, 2);
        assert_eq!(
            recovered.owner_fingerprint,
            hex::encode(Sha256::digest(replacement_key.verifying_key().to_bytes()))
        );
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            1,
            "the recovery must not repeat the upstream rotation"
        );
        let recovered_state: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                    (SELECT count(*) FROM org_rotation_directives WHERE org_id = $1)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count CAP-side rows after the receipt recovery");
        assert_eq!(
            recovered_state,
            (2, 1),
            "exactly one v2 keyring and one directive consumption"
        );
        let finalized_by: Uuid = sqlx::query_scalar(
            "SELECT user_id FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load the rotation audit row");
        assert_eq!(
            finalized_by, remaining_owner_id,
            "the remaining owner, not the demoted initiator, finalized the rotation"
        );

        // A fresh rotation by the remaining owner with a key registered
        // only to the initiator keeps the caller-bound registration
        // requirement: no receipt can authorize it.
        let fresh = rotation_request(
            org_id,
            initiator_id,
            &replacement_key,
            &third_key,
            3,
            3,
            Utc::now(),
            "handoff-fresh",
        );
        let fresh_error = rotate_org_owner(
            remaining_auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(fresh),
        )
        .await
        .expect_err("fresh rotations keep the caller-bound registration requirement");
        assert_eq!(fresh_error.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            1,
            "the denied fresh rotation must not reach the upstream service"
        );

        crate::test_support::drop_isolated_database("cap185_receipt_handoff", pool).await;
    }

    #[tokio::test]
    async fn owner_rotation_version_ceiling_rejects_successor_and_preserves_replay() {
        // derive_rotation_path must not compute latest+1 unchecked: at
        // the bigint ceiling no successor version exists. A proposal
        // below the ceiling must get the normal stale-version conflict
        // (the unchecked add would panic in debug and wrap in release),
        // and the exact existing-version replay at the ceiling must keep
        // working.
        let (_db_cleanup, pool) =
            crate::test_support::isolated_database_test_pool("cap185_version_ceiling").await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-version-ceiling-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert version ceiling org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Version Ceiling Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert version ceiling user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert version ceiling membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert version ceiling signing keys");

        // Seed the latest keyring at the bigint ceiling exactly as the
        // committed writers store it: normalized payload bytes signed by
        // the replacement key.
        let replay = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            i64::MAX,
            9,
            Utc::now(),
            "ceiling-replay",
        );
        let replacement_key_id: Uuid = sqlx::query_scalar(
            "SELECT id FROM user_signing_keys
              WHERE user_id = $1 AND pubkey = $2 AND revoked_at IS NULL",
        )
        .bind(user_id)
        .bind(replacement_key.verifying_key().to_bytes().to_vec())
        .fetch_one(&pool)
        .await
        .expect("load replacement key registration");
        sqlx::query(
            "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(org_id)
        .bind(i64::MAX)
        .bind(normalized_keyring_bytes(
            org_id,
            user_id,
            replacement_key.verifying_key().to_bytes(),
            i64::MAX,
            9,
        ))
        .bind(hex::decode(&replay.signature).expect("decode replay signature"))
        .bind(replacement_key_id)
        .execute(&pool)
        .await
        .expect("insert keyring at the bigint version ceiling");

        let (mock_url, mock) = spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: replacement_key.verifying_key().to_bytes(),
                changed_at: Utc::now(),
                version: 1,
                rotate_calls: 0,
            },
        )
        .await;
        let mut state = crate::test_support::lazy_state();
        state.db = isolated_single_connection_pool("cap185_version_ceiling").await;
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(mock_url, None)
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

        let below_ceiling = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            i64::MAX - 1,
            8,
            Utc::now(),
            "ceiling-stale",
        );
        let stale_error = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(below_ceiling),
        )
        .await
        .expect_err("a version below the committed ceiling is stale");
        assert_eq!(stale_error.0, StatusCode::CONFLICT);

        let recovered = rotate_org_owner(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(replay),
        )
        .await
        .expect("exact existing-version replay at the ceiling succeeds");
        assert_eq!(recovered.keyring_version, i64::MAX);
        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            0,
            "neither the stale proposal nor the ceiling replay rotates upstream"
        );

        crate::test_support::drop_isolated_database("cap185_version_ceiling", pool).await;
    }

    #[tokio::test]
    async fn owner_rotation_lane_waiter_rereads_owner_before_remote_rotation() {
        // Both requests queue while the upstream owner is still the original key.
        // A pre-lane snapshot would send the duplicate RPC with the revoked signer.
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-lane-waiter-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert lane waiter org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Lane Waiter Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert lane waiter user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert lane waiter membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2), ($1, $3)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .bind(replacement_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert lane waiter signing keys");

        let (mock_url, mock) = spawn_mock_signing_service_owner(
            org_id,
            MockSigningServiceOwner {
                owner: current_key.verifying_key().to_bytes(),
                changed_at: Utc::now(),
                version: 1,
                rotate_calls: 0,
            },
        )
        .await;
        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(mock_url, None)
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

        // Hold the org's signing-authority lane so both rotation requests
        // queue behind this transaction in a known order.
        let mut lane_blocker = pool.begin().await.expect("begin lane blocker");
        sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
            .bind(crate::signing_service::ORG_SIGNING_AUTHORITY_LANE_DOMAIN)
            .bind(crate::signing_service::org_signing_advisory_key(org_id))
            .execute(&mut *lane_blocker)
            .await
            .expect("hold signing authority lane");

        let winner_application = format!("keyring-lane-waiter-winner-{suffix}");
        let mut winner_state = crate::test_support::lazy_state();
        winner_state.db = named_database_test_pool(&winner_application).await;
        winner_state.signing_service = state.signing_service.clone();
        let winner_request = rotation_request(
            org_id,
            user_id,
            &current_key,
            &replacement_key,
            2,
            2,
            Utc::now(),
            "lane-waiter",
        );
        let winner = tokio::spawn(rotate_org_owner(
            auth.clone(),
            State(winner_state),
            Path(org_name.clone()),
            Json(winner_request.clone()),
        ));
        wait_for_named_lock_waiter(&pool, &winner_application).await;

        // A byte-identical duplicate of the same rotation, queued strictly
        // behind the winner. Whichever of the two lands the insert, the
        // other must observe the winner's committed upstream state (owner,
        // receipt) instead of its pre-lane snapshot.
        let waiter_application = format!("keyring-lane-waiter-retry-{suffix}");
        let mut waiter_state = crate::test_support::lazy_state();
        waiter_state.db = named_database_test_pool(&waiter_application).await;
        waiter_state.signing_service = state.signing_service.clone();
        let waiter = tokio::spawn(rotate_org_owner(
            auth.clone(),
            State(waiter_state),
            Path(org_name.clone()),
            Json(winner_request),
        ));
        wait_for_named_lock_waiter(&pool, &waiter_application).await;

        lane_blocker
            .rollback()
            .await
            .expect("release signing authority lane");
        let _ = winner
            .await
            .expect("join winner rotation")
            .expect("winner rotation commits");
        let _ = waiter
            .await
            .expect("join queued duplicate rotation")
            .expect("queued duplicate completes idempotently without a second upstream rotation");

        assert_eq!(
            mock.lock().expect("mock owner lock").rotate_calls,
            1,
            "exactly one upstream rotation serves both requests"
        );
        let outcome: (i64, i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'),
                    (SELECT count(*) FROM org_rotation_directives WHERE org_id = $1)",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count lane waiter rotation rows");
        assert_eq!(
            outcome,
            (2, 1, 1),
            "one v2 keyring, one audit row, and one directive consumption"
        );

        sqlx::query("DELETE FROM audit_log WHERE org_id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete lane waiter audit rows");
        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete lane waiter org");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete lane waiter user");
    }

    #[tokio::test]
    async fn owner_rotation_expired_exact_retry_stays_idempotent() {
        // The signed_at max-age is a first-use
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
        // org_keyrings.created_at must witness
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
    async fn put_keyring_response_returns_normalized_deployable_keyring() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-normalize-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring normalization org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Keyring Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert keyring normalization owner");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert keyring normalization membership");
        let key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert keyring normalization signing key");

        let mut request = signed_keyring_request(org_id, user_id, &key, 1, 1);
        // An otherwise-valid extra field: the typed parse ignores it, but the
        // 200 response must echo the normalized stored form, not the raw
        // request JSON, so the response is immediately deployable as an
        // org_keyring_blob under the strict envelope parser (#128 P2).
        request.keyring_payload["future_extension"] = serde_json::json!("must-not-echo");

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

        let (status, put_response) = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(request),
        )
        .await
        .expect("publish keyring carrying an extra field");
        assert_eq!(status, StatusCode::OK);
        assert!(
            put_response
                .keyring_payload
                .get("future_extension")
                .is_none(),
            "PUT response must not echo unknown request fields verbatim"
        );

        let stored_payload: Vec<u8> = sqlx::query_scalar(
            "SELECT keyring_payload FROM org_keyrings WHERE org_id = $1 AND version = 1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("load stored normalized keyring payload");
        let stored: serde_json::Value =
            serde_json::from_slice(&stored_payload).expect("decode stored keyring payload");
        assert_eq!(
            put_response.keyring_payload, stored,
            "PUT response payload must match the stored normalized bytes"
        );

        let get_response = get_keyring(auth.clone(), State(state.clone()), Path(org_name.clone()))
            .await
            .expect("GET keyring after PUT");
        assert_eq!(
            put_response.keyring_payload, get_response.keyring_payload,
            "PUT and GET responses must serve the identical normalized keyring"
        );

        let mut legacy = signed_keyring_request(org_id, user_id, &key, 2, 2);
        // Seed the verbatim payload written before normalization.
        legacy.keyring_payload["future_extension"] = serde_json::json!("legacy-extra");
        sqlx::query(
            "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, 2, $2, $3,
                     (SELECT id FROM user_signing_keys WHERE user_id = $4 AND pubkey = $5))",
        )
        .bind(org_id)
        .bind(serde_json::to_vec(&legacy.keyring_payload).expect("encode legacy payload"))
        .bind(hex::decode(&legacy.signature).expect("decode legacy signature"))
        .bind(user_id)
        .bind(key.verifying_key().to_bytes().to_vec())
        .execute(&pool)
        .await
        .expect("persist a keyring with the pre-normalization writer");
        let (status, _) = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(legacy),
        )
        .await
        .expect("normalization must preserve replay of an existing keyring");
        assert_eq!(status, StatusCode::OK);

        let legacy_get = get_keyring(auth, State(state), Path(org_name))
            .await
            .expect("GET keyring after legacy replay");
        assert_eq!(legacy_get.version, 2);
        assert!(
            legacy_get.keyring_payload.get("future_extension").is_none(),
            "GET must normalize legacy rows so org_keyring_blob wrapping stays deployable"
        );
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

    /// Regression (PR #185 review, Devin "concurrent upload leaves owner
    /// authority drifted"): rotate_org_owner pins the replacement in the
    /// signing service before it writes the successor keyring version and
    /// releases the lane between those phases. In that window an upload
    /// signed by the still-pinned owner must not be able to claim the
    /// successor version (409), while the identical request succeeds as
    /// soon as the service owner and the pinned owner agree again.
    #[tokio::test]
    async fn keyring_upload_fence_refuses_successor_while_service_owner_diverges() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        let org_name = format!("keyring-fence-{suffix}");
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert keyring fence org");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Fence Owner')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert fence owner");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert fence membership");
        let current_key = SigningKey::generate(&mut OsRng);
        let replacement_key = SigningKey::generate(&mut OsRng);
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(current_key.verifying_key().to_bytes().to_vec())
            .execute(&pool)
            .await
            .expect("insert fence signing key");

        let mut state = crate::test_support::lazy_state();
        state.db = pool.clone();
        // The interleave window: the signing service already holds the
        // replacement owner while CAP still pins the current owner on v1.
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, replacement_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build divergent mock signing service client"),
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
        .expect("insert v1 keyring");

        let successor = signed_keyring_request(org_id, user_id, &current_key, 2, 2);
        let fenced = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(successor),
        )
        .await
        .expect_err("the successor version must not be claimable while the service owner diverges");
        assert_eq!(fenced.0, StatusCode::CONFLICT);
        assert_eq!(
            fenced.1.0["error"],
            "signing service owner does not match the current pinned owner (owner rotation in progress)"
        );
        let counts_after_fence: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put')",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rows after fenced upload");
        assert_eq!(
            counts_after_fence,
            (1, 1),
            "the fenced upload must not mutate keyring or audit authority"
        );

        // Fail closed (self-check P1): an unreadable owner status is not
        // evidence of agreement. With a signing service configured but
        // unreachable, the successor insert must be refused with 502 and
        // still write nothing -- this is the exact inter-phase window where
        // the race re-opened in the fail-open variant of this fence.
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                "http://127.0.0.1:1".to_string(),
                None,
            )
            .expect("build unreachable mock signing service client"),
        );
        let closed = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 2, 2)),
        )
        .await
        .expect_err("an unreadable owner status must not clear the successor insert");
        assert_eq!(closed.0, StatusCode::BAD_GATEWAY);
        let counts_after_closed: (i64, i64) = sqlx::query_as(
            "SELECT
                 (SELECT count(*) FROM org_keyrings WHERE org_id = $1),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $1 AND action = 'org.keyring.put')",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rows after fail-closed upload");
        assert_eq!(
            counts_after_closed,
            (1, 1),
            "the fail-closed upload must not mutate keyring or audit authority"
        );

        // Positive control: once the service owner and the pinned owner
        // agree again, the identical successor request is accepted.
        state.signing_service = Some(
            crate::signing_service::SigningServiceClient::new(
                mock_signing_service_owner_api(org_id, current_key.verifying_key().to_bytes())
                    .await,
                None,
            )
            .expect("build aligned mock signing service client"),
        );
        let _ = put_keyring(
            auth.clone(),
            State(state.clone()),
            Path(org_name.clone()),
            Json(signed_keyring_request(org_id, user_id, &current_key, 2, 2)),
        )
        .await
        .expect("aligned service owner accepts the successor upload");
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
