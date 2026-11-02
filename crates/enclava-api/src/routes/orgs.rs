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
/// to re-parse as jsonb (migration 0061's shape CHECK, and the candidate
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

    // Re-read the latest keyring only after acquiring the shared
    // signing-authority lane. Rotation and signed acceptance therefore
    // linearize on one exact owner authority generation.
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
    } else {
        // Migration 0061 quarantines a malformed CURRENT keyring by dropping
        // every keyring row of the org while the signing service's owner
        // registration stays live. A marker row records that this first
        // version restores quarantined authority instead of initializing a
        // fresh org, and the replacement signer must match the live
        // signing-service owner -- or, when no live owner is readable, the
        // quarantined signing owner archived in org_keyring_repairs --
        // before authority is restored (review finding: without this gate
        // the unrestricted first-version path accepts any active org owner's
        // registered key -- bypassing the current owner's cryptographic
        // authorization, or leaving CAP pinned to a different owner than
        // the signing service and blocking future signing and rotation).
        let recovery_marker: Option<i64> = sqlx::query_scalar(
            "SELECT quarantined_latest_version FROM org_keyring_shape_recoveries WHERE org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|_| db_error())?;
        if let Some(quarantined_latest_version) = recovery_marker {
            fence_quarantined_keyring_recovery(
                &state,
                &mut tx,
                org_id,
                quarantined_latest_version,
                &signing_pubkey,
            )
            .await?;
            // Consume the marker before the insert. Migration 0085's BEFORE
            // INSERT trigger rejects any keyring write while the marker
            // remains, so a pre-0085 binary cannot re-insert the replacement
            // this migration just removed. The delete is in this transaction:
            // a failed insert rolls the marker back, and only a recovery that
            // passed the displaced-signer check reaches the insert.
            sqlx::query("DELETE FROM org_keyring_shape_recoveries WHERE org_id = $1")
                .bind(org_id)
                .execute(&mut *tx)
                .await
                .map_err(|_| db_error())?;
        }
    }

    if insert_new_version {
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
        // migration 0061's INSERT trigger (durable selector debt) and
        // consumed only after the filtered policy body is published, never
        // bumped directly here.
    }

    tx.commit().await.map_err(|_| db_error())?;
    confirm_keyring_kbs_publication(&state).await?;

    let fingerprint = hex::encode(Sha256::digest(&canonical_bytes));
    // Answer with the stored envelope's encoding (lowercase hex of the
    // decoded bytes), never a byte-for-byte echo of the submitted casing:
    // a semantically identical replay must read back exactly like GET.
    Ok((
        StatusCode::OK,
        Json(OrgKeyringResponse {
            org_id,
            version: body.version,
            keyring_payload: normalized_keyring_payload,
            signature: hex::encode(&signature),
            signing_pubkey: hex::encode(&signing_pubkey),
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
/// version-recency bound. Pre-0065 rows keep legacy transaction-start
/// created_at semantics, so their stored timestamp is floored at the
/// watermark recorded when 0065 committed.
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
        // checked_sub/checked_add (PR #185 review, Devin "maximum keyring
        // version overflows rotation"): the version space has an i64
        // ceiling, and unclipped arithmetic here panicked on overflow
        // instead of returning a version error.
        let previous: Option<(Vec<u8>, Vec<u8>)> = match body_version.checked_sub(1) {
            Some(previous_version) => sqlx::query_as(
                "SELECT ok.keyring_payload, usk.pubkey
                   FROM org_keyrings ok
                   JOIN user_signing_keys usk ON usk.id = ok.signing_key_id
                  WHERE ok.org_id = $1 AND ok.version = $2",
            )
            .bind(org_id)
            .bind(previous_version)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| db_error())?,
            None => None,
        };
        Ok(previous.map(|(payload, owner)| (payload, owner, false)))
    } else if Some(body_version) == latest.0.checked_add(1) {
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

/// Read the signing service's live owner for `org_id`, strictly after the
/// signing-authority lane is acquired (queue time behind other lane writers
/// can outlast any freshness window). Returns `None` when the service holds
/// no owner registration for this org. Missing or unreadable authority fails
/// closed: a prior rotation may have changed upstream authority without a CAP
/// commit, and without a configured service only recorded rotation history
/// proves that upstream authority ever existed.
async fn read_fence_service_owner(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
) -> Result<Option<Vec<u8>>, (StatusCode, Json<serde_json::Value>)> {
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
        return Ok(None);
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
    owner_status
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
        })
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
    let service_owner = read_fence_service_owner(state, tx, org_id).await?;
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

/// Quarantine recovery (quarantine in migration 0061, marker in migration
/// 0085) restores dropped authority through
/// the first-version path, which has no pinned predecessor whose signature
/// could authorize the replacement. The quarantine removed every keyring row
/// of the org but left the signing service's owner registration live, so an
/// unrestricted first-version accept would either bypass that owner's
/// cryptographic authorization or pin CAP to a different owner than the
/// signing service -- blocking future signing and rotation. Require the
/// replacement v1 signer to match the live signing-service owner before
/// authority is restored. When no live owner is readable, bind the recovery
/// to the displaced signer instead: migration 0061 archived every dropped
/// row in `org_keyring_repairs` and migration 0085 wrote the recovery
/// marker from that archive, so the
/// signer of the quarantined latest version is durable provenance, and
/// `put_keyring` already verifies the replacement envelope under the
/// caller's own registered key -- a matching signer means the displaced
/// owner signed the replacement (review finding: accepting any active
/// owner's key here let a different owner replace the quarantined keyring
/// without the previously authorized owner's signature). Unresolvable
/// provenance fails closed instead of falling back to a genuine first
/// upload: a genuine first upload has no recovery marker and never reaches
/// this fence. Recorded rotation history without a configured service still
/// fails closed inside `read_fence_service_owner`, because that history
/// proves upstream authority existed and cannot be read now.
async fn fence_quarantined_keyring_recovery(
    state: &AppState,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    org_id: Uuid,
    quarantined_latest_version: i64,
    replacement_signer: &[u8],
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let service_owner = read_fence_service_owner(state, tx, org_id).await?;
    if let Some(owner) = service_owner {
        if owner.as_slice() != replacement_signer {
            return Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": "quarantined keyring recovery signer does not match the live signing-service owner"
                })),
            ));
        }
        return Ok(());
    }
    let displaced_signer: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT usk.pubkey
           FROM org_keyring_repairs okr
           JOIN user_signing_keys usk ON usk.id = okr.signing_key_id
          WHERE okr.org_id = $1 AND okr.version = $2",
    )
    .bind(org_id)
    .bind(quarantined_latest_version)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| db_error())?;
    let Some(displaced_signer) = displaced_signer else {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "quarantined keyring recovery provenance is unavailable"
            })),
        ));
    };
    if displaced_signer.as_slice() != replacement_signer {
        return Err((
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": "quarantined keyring recovery signer does not match the quarantined signing owner"
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
///
/// Presentation rows (`org_rotation_intents`) never satisfy this query: an
/// intent is proof of presentation only, never of execution. (The historical
/// SQL comment in migration `0064` describes the superseded intent-row
/// waiver; that file is byte-frozen because sqlx checksums applied migration
/// bytes — see `DEPLOYMENT.md` for the current semantics.)
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

/// Advisory-lock domain for the per-org rotation-intent quota lock
/// ("RINT"). Deliberately disjoint from `ORG_SIGNING_AUTHORITY_LANE_DOMAIN`
/// ("SIGN") and `PAAS_USER_MAPPING_LANE_DOMAIN` ("PUSE"): the intent row is
/// recorded BEFORE the signing-authority lane opens, and sharing a domain
/// would make unrelated writers serialize on each other.
const ORG_ROTATION_INTENT_LANE_DOMAIN: i32 = 0x5249_4e54;

/// Distinct directive presentations accepted per org per rolling hour.
/// `org_rotation_intents` has no purge path, so this bounds storage growth
/// from a compromised owner key.
const MAX_INTENTS_PER_HOUR: i64 = 50;

/// Records one verified rotation presentation under the per-org hourly cap.
/// `created_at` is `statement_timestamp()` (the post-lock statement), not the
/// column default `now()` (transaction start): a writer queued on the
/// advisory lock must not stamp the row early and leave the rolling-hour
/// count early. Shared with the regression that executes this statement
/// against real PostgreSQL, so the stamp cannot drift from the handler.
const ORG_ROTATION_INTENT_INSERT_SQL: &str =
    "INSERT INTO org_rotation_intents (org_id, directive_sha256, keyring_sha256, created_at)
         SELECT $1, $2, $3, statement_timestamp()
          WHERE NOT EXISTS (
                SELECT 1 FROM org_rotation_intents
                 WHERE org_id = $1 AND directive_sha256 = $2 AND keyring_sha256 = $3
          )
            AND (SELECT count(*) FROM org_rotation_intents
                  WHERE org_id = $1 AND created_at > statement_timestamp() - interval '1 hour')
                < $4
         ON CONFLICT DO NOTHING";

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
    // receipt (org_rotation_upstream_receipts, migration 0066) proves this
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

    // Preliminary validity checks (PR #185, Codex P2 "reject invalid
    // directives before persisting their intents"): the intent insert below
    // commits before any lane validation runs, and org_rotation_intents has
    // no purge path, so a rejected request used to leave a durable row
    // behind -- a compromised owner key could grow the database without
    // completing any rotation. Only checks whose verdicts cannot flip while
    // queueing for the signing-authority lane are safe here; anything
    // race-sensitive (missing keyring, version too high -- both can be
    // legalized by a concurrent commit before the lane is acquired) stays
    // post-lane and authoritative.
    //
    // Two accepted tradeoffs of this fail-closed posture (documented after
    // review; identical to #185, whose contract this branch keeps):
    // 1. A directive signed more than PRECHECK_CLOCK_SKEW_SECONDS into the
    //    future is rejected at presentation even if the request could queue
    //    until the timestamp becomes valid. Honest client clocks sit well
    //    inside the 300s allowance; a timestamp beyond it violates the
    //    signing contract, the rejection is deterministic, and the lane
    //    re-checks authoritatively for anything that reaches it.
    // 2. An expired retry that overlaps the commit of its matching receipt
    //    (a concurrent in-flight first presentation) can be rejected here
    //    before the receipt row exists. Receipts are never deleted, so the
    //    idempotent retry after that commit hits the receipted-expired
    //    waiver and recovers through the lane.
    {
        let precheck_now = Utc::now();
        // The lane reads its clock after queueing, which can outlast any
        // window captured here, so both bounds carry a skew allowance:
        // only directives that no realistic clock skew plus queue delay
        // could legitimize are rejected pre-lane (enclava-api and
        // PostgreSQL run on different hosts).
        const PRECHECK_CLOCK_SKEW_SECONDS: i64 = 300;
        if body.signed_at > precheck_now + chrono::Duration::seconds(PRECHECK_CLOCK_SKEW_SECONDS) {
            return Err(bad_request(
                "owner rotation directive signed_at is in the future",
            ));
        }
        // Versions only ever increment, so a body.version strictly below
        // the current latest can never become an exact replay or a legal
        // successor. The created_at floor is re-read at the lane; it is
        // not stable enough to reject here, because a directive captured
        // during a queued insert can still clear a transaction-start stamp.
        let latest_version: Option<i64> =
            sqlx::query_scalar("SELECT max(version) FROM org_keyrings WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&state.db)
                .await
                .map_err(|_| db_error())?;
        if let Some(latest_version) = latest_version {
            if body.version <= latest_version {
                // Same-version requests are idempotent replays whose
                // freshness the lane deliberately does not bound; only
                // strictly-below versions are stable-rejectable.
                if body.version < latest_version {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(serde_json::json!({
                            "error": "keyring version is stale"
                        })),
                    ));
                }
            } else if body.signed_at
                < precheck_now
                    - chrono::Duration::seconds(
                        MAX_DIRECTIVE_AGE_SECONDS + PRECHECK_CLOCK_SKEW_SECONDS,
                    )
            {
                // New-version path. An expired directive with no committed
                // receipt for these exact digests cannot be waived at the
                // lane either, and receipts are never deleted, so the
                // verdict is stable. Skew allowance in both directions.
                let receipted: Option<i32> = sqlx::query_scalar(
                    "SELECT 1 FROM org_rotation_upstream_receipts
                      WHERE org_id = $1 AND directive_sha256 = $2 AND keyring_sha256 = $3",
                )
                .bind(org_id)
                .bind(directive_digest.as_slice())
                .bind(intent_digest.as_slice())
                .fetch_optional(&state.db)
                .await
                .map_err(|_| db_error())?;
                if receipted.is_none() {
                    return Err(bad_request("owner rotation directive signed_at is too old"));
                }
            }
        }
    }

    let signing_service = state.signing_service.as_ref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"error": "platform signing service is not configured"})),
    ))?;

    // Durable presentation record (migration 0064), committed on its own
    // short-lived connection BEFORE the lane transaction opens: with the
    // pool capped, waiting on a second connection while holding the lane
    // transaction's connection could starve the whole cluster. The row
    // records that an authenticated, signature-verified presentation
    // reached this handler; it authorizes nothing by itself.
    //
    // Rate bound (PR #185 review, Codex follow-ups "serialize the per-org
    // rotation-intent rate limit" and "acquire the per-org intent lock
    // before checking the quota"): concurrent writers serialize on a
    // per-org advisory lock held across the count/insert. The lock must be
    // acquired as its OWN statement in a short explicit transaction, with
    // the count/insert as a subsequent statement: PostgreSQL never
    // evaluates an unreferenced `WITH org_lock AS (...)` CTE (the first
    // attempt therefore acquired no lock at all), and even a referenced
    // CTE could not help -- a READ COMMITTED statement snapshot is fixed
    // at statement start, so the count would still miss rows committed by
    // a previous lock holder mid-statement. Locking first and counting in
    // a later statement gives the count a post-lock snapshot, so the
    // hourly cap holds under concurrent bursts. The lock is
    // transaction-scoped (released at commit) and no other lock is taken
    // in this transaction, so it cannot deadlock against the lane. The
    // whole record stays on ONE pooled connection, preserving the
    // short-lived-connection property the comment above requires.
    //
    // The rolling-hour clock is sampled in the post-lock statement rather
    // than at transaction start, so time waiting for the lock is excluded.
    // The inserted row's created_at is that same statement_timestamp():
    // the column default now() is transaction_timestamp (BEGIN), so a
    // writer that waited on the lock would otherwise record an intent that
    // leaves the rolling-hour count early.
    //
    // Concurrent-insert handling (Codex follow-up "handle concurrent inserts
    // of the same rotation intent"): ON CONFLICT DO NOTHING makes the PK
    // violation from a race between two identical requests return 0 rows
    // instead of throwing an error, then the already_recorded check allows
    // the retry to proceed.
    let mut intent_tx = state.db.begin().await.map_err(|_| db_error())?;
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(ORG_ROTATION_INTENT_LANE_DOMAIN)
        .bind(crate::signing_service::org_signing_advisory_key(org_id))
        .execute(&mut *intent_tx)
        .await
        .map_err(|_| db_error())?;
    let intent_rows = sqlx::query(ORG_ROTATION_INTENT_INSERT_SQL)
        .bind(org_id)
        .bind(directive_digest.as_slice())
        .bind(intent_digest.as_slice())
        .bind(MAX_INTENTS_PER_HOUR)
        .execute(&mut *intent_tx)
        .await
        .map_err(|_| db_error())?
        .rows_affected();
    // Distinguish the rate cap (reject) from the exact-replay case (already
    // recorded; proceed -- the lane remains authoritative). Checked inside
    // the same locked transaction: no other intent writer can commit
    // between the insert attempt and this verdict.
    let mut already_recorded = false;
    if intent_rows == 0 {
        already_recorded = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT 1 FROM org_rotation_intents
                 WHERE org_id = $1 AND directive_sha256 = $2 AND keyring_sha256 = $3
            )",
        )
        .bind(org_id)
        .bind(directive_digest.as_slice())
        .bind(intent_digest.as_slice())
        .fetch_one(&mut *intent_tx)
        .await
        .map_err(|_| db_error())?;
    }
    intent_tx.commit().await.map_err(|_| db_error())?;
    if intent_rows == 0 && !already_recorded {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({
                "error": "owner rotation directive rate limit exceeded; retry later"
            })),
        ));
    }

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
    // keyring, service owner, and freshness are re-read and re-derived here.
    // Recheck and lock the caller's current membership before committing any
    // successor keyring. A removal committed during the lane gap must win;
    // a removal racing this lock waits until finalization commits. If the
    // upstream owner already changed, the durable receipt lets a remaining
    // owner recover the exact transition instead of granting a removed owner
    // continued signing authority. This phase never issues an upstream RPC (at most
    // one per request, spent or deliberately skipped in phase 1): the
    // service must already hold the replacement owner before any CAP
    // write, so the stored keyring authority and the service stay pinned
    // to the same owner.
    let mut tx = state.db.begin().await.map_err(|_| db_error())?;
    let lane_now = crate::signing_service::lock_org_signing_authority_lane_now(&mut tx, org_id)
        .await
        .map_err(|_| db_error())?;
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
    let current_role =
        scopes::lock_and_read_active_membership_role_in_tx(&mut tx, org_id, auth.user_id).await?;
    scopes::require_owner_role(current_role)?;
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

    let invitee: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM user_identities WHERE provider = 'email' AND identifier = $1",
    )
    .bind(&body.email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| db_error())?;

    // Anti-enumeration (issue #121): a bad role fails identically for
    // known and unknown emails (the lookup result is only consumed after
    // parse_role), and the unknown-invitee path performs the same reads
    // up to the membership SELECT (lane locks, caller role read, invitee
    // membership read). It must not return a success-shaped response: a
    // fake 200 would both lie to the caller (CLI prints "Invited ...")
    // and re-open the oracle via GET /orgs/{name}/members, where a real
    // invite adds a visible row and this one would not.
    //
    // RESIDUAL RISKS (accepted, like the signup 201-vs-400 split; fully
    // closing them needs a pending-invite model — invite token emailed
    // to the address, membership only on accept — a product change with
    // a new table, out of scope for this fix):
    // - status split: a successful invite returns 200 while an unknown
    //   email returns the generic 403 "invite not permitted" below;
    // - body split for admin callers: an admin inviting role "member"
    //   gets "invite not permitted" for an unknown email, but the
    //   owner-gate 403 ("only owners can grant, change, or remove admin
    //   and owner roles") when the target is an existing admin/owner;
    // - sole-owner demotion of a KNOWN owner can return 400 ("organization
    //   must retain at least one owner"), which an unknown email never
    //   triggers;
    // - timing is not uniform: the unknown path ends in a rollback while
    //   a real invite INSERTs and commits.
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

    // Both paths read the membership row for the invitee id (the nil UUID
    // for an unknown email matches no row), so the reads up to this point
    // are the same; a real invite additionally INSERTs and commits while
    // the unknown path rolls back (see the residual-risk note above).
    let invitee_id = invitee.map(|(id,)| id).unwrap_or_else(Uuid::nil);
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

    // Unknown email: generic 403 (see residual-risk note above for what
    // this still reveals).
    if invitee.is_none() {
        tx.rollback().await.map_err(|_| db_error())?;
        return Err((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "invite not permitted"})),
        ));
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
mod tests;
