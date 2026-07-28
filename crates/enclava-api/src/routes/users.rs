use axum::{Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::state::AppState;

#[derive(Debug, Clone, Serialize)]
pub struct CurrentUserOrg {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub role: String,
    pub is_personal: bool,
    pub entitlement_class: String,
    pub deploy_allowed: bool,
    pub deploy_block_reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CurrentUserResponse {
    pub user_id: Uuid,
    pub display_name: String,
    pub active_org: CurrentUserOrg,
    pub orgs: Vec<CurrentUserOrg>,
}

/// GET /users/me
pub async fn current_user(
    auth: AuthContext,
    State(state): State<AppState>,
) -> Result<Json<CurrentUserResponse>, (StatusCode, Json<serde_json::Value>)> {
    let display_name: String = sqlx::query_scalar("SELECT display_name FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|_| db_error())?
        .ok_or((
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "user not found"})),
        ))?;

    let api_key_org = auth.api_key.as_ref().map(|_| auth.org_id);
    let rows: Vec<(
        Uuid,
        String,
        Option<String>,
        crate::models::Role,
        bool,
        String,
    )> = sqlx::query_as(
        "SELECT o.id, o.name, o.display_name, m.role as \"role: _\", o.is_personal, o.entitlement_class
         FROM organizations o
         JOIN memberships m ON m.org_id = o.id
         WHERE m.user_id = $1
           AND m.removed_at IS NULL
           AND ($2::uuid IS NULL OR o.id = $2)
         ORDER BY o.is_personal DESC, o.name",
    )
    .bind(auth.user_id)
    .bind(api_key_org)
    .fetch_all(&state.db)
    .await
    .map_err(|_| db_error())?;

    let mut orgs: Vec<CurrentUserOrg> = Vec::with_capacity(rows.len());
    for (id, name, display_name, role, is_personal, entitlement_class) in rows {
        let decision =
            crate::entitlements::entitlement_decision_for_org(&state.db, id, &entitlement_class)
                .await
                .map_err(|_| db_error())?;
        orgs.push(CurrentUserOrg {
            id,
            name,
            display_name,
            role: format!("{role:?}").to_lowercase(),
            is_personal,
            entitlement_class,
            deploy_allowed: decision.deploy_allowed,
            deploy_block_reason: decision.deploy_block_reason,
        });
    }

    let active_org = orgs
        .iter()
        .find(|org| org.id == auth.org_id)
        .cloned()
        .unwrap_or(CurrentUserOrg {
            id: auth.org_id,
            name: auth.org_name.clone(),
            display_name: None,
            role: format!("{:?}", auth.role).to_lowercase(),
            is_personal: false,
            entitlement_class: "unknown".to_string(),
            deploy_allowed: false,
            deploy_block_reason: Some("org_membership_not_found".to_string()),
        });

    Ok(Json(CurrentUserResponse {
        user_id: auth.user_id,
        display_name,
        active_org,
        orgs,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RegisterPublicKeyRequest {
    pub public_key: String,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RegisterPublicKeyResponse {
    pub id: Uuid,
    pub public_key: String,
}

pub async fn register_public_key(
    auth: AuthContext,
    State(state): State<AppState>,
    Json(body): Json<RegisterPublicKeyRequest>,
) -> Result<(StatusCode, Json<RegisterPublicKeyResponse>), (StatusCode, Json<serde_json::Value>)> {
    crate::routes::deployments::require_workload_mutations_enabled(&state)?;
    let pubkey = decode_hex32(&body.public_key)?;
    let id = Uuid::new_v4();
    let row: (Uuid, Vec<u8>) = sqlx::query_as(
        "INSERT INTO user_signing_keys (id, user_id, pubkey)
         VALUES ($1, $2, $3)
         ON CONFLICT (user_id, pubkey) WHERE revoked_at IS NULL
         DO UPDATE SET pubkey = EXCLUDED.pubkey
         RETURNING id, pubkey",
    )
    .bind(id)
    .bind(auth.user_id)
    .bind(pubkey.to_vec())
    .fetch_one(&state.db)
    .await
    .map_err(|_| db_error())?;

    let _ = sqlx::query(
        "INSERT INTO audit_log (user_id, action, detail)
         VALUES ($1, 'user.public_key.register', $2)",
    )
    .bind(auth.user_id)
    .bind(serde_json::json!({
        "key_id": row.0,
        "label": body.label,
        "public_key": hex::encode(&row.1),
    }))
    .execute(&state.db)
    .await;

    Ok((
        StatusCode::OK,
        Json(RegisterPublicKeyResponse {
            id: row.0,
            public_key: hex::encode(row.1),
        }),
    ))
}

fn decode_hex32(value: &str) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    let bytes = hex::decode(value.trim()).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "public_key must be lowercase hex"})),
        )
    })?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "public_key must decode to 32 bytes",
                "got": bytes.len()
            })),
        )
    })
}

fn db_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"error": "database error"})),
    )
}
