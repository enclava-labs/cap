//! Central authorization helpers for org-scoped API routes.

use axum::{Json, http::StatusCode};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::auth::middleware::AuthContext;
use crate::models::Role;

pub type AuthzError = (StatusCode, Json<serde_json::Value>);
pub type AuthzResult<T = ()> = Result<T, AuthzError>;

fn error(status: StatusCode, message: impl Into<String>) -> AuthzError {
    (status, Json(serde_json::json!({ "error": message.into() })))
}

fn forbidden(message: impl Into<String>) -> AuthzError {
    error(StatusCode::FORBIDDEN, message)
}

fn database_error() -> AuthzError {
    error(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

pub fn require_member(_auth: &AuthContext) -> AuthzResult {
    Ok(())
}

pub fn require_admin(auth: &AuthContext) -> AuthzResult {
    require_admin_role(auth.role)
}

pub fn require_owner(auth: &AuthContext) -> AuthzResult {
    require_owner_role(auth.role)
}

pub fn require_scope(auth: &AuthContext, scope: &str) -> AuthzResult {
    if let Some(key) = &auth.api_key {
        crate::auth::api_key::require_scope(key, scope)
            .map_err(|_| forbidden(format!("API key scope required: {scope}")))?;
    }
    Ok(())
}

pub fn require_requested_api_key_scopes(
    auth: &AuthContext,
    requested_scopes: &[String],
) -> AuthzResult {
    require_admin(auth)?;
    require_scope(auth, "org:admin")?;
    if let Some(key) = &auth.api_key {
        for scope in requested_scopes {
            crate::auth::api_key::require_scope(key, scope)
                .map_err(|_| forbidden(format!("API key cannot grant scope it lacks: {scope}")))?;
        }
    }
    Ok(())
}

pub fn require_app_read(auth: &AuthContext) -> AuthzResult {
    require_scope(auth, "apps:read")
}

pub fn require_app_write(auth: &AuthContext) -> AuthzResult {
    require_admin(auth)?;
    require_scope(auth, "apps:write")
}

pub fn require_config_metadata_write(auth: &AuthContext) -> AuthzResult {
    require_admin(auth)?;
    require_scope(auth, "config:write")
}

pub fn require_admin_role(role: Role) -> AuthzResult {
    match role {
        Role::Owner | Role::Admin => Ok(()),
        Role::Member => Err(forbidden("admin role required")),
    }
}

pub fn require_owner_role(role: Role) -> AuthzResult {
    match role {
        Role::Owner => Ok(()),
        Role::Admin | Role::Member => Err(forbidden("owner role required")),
    }
}

pub fn parse_role(role: &str) -> AuthzResult<Role> {
    match role {
        "owner" => Ok(Role::Owner),
        "admin" => Ok(Role::Admin),
        "member" => Ok(Role::Member),
        _ => Err(error(StatusCode::BAD_REQUEST, "invalid role")),
    }
}

pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Owner => "owner",
        Role::Admin => "admin",
        Role::Member => "member",
    }
}

pub fn require_owner_to_modify_owner(
    caller_role: Role,
    current_role: Option<Role>,
    requested_role: Option<Role>,
) -> AuthzResult {
    let touches_owner = current_role == Some(Role::Owner) || requested_role == Some(Role::Owner);
    if touches_owner {
        require_owner_role(caller_role)?;
    }
    Ok(())
}

/// Lock active owner rows and verify the requested membership mutation leaves
/// at least one active owner in the organization.
pub async fn ensure_last_owner_invariant(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
    target_user_id: Uuid,
    target_role_after: Option<Role>,
) -> AuthzResult {
    let owners: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT user_id
         FROM memberships
         WHERE org_id = $1 AND role = 'owner' AND removed_at IS NULL
         FOR UPDATE",
    )
    .bind(org_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(|_| database_error())?;

    let remaining_owners = owners
        .iter()
        .filter(|(user_id,)| *user_id != target_user_id)
        .count()
        + usize::from(target_role_after == Some(Role::Owner));

    if remaining_owners == 0 {
        return Err(error(
            StatusCode::BAD_REQUEST,
            "organization must retain at least one owner",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::api_key::ValidatedApiKey;

    fn auth(role: Role, scopes: &[&str]) -> AuthContext {
        AuthContext {
            user_id: Uuid::nil(),
            org_id: Uuid::nil(),
            org_name: "org".to_string(),
            role,
            api_key: if scopes.is_empty() {
                None
            } else {
                Some(ValidatedApiKey {
                    id: Uuid::nil(),
                    org_id: Uuid::nil(),
                    created_by: Uuid::nil(),
                    scopes: scopes.iter().map(|s| s.to_string()).collect(),
                })
            },
        }
    }

    #[test]
    fn admin_cannot_grant_or_remove_owner_role() {
        assert!(
            require_owner_to_modify_owner(Role::Admin, Some(Role::Member), Some(Role::Owner))
                .is_err()
        );
        assert!(
            require_owner_to_modify_owner(Role::Admin, Some(Role::Owner), Some(Role::Admin))
                .is_err()
        );
        assert!(
            require_owner_to_modify_owner(Role::Owner, Some(Role::Admin), Some(Role::Owner))
                .is_ok()
        );
    }

    #[test]
    fn admin_can_modify_non_owner_roles() {
        assert!(
            require_owner_to_modify_owner(Role::Admin, Some(Role::Member), Some(Role::Admin))
                .is_ok()
        );
        assert!(require_admin_role(Role::Admin).is_ok());
        assert!(require_admin_role(Role::Owner).is_ok());
        assert!(require_admin_role(Role::Member).is_err());
    }

    #[test]
    fn api_key_scope_required_only_for_api_keys() {
        assert!(require_scope(&auth(Role::Admin, &[]), "apps:write").is_ok());
        assert!(require_scope(&auth(Role::Admin, &["apps:write"]), "apps:write").is_ok());
        assert!(require_scope(&auth(Role::Admin, &["apps:read"]), "apps:write").is_err());
    }

    #[test]
    fn api_key_creation_requires_admin_and_org_admin_scope() {
        let requested = vec!["apps:read".to_string()];

        assert!(require_requested_api_key_scopes(&auth(Role::Member, &[]), &requested).is_err());
        assert!(
            require_requested_api_key_scopes(&auth(Role::Admin, &["apps:read"]), &requested)
                .is_err()
        );
        assert!(
            require_requested_api_key_scopes(&auth(Role::Admin, &["org:admin"]), &requested)
                .is_err()
        );
        assert!(
            require_requested_api_key_scopes(
                &auth(Role::Admin, &["org:admin", "apps:read"]),
                &requested
            )
            .is_ok()
        );
        assert!(require_requested_api_key_scopes(&auth(Role::Admin, &[]), &requested).is_ok());
    }

    #[test]
    fn api_key_cannot_grant_scope_it_does_not_have() {
        let requested = vec!["apps:write".to_string()];
        assert!(
            require_requested_api_key_scopes(
                &auth(Role::Admin, &["org:admin", "apps:read"]),
                &requested
            )
            .is_err()
        );
    }

    #[test]
    fn app_write_requires_admin_role_and_apps_write_scope() {
        assert!(require_app_write(&auth(Role::Member, &[])).is_err());
        assert!(require_app_write(&auth(Role::Admin, &["apps:read"])).is_err());
        assert!(require_app_write(&auth(Role::Admin, &["apps:write"])).is_ok());
        assert!(require_app_write(&auth(Role::Owner, &[])).is_ok());
    }

    #[test]
    fn app_read_requires_apps_read_scope_for_api_keys() {
        assert!(require_app_read(&auth(Role::Member, &[])).is_ok());
        assert!(require_app_read(&auth(Role::Member, &["apps:read"])).is_ok());
        assert!(require_app_read(&auth(Role::Member, &["config:write"])).is_err());
    }

    #[test]
    fn config_metadata_write_requires_admin_and_config_write_scope() {
        assert!(require_config_metadata_write(&auth(Role::Member, &[])).is_err());
        assert!(require_config_metadata_write(&auth(Role::Admin, &["apps:write"])).is_err());
        assert!(require_config_metadata_write(&auth(Role::Admin, &["config:write"])).is_ok());
        assert!(require_config_metadata_write(&auth(Role::Owner, &[])).is_ok());
    }
}
