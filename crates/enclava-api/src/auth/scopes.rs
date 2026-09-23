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

/// Re-read an actor's active organization role while the caller holds the
/// organization authority lane that serializes the pending mutation.
///
/// Request authentication happens before potentially slow deployment and
/// signing validation. This check prevents a membership removal or demotion
/// that wins the authority lane from being overwritten by a stale request.
pub async fn active_membership_role_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
    user_id: Uuid,
) -> AuthzResult<Role> {
    sqlx::query_scalar(
        "SELECT role as \"role: _\"
           FROM memberships
          WHERE org_id = $1
            AND user_id = $2
            AND removed_at IS NULL",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|_| database_error())?
    .ok_or_else(|| forbidden("active organization membership required"))
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

/// Privileged-role membership changes (admin or owner) are owner-gated: an
/// admin must not promote another member to admin, change another admin's
/// role, or remove an existing admin — only owners manage privileged roles.
/// Admins keep full control over plain members.
///
/// Self-service exception: an admin targeting *themselves* with a
/// non-privileged requested role (demote-to-member via invite, or removal)
/// is allowed. Such a change only ever lowers the caller's own privileges,
/// so it cannot escalate anything; it exists so an admin is never trapped
/// in the role when no owner is available. Granting or keeping a privileged
/// role — even to oneself — still requires an owner. The exemption requires
/// the caller's in-transaction role read AND the FOR UPDATE-locked target
/// row to both say admin, so a stale admin read against a concurrently
/// promoted-to-owner row fails closed into the owner gate.
pub fn require_owner_to_modify_privileged_role(
    caller_role: Role,
    current_role: Option<Role>,
    requested_role: Option<Role>,
    target_is_caller: bool,
) -> AuthzResult {
    let touches_privileged = current_role.is_some_and(is_privileged_role)
        || requested_role.is_some_and(is_privileged_role);
    let self_release = target_is_caller
        && matches!(caller_role, Role::Admin)
        && current_role == Some(Role::Admin)
        && !requested_role.is_some_and(is_privileged_role);
    if touches_privileged && !self_release && !matches!(caller_role, Role::Owner) {
        return Err(forbidden(
            "only owners can grant, change, or remove admin and owner roles",
        ));
    }
    Ok(())
}

fn is_privileged_role(role: Role) -> bool {
    matches!(role, Role::Owner | Role::Admin)
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
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
        }
    }

    #[test]
    fn admin_cannot_grant_or_remove_owner_role() {
        // Granting the owner role.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Member),
                Some(Role::Owner),
                false
            )
            .is_err()
        );
        // Changing an existing owner's role.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Owner),
                Some(Role::Admin),
                false
            )
            .is_err()
        );
        // Removing an owner.
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, Some(Role::Owner), None, false)
                .is_err()
        );
        // Owner-to-owner changes remain owner-gated but allowed for owners.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Owner,
                Some(Role::Admin),
                Some(Role::Owner),
                false
            )
            .is_ok()
        );
    }

    #[test]
    fn admin_cannot_promote_demote_or_remove_admins() {
        // Promoting a member to admin.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Member),
                Some(Role::Admin),
                false
            )
            .is_err()
        );
        // Changing an existing admin's role (demotion or re-invite as admin).
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Member),
                false
            )
            .is_err()
        );
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Admin),
                false
            )
            .is_err()
        );
        // Removing an existing admin (no requested role).
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, Some(Role::Admin), None, false)
                .is_err()
        );
        // Inviting a brand-new admin (no current role).
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, None, Some(Role::Admin), false)
                .is_err()
        );
        // Owner changes touching admins are allowed.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Owner,
                Some(Role::Member),
                Some(Role::Admin),
                false
            )
            .is_ok()
        );
        assert!(
            require_owner_to_modify_privileged_role(Role::Owner, Some(Role::Admin), None, false)
                .is_ok()
        );
    }

    #[test]
    fn admin_can_modify_plain_members() {
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Member),
                Some(Role::Member),
                false
            )
            .is_ok()
        );
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, Some(Role::Member), None, false)
                .is_ok()
        );
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, None, Some(Role::Member), false)
                .is_ok()
        );
        assert!(require_admin_role(Role::Admin).is_ok());
        assert!(require_admin_role(Role::Owner).is_ok());
        assert!(require_admin_role(Role::Member).is_err());
    }

    #[test]
    fn self_service_admin_release_is_allowed_but_self_promotion_is_not() {
        // Admin demoting themselves to member via re-invite: allowed.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Member),
                true
            )
            .is_ok()
        );
        // Admin removing themselves: allowed.
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, Some(Role::Admin), None, true)
                .is_ok()
        );
        // Admin re-inviting themselves as admin (keeping the role): still owner-gated.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Admin),
                true
            )
            .is_err()
        );
        // Admin promoting themselves to owner or admin: still owner-gated.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Member),
                Some(Role::Admin),
                true
            )
            .is_err()
        );
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Owner),
                true
            )
            .is_err()
        );
        // The exemption never applies when targeting someone else.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Admin),
                Some(Role::Member),
                false
            )
            .is_err()
        );
        // Stale-read hardening: a stale admin caller-role read paired with a
        // target row that has since been promoted to owner fails closed into
        // the owner gate instead of waiving it.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Owner),
                Some(Role::Member),
                true
            )
            .is_err()
        );
        assert!(
            require_owner_to_modify_privileged_role(Role::Admin, Some(Role::Owner), None, true)
                .is_err()
        );
        // A member self-targeting never passes either: member rows do not
        // touch privileged roles (no gate), but a stale admin read paired
        // with a demoted-to-member row must not resurrect the exemption.
        assert!(
            require_owner_to_modify_privileged_role(
                Role::Admin,
                Some(Role::Member),
                Some(Role::Member),
                true
            )
            .is_ok()
        );
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
