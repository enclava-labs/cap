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
///
/// The memberships row is locked with `FOR UPDATE` so the read role is held
/// stable until the caller's transaction commits: a concurrent demotion or
/// removal blocks on the row lock instead of committing between this read and
/// the caller's commit.
///
/// # Precondition (deadlock safety)
///
/// Deadlock safety relies on lane discipline rather than on this function.
/// PRECONDITION: every caller must already hold the organization entitlement
/// lane or the signing authority lane before calling this function, and every
/// memberships writer must acquire those lanes before touching the row, so
/// the row lock can only queue behind a lane-ordered mutation, never cycle
/// with it. A call site that skips the lane silently reintroduces cycle risk
/// (see review of #174): if you see `lock_and_read_` on a path that does not
/// hold a lane, that is a bug.
pub async fn lock_and_read_active_membership_role_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
    user_id: Uuid,
) -> AuthzResult<Role> {
    sqlx::query_scalar(
        "SELECT role as \"role: _\"
           FROM memberships
          WHERE org_id = $1
            AND user_id = $2
            AND removed_at IS NULL
          FOR UPDATE",
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
            management_origin: crate::auth::middleware::ManagementOrigin::Public,
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

    async fn scopes_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect membership role lock regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate membership role lock regression database");
        pool
    }

    /// Regression test for #131: the in-transaction membership role read must
    /// hold a row lock, so a concurrent demotion cannot commit between the
    /// role check and the caller's commit.
    #[tokio::test]
    async fn active_membership_role_read_blocks_concurrent_demotion() {
        let pool = scopes_test_pool().await;
        let org_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
            .bind(org_id)
            .bind(format!("role-lock-{suffix}"))
            .bind(&suffix[..8])
            .execute(&pool)
            .await
            .expect("insert role lock test organization");
        sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Role Lock Admin')")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("insert role lock test user");
        sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'admin')")
            .bind(user_id)
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("insert role lock test membership");

        // The mutating route's transaction: read (and lock) the actor's role.
        let mut reader = pool.begin().await.expect("begin role lock reader");
        let role = lock_and_read_active_membership_role_in_tx(&mut reader, org_id, user_id)
            .await
            .expect("read active membership role under row lock");
        assert_eq!(role, Role::Admin);

        // A concurrent demotion of the same member must block on the row
        // lock instead of committing while the reader still sees admin.
        // The demoter publishes its backend pid so the lock-wait check below
        // cannot false-positive on an unrelated backend in the shared test
        // database.
        let demoter_pool = pool.clone();
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let demotion = tokio::spawn(async move {
            let mut tx = demoter_pool
                .begin()
                .await
                .expect("begin concurrent demotion");
            let demoter_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .expect("concurrent demotion backend pid");
            pid_sender.send(demoter_pid).expect("send demoter pid");
            sqlx::query(
                "UPDATE memberships
                    SET role = 'member'
                  WHERE org_id = $1 AND user_id = $2 AND removed_at IS NULL",
            )
            .bind(org_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .expect("stage concurrent demotion");
            tx.commit().await.expect("commit concurrent demotion");
        });

        // The demotion's UPDATE must be waiting on the reader's row lock.
        // Without FOR UPDATE in lock_and_read_active_membership_role_in_tx the UPDATE would
        // commit immediately and this backend would never sit in Lock wait.
        let demoter_pid = pid_receiver.await.expect("receive demoter pid");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let demotion_blocked: bool = sqlx::query_scalar(
                    "SELECT COALESCE((
                         SELECT wait_event_type = 'Lock'
                           FROM pg_stat_activity
                          WHERE pid = $1), false)",
                )
                .bind(demoter_pid)
                .fetch_one(&pool)
                .await
                .expect("inspect concurrent demotion lock state");
                if demotion_blocked {
                    return;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("concurrent demotion must block on the locked membership row");

        // Releasing the reader lets the demotion finish.
        reader.rollback().await.expect("roll back role lock reader");
        demotion.await.expect("join concurrent demotion");

        let final_role: Option<String> = sqlx::query_scalar(
            "SELECT role::text FROM memberships WHERE org_id = $1 AND user_id = $2",
        )
        .bind(org_id)
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("read final membership role");
        assert_eq!(final_role.as_deref(), Some("member"));

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete role lock test organization");
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("delete role lock test user");
    }
}
