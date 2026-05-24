use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::provider::VerifiedIdentity;

#[derive(Debug, thiserror::Error)]
pub enum EmailAuthError {
    #[error("email is required")]
    EmailRequired,
    #[error("password is required")]
    PasswordRequired,
    #[error("email already registered")]
    EmailExists,
    #[error("invalid email or password")]
    InvalidCredentials,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("password hashing error: {0}")]
    Hash(String),
}

/// Hash a password with argon2id.
pub fn hash_password(password: &str) -> Result<String, EmailAuthError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| EmailAuthError::Hash(e.to_string()))
}

/// Verify a password against an argon2id hash.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, EmailAuthError> {
    let parsed = PasswordHash::new(hash).map_err(|e| EmailAuthError::Hash(e.to_string()))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Register a new user with email + password. Creates user, identity, personal org, and membership.
/// Returns (user_id, org_id).
pub async fn signup(
    pool: &PgPool,
    email: &str,
    password: &str,
    display_name: Option<&str>,
) -> Result<(Uuid, Uuid), EmailAuthError> {
    if email.is_empty() {
        return Err(EmailAuthError::EmailRequired);
    }
    if password.is_empty() {
        return Err(EmailAuthError::PasswordRequired);
    }

    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM user_identities WHERE provider = 'email' AND identifier = $1)",
    )
    .bind(email)
    .fetch_one(pool)
    .await?;

    if exists {
        return Err(EmailAuthError::EmailExists);
    }

    let credential_hash = hash_password(password)?;
    let user_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();

    let name = display_name.unwrap_or_else(|| email.split('@').next().unwrap_or("user"));
    // Sanitize org name: lowercase, replace non-alphanumeric with hyphens
    let org_name = format!(
        "{}-{}",
        name.to_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>(),
        &user_id.to_string()[..8]
    );

    let mut tx = pool.begin().await?;

    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, $2)")
        .bind(user_id)
        .bind(name)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO user_identities (id, user_id, provider, identifier, credential_hash, is_primary, verified_at)
         VALUES ($1, $2, 'email', $3, $4, true, now())",
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(email)
    .bind(&credential_hash)
    .execute(&mut *tx)
    .await?;

    crate::db::orgs::insert_org_conn(&mut tx, org_id, &org_name, Some(name), true).await?;

    sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok((user_id, org_id))
}

/// Verify email + password and return the verified identity.
pub async fn login(
    pool: &PgPool,
    email: &str,
    password: &str,
) -> Result<VerifiedIdentity, EmailAuthError> {
    if email.is_empty() {
        return Err(EmailAuthError::EmailRequired);
    }
    if password.is_empty() {
        return Err(EmailAuthError::PasswordRequired);
    }

    let row: Option<(Uuid, String, Option<String>)> = sqlx::query_as(
        "SELECT ui.user_id, ui.credential_hash, u.display_name
         FROM user_identities ui
         JOIN users u ON u.id = ui.user_id
         WHERE ui.provider = 'email' AND ui.identifier = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    let (_user_id, hash_str, display_name) = row.ok_or(EmailAuthError::InvalidCredentials)?;

    if !verify_password(password, &hash_str)? {
        return Err(EmailAuthError::InvalidCredentials);
    }

    Ok(VerifiedIdentity {
        identifier: email.to_string(),
        provider: "email".to_string(),
        display_name: display_name
            .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string()),
    })
}
