use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use sqlx::PgPool;
use uuid::Uuid;

use crate::auth::provider::VerifiedIdentity;

/// A fixed, parseable argon2id hash used as a decoy target when an email
/// login names no account. Verifying the submitted password against this
/// constant makes the missing-row path do the same Argon2 work as the
/// hit path, so login timing and response shape do not reveal whether
/// the email is registered (issue #121). It is a hash of a random
/// 256-bit OsRng secret generated once when this constant was authored
/// and never stored or disclosed anywhere else.
const DUMMY_CREDENTIAL_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$d4t67vzZ6lgVAEyVBkQwcQ$lB19QKhSbbMwhV8LfbGVNM+N+vntLboyrQRIVQb1Rx4";

#[derive(Debug, thiserror::Error)]
pub enum EmailAuthError {
    #[error("email is required")]
    EmailRequired,
    #[error("password is required")]
    PasswordRequired,
    /// Generic signup failure used for duplicate emails so the response does
    /// not disclose whether the address is already registered (issue #121).
    #[error("signup failed")]
    SignupFailed,
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

    // Anti-enumeration (issue #121): hash the password BEFORE the conflict
    // check so that a duplicate-email signup costs the same Argon2 work as
    // a fresh one, and keep the error message identical to a failed signup
    // ("signup failed") instead of "email already registered".
    let credential_hash = hash_password(password)?;

    if exists {
        return Err(EmailAuthError::SignupFailed);
    }

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

    // Anti-enumeration: when the email is unknown, verify the submitted
    // password against the fixed decoy hash so this path performs the same
    // Argon2 work (and returns the same InvalidCredentials error) as a
    // wrong password for a known account (issue #121).
    let password_ok = match row.as_ref() {
        Some((_user_id, hash_str, _display_name)) => verify_password(password, hash_str)?,
        None => verify_password(password, DUMMY_CREDENTIAL_HASH)?,
    };

    if !password_ok {
        return Err(EmailAuthError::InvalidCredentials);
    }

    let (_user_id, _hash_str, display_name) = row.ok_or(EmailAuthError::InvalidCredentials)?;

    Ok(VerifiedIdentity {
        identifier: email.to_string(),
        provider: "email".to_string(),
        display_name: display_name
            .unwrap_or_else(|| email.split('@').next().unwrap_or("user").to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dummy_hash_is_parseable_and_rejects_common_passwords() {
        // The decoy must parse (so the missing-row path performs a real
        // Argon2 verification) and must not verify typical passwords.
        for pw in ["password", "correct horse battery staple", "hunter2", ""] {
            assert!(
                !verify_password(pw, DUMMY_CREDENTIAL_HASH).unwrap(),
                "dummy hash must not verify {pw:?}"
            );
        }
    }

    #[test]
    fn login_missing_email_performs_full_argon2_work() {
        // Regression test for issue #121: the unknown-email login path must
        // do real Argon2 verification work (comparable duration to the
        // known-email wrong-password path), not return instantly.
        let dummy_hash = hash_password("some real hash material").unwrap();
        let iterations = 3;
        let mut missing_row_elapsed = std::time::Duration::ZERO;
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            let _ = verify_password("attacker guess", DUMMY_CREDENTIAL_HASH).unwrap();
            missing_row_elapsed += start.elapsed();
        }
        let mut hit_elapsed = std::time::Duration::ZERO;
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            let _ = verify_password("attacker guess", &dummy_hash).unwrap();
            hit_elapsed += start.elapsed();
        }
        assert!(
            missing_row_elapsed.as_nanos() > 50_000,
            "missing-row path must do real Argon2 work, took {missing_row_elapsed:?}"
        );
        // Same order of magnitude as the hit path (within 10x — Argon2 runs
        // are ~tens of ms with default params, network jitter excluded).
        let ratio = missing_row_elapsed.as_secs_f64() / hit_elapsed.as_secs_f64().max(1e-9);
        assert!(
            ratio > 0.1 && ratio < 10.0,
            "missing-row and hit-path Argon2 work must be comparable: ratio {ratio:.3}"
        );
    }

    #[test]
    fn signup_error_messages_do_not_disclose_account_existence() {
        // The duplicate-email signup error must be the generic SignupFailed
        // message, not "email already registered".
        assert_eq!(EmailAuthError::SignupFailed.to_string(), "signup failed");
    }
}
