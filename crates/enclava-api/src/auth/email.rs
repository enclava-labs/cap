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
    /// Duplicate-email signup failure. The message is generic so the error
    /// body alone does not spell out "email already registered" (issue #121),
    /// but note the HTTP responses still differ observably (400 vs 201
    /// Created): fully closing the signup oracle needs out-of-band email
    /// verification, which is a product change tracked outside this fix.
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

    // Anti-enumeration (issue #121): hash the password on BOTH branches
    // (before the conflict decision) so a duplicate-email signup costs the
    // same Argon2 work as a fresh one, and use a generic error message.
    // The EXISTS check sits outside the transaction; a concurrent
    // duplicate insert can still surface as a unique-violation DB error,
    // which is mapped to the same generic SignupFailed below.
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
    .await
    .map_err(|e| {
        // The unique constraint on (provider, identifier) can fire when a
        // concurrent signup registered the same email between the EXISTS
        // check and this insert. Map it to the same generic SignupFailed
        // so the constraint race does not leak a distinct error body
        // (which could echo the conflicting identifier).
        if let sqlx::Error::Database(ref db) = e
            && db.constraint() == Some("user_identities_provider_identifier_key")
        {
            return EmailAuthError::SignupFailed;
        }
        EmailAuthError::Db(e)
    })?;

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

    let row: Option<(Uuid, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT ui.user_id, ui.credential_hash, u.display_name
         FROM user_identities ui
         JOIN users u ON u.id = ui.user_id
         WHERE ui.provider = 'email' AND ui.identifier = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?;

    // Anti-enumeration: every failure path must do the same Argon2 work
    // against the fixed decoy hash and return the same InvalidCredentials
    // error (issue #121): unknown email, NULL credential_hash, garbage
    // stored hash, and wrong password are indistinguishable in body and
    // cost. (verify_password parses the PHC string before running Argon2,
    // so the unparseable cases must still run a decoy verify to match the
    // timing of a real wrong-password attempt.)
    let password_ok = match row.as_ref() {
        Some((_user_id, Some(hash_str), _display_name)) => verify_password(password, hash_str)
            .unwrap_or_else(|_| {
                let _ = verify_password(password, DUMMY_CREDENTIAL_HASH);
                false
            }),
        _ => verify_password(password, DUMMY_CREDENTIAL_HASH).unwrap_or(false),
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
        // Regression test for issue #121: the unknown-email login path
        // verifies against DUMMY_CREDENTIAL_HASH, which must use exactly
        // the same PHC parameters as hash_password()/Argon2::default(),
        // or the timing gap re-opens. Pin the parameters structurally
        // (not by wall-clock ratio, which flakes and misses slow drift).
        let fresh = hash_password("some real hash material").unwrap();
        let params = |phc: &str| -> (String, u32, argon2::password_hash::ParamsString) {
            let parsed = PasswordHash::new(phc).expect("parse PHC string");
            (
                parsed.algorithm.as_str().to_string(),
                parsed
                    .version
                    .expect("explicit argon2 version in PHC string"),
                parsed.params.clone(),
            )
        };
        assert_eq!(
            params(DUMMY_CREDENTIAL_HASH),
            params(&fresh),
            "DUMMY_CREDENTIAL_HASH must match hash_password()'s argon2 parameters exactly"
        );
        // And both must be the argon2 crate defaults (argon2id v19,
        // m=19456 KiB, t=2, p=1).
        let (algo, version, parameters) = params(&fresh);
        assert_eq!(algo.as_str(), "argon2id");
        assert_eq!(version, 19);
        let m = parameters
            .get("m")
            .expect("memory param")
            .decimal()
            .expect("m decimal");
        let t = parameters
            .get("t")
            .expect("iterations param")
            .decimal()
            .expect("t decimal");
        let p = parameters
            .get("p")
            .expect("parallelism param")
            .decimal()
            .expect("p decimal");
        let defaults = argon2::Params::DEFAULT;
        assert_eq!(m, defaults.m_cost());
        assert_eq!(t, defaults.t_cost());
        assert_eq!(p, defaults.p_cost());
    }

    #[test]
    fn signup_error_message_is_generic_for_duplicate_emails() {
        // The duplicate-email signup error must be the generic SignupFailed
        // message, not "email already registered". (The signup endpoint
        // still reveals existence via 201-vs-400 status; closing that needs
        // out-of-band email verification — documented in the PR.)
        assert_eq!(EmailAuthError::SignupFailed.to_string(), "signup failed");
        // The string must never regress to an explicit disclosure.
        let msg = EmailAuthError::SignupFailed.to_string();
        assert!(
            !msg.contains("registered"),
            "message must stay generic: {msg}"
        );
    }
}
