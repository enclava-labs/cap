//! Nostr NIP-98 HTTP Auth provider.
//!
//! Flow:
//! 1. Client creates a kind-27235 Nostr event with:
//!    - `url` tag matching the API endpoint
//!    - `method` tag matching the HTTP method
//!    - `payload` tag (optional, SHA256 of request body)
//!    - created_at within 60 seconds of server time
//! 2. Client sends the signed event as a base64 Authorization header or JSON body.
//! 3. Server verifies the signature and extracts the npub.

use crate::auth::provider::VerifiedIdentity;
use nostr::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum NostrAuthError {
    #[error("nostr event is required")]
    EventRequired,
    #[error("invalid nostr event: {0}")]
    InvalidEvent(String),
    #[error("event kind must be 27235 (NIP-98 HTTP Auth)")]
    WrongKind,
    #[error("event signature verification failed")]
    InvalidSignature,
    #[error("event expired (created_at must be within 60 seconds of server time)")]
    Expired,
    #[error("event url tag does not match request URL")]
    UrlMismatch,
    #[error("event method tag does not match request method")]
    MethodMismatch,
    #[error("event payload tag missing for mutating request with body")]
    PayloadTagMissing,
    #[error("event payload tag does not match sha256(body)")]
    PayloadMismatch,
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
}

/// Verify a NIP-98 signed event including the `payload` tag binding to
/// `sha256(body)`. Use this on every mutating endpoint that carries a body.
pub fn verify_nip98_event_with_body(
    event_json: &str,
    expected_url: &str,
    expected_method: &str,
    body: &[u8],
) -> Result<VerifiedIdentity, NostrAuthError> {
    let identity = verify_nip98_event(event_json, expected_url, expected_method)?;

    let method_upper = expected_method.to_ascii_uppercase();
    let mutating = matches!(method_upper.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");

    if !mutating || body.is_empty() {
        return Ok(identity);
    }

    let event: Event =
        Event::from_json(event_json).map_err(|e| NostrAuthError::InvalidEvent(e.to_string()))?;

    let payload_tag = event
        .tags
        .iter()
        .find(|t| t.kind().as_str() == "payload")
        .and_then(|t| t.content())
        .ok_or(NostrAuthError::PayloadTagMissing)?;

    let expected = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    };

    if !payload_tag.eq_ignore_ascii_case(&expected) {
        return Err(NostrAuthError::PayloadMismatch);
    }

    Ok(identity)
}

/// Verify a NIP-98 signed event and return the verified identity.
/// If the npub is new, does NOT create the user (signup does that separately).
pub fn verify_nip98_event(
    event_json: &str,
    expected_url: &str,
    expected_method: &str,
) -> Result<VerifiedIdentity, NostrAuthError> {
    let event: Event =
        Event::from_json(event_json).map_err(|e| NostrAuthError::InvalidEvent(e.to_string()))?;

    // Must be NIP-98 HTTP Auth kind
    if event.kind != Kind::HttpAuth {
        return Err(NostrAuthError::WrongKind);
    }

    // Verify event signature
    event
        .verify()
        .map_err(|_| NostrAuthError::InvalidSignature)?;

    // Check timestamp freshness (60-second window)
    let now = Timestamp::now();
    let created = event.created_at;
    let diff = if now > created {
        now.as_secs() - created.as_secs()
    } else {
        created.as_secs() - now.as_secs()
    };
    if diff > 60 {
        return Err(NostrAuthError::Expired);
    }

    // Verify url tag matches
    let url_tag = event
        .tags
        .iter()
        .find(|t| matches!(t.kind().as_str(), "u" | "url"))
        .and_then(|t| t.content())
        .ok_or_else(|| NostrAuthError::InvalidEvent("missing url tag".to_string()))?;

    if url_tag != expected_url {
        return Err(NostrAuthError::UrlMismatch);
    }

    // Verify method tag matches
    let method_tag = event
        .tags
        .iter()
        .find(|t| t.kind().as_str() == "method")
        .and_then(|t| t.content())
        .ok_or_else(|| NostrAuthError::InvalidEvent("missing method tag".to_string()))?;

    if !method_tag.eq_ignore_ascii_case(expected_method) {
        return Err(NostrAuthError::MethodMismatch);
    }

    let npub = event
        .pubkey
        .to_bech32()
        .unwrap_or_else(|_| event.pubkey.to_hex());
    // Use first 8 chars of hex pubkey as display name fallback
    let display_name = format!("nostr-{}", &event.pubkey.to_hex()[..8]);

    Ok(VerifiedIdentity {
        identifier: npub,
        provider: "nostr".to_string(),
        display_name,
    })
}

/// Sign up or login a Nostr user. Creates user + personal org if new.
/// Returns (user_id, org_id, is_new_user).
pub async fn signup_or_login(
    pool: &PgPool,
    identity: &VerifiedIdentity,
) -> Result<(Uuid, Uuid, bool), NostrAuthError> {
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT user_id FROM user_identities WHERE provider = 'nostr' AND identifier = $1",
    )
    .bind(&identity.identifier)
    .fetch_optional(pool)
    .await?;

    if let Some((user_id,)) = existing {
        // Existing user: find their personal org
        let org_id: Uuid = sqlx::query_scalar(
            "SELECT o.id FROM organizations o
             JOIN memberships m ON m.org_id = o.id
             WHERE m.user_id = $1 AND o.is_personal = true
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await?;

        return Ok((user_id, org_id, false));
    }

    // New user: create user, identity, personal org, membership
    let user_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let identity_id = Uuid::new_v4();
    let org_name = format!("{}-{}", identity.display_name, &user_id.to_string()[..8]);

    let mut tx = pool.begin().await?;

    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, $2)")
        .bind(user_id)
        .bind(&identity.display_name)
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO user_identities (id, user_id, provider, identifier, is_primary, verified_at)
         VALUES ($1, $2, 'nostr', $3, true, now())",
    )
    .bind(identity_id)
    .bind(user_id)
    .bind(&identity.identifier)
    .execute(&mut *tx)
    .await?;

    crate::db::orgs::insert_org_conn(
        &mut tx,
        org_id,
        &org_name,
        Some(&identity.display_name),
        true,
    )
    .await?;

    sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'owner')")
        .bind(user_id)
        .bind(org_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok((user_id, org_id, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_http_auth_event(url_tag_key: &str, url: &str, method: &str) -> String {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tag(
                Tag::parse([url_tag_key.to_string(), url.to_string()])
                    .expect("failed to build url tag"),
            )
            .tag(
                Tag::parse(["method".to_string(), method.to_string()])
                    .expect("failed to build method tag"),
            )
            .sign_with_keys(&keys)
            .expect("failed to sign NIP-98 event");

        JsonUtil::as_json(&event)
    }

    #[test]
    fn verify_nip98_accepts_matching_method_and_u_tag() {
        let url = "https://api.example.test/auth/login";
        let event_json = signed_http_auth_event("u", url, "POST");

        let verified = verify_nip98_event(&event_json, url, "POST");
        assert!(verified.is_ok());
    }

    #[test]
    fn verify_nip98_rejects_method_mismatch() {
        let url = "https://api.example.test/auth/login";
        let event_json = signed_http_auth_event("u", url, "POST");

        let err = verify_nip98_event(&event_json, url, "DELETE").unwrap_err();
        assert!(matches!(err, NostrAuthError::MethodMismatch));
    }

    #[test]
    fn verify_nip98_accepts_legacy_url_tag() {
        let url = "https://api.example.test/auth/signup";
        let event_json = signed_http_auth_event("url", url, "POST");

        let verified = verify_nip98_event(&event_json, url, "POST");
        assert!(verified.is_ok());
    }

    fn signed_http_auth_event_with_payload(
        url: &str,
        method: &str,
        payload_hex: Option<&str>,
    ) -> String {
        let keys = Keys::generate();
        let mut builder = EventBuilder::new(Kind::HttpAuth, "")
            .tag(Tag::parse(["u".to_string(), url.to_string()]).unwrap())
            .tag(Tag::parse(["method".to_string(), method.to_string()]).unwrap());
        if let Some(p) = payload_hex {
            builder = builder.tag(Tag::parse(["payload".to_string(), p.to_string()]).unwrap());
        }
        let event = builder.sign_with_keys(&keys).unwrap();
        JsonUtil::as_json(&event)
    }

    fn sha256_hex(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    }

    #[test]
    fn verify_nip98_with_body_requires_payload_tag_for_mutating_request() {
        let url = "https://api.example.test/apps";
        let body = br#"{"name":"foo"}"#;
        let event = signed_http_auth_event_with_payload(url, "POST", None);
        let err = verify_nip98_event_with_body(&event, url, "POST", body).unwrap_err();
        assert!(matches!(err, NostrAuthError::PayloadTagMissing));
    }

    #[test]
    fn verify_nip98_with_body_rejects_payload_mismatch() {
        let url = "https://api.example.test/apps";
        let body = br#"{"name":"foo"}"#;
        let event =
            signed_http_auth_event_with_payload(url, "POST", Some(&sha256_hex(b"different")));
        let err = verify_nip98_event_with_body(&event, url, "POST", body).unwrap_err();
        assert!(matches!(err, NostrAuthError::PayloadMismatch));
    }

    #[test]
    fn verify_nip98_with_body_accepts_matching_payload_tag() {
        let url = "https://api.example.test/apps";
        let body = br#"{"name":"foo"}"#;
        let event = signed_http_auth_event_with_payload(url, "POST", Some(&sha256_hex(body)));
        let verified = verify_nip98_event_with_body(&event, url, "POST", body);
        assert!(verified.is_ok(), "payload-bound event should verify");
    }

    #[test]
    fn verify_nip98_with_body_skips_payload_check_when_body_empty() {
        let url = "https://api.example.test/apps";
        let event = signed_http_auth_event_with_payload(url, "POST", None);
        verify_nip98_event_with_body(&event, url, "POST", &[]).unwrap();
    }
}
