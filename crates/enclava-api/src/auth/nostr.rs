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
use std::time::Duration;
use uuid::Uuid;

/// Replay cache retention. A cached event id only matters while the event
/// is inside the 60-second freshness window; 15 minutes comfortably covers
/// clock skew between API replicas.
const NIP98_REPLAY_CACHE_RETENTION: Duration = Duration::from_secs(15 * 60);

/// Reaper tick interval. An expired row can survive up to
/// `NIP98_REPLAY_CACHE_RETENTION + NIP98_REPLAY_CACHE_REAP_INTERVAL`
/// (~75 minutes worst case) before the next purge deletes it, so the table
/// is bounded by the login-event rate of a ~75-minute window, not 15.
/// This is a table-size bound only — rows are security-inert once the
/// event leaves the 60-second freshness window. The `first_seen` purge
/// index (migration 0051) keeps each hourly DELETE an index scan over that
/// backlog instead of a full-table scan.
const NIP98_REPLAY_CACHE_REAP_INTERVAL: Duration = Duration::from_secs(3600);

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
    #[error("nostr event was already used (replay detected)")]
    ReplayDetected,
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
///
/// SECURITY: this variant does NOT record the event id, so the same event
/// stays valid until its 60-second freshness window closes. It must never
/// gate session minting (/auth/login, /auth/signup) — those callers must
/// use `verify_and_consume_nip98_event`. It is only appropriate for
/// request authentication where each event is single-use by construction.
pub fn verify_nip98_event(
    event_json: &str,
    expected_url: &str,
    expected_method: &str,
) -> Result<VerifiedIdentity, NostrAuthError> {
    let event: Event =
        Event::from_json(event_json).map_err(|e| NostrAuthError::InvalidEvent(e.to_string()))?;

    verify_nip98_parsed_event(&event, expected_url, expected_method)
}

/// Core verification shared by `verify_nip98_event` and the replay-guarded
/// login path. Checks kind, signature, freshness, and url/method tag
/// bindings. Replay protection is layered on top by the callers that mint
/// sessions (see `verify_and_consume_nip98_event`).
fn verify_nip98_parsed_event(
    event: &Event,
    expected_url: &str,
    expected_method: &str,
) -> Result<VerifiedIdentity, NostrAuthError> {
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

/// Verify a NIP-98 signed event and atomically mark its id as consumed in
/// the shared replay cache. The second presentation of the same event id
/// fails with `ReplayDetected` even while the event is still inside the
/// 60-second freshness window (#116).
///
/// Callers that mint sessions from a NIP-98 event (/auth/login,
/// /auth/signup) must use this; the session-free `verify_nip98_event`
/// remains for request authentication where each event is single-use by
/// construction.
///
/// The event id is claimed (burned) before the caller proceeds, so if the
/// subsequent signup/login step fails the client must sign a fresh event
/// to retry — retrying with the same event inside its freshness window
/// returns `ReplayDetected`.
pub async fn verify_and_consume_nip98_event(
    pool: &PgPool,
    event_json: &str,
    expected_url: &str,
    expected_method: &str,
) -> Result<VerifiedIdentity, NostrAuthError> {
    let event: Event =
        Event::from_json(event_json).map_err(|e| NostrAuthError::InvalidEvent(e.to_string()))?;

    let identity = verify_nip98_parsed_event(&event, expected_url, expected_method)?;

    // Claim the event id. INSERT ... ON CONFLICT DO NOTHING reports whether
    // this call is the first consumer: `rows_affected() == 0` means the id
    // is already cached, i.e. a replay.
    let insert = sqlx::query(
        "INSERT INTO nip98_replay_cache (event_id)
         VALUES ($1)
         ON CONFLICT (event_id) DO NOTHING",
    )
    .bind(event.id.to_hex())
    .execute(pool)
    .await?;

    if insert.rows_affected() == 0 {
        return Err(NostrAuthError::ReplayDetected);
    }

    Ok(identity)
}

/// Delete replay-cache rows older than the retention window. Spawned as a
/// background task at startup; failures are logged and retried on the next
/// tick.
pub async fn reap_nip98_replay_cache(pool: &PgPool) -> Result<u64, NostrAuthError> {
    let result =
        sqlx::query("DELETE FROM nip98_replay_cache WHERE first_seen < now() - $1::interval")
            .bind(format!(
                "{} seconds",
                NIP98_REPLAY_CACHE_RETENTION.as_secs()
            ))
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// Periodically purge expired replay-cache rows so the table stays bounded
/// (worst-case accumulation between purges: retention + one tick interval,
/// see the `NIP98_REPLAY_CACHE_*` constants above).
pub fn spawn_nip98_replay_cache_reaper(pool: PgPool) {
    use tokio::time::{MissedTickBehavior, interval};

    tokio::spawn(async move {
        // First tick fires immediately, which also cleans up any backlog
        // left by a previous instance.
        let mut interval = interval(NIP98_REPLAY_CACHE_REAP_INTERVAL);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match reap_nip98_replay_cache(&pool).await {
                Ok(0) => {}
                Ok(n) => tracing::debug!(purged = n, "purged expired NIP-98 replay cache rows"),
                Err(e) => {
                    tracing::warn!(error = %e, "NIP-98 replay cache purge failed")
                }
            }
        }
    });
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

    /// Build a signed NIP-98 event pinned to an explicit `created_at` and
    /// carrying a per-attempt `nonce` tag — the shape enclava-cli produces
    /// for every login attempt (see `build_nip98_login_event` there).
    fn signed_http_auth_event_with_nonce(
        keys: &Keys,
        url: &str,
        method: &str,
        nonce: &str,
        created_at: Timestamp,
    ) -> String {
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tag(Tag::parse(["u".to_string(), url.to_string()]).expect("failed to build url tag"))
            .tag(
                Tag::parse(["method".to_string(), method.to_string()])
                    .expect("failed to build method tag"),
            )
            .tag(
                Tag::parse(["nonce".to_string(), nonce.to_string()])
                    .expect("failed to build nonce tag"),
            )
            .custom_created_at(created_at)
            .sign_with_keys(keys)
            .expect("failed to sign NIP-98 event");

        JsonUtil::as_json(&event)
    }

    async fn nostr_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect NIP-98 replay regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate NIP-98 replay regression database");
        pool
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

    /// Regression test for #116: a NIP-98 login event that already had its
    /// id consumed must be rejected as a replay even while it is still
    /// inside the 60-second freshness window.
    #[tokio::test]
    async fn verify_and_consume_rejects_replayed_event_within_freshness_window() {
        let pool = nostr_test_pool().await;
        let url = "https://api.example.test/auth/login";
        let event_json = signed_http_auth_event("u", url, "POST");

        // First presentation succeeds and claims the event id.
        let first = verify_and_consume_nip98_event(&pool, &event_json, url, "POST").await;
        assert!(first.is_ok(), "first presentation should verify");

        // Immediate replay of the identical signed event must fail.
        let err = verify_and_consume_nip98_event(&pool, &event_json, url, "POST")
            .await
            .unwrap_err();
        assert!(
            matches!(err, NostrAuthError::ReplayDetected),
            "expected ReplayDetected, got {err:?}"
        );

        // Cleanup so the shared test database stays tidy for re-runs.
        let event: Event = Event::from_json(&event_json).unwrap();
        sqlx::query("DELETE FROM nip98_replay_cache WHERE event_id = $1")
            .bind(event.id.to_hex())
            .execute(&pool)
            .await
            .expect("clean up replay cache test row");
    }

    /// A fresh event with a different id must still verify after a replay
    /// was rejected — the cache rejects ids, not users.
    #[tokio::test]
    async fn verify_and_consume_accepts_new_event_after_replay_rejected() {
        let pool = nostr_test_pool().await;
        let url = "https://api.example.test/auth/login";
        let event_json = signed_http_auth_event("u", url, "POST");

        assert!(
            verify_and_consume_nip98_event(&pool, &event_json, url, "POST")
                .await
                .is_ok()
        );
        assert!(
            verify_and_consume_nip98_event(&pool, &event_json, url, "POST")
                .await
                .is_err()
        );

        let fresh_json = signed_http_auth_event("u", url, "POST");
        assert!(
            verify_and_consume_nip98_event(&pool, &fresh_json, url, "POST")
                .await
                .is_ok(),
            "a freshly signed event must not be affected by the cached id"
        );

        let event: Event = Event::from_json(&event_json).unwrap();
        let fresh: Event = Event::from_json(&fresh_json).unwrap();
        sqlx::query("DELETE FROM nip98_replay_cache WHERE event_id = ANY($1)")
            .bind(vec![event.id.to_hex(), fresh.id.to_hex()])
            .execute(&pool)
            .await
            .expect("clean up replay cache test rows");
    }

    /// The retry path: when a login request reaches the server but its
    /// response is lost (or a later login step fails), the event id is
    /// already burned. Re-signing with the same key in the same second
    /// reproduces the same event id unless the event carries per-attempt
    /// entropy, so the client adds a fresh `nonce` tag on every attempt (see
    /// `build_nip98_login_event` in enclava-cli). The replay guard must
    /// accept that re-signed event: its id is distinct and unclaimed.
    #[tokio::test]
    async fn verify_and_consume_accepts_same_second_resign_with_fresh_nonce() {
        let pool = nostr_test_pool().await;
        let url = "https://api.example.test/auth/login";
        let keys = Keys::generate();
        let created = Timestamp::now();
        let first_json =
            signed_http_auth_event_with_nonce(&keys, url, "POST", "attempt-1", created);
        let retry_json =
            signed_http_auth_event_with_nonce(&keys, url, "POST", "attempt-2", created);

        let first: Event = Event::from_json(&first_json).unwrap();
        let retry: Event = Event::from_json(&retry_json).unwrap();
        assert_eq!(first.created_at, retry.created_at);
        assert_ne!(
            first.id, retry.id,
            "per-attempt nonce must change the event id within the same second"
        );

        assert!(
            verify_and_consume_nip98_event(&pool, &first_json, url, "POST")
                .await
                .is_ok()
        );
        assert!(
            verify_and_consume_nip98_event(&pool, &retry_json, url, "POST")
                .await
                .is_ok(),
            "a same-second re-sign with a fresh nonce is a fresh attempt, not a replay"
        );

        sqlx::query("DELETE FROM nip98_replay_cache WHERE event_id = ANY($1)")
            .bind(vec![first.id.to_hex(), retry.id.to_hex()])
            .execute(&pool)
            .await
            .expect("clean up replay cache test rows");
    }

    /// The reaper must delete rows older than the retention window so the
    /// cache table stays bounded.
    #[tokio::test]
    async fn reap_nip98_replay_cache_deletes_only_expired_rows() {
        let pool = nostr_test_pool().await;
        let stale = "reap-test-stale-event-id";
        let fresh = "reap-test-fresh-event-id";

        sqlx::query("INSERT INTO nip98_replay_cache (event_id, first_seen) VALUES ($1, now() - interval '1 hour')")
            .bind(stale)
            .execute(&pool)
            .await
            .expect("seed stale replay row");
        sqlx::query("INSERT INTO nip98_replay_cache (event_id, first_seen) VALUES ($1, now())")
            .bind(fresh)
            .execute(&pool)
            .await
            .expect("seed fresh replay row");

        let purged = reap_nip98_replay_cache(&pool)
            .await
            .expect("reap replay cache");
        assert!(purged >= 1, "at least the stale row must be purged");

        let remaining: Vec<(String,)> =
            sqlx::query_as("SELECT event_id FROM nip98_replay_cache WHERE event_id = ANY($1)")
                .bind(vec![stale.to_string(), fresh.to_string()])
                .fetch_all(&pool)
                .await
                .expect("read back replay rows");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].0, fresh);

        sqlx::query("DELETE FROM nip98_replay_cache WHERE event_id = $1")
            .bind(fresh)
            .execute(&pool)
            .await
            .expect("clean up fresh replay row");
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
