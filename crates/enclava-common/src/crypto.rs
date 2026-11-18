use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::canonical::{ce_v1_bytes, ce_v1_hash};

/// Owner-rotation directive bytes (CE-v1 contract, purpose v2).
///
/// The signed bytes bind the keyring version the rotation supersedes and
/// that version's creation witness (`base_keyring_created_at`, the stored
/// `org_keyrings.created_at`). `signed_at` alone is signer-chosen and can
/// never prove when a directive was actually created; the creation witness
/// is server-assigned at version insertion and cannot be known before the
/// version exists, so a directive covering it provably post-dates the
/// version it supersedes (issue #188). Callers must carry the same pair in
/// the unauthenticated request so the service can re-derive these bytes;
/// the platform signing service re-derives them verbatim (coordinated
/// contract change per AGENTS.md).
pub fn owner_rotation_directive_bytes(
    org_id: Uuid,
    revoked_pubkey: &[u8; 32],
    replacement_pubkey: &[u8; 32],
    base_keyring_version: i64,
    base_keyring_created_at: DateTime<Utc>,
    signed_at: DateTime<Utc>,
    reason: &str,
) -> Vec<u8> {
    let base_keyring_created_at = base_keyring_created_at.to_rfc3339();
    let base_keyring_version = base_keyring_version.to_string();
    let signed_at = signed_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-recovery-v2"),
        ("org_id", org_id.as_bytes().as_slice()),
        ("revoked_pubkey", revoked_pubkey),
        ("replacement_pubkey", replacement_pubkey),
        ("base_keyring_version", base_keyring_version.as_bytes()),
        (
            "base_keyring_created_at",
            base_keyring_created_at.as_bytes(),
        ),
        ("signed_at", signed_at.as_bytes()),
        ("reason", reason.as_bytes()),
    ])
}

/// Compute stable tenant instance identity hash using CE-v1 (D11 / Phase 1).
///
/// The previous implementation used colon-concatenated SHA-256, which was
/// vulnerable to length-shift / boundary-confusion attacks. CE-v1 enforces
/// length-prefixed TLV records with a versioned domain-separation label,
/// so a variable-length field cannot shift boundaries to forge a collision.
///
/// `bootstrap_owner_pubkey_hash` is the hex-encoded SHA-256 of the owner's
/// raw Ed25519 public key (preserved from the previous signature so all
/// existing callers compile unchanged).
pub fn compute_identity_hash(
    tenant_id: &str,
    instance_id: &str,
    bootstrap_owner_pubkey_hash: &str,
) -> String {
    let hash = ce_v1_hash(&[
        ("purpose", b"enclava-identity-v1"),
        ("tenant_id", tenant_id.as_bytes()),
        ("instance_id", instance_id.as_bytes()),
        (
            "bootstrap_owner_pubkey",
            bootstrap_owner_pubkey_hash.as_bytes(),
        ),
    ]);
    hex::encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn identity_hash_is_lowercase_hex_64_chars() {
        let hash = compute_identity_hash("t", "i", "p");
        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(hash, hash.to_lowercase());
    }

    #[test]
    fn identity_hash_deterministic() {
        let a = compute_identity_hash("x", "y", "z");
        let b = compute_identity_hash("x", "y", "z");
        assert_eq!(a, b);
    }

    #[test]
    fn identity_hash_sensitive_to_all_inputs() {
        let base = compute_identity_hash("t", "i", "p");
        assert_ne!(base, compute_identity_hash("T", "i", "p"));
        assert_ne!(base, compute_identity_hash("t", "I", "p"));
        assert_ne!(base, compute_identity_hash("t", "i", "P"));
    }

    #[test]
    fn identity_hash_resists_boundary_collision() {
        // The colon-concatenated implementation was vulnerable: the inputs
        // ("a","bc","x") and ("ab","c","x") produced different — but only
        // because of the colon delimiter; without delimiters, "abcx" would
        // collide. CE-v1 length-prefixes every record so even adversarially
        // chosen splits produce different bytes.
        let a = compute_identity_hash("a", "bc", "x");
        let b = compute_identity_hash("ab", "c", "x");
        assert_ne!(a, b);
    }

    #[test]
    fn owner_rotation_directive_is_deterministic_and_domain_separated() {
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap();
        let created_at = Utc.with_ymd_and_hms(2026, 8, 12, 11, 0, 0).unwrap();
        let bytes = owner_rotation_directive_bytes(
            org_id,
            &[0x11; 32],
            &[0x22; 32],
            7,
            created_at,
            at,
            "routine",
        );
        assert_eq!(
            bytes,
            owner_rotation_directive_bytes(
                org_id,
                &[0x11; 32],
                &[0x22; 32],
                7,
                created_at,
                at,
                "routine"
            )
        );
        assert_ne!(
            bytes,
            owner_rotation_directive_bytes(
                org_id,
                &[0x11; 32],
                &[0x22; 32],
                7,
                created_at,
                at,
                "incident"
            )
        );
    }

    #[test]
    fn owner_rotation_directive_v2_golden_vector() {
        // Known-answer vector for the CE-v1 directive byte contract v2.
        // The platform signing service (policy-templates) re-derives these
        // bytes verbatim; any implementation drift must fail against this
        // pinned encoding rather than at deploy time.
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let created_at = Utc.with_ymd_and_hms(2026, 8, 12, 11, 0, 0).unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap();
        let bytes = owner_rotation_directive_bytes(
            org_id,
            &[0x11; 32],
            &[0x22; 32],
            7,
            created_at,
            at,
            "routine",
        );
        assert_eq!(
            hex::encode(&bytes),
            "0007707572706f736500000013656e636c6176612d7265636f766572792d763200066f72675f696400000010\
             11111111111111111111111111111111000e7265766f6b65645f7075626b6579000000201111111111111111\
             11111111111111111111111111111111111111111111111100127265706c6163656d656e745f7075626b6579\
             0000002022222222222222222222222222222222222222222222222222222222222222220014626173655f6b\
             657972696e675f76657273696f6e00000001370017626173655f6b657972696e675f637265617465645f6174\
             00000019323032362d30382d31325431313a30303a30302b30303a303000097369676e65645f617400000019\
             323032362d30382d31325431323a30303a30302b30303a30300006726561736f6e00000007726f7574696e65"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(bytes.len(), 308);
    }

    #[test]
    fn owner_rotation_directive_binds_base_version_and_creation_witness() {
        // Issue #188: the signed bytes must cover the superseded version
        // and its creation witness so no directive can be reused across a
        // version boundary or minted before the version existed.
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let at = Utc.with_ymd_and_hms(2026, 8, 12, 12, 0, 0).unwrap();
        let created_at = Utc.with_ymd_and_hms(2026, 8, 12, 11, 0, 0).unwrap();
        let base = owner_rotation_directive_bytes(
            org_id,
            &[0x11; 32],
            &[0x22; 32],
            7,
            created_at,
            at,
            "routine",
        );
        // A different base version changes the bytes.
        assert_ne!(
            base,
            owner_rotation_directive_bytes(
                org_id,
                &[0x11; 32],
                &[0x22; 32],
                8,
                created_at,
                at,
                "routine"
            )
        );
        // A different creation witness changes the bytes: a directive
        // minted before the version existed cannot cover its witness.
        assert_ne!(
            base,
            owner_rotation_directive_bytes(
                org_id,
                &[0x11; 32],
                &[0x22; 32],
                7,
                created_at + chrono::Duration::seconds(1),
                at,
                "routine"
            )
        );
    }
}
