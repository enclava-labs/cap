//! Input validators for platform identifiers.
//!
//! These validators are conservative: they reject anything that isn't
//! unambiguously safe to interpolate into hostnames, Kubernetes object
//! names, container image references, or filesystem paths. Anything
//! suspicious — non-ASCII, control characters, RTL overrides, IDN
//! homograph patterns, oversized inputs — is rejected.

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ValidateError {
    #[error("invalid DNS label: {0}")]
    InvalidDnsLabel(&'static str),
    #[error("invalid org slug: {0}")]
    InvalidOrgSlug(&'static str),
    #[error("invalid app name: {0}")]
    InvalidAppName(&'static str),
    #[error("invalid FQDN: {0}")]
    InvalidFqdn(&'static str),
    #[error("invalid image digest: {0}")]
    InvalidImageDigest(&'static str),
}

const MAX_DNS_LABEL_LEN: usize = 63;
const MAX_FQDN_LEN: usize = 253;
const MAX_APP_NAME_LEN: usize = 32;
const ORG_SLUG_LEN: usize = 8;
const IMAGE_DIGEST_HEX_LEN: usize = 64;
const IMAGE_DIGEST_PREFIX: &str = "sha256:";

/// RFC 1123 DNS label (1–63 chars, `[a-z0-9-]`, no leading/trailing hyphen).
///
/// All-digit labels are valid here — RFC 1123 §2.1 dropped the
/// "must contain at least one alpha" rule from RFC 952, and the platform's
/// 8-hex `org_slug` may be all-digit (e.g. `12345678`) which must round-trip
/// through `app_hostname()` cleanly. Stricter caller types (e.g. K8s service
/// names) layer their own all-digit rejection on top.
pub fn validate_dns_label(s: &str) -> Result<(), ValidateError> {
    if s.is_empty() {
        return Err(ValidateError::InvalidDnsLabel("empty"));
    }
    if s.len() > MAX_DNS_LABEL_LEN {
        return Err(ValidateError::InvalidDnsLabel("exceeds 63 characters"));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(ValidateError::InvalidDnsLabel(
            "must contain only [a-z0-9-]",
        ));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(ValidateError::InvalidDnsLabel(
            "must not start or end with '-'",
        ));
    }
    Ok(())
}

/// Exactly 8 lowercase hex chars.
pub fn validate_org_slug(s: &str) -> Result<(), ValidateError> {
    if s.len() != ORG_SLUG_LEN {
        return Err(ValidateError::InvalidOrgSlug(
            "must be exactly 8 characters",
        ));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidateError::InvalidOrgSlug(
            "must be lowercase hex [0-9a-f]",
        ));
    }
    Ok(())
}

/// DNS-1123 label with extra constraint length ≤ 32.
pub fn validate_app_name(s: &str) -> Result<(), ValidateError> {
    if s.is_empty() {
        return Err(ValidateError::InvalidAppName("empty"));
    }
    if s.len() > MAX_APP_NAME_LEN {
        return Err(ValidateError::InvalidAppName("exceeds 32 characters"));
    }
    validate_dns_label(s).map_err(|_| {
        ValidateError::InvalidAppName(
            "must be a DNS-1123 label: [a-z0-9-], no leading/trailing '-'",
        )
    })?;
    if s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ValidateError::InvalidAppName("must not be all digits"));
    }
    Ok(())
}

/// Every label valid, total length ≤ 253, no trailing dot.
pub fn validate_fqdn(s: &str) -> Result<(), ValidateError> {
    if s.is_empty() {
        return Err(ValidateError::InvalidFqdn("empty"));
    }
    if s.len() > MAX_FQDN_LEN {
        return Err(ValidateError::InvalidFqdn("exceeds 253 characters"));
    }
    if s.ends_with('.') {
        return Err(ValidateError::InvalidFqdn("must not have trailing dot"));
    }
    if s.starts_with('.') {
        return Err(ValidateError::InvalidFqdn("must not have leading dot"));
    }
    if s.contains("..") {
        return Err(ValidateError::InvalidFqdn("must not contain empty labels"));
    }
    // IDN homograph guard: reject Punycode-encoded labels and any non-ASCII.
    // Visible names must not look like one thing while resolving as another.
    if !s.is_ascii() {
        return Err(ValidateError::InvalidFqdn("must be ASCII"));
    }
    for label in s.split('.') {
        if label.starts_with("xn--") {
            return Err(ValidateError::InvalidFqdn(
                "Punycode (xn--) labels are not allowed",
            ));
        }
        validate_dns_label(label)
            .map_err(|_| ValidateError::InvalidFqdn("contains invalid DNS label"))?;
    }
    Ok(())
}

/// Exactly `sha256:` followed by 64 lowercase hex chars.
pub fn validate_image_digest(s: &str) -> Result<(), ValidateError> {
    if !s.starts_with(IMAGE_DIGEST_PREFIX) {
        return Err(ValidateError::InvalidImageDigest(
            "must start with 'sha256:'",
        ));
    }
    let hex = &s[IMAGE_DIGEST_PREFIX.len()..];
    if hex.len() != IMAGE_DIGEST_HEX_LEN {
        return Err(ValidateError::InvalidImageDigest(
            "hex section must be exactly 64 characters",
        ));
    }
    if !hex
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ValidateError::InvalidImageDigest(
            "hex section must be lowercase hex [0-9a-f]",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_label_accepts_valid() {
        assert!(validate_dns_label("a").is_ok());
        assert!(validate_dns_label("app").is_ok());
        assert!(validate_dns_label("my-app").is_ok());
        assert!(validate_dns_label("app1").is_ok());
        assert!(validate_dns_label("a1b2c3").is_ok());
    }

    #[test]
    fn dns_label_rejects_empty() {
        assert!(validate_dns_label("").is_err());
    }

    #[test]
    fn dns_label_rejects_oversized() {
        let s = "a".repeat(64);
        assert!(validate_dns_label(&s).is_err());
        let s = "a".repeat(63);
        assert!(validate_dns_label(&s).is_ok());
    }

    #[test]
    fn dns_label_rejects_uppercase() {
        assert!(validate_dns_label("App").is_err());
        assert!(validate_dns_label("APP").is_err());
    }

    #[test]
    fn dns_label_rejects_underscore_and_dot() {
        assert!(validate_dns_label("my_app").is_err());
        assert!(validate_dns_label("my.app").is_err());
    }

    #[test]
    fn dns_label_rejects_leading_or_trailing_hyphen() {
        assert!(validate_dns_label("-app").is_err());
        assert!(validate_dns_label("app-").is_err());
        assert!(validate_dns_label("-").is_err());
    }

    #[test]
    fn dns_label_accepts_all_digits() {
        // RFC 1123 dropped the "must contain at least one alpha" rule.
        // The 8-hex org_slug field can be all-digit (e.g. `12345678`).
        assert!(validate_dns_label("12345678").is_ok());
        assert!(validate_dns_label("0").is_ok());
    }

    #[test]
    fn dns_label_rejects_path_traversal_and_control_chars() {
        assert!(validate_dns_label("..").is_err());
        assert!(validate_dns_label("a/b").is_err());
        assert!(validate_dns_label("a\\b").is_err());
        assert!(validate_dns_label("a\0b").is_err());
        assert!(validate_dns_label("a\nb").is_err());
        assert!(validate_dns_label("a\rb").is_err());
        assert!(validate_dns_label("a\tb").is_err());
        assert!(validate_dns_label(" a").is_err());
        assert!(validate_dns_label("a ").is_err());
    }

    #[test]
    fn dns_label_rejects_unicode_and_rtl_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — visual spoofing vector
        assert!(validate_dns_label("a\u{202E}b").is_err());
        // Cyrillic 'а' (U+0430) mimicking Latin 'a'
        assert!(validate_dns_label("\u{0430}pp").is_err());
        // Generic non-ASCII
        assert!(validate_dns_label("café").is_err());
    }

    #[test]
    fn dns_label_rejects_at_sign() {
        assert!(validate_dns_label("user@host").is_err());
        assert!(validate_dns_label("a@@b").is_err());
    }

    #[test]
    fn org_slug_accepts_8_lowercase_hex() {
        assert!(validate_org_slug("abcd1234").is_ok());
        assert!(validate_org_slug("00000000").is_ok());
        assert!(validate_org_slug("ffffffff").is_ok());
    }

    #[test]
    fn org_slug_rejects_wrong_length() {
        assert!(validate_org_slug("abc").is_err());
        assert!(validate_org_slug("abcd12345").is_err());
        assert!(validate_org_slug("").is_err());
    }

    #[test]
    fn org_slug_rejects_uppercase_or_non_hex() {
        assert!(validate_org_slug("ABCD1234").is_err());
        assert!(validate_org_slug("abcd123g").is_err());
        assert!(validate_org_slug("abcd-123").is_err());
        assert!(validate_org_slug("abcd 123").is_err());
    }

    #[test]
    fn app_name_accepts_valid() {
        assert!(validate_app_name("api").is_ok());
        assert!(validate_app_name("my-app").is_ok());
        let s = "a".repeat(32);
        assert!(validate_app_name(&s).is_ok());
    }

    #[test]
    fn app_name_rejects_oversized() {
        let s = "a".repeat(33);
        assert!(validate_app_name(&s).is_err());
    }

    #[test]
    fn app_name_inherits_dns_label_rules() {
        assert!(validate_app_name("").is_err());
        assert!(validate_app_name("My-App").is_err());
        assert!(validate_app_name("-app").is_err());
        assert!(validate_app_name("app-").is_err());
        assert!(validate_app_name("..").is_err());
        assert!(validate_app_name("a\0b").is_err());
        assert!(validate_app_name("café").is_err());
    }

    #[test]
    fn app_name_rejects_all_digits() {
        // Stricter than validate_dns_label: app names propagate to K8s
        // service / SA names which must not be all-numeric.
        assert!(validate_app_name("123").is_err());
        assert!(validate_app_name("0").is_err());
    }

    #[test]
    fn fqdn_accepts_all_digit_label() {
        // The 8-hex org_slug position can be all-digit.
        assert!(validate_fqdn("app.12345678.enclava.dev").is_ok());
        assert!(validate_fqdn("app.00000000.enclava.dev").is_ok());
    }

    #[test]
    fn fqdn_accepts_valid() {
        assert!(validate_fqdn("enclava.dev").is_ok());
        assert!(validate_fqdn("app.abcd1234.enclava.dev").is_ok());
        assert!(validate_fqdn("a.b.c.d.e").is_ok());
    }

    #[test]
    fn fqdn_rejects_empty_or_oversized() {
        assert!(validate_fqdn("").is_err());
        let s = format!("{}.dev", "a".repeat(255));
        assert!(validate_fqdn(&s).is_err());
    }

    #[test]
    fn fqdn_rejects_trailing_or_leading_dot() {
        assert!(validate_fqdn("enclava.dev.").is_err());
        assert!(validate_fqdn(".enclava.dev").is_err());
    }

    #[test]
    fn fqdn_rejects_empty_label() {
        assert!(validate_fqdn("a..b").is_err());
    }

    #[test]
    fn fqdn_rejects_invalid_labels() {
        assert!(validate_fqdn("App.dev").is_err());
        assert!(validate_fqdn("-app.dev").is_err());
        assert!(validate_fqdn("app-.dev").is_err());
    }

    #[test]
    fn fqdn_rejects_punycode_idn() {
        // xn-- is the IDN/Punycode prefix — homograph attack vector
        assert!(validate_fqdn("xn--80akhbyknj4f.dev").is_err());
        assert!(validate_fqdn("app.xn--example.dev").is_err());
    }

    #[test]
    fn fqdn_rejects_non_ascii_homograph() {
        // Cyrillic 'а' mimicking Latin 'a'
        assert!(validate_fqdn("\u{0430}pp.enclava.dev").is_err());
        assert!(validate_fqdn("app.\u{202E}enclava.dev").is_err());
    }

    #[test]
    fn fqdn_rejects_path_and_control_chars() {
        assert!(validate_fqdn("a/b.dev").is_err());
        assert!(validate_fqdn("a\0b.dev").is_err());
        assert!(validate_fqdn("a\nb.dev").is_err());
        assert!(validate_fqdn("a b.dev").is_err());
    }

    #[test]
    fn image_digest_accepts_valid() {
        let d = format!("sha256:{}", "a".repeat(64));
        assert!(validate_image_digest(&d).is_ok());
        let d = format!("sha256:{}", "0123456789abcdef".repeat(4));
        assert!(validate_image_digest(&d).is_ok());
    }

    #[test]
    fn image_digest_rejects_missing_prefix() {
        let d = "a".repeat(64);
        assert!(validate_image_digest(&d).is_err());
        assert!(validate_image_digest("SHA256:aaaa").is_err());
        let d = format!("sha512:{}", "a".repeat(64));
        assert!(validate_image_digest(&d).is_err());
    }

    #[test]
    fn image_digest_rejects_wrong_hex_length() {
        let d = format!("sha256:{}", "a".repeat(63));
        assert!(validate_image_digest(&d).is_err());
        let d = format!("sha256:{}", "a".repeat(65));
        assert!(validate_image_digest(&d).is_err());
        assert!(validate_image_digest("sha256:").is_err());
    }

    #[test]
    fn image_digest_rejects_uppercase_or_non_hex() {
        let d = format!("sha256:{}", "A".repeat(64));
        assert!(validate_image_digest(&d).is_err());
        let d = format!("sha256:{}", "g".repeat(64));
        assert!(validate_image_digest(&d).is_err());
    }
}
