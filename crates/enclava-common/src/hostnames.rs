//! Hostname construction helpers.
//!
//! Per D1: app hostnames are `<app>.<orgSlug>.<platform_domain>` and TEE
//! hostnames are `<app>.<orgSlug>.<tee_domain_suffix>`. These helpers
//! validate every input through `validate.rs` before formatting, so the
//! returned hostname is always RFC-1123 compliant and free of injection
//! vectors.

use crate::validate::{ValidateError, validate_app_name, validate_fqdn, validate_org_slug};

/// Plain-http is only acceptable for loopback or cluster-internal service
/// hosts (`.svc`, `.svc.cluster.local`): bearer tokens must not transit
/// cleartext on any network an off-cluster attacker can observe.
/// Shared by the API signing-service client and platform-release payload
/// validation so the two cannot drift.
pub fn plain_http_host_allowed(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }
    let host = host.to_ascii_lowercase();
    host.ends_with(".svc") || host.ends_with(".svc.cluster.local")
}

/// Build the user-facing hostname for an app: `<app>.<orgSlug>.<platform_domain>`.
pub fn app_hostname(
    app_name: &str,
    org_slug: &str,
    platform_domain: &str,
) -> Result<String, ValidateError> {
    validate_app_name(app_name)?;
    validate_org_slug(org_slug)?;
    validate_fqdn(platform_domain)?;
    let host = format!("{app_name}.{org_slug}.{platform_domain}");
    // Defense in depth: the assembled hostname must itself be a valid FQDN
    // (length, label rules) — guards against an oversized concatenation.
    validate_fqdn(&host)?;
    Ok(host)
}

/// Build the TEE-facing hostname for an app: `<app>.<orgSlug>.<tee_domain_suffix>`.
pub fn tee_hostname(
    app_name: &str,
    org_slug: &str,
    tee_domain_suffix: &str,
) -> Result<String, ValidateError> {
    validate_app_name(app_name)?;
    validate_org_slug(org_slug)?;
    validate_fqdn(tee_domain_suffix)?;
    let host = format!("{app_name}.{org_slug}.{tee_domain_suffix}");
    validate_fqdn(&host)?;
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_hostname_happy_path() {
        let h = app_hostname("api", "abcd1234", "enclava.dev").unwrap();
        assert_eq!(h, "api.abcd1234.enclava.dev");
    }

    #[test]
    fn tee_hostname_happy_path() {
        let h = tee_hostname("api", "abcd1234", "tee.enclava.dev").unwrap();
        assert_eq!(h, "api.abcd1234.tee.enclava.dev");
    }

    #[test]
    fn rejects_invalid_app_name() {
        assert!(app_hostname("My-App", "abcd1234", "enclava.dev").is_err());
        assert!(app_hostname("", "abcd1234", "enclava.dev").is_err());
        assert!(app_hostname("app..bad", "abcd1234", "enclava.dev").is_err());
        assert!(tee_hostname("My-App", "abcd1234", "tee.enclava.dev").is_err());
    }

    #[test]
    fn rejects_invalid_org_slug() {
        assert!(app_hostname("api", "ABCD1234", "enclava.dev").is_err());
        assert!(app_hostname("api", "short", "enclava.dev").is_err());
        assert!(tee_hostname("api", "ABCD1234", "tee.enclava.dev").is_err());
    }

    #[test]
    fn rejects_invalid_platform_domain() {
        assert!(app_hostname("api", "abcd1234", "enclava.dev.").is_err());
        assert!(app_hostname("api", "abcd1234", ".enclava.dev").is_err());
        assert!(app_hostname("api", "abcd1234", "xn--example.dev").is_err());
        assert!(app_hostname("api", "abcd1234", "Enclava.Dev").is_err());
    }

    #[test]
    fn rejects_assembled_hostname_too_long() {
        let long_suffix = format!("{}.dev", "a".repeat(240));
        assert!(app_hostname("api", "abcd1234", &long_suffix).is_err());
    }

    #[test]
    fn rejects_injection_attempts() {
        // Path traversal / control chars in any component
        assert!(app_hostname("api/v1", "abcd1234", "enclava.dev").is_err());
        assert!(app_hostname("api", "abcd1234", "enclava.dev/path").is_err());
        assert!(app_hostname("api\0", "abcd1234", "enclava.dev").is_err());
    }

    #[test]
    fn plain_http_is_limited_to_loopback_and_cluster_hosts() {
        assert!(plain_http_host_allowed(Some("localhost")));
        assert!(plain_http_host_allowed(Some("127.0.0.1")));
        assert!(plain_http_host_allowed(Some("[::1]")));
        assert!(plain_http_host_allowed(Some(
            "signing-service.enclava-policy.svc.cluster.local"
        )));
        assert!(plain_http_host_allowed(Some("signing.enclava.svc")));
        assert!(!plain_http_host_allowed(Some("signing.example.com")));
        assert!(!plain_http_host_allowed(None));
    }
}
