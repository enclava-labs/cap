//! Production environment-variable safety gates.
//!
//! Refuses to start if dangerous developer-only flags are set in a release
//! build, or if mandatory secrets are empty (any build).

#[derive(Debug, thiserror::Error)]
pub enum EnvGateError {
    #[error("env var `{0}` is set but only allowed in debug builds")]
    DebugOnlyFlagInRelease(&'static str),
    #[error("env var `{0}` must be set and non-empty")]
    MissingRequired(&'static str),
    #[error(
        "ACME directory `{0}` points at production Let's Encrypt; set CAP_ALLOW_PRODUCTION_ACME=true only for production CAP"
    )]
    ProductionAcmeWithoutExplicitAllow(&'static str),
}

const CAP_ALLOW_PRODUCTION_ACME: &str = "CAP_ALLOW_PRODUCTION_ACME";
const CAP_ALLOW_INTERNAL_TENANT_TLS: &str = "CAP_ALLOW_INTERNAL_TENANT_TLS";
const LETS_ENCRYPT_PRODUCTION_DIRECTORY_URL: &str =
    "https://acme-v02.api.letsencrypt.org/directory";

const DEBUG_ONLY_FLAGS: &[&str] = &[
    "SKIP_COSIGN_VERIFY",
    "COSIGN_ALLOW_HTTP_REGISTRY",
    "ALLOW_EPHEMERAL_KEYS",
    "TENANT_TEE_ACCEPT_INVALID_CERTS",
    "ENCLAVA_TEE_ACCEPT_INVALID_CERTS",
    "LEGACY_BOOTSTRAP_SCRIPT",
];

fn flag_is_truthy(value: &str) -> bool {
    matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES")
}

fn debug_assertions_on() -> bool {
    cfg!(debug_assertions)
}

fn is_letsencrypt_production_acme_url(value: &str) -> bool {
    value
        .trim()
        .trim_end_matches('/')
        .eq_ignore_ascii_case(LETS_ENCRYPT_PRODUCTION_DIRECTORY_URL)
}

fn validate_acme_directory_url(
    source_name: &'static str,
    value: &str,
    production_acme_allowed: bool,
) -> Result<(), EnvGateError> {
    if is_letsencrypt_production_acme_url(value) && !production_acme_allowed {
        return Err(EnvGateError::ProductionAcmeWithoutExplicitAllow(
            source_name,
        ));
    }
    Ok(())
}

pub fn ensure_acme_directory_allowed(
    source_name: &'static str,
    value: &str,
) -> Result<(), EnvGateError> {
    let production_acme_allowed = std::env::var(CAP_ALLOW_PRODUCTION_ACME)
        .ok()
        .is_some_and(|value| flag_is_truthy(&value));
    validate_acme_directory_url(source_name, value, production_acme_allowed)
}

/// Apply Phase-0 production gates. Should be called early in `main`, before
/// any subsystem reads environment variables.
pub fn enforce_production_env_gates() -> Result<(), EnvGateError> {
    enforce_with(debug_assertions_on(), |name| std::env::var(name).ok())
}

fn enforce_with(
    debug_assertions: bool,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(), EnvGateError> {
    if !debug_assertions {
        for flag in DEBUG_ONLY_FLAGS {
            if let Some(value) = lookup(flag)
                && flag_is_truthy(&value)
            {
                return Err(EnvGateError::DebugOnlyFlagInRelease(flag));
            }
        }

        if let Some(mode) = lookup("TENANT_TEE_TLS_MODE")
            && matches!(mode.trim(), "staging" | "insecure")
        {
            return Err(EnvGateError::DebugOnlyFlagInRelease("TENANT_TEE_TLS_MODE"));
        }

        if let Some(mode) = lookup("TENANT_CADDY_TLS_MODE")
            && mode.trim().eq_ignore_ascii_case("internal")
            && !lookup(CAP_ALLOW_INTERNAL_TENANT_TLS).is_some_and(|value| flag_is_truthy(&value))
        {
            return Err(EnvGateError::DebugOnlyFlagInRelease(
                "TENANT_CADDY_TLS_MODE",
            ));
        }

        let production_acme_allowed =
            lookup(CAP_ALLOW_PRODUCTION_ACME).is_some_and(|value| flag_is_truthy(&value));
        for acme_source_name in ["ACME_DIRECTORY_URL", "TENANT_CADDY_ACME_CA"] {
            if let Some(value) = lookup(acme_source_name) {
                validate_acme_directory_url(acme_source_name, &value, production_acme_allowed)?;
            }
        }

        let api_key_pepper_present = lookup("API_KEY_HMAC_PEPPER")
            .is_some_and(|v| !v.trim().is_empty())
            || lookup("API_KEY_HMAC_PEPPER_BASE64").is_some_and(|v| !v.trim().is_empty());
        if !api_key_pepper_present {
            return Err(EnvGateError::MissingRequired("API_KEY_HMAC_PEPPER"));
        }

        match lookup("TRUSTEE_POLICY_READ_AVAILABLE") {
            Some(value) if flag_is_truthy(&value) => {}
            _ => {
                return Err(EnvGateError::MissingRequired(
                    "TRUSTEE_POLICY_READ_AVAILABLE",
                ));
            }
        }

        if let Some(value) = lookup("TRUSTEE_KBS_URL")
            && value.trim().starts_with("http://")
        {
            return Err(EnvGateError::DebugOnlyFlagInRelease("TRUSTEE_KBS_URL"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ok_required() -> HashMap<&'static str, &'static str> {
        let mut m = HashMap::new();
        m.insert("API_KEY_HMAC_PEPPER", "01234567890123456789012345678901");
        m.insert("TRUSTEE_POLICY_READ_AVAILABLE", "true");
        m
    }

    fn run(env: HashMap<&'static str, &'static str>, debug: bool) -> Result<(), EnvGateError> {
        enforce_with(debug, |k| env.get(k).map(|v| v.to_string()))
    }

    #[test]
    fn release_rejects_skip_cosign_verify() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "1");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::DebugOnlyFlagInRelease("SKIP_COSIGN_VERIFY")
        ));
    }

    #[test]
    fn release_rejects_tee_accept_invalid_certs() {
        for flag in [
            "TENANT_TEE_ACCEPT_INVALID_CERTS",
            "ENCLAVA_TEE_ACCEPT_INVALID_CERTS",
        ] {
            let mut env = ok_required();
            env.insert(flag, "true");
            assert!(run(env, false).is_err(), "{flag} should be rejected");
        }
    }

    #[test]
    fn release_rejects_insecure_tee_tls_mode() {
        let mut env = ok_required();
        env.insert("TENANT_TEE_TLS_MODE", "insecure");
        assert!(run(env, false).is_err());
    }

    #[test]
    fn release_rejects_internal_caddy_tls_mode() {
        let mut env = ok_required();
        env.insert("TENANT_CADDY_TLS_MODE", "internal");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::DebugOnlyFlagInRelease("TENANT_CADDY_TLS_MODE")
        ));
    }

    #[test]
    fn release_allows_internal_caddy_tls_mode_with_explicit_preprod_override() {
        let mut env = ok_required();
        env.insert("TENANT_CADDY_TLS_MODE", "internal");
        env.insert("CAP_ALLOW_INTERNAL_TENANT_TLS", "true");

        run(env, false).expect("explicit preprod internal TLS override should be allowed");
    }

    #[test]
    fn debug_allows_debug_only_flags() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "1");
        env.insert("ALLOW_EPHEMERAL_KEYS", "1");
        run(env, true).expect("debug build should permit dev flags");
    }

    #[test]
    fn debug_core_allows_no_hosted_secret() {
        let env = HashMap::new();
        run(env, true).expect("core debug mode should not require hosted-service secrets");
    }

    #[test]
    fn release_requires_api_key_hmac_pepper() {
        let mut env = ok_required();
        env.remove("API_KEY_HMAC_PEPPER");
        assert!(matches!(
            run(env, false).unwrap_err(),
            EnvGateError::MissingRequired("API_KEY_HMAC_PEPPER")
        ));
    }

    #[test]
    fn release_accepts_api_key_hmac_pepper_base64() {
        let mut env = ok_required();
        env.remove("API_KEY_HMAC_PEPPER");
        env.insert(
            "API_KEY_HMAC_PEPPER_BASE64",
            "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
        );
        run(env, false).expect("base64 pepper should satisfy release gate");
    }

    #[test]
    fn falsy_debug_only_flag_is_allowed() {
        let mut env = ok_required();
        env.insert("SKIP_COSIGN_VERIFY", "0");
        run(env, false).expect("falsy flag should not trip the gate");
    }

    #[test]
    fn release_requires_trustee_policy_read_available() {
        let mut env = ok_required();
        env.remove("TRUSTEE_POLICY_READ_AVAILABLE");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::MissingRequired("TRUSTEE_POLICY_READ_AVAILABLE")
        ));
    }

    #[test]
    fn release_rejects_legacy_bootstrap_script() {
        let mut env = ok_required();
        env.insert("TRUSTEE_POLICY_READ_AVAILABLE", "true");
        env.insert("LEGACY_BOOTSTRAP_SCRIPT", "true");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::DebugOnlyFlagInRelease("LEGACY_BOOTSTRAP_SCRIPT")
        ));
    }

    #[test]
    fn release_rejects_http_kbs_url() {
        let mut env = ok_required();
        env.insert("TRUSTEE_POLICY_READ_AVAILABLE", "true");
        env.insert("TRUSTEE_KBS_URL", "http://kbs.example.test:8080");
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::DebugOnlyFlagInRelease("TRUSTEE_KBS_URL")
        ));
    }

    #[test]
    fn release_rejects_production_acme_without_explicit_allow() {
        let mut env = ok_required();
        env.insert(
            "ACME_DIRECTORY_URL",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::ProductionAcmeWithoutExplicitAllow("ACME_DIRECTORY_URL")
        ));
    }

    #[test]
    fn release_rejects_production_tenant_caddy_acme_without_explicit_allow() {
        let mut env = ok_required();
        env.insert(
            "TENANT_CADDY_ACME_CA",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        let err = run(env, false).unwrap_err();
        assert!(matches!(
            err,
            EnvGateError::ProductionAcmeWithoutExplicitAllow("TENANT_CADDY_ACME_CA")
        ));
    }

    #[test]
    fn release_allows_staging_acme() {
        let mut env = ok_required();
        env.insert(
            "ACME_DIRECTORY_URL",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );
        env.insert(
            "TENANT_CADDY_ACME_CA",
            "https://acme-staging-v02.api.letsencrypt.org/directory",
        );
        run(env, false).expect("staging ACME should be allowed by default");
    }

    #[test]
    fn release_allows_production_acme_with_explicit_allow() {
        let mut env = ok_required();
        env.insert("CAP_ALLOW_PRODUCTION_ACME", "true");
        env.insert(
            "ACME_DIRECTORY_URL",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        env.insert(
            "TENANT_CADDY_ACME_CA",
            "https://acme-v02.api.letsencrypt.org/directory",
        );
        run(env, false).expect("explicit production ACME override should be allowed");
    }
}
