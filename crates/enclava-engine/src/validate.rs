use enclava_common::log_encryption;
use enclava_common::validate::{ValidateError, validate_fqdn};

use crate::types::ConfidentialApp;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("app name is invalid: {0}")]
    InvalidName(String),
    #[error("namespace is invalid: {0}")]
    InvalidNamespace(String),
    #[error("service account is invalid: {0}")]
    InvalidServiceAccount(String),
    #[error("tenant id is invalid: {0}")]
    InvalidTenantId(String),
    #[error("at least one container is required")]
    NoContainers,
    #[error("exactly one primary container is required")]
    NoPrimaryContainer,
    #[error("container '{name}' image must be pinned by digest: {detail}")]
    ImageNotPinned { name: String, detail: String },
    #[error("bootstrap_owner_pubkey_hash must not be empty")]
    EmptyPubkeyHash,
    #[error("tenant_instance_identity_hash must not be empty")]
    EmptyIdentityHash,
    #[error("tenant_instance_identity_hash must be 64 hex characters (SHA256), got {0} chars")]
    InvalidIdentityHashLength(usize),
    #[error("tenant_instance_identity_hash must be lowercase hex, got non-hex characters")]
    InvalidIdentityHashHex,
    #[error("sidecar image '{name}' must be pinned by digest: {detail}")]
    SidecarImageNotPinned { name: String, detail: String },
    #[error("verification material exceeds 716800 bytes")]
    VerificationMaterialTooLarge,
    #[error("resource quantity is invalid: {field} ({detail})")]
    InvalidResourceQuantity { field: &'static str, detail: String },
    #[error("storage size is invalid: {field} ({detail})")]
    InvalidStorageSize { field: &'static str, detail: String },
    #[error("domain is invalid: {field} ({detail})")]
    InvalidDomain { field: &'static str, detail: String },
    #[error("egress_allowlist entry {index} is invalid: {detail}")]
    InvalidEgressAllowlist { index: usize, detail: String },
    #[error("attestation pubkey is invalid: {field} ({detail})")]
    InvalidAttestationPubkey { field: &'static str, detail: String },
    #[error("log_encryption config is invalid: {0}")]
    InvalidLogEncryption(String),
}

/// Validates that a ConfidentialApp spec is well-formed.
/// Does NOT check cluster state or tier limits -- those are API-level concerns.
pub fn validate_app(app: &ConfidentialApp) -> Result<(), ValidationError> {
    validate_name(&app.name)?;

    // Namespace, service account, and tenant id are interpolated into
    // Kubernetes object names, labels, Rego policy, and TOML config; they must
    // be DNS-label safe (defense in depth on top of API-side validation).
    validate_dns_label_field(&app.namespace, ValidationError::InvalidNamespace)?;
    validate_dns_label_field(&app.service_account, ValidationError::InvalidServiceAccount)?;
    validate_dns_label_field(&app.tenant_id, ValidationError::InvalidTenantId)?;
    if app.namespace.len() > 63 {
        return Err(ValidationError::InvalidNamespace(
            "namespace exceeds 63 characters".to_string(),
        ));
    }

    if app.containers.is_empty() {
        return Err(ValidationError::NoContainers);
    }

    let primary_count = app.containers.iter().filter(|c| c.is_primary).count();
    if primary_count != 1 {
        return Err(ValidationError::NoPrimaryContainer);
    }

    for container in &app.containers {
        if let Err(e) = container.image.require_digest() {
            return Err(ValidationError::ImageNotPinned {
                name: container.name.clone(),
                detail: e.to_string(),
            });
        }
    }

    // Identity fields are required for ALL apps (OID-1).
    if app.bootstrap_owner_pubkey_hash.is_empty() {
        return Err(ValidationError::EmptyPubkeyHash);
    }

    if app.tenant_instance_identity_hash.is_empty() {
        return Err(ValidationError::EmptyIdentityHash);
    }

    if app.tenant_instance_identity_hash.len() != 64 {
        return Err(ValidationError::InvalidIdentityHashLength(
            app.tenant_instance_identity_hash.len(),
        ));
    }

    if !app
        .tenant_instance_identity_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(ValidationError::InvalidIdentityHashHex);
    }

    // Sidecar images must also be digest-pinned.
    if let Err(e) = app.attestation.proxy_image.require_digest() {
        return Err(ValidationError::SidecarImageNotPinned {
            name: "attestation-proxy".to_string(),
            detail: e.to_string(),
        });
    }

    if let Err(e) = app.attestation.caddy_image.require_digest() {
        return Err(ValidationError::SidecarImageNotPinned {
            name: "caddy".to_string(),
            detail: e.to_string(),
        });
    }

    if app
        .attestation
        .verification_material
        .as_ref()
        .is_some_and(|material| material.len() > crate::manifest::verification_material::MAX_BYTES)
    {
        return Err(ValidationError::VerificationMaterialTooLarge);
    }

    // The engine interpolates resources, storage sizes, domains, egress
    // rules, and attestation/log-encryption material into Kubernetes
    // manifests and cc_init_data. The API validates these on admission;
    // the engine re-validates as defense in depth so a DB write that
    // bypassed the API (or a future admission gap) cannot reach manifest
    // generation with malformed values (#138).
    validate_resource_quantity("cpu", &app.resources.cpu).map_err(|detail| {
        ValidationError::InvalidResourceQuantity {
            field: "cpu",
            detail,
        }
    })?;
    // Memory limits use the same binary Mi/Gi/Ti grammar as storage sizes
    // (the API's parse_binary_mib), not the CPU millicore grammar, so the
    // shared binary-quantity validator is reused here; the error is filed
    // as a resource-quantity error with field "memory" for caller clarity.
    validate_storage_size("memory", &app.resources.memory).map_err(|detail| {
        ValidationError::InvalidResourceQuantity {
            field: "memory",
            detail: format!("memory uses binary Mi/Gi/Ti units: {detail}"),
        }
    })?;
    validate_storage_size("storage.app_data.size", &app.storage.app_data.size).map_err(
        |detail| ValidationError::InvalidStorageSize {
            field: "storage.app_data.size",
            detail,
        },
    )?;
    validate_storage_size("storage.tls_data.size", &app.storage.tls_data.size).map_err(
        |detail| ValidationError::InvalidStorageSize {
            field: "storage.tls_data.size",
            detail,
        },
    )?;

    validate_domain("domain.platform_domain", &app.domain.platform_domain)?;
    if let Some(custom) = app.domain.custom_domain.as_deref() {
        validate_domain("domain.custom_domain", custom)?;
    }

    for (index, rule) in app.egress_allowlist.iter().enumerate() {
        validate_egress_rule(rule)
            .map_err(|detail| ValidationError::InvalidEgressAllowlist { index, detail })?;
    }

    validate_attestation_pubkey(
        "attestation.platform_trustee_policy_pubkey_hex",
        app.attestation
            .platform_trustee_policy_pubkey_hex
            .as_deref(),
    )?;
    validate_attestation_pubkey(
        "attestation.signing_service_pubkey_hex",
        app.attestation.signing_service_pubkey_hex.as_deref(),
    )?;

    if let Some(config) = app.log_encryption.as_ref() {
        log_encryption::validate_public_key(
            config.key_id.clone(),
            config.public_key_base64url.clone(),
            config.public_key_sha256.clone(),
        )
        .map_err(|e| ValidationError::InvalidLogEncryption(e.to_string()))?;
        if config.algorithm != log_encryption::LOG_ENCRYPTION_ALGORITHM {
            return Err(ValidationError::InvalidLogEncryption(format!(
                "unsupported algorithm {:?}; expected {:?}",
                config.algorithm,
                log_encryption::LOG_ENCRYPTION_ALGORITHM
            )));
        }
    }

    Ok(())
}

/// CPU quantity: millicore (`250m`) or whole cores (`1`, `1.5`), matching the
/// API's `parse_cpu_cores` admission grammar.
fn validate_resource_quantity(field: &'static str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} must be a non-empty CPU quantity"));
    }
    let numeric = trimmed.strip_suffix('m').unwrap_or(trimmed);
    // Match the API's ScaledDecimal grammar: plain decimal digits with an
    // optional single `.` separator. f64 parsing would also admit `1e2`,
    // `+5`, `5.`, and `inf`-adjacent forms the API never writes.
    let mut seen_dot = false;
    let valid = !numeric.is_empty()
        && numeric.chars().all(|c| match c {
            '0'..='9' => true,
            '.' if !seen_dot => {
                seen_dot = true;
                true
            }
            _ => false,
        })
        && !numeric.starts_with('.')
        && !numeric.ends_with('.');
    if !valid {
        return Err(format!(
            "{field} must be a positive number or millicpu quantity"
        ));
    }
    let parsed: f64 = numeric
        .parse()
        .map_err(|_| format!("{field} must be a positive number or millicpu quantity"))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(format!(
            "{field} must be a positive number or millicpu quantity"
        ));
    }
    Ok(())
}

/// Storage/memory binary quantity with an explicit Mi/Gi/Ti (or MiB/GiB/TiB)
/// suffix, matching the API's `parse_binary_mib` admission grammar. The value
/// must be a positive number; a bare number without a unit is rejected so the
/// quota/summing code never silently treats bytes as MiB.
fn validate_storage_size(field: &'static str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} must be a non-empty binary quantity"));
    }
    let units = ["TiB", "Ti", "GiB", "Gi", "MiB", "Mi"];
    let Some((number, _)) = units
        .iter()
        .find_map(|suffix| trimmed.strip_suffix(suffix).map(|n| (n, *suffix)))
    else {
        return Err(format!("{field} must use Mi, Gi, or Ti binary units"));
    };
    let parsed: f64 = number
        .parse()
        .map_err(|_| format!("{field} must be a positive binary quantity"))?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(format!("{field} must be a positive binary quantity"));
    }
    Ok(())
}

fn validate_domain(field: &'static str, value: &str) -> Result<(), ValidationError> {
    validate_fqdn(value).map_err(|e| ValidationError::InvalidDomain {
        field,
        detail: fqdn_error_detail(e),
    })
}

/// Structural egress-rule validation only. The API additionally enforces the
/// internal-host denylist (localhost, metadata, *.svc, rebinding helpers)
/// with an operator opt-in env (`enforce_egress_allowlist_host`); that policy
/// decision stays API-side so the engine does not second-guess operator
/// opt-outs on rows the API already admitted.
fn validate_egress_rule(rule: &crate::types::EgressRule) -> Result<(), String> {
    if rule.host.parse::<std::net::IpAddr>().is_ok() {
        return Err("host must be a DNS hostname, not an IP address".to_string());
    }
    validate_fqdn(&rule.host).map_err(|e| format!("invalid host: {}", fqdn_error_detail(e)))?;
    if rule.ports.is_empty() {
        return Err("ports must not be empty".to_string());
    }
    Ok(())
}

/// Optional Ed25519 public key, hex encoded (64 hex chars) when present.
fn validate_attestation_pubkey(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ValidationError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.len() != 64
        || !value
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    {
        return Err(ValidationError::InvalidAttestationPubkey {
            field,
            detail: "must be 64 lowercase hex characters (Ed25519 public key)".to_string(),
        });
    }
    Ok(())
}

fn fqdn_error_detail(error: ValidateError) -> String {
    match error {
        ValidateError::InvalidFqdn(detail) => detail.to_string(),
        other => other.to_string(),
    }
}

/// Validates that a name is DNS-safe: lowercase alphanumeric + hyphens, starts with letter/digit.
fn validate_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::InvalidName(
            "name cannot be empty".to_string(),
        ));
    }

    let valid = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit());

    if !valid {
        return Err(ValidationError::InvalidName(format!(
            "'{name}' must be lowercase alphanumeric with hyphens, starting with a letter or digit"
        )));
    }

    Ok(())
}

/// DNS-label check shared by namespace / service-account / tenant-id fields.
fn validate_dns_label_field(
    value: &str,
    error: fn(String) -> ValidationError,
) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(error("cannot be empty".to_string()));
    }
    let valid = value
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !value.starts_with('-')
        && !value.ends_with('-');
    if !valid {
        return Err(error(format!(
            "'{value}' must be lowercase alphanumeric with hyphens, not starting or ending with '-'"
        )));
    }
    Ok(())
}
