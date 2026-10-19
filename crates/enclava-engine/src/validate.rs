use std::path::Component;

use enclava_common::log_encryption;
use enclava_common::validate::validate_fqdn;

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
    #[error("storage path {path:?} is invalid: {detail}")]
    InvalidStoragePath { path: String, detail: String },
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
    // Grammar only (positive binary quantity): the 32 MiB fresh-format
    // floor is deliberately NOT here — validate_app runs on every apply
    // path and the spec carries no provisioning state, so a floor would
    // break reapplies of apps whose volumes predate it. Callers enforce
    // validate_persistent_volume_size_for_fresh_provisioning when the size
    // governs a fresh volume (API admission; apply_and_watch's PVC check).
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
    // tee_domain flows into the attestation container's TEE_DOMAIN env and
    // the TEE TLSRoute hostname, so it gets the same FQDN gate as the other
    // domains (defense in depth for rows that bypassed API admission).
    validate_domain("domain.tee_domain", &app.domain.tee_domain)?;
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

    // cap#290 review: the v2 log spool lives at <state-root>/.enclava/
    // log-spool and is bind-mounted over /run/enclava-logs. A tenant
    // storage_path mapping onto the reserved .enclava state subdir would
    // share that directory with the spool, so wait-exec could append to
    // and rotate tenant files as encrypted-log data; a storage_path whose
    // guest mount covers the spool target (the dir itself, an ancestor
    // that would shadow the bind, or a descendant the bind would mount
    // over) collides the same way. Reject both at validation instead of
    // rendering a corrupting manifest, and require enough state PVC for
    // the 32 MiB rotation cap plus temp/headroom.
    if crate::manifest::enclava_init_config::log_spool_state_bind(app) {
        // Exact rational compare — no rounding: a fractional quantity just
        // under the floor (e.g. 127.5Mi) must not ceil past it.
        if let Some((numerator, scale)) = binary_quantity_mib_parts(&app.storage.app_data.size)
            && numerator < LOG_SPOOL_MIN_STATE_MIB * 10u128.pow(scale)
        {
            return Err(ValidationError::InvalidStorageSize {
                field: "storage.app_data.size",
                detail: format!(
                    "guest-memory-v2 log spool binds to the state PVC and needs at \
                     least {LOG_SPOOL_MIN_STATE_MIB}Mi (32Mi rotation cap plus \
                     rotation-temp and fs/platform headroom), got {:?}",
                    app.storage.app_data.size
                ),
            });
        }
        for container in &app.containers {
            for path in &container.storage_paths {
                if crate::manifest::enclava_init_config::storage_subdir(path) == ".enclava" {
                    return Err(ValidationError::InvalidStoragePath {
                        path: path.clone(),
                        detail: "maps onto the platform-reserved \".enclava\" state subdir"
                            .to_string(),
                    });
                }
                if mount_path_covers_log_spool_target(path) {
                    return Err(ValidationError::InvalidStoragePath {
                        path: path.clone(),
                        detail: "covers /run/enclava-logs, the encrypted log spool \
                                 bind target"
                            .to_string(),
                    });
                }
            }
        }
    }

    Ok(())
}

/// CPU quantity: millicore (`250m`) or whole cores (`1`, `1.5`), matching the
/// API's `parse_cpu_cores` admission grammar — including the
/// `ScaledDecimal::parse` digit/scale bounds (≤38 total digits, ≤24
/// fractional digits, non-zero, no u128 overflow) so values the API would
/// never persist are rejected here too.
fn validate_resource_quantity(field: &'static str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} must be a non-empty CPU quantity"));
    }
    let numeric = trimmed.strip_suffix('m').unwrap_or(trimmed);
    validate_scaled_decimal(numeric, 1)
        .map(|_| ())
        .map_err(|_| format!("{field} must be a positive number or millicpu quantity"))
}

/// Storage/memory binary quantity with an explicit Mi/Gi/Ti (or MiB/GiB/TiB)
/// suffix, matching the API's `parse_binary_mib` admission grammar. The value
/// must be a positive number; a bare number without a unit is rejected so the
/// quota/summing code never silently treats bytes as MiB. The exact-Mi
/// conversion must not overflow, exactly as the API's `checked_mul` requires.
fn validate_storage_size(field: &'static str, value: &str) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} must be a non-empty binary quantity"));
    }
    let Some((number, multiplier)) = binary_quantity_parts(trimmed) else {
        return Err(format!("{field} must use Mi, Gi, or Ti binary units"));
    };
    validate_scaled_decimal(number, multiplier)
        .map(|_| ())
        .map_err(|_| format!("{field} must be a positive binary quantity"))
}

/// Fresh-provisioning floor for the LUKS-formatted state/tls-state volumes.
/// The LUKS2 header occupies the first 16 MiB and `luksFormat` succeeds on
/// devices that end inside it — activation then has no data area and the
/// volume is bricked. The floor adds 16 MiB of payload headroom. It is a
/// FRESH-format policy, not an activation bound: sub-floor volumes that
/// already exist activate and keep operating, so `validate_app` must not
/// enforce it (see its comment). Enforced in lockstep with enclava-init
/// `MIN_VOLUME_BYTES` — keep the two bounds identical.
pub const MIN_VOLUME_SIZE_MIB: u128 = 32;

/// Fresh-state floor for `storage.app_data.size` when the v2 signed layout
/// re-binds the encrypted log spool onto the state PVC (`log_spool_state_bind`).
/// The spool dir holds a 32 MiB live file plus a rotation temp copy, and the
/// filesystem/platform need headroom on top (cap#290 round-2 review).
pub const LOG_SPOOL_MIN_STATE_MIB: u128 = 128;

/// Whether a guest mount path covers the encrypted log spool bind target
/// `/run/enclava-logs` (cap#290 round-2 review): equal, an ancestor that
/// would shadow the bind (e.g. `/run`, `/`), or a descendant the bind
/// would mount over (`/run/enclava-logs/sub`). Comparison is lexical on
/// normalized components (`.` skipped); a `..` segment fails closed as
/// covering — such paths are invalid downstream anyway.
fn mount_path_covers_log_spool_target(path: &str) -> bool {
    fn normal_components(path: &str) -> Option<Vec<std::ffi::OsString>> {
        let mut out = Vec::new();
        for component in std::path::Path::new(path).components() {
            match component {
                Component::Normal(part) => out.push(part.to_os_string()),
                Component::CurDir => {}
                Component::ParentDir => return None,
                Component::RootDir | Component::Prefix(_) => {}
            }
        }
        Some(out)
    }
    let Some(mount) = normal_components(path) else {
        return true;
    };
    let Some(target) = normal_components("/run/enclava-logs") else {
        return true;
    };
    (mount.len() <= target.len() && target.starts_with(&mount))
        || (target.len() <= mount.len() && mount.starts_with(&target))
}

/// Validate that a persistent-volume size is a positive binary quantity of
/// at least [`MIN_VOLUME_SIZE_MIB`]. Shared by API admission paths; exact
/// rational compare (numerator / 10^scale Mi) — no float rounding.
pub fn validate_persistent_volume_size_for_fresh_provisioning(
    field: &'static str,
    value: &str,
) -> Result<(), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!("{field} must be a non-empty binary quantity"));
    }
    let Some((number, multiplier)) = binary_quantity_parts(trimmed) else {
        return Err(format!("{field} must use Mi, Gi, or Ti binary units"));
    };
    let (numerator, scale) = validate_scaled_decimal(number, multiplier)
        .map_err(|_| format!("{field} must be a positive binary quantity"))?;
    if numerator < MIN_VOLUME_SIZE_MIB * 10u128.pow(scale) {
        return Err(format!(
            "{field} must be at least {MIN_VOLUME_SIZE_MIB}Mi — the fresh-format floor: a LUKS2 volume needs its 16 MiB header plus enough data-area headroom to stay usable"
        ));
    }
    Ok(())
}

/// (suffix, multiplier-in-Mi) pairs mirroring the API's parse_binary_mib.
fn binary_quantity_parts(trimmed: &str) -> Option<(&str, u128)> {
    const BINARY_UNITS: [(&str, u128); 6] = [
        ("TiB", 1024 * 1024),
        ("Ti", 1024 * 1024),
        ("GiB", 1024),
        ("Gi", 1024),
        ("MiB", 1),
        ("Mi", 1),
    ];
    BINARY_UNITS
        .iter()
        .find_map(|(suffix, multiplier)| trimmed.strip_suffix(*suffix).map(|n| (n, *multiplier)))
}

/// `(numerator, scale)` of a binary quantity in Mi units — an exact
/// rational (`value_mib = numerator / 10^scale`) so floors can compare
/// against `MIN * 10^scale` without floats or rounding (mirroring
/// `validate_persistent_volume_size_for_fresh_provisioning`). `None` for
/// grammar-invalid values; callers that already ran the storage grammar
/// may treat that as "no floor opinion".
fn binary_quantity_mib_parts(value: &str) -> Option<(u128, u32)> {
    let (number, multiplier) = binary_quantity_parts(value.trim())?;
    validate_scaled_decimal(number, multiplier).ok()
}

/// Whether a persistent-volume size parses as a valid binary quantity that
/// is strictly below [`MIN_VOLUME_SIZE_MIB`]. Only these sizes can need the
/// fresh-format floor's cluster check; callers must still run
/// `validate_persistent_volume_size_for_fresh_provisioning` for the actual
/// admission error, and grammar-invalid values return false here (they are
/// rejected by the validator/limits path, not waived by claim evidence).
pub fn is_sub_floor_volume_size(value: &str) -> bool {
    let Some((numerator, scale)) = binary_quantity_mib_parts(value) else {
        return false;
    };
    numerator < MIN_VOLUME_SIZE_MIB * 10u128.pow(scale)
}

/// Exact MiB value of a binary quantity, rounded UP. Used where a
/// quantity-derived budget must never underestimate the configured size
/// (e.g. rollout windows sized by volume bytes). Reuses the same grammar
/// and overflow bounds as `validate_storage_size`; errors bubble as plain
/// strings for the caller to wrap.
pub fn storage_quantity_mib_ceil(value: &str) -> Result<u128, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return Err(format!(
            "storage quantity {value:?} must be a non-empty binary quantity"
        ));
    }
    let Some((number, multiplier)) = binary_quantity_parts(trimmed) else {
        return Err(format!(
            "storage quantity {value:?} must use Mi, Gi, or Ti binary units"
        ));
    };
    let (numerator, scale) = validate_scaled_decimal(number, multiplier)
        .map_err(|e| format!("storage quantity {value:?} is invalid: {e}"))?;
    Ok(numerator.div_ceil(10u128.pow(scale)))
}

/// Digit, scale, and overflow bounds mirroring the API's
/// `ScaledDecimal::parse` + `checked_mul` (entitlements.rs): plain decimal
/// grammar, at most 38 total digits, at most 24 fractional digits, non-zero
/// coefficient, and an exact-Mi conversion (`multiplier`) that must not
/// overflow u128. f64 parsing would silently admit all of those. Returns the
/// normalized exact value as `(numerator, scale)` with
/// `value_mib = numerator / 10^scale`, so callers can do exact bounds
/// compares without floats.
fn validate_scaled_decimal(number: &str, multiplier: u128) -> Result<(u128, u32), String> {
    if !is_plain_decimal(number) {
        return Err("must be a positive decimal quantity".to_string());
    }
    let (integer, fraction) = number.split_once('.').unwrap_or((number, ""));
    if integer.len() + fraction.len() > 38 || fraction.len() > 24 {
        return Err("has too much precision".to_string());
    }
    let coefficient: u128 = format!("{integer}{fraction}")
        .parse()
        .map_err(|_| "is too large".to_string())?;
    if coefficient == 0 {
        return Err("must be positive".to_string());
    }
    // Mirror `ScaledDecimal::parse`'s trailing-zero normalization
    // (entitlements.rs `normalized()`) before the exact-Mi multiply: the
    // API divides trailing zeros out of the coefficient as it lowers the
    // scale, so `10000000000000.000000000000000000000000Ti` multiplies
    // 10^13 by 2^20 there — while the raw 38-digit coefficient (10^37)
    // times 2^20 overflows u128. Without this step the engine gate
    // rejected quantities the API accepts (round-16 self-check P3).
    let mut coefficient = coefficient;
    let mut scale = fraction.len();
    while scale > 0 && coefficient.is_multiple_of(10) {
        coefficient /= 10;
        scale -= 1;
    }
    let numerator = coefficient
        .checked_mul(multiplier)
        .ok_or_else(|| "is too large".to_string())?;
    Ok((numerator, scale as u32))
}

/// True for plain decimal digits with at most one interior `.` — the grammar
/// the API's `ScaledDecimal::parse` accepts.
fn is_plain_decimal(s: &str) -> bool {
    let mut seen_dot = false;
    !s.is_empty()
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.chars().all(|c| match c {
            '0'..='9' => true,
            '.' if !seen_dot => {
                seen_dot = true;
                true
            }
            _ => false,
        })
}

fn validate_domain(field: &'static str, value: &str) -> Result<(), ValidationError> {
    validate_fqdn(value).map_err(|e| ValidationError::InvalidDomain {
        field,
        detail: e.to_string(),
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
    validate_fqdn(&rule.host).map_err(|e| format!("invalid host: {e}"))?;
    if rule.ports.is_empty() {
        return Err("ports must not be empty".to_string());
    }
    if rule.ports.contains(&0) {
        return Err("ports must be non-zero".to_string());
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
    // cap#218 follow-up: mirror the release-ingestion checks — the key must
    // decompress to an Edwards point that is not small-order. Policy
    // acceptance uses verify(), not verify_strict(), and a zero signature
    // verifies against a small-order key for a large share of messages.
    let raw = hex::decode(value).map_err(|_| ValidationError::InvalidAttestationPubkey {
        field,
        detail: "must be 64 lowercase hex characters (Ed25519 public key)".to_string(),
    })?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|_| ValidationError::InvalidAttestationPubkey {
            field,
            detail: "must be 64 lowercase hex characters (Ed25519 public key)".to_string(),
        })?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|_| {
        ValidationError::InvalidAttestationPubkey {
            field,
            detail: "not a decompressible Ed25519 public key".to_string(),
        }
    })?;
    if key.is_weak() {
        return Err(ValidationError::InvalidAttestationPubkey {
            field,
            detail: "Ed25519 public key has small order and provides no unforgeability".to_string(),
        });
    }
    Ok(())
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
