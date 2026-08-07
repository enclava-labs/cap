use crate::types::ConfidentialApp;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("app name is invalid: {0}")]
    InvalidName(String),
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
}

/// Validates that a ConfidentialApp spec is well-formed.
/// Does NOT check cluster state or tier limits -- those are API-level concerns.
pub fn validate_app(app: &ConfidentialApp) -> Result<(), ValidationError> {
    validate_name(&app.name)?;

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
