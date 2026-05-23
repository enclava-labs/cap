use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceProvider {
    #[serde(rename = "github")]
    GitHub,
    #[serde(rename = "gitlab")]
    GitLab,
}

impl SourceProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GitHub => "github",
            Self::GitLab => "gitlab",
        }
    }

    pub fn default_issuer(self) -> &'static str {
        match self {
            Self::GitHub => "https://token.actions.githubusercontent.com",
            Self::GitLab => "https://gitlab.com",
        }
    }

    fn registry_host(self) -> &'static str {
        match self {
            Self::GitHub => "ghcr.io",
            Self::GitLab => "registry.gitlab.com",
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SourceProviderError {
    #[error("source provider requires source_repository")]
    MissingRepository,
    #[error("source_repository `{0}` is invalid for provider `{1}`")]
    InvalidRepository(String, &'static str),
    #[error("image registry `{actual}` does not match provider `{provider}` registry `{expected}`")]
    RegistryMismatch {
        provider: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("signing issuer `{actual}` does not match provider `{provider}` issuer `{expected}`")]
    IssuerMismatch {
        provider: &'static str,
        expected: &'static str,
        actual: String,
    },
    #[error("image repository `{actual}` does not match source repository `{expected}`")]
    ImageRepositoryMismatch { expected: String, actual: String },
    #[error("signing subject `{subject}` does not match source repository `{repository}`")]
    SubjectMismatch { repository: String, subject: String },
    #[error("invalid image reference: {0}")]
    InvalidImage(String),
}

pub fn validate_source_repository(
    provider: SourceProvider,
    repository: &str,
) -> Result<(), SourceProviderError> {
    let parts = repository_parts(provider, repository)?;
    match provider {
        SourceProvider::GitHub if parts.len() == 2 => Ok(()),
        SourceProvider::GitHub => Err(SourceProviderError::InvalidRepository(
            repository.to_string(),
            provider.as_str(),
        )),
        SourceProvider::GitLab if parts.len() >= 2 => Ok(()),
        SourceProvider::GitLab => Err(SourceProviderError::InvalidRepository(
            repository.to_string(),
            provider.as_str(),
        )),
    }
}

pub fn validate_signing_identity(
    provider: SourceProvider,
    repository: &str,
    subject: &str,
    issuer: &str,
) -> Result<(), SourceProviderError> {
    validate_source_repository(provider, repository)?;
    validate_issuer(provider, issuer)?;
    validate_subject(provider, repository, subject)
}

pub fn validate_source_context(
    provider: SourceProvider,
    repository: &str,
    image: &str,
    subject: &str,
    issuer: &str,
) -> Result<(), SourceProviderError> {
    validate_signing_identity(provider, repository, subject, issuer)?;

    let image_ref = enclava_common::image::ImageRef::parse(image)
        .map_err(|e| SourceProviderError::InvalidImage(e.to_string()))?;
    if image_ref.registry() != provider.registry_host() {
        return Err(SourceProviderError::RegistryMismatch {
            provider: provider.as_str(),
            expected: provider.registry_host(),
            actual: image_ref.registry().to_string(),
        });
    }

    match provider {
        SourceProvider::GitHub => {
            let owner = repository_parts(provider, repository)?
                .into_iter()
                .next()
                .ok_or(SourceProviderError::MissingRepository)?;
            let expected_prefix = format!("{owner}/");
            if !image_ref.repository().starts_with(&expected_prefix) {
                return Err(SourceProviderError::ImageRepositoryMismatch {
                    expected: expected_prefix,
                    actual: image_ref.repository().to_string(),
                });
            }
        }
        SourceProvider::GitLab => {
            if image_ref.repository() != repository
                && !image_ref
                    .repository()
                    .starts_with(&format!("{repository}/"))
            {
                return Err(SourceProviderError::ImageRepositoryMismatch {
                    expected: repository.to_string(),
                    actual: image_ref.repository().to_string(),
                });
            }
        }
    }

    Ok(())
}

fn validate_issuer(provider: SourceProvider, issuer: &str) -> Result<(), SourceProviderError> {
    if issuer == provider.default_issuer() {
        Ok(())
    } else {
        Err(SourceProviderError::IssuerMismatch {
            provider: provider.as_str(),
            expected: provider.default_issuer(),
            actual: issuer.to_string(),
        })
    }
}

fn validate_subject(
    provider: SourceProvider,
    repository: &str,
    subject: &str,
) -> Result<(), SourceProviderError> {
    let expected_prefix = match provider {
        SourceProvider::GitHub => format!("https://github.com/{repository}/"),
        SourceProvider::GitLab => format!("https://gitlab.com/{repository}/"),
    };
    if subject.starts_with(&expected_prefix) {
        Ok(())
    } else {
        Err(SourceProviderError::SubjectMismatch {
            repository: repository.to_string(),
            subject: subject.to_string(),
        })
    }
}

fn repository_parts(
    provider: SourceProvider,
    repository: &str,
) -> Result<Vec<&str>, SourceProviderError> {
    if repository.trim() != repository || repository.is_empty() {
        return Err(SourceProviderError::InvalidRepository(
            repository.to_string(),
            provider.as_str(),
        ));
    }
    let parts: Vec<&str> = repository.split('/').collect();
    if parts.iter().any(|part| !valid_repository_segment(part)) {
        return Err(SourceProviderError::InvalidRepository(
            repository.to_string(),
            provider.as_str(),
        ));
    }
    Ok(parts)
}

fn valid_repository_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_github_source_context_passes() {
        validate_source_context(
            SourceProvider::GitHub,
            "acme/confidential-app",
            "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        )
        .unwrap();
    }

    #[test]
    fn valid_gitlab_source_context_passes() {
        validate_source_context(
            SourceProvider::GitLab,
            "acme/platform/confidential-app",
            "registry.gitlab.com/acme/platform/confidential-app/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://gitlab.com/acme/platform/confidential-app/-/blob/main/.gitlab-ci.yml@refs/heads/main",
            "https://gitlab.com",
        )
        .unwrap();
    }

    #[test]
    fn github_provider_rejects_gitlab_registry() {
        let err = validate_source_context(
            SourceProvider::GitHub,
            "acme/confidential-app",
            "registry.gitlab.com/acme/confidential-app/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        )
        .unwrap_err();

        assert!(matches!(err, SourceProviderError::RegistryMismatch { .. }));
    }

    #[test]
    fn gitlab_provider_rejects_ghcr_registry() {
        let err = validate_source_context(
            SourceProvider::GitLab,
            "acme/confidential-app",
            "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://gitlab.com/acme/confidential-app/-/blob/main/.gitlab-ci.yml@refs/heads/main",
            "https://gitlab.com",
        )
        .unwrap_err();

        assert!(matches!(err, SourceProviderError::RegistryMismatch { .. }));
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let err = validate_source_context(
            SourceProvider::GitLab,
            "acme/confidential-app",
            "registry.gitlab.com/acme/confidential-app/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://gitlab.com/acme/confidential-app/-/blob/main/.gitlab-ci.yml@refs/heads/main",
            "https://token.actions.githubusercontent.com",
        )
        .unwrap_err();

        assert!(matches!(err, SourceProviderError::IssuerMismatch { .. }));
    }

    #[test]
    fn source_repository_must_match_image_namespace() {
        let err = validate_source_context(
            SourceProvider::GitLab,
            "acme/confidential-app",
            "registry.gitlab.com/other/confidential-app/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "https://gitlab.com/acme/confidential-app/-/blob/main/.gitlab-ci.yml@refs/heads/main",
            "https://gitlab.com",
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SourceProviderError::ImageRepositoryMismatch { .. }
        ));
    }
}
