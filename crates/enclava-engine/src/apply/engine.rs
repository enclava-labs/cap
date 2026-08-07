use kube::Client;

use super::types::ApplyConfig;

/// Error type for all K8s apply/watch/cleanup operations.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Kubernetes mutating request exceeded its 30 second deadline")]
    ProviderWriteTimeout,

    #[error("durable provider mutation generation must be positive, got {0}")]
    InvalidMutationGeneration(i64),

    #[error("{kind} '{name}' has invalid provider mutation generation metadata")]
    InvalidLiveMutationGeneration { kind: String, name: String },

    #[error(
        "stale provider mutation for {kind} '{name}': requested generation {desired}, live generation {actual}"
    )]
    StaleMutationGeneration {
        kind: String,
        name: String,
        desired: i64,
        actual: i64,
    },

    #[error(
        "Kubernetes accepted {kind} '{name}' without provider mutation generation {expected} (found {actual})"
    )]
    ProviderGenerationNotApplied {
        kind: String,
        name: String,
        expected: i64,
        actual: i64,
    },

    #[error("{0} is missing the UID, name, or resourceVersion required for a fenced mutation")]
    MissingResourceIdentity(String),

    #[error("{kind} '{name}' was not found for a fenced partial mutation")]
    ResourceNotFound { kind: String, name: String },

    #[error("conditional mutation retries exhausted for {kind} '{name}'")]
    MutationConflictExhausted { kind: String, name: String },

    #[error("namespace '{0}' must be created before applying namespaced resources")]
    NamespaceNotReady(String),

    #[error("rollout timed out after {0:?}: {1}")]
    RolloutTimeout(std::time::Duration, String),

    #[error("rollout failed: {0}")]
    RolloutFailed(String),

    #[error("cleanup step '{step}' failed: {detail}")]
    CleanupStepFailed { step: String, detail: String },

    #[error("teardown proxy notification failed: {0}")]
    TeardownProxyFailed(String),

    #[error("manifest generation error: {0}")]
    ManifestGeneration(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl ApplyError {
    /// Return a bounded failure code safe for persistence and operator logs.
    ///
    /// The wrapped Kubernetes, manifest, and provider messages can contain
    /// workload-controlled names or response text and must stay internal.
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::Kube(_) => "kubernetes_api_error",
            Self::ProviderWriteTimeout => "provider_write_timeout",
            Self::InvalidMutationGeneration(_) => "invalid_mutation_generation",
            Self::InvalidLiveMutationGeneration { .. } => "invalid_live_mutation_generation",
            Self::StaleMutationGeneration { .. } => "stale_mutation_generation",
            Self::ProviderGenerationNotApplied { .. } => "provider_generation_not_applied",
            Self::MissingResourceIdentity(_) => "missing_resource_identity",
            Self::ResourceNotFound { .. } => "resource_not_found",
            Self::MutationConflictExhausted { .. } => "mutation_conflict_exhausted",
            Self::NamespaceNotReady(_) => "namespace_not_ready",
            Self::RolloutTimeout(_, _) => "rollout_timeout",
            Self::RolloutFailed(_) => "rollout_failed",
            Self::CleanupStepFailed { .. } => "cleanup_failed",
            Self::TeardownProxyFailed(_) => "teardown_proxy_failed",
            Self::ManifestGeneration(_) => "manifest_generation_error",
            Self::Serialization(_) => "serialization_error",
        }
    }
}

/// The Kubernetes operations engine. Wraps a kube::Client and applies,
/// watches, cleans up, and drift-checks confidential app resources.
pub struct ApplyEngine {
    client: Client,
    config: ApplyConfig,
}

impl ApplyEngine {
    /// Create an ApplyEngine from an existing kube::Client.
    pub fn new(client: Client, config: ApplyConfig) -> Self {
        Self { client, config }
    }

    /// Create an ApplyEngine using the default kubeconfig (from KUBECONFIG env
    /// or in-cluster service account).
    pub async fn try_default() -> Result<Self, ApplyError> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            config: ApplyConfig::default(),
        })
    }

    /// Create an ApplyEngine with custom config using default kubeconfig.
    pub async fn try_with_config(config: ApplyConfig) -> Result<Self, ApplyError> {
        let client = Client::try_default().await?;
        Ok(Self { client, config })
    }

    /// Returns a reference to the underlying kube::Client.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns a reference to the apply configuration.
    pub fn config(&self) -> &ApplyConfig {
        &self.config
    }
}

#[cfg(test)]
mod public_code_tests {
    use super::ApplyError;

    #[test]
    fn provider_fencing_errors_have_fixed_public_codes() {
        const SECRET: &str = "tenant-secret-resource";
        let errors = [
            (ApplyError::ProviderWriteTimeout, "provider_write_timeout"),
            (
                ApplyError::InvalidMutationGeneration(-1),
                "invalid_mutation_generation",
            ),
            (
                ApplyError::InvalidLiveMutationGeneration {
                    kind: SECRET.to_string(),
                    name: SECRET.to_string(),
                },
                "invalid_live_mutation_generation",
            ),
            (
                ApplyError::StaleMutationGeneration {
                    kind: SECRET.to_string(),
                    name: SECRET.to_string(),
                    desired: 2,
                    actual: 3,
                },
                "stale_mutation_generation",
            ),
            (
                ApplyError::ProviderGenerationNotApplied {
                    kind: SECRET.to_string(),
                    name: SECRET.to_string(),
                    expected: 2,
                    actual: 1,
                },
                "provider_generation_not_applied",
            ),
            (
                ApplyError::MissingResourceIdentity(SECRET.to_string()),
                "missing_resource_identity",
            ),
            (
                ApplyError::ResourceNotFound {
                    kind: SECRET.to_string(),
                    name: SECRET.to_string(),
                },
                "resource_not_found",
            ),
            (
                ApplyError::MutationConflictExhausted {
                    kind: SECRET.to_string(),
                    name: SECRET.to_string(),
                },
                "mutation_conflict_exhausted",
            ),
        ];

        for (error, expected) in errors {
            assert_eq!(error.public_code(), expected);
            assert!(!error.public_code().contains(SECRET));
        }
    }
}
