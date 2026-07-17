use kube::Client;

use super::types::ApplyConfig;

/// Error type for all K8s apply/watch/cleanup operations.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

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
