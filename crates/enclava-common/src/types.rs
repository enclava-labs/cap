use serde::{Deserialize, Serialize};

/// Tier determines resource limits and app count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Free,
    Pro,
    Enterprise,
}

/// How the app's encrypted storage is unlocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UnlockMode {
    /// Owner seed wrapped for KBS-attestation-gated release; no user
    /// interaction needed on restart.
    #[default]
    Auto,
    /// Requires user password via claim/unlock flow.
    Password,
}

/// Volume durability class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Durability {
    /// Fail closed on key mismatch — data loss is unacceptable.
    DurableState,
    /// May reinitialize on mismatch — data is recreatable.
    DisposableState,
}

/// Bootstrap policy for LUKS volume initialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapPolicy {
    /// Initialize only when no LUKS header exists yet.
    FirstBootOnly,
    /// Reset on mismatch. Only valid for disposable state.
    AllowReinit,
    /// Any mismatch is a hard failure.
    NeverReinit,
}

/// Resource limits for an app, constrained by tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub cpu: String,
    pub memory: String,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu: "1".to_string(),
            memory: "1Gi".to_string(),
        }
    }
}

/// Tier-level resource constraints.
pub struct TierLimits {
    pub max_apps: u32,
    pub max_cpu: &'static str,
    pub max_memory: &'static str,
    pub max_app_data_storage: &'static str,
}

impl Tier {
    pub fn limits(&self) -> TierLimits {
        match self {
            Tier::Free => TierLimits {
                max_apps: 1,
                max_cpu: "1",
                max_memory: "1Gi",
                max_app_data_storage: "5Gi",
            },
            Tier::Pro => TierLimits {
                max_apps: 5,
                max_cpu: "4",
                max_memory: "8Gi",
                max_app_data_storage: "50Gi",
            },
            Tier::Enterprise => TierLimits {
                max_apps: u32::MAX,
                max_cpu: "32",
                max_memory: "64Gi",
                max_app_data_storage: "500Gi",
            },
        }
    }
}
