use std::time::Duration;

/// Phase of a deployment rollout. Progresses monotonically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DeployPhase {
    /// SSA applying manifests to cluster.
    Applying = 0,
    /// Pods have been scheduled to a node.
    PodsScheduled = 1,
    /// Kata VM (TEE) is starting.
    TeeBooting = 2,
    /// Attestation proxy is contacting KBS.
    Attesting = 3,
    /// All containers ready, app is serving traffic.
    Running = 4,
    /// Deployment failed (container crash, attestation failure, etc.).
    Failed = 5,
    /// Rollout exceeded the configured timeout.
    TimedOut = 6,
}

/// Snapshot of deployment progress.
#[derive(Debug, Clone)]
pub struct DeployStatus {
    pub phase: DeployPhase,
    pub message: Option<String>,
}

impl DeployStatus {
    pub fn new() -> Self {
        Self {
            phase: DeployPhase::Applying,
            message: None,
        }
    }

    pub fn with_phase(phase: DeployPhase) -> Self {
        Self {
            phase,
            message: None,
        }
    }

    pub fn failed(msg: &str) -> Self {
        Self {
            phase: DeployPhase::Failed,
            message: Some(msg.to_string()),
        }
    }

    pub fn timed_out(msg: &str) -> Self {
        Self {
            phase: DeployPhase::TimedOut,
            message: Some(msg.to_string()),
        }
    }

    /// Whether this status represents a final state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            DeployPhase::Running | DeployPhase::Failed | DeployPhase::TimedOut
        )
    }
}

impl Default for DeployStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for apply and watch operations.
#[derive(Debug, Clone)]
pub struct ApplyConfig {
    /// SSA field manager name.
    pub field_manager: String,
    /// Maximum time to wait for rollout to complete.
    pub rollout_timeout: Duration,
    /// Polling interval for rollout status checks.
    pub poll_interval: Duration,
    /// Timeout for waiting on PVC deletion during cleanup.
    pub pvc_delete_timeout: Duration,
    /// Timeout for waiting on namespace deletion during cleanup.
    pub namespace_delete_timeout: Duration,
}

impl Default for ApplyConfig {
    fn default() -> Self {
        Self {
            field_manager: "enclava-platform".to_string(),
            rollout_timeout: Duration::from_secs(600),
            poll_interval: Duration::from_secs(5),
            pvc_delete_timeout: Duration::from_secs(120),
            namespace_delete_timeout: Duration::from_secs(120),
        }
    }
}
