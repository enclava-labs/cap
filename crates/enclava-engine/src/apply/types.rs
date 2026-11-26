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
    /// Rollout budget excluding volume-size-dependent initialization work.
    pub rollout_timeout: Duration,
    /// Polling interval for rollout status checks.
    pub poll_interval: Duration,
    /// Timeout for waiting on PVC deletion during cleanup.
    pub pvc_delete_timeout: Duration,
    /// Timeout for waiting on namespace deletion during cleanup.
    pub namespace_delete_timeout: Duration,
}

impl ApplyConfig {
    /// Rollout budget for this render. The configured baseline (600s in
    /// [`ApplyConfig::default`]) always applies. Only claims `fresh` marked
    /// as lacking positive initialization evidence — the admission signal the
    /// security review called `expects_fresh_volume` — add the first-boot
    /// allowance: two sequential passes at 32 MiB/s. Selected claims are
    /// summed in MiB (each already ceiled) and rounded up once
    /// (`ceil(total_fresh_MiB / 16)` seconds), qualified to the selected
    /// storage backend, not a universal SLA. An already-initialized volume is opened, never re-scanned, so an
    /// ordinary redeploy or domain reapply must not inherit the fresh-format
    /// wait.
    ///
    /// This value is floor and deadline control only. It is not the signed
    /// volume-provenance claim in cap#249, and it never authorizes skipping
    /// the in-guest zero scan. Callers persist the result once; observer
    /// restarts reuse that recorded deadline instead of recomputing it.
    pub fn rollout_timeout_for_storage(
        &self,
        app_data_size: &str,
        tls_data_size: &str,
        fresh: crate::apply::orchestrator::FreshVolumeClaims,
    ) -> Result<Duration, String> {
        let mut total_mib = 0u128;
        for (selected, size) in [
            (fresh.app_data, app_data_size),
            (fresh.tls_data, tls_data_size),
        ] {
            if selected {
                total_mib = total_mib
                    .checked_add(crate::validate::storage_quantity_mib_ceil(size)?)
                    .ok_or("volume initialization size is too large")?;
            }
        }
        // Two passes at 32 MiB/s, qualified to the selected storage backend,
        // not a universal SLA. seconds = ceil(combined fresh MiB / 16), not
        // a per-claim ceil. Recalibrate if qualified guests on that backend
        // are slower. Not cap#249: this never skips the in-guest zero scan.
        let seconds = u64::try_from(total_mib.div_ceil(16))
            .map_err(|_| "volume initialization duration is too large")?;
        self.rollout_timeout
            .checked_add(Duration::from_secs(seconds))
            .ok_or_else(|| "volume initialization duration is too large".to_string())
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apply::orchestrator::FreshVolumeClaims;

    #[test]
    fn rollout_budget_selects_only_fresh_claims() {
        let config = ApplyConfig::default();
        // Initialized volumes only open: the base budget applies verbatim.
        let initialized = config
            .rollout_timeout_for_storage("2Ti", "2Ti", FreshVolumeClaims::NONE)
            .unwrap();
        assert_eq!(initialized, config.rollout_timeout);

        // A single fresh claim adds only its own two-pass allowance: the
        // mixed budget is exactly the all-fresh budget minus the other
        // claim's share.
        let tls_only = config
            .rollout_timeout_for_storage(
                "2Ti",
                "2Ti",
                FreshVolumeClaims {
                    app_data: false,
                    tls_data: true,
                },
            )
            .unwrap();
        let all = config
            .rollout_timeout_for_storage("2Ti", "2Ti", FreshVolumeClaims::ALL)
            .unwrap();
        assert!(initialized < tls_only && tls_only < all);
        assert_eq!(all - tls_only, tls_only - initialized);

        // A non-selected claim contributes nothing, so its quantity is never
        // consulted.
        assert_eq!(
            config
                .rollout_timeout_for_storage(
                    "bogus",
                    "32Mi",
                    FreshVolumeClaims {
                        app_data: false,
                        tls_data: true,
                    },
                )
                .unwrap(),
            config
                .rollout_timeout_for_storage(
                    "2Ti",
                    "32Mi",
                    FreshVolumeClaims {
                        app_data: false,
                        tls_data: true,
                    },
                )
                .unwrap()
        );
    }

    /// cap#257: pin the absolute arithmetic, not only relative ordering.
    /// Default baseline is 600s. Selected fresh claims add
    /// `ceil(total_fresh_MiB / 16)` seconds (two passes at the qualified
    /// 32 MiB/s selected-backend estimate) on top of whatever baseline is
    /// configured. The ceil is on the combined MiB, not per claim. An
    /// initialized redeploy keeps the baseline alone, at any size.
    /// Persistence of that result is covered by the API observer test, not
    /// here.
    #[test]
    fn fresh_claim_budget_is_baseline_plus_two_passes_at_32_mib_s() {
        let config = ApplyConfig::default();
        let baseline = Duration::from_secs(600);
        assert_eq!(config.rollout_timeout, baseline);

        let initialized = config
            .rollout_timeout_for_storage("2Ti", "2Ti", FreshVolumeClaims::NONE)
            .unwrap();
        assert_eq!(initialized, baseline);

        // 1Gi = 1024 MiB; two passes at 32 MiB/s = 64s. TLS is not selected,
        // so a huge tls quantity must not move the budget.
        let app_only = config
            .rollout_timeout_for_storage(
                "1Gi",
                "2Ti",
                FreshVolumeClaims {
                    app_data: true,
                    tls_data: false,
                },
            )
            .unwrap();
        assert_eq!(app_only, baseline + Duration::from_secs(64));

        // 32Mi / 32 MiB/s * 2 = 2s. The unselected app quantity is ignored.
        let tls_only = config
            .rollout_timeout_for_storage(
                "not-a-quantity",
                "32Mi",
                FreshVolumeClaims {
                    app_data: false,
                    tls_data: true,
                },
            )
            .unwrap();
        assert_eq!(tls_only, baseline + Duration::from_secs(2));

        // 33Mi does not divide 16: ceil(33/16) = 3, not a truncated 2.
        let rounded = config
            .rollout_timeout_for_storage(
                "33Mi",
                "1Gi",
                FreshVolumeClaims {
                    app_data: true,
                    tls_data: false,
                },
            )
            .unwrap();
        assert_eq!(rounded, baseline + Duration::from_secs(3));

        let both = config
            .rollout_timeout_for_storage("1Gi", "32Mi", FreshVolumeClaims::ALL)
            .unwrap();
        assert_eq!(both, baseline + Duration::from_secs(64 + 2));

        // Combined ceil, not per-claim: 33+33 = 66 MiB, ceil(66/16) = 5,
        // not 3+3.
        let combined = config
            .rollout_timeout_for_storage("33Mi", "33Mi", FreshVolumeClaims::ALL)
            .unwrap();
        assert_eq!(combined, baseline + Duration::from_secs(5));

        // The allowance is added to the configured baseline, not a hardcoded
        // 600 inside the function. A non-default baseline must survive.
        let custom = ApplyConfig {
            rollout_timeout: Duration::from_secs(90),
            ..ApplyConfig::default()
        };
        assert_eq!(
            custom
                .rollout_timeout_for_storage("2Ti", "2Ti", FreshVolumeClaims::NONE)
                .unwrap(),
            Duration::from_secs(90)
        );
        assert_eq!(
            custom
                .rollout_timeout_for_storage(
                    "32Mi",
                    "32Mi",
                    FreshVolumeClaims {
                        app_data: true,
                        tls_data: false,
                    },
                )
                .unwrap(),
            Duration::from_secs(92)
        );
    }
}
