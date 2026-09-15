//! Workload shape resolution: derive the per-app pod shape from the signed,
//! persisted application memory limit.
//!
//! Two profiles exist:
//!
//! - `Standard` — the long-standing shape: 512Mi app request, 128Mi/256Mi
//!   sidecar budgets, the deployment-default Kata baseline (no annotation), the
//!   deployment-default RuntimeClass, and the 4Gi/1 RuntimeClass overhead in
//!   the tenant ResourceQuota.
//! - `Small` — the capacity-test shape used when the application memory limit
//!   is below the standard app request (512Mi). Such limits are otherwise
//!   undeployable (request must not exceed limit), so gating on them cannot
//!   regress an existing workload. Small apps render with the app request
//!   lowered to the limit, standard sidecar budgets, a 1536Mi Kata baseline via
//!   the allow-listed `default_memory` annotation, the dedicated small
//!   RuntimeClass, and that class's 1536Mi/500m overhead in the quota.
//!
//! Everything here is a pure function of `app.resources.memory`, which flows
//! through the signed descriptor and the deployment record, so the descriptor's
//! `expected_runtime_class` and `expected_cc_init_data_hash` stay bound to the
//! rendered shape without any unsigned channel.

use crate::types::ConfidentialApp;

/// RuntimeClass used by small-shape workloads. The class is provisioned per
/// test window (existing SNP handler, scoped scheduling); it is never a valid
/// deployment-global default.
pub const SMALL_RUNTIME_CLASS: &str = "kata-qemu-snp-small";

/// Kata `default_memory` annotation (MiB) for small-shape pods. Matches the
/// RuntimeClass podFixed overhead carried in the tenant quota so accounting
/// stays exact, and leaves room for worst-case simultaneous peaks (claim-time
/// proxy burst + init Argon2 + guest OS) that exceed the container requests.
pub const SMALL_VM_BASELINE_MIB: u32 = 1536;

/// RuntimeClass podFixed overhead carried in the tenant ResourceQuota.
pub const STANDARD_RC_OVERHEAD_CPU: &str = "1";
pub const STANDARD_RC_OVERHEAD_MEMORY: &str = "4Gi";
pub const SMALL_RC_OVERHEAD_CPU: &str = "500m";
pub const SMALL_RC_OVERHEAD_MEMORY: &str = "1536Mi";

/// Fixed app/sidecar request and limit values.
pub const APP_CPU_REQUEST: &str = "250m";
pub const STANDARD_APP_MEMORY_REQUEST: &str = "512Mi";
pub const STANDARD_SIDECAR_MEMORY_REQUEST: &str = "128Mi";
pub const STANDARD_SIDECAR_MEMORY_LIMIT: &str = "256Mi";
/// Small-shape sidecars keep the standard budget. Sidecar working set is
/// fixed platform overhead, not density-scalable: the attestation proxy's
/// claim path (TLS, attestation, seed envelope, KBS handoff) demonstrably
/// exceeds 64Mi and a request below the working set would make the pod a
/// prime eviction candidate under node pressure — exactly the regime the
/// density test exercises.
pub const SMALL_SIDECAR_MEMORY_REQUEST: &str = "128Mi";
pub const SMALL_SIDECAR_MEMORY_LIMIT: &str = "256Mi";
pub const INIT_MEMORY_REQUEST: &str = "64Mi";
/// enclava-init keeps its 512Mi ceiling in every shape: Argon2 must not be
/// weakened for density.
pub const INIT_MEMORY_LIMIT: &str = "512Mi";
pub const SIDECAR_CPU_REQUEST: &str = "100m";
pub const SIDECAR_CPU_LIMIT: &str = "500m";
pub const INIT_CPU_REQUEST: &str = "50m";
pub const INIT_CPU_LIMIT: &str = "250m";
pub const TOOLS_MEMORY_REQUEST: &str = "16Mi";
pub const TOOLS_MEMORY_LIMIT: &str = "64Mi";
pub const TOOLS_CPU_REQUEST: &str = "10m";
pub const TOOLS_CPU_LIMIT: &str = "50m";

/// Small-shape tenant gateway (envoy + shutdown-manager) request split. The
/// dedicated gateway keeps its existing limits; only scheduler requests drop
/// to the 128Mi total chosen from control measurements (envoy ~75-85MiB
/// observed, shutdown-manager ~31MiB).
pub const SMALL_GATEWAY_ENVOY_MEMORY_REQUEST: &str = "96Mi";
pub const SMALL_GATEWAY_ENVOY_CPU_REQUEST: &str = "100m";
pub const SMALL_GATEWAY_SHUTDOWN_MEMORY_REQUEST: &str = "32Mi";
pub const SMALL_GATEWAY_SHUTDOWN_CPU_REQUEST: &str = "10m";

/// Node label shared with the sandbox pod's own selector; used to keep the
/// small gateway's envoy Deployment on tenant-capable worker nodes without
/// hard-coding a hostname into CAP.
pub const WORKER_NODE_LABEL: (&str, &str) = ("node.kubernetes.io/worker", "true");

/// The fixed standard app request in MiB; any application memory limit below
/// this cannot satisfy the standard request and therefore selects `Small`.
const APP_REQUEST_CEILING_MIB: u64 = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadShape {
    Standard,
    Small,
}

/// Parse a binary memory quantity ("128Mi", "1Gi", "1.5GiB") into MiB.
///
/// Accepts the same Mi/Gi/Ti units as the API's entitlement validator. Returns
/// `None` for unparseable or non-binary-unit values; callers treat that as
/// `Standard` so malformed limits keep today's rendering and fail at the
/// API's own resource validation instead.
pub fn memory_limit_mib(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return None;
    }
    let units = [
        ("TiB", 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0),
        ("GiB", 1024.0),
        ("Gi", 1024.0),
        ("MiB", 1.0),
        ("Mi", 1.0),
    ];
    let (number, multiplier) = units
        .iter()
        .find_map(|(suffix, multiplier)| trimmed.strip_suffix(suffix).map(|n| (n, *multiplier)))?;
    let parsed: f64 = number.parse().ok()?;
    if !parsed.is_finite() || parsed < 0.0 {
        return None;
    }
    Some(parsed * multiplier)
}

pub fn shape_for_memory_limit(memory_limit: &str) -> WorkloadShape {
    match memory_limit_mib(memory_limit) {
        Some(mib) if mib < APP_REQUEST_CEILING_MIB as f64 => WorkloadShape::Small,
        _ => WorkloadShape::Standard,
    }
}

pub fn shape_for_app(app: &ConfidentialApp) -> WorkloadShape {
    shape_for_memory_limit(&app.resources.memory)
}

/// App container memory request: the standard 512Mi, lowered to the limit for
/// small limits so request never exceeds limit. Always emitted in MiB.
pub fn app_memory_request(memory_limit: &str) -> String {
    match shape_for_memory_limit(memory_limit) {
        WorkloadShape::Standard => STANDARD_APP_MEMORY_REQUEST.to_string(),
        WorkloadShape::Small => match memory_limit_mib(memory_limit) {
            Some(mib) if mib == mib.trunc() => format!("{}Mi", mib as u64),
            Some(mib) => format!("{mib}Mi"),
            None => unreachable!("small shape requires a parseable limit"),
        },
    }
}

/// Effective pod RuntimeClass for an app: the deployment default for standard
/// workloads, the dedicated small class for small ones.
pub fn runtime_class_for(memory_limit: &str, deployment_default: &str) -> String {
    match shape_for_memory_limit(memory_limit) {
        WorkloadShape::Standard => deployment_default.to_string(),
        WorkloadShape::Small => SMALL_RUNTIME_CLASS.to_string(),
    }
}

/// RuntimeClass resolved for this app from its persisted memory limit and the
/// process's configured default class.
pub fn resolved_runtime_class(app: &ConfidentialApp) -> String {
    runtime_class_for(
        &app.resources.memory,
        &crate::manifest::cc_init_data::runtime_class(),
    )
}

/// Kata `default_memory` annotation value (MiB) for the pod, or `None` when the
/// runtime's default baseline applies.
pub fn vm_baseline_annotation(memory_limit: &str) -> Option<String> {
    match shape_for_memory_limit(memory_limit) {
        WorkloadShape::Standard => None,
        WorkloadShape::Small => Some(SMALL_VM_BASELINE_MIB.to_string()),
    }
}

/// Sidecar (attestation-proxy / tenant-ingress) memory request and limit.
pub fn sidecar_memory(shape: WorkloadShape) -> (&'static str, &'static str) {
    match shape {
        WorkloadShape::Standard => (
            STANDARD_SIDECAR_MEMORY_REQUEST,
            STANDARD_SIDECAR_MEMORY_LIMIT,
        ),
        WorkloadShape::Small => (SMALL_SIDECAR_MEMORY_REQUEST, SMALL_SIDECAR_MEMORY_LIMIT),
    }
}

/// RuntimeClass podFixed overhead reflected in the tenant ResourceQuota.
pub fn rc_overhead(shape: WorkloadShape) -> (&'static str, &'static str) {
    match shape {
        WorkloadShape::Standard => (STANDARD_RC_OVERHEAD_CPU, STANDARD_RC_OVERHEAD_MEMORY),
        WorkloadShape::Small => (SMALL_RC_OVERHEAD_CPU, SMALL_RC_OVERHEAD_MEMORY),
    }
}

/// Per-container request values patched onto the small-shape tenant gateway's
/// envoy Deployment. `None` for standard apps: gateway requests and limits are
/// left to the platform's existing template.
pub fn gateway_container_requests(
    shape: WorkloadShape,
) -> Option<[(&'static str, &'static str, &'static str); 2]> {
    match shape {
        WorkloadShape::Standard => None,
        WorkloadShape::Small => Some([
            (
                "envoy",
                SMALL_GATEWAY_ENVOY_CPU_REQUEST,
                SMALL_GATEWAY_ENVOY_MEMORY_REQUEST,
            ),
            (
                "shutdown-manager",
                SMALL_GATEWAY_SHUTDOWN_CPU_REQUEST,
                SMALL_GATEWAY_SHUTDOWN_MEMORY_REQUEST,
            ),
        ]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binary_quantities_parse_to_mib() {
        assert_eq!(memory_limit_mib("128Mi"), Some(128.0));
        assert_eq!(memory_limit_mib("1Gi"), Some(1024.0));
        assert_eq!(memory_limit_mib("1.5Gi"), Some(1536.0));
        assert_eq!(memory_limit_mib("2Ti"), Some(2.0 * 1024.0 * 1024.0));
        assert_eq!(memory_limit_mib("512MiB"), Some(512.0));
        assert_eq!(memory_limit_mib(""), None);
        assert_eq!(memory_limit_mib(" 128Mi"), None);
        assert_eq!(memory_limit_mib("128M"), None);
        assert_eq!(memory_limit_mib("lots"), None);
        assert_eq!(memory_limit_mib("-1Gi"), None);
    }

    #[test]
    fn small_shape_selects_below_standard_request() {
        assert_eq!(shape_for_memory_limit("128Mi"), WorkloadShape::Small);
        assert_eq!(shape_for_memory_limit("511Mi"), WorkloadShape::Small);
        assert_eq!(shape_for_memory_limit("512Mi"), WorkloadShape::Standard);
        assert_eq!(shape_for_memory_limit("1Gi"), WorkloadShape::Standard);
        // Unparseable limits fail safe to today's rendering; the API's own
        // validation rejects them before they reach the engine.
        assert_eq!(shape_for_memory_limit("bogus"), WorkloadShape::Standard);
    }

    #[test]
    fn small_request_never_exceeds_limit() {
        assert_eq!(app_memory_request("128Mi"), "128Mi");
        assert_eq!(app_memory_request("1Gi"), "512Mi");
        assert_eq!(app_memory_request("512Mi"), "512Mi");
    }

    #[test]
    fn small_shape_uses_dedicated_class() {
        assert_eq!(
            runtime_class_for("128Mi", "kata-qemu-snp"),
            SMALL_RUNTIME_CLASS
        );
        assert_eq!(runtime_class_for("1Gi", "kata-qemu-snp"), "kata-qemu-snp");
        assert_eq!(vm_baseline_annotation("128Mi"), Some("1536".to_string()));
        assert_eq!(vm_baseline_annotation("1Gi"), None);
        assert_eq!(rc_overhead(WorkloadShape::Small), ("500m", "1536Mi"));
        assert_eq!(rc_overhead(WorkloadShape::Standard), ("1", "4Gi"));
    }
}
