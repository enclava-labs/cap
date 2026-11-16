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
pub const INIT_CPU_LIMIT: &str = "500m";
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

/// Kata's baseline vCPU count (`default_vcpus`) for the SNP handler, in
/// millicores. Kata sizes a confidential VM statically: the guest boots with
/// `ceil(default_vcpus + sum of container CPU limits)` vCPUs.
pub const KATA_BASELINE_VCPU_MILLIS: u64 = 1000;

/// The vCPU count whose SNP launch measurement the platform approves.
///
/// Every vCPU contributes a measured VMSA, so a guest booted with any other
/// count reports a different launch measurement. Trustee's reference values
/// and the signed platform release (`expected_firmware_measurement`) carry
/// exactly one measurement, computed for this count; a guest outside it gets
/// a successful attestation token whose appraisal is not affirming, and the
/// KBS resource policy then denies every key release with a bare
/// `PolicyDeny` (cap#392).
pub const APPROVED_SNP_VM_VCPUS: u64 = 4;

/// A CPU quantity (`250m`, `1`, `1.5`) in millicores, rounded up to the next
/// whole millicore exactly as Kubernetes rounds a container limit. `None` for
/// values outside the admission grammar or too large to represent.
pub fn cpu_quantity_millis(value: &str) -> Option<u64> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    let (number, millis_per_unit) = match value.strip_suffix('m') {
        Some(number) => (number, 1u64),
        None => (value, 1000u64),
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut millis = whole.checked_mul(millis_per_unit)?;
    // Fractional digits beyond millicore precision round the quantity up.
    let kept_digits = if millis_per_unit == 1000 { 3 } else { 0 };
    let mut scale = millis_per_unit;
    let mut round_up = false;
    for (index, digit) in fraction.bytes().enumerate() {
        let digit = u64::from(digit - b'0');
        if index < kept_digits {
            scale /= 10;
            millis = millis.checked_add(digit * scale)?;
        } else if digit != 0 {
            round_up = true;
        }
    }
    if round_up {
        millis = millis.checked_add(1)?;
    }
    Some(millis)
}

/// Summed CPU limit, in millicores, of the platform containers that share the
/// pod with the application container. Must match the containers
/// `generate_statefulset` renders: attestation-proxy and tenant-ingress always,
/// plus the enclava-init sidecar outside the legacy bootstrap layout.
pub fn platform_container_cpu_limit_millis(legacy_bootstrap: bool) -> u64 {
    let limit = |quantity: &str| {
        cpu_quantity_millis(quantity).expect("platform CPU limit constants are valid quantities")
    };
    let sidecars = 2 * limit(SIDECAR_CPU_LIMIT);
    if legacy_bootstrap {
        sidecars
    } else {
        sidecars + limit(INIT_CPU_LIMIT)
    }
}

/// vCPU count Kata boots the confidential VM with for an application CPU
/// limit. `None` when the limit is not a representable CPU quantity.
pub fn snp_vm_vcpus(app_cpu_limit: &str, legacy_bootstrap: bool) -> Option<u64> {
    let total = KATA_BASELINE_VCPU_MILLIS
        .checked_add(platform_container_cpu_limit_millis(legacy_bootstrap))?
        .checked_add(cpu_quantity_millis(app_cpu_limit)?)?;
    Some(total.div_ceil(1000))
}

/// Application CPU limits, in millicores, that boot the approved vCPU count:
/// strictly above the first value, up to and including the second.
pub fn approved_app_cpu_limit_range_millis(legacy_bootstrap: bool) -> (u64, u64) {
    let fixed = KATA_BASELINE_VCPU_MILLIS + platform_container_cpu_limit_millis(legacy_bootstrap);
    let max_inclusive = (APPROVED_SNP_VM_VCPUS * 1000).saturating_sub(fixed);
    (max_inclusive.saturating_sub(1000), max_inclusive)
}

/// An application CPU limit that would boot a confidential VM whose launch
/// measurement is not approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnapprovedVmCpuShape {
    pub cpu_limit: String,
    /// vCPU count the limit would boot; `None` when it cannot be computed.
    pub vm_vcpus: Option<u64>,
    pub approved_vm_vcpus: u64,
    pub min_cpu_exclusive_millis: u64,
    pub max_cpu_inclusive_millis: u64,
}

impl std::fmt::Display for UnapprovedVmCpuShape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.vm_vcpus {
            Some(vcpus) => write!(
                f,
                "cpu limit {} boots a {vcpus}-vCPU confidential VM",
                self.cpu_limit
            )?,
            None => write!(f, "cpu limit {} is not supported", self.cpu_limit)?,
        }
        write!(
            f,
            "; only the {}-vCPU launch measurement is approved, so its keys would never be \
             released. Use a cpu limit above {}m and at most {}m",
            self.approved_vm_vcpus, self.min_cpu_exclusive_millis, self.max_cpu_inclusive_millis
        )
    }
}

/// Reject an application CPU limit that boots a vCPU count other than
/// [`APPROVED_SNP_VM_VCPUS`]. Applies only to SNP runtime classes: the
/// simulated CoCo dev class has no launch measurement to appraise.
pub fn check_vm_cpu_shape(
    app_cpu_limit: &str,
    deployment_runtime_class: &str,
    legacy_bootstrap: bool,
) -> Result<(), UnapprovedVmCpuShape> {
    if deployment_runtime_class == crate::manifest::cc_init_data::COCO_DEV_RUNTIME_CLASS {
        return Ok(());
    }
    let vm_vcpus = snp_vm_vcpus(app_cpu_limit, legacy_bootstrap);
    if vm_vcpus == Some(APPROVED_SNP_VM_VCPUS) {
        return Ok(());
    }
    let (min_cpu_exclusive_millis, max_cpu_inclusive_millis) =
        approved_app_cpu_limit_range_millis(legacy_bootstrap);
    Err(UnapprovedVmCpuShape {
        cpu_limit: app_cpu_limit.to_string(),
        vm_vcpus,
        approved_vm_vcpus: APPROVED_SNP_VM_VCPUS,
        min_cpu_exclusive_millis,
        max_cpu_inclusive_millis,
    })
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
    fn cpu_quantities_round_up_to_millicores() {
        assert_eq!(cpu_quantity_millis("250m"), Some(250));
        assert_eq!(cpu_quantity_millis("1"), Some(1000));
        assert_eq!(cpu_quantity_millis("1.5"), Some(1500));
        assert_eq!(cpu_quantity_millis("0.25"), Some(250));
        assert_eq!(cpu_quantity_millis(".5"), Some(500));
        assert_eq!(cpu_quantity_millis("0.5m"), Some(1));
        assert_eq!(cpu_quantity_millis("1.0000000000000000001"), Some(1001));
        assert_eq!(cpu_quantity_millis("1.5000"), Some(1500));
        assert_eq!(cpu_quantity_millis(""), None);
        assert_eq!(cpu_quantity_millis(" 1"), None);
        assert_eq!(cpu_quantity_millis("-1"), None);
        assert_eq!(cpu_quantity_millis("1e3"), None);
        assert_eq!(cpu_quantity_millis("m"), None);
        assert_eq!(cpu_quantity_millis("99999999999999999999999"), None);
    }

    #[test]
    fn only_the_approved_vcpu_count_passes() {
        let snp = "kata-qemu-snp";
        // baseline 1 + proxy 0.5 + ingress 0.5 + init 0.5 + app
        assert_eq!(snp_vm_vcpus("1", false), Some(4));
        assert_eq!(snp_vm_vcpus("500m", false), Some(3));
        assert_eq!(snp_vm_vcpus("501m", false), Some(4));
        assert_eq!(snp_vm_vcpus("1500m", false), Some(4));
        assert_eq!(snp_vm_vcpus("1501m", false), Some(5));
        assert_eq!(approved_app_cpu_limit_range_millis(false), (500, 1500));

        assert!(check_vm_cpu_shape("1", snp, false).is_ok());
        assert!(check_vm_cpu_shape("1.5", snp, false).is_ok());
        assert!(check_vm_cpu_shape("1", SMALL_RUNTIME_CLASS, false).is_ok());

        let low = check_vm_cpu_shape("250m", snp, false).unwrap_err();
        assert_eq!(low.vm_vcpus, Some(3));
        assert_eq!(low.approved_vm_vcpus, 4);
        assert_eq!(
            low.to_string(),
            "cpu limit 250m boots a 3-vCPU confidential VM; only the 4-vCPU launch \
             measurement is approved, so its keys would never be released. Use a cpu limit \
             above 500m and at most 1500m"
        );
        let high = check_vm_cpu_shape("2", snp, false).unwrap_err();
        assert_eq!(high.vm_vcpus, Some(5));
        assert_eq!(
            check_vm_cpu_shape("bogus", snp, false)
                .unwrap_err()
                .vm_vcpus,
            None
        );
    }

    #[test]
    fn legacy_bootstrap_layout_has_no_init_sidecar() {
        assert_eq!(snp_vm_vcpus("1", true), Some(3));
        assert_eq!(approved_app_cpu_limit_range_millis(true), (1000, 2000));
        assert!(check_vm_cpu_shape("2", "kata-qemu-snp", true).is_ok());
        assert!(check_vm_cpu_shape("1", "kata-qemu-snp", true).is_err());
    }

    #[test]
    fn simulated_dev_runtime_class_is_not_measured() {
        let dev = crate::manifest::cc_init_data::COCO_DEV_RUNTIME_CLASS;
        assert!(check_vm_cpu_shape("250m", dev, false).is_ok());
        assert!(check_vm_cpu_shape("8", dev, false).is_ok());
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
