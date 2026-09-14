use k8s_openapi::api::core::v1::ResourceQuota;
use k8s_openapi::api::core::v1::ResourceQuotaSpec;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use std::collections::BTreeMap;

use crate::types::ConfidentialApp;

/// Generate a ResourceQuota matching the live tenant shape now rendered by CAP.
///
/// Includes the full resource set: CPU, memory, storage, PVCs, pods, services,
/// load balancers (0), node ports (0), secrets, configmaps.
pub fn generate_resource_quota(app: &ConfidentialApp) -> ResourceQuota {
    use crate::manifest::shape;
    let mut hard = BTreeMap::new();

    let ws = shape::shape_for_app(app);
    let app_mem_req = shape::app_memory_request(&app.resources.memory);
    let (sidecar_req, sidecar_lim) = shape::sidecar_memory(ws);
    let (rc_cpu, rc_mem) = shape::rc_overhead(ws);

    let request_cpu = vec![
        shape::APP_CPU_REQUEST,     // workload
        shape::SIDECAR_CPU_REQUEST, // attestation-proxy
        shape::SIDECAR_CPU_REQUEST, // tenant-ingress
        shape::INIT_CPU_REQUEST,    // enclava-init sidecar
        rc_cpu,                     // RuntimeClass overhead
    ];
    let limit_cpu = vec![
        app.resources.cpu.as_str(), // workload
        shape::SIDECAR_CPU_LIMIT,   // attestation-proxy
        shape::SIDECAR_CPU_LIMIT,   // tenant-ingress
        shape::INIT_CPU_LIMIT,      // enclava-init sidecar
        rc_cpu,                     // RuntimeClass overhead
    ];
    let request_memory = vec![
        app_mem_req.as_str(),       // workload
        sidecar_req,                // attestation-proxy
        sidecar_req,                // tenant-ingress
        shape::INIT_MEMORY_REQUEST, // enclava-init sidecar
        rc_mem,                     // RuntimeClass overhead
    ];
    let limit_memory = vec![
        app.resources.memory.as_str(), // workload
        sidecar_lim,                   // attestation-proxy
        sidecar_lim,                   // tenant-ingress
        shape::INIT_MEMORY_LIMIT,      // enclava-init sidecar
        rc_mem,                        // RuntimeClass overhead
    ];

    hard.insert(
        "requests.cpu".to_string(),
        Quantity(sum_cpu_quantities(&request_cpu)),
    );
    hard.insert(
        "limits.cpu".to_string(),
        Quantity(sum_cpu_quantities(&limit_cpu)),
    );

    // Memory. See CPU note above.
    hard.insert(
        "requests.memory".to_string(),
        Quantity(sum_memory_quantities(&request_memory)),
    );
    hard.insert(
        "limits.memory".to_string(),
        Quantity(sum_memory_quantities(&limit_memory)),
    );

    // Storage must cover both StatefulSet volumeClaimTemplates. If this is too
    // low, Kubernetes creates the first PVC and then blocks the second one.
    hard.insert(
        "requests.storage".to_string(),
        Quantity(sum_storage_quantities(
            &app.storage.app_data.size,
            &app.storage.tls_data.size,
        )),
    );
    hard.insert(
        "persistentvolumeclaims".to_string(),
        Quantity("5".to_string()),
    );

    // Pod and service limits
    hard.insert("pods".to_string(), Quantity("20".to_string()));
    hard.insert("services".to_string(), Quantity("20".to_string()));
    hard.insert(
        "services.loadbalancers".to_string(),
        Quantity("0".to_string()),
    );
    hard.insert("services.nodeports".to_string(), Quantity("0".to_string()));

    hard.insert("secrets".to_string(), Quantity("50".to_string()));
    hard.insert("configmaps".to_string(), Quantity("50".to_string()));

    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "enclava-platform".to_string(),
    );

    ResourceQuota {
        metadata: ObjectMeta {
            name: Some("tenant-quota".to_string()),
            namespace: Some(app.namespace.clone()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(ResourceQuotaSpec {
            hard: Some(hard),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Split a quantity like "10Gi" into ("10", "Gi").
fn split_quantity(q: &str) -> (&str, &str) {
    let pos = q
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(q.len());
    (&q[..pos], &q[pos..])
}

fn sum_cpu_quantities(values: &[&str]) -> String {
    let mut total_millis = 0f64;

    for value in values {
        if let Some(millis) = value.strip_suffix('m') {
            total_millis += millis.parse::<f64>().unwrap_or(0.0);
        } else {
            total_millis += value.parse::<f64>().unwrap_or(0.0) * 1000.0;
        }
    }

    if total_millis % 1000.0 == 0.0 {
        format!("{}", (total_millis / 1000.0) as i64)
    } else {
        format!("{}m", total_millis as i64)
    }
}

fn sum_memory_quantities(values: &[&str]) -> String {
    let mut total_mib = 0f64;

    for value in values {
        let (num, suffix) = split_quantity(value);
        let Ok(parsed) = num.parse::<f64>() else {
            continue;
        };

        total_mib += match suffix {
            "Gi" | "GiB" => parsed * 1024.0,
            "Mi" | "MiB" => parsed,
            _ => parsed,
        };
    }

    if total_mib % 1024.0 == 0.0 {
        format!("{}Gi", (total_mib / 1024.0) as i64)
    } else {
        // Round up: the quota must never admit less than the pod actually
        // requests when a fractional-MiB app request is summed.
        format!("{}Mi", total_mib.ceil() as i64)
    }
}

fn storage_mib(value: &str) -> Option<f64> {
    let (num, suffix) = split_quantity(value);
    let parsed: f64 = num.parse().ok()?;
    match suffix {
        "Ti" | "TiB" => Some(parsed * 1024.0 * 1024.0),
        "Gi" | "GiB" => Some(parsed * 1024.0),
        "Mi" | "MiB" => Some(parsed),
        _ => None,
    }
}

fn sum_storage_quantities(a: &str, b: &str) -> String {
    let (a_num, a_suffix) = split_quantity(a);
    let (b_num, b_suffix) = split_quantity(b);

    if a_suffix == b_suffix
        && let (Ok(a), Ok(b)) = (a_num.parse::<f64>(), b_num.parse::<f64>())
    {
        let total = a + b;
        if total == total.floor() {
            return format!("{}{a_suffix}", total as i64);
        }
        return format!("{total}{a_suffix}");
    }

    // Mixed units: normalize to MiB so e.g. "5Gi" + "512Mi" yields "5632Mi"
    // instead of silently dropping the TLS volume's request.
    match (storage_mib(a), storage_mib(b)) {
        (Some(a_mib), Some(b_mib)) => {
            let total = a_mib + b_mib;
            if total % 1024.0 == 0.0 {
                format!("{}Gi", (total / 1024.0) as i64)
            } else {
                format!("{}Mi", total.ceil() as i64)
            }
        }
        _ => a.to_string(),
    }
}
