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
    let mut hard = BTreeMap::new();

    // CPU. ResourceQuota admission accounts the sum of regular containers and
    // RuntimeClass overhead. Keep these constants aligned with
    // manifest/containers.rs and the kata-qemu-snp RuntimeClass used by the
    // StatefulSet.
    hard.insert(
        "requests.cpu".to_string(),
        Quantity(sum_cpu_quantities(&[
            "250m", // workload
            "100m", // attestation-proxy
            "100m", // tenant-ingress
            "50m",  // enclava-init sidecar
            "1",    // kata-qemu-snp overhead
        ])),
    );
    hard.insert(
        "limits.cpu".to_string(),
        Quantity(sum_cpu_quantities(&[
            &app.resources.cpu, // workload
            "500m",             // attestation-proxy
            "500m",             // tenant-ingress
            "250m",             // enclava-init sidecar
            "1",                // kata-qemu-snp overhead
        ])),
    );

    // Memory. See CPU note above.
    hard.insert(
        "requests.memory".to_string(),
        Quantity(sum_memory_quantities(&[
            "512Mi", // workload
            "128Mi", // attestation-proxy
            "128Mi", // tenant-ingress
            "64Mi",  // enclava-init sidecar
            "4Gi",   // kata-qemu-snp overhead
        ])),
    );
    hard.insert(
        "limits.memory".to_string(),
        Quantity(sum_memory_quantities(&[
            &app.resources.memory, // workload
            "256Mi",               // attestation-proxy
            "256Mi",               // tenant-ingress
            "128Mi",               // enclava-init sidecar
            "4Gi",                 // kata-qemu-snp overhead
        ])),
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

    // Secrets and ConfigMaps
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
        format!("{}Mi", total_mib as i64)
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

    // The UI/API defaults use matching units. If a future caller mixes units,
    // keep the old conservative app-data value instead of inventing a lossy
    // quantity conversion here.
    a.to_string()
}
