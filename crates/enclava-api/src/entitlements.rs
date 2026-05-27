use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntitlementLimits {
    pub name: String,
    pub max_apps: u32,
    pub max_cpu: String,
    pub max_memory: String,
    pub max_storage: String,
}

/// Core resource classes used by CAP to prevent accidental cluster exhaustion.
/// Products built on CAP can map their own plans to these classes externally.
pub fn limits_for_entitlement_class(entitlement_class: &str) -> Option<EntitlementLimits> {
    match entitlement_class {
        "core" => Some(EntitlementLimits {
            name: "core".to_string(),
            max_apps: u32::MAX,
            max_cpu: "64".to_string(),
            max_memory: "256Gi".to_string(),
            max_storage: "2Ti".to_string(),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_entitlement_does_not_cap_instance_count() {
        let limits = limits_for_entitlement_class("core").expect("core entitlement class exists");
        assert_eq!(limits.max_apps, u32::MAX);
    }
}
