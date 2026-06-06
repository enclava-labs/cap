use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementLimits {
    pub name: String,
    pub max_apps: u32,
    pub max_cpu: String,
    pub max_memory: String,
    pub max_storage: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntitlementDecision {
    pub limits: Option<EntitlementLimits>,
    pub deploy_allowed: bool,
    pub deploy_block_reason: Option<String>,
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

pub async fn is_paas_managed_org(pool: &PgPool, org_id: Uuid) -> Result<bool, sqlx::Error> {
    let mode: Option<String> =
        sqlx::query_scalar("SELECT mode FROM organization_management WHERE org_id = $1")
            .bind(org_id)
            .fetch_optional(pool)
            .await?;
    Ok(mode.as_deref() == Some("paas_managed"))
}

pub async fn entitlement_decision_for_org(
    pool: &PgPool,
    org_id: Uuid,
    entitlement_class: &str,
) -> Result<EntitlementDecision, sqlx::Error> {
    if is_paas_managed_org(pool, org_id).await? {
        let row: Option<(bool, Option<String>, serde_json::Value)> = sqlx::query_as(
            "SELECT deploy_allowed, block_reason, limits
               FROM organization_entitlements
              WHERE org_id = $1",
        )
        .bind(org_id)
        .fetch_optional(pool)
        .await?;
        let Some((deploy_allowed, block_reason, limits)) = row else {
            return Ok(EntitlementDecision {
                limits: None,
                deploy_allowed: false,
                deploy_block_reason: Some("paas_managed_entitlement_missing".to_string()),
            });
        };
        let limits =
            serde_json::from_value(limits).map_err(|err| sqlx::Error::Decode(Box::new(err)))?;
        return Ok(EntitlementDecision {
            limits: Some(limits),
            deploy_allowed,
            deploy_block_reason: if deploy_allowed {
                None
            } else {
                Some(block_reason.unwrap_or_else(|| "paas_managed_entitlement_blocked".to_string()))
            },
        });
    }

    Ok(match limits_for_entitlement_class(entitlement_class) {
        Some(limits) => EntitlementDecision {
            limits: Some(limits),
            deploy_allowed: true,
            deploy_block_reason: None,
        },
        None => EntitlementDecision {
            limits: None,
            deploy_allowed: false,
            deploy_block_reason: Some("unknown_entitlement_class".to_string()),
        },
    })
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
