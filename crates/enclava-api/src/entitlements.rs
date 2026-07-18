use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::models::AppResources;

const ORG_ENTITLEMENT_LANE_DOMAIN: i32 = 0x454e_544c;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeEntitlement {
    /// Monotonic PaaS authority version. Local CAP entitlement classes do not
    /// have an external version and therefore return `None`.
    pub version: Option<i64>,
    pub decision: EntitlementDecision,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResourceLimitError {
    Invalid {
        field: &'static str,
        message: String,
    },
    Exceeded {
        code: &'static str,
        field: &'static str,
        requested: String,
        allowed: String,
    },
}

fn uuid_advisory_key(id: Uuid) -> i32 {
    let bytes = id.as_bytes();
    let a = u32::from_be_bytes(bytes[0..4].try_into().expect("UUID word"));
    let b = u32::from_be_bytes(bytes[4..8].try_into().expect("UUID word"));
    let c = u32::from_be_bytes(bytes[8..12].try_into().expect("UUID word"));
    let d = u32::from_be_bytes(bytes[12..16].try_into().expect("UUID word"));
    (a ^ b ^ c ^ d) as i32
}

/// Serialize all mutations and acceptance decisions that depend on one
/// organization's hosted management/entitlement authority.
///
/// Lock order is global: entitlement -> signing authority -> app lane.
/// A 32-bit collision only over-serializes unrelated organizations.
pub async fn lock_org_entitlement_lane(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_xact_lock($1, $2)")
        .bind(ORG_ENTITLEMENT_LANE_DOMAIN)
        .bind(uuid_advisory_key(org_id))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Re-read hosted management and entitlement authority while the caller holds
/// [`lock_org_entitlement_lane`].
pub async fn authoritative_entitlement_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    org_id: Uuid,
) -> Result<AuthoritativeEntitlement, sqlx::Error> {
    type AuthorityRow = (
        String,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<bool>,
        Option<String>,
        Option<serde_json::Value>,
    );

    let row: AuthorityRow = sqlx::query_as(
        "SELECT o.entitlement_class,
                om.mode,
                om.status,
                oe.version,
                oe.deploy_allowed,
                oe.block_reason,
                oe.limits
           FROM organizations o
           LEFT JOIN organization_management om ON om.org_id = o.id
           LEFT JOIN organization_entitlements oe ON oe.org_id = o.id
          WHERE o.id = $1",
    )
    .bind(org_id)
    .fetch_one(&mut **tx)
    .await?;

    let (entitlement_class, management_mode, management_status, version, allowed, reason, limits) =
        row;
    if management_mode.as_deref() == Some("paas_managed") {
        if management_status.as_deref() != Some("active") {
            return Ok(AuthoritativeEntitlement {
                version,
                decision: EntitlementDecision {
                    limits: None,
                    deploy_allowed: false,
                    deploy_block_reason: Some(match management_status.as_deref() {
                        Some("suspended") => "paas_managed_org_suspended".to_string(),
                        Some("deleted") => "paas_managed_org_deleted".to_string(),
                        _ => "paas_managed_org_inactive".to_string(),
                    }),
                },
            });
        }

        let Some((deploy_allowed, limits)) = allowed.zip(limits) else {
            return Ok(AuthoritativeEntitlement {
                version,
                decision: EntitlementDecision {
                    limits: None,
                    deploy_allowed: false,
                    deploy_block_reason: Some("paas_managed_entitlement_missing".to_string()),
                },
            });
        };
        let limits =
            serde_json::from_value(limits).map_err(|error| sqlx::Error::Decode(Box::new(error)))?;
        return Ok(AuthoritativeEntitlement {
            version,
            decision: EntitlementDecision {
                limits: Some(limits),
                deploy_allowed,
                deploy_block_reason: (!deploy_allowed).then(|| {
                    reason.unwrap_or_else(|| "paas_managed_entitlement_blocked".to_string())
                }),
            },
        });
    }

    Ok(AuthoritativeEntitlement {
        version: None,
        decision: match limits_for_entitlement_class(&entitlement_class) {
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
        },
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ScaledDecimal {
    coefficient: u128,
    scale: u32,
}

impl ScaledDecimal {
    fn parse(value: &str, field: &'static str) -> Result<Self, String> {
        let trimmed = value.trim();
        if trimmed != value || trimmed.is_empty() {
            return Err(format!("{field} must be a positive decimal quantity"));
        }
        let mut parts = trimmed.split('.');
        let integer = parts.next().unwrap_or_default();
        let fraction = parts.next();
        if parts.next().is_some()
            || integer.is_empty()
            || !integer.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|part| {
                part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(format!("{field} must be a positive decimal quantity"));
        }
        let fraction = fraction.unwrap_or_default();
        let digits = format!("{integer}{fraction}");
        if digits.len() > 38 || fraction.len() > 24 {
            return Err(format!("{field} has too much precision"));
        }
        let coefficient = digits
            .parse::<u128>()
            .map_err(|_| format!("{field} is too large"))?;
        if coefficient == 0 {
            return Err(format!("{field} must be positive"));
        }
        Ok(Self {
            coefficient,
            scale: fraction.len() as u32,
        }
        .normalized())
    }

    fn normalized(mut self) -> Self {
        while self.scale > 0 && self.coefficient.is_multiple_of(10) {
            self.coefficient /= 10;
            self.scale -= 1;
        }
        self
    }

    fn checked_mul(self, multiplier: u128, field: &'static str) -> Result<Self, String> {
        Ok(Self {
            coefficient: self
                .coefficient
                .checked_mul(multiplier)
                .ok_or_else(|| format!("{field} is too large"))?,
            scale: self.scale,
        }
        .normalized())
    }

    fn checked_scale(self, extra: u32, field: &'static str) -> Result<Self, String> {
        let scale = self
            .scale
            .checked_add(extra)
            .filter(|scale| *scale <= 38)
            .ok_or_else(|| format!("{field} has too much precision"))?;
        Ok(Self {
            coefficient: self.coefficient,
            scale,
        }
        .normalized())
    }

    fn cmp_exact(self, other: Self) -> Result<std::cmp::Ordering, String> {
        use std::cmp::Ordering;

        match self.scale.cmp(&other.scale) {
            Ordering::Equal => Ok(self.coefficient.cmp(&other.coefficient)),
            Ordering::Greater => {
                let factor = 10u128
                    .checked_pow(self.scale - other.scale)
                    .ok_or_else(|| "resource quantity precision overflow".to_string())?;
                let rhs = other
                    .coefficient
                    .checked_mul(factor)
                    .ok_or_else(|| "resource quantity magnitude overflow".to_string())?;
                Ok(self.coefficient.cmp(&rhs))
            }
            Ordering::Less => {
                let factor = 10u128
                    .checked_pow(other.scale - self.scale)
                    .ok_or_else(|| "resource quantity precision overflow".to_string())?;
                let lhs = self
                    .coefficient
                    .checked_mul(factor)
                    .ok_or_else(|| "resource quantity magnitude overflow".to_string())?;
                Ok(lhs.cmp(&other.coefficient))
            }
        }
    }
}

fn parse_cpu_cores(value: &str) -> Result<ScaledDecimal, String> {
    let trimmed = value.trim();
    if trimmed != value || trimmed.is_empty() {
        return Err("CPU must be a positive number or millicpu quantity".to_string());
    }
    if let Some(millis) = trimmed.strip_suffix('m') {
        ScaledDecimal::parse(millis, "CPU")?.checked_scale(3, "CPU")
    } else {
        ScaledDecimal::parse(trimmed, "CPU")
    }
}

/// Parse a binary quantity into exact Mi units. `resources.storage` maps to
/// app data storage; TLS storage is a separate field and is intentionally not
/// charged against the app-data `max_storage` limit.
fn parse_binary_mib(value: &str, field: &'static str) -> Result<ScaledDecimal, String> {
    let trimmed = value.trim();
    if trimmed != value || trimmed.is_empty() {
        return Err(format!("{field} must be a positive binary quantity"));
    }
    let units = [
        ("TiB", 1024u128 * 1024),
        ("Ti", 1024u128 * 1024),
        ("GiB", 1024u128),
        ("Gi", 1024u128),
        ("MiB", 1u128),
        ("Mi", 1u128),
    ];
    let Some((number, multiplier)) = units
        .iter()
        .find_map(|(suffix, multiplier)| trimmed.strip_suffix(suffix).map(|n| (n, *multiplier)))
    else {
        return Err(format!("{field} must use Mi, Gi, or Ti binary units"));
    };
    ScaledDecimal::parse(number, field)?.checked_mul(multiplier, field)
}

/// Validate the exact candidate resource row that will be committed and
/// serialized into a durable apply job.
pub fn validate_resource_limits(
    resources: &AppResources,
    limits: &EntitlementLimits,
) -> Result<(), ResourceLimitError> {
    let requested_cpu =
        parse_cpu_cores(&resources.cpu_limit).map_err(|message| ResourceLimitError::Invalid {
            field: "cpu",
            message,
        })?;
    let allowed_cpu =
        parse_cpu_cores(&limits.max_cpu).map_err(|message| ResourceLimitError::Invalid {
            field: "entitlement.max_cpu",
            message,
        })?;
    if requested_cpu
        .cmp_exact(allowed_cpu)
        .map_err(|message| ResourceLimitError::Invalid {
            field: "cpu",
            message,
        })?
        .is_gt()
    {
        return Err(ResourceLimitError::Exceeded {
            code: "entitlement_cpu_limit",
            field: "cpu",
            requested: resources.cpu_limit.clone(),
            allowed: limits.max_cpu.clone(),
        });
    }

    let requested_memory =
        parse_binary_mib(&resources.memory_limit, "memory").map_err(|message| {
            ResourceLimitError::Invalid {
                field: "memory",
                message,
            }
        })?;
    let allowed_memory =
        parse_binary_mib(&limits.max_memory, "entitlement.max_memory").map_err(|message| {
            ResourceLimitError::Invalid {
                field: "entitlement.max_memory",
                message,
            }
        })?;
    if requested_memory
        .cmp_exact(allowed_memory)
        .map_err(|message| ResourceLimitError::Invalid {
            field: "memory",
            message,
        })?
        .is_gt()
    {
        return Err(ResourceLimitError::Exceeded {
            code: "entitlement_memory_limit",
            field: "memory",
            requested: resources.memory_limit.clone(),
            allowed: limits.max_memory.clone(),
        });
    }

    let requested_storage =
        parse_binary_mib(&resources.app_data_size, "storage").map_err(|message| {
            ResourceLimitError::Invalid {
                field: "storage",
                message,
            }
        })?;
    let allowed_storage = parse_binary_mib(&limits.max_storage, "entitlement.max_storage")
        .map_err(|message| ResourceLimitError::Invalid {
            field: "entitlement.max_storage",
            message,
        })?;
    if requested_storage
        .cmp_exact(allowed_storage)
        .map_err(|message| ResourceLimitError::Invalid {
            field: "storage",
            message,
        })?
        .is_gt()
    {
        return Err(ResourceLimitError::Exceeded {
            code: "entitlement_storage_limit",
            field: "storage",
            requested: resources.app_data_size.clone(),
            allowed: limits.max_storage.clone(),
        });
    }
    Ok(())
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

    async fn database_test_pool() -> PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
        let pool = PgPool::connect(&database_url)
            .await
            .expect("connect entitlement regression database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate entitlement regression database");
        pool
    }

    fn limits(
        max_apps: u32,
        max_cpu: &str,
        max_memory: &str,
        max_storage: &str,
    ) -> EntitlementLimits {
        EntitlementLimits {
            name: "test".to_string(),
            max_apps,
            max_cpu: max_cpu.to_string(),
            max_memory: max_memory.to_string(),
            max_storage: max_storage.to_string(),
        }
    }

    #[test]
    fn core_entitlement_does_not_cap_instance_count() {
        let limits = limits_for_entitlement_class("core").expect("core entitlement class exists");
        assert_eq!(limits.max_apps, u32::MAX);
    }

    #[test]
    fn candidate_resources_reject_malformed_nonpositive_and_over_limit_values() {
        let configured_limits = limits(2, "2", "4Gi", "10Gi");
        let mut resources = AppResources {
            app_id: Uuid::new_v4(),
            cpu_limit: "500m".to_string(),
            memory_limit: "2048Mi".to_string(),
            app_data_size: "0.009Ti".to_string(),
            tls_data_size: "2Gi".to_string(),
        };
        validate_resource_limits(&resources, &configured_limits)
            .expect("valid converted quantities");

        resources.cpu_limit = "not-a-cpu".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &configured_limits),
            Err(ResourceLimitError::Invalid { field: "cpu", .. })
        ));
        resources.cpu_limit = "0".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &configured_limits),
            Err(ResourceLimitError::Invalid { field: "cpu", .. })
        ));
        resources.cpu_limit = "3".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &configured_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_cpu_limit",
                ..
            })
        ));
        resources.cpu_limit = "1".to_string();
        resources.memory_limit = "5Gi".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &configured_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_memory_limit",
                ..
            })
        ));
        resources.memory_limit = "1Gi".to_string();
        resources.app_data_size = "11Gi".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &configured_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_storage_limit",
                ..
            })
        ));

        let unit_limits = limits(2, "1", "1Gi", "1Gi");
        resources.cpu_limit = "1.0000000000000000001".to_string();
        resources.memory_limit = "1Gi".to_string();
        resources.app_data_size = "1Gi".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &unit_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_cpu_limit",
                ..
            })
        ));
        resources.cpu_limit = "1".to_string();
        resources.memory_limit = "1.0000000000000000001Gi".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &unit_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_memory_limit",
                ..
            })
        ));
        resources.memory_limit = "1Gi".to_string();
        resources.app_data_size = "1.0000000000000000001Gi".to_string();
        assert!(matches!(
            validate_resource_limits(&resources, &unit_limits),
            Err(ResourceLimitError::Exceeded {
                code: "entitlement_storage_limit",
                ..
            })
        ));

        // The deploy API's resources.storage field governs app_data_size.
        // TLS storage is configured separately and does not consume that
        // authority limit.
        resources.app_data_size = "1Gi".to_string();
        resources.tls_data_size = "100Gi".to_string();
        validate_resource_limits(&resources, &unit_limits)
            .expect("separate TLS storage does not alter app-data limit");
    }

    #[tokio::test]
    async fn acceptance_waits_for_n_plus_one_entitlement_revocation_and_rejects() {
        let pool = database_test_pool().await;
        let org_id = Uuid::new_v4();
        let suffix = org_id.simple().to_string();
        sqlx::query(
            "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
        )
        .bind(org_id)
        .bind(format!("entitlement-race-{suffix}"))
        .bind(&suffix[..8])
        .execute(&pool)
        .await
        .expect("insert entitlement race org");
        sqlx::query(
            "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
        )
        .bind(org_id)
        .bind(format!("paas-{suffix}"))
        .execute(&pool)
        .await
        .expect("mark race org PaaS managed");
        sqlx::query(
            "INSERT INTO organization_entitlements (
                 org_id, version, deploy_allowed, limits
             ) VALUES ($1, 1, true, $2)",
        )
        .bind(org_id)
        .bind(serde_json::to_value(limits(5, "4", "8Gi", "20Gi")).unwrap())
        .execute(&pool)
        .await
        .expect("insert initial entitlement");

        let early = entitlement_decision_for_org(&pool, org_id, "core")
            .await
            .expect("load early entitlement");
        assert!(early.deploy_allowed, "long validation starts under N");

        let mut revocation = pool.begin().await.expect("begin N+1 revocation");
        lock_org_entitlement_lane(&mut revocation, org_id)
            .await
            .expect("lock entitlement writer lane");
        sqlx::query(
            "UPDATE organization_entitlements
                SET version = 2,
                    deploy_allowed = false,
                    block_reason = 'billing_revoked',
                    limits = $2,
                    updated_at = clock_timestamp()
              WHERE org_id = $1",
        )
        .bind(org_id)
        .bind(serde_json::to_value(limits(0, "250m", "512Mi", "1Gi")).unwrap())
        .execute(&mut *revocation)
        .await
        .expect("stage N+1 revocation");

        let acceptance_pool = pool.clone();
        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let acceptance = tokio::spawn(async move {
            let mut tx = acceptance_pool.begin().await.expect("begin acceptance");
            let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
                .fetch_one(&mut *tx)
                .await
                .expect("acceptance backend pid");
            pid_sender.send(pid).expect("send backend pid");
            lock_org_entitlement_lane(&mut tx, org_id)
                .await
                .expect("wait for entitlement lane");
            let authority = authoritative_entitlement_in_tx(&mut tx, org_id)
                .await
                .expect("reload authoritative entitlement");
            tx.rollback().await.expect("rollback rejected acceptance");
            authority
        });
        let backend_pid = pid_receiver.await.expect("receive backend pid");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT COALESCE((
                         SELECT wait_event_type = 'Lock'
                           FROM pg_stat_activity
                          WHERE pid = $1
                     ), false)",
                )
                .bind(backend_pid)
                .fetch_one(&pool)
                .await
                .expect("inspect acceptance wait state");
                if waiting {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("acceptance did not wait for entitlement writer");
        revocation.commit().await.expect("commit N+1 revocation");

        let authority = acceptance.await.expect("join acceptance");
        assert_eq!(authority.version, Some(2));
        assert!(!authority.decision.deploy_allowed);
        assert_eq!(
            authority.decision.deploy_block_reason.as_deref(),
            Some("billing_revoked")
        );
        let app_count: i64 = sqlx::query_scalar("SELECT count(*) FROM apps WHERE org_id = $1")
            .bind(org_id)
            .fetch_one(&pool)
            .await
            .expect("count rejected apps");
        let deployment_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM deployments WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("count rejected deployments");
        let artifact_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM workload_artifacts wa
             JOIN apps a ON a.id = wa.app_id
             WHERE a.org_id = $1",
        )
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rejected artifacts");
        let audit_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE org_id = $1")
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .expect("count rejected audit rows");
        assert_eq!(
            (app_count, deployment_count, artifact_count, audit_count),
            (0, 0, 0, 0)
        );

        sqlx::query("DELETE FROM organizations WHERE id = $1")
            .bind(org_id)
            .execute(&pool)
            .await
            .expect("delete entitlement race org");
    }
}
