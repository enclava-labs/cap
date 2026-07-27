//! Database-lifetime identity for external generation metadata.
//!
//! Monotonic mutation generations are meaningful only inside one Postgres
//! authority lifetime. Kubernetes ConfigMaps and workload controllers can
//! survive a clean database initialization or a database restore, so every
//! published generation also carries this durable epoch. The deployment owns
//! an out-of-database monotonic restore generation. Advancing it rotates the
//! epoch atomically at startup; moving it backwards fails closed.

use sqlx::{PgPool, Postgres, Transaction};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum EstablishAuthorityError {
    #[error("database error while establishing runtime authority: {0}")]
    Database(#[from] sqlx::Error),
    #[error(
        "CAP_DATABASE_RESTORE_GENERATION {configured} is older than the database value {stored}; \
         refusing to reuse an older deployment incarnation"
    )]
    RestoreGenerationRollback { configured: i64, stored: i64 },
    #[error(
        "active mutation authority has not completed its provider quarantine; refusing restore generation rotation"
    )]
    MutationQuarantineActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeAuthority {
    pub epoch: Uuid,
    pub restore_generation: i64,
}

impl RuntimeAuthority {
    /// Lock and compare the singleton authority in a mutation-claim
    /// transaction. The shared row lock prevents a concurrent restore
    /// generation rotation from committing until that claim either commits or
    /// rolls back.
    pub async fn is_current_in_tx(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
    ) -> Result<bool, sqlx::Error> {
        let observed: (Uuid, i64) = sqlx::query_as(
            "SELECT authority_epoch, restore_generation
              FROM cap_runtime_authority
              WHERE singleton
              FOR SHARE",
        )
        .fetch_one(&mut **transaction)
        .await?;
        Ok(observed == (self.epoch, self.restore_generation))
    }
}

#[cfg(test)]
pub const TEST_RUNTIME_AUTHORITY: RuntimeAuthority = RuntimeAuthority {
    epoch: Uuid::from_u128(0x44444444444444448444444444444444),
    restore_generation: 1,
};

pub async fn establish_epoch(
    pool: &PgPool,
    restore_generation: i64,
) -> Result<RuntimeAuthority, EstablishAuthorityError> {
    let mut transaction = pool.begin().await?;
    let authority = establish_epoch_with(&mut transaction, restore_generation).await?;
    transaction.commit().await?;
    Ok(authority)
}

async fn establish_epoch_with(
    transaction: &mut Transaction<'_, Postgres>,
    restore_generation: i64,
) -> Result<RuntimeAuthority, EstablishAuthorityError> {
    // Serialize startup authority establishment. A single-statement CTE can
    // retain a stale MVCC snapshot after waiting for a concurrent UPDATE,
    // which would let a lower restore generation report success. Locking and
    // then comparing in one transaction makes rollback refusal deterministic.
    let (current_epoch, stored_generation): (Uuid, i64) = sqlx::query_as(
        "SELECT authority_epoch, restore_generation
           FROM cap_runtime_authority
          WHERE singleton
          FOR UPDATE",
    )
    .fetch_one(&mut **transaction)
    .await?;

    if restore_generation < stored_generation {
        return Err(EstablishAuthorityError::RestoreGenerationRollback {
            configured: restore_generation,
            stored: stored_generation,
        });
    }

    if restore_generation == stored_generation {
        return Ok(RuntimeAuthority {
            epoch: current_epoch,
            restore_generation: stored_generation,
        });
    }

    // Every provider guard holds this singleton row `FOR SHARE` for the entire
    // external operation. Acquiring `FOR UPDATE` above therefore drains all
    // already-admitted calls before rotation can reach this point. A surviving
    // old process also keeps refreshing its owner rows, so require one complete
    // provider quarantine with no owner activity before retiring restored
    // tokens, including explicitly poisoned generations.
    let quarantine_clear: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS (
             SELECT 1
               FROM app_mutation_leases
              WHERE owner_token IS NOT NULL
                AND updated_at >
                    clock_timestamp() - ($1::bigint * interval '1 second')
             UNION ALL
             SELECT 1
               FROM external_resource_mutation_leases
              WHERE owner_token IS NOT NULL
                AND updated_at >
                    clock_timestamp() - ($1::bigint * interval '1 second')
         )",
    )
    .bind(crate::mutation_leases::RECLAIM_QUARANTINE_SECONDS)
    .fetch_one(&mut **transaction)
    .await?;
    if !quarantine_clear {
        return Err(EstablishAuthorityError::MutationQuarantineActive);
    }

    // A higher out-of-database restore generation is explicit authority to
    // retire every owner restored from the backup. Increment generations as
    // well as clearing tokens so stale in-memory handles cannot match even if
    // they survive outside the guarded provider path.
    sqlx::query(
        "UPDATE app_mutation_leases
            SET generation = generation + 1,
                owner_token = NULL,
                operation_kind = NULL,
                operation_id = NULL,
                locked_until = NULL,
                reclaim_after = NULL,
                updated_at = clock_timestamp()
          WHERE owner_token IS NOT NULL",
    )
    .execute(&mut **transaction)
    .await?;
    sqlx::query(
        "UPDATE external_resource_mutation_leases
            SET generation = generation + 1,
                owner_token = NULL,
                operation_kind = NULL,
                operation_id = NULL,
                locked_until = NULL,
                reclaim_after = NULL,
                updated_at = clock_timestamp()
          WHERE owner_token IS NOT NULL",
    )
    .execute(&mut **transaction)
    .await?;
    // Exact failed-rollout cleanup from the restored authority is no longer
    // valid after its owners are retired. The generic KBS and edge startup
    // reconcilers publish restored database truth under the new authority.
    sqlx::query(
        "UPDATE deployment_apply_jobs
            SET state = 'completed',
                lock_token = NULL,
                locked_until = NULL,
                last_error_code = 'runtime_authority_rotated',
                updated_at = clock_timestamp()
          WHERE state IN ('rollout_cleanup_pending', 'rollout_cleaning_up')",
    )
    .execute(&mut **transaction)
    .await?;

    let (epoch, stored_generation): (Uuid, i64) = sqlx::query_as(
        "UPDATE cap_runtime_authority
            SET authority_epoch = gen_random_uuid(),
                epoch_established_at = clock_timestamp(),
                restore_generation = $1
          WHERE singleton
      RETURNING authority_epoch, restore_generation",
    )
    .bind(restore_generation)
    .fetch_one(&mut **transaction)
    .await?;

    Ok(RuntimeAuthority {
        epoch,
        restore_generation: stored_generation,
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
            .expect("connect runtime authority test database");
        crate::db::pool::run_migrations(&pool)
            .await
            .expect("migrate runtime authority test database");
        pool
    }

    #[tokio::test]
    async fn restore_generation_rotates_once_and_rollbacks_fail_closed() {
        let pool = database_test_pool().await;
        let mut tx = pool.begin().await.expect("begin runtime authority test");
        let baseline_generation: i64 = sqlx::query_scalar(
            "SELECT restore_generation FROM cap_runtime_authority WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("load baseline restore generation");
        let baseline_epoch = Uuid::new_v4();
        sqlx::query(
            "UPDATE cap_runtime_authority
                SET authority_epoch = $1,
                    restore_generation = $2
              WHERE singleton",
        )
        .bind(baseline_epoch)
        .bind(baseline_generation)
        .execute(&mut *tx)
        .await
        .expect("set isolated baseline authority");
        let baseline = RuntimeAuthority {
            epoch: baseline_epoch,
            restore_generation: baseline_generation,
        };
        assert!(
            baseline
                .is_current_in_tx(&mut tx)
                .await
                .expect("validate baseline authority")
        );

        let advanced = establish_epoch_with(&mut tx, baseline_generation + 1)
            .await
            .expect("advance restore generation");
        assert_ne!(advanced.epoch, baseline_epoch);
        assert_eq!(advanced.restore_generation, baseline_generation + 1);
        assert!(
            !baseline
                .is_current_in_tx(&mut tx)
                .await
                .expect("reject cached pre-restore authority")
        );
        assert!(
            advanced
                .is_current_in_tx(&mut tx)
                .await
                .expect("validate rotated authority")
        );

        let stable = establish_epoch_with(&mut tx, baseline_generation + 1)
            .await
            .expect("re-establish matching restore generation");
        assert_eq!(stable, advanced);

        let rollback = establish_epoch_with(&mut tx, baseline_generation)
            .await
            .expect_err("older deployment restore generation must fail closed");
        assert!(matches!(
            rollback,
            EstablishAuthorityError::RestoreGenerationRollback {
                configured,
                stored
            } if configured == baseline_generation && stored == baseline_generation + 1
        ));

        tx.rollback()
            .await
            .expect("rollback runtime authority test");
    }

    #[tokio::test]
    async fn restore_rotation_quarantines_recent_owners_then_retires_poisoned_generations() {
        let pool = database_test_pool().await;
        let mut tx = pool.begin().await.expect("begin owner retirement test");
        let baseline_generation: i64 = sqlx::query_scalar(
            "SELECT restore_generation FROM cap_runtime_authority WHERE singleton",
        )
        .fetch_one(&mut *tx)
        .await
        .expect("load baseline restore generation");
        let baseline_epoch = Uuid::new_v4();
        sqlx::query(
            "UPDATE cap_runtime_authority
                SET authority_epoch = $1,
                    restore_generation = $2
              WHERE singleton",
        )
        .bind(baseline_epoch)
        .bind(baseline_generation)
        .execute(&mut *tx)
        .await
        .expect("set isolated retirement authority");

        let resource_key = format!("restore-poison-{}", Uuid::new_v4().simple());
        let owner_token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO external_resource_mutation_leases (
                 resource_scope, resource_key, generation, owner_token,
                 operation_kind, operation_id, locked_until, reclaim_after,
                 updated_at
             )
             VALUES (
                 'restore_retirement_test', $1, 7, $2,
                 'pre_restore_provider', $3,
                 clock_timestamp() + interval '3 minutes',
                 'infinity'::timestamptz,
                 clock_timestamp()
             )",
        )
        .bind(&resource_key)
        .bind(owner_token)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .expect("insert recently active poisoned owner");

        let quarantined = establish_epoch_with(&mut tx, baseline_generation + 1)
            .await
            .expect_err("recent provider authority must block restore rotation");
        assert!(matches!(
            quarantined,
            EstablishAuthorityError::MutationQuarantineActive
        ));
        let unchanged: (Uuid, i64, Option<Uuid>) = sqlx::query_as(
            "SELECT authority.authority_epoch,
                    authority.restore_generation,
                    resource.owner_token
               FROM cap_runtime_authority AS authority
               JOIN external_resource_mutation_leases AS resource
                 ON resource.resource_scope = 'restore_retirement_test'
                AND resource.resource_key = $1
              WHERE authority.singleton",
        )
        .bind(&resource_key)
        .fetch_one(&mut *tx)
        .await
        .expect("load quarantined authority");
        assert_eq!(
            unchanged,
            (baseline_epoch, baseline_generation, Some(owner_token))
        );

        sqlx::query(
            "UPDATE external_resource_mutation_leases
                SET updated_at = clock_timestamp()
                    - (($2 + 1)::bigint * interval '1 second')
              WHERE resource_scope = 'restore_retirement_test'
                AND resource_key = $1",
        )
        .bind(&resource_key)
        .bind(crate::mutation_leases::RECLAIM_QUARANTINE_SECONDS)
        .execute(&mut *tx)
        .await
        .expect("age retired provider past the complete quarantine");

        let advanced = establish_epoch_with(&mut tx, baseline_generation + 1)
            .await
            .expect("explicit restore generation retires quiet poisoned owner");
        assert_ne!(advanced.epoch, baseline_epoch);
        assert_eq!(advanced.restore_generation, baseline_generation + 1);
        let retired: (i64, Option<Uuid>, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            "SELECT generation, owner_token, reclaim_after
                   FROM external_resource_mutation_leases
                  WHERE resource_scope = 'restore_retirement_test'
                    AND resource_key = $1",
        )
        .bind(&resource_key)
        .fetch_one(&mut *tx)
        .await
        .expect("load retired poisoned owner");
        assert_eq!(retired, (8, None, None));

        tx.rollback().await.expect("rollback owner retirement test");
    }
}
