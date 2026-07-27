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
}
