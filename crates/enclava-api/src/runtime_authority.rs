//! Database-lifetime identity for external generation metadata.
//!
//! Monotonic mutation generations are meaningful only inside one Postgres
//! authority lifetime. Kubernetes ConfigMaps and workload controllers can
//! survive a clean database initialization or a database restore, so every
//! published generation also carries this durable epoch. The deployment owns
//! an out-of-database monotonic restore generation. Advancing it rotates the
//! epoch atomically at startup; moving it backwards fails closed.

use sqlx::{Executor, PgPool, Postgres};
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

pub async fn establish_epoch(
    pool: &PgPool,
    restore_generation: i64,
) -> Result<RuntimeAuthority, EstablishAuthorityError> {
    establish_epoch_with(pool, restore_generation).await
}

async fn establish_epoch_with<'e, E>(
    executor: E,
    restore_generation: i64,
) -> Result<RuntimeAuthority, EstablishAuthorityError>
where
    E: Executor<'e, Database = Postgres>,
{
    let (epoch, stored_generation, rejected): (Uuid, i64, bool) = sqlx::query_as(
        "WITH current_authority AS (
             SELECT authority_epoch, restore_generation
               FROM cap_runtime_authority
              WHERE singleton
         ),
         updated_authority AS (
             UPDATE cap_runtime_authority
                SET authority_epoch = CASE
                        WHEN restore_generation < $1 THEN gen_random_uuid()
                        ELSE authority_epoch
                    END,
                    epoch_established_at = CASE
                        WHEN restore_generation < $1 THEN clock_timestamp()
                        ELSE epoch_established_at
                    END,
                    restore_generation = $1
              WHERE singleton
                AND restore_generation <= $1
          RETURNING authority_epoch, restore_generation
         )
         SELECT COALESCE(updated.authority_epoch, current.authority_epoch),
                COALESCE(updated.restore_generation, current.restore_generation),
                current.restore_generation > $1
           FROM current_authority AS current
           LEFT JOIN updated_authority AS updated ON true",
    )
    .bind(restore_generation)
    .fetch_one(executor)
    .await?;

    if rejected {
        return Err(EstablishAuthorityError::RestoreGenerationRollback {
            configured: restore_generation,
            stored: stored_generation,
        });
    }

    Ok(RuntimeAuthority {
        epoch,
        restore_generation: stored_generation,
    })
}

pub async fn load_epoch(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT authority_epoch
           FROM cap_runtime_authority
          WHERE singleton",
    )
    .fetch_one(pool)
    .await
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

        let advanced = establish_epoch_with(&mut *tx, baseline_generation + 1)
            .await
            .expect("advance restore generation");
        assert_ne!(advanced.epoch, baseline_epoch);
        assert_eq!(advanced.restore_generation, baseline_generation + 1);

        let stable = establish_epoch_with(&mut *tx, baseline_generation + 1)
            .await
            .expect("re-establish matching restore generation");
        assert_eq!(stable, advanced);

        let rollback = establish_epoch_with(&mut *tx, baseline_generation)
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
