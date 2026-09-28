use anyhow::{Result, bail};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MigrationMode {
    Apply,
    Verify,
}

impl MigrationMode {
    pub fn from_env() -> Result<Self> {
        Self::parse(std::env::var("DATABASE_MIGRATION_MODE").ok().as_deref())
    }

    fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("apply") {
            "apply" => Ok(Self::Apply),
            "verify" => Ok(Self::Verify),
            value => bail!("DATABASE_MIGRATION_MODE must be apply or verify, found {value}"),
        }
    }
}

/// Create a connection pool from a DATABASE_URL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

/// Run all pending migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    MIGRATOR.run(pool).await
}

/// Apply migrations for standalone installs, or only verify the schema when a
/// deployment migration Job owns upgrades.
pub async fn prepare_schema(pool: &PgPool, mode: MigrationMode) -> Result<()> {
    if mode == MigrationMode::Apply {
        run_migrations(pool).await?;
        verify_nip98_purge_index(pool).await?;
        return Ok(());
    }

    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    verify_migration_ledger(&applied, &MIGRATOR)?;
    verify_nip98_purge_index(pool).await
}

/// Fail startup when the NIP-98 replay-cache purge index is missing or
/// INVALID. Migration 0057 builds it with `CREATE INDEX CONCURRENTLY`
/// (no-transaction): a build that fails halfway leaves an index with
/// `indisvalid = false`, and `IF NOT EXISTS` on retry treats that broken
/// index as present — which would silently degrade every reaper purge to a
/// sequential scan. The check lives here rather than in the migration file
/// because a CONCURRENTLY statement cannot share a migration batch with
/// any other statement (Postgres would wrap the batch in an implicit
/// transaction and reject the CONCURRENTLY build).
async fn verify_nip98_purge_index(pool: &PgPool) -> Result<()> {
    let index_state: Option<(bool,)> = sqlx::query_as(
        "SELECT indisvalid FROM pg_index i \
         JOIN pg_class c ON c.oid = i.indexrelid \
         WHERE c.relname = 'nip98_replay_cache_first_seen_purge'",
    )
    .fetch_optional(pool)
    .await?;
    if !matches!(index_state, Some((true,))) {
        bail!(
            "nip98_replay_cache_first_seen_purge is missing or INVALID \
             (failed CONCURRENTLY build or manual drop); DROP INDEX and clean \
             the version-57 _sqlx_migrations row, then re-run cap_migrate"
        );
    }
    Ok(())
}

fn verify_migration_ledger(
    applied: &[(i64, bool, Vec<u8>)],
    migrator: &sqlx::migrate::Migrator,
) -> Result<()> {
    if let Some((version, _, _)) = applied.iter().find(|(_, success, _)| !success) {
        bail!("database migration {version} is not successfully applied");
    }
    let expected: Vec<_> = migrator
        .iter()
        .filter(|migration| !migration.migration_type.is_down_migration())
        .collect();
    if applied.len() != expected.len() {
        bail!(
            "database has {} migration rows but binary requires {}",
            applied.len(),
            expected.len()
        );
    }
    for ((version, _, checksum), migration) in applied.iter().zip(expected) {
        if *version != migration.version {
            bail!(
                "database migration version {version} does not match binary version {}",
                migration.version
            );
        }
        if checksum.as_slice() != &*migration.checksum {
            bail!("database migration {version} checksum does not match binary");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn schema_test_pool() -> sqlx::PgPool {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://test:***@localhost:5432/test".to_string());
        let pool = sqlx::PgPool::connect(&database_url)
            .await
            .expect("connect schema guard test database");
        run_migrations(&pool)
            .await
            .expect("migrate schema guard test database");
        pool
    }

    #[tokio::test]
    async fn prepare_schema_accepts_a_valid_purge_index() {
        let pool = schema_test_pool().await;
        prepare_schema(&pool, MigrationMode::Verify)
            .await
            .expect("verify mode must accept a fully migrated database with a valid purge index");
    }

    #[tokio::test]
    async fn prepare_schema_rejects_an_invalid_purge_index() {
        let pool = schema_test_pool().await;
        sqlx::query(
            "UPDATE pg_index SET indisvalid = false WHERE indexrelid = \
                     (SELECT c.oid FROM pg_class c WHERE c.relname = \
                      'nip98_replay_cache_first_seen_purge')",
        )
        .execute(&pool)
        .await
        .expect("mark purge index invalid");
        let err = prepare_schema(&pool, MigrationMode::Verify)
            .await
            .expect_err("invalid purge index must fail startup");
        assert!(
            err.to_string()
                .contains("nip98_replay_cache_first_seen_purge")
        );
        // restore for sibling tests sharing the database
        sqlx::query(
            "UPDATE pg_index SET indisvalid = true WHERE indexrelid = \
                     (SELECT c.oid FROM pg_class c WHERE c.relname = \
                      'nip98_replay_cache_first_seen_purge')",
        )
        .execute(&pool)
        .await
        .expect("restore purge index validity");
    }

    #[tokio::test]
    async fn prepare_schema_rejects_a_missing_purge_index() {
        let pool = schema_test_pool().await;
        sqlx::query("DROP INDEX IF EXISTS nip98_replay_cache_first_seen_purge")
            .execute(&pool)
            .await
            .expect("drop purge index");
        let err = prepare_schema(&pool, MigrationMode::Verify)
            .await
            .expect_err("missing purge index must fail startup");
        assert!(
            err.to_string()
                .contains("nip98_replay_cache_first_seen_purge")
        );
        // restore for sibling tests sharing the database
        sqlx::query(
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS \
                     nip98_replay_cache_first_seen_purge ON nip98_replay_cache (first_seen)",
        )
        .execute(&pool)
        .await
        .expect("restore purge index");
    }

    #[test]
    fn migration_mode_defaults_to_apply_and_accepts_verify() {
        assert_eq!(MigrationMode::parse(None).unwrap(), MigrationMode::Apply);
        assert_eq!(
            MigrationMode::parse(Some("verify")).unwrap(),
            MigrationMode::Verify
        );
        assert!(MigrationMode::parse(Some("automatic")).is_err());
    }

    #[test]
    fn verify_mode_requires_the_exact_successful_migration_ledger() {
        let exact: Vec<_> = MIGRATOR
            .iter()
            .filter(|migration| !migration.migration_type.is_down_migration())
            .map(|migration| (migration.version, true, migration.checksum.to_vec()))
            .collect();
        verify_migration_ledger(&exact, &MIGRATOR).unwrap();

        let mut dirty = exact.clone();
        dirty[0].1 = false;
        assert!(verify_migration_ledger(&dirty, &MIGRATOR).is_err());

        let mut mismatched = exact.clone();
        mismatched[0].2[0] ^= 0xff;
        assert!(verify_migration_ledger(&mismatched, &MIGRATOR).is_err());

        assert!(verify_migration_ledger(&exact[..exact.len() - 1], &MIGRATOR).is_err());
    }
}
