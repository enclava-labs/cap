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
        return Ok(());
    }

    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    verify_migration_ledger(&applied, &MIGRATOR)
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
