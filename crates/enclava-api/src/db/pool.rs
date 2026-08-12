use anyhow::{Result, bail};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

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
    sqlx::migrate!("./migrations").run(pool).await
}

/// Apply migrations for standalone installs, or only verify the schema when a
/// deployment migration Job owns upgrades.
pub async fn prepare_schema(pool: &PgPool, mode: MigrationMode) -> Result<()> {
    if mode == MigrationMode::Apply {
        run_migrations(pool).await?;
        return Ok(());
    }

    let expected = sqlx::migrate!("./migrations")
        .iter()
        .map(|migration| migration.version)
        .max();
    let actual: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(pool)
            .await?;
    if actual != expected {
        bail!("database schema version {actual:?} does not match binary version {expected:?}");
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
}
