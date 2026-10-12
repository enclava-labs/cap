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

/// Run all pending migrations, then verify the objects those migrations
/// promise are usable (see [`verify_nip98_purge_index`]).
///
/// The guard runs here, not only in [`prepare_schema`], so every migration
/// entry point — the `cap_migrate` Job binary, API startup, and the test
/// harnesses — reports the same verdict. A migration Job that exits 0 over
/// a broken purge index only surfaces the problem later, at API startup,
/// with nothing linking it back to the schema step that "succeeded".
pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    MIGRATOR.run(pool).await?;
    verify_nip98_purge_index(pool).await
}

/// Apply migrations for standalone installs, or only verify the schema when a
/// deployment migration Job owns upgrades.
pub async fn prepare_schema(pool: &PgPool, mode: MigrationMode) -> Result<()> {
    if mode == MigrationMode::Apply {
        return run_migrations(pool).await;
    }

    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(pool)
            .await?;
    verify_migration_ledger(&applied, &MIGRATOR)?;
    verify_nip98_purge_index(pool).await
}

/// Fail when the NIP-98 replay-cache purge index is missing, INVALID, or not
/// the definition migration 0057 builds.
///
/// Why this is needed at all: migration 0057 builds the index with
/// `CREATE INDEX CONCURRENTLY` (no-transaction), and a build that fails
/// halfway leaves an index with `indisvalid = false`. `IF NOT EXISTS` on the
/// retry treats that broken index as present, so the migration would count
/// as applied while every reaper purge degrades to a sequential scan. The
/// check lives in Rust rather than in the migration file because a
/// CONCURRENTLY statement cannot share a migration batch with any other
/// statement (Postgres wraps multi-statement batches in an implicit
/// transaction and rejects the CONCURRENTLY build).
///
/// Why the lookup is table-scoped: PostgreSQL index names are scoped to
/// schemas, not globally unique, and the reaper purges through the
/// unqualified `nip98_replay_cache` name — i.e. whatever the active search
/// path resolves. The guard therefore resolves the table the same way
/// (`to_regclass`) and requires the named index to sit on that exact table:
/// a valid namesake in another schema, or on another table, must not stand
/// in for the real purge index.
///
/// Recovery when this fails (also documented in migration 0057's header):
/// drop the stale index (`DROP INDEX [CONCURRENTLY] IF EXISTS
/// nip98_replay_cache_first_seen_purge`), delete the version-57
/// `_sqlx_migrations` row if one exists, then re-run `cap_migrate` to
/// rebuild and re-verify. Note that sqlx 0.8.6 records a no-transaction
/// migration only after its script succeeds, so a failed 0057 run leaves no
/// ledger row to clean up; the DELETE step only matters for the
/// applied-then-broken case.
async fn verify_nip98_purge_index<'e, E>(exec: E) -> Result<()>
where
    E: sqlx::PgExecutor<'e>,
{
    let index_facts: Option<(bool, bool, bool, bool, bool)> = sqlx::query_as(
        "SELECT i.indisvalid,
                am.amname = 'btree',
                i.indpred IS NULL,
                i.indexprs IS NULL,
                (string_to_array(i.indkey::text, ' '))[1]::int = a.attnum
         FROM pg_class idx
         JOIN pg_index i ON i.indexrelid = idx.oid
         JOIN pg_class tbl ON tbl.oid = i.indrelid
         JOIN pg_am am ON am.oid = idx.relam
         JOIN pg_attribute a ON a.attrelid = tbl.oid AND a.attname = 'first_seen'
         WHERE idx.relname = 'nip98_replay_cache_first_seen_purge'
           AND tbl.oid = to_regclass('nip98_replay_cache')",
    )
    .fetch_optional(exec)
    .await?;
    let recovery = "drop it (DROP INDEX [CONCURRENTLY] IF EXISTS \
                    nip98_replay_cache_first_seen_purge), delete the \
                    version-57 _sqlx_migrations row if one exists, then \
                    re-run cap_migrate to rebuild and re-verify";
    match index_facts {
        Some((true, true, true, true, true)) => Ok(()),
        Some((false, ..)) => bail!(
            "nip98_replay_cache_first_seen_purge is INVALID (failed or interrupted CONCURRENTLY build); {recovery}"
        ),
        Some(_) => bail!(
            "nip98_replay_cache_first_seen_purge does not match the expected definition (btree index on the first_seen column of the search_path-visible nip98_replay_cache, no predicate or expression); {recovery}"
        ),
        None => bail!(
            "nip98_replay_cache_first_seen_purge is missing on the search_path-visible nip98_replay_cache (failed CONCURRENTLY build, manual drop, or only a namesake index elsewhere); {recovery}"
        ),
    }
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
            .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
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

    /// Mutate the shared database and run the guard over the mutated state,
    /// always inside a transaction that is rolled back afterwards: even a
    /// panic cannot leak a dropped or catalog-hacked index to sibling tests
    /// (CI runs the whole workspace against one shared PostgreSQL service).
    /// The catalog-hack case needs a superuser role, which CI's
    /// `POSTGRES_USER` provides.
    async fn guard_error_after(mutations: &[&str]) -> String {
        let pool = schema_test_pool().await;
        let mut tx = pool.begin().await.expect("begin guard test transaction");
        for sql in mutations {
            sqlx::query(sql)
                .execute(&mut *tx)
                .await
                .expect("apply guard test mutation");
        }
        let err = verify_nip98_purge_index(&mut *tx)
            .await
            .expect_err("guard must reject the mutated purge-index state");
        tx.rollback().await.expect("roll back guard test mutations");
        err.to_string()
    }

    #[tokio::test]
    async fn purge_index_guard_rejects_a_missing_index() {
        let err =
            guard_error_after(&["DROP INDEX IF EXISTS nip98_replay_cache_first_seen_purge"]).await;
        assert!(err.contains("nip98_replay_cache_first_seen_purge"));
        assert!(err.contains("missing"));
    }

    #[tokio::test]
    async fn purge_index_guard_rejects_an_invalid_index() {
        let err = guard_error_after(&["UPDATE pg_index SET indisvalid = false \
             WHERE indexrelid = to_regclass('nip98_replay_cache_first_seen_purge')"])
        .await;
        assert!(err.contains("nip98_replay_cache_first_seen_purge"));
        assert!(err.contains("INVALID"));
    }

    #[tokio::test]
    async fn purge_index_guard_rejects_a_namesake_on_another_table() {
        let err = guard_error_after(&[
            "DROP INDEX IF EXISTS nip98_replay_cache_first_seen_purge",
            "CREATE TABLE guard_decoy (first_seen timestamptz)",
            "CREATE INDEX nip98_replay_cache_first_seen_purge ON guard_decoy (first_seen)",
        ])
        .await;
        assert!(err.contains("nip98_replay_cache_first_seen_purge"));
    }

    #[tokio::test]
    async fn purge_index_guard_rejects_a_namesake_in_another_schema() {
        let err = guard_error_after(&[
            "DROP INDEX IF EXISTS nip98_replay_cache_first_seen_purge",
            "CREATE SCHEMA guard_decoy",
            "CREATE TABLE guard_decoy.decoy (first_seen timestamptz)",
            "CREATE INDEX nip98_replay_cache_first_seen_purge ON guard_decoy.decoy (first_seen)",
        ])
        .await;
        assert!(err.contains("nip98_replay_cache_first_seen_purge"));
    }

    #[tokio::test]
    async fn purge_index_guard_rejects_a_misdefined_index() {
        let err = guard_error_after(&[
            "DROP INDEX IF EXISTS nip98_replay_cache_first_seen_purge",
            "CREATE INDEX nip98_replay_cache_first_seen_purge ON nip98_replay_cache (event_id)",
        ])
        .await;
        assert!(err.contains("nip98_replay_cache_first_seen_purge"));
        assert!(err.contains("expected definition"));
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
