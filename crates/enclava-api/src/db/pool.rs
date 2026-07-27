use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

/// Create a connection pool from a DATABASE_URL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

/// Run all pending migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await?;
    #[cfg(test)]
    sqlx::query(
        "UPDATE cap_runtime_authority
            SET authority_epoch = $1,
                restore_generation = $2
          WHERE singleton",
    )
    .bind(crate::runtime_authority::TEST_RUNTIME_AUTHORITY.epoch)
    .bind(crate::runtime_authority::TEST_RUNTIME_AUTHORITY.restore_generation)
    .execute(pool)
    .await?;
    Ok(())
}
