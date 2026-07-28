fn install_default_rustls_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_default_rustls_crypto_provider();

    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let pool = enclava_api::db::pool::create_pool(&database_url).await?;
    enclava_api::db::pool::run_migrations(&pool).await?;
    let version: Option<i64> =
        sqlx::query_scalar("SELECT max(version) FROM _sqlx_migrations WHERE success")
            .fetch_one(&pool)
            .await?;
    println!(
        "{}",
        serde_json::json!({
            "status": "migrated",
            "schema_version": version,
        })
    );
    Ok(())
}
