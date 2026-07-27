//! Database-lifetime identity for external generation metadata.
//!
//! Monotonic mutation generations are meaningful only inside one Postgres
//! authority lifetime. Kubernetes ConfigMaps and workload controllers can
//! survive a clean database initialization or a database restore, so every
//! published generation also carries this durable epoch.

use sqlx::PgPool;
use uuid::Uuid;

pub async fn load_epoch(pool: &PgPool) -> Result<Uuid, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT authority_epoch
           FROM cap_runtime_authority
          WHERE singleton",
    )
    .fetch_one(pool)
    .await
}
