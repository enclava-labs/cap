//! Apply-job generation stamped into config tokens.
//!
//! Deployment-scoped tokens are bound to that deployment's generation even
//! after it is superseded, so a refresh cannot upgrade into a later writer.
//! App-scoped operator tokens take the newest generation for the app so a
//! manual write is not stuck behind a failed higher generation and is not a
//! generation-0 bypass after a fenced write.

use sqlx::PgPool;
use uuid::Uuid;

pub async fn deployment_apply_generation(
    pool: &PgPool,
    deployment_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT generation
           FROM deployment_apply_jobs
          WHERE deployment_id = $1",
    )
    .bind(deployment_id)
    .fetch_optional(pool)
    .await
}

/// Newest apply-job generation for the app, including failed and in-flight jobs.
///
/// Operator `config set` must still be able to write after a held deploy
/// advanced the TEE mark and then failed. The stale-CLI race is closed by
/// the deployment-scoped refresh, not by narrowing this stamp.
pub async fn app_config_write_generation(
    pool: &PgPool,
    app_id: Uuid,
) -> Result<Option<i64>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT MAX(generation)
           FROM deployment_apply_jobs
          WHERE app_id = $1",
    )
    .bind(app_id)
    .fetch_one(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn deployment_token_generation_stays_on_that_deployment() {
        let pool = crate::test_support::database_test_pool().await;
        let org_id = Uuid::new_v4();
        let app_id = Uuid::new_v4();
        let older = Uuid::new_v4();
        let newer = Uuid::new_v4();
        let suffix = app_id.simple().to_string();
        sqlx::query("INSERT INTO organizations (id, name, cust_slug) VALUES ($1, $2, $3)")
            .bind(org_id)
            .bind(format!("gen-{suffix}"))
            .bind(&suffix[..8])
            .execute(&pool)
            .await
            .expect("insert org");
        sqlx::query(
            "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain, status
             ) VALUES ($1, $2, $3, $4, $5, $5, 'cap-gen-sa',
                       $6, $7, $8, $9, 'running'::app_status_enum)",
        )
        .bind(app_id)
        .bind(org_id)
        .bind(format!("app-{suffix}"))
        .bind(format!("ns-{suffix}"))
        .bind(&suffix)
        .bind("00".repeat(32))
        .bind("11".repeat(32))
        .bind(format!("{suffix}.example.test"))
        .bind(format!("{suffix}.tee.example.test"))
        .execute(&pool)
        .await
        .expect("insert app");
        let mut tx = pool.begin().await.expect("begin generation fixture");
        for (deployment_id, job_state, deploy_status) in [
            (older, "completed", "healthy"),
            (newer, "pending", "pending"),
        ] {
            sqlx::query(
                "INSERT INTO deployment_apply_jobs (
                     deployment_id, app_id, org_id, source_deployment_id,
                     payload_version, payload, payload_sha256,
                     cleanup_app_on_setup_failure, signed_required, state
                 ) VALUES ($1, $2, $3, $1, 1, '{\"version\":1,\"log_encryption\":null}'::jsonb, $4,
                           false, false, $5)",
            )
            .bind(deployment_id)
            .bind(app_id)
            .bind(org_id)
            .bind(vec![7u8; 32])
            .bind(job_state)
            .execute(&mut *tx)
            .await
            .expect("insert apply job");
            sqlx::query(
                "INSERT INTO deployments (id, org_id, app_id, status, spec_snapshot)
                 VALUES ($1, $2, $3, $4::deploy_status_enum, '{}'::jsonb)",
            )
            .bind(deployment_id)
            .bind(org_id)
            .bind(app_id)
            .bind(deploy_status)
            .execute(&mut *tx)
            .await
            .expect("insert deployment");
        }
        tx.commit().await.expect("commit generation fixture");
        let older_generation = deployment_apply_generation(&pool, older)
            .await
            .expect("older generation")
            .expect("older job has a generation");
        let newer_generation = deployment_apply_generation(&pool, newer)
            .await
            .expect("newer generation")
            .expect("newer job has a generation");
        assert!(newer_generation > older_generation);
        assert_eq!(
            app_config_write_generation(&pool, app_id)
                .await
                .expect("app generation"),
            Some(newer_generation),
            "operator tokens must include a failed or in-flight generation the TEE may already have accepted"
        );
        assert_ne!(
            deployment_apply_generation(&pool, older)
                .await
                .expect("stale lookup")
                .expect("stale generation"),
            newer_generation,
            "a superseded deployment's token must not be upgraded to the later generation"
        );
    }
}
