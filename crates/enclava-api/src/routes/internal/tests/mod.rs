use super::*;
use axum::http::HeaderValue;
use sqlx::Connection;

#[test]
fn create_app_request_without_resources_serializes_legacy_form() {
    let request = InternalCreateAppRequest {
        name: "app".to_string(),
        unlock_mode: "password".to_string(),
        bootstrap_pubkey_hash: None,
        signer_identity_subject: None,
        signer_identity_issuer: None,
        egress_allowlist: Vec::new(),
        egress_mode: crate::routes::apps::default_egress_mode(),
        resources: None,
    };
    let json = serde_json::to_value(&request).expect("serialize create request");
    // Absent resources must not appear: replayed pre-upgrade requests are
    // compared to their persisted fingerprint, which has no such key.
    assert!(json.get("resources").is_none());

    // A pre-upgrade payload without the key still deserializes.
    let decoded: InternalCreateAppRequest =
        serde_json::from_value(serde_json::json!({"name": "app"}))
            .expect("decode legacy create request");
    assert!(decoded.resources.is_none());
}

async fn database_test_pool() -> sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("connect membership sync regression database");
    crate::db::pool::run_migrations(&pool)
        .await
        .expect("migrate membership sync regression database");
    pool
}

async fn named_database_test_pool(application_name: &str) -> sqlx::PgPool {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let options = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("parse membership sync regression database URL")
        .application_name(application_name);
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with(options)
        .await
        .expect("connect named membership sync pool")
}

async fn wait_for_named_lock_waiters(pool: &sqlx::PgPool, application_name: &str, expected: i64) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let waiting: i64 = sqlx::query_scalar(
                "SELECT count(*)
                       FROM pg_stat_activity
                      WHERE datname = current_database()
                        AND application_name = $1
                        AND wait_event_type = 'Lock'",
            )
            .bind(application_name)
            .fetch_one(pool)
            .await
            .expect("inspect named membership sync lock state");
            if waiting >= expected {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("membership sync writers did not reach the mapping lane");
}

fn idempotency_headers(key: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "idempotency-key",
        HeaderValue::from_str(key).expect("valid idempotency key"),
    );
    headers
}

async fn sync_member(
    state: &AppState,
    paas_org_id: &str,
    paas_user_id: &str,
    idempotency_key: &str,
    body: SyncPaaSMemberRequest,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    sync_paas_member(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state.clone()),
        Path((paas_org_id.to_string(), paas_user_id.to_string())),
        idempotency_headers(idempotency_key),
        Json(body),
    )
    .await
}

fn member_request(
    display_name: &str,
    role: &str,
    active: bool,
    version: i64,
) -> SyncPaaSMemberRequest {
    SyncPaaSMemberRequest {
        display_name: display_name.to_string(),
        role: role.to_string(),
        active,
        version,
    }
}

async fn insert_mapped_org(pool: &sqlx::PgPool, org_id: Uuid, org_name: &str, paas_org_id: &str) {
    crate::db::orgs::insert_org_pool(pool, org_id, org_name, None, false)
        .await
        .expect("insert membership sync organization");
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id, org_id)
             VALUES ('organization', $1, $2, $2)",
    )
    .bind(paas_org_id)
    .bind(org_id)
    .execute(pool)
    .await
    .expect("map membership sync organization");
}

fn idempotency_test_state(pool: sqlx::PgPool) -> AppState {
    let mut state = crate::test_support::lazy_state();
    state.side_effect_admission = crate::state::side_effect_admission_for_pool(&pool);
    state.db = pool;
    state
}

fn expect_idempotency_execution(begin: IdempotencyBegin) -> IdempotencyLease {
    match begin {
        IdempotencyBegin::Execute(lease) => lease,
        IdempotencyBegin::Replay((status, body)) => {
            panic!("expected execution, got replay {status}: {body}")
        }
    }
}

fn expect_idempotency_replay(begin: IdempotencyBegin) -> IdempotencyResponse {
    match begin {
        IdempotencyBegin::Replay(response) => response,
        IdempotencyBegin::Execute(_) => panic!("expected replay, got execution"),
    }
}

fn test_config_token_binding() -> ConfigTokenResourceBinding {
    ConfigTokenResourceBinding {
        resource_id: Uuid::new_v4(),
        instance_id: format!("test-instance-{}", Uuid::new_v4().simple()),
    }
}

async fn begin_test_config_token_receipt(
    state: &AppState,
    key: &str,
    path: &str,
    hash: &[u8],
    binding: &ConfigTokenResourceBinding,
) -> Result<IdempotencyBegin, InternalRouteError> {
    begin_idempotent_request_with_recovery_and_binding(
        state,
        key,
        "POST",
        path,
        hash,
        IdempotencyRecovery::DeterministicExpiringCapability,
        ConfigTokenIdempotencyOptions {
            binding: Some(binding),
            legacy_request_hash: None,
        },
    )
    .await
}

async fn insert_config_token_test_actor(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    org_name: &str,
    paas_org_id: &str,
    user_id: Uuid,
    paas_user_id: &str,
) {
    insert_mapped_org(pool, org_id, org_name, paas_org_id).await;
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Config Token Test')")
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert config-token actor");
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
    )
    .bind(paas_user_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("map config-token actor");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner')",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(pool)
    .await
    .expect("authorize config-token actor");
}

async fn insert_config_token_test_app(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    org_name: &str,
    app_id: Uuid,
    app_name: &str,
    identity_suffix: &str,
) {
    let namespace = format!("cap-{org_name}-{app_name}-{identity_suffix}");
    sqlx::query(
        "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain,
                 signer_identity_subject, signer_identity_issuer,
                 egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 $12, $13, '[]'::jsonb, 'restricted'
             )",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(app_name)
    .bind(&namespace)
    .bind(format!("{org_name}-{identity_suffix}"))
    .bind(org_name)
    .bind(format!("cap-{app_name}-{identity_suffix}-sa"))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!(
        "{app_name}-{identity_suffix}.{org_name}.enclava.test"
    ))
    .bind(format!(
        "{app_name}-{identity_suffix}.{org_name}.tee.enclava.test"
    ))
    .bind("https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main")
    .bind("https://token.actions.githubusercontent.com")
    .execute(pool)
    .await
    .expect("insert config-token app");
}

fn config_token_actor_headers(key: &str, paas_user_id: &str) -> HeaderMap {
    let mut headers = idempotency_headers(key);
    headers.insert(
        "x-enclava-paas-user-id",
        HeaderValue::from_str(paas_user_id).expect("valid PaaS actor header"),
    );
    headers
}

fn internal_test_auth() -> InternalAuth {
    InternalAuth {
        client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
    }
}

async fn expire_idempotency_lease(pool: &sqlx::PgPool, key: &str) {
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET lease_expires_at = clock_timestamp() - interval '1 minute',
                    updated_at = clock_timestamp() - interval '1 minute'
              WHERE idempotency_key = $1",
    )
    .bind(key)
    .execute(pool)
    .await
    .expect("expire idempotency lease with the database clock");
}

#[tokio::test]
async fn migration_terminalizes_only_stale_legacy_reservations_without_data_leakage() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let mut connection = sqlx::PgConnection::connect(&database_url)
        .await
        .expect("connect isolated idempotency migration database");
    let schema = format!("idempotency_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .expect("create isolated idempotency migration schema");
    sqlx::query(&format!("SET search_path TO {schema}, public"))
        .execute(&mut connection)
        .await
        .expect("select isolated idempotency migration schema");

    let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations: Vec<std::path::PathBuf> = std::fs::read_dir(&migration_dir)
        .expect("read API migrations")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect();
    migrations.sort();
    let lease_migration = migrations
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("0040_"))
        })
        .cloned()
        .expect("find idempotency lease migration");
    for migration in migrations.iter().filter(|path| *path < &lease_migration) {
        let sql = std::fs::read_to_string(migration).expect("read prerequisite migration");
        sqlx::raw_sql(&sql)
            .execute(&mut connection)
            .await
            .unwrap_or_else(|error| panic!("apply {}: {error}", migration.display()));
    }

    let stale_key = "migration-stale-legacy";
    let recent_key = "migration-recent-legacy";
    let completed_key = "migration-completed-legacy";
    let path = "/internal/test/migration-terminalization";
    let stale_hash = Sha256::digest(b"stale secret request payload").to_vec();
    let recent_hash = Sha256::digest(b"recent secret request payload").to_vec();
    let completed_hash = Sha256::digest(b"completed secret request payload").to_vec();
    sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash, updated_at
             ) VALUES
                 ($1, 'POST', $4, $5, clock_timestamp() - interval '31 minutes'),
                 ($2, 'POST', $4, $6, clock_timestamp() - interval '29 minutes'),
                 ($3, 'POST', $4, $7, clock_timestamp() - interval '1 day')",
    )
    .bind(stale_key)
    .bind(recent_key)
    .bind(completed_key)
    .bind(path)
    .bind(&stale_hash)
    .bind(&recent_hash)
    .bind(&completed_hash)
    .execute(&mut connection)
    .await
    .expect("seed pre-lease idempotency rows");
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET response_status = 201,
                    response_body = '{\"status\":\"already-complete\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
    )
    .bind(completed_key)
    .execute(&mut connection)
    .await
    .expect("complete control legacy row before lease migration");

    let migration_sql =
        std::fs::read_to_string(&lease_migration).expect("read idempotency lease migration");
    sqlx::raw_sql(&migration_sql)
        .execute(&mut connection)
        .await
        .expect("apply idempotency lease migration");

    type MigrationLedgerMetadata = (
        Option<Uuid>,
        Option<Uuid>,
        Option<String>,
        Option<i32>,
        Option<serde_json::Value>,
        bool,
        i32,
    );
    let stale_metadata: MigrationLedgerMetadata = sqlx::query_as(
        "SELECT reservation_token, operation_id, recovery_kind,
                    response_status, response_body,
                    completed_at IS NOT NULL, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(stale_key)
    .fetch_one(&mut connection)
    .await
    .expect("load migration-terminalized legacy row");
    assert!(stale_metadata.0.is_some());
    assert_eq!(stale_metadata.1, stale_metadata.0);
    assert_eq!(stale_metadata.2.as_deref(), Some("fail_closed"));
    assert_eq!(stale_metadata.3, Some(409));
    assert_eq!(
        stale_metadata.4,
        Some(serde_json::json!({
            "error": "idempotency_recovery_required",
            "retryable": false,
            "disposition": "reconcile_then_retry_with_new_key",
        }))
    );
    assert!(stale_metadata.5);
    assert_eq!(stale_metadata.6, 1);
    assert_eq!(
        stale_metadata
            .4
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .map(serde_json::Map::len),
        Some(3),
        "terminal response must not expose the key, path, hash, or request payload"
    );

    let pre_upgrade_completion = sqlx::query(
        "UPDATE cap_internal_idempotency
                SET response_status = 200,
                    response_body = '{\"status\":\"late-old-handler\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
    )
    .bind(stale_key)
    .execute(&mut connection)
    .await
    .expect_err("migration fence must reject pre-upgrade key-only completion");
    assert_eq!(
        pre_upgrade_completion
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );

    let stale_row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                    reservation_token, operation_id, lease_expires_at,
                    recovery_kind,
                    NULL::smallint AS capability_receipt_version,
                    NULL::uuid AS capability_resource_id,
                    NULL::text AS capability_instance_id,
                    false AS known_not_applied,
                    completed_at, created_at, updated_at,
                    clock_timestamp() AS database_now
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(stale_key)
    .fetch_one(&mut connection)
    .await
    .expect("load migration-terminalized row for replay");
    assert_eq!(
        idempotency_replay("POST", path, &stale_hash, stale_row)
            .expect("terminal migration row is replayable")
            .expect("terminal migration row has a response"),
        (
            StatusCode::CONFLICT,
            serde_json::json!({
                "error": "idempotency_recovery_required",
                "retryable": false,
                "disposition": "reconcile_then_retry_with_new_key",
            })
        )
    );

    let recent_metadata: MigrationLedgerMetadata = sqlx::query_as(
        "SELECT reservation_token, operation_id, recovery_kind,
                    response_status, response_body,
                    completed_at IS NOT NULL, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(recent_key)
    .fetch_one(&mut connection)
    .await
    .expect("load recent legacy row after migration");
    assert_eq!(recent_metadata, (None, None, None, None, None, false, 0));
    let recent_row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                    reservation_token, operation_id, lease_expires_at,
                    recovery_kind,
                    NULL::smallint AS capability_receipt_version,
                    NULL::uuid AS capability_resource_id,
                    NULL::text AS capability_instance_id,
                    false AS known_not_applied,
                    completed_at, created_at, updated_at,
                    clock_timestamp() AS database_now
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(recent_key)
    .fetch_one(&mut connection)
    .await
    .expect("load recent row for in-progress replay check");
    let recent_error = idempotency_replay("POST", path, &recent_hash, recent_row)
        .expect_err("recent legacy reservation remains in progress");
    assert_eq!(recent_error.0, StatusCode::CONFLICT);
    assert_eq!(
        recent_error.1.0,
        serde_json::json!({
            "error": "idempotency_request_in_progress",
            "retryable": true,
            "disposition": "retry_same_key",
            "idempotency_disposition": "deferred",
        })
    );

    let completed_control: (Option<i32>, Option<serde_json::Value>, bool) = sqlx::query_as(
        "SELECT response_status, response_body, completed_at IS NOT NULL
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
    )
    .bind(completed_key)
    .fetch_one(&mut connection)
    .await
    .expect("load completed migration control row");
    assert_eq!(
        completed_control,
        (
            Some(201),
            Some(serde_json::json!({"status": "already-complete"})),
            true,
        )
    );

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop isolated idempotency migration schema");
}

#[tokio::test]
async fn deterministic_config_token_migration_scrubs_legacy_and_enforces_confidentiality() {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let mut connection = sqlx::PgConnection::connect(&database_url)
        .await
        .expect("connect isolated config-token migration database");
    let schema = format!("config_token_migration_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&mut connection)
        .await
        .expect("create isolated config-token migration schema");
    sqlx::query(&format!("SET search_path TO {schema}, public"))
        .execute(&mut connection)
        .await
        .expect("select isolated config-token migration schema");

    let migration_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut migrations: Vec<std::path::PathBuf> = std::fs::read_dir(&migration_dir)
        .expect("read API migrations")
        .map(|entry| entry.expect("read migration entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "sql"))
        .collect();
    migrations.sort();
    let receipt_migration = migrations
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("0043_"))
        })
        .cloned()
        .expect("find deterministic config-token receipt migration");
    let known_not_applied_migration = migrations
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("0045_"))
        })
        .cloned()
        .expect("find known-not-applied migration");
    for migration in migrations.iter().filter(|path| *path < &receipt_migration) {
        let sql = std::fs::read_to_string(migration).expect("read prerequisite migration");
        sqlx::raw_sql(&sql)
            .execute(&mut connection)
            .await
            .unwrap_or_else(|error| panic!("apply {}: {error}", migration.display()));
    }

    let app_key = format!("legacy-app-{}", Uuid::new_v4().simple());
    let deployment_key = format!("legacy-deployment-{}", Uuid::new_v4().simple());
    let signer_key = format!("legacy-signer-{}", Uuid::new_v4().simple());
    let null_kind_key = format!("legacy-null-kind-{}", Uuid::new_v4().simple());
    let incomplete_null_key = format!("legacy-null-incomplete-{}", Uuid::new_v4().simple());
    let deployment_id = Uuid::new_v4();
    let app_secret = format!("legacy-app-bearer-{}", Uuid::new_v4());
    let deployment_secret = format!("legacy-deployment-bearer-{}", Uuid::new_v4());
    let signer_secret = format!("legacy-signer-bearer-{}", Uuid::new_v4());
    let null_kind_secret = format!("legacy-null-bearer-{}", Uuid::new_v4());
    let app_path = "/internal/paas/orgs/legacy/apps/example/config-token";
    let deployment_path =
        format!("/internal/paas/orgs/legacy/deployments/{deployment_id}/config-token");
    let signer_path = "/internal/paas/orgs/legacy/apps/example/signer/rotation-token";
    let null_kind_path = format!(
        "/internal/paas/orgs/legacy/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let incomplete_null_path = format!(
        "/internal/paas/orgs/legacy/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let legacy_auth = AuthContext {
        user_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        org_name: "legacy-migration-org".to_string(),
        role: Role::Owner,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    };
    let legacy_body = serde_json::json!({"migration": "direct-replay"});
    let null_kind_hash = request_hash(&serde_json::json!({
        "cap_user_id": legacy_auth.user_id,
        "cap_org_id": legacy_auth.org_id,
        "body": &legacy_body,
    }))
    .expect("hash pre-0043 null-kind request");
    for (key, path, status, body) in [
        (
            app_key.as_str(),
            app_path,
            200_i32,
            serde_json::json!({
                "token": app_secret,
                "tee_url": "https://legacy-secret.example.test/config"
            }),
        ),
        (
            deployment_key.as_str(),
            deployment_path.as_str(),
            409_i32,
            serde_json::json!({
                "error": "idempotency_recovery_required",
                "retryable": false,
                "disposition": "reconcile_then_retry_with_new_key",
                "discarded_marker": deployment_secret,
            }),
        ),
        (
            signer_key.as_str(),
            signer_path,
            200_i32,
            serde_json::json!({"token": signer_secret}),
        ),
    ] {
        let token = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                     idempotency_key, method, path, request_hash,
                     response_status, response_body, completed_at,
                     reservation_token, operation_id, lease_expires_at,
                     recovery_kind, attempt_count, created_at, updated_at
                 ) VALUES (
                     $1, 'POST', $2, $3, $4, $5,
                     clock_timestamp() - interval '1 minute',
                     $6, $6,
                     date_trunc('second', clock_timestamp()) - interval '1 minute',
                     'expiring_capability', 1,
                     date_trunc('second', clock_timestamp()) - interval '7 minutes',
                     clock_timestamp() - interval '1 minute'
                 )",
        )
        .bind(key)
        .bind(path)
        .bind(Sha256::digest(key.as_bytes()).to_vec())
        .bind(status)
        .bind(body)
        .bind(token)
        .execute(&mut connection)
        .await
        .expect("seed pre-0043 capability row");
    }
    sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 recovery_kind, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, 200,
                 jsonb_build_object('token', $4::text),
                 clock_timestamp() - interval '1 minute', NULL,
                 date_trunc('second', clock_timestamp()) - interval '7 minutes',
                 clock_timestamp() - interval '1 minute'
             )",
    )
    .bind(&null_kind_key)
    .bind(&null_kind_path)
    .bind(&null_kind_hash)
    .bind(&null_kind_secret)
    .execute(&mut connection)
    .await
    .expect("seed pre-0043 completed null-kind config-token row");
    sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 recovery_kind, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, NULL,
                 date_trunc('second', clock_timestamp()) - interval '1 day',
                 clock_timestamp() - interval '1 day'
             )",
    )
    .bind(&incomplete_null_key)
    .bind(&incomplete_null_path)
    .bind(&null_kind_hash)
    .execute(&mut connection)
    .await
    .expect("seed pre-0043 incomplete null-kind config-token row");

    let migration_sql =
        std::fs::read_to_string(&receipt_migration).expect("read receipt migration");
    sqlx::raw_sql(&migration_sql)
        .execute(&mut connection)
        .await
        .expect("apply deterministic config-token receipt migration");
    let known_not_applied_sql = std::fs::read_to_string(&known_not_applied_migration)
        .expect("read known-not-applied migration");
    sqlx::raw_sql(&known_not_applied_sql)
        .execute(&mut connection)
        .await
        .expect("apply known-not-applied migration");

    for (key, secret) in [
        (app_key.as_str(), app_secret.as_str()),
        (deployment_key.as_str(), deployment_secret.as_str()),
    ] {
        let (status, body, ledger_text): (i32, serde_json::Value, String) = sqlx::query_as(
            "SELECT response_status, response_body,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(key)
        .fetch_one(&mut connection)
        .await
        .expect("inspect migrated legacy config-token row");
        assert_eq!(status, 409);
        assert_eq!(body["error"], "idempotency_capability_expired");
        assert_eq!(body["retryable"], false);
        assert_eq!(body["disposition"], "new_key_after_expiry");
        assert_eq!(body["proof_version"], "legacy_expiring_capability_lease_v1");
        assert!(body.get("recovery_after").is_some());
        assert!(body.get("capability_expires_at").is_none());
        assert!(!ledger_text.contains(secret));
        assert!(!ledger_text.contains("legacy-secret.example.test"));
    }
    let signer_control: (i32, serde_json::Value) = sqlx::query_as(
        "SELECT response_status, response_body
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&signer_key)
    .fetch_one(&mut connection)
    .await
    .expect("inspect signer-rotation control row");
    assert_eq!(signer_control.0, 200);
    assert_eq!(signer_control.1["token"], signer_secret);

    let null_kind_terminal: (i32, serde_json::Value, Option<String>, String) = sqlx::query_as(
        "SELECT response_status, response_body, recovery_kind,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
    )
    .bind(&null_kind_key)
    .fetch_one(&mut connection)
    .await
    .expect("inspect migrated null-kind config-token row");
    assert_eq!(null_kind_terminal.0, StatusCode::CONFLICT.as_u16() as i32);
    assert_eq!(
        null_kind_terminal.1["error"],
        "idempotency_capability_expired"
    );
    assert_eq!(
        null_kind_terminal.1["proof_version"],
        "legacy_expiring_capability_lease_v1"
    );
    assert_eq!(null_kind_terminal.2, None);
    assert!(!null_kind_terminal.3.contains(&null_kind_secret));

    let replay_options = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("parse isolated config-token migration database URL")
        .options([("search_path", format!("{schema},public"))]);
    let replay_pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(replay_options)
        .await
        .expect("connect isolated config-token migration replay pool");
    let replay_state = idempotency_test_state(replay_pool.clone());
    let replay_headers = idempotency_headers(&null_kind_key);
    let binding = test_config_token_binding();
    let (replay_status, replay_body) = expect_idempotency_replay(
        begin_actor_deterministic_config_token_request(
            &replay_state,
            &replay_headers,
            &null_kind_path,
            &legacy_auth,
            &legacy_body,
            &binding,
        )
        .await
        .expect("replay migrated null-kind config-token terminal"),
    );
    assert_eq!(replay_status, StatusCode::CONFLICT);
    assert_eq!(replay_body, null_kind_terminal.1);

    let incomplete_headers = idempotency_headers(&incomplete_null_key);
    let incomplete = begin_actor_deterministic_config_token_request(
        &replay_state,
        &incomplete_headers,
        &incomplete_null_path,
        &legacy_auth,
        &legacy_body,
        &binding,
    )
    .await
    .err()
    .expect("incomplete null-kind row must not gain legacy compatibility");
    assert_eq!(incomplete.0, StatusCode::CONFLICT);
    assert_eq!(incomplete.1.0["error"], "idempotency_key_reused");
    replay_pool.close().await;

    let constraint_path = format!(
        "/internal/paas/orgs/constraint/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let missing_binding = sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $4,
                 clock_timestamp() + interval '1 minute',
                 'deterministic_expiring_capability', 1
             )",
    )
    .bind(format!("missing-binding-{}", Uuid::new_v4()))
    .bind(&constraint_path)
    .bind(vec![1_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&mut connection)
    .await
    .expect_err("deterministic receipt requires its complete binding");
    assert_eq!(
        missing_binding
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    let invalid_binding = sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count,
                 capability_receipt_version, capability_resource_id,
                 capability_instance_id
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $4,
                 clock_timestamp() + interval '1 minute',
                 'deterministic_expiring_capability', 1, 2, $5, ''
             )",
    )
    .bind(format!("invalid-binding-{}", Uuid::new_v4()))
    .bind(&constraint_path)
    .bind(vec![2_u8; 32])
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut connection)
    .await
    .expect_err("deterministic receipt rejects unknown version and empty instance");
    assert_eq!(
        invalid_binding
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    let malicious_body = sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 reservation_token, operation_id, recovery_kind, attempt_count,
                 capability_receipt_version, capability_resource_id,
                 capability_instance_id, created_at
             ) VALUES (
                 $1, 'POST', $2, $3, 409,
                 jsonb_build_object(
                     'error', 'idempotency_capability_expired',
                     'retryable', false,
                     'disposition', 'new_key_after_expiry',
                     'proof_version', 'deterministic_config_token_receipt_v1',
                     'capability_issued_at', 'eyJhbGciOiJFZERTQSJ9.bearer',
                     'capability_expires_at', 'eyJhbGciOiJFZERTQSJ9.bearer',
                     'token', 'extra-bearer-sink'
                 ),
                 clock_timestamp(), $4, $4,
                 'deterministic_expiring_capability', 1, 1, $5,
                 'safe-instance', date_trunc('second', clock_timestamp())
             )",
    )
    .bind(format!("malicious-body-{}", Uuid::new_v4()))
    .bind(&constraint_path)
    .bind(vec![3_u8; 32])
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&mut connection)
    .await
    .expect_err("terminal timestamp fields and extra keys cannot carry bearers");
    assert_eq!(
        malicious_body
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    let stale_writer_success = sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 reservation_token, operation_id, recovery_kind, attempt_count
             ) VALUES (
                 $1, 'POST', $2, $3, 200,
                 '{\"token\":\"stale-old-writer-bearer\"}'::jsonb,
                 clock_timestamp(), $4, $4, 'expiring_capability', 1
             )",
    )
    .bind(format!("stale-writer-{}", Uuid::new_v4()))
    .bind(&constraint_path)
    .bind(vec![4_u8; 32])
    .bind(Uuid::new_v4())
    .execute(&mut connection)
    .await
    .expect_err("all config-token route families reject stored 2xx responses");
    assert_eq!(
        stale_writer_success
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("23514")
    );

    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&mut connection)
        .await
        .expect("drop isolated config-token migration schema");
}

#[test]
fn deterministic_operation_identity_is_stable_and_request_bound() {
    let hash_a = Sha256::digest(b"request-a").to_vec();
    let hash_b = Sha256::digest(b"request-b").to_vec();
    let operation = idempotency_operation_id("key-a", "POST", "/internal/test", &hash_a);

    assert_eq!(
        operation,
        idempotency_operation_id("key-a", "POST", "/internal/test", &hash_a)
    );
    assert_ne!(
        operation,
        idempotency_operation_id("key-b", "POST", "/internal/test", &hash_a)
    );
    assert_ne!(
        operation,
        idempotency_operation_id("key-a", "PUT", "/internal/test", &hash_a)
    );
    assert_ne!(
        operation,
        idempotency_operation_id("key-a", "POST", "/internal/test", &hash_b)
    );
    assert_eq!(operation.get_version_num(), 8);
    assert_eq!(
        idempotency_deployment_external_id(operation),
        format!("cap-internal-idempotency-{operation}")
    );
}

#[tokio::test]
async fn abandoned_lease_reclaims_once_and_replays_the_committed_response() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("lease-reclaim-{suffix}");
    let path = format!("/internal/test/lease-reclaim/{suffix}");
    let hash = Sha256::digest(b"same-request").to_vec();

    let first = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("reserve first attempt"),
    );
    let operation_id = first.operation_id();
    let first_token = first.token;
    drop(first);
    expire_idempotency_lease(&pool, &key).await;

    let second = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("reclaim abandoned attempt"),
    );
    assert!(second.reclaimed());
    assert_eq!(second.operation_id(), operation_id);
    assert_ne!(second.token, first_token);
    let response = serde_json::json!({"result": "committed", "operation_id": operation_id});
    finish_idempotent_request(second, StatusCode::CREATED, &response)
        .await
        .expect("complete reclaimed attempt");

    let replay = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("replay reclaimed response"),
    );
    assert_eq!(replay, (StatusCode::CREATED, response));
    let attempts: i32 = sqlx::query_scalar(
        "SELECT attempt_count FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("read reclaimed attempt count");
    assert_eq!(attempts, 2);
}

#[tokio::test]
async fn idempotency_receipt_reports_what_a_same_key_retry_would_do() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("receipt-{suffix}");
    let path = format!("/internal/test/receipt/{suffix}");
    let hash = Sha256::digest(b"receipt-request").to_vec();
    let receipt = |key: &str| {
        get_paas_idempotency_receipt(
            internal_test_auth(),
            State(state.clone()),
            Query(IdempotencyReceiptQuery {
                key: key.to_string(),
            }),
        )
    };

    let Json(absent) = receipt(&key).await.expect("read absent receipt");
    assert_eq!(absent["state"], "absent");

    let first = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("reserve first attempt"),
    );
    let operation_id = first.operation_id();
    let Json(live) = receipt(&key).await.expect("read live receipt");
    assert_eq!(live["state"], "in_progress");
    assert_eq!(live["operation_id"], serde_json::json!(operation_id));
    let retry_after = live["retry_after"].as_i64().expect("live lease retry hint");
    assert!((1..=IDEMPOTENCY_DEFAULT_LEASE_SECONDS).contains(&retry_after));
    let (status, Json(body)) = begin_idempotent_request_with_recovery(
        &state,
        &key,
        "POST",
        &path,
        &hash,
        IdempotencyRecovery::RetrySafe,
    )
    .await
    .err()
    .expect("a same-key retry under a live lease is deferred");
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_request_in_progress");
    drop(first);
    expire_idempotency_lease(&pool, &key).await;

    let Json(abandoned) = receipt(&key).await.expect("read abandoned receipt");
    assert_eq!(abandoned["state"], "abandoned");
    assert_eq!(abandoned["response_status"], serde_json::Value::Null);
    assert_eq!(abandoned["retry_after"], serde_json::Value::Null);

    let reclaimed = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("reclaim abandoned attempt"),
    );
    let response = serde_json::json!({"result": "committed"});
    finish_idempotent_request(reclaimed, StatusCode::CREATED, &response)
        .await
        .expect("complete reclaimed attempt");
    let Json(completed) = receipt(&key).await.expect("read completed receipt");
    assert_eq!(completed["state"], "completed");
    assert_eq!(completed["method"], "POST");
    assert_eq!(completed["path"], path);
    assert_eq!(completed["operation_id"], serde_json::json!(operation_id));
    assert_eq!(completed["response_status"], 201);
    assert!(
        completed.get("response_body").is_none(),
        "the receipt is metadata only; the stored body stays behind the original request"
    );

    let (status, _) = receipt("  ").await.expect_err("blank key is rejected");
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn idempotency_receipt_matches_the_retry_decision_for_legacy_and_released_rows() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let hash = Sha256::digest(b"receipt-shape-request").to_vec();
    // (label, has reservation token, lease offset seconds, known_not_applied,
    // updated_at offset seconds, expected receipt state)
    let shapes = [
        ("legacy-recent", false, None, false, -60, "in_progress"),
        (
            "legacy-stale",
            false,
            None,
            false,
            -(IDEMPOTENCY_LEGACY_STALE_SECONDS + 60),
            "abandoned",
        ),
        (
            "leased-without-deadline",
            true,
            None,
            false,
            -60,
            "in_progress",
        ),
        ("released-live", true, Some(30), true, -1, "in_progress"),
        ("released-expired", true, Some(-30), true, -60, "abandoned"),
    ];
    for (label, has_token, lease_offset, known_not_applied, updated_offset, expected) in shapes {
        let suffix = Uuid::new_v4().simple().to_string();
        let key = format!("receipt-{label}-{suffix}");
        let path = format!("/internal/test/receipt-shape/{suffix}");
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash, reservation_token,
                 operation_id, lease_expires_at, recovery_kind, known_not_applied,
                 updated_at
             )
             VALUES (
                 $1, 'POST', $2, $3, $4, $5,
                 clock_timestamp() + $6 * interval '1 second',
                 CASE WHEN $4::uuid IS NULL THEN NULL ELSE 'retry_safe' END,
                 $7,
                 clock_timestamp() + $8 * interval '1 second'
             )",
        )
        .bind(&key)
        .bind(&path)
        .bind(&hash)
        .bind(has_token.then(Uuid::new_v4))
        .bind(has_token.then(Uuid::new_v4))
        .bind(lease_offset.map(|seconds| seconds as f64))
        .bind(known_not_applied)
        .bind(updated_offset as f64)
        .execute(&pool)
        .await
        .unwrap_or_else(|error| panic!("insert {label} idempotency row: {error}"));

        let Json(receipt) = get_paas_idempotency_receipt(
            internal_test_auth(),
            State(state.clone()),
            Query(IdempotencyReceiptQuery { key: key.clone() }),
        )
        .await
        .unwrap_or_else(|_| panic!("read {label} receipt"));
        assert_eq!(receipt["state"], expected, "{label} receipt state");

        let retry = begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await;
        let deferred = matches!(
            &retry,
            Err((status, Json(body)))
                if *status == StatusCode::CONFLICT
                    && body["error"] == "idempotency_request_in_progress"
        );
        assert_eq!(
            deferred,
            expected == "in_progress",
            "{label}: receipt state must predict whether a same-key retry is deferred"
        );
    }
}

#[tokio::test]
async fn live_lease_does_not_starve_a_single_connection_pool() {
    let migration_pool = database_test_pool().await;
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".to_string());
    let options = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()
        .expect("parse single-connection idempotency database URL")
        .application_name(&format!("idempotency-pool-one-{}", Uuid::new_v4()));
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("connect single-connection idempotency pool");
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("pool-one-{suffix}");
    let path = format!("/internal/test/pool-one/{suffix}");
    let hash = Sha256::digest(b"pool-one-request").to_vec();

    let lease = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "PUT", &path, &hash)
            .await
            .expect("reserve with a one-connection pool"),
    );
    let available: i32 = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        sqlx::query_scalar("SELECT 1").fetch_one(&pool),
    )
    .await
    .expect("reservation must not hold the only pool connection")
    .expect("query through the available connection");
    assert_eq!(available, 1);

    let in_progress = begin_idempotent_request(&state, &key, "PUT", &path, &hash)
        .await
        .err()
        .expect("a live exact reservation remains in progress");
    assert_eq!(in_progress.0, StatusCode::CONFLICT);
    assert_eq!(in_progress.1.0["error"], "idempotency_request_in_progress");

    let response = serde_json::json!({"status": "done"});
    finish_idempotent_request(lease, StatusCode::OK, &response)
        .await
        .expect("complete through one-connection pool");
    assert_eq!(
        expect_idempotency_replay(
            begin_idempotent_request(&state, &key, "PUT", &path, &hash)
                .await
                .expect("replay through one-connection pool")
        ),
        (StatusCode::OK, response)
    );
    drop(migration_pool);
}

#[tokio::test]
async fn stale_owner_and_pre_upgrade_completion_are_fenced_after_reclaim() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("owner-fence-{suffix}");
    let path = format!("/internal/test/owner-fence/{suffix}");
    let hash = Sha256::digest(b"owner-fence-request").to_vec();

    let first = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("reserve old owner"),
    );
    let stale_token = first.token;
    let operation_id = first.operation_id();
    drop(first);
    expire_idempotency_lease(&pool, &key).await;
    let current = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("reclaim with current owner"),
    );
    assert_ne!(current.token, stale_token);

    let blind_write = sqlx::query(
        "UPDATE cap_internal_idempotency
                SET response_status = 200,
                    response_body = '{\"owner\":\"pre-upgrade\"}'::jsonb,
                    completed_at = clock_timestamp()
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .execute(&pool)
    .await
    .expect_err("pre-upgrade key-only completion must be fenced");
    assert_eq!(
        blind_write
            .as_database_error()
            .and_then(|error| error.code().map(|code| code.into_owned()))
            .as_deref(),
        Some("42501")
    );

    let stale_lease = IdempotencyLease {
        pool: pool.clone(),
        key: key.clone(),
        token: stale_token,
        operation_id,
        reclaimed: false,
        regenerate: false,
        committed_keyring_checkpoint: false,
        config_token_receipt: None,
        heartbeat: None,
    };
    let stale_completion = finish_idempotent_request(
        stale_lease,
        StatusCode::OK,
        &serde_json::json!({"owner": "stale"}),
    )
    .await
    .expect_err("stale token cannot complete a reclaimed row");
    assert_eq!(stale_completion.0, StatusCode::INTERNAL_SERVER_ERROR);

    let response = serde_json::json!({"owner": "current"});
    finish_idempotent_request(current, StatusCode::OK, &response)
        .await
        .expect("current owner completes the row");
    assert_eq!(
        expect_idempotency_replay(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("replay current owner response")
        ),
        (StatusCode::OK, response)
    );
}

#[tokio::test]
async fn recovery_deadlines_are_decided_by_the_database_clock() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let legacy_key = format!("database-clock-legacy-{suffix}");
    let legacy_path = format!("/internal/test/database-clock-legacy/{suffix}");
    let legacy_hash = Sha256::digest(b"database-clock-legacy").to_vec();
    sqlx::query(
        "INSERT INTO cap_internal_idempotency
                 (idempotency_key, method, path, request_hash, updated_at)
             VALUES ($1, 'POST', $2, $3, clock_timestamp() + interval '1 day')",
    )
    .bind(&legacy_key)
    .bind(&legacy_path)
    .bind(&legacy_hash)
    .execute(&pool)
    .await
    .expect("seed forward-skewed legacy reservation");

    let future = begin_idempotent_request_with_recovery(
        &state,
        &legacy_key,
        "POST",
        &legacy_path,
        &legacy_hash,
        IdempotencyRecovery::RetrySafe,
    )
    .await
    .err()
    .expect("database-future row must remain live");
    assert_eq!(future.1.0["error"], "idempotency_request_in_progress");
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET updated_at = clock_timestamp() - interval '1 day'
              WHERE idempotency_key = $1",
    )
    .bind(&legacy_key)
    .execute(&pool)
    .await
    .expect("move legacy reservation behind database clock");
    let reclaimed_legacy = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &legacy_key,
            "POST",
            &legacy_path,
            &legacy_hash,
            IdempotencyRecovery::RetrySafe,
        )
        .await
        .expect("database-past legacy row is reclaimable"),
    );
    assert!(reclaimed_legacy.reclaimed());
    finish_idempotent_request(
        reclaimed_legacy,
        StatusCode::OK,
        &serde_json::json!({"legacy": "recovered"}),
    )
    .await
    .expect("complete legacy recovery");

    let capability_key = format!("database-clock-capability-{suffix}");
    let capability_path = format!("/internal/test/database-clock-capability/{suffix}");
    let capability_hash = Sha256::digest(b"database-clock-capability").to_vec();
    let capability_recovery = IdempotencyRecovery::ExpiringCapability {
        recovery_after_seconds: 360,
    };
    let capability = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &capability_key,
            "POST",
            &capability_path,
            &capability_hash,
            capability_recovery,
        )
        .await
        .expect("reserve expiring capability"),
    );
    drop(capability);
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET lease_expires_at = clock_timestamp() + interval '1 day'
              WHERE idempotency_key = $1",
    )
    .bind(&capability_key)
    .execute(&pool)
    .await
    .expect("move capability deadline ahead of database clock");
    let live_capability = begin_idempotent_request_with_recovery(
        &state,
        &capability_key,
        "POST",
        &capability_path,
        &capability_hash,
        capability_recovery,
    )
    .await
    .err()
    .expect("database-future capability remains live");
    assert_eq!(
        live_capability.1.0["error"],
        "idempotency_request_in_progress"
    );
    expire_idempotency_lease(&pool, &capability_key).await;
    let (status, body) = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(
            &state,
            &capability_key,
            "POST",
            &capability_path,
            &capability_hash,
            capability_recovery,
        )
        .await
        .expect("database-past capability is closed for reconciliation"),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "idempotency_recovery_required");
    assert_eq!(body["retryable"], false);
    assert_eq!(body["disposition"], "reconcile_then_retry_with_new_key");
}

#[tokio::test]
async fn expiring_capability_plaintext_never_enters_idempotency_ledger() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("capability-confidentiality-{suffix}");
    let path = "/internal/paas/orgs/org/apps/app/signer/rotation-token".to_string();
    let hash = Sha256::digest(format!("capability-{suffix}")).to_vec();
    let recovery = IdempotencyRecovery::ExpiringCapability {
        recovery_after_seconds: 360,
    };
    let lease = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .expect("reserve capability request"),
    );
    let secret_token = format!("jwt-secret-marker-{suffix}");
    let secret_url = format!("https://secret-{suffix}.example.test");
    let secret_ip = "192.0.2.77";
    let response = serde_json::json!({
        "token": secret_token,
        "tee_url": secret_url,
        "resolve_ip": secret_ip,
    });
    let (status, returned) =
        complete_expiring_capability_result(lease, Ok((StatusCode::OK, response.clone())))
            .await
            .expect("return capability once");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(returned, response);

    let stored: (Option<i32>, Option<serde_json::Value>, bool) = sqlx::query_as(
        "SELECT response_status, response_body, completed_at IS NOT NULL
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("read capability ledger marker");
    assert_eq!(stored, (None, None, false));

    let duplicate =
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .err()
            .expect("live capability cannot be replayed or reissued");
    assert_eq!(duplicate.1.0["error"], "idempotency_request_in_progress");

    expire_idempotency_lease(&pool, &key).await;
    let (status, tombstone) = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .expect("expired capability closes with tombstone"),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(tombstone["retryable"], false);
    let ledger_text: String = sqlx::query_scalar(
        "SELECT response_body::text FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("read capability tombstone");
    for marker in [secret_token.as_str(), secret_url.as_str(), secret_ip] {
        assert!(!ledger_text.contains(marker));
    }
}

#[tokio::test]
async fn deterministic_config_token_receipt_regenerates_exact_bearer_without_plaintext() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let deployment_id = Uuid::new_v4();
    let key = format!("deterministic-config-token-{suffix}");
    let path = format!("/internal/paas/orgs/org-{suffix}/deployments/{deployment_id}/config-token");
    let hash = Sha256::digest(format!("deterministic-config-token-{suffix}")).to_vec();
    let binding = test_config_token_binding();
    let first = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("reserve deterministic config-token receipt"),
    );
    let first_receipt = first.config_token_receipt().unwrap().clone();
    let user_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let issued = crate::auth::jwt::issue_config_token_for_issuance(
        &state.signing_key,
        user_id,
        org_id,
        binding.resource_id,
        &binding.instance_id,
        vec!["config:write".to_string()],
        &first_receipt.issuance(),
    )
    .expect("issue deterministic config bearer");
    let secret_url = format!("https://tee-{suffix}.example.test/config");
    let secret_ip = "192.0.2.77";
    let first_response = serde_json::json!({
        "token": issued.token,
        "tee_url": secret_url,
        "tee_resolve_ip": secret_ip,
        "issued_at": issued.issued_at,
        "expires_at": issued.expires_at,
        "expires_in_seconds": 299,
    });
    let first_returned = complete_deterministic_config_token_result_with_timeout(
        first,
        async { Ok((StatusCode::OK, first_response.clone())) },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect("complete non-secret issuance receipt");
    assert_eq!(first_returned, (StatusCode::OK, first_response.clone()));

    let ledger: (bool, Option<i32>, Option<serde_json::Value>, String) = sqlx::query_as(
        "SELECT completed_at IS NOT NULL, response_status, response_body,
                    to_jsonb(cap_internal_idempotency)::text
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect deterministic capability receipt");
    assert!(ledger.0);
    assert_eq!(ledger.1, None);
    assert_eq!(ledger.2, None);
    for marker in [
        first_response["token"].as_str().unwrap(),
        first_response["tee_url"].as_str().unwrap(),
        secret_ip,
    ] {
        assert!(!ledger.3.contains(marker));
    }

    let duplicate = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("regenerate completed config-token receipt"),
    );
    assert!(duplicate.regenerate);
    let duplicate_receipt = duplicate.config_token_receipt().unwrap().clone();
    assert_eq!(duplicate_receipt.issued_at, first_receipt.issued_at);
    assert_eq!(duplicate_receipt.expires_at, first_receipt.expires_at);
    let regenerated = crate::auth::jwt::issue_config_token_for_issuance(
        &state.signing_key,
        user_id,
        org_id,
        binding.resource_id,
        &binding.instance_id,
        vec!["config:write".to_string()],
        &duplicate_receipt.issuance(),
    )
    .expect("regenerate exact config bearer");
    assert_eq!(regenerated.token, first_response["token"]);
    assert_eq!(regenerated.issued_at, issued.issued_at);
    assert_eq!(regenerated.expires_at, issued.expires_at);
    let duplicate_response = serde_json::json!({
        "token": regenerated.token,
        "tee_url": first_response["tee_url"],
        "tee_resolve_ip": "192.0.2.88",
        "issued_at": regenerated.issued_at,
        "expires_at": regenerated.expires_at,
        "expires_in_seconds": 298,
    });
    let duplicate_returned = complete_deterministic_config_token_result_with_timeout(
        duplicate,
        async { Ok((StatusCode::OK, duplicate_response.clone())) },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect("return regenerated config bearer");
    assert_eq!(duplicate_returned, (StatusCode::OK, duplicate_response));
}

#[tokio::test]
async fn deterministic_config_token_errors_cancel_and_live_then_stale_lease_reclaims() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let deployment_id = Uuid::new_v4();
    let path = format!("/internal/paas/orgs/org-{suffix}/deployments/{deployment_id}/config-token");
    let hash = Sha256::digest(format!("config-token-errors-{suffix}")).to_vec();
    let binding = test_config_token_binding();
    let error_key = format!("config-token-error-{suffix}");
    let first = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &error_key, &path, &hash, &binding)
            .await
            .expect("reserve failing config-token attempt"),
    );
    let failure = complete_deterministic_config_token_result_with_timeout(
        first,
        async {
            Err(json_error(
                StatusCode::BAD_GATEWAY,
                "bounded config token failure",
            ))
        },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect_err("explicit handler failure is returned");
    assert_eq!(failure.0, StatusCode::BAD_GATEWAY);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&error_key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0, "explicit failure must release the exact key");
    let retry = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &error_key, &path, &hash, &binding)
            .await
            .expect("retry released key"),
    );
    cancel_idempotency_reservation(retry).await.unwrap();

    let stale_key = format!("config-token-stale-{suffix}");
    let live = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
            .await
            .expect("reserve live config-token attempt"),
    );
    let in_progress = begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
        .await
        .err()
        .expect("live receipt remains exclusive");
    assert_eq!(in_progress.1.0["error"], "idempotency_request_in_progress");
    let issued_at = live.config_token_receipt().unwrap().issued_at;
    drop(live);
    expire_idempotency_lease(&pool, &stale_key).await;
    let reclaimed = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &stale_key, &path, &hash, &binding)
            .await
            .expect("stale config-token lease is reclaimable"),
    );
    assert!(reclaimed.reclaimed());
    assert_eq!(
        reclaimed.config_token_receipt().unwrap().issued_at,
        issued_at
    );
    cancel_idempotency_reservation(reclaimed).await.unwrap();
}

#[tokio::test]
async fn deterministic_config_token_policy_cannot_reclaim_generic_deploy_mutation() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("generic-deploy-not-config-{suffix}");
    let path = format!("/internal/paas/orgs/org-{suffix}/deployments");
    let hash = Sha256::digest(format!("generic-deploy-not-config-{suffix}")).to_vec();
    let original = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::DeterministicResource {
                legacy_identity_bound: true,
            },
        )
        .await
        .expect("reserve generic deploy mutation"),
    );
    let original_token = original.token;
    drop(original);
    expire_idempotency_lease(&pool, &key).await;

    let rejected = begin_idempotent_request_with_recovery(
        &state,
        &key,
        "POST",
        &path,
        &hash,
        IdempotencyRecovery::DeterministicExpiringCapability,
    )
    .await
    .err()
    .expect("config-token recovery is path scoped");
    assert_eq!(rejected.0, StatusCode::INTERNAL_SERVER_ERROR);
    let unchanged: (Uuid, i32) = sqlx::query_as(
        "SELECT reservation_token, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(unchanged, (original_token, 1));
}

#[tokio::test]
async fn config_token_finalizers_enforce_safe_return_cutoff_and_terminal_authority() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let path = format!(
        "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let hash = Sha256::digest(format!("safe-return-{suffix}")).to_vec();
    let binding = test_config_token_binding();

    // Initial completion is also fenced. Even if its route future
    // succeeds, CAP must not hand a bearer across the final 30 seconds.
    let initial_key = format!("safe-return-initial-{suffix}");
    let initial = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &initial_key, &path, &hash, &binding)
            .await
            .expect("reserve initial safe-return receipt"),
    );
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '271 seconds'
              WHERE idempotency_key = $1",
    )
    .bind(&initial_key)
    .execute(&pool)
    .await
    .expect("move initial receipt inside safe-return cutoff");
    let initial_error = complete_deterministic_config_token_result_with_timeout(
        initial,
        async {
            Ok((
                StatusCode::OK,
                serde_json::json!({"token": "must-not-cross-cutoff"}),
            ))
        },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect_err("initial completion inside cutoff is deferred");
    assert_eq!(initial_error.0, StatusCode::CONFLICT);
    assert_eq!(
        initial_error.1.0["error"],
        "idempotency_request_in_progress"
    );
    let initial_stored: (bool, Option<i32>, Option<serde_json::Value>) = sqlx::query_as(
        "SELECT completed_at IS NOT NULL, response_status, response_body
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&initial_key)
    .fetch_one(&pool)
    .await
    .expect("inspect cutoff-fenced initial receipt");
    assert_eq!(initial_stored, (true, None, None));

    // A paused regeneration that crosses absolute expiry must observe the
    // concurrently committed terminal proof, never return its bearer.
    let replay_key = format!("safe-return-replay-{suffix}");
    let first = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
            .await
            .expect("reserve replay cutoff receipt"),
    );
    complete_deterministic_config_token_result_with_timeout(
        first,
        async { Ok((StatusCode::OK, serde_json::json!({"token": "first"}))) },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect("complete replay cutoff receipt");
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '299 seconds'
              WHERE idempotency_key = $1",
    )
    .bind(&replay_key)
    .execute(&pool)
    .await
    .expect("move replay receipt next to expiry");
    let replay = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
            .await
            .expect("begin near-expiry regeneration"),
    );
    let expires_at = replay.config_token_receipt().unwrap().expires_at;
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let paused = tokio::spawn(async move {
        complete_deterministic_config_token_result_with_timeout(
            replay,
            async move {
                let _ = release_rx.await;
                Ok((
                    StatusCode::OK,
                    serde_json::json!({"token": "must-not-cross-expiry"}),
                ))
            },
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(1),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if database_clock(&pool).await.expect("read DB clock") >= expires_at {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("receipt reaches DB-authored expiry");
    let terminal = expect_idempotency_replay(
        begin_test_config_token_receipt(&state, &replay_key, &path, &hash, &binding)
            .await
            .expect("terminalize expired receipt"),
    );
    assert_eq!(terminal.0, StatusCode::CONFLICT);
    assert_eq!(terminal.1["error"], "idempotency_capability_expired");
    release_tx.send(()).expect("release paused regeneration");
    let paused_result = paused
        .await
        .expect("join paused regeneration")
        .expect("terminal proof is returned as an idempotency response");
    assert_eq!(paused_result, terminal);
    assert!(paused_result.1.get("token").is_none());
}

#[tokio::test]
async fn config_token_timeout_is_bounded_and_completion_cancellation_is_cas_safe() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("bounded-cancellation-{suffix}");
    let path = format!(
        "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let hash = Sha256::digest(format!("bounded-cancellation-{suffix}")).to_vec();
    let binding = test_config_token_binding();
    let lease = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("reserve bounded cancellation receipt"),
    );
    let stale_cancellation = lease.cancellation();
    let mut blocker = pool.begin().await.expect("begin cancellation blocker");
    sqlx::query(
        "SELECT 1 FROM cap_internal_idempotency
              WHERE idempotency_key = $1 FOR UPDATE",
    )
    .bind(&key)
    .fetch_one(&mut *blocker)
    .await
    .expect("lock cancellation receipt");
    let started = std::time::Instant::now();
    let timed_out = complete_deterministic_config_token_result_with_timeout(
        lease,
        async {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            Ok((StatusCode::OK, serde_json::json!({"token": "late"})))
        },
        std::time::Duration::from_millis(20),
        std::time::Duration::from_millis(30),
    )
    .await
    .expect_err("blocked cancellation remains bounded");
    assert_eq!(timed_out.0, StatusCode::GATEWAY_TIMEOUT);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    blocker
        .rollback()
        .await
        .expect("release cancellation blocker");
    let still_incomplete: Option<bool> = sqlx::query_scalar(
        "SELECT completed_at IS NULL FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_optional(&pool)
    .await
    .expect("bounded cancellation leaves locked receipt for lease recovery");
    if still_incomplete == Some(true) {
        expire_idempotency_lease(&pool, &key).await;
    }
    let current = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("retry absent receipt or reclaim after fixed receipt lease"),
    );
    assert_eq!(current.reclaimed(), still_incomplete == Some(true));
    let mut current = current;
    assert!(matches!(
        finish_config_token_receipt(&mut current).await.unwrap(),
        ConfigTokenReceiptCompletion::Completed
    ));
    cancel_incomplete_idempotency_reservation(&stale_cancellation)
        .await
        .expect("late old cancellation must not delete current completed receipt");
    let completed: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("completed receipt survives stale cancellation");
    assert!(completed);
}

#[tokio::test]
async fn config_token_finish_error_releases_exact_reservation_for_retry() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("finish-error-{suffix}");
    let path = format!(
        "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let hash = Sha256::digest(format!("finish-error-{suffix}")).to_vec();
    let binding = test_config_token_binding();
    let lease = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("reserve finish-error receipt"),
    );
    let function_name = format!("fail_config_finish_{suffix}");
    let trigger_name = format!("fail_config_finish_trigger_{suffix}");
    let ddl = format!(
        "CREATE FUNCTION {function_name}() RETURNS trigger LANGUAGE plpgsql AS $$
             BEGIN RAISE EXCEPTION 'forced config receipt finish failure'; END $$;
             CREATE TRIGGER {trigger_name}
             BEFORE UPDATE OF completed_at ON cap_internal_idempotency
             FOR EACH ROW WHEN (OLD.idempotency_key = '{key}')
             EXECUTE FUNCTION {function_name}();"
    );
    sqlx::raw_sql(&ddl)
        .execute(&pool)
        .await
        .expect("install scoped finish failure trigger");
    let error = complete_deterministic_config_token_result_with_timeout(
        lease,
        async { Ok((StatusCode::OK, serde_json::json!({"token": "not-returned"}))) },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect_err("finish failure is returned");
    assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
    let remaining: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect failed receipt cleanup");
    assert_eq!(remaining, 0);
    let cleanup = format!(
        "DROP TRIGGER {trigger_name} ON cap_internal_idempotency;
             DROP FUNCTION {function_name}();"
    );
    sqlx::raw_sql(&cleanup)
        .execute(&pool)
        .await
        .expect("remove scoped finish failure trigger");
    let retry = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("retry key released by finish failure"),
    );
    cancel_idempotency_reservation(retry).await.unwrap();
}

#[tokio::test]
async fn config_token_binding_mismatch_rejects_same_key() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("binding-mismatch-{suffix}");
    let path = format!(
        "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let hash = Sha256::digest(format!("binding-mismatch-{suffix}")).to_vec();
    let binding = test_config_token_binding();
    let first = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("reserve bound receipt"),
    );
    complete_deterministic_config_token_result_with_timeout(
        first,
        async { Ok((StatusCode::OK, serde_json::json!({"token": "first"}))) },
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
    )
    .await
    .expect("complete bound receipt");
    let mutated = ConfigTokenResourceBinding {
        resource_id: binding.resource_id,
        instance_id: format!("{}-mutated", binding.instance_id),
    };
    let reused = begin_test_config_token_receipt(&state, &key, &path, &hash, &mutated)
        .await
        .err()
        .expect("mutated instance binding must not regenerate");
    assert_eq!(reused.0, StatusCode::CONFLICT);
    assert_eq!(reused.1.0["error"], "idempotency_key_reused");
}

#[tokio::test]
async fn app_config_token_route_replays_exactly_and_rejects_name_recreation() {
    let pool = database_test_pool().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_a = Uuid::new_v4();
    let app_b = Uuid::new_v4();
    let org_name = format!("tokenorg{}", &suffix[..8]);
    let paas_org_id = format!("paas-token-org-{suffix}");
    let paas_user_id = format!("paas-token-user-{suffix}");
    let app_name = format!("tokenapp{}", &suffix[..8]);
    insert_config_token_test_actor(
        &pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    insert_config_token_test_app(&pool, org_id, &org_name, app_a, &app_name, "a").await;
    let state = idempotency_test_state(pool.clone());
    let key = format!("app-config-route-{suffix}");
    let headers = config_token_actor_headers(&key, &paas_user_id);
    let call = |state: AppState, headers: HeaderMap| {
        issue_paas_config_token(
            internal_test_auth(),
            State(state),
            Path((paas_org_id.clone(), app_name.clone())),
            headers,
            Json(serde_json::json!({})),
        )
    };
    let (first_status, Json(first)) = call(state.clone(), headers.clone())
        .await
        .expect("issue first app config token");
    assert_eq!(first_status, StatusCode::OK);
    let (duplicate_status, Json(duplicate)) = call(state.clone(), headers.clone())
        .await
        .expect("regenerate exact app config token");
    assert_eq!(duplicate_status, StatusCode::OK);
    assert_eq!(duplicate["token"], first["token"]);
    assert_eq!(duplicate["issued_at"], first["issued_at"]);
    assert_eq!(duplicate["expires_at"], first["expires_at"]);
    let issued_at = chrono::DateTime::parse_from_rfc3339(
        first["issued_at"].as_str().expect("issued_at string"),
    )
    .unwrap();
    let expires_at = chrono::DateTime::parse_from_rfc3339(
        first["expires_at"].as_str().expect("expires_at string"),
    )
    .unwrap();
    assert_eq!((expires_at - issued_at).num_seconds(), 300);

    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app_a)
        .execute(&pool)
        .await
        .expect("delete original app identity");

    let missing = call(
        state.clone(),
        config_token_actor_headers(&format!("app-config-missing-{suffix}"), &paas_user_id),
    )
    .await
    .expect_err("a new key still observes the missing app");
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(missing.1.0["error"], "app not found");

    let live_receipt = call(state.clone(), headers.clone())
        .await
        .expect_err("a deleted app cannot regenerate a live receipt");
    assert_eq!(live_receipt.0, StatusCode::CONFLICT);
    assert_eq!(live_receipt.1.0["error"], "idempotency_request_in_progress");

    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '301 seconds'
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .execute(&pool)
    .await
    .expect("expire deleted-app config-token receipt");
    let (expired_status, Json(expired)) = call(state.clone(), headers.clone())
        .await
        .expect("terminalize deleted-app config-token receipt");
    assert_eq!(expired_status, StatusCode::CONFLICT);
    assert_eq!(expired["error"], "idempotency_capability_expired");
    assert_eq!(expired["retryable"], false);
    assert_eq!(expired["disposition"], "new_key_after_expiry");
    assert_eq!(
        expired["proof_version"],
        "deterministic_config_token_receipt_v1"
    );
    assert!(expired.get("capability_issued_at").is_some());
    assert!(expired.get("capability_expires_at").is_some());
    assert!(expired.get("token").is_none());

    let legacy_hash = request_hash(&serde_json::json!({
        "cap_user_id": user_id,
        "cap_org_id": org_id,
        "body": serde_json::json!({}),
    }))
    .expect("hash deleted-app legacy request");
    let legacy_created_at: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT date_trunc('second', clock_timestamp()) - interval '7 minutes'")
            .fetch_one(&pool)
            .await
            .expect("select deleted-app legacy receipt time");
    let legacy_proof = expired_config_token_body(
        legacy_created_at,
        legacy_created_at + chrono::Duration::minutes(6),
        true,
    );
    for (legacy_variant, recovery_kind) in
        [("null", None), ("expiring", Some("expiring_capability"))]
    {
        let legacy_key = format!("legacy-deleted-app-{legacy_variant}-{suffix}");
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                     idempotency_key, method, path, request_hash,
                     response_status, response_body, completed_at,
                     recovery_kind, created_at, updated_at
                 ) VALUES (
                     $1, 'POST', $2, $3, 409, $4, clock_timestamp(),
                     $5, $6, clock_timestamp()
                 )",
        )
        .bind(&legacy_key)
        .bind(format!(
            "/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token"
        ))
        .bind(&legacy_hash)
        .bind(&legacy_proof)
        .bind(recovery_kind)
        .bind(legacy_created_at)
        .execute(&pool)
        .await
        .expect("seed migrated legacy receipt for deleted app");
        let (legacy_status, Json(legacy_replay)) = call(
            state.clone(),
            config_token_actor_headers(&legacy_key, &paas_user_id),
        )
        .await
        .expect("replay safe migrated legacy terminal after app deletion");
        assert_eq!(legacy_status, StatusCode::CONFLICT);
        assert_eq!(legacy_replay, legacy_proof);
    }

    insert_config_token_test_app(&pool, org_id, &org_name, app_b, &app_name, "b").await;
    let (recreated_status, Json(recreated)) = call(state, headers)
        .await
        .expect("an expired receipt replays its terminal proof after name recreation");
    assert_eq!(recreated_status, StatusCode::CONFLICT);
    assert_eq!(recreated, expired);
    let ledger: (Uuid, String, Option<i32>, Option<serde_json::Value>, String) = sqlx::query_as(
        "SELECT capability_resource_id, capability_instance_id,
                        response_status, response_body,
                        to_jsonb(cap_internal_idempotency)::text
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect app config-token receipt");
    assert_eq!(ledger.0, app_a);
    assert!(ledger.1.ends_with(&format!("-{app_name}")));
    assert_eq!(ledger.2, Some(StatusCode::CONFLICT.as_u16() as i32));
    assert_eq!(ledger.3, Some(expired));
    assert!(!ledger.4.contains(first["token"].as_str().unwrap()));
}

#[tokio::test]
async fn generic_deployment_config_token_route_replays_and_rejects_app_rebind() {
    let pool = database_test_pool().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_a = Uuid::new_v4();
    let app_b = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let org_name = format!("genericorg{}", &suffix[..8]);
    let paas_org_id = format!("paas-generic-org-{suffix}");
    let paas_user_id = format!("paas-generic-user-{suffix}");
    let app_name_a = format!("genericapp{}", &suffix[..8]);
    let app_name_b = format!("reboundapp{}", &suffix[..8]);
    insert_config_token_test_actor(
        &pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    insert_config_token_test_app(&pool, org_id, &org_name, app_a, &app_name_a, "a").await;
    sqlx::query(
        "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(app_a)
    .execute(&pool)
    .await
    .expect("insert generic config-token deployment");
    let state = idempotency_test_state(pool.clone());
    let key = format!("generic-config-route-{suffix}");
    let headers = config_token_actor_headers(&key, &paas_user_id);
    let call = |state: AppState, headers: HeaderMap| {
        issue_paas_generic_config_token(
            internal_test_auth(),
            State(state),
            Path((paas_org_id.clone(), deployment_id)),
            headers,
            Json(serde_json::json!({})),
        )
    };
    let (first_status, Json(first)) = call(state.clone(), headers.clone())
        .await
        .expect("issue first generic config token");
    let (duplicate_status, Json(duplicate)) = call(state.clone(), headers.clone())
        .await
        .expect("regenerate exact generic config token");
    assert_eq!(first_status, StatusCode::OK);
    assert_eq!(duplicate_status, StatusCode::OK);
    assert_eq!(first["deployment_id"], deployment_id.to_string());
    assert_eq!(duplicate["token"], first["token"]);
    assert_eq!(duplicate["issued_at"], first["issued_at"]);
    assert_eq!(duplicate["expires_at"], first["expires_at"]);
    // PaaS attests only TEEs launched under one of these identities. This
    // fixture admits no workload, so there is nothing to attest against.
    assert_eq!(first["launch_identities"], serde_json::json!([]));
    assert_eq!(duplicate["launch_identities"], first["launch_identities"]);

    insert_config_token_test_app(&pool, org_id, &org_name, app_b, &app_name_b, "b").await;
    sqlx::query("DELETE FROM deployments WHERE id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("remove deployment before identity rebind");

    let missing = call(
        state.clone(),
        config_token_actor_headers(&format!("generic-config-missing-{suffix}"), &paas_user_id),
    )
    .await
    .expect_err("a new key still observes the missing deployment");
    assert_eq!(missing.0, StatusCode::NOT_FOUND);
    assert_eq!(missing.1.0["error"], "deployment not found");

    let live_receipt = call(state.clone(), headers.clone())
        .await
        .expect_err("a deleted deployment cannot regenerate a live receipt");
    assert_eq!(live_receipt.0, StatusCode::CONFLICT);
    assert_eq!(live_receipt.1.0["error"], "idempotency_request_in_progress");

    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '301 seconds'
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .execute(&pool)
    .await
    .expect("expire deleted-deployment config-token receipt");
    let (expired_status, Json(expired)) = call(state.clone(), headers.clone())
        .await
        .expect("terminalize deleted-deployment config-token receipt");
    assert_eq!(expired_status, StatusCode::CONFLICT);
    assert_eq!(expired["error"], "idempotency_capability_expired");
    assert_eq!(expired["retryable"], false);
    assert_eq!(expired["disposition"], "new_key_after_expiry");
    assert_eq!(
        expired["proof_version"],
        "deterministic_config_token_receipt_v1"
    );
    assert!(expired.get("capability_issued_at").is_some());
    assert!(expired.get("capability_expires_at").is_some());
    assert!(expired.get("token").is_none());

    sqlx::query(
        "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(app_b)
    .execute(&pool)
    .await
    .expect("recreate deployment ID against a different app identity");
    let (rebound_status, Json(rebound)) = call(state, headers)
        .await
        .expect("an expired receipt replays its terminal proof after app rebind");
    assert_eq!(rebound_status, StatusCode::CONFLICT);
    assert_eq!(rebound, expired);
    let ledger: (Option<i32>, Option<serde_json::Value>, String) = sqlx::query_as(
        "SELECT response_status, response_body,
                    to_jsonb(cap_internal_idempotency)::text
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect generic config-token receipt");
    assert_eq!(ledger.0, Some(StatusCode::CONFLICT.as_u16() as i32));
    assert_eq!(ledger.1, Some(expired));
    assert!(!ledger.2.contains(first["token"].as_str().unwrap()));
}

#[tokio::test]
async fn deleted_and_rebound_config_token_routes_do_not_extend_or_mask_expiry() {
    let pool = database_test_pool().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_original = Uuid::new_v4();
    let app_recreated = Uuid::new_v4();
    let deployment_app_original = Uuid::new_v4();
    let deployment_app_rebound = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let org_name = format!("recoveryorg{}", &suffix[..8]);
    let paas_org_id = format!("paas-recovery-org-{suffix}");
    let paas_user_id = format!("paas-recovery-user-{suffix}");
    let app_name = format!("recoveryapp{}", &suffix[..8]);
    let deployment_app_name = format!("deployapp{}", &suffix[..8]);
    let rebound_app_name = format!("reboundapp{}", &suffix[..8]);
    insert_config_token_test_actor(
        &pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    insert_config_token_test_app(
        &pool,
        org_id,
        &org_name,
        app_original,
        &app_name,
        "original",
    )
    .await;
    insert_config_token_test_app(
        &pool,
        org_id,
        &org_name,
        deployment_app_original,
        &deployment_app_name,
        "deploy-original",
    )
    .await;
    insert_config_token_test_app(
        &pool,
        org_id,
        &org_name,
        deployment_app_rebound,
        &rebound_app_name,
        "deploy-rebound",
    )
    .await;
    sqlx::query(
        "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(deployment_app_original)
    .execute(&pool)
    .await
    .expect("insert recovery-test deployment");

    let state = idempotency_test_state(pool.clone());
    let auth = AuthContext {
        user_id,
        org_id,
        org_name: org_name.clone(),
        role: Role::Owner,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    };
    let body = serde_json::json!({});
    let app_path = format!("/internal/paas/orgs/{paas_org_id}/apps/{app_name}/config-token");
    let deployment_path =
        format!("/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/config-token");
    let app_key = format!("deleted-incomplete-app-{suffix}");
    let deployment_key = format!("deleted-incomplete-deployment-{suffix}");
    let app_headers = config_token_actor_headers(&app_key, &paas_user_id);
    let deployment_headers = config_token_actor_headers(&deployment_key, &paas_user_id);
    let app_binding = app_config_token_resource_binding(&state, org_id, &app_name)
        .await
        .expect("resolve original app binding");
    let deployment_binding =
        deployment_config_token_resource_binding(&state, org_id, deployment_id)
            .await
            .expect("resolve original deployment binding");
    let app_lease = expect_idempotency_execution(
        begin_actor_deterministic_config_token_request(
            &state,
            &app_headers,
            &app_path,
            &auth,
            &body,
            &app_binding,
        )
        .await
        .expect("reserve incomplete app receipt"),
    );
    let deployment_lease = expect_idempotency_execution(
        begin_actor_deterministic_config_token_request(
            &state,
            &deployment_headers,
            &deployment_path,
            &auth,
            &body,
            &deployment_binding,
        )
        .await
        .expect("reserve incomplete deployment receipt"),
    );
    drop(app_lease);
    drop(deployment_lease);

    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app_original)
        .execute(&pool)
        .await
        .expect("delete app while its receipt is incomplete");
    sqlx::query("DELETE FROM deployments WHERE id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("delete deployment while its receipt is incomplete");
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET lease_expires_at = clock_timestamp() - interval '1 minute',
                    updated_at = clock_timestamp() - interval '1 minute'
              WHERE idempotency_key = ANY($1)",
    )
    .bind(vec![app_key.clone(), deployment_key.clone()])
    .execute(&pool)
    .await
    .expect("expire both deleted-resource receipt leases");
    let before: Vec<(String, Option<chrono::DateTime<chrono::Utc>>, i32)> = sqlx::query_as(
        "SELECT idempotency_key, lease_expires_at, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = ANY($1)
              ORDER BY idempotency_key",
    )
    .bind(vec![app_key.clone(), deployment_key.clone()])
    .fetch_all(&pool)
    .await
    .expect("inspect receipt leases before deleted-resource retry");

    let app_missing = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), app_name.clone())),
        app_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect_err("deleted app receipt remains unavailable before absolute expiry");
    assert_eq!(app_missing.0, StatusCode::CONFLICT);
    assert_eq!(app_missing.1.0["error"], "idempotency_request_in_progress");
    let deployment_missing = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), deployment_id)),
        deployment_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect_err("deleted deployment receipt remains unavailable before absolute expiry");
    assert_eq!(deployment_missing.0, StatusCode::CONFLICT);
    assert_eq!(
        deployment_missing.1.0["error"],
        "idempotency_request_in_progress"
    );
    let after: Vec<(String, Option<chrono::DateTime<chrono::Utc>>, i32)> = sqlx::query_as(
        "SELECT idempotency_key, lease_expires_at, attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = ANY($1)
              ORDER BY idempotency_key",
    )
    .bind(vec![app_key.clone(), deployment_key.clone()])
    .fetch_all(&pool)
    .await
    .expect("inspect receipt leases after deleted-resource retry");
    assert_eq!(
        after, before,
        "deleted retries must not renew receipt leases"
    );

    insert_config_token_test_app(
        &pool,
        org_id,
        &org_name,
        app_recreated,
        &app_name,
        "recreated",
    )
    .await;
    sqlx::query(
        "INSERT INTO deployments
                 (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'healthy', '{}'::jsonb)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(deployment_app_rebound)
    .execute(&pool)
    .await
    .expect("rebind deployment before receipt expiry");
    let app_rebound = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), app_name.clone())),
        app_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect_err("recreated app binding cannot use an unexpired old receipt");
    assert_eq!(app_rebound.1.0["error"], "idempotency_key_reused");
    let deployment_rebound = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), deployment_id)),
        deployment_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect_err("rebound deployment cannot use an unexpired old receipt");
    assert_eq!(deployment_rebound.1.0["error"], "idempotency_key_reused");

    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET created_at = date_trunc('second', clock_timestamp()) - interval '301 seconds',
                    lease_expires_at = clock_timestamp() + interval '10 minutes'
              WHERE idempotency_key = ANY($1)",
    )
    .bind(vec![app_key.clone(), deployment_key.clone()])
    .execute(&pool)
    .await
    .expect("expire receipts while leaving their stale leases in the future");
    let (app_status, Json(app_terminal)) = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), app_name.clone())),
        app_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect("absolute expiry terminalizes before recreated binding mismatch");
    let (deployment_status, Json(deployment_terminal)) = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), deployment_id)),
        deployment_headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect("absolute expiry terminalizes before deployment binding mismatch");
    for (status, terminal) in [
        (app_status, &app_terminal),
        (deployment_status, &deployment_terminal),
    ] {
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(terminal["error"], "idempotency_capability_expired");
        assert_eq!(
            terminal["proof_version"],
            "deterministic_config_token_receipt_v1"
        );
        assert!(terminal.get("token").is_none());
    }
    let (_, Json(app_replay)) = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), app_name)),
        app_headers,
        Json(body.clone()),
    )
    .await
    .expect("recreated app replays terminal proof");
    let (_, Json(deployment_replay)) = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state),
        Path((paas_org_id, deployment_id)),
        deployment_headers,
        Json(body),
    )
    .await
    .expect("rebound deployment replays terminal proof");
    assert_eq!(app_replay, app_terminal);
    assert_eq!(deployment_replay, deployment_terminal);
    let terminal_leases: Vec<Option<chrono::DateTime<chrono::Utc>>> = sqlx::query_scalar(
        "SELECT lease_expires_at
               FROM cap_internal_idempotency
              WHERE idempotency_key = ANY($1)
              ORDER BY idempotency_key",
    )
    .bind(vec![app_key, deployment_key])
    .fetch_all(&pool)
    .await
    .expect("inspect deterministic terminal leases");
    assert_eq!(terminal_leases, vec![None, None]);
}

#[tokio::test]
async fn deleted_legacy_config_token_routes_preserve_extended_terminal_proof() {
    let pool = database_test_pool().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let org_name = format!("legacydelete{}", &suffix[..8]);
    let paas_org_id = format!("paas-legacy-delete-org-{suffix}");
    let paas_user_id = format!("paas-legacy-delete-user-{suffix}");
    let missing_app_name = format!("missingapp{}", &suffix[..8]);
    insert_config_token_test_actor(
        &pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    let state = idempotency_test_state(pool.clone());
    let body = serde_json::json!({});
    let auth = AuthContext {
        user_id,
        org_id,
        org_name,
        role: Role::Owner,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    };
    let legacy_hash = legacy_config_token_request_hash(&auth, &body)
        .expect("hash deleted-resource legacy request");
    let app_key = format!("deleted-legacy-app-{suffix}");
    let deployment_key = format!("deleted-legacy-deployment-{suffix}");
    let app_path =
        format!("/internal/paas/orgs/{paas_org_id}/apps/{missing_app_name}/config-token");
    let deployment_path =
        format!("/internal/paas/orgs/{paas_org_id}/deployments/{deployment_id}/config-token");
    for (key, path) in [
        (app_key.as_str(), app_path.as_str()),
        (deployment_key.as_str(), deployment_path.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO cap_internal_idempotency (
                     idempotency_key, method, path, request_hash,
                     reservation_token, operation_id, lease_expires_at,
                     recovery_kind, attempt_count, created_at, updated_at
                 ) VALUES (
                     $1, 'POST', $2, $3, $4, $5,
                     date_trunc('second', clock_timestamp()) - interval '1 minute',
                     'expiring_capability', 1,
                     date_trunc('second', clock_timestamp()) - interval '10 minutes',
                     clock_timestamp() - interval '1 minute'
                 )",
        )
        .bind(key)
        .bind(path)
        .bind(&legacy_hash)
        .bind(Uuid::new_v4())
        .bind(idempotency_operation_id(key, "POST", path, &legacy_hash))
        .execute(&pool)
        .await
        .expect("seed deleted-resource legacy lease with extended deadline");
    }

    let (app_status, Json(app_terminal)) = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), missing_app_name.clone())),
        config_token_actor_headers(&app_key, &paas_user_id),
        Json(body.clone()),
    )
    .await
    .expect("deleted app legacy lease reaches terminal proof");
    let (deployment_status, Json(deployment_terminal)) = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), deployment_id)),
        config_token_actor_headers(&deployment_key, &paas_user_id),
        Json(body.clone()),
    )
    .await
    .expect("deleted deployment legacy lease reaches terminal proof");
    for (status, terminal) in [
        (app_status, &app_terminal),
        (deployment_status, &deployment_terminal),
    ] {
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(terminal["error"], "idempotency_capability_expired");
        assert_eq!(
            terminal["proof_version"],
            "legacy_expiring_capability_lease_v1"
        );
        assert!(terminal.get("recovery_after").is_some());
        assert!(terminal.get("token").is_none());
    }

    for (key, expected) in [
        (app_key.as_str(), &app_terminal),
        (deployment_key.as_str(), &deployment_terminal),
    ] {
        let row: IdempotencyRow = sqlx::query_as(
            "SELECT method, path, request_hash, response_status, response_body,
                        reservation_token, operation_id, lease_expires_at,
                        recovery_kind, capability_receipt_version,
                        capability_resource_id, capability_instance_id,
                        known_not_applied,
                        completed_at, created_at, updated_at,
                        clock_timestamp() AS database_now
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .expect("inspect terminal legacy proof row");
        assert!(row.lease_expires_at.is_some());
        assert!(is_safe_migrated_legacy_config_token_terminal(&row));
        assert_eq!(row.response_body.as_ref(), Some(expected));
    }

    let (_, Json(app_replay)) = issue_paas_config_token(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), missing_app_name)),
        config_token_actor_headers(&app_key, &paas_user_id),
        Json(body.clone()),
    )
    .await
    .expect("deleted app replays the preserved legacy proof");
    let (_, Json(deployment_replay)) = issue_paas_generic_config_token(
        internal_test_auth(),
        State(state),
        Path((paas_org_id, deployment_id)),
        config_token_actor_headers(&deployment_key, &paas_user_id),
        Json(body),
    )
    .await
    .expect("deleted deployment replays the preserved legacy proof");
    assert_eq!(app_replay, app_terminal);
    assert_eq!(deployment_replay, deployment_terminal);
}

#[tokio::test]
async fn legacy_completed_config_token_sanitizer_preserves_extended_lease_proof() {
    let pool = database_test_pool().await;
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("legacy-sanitizer-{suffix}");
    let path = format!("/internal/test/legacy-sanitizer/{suffix}");
    let hash = Sha256::digest(format!("legacy-sanitizer-{suffix}")).to_vec();
    let token = Uuid::new_v4();
    let operation_id = idempotency_operation_id(&key, "POST", &path, &hash);
    let secret = format!("legacy-sanitizer-secret-{suffix}");
    let (issued_at, recovery_after): (
        chrono::DateTime<chrono::Utc>,
        chrono::DateTime<chrono::Utc>,
    ) = sqlx::query_as(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 response_status, response_body, completed_at,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, 200,
                 jsonb_build_object('token', $4::text), clock_timestamp(),
                 $5, $6,
                 date_trunc('second', clock_timestamp()) - interval '1 minute',
                 'expiring_capability', 1,
                 date_trunc('second', clock_timestamp()) - interval '10 minutes',
                 clock_timestamp()
             )
             RETURNING date_trunc('second', created_at), lease_expires_at",
    )
    .bind(&key)
    .bind(&path)
    .bind(&hash)
    .bind(&secret)
    .bind(token)
    .bind(operation_id)
    .fetch_one(&pool)
    .await
    .expect("seed completed legacy response with an extended lease");
    let (status, proof) = expect_idempotency_replay(
        sanitize_legacy_completed_config_token_response(
            &pool,
            &key,
            Some(token),
            operation_id,
            issued_at,
            recovery_after,
        )
        .await
        .expect("sanitize completed legacy response"),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    let proof_recovery_after = chrono::DateTime::parse_from_rfc3339(
        proof["recovery_after"]
            .as_str()
            .expect("legacy proof recovery timestamp"),
    )
    .expect("parse legacy proof recovery timestamp")
    .with_timezone(&chrono::Utc);
    assert_eq!(proof_recovery_after, recovery_after);

    let row: IdempotencyRow = sqlx::query_as(
        "SELECT method, path, request_hash, response_status, response_body,
                    reservation_token, operation_id, lease_expires_at,
                    recovery_kind, capability_receipt_version,
                    capability_resource_id, capability_instance_id,
                    known_not_applied,
                    completed_at, created_at, updated_at,
                    clock_timestamp() AS database_now
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect sanitized legacy response");
    assert_eq!(row.lease_expires_at, Some(recovery_after));
    assert!(is_safe_migrated_legacy_config_token_terminal(&row));
    let ledger_text = serde_json::to_string(&row.response_body).unwrap();
    assert!(!ledger_text.contains(&secret));
}

#[tokio::test]
async fn legacy_config_token_receipt_uses_conservative_lease_proof() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("legacy-config-receipt-{suffix}");
    let path = format!(
        "/internal/paas/orgs/org-{suffix}/deployments/{}/config-token",
        Uuid::new_v4()
    );
    let auth = AuthContext {
        user_id: Uuid::new_v4(),
        org_id: Uuid::new_v4(),
        org_name: format!("org-{suffix}"),
        role: Role::Owner,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    };
    let body = serde_json::json!({});
    let legacy_hash = request_hash(&serde_json::json!({
        "cap_user_id": auth.user_id,
        "cap_org_id": auth.org_id,
        "body": body,
    }))
    .unwrap();
    let operation_id = idempotency_operation_id(&key, "POST", &path, &legacy_hash);
    let token = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO cap_internal_idempotency (
                 idempotency_key, method, path, request_hash,
                 reservation_token, operation_id, lease_expires_at,
                 recovery_kind, attempt_count, created_at, updated_at
             ) VALUES (
                 $1, 'POST', $2, $3, $4, $5,
                 date_trunc('second', clock_timestamp()) - interval '1 minute',
                 'expiring_capability', 1,
                 date_trunc('second', clock_timestamp()) - interval '7 minutes',
                 clock_timestamp() - interval '1 minute'
             )",
    )
    .bind(&key)
    .bind(&path)
    .bind(&legacy_hash)
    .bind(token)
    .bind(operation_id)
    .execute(&pool)
    .await
    .expect("seed legacy config-token lease");
    let binding = test_config_token_binding();
    let headers = idempotency_headers(&key);
    let (status, proof) = expect_idempotency_replay(
        begin_actor_deterministic_config_token_request(
            &state, &headers, &path, &auth, &body, &binding,
        )
        .await
        .expect("terminalize legacy config-token lease"),
    );
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(proof["error"], "idempotency_capability_expired");
    assert_eq!(proof["retryable"], false);
    assert_eq!(proof["disposition"], "new_key_after_expiry");
    assert_eq!(
        proof["proof_version"],
        "legacy_expiring_capability_lease_v1"
    );
    assert!(proof.get("recovery_after").is_some());
    assert!(proof.get("capability_expires_at").is_none());
    assert!(proof.get("token").is_none());
}

#[tokio::test]
async fn ordinary_handler_error_is_completed_and_replayed_without_side_effect_retry() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("error-replay-{suffix}");
    let path = format!("/internal/test/error-replay/{suffix}");
    let hash = Sha256::digest(b"error-replay-request").to_vec();
    let side_effects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let lease = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("reserve failing handler"),
    );
    let attempt_side_effects = side_effects.clone();
    let result: Result<IdempotencyResponse, InternalRouteError> = async move {
        attempt_side_effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bounded_handler_failure",
        ))
    }
    .await;
    let failure = complete_idempotent_result(lease, result)
        .await
        .expect_err("first handler returns its completed error");
    assert_eq!(failure.0, StatusCode::UNPROCESSABLE_ENTITY);

    let (status, body) = expect_idempotency_replay(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("exact retry replays the completed error"),
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "bounded_handler_failure");
    assert_eq!(
        side_effects.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "replay must not invoke the handler side effect again"
    );
    let completed: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect completed handler error");
    assert!(completed);
}

#[tokio::test]
async fn completed_error_is_stamped_in_returned_and_cached_body() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("completed-stamp-{suffix}");
    let path = format!("/internal/test/completed-stamp/{suffix}");
    let hash = Sha256::digest(b"completed-stamp-request").to_vec();

    let lease = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("reserve stamped handler error"),
    );
    let result: Result<IdempotencyResponse, InternalRouteError> = async {
        Err(json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "bounded_handler_failure",
        ))
    }
    .await;
    let failure = complete_idempotent_result(lease, result)
        .await
        .expect_err("completed error is returned as Err");
    // The returned body carries the explicit completion stamp.
    assert_eq!(failure.0, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(failure.1["error"], "bounded_handler_failure");
    assert_eq!(failure.1["idempotency_disposition"], "completed");
    assert_eq!(failure.1["retryable"], false);

    // The cached (replayed) body carries the same stamp.
    let (status, body) = expect_idempotency_replay(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("replay stamped completed error"),
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["error"], "bounded_handler_failure");
    assert_eq!(body["idempotency_disposition"], "completed");
    assert_eq!(body["retryable"], false);
}

#[tokio::test]
async fn deferred_response_is_stamped_and_leaves_row_incomplete() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("deferred-stamp-{suffix}");
    let path = format!("/internal/test/deferred-stamp/{suffix}");
    let hash = Sha256::digest(b"deferred-stamp-request").to_vec();

    let lease = expect_idempotency_execution(
        begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("reserve deferred handler"),
    );
    let deferred = defer_idempotent_request(lease, None).await;
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(deferred.1["idempotency_disposition"], "deferred");
    assert_eq!(deferred.1["retryable"], true);
    assert_eq!(deferred.1["disposition"], "retry_same_key");

    // Deferral leaves the row incomplete so a same-key retry can re-acquire.
    let completed: bool = sqlx::query_scalar(
        "SELECT completed_at IS NOT NULL
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect deferred row");
    assert!(!completed);
}

#[tokio::test]
async fn known_not_applied_retry_preserves_original_key_binding() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("known-not-applied-binding-{suffix}");
    let path = format!("/internal/test/known-not-applied-binding/{suffix}");
    let original_hash = Sha256::digest(b"original-request").to_vec();
    let different_hash = Sha256::digest(b"different-request").to_vec();

    let lease = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &original_hash,
            IdempotencyRecovery::FailClosed,
        )
        .await
        .expect("reserve original request"),
    );
    let known_not_applied: Result<IdempotencyResponse, InternalRouteError> = Err((
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "app mutation already in progress"})),
    ));
    let deferred = complete_idempotent_result(lease, known_not_applied)
        .await
        .expect_err("known-not-applied conflict asks for a same-key retry");
    assert_eq!(deferred.1["idempotency_disposition"], "deferred");

    let rebound = begin_idempotent_request_with_recovery(
        &state,
        &key,
        "POST",
        &path,
        &different_hash,
        IdempotencyRecovery::FailClosed,
    )
    .await
    .err()
    .expect("a released key remains bound to its original request");
    assert_eq!(rebound.1.0["error"], "idempotency_key_reused");

    match begin_idempotent_request_with_recovery(
        &state,
        &key,
        "POST",
        &path,
        &original_hash,
        IdempotencyRecovery::FailClosed,
    )
    .await
    .expect("the exact original request can re-acquire immediately")
    {
        IdempotencyBegin::Execute(_) => {}
        IdempotencyBegin::Replay((status, body)) => {
            panic!("known-not-applied retry must execute, not replay {status}: {body}");
        }
    }
}

#[tokio::test]
async fn replayed_hold_refresh_distinguishes_terminal_and_released_holds() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();

    // A held apply job in setup_pending with a live deadline.
    let org_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let mut tx = pool.begin().await.expect("begin replay fixture");
    sqlx::query(
        "INSERT INTO organizations (id, name, cust_slug)
             VALUES ($1, $2, $3)",
    )
    .bind(org_id)
    .bind(format!("replay-hold-{suffix}"))
    .bind(&suffix[..8])
    .execute(&mut *tx)
    .await
    .expect("insert replay org");
    sqlx::query(
        "INSERT INTO apps (
                id, org_id, name, namespace, instance_id, tenant_id,
                service_account, bootstrap_owner_pubkey_hash,
                tenant_instance_identity_hash, domain, tee_domain
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(format!("app-{suffix}"))
    .bind(format!("cap-app-{suffix}"))
    .bind(format!("instance-{suffix}"))
    .bind(&suffix[..8])
    .bind(format!("cap-app-{suffix}-sa"))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("app-{suffix}.{}.enclava.dev", &suffix[..8]))
    .bind(format!("app-{suffix}.{}.tee.enclava.dev", &suffix[..8]))
    .execute(&mut *tx)
    .await
    .expect("insert replay app");
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 artifact_deployment_id, artifact_descriptor_core_hash,
                 log_encryption, state, next_attempt_at,
                 customer_config_hold, customer_config_hold_until
             ) VALUES (
                 $1, $2, $3, $1, 1,
                 '{\"version\":1,\"log_encryption\":null}'::jsonb,
                 $4, false, false, NULL, NULL, NULL, 'setup_pending',
                 'infinity'::timestamptz, true,
                 clock_timestamp() + interval '1 hour'
             )",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(org_id)
    .bind(vec![7_u8; 32])
    .execute(&mut *tx)
    .await
    .expect("insert held apply job");
    sqlx::query(
        "INSERT INTO deployments (id, org_id, app_id, trigger, status, spec_snapshot)
             VALUES ($1, $2, $3, 'api', 'pending', '{}'::jsonb)",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(app_id)
    .execute(&mut *tx)
    .await
    .expect("insert pending deployment");
    tx.commit().await.expect("commit replay fixture");

    let cached = serde_json::json!({
        "deployment_id": deployment_id.to_string(),
        "app_name": format!("app-{suffix}"),
        "customer_config_hold": true,
        "customer_config_hold_until": "2020-01-01T00:00:00Z",
        "customer_config_hold_remaining_ms": 3_600_000_i64,
    });

    // Open hold: refreshed expiry and a fresh database-clock remainder.
    let (status, body) =
        refresh_replayed_hold_remainder(&state, StatusCode::CREATED, cached.clone())
            .await
            .expect("refresh an open hold");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["customer_config_hold"], true);
    let refreshed_until = body["customer_config_hold_until"].as_str().expect("until");
    assert_ne!(
        refreshed_until, "2020-01-01T00:00:00Z",
        "the stored expiry must replace the cached one"
    );
    let refreshed_ms = body["customer_config_hold_remaining_ms"]
        .as_i64()
        .expect("remaining");
    assert!(
        refreshed_ms > 0 && refreshed_ms <= 3_600_000,
        "a fresh database-clock remainder must be quoted, got {refreshed_ms}"
    );

    // Released: the hold flag drops and no deadline fields remain.
    sqlx::query(
        "UPDATE deployment_apply_jobs
                SET customer_config_released_at = clock_timestamp()
              WHERE deployment_id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("release the hold");
    let (status, body) =
        refresh_replayed_hold_remainder(&state, StatusCode::CREATED, cached.clone())
            .await
            .expect("refresh a released hold");
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["customer_config_hold"], false);
    assert_eq!(body["customer_config_hold_until"], serde_json::Value::Null);
    assert_eq!(
        body["customer_config_hold_remaining_ms"],
        serde_json::Value::Null
    );

    // Terminally ended without a release: the cached success body must
    // be replaced with a terminal failure, never replayed as an
    // ordinary unheld deploy. The deployment terminalizes first: the
    // schema's deferred job-preservation trigger refuses a nonterminal
    // deployment whose apply job left `setup_pending`.
    sqlx::query("UPDATE deployments SET status = 'failed' WHERE id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("fail the held deployment");
    sqlx::query(
        "UPDATE deployment_apply_jobs
                SET customer_config_released_at = NULL,
                    state = 'failed',
                    last_error_code = 'customer_config_hold_expired'
              WHERE deployment_id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("expire the hold");
    let (status, body) =
        refresh_replayed_hold_remainder(&state, StatusCode::CREATED, cached.clone())
            .await
            .expect("refresh a terminally ended hold");
    assert_eq!(status, StatusCode::GONE);
    assert!(
        body["error"]
            .as_str()
            .expect("terminal error")
            .contains("ended without a release"),
        "terminal holds must replay a failure, got {body}"
    );
    assert_eq!(body["app_name"], format!("app-{suffix}"));

    // A cached held response whose job row vanished fails closed too.
    // The apply job references the deployment (deferrable FK), so
    // deleting the job alone is valid and leaves the deployment row.
    sqlx::query("DELETE FROM deployment_apply_jobs WHERE deployment_id = $1")
        .bind(deployment_id)
        .execute(&pool)
        .await
        .expect("delete the apply job");
    let (status, body) = refresh_replayed_hold_remainder(&state, StatusCode::CREATED, cached)
        .await
        .expect("refresh a vanished held job");
    assert_eq!(status, StatusCode::GONE);
    assert!(
        body["error"]
            .as_str()
            .expect("terminal error")
            .contains("ended without a release"),
        "a vanished held job must not replay as a live hold, got {body}"
    );
}

#[tokio::test]
async fn whitelisted_known_not_applied_outcomes_preserve_binding_and_re_execute() {
    // The exact-match whitelist is the complete set of known-not-applied
    // 409s that release the bound reservation so a same-key retry
    // re-executes.
    // Iterating the const pins the contract: add an entry here only by
    // editing TRANSIENT_RETRY_CONFLICT_MESSAGES. Every former substring
    // match ("... changed ...; retry", "authority changed", deletion) is
    // now terminal and lives in
    // permanent_conflicts_are_stamped_completed_and_cached.
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let hash = Sha256::digest(b"transient-retry-cancel-request").to_vec();
    let messages: Vec<&str> = TRANSIENT_RETRY_CONFLICT_MESSAGES.to_vec();
    assert_eq!(
        messages.len(),
        7,
        "whitelist drift: update this count when editing the constant"
    );
    for (i, message) in messages.iter().enumerate() {
        let key = format!("transient-retry-cancel-{suffix}-{i}");
        let path = format!("/internal/test/transient-retry-cancel-{suffix}/{i}");
        let lease = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("reserve transient-retry handler"),
        );
        let active_token = lease.token;
        let result: Result<IdempotencyResponse, InternalRouteError> = async {
            Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": message})),
            ))
        }
        .await;
        let deferred = complete_idempotent_result(lease, result)
            .await
            .expect_err("known-not-applied 409 releases and returns the deferred body");
        assert_eq!(deferred.0, StatusCode::CONFLICT);
        assert_eq!(deferred.1["idempotency_disposition"], "deferred");
        assert_eq!(deferred.1["retryable"], true);
        assert_ne!(deferred.1["error"], *message);

        let marker: (bool, Vec<u8>, Uuid) = sqlx::query_as(
            "SELECT known_not_applied, request_hash, reservation_token
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect released bound row");
        assert!(marker.0, "known-not-applied authority marker must persist");
        assert_eq!(
            marker.1.as_slice(),
            hash.as_slice(),
            "the original request hash must persist"
        );
        assert_ne!(
            marker.2, active_token,
            "release must revoke any in-flight heartbeat authority"
        );

        // A same-key retry re-executes, never replays a cached conflict.
        match begin_idempotent_request(&state, &key, "POST", &path, &hash)
            .await
            .expect("re-begin released exact request")
        {
            IdempotencyBegin::Execute(_) => { /* re-executed as intended */ }
            IdempotencyBegin::Replay((status, body)) => {
                panic!("same-key retry should re-execute, not replay {status}: {body}");
            }
        }
    }
}

#[tokio::test]
async fn permanent_conflicts_are_stamped_completed_and_cached() {
    // Terminal-by-default: every 409 that is NOT on the exact-match
    // whitelist is stamped completed and durably cached, so a same-key
    // retry replays the cached body instead of re-executing. This pins the
    // former substring matches ("... changed ...; retry", "authority
    // changed", "app deletion is in progress", the setup-incomplete guard)
    // as terminal -- a same-key retry deterministically re-fails them, so
    // cancelling/re-running would spin or replay a stale block. A few
    // ("app creation was superseded", "app signer authority is
    // unavailable") are terminal for side-effect / heartbeat reasons.
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let hash = Sha256::digest(b"permanent-conflict-stamp-request").to_vec();
    let messages = [
        // duplicate / shape / state guards (never carried a transient substring):
        "app name already taken in this org",
        "deployment with external_id already exists in this org",
        "dns_hostname_in_use",
        "invalid unlock mode transition",
        "replayed transition_receipt",
        "app deletion phase is invalid",
        "app signer identity is incomplete",
        "app creation was superseded",
        "app signer authority is unavailable",
        "rollback target has no valid immutable apply snapshot",
        "external_id already exists with different security.log_encryption",
        // former substring matches, now correctly terminal (CAS-guard
        // "changed"/"authority" + one-way deletion; same-key retry re-fails):
        "app authority changed",
        "custom domain authority changed",
        "app deployment inputs changed while deployment was validating; retry the deployment",
        "app metadata changed while deployment was validating; retry the deployment",
        "app resource authority changed; retry deletion",
        "app deletion is in progress",
        "rollback target changed while validating; retry the rollback",
        "rollback target authority changed; retry the rollback",
        "app deployment inputs changed while rollback was validating; retry the rollback",
        "app changed while unlock mode transition was validating; retry",
        "app runtime changed while unlock mode transition was validating; retry",
        "deployment generation changed while unlock mode transition was validating; retry",
    ];
    for (i, message) in messages.iter().enumerate() {
        let key = format!("permanent-stamp-{suffix}-{i}");
        let path = format!("/internal/test/permanent-stamp-{suffix}/{i}");
        let lease = expect_idempotency_execution(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("reserve permanent-conflict handler"),
        );
        let result: Result<IdempotencyResponse, InternalRouteError> = async {
            Err((
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": message})),
            ))
        }
        .await;
        let stamped = complete_idempotent_result(lease, result)
            .await
            .expect_err("permanent 409 is stamped completed and returned");
        assert_eq!(stamped.0, StatusCode::CONFLICT);
        assert_eq!(stamped.1["error"], *message);
        assert_eq!(stamped.1["idempotency_disposition"], "completed");
        assert_eq!(stamped.1["retryable"], false);

        // Cached as completed: a same-key retry replays the stamped body.
        let replay = expect_idempotency_replay(
            begin_idempotent_request(&state, &key, "POST", &path, &hash)
                .await
                .expect("re-begin replays the cached permanent conflict"),
        );
        assert_eq!(replay.0, StatusCode::CONFLICT);
        assert_eq!(replay.1["error"], *message);
        assert_eq!(replay.1["idempotency_disposition"], "completed");
    }
}

async fn app_delete_fixture() -> (AppState, AuthContext, String, Uuid) {
    let pool = database_test_pool().await;
    app_delete_fixture_on(pool).await
}

async fn app_delete_fixture_on(pool: sqlx::PgPool) -> (AppState, AuthContext, String, Uuid) {
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("delete{}", &suffix[..8]);
    let app_name = "delete-test".to_string();
    insert_config_token_test_actor(&pool, org_id, &org_name, &suffix, user_id, &suffix).await;
    insert_config_token_test_app(&pool, org_id, &org_name, app_id, &app_name, "old").await;
    sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut state = idempotency_test_state(pool);
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    let auth = AuthContext {
        user_id,
        org_id,
        org_name,
        role: Role::Owner,
        api_key: None,
        management_origin: ManagementOrigin::PaasInternal,
    };
    (state, auth, app_name, app_id)
}

#[tokio::test]
async fn app_mutation_busy_names_holder_and_retry_window() {
    let (state, _auth, _app_name, app_id) = app_delete_fixture().await;
    // Ensure a lane row exists, then simulate a live holder (a deployment
    // that claimed the lane ~60s ago).
    sqlx::query(
        "INSERT INTO app_mutation_leases (app_id) VALUES ($1)
             ON CONFLICT (app_id) DO NOTHING",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE app_mutation_leases
                SET owner_token = gen_random_uuid(),
                    operation_kind = 'deployment',
                    operation_id = gen_random_uuid(),
                    locked_until = clock_timestamp() + interval '60 seconds',
                    reclaim_after = clock_timestamp() + interval '120 seconds'
              WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    let (status, Json(body)) =
        crate::routes::apps::app_mutation_busy_error(&state.db, app_id, &[]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "app mutation already in progress");
    assert_eq!(body["held_by"], "deployment");
    let retry_after = body["retry_after"].as_i64().expect("retry_after hint");
    assert!(
        (1..=60).contains(&retry_after),
        "hint should track the 60s lock, got {retry_after}"
    );
    assert!(retry_after <= IDEMPOTENCY_RETRY_HINT_MAX_SECONDS);

    // Free lane: the same answer carries no invented hints.
    sqlx::query(
        "UPDATE app_mutation_leases
                SET owner_token = NULL, operation_kind = NULL, operation_id = NULL,
                    locked_until = NULL, reclaim_after = NULL
              WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    let (status, Json(body)) =
        crate::routes::apps::app_mutation_busy_error(&state.db, app_id, &[]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "app mutation already in progress");
    assert!(body.get("held_by").is_none());
    assert!(body.get("retry_after").is_none());
}

#[tokio::test]
async fn app_mutation_busy_hint_follows_reclaim_quarantine() {
    let (state, _auth, _app_name, app_id) = app_delete_fixture().await;
    // A lost owner: the renewable lock lapsed but the row still blocks
    // claims until the reclaim quarantine expires. The hint must track
    // THAT deadline -- the dead lock expiry admits nothing, and a hint
    // there leaves the caller retried into a hintless Busy.
    sqlx::query(
        "INSERT INTO app_mutation_leases (app_id) VALUES ($1)
             ON CONFLICT (app_id) DO NOTHING",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE app_mutation_leases
                SET owner_token = gen_random_uuid(),
                    operation_kind = 'deployment',
                    operation_id = gen_random_uuid(),
                    locked_until = clock_timestamp() - interval '60 seconds',
                    reclaim_after = clock_timestamp() + interval '240 seconds'
              WHERE app_id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    let (status, Json(body)) =
        crate::routes::apps::app_mutation_busy_error(&state.db, app_id, &[]).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["held_by"], "deployment");
    let retry_after = body["retry_after"].as_i64().expect("retry_after hint");
    assert!(
        (230..=240).contains(&retry_after),
        "hint should follow the reclaim quarantine (240s), got {retry_after}"
    );
}

#[tokio::test]
async fn app_mutation_busy_resolves_resource_fence_holder() {
    let (state, _auth, _app_name, app_id) = app_delete_fixture().await;
    // A resource-fence conflict rolls the app-row claim back, so the
    // holder lives on the contested fence's row (which can belong to
    // another app or a global provider operation): the hint must read
    // THAT row, not this app's empty one.
    let fence = crate::mutation_leases::ResourceFence::new("test_scope", "test_key");
    sqlx::query(
        "INSERT INTO external_resource_mutation_leases (resource_scope, resource_key)
             VALUES ('test_scope', 'test_key')
             ON CONFLICT (resource_scope, resource_key) DO NOTHING",
    )
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "UPDATE external_resource_mutation_leases
                SET owner_token = gen_random_uuid(),
                    operation_kind = 'custom_domain_set',
                    operation_id = gen_random_uuid(),
                    locked_until = clock_timestamp() + interval '90 seconds',
                    reclaim_after = clock_timestamp() + interval '450 seconds'
              WHERE resource_scope = 'test_scope' AND resource_key = 'test_key'",
    )
    .execute(&state.db)
    .await
    .unwrap();
    let (status, Json(body)) = crate::routes::apps::app_mutation_busy_error(
        &state.db,
        app_id,
        std::slice::from_ref(&fence),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["error"], "app mutation already in progress");
    assert_eq!(body["held_by"], "custom_domain_set");
    let retry_after = body["retry_after"].as_i64().expect("retry_after hint");
    assert!(
        (80..=90).contains(&retry_after),
        "hint should track the fence holder's 90s lock, got {retry_after}"
    );
}

#[tokio::test]
async fn app_delete_partial_failure_defers_and_same_key_reexecutes() {
    let (state, auth, app_name, _) = app_delete_fixture().await;
    let key = format!("partial-delete-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let operation_id = lease.operation_id();
    let failure = complete_app_delete_result(
        lease,
        Err(json_error(
            StatusCode::BAD_GATEWAY,
            "app_delete_namespace_unavailable",
        )),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.0, StatusCode::CONFLICT);
    assert_eq!(
        failure.1.0["error"], "idempotency_request_in_progress",
        "the deferral shape stays intact: {:?}",
        failure.1.0
    );
    let receipt: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT completed_at IS NULL, response_status IS NULL,
                    response_body IS NULL, known_not_applied
               FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(receipt, (true, true, true, false));
    let busy = begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
        .await
        .err()
        .expect("live lease must defer");
    assert_eq!(busy.0, StatusCode::CONFLICT);
    assert_eq!(
        busy.1.0["error"], "idempotency_request_in_progress",
        "the deferral shape stays intact: {:?}",
        busy.1.0
    );
    // Lane etiquette: a live-lease deferral must carry the server-clock
    // retry hint so callers stop scheduling into the lease.
    let retry_after = busy.1.0["retry_after"].as_i64().expect("retry_after hint");
    assert!((1..=IDEMPOTENCY_RETRY_HINT_MAX_SECONDS).contains(&retry_after));
    expire_idempotency_lease(&state.db, &key).await;
    let retry = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    assert!(retry.reclaimed());
    assert_eq!(retry.operation_id(), operation_id);
    let response = (
        StatusCode::NO_CONTENT,
        serde_json::json!({"status": "deleted"}),
    );
    complete_app_delete_result(retry, Ok(response.clone()))
        .await
        .unwrap();
    assert_eq!(
        expect_idempotency_replay(
            begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
                .await
                .unwrap(),
        ),
        response
    );
}

#[tokio::test]
async fn app_delete_deferral_carries_teardown_disposition() {
    // An isolated per-test database: this test only asserts the deferral
    // body shape, but the shared test database's global state (the
    // signed-policy singleton, orphaned global fences, and the migration
    // advisory lock a sibling CI worktree can hold on the same server)
    // makes the fixture's pool acquisition and lane claims nondeterministic.
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_delete_disposition").await;
    let (state, auth, app_name, _) = app_delete_fixture_on(pool.clone()).await;
    let key = format!("disposition-delete-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let mut failure = json_error(StatusCode::BAD_GATEWAY, "app_delete_teardown_unavailable");
    failure.1.0["reason"] = serde_json::json!("app_kept_deleting");
    let deferred = complete_app_delete_result(lease, Err(failure))
        .await
        .unwrap_err();
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(
        deferred.1.0["error"], "idempotency_request_in_progress",
        "the deferral shape stays intact"
    );
    assert_eq!(
        deferred.1.0["reason"], "app_kept_deleting",
        "the teardown disposition must ride the deferral for hosted callers"
    );

    // A locked teardown (423) carries the same disposition — the handler
    // attaches `reason` for every deferral-worthy teardown status — and
    // must keep its `cause` too.
    let (state, auth, app_name, _) = app_delete_fixture_on(pool.clone()).await;
    let key = format!("disposition-locked-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let mut locked =
        crate::routes::apps::workload_teardown_http_failure(Uuid::new_v4(), StatusCode::LOCKED);
    locked.1.0["reason"] = serde_json::json!("app_restored");
    let deferred = complete_app_delete_result(lease, Err(locked))
        .await
        .unwrap_err();
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(deferred.1.0["cause"], "app_delete_teardown_locked");
    assert_eq!(
        deferred.1.0["reason"], "app_restored",
        "locked teardowns keep the app disposition on the deferral"
    );

    crate::test_support::drop_isolated_database("cap_delete_disposition", pool).await;
}

#[tokio::test]
async fn app_delete_budget_conflict_defers_instead_of_terminalizing() {
    let (state, auth, app_name, _) = app_delete_fixture().await;
    let key = format!("budget-defer-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    // The admission gate's real failure shape (Codex review on 3b168c73):
    // another app's teardown pins occupy the shared budget. This is a
    // transient pre-mutation rejection — it must defer, not terminalize
    // the receipt with retryable:false.
    let failure = json_error(
        StatusCode::CONFLICT,
        "app_delete_kbs_policy_budget_exceeded",
    );
    let deferred = complete_app_delete_result(lease, Err(failure))
        .await
        .unwrap_err();
    assert_eq!(
        deferred.0,
        StatusCode::CONFLICT,
        "budget conflicts defer like a server error"
    );
    assert_eq!(
        deferred.1.0.get("error"),
        idempotency_in_progress_error().1.0.get("error"),
        "budget conflicts defer like a server error"
    );
    assert_eq!(
        deferred.1.0.get("cause"),
        Some(&serde_json::json!("app_delete_kbs_policy_budget_exceeded")),
        "deferred budget conflicts must name their cause"
    );
    // The receipt stays incomplete: a same-key retry re-executes once
    // other teardowns free the budget instead of replaying the conflict.
    let receipt: (bool, bool, bool) = sqlx::query_as(
        "SELECT completed_at IS NULL, response_status IS NULL, known_not_applied
               FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(receipt, (true, true, false));
}

#[tokio::test]
async fn app_delete_terminal_failure_recovery_preserves_success_and_incarnation() {
    let (state, auth, app_name, app_id) = app_delete_fixture().await;
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    for (index, status, response, recover) in [
        (
            0,
            StatusCode::CONFLICT,
            idempotency_recovery_required_body(),
            true,
        ),
        (
            1,
            StatusCode::NO_CONTENT,
            serde_json::json!({"status": "deleted"}),
            false,
        ),
        (
            2,
            StatusCode::FORBIDDEN,
            serde_json::json!({"error": "scope_not_allowed", "idempotency_disposition": "completed"}),
            false,
        ),
        (
            3,
            StatusCode::CONFLICT,
            serde_json::json!({"error": "idempotency_recovery_required"}),
            false,
        ),
    ] {
        let key = format!("terminal-delete-{index}-{}", Uuid::new_v4());
        let headers = idempotency_headers(&key);
        let lease = expect_idempotency_execution(
            begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
                .await
                .unwrap(),
        );
        let token = lease.token;
        let operation = lease.operation_id();
        finish_idempotent_request(lease, status, &response)
            .await
            .unwrap();
        // Validate all request bindings before allowing terminal recovery.
        for (method, changed_path, changed_auth, changed_body) in [
            ("POST", path.clone(), auth.clone(), body.clone()),
            (
                "DELETE",
                format!("{path}-other"),
                auth.clone(),
                body.clone(),
            ),
            (
                "DELETE",
                path.clone(),
                AuthContext {
                    user_id: Uuid::new_v4(),
                    ..auth.clone()
                },
                body.clone(),
            ),
            (
                "DELETE",
                path.clone(),
                AuthContext {
                    org_id: Uuid::new_v4(),
                    ..auth.clone()
                },
                body.clone(),
            ),
            (
                "DELETE",
                path.clone(),
                auth.clone(),
                serde_json::json!({"changed": true}),
            ),
        ] {
            let mismatch = if method == "POST" {
                begin_actor_idempotent_request(
                    &state,
                    &headers,
                    method,
                    &changed_path,
                    &changed_auth,
                    &changed_body,
                    IdempotencyRecovery::RetrySafe,
                )
                .await
            } else {
                begin_app_delete_request(
                    &state,
                    &headers,
                    &changed_path,
                    &changed_auth,
                    &changed_body,
                    &app_name,
                )
                .await
            }
            .err()
            .expect("request mismatch rejects before replay/recovery");
            assert_eq!(mismatch.1.0["error"], "idempotency_key_reused");
        }
        let next = begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap();
        if recover {
            let recovered = expect_idempotency_execution(next);
            assert!(recovered.reclaimed());
            assert_ne!(recovered.token, token);
            assert_eq!(recovered.operation_id(), operation);
            finish_idempotent_request(recovered, status, &response)
                .await
                .unwrap();
            // A live but non-deleting app cannot reopen this receipt.
            sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
                .bind(app_id)
                .execute(&state.db)
                .await
                .unwrap();
            assert_eq!(
                expect_idempotency_replay(
                    begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name,)
                        .await
                        .unwrap()
                ),
                (status, response.clone())
            );
            sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
                .bind(app_id)
                .execute(&state.db)
                .await
                .unwrap();
        } else {
            assert_eq!(expect_idempotency_replay(next), (status, response));
        }
    }
    let key = format!("incarnation-delete-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let created_before: chrono::DateTime<chrono::Utc> = sqlx::query_scalar(
        "SELECT created_at FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&state.db)
    .await
    .unwrap();
    finish_idempotent_request(
        lease,
        StatusCode::CONFLICT,
        &idempotency_recovery_required_body(),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM apps WHERE id = $1")
        .bind(app_id)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(
        expect_idempotency_replay(
            begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name,)
                .await
                .unwrap()
        )
        .1,
        idempotency_recovery_required_body()
    );
    let replacement = Uuid::new_v4();
    insert_config_token_test_app(
        &state.db,
        auth.org_id,
        &auth.org_name,
        replacement,
        &app_name,
        "new",
    )
    .await;
    sqlx::query("UPDATE apps SET status = 'deleting' WHERE id = $1")
        .bind(replacement)
        .execute(&state.db)
        .await
        .unwrap();
    assert_eq!(
        expect_idempotency_replay(
            begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name,)
                .await
                .unwrap()
        )
        .1,
        idempotency_recovery_required_body()
    );
    // Also fence recreation after receipt recovery but before route execution.
    let rejected = crate::routes::apps::delete_app_before(
        auth,
        State(state.clone()),
        Path(app_name),
        Some(created_before),
        false,
    )
    .await
    .unwrap_err();
    assert_eq!(rejected.1.0["error"], "idempotency_resource_conflict");
    assert!(
        sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM apps WHERE id = $1)")
            .bind(replacement)
            .fetch_one(&state.db)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn app_delete_recovery_has_one_reservation_winner() {
    let (state, auth, app_name, _) = app_delete_fixture().await;
    let key = format!("concurrent-delete-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let operation = lease.operation_id();
    finish_idempotent_request(
        lease,
        StatusCode::CONFLICT,
        &idempotency_recovery_required_body(),
    )
    .await
    .unwrap();
    let (a, b) = tokio::join!(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name),
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name),
    );
    let mut winners = Vec::new();
    for attempt in [a, b] {
        match attempt {
            Ok(IdempotencyBegin::Execute(lease)) => winners.push(lease),
            Err(error) => {
                assert_eq!(error.0, StatusCode::CONFLICT);
                assert_eq!(error.1.0["error"], "idempotency_request_in_progress");
            }
            Ok(IdempotencyBegin::Replay(_)) => panic!("failed receipt must not replay"),
        }
    }
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0].operation_id(), operation);
    assert!(winners[0].reclaimed());
    let attempts: i32 = sqlx::query_scalar(
        "SELECT attempt_count FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(attempts, 2);
    complete_app_delete_result(winners.pop().unwrap(), Ok((StatusCode::NO_CONTENT, body)))
        .await
        .unwrap();
}

#[tokio::test]
async fn app_delete_locked_teardown_defers_and_same_key_reexecutes() {
    let (state, auth, app_name, _) = app_delete_fixture().await;
    let key = format!("locked-delete-{}", Uuid::new_v4());
    let headers = idempotency_headers(&key);
    let path = format!("/internal/paas/orgs/{}/apps/{app_name}", auth.org_id);
    let body = serde_json::json!({});
    let lease = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    let operation_id = lease.operation_id();
    // A locked TEE is recoverable once the owner unlocks it: the 423 must
    // defer (row stays incomplete) instead of caching a terminal receipt
    // that every same-key retry would replay. The body comes from the
    // route's real helper so the error code cannot drift.
    let failure = complete_app_delete_result(
        lease,
        Err(crate::routes::apps::workload_teardown_http_failure(
            Uuid::new_v4(),
            StatusCode::LOCKED,
        )),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.0, StatusCode::CONFLICT);
    assert_eq!(
        failure.1.0.get("error"),
        idempotency_in_progress_error().1.0.get("error"),
        "locked teardown defers like a server error"
    );
    assert_eq!(
        failure.1.0.get("cause"),
        Some(&serde_json::json!("app_delete_teardown_locked")),
        "deferred locked teardown must name its cause"
    );
    let receipt: (bool, bool, bool, bool) = sqlx::query_as(
        "SELECT completed_at IS NULL, response_status IS NULL,
                    response_body IS NULL, known_not_applied
               FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(receipt, (true, true, true, false));
    expire_idempotency_lease(&state.db, &key).await;
    let retry = expect_idempotency_execution(
        begin_app_delete_request(&state, &headers, &path, &auth, &body, &app_name)
            .await
            .unwrap(),
    );
    assert!(retry.reclaimed());
    assert_eq!(retry.operation_id(), operation_id);
    complete_app_delete_result(
        retry,
        Ok((
            StatusCode::NO_CONTENT,
            serde_json::json!({"status": "deleted"}),
        )),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn app_delete_retry_finishes_after_namespace_removal() {
    const CHILD: &str = "CAP_APP_DELETE_TEST_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // KBS policy state and provider leases are global within a schema.
        // Other tests (including failed runs) must not select an earlier failure.
        let pool = database_test_pool().await;
        let schema = format!("app_delete_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .unwrap();
        let mut database_url = reqwest::Url::parse(
            &std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".into()),
        )
        .unwrap();
        database_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        // Isolate kube's process-wide configuration from other lib tests.
        let deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let namespace_deletes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mock_deleted = deleted.clone();
        let mock_deletes = namespace_deletes.clone();
        let resources = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            serde_json::Value,
        >::new()));
        let server = axum::Router::new().fallback(move |request: axum::extract::Request| {
                let deleted = mock_deleted.clone();
                let deletes = mock_deletes.clone();
                let resources = resources.clone();
                async move {
                    use std::sync::atomic::Ordering::SeqCst;
                    let path = request.uri().path().to_string();
                    let method = request.method().clone();
                    if path.starts_with("/zones/") {
                        return (StatusCode::OK, Json(serde_json::json!({"success":true, "result":[], "errors":[]})));
                    }
                    let name = path.rsplit('/').next().unwrap();
                    let metadata = serde_json::json!({"name": name, "uid": "fixture", "resourceVersion": "1"});
                    if path.contains("/gateways/") {
                        // No tenant Gateway exists for these fixtures; the
                        // resolver maps 404 -> Ok(None) -> public origin.
                        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "code":404})));
                    }
                    if path.starts_with("/api/v1/namespaces/cap-") {
                        if method == axum::http::Method::DELETE {
                            deletes.fetch_add(1, SeqCst);
                            deleted.store(true, SeqCst);
                            return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Success", "code":200})));
                        }
                        if deleted.load(SeqCst) {
                            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "message":"absent", "code":404})));
                        }
                        return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Namespace", "metadata":metadata})));
                    }
                    if method == axum::http::Method::PUT {
                        let bytes = axum::body::to_bytes(request.into_body(), 1_048_576).await.unwrap();
                        let resource: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        resources.lock().unwrap().insert(path, resource.clone());
                        return (StatusCode::OK, Json(resource));
                    }
                    if let Some(resource) = resources.lock().unwrap().get(&path).cloned() {
                        return (StatusCode::OK, Json(resource));
                    }
                    let resource = if path.contains("/configmaps/") {
                        serde_json::json!({"apiVersion":"v1", "kind":"ConfigMap", "metadata":metadata,
                            "data":{"haproxy.cfg":"", "policy.rego":"package policy\nresource_bindings := {}\nowner_resource_bindings := {}\n"}})
                    } else {
                        assert!(path.contains("/daemonsets/") || path.contains("/deployments/"), "unexpected provider request {path}");
                        serde_json::json!({"apiVersion":"apps/v1", "kind": if path.contains("/daemonsets/") {"DaemonSet"} else {"Deployment"},
                            "metadata":metadata, "spec":{"replicas":1, "selector":{}, "template":{"metadata":{}, "spec":{"containers":[]}}},
                            "status":{"replicas":1, "readyReplicas":1, "availableReplicas":1, "updatedReplicas":1, "observedGeneration":1}})
                    };
                    (StatusCode::OK, Json(resource))
                }
            });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        let config = std::env::temp_dir().join(format!("cap-delete-kube-{}.json", Uuid::new_v4()));
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "apiVersion":"v1", "kind":"Config", "current-context":"test",
                "clusters":[{"name":"test", "cluster":{"server":format!("http://{address}")}}],
                "contexts":[{"name":"test", "context":{"cluster":"test", "user":"test"}}],
                "users":[{"name":"test", "user":{}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "routes::internal::tests::app_delete_retry_finishes_after_namespace_removal",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env("DATABASE_URL", database_url.as_str())
            .env("KUBECONFIG", &config)
            .env(
                "CAP_APP_DELETE_TEST_PROVIDER_URL",
                format!("http://{address}"),
            )
            .env("TENANT_HAPROXY_NAMESPACE", "tenant-envoy")
            .env("TENANT_HAPROXY_CONFIGMAP", "haproxy-tenant")
            .env("TENANT_HAPROXY_DAEMONSET", "haproxy-tenant")
            .kill_on_drop(true)
            .output();
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), output).await;
        task.abort();
        std::fs::remove_file(config).unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        let output = output.expect("delete retry must not deadlock").unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout)
                .matches("app_delete_kbs_policy_failed")
                .count(),
            1,
            "the first attempt must fail at KBS reconciliation"
        );
        assert_eq!(
            namespace_deletes.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_test_writer()
        .init();
    let (mut state, auth, app_name, app_id) = app_delete_fixture().await;
    // The missing KBS config fails after both namespace teardown and soft deletes.
    state.kbs_policy = None;
    state.dns = Some(crate::dns::DnsConfig {
        cloudflare_api_token: "test".into(),
        cloudflare_api_base_url: std::env::var("CAP_APP_DELETE_TEST_PROVIDER_URL").unwrap(),
        cloudflare_zone_id: Some("test".into()),
        cloudflare_zone_name: "enclava.test".into(),
        target: "192.0.2.1".into(),
        required: true,
    });
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(10))
        // The per-request teardown timeout overrides the client timeout,
        // so bound the connect/DNS phase explicitly against resolver stalls.
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    for table in ["kbs_owner_bindings", "kbs_tls_bindings"] {
        sqlx::query(&format!("INSERT INTO {table} (app_id, binding_key, namespace, service_account, tenant_instance_identity_hash)
                SELECT id, id::text, namespace, service_account, tenant_instance_identity_hash FROM apps WHERE id = $1"))
                .bind(app_id).execute(&state.db).await.unwrap();
    }
    let paas_id = auth.org_id.simple().to_string();
    let key = format!("teardown-retry-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&key, &paas_id);
    let failed = delete_paas_app(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_id.clone(), app_name.clone())),
        headers.clone(),
        Json(serde_json::json!({})),
    )
    .await
    .unwrap_err();
    assert_eq!(failed.0, StatusCode::CONFLICT);
    assert_eq!(
        failed.1.0["error"], "idempotency_request_in_progress",
        "the deferral shape stays intact: {:?}",
        failed.1.0
    );
    assert!(
        failed.1.0.get("reason").is_none(),
        "non-teardown 502 deferrals carry no disposition: {:?}",
        failed.1.0
    );
    let state_after_failure: (String, bool, bool, i64) = sqlx::query_as(
            "SELECT status::text,
                (SELECT deleted_at IS NOT NULL FROM kbs_owner_bindings WHERE app_id = apps.id),
                (SELECT deleted_at IS NOT NULL FROM kbs_tls_bindings WHERE app_id = apps.id),
                (SELECT count(*) FROM audit_log WHERE org_id = apps.org_id AND action = 'app.delete')
             FROM apps WHERE id = $1",
        ).bind(app_id).fetch_one(&state.db).await.unwrap();
    assert_eq!(state_after_failure, ("deleting".into(), true, true, 0));
    let retained: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM external_resource_mutation_leases
              WHERE operation_id = $1 AND resource_scope IN ('dns_hostname', 'kubernetes_namespace')
                AND owner_token IS NOT NULL",
    )
    .bind(app_id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        retained, 0,
        "confirmed cleanup must be durably released before KBS failure"
    );
    // Advance only finite quarantine. This must never hide an infinite-fence bug.
    sqlx::query("UPDATE app_mutation_leases SET locked_until = clock_timestamp() - interval '2 seconds', reclaim_after = clock_timestamp() - interval '1 second' WHERE app_id = $1")
            .bind(app_id).execute(&state.db).await.unwrap();
    sqlx::query("UPDATE external_resource_mutation_leases SET locked_until = clock_timestamp() - interval '2 seconds', reclaim_after = clock_timestamp() - interval '1 second' WHERE operation_id = $1 AND reclaim_after <> 'infinity'::timestamptz")
            .bind(app_id).execute(&state.db).await.unwrap();
    expire_idempotency_lease(&state.db, &key).await;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    for _ in 0..2 {
        let (status, _) = delete_paas_app(
            internal_test_auth(),
            State(state.clone()),
            Path((paas_id.clone(), app_name.clone())),
            headers.clone(),
            Json(serde_json::json!({})),
        )
        .await
        .expect("retry completes and then replays");
        assert_eq!(status, StatusCode::NO_CONTENT);
    }
    let final_rows: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM apps WHERE id = $1),
                    (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.delete')",
    )
    .bind(app_id)
    .bind(auth.org_id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(final_rows, (0, 1));
    // Legacy-install guard (fresh schema: no signed acceptance ever ran,
    // so signed-policy mode was never active). The post-delete
    // reconciliation must not activate signed mode here — publishing an
    // empty artifact set would strip every other app's Rego-authorized
    // KBS access on an unsigned installation.
    let signed_generation: Option<i64> = sqlx::query_scalar(
        "SELECT desired_generation FROM kbs_signed_policy_reconciliation WHERE singleton",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        signed_generation,
        Some(0),
        "a delete must never activate signed-policy mode on a legacy install"
    );
}

/// Route-level pin of the durable teardown decision and completion marker
/// (the #109 retry contract): a running app requires teardown, an
/// unreachable TEE fails the first attempt atomically (the app is restored
/// before any other cleanup), and once the completion marker exists the
/// retry finishes with the TEE gone.
#[tokio::test]
async fn app_delete_retry_finishes_after_teardown_completion_marker() {
    const CHILD: &str = "CAP_APP_DELETE_TEST_TEARDOWN_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // KBS policy state and provider leases are global within a schema.
        let pool = database_test_pool().await;
        let schema = format!("app_delete_td_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .unwrap();
        let mut database_url = reqwest::Url::parse(
            &std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".into()),
        )
        .unwrap();
        database_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        // Isolate kube's process-wide configuration from other lib tests.
        let mock_deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resources = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            serde_json::Value,
        >::new()));
        let deleted = mock_deleted.clone();
        let mock_resources = resources.clone();
        let server = axum::Router::new().fallback(
                move |request: axum::extract::Request| {
                    let deleted = deleted.clone();
                    let resources = mock_resources.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        let method = request.method().clone();
                        if path.starts_with("/zones/") {
                            return (StatusCode::OK, Json(serde_json::json!({"success":true, "result":[], "errors":[]})));
                        }
                        let name = path.rsplit('/').next().unwrap();
                        let metadata = serde_json::json!({"name": name, "uid": "fixture", "resourceVersion": "1"});
                        if path.contains("/gateways/") {
                            // No tenant Gateway exists for these fixtures; the
                            // resolver maps 404 -> Ok(None) -> public origin.
                            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "code":404})));
                        }
                        if path.starts_with("/api/v1/namespaces/cap-") {
                            if method == axum::http::Method::DELETE {
                                deleted.store(true, std::sync::atomic::Ordering::SeqCst);
                                return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Success", "code":200})));
                            }
                            if deleted.load(std::sync::atomic::Ordering::SeqCst) {
                                return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "message":"absent", "code":404})));
                            }
                            return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Namespace", "metadata":metadata})));
                        }
                        if method == axum::http::Method::PUT {
                            let bytes = axum::body::to_bytes(request.into_body(), 1_048_576).await.unwrap();
                            let resource: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                            resources.lock().unwrap().insert(path, resource.clone());
                            return (StatusCode::OK, Json(resource));
                        }
                        if let Some(resource) = resources.lock().unwrap().get(&path).cloned() {
                            return (StatusCode::OK, Json(resource));
                        }
                        let resource = if path.contains("/configmaps/") {
                            serde_json::json!({"apiVersion":"v1", "kind":"ConfigMap", "metadata":metadata,
                                "data":{"haproxy.cfg":"", "policy.rego":"package policy\nresource_bindings := {}\nowner_resource_bindings := {}\n"}})
                        } else {
                            assert!(path.contains("/daemonsets/") || path.contains("/deployments/"), "unexpected provider request {path}");
                            serde_json::json!({"apiVersion":"apps/v1", "kind": if path.contains("/daemonsets/") {"DaemonSet"} else {"Deployment"},
                                "metadata":metadata, "spec":{"replicas":1, "selector":{}, "template":{"metadata":{}, "spec":{"containers":[]}}},
                                "status":{"replicas":1, "readyReplicas":1, "availableReplicas":1, "updatedReplicas":1, "observedGeneration":1}})
                        };
                        (StatusCode::OK, Json(resource))
                    }
                },
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        let config = std::env::temp_dir().join(format!("cap-delete-td-{}.json", Uuid::new_v4()));
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "apiVersion":"v1", "kind":"Config", "current-context":"test",
                "clusters":[{"name":"test", "cluster":{"server":format!("http://{address}")}}],
                "contexts":[{"name":"test", "context":{"cluster":"test", "user":"test"}}],
                "users":[{"name":"test", "user":{}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "routes::internal::tests::app_delete_retry_finishes_after_teardown_completion_marker",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD, "1")
                .env("DATABASE_URL", database_url.as_str())
                .env("KUBECONFIG", &config)
                .env("CAP_APP_DELETE_TEST_PROVIDER_URL", format!("http://{address}"))
                .env("TENANT_HAPROXY_NAMESPACE", "tenant-envoy")
                .env("TENANT_HAPROXY_CONFIGMAP", "haproxy-tenant")
                .env("TENANT_HAPROXY_DAEMONSET", "haproxy-tenant")
                .kill_on_drop(true)
                .output();
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), output).await;
        task.abort();
        std::fs::remove_file(config).unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        let output = output.expect("teardown retry must not deadlock").unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_test_writer()
        .init();
    let (mut state, auth, app_name, app_id) = app_delete_fixture().await;
    // A running app holds confidential state: teardown is required and the
    // pre-delete decision must survive the deleting transition. The
    // fixture's .test tee domain fails teardown resolution instantly
    // (reserved TLD, no resolver dependency beyond NXDOMAIN).
    sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
        .bind(app_id)
        .execute(&state.db)
        .await
        .unwrap();
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.dns = Some(crate::dns::DnsConfig {
        cloudflare_api_token: "test".into(),
        cloudflare_api_base_url: std::env::var("CAP_APP_DELETE_TEST_PROVIDER_URL").unwrap(),
        cloudflare_zone_id: Some("test".into()),
        cloudflare_zone_name: "enclava.test".into(),
        target: "192.0.2.1".into(),
        required: true,
    });
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    // The TEE is unreachable for both attempts; only the durable marker
    // can let the retry through.
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(10))
        // The per-request teardown timeout overrides the client timeout,
        // so bound the connect/DNS phase explicitly against resolver stalls.
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    for table in ["kbs_owner_bindings", "kbs_tls_bindings"] {
        sqlx::query(&format!("INSERT INTO {table} (app_id, binding_key, namespace, service_account, tenant_instance_identity_hash)
                SELECT id, id::text, namespace, service_account, tenant_instance_identity_hash FROM apps WHERE id = $1"))
                .bind(app_id).execute(&state.db).await.unwrap();
    }
    let paas_id = auth.org_id.simple().to_string();
    let key = format!("teardown-marker-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&key, &paas_id);
    let failed = delete_paas_app(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_id.clone(), app_name.clone())),
        headers.clone(),
        Json(serde_json::json!({})),
    )
    .await
    .unwrap_err();
    assert_eq!(failed.0, StatusCode::CONFLICT);
    assert_eq!(
        failed.1.0["error"], "idempotency_request_in_progress",
        "the deferral shape stays intact: {:?}",
        failed.1.0
    );
    assert_eq!(
        failed.1.0["reason"], "app_restored",
        "this attempt restored the app; the deferral must say so"
    );
    let after_first: (String, bool, bool, bool) = sqlx::query_as(
        "SELECT status::text, workload_teardown_required,
                    workload_teardown_completed_at IS NOT NULL,
                    (SELECT deleted_at IS NULL FROM kbs_owner_bindings WHERE app_id = apps.id)
               FROM apps WHERE id = $1",
    )
    .bind(app_id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        after_first,
        ("running".into(), true, false, true),
        "unreachable teardown must fail atomically: restored and untouched before KBS revocation"
    );
    // The failed teardown must release the shared fences immediately: an
    // abandoned lease would hold cluster-wide edge_config and kbs_policy
    // through reclaim quarantine and stall every tenant's deploys.
    let shared_fences: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM external_resource_mutation_leases
              WHERE resource_key = 'global'
                AND resource_scope IN ('edge_config', 'kbs_policy')
                AND owner_token IS NOT NULL",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(
        shared_fences, 0,
        "a failed teardown must not abandon the shared mutation fences"
    );
    // Simulate the durable marker left by a previously successful teardown
    // (or the documented operator recovery for an already-erased wrap).
    sqlx::query("UPDATE apps SET workload_teardown_completed_at = clock_timestamp() WHERE id = $1")
        .bind(app_id)
        .execute(&state.db)
        .await
        .unwrap();
    // Only the idempotency lease needs expiring: the mutation fences were
    // durably released above, so the retry re-claims them normally.
    expire_idempotency_lease(&state.db, &key).await;
    let (status, _) = delete_paas_app(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_id.clone(), app_name.clone())),
        headers.clone(),
        Json(serde_json::json!({})),
    )
    .await
    .expect("retry must complete via the completion marker");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let final_rows: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM apps WHERE id = $1),
                    (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.delete')",
    )
    .bind(app_id)
    .bind(auth.org_id)
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert_eq!(final_rows, (0, 1));
}

/// An abandoned destroy (unreachable teardown + the operator override)
/// must complete the cleanup tail, record the waiver in a table that
/// survives the app row, and refuse a same-name recreate with
/// `stale_owner_seed`.
#[tokio::test]
async fn abandoned_destroy_records_waiver_and_blocks_recreate() {
    const CHILD: &str = "CAP_APP_DELETE_TEST_ABANDON_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let pool = database_test_pool().await;
        let schema = format!("app_delete_ab_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&pool)
            .await
            .unwrap();
        let mut database_url = reqwest::Url::parse(
            &std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgresql://test:test@localhost:5432/test".into()),
        )
        .unwrap();
        database_url
            .query_pairs_mut()
            .append_pair("options", &format!("-csearch_path={schema}"));
        let mock_deleted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let resources = Arc::new(std::sync::Mutex::new(std::collections::HashMap::<
            String,
            serde_json::Value,
        >::new()));
        let deleted = mock_deleted.clone();
        let mock_resources = resources.clone();
        let server = axum::Router::new().fallback(
                move |request: axum::extract::Request| {
                    let deleted = deleted.clone();
                    let resources = mock_resources.clone();
                    async move {
                        let path = request.uri().path().to_string();
                        let method = request.method().clone();
                        if path.starts_with("/zones/") {
                            return (StatusCode::OK, Json(serde_json::json!({"success":true, "result":[], "errors":[]})));
                        }
                        let name = path.rsplit('/').next().unwrap();
                        let metadata = serde_json::json!({"name": name, "uid": "fixture", "resourceVersion": "1"});
                        if path.contains("/gateways/") {
                            // No tenant Gateway exists for these fixtures; the
                            // resolver maps 404 -> Ok(None) -> public origin.
                            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "code":404})));
                        }
                        if path.starts_with("/api/v1/namespaces/cap-") {
                            if method == axum::http::Method::DELETE {
                                deleted.store(true, std::sync::atomic::Ordering::SeqCst);
                                return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Success", "code":200})));
                            }
                            if deleted.load(std::sync::atomic::Ordering::SeqCst) {
                                return (StatusCode::NOT_FOUND, Json(serde_json::json!({"apiVersion":"v1", "kind":"Status", "status":"Failure", "reason":"NotFound", "message":"absent", "code":404})));
                            }
                            return (StatusCode::OK, Json(serde_json::json!({"apiVersion":"v1", "kind":"Namespace", "metadata":metadata})));
                        }
                        if method == axum::http::Method::PUT {
                            let bytes = axum::body::to_bytes(request.into_body(), 1_048_576).await.unwrap();
                            let resource: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                            resources.lock().unwrap().insert(path, resource.clone());
                            return (StatusCode::OK, Json(resource));
                        }
                        if let Some(resource) = resources.lock().unwrap().get(&path).cloned() {
                            return (StatusCode::OK, Json(resource));
                        }
                        let resource = if path.contains("/configmaps/") {
                            serde_json::json!({"apiVersion":"v1", "kind":"ConfigMap", "metadata":metadata,
                                "data":{"haproxy.cfg":"", "policy.rego":"package policy\nresource_bindings := {}\nowner_resource_bindings := {}\n"}})
                        } else {
                            assert!(path.contains("/daemonsets/") || path.contains("/deployments/"), "unexpected provider request {path}");
                            // Status must include `replicas`: the rollout
                            // readiness check treats missing status.replicas as
                            // a not-yet-converged rollout (available replicas
                            // may belong to the previous ReplicaSet).
                            serde_json::json!({"apiVersion":"apps/v1", "kind": if path.contains("/daemonsets/") {"DaemonSet"} else {"Deployment"},
                                "metadata":metadata, "spec":{"replicas":1, "selector":{}, "template":{"metadata":{}, "spec":{"containers":[]}}},
                                "status":{"replicas":1, "readyReplicas":1, "availableReplicas":1, "updatedReplicas":1, "observedGeneration":1}})
                        };
                        (StatusCode::OK, Json(resource))
                    }
                },
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
        let config = std::env::temp_dir().join(format!("cap-delete-ab-{}.json", Uuid::new_v4()));
        std::fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "apiVersion":"v1", "kind":"Config", "current-context":"test",
                "clusters":[{"name":"test", "cluster":{"server":format!("http://{address}")}}],
                "contexts":[{"name":"test", "context":{"cluster":"test", "user":"test"}}],
                "users":[{"name":"test", "user":{}}]
            }))
            .unwrap(),
        )
        .unwrap();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "routes::internal::tests::abandoned_destroy_records_waiver_and_blocks_recreate",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .env("DATABASE_URL", database_url.as_str())
            .env("KUBECONFIG", &config)
            .env(
                "CAP_APP_DELETE_TEST_PROVIDER_URL",
                format!("http://{address}"),
            )
            .env("TENANT_HAPROXY_NAMESPACE", "tenant-envoy")
            .env("TENANT_HAPROXY_CONFIGMAP", "haproxy-tenant")
            .env("TENANT_HAPROXY_DAEMONSET", "haproxy-tenant")
            .kill_on_drop(true)
            .output();
        let output = tokio::time::timeout(std::time::Duration::from_secs(60), output).await;
        task.abort();
        std::fs::remove_file(config).unwrap();
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        let output = output
            .expect("abandoned destroy must not deadlock")
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert_eq!(
            stdout.matches("app_delete_teardown_abandoned").count(),
            1,
            "exactly one abandoned teardown"
        );
        return;
    }

    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_test_writer()
        .init();
    let (mut state, auth, app_name, app_id) = app_delete_fixture().await;
    sqlx::query("UPDATE apps SET status = 'running' WHERE id = $1")
        .bind(app_id)
        .execute(&state.db)
        .await
        .unwrap();
    // The hosted create path needs an authoritative entitlement for the
    // recreate attempt to reach the stale-owner-seed guard.
    sqlx::query(
        "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
    )
    .bind(auth.org_id)
    .bind(serde_json::json!({
        "max_apps": 10, "max_cpu": "10", "max_memory": "10Gi", "max_storage": "100Gi"
    }))
    .execute(&state.db)
    .await
    .unwrap();
    // The waiver must be keyed by the REAL derivation (namespace =
    // cap-{org}-{name}, binding key = {namespace}-{name}-owner): the
    // fixture's namespace carries an identity suffix and its binding key
    // is a placeholder, both of which would hide a key-derivation
    // mismatch between the destroy and the recreate.
    sqlx::query(
        "UPDATE apps
                SET namespace = 'cap-' || (SELECT name FROM organizations WHERE id = org_id)
                           || '-' || name
              WHERE id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO kbs_owner_bindings (
                 app_id, binding_key, namespace, service_account,
                 tenant_instance_identity_hash
             )
             SELECT id, namespace || '-' || name || '-owner', namespace,
                    service_account, tenant_instance_identity_hash
               FROM apps WHERE id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO kbs_tls_bindings (
                 app_id, binding_key, namespace, service_account,
                 tenant_instance_identity_hash
             )
             SELECT id, id::text, namespace, service_account,
                    tenant_instance_identity_hash
               FROM apps WHERE id = $1",
    )
    .bind(app_id)
    .execute(&state.db)
    .await
    .unwrap();
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.dns = Some(crate::dns::DnsConfig {
        cloudflare_api_token: "test".into(),
        cloudflare_api_base_url: std::env::var("CAP_APP_DELETE_TEST_PROVIDER_URL").unwrap(),
        cloudflare_zone_id: Some("test".into()),
        cloudflare_zone_name: "enclava.test".into(),
        target: "192.0.2.1".into(),
        required: true,
    });
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    state.tee_http_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(10))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()
        .unwrap();
    let paas_id = auth.org_id.simple().to_string();

    // Abandoned attempt: the override proceeds past the unreachable
    // teardown, completes the cleanup tail, and deletes the app row.
    let key_abandon = format!("abandon-waiver-2-{}", Uuid::new_v4());
    let (status, _) = delete_paas_app(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_id.clone(), app_name.clone())),
        config_token_actor_headers(&key_abandon, &paas_id),
        Json(serde_json::json!({"abandon_teardown": true})),
    )
    .await
    .expect("abandoned destroy must complete the tail");
    assert_eq!(status, StatusCode::NO_CONTENT);
    let app_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(app_rows, 0, "the abandoned destroy must delete the app row");
    let binding_rows: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kbs_owner_bindings WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(
        binding_rows, 0,
        "kbs_owner_bindings cascades away with the app row"
    );
    let waiver: Option<String> =
        sqlx::query_scalar("SELECT binding_key FROM kbs_owner_seed_waivers LIMIT 1")
            .fetch_optional(&state.db)
            .await
            .unwrap();
    assert!(
        waiver.is_some(),
        "the waiver must survive the app row deletion"
    );

    // A same-name recreate must be refused: the previous incarnation's
    // owner seed may still exist in KBS.
    let key_create = format!("abandon-waiver-3-{}", Uuid::new_v4());
    let create_headers = config_token_actor_headers(&key_create, &paas_id);
    let recreate = create_paas_app(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_id.clone()),
        create_headers.clone(),
        Json(InternalCreateAppRequest {
            name: app_name.clone(),
            unlock_mode: "password".into(),
            bootstrap_pubkey_hash: Some("00".repeat(32)),
            signer_identity_subject: None,
            signer_identity_issuer: None,
            egress_allowlist: vec![],
            egress_mode: crate::routes::apps::default_egress_mode(),
            resources: None,
        }),
    )
    .await;
    // The create also rides the idempotency lane: defer once, then the
    // same-key retry must hit the stale-owner-seed guard.
    let recreate = match recreate {
        Err((StatusCode::CONFLICT, body))
            if (body.0)["error"] == idempotency_in_progress_error().1.0["error"] =>
        {
            expire_idempotency_lease(&state.db, &key_create).await;
            create_paas_app(
                internal_test_auth(),
                State(state.clone()),
                Path(paas_id.clone()),
                create_headers,
                Json(InternalCreateAppRequest {
                    name: app_name.clone(),
                    unlock_mode: "password".into(),
                    bootstrap_pubkey_hash: Some("00".repeat(32)),
                    signer_identity_subject: None,
                    signer_identity_issuer: None,
                    egress_allowlist: vec![],
                    egress_mode: crate::routes::apps::default_egress_mode(),
                    resources: None,
                }),
            )
            .await
        }
        other => other,
    };
    match recreate {
        Err((StatusCode::CONFLICT, body)) => {
            assert_eq!(
                body["error"], "stale_owner_seed",
                "recreate must be refused with the stale-owner-seed guard"
            );
        }
        other => panic!("expected 409 stale_owner_seed, got {other:?}"),
    }
}

#[tokio::test]
async fn successful_teardown_persists_completion_marker() {
    let (state, _auth, _app_name, app_id) = app_delete_fixture().await;
    let app: crate::models::App = sqlx::query_as("SELECT * FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = axum::Router::new().route(
        "/.well-known/confidential/teardown",
        axum::routing::post(|| async {
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "teardown_complete"})),
            )
        }),
    );
    let task = tokio::spawn(async move { axum::serve(listener, server).await.unwrap() });
    let mut teardown_state = state.clone();
    teardown_state.tee_http_client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{address}/.well-known/confidential/teardown");
    let result =
        crate::routes::apps::post_workload_teardown(&teardown_state, &app, "teardown-token", &url)
            .await;
    task.abort();
    result.expect("successful teardown must not fail the delete");
    let completed_at: Option<chrono::DateTime<chrono::Utc>> =
        sqlx::query_scalar("SELECT workload_teardown_completed_at FROM apps WHERE id = $1")
            .bind(app_id)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert!(
        completed_at.is_some(),
        "a 2xx teardown must persist the durable completion marker"
    );
}

#[tokio::test]
async fn untyped_post_lease_five_xx_fails_closed_without_reexecution() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let hash = Sha256::digest(b"untyped-five-xx-request").to_vec();
    let recoveries = [
        IdempotencyRecovery::RetrySafe,
        IdempotencyRecovery::DeterministicResource {
            legacy_identity_bound: true,
        },
        IdempotencyRecovery::FailClosed,
    ];
    for (index, recovery) in recoveries.into_iter().enumerate() {
        let key = format!("untyped-five-xx-fail-closed-{suffix}-{index}");
        let path = format!("/internal/test/untyped-five-xx-fail-closed/{suffix}/{index}");
        let side_effects = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let lease = expect_idempotency_execution(
            begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
                .await
                .expect("reserve generic post-lease handler"),
        );
        let attempt_side_effects = side_effects.clone();
        let result: Result<IdempotencyResponse, InternalRouteError> = async move {
            attempt_side_effects.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(json_error(
                StatusCode::BAD_GATEWAY,
                "untyped post-lease failure",
            ))
        }
        .await;
        let terminal = complete_idempotent_result(lease, result)
            .await
            .expect_err("an untyped 5xx must fail closed");
        assert_eq!(terminal.0, StatusCode::CONFLICT);
        assert_eq!(terminal.1["error"], "idempotency_recovery_required");
        assert_eq!(terminal.1["retryable"], false);
        assert_eq!(terminal.1["idempotency_disposition"], "completed");

        let replay = expect_idempotency_replay(
            begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
                .await
                .expect("the unknown outcome is terminal and replayable"),
        );
        assert_eq!(replay, (terminal.0, terminal.1.0.clone()));
        assert_eq!(
            side_effects.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an untyped unknown outcome must never be re-executed"
        );
    }
}

#[tokio::test]
async fn five_xx_in_config_token_path_cancels_bounded_proof_reclaim_intact() {
    // DeterministicExpiringCapability routes complete via
    // `complete_deterministic_config_token_result`, NOT
    // `complete_idempotent_result`. A handler 5xx there cancels the
    // reservation (row deleted) and returns the raw error unstamped -- A-2's
    // 5xx-defer does not apply. The bounded-proof reclaim rules (regenerate
    // within validity, terminalize after expiry) act only on incomplete rows
    // left by timeouts/regenerate, which a handler 5xx never produces, so
    // they are structurally isolated from A-2.
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("five-xx-config-token-{suffix}");
    let app = format!("app-{suffix}");
    let path = format!("/internal/paas/orgs/org-{suffix}/apps/{app}/config-token");
    let hash = Sha256::digest(b"five-xx-config-token-request").to_vec();
    let binding = test_config_token_binding();

    let lease = expect_idempotency_execution(
        begin_test_config_token_receipt(&state, &key, &path, &hash, &binding)
            .await
            .expect("reserve config-token handler"),
    );
    let result: Result<IdempotencyResponse, InternalRouteError> =
        Err(json_error(StatusCode::BAD_GATEWAY, "upstream signer 5xx"));
    let failure = complete_deterministic_config_token_result(lease, async move { result })
        .await
        .expect_err("config-token 5xx returned raw");
    assert_eq!(failure.0, StatusCode::BAD_GATEWAY);
    assert_eq!(failure.1["error"], "upstream signer 5xx");
    assert!(
        failure.1.get("idempotency_disposition").is_none(),
        "DEC path does not stamp or defer at the completion boundary"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*)
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect cancelled row");
    assert_eq!(
        count, 0,
        "config-token 5xx cancels the reservation, leaving no row to reclaim"
    );
}

#[tokio::test]
async fn five_xx_in_capability_path_defers_preserving_capability_lease() {
    // A handler 5xx during capability issuance is an unknown outcome, so
    // defer (leave the row incomplete). But unlike the generic defer in
    // `complete_idempotent_result`, the capability's DB-authored lease hold
    // (`lease_seconds()` = `recovery_after_seconds`) must be PRESERVED --
    // not shortened to the ~5 s generic retry interval -- so reclaim holds
    // the capability window instead of collapsing to `recovery_required`
    // seconds after a transient 5xx. `complete_expiring_capability_result`
    // intercepts the 5xx before delegating for exactly this reason.
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("five-xx-capability-{suffix}");
    let path = format!("/internal/paas/orgs/org-{suffix}/apps/app-{suffix}/signer/rotation-token");
    let hash = Sha256::digest(b"five-xx-capability-request").to_vec();
    // A deliberately long window so the NOT-shortened invariant is
    // observable: the generic defer would set lease_expires_at to ~now+5s;
    // the preserved lease stays near now + recovery_after_seconds.
    let recovery = IdempotencyRecovery::ExpiringCapability {
        recovery_after_seconds: 600,
    };
    let lease = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .expect("reserve capability handler"),
    );
    let result: Result<IdempotencyResponse, InternalRouteError> =
        async { Err(json_error(StatusCode::BAD_GATEWAY, "signing service 5xx")) }.await;
    let deferred = complete_expiring_capability_result(lease, result)
        .await
        .expect_err("5xx defers, preserving the capability lease");
    // Same stamped deferred body as the generic defer path.
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(deferred.1["error"], "idempotency_request_in_progress");
    assert_eq!(deferred.1["idempotency_disposition"], "deferred");
    assert_eq!(deferred.1["retryable"], true);

    // Row is incomplete AND the lease hold was NOT shortened: it stays near
    // now + recovery_after_seconds (600s), not now + IDEMPOTENCY_RETRY_DEFER_SECONDS (5s).
    let (completed, lease_expires_at): (bool, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as(
            "SELECT completed_at IS NOT NULL, lease_expires_at
                   FROM cap_internal_idempotency
                  WHERE idempotency_key = $1",
        )
        .bind(&key)
        .fetch_one(&pool)
        .await
        .expect("inspect deferred capability row");
    assert!(!completed, "5xx must not cache a capability result");
    let now = chrono::Utc::now();
    let expires_at = lease_expires_at.expect("lease_expires_at is set");
    // The bug would set this to ~now+5s; the fix preserves ~now+600s. A
    // 300s threshold cleanly separates them and tolerates DB/app clock skew.
    assert!(
        expires_at > now + chrono::Duration::seconds(300),
        "capability lease must be preserved (~now+600s), not shortened to the ~5s generic defer; got {expires_at}"
    );

    // Same-key retry within the window -> still in-progress (lease not expired).
    let in_progress =
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .err()
            .expect("live capability window blocks same-key retry");
    assert_eq!(in_progress.1.0["error"], "idempotency_request_in_progress");
    assert_eq!(in_progress.1.0["idempotency_disposition"], "deferred");

    // After the window elapses, reclaim terminalizes recovery_required.
    expire_idempotency_lease(&pool, &key).await;
    let terminal = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(&state, &key, "POST", &path, &hash, recovery)
            .await
            .expect("expired capability closes with recovery_required"),
    );
    assert_eq!(terminal.0, StatusCode::CONFLICT);
    assert_eq!(terminal.1["error"], "idempotency_recovery_required");
    assert_eq!(terminal.1["retryable"], false);
}

#[tokio::test]
async fn pre_lease_error_bypasses_idempotency_boundary_uncached_and_unstamped() {
    // Errors raised before lease acquisition (validation, auth, the
    // deploy-path entitlement gate) early-return and never reach the
    // completion boundary, so they carry no disposition stamp and create no
    // idempotency row -- the contract's conservative "missing field"
    // fallback. This is status-agnostic: a pre-lease 5xx (e.g. a DB failure
    // in `require_deploy_entitlement`'s read) follows the identical
    // no-lease path and remains retryable. The 400 here is the cheapest
    // deterministic pre-lease trigger.
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("pre-lease-{suffix}");

    let failure = upsert_paas_org(
        internal_test_auth(),
        State(state),
        Path(format!(" padded-{suffix} ")),
        idempotency_headers(&key),
        Json(UpsertPaaSOrgRequest {
            name: format!("pre-lease-org-{suffix}"),
            display_name: None,
            status: "active".to_string(),
        }),
    )
    .await
    .expect_err("pre-lease validation rejects the padded path segment");
    assert_eq!(failure.0, StatusCode::BAD_REQUEST);
    assert!(
        failure.1.get("idempotency_disposition").is_none(),
        "pre-lease errors are unstamped"
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*)
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect idempotency rows");
    assert_eq!(count, 0, "pre-lease rejection creates no idempotency row");
}

#[tokio::test]
async fn unsafe_legacy_recovery_terminalizes_with_nonretryable_disposition() {
    let pool = database_test_pool().await;
    let state = idempotency_test_state(pool.clone());
    let suffix = Uuid::new_v4().simple().to_string();
    let key = format!("fail-closed-{suffix}");
    let path = format!("/internal/test/fail-closed/{suffix}");
    let hash = Sha256::digest(b"fail-closed-request").to_vec();
    sqlx::query(
        "INSERT INTO cap_internal_idempotency
                 (idempotency_key, method, path, request_hash, updated_at)
             VALUES ($1, 'POST', $2, $3, clock_timestamp() - interval '1 day')",
    )
    .bind(&key)
    .bind(&path)
    .bind(&hash)
    .execute(&pool)
    .await
    .expect("seed abandoned unsafe legacy reservation");

    let first = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "POST",
            &path,
            &hash,
            IdempotencyRecovery::FailClosed,
        )
        .await
        .expect("terminalize unsafe legacy reservation"),
    );
    assert_eq!(first.0, StatusCode::CONFLICT);
    assert_eq!(first.1["error"], "idempotency_recovery_required");
    assert_eq!(first.1["retryable"], false);
    assert_eq!(first.1["disposition"], "reconcile_then_retry_with_new_key");
    // The terminal body carries the completed disposition marker so a
    // disposition-driven PaaS terminalizes through the completed channel;
    // the cached row replays verbatim on a same-key retry.
    assert_eq!(first.1["idempotency_disposition"], "completed");
    assert_eq!(
        expect_idempotency_replay(
            begin_idempotent_request_with_recovery(
                &state,
                &key,
                "POST",
                &path,
                &hash,
                IdempotencyRecovery::FailClosed,
            )
            .await
            .expect("replay terminal legacy disposition")
        ),
        first
    );

    let persisted: (bool, i32, String) = sqlx::query_as(
        "SELECT completed_at IS NOT NULL, attempt_count, recovery_kind
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect terminal legacy disposition");
    assert_eq!(persisted, (true, 1, "fail_closed".to_string()));
}

#[tokio::test]
async fn create_app_adopts_only_the_exact_operation_after_response_loss() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("idemapp{}", &suffix[..8]);
    let paas_org_id = format!("paas-app-recovery-{suffix}");
    insert_mapped_org(&pool, org_id, &org_name, &paas_org_id).await;
    sqlx::query(
        "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
    )
    .bind(org_id)
    .bind(&paas_org_id)
    .execute(&pool)
    .await
    .expect("mark app recovery org PaaS-managed");
    sqlx::query(
        "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
    )
    .bind(org_id)
    .bind(serde_json::json!({
        "name": "app-recovery-test",
        "max_apps": 10,
        "max_cpu": "10",
        "max_memory": "10Gi",
        "max_storage": "100Gi"
    }))
    .execute(&pool)
    .await
    .expect("insert app recovery entitlement");

    let state = idempotency_test_state(pool.clone());
    let key = format!("create-app-recovery-{suffix}");
    let body = InternalCreateAppRequest {
        name: format!("recover{}", &suffix[..8]),
        unlock_mode: "password".to_string(),
        bootstrap_pubkey_hash: Some("a".repeat(64)),
        signer_identity_subject: None,
        signer_identity_issuer: None,
        egress_allowlist: Vec::new(),
        egress_mode: "restricted".to_string(),
        resources: None,
    };
    let first = create_paas_app(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state.clone()),
        Path(paas_org_id.clone()),
        idempotency_headers(&key),
        Json(body),
    )
    .await
    .expect("create app before simulated response loss");
    assert_eq!(first.0, StatusCode::CREATED);
    let first_response = first.1.0;
    let app_id = first_response["cap_app_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("created app ID");

    let token: Uuid = sqlx::query_scalar(
        "SELECT reservation_token
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("load completed app reservation token");
    let mut tx = pool
        .begin()
        .await
        .expect("begin simulated response-loss update");
    set_idempotency_completion_owner(&mut tx, token)
        .await
        .expect("prove simulated response-loss owner");
    sqlx::query(
        "UPDATE cap_internal_idempotency
                SET response_status = NULL,
                    response_body = NULL,
                    completed_at = NULL,
                    lease_expires_at = clock_timestamp() - interval '1 minute',
                    updated_at = clock_timestamp() - interval '1 minute'
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .execute(&mut *tx)
    .await
    .expect("simulate committed app with lost response");
    tx.commit().await.expect("commit simulated response loss");

    let retry_body = InternalCreateAppRequest {
        name: format!("recover{}", &suffix[..8]),
        unlock_mode: "password".to_string(),
        bootstrap_pubkey_hash: Some("a".repeat(64)),
        signer_identity_subject: None,
        signer_identity_issuer: None,
        egress_allowlist: Vec::new(),
        egress_mode: "restricted".to_string(),
        resources: None,
    };
    let retried = create_paas_app(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state),
        Path(paas_org_id),
        idempotency_headers(&key),
        Json(retry_body),
    )
    .await
    .expect("adopt exact app after response loss");
    assert_eq!(retried.0, StatusCode::CREATED);
    assert_eq!(retried.1.0, first_response);

    let authority: (i64, i64, i32) = sqlx::query_as(
        "SELECT
                 (SELECT count(*) FROM apps WHERE id = $1),
                 (SELECT count(*) FROM apps WHERE org_id = $2 AND name = $3),
                 (SELECT attempt_count FROM cap_internal_idempotency
                   WHERE idempotency_key = $4)",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(format!("recover{}", &suffix[..8]))
    .bind(&key)
    .fetch_one(&pool)
    .await
    .expect("inspect exact app adoption authority");
    assert_eq!(authority, (1, 1, 2));
}

#[tokio::test]
async fn generic_deployment_setup_pending_stays_retriable_then_adopts_exactly() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let deployment_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("idemdeploy{}", &suffix[..8]);
    let paas_org_id = format!("paas-deploy-recovery-{suffix}");
    let paas_user_id = format!("paas-deploy-user-{suffix}");
    let app_name = format!("recover{}", &suffix[..8]);
    let repository = "acme/confidential-app";
    let image = "ghcr.io/acme/confidential-app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let signer_subject =
        "https://github.com/acme/confidential-app/.github/workflows/build.yml@refs/heads/main";
    let signer_issuer = "https://token.actions.githubusercontent.com";
    insert_mapped_org(&pool, org_id, &org_name, &paas_org_id).await;
    sqlx::query(
        "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
    )
    .bind(org_id)
    .bind(&paas_org_id)
    .execute(&pool)
    .await
    .expect("mark deployment recovery org PaaS-managed");
    sqlx::query(
        "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
    )
    .bind(org_id)
    .bind(serde_json::json!({
        "name": "deployment-recovery-test",
        "max_apps": 10,
        "max_cpu": "10",
        "max_memory": "10Gi",
        "max_storage": "100Gi"
    }))
    .execute(&pool)
    .await
    .expect("insert deployment recovery entitlement");
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Deploy Recovery User')")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert deployment recovery user");
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
    )
    .bind(&paas_user_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("map deployment recovery user");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role)
             VALUES ($1, $2, 'owner')",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("authorize deployment recovery user");
    sqlx::query(
        "INSERT INTO apps (
                 id, org_id, name, namespace, instance_id, tenant_id,
                 service_account, bootstrap_owner_pubkey_hash,
                 tenant_instance_identity_hash, domain, tee_domain,
                 signer_identity_subject, signer_identity_issuer,
                 source_provider, source_repository, egress_allowlist, egress_mode
             ) VALUES (
                 $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,
                 $12, $13, 'github', $14, '[]'::jsonb, 'restricted'
             )",
    )
    .bind(app_id)
    .bind(org_id)
    .bind(&app_name)
    .bind(format!("cap-{org_name}-{app_name}"))
    .bind(format!("{org_name}-{}", &app_id.simple().to_string()[..8]))
    .bind(&org_name)
    .bind(format!("cap-{app_name}-sa"))
    .bind("11".repeat(32))
    .bind("22".repeat(32))
    .bind(format!("{app_name}.{org_name}.enclava.test"))
    .bind(format!("{app_name}.{org_name}.tee.enclava.test"))
    .bind(signer_subject)
    .bind(signer_issuer)
    .bind(repository)
    .execute(&pool)
    .await
    .expect("insert exact generic deployment app");

    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    let key = format!("generic-deploy-recovery-{suffix}");
    let path = format!("/internal/paas/orgs/{paas_org_id}/deployments");
    let body = serde_json::json!({
        "app": {
            "name": app_name,
            "create_if_missing": false,
            "unlock_mode": "password",
            "egress_allowlist": [],
            "egress_mode": "restricted"
        },
        "source": {
            "provider": "github",
            "repository": repository
        },
        "workload": {
            "image": image,
            "container_name": null,
            "resources": null
        },
        "signing": {
            "subject": signer_subject,
            "issuer": signer_issuer
        },
        "security": {
            "workload_security_profile": null,
            "log_encryption": null
        }
    });
    let mut headers = idempotency_headers(&key);
    headers.insert(
        "x-enclava-paas-user-id",
        HeaderValue::from_str(&paas_user_id).expect("valid deployment actor header"),
    );
    let auth = internal_actor_context(&state, &paas_org_id, &headers)
        .await
        .expect("resolve deployment recovery actor");
    let first = expect_idempotency_execution(
        begin_actor_idempotent_request(
            &state,
            &headers,
            "POST",
            &path,
            &auth,
            &body,
            IdempotencyRecovery::DeterministicResource {
                legacy_identity_bound: false,
            },
        )
        .await
        .expect("reserve generic deployment before response loss"),
    );
    let external_id = idempotency_deployment_external_id(first.operation_id());
    drop(first);
    let mut deployment_tx = pool
        .begin()
        .await
        .expect("begin durable pending deployment seed");
    sqlx::query(
        "INSERT INTO deployments (
                 id, org_id, app_id, trigger, status, spec_snapshot,
                 image_digest, cosign_verified, external_id,
                 source_provider, source_repository
             ) VALUES (
                 $1, $2, $3, 'api', 'pending', $4, $5, true, $6,
                 'github', $7
             )",
    )
    .bind(deployment_id)
    .bind(org_id)
    .bind(app_id)
    .bind(serde_json::json!({
        "app_name": app_name,
        "image": image,
        "container_name": "web",
        "resources": null,
        "external_id": external_id,
        "workload_security_profile": "restricted",
        "log_encryption": null,
        "setup_state": "dns_pending"
    }))
    .bind("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind(&external_id)
    .bind(repository)
    .execute(&mut *deployment_tx)
    .await
    .expect("seed committed deployment with setup pending");
    sqlx::query(
        "INSERT INTO deployment_apply_jobs (
                 deployment_id, app_id, org_id, source_deployment_id,
                 payload_version, payload, payload_sha256,
                 cleanup_app_on_setup_failure, signed_required,
                 log_encryption, state
             ) VALUES (
                 $1, $2, $3, $1, 1, $4, $5,
                 false, false, NULL, 'setup_pending'
             )",
    )
    .bind(deployment_id)
    .bind(app_id)
    .bind(org_id)
    .bind(serde_json::json!({"version": 1, "log_encryption": null}))
    .bind(vec![0_u8; 32])
    .execute(&mut *deployment_tx)
    .await
    .expect("seed durable pending deployment apply job");
    deployment_tx
        .commit()
        .await
        .expect("commit durable pending deployment seed");
    expire_idempotency_lease(&pool, &key).await;

    let pending = create_paas_generic_deployment(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(body.clone()),
    )
    .await
    .expect_err("setup-pending exact deployment remains retriable");
    assert_eq!(pending.0, StatusCode::CONFLICT);
    assert_eq!(pending.1.0["error"], "idempotency_request_in_progress");
    assert_eq!(pending.1.0["retryable"], true);
    assert_eq!(pending.1.0["disposition"], "retry_same_key");
    // The central in-progress helper carries the `deferred` stamp on every
    // path -- including this live-lease retry through
    // `begin_idempotent_request_with_recovery`, not only the explicit
    // defer/cancel paths.
    assert_eq!(pending.1.0["idempotency_disposition"], "deferred");
    let pending_authority: (bool, i64, i32) = sqlx::query_as(
        "SELECT completed_at IS NULL,
                    (SELECT count(*) FROM deployments WHERE external_id = $2),
                    attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .bind(&external_id)
    .fetch_one(&pool)
    .await
    .expect("inspect deferred generic deployment recovery");
    assert_eq!(pending_authority, (true, 1, 2));

    sqlx::query(
        "UPDATE deployments
                SET spec_snapshot = jsonb_set(
                    spec_snapshot,
                    '{setup_state}',
                    to_jsonb($2::text)
                )
              WHERE id = $1",
    )
    .bind(deployment_id)
    .bind("accepted")
    .execute(&pool)
    .await
    .expect("accept durable deployment setup");
    sqlx::query(
        "UPDATE deployment_apply_jobs
                SET state = 'pending', updated_at = clock_timestamp()
              WHERE deployment_id = $1",
    )
    .bind(deployment_id)
    .execute(&pool)
    .await
    .expect("advance durable deployment job after setup acceptance");
    expire_idempotency_lease(&pool, &key).await;
    let adopted = create_paas_generic_deployment(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state),
        Path(paas_org_id),
        headers,
        Json(body),
    )
    .await
    .expect("adopt exact deployment after durable setup accepts");
    assert_eq!(adopted.0, StatusCode::OK);
    assert_eq!(adopted.1.0["deployment_id"], deployment_id.to_string());
    assert_eq!(adopted.1.0["app_id"], app_id.to_string());

    let completed_authority: (bool, i64, i32) = sqlx::query_as(
        "SELECT completed_at IS NOT NULL,
                    (SELECT count(*) FROM deployments WHERE external_id = $2),
                    attempt_count
               FROM cap_internal_idempotency
              WHERE idempotency_key = $1",
    )
    .bind(&key)
    .bind(&external_id)
    .fetch_one(&pool)
    .await
    .expect("inspect completed exact deployment adoption");
    assert_eq!(completed_authority, (true, 1, 3));
}

#[tokio::test]
async fn membership_idempotency_key_cannot_replay_across_tenants() {
    let pool = database_test_pool().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let suffix = org_a.simple().to_string();
    let paas_org_a = format!("paas-idem-a-{suffix}");
    let paas_org_b = format!("paas-idem-b-{suffix}");
    let paas_user_a = format!("paas-idem-user-a-{suffix}");
    let paas_user_b = format!("paas-idem-user-b-{suffix}");
    insert_mapped_org(
        &pool,
        org_a,
        &format!("member-idem-a-{suffix}"),
        &paas_org_a,
    )
    .await;
    insert_mapped_org(
        &pool,
        org_b,
        &format!("member-idem-b-{suffix}"),
        &paas_org_b,
    )
    .await;

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let key = format!("membership-cross-tenant-{suffix}");
    let (_, Json(first_response)) = sync_member(
        &state,
        &paas_org_a,
        &paas_user_a,
        &key,
        member_request("Shared Display", "member", true, 1),
    )
    .await
    .expect("apply first tenant membership sync");
    assert_eq!(first_response["cap_org_id"], org_a.to_string());

    let reused = sync_member(
        &state,
        &paas_org_b,
        &paas_user_b,
        &key,
        member_request("Shared Display", "member", true, 1),
    )
    .await
    .expect_err("same key on another tenant path must not replay");
    assert_eq!(reused.0, StatusCode::CONFLICT);
    assert_eq!(reused.1.0["error"], "idempotency_key_reused");

    let second_tenant_rows: (i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT count(*) FROM paas_external_mappings
                   WHERE resource_type = 'user' AND paas_external_id = $1),
                 (SELECT count(*) FROM memberships WHERE org_id = $2),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $2 AND action = 'org.member.sync')",
    )
    .bind(&paas_user_b)
    .bind(org_b)
    .fetch_one(&pool)
    .await
    .expect("inspect rejected cross-tenant replay");
    assert_eq!(second_tenant_rows, (0, 0, 0));
}

#[tokio::test]
async fn membership_transaction_rollback_does_not_strand_idempotency_reservation() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let missing_user_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let paas_org_id = format!("paas-rollback-org-{suffix}");
    let paas_user_id = format!("paas-rollback-user-{suffix}");
    insert_mapped_org(
        &pool,
        org_id,
        &format!("member-rollback-{suffix}"),
        &paas_org_id,
    )
    .await;
    // User mappings intentionally have no user FK. Seed a legacy corrupt
    // mapping so the membership FK fails after the transaction reserves
    // the idempotency key.
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
    )
    .bind(&paas_user_id)
    .bind(missing_user_id)
    .execute(&pool)
    .await
    .expect("seed missing-user mapping");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let key = format!("membership-rollback-{suffix}");
    let failed = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &key,
        member_request("Missing User", "member", true, 1),
    )
    .await
    .expect_err("membership FK failure must roll back the request");
    assert_eq!(failed.0, StatusCode::INTERNAL_SERVER_ERROR);

    let rolled_back: (i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT count(*) FROM cap_internal_idempotency
                   WHERE idempotency_key = $1),
                 (SELECT count(*) FROM paas_membership_sync_state
                   WHERE org_id = $2),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $2 AND action = 'org.member.sync')",
    )
    .bind(&key)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("inspect rolled-back membership request");
    assert_eq!(rolled_back, (0, 0, 0));
}

#[tokio::test]
async fn concurrent_same_key_membership_sync_has_one_mutation_and_audit() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let paas_org_id = format!("paas-same-key-org-{suffix}");
    let paas_user_id = format!("paas-same-key-user-{suffix}");
    insert_mapped_org(
        &pool,
        org_id,
        &format!("member-same-key-{suffix}"),
        &paas_org_id,
    )
    .await;

    let application_name = format!("member-same-key-{suffix}");
    let mut state = crate::test_support::lazy_state();
    state.db = named_database_test_pool(&application_name).await;
    let mut blocker = pool.begin().await.expect("begin same-key mapping blocker");
    lock_paas_user_mapping_lane(&mut blocker, &paas_user_id)
        .await
        .expect("block same-key mapping lane");

    let key = format!("membership-same-key-{suffix}");
    let spawn_writer = |state: AppState| {
        let paas_org_id = paas_org_id.clone();
        let paas_user_id = paas_user_id.clone();
        let key = key.clone();
        tokio::spawn(async move {
            sync_member(
                &state,
                &paas_org_id,
                &paas_user_id,
                &key,
                member_request("One Member", "admin", true, 1),
            )
            .await
        })
    };
    let writer_a = spawn_writer(state.clone());
    let writer_b = spawn_writer(state);
    wait_for_named_lock_waiters(&pool, &application_name, 2).await;
    blocker
        .commit()
        .await
        .expect("release same-key mapping lane");

    let (status_a, Json(response_a)) = writer_a
        .await
        .expect("join first same-key writer")
        .expect("first same-key writer succeeds");
    let (status_b, Json(response_b)) = writer_b
        .await
        .expect("join second same-key writer")
        .expect("second same-key writer replays");
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(status_b, StatusCode::OK);
    assert_eq!(response_a, response_b);

    let committed: (i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT
                 (SELECT count(*) FROM cap_internal_idempotency
                   WHERE idempotency_key = $1 AND completed_at IS NOT NULL),
                 (SELECT count(*) FROM paas_external_mappings
                   WHERE resource_type = 'user' AND paas_external_id = $2),
                 (SELECT count(*) FROM memberships WHERE org_id = $3),
                 (SELECT count(*) FROM paas_membership_sync_state WHERE org_id = $3),
                 (SELECT count(*) FROM audit_log
                   WHERE org_id = $3 AND action = 'org.member.sync')",
    )
    .bind(&key)
    .bind(&paas_user_id)
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("inspect concurrent same-key authority");
    assert_eq!(committed, (1, 1, 1, 1, 1));
}

#[tokio::test]
async fn exact_membership_replay_repairs_legacy_projection_before_success() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let paas_org_id = format!("paas-repair-org-{suffix}");
    let paas_user_id = format!("paas-repair-user-{suffix}");
    insert_mapped_org(
        &pool,
        org_id,
        &format!("member-repair-{suffix}"),
        &paas_org_id,
    )
    .await;
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Removed Member')")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert legacy split-brain user");
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id)
             VALUES ('user', $1, $2)",
    )
    .bind(&paas_user_id)
    .bind(user_id)
    .execute(&pool)
    .await
    .expect("map legacy split-brain user");
    sqlx::query(
        "INSERT INTO memberships (user_id, org_id, role, removed_at)
             VALUES ($1, $2, 'owner', NULL)",
    )
    .bind(user_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("seed stale active owner projection");
    sqlx::query(
        "INSERT INTO paas_membership_sync_state
                 (org_id, user_id, paas_user_id, role, version, active)
             VALUES ($1, $2, $3, 'member', 2, false)",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(&paas_user_id)
    .execute(&pool)
    .await
    .expect("seed latest inactive membership authority");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let (status, _) = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &format!("membership-repair-{suffix}"),
        member_request("Removed Member", "member", false, 2),
    )
    .await
    .expect("exact latest replay repairs stale membership projection");
    assert_eq!(status, StatusCode::OK);

    let repaired: (String, bool, i64, String, bool, serde_json::Value) = sqlx::query_as(
        "SELECT m.role::text,
                    m.removed_at IS NULL,
                    pms.version,
                    pms.role,
                    pms.active,
                    audit.detail
               FROM memberships m
               JOIN paas_membership_sync_state pms
                 ON pms.org_id = m.org_id AND pms.user_id = m.user_id
               JOIN LATERAL (
                    SELECT detail FROM audit_log
                     WHERE org_id = m.org_id
                       AND user_id = m.user_id
                       AND action = 'org.member.sync'
                     ORDER BY id DESC LIMIT 1
               ) audit ON TRUE
              WHERE m.org_id = $1 AND m.user_id = $2",
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_one(&pool)
    .await
    .expect("load repaired membership projection");
    assert_eq!(
        repaired,
        (
            "member".to_string(),
            false,
            2,
            "member".to_string(),
            false,
            serde_json::json!({
                "role": "member",
                "active": false,
                "version": 2,
                "client_san": "spiffe://paas.example.test/enclava-paas",
                "repair": "legacy_membership_projection",
            }),
        )
    );

    let mut actor_headers = HeaderMap::new();
    actor_headers.insert(
        "x-enclava-paas-user-id",
        HeaderValue::from_str(&paas_user_id).expect("valid actor header"),
    );
    let rejected = internal_actor_context(&state, &paas_org_id, &actor_headers)
        .await
        .expect_err("repaired removed member cannot remain authorized");
    assert_eq!(rejected.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn membership_sync_rejects_stale_or_divergent_authority_and_replays_exactly() {
    let pool = database_test_pool().await;
    let org_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("member-authority-{suffix}");
    let paas_org_id = format!("paas-org-{suffix}");
    let paas_user_id = format!("paas-user-{suffix}");
    crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
        .await
        .expect("insert membership authority org");
    sqlx::query(
        "INSERT INTO paas_external_mappings
                 (resource_type, paas_external_id, cap_id, org_id)
             VALUES ('organization', $1, $2, $2)",
    )
    .bind(&paas_org_id)
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("map membership authority org");

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let _ = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &format!("member-v1-{suffix}"),
        member_request("Initial Owner", "owner", true, 1),
    )
    .await
    .expect("apply initial membership authority");
    let _ = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &format!("member-v2-{suffix}"),
        member_request("Removed Member", "member", false, 2),
    )
    .await
    .expect("apply membership removal and demotion");

    sqlx::query(
        "UPDATE memberships
                SET role = 'owner', removed_at = NULL
              WHERE org_id = $1",
    )
    .bind(org_id)
    .execute(&pool)
    .await
    .expect("seed stale active-owner projection before stale delivery");

    let stale_key = format!("member-stale-{suffix}");
    let stale = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &stale_key,
        member_request("Stale Re-Escalation", "owner", true, 1),
    )
    .await
    .expect_err("stale membership reactivation must fail");
    assert_eq!(stale.0, StatusCode::CONFLICT);
    assert_eq!(stale.1.0["error"], "membership version is stale");
    assert_eq!(stale.1.0["idempotency_disposition"], "completed");
    assert_eq!(stale.1.0["retryable"], false);
    let (stale_retry_status, Json(stale_retry_body)) = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &stale_key,
        member_request("Stale Re-Escalation", "owner", true, 1),
    )
    .await
    .expect("stale membership error replay is completed");
    assert_eq!(stale_retry_status, StatusCode::CONFLICT);
    assert_eq!(stale_retry_body["error"], "membership version is stale");
    assert_eq!(stale_retry_body["idempotency_disposition"], "completed");
    assert_eq!(stale_retry_body["retryable"], false);

    let _ = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &format!("member-v2-replay-{suffix}"),
        member_request("Removed Member", "member", false, 2),
    )
    .await
    .expect("exact same-version membership replay is idempotent");

    let divergent_key = format!("member-v2-divergent-{suffix}");
    let divergent = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &divergent_key,
        member_request("Removed Member", "owner", true, 2),
    )
    .await
    .expect_err("same-version divergent membership authority must fail");
    assert_eq!(divergent.0, StatusCode::CONFLICT);
    assert_eq!(
        divergent.1.0["error"],
        "membership version already exists with different content"
    );
    assert_eq!(divergent.1.0["idempotency_disposition"], "completed");
    assert_eq!(divergent.1.0["retryable"], false);
    let (divergent_retry_status, Json(divergent_retry_body)) = sync_member(
        &state,
        &paas_org_id,
        &paas_user_id,
        &divergent_key,
        member_request("Removed Member", "owner", true, 2),
    )
    .await
    .expect("divergent membership error replay is completed");
    assert_eq!(divergent_retry_status, StatusCode::CONFLICT);
    assert_eq!(
        divergent_retry_body["error"],
        "membership version already exists with different content"
    );
    assert_eq!(divergent_retry_body["idempotency_disposition"], "completed");
    assert_eq!(divergent_retry_body["retryable"], false);

    let authority: (String, bool, i64, String, bool, String) = sqlx::query_as(
        "SELECT m.role::text,
                    m.removed_at IS NULL,
                    pms.version,
                    pms.role,
                    pms.active,
                    u.display_name
               FROM paas_membership_sync_state pms
               JOIN memberships m
                 ON m.org_id = pms.org_id AND m.user_id = pms.user_id
               JOIN users u ON u.id = pms.user_id
              WHERE pms.org_id = $1",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("load final membership authority");
    assert_eq!(
        authority,
        (
            "member".to_string(),
            false,
            2,
            "member".to_string(),
            false,
            "Removed Member".to_string(),
        ),
        "stale and divergent deliveries must not reactivate, re-escalate, or rename the member"
    );

    let audits: Vec<(i64, String, bool, serde_json::Value)> = sqlx::query_as(
        "SELECT (detail->>'version')::bigint,
                    detail->>'role',
                    (detail->>'active')::boolean,
                    detail
               FROM audit_log
              WHERE org_id = $1 AND action = 'org.member.sync'
              ORDER BY id",
    )
    .bind(org_id)
    .fetch_all(&pool)
    .await
    .expect("load membership authority audit");
    assert_eq!(
        audits,
        vec![
            (
                1,
                "owner".to_string(),
                true,
                serde_json::json!({
                    "role": "owner",
                    "active": true,
                    "version": 1,
                    "client_san": "spiffe://paas.example.test/enclava-paas",
                }),
            ),
            (
                2,
                "member".to_string(),
                false,
                serde_json::json!({
                    "role": "member",
                    "active": false,
                    "version": 2,
                    "client_san": "spiffe://paas.example.test/enclava-paas",
                }),
            ),
            (
                2,
                "member".to_string(),
                false,
                serde_json::json!({
                    "role": "member",
                    "active": false,
                    "version": 2,
                    "client_san": "spiffe://paas.example.test/enclava-paas",
                    "repair": "legacy_membership_projection",
                }),
            ),
        ],
        "only committed authority generations and repairs receive minimal audit rows without user plaintext"
    );
}

#[tokio::test]
async fn exact_org_replay_does_not_overwrite_global_display_from_another_org() {
    let pool = database_test_pool().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let suffix = org_a.simple().to_string();
    let paas_org_a = format!("paas-display-a-{suffix}");
    let paas_org_b = format!("paas-display-b-{suffix}");
    let paas_user_id = format!("paas-display-user-{suffix}");
    insert_mapped_org(
        &pool,
        org_a,
        &format!("member-display-a-{suffix}"),
        &paas_org_a,
    )
    .await;
    insert_mapped_org(
        &pool,
        org_b,
        &format!("member-display-b-{suffix}"),
        &paas_org_b,
    )
    .await;

    let mut state = crate::test_support::lazy_state();
    state.db = pool.clone();
    let _ = sync_member(
        &state,
        &paas_org_a,
        &paas_user_id,
        &format!("display-a-v1-{suffix}"),
        member_request("Display A", "member", true, 1),
    )
    .await
    .expect("sync user through first org");
    let _ = sync_member(
        &state,
        &paas_org_b,
        &paas_user_id,
        &format!("display-b-v1-{suffix}"),
        member_request("Display B", "member", true, 1),
    )
    .await
    .expect("sync newer global display through second org");
    let _ = sync_member(
        &state,
        &paas_org_a,
        &paas_user_id,
        &format!("display-a-replay-{suffix}"),
        member_request("Display A", "member", true, 1),
    )
    .await
    .expect("exact first-org authority replay remains idempotent");

    let state_after_replay: (String, i64) = sqlx::query_as(
        "SELECT u.display_name,
                    (SELECT count(*) FROM audit_log
                      WHERE org_id IN ($1, $2) AND action = 'org.member.sync')
               FROM users u
               JOIN paas_external_mappings m
                 ON m.resource_type = 'user' AND m.cap_id = u.id
              WHERE m.paas_external_id = $3",
    )
    .bind(org_a)
    .bind(org_b)
    .bind(&paas_user_id)
    .fetch_one(&pool)
    .await
    .expect("load global display after exact org replay");
    assert_eq!(state_after_replay, ("Display B".to_string(), 2));
}

#[tokio::test]
async fn concurrent_same_user_syncs_across_orgs_share_one_atomic_mapping() {
    let pool = database_test_pool().await;
    let org_a = Uuid::new_v4();
    let org_b = Uuid::new_v4();
    let suffix = org_a.simple().to_string();
    let paas_org_a = format!("paas-org-a-{suffix}");
    let paas_org_b = format!("paas-org-b-{suffix}");
    let paas_user_id = format!("paas-shared-user-{suffix}");
    let display_name = format!("Shared User {suffix}");
    for (org_id, org_name, paas_org_id) in [
        (org_a, format!("member-map-a-{suffix}"), &paas_org_a),
        (org_b, format!("member-map-b-{suffix}"), &paas_org_b),
    ] {
        crate::db::orgs::insert_org_pool(&pool, org_id, &org_name, None, false)
            .await
            .expect("insert concurrent mapping org");
        sqlx::query(
            "INSERT INTO paas_external_mappings
                     (resource_type, paas_external_id, cap_id, org_id)
                 VALUES ('organization', $1, $2, $2)",
        )
        .bind(paas_org_id)
        .bind(org_id)
        .execute(&pool)
        .await
        .expect("map concurrent membership org");
    }

    let application_name = format!("member-map-{suffix}");
    let writer_pool = named_database_test_pool(&application_name).await;
    let mut state = crate::test_support::lazy_state();
    state.db = writer_pool;

    let mut blocker = pool.begin().await.expect("begin user mapping blocker");
    lock_paas_user_mapping_lane(&mut blocker, &paas_user_id)
        .await
        .expect("block shared user mapping lane");

    let writer_a_state = state.clone();
    let writer_a_org = paas_org_a.clone();
    let writer_a_user = paas_user_id.clone();
    let writer_a_name = display_name.clone();
    let writer_a_key = format!("member-map-a-{suffix}");
    let writer_a = tokio::spawn(async move {
        sync_member(
            &writer_a_state,
            &writer_a_org,
            &writer_a_user,
            &writer_a_key,
            member_request(&writer_a_name, "owner", true, 1),
        )
        .await
    });
    let writer_b_state = state;
    let writer_b_org = paas_org_b.clone();
    let writer_b_user = paas_user_id.clone();
    let writer_b_name = display_name.clone();
    let writer_b_key = format!("member-map-b-{suffix}");
    let writer_b = tokio::spawn(async move {
        sync_member(
            &writer_b_state,
            &writer_b_org,
            &writer_b_user,
            &writer_b_key,
            member_request(&writer_b_name, "owner", true, 1),
        )
        .await
    });

    wait_for_named_lock_waiters(&pool, &application_name, 2).await;
    blocker.commit().await.expect("release user mapping lane");
    let _ = writer_a
        .await
        .expect("join first shared user sync")
        .expect("sync shared user into first org");
    let _ = writer_b
        .await
        .expect("join second shared user sync")
        .expect("sync shared user into second org");

    let mapping_count: i64 = sqlx::query_scalar(
        "SELECT count(*)
               FROM paas_external_mappings
              WHERE resource_type = 'user' AND paas_external_id = $1",
    )
    .bind(&paas_user_id)
    .fetch_one(&pool)
    .await
    .expect("count shared user mappings");
    assert_eq!(mapping_count, 1);
    let local_user_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM users WHERE display_name = $1")
            .bind(&display_name)
            .fetch_one(&pool)
            .await
            .expect("count shared local users");
    assert_eq!(local_user_count, 1, "no orphan duplicate user may survive");
    let authority: (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*),
                    count(DISTINCT user_id),
                    (SELECT count(*) FROM audit_log
                      WHERE org_id IN ($1, $2) AND action = 'org.member.sync')
               FROM paas_membership_sync_state
              WHERE org_id IN ($1, $2)",
    )
    .bind(org_a)
    .bind(org_b)
    .fetch_one(&pool)
    .await
    .expect("load shared membership authority");
    assert_eq!(authority, (2, 1, 2));
}

/// Canonical keyring bytes for the single-owner keyrings these tests sign.
/// Mirrors routes::orgs's private canonicalization (CE-v1 records) so a
/// signature made here verifies inside put_keyring / rotate_org_owner.
fn test_canonical_keyring_bytes(
    org_id: Uuid,
    version: u64,
    member: &(Uuid, [u8; 32], chrono::DateTime<chrono::Utc>),
    updated_at: &chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    let (user_id, pubkey, added_at) = member;
    let role = b"owner".to_vec();
    let added_at_bytes = added_at.to_rfc3339().into_bytes();
    let member_hash = enclava_common::canonical::ce_v1_hash(&[
        ("user_id", user_id.as_bytes().as_slice()),
        ("pubkey", pubkey.as_slice()),
        ("role", &role),
        ("added_at", &added_at_bytes),
    ]);
    let member_label = user_id.to_string();
    let members_hash =
        enclava_common::canonical::ce_v1_hash(&[(member_label.as_str(), member_hash.as_slice())]);
    let version_be = version.to_be_bytes();
    let updated_at_bytes = updated_at.to_rfc3339().into_bytes();
    enclava_common::canonical::ce_v1_bytes(&[
        ("purpose", b"enclava-org-keyring-v1"),
        ("org_id", org_id.as_bytes().as_slice()),
        ("version", &version_be),
        ("members", &members_hash),
        ("updated_at", &updated_at_bytes),
    ])
}

fn signed_keyring_body(
    org_id: Uuid,
    user_id: Uuid,
    key: &ed25519_dalek::SigningKey,
    version: i64,
    updated_second: u32,
) -> serde_json::Value {
    use chrono::TimeZone;
    use ed25519_dalek::Signer;
    let added_at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let updated_at = chrono::Utc
        .with_ymd_and_hms(2026, 1, 1, 0, 0, updated_second)
        .unwrap();
    let pubkey = key.verifying_key().to_bytes();
    let canonical = test_canonical_keyring_bytes(
        org_id,
        version as u64,
        &(user_id, pubkey, added_at),
        &updated_at,
    );
    let signature = key.sign(&canonical);
    serde_json::json!({
        "version": version,
        "keyring_payload": {
            "org_id": org_id,
            "version": version,
            "members": [{
                "user_id": user_id,
                "pubkey": hex::encode(pubkey),
                "role": "owner",
                "added_at": added_at,
            }],
            "updated_at": updated_at,
        },
        "signature": hex::encode(signature.to_bytes()),
        "signing_pubkey": hex::encode(pubkey),
    })
}

fn signed_rotation_body(
    org_id: Uuid,
    user_id: Uuid,
    current_key: &ed25519_dalek::SigningKey,
    replacement_key: &ed25519_dalek::SigningKey,
) -> serde_json::Value {
    use chrono::TimeZone;
    use ed25519_dalek::Signer;
    let added_at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let updated_at = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 1, 0).unwrap();
    let current_pubkey = current_key.verifying_key().to_bytes();
    let replacement_pubkey = replacement_key.verifying_key().to_bytes();
    let canonical = test_canonical_keyring_bytes(
        org_id,
        2,
        &(user_id, replacement_pubkey, added_at),
        &updated_at,
    );
    let keyring_signature = replacement_key.sign(&canonical);
    let signed_at = chrono::Utc::now();
    let reason = "owner key compromised";
    let directive = enclava_common::crypto::owner_rotation_directive_bytes(
        org_id,
        &current_pubkey,
        &replacement_pubkey,
        signed_at,
        reason,
    );
    let rotation_signature = current_key.sign(&directive);
    serde_json::json!({
        "version": 2,
        "keyring_payload": {
            "org_id": org_id,
            "version": 2,
            "members": [{
                "user_id": user_id,
                "pubkey": hex::encode(replacement_pubkey),
                "role": "owner",
                "added_at": added_at,
            }],
            "updated_at": updated_at,
        },
        "signature": hex::encode(keyring_signature.to_bytes()),
        "replacement_signing_pubkey": hex::encode(replacement_pubkey),
        "current_signing_pubkey": hex::encode(current_pubkey),
        "signed_at": signed_at,
        "reason": reason,
        "rotation_signature": hex::encode(rotation_signature.to_bytes()),
    })
}

async fn seed_keyring_pending_org(
    pool: &sqlx::PgPool,
    signing_keys: &[ed25519_dalek::SigningKey],
) -> (Uuid, Uuid, String, String) {
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("keyring-pending-{}", &suffix[..16]);
    let paas_org_id = format!("paas-keyring-org-{suffix}");
    let paas_user_id = format!("paas-keyring-user-{suffix}");
    insert_config_token_test_actor(
        pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    for key in signing_keys {
        sqlx::query("INSERT INTO user_signing_keys (user_id, pubkey) VALUES ($1, $2)")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .execute(pool)
            .await
            .expect("register keyring pending signing key");
    }
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
    )
    .execute(pool)
    .await
    .expect("activate signed-policy mode without a converged generation");
    (org_id, user_id, paas_org_id, paas_user_id)
}

/// Insert keyring v1 signed by `key` directly, bypassing the HTTP route
/// (routing the seed through put_paas_keyring would defer under pending
/// KBS state or terminalize under an unrelated failure).
async fn seed_owner_keyring_v1(
    pool: &sqlx::PgPool,
    org_id: Uuid,
    user_id: Uuid,
    key: &ed25519_dalek::SigningKey,
) {
    let body = signed_keyring_body(org_id, user_id, key, 1, 0);
    let signing_key_id: Uuid =
        sqlx::query_scalar("SELECT id FROM user_signing_keys WHERE user_id = $1 AND pubkey = $2")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .fetch_one(pool)
            .await
            .expect("resolve v1 signing key id");
    sqlx::query(
        "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, 1, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(serde_json::to_vec(&body["keyring_payload"]).expect("serialize v1 keyring payload"))
    .bind(
        hex::decode(body["signature"].as_str().expect("v1 signature"))
            .expect("decode v1 keyring signature"),
    )
    .bind(signing_key_id)
    .execute(pool)
    .await
    .expect("seed keyring v1");
}

#[tokio::test]
async fn reclaimed_keyring_checkpoint_survives_unrelated_five_xx() {
    let (_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_keyring_checkpoint_retry").await;
    let state = idempotency_test_state(pool.clone());
    let key = format!("keyring-checkpoint-{}", Uuid::new_v4());
    let path = "/internal/paas/orgs/test/keyring";
    let hash = Sha256::digest(b"keyring-checkpoint-request").to_vec();
    let begin = || {
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "PUT",
            path,
            &hash,
            IdempotencyRecovery::FailClosed,
        )
    };
    let initial = expect_idempotency_execution(begin().await.expect("reserve keyring"));
    let pending = json_error(StatusCode::SERVICE_UNAVAILABLE, "publication pending");
    let mut pending = pending;
    pending.1.0["code"] = serde_json::json!(KEYRING_POLICY_RECONCILIATION_PENDING_CODE);
    let deferred = complete_keyring_result(initial, Err(pending))
        .await
        .expect_err("committed keyring defers");
    assert_eq!(deferred.1.0["idempotency_disposition"], "deferred");

    expire_idempotency_lease(&pool, &key).await;
    let reclaimed = expect_idempotency_execution(begin().await.expect("reclaim checkpoint"));
    assert!(reclaimed.committed_keyring_checkpoint);
    let unrelated = complete_keyring_result(
        reclaimed,
        Err(json_error(
            StatusCode::BAD_GATEWAY,
            "unrelated upstream failure",
        )),
    )
    .await
    .expect_err("an unrelated 5xx must not stay publication-pending");
    assert_eq!(unrelated.0, StatusCode::CONFLICT);
    assert_eq!(unrelated.1.0["error"], "idempotency_recovery_required");
    assert_eq!(unrelated.1.0["retryable"], false);
    assert_ne!(
        unrelated.1.0["cause"],
        KEYRING_POLICY_RECONCILIATION_PENDING_CODE
    );
    let replay = expect_idempotency_replay(begin().await.expect("replay terminal 5xx"));
    assert_eq!(replay.0, StatusCode::CONFLICT);
    assert_eq!(replay.1["error"], "idempotency_recovery_required");
}

#[tokio::test]
async fn put_keyring_committed_pending_defers_and_same_key_reexecutes() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_keyring_pending_put").await;
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let (org_id, user_id, paas_org_id, paas_user_id) =
        seed_keyring_pending_org(&pool, std::slice::from_ref(&key)).await;
    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    let idempotency_key = format!("keyring-pending-put-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&idempotency_key, &paas_user_id);
    let request = signed_keyring_body(org_id, user_id, &key, 1, 0);

    // Active signed mode with no KBS config: the keyring transaction
    // commits, publication cannot be confirmed, and the wrapper must
    // defer rather than cache success or a terminal outcome.
    let deferred = put_paas_keyring(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(request.clone()),
    )
    .await
    .expect_err("committed-but-unconfirmed keyring must defer, not succeed");
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(deferred.1.0["error"], "idempotency_request_in_progress");
    assert_eq!(deferred.1.0["idempotency_disposition"], "deferred");
    assert_eq!(deferred.1.0["retryable"], true);
    assert_eq!(
        deferred.1.0["cause"],
        KEYRING_POLICY_RECONCILIATION_PENDING_CODE
    );

    // The keyring version, its audit row and the request binding are
    // durable; the idempotency row stays incomplete and not-applied-free.
    let receipt: (bool, bool) = sqlx::query_as(
        "SELECT completed_at IS NULL, known_not_applied
               FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&idempotency_key)
    .fetch_one(&pool)
    .await
    .expect("inspect deferred keyring receipt");
    assert_eq!(receipt, (true, false));
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version")
            .bind(org_id)
            .fetch_all(&pool)
            .await
            .expect("read committed keyring versions");
    assert_eq!(versions, vec![1]);
    let put_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.put'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count keyring put audits");
    assert_eq!(put_audits, 1);

    // A same-key retry under the live deferred lease stays deferred, and
    // a different payload cannot hijack the bound key.
    let busy = put_paas_keyring(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(request.clone()),
    )
    .await
    .expect_err("a live deferred lease must keep deferring same-key retries");
    let (expected_status, Json(expected_body)) = idempotency_in_progress_error();
    assert_eq!(busy.0, expected_status);
    for (field, value) in expected_body
        .as_object()
        .expect("contract body is an object")
    {
        assert_eq!(
            busy.1.0.get(field),
            Some(value),
            "deferred-409 contract field {field} must hold"
        );
    }
    // The live-lease branch additionally stamps a server-clock retry hint;
    // exact value depends on the remaining lease window, only its shape is
    // contractual here.
    let retry_after = busy
        .1
        .0
        .get("retry_after")
        .and_then(serde_json::Value::as_i64);
    assert!(
        retry_after
            .is_some_and(|seconds| (1..=IDEMPOTENCY_RETRY_HINT_MAX_SECONDS).contains(&seconds)),
        "live deferred lease must carry a bounded retry_after hint, got {retry_after:?}"
    );
    let mut hijack = request.clone();
    hijack["version"] = serde_json::json!(2);
    let rejected = put_paas_keyring(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(hijack),
    )
    .await
    .expect_err("a different payload must not reuse the bound key");
    assert_eq!(rejected.0, StatusCode::CONFLICT);
    assert_eq!(rejected.1.0["error"], "idempotency_key_reused");

    // A concurrent newer keyring makes the reclaimed same-key retry
    // re-execute the handler (stale-version conflict, terminal receipt)
    // instead of replaying the deferred committed-pending response.
    let signing_key_id: Uuid =
        sqlx::query_scalar("SELECT id FROM user_signing_keys WHERE user_id = $1 AND pubkey = $2")
            .bind(user_id)
            .bind(key.verifying_key().to_bytes().to_vec())
            .fetch_one(&pool)
            .await
            .expect("resolve signing key id");
    let concurrent = signed_keyring_body(org_id, user_id, &key, 2, 30);
    sqlx::query(
        "INSERT INTO org_keyrings
                 (org_id, version, keyring_payload, signature, signing_key_id)
             VALUES ($1, 2, $2, $3, $4)",
    )
    .bind(org_id)
    .bind(
        serde_json::to_vec(&concurrent["keyring_payload"])
            .expect("serialize concurrent keyring payload"),
    )
    .bind(
        hex::decode(
            concurrent["signature"]
                .as_str()
                .expect("concurrent signature"),
        )
        .expect("decode concurrent keyring signature"),
    )
    .bind(signing_key_id)
    .execute(&pool)
    .await
    .expect("insert concurrent newer keyring");
    expire_idempotency_lease(&pool, &idempotency_key).await;
    let retried = put_paas_keyring(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(request.clone()),
    )
    .await
    .expect_err("the stale-version retry is a conflict, not a success");
    assert_eq!(retried.0, StatusCode::CONFLICT);
    assert_eq!(retried.1.0["idempotency_disposition"], "completed");
    assert_eq!(retried.1.0["retryable"], false);
    assert_ne!(retried.1.0["error"], "idempotency_request_in_progress");
    assert_ne!(retried.1.0["error"], "idempotency_recovery_required");
    assert!(
        retried.1.0.get("cause").is_none(),
        "the retry must re-execute against the newer keyring, not replay the defer"
    );
    let versions_after: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version")
            .bind(org_id)
            .fetch_all(&pool)
            .await
            .expect("read keyring versions after retry");
    assert_eq!(versions_after, vec![1, 2]);
    let put_audits_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.put'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count keyring put audits after retry");
    assert_eq!(
        put_audits_after, 1,
        "the re-executed stale retry must not write another version or audit"
    );

    // The terminal receipt is now cached and replays exactly.
    let replayed = put_paas_keyring(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(request.clone()),
    )
    .await
    .expect("the completed stale conflict replays");
    assert_eq!(replayed.0, retried.0);
    assert_eq!(replayed.1.0, retried.1.0);

    crate::test_support::drop_isolated_database("cap_keyring_pending_put", pool).await;
}

#[tokio::test]
async fn rotate_owner_committed_pending_defers_and_exact_replay_retries_publication() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_keyring_pending_rotate").await;
    let current_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let replacement_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let (org_id, user_id, paas_org_id, paas_user_id) =
        seed_keyring_pending_org(&pool, &[current_key.clone(), replacement_key.clone()]).await;

    // Publish v1 as the current owner directly: routing the seed through
    // put_paas_keyring would itself defer under the pending KBS state.
    seed_owner_keyring_v1(&pool, org_id, user_id, &current_key).await;

    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    // The signing service already reports the replacement owner, so the
    // rotation commits locally without a remote owner change.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind signing service mock");
    let address = listener.local_addr().expect("mock signing service address");
    let replacement_hex = hex::encode(replacement_key.verifying_key().to_bytes());
    let status_org_id = org_id;
    let mock = tokio::spawn(async move {
        use axum::{Json, routing::get};
        let app = axum::Router::new().route(
            "/orgs/{org_id}/owner",
            get(move || {
                let org_id = status_org_id;
                let owner_hex = replacement_hex.clone();
                async move {
                    Json(serde_json::json!({
                        "org_id": org_id,
                        "state": "ready",
                        "version": 2,
                        "owner_pubkey_hex": owner_hex,
                        "last_changed_at": null,
                    }))
                }
            }),
        );
        axum::serve(listener, app).await.expect("serve mock");
    });
    state.signing_service = Some(
        crate::signing_service::SigningServiceClient::new(format!("http://{address}"), None)
            .expect("mock signing service client"),
    );

    let idempotency_key = format!("keyring-pending-rotate-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&idempotency_key, &paas_user_id);
    let rotation = signed_rotation_body(org_id, user_id, &current_key, &replacement_key);

    let deferred = rotate_paas_keyring_owner(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(rotation.clone()),
    )
    .await
    .expect_err("committed-but-unconfirmed rotation must defer, not succeed");
    assert_eq!(deferred.0, StatusCode::CONFLICT);
    assert_eq!(deferred.1.0["idempotency_disposition"], "deferred");
    assert_eq!(
        deferred.1.0["cause"],
        KEYRING_POLICY_RECONCILIATION_PENDING_CODE
    );

    // The rotation committed exactly once: version 2 exists with exactly
    // one rotation audit row, and the idempotency row stays incomplete.
    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version")
            .bind(org_id)
            .fetch_all(&pool)
            .await
            .expect("read rotation keyring versions");
    assert_eq!(versions, vec![1, 2]);
    let rotate_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count rotation audits");
    assert_eq!(rotate_audits, 1);
    let receipt: (bool, bool) = sqlx::query_as(
        "SELECT completed_at IS NULL, known_not_applied
               FROM cap_internal_idempotency WHERE idempotency_key = $1",
    )
    .bind(&idempotency_key)
    .fetch_one(&pool)
    .await
    .expect("inspect deferred rotation receipt");
    assert_eq!(receipt, (true, false));

    // Exact replay after the lease frees re-executes and defers again --
    // retrying publication -- without repeating the owner rotation.
    expire_idempotency_lease(&pool, &idempotency_key).await;
    let retried = rotate_paas_keyring_owner(
        internal_test_auth(),
        State(state.clone()),
        Path(paas_org_id.clone()),
        headers.clone(),
        Json(rotation.clone()),
    )
    .await
    .expect_err("exact replay retries publication and defers again");
    assert_eq!(retried.0, StatusCode::CONFLICT);
    assert_eq!(retried.1.0["idempotency_disposition"], "deferred");
    assert_eq!(
        retried.1.0["cause"],
        KEYRING_POLICY_RECONCILIATION_PENDING_CODE
    );
    let versions_after: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version")
            .bind(org_id)
            .fetch_all(&pool)
            .await
            .expect("read keyring versions after replay");
    assert_eq!(versions_after, vec![1, 2]);
    let rotate_audits_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count rotation audits after replay");
    assert_eq!(
        rotate_audits_after, 1,
        "exact replay must never repeat the owner rotation"
    );

    mock.abort();
    crate::test_support::drop_isolated_database("cap_keyring_pending_rotate", pool).await;
}

/// An org, a mapped PaaS owner, and an app pinned to the legacy test
/// signer identity: exactly what a signer rotation starts from.
async fn seed_signer_rotation_fixture(
    pool: &sqlx::PgPool,
) -> (Uuid, Uuid, Uuid, String, String, String) {
    let org_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let app_id = Uuid::new_v4();
    let suffix = org_id.simple().to_string();
    let org_name = format!("signer-rotate-{}", &suffix[..16]);
    let paas_org_id = format!("paas-signer-org-{suffix}");
    let paas_user_id = format!("paas-signer-user-{suffix}");
    insert_config_token_test_actor(
        pool,
        org_id,
        &org_name,
        &paas_org_id,
        user_id,
        &paas_user_id,
    )
    .await;
    let app_name = format!("signer-app-{}", &suffix[..12]);
    insert_config_token_test_app(pool, org_id, &org_name, app_id, &app_name, "sr1").await;
    (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id)
}

#[tokio::test]
async fn rotate_signer_committed_pending_defers_and_same_key_retry_is_publication_only() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_pending_rotate").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("activate signed-policy mode without a converged generation");

    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject =
        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let new_issuer = "https://rotated-issuer.example.test";
    let token = crate::auth::jwt::issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &crate::auth::jwt::SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_subject.to_string(),
            previous_issuer: previous_issuer.to_string(),
            new_subject: new_subject.to_string(),
            new_issuer: new_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue signer rotation token");
    let idempotency_key = format!("signer-pending-rotate-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&idempotency_key, &paas_user_id);
    let request = serde_json::json!({
        "subject": new_subject,
        "issuer": new_issuer,
        "email_confirmation_token": token,
    });

    let unconfigured = rotate_paas_signer(
        internal_test_auth(),
        State(state.clone()),
        Path((paas_org_id.clone(), app_name.clone())),
        headers.clone(),
        Json(request.clone()),
    )
    .await
    .expect_err("missing publication configuration must defer before mutation");
    assert_eq!(unconfigured.0, StatusCode::CONFLICT);
    assert_eq!(unconfigured.1.0["idempotency_disposition"], "deferred");
    assert_eq!(unconfigured.1.0["cause"], "kbs_publication_not_configured");
    let unapplied: (Option<String>, i64, i64) = sqlx::query_as(
            "SELECT signer_identity_subject,
                    (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                    (SELECT count(*) FROM audit_log WHERE app_id = $1 AND action = 'app.signer.rotate')
               FROM apps WHERE id = $1",
        )
        .bind(app_id)
        .fetch_one(&pool)
        .await
        .expect("inspect rejected rotation");
    assert_eq!(unapplied.0.as_deref(), Some(previous_subject));
    assert_eq!((unapplied.1, unapplied.2), (0, 0));

    expire_idempotency_lease(&pool, &idempotency_key).await;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::test_support::KbsPolicyProvider::new(false),
    ));
    crate::kbs::TEST_KUBE_CLIENT
            .scope(crate::test_support::kbs_policy_kube_client(provider), async {
        // The same request may now commit, but failed publication must retain
        // a checkpoint rather than consume another token on subsequent retries.
        let deferred = rotate_paas_signer(
            internal_test_auth(),
            State(state.clone()),
            Path((paas_org_id.clone(), app_name.clone())),
            headers.clone(),
            Json(request.clone()),
        )
        .await
        .expect_err("committed-but-unconfirmed rotation must defer, not succeed");
        assert_eq!(deferred.0, StatusCode::CONFLICT);
        assert_eq!(deferred.1.0["error"], "idempotency_request_in_progress");
        assert_eq!(deferred.1.0["idempotency_disposition"], "deferred");
        assert_eq!(deferred.1.0["retryable"], true);
        assert_eq!(
            deferred.1.0["cause"],
            crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
        );

        let committed_subject: Option<String> =
            sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("load app subject after committed rotation");
        assert_eq!(committed_subject.as_deref(), Some(new_subject));
        let rotation_receipts: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                    (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate')",
        )
        .bind(app_id)
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rotation receipts");
        assert_eq!(rotation_receipts, (1, 1));

        // A same-key retry under the live deferred lease stays deferred, and
        // a different payload cannot hijack the bound key.
        let busy = rotate_paas_signer(
            internal_test_auth(),
            State(state.clone()),
            Path((paas_org_id.clone(), app_name.clone())),
            headers.clone(),
            Json(request.clone()),
        )
        .await
        .expect_err("a live deferred lease must keep deferring same-key retries");
        let (expected_status, Json(expected_body)) = idempotency_in_progress_error();
        assert_eq!(busy.0, expected_status);
        for (field, value) in expected_body.as_object().expect("contract body is an object") {
            assert_eq!(
                busy.1.0.get(field), Some(value),
                "deferred-409 contract field {field} must hold"
            );
        }
        // The live-lease branch additionally stamps a server-clock retry hint;
        // exact value depends on the remaining lease window, only its shape is
        // contractual here.
        let retry_after = busy.1.0.get("retry_after").and_then(serde_json::Value::as_i64);
        assert!(
            retry_after.is_some_and(|seconds| (1..=IDEMPOTENCY_RETRY_HINT_MAX_SECONDS).contains(&seconds)),
            "live deferred lease must carry a bounded retry_after hint, got {retry_after:?}"
        );
        let mut hijack = request.clone();
        hijack["subject"] = serde_json::json!(
            "https://github.com/enclava/hijack/.github/workflows/build.yml@refs/heads/main"
        );
        let rejected = rotate_paas_signer(
            internal_test_auth(),
            State(state.clone()),
            Path((paas_org_id.clone(), app_name.clone())),
            headers.clone(),
            Json(hijack),
        )
        .await
        .expect_err("a different payload must not reuse the bound key");
        assert_eq!(rejected.0, StatusCode::CONFLICT);
        assert_eq!(rejected.1.0["error"], "idempotency_key_reused");

        // Losing configuration after the commit must not re-run the mutation.
        expire_idempotency_lease(&pool, &idempotency_key).await;
        state.kbs_policy = None;
        let retried = rotate_paas_signer(
            internal_test_auth(),
            State(state.clone()),
            Path((paas_org_id.clone(), app_name.clone())),
            headers.clone(),
            Json(request.clone()),
        )
        .await
        .expect_err("publication-only retry defers again while KBS stays unconfigured");
        assert_eq!(retried.0, StatusCode::CONFLICT);
        assert_eq!(retried.1.0["idempotency_disposition"], "deferred");
        assert_eq!(
            retried.1.0["cause"],
            crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
        );
        let rotation_receipts_after: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                    (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate')",
        )
        .bind(app_id)
        .bind(org_id)
        .fetch_one(&pool)
        .await
        .expect("count rotation receipts after publication-only retry");
        assert_eq!(
            rotation_receipts_after,
            (1, 1),
            "the publication-only retry must not re-run the rotation"
        );
        let subject_after: Option<String> =
            sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                .bind(app_id)
                .fetch_one(&pool)
                .await
                .expect("load app subject after publication-only retry");
        assert_eq!(subject_after.as_deref(), Some(new_subject));

            })
            .await;

    crate::test_support::drop_isolated_database("cap_signer_pending_rotate", pool).await;
}

/// An unrelated handler 5xx carries no committed signer outcome: it
/// must keep the generic fail-closed disposition, never a retryable
/// publication checkpoint.
#[tokio::test]
async fn rotate_signer_unrelated_five_xx_stays_fail_closed() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_pending_unrelated").await;
    let state = idempotency_test_state(pool.clone());
    let key = format!("signer-pending-unrelated-{}", Uuid::new_v4());
    let path = "/internal/paas/orgs/paas-org/apps/app/signer";
    let lease = expect_idempotency_execution(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "PATCH",
            path,
            &[1, 2, 3, 4],
            IdempotencyRecovery::FailClosed,
        )
        .await
        .unwrap(),
    );
    let terminal = complete_signer_result(
        lease,
        Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error",
        )),
    )
    .await
    .unwrap_err();
    assert_eq!(terminal.0, StatusCode::CONFLICT);
    assert_eq!(terminal.1.0["error"], "idempotency_recovery_required");
    assert_eq!(terminal.1.0["idempotency_disposition"], "completed");
    assert_eq!(terminal.1.0["retryable"], false);

    // The fail-closed receipt is terminal and replays without granting
    // a publication-only retry.
    let replay = expect_idempotency_replay(
        begin_idempotent_request_with_recovery(
            &state,
            &key,
            "PATCH",
            path,
            &[1, 2, 3, 4],
            IdempotencyRecovery::FailClosed,
        )
        .await
        .unwrap(),
    );
    let Json(terminal_body) = terminal.1;
    assert_eq!((replay.0, replay.1), (terminal.0, terminal_body));

    crate::test_support::drop_isolated_database("cap_signer_pending_unrelated", pool).await;
}

/// End-to-end signer rotation publication recovery against the fake
/// kube provider: the first attempt commits the rotation and defers
/// when the provider fails; after the provider recovers, the exact
/// same-key retry publishes and replays the saved committed result
/// without re-running the single-use mutation.
#[tokio::test]
async fn rotate_signer_publication_retry_publishes_after_kbs_recovery() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_rot_recovery").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    // The legacy Rego render source for the rotation's identity carry.
    sqlx::query(
            "INSERT INTO kbs_tls_bindings (app_id, binding_key, namespace, service_account, tenant_instance_identity_hash)
             SELECT id, id::text, namespace, service_account, tenant_instance_identity_hash FROM apps WHERE id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let new_subject =
        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let new_issuer = "https://rotated-issuer.example.test";
    let token = crate::auth::jwt::issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &crate::auth::jwt::SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_subject.to_string(),
            previous_issuer: previous_issuer.to_string(),
            new_subject: new_subject.to_string(),
            new_issuer: new_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .unwrap();
    let idempotency_key = format!("signer-rot-recovery-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&idempotency_key, &paas_user_id);
    let request = serde_json::json!({
        "subject": new_subject,
        "issuer": new_issuer,
        "email_confirmation_token": token,
    });
    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::test_support::KbsPolicyProvider::new(false),
    ));
    crate::kbs::TEST_KUBE_CLIENT
            .scope(crate::test_support::kbs_policy_kube_client(provider.clone()), async {
                // The provider rejects configmap reads: the rotation commits
                // and the wrapper defers with the incomplete publication
                // checkpoint.
                let deferred = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    headers.clone(),
                    Json(request.clone()),
                )
                .await
                .unwrap_err();
                assert_eq!(deferred.0, StatusCode::CONFLICT);
                assert_eq!(deferred.1.0["error"], "idempotency_request_in_progress");
                assert_eq!(deferred.1.0["idempotency_disposition"], "deferred");
                assert_eq!(deferred.1.0["retryable"], true);
                assert_eq!(
                    deferred.1.0["cause"],
                    crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                );
                let subject: Option<String> =
                    sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                        .bind(app_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert_eq!(subject.as_deref(), Some(new_subject));
                let rotation_receipts: (i64, i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                            (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate')",
                )
                .bind(app_id)
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(rotation_receipts, (1, 1));

                // Recovery: the provider heals, the deferred lease frees, and
                // the exact same-key retry reconciles publication only.
                {
                    let mut provider = provider.lock().await;
                    provider.healthy = true;
                }
                expire_idempotency_lease(&pool, &idempotency_key).await;
                let (status, Json(published)) = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    headers.clone(),
                    Json(request.clone()),
                )
                .await
                .unwrap();
                assert_eq!(status, StatusCode::OK);
                assert_eq!(published["signer_identity_subject"], new_subject);
                assert_eq!(published["id"], app_id.to_string());
                assert!(
                    published.get("rotation_count").is_none()
                        && published.get("signer_rotation_generation").is_none(),
                    "the confirmed success must expose only the AppResponse contract"
                );
                let rotation_receipts_after: (i64, i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                            (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate')",
                )
                .bind(app_id)
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(
                    rotation_receipts_after, (1, 1),
                    "the publication-only retry must not re-run the single-use rotation"
                );
                let subject_after: Option<String> =
                    sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                        .bind(app_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert_eq!(subject_after.as_deref(), Some(new_subject));

                // The provider's stored ConfigMap is the real legacy Rego
                // render: the binding is admitted under the rotated
                // identity, and nothing under the withdrawn one.
                {
                    let provider = provider.lock().await;
                    let policy = provider.configmap["data"]["policy.rego"]
                        .as_str()
                        .expect("published legacy policy body");
                    assert!(
                        policy.contains(&format!(
                            "\"allowed_signer_identity_subjects\": [\"{new_subject}\"]"
                        )),
                        "the published policy must admit the rotated signer identity"
                    );
                    assert!(
                        !policy.contains(previous_subject),
                        "the withdrawn identity must not be readmitted by publication"
                    );
                    assert_eq!(
                        provider.configmap_replaces, 1,
                        "the retry must publish the configmap exactly once"
                    );
                }

                // The completed receipt replays exactly, and an older one that
                // still carries private fencing metadata has it stripped:
                // the AppResponse contract never exposes generation or count.
                rewrite_idempotency_fixture(
                    &pool,
                    &idempotency_key,
                    "UPDATE cap_internal_idempotency
                        SET response_body = jsonb_set(
                                jsonb_set(response_body, '{rotation_count}', '1'),
                                '{signer_rotation_generation}', '2'
                            )
                      WHERE idempotency_key = $1",
                )
                .await;
                let (replay_status, Json(replayed)) = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    headers.clone(),
                    Json(request.clone()),
                )
                .await
                .unwrap();
                assert_eq!((replay_status, replayed), (status, published));
            })
            .await;

    crate::test_support::drop_isolated_database("cap_signer_rot_recovery", pool).await;
}

#[tokio::test]
async fn rotate_signer_retry_after_superseding_rotation_is_terminal_conflict() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_superseded").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    sqlx::query(
            "INSERT INTO kbs_tls_bindings (app_id, binding_key, namespace, service_account, tenant_instance_identity_hash)
             SELECT id, id::text, namespace, service_account, tenant_instance_identity_hash FROM apps WHERE id = $1",
        )
        .bind(app_id)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("activate signed-policy mode without a converged generation");

    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let superseded_subject =
        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let superseded_issuer = "https://rotated-issuer.example.test";
    let authority_subject =
        "https://github.com/enclava/authority/.github/workflows/build.yml@refs/heads/main";
    let authority_issuer = "https://authority-issuer.example.test";

    let old_token = crate::auth::jwt::issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &crate::auth::jwt::SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_subject.to_string(),
            previous_issuer: previous_issuer.to_string(),
            new_subject: superseded_subject.to_string(),
            new_issuer: superseded_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue superseded rotation token");
    let old_idempotency_key = format!("signer-superseded-old-{}", Uuid::new_v4());
    let old_headers = config_token_actor_headers(&old_idempotency_key, &paas_user_id);
    let old_request = serde_json::json!({
        "subject": superseded_subject,
        "issuer": superseded_issuer,
        "email_confirmation_token": old_token,
    });
    let authority_token = crate::auth::jwt::issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &crate::auth::jwt::SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: superseded_subject.to_string(),
            previous_issuer: superseded_issuer.to_string(),
            new_subject: authority_subject.to_string(),
            new_issuer: authority_issuer.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue authority rotation token");

    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::test_support::KbsPolicyProvider::new(false),
    ));
    crate::kbs::TEST_KUBE_CLIENT
            .scope(crate::test_support::kbs_policy_kube_client(provider.clone()), async {
                let deferred = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect_err("committed-but-unconfirmed rotation must defer, not succeed");
                assert_eq!(deferred.0, StatusCode::CONFLICT);
                assert_eq!(
                    deferred.1.0["cause"],
                    crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                );
                let committed_subject: Option<String> =
                    sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                        .bind(app_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert_eq!(committed_subject.as_deref(), Some(superseded_subject));

                expire_idempotency_lease(&pool, &old_idempotency_key).await;
                {
                    let mut provider = provider.lock().await;
                    provider.healthy = true;
                }
                let authority_key = format!("signer-superseded-new-{}", Uuid::new_v4());
                let authority_headers = config_token_actor_headers(&authority_key, &paas_user_id);
                let (authority_status, Json(published)) = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    authority_headers,
                    Json(serde_json::json!({
                        "subject": authority_subject,
                        "issuer": authority_issuer,
                        "email_confirmation_token": authority_token,
                    })),
                )
                .await
                .expect("the legitimate later rotation must publish");
                assert_eq!(authority_status, StatusCode::OK);
                assert_eq!(published["signer_identity_subject"], authority_subject);
                assert!(
                    published.get("rotation_count").is_none()
                        && published.get("signer_rotation_generation").is_none(),
                    "a fresh success must expose only the AppResponse contract"
                );

                // Supersession must terminate even while KBS is unavailable.
                {
                    let mut provider = provider.lock().await;
                    provider.healthy = false;
                }
                let superseded = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect_err("the superseded retry must report a terminal conflict");
                assert_eq!(superseded.0, StatusCode::CONFLICT);
                assert_eq!(
                    superseded.1.0["code"],
                    crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE
                );
                assert_eq!(superseded.1.0["idempotency_disposition"], "completed");
                assert_eq!(superseded.1.0["retryable"], false);
                assert!(superseded.1.0.get("committed_response").is_none());

                let receipts: (i64, i64, i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                            (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate'),
                            (SELECT count(*) FROM withdrawn_signer_artifacts WHERE app_id = $1)",
                )
                .bind(app_id)
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(receipts, (2, 2, 0));

                let replayed = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect("the terminal receipt must replay as the same conflict");
                assert_eq!(replayed.0, StatusCode::CONFLICT);
                assert_eq!(replayed.1.0, superseded.1.0);

                let receipts_after: (i64, i64, i64) = sqlx::query_as(
                    "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                            (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate'),
                            (SELECT count(*) FROM withdrawn_signer_artifacts WHERE app_id = $1)",
                )
                .bind(app_id)
                .bind(org_id)
                .fetch_one(&pool)
                .await
                .unwrap();
                assert_eq!(receipts_after, (2, 2, 0));
                let subject_after: Option<String> =
                    sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                        .bind(app_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                assert_eq!(subject_after.as_deref(), Some(authority_subject));
            })
            .await;

    crate::test_support::drop_isolated_database("cap_signer_superseded", pool).await;
}

#[tokio::test]
async fn rotate_signer_retry_after_app_removal_is_terminal_conflict() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_superseded_removal").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (org_id_2, user_id_2, app_id_2, app_name_2, paas_org_id_2, paas_user_id_2) =
        seed_signer_rotation_fixture(&pool).await;
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
    )
    .execute(&pool)
    .await
    .expect("activate signed-policy mode without a converged generation");

    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let superseded_subject =
        "https://github.com/enclava/gone/.github/workflows/build.yml@refs/heads/main";
    let superseded_issuer = "https://gone-issuer.example.test";

    let issue_request = |org_id: Uuid,
                         user_id: Uuid,
                         app_id: Uuid,
                         paas_user_id: &str|
     -> (String, HeaderMap, serde_json::Value) {
        let token = crate::auth::jwt::issue_signer_rotation_token(
            state.hmac_key.as_ref(),
            &crate::auth::jwt::SignerRotationTokenInput {
                user_id,
                org_id,
                app_id,
                previous_subject: previous_subject.to_string(),
                previous_issuer: previous_issuer.to_string(),
                new_subject: superseded_subject.to_string(),
                new_issuer: superseded_issuer.to_string(),
            },
            chrono::Duration::seconds(600),
        )
        .expect("issue signer rotation token");
        let key = format!("signer-removal-{}", Uuid::new_v4());
        let headers = config_token_actor_headers(&key, paas_user_id);
        (
            key,
            headers,
            serde_json::json!({
                "subject": superseded_subject,
                "issuer": superseded_issuer,
                "email_confirmation_token": token,
            }),
        )
    };

    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::test_support::KbsPolicyProvider::new(false),
    ));
    crate::kbs::TEST_KUBE_CLIENT
        .scope(
            crate::test_support::kbs_policy_kube_client(provider.clone()),
            async {
                let (deleting_key, deleting_headers, deleting_request) =
                    issue_request(org_id, user_id, app_id, &paas_user_id);
                let (missing_key, missing_headers, missing_request) =
                    issue_request(org_id_2, user_id_2, app_id_2, &paas_user_id_2);
                for (app_name, paas_org_id, headers, request) in [
                    (
                        &app_name,
                        &paas_org_id,
                        &deleting_headers,
                        &deleting_request,
                    ),
                    (
                        &app_name_2,
                        &paas_org_id_2,
                        &missing_headers,
                        &missing_request,
                    ),
                ] {
                    let deferred = rotate_paas_signer(
                        internal_test_auth(),
                        State(state.clone()),
                        Path((paas_org_id.clone(), app_name.clone())),
                        headers.clone(),
                        Json(request.clone()),
                    )
                    .await
                    .expect_err("committed-but-unconfirmed rotation must defer");
                    assert_eq!(deferred.0, StatusCode::CONFLICT);
                    assert_eq!(
                        deferred.1.0["cause"],
                        crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                    );
                }
                expire_idempotency_lease(&pool, &deleting_key).await;
                expire_idempotency_lease(&pool, &missing_key).await;

                sqlx::query("UPDATE apps SET status = 'deleting'::app_status_enum WHERE id = $1")
                    .bind(app_id)
                    .execute(&pool)
                    .await
                    .expect("mark the first app deleting");
                let deleting = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    deleting_headers.clone(),
                    Json(deleting_request.clone()),
                )
                .await
                .expect_err("a deleting app must not keep deferring publication");
                assert_eq!(deleting.0, StatusCode::CONFLICT);
                assert_eq!(
                    deleting.1.0["code"],
                    crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE
                );
                assert_eq!(deleting.1.0["idempotency_disposition"], "completed");

                for table in [
                    "DELETE FROM consumed_signer_rotation_tokens WHERE app_id = $1",
                    "DELETE FROM audit_log WHERE app_id = $1",
                    "DELETE FROM kbs_tls_bindings WHERE app_id = $1",
                    "DELETE FROM apps WHERE id = $1",
                ] {
                    sqlx::query(table)
                        .bind(app_id_2)
                        .execute(&pool)
                        .await
                        .expect("remove the second app and its dependents");
                }
                let missing = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id_2.clone(), app_name_2.clone())),
                    missing_headers.clone(),
                    Json(missing_request.clone()),
                )
                .await
                .expect_err("a deleted app must not keep deferring publication");
                assert_eq!(missing.0, StatusCode::CONFLICT);
                assert_eq!(
                    missing.1.0["code"],
                    crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE
                );
                assert_eq!(missing.1.0["idempotency_disposition"], "completed");
            },
        )
        .await;

    crate::test_support::drop_isolated_database("cap_signer_superseded_removal", pool).await;
}

fn issue_test_signer_rotation_token(
    state: &AppState,
    user_id: Uuid,
    org_id: Uuid,
    app_id: Uuid,
    previous_identity: (&str, &str),
    new_identity: (&str, &str),
) -> String {
    crate::auth::jwt::issue_signer_rotation_token(
        state.hmac_key.as_ref(),
        &crate::auth::jwt::SignerRotationTokenInput {
            user_id,
            org_id,
            app_id,
            previous_subject: previous_identity.0.to_string(),
            previous_issuer: previous_identity.1.to_string(),
            new_subject: new_identity.0.to_string(),
            new_issuer: new_identity.1.to_string(),
        },
        chrono::Duration::seconds(600),
    )
    .expect("issue signer rotation token")
}

async fn rewrite_idempotency_fixture(pool: &sqlx::PgPool, key: &str, statement: &str) {
    let mut tx = pool.begin().await.expect("begin fixture receipt rewrite");
    let token: Uuid = sqlx::query_scalar(
        "SELECT reservation_token FROM cap_internal_idempotency
              WHERE idempotency_key = $1 FOR UPDATE",
    )
    .bind(key)
    .fetch_one(&mut *tx)
    .await
    .expect("load the fixture receipt owner");
    set_idempotency_completion_owner(&mut tx, token)
        .await
        .expect("retain the fixture receipt owner guard");
    sqlx::query(statement)
        .bind(key)
        .execute(&mut *tx)
        .await
        .expect("rewrite the fixture receipt");
    tx.commit().await.expect("commit the fixture receipt");
}

async fn signer_rotation_publication_state(
    pool: &sqlx::PgPool,
    app_id: Uuid,
) -> (
    AppState,
    std::sync::Arc<tokio::sync::Mutex<crate::test_support::KbsPolicyProvider>>,
) {
    sqlx::query(
            "INSERT INTO kbs_tls_bindings (app_id, binding_key, namespace, service_account, tenant_instance_identity_hash)
             SELECT id, id::text, namespace, service_account, tenant_instance_identity_hash FROM apps WHERE id = $1",
        )
        .bind(app_id)
        .execute(pool)
        .await
        .expect("seed legacy binding for the rotation");
    sqlx::query(
        "UPDATE kbs_signed_policy_reconciliation
                SET desired_generation = 5,
                    selector_bumps_owed = 0,
                    configmap_generation = 0,
                    applied_generation = 0,
                    configmap_policy_sha256 = NULL,
                    applied_policy_sha256 = NULL,
                    configmap_resource_version = NULL
              WHERE singleton",
    )
    .execute(pool)
    .await
    .expect("activate signed-policy mode without a converged generation");
    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    state.kbs_policy = Some(crate::kbs::KbsPolicyConfig {
        namespace: "kbs-test".into(),
        configmap_name: "resource-policy".into(),
        policy_key: "policy.rego".into(),
        deployment_name: "trustee".into(),
        required: true,
        signed_policy_retention: 1,
        signed_policy_max_bytes: 1_048_576,
    });
    let provider = std::sync::Arc::new(tokio::sync::Mutex::new(
        crate::test_support::KbsPolicyProvider::new(false),
    ));
    (state, provider)
}

async fn signer_rotation_receipts(pool: &sqlx::PgPool, app_id: Uuid, org_id: Uuid) -> (i64, i64) {
    sqlx::query_as(
            "SELECT (SELECT count(*) FROM consumed_signer_rotation_tokens WHERE app_id = $1),
                    (SELECT count(*) FROM audit_log WHERE org_id = $2 AND action = 'app.signer.rotate')",
        )
        .bind(app_id)
        .bind(org_id)
        .fetch_one(pool)
        .await
        .expect("count signer rotation receipts")
}

#[tokio::test]
async fn rotate_signer_retry_after_rotate_back_is_terminal_conflict() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_rotate_back").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (state, provider) = signer_rotation_publication_state(&pool, app_id).await;
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let pending_subject =
        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let pending_issuer = "https://rotated-issuer.example.test";
    let intervening_subject =
        "https://github.com/enclava/intervening/.github/workflows/build.yml@refs/heads/main";
    let intervening_issuer = "https://intervening-issuer.example.test";

    let old_token = issue_test_signer_rotation_token(
        &state,
        user_id,
        org_id,
        app_id,
        (previous_subject, previous_issuer),
        (pending_subject, pending_issuer),
    );
    let old_idempotency_key = format!("signer-rotate-back-old-{}", Uuid::new_v4());
    let old_headers = config_token_actor_headers(&old_idempotency_key, &paas_user_id);
    let old_request = serde_json::json!({
        "subject": pending_subject,
        "issuer": pending_issuer,
        "email_confirmation_token": old_token,
    });

    crate::kbs::TEST_KUBE_CLIENT
        .scope(
            crate::test_support::kbs_policy_kube_client(provider.clone()),
            async {
                let deferred = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect_err("committed-but-unconfirmed rotation must defer, not succeed");
                assert_eq!(deferred.0, StatusCode::CONFLICT);
                assert_eq!(
                    deferred.1.0["cause"],
                    crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                );

                // A real B -> C -> B: the pending identity matches again, but
                // the count proves a later authority intervened.
                expire_idempotency_lease(&pool, &old_idempotency_key).await;
                provider.lock().await.healthy = true;
                let intervening_key = format!("signer-rotate-back-new-{}", Uuid::new_v4());
                let intervening_headers =
                    config_token_actor_headers(&intervening_key, &paas_user_id);
                let intervening_token = issue_test_signer_rotation_token(
                    &state,
                    user_id,
                    org_id,
                    app_id,
                    (pending_subject, pending_issuer),
                    (intervening_subject, intervening_issuer),
                );
                let (intervening_status, Json(intervening_published)) = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    intervening_headers,
                    Json(serde_json::json!({
                        "subject": intervening_subject,
                        "issuer": intervening_issuer,
                        "email_confirmation_token": intervening_token,
                    })),
                )
                .await
                .expect("the intervening rotation must publish");
                assert_eq!(intervening_status, StatusCode::OK);
                assert!(
                    intervening_published.get("rotation_count").is_none()
                        && intervening_published
                            .get("signer_rotation_generation")
                            .is_none()
                );
                let rotate_back_key = format!("signer-rotate-back-return-{}", Uuid::new_v4());
                let rotate_back_headers =
                    config_token_actor_headers(&rotate_back_key, &paas_user_id);
                let rotate_back_token = issue_test_signer_rotation_token(
                    &state,
                    user_id,
                    org_id,
                    app_id,
                    (intervening_subject, intervening_issuer),
                    (pending_subject, pending_issuer),
                );
                let (rotate_back_status, Json(rotate_back_published)) = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    rotate_back_headers,
                    Json(serde_json::json!({
                        "subject": pending_subject,
                        "issuer": pending_issuer,
                        "email_confirmation_token": rotate_back_token,
                    })),
                )
                .await
                .expect("the rotate-back rotation must publish");
                assert_eq!(rotate_back_status, StatusCode::OK);
                assert!(
                    rotate_back_published.get("rotation_count").is_none()
                        && rotate_back_published
                            .get("signer_rotation_generation")
                            .is_none()
                );
                let live_subject: Option<String> =
                    sqlx::query_scalar("SELECT signer_identity_subject FROM apps WHERE id = $1")
                        .bind(app_id)
                        .fetch_one(&pool)
                        .await
                        .expect("load app subject after the rotate-back");
                assert_eq!(live_subject.as_deref(), Some(pending_subject));
                assert_eq!(
                    signer_rotation_receipts(&pool, app_id, org_id).await,
                    (3, 3)
                );

                let superseded = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect_err("the rotate-back superseded retry must report a terminal conflict");
                assert_eq!(superseded.0, StatusCode::CONFLICT);
                assert_eq!(
                    superseded.1.0["code"],
                    crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE
                );
                assert_eq!(superseded.1.0["idempotency_disposition"], "completed");
                assert_eq!(superseded.1.0["retryable"], false);
                assert!(superseded.1.0.get("committed_response").is_none());

                // The terminal receipt replays stably without new commits.
                let replayed = rotate_paas_signer(
                    internal_test_auth(),
                    State(state.clone()),
                    Path((paas_org_id.clone(), app_name.clone())),
                    old_headers.clone(),
                    Json(old_request.clone()),
                )
                .await
                .expect("the terminal receipt must replay as the same conflict");
                assert_eq!((replayed.0, replayed.1.0), (superseded.0, superseded.1.0));
                assert_eq!(
                    signer_rotation_receipts(&pool, app_id, org_id).await,
                    (3, 3)
                );
            },
        )
        .await;

    crate::test_support::drop_isolated_database("cap_signer_rotate_back", pool).await;
}

#[tokio::test]
async fn rotate_signer_retry_rejects_rotation_committed_during_publication() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_during_publication").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (state, provider) = signer_rotation_publication_state(&pool, app_id).await;
    let previous_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main";
    let previous_issuer = "https://token.actions.githubusercontent.com";
    let pending_subject =
        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let pending_issuer = "https://rotated-issuer.example.test";
    let intervening_subject =
        "https://github.com/enclava/intervening/.github/workflows/build.yml@refs/heads/main";
    let intervening_issuer = "https://intervening-issuer.example.test";

    let old_token = issue_test_signer_rotation_token(
        &state,
        user_id,
        org_id,
        app_id,
        (previous_subject, previous_issuer),
        (pending_subject, pending_issuer),
    );
    let old_idempotency_key = format!("signer-during-publication-{}", Uuid::new_v4());
    let old_headers = config_token_actor_headers(&old_idempotency_key, &paas_user_id);
    let old_request = serde_json::json!({
        "subject": pending_subject,
        "issuer": pending_issuer,
        "email_confirmation_token": old_token,
    });

    crate::kbs::TEST_KUBE_CLIENT
            .scope(
                crate::test_support::kbs_policy_kube_client(provider.clone()),
                async {
                    let deferred = rotate_paas_signer(
                        internal_test_auth(),
                        State(state.clone()),
                        Path((paas_org_id.clone(), app_name.clone())),
                        old_headers.clone(),
                        Json(old_request.clone()),
                    )
                    .await
                    .expect_err("committed-but-unconfirmed rotation must defer, not succeed");
                    assert_eq!(deferred.0, StatusCode::CONFLICT);
                    assert_eq!(
                        deferred.1.0["cause"],
                        crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                    );

                    expire_idempotency_lease(&pool, &old_idempotency_key).await;
                    let (reached_tx, reached_rx) = tokio::sync::oneshot::channel::<()>();
                    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
                    {
                        let mut gated = provider.lock().await;
                        gated.healthy = true;
                        gated.configmap_put_hold = Some((reached_tx, release_rx));
                    }

                    // Both futures run on this task: the test kube client is
                    // task-local, and the retry must park inside its publication
                    // while a later writer changes authority underneath it. The
                    // interleaved writer records a token in the same transaction
                    // as the identity change: a token-less update is rejected by
                    // the 0067 consumption fence, and only the trigger-backed
                    // generation distinguishes this rotate-back from the parked
                    // retry's own commit.
                    let retry_state = state.clone();
                    let retry_paas_org_id = paas_org_id.clone();
                    let retry_app_name = app_name.clone();
                    let retry_headers = old_headers.clone();
                    let retry_request = old_request.clone();
                    let interleave_pool = pool.clone();
                    let (retry_result, ()) = tokio::join!(
                        async move {
                            rotate_paas_signer(
                                internal_test_auth(),
                                State(retry_state),
                                Path((retry_paas_org_id, retry_app_name)),
                                retry_headers,
                                Json(retry_request),
                            )
                            .await
                        },
                        async move {
                            reached_rx
                                .await
                                .expect("publication parks at the configmap write");
                            for (subject, issuer) in [
                                (intervening_subject, intervening_issuer),
                                (pending_subject, pending_issuer),
                            ] {
                                let mut tx = interleave_pool
                                    .begin()
                                    .await
                                    .expect("begin interleaved rotation");
                                sqlx::query(
                                    "UPDATE apps
                                        SET signer_identity_subject = $2,
                                            signer_identity_issuer = $3
                                      WHERE id = $1",
                                )
                                .bind(app_id)
                                .bind(subject)
                                .bind(issuer)
                                .execute(&mut *tx)
                                .await
                                .expect("stage the interleaved identity");
                                sqlx::query(
                                    "INSERT INTO consumed_signer_rotation_tokens (
                                         jti, user_id, org_id, app_id, subject, issuer, expires_at
                                     ) VALUES ($1, $2, $3, $4, $5, $6, now() + interval '1 hour')",
                                )
                                .bind(Uuid::new_v4().to_string())
                                .bind(user_id)
                                .bind(org_id)
                                .bind(app_id)
                                .bind(subject)
                                .bind(issuer)
                                .execute(&mut *tx)
                                .await
                                .expect("consume the interleaved rotation token");
                                tx.commit().await.expect("commit the interleaved identity");
                            }
                            release_tx.send(()).expect("release the parked publication");
                        }
                    );
                    let superseded = retry_result
                        .expect_err("a rotation committed during publication must not pass");
                    assert_eq!(superseded.0, StatusCode::CONFLICT);
                    assert_eq!(
                        superseded.1.0["code"],
                        crate::routes::apps::SIGNER_ROTATION_SUPERSEDED_CODE
                    );
                    assert_eq!(superseded.1.0["idempotency_disposition"], "completed");
                    assert_eq!(superseded.1.0["retryable"], false);
                    assert!(superseded.1.0.get("committed_response").is_none());

                    assert_eq!(
                        signer_rotation_receipts(&pool, app_id, org_id).await,
                        (3, 1),
                        "the parked rotation and both interleaved rotations consume a token; only the route writes an audit row"
                    );
                },
            )
            .await;

    crate::test_support::drop_isolated_database("cap_signer_during_publication", pool).await;
}

async fn seed_committed_signer_identity(pool: &sqlx::PgPool, app_id: Uuid) -> i64 {
    let subject = "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main";
    let issuer = "https://rotated-issuer.example.test";
    let mut tx = pool.begin().await.expect("begin signer seed");
    let org_id: Uuid = sqlx::query_scalar("SELECT org_id FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(&mut *tx)
        .await
        .expect("load app org for the seeded rotation");
    // The fixture already has a signer. A later identity change is a
    // rotation and must consume a token in the same transaction.
    sqlx::query(
        "UPDATE apps
                SET signer_identity_subject = $2,
                    signer_identity_issuer = $3
              WHERE id = $1",
    )
    .bind(app_id)
    .bind(subject)
    .bind(issuer)
    .execute(&mut *tx)
    .await
    .expect("stage the pending signer identity");
    sqlx::query(
        "INSERT INTO consumed_signer_rotation_tokens (
                 jti, user_id, org_id, app_id, subject, issuer, expires_at
             ) VALUES ($1, $2, $3, $4, $5, $6, now() + interval '1 hour')",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(Uuid::new_v4())
    .bind(org_id)
    .bind(app_id)
    .bind(subject)
    .bind(issuer)
    .execute(&mut *tx)
    .await
    .expect("consume the seeded rotation token");
    tx.commit()
        .await
        .expect("commit the pending signer identity");
    sqlx::query_scalar("SELECT signer_rotation_generation FROM apps WHERE id = $1")
        .bind(app_id)
        .fetch_one(pool)
        .await
        .expect("read the trigger-backed signer rotation generation")
}

async fn retained_kbs_fences(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM external_resource_mutation_leases
              WHERE resource_scope = 'kbs_policy' AND resource_key = 'global'
                AND owner_token IS NOT NULL
                AND reclaim_after > clock_timestamp()",
    )
    .fetch_one(pool)
    .await
    .expect("read KBS fence ownership")
}

#[tokio::test]
async fn uncertain_signer_publication_write_failure_retains_kbs_fence() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_fence_uncertain").await;
    let (_org_id, _user_id, app_id, _app_name, _paas_org_id, _paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (state, provider) = signer_rotation_publication_state(&pool, app_id).await;
    let generation = seed_committed_signer_identity(&pool, app_id).await;
    {
        let mut gated = provider.lock().await;
        gated.healthy = true;
        // Fail every Trustee deployment write after the ConfigMap write
        // has landed: the reconcile surfaces a Kubernetes mutating-request
        // failure whose outcome cannot be proven.
        gated.deployment_put_failures = usize::MAX;
    }

    crate::kbs::TEST_KUBE_CLIENT
            .scope(
                crate::test_support::kbs_policy_kube_client(provider.clone()),
                async {
                    let pending = crate::routes::apps::reconcile_signer_publication(
                        &state,
                        app_id,
                        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main",
                        "https://rotated-issuer.example.test",
                        generation,
                    )
                    .await
                    .expect_err("an uncertain provider write must stay pending");
                    assert_eq!(pending.0, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(
                        pending.1.0["error"], "signer_rotation_publication_pending",
                        "the committed rotation stays retryable: {:?}",
                        pending.1.0
                    );
                },
            )
            .await;

    assert_eq!(
        retained_kbs_fences(&pool).await,
        1,
        "an uncertain provider write must keep the KBS fence owned through the reclaim \
             quarantine so a possibly in-flight write cannot overlap the next publisher"
    );
    crate::test_support::drop_isolated_database("cap_signer_fence_uncertain", pool).await;
}

#[tokio::test]
async fn pre_write_signer_publication_failure_releases_kbs_fence() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_fence_pre_write").await;
    let (_org_id, _user_id, app_id, _app_name, _paas_org_id, _paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (state, provider) = signer_rotation_publication_state(&pool, app_id).await;
    let generation = seed_committed_signer_identity(&pool, app_id).await;
    // The provider double stays unhealthy: every request 404s at the
    // ConfigMap READ, before any mutating request is sent, so the failure
    // provably has no provider write in flight.

    crate::kbs::TEST_KUBE_CLIENT
            .scope(
                crate::test_support::kbs_policy_kube_client(provider.clone()),
                async {
                    let pending = crate::routes::apps::reconcile_signer_publication(
                        &state,
                        app_id,
                        "https://github.com/enclava/rotated/.github/workflows/build.yml@refs/heads/main",
                        "https://rotated-issuer.example.test",
                        generation,
                    )
                    .await
                    .expect_err("the read failure must stay pending");
                    assert_eq!(pending.0, StatusCode::SERVICE_UNAVAILABLE);
                    assert_eq!(pending.1.0["error"], "signer_rotation_publication_pending");
                },
            )
            .await;

    assert_eq!(
        retained_kbs_fences(&pool).await,
        0,
        "a failure with no provider write in flight must release the fence instead of \
             holding the cluster-wide kbs_policy resource through the quarantine window"
    );
    crate::test_support::drop_isolated_database("cap_signer_fence_pre_write", pool).await;
}

/// A checkpoint written before the generation field existed (or otherwise
/// unverifiable: wrong type, negative, or contradictory metadata) must
/// terminalize to the bounded new-key disposition on the completed
/// channel — not 500 forever: the publication-checkpoint reclaim
/// carve-out would otherwise re-run the handler after every lease expiry
/// and never complete the row. No generation is ever invented for it.
#[tokio::test]
async fn signer_checkpoint_without_generation_terminalizes_to_new_key_disposition() {
    let _singleton = crate::test_support::SIGNED_POLICY_SINGLETON_LOCK
        .lock()
        .await;
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_signer_stale_checkpoint").await;
    let (org_id, user_id, app_id, app_name, paas_org_id, paas_user_id) =
        seed_signer_rotation_fixture(&pool).await;
    let (state, provider) = signer_rotation_publication_state(&pool, app_id).await;
    let mut current_subject =
        "https://github.com/enclava/test/.github/workflows/build.yml@refs/heads/main".to_string();
    let mut current_issuer = "https://token.actions.githubusercontent.com".to_string();

    // Every scenario first defers a real committed rotation, then rewrites
    // its checkpoint into an unverifiable pre-generation shape.
    let scenarios: &[(&str, &str)] = &[
        (
            "missing",
            "UPDATE cap_internal_idempotency
                    SET response_body = response_body - 'signer_rotation_generation'
                  WHERE idempotency_key = $1",
        ),
        (
            "wrong-type",
            "UPDATE cap_internal_idempotency
                    SET response_body = jsonb_set(
                        response_body,
                        '{signer_rotation_generation}',
                        '\"unverifiable\"'::jsonb
                    )
                  WHERE idempotency_key = $1",
        ),
        (
            "negative",
            "UPDATE cap_internal_idempotency
                    SET response_body = jsonb_set(
                        response_body,
                        '{signer_rotation_generation}',
                        '-1'::jsonb
                    )
                  WHERE idempotency_key = $1",
        ),
        (
            "contradictory",
            "UPDATE cap_internal_idempotency
                    SET response_body = jsonb_set(
                        response_body,
                        '{rotation_count}',
                        '1'::jsonb
                    )
                  WHERE idempotency_key = $1",
        ),
        (
            "embedded-private-metadata",
            "UPDATE cap_internal_idempotency
                    SET response_body = jsonb_set(
                        response_body,
                        '{committed_response,rotation_count}',
                        '1'::jsonb
                    )
                  WHERE idempotency_key = $1",
        ),
    ];

    crate::kbs::TEST_KUBE_CLIENT
            .scope(
                crate::test_support::kbs_policy_kube_client(provider.clone()),
                async {
                    for (label, rewrite) in scenarios {
                        let next_subject = format!(
                            "https://github.com/enclava/{label}/.github/workflows/build.yml@refs/heads/main"
                        );
                        let next_issuer = format!("https://{label}-issuer.example.test");
                        let idempotency_key =
                            format!("signer-stale-checkpoint-{label}-{}", Uuid::new_v4());
                        let headers =
                            config_token_actor_headers(&idempotency_key, &paas_user_id);
                        let request = serde_json::json!({
                            "subject": next_subject.clone(),
                            "issuer": next_issuer.clone(),
                            "email_confirmation_token": issue_test_signer_rotation_token(
                                &state,
                                user_id,
                                org_id,
                                app_id,
                                (&current_subject, &current_issuer),
                                (&next_subject, &next_issuer),
                            ),
                        });
                        let deferred = rotate_paas_signer(
                            internal_test_auth(),
                            State(state.clone()),
                            Path((paas_org_id.clone(), app_name.clone())),
                            headers.clone(),
                            Json(request.clone()),
                        )
                        .await
                        .expect_err("committed-but-unconfirmed rotation must defer");
                        assert_eq!(deferred.0, StatusCode::CONFLICT);
                        assert_eq!(
                            deferred.1.0["cause"],
                            crate::routes::apps::SIGNER_ROTATION_PUBLICATION_PENDING_CODE
                        );

                        rewrite_idempotency_fixture(&pool, &idempotency_key, rewrite).await;
                        expire_idempotency_lease(&pool, &idempotency_key).await;
                        let terminal = rotate_paas_signer(
                            internal_test_auth(),
                            State(state.clone()),
                            Path((paas_org_id.clone(), app_name.clone())),
                            headers.clone(),
                            Json(request.clone()),
                        )
                        .await
                        .expect_err("an unverifiable checkpoint must not report success");
                        assert_eq!(terminal.0, StatusCode::CONFLICT);
                        assert_eq!(terminal.1.0["error"], "idempotency_recovery_required");
                        assert_eq!(terminal.1.0["retryable"], false);
                        assert_eq!(
                            terminal.1.0["disposition"],
                            "reconcile_then_retry_with_new_key"
                        );
                        assert_eq!(terminal.1.0["idempotency_disposition"], "completed");

                        // The terminal disposition is persisted on the
                        // completed channel, so the row is finished and
                        // replays stably instead of re-running after every
                        // lease expiry.
                        let completed: Option<bool> = sqlx::query_scalar(
                            "SELECT completed_at IS NOT NULL
                               FROM cap_internal_idempotency WHERE idempotency_key = $1",
                        )
                        .bind(&idempotency_key)
                        .fetch_one(&pool)
                        .await
                        .unwrap();
                        assert_eq!(completed, Some(true));

                        let replayed = rotate_paas_signer(
                            internal_test_auth(),
                            State(state.clone()),
                            Path((paas_org_id.clone(), app_name.clone())),
                            headers.clone(),
                            Json(request.clone()),
                        )
                        .await
                        .expect("the terminal receipt must replay as the same conflict");
                        assert_eq!(replayed.0, StatusCode::CONFLICT);
                        assert_eq!(replayed.1.0, terminal.1.0);

                        current_subject = next_subject;
                        current_issuer = next_issuer;
                    }
                    // Each scenario committed exactly one real rotation and
                    // consumed exactly one single-use token; no retry re-ran
                    // the mutation.
                    assert_eq!(
                        signer_rotation_receipts(&pool, app_id, org_id).await,
                        (scenarios.len() as i64, scenarios.len() as i64)
                    );
                },
            )
            .await;

    crate::test_support::drop_isolated_database("cap_signer_stale_checkpoint", pool).await;
}

#[tokio::test]
async fn keyring_unrelated_five_xx_stays_fail_closed() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_keyring_pending_unrelated").await;
    let current_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let replacement_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let (org_id, user_id, paas_org_id, paas_user_id) =
        seed_keyring_pending_org(&pool, &[current_key.clone(), replacement_key.clone()]).await;
    seed_owner_keyring_v1(&pool, org_id, user_id, &current_key).await;
    let mut state = idempotency_test_state(pool.clone());
    state.management_mode = crate::state::CapManagementMode::PaasManaged;
    let idempotency_key = format!("keyring-pending-unrelated-{}", Uuid::new_v4());
    let headers = config_token_actor_headers(&idempotency_key, &paas_user_id);
    let rotation = signed_rotation_body(org_id, user_id, &current_key, &replacement_key);
    let call = |state: AppState, headers: HeaderMap| {
        rotate_paas_keyring_owner(
            internal_test_auth(),
            State(state),
            Path(paas_org_id.clone()),
            headers,
            Json(rotation.clone()),
        )
    };

    // No signing service is configured: the handler fails with an
    // unrelated 503 before anything commits, and the wrapper must keep
    // the generic fail-closed disposition instead of deferring.
    let terminal = call(state.clone(), headers.clone())
        .await
        .expect_err("an unrelated 503 must fail closed, not defer");
    assert_eq!(terminal.0, StatusCode::CONFLICT);
    assert_eq!(terminal.1.0["error"], "idempotency_recovery_required");
    assert_eq!(terminal.1.0["idempotency_disposition"], "completed");
    assert_eq!(terminal.1.0["retryable"], false);

    // The fail-closed receipt is terminal and replays without
    // re-executing the handler.
    let (replayed_status, Json(replayed)) = call(state.clone(), headers.clone())
        .await
        .expect("the fail-closed receipt is terminal and replays");
    assert_eq!((replayed_status, replayed), (terminal.0, terminal.1.0));

    let versions: Vec<i64> =
        sqlx::query_scalar("SELECT version FROM org_keyrings WHERE org_id = $1 ORDER BY version")
            .bind(org_id)
            .fetch_all(&pool)
            .await
            .expect("read keyring versions after unrelated failure");
    assert_eq!(versions, vec![1]);
    let rotate_audits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log
              WHERE org_id = $1 AND action = 'org.keyring.owner.rotate'",
    )
    .bind(org_id)
    .fetch_one(&pool)
    .await
    .expect("count rotation audits after unrelated failure");
    assert_eq!(rotate_audits, 0);

    crate::test_support::drop_isolated_database("cap_keyring_pending_unrelated", pool).await;
}

/// The public create route and the hosted internal create must persist
/// the same app and resource rows for the same request: the shared write
/// core leaves only caller-derived fields (identity columns from the
/// deterministic PaaS app id, timestamps, and per-path org/name) to
/// legitimately differ.
#[tokio::test]
async fn public_and_hosted_creates_persist_identical_app_rows() {
    let (_db_cleanup, pool) =
        crate::test_support::isolated_database_test_pool("cap_create_parity").await;

    // The PaaS org carries the hosted management/entitlement rows its
    // pre-checks read; the public org is a plain core-class org.
    let paas_org_id = format!("paas-create-parity-{}", Uuid::new_v4().simple());
    let cap_org_id = Uuid::new_v4();
    let org_name = format!("parity{}", &cap_org_id.simple().to_string()[..8]);
    insert_mapped_org(&pool, cap_org_id, &org_name, &paas_org_id).await;
    sqlx::query(
        "INSERT INTO organization_management (org_id, mode, paas_org_id, status)
             VALUES ($1, 'paas_managed', $2, 'active')",
    )
    .bind(cap_org_id)
    .bind(&paas_org_id)
    .execute(&pool)
    .await
    .expect("mark parity org PaaS-managed");
    sqlx::query(
        "INSERT INTO organization_entitlements
                 (org_id, version, deploy_allowed, limits)
             VALUES ($1, 1, true, $2)",
    )
    .bind(cap_org_id)
    .bind(serde_json::json!({
        "name": "create-parity-test",
        "max_apps": 10,
        "max_cpu": "10",
        "max_memory": "10Gi",
        "max_storage": "100Gi"
    }))
    .execute(&pool)
    .await
    .expect("insert parity entitlement");

    let public_org_id = Uuid::new_v4();
    let public_org_name = format!("paritypub{}", &public_org_id.simple().to_string()[..8]);
    crate::db::orgs::insert_org_pool(&pool, public_org_id, &public_org_name, None, false)
        .await
        .expect("insert public parity organization");
    let public_user_id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, display_name) VALUES ($1, 'Parity Admin')")
        .bind(public_user_id)
        .execute(&pool)
        .await
        .expect("insert public parity user");
    sqlx::query("INSERT INTO memberships (user_id, org_id, role) VALUES ($1, $2, 'admin')")
        .bind(public_user_id)
        .bind(public_org_id)
        .execute(&pool)
        .await
        .expect("insert public parity membership");

    let state = idempotency_test_state(pool.clone());
    let pubkey_hash = "b".repeat(64);
    let signer_subject = "https://github.com/acme/app/.github/workflows/build.yml@refs/heads/main";
    let signer_issuer = "https://token.actions.githubusercontent.com";

    let (paas_status, Json(paas_response)) = create_paas_app(
        InternalAuth {
            client_san: "spiffe://paas.example.test/enclava-paas".to_string(),
        },
        State(state.clone()),
        Path(paas_org_id),
        idempotency_headers(&format!("create-parity-{}", Uuid::new_v4())),
        Json(InternalCreateAppRequest {
            name: "parity-app".to_string(),
            unlock_mode: "password".to_string(),
            bootstrap_pubkey_hash: Some(pubkey_hash.clone()),
            signer_identity_subject: Some(signer_subject.to_string()),
            signer_identity_issuer: Some(signer_issuer.to_string()),
            egress_allowlist: Vec::new(),
            egress_mode: "restricted".to_string(),
            resources: None,
        }),
    )
    .await
    .expect("hosted create should succeed");
    assert_eq!(paas_status, StatusCode::CREATED);

    let public_auth = AuthContext {
        user_id: public_user_id,
        org_id: public_org_id,
        org_name: public_org_name,
        role: Role::Admin,
        api_key: None,
        management_origin: ManagementOrigin::Public,
    };
    let (public_status, Json(public_response)) = crate::routes::apps::create_app(
        public_auth,
        State(state),
        Json(crate::routes::apps::CreateAppRequest {
            name: "parity-app".to_string(),
            unlock_mode: "password".to_string(),
            bootstrap_pubkey_hash: Some(pubkey_hash.clone()),
            signer_identity_subject: Some(signer_subject.to_string()),
            signer_identity_issuer: Some(signer_issuer.to_string()),
            source_provider: None,
            source_repository: None,
            egress_allowlist: Vec::new(),
            egress_mode: "restricted".to_string(),
        }),
    )
    .await
    .expect("public create should succeed");
    assert_eq!(public_status, StatusCode::CREATED);
    let paas_app_id: Uuid = paas_response["cap_app_id"]
        .as_str()
        .and_then(|value| Uuid::parse_str(value).ok())
        .expect("hosted create reports its app id");

    let mut paas_app: serde_json::Value =
        sqlx::query_scalar("SELECT row_to_json(a) FROM apps a WHERE id = $1")
            .bind(paas_app_id)
            .fetch_one(&pool)
            .await
            .expect("read hosted app row");
    let mut public_app: serde_json::Value =
        sqlx::query_scalar("SELECT row_to_json(a) FROM apps a WHERE id = $1")
            .bind(public_response.id)
            .fetch_one(&pool)
            .await
            .expect("read public app row");

    // Columns that legitimately differ between the two paths: identity
    // columns derived from the app id or the org/name, and timestamps.
    for key in [
        "id",
        "org_id",
        "tenant_id",
        "namespace",
        "instance_id",
        "service_account",
        "domain",
        "tee_domain",
        "tenant_instance_identity_hash",
        "signer_identity_set_at",
        "created_at",
        "updated_at",
    ] {
        paas_app.as_object_mut().unwrap().remove(key);
        public_app.as_object_mut().unwrap().remove(key);
    }
    assert_eq!(paas_app, public_app);

    let paas_resources: serde_json::Value =
        sqlx::query_scalar("SELECT row_to_json(r) FROM app_resources r WHERE app_id = $1")
            .bind(paas_app_id)
            .fetch_one(&pool)
            .await
            .expect("read hosted app resources");
    let public_resources: serde_json::Value =
        sqlx::query_scalar("SELECT row_to_json(r) FROM app_resources r WHERE app_id = $1")
            .bind(public_response.id)
            .fetch_one(&pool)
            .await
            .expect("read public app resources");
    let strip_app_id = |mut row: serde_json::Value| {
        row.as_object_mut().unwrap().remove("app_id");
        row
    };
    assert_eq!(strip_app_id(paas_resources), strip_app_id(public_resources));

    crate::test_support::drop_isolated_database("cap_create_parity", pool).await;
}

mod confidentiality_tests {
    use super::{project_internal_deployment_error, validated_proof_origin};

    #[test]
    fn proof_origin_accepts_only_bare_signed_https_domains() {
        let allowed = ["app.example", "custom.example"];
        assert_eq!(
            validated_proof_origin("https://custom.example", &allowed).as_deref(),
            Some("https://custom.example")
        );
        for rejected in [
            "http://app.example",
            "https://app.example.evil",
            "https://app.example/path",
            "https://user@app.example",
            "https://app.example:8443",
        ] {
            assert_eq!(validated_proof_origin(rejected, &allowed), None);
        }
    }

    #[test]
    fn stored_internal_deployment_errors_are_projected_without_plaintext() {
        const STORED_SECRET: &str =
            "pod 'tenant-pod' container 'tenant-app' is CrashLoopBackOff: secret=private-key";
        let response = serde_json::json!({
            "latest_deployment": {
                "status": "failed",
                "error_message": project_internal_deployment_error(None, Some(STORED_SECRET)),
            }
        });
        let serialized = serde_json::to_string(&response).expect("serialize internal response");

        assert_eq!(
            response["latest_deployment"]["error_message"],
            "deployment_error"
        );
        assert!(!serialized.contains(STORED_SECRET));
        assert!(!serialized.contains("private-key"));
        assert!(serialized.len() < 128);
    }

    #[test]
    fn internal_deployment_projection_preserves_safe_supersession_code() {
        let projected = project_internal_deployment_error(
            None,
            Some(crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR),
        );

        assert_eq!(
            projected.as_deref(),
            Some(crate::deploy::DEPLOYMENT_SUPERSEDED_ERROR)
        );
    }

    #[test]
    fn bounded_live_runtime_error_takes_precedence_over_recorded_error() {
        let live = "container_runtime_failure status=waiting code=crash_loop_back_off";
        let projected = project_internal_deployment_error(
            Some(live.to_string()),
            Some("stored-secret=tenant-token"),
        );

        assert_eq!(projected.as_deref(), Some(live));
    }
}
