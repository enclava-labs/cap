use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use enclava_common::image::ImageRef;
use enclava_engine::types::AttestationConfig;
use rand::rngs::OsRng;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use enclava_api::{
    auth::jwt, build_router, dns::DnsConfig, platform_release::PlatformRelease, state::AppState,
};

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn tee_accepts_invalid_certs() -> bool {
    std::env::var("TENANT_TEE_TLS_MODE")
        .map(|mode| matches!(mode.as_str(), "staging" | "insecure"))
        .unwrap_or(false)
        || env_flag("TENANT_TEE_ACCEPT_INVALID_CERTS")
}

fn read_key_file(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| anyhow::anyhow!("failed to read key file {}: {}", path, e))
}

fn load_signing_key() -> anyhow::Result<SigningKey> {
    if let Ok(path) = std::env::var("API_SIGNING_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PATH PKCS#8 key: {}", e));
    }

    if let Ok(b64) = std::env::var("API_SIGNING_KEY_PKCS8_BASE64") {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64: {}", e))?;
        return SigningKey::from_pkcs8_der(&bytes)
            .map_err(|e| anyhow::anyhow!("invalid API_SIGNING_KEY_PKCS8_BASE64 key: {}", e));
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral API signing key");
        return Ok(SigningKey::generate(&mut OsRng));
    }

    anyhow::bail!(
        "missing API signing key: set API_SIGNING_KEY_PATH or API_SIGNING_KEY_PKCS8_BASE64"
    )
}

fn load_hmac_key() -> anyhow::Result<[u8; 32]> {
    if let Ok(path) = std::env::var("SESSION_HMAC_KEY_PATH") {
        let bytes = read_key_file(&path)?;
        if bytes.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            return Ok(key);
        }

        let text = std::str::from_utf8(&bytes)
            .map_err(|e| anyhow::anyhow!("SESSION_HMAC_KEY_PATH content is not UTF-8: {}", e))?;
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .map_err(|e| {
                anyhow::anyhow!(
                    "SESSION_HMAC_KEY_PATH is neither raw 32 bytes nor base64: {}",
                    e
                )
            })?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_PATH must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if let Ok(b64) = std::env::var("SESSION_HMAC_KEY_BASE64") {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .map_err(|e| anyhow::anyhow!("invalid SESSION_HMAC_KEY_BASE64: {}", e))?;
        if decoded.len() != 32 {
            anyhow::bail!(
                "SESSION_HMAC_KEY_BASE64 must decode to exactly 32 bytes, got {}",
                decoded.len()
            );
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        return Ok(key);
    }

    if env_flag("ALLOW_EPHEMERAL_KEYS") {
        tracing::warn!("ALLOW_EPHEMERAL_KEYS enabled: generating ephemeral JWT HMAC key");
        return Ok(jwt::generate_hmac_key());
    }

    anyhow::bail!("missing session HMAC key: set SESSION_HMAC_KEY_PATH or SESSION_HMAC_KEY_BASE64")
}

fn parse_image_ref(name: &str, value: &str) -> anyhow::Result<ImageRef> {
    let image = ImageRef::parse(value)
        .map_err(|e| anyhow::anyhow!("invalid {name} image reference: {}", e))?;
    image
        .require_digest()
        .map_err(|e| anyhow::anyhow!("invalid {name}: {}", e))?;
    Ok(image)
}

fn load_url_env(env_name: &str, required: bool) -> anyhow::Result<Option<String>> {
    load_url_value(env_name, env_nonempty(env_name), required)
}

fn load_url_value(
    name: &str,
    value: Option<String>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        if required {
            anyhow::bail!("missing {name}");
        }
        return Ok(None);
    };
    let url =
        reqwest::Url::parse(&value).map_err(|e| anyhow::anyhow!("invalid {name} URL: {}", e))?;
    if !matches!(url.scheme(), "http" | "https") {
        anyhow::bail!("invalid {name}: URL scheme must be http or https");
    }
    Ok(Some(value))
}

fn load_pubkey_hex_value(
    name: &str,
    value: Option<String>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else {
        if required {
            anyhow::bail!("missing {name}");
        }
        return Ok(None);
    };
    let raw = hex::decode(&value).map_err(|e| anyhow::anyhow!("invalid {name}: {}", e))?;
    if raw.len() != 32 {
        anyhow::bail!("invalid {name}: expected 32-byte Ed25519 public key hex");
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn platform_release_enabled(trustee_policy_read_available: bool) -> bool {
    trustee_policy_read_available
        || env_flag("ENCLAVA_USE_PLATFORM_RELEASE")
        || env_nonempty("ENCLAVA_PLATFORM_RELEASE_PATH").is_some()
}

fn load_platform_release(enabled: bool) -> anyhow::Result<Option<PlatformRelease>> {
    if !enabled {
        return Ok(None);
    }
    let release = PlatformRelease::load_verified()
        .map_err(|e| anyhow::anyhow!("failed to load signed platform release: {}", e))?;
    if release.expected_runtime_class
        != enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS
    {
        anyhow::bail!(
            "signed platform release runtime class `{}` does not match API runtime class `{}`",
            release.expected_runtime_class,
            enclava_engine::manifest::cc_init_data::DEFAULT_RUNTIME_CLASS
        );
    }
    Ok(Some(release))
}

fn release_env_value(
    env_name: &str,
    release_value: Option<&str>,
    required: bool,
) -> anyhow::Result<Option<String>> {
    match (env_nonempty(env_name), release_value) {
        (Some(value), Some(expected)) => {
            if value != expected {
                anyhow::bail!(
                    "{env_name} conflicts with signed platform release: env `{value}` != release `{expected}`"
                );
            }
            Ok(Some(value))
        }
        (Some(value), None) => Ok(Some(value)),
        (None, Some(expected)) => Ok(Some(expected.to_string())),
        (None, None) if required => anyhow::bail!("missing {env_name}"),
        (None, None) => Ok(None),
    }
}

fn load_attestation_config(
    platform_release: Option<&PlatformRelease>,
) -> anyhow::Result<Option<AttestationConfig>> {
    let trustee_policy_read_available = env_flag("TRUSTEE_POLICY_READ_AVAILABLE");
    let proxy_image_ref = release_env_value(
        "ATTESTATION_PROXY_IMAGE",
        platform_release.map(|release| release.attestation_proxy_image.as_str()),
        false,
    )?;
    let caddy_image_ref = release_env_value(
        "CADDY_INGRESS_IMAGE",
        platform_release.map(|release| release.caddy_ingress_image.as_str()),
        false,
    )?;
    let has_any = proxy_image_ref.is_some() || caddy_image_ref.is_some();
    if !has_any {
        if trustee_policy_read_available {
            anyhow::bail!(
                "TRUSTEE_POLICY_READ_AVAILABLE=true requires ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE"
            );
        }
        tracing::warn!(
            "ATTESTATION_PROXY_IMAGE and CADDY_INGRESS_IMAGE are unset; deploy requests will fail until configured"
        );
        return Ok(None);
    }
    let Some(proxy_image_ref) = proxy_image_ref else {
        anyhow::bail!("missing ATTESTATION_PROXY_IMAGE");
    };
    let Some(caddy_image_ref) = caddy_image_ref else {
        anyhow::bail!("missing CADDY_INGRESS_IMAGE");
    };

    let workload_artifacts_url =
        load_url_env("WORKLOAD_ARTIFACTS_URL", trustee_policy_read_available)?;
    let trustee_policy_url = load_url_env("TRUSTEE_POLICY_URL", trustee_policy_read_available)?;
    let release_pubkey =
        platform_release.map(|release| release.signing_service_pubkey_hex.as_str());
    let platform_trustee_policy_pubkey_hex = load_pubkey_hex_value(
        "PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX",
        release_env_value("PLATFORM_TRUSTEE_POLICY_PUBKEY_HEX", release_pubkey, false)?,
        false,
    )?;
    let signing_service_pubkey_hex = load_pubkey_hex_value(
        "SIGNING_SERVICE_PUBKEY_HEX",
        release_env_value("SIGNING_SERVICE_PUBKEY_HEX", release_pubkey, false)?,
        false,
    )?;

    Ok(AttestationConfig {
        proxy_image: parse_image_ref("ATTESTATION_PROXY_IMAGE", &proxy_image_ref)?,
        caddy_image: parse_image_ref("CADDY_INGRESS_IMAGE", &caddy_image_ref)?,
        acme_ca_url: std::env::var("TENANT_CADDY_ACME_CA")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(enclava_engine::types::default_acme_ca_url),
        trustee_policy_read_available,
        workload_artifacts_url,
        trustee_policy_url,
        local_workload_artifacts_json: None,
        local_trustee_policy_json: None,
        platform_trustee_policy_pubkey_hex,
        signing_service_pubkey_hex,
    }
    .into())
}

fn load_dns_config() -> anyhow::Result<Option<DnsConfig>> {
    let required = env_flag("DNS_MANAGEMENT_REQUIRED");
    let cloudflare_api_token = match std::env::var("CLOUDFLARE_API_TOKEN") {
        Ok(token) if !token.trim().is_empty() => token,
        _ if required => anyhow::bail!("missing CLOUDFLARE_API_TOKEN"),
        _ => {
            tracing::warn!(
                "CLOUDFLARE_API_TOKEN is unset; CAP DNS management is disabled for this process"
            );
            return Ok(None);
        }
    };

    let cloudflare_zone_name =
        std::env::var("CLOUDFLARE_ZONE_NAME").unwrap_or_else(|_| "enclava.dev".to_string());
    let target = match std::env::var("TENANT_DNS_TARGET") {
        Ok(target) if !target.trim().is_empty() => target,
        _ if required => anyhow::bail!("missing TENANT_DNS_TARGET"),
        _ => {
            tracing::warn!(
                "TENANT_DNS_TARGET is unset; CAP DNS management is disabled for this process"
            );
            return Ok(None);
        }
    };

    Ok(Some(DnsConfig {
        cloudflare_api_token,
        cloudflare_zone_id: std::env::var("CLOUDFLARE_ZONE_ID")
            .ok()
            .filter(|v| !v.trim().is_empty()),
        cloudflare_zone_name,
        target,
        required,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclava_api=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Err(e) = enclava_api::env_gates::enforce_production_env_gates() {
        eprintln!("startup refused: {e}");
        std::process::exit(1);
    }

    let trustee_policy_read_available = env_flag("TRUSTEE_POLICY_READ_AVAILABLE");
    let platform_release =
        match load_platform_release(platform_release_enabled(trustee_policy_read_available)) {
            Ok(release) => release,
            Err(e) => {
                eprintln!("startup refused: {e}");
                std::process::exit(1);
            }
        };
    if let Some(release) = &platform_release {
        tracing::info!(
            platform_release_version = %release.platform_release_version,
            genpolicy_version = %release.genpolicy_version,
            "signed platform release loaded"
        );
    }

    // Phase 11: cosign-verify the platform-controlled sidecars before serving
    // any deploy/unlock requests. Refusing to start prevents an operator who
    // has swapped a sidecar image from booting CAP and minting cc_init_data
    // that anchors the swapped digest.
    let startup_proxy_image = match release_env_value(
        "ATTESTATION_PROXY_IMAGE",
        platform_release
            .as_ref()
            .map(|release| release.attestation_proxy_image.as_str()),
        false,
    ) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    };
    let startup_caddy_image = match release_env_value(
        "CADDY_INGRESS_IMAGE",
        platform_release
            .as_ref()
            .map(|release| release.caddy_ingress_image.as_str()),
        false,
    ) {
        Ok(value) => value,
        Err(e) => {
            eprintln!("startup refused: {e}");
            std::process::exit(1);
        }
    };
    match enclava_api::cosign::sidecar_pins_from_images(
        startup_proxy_image.as_deref(),
        startup_caddy_image.as_deref(),
    ) {
        Ok(Some(pins)) => match enclava_api::cosign::verify_sidecars_at_startup(&pins).await {
            Ok(v) => tracing::info!(
                attestation_proxy = %v.attestation_proxy,
                caddy_ingress = %v.caddy_ingress,
                "platform sidecar images verified"
            ),
            Err(e) => {
                eprintln!("startup refused: sidecar cosign verification failed: {e}");
                std::process::exit(1);
            }
        },
        Ok(None) => tracing::warn!(
            "no sidecar images configured; deploy requests will fail until \
             ATTESTATION_PROXY_IMAGE/CADDY_INGRESS_IMAGE are set"
        ),
        Err(e) => {
            eprintln!("startup refused: invalid sidecar pin configuration: {e}");
            std::process::exit(1);
        }
    }

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let api_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let btcpay_url =
        std::env::var("BTCPAY_URL").unwrap_or_else(|_| "http://localhost:23001".to_string());
    let btcpay_api_key = std::env::var("BTCPAY_API_KEY").unwrap_or_default();
    let btcpay_webhook_secret = std::env::var("BTCPAY_WEBHOOK_SECRET").unwrap_or_default();
    let platform_domain =
        std::env::var("PLATFORM_DOMAIN").unwrap_or_else(|_| "enclava.dev".to_string());
    let tee_domain_suffix =
        std::env::var("TEE_DOMAIN_SUFFIX").unwrap_or_else(|_| format!("tee.{}", platform_domain));

    let pool = enclava_api::db::pool::create_pool(&database_url)
        .await
        .expect("failed to connect to database");

    enclava_api::db::pool::run_migrations(&pool)
        .await
        .expect("failed to run migrations");

    let signing_key = load_signing_key().expect("failed to load API signing key");
    tracing::info!(
        "API signing public key (base64): {}",
        enclava_api::auth::jwt::public_key_base64(&signing_key)
    );

    let hmac_key = load_hmac_key().expect("failed to load session HMAC key");
    tracing::info!("Loaded session HMAC key");
    let attestation = load_attestation_config(platform_release.as_ref())
        .expect("failed to load attestation config");
    let dns = load_dns_config().expect("failed to load DNS config");
    let kbs_policy = enclava_api::kbs::config_from_env();
    let trustee_required = attestation
        .as_ref()
        .map(|cfg| cfg.trustee_policy_read_available)
        .unwrap_or(false);
    let trustee_attestation_verify_url =
        load_url_env("TRUSTEE_ATTESTATION_VERIFY_URL", trustee_required)
            .expect("failed to load Trustee attestation verify URL");
    // The signed release identifies the signing-service key and default URL,
    // but the transport address is deployment-local. CAP may need an internal
    // cluster DNS name while customer tooling uses the public API broker.
    let signing_service_url = load_url_value(
        "PLATFORM_SIGNING_SERVICE_URL",
        env_nonempty("PLATFORM_SIGNING_SERVICE_URL").or_else(|| {
            platform_release
                .as_ref()
                .map(|release| release.signing_service_url.clone())
        }),
        trustee_required,
    )
    .expect("failed to load platform signing service URL");
    let signing_service = signing_service_url.map(|url| {
        enclava_api::signing_service::SigningServiceClient::new(
            url,
            env_nonempty("PLATFORM_SIGNING_SERVICE_TOKEN"),
        )
        .expect("failed to configure platform signing service client")
    });
    let require_customer_signed_policy_artifact =
        env_flag("REQUIRE_CUSTOMER_SIGNED_POLICY_ARTIFACT");
    let max_concurrent_applies = std::env::var("CAP_MAX_CONCURRENT_APPLIES")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    tracing::info!(
        max_concurrent_applies,
        "configured deployment apply concurrency"
    );
    let tee_http_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(tee_accepts_invalid_certs())
        .https_only(true)
        .build()
        .expect("failed to build tenant TEE HTTP client");

    let outbound_config = enclava_api::clients::ClientConfig::from_env();
    let http_client = enclava_api::clients::build_guarded_client(&outbound_config)
        .expect("failed to build SSRF-defended outbound HTTP client");

    let state = AppState {
        db: pool,
        signing_key: Arc::new(signing_key),
        hmac_key: Arc::new(hmac_key),
        api_url,
        btcpay_url,
        btcpay_api_key,
        platform_domain,
        tee_domain_suffix,
        http_client,
        tee_http_client,
        btcpay_webhook_secret,
        attestation,
        dns,
        kbs_policy,
        trustee_attestation_verify_url,
        signing_service,
        require_customer_signed_policy_artifact,
        deployment_apply_permits: Arc::new(tokio::sync::Semaphore::new(max_concurrent_applies)),
    };

    let app = build_router(state);

    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("failed to bind");
    tracing::info!("listening on {}", bind_addr);

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
    .expect("server error");
}
