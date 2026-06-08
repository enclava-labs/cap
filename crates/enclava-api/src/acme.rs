use std::path::PathBuf;
use std::time::Duration;

use crate::dns::{self, DnsConfig};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, OrderStatus, RetryPolicy,
};

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub account_credentials_path: Option<PathBuf>,
    pub dns_propagation_wait: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    #[error("ACME account load failed: {0}")]
    AccountLoad(String),
    #[error("ACME failed: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("DNS challenge failed: {0}")]
    Dns(#[from] dns::DnsError),
    #[error("invalid CSR DER base64: {0}")]
    Csr(String),
    #[error("unexpected ACME authorization status: {0:?}")]
    AuthorizationStatus(AuthorizationStatus),
    #[error("unexpected ACME order status: {0:?}")]
    OrderStatus(OrderStatus),
    #[error("DNS challenge TXT did not propagate for {record_name}")]
    DnsPropagation { record_name: String },
    #[error("account credential persistence failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("account credential serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn issue_dns01_certificate(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
) -> Result<String, AcmeError> {
    let account = load_or_create_account(acme_config).await?;
    let identifiers = hostnames
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

    let mut challenge_records = Vec::new();
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                other => return Err(AcmeError::AuthorizationStatus(other)),
            }
            let mut challenge = authz.challenge(ChallengeType::Dns01).ok_or_else(|| {
                AcmeError::AccountLoad("ACME order has no DNS-01 challenge".into())
            })?;
            let hostname = challenge.identifier().to_string();
            let record_name = format!("_acme-challenge.{hostname}");
            let record_value = challenge.key_authorization().dns_value();
            dns::ensure_txt_record(http_client, dns_config, &record_name, &record_value).await?;
            challenge_records.push((record_name.clone(), record_value.clone()));
            if let Err(err) = wait_for_txt_record(
                &record_name,
                &record_value,
                acme_config.dns_propagation_wait,
            )
            .await
            {
                cleanup_challenges(http_client, dns_config, &challenge_records).await;
                return Err(err);
            }
            challenge.set_ready().await?;
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        cleanup_challenges(http_client, dns_config, &challenge_records).await;
        return Err(AcmeError::OrderStatus(status));
    }

    if let Err(err) = finalize_csr_after_ready(&mut order, csr_der).await {
        cleanup_challenges(http_client, dns_config, &challenge_records).await;
        return Err(err);
    }
    let cert_chain = match poll_certificate_after_finalize(&mut order).await {
        Ok(cert_chain) => cert_chain,
        Err(err) => {
            cleanup_challenges(http_client, dns_config, &challenge_records).await;
            return Err(err);
        }
    };
    cleanup_challenges(http_client, dns_config, &challenge_records).await;
    Ok(cert_chain)
}

async fn finalize_csr_after_ready(
    order: &mut instant_acme::Order,
    csr_der: &[u8],
) -> Result<(), AcmeError> {
    for attempt in 0..5 {
        match order.finalize_csr(csr_der).await {
            Ok(()) => return Ok(()),
            Err(err) if attempt < 4 && is_order_not_ready_finalize_error(&err.to_string()) => {
                let status = order.poll_ready(&RetryPolicy::default()).await?;
                if status != OrderStatus::Ready {
                    return Err(AcmeError::OrderStatus(status));
                }
                tokio::time::sleep(Duration::from_secs(1 + attempt)).await;
            }
            Err(err) => return Err(AcmeError::Acme(err)),
        }
    }
    unreachable!("bounded finalize retry loop always returns")
}

fn is_order_not_ready_finalize_error(message: &str) -> bool {
    message.contains("orderNotReady")
        || (message.contains("not acceptable for finalization") && message.contains("pending"))
}

async fn poll_certificate_after_finalize(
    order: &mut instant_acme::Order,
) -> Result<String, AcmeError> {
    for attempt in 0..5 {
        match order.poll_certificate(&RetryPolicy::default()).await {
            Ok(cert_chain) => return Ok(cert_chain),
            Err(err) if attempt < 4 && is_certificate_not_found_poll_error(&err.to_string()) => {
                tokio::time::sleep(Duration::from_secs(1 + attempt)).await;
            }
            Err(err) => return Err(AcmeError::Acme(err)),
        }
    }
    unreachable!("bounded certificate polling retry loop always returns")
}

fn is_certificate_not_found_poll_error(message: &str) -> bool {
    message.contains("Certificate not found")
        && message.contains("urn:ietf:params:acme:error:malformed")
}

async fn wait_for_txt_record(
    record_name: &str,
    expected_value: &str,
    timeout: Duration,
) -> Result<(), AcmeError> {
    if timeout.is_zero() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match lookup_txt(record_name).await {
            Ok(values) if values.iter().any(|value| value == expected_value) => return Ok(()),
            Ok(values) => tracing::info!(
                record = %record_name,
                expected = %expected_value,
                observed = ?values,
                "waiting for ACME DNS-01 TXT propagation"
            ),
            Err(err) => tracing::info!(
                record = %record_name,
                error = %err,
                "waiting for ACME DNS-01 TXT lookup"
            ),
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::DnsPropagation {
                record_name: record_name.to_string(),
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn lookup_txt(name: &str) -> Result<Vec<String>, String> {
    match lookup_txt_external(name).await {
        Ok(values) => Ok(values),
        Err(err) => {
            tracing::warn!(
                record = %name,
                error = %err,
                "external DNS lookup failed; falling back to system resolver"
            );
            lookup_txt_system(name).await
        }
    }
}

async fn lookup_txt_external(name: &str) -> Result<Vec<String>, String> {
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::udp_and_tcp(&CLOUDFLARE),
        TokioRuntimeProvider::default(),
    )
    .with_options(ResolverOpts::default())
    .build()
    .map_err(|e| e.to_string())?;
    collect_txt_values(resolver.txt_lookup(name).await.map_err(|e| e.to_string())?)
}

async fn lookup_txt_system(name: &str) -> Result<Vec<String>, String> {
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .map_err(|e| e.to_string())?;
    collect_txt_values(resolver.txt_lookup(name).await.map_err(|e| e.to_string())?)
}

fn collect_txt_values(response: hickory_resolver::lookup::Lookup) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for record in response.answers() {
        let RData::TXT(rdata) = &record.data else {
            continue;
        };
        for chunk in rdata.txt_data.iter() {
            if let Ok(s) = std::str::from_utf8(chunk) {
                out.push(s.to_string());
            }
        }
    }
    Ok(out)
}

async fn cleanup_challenges(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    records: &[(String, String)],
) {
    for (name, value) in records {
        if let Err(err) = dns::delete_txt_record(http_client, dns_config, name, value).await {
            tracing::warn!(
                record = %name,
                error = %err,
                "failed to clean up ACME DNS-01 TXT record"
            );
        }
    }
}

async fn load_or_create_account(config: &AcmeConfig) -> Result<Account, AcmeError> {
    if let Some(path) = config.account_credentials_path.as_ref()
        && path.is_file()
    {
        let bytes = std::fs::read(path)?;
        let credentials: AccountCredentials = serde_json::from_slice(&bytes)?;
        return Account::builder()?
            .from_credentials(credentials)
            .await
            .map_err(AcmeError::Acme);
    }

    let (account, credentials) = Account::builder()?
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            config.directory_url.clone(),
            None,
        )
        .await?;
    if let Some(path) = config.account_credentials_path.as_ref() {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, serde_json::to_vec(&credentials)?)?;
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns01_challenge_is_marked_ready_after_propagation_wait() {
        let source = include_str!("acme.rs");
        let wait_pos = source.find("wait_for_txt_record").expect("TXT self-check");
        let ready_pos = source
            .find("challenge.set_ready()")
            .expect("set_ready call");

        assert!(
            wait_pos < ready_pos,
            "ACME DNS-01 must verify TXT propagation before challenge.set_ready()"
        );
    }

    #[test]
    fn dns01_txt_lookup_prefers_external_resolver() {
        let source = include_str!("acme.rs");
        let lookup = source
            .split("async fn lookup_txt_external")
            .nth(1)
            .expect("lookup_txt_external function");

        assert!(
            lookup.contains("ResolverConfig::udp_and_tcp(&CLOUDFLARE)"),
            "ACME DNS-01 TXT self-check should use an external recursive resolver"
        );
    }

    #[test]
    fn dns01_txt_lookup_falls_back_when_external_dns_is_blocked() {
        let source = include_str!("acme.rs");
        let lookup = source
            .split("async fn lookup_txt")
            .nth(1)
            .expect("lookup_txt function");
        let fallback = source
            .split("async fn lookup_txt_system")
            .nth(1)
            .expect("lookup_txt_system function");

        assert!(
            fallback.contains("builder_tokio()"),
            "ACME DNS-01 TXT self-check must fall back to a fresh system resolver when pod egress to external DNS is blocked"
        );
        assert!(
            lookup.contains("external DNS lookup failed; falling back to system resolver"),
            "ACME DNS-01 TXT fallback should log external resolver failures for live diagnosis"
        );
    }

    #[test]
    fn dns01_finalize_retries_pending_order_not_ready_errors() {
        assert!(super::is_order_not_ready_finalize_error(
            "ACME failed: API error: Order's status (\"pending\") is not acceptable for finalization (urn:ietf:params:acme:error:orderNotReady)"
        ));
        assert!(!super::is_order_not_ready_finalize_error(
            "ACME failed: API error: account is rate limited"
        ));

        let source = include_str!("acme.rs");
        let finalize = source
            .split("async fn finalize_csr_after_ready")
            .nth(1)
            .expect("finalize retry helper");

        assert!(
            finalize.contains("order.finalize_csr(csr_der).await"),
            "ACME DNS-01 must finalize the CSR in the helper"
        );
        assert!(
            finalize.contains("order.poll_ready(&RetryPolicy::default()).await"),
            "ACME DNS-01 must re-poll order readiness before retrying a pending finalization"
        );
    }

    #[test]
    fn dns01_certificate_poll_retries_staging_certificate_not_found() {
        assert!(super::is_certificate_not_found_poll_error(
            "ACME failed: API error: Certificate not found (urn:ietf:params:acme:error:malformed)"
        ));
        assert!(!super::is_certificate_not_found_poll_error(
            "ACME failed: API error: account is rate limited"
        ));

        let source = include_str!("acme.rs");
        let poll = source
            .split("async fn poll_certificate_after_finalize")
            .nth(1)
            .expect("certificate polling retry helper");

        assert!(
            poll.contains("order.poll_certificate(&RetryPolicy::default()).await"),
            "ACME DNS-01 must poll the finalized certificate in the helper"
        );
        assert!(
            poll.contains("is_certificate_not_found_poll_error"),
            "ACME DNS-01 must retry transient staging certificate-not-found polling errors"
        );
    }
}
