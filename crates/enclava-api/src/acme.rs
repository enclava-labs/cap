use std::path::PathBuf;
use std::time::Duration;

use crate::dns::{self, DnsConfig};
use crate::workload_tls_timing::{Phase, RequestTiming};
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
    issue_dns01_certificate_timed(
        http_client,
        dns_config,
        acme_config,
        hostnames,
        csr_der,
        RequestTiming::new(),
    )
    .await
}

pub(crate) async fn issue_dns01_certificate_timed(
    http_client: &reqwest::Client,
    dns_config: &DnsConfig,
    acme_config: &AcmeConfig,
    hostnames: &[String],
    csr_der: &[u8],
    timing: RequestTiming,
) -> Result<String, AcmeError> {
    let account = timing
        .measure(Phase::AcmeAccount, load_or_create_account(acme_config))
        .await?;
    let identifiers = hostnames
        .iter()
        .map(|host| Identifier::Dns(host.clone()))
        .collect::<Vec<_>>();
    let mut order = timing
        .measure(
            Phase::AcmeOrder,
            account.new_order(&NewOrder::new(&identifiers)),
        )
        .await?;

    let mut challenge_records = Vec::new();
    {
        let mut authorizations = order.authorizations();
        loop {
            let mut authorization = timing.start(Phase::AcmeAuthorization);
            let result = authorizations.next().await;
            authorization.finish(result.as_ref().is_none_or(Result::is_ok));
            drop(authorization);
            let Some(result) = result else {
                break;
            };
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
            let record = timing
                .measure(
                    Phase::DnsCreate,
                    dns::create_txt_record(http_client, dns_config, &record_name, &record_value),
                )
                .await?;
            challenge_records.push(record);
            if let Err(err) = timing
                .measure(
                    Phase::DnsVisibility,
                    wait_for_txt_record(
                        &record_name,
                        &record_value,
                        acme_config.dns_propagation_wait,
                        timing,
                    ),
                )
                .await
            {
                cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
                return Err(err);
            }
            timing
                .measure(Phase::AcmeChallengeReady, challenge.set_ready())
                .await?;
        }
    }

    let status = timing
        .measure(
            Phase::AcmeOrderReady,
            order.poll_ready(&RetryPolicy::default()),
        )
        .await?;
    if status != OrderStatus::Ready {
        cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
        return Err(AcmeError::OrderStatus(status));
    }

    timing
        .measure(Phase::AcmeFinalize, order.finalize_csr(csr_der))
        .await?;
    let cert_chain = timing
        .measure(
            Phase::AcmeCertificate,
            order.poll_certificate(&RetryPolicy::default()),
        )
        .await?;
    cleanup_challenges(http_client, dns_config, &challenge_records, timing).await;
    Ok(cert_chain)
}

async fn wait_for_txt_record(
    record_name: &str,
    expected_value: &str,
    timeout: Duration,
    timing: RequestTiming,
) -> Result<(), AcmeError> {
    if timeout.is_zero() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match lookup_txt(record_name, timing).await {
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

async fn lookup_txt(name: &str, timing: RequestTiming) -> Result<Vec<String>, String> {
    match timing
        .measure(Phase::DnsExternalLookup, lookup_txt_external(name))
        .await
    {
        Ok(values) => Ok(values),
        Err(err) => {
            tracing::warn!(
                record = %name,
                error = %err,
                "external DNS lookup failed; falling back to system resolver"
            );
            timing
                .measure(Phase::DnsSystemLookup, lookup_txt_system(name))
                .await
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
    records: &[dns::DnsRecordHandle],
    timing: RequestTiming,
) {
    for record in records {
        if let Err(err) = timing
            .measure(
                Phase::DnsCleanup,
                dns::delete_txt_record(http_client, dns_config, record),
            )
            .await
        {
            tracing::warn!(
                record = %record.hostname(),
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
}
