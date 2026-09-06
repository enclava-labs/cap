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
    pub dns_lookup_prefer_system: bool,
    pub dns_lookup_timeout: Option<Duration>,
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
                    wait_for_txt_record(&record_name, &record_value, acme_config, timing),
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
    config: &AcmeConfig,
    timing: RequestTiming,
) -> Result<(), AcmeError> {
    if config.dns_propagation_wait.is_zero() {
        return Ok(());
    }

    let deadline = tokio::time::Instant::now() + config.dns_propagation_wait;
    loop {
        match lookup_txt(record_name, config, timing).await {
            Ok(values) if values.iter().any(|value| value == expected_value) => return Ok(()),
            Ok(_) => tracing::info!("waiting for ACME DNS-01 TXT propagation"),
            Err(_) => tracing::info!("waiting for ACME DNS-01 TXT lookup"),
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(AcmeError::DnsPropagation {
                record_name: record_name.to_string(),
            });
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn lookup_txt(
    name: &str,
    config: &AcmeConfig,
    timing: RequestTiming,
) -> Result<Vec<String>, String> {
    lookup_txt_with_resolvers(config, timing, |system| async move {
        if system {
            lookup_txt_system(name).await
        } else {
            lookup_txt_external(name).await
        }
    })
    .await
}

async fn lookup_txt_with_resolvers<F: std::future::Future<Output = Result<Vec<String>, String>>>(
    config: &AcmeConfig,
    timing: RequestTiming,
    mut lookup: impl FnMut(bool) -> F,
) -> Result<Vec<String>, String> {
    let mut last_error = String::new();
    for system in [
        config.dns_lookup_prefer_system,
        !config.dns_lookup_prefer_system,
    ] {
        let phase = if system {
            Phase::DnsSystemLookup
        } else {
            Phase::DnsExternalLookup
        };
        let result = timing
            .measure(phase, async {
                let work = lookup(system);
                match config.dns_lookup_timeout {
                    Some(timeout) => tokio::time::timeout(timeout, work)
                        .await
                        .map_err(|_| "DNS TXT lookup timed out".to_string())?,
                    None => work.await,
                }
            })
            .await;
        match result {
            // Empty or nonmatching answers still belong to this resolver. The
            // propagation loop, not the fallback, checks the exact challenge.
            Ok(values) => return Ok(values),
            Err(err) => last_error = err,
        }
        if system == config.dns_lookup_prefer_system {
            let message = if system {
                "system DNS lookup failed; falling back to external resolver"
            } else {
                "external DNS lookup failed; falling back to system resolver"
            };
            tracing::warn!("{message}");
        }
    }
    Err(last_error)
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
    use super::*;

    fn config(system: bool, timeout: Option<Duration>) -> AcmeConfig {
        AcmeConfig {
            directory_url: "https://acme.invalid/directory".into(),
            account_credentials_path: None,
            dns_propagation_wait: Duration::from_secs(30),
            dns_lookup_prefer_system: system,
            dns_lookup_timeout: timeout,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn lookup_timings_follow_actual_order_and_do_not_log_answers_or_errors() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        struct Writer(Arc<Mutex<Vec<u8>>>);
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for system in [false, true] {
            let logs = Arc::new(Mutex::new(Vec::new()));
            let output = logs.clone();
            let subscriber = tracing_subscriber::fmt()
                .without_time()
                .with_ansi(false)
                .with_env_filter("enclava_api=debug,cap::workload_tls_timing=debug")
                .with_writer(move || Writer(output.clone()))
                .finish();
            let _guard = tracing::subscriber::set_default(subscriber);
            lookup_txt_with_resolvers(&config(system, None), RequestTiming::new(), |resolver| {
                std::future::ready(if resolver == system {
                    Err("private-error".into())
                } else {
                    Ok(vec!["private-answer".into()])
                })
            })
            .await
            .unwrap();
            let text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
            assert!(!text.contains("private-"));
            let lines: Vec<_> = text
                .lines()
                .filter(|line| line.contains("event=\"workload_tls_timing\""))
                .collect();
            assert_eq!(lines.len(), 2);
            let phases = if system {
                ["dns_system_lookup", "dns_external_lookup"]
            } else {
                ["dns_external_lookup", "dns_system_lookup"]
            };
            for (line, phase) in lines.iter().zip(phases) {
                assert!(line.contains(&format!("phase=\"{phase}\"")));
            }
            assert!(lines[0].contains("outcome=\"error\""));
            assert!(lines[1].contains("outcome=\"success\""));
            let seq = |line: &str| {
                line.split_whitespace()
                    .find(|field| field.starts_with("request_seq="))
                    .unwrap()
                    .to_owned()
            };
            assert_eq!(seq(lines[0]), seq(lines[1]));
        }
        let source = include_str!("acme.rs");
        let wait = source
            .split("async fn wait_for_txt_record")
            .nth(1)
            .unwrap()
            .split("async fn lookup_txt")
            .next()
            .unwrap();
        assert!(!wait.contains("expected ="));
        assert!(!wait.contains("observed ="));
        assert!(!wait.contains("error ="));
        assert!(wait.contains("value == expected_value"));
    }

    #[tokio::test]
    async fn resolver_success_including_negative_answers_never_falls_back() {
        for system in [false, true] {
            for values in [vec![], vec!["wrong".into()], vec!["expected".into()]] {
                let mut calls = Vec::new();
                let result = lookup_txt_with_resolvers(
                    &config(system, None),
                    RequestTiming::new(),
                    |resolver| {
                        calls.push(resolver);
                        std::future::ready(Ok(values.clone()))
                    },
                )
                .await
                .unwrap();
                assert_eq!(result, values);
                assert_eq!(calls, vec![system]);
            }
        }
    }

    #[tokio::test]
    async fn resolver_errors_fall_back_in_configured_order() {
        for system in [false, true] {
            for fallback in [Ok(vec!["expected".into()]), Err("secondary failed".into())] {
                let mut calls = Vec::new();
                let result = lookup_txt_with_resolvers(
                    &config(system, None),
                    RequestTiming::new(),
                    |resolver| {
                        calls.push(resolver);
                        std::future::ready(if resolver == system {
                            Err("primary failed".into())
                        } else {
                            fallback.clone()
                        })
                    },
                )
                .await;
                assert_eq!(result, fallback);
                assert_eq!(calls, vec![system, !system]);
            }
        }
    }

    struct DropFlag<'a>(&'a std::cell::Cell<bool>);
    impl Drop for DropFlag<'_> {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    #[tokio::test]
    async fn timeout_drops_primary_before_fallback_and_bounds_secondary() {
        for system in [false, true] {
            for secondary_stalls in [false, true] {
                let dropped = std::cell::Cell::new(false);
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    lookup_txt_with_resolvers(
                        &config(system, Some(Duration::from_millis(10))),
                        RequestTiming::new(),
                        |resolver| {
                            let dropped = &dropped;
                            async move {
                                if resolver == system {
                                    let _guard = DropFlag(dropped);
                                    std::future::pending::<()>().await;
                                } else {
                                    assert!(dropped.get());
                                    if secondary_stalls {
                                        std::future::pending::<()>().await;
                                    }
                                }
                                Ok(vec!["expected".into()])
                            }
                        },
                    ),
                )
                .await
                .expect("both attempts must be bounded");
                assert!(dropped.get());
                if secondary_stalls {
                    assert_eq!(result.unwrap_err(), "DNS TXT lookup timed out");
                } else {
                    assert_eq!(result.unwrap(), vec!["expected"]);
                }
            }
        }
    }

    #[tokio::test]
    async fn unset_timeout_preserves_native_wait_and_outer_cancellation_drops_work() {
        let dropped = std::cell::Cell::new(false);
        let calls = std::cell::Cell::new(0);
        let result = tokio::time::timeout(
            Duration::from_millis(30),
            lookup_txt_with_resolvers(&config(false, None), RequestTiming::new(), |_| async {
                calls.set(calls.get() + 1);
                let _guard = DropFlag(&dropped);
                std::future::pending::<Result<Vec<String>, String>>().await
            }),
        )
        .await;
        assert!(result.is_err());
        assert!(dropped.get());
        assert_eq!(calls.get(), 1);
    }
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
        let fallback = source
            .split("async fn lookup_txt_system")
            .nth(1)
            .expect("lookup_txt_system function");

        assert!(
            fallback.contains("builder_tokio()"),
            "ACME DNS-01 TXT self-check must fall back to a fresh system resolver when pod egress to external DNS is blocked"
        );
    }
}
