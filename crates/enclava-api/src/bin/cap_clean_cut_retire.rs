use sha2::{Digest, Sha256};

fn install_default_rustls_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

fn require_exact_execute_confirmation(value: Option<&str>) -> anyhow::Result<()> {
    match value {
        Some("true") => Ok(()),
        Some(_) => anyhow::bail!("CAP_CLEAN_CUT_RETIRE_EXECUTE must be exactly `true`"),
        None => anyhow::bail!("execute requires CAP_CLEAN_CUT_RETIRE_EXECUTE=true"),
    }
}

fn exact_execute_confirmation() -> anyhow::Result<()> {
    match std::env::var("CAP_CLEAN_CUT_RETIRE_EXECUTE") {
        Ok(value) => require_exact_execute_confirmation(Some(value.as_str())),
        Err(std::env::VarError::NotPresent) => require_exact_execute_confirmation(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("CAP_CLEAN_CUT_RETIRE_EXECUTE must be valid UTF-8")
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    install_default_rustls_crypto_provider();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "enclava_api=info".into()),
        )
        .json()
        .init();

    let mut execute = false;
    let mut validate_plan_only = false;
    for argument in std::env::args().skip(1) {
        match argument.as_str() {
            "--execute" if !execute && !validate_plan_only => execute = true,
            "--validate-plan" if !validate_plan_only && !execute => validate_plan_only = true,
            _ => anyhow::bail!(
                "usage: cap-clean-cut-retire [--validate-plan|--execute]; dry-run is the default"
            ),
        }
    }

    let plan_path = std::env::var("CAP_CLEAN_CUT_RETIRE_PLAN_PATH")
        .map_err(|_| anyhow::anyhow!("CAP_CLEAN_CUT_RETIRE_PLAN_PATH is required"))?;
    let plan_bytes = std::fs::read(&plan_path)
        .map_err(|error| anyhow::anyhow!("failed to read clean-cut plan: {error}"))?;
    let plan_sha256 = hex::encode(Sha256::digest(&plan_bytes));
    let plan: enclava_api::clean_cut::CleanCutPlan = serde_json::from_slice(&plan_bytes)
        .map_err(|error| anyhow::anyhow!("invalid clean-cut plan JSON: {error}"))?;
    plan.validate()?;

    if validate_plan_only {
        println!(
            "{}",
            serde_json::json!({
                "status": "plan_validated",
                "plan_sha256": plan_sha256,
                "target_count": plan.targets.len(),
            })
        );
        return Ok(());
    }

    if execute {
        exact_execute_confirmation()?;
        let expected_sha256 =
            std::env::var("CAP_CLEAN_CUT_RETIRE_EXPECTED_PLAN_SHA256").map_err(|_| {
                anyhow::anyhow!(
                    "execute requires CAP_CLEAN_CUT_RETIRE_EXPECTED_PLAN_SHA256={plan_sha256}"
                )
            })?;
        if expected_sha256 != plan_sha256 {
            anyhow::bail!(
                "reviewed plan SHA-256 mismatch: expected {expected_sha256}, actual {plan_sha256}"
            );
        }
    }

    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("DATABASE_URL is required"))?;
    let pool = enclava_api::db::pool::create_pool(&database_url).await?;
    enclava_api::clean_cut::required_schema_present(&pool).await?;

    let client = kube::Client::try_default().await?;
    let result = enclava_api::clean_cut::run(&pool, client, &plan, &plan_sha256, execute).await?;
    let result_json = serde_json::to_string(&result)?;
    if let Ok(receipt_path) = std::env::var("CAP_CLEAN_CUT_RETIRE_RECEIPT_PATH") {
        std::fs::write(&receipt_path, &result_json)
            .map_err(|error| anyhow::anyhow!("failed to write receipt {receipt_path}: {error}"))?;
    }
    println!("{result_json}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::require_exact_execute_confirmation;

    #[test]
    fn execute_confirmation_is_strict_and_fail_closed() {
        require_exact_execute_confirmation(Some("true")).expect("exact confirmation");
        for invalid in [
            None,
            Some(""),
            Some("1"),
            Some("TRUE"),
            Some("yes"),
            Some("true "),
        ] {
            assert!(
                require_exact_execute_confirmation(invalid).is_err(),
                "{invalid:?} must not authorize retirement"
            );
        }
    }
}
