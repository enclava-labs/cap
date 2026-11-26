mod commands;

use clap::Parser;
use commands::Cli;

const DEBUG_ONLY_FLAGS: &[&str] = &[
    "SKIP_COSIGN_VERIFY",
    "COSIGN_ALLOW_HTTP_REGISTRY",
    "ALLOW_EPHEMERAL_KEYS",
    "TENANT_TEE_ACCEPT_INVALID_CERTS",
    "ENCLAVA_TEE_ACCEPT_INVALID_CERTS",
];

fn enforce_production_env_gates() -> Result<(), String> {
    if !cfg!(debug_assertions) {
        for flag in DEBUG_ONLY_FLAGS {
            if let Ok(value) = std::env::var(flag)
                && matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES")
            {
                return Err(format!(
                    "env var `{flag}` is set but only allowed in debug builds"
                ));
            }
        }
        for mode_var in ["TENANT_TEE_TLS_MODE", "ENCLAVA_TEE_TLS_MODE"] {
            if let Ok(mode) = std::env::var(mode_var)
                && matches!(mode.trim(), "staging" | "insecure")
            {
                return Err(format!(
                    "{mode_var}=staging|insecure is only allowed in debug builds"
                ));
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = enforce_production_env_gates() {
        eprintln!("startup refused: {e}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    let update_check = commands::update::spawn_notice_check(&cli.command);
    let result = commands::run(cli).await;
    if let Err(e) = &result {
        eprintln!("error: {e}");
    }
    commands::update::print_notice(update_check).await;
    if result.is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_build_allows_dev_flags() {
        // The test binary is a debug build, so the gate should always pass
        // even with debug-only flags set in the environment.
        // We don't mutate process env; this just documents the contract.
        const { assert!(cfg!(debug_assertions)) };
        assert!(enforce_production_env_gates().is_ok());
    }
}
