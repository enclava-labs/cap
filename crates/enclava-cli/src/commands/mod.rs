pub mod app;
pub mod auth;
pub mod config;
pub mod describe;
pub mod descriptor;
pub mod domains;
pub mod init;
pub mod key;
pub mod org;
pub mod ownership;
pub mod prepare;
pub mod template;
pub mod verify;

use std::time::Duration;

use clap::{Parser, Subcommand};

pub(crate) fn counted_progress(label: &str, completed: usize, total: usize) -> String {
    format!("{label}: {completed}/{total}")
}

pub(crate) fn timed_progress(label: &str, elapsed: Duration, timeout: Duration) -> String {
    format!(
        "[{} / {}] {label}",
        format_duration(elapsed),
        format_duration(timeout)
    )
}

pub(crate) fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

#[derive(Parser)]
#[command(
    name = "enclava",
    version,
    about = "Deploy confidential apps in hardware-encrypted enclaves"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create an account
    Signup,
    /// Authenticate with the platform
    Login(auth::LoginArgs),
    /// Show authenticated user and active organization
    Whoami,
    /// Clear the saved platform session
    Logout,
    /// Generate enclava.toml for manual deployment
    Init,
    /// Prepare this repository for Enclava deployment
    Prepare,
    /// Create a new app from enclava.toml
    Create(app::CreateArgs),
    /// Deploy or update an app
    Deploy(app::DeployArgs),
    /// Show live app status
    Status(app::StatusArgs),
    /// Stream app logs
    Logs(app::LogsArgs),
    /// Manage hosted log encryption keys
    #[command(subcommand)]
    LogKey(app::LogKeyCommand),
    /// Manage app configuration secrets
    #[command(subcommand)]
    Config(config::ConfigCommand),
    /// Manage hosted templates
    #[command(subcommand)]
    Template(template::TemplateCommand),
    /// Manage custom domains
    #[command(subcommand)]
    Domains(domains::DomainsCommand),
    /// First-time ownership claim (password mode)
    Claim(ownership::ClaimArgs),
    /// Unlock storage on restart (password mode)
    Unlock(ownership::UnlockArgs),
    /// Recover with BIP39 mnemonic (password mode)
    Recover(ownership::RecoverArgs),
    /// Change unlock password (password mode)
    ChangePassword(ownership::ChangePasswordArgs),
    /// Manage auto-unlock
    #[command(subcommand)]
    AutoUnlock(ownership::AutoUnlockCommand),
    /// Rollback to a previous deployment
    Rollback(app::RollbackArgs),
    /// Destroy an app with confirmation
    Destroy(app::DestroyArgs),
    /// Manage the per-app cosign Fulcio signer identity
    #[command(subcommand)]
    Signer(app::SignerCommand),
    /// Manage organizations
    #[command(subcommand)]
    Org(org::OrgCommand),
    /// Manage local recovery and deployment keys
    #[command(subcommand)]
    Key(key::KeyCommand),
    /// Inspect a deployment descriptor (debug; phase 7 groundwork)
    #[command(subcommand)]
    Descriptor(descriptor::DescriptorCommand),
    /// Independently verify a live target or saved proof bundle
    Verify(verify::VerifyArgs),
    /// Observe what a live target or saved proof bundle contains (no appraisal)
    Describe(describe::DescribeArgs),
}

pub async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Signup => auth::signup().await,
        Command::Login(args) => auth::login(args).await,
        Command::Whoami => auth::whoami().await,
        Command::Logout => auth::logout().await,
        Command::Init => init::init().await,
        Command::Prepare => prepare::prepare().await,
        Command::Create(args) => app::create(args).await,
        Command::Deploy(args) => app::deploy(args).await,
        Command::Status(args) => app::status(args).await,
        Command::Logs(args) => app::logs(args).await,
        Command::LogKey(cmd) => app::log_key(cmd).await,
        Command::Config(cmd) => config::run(cmd).await,
        Command::Template(cmd) => template::run(cmd).await,
        Command::Domains(cmd) => domains::run(cmd).await,
        Command::Claim(args) => ownership::claim(args).await,
        Command::Unlock(args) => ownership::unlock(args).await,
        Command::Recover(args) => ownership::recover(args).await,
        Command::ChangePassword(args) => ownership::change_password(args).await,
        Command::AutoUnlock(cmd) => ownership::auto_unlock(cmd).await,
        Command::Rollback(args) => app::rollback(args).await,
        Command::Destroy(args) => app::destroy(args).await,
        Command::Signer(cmd) => app::signer(cmd).await,
        Command::Org(cmd) => org::run(cmd).await,
        Command::Key(cmd) => key::run(cmd).await,
        Command::Descriptor(cmd) => descriptor::run(cmd).await,
        Command::Verify(args) => verify::run(args).await,
        Command::Describe(args) => describe::run(args).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_progress_formats_counts_and_deadlines() {
        assert_eq!(
            counted_progress("Platform config", 7, 13),
            "Platform config: 7/13"
        );
        assert_eq!(
            timed_progress(
                "TEE boot: Pod Running",
                Duration::from_secs(134),
                Duration::from_secs(900),
            ),
            "[02:14 / 15:00] TEE boot: Pod Running"
        );
    }
}
