use std::fs;
use std::io::Read;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use enclava_vault::connection::{ConnectionSpec, Origin, Position};
use enclava_vault::{Proxy, ProxyConfig, Store, VaultCa};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "enclava-vault", about = "Credential-substituting egress proxy")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the proxy.
    Serve(ServeArgs),
    /// Manage stored connections.
    #[command(subcommand)]
    Connection(ConnectionCommand),
}

#[derive(Args)]
struct ServeArgs {
    /// Address to listen on. Must be loopback.
    #[arg(long, env = "ENCLAVA_VAULT_LISTEN", default_value = "127.0.0.1:8470")]
    listen: SocketAddr,
    #[arg(long, env = "ENCLAVA_VAULT_STORE_DIR")]
    store_dir: PathBuf,
    /// Where to write the CA certificate the workload must trust.
    #[arg(long, env = "ENCLAVA_VAULT_CA_CERT_OUT")]
    ca_cert_out: Option<PathBuf>,
    /// Origin relayed without interception, as `https://host[:port]`.
    #[arg(
        long = "passthrough",
        env = "ENCLAVA_VAULT_PASSTHROUGH",
        value_delimiter = ','
    )]
    passthrough: Vec<String>,
}

#[derive(Subcommand)]
enum ConnectionCommand {
    /// Create a connection, or replace the credential of an existing one.
    Set(SetArgs),
    /// List connections. Never prints credentials.
    List(StoreArgs),
    /// Remove a connection.
    Rm(RmArgs),
}

#[derive(Args)]
struct StoreArgs {
    #[arg(long, env = "ENCLAVA_VAULT_STORE_DIR")]
    store_dir: PathBuf,
}

#[derive(Args)]
struct SetArgs {
    #[command(flatten)]
    store: StoreArgs,
    #[arg(long)]
    name: String,
    /// `https://host[:port]` the credential may be sent to.
    #[arg(long)]
    origin: String,
    #[arg(long, default_value = "/")]
    path_prefix: String,
    #[command(flatten)]
    position: PositionArgs,
    /// Config key under which the workload receives the placeholder.
    #[arg(long)]
    expose_as: Option<String>,
    /// File holding the credential, or `-` for stdin.
    #[arg(long)]
    secret_file: PathBuf,
}

#[derive(Args)]
#[group(required = true, multiple = false)]
struct PositionArgs {
    /// Swap inside the value of this header.
    #[arg(long, value_name = "NAME")]
    header: Option<String>,
    /// Swap the value of this query parameter.
    #[arg(long, value_name = "NAME")]
    query: Option<String>,
    /// Swap inside `Authorization: Basic` credentials.
    #[arg(long)]
    basic_auth: bool,
    /// Swap inside the request path.
    #[arg(long)]
    path_segment: bool,
}

impl PositionArgs {
    fn into_position(self) -> Position {
        if let Some(name) = self.header {
            Position::Header { name }
        } else if let Some(name) = self.query {
            Position::Query { name }
        } else if self.basic_auth {
            Position::BasicAuth
        } else {
            Position::PathSegment
        }
    }
}

#[derive(Args)]
struct RmArgs {
    #[command(flatten)]
    store: StoreArgs,
    #[arg(long)]
    name: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Credentials live in this process: no core dumps, and no ptrace from a
    // process that merely shares the UID.
    #[cfg(target_os = "linux")]
    nix::sys::prctl::set_dumpable(false).context("marking the process non-dumpable")?;

    match Cli::parse().command {
        Command::Serve(args) => serve(args),
        Command::Connection(ConnectionCommand::Set(args)) => set(args),
        Command::Connection(ConnectionCommand::List(args)) => list(args),
        Command::Connection(ConnectionCommand::Rm(args)) => {
            let store = Store::open(&args.store.store_dir)?;
            if !store.remove(&args.name)? {
                bail!("no connection named {}", args.name);
            }
            Ok(())
        }
    }
}

fn serve(args: ServeArgs) -> anyhow::Result<()> {
    // Any caller that can reach the listener can use every stored
    // credential. Until callers are authenticated, that has to mean
    // "processes in this network namespace" and nothing wider.
    if !args.listen.ip().is_loopback() {
        bail!(
            "refusing to listen on {}: only loopback is supported",
            args.listen
        );
    }
    let passthrough = args
        .passthrough
        .iter()
        .map(|origin| Origin::parse(origin).with_context(|| format!("--passthrough {origin}")))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let store = Store::open(&args.store_dir).context("opening the store")?;
    let ca = VaultCa::load_or_generate(store.dir()).context("loading the vault CA")?;
    if let Some(path) = &args.ca_cert_out {
        fs::write(path, ca.cert_pem())
            .with_context(|| format!("writing the CA certificate to {}", path.display()))?;
    }
    let proxy = Proxy::new(
        store,
        ca,
        ProxyConfig {
            passthrough,
            ..ProxyConfig::default()
        },
    )?;

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = tokio::net::TcpListener::bind(args.listen).await?;
            tracing::info!(listen = %args.listen, "enclava-vault listening");
            proxy.serve(listener).await?;
            Ok(())
        })
}

fn set(args: SetArgs) -> anyhow::Result<()> {
    let secret = read_secret(&args.secret_file)?;
    let store = Store::open(&args.store.store_dir)?;
    let connection = store.put(
        ConnectionSpec {
            name: args.name,
            origin: Origin::parse(&args.origin)?,
            path_prefix: args.path_prefix,
            position: args.position.into_position(),
            expose_as: args.expose_as,
        },
        &secret,
    )?;
    // The placeholder is what the workload is given; it is not a secret.
    println!("{}", connection.placeholder);
    Ok(())
}

fn list(args: StoreArgs) -> anyhow::Result<()> {
    let snapshot = Store::open(&args.store_dir)?.snapshot()?;
    for connection in snapshot.connections() {
        let spec = &connection.spec;
        let position = match &spec.position {
            Position::Header { name } => format!("header:{name}"),
            Position::Query { name } => format!("query:{name}"),
            Position::BasicAuth => "basic-auth".to_owned(),
            Position::PathSegment => "path-segment".to_owned(),
        };
        println!(
            "{}\t{}{}\t{}\t{}\t{}",
            spec.name,
            spec.origin,
            if spec.path_prefix == "/" {
                ""
            } else {
                &spec.path_prefix
            },
            position,
            spec.expose_as.as_deref().unwrap_or("-"),
            connection.placeholder,
        );
    }
    Ok(())
}

/// Reads the credential and drops one trailing line ending, which is what
/// `echo` and most editors add.
fn read_secret(path: &PathBuf) -> anyhow::Result<Zeroizing<String>> {
    let mut secret = Zeroizing::new(String::new());
    if path.as_os_str() == "-" {
        std::io::stdin().read_to_string(&mut secret)?;
    } else {
        fs::File::open(path)
            .with_context(|| format!("opening {}", path.display()))?
            .read_to_string(&mut secret)?;
    }
    if secret.ends_with('\n') {
        secret.pop();
        if secret.ends_with('\r') {
            secret.pop();
        }
    }
    Ok(secret)
}
