mod healthcheck;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand};
use dns_config::LoadedConfig;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "dns-rs",
    version,
    about = "A validating, recursive, caching DNS resolver",
    long_about = None
)]
struct Cli {
    /// Configuration file. `.toml` uses native syntax; other names use the
    /// supported `unbound.conf` subset.
    #[arg(
        short = 'c',
        long,
        global = true,
        default_value = "dns-rs.conf",
        value_name = "FILE"
    )]
    config: PathBuf,

    /// Increase log verbosity (`-v` = debug, `-vv` = trace).
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration and exit.
    Checkconf,
    /// Run the resolver.
    Run,
    /// Query a running resolver and exit non-zero if it does not answer.
    ///
    /// Intended for container healthchecks and for simple liveness checks.
    Healthcheck {
        /// Address to probe. Defaults to the first plain-DNS listener.
        #[arg(long, value_name = "ADDR")]
        address: Option<IpAddr>,

        /// Port to probe. Defaults to the listener or server port.
        #[arg(long, value_name = "PORT")]
        port: Option<u16>,

        /// Query name. Defaults to the built-in `localhost.` record.
        #[arg(long, value_name = "NAME", default_value = "localhost.")]
        name: String,

        /// Per-operation timeout in milliseconds.
        #[arg(long, value_name = "MILLISECONDS", default_value_t = 2000)]
        timeout: u64,

        /// Force TCP instead of UDP.
        #[arg(long)]
        tcp: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Checkconf => checkconf(&cli.config),
        Command::Run => {
            init_tracing(cli.verbose);
            run(&cli.config).await
        }
        Command::Healthcheck {
            address,
            port,
            name,
            timeout,
            tcp,
        } => healthcheck::run(
            &cli.config,
            &healthcheck::Options {
                address,
                port,
                name: &name,
                timeout: Duration::from_millis(timeout),
                tcp,
            },
        ),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn checkconf(path: &Path) -> Result<()> {
    let loaded = load(path)?;
    let config = &loaded.config;

    let interfaces = config
        .server
        .interfaces
        .iter()
        .map(|address| address.socket_addr(config.server.port).to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!("configuration OK: {}", path.display());
    println!("  interfaces: {interfaces}");
    println!("  threads: {}", config.server.num_threads);
    println!("  forward zones: {}", config.forward_zones.len());
    if !loaded.warnings.is_empty() {
        println!("  warnings: {}", loaded.warnings.len());
    }
    Ok(())
}

async fn run(path: &Path) -> Result<()> {
    let loaded = load(path)?;
    let config = Arc::new(loaded.config);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %path.display(),
        "starting dns-rs"
    );

    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_config = Arc::clone(&config);
    let mut server =
        tokio::spawn(async move { dns_server::serve(server_config, server_shutdown).await });

    tokio::select! {
        result = &mut server => {
            result.context("server task panicked")??;
            return Ok(());
        }
        () = shutdown_signal() => {
            tracing::info!("shutdown signal received");
            shutdown.cancel();
        }
    }

    server.await.context("server task panicked")??;
    Ok(())
}

fn load(path: &Path) -> Result<LoadedConfig> {
    let loaded = dns_config::load(path)
        .with_context(|| format!("failed to load configuration {}", path.display()))?;
    for warning in &loaded.warnings {
        eprintln!("warning: {warning}");
    }
    Ok(loaded)
}

fn init_tracing(verbose: u8) {
    let default_level = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(error) => {
                tracing::error!(%error, "failed to install SIGTERM handler");
                return;
            }
        };

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    tracing::error!(%error, "failed to listen for Ctrl-C");
                }
            }
            _ = terminate.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to listen for Ctrl-C");
        }
    }
}
