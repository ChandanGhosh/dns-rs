#[cfg(feature = "alloc-stats")]
mod alloc_stats;
mod control;
mod healthcheck;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use dns_config::{Config, LoadedConfig};
use dns_control::ControlCommand;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Registry, reload};

/// The resolver allocates per-query names, records, and response buffers.
/// mimalloc handles that allocation pattern better than the system allocator,
/// especially in the static musl container image. The `alloc-stats` feature
/// swaps in a counting wrapper for benchmarks; mimalloc stays underneath so
/// instrumented builds allocate exactly like production ones.
#[cfg(not(feature = "alloc-stats"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Counting build of the same allocator (see the `alloc_stats` module).
#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOCATOR: alloc_stats::CountingMiMalloc = alloc_stats::CountingMiMalloc;

/// Release version. Container builds pass the workspace version through
/// `DNS_RS_VERSION` so the binary and the image label always agree; local
/// builds fall back to `Cargo.toml`.
const VERSION: &str = match option_env!("DNS_RS_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// UTC build timestamp, or `unknown` for local builds. Reported in the startup
/// log so a running resolver can be matched to an image.
const BUILD_DATE: &str = match option_env!("DNS_RS_BUILD_DATE") {
    Some(date) => date,
    None => "unknown",
};

#[derive(Debug, Parser)]
#[command(
    name = "dns-rs",
    version = VERSION,
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

    /// Raise the log filter (`-v` = debug, `-vv` = trace), overriding the
    /// `verbosity` server setting. `RUST_LOG` overrides both.
    #[arg(short = 'v', long, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

/// Commands accepted by the `control` subcommand.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum ControlCommandArg {
    /// Print process information.
    Status,
    /// Print pipeline counters as JSON.
    Stats,
    /// Print pipeline counters in Prometheus text format.
    StatsPrometheus,
    /// Ask the daemon to reload its configuration.
    Reload,
    /// Ask the daemon to shut down.
    Stop,
}

impl From<ControlCommandArg> for ControlCommand {
    fn from(command: ControlCommandArg) -> Self {
        match command {
            ControlCommandArg::Status => Self::Status,
            ControlCommandArg::Stats => Self::Stats,
            ControlCommandArg::StatsPrometheus => Self::StatsPrometheus,
            ControlCommandArg::Reload => Self::Reload,
            ControlCommandArg::Stop => Self::Stop,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the configuration and exit.
    Checkconf,
    /// Send one command to a running resolver's control socket.
    Control {
        /// Command to send.
        #[arg(value_enum)]
        command: ControlCommandArg,

        /// Control socket path. Defaults to the first enabled
        /// `control-interface` in the configuration.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
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

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Checkconf => checkconf(&cli.config),
        Command::Control { command, socket } => control::run(
            &cli.config,
            &control::Options {
                socket: socket.as_deref(),
                command: command.into(),
            },
        ),
        Command::Run => run(&cli),
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
    if config.remote_control.enabled {
        let control = config
            .remote_control
            .interfaces
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        println!("  control: {control}");
    }
    if !loaded.warnings.is_empty() {
        println!("  warnings: {}", loaded.warnings.len());
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<()> {
    // Log level is resolved after the configuration loads so the `verbosity`
    // server key mirrors Unbound and is honoured before the flags or `RUST_LOG`.
    let loaded = load(&cli.config)?;
    let on_reload = init_tracing(cli.verbose, loaded.config.server.verbosity);
    // `num-threads` is the number of resolver worker threads. Build the
    // runtime explicitly so the setting controls Tokio's worker pool instead
    // of always using one worker per available CPU. `0` and `"auto"` resolve
    // to the CPUs visible to this process, including cgroup limits.
    let threads = loaded.config.server.num_threads.resolve();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .context("failed to build the Tokio runtime")?;
    // `alloc-stats` benchmark builds print `stats allocs=` lines that the
    // runner snapshots around its load window; the reporter thread lives for
    // the whole run.
    #[cfg(feature = "alloc-stats")]
    alloc_stats::spawn_reporter();
    // `phase-stats` builds print `stats phases ...` the same way, so the
    // runner can attribute time to a stage of the pipeline.
    #[cfg(feature = "phase-stats")]
    dns_server::spawn_reporter();
    runtime.block_on(run_server(&cli.config, loaded.config, on_reload))
}

async fn run_server(path: &Path, config: Config, on_reload: ReloadCallback) -> Result<()> {
    let config = Arc::new(config);

    tracing::info!(
        version = VERSION,
        build_date = BUILD_DATE,
        config = %path.display(),
        threads = %config.server.num_threads,
        "starting dns-rs"
    );

    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_config = Arc::clone(&config);
    let config_path = path.to_path_buf();
    let mut server = tokio::spawn(async move {
        // The server owns `SIGHUP` and the control socket's `reload` command.
        dns_server::serve_with_reload(server_config, config_path, server_shutdown, Some(on_reload))
            .await
    });

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

/// Default filter from the `-v` flags, falling back to the `verbosity` server
/// key for Unbound compatibility. Precedence: `RUST_LOG` > `-v`/`-vv` >
/// `verbosity`. `0` maps to warnings only, `1` (the default) to info, `2` and
/// `3` to debug (including the per-query lines), and `4` or `5` to trace.
fn default_filter(flag_verbose: u8, config_verbosity: u8) -> &'static str {
    match flag_verbose {
        0 => match config_verbosity {
            0 => "warn",
            1 => "info",
            2..=3 => "debug",
            _ => "trace",
        },
        1 => "debug",
        _ => "trace",
    }
}

/// Applied after a successful reload so the daemon can update live settings.
type ReloadCallback = Arc<dyn Fn(&Config) + Send + Sync>;

/// Install a subscriber with a reloadable log filter and return the reload hook.
///
/// `RUST_LOG` wins over `-v`, which wins over `server.verbosity`. When `RUST_LOG`
/// is set, reloads leave the environment filter in place.
fn init_tracing(flag_verbose: u8, config_verbosity: u8) -> ReloadCallback {
    let env_filter = EnvFilter::try_from_default_env();
    let from_env = env_filter.is_ok();
    let filter = env_filter
        .unwrap_or_else(|_| EnvFilter::new(default_filter(flag_verbose, config_verbosity)));
    let (filter_layer, handle) = reload::Layer::new(filter);
    Registry::default()
        .with(filter_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_target(false),
        )
        .init();

    let controller = LogController {
        handle,
        flag_verbose,
        from_env,
    };
    Arc::new(move |config: &Config| controller.apply(config.server.verbosity))
}

struct LogController {
    handle: reload::Handle<EnvFilter, Registry>,
    flag_verbose: u8,
    from_env: bool,
}

impl LogController {
    fn apply(&self, config_verbosity: u8) {
        if self.from_env {
            return;
        }
        let filter = EnvFilter::new(default_filter(self.flag_verbose, config_verbosity));
        if let Err(error) = self.handle.reload(filter) {
            tracing::error!(%error, "failed to apply the reloaded log verbosity");
        }
    }
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

#[cfg(test)]
mod tests {
    use super::default_filter;

    /// `-v` wins over the config, `RUST_LOG` still overrides everything at
    /// runtime, and the `verbosity` values map onto the tracing levels.
    #[test]
    fn verbosity_precedence_and_mapping() {
        let cases: &[(u8, u8, &str)] = &[
            // Flags override the configuration.
            (1, 0, "debug"),
            (1, 1, "debug"),
            (1, 5, "debug"),
            (2, 0, "trace"),
            (2, 5, "trace"),
            // No flags: the Unbound-style key picks the level.
            (0, 0, "warn"),
            (0, 1, "info"),
            (0, 2, "debug"),
            (0, 3, "debug"),
            (0, 4, "trace"),
            (0, 5, "trace"),
        ];
        for &(flag, config, expected) in cases {
            assert_eq!(
                default_filter(flag, config),
                expected,
                "flag={flag} config={config}"
            );
        }
    }
}
