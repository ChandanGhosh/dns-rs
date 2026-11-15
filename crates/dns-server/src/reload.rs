//! Live configuration reload.
//!
//! A reload re-reads the daemon's own configuration file, builds a fresh query
//! pipeline (and therefore empty caches), and swaps it in atomically. Queries
//! already in flight keep the pipeline they started with until they finish.
//!
//! The request carries no path: the control socket and `SIGHUP` can only
//! re-read the file the daemon was started with, so a local client cannot use
//! reload to make the daemon read an arbitrary file.

use std::path::PathBuf;
use std::sync::Arc;

use dns_config::Config;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::pipeline::{PipelineHandle, QueryPipeline};

/// A cloneable handle that rebuilds the query pipeline from disk.
#[derive(Clone)]
pub(crate) struct Reloader {
    config_path: Arc<PathBuf>,
    pipeline: PipelineHandle,
    /// Serializes reloads so two requests cannot interleave and leave the
    /// older pipeline installed.
    gate: Arc<Mutex<()>>,
}

/// Why a reload was refused.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ReloadError {
    /// The configuration file could not be read, parsed, or validated.
    #[error(transparent)]
    Config(#[from] dns_config::ConfigError),
    /// The blocking reload worker panicked or was cancelled.
    #[error("reload worker failed: {0}")]
    Worker(#[from] tokio::task::JoinError),
}

impl Reloader {
    /// Create a reloader for `config_path` that installs into `pipeline`.
    pub(crate) fn new(config_path: PathBuf, pipeline: PipelineHandle) -> Self {
        Self {
            config_path: Arc::new(config_path),
            pipeline,
            gate: Arc::new(Mutex::new(())),
        }
    }

    /// Re-read the configuration file and install a fresh pipeline.
    ///
    /// The running configuration is left untouched when the file cannot be
    /// read, parsed, or validated, or when the worker panics. Caches are always
    /// empty in the new pipeline, matching Unbound's default reload behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`ReloadError::Config`] for an invalid configuration and
    /// [`ReloadError::Worker`] when the blocking worker fails.
    pub(crate) async fn reload(&self) -> Result<(), ReloadError> {
        let _gate = self.gate.lock().await;

        let path = Arc::clone(&self.config_path);
        let loaded = tokio::task::spawn_blocking(move || dns_config::load(&*path))
            .await
            .map_err(ReloadError::Worker)??;
        for warning in &loaded.warnings {
            warn!(%warning, "configuration warning");
        }

        let config = Arc::new(loaded.config);
        // Building a pipeline resolves upstream hostnames and reads trust
        // anchors and CA bundles, so keep it off the runtime's worker threads.
        let handle = tokio::runtime::Handle::current();
        let build = Arc::clone(&config);
        let pipeline = tokio::task::spawn_blocking(move || {
            let _guard = handle.enter();
            QueryPipeline::new(build)
        })
        .await
        .map_err(ReloadError::Worker)?;

        let restart = restart_required(&self.pipeline.config(), &config);
        if !restart.is_empty() {
            warn!(
                settings = %restart.join(", "),
                "settings that require a restart changed; the running listeners were kept"
            );
        }

        self.pipeline.replace(pipeline);
        info!(
            config = %self.config_path.display(),
            "configuration reloaded; caches flushed"
        );
        Ok(())
    }
}

/// Server settings that are fixed when the listeners are bound.
///
/// A reload can only replace the query pipeline, so changes to these settings
/// are reported instead of being silently ignored.
fn restart_required(previous: &Config, next: &Config) -> Vec<&'static str> {
    let old = &previous.server;
    let new = &next.server;
    let mut changed = Vec::new();

    // Every `server` setting that is captured when the listeners are bound.
    macro_rules! restart_only {
        ($($field:ident => $name:literal),* $(,)?) => {
            $(
                if old.$field != new.$field {
                    changed.push($name);
                }
            )*
        };
    }

    restart_only! {
        interfaces => "server.interfaces",
        port => "server.port",
        do_ip4 => "server.do-ip4",
        do_ip6 => "server.do-ip6",
        do_udp => "server.do-udp",
        do_tcp => "server.do-tcp",
        num_threads => "server.num-threads",
        incoming_num_tcp => "server.incoming-num-tcp",
        tls_service_key => "server.tls-service-key",
        tls_service_pem => "server.tls-service-pem",
        tls_port => "server.tls-port",
        https_port => "server.https-port",
        http_endpoint => "server.http-endpoint",
        udp_recv_buffer_size => "server.udp-recv-buffer-size",
        udp_send_buffer_size => "server.udp-send-buffer-size",
        tcp_recv_buffer_size => "server.tcp-recv-buffer-size",
        tcp_send_buffer_size => "server.tcp-send-buffer-size",
        tcp_user_timeout_ms => "server.tcp-user-timeout",
        verbosity => "server.verbosity",
    }

    if previous.remote_control != next.remote_control {
        changed.push("remote-control");
    }

    changed
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use dns_config::{Config, ServerConfig};
    use dns_proto::{Message, RData, RecordType, ResponseCode};
    use dns_testutil::query_bytes;
    use tempfile::tempdir;
    use tokio_util::sync::CancellationToken;

    use super::{Reloader, restart_required};
    use crate::pipeline::{PipelineHandle, Transport};

    fn client() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    fn config_text(address: &str) -> String {
        format!(
            "local_data = [\"reload.test. 60 IN A {address}\"]\n\
             \n\
             [server]\n\
             interfaces = [\"127.0.0.1@5353\"]\n\
             dnssec_validation = false\n"
        )
    }

    async fn answer(pipeline: &PipelineHandle) -> Ipv4Addr {
        let response = pipeline
            .handle_with_cancel(
                &query_bytes("reload.test.", RecordType::A),
                client(),
                Transport::Udp,
                CancellationToken::new(),
            )
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        match &message.answers.first().expect("answer").data {
            RData::A(address) => address.0,
            other => panic!("unexpected record: {other:?}"),
        }
    }

    #[tokio::test]
    async fn reload_installs_the_new_configuration() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.toml");
        std::fs::write(&path, config_text("192.0.2.1")).expect("write config");

        let loaded = dns_config::load(&path).expect("load config");
        let pipeline = PipelineHandle::new(Arc::new(loaded.config));
        let reloader = Reloader::new(path.clone(), pipeline.clone());

        assert_eq!(answer(&pipeline).await, Ipv4Addr::new(192, 0, 2, 1));

        std::fs::write(&path, config_text("192.0.2.2")).expect("rewrite config");
        reloader.reload().await.expect("reload");

        assert_eq!(answer(&pipeline).await, Ipv4Addr::new(192, 0, 2, 2));
    }

    #[tokio::test]
    async fn a_failed_reload_keeps_the_running_configuration() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.toml");
        std::fs::write(&path, config_text("192.0.2.1")).expect("write config");

        let loaded = dns_config::load(&path).expect("load config");
        let pipeline = PipelineHandle::new(Arc::new(loaded.config));
        let reloader = Reloader::new(path.clone(), pipeline.clone());

        std::fs::write(&path, "[server\ninterfaces = []\n").expect("write broken config");
        reloader.reload().await.expect_err("invalid config");

        assert_eq!(answer(&pipeline).await, Ipv4Addr::new(192, 0, 2, 1));
    }

    #[test]
    fn restart_only_settings_are_reported() {
        let base = Config::default();

        let mut reloadable = base.clone();
        reloadable.server.prefetch = !base.server.prefetch;
        assert!(restart_required(&base, &reloadable).is_empty());

        let mut listener = base.clone();
        listener.server.interfaces = vec![dns_config::ListenAddress::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(5353),
        )];
        assert_eq!(
            restart_required(&base, &listener),
            vec!["server.interfaces"]
        );

        let mut control = base.clone();
        control.remote_control.enabled = true;
        assert_eq!(restart_required(&base, &control), vec!["remote-control"]);

        let threads = Config {
            server: ServerConfig {
                num_threads: dns_config::ThreadCount::Fixed(4),
                ..ServerConfig::default()
            },
            ..Config::default()
        };
        assert_eq!(
            restart_required(&base, &threads),
            vec!["server.num-threads"]
        );
    }
}
