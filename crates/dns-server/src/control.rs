//! Control socket service backed by the query pipeline.
//!
//! The service reads counters, asks the existing shutdown token to cancel, and
//! re-reads the daemon's own configuration file. It has no command that
//! executes code and no command that takes a filesystem path: a reload can only
//! read the file the daemon was started with.

use std::process;
use std::sync::Arc;
use std::time::Instant;

use dns_config::RemoteControlConfig;
use dns_control::{
    ControlError, ControlService, PROTOCOL_VERSION, ReloadFuture, Server, StatsSnapshot, StatusInfo,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::pipeline::{PipelineHandle, PipelineStats};
use crate::reload::Reloader;

/// Prefer the version injected by container builds, matching the daemon.
const VERSION: &str = match option_env!("DNS_RS_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

struct Service {
    pipeline: PipelineHandle,
    reloader: Option<Reloader>,
    shutdown: CancellationToken,
    started: Instant,
}

impl ControlService for Service {
    fn status(&self) -> StatusInfo {
        StatusInfo {
            version: VERSION.to_owned(),
            pid: process::id(),
            uptime_secs: self.started.elapsed().as_secs(),
            protocol: PROTOCOL_VERSION,
        }
    }

    fn stats(&self) -> StatsSnapshot {
        snapshot(self.pipeline.stats())
    }

    fn prometheus(&self) -> String {
        self.pipeline.stats().render_prometheus()
    }

    fn reload(&self) -> ReloadFuture<'_> {
        Box::pin(async move {
            let Some(reloader) = &self.reloader else {
                return Err(
                    "configuration reload is disabled; the daemon was not started with a \
                     configuration file"
                        .to_owned(),
                );
            };
            reloader.reload().await.map_err(|error| error.to_string())
        })
    }

    fn stop(&self) {
        info!("control socket requested shutdown");
        self.shutdown.cancel();
    }
}

fn snapshot(stats: PipelineStats) -> StatsSnapshot {
    StatsSnapshot {
        cache_hits: stats.cache.hits,
        cache_misses: stats.cache.misses,
        cache_stale_hits: stats.cache.stale_hits,
        cache_entries: stats.cache_entries,
        prefetches: stats.prefetches,
        coalesce_leaders: stats.coalesce.leaders,
        coalesce_followers: stats.coalesce.followers,
        coalesce_abandoned: stats.coalesce.abandoned,
    }
}

/// Bind every configured control socket and serve it until shutdown.
///
/// All paths are bound before any server task starts, so one bad path fails
/// startup without leaving a partially active control channel.
pub(crate) fn start(
    config: &RemoteControlConfig,
    pipeline: PipelineHandle,
    reloader: Option<Reloader>,
    shutdown: CancellationToken,
) -> Result<(), ControlError> {
    let mut servers = Vec::with_capacity(config.interfaces.len());
    for path in &config.interfaces {
        servers.push((path.clone(), Server::bind(path)?));
    }

    let service = Arc::new(Service {
        pipeline,
        reloader,
        shutdown: shutdown.clone(),
        started: Instant::now(),
    });
    for (path, server) in servers {
        info!(path = %path.display(), "control socket listening");
        let service = Arc::clone(&service);
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            if let Err(error) = server.run(service, shutdown).await {
                warn!(path = %path.display(), %error, "control socket stopped with an error");
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use dns_cache::{CacheStats, CoalesceStats};

    use super::{PipelineStats, StatsSnapshot, snapshot};

    #[test]
    fn maps_pipeline_counters_without_losing_fields() {
        let stats = PipelineStats {
            cache: CacheStats {
                hits: 1,
                misses: 2,
                stale_hits: 3,
            },
            cache_entries: 4,
            prefetches: 5,
            coalesce: CoalesceStats {
                leaders: 6,
                followers: 7,
                abandoned: 8,
            },
        };
        assert_eq!(
            snapshot(stats),
            StatsSnapshot {
                cache_hits: 1,
                cache_misses: 2,
                cache_stale_hits: 3,
                cache_entries: 4,
                prefetches: 5,
                coalesce_leaders: 6,
                coalesce_followers: 7,
                coalesce_abandoned: 8,
            }
        );
    }
}
