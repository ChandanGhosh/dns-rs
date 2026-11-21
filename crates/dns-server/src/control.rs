//! Control socket service backed by the query pipeline.
//!
//! The service reads counters, asks the existing shutdown token to cancel, and
//! re-reads the daemon's own configuration file. It has no command that
//! executes code and no command that takes a filesystem path: a reload can only
//! read the file the daemon was started with.

use std::path::PathBuf;
use std::process;
use std::sync::Arc;
use std::time::Instant;

use dns_config::RemoteControlConfig;
use dns_control::{
    ControlError, ControlService, PROTOCOL_VERSION, ReloadFuture, Server, StatsSnapshot,
    StatusInfo, TransportCounts,
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
        queries_total: stats.queries.queries_total,
        queries_by_transport: TransportCounts {
            udp: stats.queries.by_transport.udp,
            tcp: stats.queries.by_transport.tcp,
            tls: stats.queries.by_transport.tls,
            https: stats.queries.by_transport.https,
        },
        responses_total: stats.queries.responses_total,
        responses_by_rcode: stats.queries.by_rcode,
        responses_truncated: stats.queries.truncated,
        responses_ede: stats.queries.ede,
        responses_ad: stats.queries.ad,
        dnssec_secure: stats.queries.dnssec_secure,
        dnssec_insecure: stats.queries.dnssec_insecure,
        dnssec_bogus: stats.queries.dnssec_bogus,
        upstreams: stats.upstreams,
        upstreams_omitted: stats.upstreams_omitted,
    }
}

/// Bind every configured control socket and serve it until shutdown.
///
/// All paths are bound before any server task starts, so one bad path fails
/// startup without leaving a partially active control channel. The bound paths
/// are returned so the caller can hand them to the target user before dropping
/// privileges.
pub(crate) fn start(
    config: &RemoteControlConfig,
    pipeline: PipelineHandle,
    reloader: Option<Reloader>,
    shutdown: CancellationToken,
) -> Result<Vec<PathBuf>, ControlError> {
    let mut servers = Vec::with_capacity(config.interfaces.len());
    for path in &config.interfaces {
        servers.push((path.clone(), Server::bind(path)?));
    }
    let paths = servers
        .iter()
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();

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
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use dns_cache::{CacheStats, CoalesceStats};
    use dns_control::{TransportCounts, UpstreamStats};

    use super::{PipelineStats, snapshot};
    use crate::pipeline::QueryStats;

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
            queries: QueryStats {
                queries_total: 9,
                by_transport: TransportCounts {
                    udp: 10,
                    tcp: 11,
                    tls: 12,
                    https: 13,
                },
                responses_total: 14,
                by_rcode: [15; 16],
                truncated: 16,
                ede: 17,
                ad: 18,
                dnssec_secure: 19,
                dnssec_insecure: 20,
                dnssec_bogus: 21,
            },
            upstreams: vec![UpstreamStats {
                address: "192.0.2.1:53".to_owned(),
                rtt_ms: 22,
                timeouts: 23,
                failures: 24,
                lame: false,
                backed_off: true,
                caps_ok: true,
            }],
            upstreams_omitted: 25,
        };
        let mapped = snapshot(stats);
        assert_eq!(mapped.queries_total, 9);
        assert_eq!(
            mapped.queries_by_transport,
            TransportCounts {
                udp: 10,
                tcp: 11,
                tls: 12,
                https: 13,
            }
        );
        assert_eq!(mapped.responses_total, 14);
        assert_eq!(mapped.responses_by_rcode, [15; 16]);
        assert_eq!(mapped.responses_truncated, 16);
        assert_eq!(mapped.responses_ede, 17);
        assert_eq!(mapped.responses_ad, 18);
        assert_eq!(mapped.dnssec_secure, 19);
        assert_eq!(mapped.dnssec_insecure, 20);
        assert_eq!(mapped.dnssec_bogus, 21);
        assert_eq!(mapped.upstreams.len(), 1);
        assert_eq!(mapped.upstreams[0].rtt_ms, 22);
        assert_eq!(mapped.upstreams_omitted, 25);
        assert_eq!(mapped.cache_hits, 1);
        assert_eq!(mapped.coalesce_abandoned, 8);
    }
}
