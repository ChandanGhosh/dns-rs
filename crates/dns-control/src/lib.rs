//! Control and statistics interface.
//!
//! The control channel is a Unix domain socket carrying one bounded JSON
//! request per connection. It deliberately has no network transport and no
//! command that executes code: a process can only query the daemon or ask it
//! to stop if it has the daemon's effective UID.

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[cfg(unix)]
mod server;

#[cfg(unix)]
pub use server::{ControlError, Server};

/// Version of the control protocol carried over the socket.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest accepted request payload, excluding the trailing newline.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Largest response a control client will accept, including the trailing
/// newline. Server responses are small, but the cap keeps a compromised or
/// spoofed local socket from streaming unbounded data into the client.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// How long one client has to send a request and read the response.
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum number of control connections handled at once.
pub const MAX_CONNECTIONS: usize = 4;

/// A command accepted by the control interface.
///
/// The set is closed on purpose: there is no shell, no argument string, and no
/// dynamic dispatch, so a control request cannot turn into arbitrary code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlCommand {
    /// Return process information.
    Status,
    /// Return pipeline counters as JSON.
    Stats,
    /// Return pipeline counters in Prometheus text format.
    StatsPrometheus,
    /// Replace the running configuration when supported; currently returns an
    /// error because live reload is not implemented.
    Reload,
    /// Stop the daemon gracefully.
    Stop,
}

/// One request line, for example `{"command":"stats"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlRequest {
    /// Command to run.
    pub command: ControlCommand,
}

/// Process information returned by [`ControlCommand::Status`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    /// Daemon version.
    pub version: String,
    /// Process ID.
    pub pid: u32,
    /// Seconds since the control service started.
    pub uptime_secs: u64,
    /// Control protocol version.
    pub protocol: u32,
}

/// Point-in-time pipeline counters returned by [`ControlCommand::Stats`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsSnapshot {
    /// Message-cache hits.
    pub cache_hits: u64,
    /// Message-cache misses.
    pub cache_misses: u64,
    /// Expired entries served by serve-expired.
    pub cache_stale_hits: u64,
    /// Entries currently held in the message cache.
    pub cache_entries: u64,
    /// Background refreshes started by prefetch or serve-expired.
    pub prefetches: u64,
    /// Queries that started an upstream resolution.
    pub coalesce_leaders: u64,
    /// Queries that joined an in-flight resolution.
    pub coalesce_followers: u64,
    /// Leaders dropped without publishing.
    pub coalesce_abandoned: u64,
}

/// One response line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum ControlResponse {
    /// Reply to [`ControlCommand::Status`].
    Status(StatusInfo),
    /// Reply to [`ControlCommand::Stats`].
    Stats(StatsSnapshot),
    /// Reply to [`ControlCommand::StatsPrometheus`].
    Prometheus {
        /// Prometheus text exposition.
        text: String,
    },
    /// Reply to a successful [`ControlCommand::Reload`].
    Reloaded,
    /// Acknowledges [`ControlCommand::Stop`] before shutdown begins.
    Stopping,
    /// The request was rejected or the command failed.
    Error {
        /// Human-readable reason.
        message: String,
    },
}

/// What the daemon exposes to the control socket.
///
/// Implementations must be cheap and non-blocking: they run on the control
/// task, not on the query path, but a slow implementation would stall other
/// control clients.
pub trait ControlService: Send + Sync + 'static {
    /// Return process information.
    fn status(&self) -> StatusInfo;
    /// Return a point-in-time counter snapshot.
    fn stats(&self) -> StatsSnapshot;
    /// Render the counters in Prometheus text format.
    fn prometheus(&self) -> String;
    /// Replace the running configuration, or explain why that is impossible.
    fn reload(&self) -> Result<(), String>;
    /// Request a graceful shutdown.
    fn stop(&self);
}

#[cfg(test)]
mod tests {
    use super::{ControlCommand, ControlRequest, ControlResponse, StatsSnapshot, StatusInfo};

    #[test]
    fn requests_use_the_documented_shape() {
        let request: ControlRequest =
            serde_json::from_str(r#"{"command":"stats-prometheus"}"#).expect("request");
        assert_eq!(request.command, ControlCommand::StatsPrometheus);

        let unknown = serde_json::from_str::<ControlRequest>(r#"{"command":"exec","arg":"sh"}"#);
        assert!(unknown.is_err(), "extra fields must not be ignored");
    }

    #[test]
    fn responses_round_trip_as_one_line() {
        let response = ControlResponse::Stats(StatsSnapshot {
            cache_hits: 7,
            ..StatsSnapshot::default()
        });
        let encoded = serde_json::to_string(&response).expect("encode");
        assert_eq!(
            encoded,
            r#"{"result":"stats","cache_hits":7,"cache_misses":0,"cache_stale_hits":0,"cache_entries":0,"prefetches":0,"coalesce_leaders":0,"coalesce_followers":0,"coalesce_abandoned":0}"#
        );
        let decoded: ControlResponse = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, response);
    }

    #[test]
    fn status_round_trips() {
        let response = ControlResponse::Status(StatusInfo {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            pid: 42,
            uptime_secs: 9,
            protocol: 1,
        });
        let encoded = serde_json::to_string(&response).expect("encode");
        let decoded: ControlResponse = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(decoded, response);
    }
}
