//! Control and statistics interface.
//!
//! The initial control protocol is native (JSON over a local socket). Compatibility
//! with `unbound-control` can be layered on later without changing command types.

use serde::{Deserialize, Serialize};

/// A command accepted by the control interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlCommand {
    /// Return process and resolver status.
    Status,
    /// Return counters and cache statistics.
    Stats,
    /// Reload configuration.
    Reload,
    /// Stop the daemon.
    Stop,
}
