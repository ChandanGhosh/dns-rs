//! Iterative DNS resolution.

mod cookies;
mod hints;
mod iterator;
mod scrub;
mod validate;

pub use cookies::CookieJar;
pub use dns_dnssec::{BogusReason, Security};
pub use hints::root_hints;
pub use iterator::{
    ForwardServer, ForwardTransport, ForwardZone, IteratorConfig, IteratorResolver, StubZone,
};
pub use validate::{ProbedDnskeys, ResolveOptions, Resolved};

use std::time::Duration;

/// Errors that terminate a resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("query cycle detected")]
    Cycle,
    #[error("CNAME chain too long")]
    CnameChainTooLong,
    #[error("maximum recursion depth exceeded")]
    DepthExceeded,
    #[error("no reachable nameservers")]
    NoNameservers,
    #[error("resolution timed out")]
    Timeout,
    #[error("invalid response: {0}")]
    InvalidResponse(String),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Resolution context
#[derive(Clone, Debug)]
pub struct ResolveContext {
    pub depth: u32,
    pub deadline: std::time::Instant,
}

impl Default for ResolveContext {
    fn default() -> Self {
        Self {
            depth: 0,
            deadline: std::time::Instant::now() + Duration::from_secs(10),
        }
    }
}
