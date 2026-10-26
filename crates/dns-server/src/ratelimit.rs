//! Response-rate limiting and per-client concurrency limits.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_TRACKED_CLIENTS: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    /// Drop the query silently.
    Drop,
    /// Answer with a truncated response so the client retries over TCP.
    Slip,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Per-client-IP token bucket.
#[derive(Clone)]
pub struct RateLimiter {
    inner: Option<Arc<Inner>>,
}

struct Inner {
    capacity: f64,
    refill_per_second: f64,
    slip: u64,
    buckets: DashMap<IpAddr, Bucket>,
    limited: AtomicU64,
}

impl RateLimiter {
    /// `rate` is responses per second; zero disables limiting.
    pub fn new(rate: u32, slip: u32) -> Self {
        if rate == 0 {
            return Self { inner: None };
        }
        Self {
            inner: Some(Arc::new(Inner {
                capacity: f64::from(rate),
                refill_per_second: f64::from(rate),
                slip: u64::from(slip),
                buckets: DashMap::new(),
                limited: AtomicU64::new(0),
            })),
        }
    }

    pub fn check(&self, client: IpAddr) -> RateDecision {
        let Some(inner) = &self.inner else {
            return RateDecision::Allow;
        };

        let now = Instant::now();
        let allowed = {
            if inner.buckets.len() > MAX_TRACKED_CLIENTS {
                inner.buckets.clear();
            }
            let mut bucket = inner.buckets.entry(client).or_insert_with(|| Bucket {
                tokens: inner.capacity,
                last: now,
            });
            let elapsed = now.saturating_duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * inner.refill_per_second).min(inner.capacity);
            bucket.last = now;
            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                true
            } else {
                false
            }
        };

        if allowed {
            return RateDecision::Allow;
        }

        let count = inner.limited.fetch_add(1, Ordering::Relaxed) + 1;
        if inner.slip > 0 && count % inner.slip == 0 {
            RateDecision::Slip
        } else {
            RateDecision::Drop
        }
    }

    pub fn limited_count(&self) -> u64 {
        self.inner
            .as_ref()
            .map_or(0, |inner| inner.limited.load(Ordering::Relaxed))
    }
}

/// Bounds concurrent in-flight queries per client IP.
#[derive(Clone)]
pub struct ClientConcurrency {
    max: usize,
    per_client: Arc<DashMap<IpAddr, Arc<Semaphore>>>,
    global: Arc<Semaphore>,
}

/// Keeps a per-client and a global slot alive for the duration of a query.
pub struct Permit {
    _client: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl ClientConcurrency {
    pub fn new(max_per_client: usize, max_global: usize) -> Self {
        Self {
            max: max_per_client.max(1),
            per_client: Arc::new(DashMap::new()),
            global: Arc::new(Semaphore::new(max_global.max(1))),
        }
    }

    /// Try to reserve a slot. Returns `None` when the client or the server as
    /// a whole is already at its limit.
    pub fn try_acquire(&self, client: IpAddr) -> Option<Permit> {
        if self.per_client.len() > MAX_TRACKED_CLIENTS {
            self.per_client.clear();
        }
        let semaphore = self
            .per_client
            .entry(client)
            .or_insert_with(|| Arc::new(Semaphore::new(self.max)))
            .clone();
        let client_permit = semaphore.try_acquire_owned().ok()?;
        let global_permit = self.global.clone().try_acquire_owned().ok()?;
        Some(Permit {
            _client: client_permit,
            _global: global_permit,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{RateDecision, RateLimiter};

    #[test]
    fn disabled_limiter_allows_everything() {
        let limiter = RateLimiter::new(0, 2);
        for _ in 0..100 {
            assert_eq!(
                limiter.check(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                RateDecision::Allow
            );
        }
    }

    #[test]
    fn limits_and_slips() {
        let limiter = RateLimiter::new(1, 2);
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(limiter.check(client), RateDecision::Allow);
        assert_eq!(limiter.check(client), RateDecision::Drop);
        assert_eq!(limiter.check(client), RateDecision::Slip);
        assert_eq!(limiter.check(client), RateDecision::Drop);
    }
}
