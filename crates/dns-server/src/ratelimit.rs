//! Response-rate limiting and per-client concurrency limits.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_TRACKED_CLIENTS: usize = 65_536;

/// Maximum entries examined per eviction pass once a table is over its cap.
const EVICTION_BATCH: usize = 512;

/// Eviction passes are spaced this many over-cap checks apart, bounding the
/// per-query scan cost even while an attack keeps the table full.
const EVICTION_TICK: u64 = 64;

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
    /// Cap on the number of tracked clients.
    max_clients: usize,
    /// Counts over-cap checks so eviction passes can be spaced apart.
    evict_clock: AtomicU64,
}

impl RateLimiter {
    /// `rate` is responses per second; zero disables limiting.
    pub fn new(rate: u32, slip: u32) -> Self {
        Self::with_max_clients(rate, slip, MAX_TRACKED_CLIENTS)
    }

    /// Same as [`Self::new`] with an explicit cap on tracked clients, so
    /// tests can exercise eviction without 65 536 allocations.
    pub(crate) fn with_max_clients(rate: u32, slip: u32, max_clients: usize) -> Self {
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
                max_clients: max_clients.max(1),
                evict_clock: AtomicU64::new(0),
            })),
        }
    }

    pub fn check(&self, client: IpAddr) -> RateDecision {
        let Some(inner) = &self.inner else {
            return RateDecision::Allow;
        };

        let now = Instant::now();
        if inner.buckets.len() > inner.max_clients {
            self.evict_stale(inner, now);
        }
        let allowed = {
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

    /// Evict buckets that have been idle long enough to refill completely.
    ///
    /// A bucket untouched for at least one full refill window holds a full
    /// complement of tokens, exactly like a newly inserted one, so removing
    /// it cannot change any future decision for that client. Evicting only
    /// those entries keeps the table bounded without the previous whole-table
    /// `clear()`, which let an attacker flood the table with spoofed sources
    /// and reset every client's rate limit at once.
    ///
    /// Returns the number of buckets removed.
    fn evict_stale(&self, inner: &Inner, now: Instant) -> usize {
        if !inner
            .evict_clock
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(EVICTION_TICK)
        {
            return 0;
        }
        self.evict_stale_pass(inner, now)
    }

    /// One eviction pass; separate from [`Self::evict_stale`] so tests can
    /// run it without the tick spacing.
    fn evict_stale_pass(&self, inner: &Inner, now: Instant) -> usize {
        // Collect first: a `DashMap` iterator holds shard locks, so removal
        // has to wait until the iteration has ended.
        let stale = inner
            .buckets
            .iter()
            .take(EVICTION_BATCH)
            .filter(|entry| {
                now.saturating_duration_since(entry.value().last)
                    .as_secs_f64()
                    * inner.refill_per_second
                    >= inner.capacity
            })
            .map(|entry| (*entry.key(), entry.value().last))
            .collect::<Vec<_>>();
        let mut removed = 0;
        for (client, last) in stale {
            // `last` pins the observed state: if the client was touched
            // between the scan and the removal, leave it alone.
            if inner
                .buckets
                .remove_if(&client, |_, bucket| bucket.last == last)
                .is_some()
            {
                removed += 1;
            }
        }
        removed
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
    /// Cap on the number of tracked clients.
    max_clients: usize,
    /// Counts over-cap acquisitions so eviction passes can be spaced apart.
    /// `Arc` so clones of the limiter share one clock.
    evict_clock: Arc<AtomicU64>,
}

/// Keeps a per-client and a global slot alive for the duration of a query.
pub struct Permit {
    _client: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

impl ClientConcurrency {
    pub fn new(max_per_client: usize, max_global: usize) -> Self {
        Self::with_max_clients(max_per_client, max_global, MAX_TRACKED_CLIENTS)
    }

    /// Same as [`Self::new`] with an explicit cap on tracked clients, so
    /// tests can exercise eviction without 65 536 allocations.
    pub(crate) fn with_max_clients(
        max_per_client: usize,
        max_global: usize,
        max_clients: usize,
    ) -> Self {
        Self {
            max: max_per_client.max(1),
            per_client: Arc::new(DashMap::new()),
            global: Arc::new(Semaphore::new(max_global.max(1))),
            max_clients: max_clients.max(1),
            evict_clock: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Try to reserve a slot. Returns `None` when the client or the server as
    /// a whole is already at its limit.
    pub fn try_acquire(&self, client: IpAddr) -> Option<Permit> {
        if self.per_client.len() > self.max_clients {
            self.evict_idle();
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

    /// Drop entries whose semaphore has every permit available, meaning no
    /// query currently holds a slot for that client. Evicting only those
    /// keeps per-client limits intact for active clients; the previous
    /// whole-map `clear()` reset every client's limit whenever spoofed
    /// sources pushed the table over its cap.
    ///
    /// `available_permits` is approximate under contention, so a permit
    /// acquired in the moment between the re-check below and the removal
    /// could leave that client briefly on a fresh semaphore while its old
    /// permits wind down — at worst a transient, bounded overshoot.
    ///
    /// Returns the number of entries removed.
    fn evict_idle(&self) -> usize {
        if !self
            .evict_clock
            .fetch_add(1, Ordering::Relaxed)
            .is_multiple_of(EVICTION_TICK)
        {
            return 0;
        }
        self.evict_idle_pass()
    }

    /// One eviction pass; separate from [`Self::evict_idle`] so tests can
    /// run it without the tick spacing.
    fn evict_idle_pass(&self) -> usize {
        // Collect first: removing while iterating would deadlock on the
        // shard read lock the iterator holds.
        let idle = self
            .per_client
            .iter()
            .take(EVICTION_BATCH)
            .filter(|entry| entry.value().available_permits() >= self.max)
            .map(|entry| *entry.key())
            .collect::<Vec<_>>();
        let mut removed = 0;
        for client in idle {
            if self
                .per_client
                .remove_if(&client, |_, semaphore| {
                    semaphore.available_permits() >= self.max
                })
                .is_some()
            {
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{ClientConcurrency, RateDecision, RateLimiter};

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

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

    /// A table over its cap must not be wiped wholesale: a client whose
    /// bucket was just drained must stay limited. Regression test for the
    /// old `clear()` that let spoofed sources reset every rate limit.
    #[test]
    fn overflow_does_not_reset_active_client_limit() {
        let limiter = RateLimiter::with_max_clients(1, 0, 4);
        let client = ip(1);
        assert_eq!(limiter.check(client), RateDecision::Allow);
        assert_eq!(limiter.check(client), RateDecision::Drop);
        // Four more clients push the table past its cap of four.
        for last in 2..=5 {
            assert_eq!(limiter.check(ip(last)), RateDecision::Allow);
        }
        let inner = limiter.inner.as_ref().map(Arc::clone).unwrap();
        assert!(inner.buckets.len() > inner.max_clients);
        assert!(inner.buckets.contains_key(&client));
        // The active client keeps its drained bucket: it does not regain a
        // full complement of tokens just because the table overflowed.
        assert_eq!(limiter.check(client), RateDecision::Drop);
    }

    /// Buckets idle for at least one full refill window are refilled and
    /// therefore safe to evict; fresh buckets survive.
    #[test]
    fn evict_stale_removes_only_refilled_buckets() {
        let limiter = RateLimiter::with_max_clients(1, 1, 100);
        assert_eq!(limiter.check(ip(1)), RateDecision::Allow);
        assert_eq!(limiter.check(ip(2)), RateDecision::Allow);
        let inner = limiter.inner.as_ref().map(Arc::clone).unwrap();

        // A clock two seconds ahead: both buckets refilled a window ago.
        let future = Instant::now() + Duration::from_secs(2);
        assert_eq!(limiter.evict_stale_pass(&inner, future), 2);
        assert_eq!(inner.buckets.len(), 0);

        // A bucket touched just before the scan's clock is kept.
        assert_eq!(limiter.check(ip(3)), RateDecision::Allow);
        assert_eq!(limiter.evict_stale_pass(&inner, Instant::now()), 0);
        assert_eq!(inner.buckets.len(), 1);
    }

    /// With the table sitting over its cap, a later check evicts the stale
    /// entries but keeps the recently active ones.
    #[test]
    fn overflow_evicts_stale_but_keeps_active() {
        let limiter = RateLimiter::with_max_clients(1, 0, 4);
        // Four clients fill the table to its cap, each spending its token.
        for last in 1..=4 {
            limiter.check(ip(last));
        }
        // Age the buckets past one full refill window.
        thread::sleep(Duration::from_millis(1100));
        // The active client refreshes its bucket ...
        assert_eq!(limiter.check(ip(1)), RateDecision::Allow);
        // ... a fresh client pushes the table over its cap ...
        assert_eq!(limiter.check(ip(5)), RateDecision::Allow);
        // ... and the next check evicts only the aged buckets.
        let inner = limiter.inner.as_ref().map(Arc::clone).unwrap();
        assert_eq!(limiter.check(ip(1)), RateDecision::Drop);
        assert_eq!(inner.buckets.len(), 2);
        assert!(inner.buckets.contains_key(&ip(1)));
        assert!(inner.buckets.contains_key(&ip(5)));
        assert!(!inner.buckets.contains_key(&ip(2)));
        assert!(!inner.buckets.contains_key(&ip(3)));
        assert!(!inner.buckets.contains_key(&ip(4)));
    }

    /// Overflow eviction must never drop a semaphore whose client still
    /// holds permits; released slots are fair game.
    #[test]
    fn eviction_keeps_clients_holding_permits() {
        let cc = ClientConcurrency::with_max_clients(1, 8, 2);
        let a = cc.try_acquire(ip(1)).expect("first client acquires");
        let _b = cc.try_acquire(ip(2)).expect("second client acquires");
        let _c = cc.try_acquire(ip(3)).expect("third client acquires");
        assert_eq!(cc.per_client.len(), 3);
        // All three hold permits, so nothing is evictable ...
        assert_eq!(cc.evict_idle_pass(), 0);
        assert_eq!(cc.per_client.len(), 3);
        // ... a client at its limit stays capped ...
        assert!(cc.try_acquire(ip(2)).is_none());
        // ... and once `a` releases its slot, the next eviction pass removes
        // only the idle entry.
        drop(a);
        assert_eq!(cc.evict_idle_pass(), 1);
        assert_eq!(cc.per_client.len(), 2);
        assert!(!cc.per_client.contains_key(&ip(1)));
        assert!(cc.per_client.contains_key(&ip(2)));
        assert!(cc.per_client.contains_key(&ip(3)));
        // Eviction leaves the limiter fully functional.
        assert!(cc.try_acquire(ip(4)).is_some());
    }
}
