//! Response-rate limiting and per-client concurrency limits.

use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use dashmap::DashMap;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_TRACKED_CLIENTS: usize = 65_536;

/// Maximum entries examined per eviction pass once a table is over its cap.
const EVICTION_BATCH: usize = 512;

/// Eviction passes are spaced this many over-cap checks apart, bounding the
/// per-query scan cost even while an attack keeps the table full.
const EVICTION_TICK: u64 = 64;

/// Visit entries from a rotating starting point.
///
/// The old fixed-prefix scans always examined the same leading entries. If
/// those entries stayed fresh or active, stale entries appended later were
/// never reached and the table grew past its cap. Each pass advances the start
/// by one batch, so every entry is eventually examined. Visiting stops as soon
/// as `visit` returns `false`, keeping each pass bounded by the batch cap.
fn for_rotating_entries<K, V, S, F>(map: &DashMap<K, V, S>, cursor: usize, mut visit: F)
where
    K: Copy + Eq + Hash,
    S: BuildHasher + Clone,
    F: FnMut(&K, &V) -> bool,
{
    let len = map.len();
    if len == 0 {
        return;
    }
    for entry in map.iter().skip(cursor % len) {
        if !visit(entry.key(), entry.value()) {
            return;
        }
    }
}

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
    /// Number of tracked clients, maintained on insert/eviction so the hot
    /// path can compare against it without scanning every map shard.
    tracked: AtomicUsize,
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
                tracked: AtomicUsize::new(0),
                evict_clock: AtomicU64::new(0),
            })),
        }
    }

    pub fn check(&self, client: IpAddr) -> RateDecision {
        let Some(inner) = &self.inner else {
            return RateDecision::Allow;
        };

        let now = Instant::now();
        if inner.tracked.load(Ordering::Relaxed) > inner.max_clients {
            self.evict_stale(inner, now);
        }
        let allowed = {
            let mut bucket = inner.buckets.entry(client).or_insert_with(|| {
                inner.tracked.fetch_add(1, Ordering::Relaxed);
                Bucket {
                    tokens: inner.capacity,
                    last: now,
                }
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
        let tick = inner.evict_clock.fetch_add(1, Ordering::Relaxed);
        if !tick.is_multiple_of(EVICTION_TICK) {
            return 0;
        }
        self.evict_stale_pass_at(
            inner,
            now,
            ((tick / EVICTION_TICK) as usize).wrapping_mul(EVICTION_BATCH),
        )
    }

    /// One eviction pass starting from a rotating cursor.
    fn evict_stale_pass_at(&self, inner: &Inner, now: Instant, cursor: usize) -> usize {
        // Collect first: the shard read locks must be released before removal.
        let mut stale = Vec::new();
        for_rotating_entries(&inner.buckets, cursor, |client, bucket| {
            if stale.len() >= EVICTION_BATCH {
                return false;
            }
            if now.saturating_duration_since(bucket.last).as_secs_f64() * inner.refill_per_second
                >= inner.capacity
            {
                stale.push((*client, bucket.last));
            }
            true
        });
        let mut removed = 0;
        for (client, last) in stale {
            // `last` pins the observed state: if the client was touched
            // between the scan and the removal, leave it alone.
            if inner
                .buckets
                .remove_if(&client, |_, bucket| bucket.last == last)
                .is_some()
            {
                inner.tracked.fetch_sub(1, Ordering::Relaxed);
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
    /// Number of tracked clients, maintained on insert/eviction so the hot
    /// path can compare against it without scanning every map shard.
    tracked: Arc<AtomicUsize>,
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
            tracked: Arc::new(AtomicUsize::new(0)),
            evict_clock: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Try to reserve a slot. Returns `None` when the client or the server as
    /// a whole is already at its limit.
    pub fn try_acquire(&self, client: IpAddr) -> Option<Permit> {
        if self.tracked.load(Ordering::Relaxed) > self.max_clients {
            self.evict_idle();
        }
        // The common case is an existing client: take a shared lock instead of
        // the entry API's exclusive shard lock.
        let semaphore = match self.per_client.get(&client) {
            Some(entry) => Arc::clone(entry.value()),
            None => self
                .per_client
                .entry(client)
                .or_insert_with(|| {
                    self.tracked.fetch_add(1, Ordering::Relaxed);
                    Arc::new(Semaphore::new(self.max))
                })
                .clone(),
        };
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
        let tick = self.evict_clock.fetch_add(1, Ordering::Relaxed);
        if !tick.is_multiple_of(EVICTION_TICK) {
            return 0;
        }
        self.evict_idle_pass_at(((tick / EVICTION_TICK) as usize).wrapping_mul(EVICTION_BATCH))
    }

    /// One eviction pass starting from a rotating cursor.
    fn evict_idle_pass_at(&self, cursor: usize) -> usize {
        // Collect first: the shard read locks must be released before removal.
        let mut idle = Vec::new();
        for_rotating_entries(&self.per_client, cursor, |client, semaphore| {
            if idle.len() >= EVICTION_BATCH {
                return false;
            }
            if semaphore.available_permits() >= self.max {
                idle.push(*client);
            }
            true
        });
        let mut removed = 0;
        for client in idle {
            if self
                .per_client
                .remove_if(&client, |_, semaphore| {
                    semaphore.available_permits() >= self.max
                })
                .is_some()
            {
                self.tracked.fetch_sub(1, Ordering::Relaxed);
                removed += 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{ClientConcurrency, EVICTION_BATCH, RateDecision, RateLimiter};

    /// The maintained entry count must match the map, otherwise the hot-path
    /// cap check either never evicts or evicts too early.
    fn assert_tracked_matches_len(limiter: &RateLimiter) {
        let Some(inner) = &limiter.inner else {
            return;
        };
        assert_eq!(
            inner.tracked.load(Ordering::Relaxed),
            inner.buckets.len(),
            "tracked count drifted from bucket map"
        );
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last))
    }

    fn ip_index(index: u16) -> IpAddr {
        let high = u8::try_from(index / 256).expect("third octet");
        let low = u8::try_from(index % 256).expect("fourth octet");
        IpAddr::V4(Ipv4Addr::new(192, 0, high, low))
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
        assert_eq!(limiter.evict_stale_pass_at(&inner, future, 0), 2);
        assert_eq!(inner.buckets.len(), 0);
        assert_tracked_matches_len(&limiter);

        // A bucket touched just before the scan's clock is kept.
        assert_eq!(limiter.check(ip(3)), RateDecision::Allow);
        assert_eq!(limiter.evict_stale_pass_at(&inner, Instant::now(), 0), 0);
        assert_eq!(inner.buckets.len(), 1);
        assert_tracked_matches_len(&limiter);
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
        assert_tracked_matches_len(&limiter);
    }

    /// A rotating pass must reach stale entries past the old fixed prefix;
    /// otherwise a flood of fresh sources pins the first batch in place and
    /// lets the table grow without bound.
    #[test]
    fn rotating_eviction_reaches_stale_entries_past_first_batch() {
        let client_count = EVICTION_BATCH + 88;
        let limiter = RateLimiter::with_max_clients(1, 0, client_count * 2);
        for index in 0..client_count as u16 {
            assert_eq!(limiter.check(ip_index(index)), RateDecision::Allow);
        }
        let inner = limiter.inner.as_ref().map(Arc::clone).expect("limiter");
        let past = Instant::now();
        let now = past + Duration::from_secs(10);

        let fresh: Vec<IpAddr> = inner
            .buckets
            .iter()
            .take(EVICTION_BATCH)
            .map(|entry| *entry.key())
            .collect();
        for mut entry in inner.buckets.iter_mut() {
            entry.value_mut().last = past;
        }
        for client in &fresh {
            inner.buckets.get_mut(client).expect("fresh entry").last = now;
        }

        assert_eq!(
            limiter.evict_stale_pass_at(&inner, now, EVICTION_BATCH),
            client_count - EVICTION_BATCH
        );
        assert_eq!(inner.buckets.len(), EVICTION_BATCH);
        assert!(
            fresh
                .iter()
                .all(|client| inner.buckets.contains_key(client))
        );
        assert_tracked_matches_len(&limiter);
    }

    /// Repeated acquisitions for one client must reuse its semaphore and not
    /// grow the tracked count (the map's shared-lock fast path).
    #[test]
    fn repeated_acquires_reuse_one_entry() {
        let cc = ClientConcurrency::with_max_clients(4, 8, 8);
        for _ in 0..100 {
            assert!(cc.try_acquire(ip(1)).is_some());
        }
        assert_eq!(cc.per_client.len(), 1);
        assert_eq!(cc.tracked.load(Ordering::Relaxed), 1);
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
        assert_eq!(cc.tracked.load(Ordering::Relaxed), 3);
        // All three hold permits, so nothing is evictable ...
        assert_eq!(cc.evict_idle_pass_at(0), 0);
        assert_eq!(cc.per_client.len(), 3);
        // ... a client at its limit stays capped ...
        assert!(cc.try_acquire(ip(2)).is_none());
        // ... and once `a` releases its slot, the next eviction pass removes
        // only the idle entry.
        drop(a);
        assert_eq!(cc.evict_idle_pass_at(0), 1);
        assert_eq!(cc.per_client.len(), 2);
        assert_eq!(cc.tracked.load(Ordering::Relaxed), 2);
        assert!(!cc.per_client.contains_key(&ip(1)));
        assert!(cc.per_client.contains_key(&ip(2)));
        assert!(cc.per_client.contains_key(&ip(3)));
        // Eviction leaves the limiter fully functional.
        assert!(cc.try_acquire(ip(4)).is_some());
    }

    /// Idle semaphores beyond the old fixed prefix must still be evictable.
    #[test]
    fn rotating_eviction_reaches_idle_entries_past_first_batch() {
        let client_count = EVICTION_BATCH + 88;
        let cc = ClientConcurrency::with_max_clients(1, client_count, client_count * 2);
        let permits: Vec<(IpAddr, _)> = (0..client_count as u16)
            .map(|index| {
                let client = ip_index(index);
                let permit = cc.try_acquire(client).expect("client acquires");
                (client, permit)
            })
            .collect();
        let busy: HashSet<IpAddr> = cc
            .per_client
            .iter()
            .take(EVICTION_BATCH)
            .map(|entry| *entry.key())
            .collect();

        let mut active = Vec::new();
        for (client, permit) in permits {
            if busy.contains(&client) {
                active.push(permit);
            } else {
                drop(permit);
            }
        }

        assert_eq!(
            cc.evict_idle_pass_at(EVICTION_BATCH),
            client_count - EVICTION_BATCH
        );
        assert_eq!(cc.per_client.len(), EVICTION_BATCH);
        assert_eq!(cc.tracked.load(Ordering::Relaxed), EVICTION_BATCH);
        assert!(busy.iter().all(|client| cc.per_client.contains_key(client)));
        assert!(!active.is_empty());
    }
}
