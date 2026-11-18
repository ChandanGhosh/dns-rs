//! Per-server infrastructure cache: RTT, lameness, EDNS/0x20 capabilities.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use moka::sync::Cache;

#[derive(Clone, Debug)]
pub struct InfraEntry {
    pub rtt: Duration,
    pub timeouts: u32,
    pub failures: u32,
    pub lame: bool,
    /// Earliest time at which this server should be tried again.
    pub retry_at: Option<Instant>,
    /// Whether the server preserves QNAME case (DNS 0x20).
    pub caps_ok: bool,
    pub last_update: Instant,
}

impl Default for InfraEntry {
    fn default() -> Self {
        Self {
            rtt: Duration::from_millis(376),
            timeouts: 0,
            failures: 0,
            lame: false,
            retry_at: None,
            caps_ok: true,
            last_update: Instant::now(),
        }
    }
}

/// Base delay before retrying a failing server. Each consecutive failure
/// doubles the delay, capped at [`BACKOFF_MAX`].
const BACKOFF_BASE: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

fn backoff_delay(attempts: u32) -> Duration {
    let shift = attempts.saturating_sub(1).min(7);
    BACKOFF_BASE.saturating_mul(1u32 << shift).min(BACKOFF_MAX)
}

fn schedule_backoff(entry: &mut InfraEntry) {
    let attempts = entry.timeouts.saturating_add(entry.failures).max(1);
    entry.retry_at = Some(Instant::now() + backoff_delay(attempts));
}

#[derive(Clone)]
pub struct InfraCache {
    // `SocketAddr` is `Hash + Eq`, so keying by it directly avoids the
    // per-lookup `String` allocation that formatting the address caused.
    cache: Cache<SocketAddr, InfraEntry>,
    min_rtt: Duration,
}

/// Default lifetime of an infrastructure entry.
pub const DEFAULT_INFRA_TTL: Duration = Duration::from_secs(3_600);

impl InfraCache {
    /// Build a cache with the default entry lifetime and no RTT floor.
    pub fn new(max_capacity: u64) -> Self {
        Self::with_options(max_capacity, DEFAULT_INFRA_TTL, Duration::ZERO)
    }

    /// Build a cache with explicit capacity, entry lifetime, and RTT floor.
    ///
    /// `min_rtt` mirrors Unbound's `infra-cache-min-rtt`: stored RTTs below it
    /// are raised so server selection does not over-favour a single sample.
    pub fn with_options(max_capacity: u64, ttl: Duration, min_rtt: Duration) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(ttl)
                .build(),
            min_rtt,
        }
    }

    pub fn get(&self, addr: &SocketAddr) -> Option<InfraEntry> {
        self.cache.get(addr)
    }

    fn entry(&self, addr: &SocketAddr) -> InfraEntry {
        self.cache.get(addr).unwrap_or_default()
    }

    fn store(&self, addr: &SocketAddr, mut entry: InfraEntry) {
        entry.last_update = Instant::now();
        self.cache.insert(*addr, entry);
    }

    pub fn update_rtt(&self, addr: &SocketAddr, rtt: Duration) {
        let mut entry = self.entry(addr);
        // Exponential moving average.
        entry.rtt =
            Duration::from_micros((entry.rtt.as_micros() as u64 * 7 + rtt.as_micros() as u64) / 8);
        if entry.rtt < self.min_rtt {
            entry.rtt = self.min_rtt;
        }
        entry.timeouts = 0;
        entry.failures = 0;
        entry.lame = false;
        entry.retry_at = None;
        self.store(addr, entry);
    }

    pub fn record_timeout(&self, addr: &SocketAddr) {
        let mut entry = self.entry(addr);
        entry.timeouts = entry.timeouts.saturating_add(1);
        if entry.timeouts >= 3 {
            entry.lame = true;
        }
        schedule_backoff(&mut entry);
        self.store(addr, entry);
    }

    /// Record a SERVFAIL/REFUSED-style failure. A single transient error does
    /// not make a server lame; repeated failures do.
    pub fn record_failure(&self, addr: &SocketAddr) {
        let mut entry = self.entry(addr);
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= 5 {
            entry.lame = true;
        }
        schedule_backoff(&mut entry);
        self.store(addr, entry);
    }

    pub fn mark_lame(&self, addr: &SocketAddr) {
        let mut entry = self.entry(addr);
        entry.lame = true;
        entry.retry_at = Some(Instant::now() + BACKOFF_MAX);
        self.store(addr, entry);
    }

    pub fn is_lame(&self, addr: &SocketAddr) -> bool {
        self.get(addr).is_some_and(|entry| entry.lame)
    }

    /// True while the server is inside its retry backoff window.
    pub fn is_backed_off(&self, addr: &SocketAddr) -> bool {
        self.backoff_remaining(addr).is_some()
    }

    /// Time left in the current backoff window, if any.
    pub fn backoff_remaining(&self, addr: &SocketAddr) -> Option<Duration> {
        let retry_at = self.get(addr)?.retry_at?;
        let remaining = retry_at.saturating_duration_since(Instant::now());
        (!remaining.is_zero()).then_some(remaining)
    }

    pub fn caps_supported(&self, addr: &SocketAddr) -> bool {
        self.get(addr).is_none_or(|entry| entry.caps_ok)
    }

    pub fn mark_caps_unsupported(&self, addr: &SocketAddr) {
        let mut entry = self.entry(addr);
        entry.caps_ok = false;
        self.store(addr, entry);
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use super::InfraCache;

    fn address() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53)
    }

    #[test]
    fn tracks_rtt_and_lameness() {
        let cache = InfraCache::new(16);
        assert!(!cache.is_lame(&address()));
        cache.mark_lame(&address());
        assert!(cache.is_lame(&address()));

        cache.update_rtt(&address(), Duration::from_millis(50));
        let entry = cache.get(&address()).expect("entry");
        assert!(entry.rtt < Duration::from_millis(376));
        assert_eq!(entry.timeouts, 0);
    }

    #[test]
    fn applies_the_configured_rtt_floor() {
        let cache = InfraCache::with_options(16, Duration::from_secs(60), Duration::from_secs(1));
        cache.update_rtt(&address(), Duration::from_millis(1));
        let entry = cache.get(&address()).expect("entry");
        assert_eq!(entry.rtt, Duration::from_secs(1));
    }

    #[test]
    fn remembers_caps_failure() {
        let cache = InfraCache::new(16);
        assert!(cache.caps_supported(&address()));
        cache.mark_caps_unsupported(&address());
        assert!(!cache.caps_supported(&address()));
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        assert_eq!(super::backoff_delay(1), Duration::from_millis(250));
        assert_eq!(super::backoff_delay(2), Duration::from_millis(500));
        assert_eq!(super::backoff_delay(3), Duration::from_millis(1000));
        assert_eq!(super::backoff_delay(8), Duration::from_secs(30));
        assert_eq!(super::backoff_delay(100), Duration::from_secs(30));
    }

    #[test]
    fn failures_schedule_a_backoff_and_success_clears_it() {
        let cache = InfraCache::new(16);
        assert!(!cache.is_backed_off(&address()));

        cache.record_timeout(&address());
        assert!(cache.is_backed_off(&address()));
        assert!(cache.backoff_remaining(&address()).is_some());

        cache.record_failure(&address());
        assert!(cache.is_backed_off(&address()));

        cache.update_rtt(&address(), Duration::from_millis(40));
        assert!(!cache.is_backed_off(&address()));
        assert!(!cache.is_lame(&address()));
    }

    #[test]
    fn repeated_timeouts_mark_the_server_lame() {
        let cache = InfraCache::new(16);
        for _ in 0..3 {
            cache.record_timeout(&address());
        }
        assert!(cache.is_lame(&address()));
    }
}
