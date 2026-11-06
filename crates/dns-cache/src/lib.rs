//! Cache primitives for dns-rs.

mod infra;
mod message;
mod registry;
mod rrset;

pub use infra::InfraCache;
pub use message::{
    CacheHit, CacheHitMeta, CacheStats, DEFAULT_STALE_TTL, MessageCache, WireRequest,
    patch_question, patch_wire, response_ttl, wire_has_opt,
};
pub use registry::{CoalesceStats, LeaderGuard, QueryKey, QueryRegistry, RegistryEntry};
pub use rrset::{CachedRrset, RrsetCache};

use std::hash::Hash;
use std::time::{Duration, Instant};

/// A concurrent cache with per-entry expiry.
pub struct TtlCache<K, V> {
    inner: moka::sync::Cache<K, Entry<V>>,
    default_ttl: Duration,
}

#[derive(Clone)]
struct Entry<V> {
    value: V,
    expires_at: Instant,
}

impl<K, V> TtlCache<K, V>
where
    K: Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(max_capacity: u64, default_ttl: Duration) -> Self {
        Self {
            inner: moka::sync::Cache::new(max_capacity),
            default_ttl,
        }
    }

    pub fn insert_default(&self, key: K, value: V) {
        self.insert(key, value, self.default_ttl);
    }

    pub fn insert(&self, key: K, value: V, ttl: Duration) {
        let now = Instant::now();
        self.insert_at(key, value, now, ttl);
    }

    pub fn insert_at(&self, key: K, value: V, now: Instant, ttl: Duration) {
        self.inner.insert(
            key,
            Entry {
                value,
                expires_at: now + ttl,
            },
        );
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.get_at(key, Instant::now())
    }

    pub fn get_at(&self, key: &K, now: Instant) -> Option<V> {
        let entry = self.inner.get(key)?;
        if entry.expires_at <= now {
            self.inner.invalidate(key);
            return None;
        }
        Some(entry.value)
    }

    pub fn remove(&self, key: &K) {
        self.inner.invalidate(key);
    }

    pub fn clear(&self) {
        self.inner.invalidate_all();
    }

    pub fn len(&self) -> u64 {
        self.inner.entry_count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::TtlCache;

    #[test]
    fn returns_unexpired_values() {
        let cache = TtlCache::new(16, Duration::from_secs(60));
        let now = Instant::now();
        cache.insert_at("key", 42, now, Duration::from_secs(30));

        assert_eq!(cache.get_at(&"key", now), Some(42));
        assert_eq!(
            cache.get_at(&"key", now + Duration::from_secs(29)),
            Some(42)
        );
    }

    #[test]
    fn expires_values() {
        let cache = TtlCache::new(16, Duration::from_secs(60));
        let now = Instant::now();
        cache.insert_at("key", 42, now, Duration::from_secs(30));

        assert_eq!(cache.get_at(&"key", now + Duration::from_secs(30)), None);
        assert!(cache.is_empty());
    }

    #[test]
    fn removes_values() {
        let cache = TtlCache::new(16, Duration::from_secs(60));
        cache.insert_default("key", 42);
        assert_eq!(cache.get(&"key"), Some(42));
        cache.remove(&"key");
        assert_eq!(cache.get(&"key"), None);
    }
}
