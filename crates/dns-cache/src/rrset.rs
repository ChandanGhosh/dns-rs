use std::time::{Duration, Instant};

use dns_proto::{Name, Record, RecordType};
use moka::sync::Cache;

#[derive(Clone, Debug)]
pub struct CachedRrset {
    pub name: Name,
    pub record_type: RecordType,
    pub records: Vec<Record>,
    pub ttl: Duration,
    pub expires_at: Instant,
}

#[derive(Clone)]
pub struct RrsetCache {
    cache: Cache<String, CachedRrset>,
}

impl RrsetCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }

    fn key(name: &Name, record_type: RecordType) -> String {
        format!("{}|{}", name.to_ascii().to_lowercase(), record_type)
    }

    pub fn insert(&self, name: Name, record_type: RecordType, records: Vec<Record>, ttl: Duration) {
        let now = Instant::now();
        let entry = CachedRrset {
            name,
            record_type,
            records,
            ttl,
            expires_at: now + ttl,
        };
        self.cache
            .insert(Self::key(&entry.name, entry.record_type), entry);
    }

    pub fn get(&self, name: &Name, record_type: RecordType) -> Option<CachedRrset> {
        let entry = self.cache.get(&Self::key(name, record_type))?;
        if entry.expires_at <= Instant::now() {
            self.cache.invalidate(&Self::key(name, record_type));
            return None;
        }
        Some(entry)
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}
