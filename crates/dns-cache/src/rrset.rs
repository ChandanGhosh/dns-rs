use std::mem::size_of;
use std::time::{Duration, Instant};

use dns_proto::{BinEncodable, BinEncoder, Name, Record, RecordType};
use moka::sync::Cache;

/// Fixed per-entry overhead charged to the byte budget.
const ENTRY_OVERHEAD: usize = 64;

fn entry_bytes(records: &[Record]) -> u32 {
    let mut scratch = Vec::with_capacity(512);
    let bytes = size_of::<CachedRrset>()
        + records
            .iter()
            .map(|record| {
                scratch.clear();
                let encoded = {
                    let mut encoder = BinEncoder::new(&mut scratch);
                    record.emit(&mut encoder)
                };
                let wire = if encoded.is_ok() { scratch.len() } else { 0 };
                size_of::<Record>() + size_of::<Name>() + wire + ENTRY_OVERHEAD
            })
            .sum::<usize>();
    u32::try_from(bytes).unwrap_or(u32::MAX).max(1)
}

#[derive(Clone, Debug)]
pub struct CachedRrset {
    pub name: Name,
    pub record_type: RecordType,
    pub records: Vec<Record>,
    pub ttl: Duration,
    pub expires_at: Instant,
    bytes: u32,
}

#[derive(Clone)]
pub struct RrsetCache {
    cache: Cache<(Name, u16), CachedRrset>,
}

impl RrsetCache {
    /// Build a cache with a byte budget.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            cache: Cache::builder()
                .max_capacity(max_bytes)
                .weigher(|_, entry: &CachedRrset| entry.bytes)
                .time_to_live(Duration::from_secs(3600))
                .build(),
        }
    }

    /// Build the cache key for one rrset.
    ///
    /// `Name` hashes and compares case-insensitively, so this matches the
    /// lowercased string keys without formatting or allocating the name.
    fn key(name: &Name, record_type: RecordType) -> (Name, u16) {
        (name.clone(), u16::from(record_type))
    }

    pub fn insert(&self, name: Name, record_type: RecordType, records: Vec<Record>, ttl: Duration) {
        let now = Instant::now();
        let bytes = entry_bytes(&records);
        let entry = CachedRrset {
            name,
            record_type,
            records,
            ttl,
            expires_at: now + ttl,
            bytes,
        };
        self.cache
            .insert(Self::key(&entry.name, entry.record_type), entry);
    }

    pub fn get(&self, name: &Name, record_type: RecordType) -> Option<CachedRrset> {
        let key = Self::key(name, record_type);
        let entry = self.cache.get(&key)?;
        if entry.expires_at <= Instant::now() {
            self.cache.invalidate(&key);
            return None;
        }
        Some(entry)
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dns_proto::{Name, RData, Record, RecordType};

    use super::{RrsetCache, entry_bytes};

    #[test]
    fn entry_bytes_scales_with_record_count() {
        let name = Name::from_ascii("example.com.").expect("name");
        let record = || {
            Record::from_rdata(
                name.clone(),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
            )
        };
        assert!(entry_bytes(&[record(), record()]) > entry_bytes(&[record()]));
    }

    #[test]
    fn lookups_match_names_case_insensitively() {
        let cache = RrsetCache::new(64 * 1024);
        let mixed = Name::from_ascii("ExAmPlE.CoM.").expect("name");
        let record = Record::from_rdata(
            mixed.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        );
        cache.insert(mixed, RecordType::A, vec![record], Duration::from_secs(60));

        let lowercase = Name::from_ascii("example.com.").expect("name");
        assert!(cache.get(&lowercase, RecordType::A).is_some());
        assert!(cache.get(&lowercase, RecordType::AAAA).is_none());
    }
}
