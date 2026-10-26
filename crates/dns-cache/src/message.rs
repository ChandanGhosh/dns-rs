//! Whole-message cache with wire-format storage and TTL ageing.
//!
//! Entries are stored as encoded DNS messages. A cache hit patches the query
//! ID and flags directly in the wire, ages every record TTL in place, and only
//! decodes when a per-client EDNS/cookie/truncation step is required. This
//! keeps the hot path free of message cloning and re-encoding.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dns_proto::{Message, Name, RData, RecordType, encode};
use moka::sync::Cache;

/// Default stale window when `serve-expired-ttl` is zero (Unbound semantics).
pub const DEFAULT_STALE_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
struct CachedWire {
    wire: Arc<Vec<u8>>,
    question_name: String,
    inserted_at: Instant,
    expires_at: Instant,
    stale_until: Instant,
    original_ttl: Duration,
}

/// Hit/miss counters for observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub stale_hits: u64,
}

/// Per-client fields needed to patch a cached wire response.
#[derive(Clone, Copy, Debug)]
pub struct WireRequest<'a> {
    pub id: u16,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    pub question_name: &'a Name,
}

/// A cache hit, already patched for the requesting client.
#[derive(Clone, Debug)]
pub struct CacheHit {
    pub wire: Vec<u8>,
    pub remaining: Duration,
    pub original_ttl: Duration,
    /// Question name exactly as it was stored.
    pub question_name: String,
    pub stale: bool,
}

#[derive(Clone)]
pub struct MessageCache {
    cache: Cache<String, CachedWire>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    stale_hits: Arc<AtomicU64>,
    stale_for: Duration,
}

impl MessageCache {
    pub fn new(max_capacity: u64) -> Self {
        Self::with_stale_window(max_capacity, Duration::ZERO)
    }

    /// Build a cache that keeps expired entries for `stale_for` so they can be
    /// served while a refresh is in flight (RFC 8767).
    pub fn with_stale_window(max_capacity: u64, stale_for: Duration) -> Self {
        Self {
            // Entries enforce their own expiry. The backend TTL only bounds
            // memory for abandoned entries, so leave room for the stale window.
            cache: Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(7 * 24 * 3600))
                .build(),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            stale_hits: Arc::new(AtomicU64::new(0)),
            stale_for,
        }
    }

    fn key(name: &Name, record_type: RecordType, do_bit: bool) -> String {
        format!(
            "{}|{}|{}",
            name.to_ascii().to_lowercase(),
            u16::from(record_type),
            u8::from(do_bit)
        )
    }

    pub fn insert(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        message: &Message,
        ttl: Duration,
    ) {
        let Ok(wire) = encode(message) else {
            return;
        };
        let question_name = message
            .queries
            .first()
            .map(|query| query.name.to_ascii())
            .unwrap_or_default();
        let now = Instant::now();
        let entry = CachedWire {
            wire: Arc::new(wire),
            question_name,
            inserted_at: now,
            expires_at: now + ttl,
            stale_until: now + ttl + self.stale_for,
            original_ttl: ttl,
        };
        self.cache
            .insert(Self::key(name, record_type, do_bit), entry);
    }

    /// Return a fresh cached response patched for `request`.
    pub fn get(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        request: WireRequest<'_>,
    ) -> Option<CacheHit> {
        let key = Self::key(name, record_type, do_bit);
        let Some(entry) = self.cache.get(&key) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };

        let now = Instant::now();
        if entry.expires_at <= now {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let elapsed = now.saturating_duration_since(entry.inserted_at).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        let mut wire = (*entry.wire).clone();
        if !age_wire(&mut wire, elapsed, None) {
            self.cache.invalidate(&key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        patch_wire(&mut wire, request);

        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(CacheHit {
            wire,
            remaining: entry.expires_at.saturating_duration_since(now),
            original_ttl: entry.original_ttl,
            question_name: entry.question_name,
            stale: false,
        })
    }

    /// Return an expired entry if it is still inside the configured stale
    /// window. TTLs are set to `reply_ttl` so downstream clients do not cache
    /// stale data for long.
    pub fn get_stale(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        request: WireRequest<'_>,
        reply_ttl: u32,
    ) -> Option<CacheHit> {
        let key = Self::key(name, record_type, do_bit);
        let entry = self.cache.get(&key)?;
        let now = Instant::now();
        if now >= entry.stale_until {
            self.cache.invalidate(&key);
            return None;
        }

        let mut wire = (*entry.wire).clone();
        if !age_wire(&mut wire, 0, Some(reply_ttl)) {
            self.cache.invalidate(&key);
            return None;
        }
        patch_wire(&mut wire, request);
        self.stale_hits.fetch_add(1, Ordering::Relaxed);
        Some(CacheHit {
            wire,
            remaining: Duration::ZERO,
            original_ttl: entry.original_ttl,
            question_name: entry.question_name,
            stale: true,
        })
    }

    /// Prefetch when less than 10% of the original TTL remains, or three
    /// seconds, whichever is larger (Unbound's prefetch trigger).
    pub fn should_prefetch(hit: &CacheHit) -> bool {
        if hit.stale {
            return true;
        }
        let threshold = (hit.original_ttl / 10).max(Duration::from_secs(3));
        hit.remaining <= threshold
    }

    pub fn remove(&self, name: &Name, record_type: RecordType, do_bit: bool) {
        self.cache.invalidate(&Self::key(name, record_type, do_bit));
    }

    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            stale_hits: self.stale_hits.load(Ordering::Relaxed),
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

/// Patch the header fields that are specific to one client.
fn patch_wire(wire: &mut [u8], request: WireRequest<'_>) {
    if wire.len() < 12 {
        return;
    }
    wire[0..2].copy_from_slice(&request.id.to_be_bytes());

    // QR is always set for a cached response. Preserve opcode/AA/TC.
    wire[2] |= 0x80;
    wire[2] = (wire[2] & !0x01) | u8::from(request.recursion_desired);

    // RA is always set by this resolver. CD follows the request and AD is
    // cleared when the client asked for checking-disabled data.
    wire[3] |= 0x80;
    wire[3] = (wire[3] & !0x10) | (u8::from(request.checking_disabled) << 4);
    if request.checking_disabled {
        wire[3] &= !0x20;
    }
}

/// Age (or overwrite) every record TTL in a DNS message.
///
/// Returns false when the wire is malformed, in which case the caller drops
/// the entry instead of serving a partially patched message.
fn age_wire(wire: &mut [u8], elapsed: u32, set_ttl: Option<u32>) -> bool {
    if wire.len() < 12 {
        return false;
    }
    let qdcount = u16::from_be_bytes([wire[4], wire[5]]);
    let ancount = u16::from_be_bytes([wire[6], wire[7]]);
    let nscount = u16::from_be_bytes([wire[8], wire[9]]);
    let arcount = u16::from_be_bytes([wire[10], wire[11]]);

    let mut offset = 12usize;
    for _ in 0..qdcount {
        let Some(next) = skip_name(wire, offset) else {
            return false;
        };
        offset = next.checked_add(4).unwrap_or(wire.len());
        if offset > wire.len() {
            return false;
        }
    }

    for count in [ancount, nscount, arcount] {
        for _ in 0..count {
            let Some(next) = skip_name(wire, offset) else {
                return false;
            };
            offset = next;
            // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
            if offset + 10 > wire.len() {
                return false;
            }
            let record_type = u16::from_be_bytes([wire[offset], wire[offset + 1]]);
            if record_type != 41 {
                // OPT uses the TTL field for extended flags, not a lifetime.
                let ttl = u32::from_be_bytes([
                    wire[offset + 4],
                    wire[offset + 5],
                    wire[offset + 6],
                    wire[offset + 7],
                ]);
                let aged = set_ttl.unwrap_or_else(|| ttl.saturating_sub(elapsed));
                wire[offset + 4..offset + 8].copy_from_slice(&aged.to_be_bytes());
            }
            let rdlength = u16::from_be_bytes([wire[offset + 8], wire[offset + 9]]);
            offset = offset
                .checked_add(10 + usize::from(rdlength))
                .unwrap_or(wire.len());
            if offset > wire.len() {
                return false;
            }
        }
    }
    true
}

/// Skip a possibly compressed name and return the offset just past it.
fn skip_name(wire: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let length = *wire.get(offset)?;
        if length & 0xC0 == 0xC0 {
            return Some(offset + 2);
        }
        if length == 0 {
            return Some(offset + 1);
        }
        offset = offset.checked_add(1 + usize::from(length))?;
        if offset > wire.len() {
            return None;
        }
    }
}

/// Compute a cacheable TTL for a response.
///
/// Positive answers use the smallest record TTL. Negative answers follow
/// RFC 2308 by taking the smaller of the SOA TTL and its MINIMUM field. The
/// result is clamped to the configured cache TTL bounds.
pub fn response_ttl(message: &Message, min_ttl: u32, max_ttl: u32) -> Duration {
    let mut ttl: Option<u32> = None;

    for record in message
        .answers
        .iter()
        .chain(message.authorities.iter())
        .chain(message.additionals.iter())
    {
        if record.record_type() == RecordType::OPT {
            continue;
        }
        ttl = Some(ttl.map_or(record.ttl, |current| current.min(record.ttl)));
    }

    if message.answers.is_empty() {
        for record in &message.authorities {
            if let RData::SOA(soa) = &record.data {
                let negative = record.ttl.min(soa.minimum);
                ttl = Some(ttl.map_or(negative, |current| current.min(negative)));
            }
        }
    }

    let seconds = ttl.unwrap_or(min_ttl).clamp(min_ttl, max_ttl.max(min_ttl));
    Duration::from_secs(u64::from(seconds))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dns_proto::{Message, MessageType, Name, OpCode, RData, Record, RecordType};

    use super::{MessageCache, WireRequest, response_ttl};

    fn answer(ttl: u32) -> Message {
        let name = Name::from_ascii("example.com.").expect("name");
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_query(dns_proto::Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        message
    }

    fn request<'a>(name: &'a Name) -> WireRequest<'a> {
        WireRequest {
            id: 0x1234,
            recursion_desired: true,
            checking_disabled: false,
            question_name: name,
        }
    }

    #[test]
    fn ages_ttls_on_read() {
        let cache = MessageCache::new(16);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );

        let hit = cache
            .get(&name, RecordType::A, false, request(&name))
            .expect("hit");
        let message = Message::from_vec(&hit.wire).expect("decode");
        assert!(message.answers[0].ttl <= 60);
        assert_eq!(message.metadata.id, 0x1234);
        assert!(message.metadata.recursion_desired);
        assert!(message.metadata.recursion_available);
        assert_eq!(cache.stats().hits, 1);
    }

    #[test]
    fn patches_flags_for_the_client() {
        let cache = MessageCache::new(16);
        let name = Name::from_ascii("example.com.").expect("name");
        let mut message = answer(60);
        message.metadata.authentic_data = true;
        cache.insert(
            &name,
            RecordType::A,
            false,
            &message,
            Duration::from_secs(60),
        );

        let hit = cache
            .get(
                &name,
                RecordType::A,
                false,
                WireRequest {
                    id: 7,
                    recursion_desired: false,
                    checking_disabled: true,
                    question_name: &name,
                },
            )
            .expect("hit");
        let response = Message::from_vec(&hit.wire).expect("decode");
        assert_eq!(response.metadata.id, 7);
        assert!(!response.metadata.recursion_desired);
        assert!(response.metadata.checking_disabled);
        assert!(!response.metadata.authentic_data);
        assert!(response.metadata.recursion_available);
    }

    #[test]
    fn distinguishes_do_bit() {
        let cache = MessageCache::new(16);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );
        assert!(
            cache
                .get(&name, RecordType::A, true, request(&name))
                .is_none()
        );
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn clamps_ttl() {
        assert_eq!(response_ttl(&answer(1), 30, 120), Duration::from_secs(30));
        assert_eq!(response_ttl(&answer(999), 0, 120), Duration::from_secs(120));
    }

    #[test]
    fn expires_entries() {
        let cache = MessageCache::new(16);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(&name, RecordType::A, false, &answer(60), Duration::ZERO);
        assert!(
            cache
                .get(&name, RecordType::A, false, request(&name))
                .is_none()
        );
    }

    #[test]
    fn serves_expired_entries_with_a_short_ttl() {
        let cache = MessageCache::with_stale_window(16, Duration::from_secs(30));
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(&name, RecordType::A, false, &answer(60), Duration::ZERO);

        let hit = cache
            .get_stale(&name, RecordType::A, false, request(&name), 30)
            .expect("stale hit");
        assert!(hit.stale);
        let message = Message::from_vec(&hit.wire).expect("decode");
        assert_eq!(message.answers[0].ttl, 30);
        assert_eq!(cache.stats().stale_hits, 1);
    }

    #[test]
    fn prefetches_near_the_end_of_the_ttl() {
        let cache = MessageCache::new(16);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );
        let hit = cache
            .get(&name, RecordType::A, false, request(&name))
            .expect("hit");
        assert!(!MessageCache::should_prefetch(&hit));

        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );
        let mut stale = hit;
        stale.remaining = Duration::from_secs(2);
        stale.original_ttl = Duration::from_secs(60);
        assert!(MessageCache::should_prefetch(&stale));
    }
}
