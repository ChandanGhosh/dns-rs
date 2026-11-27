//! Whole-message cache with wire-format storage and TTL ageing.
//!
//! Entries are stored as encoded DNS messages. A cache hit patches the query
//! ID and flags directly in the wire, ages every record TTL in place, and only
//! decodes when a per-client EDNS/cookie/truncation step is required. This
//! keeps the hot path free of message cloning and re-encoding.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dns_proto::{Message, Name, Query, RData, RecordType, encode};
use moka::sync::Cache;

/// Default stale window when `serve-expired-ttl` is zero (Unbound semantics).
pub const DEFAULT_STALE_TTL: Duration = Duration::from_secs(30);

/// Fixed per-entry overhead charged to the byte budget alongside the wire bytes.
const ENTRY_OVERHEAD: u32 = 256;

fn entry_weight(entry: &CachedWire) -> u32 {
    u32::try_from(entry.wire.len())
        .unwrap_or(u32::MAX)
        .saturating_add(ENTRY_OVERHEAD)
        .max(1)
}

#[derive(Clone, Debug)]
struct CachedWire {
    wire: Arc<Vec<u8>>,
    inserted_at: Instant,
    expires_at: Instant,
    stale_until: Instant,
    original_ttl: Duration,
    /// Whether the stored wire already has an OPT record. Normal responses do
    /// not, but keeping the flag makes the cache-hit fast path safe for any
    /// caller that inserts a message with EDNS state.
    has_edns: bool,
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
pub struct WireRequest {
    pub id: u16,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
}

/// Metadata for a cache hit. The response bytes are produced separately so
/// callers on the hot path can fill a reusable buffer (see [`MessageCache::get_into`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheHitMeta {
    pub remaining: Duration,
    pub original_ttl: Duration,
    pub stale: bool,
    /// Whether the stored wire already contains an OPT record.
    pub has_edns: bool,
}

/// A cache hit, already patched for the requesting client.
#[derive(Clone, Debug)]
pub struct CacheHit {
    pub wire: Vec<u8>,
    pub remaining: Duration,
    pub original_ttl: Duration,
    pub stale: bool,
    /// Whether the stored wire already contains an OPT record.
    pub has_edns: bool,
}

impl CacheHit {
    fn from_meta(meta: CacheHitMeta, wire: Vec<u8>) -> Self {
        Self {
            wire,
            remaining: meta.remaining,
            original_ttl: meta.original_ttl,
            stale: meta.stale,
            has_edns: meta.has_edns,
        }
    }
}

#[derive(Clone)]
pub struct MessageCache {
    cache: Cache<(Name, u16, bool), CachedWire>,
    hits: Arc<AtomicU64>,
    misses: Arc<AtomicU64>,
    stale_hits: Arc<AtomicU64>,
    stale_for: Duration,
}

impl MessageCache {
    /// Build a cache with a byte budget.
    pub fn new(max_bytes: u64) -> Self {
        Self::with_stale_window(max_bytes, Duration::ZERO)
    }

    /// Build a cache with a byte budget that keeps expired entries for
    /// `stale_for` so they can be served while a refresh is in flight (RFC 8767).
    pub fn with_stale_window(max_bytes: u64, stale_for: Duration) -> Self {
        Self {
            // Entries enforce their own expiry. The backend TTL only bounds
            // memory for abandoned entries, so leave room for the stale window.
            cache: Cache::builder()
                .max_capacity(max_bytes)
                .weigher(|_, entry| entry_weight(entry))
                .time_to_live(Duration::from_secs(7 * 24 * 3600))
                .build(),
            hits: Arc::new(AtomicU64::new(0)),
            misses: Arc::new(AtomicU64::new(0)),
            stale_hits: Arc::new(AtomicU64::new(0)),
            stale_for,
        }
    }

    /// Build the cache key for one query.
    ///
    /// `Name` hashes and compares case-insensitively, so this matches the
    /// lowercased string keys without formatting or allocating the name.
    fn key(name: &Name, record_type: RecordType, do_bit: bool) -> (Name, u16, bool) {
        (name.clone(), u16::from(record_type), do_bit)
    }

    /// Encode `message` and store it under the key for `name`/`record_type`/`do_bit`.
    ///
    /// # Arguments
    ///
    /// * `name` - Query name the entry is stored under
    /// * `record_type` - Query type the entry is stored under
    /// * `do_bit` - Whether the query had the EDNS DO bit set
    /// * `message` - Response to encode and store
    /// * `ttl` - Time until the entry expires
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
        self.insert_encoded(name, record_type, do_bit, Arc::new(wire), ttl);
    }

    /// Store a response that has already been encoded.
    ///
    /// The pre-encoded `wire` is shared with the single-flight broadcast, so
    /// a cache miss encodes the response once instead of once per
    /// destination. The entry's `has_edns` flag is derived from the wire
    /// itself, keeping the cache-hit fast path safe for responses that
    /// already contain an OPT record.
    ///
    /// # Arguments
    ///
    /// * `name` - Query name the entry is stored under
    /// * `record_type` - Query type the entry is stored under
    /// * `do_bit` - Whether the query had the EDNS DO bit set
    /// * `wire` - The encoded response, shared with the callers that answer
    ///   clients from the same bytes
    /// * `ttl` - Time until the entry expires
    pub fn insert_encoded(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        wire: Arc<Vec<u8>>,
        ttl: Duration,
    ) {
        let now = Instant::now();
        let entry = CachedWire {
            has_edns: wire_has_opt(&wire),
            wire,
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
        request: WireRequest,
    ) -> Option<CacheHit> {
        let mut wire = Vec::new();
        let meta = self.get_into(name, record_type, do_bit, request, &mut wire)?;
        Some(CacheHit::from_meta(meta, wire))
    }

    /// Like [`Self::get`], but writes the patched response into `out` instead of
    /// allocating a new buffer. `out` is cleared and reused, preserving its
    /// capacity across calls so steady-state cache hits avoid allocator traffic.
    pub fn get_into(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        request: WireRequest,
        out: &mut Vec<u8>,
    ) -> Option<CacheHitMeta> {
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
        out.clear();
        out.extend_from_slice(&entry.wire);
        if !age_wire(out, elapsed, None) {
            self.cache.invalidate(&key);
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        patch_wire(out, request);

        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(CacheHitMeta {
            remaining: entry.expires_at.saturating_duration_since(now),
            original_ttl: entry.original_ttl,
            stale: false,
            has_edns: entry.has_edns,
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
        request: WireRequest,
        reply_ttl: u32,
    ) -> Option<CacheHit> {
        let mut wire = Vec::new();
        let meta = self.get_stale_into(name, record_type, do_bit, request, reply_ttl, &mut wire)?;
        Some(CacheHit::from_meta(meta, wire))
    }

    /// Like [`Self::get_stale`], but writes the patched response into `out`
    /// instead of allocating a new buffer.
    pub fn get_stale_into(
        &self,
        name: &Name,
        record_type: RecordType,
        do_bit: bool,
        request: WireRequest,
        reply_ttl: u32,
        out: &mut Vec<u8>,
    ) -> Option<CacheHitMeta> {
        let key = Self::key(name, record_type, do_bit);
        let entry = self.cache.get(&key)?;
        let now = Instant::now();
        if now >= entry.stale_until {
            self.cache.invalidate(&key);
            return None;
        }

        out.clear();
        out.extend_from_slice(&entry.wire);
        if !age_wire(out, 0, Some(reply_ttl)) {
            self.cache.invalidate(&key);
            return None;
        }
        patch_wire(out, request);
        self.stale_hits.fetch_add(1, Ordering::Relaxed);
        Some(CacheHitMeta {
            remaining: Duration::ZERO,
            original_ttl: entry.original_ttl,
            stale: true,
            has_edns: entry.has_edns,
        })
    }

    /// Prefetch when less than 10% of the original TTL remains, or three
    /// seconds, whichever is larger (Unbound's prefetch trigger).
    pub fn should_prefetch(hit: &CacheHit) -> bool {
        Self::should_prefetch_meta(&CacheHitMeta {
            remaining: hit.remaining,
            original_ttl: hit.original_ttl,
            stale: hit.stale,
            has_edns: hit.has_edns,
        })
    }

    /// Like [`Self::should_prefetch`], but takes hit metadata directly.
    pub fn should_prefetch_meta(meta: &CacheHitMeta) -> bool {
        if meta.stale {
            return true;
        }
        let threshold = (meta.original_ttl / 10).max(Duration::from_secs(3));
        meta.remaining <= threshold
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
///
/// Used both for cache hits and for client replies built from the canonical
/// miss wire, so both paths set the same ID, QR, RD, RA, CD, and AD bits a
/// full re-encode would produce.
pub fn patch_wire(wire: &mut [u8], request: WireRequest) {
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

/// Verify the wire's single question matches `question` and copy the
/// client's exact label bytes onto it.
///
/// Matching is case-insensitive as DNS requires; a match overwrites the
/// stored label bytes with `question`'s, so the reply echoes the client's
/// casing byte for byte exactly as a re-encode would. The question section
/// is first in the wire, so its name can never use a backward compression
/// pointer and is safe to patch in place.
///
/// # Returns
///
/// `true` when the wire carried exactly this question. `false` when the
/// question count, name, type, or class differ, or the wire is malformed,
/// in which case the caller must fall back to a full decode and re-encode.
pub fn patch_question(wire: &mut [u8], question: &Query) -> bool {
    if wire.len() < 12 {
        return false;
    }
    if u16::from_be_bytes([wire[4], wire[5]]) != 1 {
        return false;
    }
    let mut offset = 12usize;
    for label in question.name.iter() {
        let Some(&length) = wire.get(offset) else {
            return false;
        };
        if usize::from(length) != label.len() {
            return false;
        }
        offset += 1;
        let end = offset + label.len();
        let Some(bytes) = wire.get(offset..end) else {
            return false;
        };
        if !bytes.eq_ignore_ascii_case(label) {
            return false;
        }
        wire[offset..end].copy_from_slice(label);
        offset = end;
    }
    if wire.get(offset) != Some(&0) {
        return false;
    }
    offset += 1;
    let mut expected = [0u8; 4];
    expected[..2].copy_from_slice(&u16::from(question.query_type).to_be_bytes());
    expected[2..].copy_from_slice(&u16::from(question.query_class).to_be_bytes());
    wire.get(offset..offset + 4) == Some(&expected)
}

/// Whether the wire contains an OPT record.
///
/// Callers that answer a client from an already-encoded wire use this to
/// decide whether an OPT record may be appended without producing a second
/// OPT.
pub fn wire_has_opt(wire: &[u8]) -> bool {
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
    for count in [ancount, nscount] {
        for _ in 0..count {
            let Some(next) = skip_name(wire, offset) else {
                return false;
            };
            offset = next;
            let Some(rdlength) = rdlength_at(wire, offset) else {
                return false;
            };
            offset = offset
                .checked_add(10 + usize::from(rdlength))
                .unwrap_or(wire.len());
            if offset > wire.len() {
                return false;
            }
        }
    }
    for _ in 0..arcount {
        let Some(next) = skip_name(wire, offset) else {
            return false;
        };
        offset = next;
        let Some(rdlength) = rdlength_at(wire, offset) else {
            return false;
        };
        if wire.get(offset..offset + 2) == Some(&41u16.to_be_bytes()) {
            return true;
        }
        offset = offset
            .checked_add(10 + usize::from(rdlength))
            .unwrap_or(wire.len());
        if offset > wire.len() {
            return false;
        }
    }
    false
}

/// Read the RDLENGTH of the record at `offset`, or `None` when truncated.
fn rdlength_at(wire: &[u8], offset: usize) -> Option<u16> {
    if offset + 10 > wire.len() {
        return None;
    }
    Some(u16::from_be_bytes([wire[offset + 8], wire[offset + 9]]))
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
/// result is clamped to the configured cache TTL bounds; negative responses
/// are additionally capped by `max_negative_ttl`.
pub fn response_ttl(
    message: &Message,
    min_ttl: u32,
    max_ttl: u32,
    max_negative_ttl: u32,
) -> Duration {
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
        // `cache-min-ttl` is a floor, so it wins over a smaller negative cap.
        let cap = max_negative_ttl.max(min_ttl);
        ttl = ttl.map(|current| current.min(cap));
    }

    let seconds = ttl.unwrap_or(min_ttl).clamp(min_ttl, max_ttl.max(min_ttl));
    Duration::from_secs(u64::from(seconds))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use dns_proto::{Message, MessageType, Name, OpCode, RData, Record, RecordType, SOA, encode};

    use super::{
        CachedWire, MessageCache, WireRequest, entry_weight, patch_question, response_ttl,
        wire_has_opt,
    };

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

    fn request() -> WireRequest {
        WireRequest {
            id: 0x1234,
            recursion_desired: true,
            checking_disabled: false,
        }
    }

    #[test]
    fn entry_weight_tracks_wire_size() {
        let now = Instant::now();
        let make = |len| CachedWire {
            wire: Arc::new(vec![0; len]),
            inserted_at: now,
            expires_at: now,
            stale_until: now,
            original_ttl: Duration::ZERO,
            has_edns: false,
        };
        assert_eq!(entry_weight(&make(4096)) - entry_weight(&make(32)), 4064);
    }

    #[test]
    fn ages_ttls_on_read() {
        let cache = MessageCache::new(64 * 1024);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );

        let hit = cache
            .get(&name, RecordType::A, false, request())
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
        let cache = MessageCache::new(64 * 1024);
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
        let cache = MessageCache::new(64 * 1024);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );
        assert!(cache.get(&name, RecordType::A, true, request()).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn clamps_ttl() {
        assert_eq!(
            response_ttl(&answer(1), 30, 120, 120),
            Duration::from_secs(30)
        );
        assert_eq!(
            response_ttl(&answer(999), 0, 120, 120),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn caps_negative_ttl() {
        let name = Name::from_ascii("example.com.").expect("name");
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_query(dns_proto::Query::query(name.clone(), RecordType::A));
        message.add_authority(Record::from_rdata(
            name.clone(),
            7_200,
            RData::SOA(SOA::new(name.clone(), name, 1, 3_600, 600, 86_400, 7_200)),
        ));

        assert_eq!(
            response_ttl(&message, 0, 86_400, 3_600),
            Duration::from_secs(3_600)
        );
        assert_eq!(
            response_ttl(&message, 0, 86_400, 60),
            Duration::from_secs(60)
        );
        // cache-min-ttl is a floor even when the negative cap is smaller.
        assert_eq!(
            response_ttl(&message, 300, 86_400, 60),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn expires_entries() {
        let cache = MessageCache::new(64 * 1024);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(&name, RecordType::A, false, &answer(60), Duration::ZERO);
        assert!(cache.get(&name, RecordType::A, false, request()).is_none());
    }

    #[test]
    fn serves_expired_entries_with_a_short_ttl() {
        let cache = MessageCache::with_stale_window(64 * 1024, Duration::from_secs(30));
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(&name, RecordType::A, false, &answer(60), Duration::ZERO);

        let hit = cache
            .get_stale(&name, RecordType::A, false, request(), 30)
            .expect("stale hit");
        assert!(hit.stale);
        let message = Message::from_vec(&hit.wire).expect("decode");
        assert_eq!(message.answers[0].ttl, 30);
        assert_eq!(cache.stats().stale_hits, 1);
    }

    #[test]
    fn prefetches_near_the_end_of_the_ttl() {
        let cache = MessageCache::new(64 * 1024);
        let name = Name::from_ascii("example.com.").expect("name");
        cache.insert(
            &name,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );
        let hit = cache
            .get(&name, RecordType::A, false, request())
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

    #[test]
    fn lookups_match_names_case_insensitively() {
        let cache = MessageCache::new(64 * 1024);
        let mixed = Name::from_ascii("ExAmPlE.CoM.").expect("name");
        cache.insert(
            &mixed,
            RecordType::A,
            false,
            &answer(60),
            Duration::from_secs(60),
        );

        let lowercase = Name::from_ascii("example.com.").expect("name");
        assert!(
            cache
                .get(&lowercase, RecordType::A, false, request())
                .is_some()
        );
    }

    #[test]
    fn insert_encoded_stores_the_shared_wire() {
        let cache = MessageCache::new(64 * 1024);
        let name = Name::from_ascii("example.com.").expect("name");
        let mut message = answer(60);
        message.edns = Some(dns_proto::Edns::new());
        let wire = Arc::new(encode(&message).expect("encode"));

        cache.insert_encoded(
            &name,
            RecordType::A,
            false,
            Arc::clone(&wire),
            Duration::from_secs(60),
        );

        let hit = cache
            .get(&name, RecordType::A, false, request())
            .expect("hit");
        let mut expected = (*wire).clone();
        super::patch_wire(&mut expected, request());
        assert_eq!(
            hit.wire, expected,
            "the stored bytes must be the shared wire"
        );
        assert!(hit.has_edns, "the OPT flag must be derived from the wire");
    }

    #[test]
    fn patch_question_copies_the_client_casing() {
        let mut stored = Message::new(1, MessageType::Response, OpCode::Query);
        stored.add_query(dns_proto::Query::query(
            Name::from_ascii("ExAmPlE.CoM.").expect("name"),
            RecordType::A,
        ));
        let mut wire = encode(&stored).expect("encode");

        let question = dns_proto::Query::query(
            Name::from_ascii("example.com.").expect("name"),
            RecordType::A,
        );
        assert!(patch_question(&mut wire, &question));
        let decoded = Message::from_vec(&wire).expect("decode");
        assert_eq!(decoded.queries[0].name.to_ascii(), "example.com.");
    }

    #[test]
    fn patch_question_rejects_mismatched_questions() {
        let mut stored = Message::new(1, MessageType::Response, OpCode::Query);
        stored.add_query(dns_proto::Query::query(
            Name::from_ascii("example.com.").expect("name"),
            RecordType::A,
        ));
        let mut wire = encode(&stored).expect("encode");

        // Same label lengths but a different name must not be patched over.
        let other_name = dns_proto::Query::query(
            Name::from_ascii("example.org.").expect("name"),
            RecordType::A,
        );
        assert!(!patch_question(&mut wire, &other_name));

        let other_type = dns_proto::Query::query(
            Name::from_ascii("example.com.").expect("name"),
            RecordType::AAAA,
        );
        assert!(!patch_question(&mut wire, &other_type));

        let question = dns_proto::Query::query(
            Name::from_ascii("example.com.").expect("name"),
            RecordType::A,
        );
        assert!(!patch_question(&mut wire[..11], &question));
        assert!(!patch_question(&mut [], &question));
    }

    #[test]
    fn wire_has_opt_detects_an_opt_record() {
        let without_opt = encode(&answer(60)).expect("encode");
        assert!(!wire_has_opt(&without_opt));

        let mut with_opt = answer(60);
        with_opt.edns = Some(dns_proto::Edns::new());
        assert!(wire_has_opt(&encode(&with_opt).expect("encode")));

        assert!(!wire_has_opt(&[0u8; 11]));
    }
}
