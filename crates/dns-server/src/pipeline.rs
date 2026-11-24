use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dns_cache::{
    CacheHitMeta, CacheStats, CoalesceStats, DEFAULT_STALE_TTL, InfraCache, MessageCache, QueryKey,
    QueryRegistry, RegistryEntry, RrsetCache, WireRequest, patch_question, patch_wire,
    response_ttl, wire_has_opt,
};
use dns_config::{Config, ForwardTarget};
use dns_control::{TransportCounts, UpstreamStats};
use dns_dnssec::{AutoTrustAnchor, AutoTrustError, TrustStore, root_trust_anchor, unix_now};
use dns_iter::{
    BogusReason, CookieJar, ForwardServer, ForwardTransport, ForwardZone, IteratorConfig,
    IteratorResolver, ResolveError, ResolveOptions, Security, StubZone,
};
use dns_proto::{
    DNSClass, Edns, EdnsOption, Message, MessageType, Name, OpCode, Query, RData, RecordType,
    ResponseCode, SVCB, SvcParamValue, decode, encode,
};
use ipnet::IpNet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::acl::{self, Decision};
use crate::edns;
use crate::local;
use crate::phase::{Phase, PhaseTimer};
use crate::ratelimit::{ClientConcurrency, RateDecision, RateLimiter};

const MESSAGE_CACHE_ENTRIES: u64 = 8_192;
const RRSET_CACHE_ENTRIES: u64 = 16_384;
const MAX_GLOBAL_INFLIGHT: usize = 8_192;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const FOLLOWER_TIMEOUT: Duration = Duration::from_secs(11);
/// Bounds the per-upstream section of a stats response so it fits the control
/// socket's response limit even with a large infrastructure cache.
const MAX_REPORTED_UPSTREAMS: usize = 64;

/// Labels matching [`Transport::index`], used in Prometheus output.
const TRANSPORT_LABELS: [&str; 4] = ["udp", "tcp", "tls", "https"];
/// Labels for the 4-bit wire response codes.
const RCODE_LABELS: [&str; 16] = [
    "noerror", "formerr", "servfail", "nxdomain", "notimp", "refused", "yxdomain", "yxrrset",
    "nxrrset", "notauth", "notzone", "badvers", "badsig", "badkey", "badtime", "badmode",
];

/// Client transport, which controls truncation behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Https,
}

impl Transport {
    fn index(self) -> usize {
        match self {
            Self::Udp => 0,
            Self::Tcp => 1,
            Self::Tls => 2,
            Self::Https => 3,
        }
    }
}

/// A resolved response plus an optional Extended DNS Error.
///
/// Misses carry the canonical encoding shared by the message cache, the
/// single-flight broadcast, and the client reply, so the response is encoded
/// once and patched per client instead of re-encoded at every step.
struct Resolution {
    /// The prepared response. Followers that can answer from `wire` alone
    /// decode it lazily, and only when the wire cannot be patched.
    message: Option<Message>,
    /// The canonical encoding, when one could be produced.
    wire: Option<Arc<Vec<u8>>>,
    /// Whether the canonical wire already carries an OPT record.
    has_opt: bool,
    ede: Option<BogusReason>,
}

/// Outcome of the synchronous front half of a query ([`QueryPipeline::prepare`]).
///
/// The job variant is only a transient ~600-byte stack value on its way out
/// of `prepare`; boxing it would charge every miss an allocation to avoid a
/// handful of copied bytes.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Prepared {
    /// The query is finished: reply bytes, or `None` to stay silent.
    Answer(Option<Vec<u8>>),
    /// Cache miss: drive this job to resolution and a reply.
    Resolve(ResolutionJob),
}

/// One cache-missed query, packaged as a self-contained unit of work.
///
/// Holds everything the upstream leg needs (decoded question, flags, the
/// client, the transport, and the concurrency permit), so the caller decides
/// how to drive it: connection handlers await [`ResolutionJob::run`] inline,
/// while the UDP receive loop spawns it as its own task.
pub(crate) struct ResolutionJob {
    pipeline: QueryPipeline,
    request: Message,
    do_bit: bool,
    checking_disabled: bool,
    client: SocketAddr,
    transport: Transport,
    cancel: CancellationToken,
    started: Instant,
    /// Held for the whole upstream wait, exactly as before the query path was
    /// split: the per-client concurrency limit counts in-flight resolutions.
    _permit: crate::ratelimit::Permit,
}

impl ResolutionJob {
    /// Coalesce with identical in-flight queries, resolve upstream when
    /// needed, and build the client reply.
    pub(crate) async fn run(self) -> Option<Vec<u8>> {
        let Self {
            pipeline,
            request,
            do_bit,
            checking_disabled,
            client,
            transport,
            cancel,
            started,
            _permit,
        } = self;
        let query = &request.queries[0];

        let resolution = match pipeline
            .resolve_coalesced(query, do_bit, checking_disabled, &cancel)
            .await
        {
            Some(resolution) => resolution,
            None => {
                if cancel.is_cancelled() {
                    debug!(%client, qname = %query.name, "client went away; resolution cancelled");
                    return None;
                }
                return pipeline.error(&request, ResponseCode::ServFail, client, transport);
            }
        };

        let finalize = PhaseTimer::start(Phase::Finalize);
        let response = pipeline.client_reply(resolution, &request, client, transport);
        finalize.end();
        debug!(
            %client,
            qname = %query.name,
            qtype = ?query.query_type,
            cache = "miss",
            elapsed_ms = started.elapsed().as_millis(),
            "query answered"
        );
        response
    }
}

/// Point-in-time counts of client queries, replies, and validation outcomes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueryStats {
    /// All queries presented to the pipeline.
    pub queries_total: u64,
    /// Queries grouped by client transport.
    pub by_transport: TransportCounts,
    /// Encoded client replies produced by the pipeline.
    pub responses_total: u64,
    /// Replies by 4-bit wire response code.
    pub by_rcode: [u64; 16],
    /// Replies with the TC bit set.
    pub truncated: u64,
    /// Replies carrying an Extended DNS Error option.
    pub ede: u64,
    /// Replies with the AD bit set.
    pub ad: u64,
    /// Resolutions validated as secure.
    pub dnssec_secure: u64,
    /// Resolutions validated as insecure.
    pub dnssec_insecure: u64,
    /// Resolutions validated as bogus.
    pub dnssec_bogus: u64,
}

/// Lock-free counters incremented on the query path.
///
/// Relaxed ordering is sufficient because no query-path decision reads these
/// values; they are only sampled for reporting.
#[derive(Debug)]
pub(crate) struct QueryCounters {
    queries_total: AtomicU64,
    by_transport: [AtomicU64; 4],
    responses_total: AtomicU64,
    by_rcode: [AtomicU64; 16],
    truncated: AtomicU64,
    ede: AtomicU64,
    ad: AtomicU64,
    dnssec_secure: AtomicU64,
    dnssec_insecure: AtomicU64,
    dnssec_bogus: AtomicU64,
}

impl Default for QueryCounters {
    fn default() -> Self {
        Self {
            queries_total: AtomicU64::new(0),
            by_transport: std::array::from_fn(|_| AtomicU64::new(0)),
            responses_total: AtomicU64::new(0),
            by_rcode: std::array::from_fn(|_| AtomicU64::new(0)),
            truncated: AtomicU64::new(0),
            ede: AtomicU64::new(0),
            ad: AtomicU64::new(0),
            dnssec_secure: AtomicU64::new(0),
            dnssec_insecure: AtomicU64::new(0),
            dnssec_bogus: AtomicU64::new(0),
        }
    }
}

impl QueryCounters {
    /// Count one query arriving on `transport`.
    fn query(&self, transport: Transport) {
        self.queries_total.fetch_add(1, Ordering::Relaxed);
        self.by_transport[transport.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Count one encoded reply from its wire header.
    ///
    /// Reading the header avoids decoding a message on the hot path. `ede` is
    /// supplied by the caller because the option lives in the OPT record.
    fn reply(&self, wire: &[u8], ede: bool) {
        self.responses_total.fetch_add(1, Ordering::Relaxed);
        if wire.len() < 4 {
            return;
        }
        if wire[2] & 0x02 != 0 {
            self.truncated.fetch_add(1, Ordering::Relaxed);
        }
        if wire[3] & 0x20 != 0 {
            self.ad.fetch_add(1, Ordering::Relaxed);
        }
        self.by_rcode[usize::from(wire[3] & 0x0f)].fetch_add(1, Ordering::Relaxed);
        if ede {
            self.ede.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one DNSSEC validation outcome.
    fn dnssec(&self, security: &Security) {
        let counter = match security {
            Security::Secure => &self.dnssec_secure,
            Security::Insecure => &self.dnssec_insecure,
            Security::Bogus(_) => &self.dnssec_bogus,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> QueryStats {
        QueryStats {
            queries_total: self.queries_total.load(Ordering::Relaxed),
            by_transport: TransportCounts {
                udp: self.by_transport[0].load(Ordering::Relaxed),
                tcp: self.by_transport[1].load(Ordering::Relaxed),
                tls: self.by_transport[2].load(Ordering::Relaxed),
                https: self.by_transport[3].load(Ordering::Relaxed),
            },
            responses_total: self.responses_total.load(Ordering::Relaxed),
            by_rcode: self
                .by_rcode
                .each_ref()
                .map(|counter| counter.load(Ordering::Relaxed)),
            truncated: self.truncated.load(Ordering::Relaxed),
            ede: self.ede.load(Ordering::Relaxed),
            ad: self.ad.load(Ordering::Relaxed),
            dnssec_secure: self.dnssec_secure.load(Ordering::Relaxed),
            dnssec_insecure: self.dnssec_insecure.load(Ordering::Relaxed),
            dnssec_bogus: self.dnssec_bogus.load(Ordering::Relaxed),
        }
    }
}

/// A point-in-time snapshot of pipeline counters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Message-cache hit, miss, and stale-hit counters.
    pub cache: CacheStats,
    /// Number of entries currently held in the message cache.
    pub cache_entries: u64,
    /// Background refreshes started by prefetch or serve-expired.
    pub prefetches: u64,
    /// Single-flight coalescing counters (leaders, followers, abandoned).
    pub coalesce: CoalesceStats,
    /// Query, reply, and validation counters.
    pub queries: QueryStats,
    /// Most recently used upstream servers.
    pub upstreams: Vec<UpstreamStats>,
    /// Upstream servers omitted because the report is bounded.
    pub upstreams_omitted: usize,
}

impl PipelineStats {
    /// Render the snapshot in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        use std::fmt::Write;

        let mut output = String::new();
        let _ = writeln!(
            output,
            "# HELP dns_rs_cache_hits_total Message-cache hits.\n\
             # TYPE dns_rs_cache_hits_total counter\n\
             dns_rs_cache_hits_total {}",
            self.cache.hits
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_cache_misses_total Message-cache misses.\n\
             # TYPE dns_rs_cache_misses_total counter\n\
             dns_rs_cache_misses_total {}",
            self.cache.misses
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_cache_stale_hits_total Expired entries served by serve-expired.\n\
             # TYPE dns_rs_cache_stale_hits_total counter\n\
             dns_rs_cache_stale_hits_total {}",
            self.cache.stale_hits
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_cache_entries Current message-cache entries.\n\
             # TYPE dns_rs_cache_entries gauge\n\
             dns_rs_cache_entries {}",
            self.cache_entries
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_prefetches_total Background refreshes started.\n\
             # TYPE dns_rs_prefetches_total counter\n\
             dns_rs_prefetches_total {}",
            self.prefetches
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_coalesce_leaders_total Queries that started an upstream resolution.\n\
             # TYPE dns_rs_coalesce_leaders_total counter\n\
             dns_rs_coalesce_leaders_total {}",
            self.coalesce.leaders
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_coalesce_followers_total Queries that joined an in-flight resolution.\n\
             # TYPE dns_rs_coalesce_followers_total counter\n\
             dns_rs_coalesce_followers_total {}",
            self.coalesce.followers
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_coalesce_abandoned_total Leaders dropped before publishing.\n\
             # TYPE dns_rs_coalesce_abandoned_total counter\n\
             dns_rs_coalesce_abandoned_total {}",
            self.coalesce.abandoned
        );

        let queries = &self.queries;
        let _ = writeln!(
            output,
            "# HELP dns_rs_queries_total Client queries presented to the pipeline.\n\
             # TYPE dns_rs_queries_total counter\n\
             dns_rs_queries_total {}",
            queries.queries_total
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_queries_by_transport_total Client queries by transport.\n\
             # TYPE dns_rs_queries_by_transport_total counter"
        );
        let by_transport = [
            queries.by_transport.udp,
            queries.by_transport.tcp,
            queries.by_transport.tls,
            queries.by_transport.https,
        ];
        for (label, count) in TRANSPORT_LABELS.iter().zip(by_transport) {
            let _ = writeln!(
                output,
                "dns_rs_queries_by_transport_total{{transport=\"{label}\"}} {count}"
            );
        }

        let _ = writeln!(
            output,
            "# HELP dns_rs_responses_total Encoded client replies.\n\
             # TYPE dns_rs_responses_total counter\n\
             dns_rs_responses_total {}",
            queries.responses_total
        );
        let _ = writeln!(
            output,
            "# HELP dns_rs_responses_by_rcode_total Client replies by response code.\n\
             # TYPE dns_rs_responses_by_rcode_total counter"
        );
        for (label, count) in RCODE_LABELS.iter().zip(queries.by_rcode) {
            let _ = writeln!(
                output,
                "dns_rs_responses_by_rcode_total{{rcode=\"{label}\"}} {count}"
            );
        }
        for (name, help, value) in [
            (
                "dns_rs_responses_truncated_total",
                "Replies with the TC bit set.",
                queries.truncated,
            ),
            (
                "dns_rs_responses_ede_total",
                "Replies carrying an Extended DNS Error option.",
                queries.ede,
            ),
            (
                "dns_rs_responses_ad_total",
                "Replies with the AD bit set.",
                queries.ad,
            ),
        ] {
            let _ = writeln!(
                output,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        }

        let _ = writeln!(
            output,
            "# HELP dns_rs_dnssec_validations_total DNSSEC validation outcomes.\n\
             # TYPE dns_rs_dnssec_validations_total counter"
        );
        for (label, count) in [
            ("secure", queries.dnssec_secure),
            ("insecure", queries.dnssec_insecure),
            ("bogus", queries.dnssec_bogus),
        ] {
            let _ = writeln!(
                output,
                "dns_rs_dnssec_validations_total{{result=\"{label}\"}} {count}"
            );
        }

        let _ = writeln!(
            output,
            "# HELP dns_rs_upstream_rtt_seconds Smoothed upstream round-trip time.\n\
             # TYPE dns_rs_upstream_rtt_seconds gauge"
        );
        for upstream in &self.upstreams {
            let _ = writeln!(
                output,
                "dns_rs_upstream_rtt_seconds{{server=\"{}\"}} {:.6}",
                upstream.address,
                upstream.rtt_ms as f64 / 1_000.0
            );
        }
        let _ = writeln!(
            output,
            "# HELP dns_rs_upstream_timeouts_total Consecutive timeouts per upstream.\n\
             # TYPE dns_rs_upstream_timeouts_total counter"
        );
        for upstream in &self.upstreams {
            let _ = writeln!(
                output,
                "dns_rs_upstream_timeouts_total{{server=\"{}\"}} {}",
                upstream.address, upstream.timeouts
            );
        }
        let _ = writeln!(
            output,
            "# HELP dns_rs_upstream_failures_total Consecutive non-timeout failures per upstream.\n\
             # TYPE dns_rs_upstream_failures_total counter"
        );
        for upstream in &self.upstreams {
            let _ = writeln!(
                output,
                "dns_rs_upstream_failures_total{{server=\"{}\"}} {}",
                upstream.address, upstream.failures
            );
        }
        for (name, help) in [
            (
                "dns_rs_upstream_lame",
                "Whether an upstream is marked lame.",
            ),
            (
                "dns_rs_upstream_backed_off",
                "Whether an upstream is inside its retry backoff window.",
            ),
            (
                "dns_rs_upstream_caps_ok",
                "Whether an upstream preserves QNAME case.",
            ),
        ] {
            let _ = writeln!(output, "# HELP {name} {help}\n# TYPE {name} gauge");
        }
        for upstream in &self.upstreams {
            let server = &upstream.address;
            let _ = writeln!(
                output,
                "dns_rs_upstream_lame{{server=\"{server}\"}} {}",
                u8::from(upstream.lame)
            );
            let _ = writeln!(
                output,
                "dns_rs_upstream_backed_off{{server=\"{server}\"}} {}",
                u8::from(upstream.backed_off)
            );
            let _ = writeln!(
                output,
                "dns_rs_upstream_caps_ok{{server=\"{server}\"}} {}",
                u8::from(upstream.caps_ok)
            );
        }
        let _ = writeln!(
            output,
            "# HELP dns_rs_upstreams_omitted Upstream servers not reported.\n\
             # TYPE dns_rs_upstreams_omitted gauge\n\
             dns_rs_upstreams_omitted {}",
            self.upstreams_omitted
        );
        output
    }
}

/// Removes the in-flight marker when a background refresh ends.
struct RefreshGuard {
    inflight: Arc<Mutex<HashSet<QueryKey>>>,
    key: QueryKey,
}

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.inflight
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&self.key);
    }
}

/// DNS rebinding protection (`private-address` / `private-domain`).
///
/// Address records in the configured private ranges are removed from public
/// names before a response is cached or returned. Local and stub-zone data is
/// exempt because it is served by configuration, not learned from the public
/// Internet.
#[derive(Clone, Debug, Default)]
struct PrivateAddressFilter {
    networks: Vec<IpNet>,
    domains: Vec<Name>,
    stub_zones: Vec<Name>,
}

impl PrivateAddressFilter {
    fn from_config(config: &Config) -> Self {
        Self {
            networks: config.server.private_networks(),
            domains: config.server.private_domains(),
            stub_zones: config
                .stub_zones
                .iter()
                .filter_map(|zone| Name::from_ascii(&zone.name).ok())
                .collect(),
        }
    }

    /// Whether `name` is covered by a `private-domain` entry.
    fn is_private_domain(&self, name: &Name) -> bool {
        self.domains.iter().any(|domain| domain.zone_of(name))
    }

    /// Whether `name` belongs to a configured stub zone.
    fn is_stub_zone(&self, name: &Name) -> bool {
        self.stub_zones.iter().any(|zone| zone.zone_of(name))
    }

    fn is_private_address(&self, address: IpAddr) -> bool {
        if self
            .networks
            .iter()
            .any(|network| network.contains(&address))
        {
            return true;
        }
        // Also catch IPv4 addresses carried in an IPv4-mapped IPv6 AAAA.
        if let IpAddr::V6(address) = address
            && let Some(address) = address.to_ipv4_mapped()
        {
            return self
                .networks
                .iter()
                .any(|network| network.contains(&IpAddr::V4(address)));
        }
        false
    }

    /// Whether an address record (A, AAAA, SVCB, or HTTPS) points at a private
    /// address. Unbound drops the whole SVCB/HTTPS record when any hint is
    /// private, because a client may use the hint without a separate lookup.
    fn has_private_address(&self, record: &dns_proto::Record) -> bool {
        match &record.data {
            RData::A(address) => self.is_private_address(IpAddr::V4(address.0)),
            RData::AAAA(address) => self.is_private_address(IpAddr::V6(address.0)),
            RData::SVCB(svcb) => self.svcb_has_private_hint(svcb),
            RData::HTTPS(https) => self.svcb_has_private_hint(&https.0),
            _ => false,
        }
    }

    fn svcb_has_private_hint(&self, svcb: &SVCB) -> bool {
        svcb.svc_params.iter().any(|(_, value)| match value {
            SvcParamValue::Ipv4Hint(hints) => hints
                .0
                .iter()
                .any(|address| self.is_private_address(IpAddr::V4(address.0))),
            SvcParamValue::Ipv6Hint(hints) => hints
                .0
                .iter()
                .any(|address| self.is_private_address(IpAddr::V6(address.0))),
            _ => false,
        })
    }

    /// Remove private addresses from public names.
    ///
    /// Returns true when at least one record was removed. Unbound checks the
    /// owner name of each RRset, removes only the offending records, and keeps
    /// the rest of the response; this mirrors that behaviour. Stub zones are
    /// exempt because their data is configured locally.
    fn apply(&self, message: &mut Message, qname: &Name) -> bool {
        if self.networks.is_empty() || self.is_stub_zone(qname) {
            return false;
        }

        let mut removed = false;
        for section in [
            &mut message.answers,
            &mut message.authorities,
            &mut message.additionals,
        ] {
            section.retain(|record| {
                if self.is_private_domain(&record.name) || self.is_stub_zone(&record.name) {
                    return true;
                }
                if self.has_private_address(record) {
                    debug!(
                        name = %record.name,
                        "removing a private address from a public name"
                    );
                    removed = true;
                    false
                } else {
                    true
                }
            });
        }
        removed
    }
}

#[derive(Clone)]
pub struct QueryPipeline {
    config: Arc<Config>,
    resolver: Option<Arc<IteratorResolver>>,
    messages: Arc<MessageCache>,
    registry: Arc<QueryRegistry>,
    cookies: CookieJar,
    rate_limiter: RateLimiter,
    concurrency: ClientConcurrency,
    counters: Arc<QueryCounters>,
    infra: Arc<InfraCache>,
    prefetch: bool,
    serve_expired: bool,
    stale_reply_ttl: u32,
    prefetch_inflight: Arc<Mutex<HashSet<QueryKey>>>,
    prefetches: Arc<AtomicU64>,
    local: local::LocalPolicy,
    auth_downstream: local::LocalZones,
    auth_upstream: local::LocalZones,
    private: PrivateAddressFilter,
    /// Stops long-lived background work (RFC 5011 maintenance) when the last
    /// handle to this pipeline is dropped, for example after a reload.
    _lifetime: Arc<PipelineLifetime>,
}

/// Cancels a pipeline's background work when its last clone is dropped.
///
/// `QueryPipeline` is cloned per query and per prefetch, so cancellation
/// cannot live in `Drop for QueryPipeline`: dropping a short-lived per-query
/// clone must not stop the maintenance task of the pipeline that is still
/// installed. Every clone shares this guard, and the token fires only when the
/// last clone goes away (for example after a reload swaps in a new pipeline).
struct PipelineLifetime(CancellationToken);

impl Drop for PipelineLifetime {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// A handle to the active query pipeline that can be swapped on reload.
///
/// Listeners and the control service hold this handle instead of an
/// `Arc<QueryPipeline>`. A reload builds a fresh pipeline and stores it
/// atomically; queries already in flight keep the pipeline they started with
/// until they finish, so a reload never interrupts an upstream resolution.
#[derive(Clone)]
pub struct PipelineHandle {
    current: Arc<ArcSwap<QueryPipeline>>,
}

impl PipelineHandle {
    /// Create a handle around a pipeline built from `config`.
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(QueryPipeline::new(config))),
        }
    }

    /// Handle one raw query, cancelling upstream work when `cancel` fires.
    pub async fn handle_with_cancel(
        &self,
        bytes: &[u8],
        client: SocketAddr,
        transport: Transport,
        cancel: CancellationToken,
    ) -> Option<Vec<u8>> {
        // Load the pipeline once and keep it alive across the await. The
        // query must not observe a pipeline that is replaced mid-flight.
        let pipeline = self.current.load_full();
        pipeline
            .handle_with_cancel(bytes, client, transport, cancel)
            .await
    }

    /// Run the synchronous front half of one query.
    pub(crate) fn prepare(
        &self,
        bytes: &[u8],
        client: SocketAddr,
        transport: Transport,
        cancel: CancellationToken,
        reply_pool: &mut Vec<Vec<u8>>,
    ) -> Prepared {
        self.current
            .load()
            .prepare(bytes, client, transport, cancel, reply_pool)
    }

    /// Return a snapshot of the current pipeline's counters.
    pub fn stats(&self) -> PipelineStats {
        self.current.load().stats()
    }

    /// Atomically install a fully built pipeline.
    pub(crate) fn replace(&self, pipeline: QueryPipeline) {
        self.current.store(Arc::new(pipeline));
    }

    /// The configuration consumed by the current pipeline.
    pub(crate) fn config(&self) -> Arc<Config> {
        Arc::clone(&self.current.load().config)
    }
}

impl QueryPipeline {
    pub fn new(config: Arc<Config>) -> Self {
        let stale_for = if config.server.serve_expired {
            let seconds = if config.server.serve_expired_ttl == 0 {
                DEFAULT_STALE_TTL.as_secs()
            } else {
                u64::from(config.server.serve_expired_ttl)
            };
            Duration::from_secs(seconds)
        } else {
            Duration::ZERO
        };
        let messages = Arc::new(MessageCache::with_stale_window(
            MESSAGE_CACHE_ENTRIES,
            stale_for,
        ));
        let rrsets = Arc::new(RrsetCache::new(RRSET_CACHE_ENTRIES));
        let infra = Arc::new(InfraCache::with_options(
            config.server.infra_cache_numhosts as u64,
            Duration::from_secs(u64::from(config.server.infra_host_ttl)),
            Duration::from_millis(u64::from(config.server.infra_cache_min_rtt)),
        ));

        // Addresses that must never be queried. Static upstreams are filtered
        // at startup so a misconfiguration is visible in the log rather than
        // failing every query later; the iterator applies the same list to
        // addresses learned from referrals.
        let do_not_query = config.server.do_not_query_networks();

        let mut forward_zones = config
            .forward_zones
            .iter()
            .filter_map(|zone| {
                let zone_name = match Name::from_ascii(&zone.name) {
                    Ok(name) => name,
                    Err(error) => {
                        warn!(
                            zone = %zone.name,
                            %error,
                            "ignoring forward-zone with an invalid name"
                        );
                        return None;
                    }
                };
                let mut servers = build_servers(
                    &zone.name,
                    &zone.forward_addrs,
                    zone.tls_upstream,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                append_resolved_hosts(
                    "forward-host",
                    &zone.name,
                    &zone.forward_hosts,
                    zone.tls_upstream,
                    &mut servers,
                );
                retain_allowed_families(
                    &zone.name,
                    &mut servers,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                retain_queryable("forward-zone", &zone.name, &mut servers, &do_not_query);
                if servers.is_empty() {
                    warn!(
                        zone = %zone.name,
                        "forward-zone has no usable forward-addr or forward-host; ignoring"
                    );
                    return None;
                }
                Some(ForwardZone {
                    zone: zone_name,
                    servers,
                    forward_first: zone.forward_first,
                    forward_fallback: zone.forward_fallback,
                })
            })
            .collect::<Vec<_>>();

        let local_domains = dns_config::local_domains();
        let gateways = dns_config::default_gateways();
        let local_gateway = gateways
            .iter()
            .find(|address| matches!(address, IpAddr::V4(_)) && config.server.do_ip4)
            .or_else(|| {
                gateways
                    .iter()
                    .find(|address| matches!(address, IpAddr::V6(_)) && config.server.do_ip6)
            })
            .copied();
        if let Some(gateway) = local_gateway {
            let server = ForwardServer::from(SocketAddr::new(gateway, 53));
            forward_zones.extend(local_domains.iter().cloned().map(|zone| ForwardZone {
                zone,
                servers: vec![server.clone()],
                forward_first: false,
                forward_fallback: false,
            }));
            info!(%gateway, "routing local namespaces through the default gateway");
        } else {
            warn!("no default gateway found; local namespaces will be refused");
        }

        if !forward_zones.is_empty() {
            info!(
                zones = forward_zones.len(),
                fallback = forward_zones
                    .iter()
                    .filter(|zone| zone.forward_fallback)
                    .count(),
                "using configured forward zones"
            );
        }

        let stub_zones = config
            .stub_zones
            .iter()
            .filter_map(|zone| {
                let zone_name = match Name::from_ascii(&zone.name) {
                    Ok(name) => name,
                    Err(error) => {
                        warn!(
                            zone = %zone.name,
                            %error,
                            "ignoring stub-zone with an invalid name"
                        );
                        return None;
                    }
                };
                let mut servers = build_servers(
                    &zone.name,
                    &zone.stub_addrs,
                    zone.tls_upstream,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                append_resolved_hosts(
                    "stub-host",
                    &zone.name,
                    &zone.stub_hosts,
                    zone.tls_upstream,
                    &mut servers,
                );
                retain_allowed_families(
                    &zone.name,
                    &mut servers,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                retain_queryable("stub-zone", &zone.name, &mut servers, &do_not_query);
                if servers.is_empty() {
                    warn!(
                        zone = %zone.name,
                        "stub-zone has no usable stub-addr or stub-host; ignoring"
                    );
                    return None;
                }
                Some(StubZone {
                    zone: zone_name,
                    servers,
                    stub_first: zone.stub_first,
                    prime: zone.stub_prime,
                    no_cache: zone.stub_no_cache,
                })
            })
            .collect::<Vec<_>>();

        if !stub_zones.is_empty() {
            info!(zones = stub_zones.len(), "using configured stub zones");
        }

        let mut anchor_files = Vec::new();
        if let Some(path) = &config.server.trust_anchor_file {
            anchor_files.push(path.clone());
        }
        let trust_store = TrustStore::from_config(&config.server.trust_anchor, &anchor_files)
            .unwrap_or_else(|error| {
                warn!(%error, "failed to load trust anchors; using the built-in root anchor");
                TrustStore::builtin()
            });

        // RFC 5011 maintenance. The auto file is authoritative for its zone,
        // so its valid keys replace the built-in root anchor rather than
        // extending it.
        let auto_anchor = config.server.auto_trust_anchor_file.as_ref().map(|path| {
            let tracker = load_or_bootstrap_auto_anchor(path);
            if tracker.has_valid_key() {
                trust_store.replace(tracker.trust_anchor());
            }
            (tracker, path.clone())
        });

        // `root-hints` seeds priming with the operator's file instead of the
        // built-in list. A broken file must not stop the daemon, so it is
        // reported and the built-in hints stay in place.
        let bootstrap_servers = if config.server.root_hints.is_empty() {
            None
        } else {
            match dns_config::load_root_hints(&config.server.root_hints) {
                Ok(servers) => Some(servers),
                Err(error) => {
                    warn!(%error, "failed to load root-hints; using built-in root hints");
                    None
                }
            }
        };

        let mut insecure_domains = config.server.insecure_domains();
        insecure_domains.extend(local_domains);
        insecure_domains.sort_unstable();
        insecure_domains.dedup();

        let iterator_config = IteratorConfig {
            case_randomization: config.server.use_caps_for_id,
            qname_minimization: config.server.qname_minimisation,
            qname_minimization_strict: config.server.qname_minimisation_strict,
            harden_glue: config.server.harden_glue,
            cookies: true,
            edns_payload: config.server.edns_buffer_size,
            min_ttl: config.server.min_ttl,
            max_ttl: config.server.max_ttl,
            forward_zones,
            stub_zones,
            allow_ipv4: config.server.do_ip4,
            allow_ipv6: config.server.do_ip6,
            do_not_query,
            bootstrap_servers,
            dnssec_validation: config.server.dnssec_validation,
            trust_store: trust_store.clone(),
            domain_insecure: insecure_domains,
            harden_dnssec_stripped: config.server.harden_dnssec_stripped,
            nsec3_max_iterations: config.server.nsec3_max_iterations,
            val_permissive_mode: config.server.val_permissive_mode,
            val_clean_additional: config.server.val_clean_additional,
            tls_cert_bundle: config.server.tls_cert_bundle.clone(),
            tls_use_system_ca: config.server.tls_use_system_ca,
            ..IteratorConfig::default()
        };
        let cookies = CookieJar::new(&iterator_config.cookie_secret);

        let bind_addr = config
            .server
            .outgoing_interfaces
            .first()
            .map(|address| SocketAddr::new(*address, 0));
        let resolver = IteratorResolver::with_config(iterator_config, bind_addr)
            .map(|resolver| Arc::new(resolver.with_caches(Arc::clone(&rrsets), Arc::clone(&infra))))
            .map_err(|error| warn!(%error, "failed to create iterative resolver"))
            .ok();

        let lifetime = Arc::new(PipelineLifetime(CancellationToken::new()));
        if let (Some((tracker, path)), Some(resolver)) = (auto_anchor, resolver.clone())
            && config.server.dnssec_validation
        {
            spawn_autotrust(
                resolver,
                trust_store.clone(),
                tracker,
                path,
                lifetime.0.clone(),
            );
        }

        let local_policy = local::LocalPolicy::from_config(&config);
        let auth_downstream = local::auth_zones(&config.auth_zones, true);
        let auth_upstream = local::auth_zones(&config.auth_zones, false);
        let private = PrivateAddressFilter::from_config(&config);

        Self {
            rate_limiter: RateLimiter::new(config.server.ratelimit, config.server.ratelimit_slip),
            concurrency: ClientConcurrency::new(
                config.server.max_concurrent_queries_per_client,
                MAX_GLOBAL_INFLIGHT,
            ),
            counters: Arc::new(QueryCounters::default()),
            infra,
            prefetch: config.server.prefetch,
            serve_expired: config.server.serve_expired,
            stale_reply_ttl: config.server.serve_expired_reply_ttl,
            config,
            resolver,
            messages,
            registry: Arc::new(QueryRegistry::new()),
            cookies,
            prefetch_inflight: Arc::new(Mutex::new(HashSet::new())),
            prefetches: Arc::new(AtomicU64::new(0)),
            local: local_policy,
            auth_downstream,
            auth_upstream,
            private,
            _lifetime: lifetime,
        }
    }

    /// Return a snapshot of cache, query, and upstream counters.
    pub fn stats(&self) -> PipelineStats {
        let (upstreams, upstreams_omitted) = self.infra.snapshot(MAX_REPORTED_UPSTREAMS);
        PipelineStats {
            cache: self.messages.stats(),
            cache_entries: self.messages.entry_count(),
            prefetches: self.prefetches.load(Ordering::Relaxed),
            coalesce: self.registry.stats(),
            queries: self.counters.snapshot(),
            upstreams: upstreams
                .into_iter()
                .map(|entry| UpstreamStats {
                    address: entry.address.to_string(),
                    rtt_ms: u64::try_from(entry.rtt.as_millis()).unwrap_or(u64::MAX),
                    timeouts: u64::from(entry.timeouts),
                    failures: u64::from(entry.failures),
                    lame: entry.lame,
                    backed_off: entry.backed_off,
                    caps_ok: entry.caps_ok,
                })
                .collect(),
            upstreams_omitted,
        }
    }

    /// Handle one raw query and return an encoded response, if any.
    pub async fn handle(
        &self,
        bytes: &[u8],
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        self.handle_with_cancel(bytes, client, transport, CancellationToken::new())
            .await
    }

    /// Handle one raw query, cancelling upstream work when `cancel` fires.
    ///
    /// Connection-oriented transports use this to stop a resolution tree when
    /// the client goes away. A cancelled leader releases its followers, which
    /// then retry as a fresh leader or return SERVFAIL.
    pub async fn handle_with_cancel(
        &self,
        bytes: &[u8],
        client: SocketAddr,
        transport: Transport,
        cancel: CancellationToken,
    ) -> Option<Vec<u8>> {
        let mut reply_pool = Vec::new();
        match self.prepare(bytes, client, transport, cancel, &mut reply_pool) {
            Prepared::Answer(reply) => reply,
            Prepared::Resolve(job) => job.run().await,
        }
    }

    /// Run the synchronous front half of one query: decode, admission checks,
    /// local-zone answers, and the cache probe.
    ///
    /// Nothing before the upstream leg yields, so a cache hit completes inside
    /// this call and the UDP receive loop can answer it inline instead of
    /// paying a task spawn and a scheduling wait per datagram. A miss comes
    /// back as [`Prepared::Resolve`]: connection handlers await
    /// [`ResolutionJob::run`] directly (the previous behavior), while the UDP
    /// receive loop spawns it as its own task.
    ///
    /// `cancel` is carried into the job; as before, it is only observed while
    /// waiting on the upstream leg.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Raw query datagram or TCP frame
    /// * `client` - Address of the querying client
    /// * `transport` - Transport the query arrived on
    /// * `cancel` - Cancellation token observed by the upstream leg
    ///
    /// # Returns
    ///
    /// [`Prepared::Answer`] with the reply bytes (`None` means stay silent),
    /// or [`Prepared::Resolve`] when the query needs recursive resolution
    pub(crate) fn prepare(
        &self,
        bytes: &[u8],
        client: SocketAddr,
        transport: Transport,
        cancel: CancellationToken,
        reply_pool: &mut Vec<Vec<u8>>,
    ) -> Prepared {
        let started = Instant::now();
        self.counters.query(transport);
        let decode_timer = PhaseTimer::start(Phase::Decode);
        let mut request = match decode(bytes) {
            Ok(message) => message,
            Err(error) => {
                debug!(%client, %error, "dropping malformed query");
                return Prepared::Answer(None);
            }
        };

        if request.metadata.message_type != MessageType::Query {
            return Prepared::Answer(None);
        }

        if request.metadata.op_code != OpCode::Query {
            return Prepared::Answer(self.error(&request, ResponseCode::NotImp, client, transport));
        }

        match acl::check(&self.config, &client) {
            Decision::Deny => return Prepared::Answer(None),
            Decision::Refuse | Decision::DenyNonLocal | Decision::RefuseNonLocal => {
                return Prepared::Answer(self.error(
                    &request,
                    ResponseCode::Refused,
                    client,
                    transport,
                ));
            }
            Decision::Allow => {}
            Decision::AllowSetrd => {
                // Unbound's `allow_setrd`: ignore the client's RD bit and
                // answer as if recursion was requested.
                request.metadata.recursion_desired = true;
            }
            Decision::AllowSnoop => {
                // Snoop mode: cache-only access, no recursion sent upstream
                // (Unbound-like: RD=0, serve from message cache if available,
                //  otherwise NXDOMAIN/SERVFAIL without recursive resolution).
                request.metadata.recursion_desired = false;
            }
        }

        if request.queries.len() != 1 {
            return Prepared::Answer(self.error(
                &request,
                ResponseCode::FormErr,
                client,
                transport,
            ));
        }
        let query = &request.queries[0];
        if query.query_class != DNSClass::IN {
            return Prepared::Answer(self.error(&request, ResponseCode::NotImp, client, transport));
        }
        if matches!(query.query_type, RecordType::AXFR | RecordType::IXFR) {
            return Prepared::Answer(self.error(&request, ResponseCode::NotImp, client, transport));
        }
        if edns::version(&request).is_some_and(|version| version != 0) {
            return Prepared::Answer(self.error(
                &request,
                ResponseCode::BADVERS,
                client,
                transport,
            ));
        }

        match self.rate_limiter.check(client.ip()) {
            RateDecision::Allow => {}
            RateDecision::Drop => {
                debug!(%client, qname = %query.name, "rate limited; dropping query");
                return Prepared::Answer(None);
            }
            RateDecision::Slip => {
                debug!(
                    %client,
                    qname = %query.name,
                    limited = self.rate_limiter.limited_count(),
                    "rate limited; slipping truncated response"
                );
                return Prepared::Answer(self.truncated_reply(&request, client, transport));
            }
        }

        let permit = match self.concurrency.try_acquire(client.ip()) {
            Some(permit) => permit,
            None => {
                debug!(%client, "per-client concurrency limit reached; dropping query");
                return Prepared::Answer(None);
            }
        };

        let do_bit = edns::dnssec_ok(&request);
        let checking_disabled = request.metadata.checking_disabled;
        let wire_request = WireRequest {
            id: request.metadata.id,
            recursion_desired: request.metadata.recursion_desired,
            checking_disabled,
        };
        // Local zones are answered before the cache, like Unbound. They are
        // never stored in the message cache because they are policy, not data.
        match self.local.answer(client.ip(), query) {
            local::LocalAction::Answer(message) => {
                return Prepared::Answer(self.finalize(*message, &request, client, transport));
            }
            local::LocalAction::Drop => return Prepared::Answer(None),
            local::LocalAction::NotHandled => {}
        }
        match self.auth_downstream.answer(query) {
            local::LocalAction::Answer(message) => {
                return Prepared::Answer(self.finalize(*message, &request, client, transport));
            }
            local::LocalAction::Drop => return Prepared::Answer(None),
            local::LocalAction::NotHandled => {}
        }

        // A CD client must see the underlying data even if a non-CD query
        // already cached a SERVFAIL for the same name. Cache entries are
        // written after `prepare_response` runs, so every hit is already
        // scrubbed by the rebinding filter.
        decode_timer.end();
        let lookup = PhaseTimer::start(Phase::Lookup);
        if !checking_disabled {
            {
                let mut wire = reply_pool.pop().unwrap_or_else(|| Vec::with_capacity(512));
                if let Some(meta) = self.messages.get_into(
                    &query.name,
                    query.query_type,
                    do_bit,
                    wire_request,
                    &mut wire,
                ) {
                    lookup.end();
                    if self.prefetch && MessageCache::should_prefetch_meta(&meta) {
                        self.spawn_refresh(query, do_bit);
                    }
                    debug!(
                        %client,
                        qname = %query.name,
                        qtype = ?query.query_type,
                        cache = "hit",
                        elapsed_ms = started.elapsed().as_millis(),
                        "query answered"
                    );
                    let finalize = PhaseTimer::start(Phase::Finalize);
                    let reply = self.serve_hit_wire(meta, wire, &request, client, transport);
                    finalize.end();
                    return Prepared::Answer(reply);
                }
                wire.clear();
                reply_pool.push(wire);
            }

            if self.serve_expired {
                let mut wire = reply_pool.pop().unwrap_or_else(|| Vec::with_capacity(512));
                if let Some(meta) = self.messages.get_stale_into(
                    &query.name,
                    query.query_type,
                    do_bit,
                    wire_request,
                    self.stale_reply_ttl,
                    &mut wire,
                ) {
                    lookup.end();
                    // RFC 8767: answer from the expired entry immediately and
                    // refresh it in the background.
                    self.spawn_refresh(query, do_bit);
                    debug!(
                        %client,
                        qname = %query.name,
                        qtype = ?query.query_type,
                        cache = "stale",
                        elapsed_ms = started.elapsed().as_millis(),
                        "query answered"
                    );
                    let finalize = PhaseTimer::start(Phase::Finalize);
                    let reply = self.serve_hit_wire(meta, wire, &request, client, transport);
                    finalize.end();
                    return Prepared::Answer(reply);
                }
                wire.clear();
                reply_pool.push(wire);
            }
        }
        lookup.end();

        // Authority zones configured for upstream use answer recursive
        // lookups from local data after the cache.
        match self.auth_upstream.answer(query) {
            local::LocalAction::Answer(message) => {
                return Prepared::Answer(self.finalize(*message, &request, client, transport));
            }
            local::LocalAction::Drop => return Prepared::Answer(None),
            local::LocalAction::NotHandled => {}
        }

        if !self.local.covers(client.ip(), &query.name)
            && !self.auth_downstream.covers(&query.name)
            && let Some(local) = local::maybe_respond(query)
        {
            return Prepared::Answer(self.finalize(local, &request, client, transport));
        }

        if !request.metadata.recursion_desired {
            return Prepared::Answer(self.error(
                &request,
                ResponseCode::Refused,
                client,
                transport,
            ));
        }

        Prepared::Resolve(ResolutionJob {
            pipeline: self.clone(),
            request,
            do_bit,
            checking_disabled,
            client,
            transport,
            cancel,
            started,
            _permit: permit,
        })
    }

    /// Return a cached wire response, adding EDNS/cookies or truncating only
    /// when the client requires it.
    ///
    /// `wire` is the response buffer (typically filled by [`MessageCache::get_into`])
    /// and may be returned directly or mutated in place so callers can recycle it.
    fn serve_hit_wire(
        &self,
        meta: CacheHitMeta,
        mut wire: Vec<u8>,
        request: &Message,
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let limit = match transport {
            Transport::Udp => usize::from(
                edns::payload_size(request).min(self.config.server.max_udp_size.max(512)),
            ),
            Transport::Tcp | Transport::Tls | Transport::Https => usize::MAX,
        };

        if request.edns.is_none() && wire.len() <= limit {
            self.counters.reply(&wire, false);
            return Some(wire);
        }

        // Common EDNS(0) case: the cached wire has no OPT record, the client
        // sent no cookie, and the response fits. Append our OPT record instead
        // of decoding and re-encoding the whole message.
        if request.edns.is_some()
            && !meta.has_edns
            && edns::requested_cookie(request).is_none()
            && wire
                .len()
                .checked_add(edns::EMPTY_OPT_LEN)
                .is_some_and(|length| length <= limit)
        {
            if edns::append_empty_opt(
                &mut wire,
                self.config.server.max_udp_size.max(512),
                edns::dnssec_ok(request),
            ) {
                self.counters.reply(&wire, false);
                return Some(wire);
            }
            let message = Message::from_vec(&wire).ok()?;
            return self.finalize_with_ede(message, request, client, transport, None);
        }

        let message = Message::from_vec(&wire).ok()?;
        self.finalize_with_ede(message, request, client, transport, None)
    }

    /// Refresh a cache entry in the background, at most once per key.
    ///
    /// The refresh goes through the coalescing registry, so it joins a client
    /// query that is already resolving the same name instead of issuing a
    /// duplicate upstream request.
    fn spawn_refresh(&self, query: &Query, do_bit: bool) {
        let key = Self::coalesce_key(query, do_bit, false);
        {
            let mut inflight = self
                .prefetch_inflight
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if !inflight.insert(key.clone()) {
                return;
            }
        }

        let pipeline = self.clone();
        let query = query.clone();
        let guard = RefreshGuard {
            inflight: Arc::clone(&self.prefetch_inflight),
            key,
        };
        self.prefetches.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            let _guard = guard;
            let _ = pipeline
                .resolve_coalesced(&query, do_bit, false, &CancellationToken::new())
                .await;
        });
    }

    /// Build the single-flight key for one client query.
    ///
    /// The name is cloned directly into the key: `Name` compares
    /// case-insensitively and stores short names inline, so this matches the
    /// old lowercased string keys without formatting or allocating.
    fn coalesce_key(query: &Query, do_bit: bool, checking_disabled: bool) -> QueryKey {
        QueryKey {
            name: query.name.clone(),
            qtype: u16::from(query.query_type),
            qclass: u16::from(DNSClass::IN),
            do_bit,
            checking_disabled,
        }
    }

    async fn resolve_coalesced(
        &self,
        query: &Query,
        do_bit: bool,
        checking_disabled: bool,
        cancel: &CancellationToken,
    ) -> Option<Resolution> {
        let key = Self::coalesce_key(query, do_bit, checking_disabled);

        let coalesce = PhaseTimer::start(Phase::Coalesce);
        match self.registry.wait_or_register(key).await {
            RegistryEntry::Leader(leader) => {
                coalesce.end();
                let upstream = PhaseTimer::start(Phase::Upstream);
                let resolution = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {
                        // Dropping the leader releases followers; they will
                        // either become a new leader or report failure.
                        drop(leader);
                        return None;
                    }
                    result = self.resolve_uncached(query, do_bit, checking_disabled) => result,
                };
                upstream.end();
                match resolution {
                    Ok(resolved) => {
                        let finalize = PhaseTimer::start(Phase::Finalize);
                        let cacheable =
                            !checking_disabled && !matches!(resolved.security, Security::Bogus(_));
                        let security = resolved.security.clone();
                        self.counters.dnssec(&security);
                        let (mut message, ede) =
                            self.prepare_response(resolved, &query.name, checking_disabled);
                        // Answer with the client's exact question bytes:
                        // patching a reply from this wire then matches a full
                        // re-encode byte for byte, including name-compression
                        // decisions, which hickory makes case-sensitively.
                        message.queries = vec![query.clone()];
                        // Encode once: the cache entry, the follower
                        // broadcast, and this client's reply all patch these
                        // bytes instead of each re-encoding the message.
                        let has_opt = message.edns.is_some();
                        let wire = encode(&message).ok().map(Arc::new);
                        if let Some(wire) = &wire {
                            if cacheable {
                                let ttl = response_ttl(
                                    &message,
                                    self.config.server.cache_min_ttl,
                                    self.config.server.cache_max_ttl,
                                    self.config.server.cache_max_negative_ttl,
                                );
                                if ttl > Duration::ZERO {
                                    self.messages.insert_encoded(
                                        &query.name,
                                        query.query_type,
                                        do_bit,
                                        Arc::clone(wire),
                                        ttl,
                                    );
                                }
                            }
                            leader.complete(Arc::clone(wire));
                        }
                        if let Security::Bogus(reason) = &security
                            && (checking_disabled || self.config.server.val_permissive_mode)
                        {
                            debug!(
                                qname = %query.name,
                                ?reason,
                                "returning bogus data because validation is disabled or permissive"
                            );
                        }
                        finalize.end();
                        Some(Resolution {
                            message: Some(message),
                            wire,
                            has_opt,
                            ede,
                        })
                    }
                    Err(error) => {
                        warn!(qname = %query.name, qtype = ?query.query_type, %error, "resolution failed");
                        drop(leader);
                        None
                    }
                }
            }
            RegistryEntry::Follower { mut rx } => {
                let wait =
                    tokio::time::timeout(FOLLOWER_TIMEOUT, rx.wait_for(|value| value.is_some()));
                let result = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return None,
                    result = wait => result,
                };
                coalesce.end();

                match result {
                    Ok(Ok(value)) => {
                        let finalize = PhaseTimer::start(Phase::Finalize);
                        let wire = value.as_ref()?.clone();
                        let has_opt = wire_has_opt(&wire);
                        finalize.end();
                        Some(Resolution {
                            message: None,
                            wire: Some(wire),
                            has_opt,
                            ede: None,
                        })
                    }
                    _ => None,
                }
            }
        }
    }

    /// Apply validation policy and DNS rebinding protection.
    fn prepare_response(
        &self,
        resolved: dns_iter::Resolved,
        qname: &Name,
        checking_disabled: bool,
    ) -> (Message, Option<BogusReason>) {
        let (mut message, ede) = self.apply_security(resolved, checking_disabled);
        if self.private.apply(&mut message, qname) {
            // The answer no longer matches the data that was validated.
            message.metadata.authentic_data = false;
        }
        (message, ede)
    }

    /// Convert a validation result into a client-facing response.
    fn apply_security(
        &self,
        resolved: dns_iter::Resolved,
        checking_disabled: bool,
    ) -> (Message, Option<BogusReason>) {
        let mut message = resolved.message;
        match resolved.security {
            Security::Bogus(reason)
                if !checking_disabled && !self.config.server.val_permissive_mode =>
            {
                let mut failure = Message::new(0, MessageType::Response, OpCode::Query);
                failure.metadata.response_code = ResponseCode::ServFail;
                failure.metadata.recursion_available = true;
                failure.queries = message.queries.clone();
                (failure, Some(reason))
            }
            Security::Bogus(_) => {
                message.metadata.authentic_data = false;
                (message, None)
            }
            Security::Secure => {
                message.metadata.authentic_data = !checking_disabled;
                (message, None)
            }
            Security::Insecure => {
                message.metadata.authentic_data = false;
                (message, None)
            }
        }
    }

    async fn resolve_uncached(
        &self,
        query: &Query,
        do_bit: bool,
        checking_disabled: bool,
    ) -> Result<dns_iter::Resolved, ResolveError> {
        let resolver = self.resolver.as_ref().ok_or(ResolveError::NoNameservers)?;
        let options = ResolveOptions {
            dnssec_ok: do_bit,
            checking_disabled,
        };
        tokio::time::timeout(
            RESOLVE_TIMEOUT,
            resolver.resolve_name_with_options(query.name.clone(), query.query_type, options),
        )
        .await
        .map_err(|_| ResolveError::Timeout)?
    }

    /// Patch a resolved message for one specific client and encode it.
    fn finalize(
        &self,
        message: Message,
        request: &Message,
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let timer = PhaseTimer::start(Phase::Finalize);
        let reply = self.finalize_with_ede(message, request, client, transport, None);
        timer.end();
        reply
    }

    /// Answer a client from a cache-miss resolution.
    ///
    /// When the canonical wire can be patched for this client, the reply is a
    /// clone of those bytes with the header bits, question casing, and an
    /// empty OPT record fixed up; otherwise the response is decoded (only
    /// followers need that) and rebuilt by [`Self::finalize_with_ede`].
    ///
    /// # Arguments
    ///
    /// * `resolution` - The resolved response, its canonical encoding, and
    ///   any Extended DNS Error
    /// * `request` - The client's query, supplying the ID, flags, question,
    ///   and EDNS state to patch in
    /// * `client` - Client socket address, used for cookie answers on the
    ///   full path
    /// * `transport` - Client transport, which decides the size limit
    ///
    /// # Returns
    ///
    /// The encoded reply, or `None` when neither path can encode one
    fn client_reply(
        &self,
        resolution: Resolution,
        request: &Message,
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let Resolution {
            message,
            wire,
            has_opt,
            ede,
        } = resolution;
        let Some(wire) = wire else {
            let message = message?;
            return self.finalize_with_ede(message, request, client, transport, ede);
        };

        // The full path rebuilds EDNS options (cookies, EDE) and extended
        // rcodes from the message: the canonical wire carries no OPT to hold
        // an extended rcode, so replies with either must go through it.
        let patchable = ede.is_none()
            && message
                .as_ref()
                .is_none_or(|message| message.metadata.response_code.high() == 0);
        if patchable
            && let Some(reply) = self.finalize_canonical(&wire, has_opt, request, transport)
        {
            self.counters.reply(&reply, false);
            return Some(reply);
        }

        let message = match message {
            Some(message) => message,
            None => Message::from_vec(&wire).ok()?,
        };
        self.finalize_with_ede(message, request, client, transport, ede)
    }

    /// Build a client reply by patching the canonical miss wire.
    ///
    /// The canonical wire already holds the full answer; only the
    /// client-specific header bits, the question's exact casing, and—when the
    /// client sent EDNS—a fresh empty OPT record differ from what a full
    /// re-encode would produce, so each is fixed up in place. The question
    /// section is first in the wire and can never use a backward compression
    /// pointer, which makes patching its labels safe.
    ///
    /// # Arguments
    ///
    /// * `wire` - The canonical, already-encoded response
    /// * `has_opt` - Whether `wire` already contains an OPT record
    /// * `request` - The client's query to patch in
    /// * `transport` - Client transport, which decides the size limit
    ///
    /// # Returns
    ///
    /// The patched reply, or `None` when the reply needs per-client EDNS
    /// work (a cookie answer), a per-client OPT rebuild, truncation, or the
    /// wire does not carry this question, and the caller must fall back to
    /// [`Self::finalize_with_ede`]
    fn finalize_canonical(
        &self,
        wire: &[u8],
        has_opt: bool,
        request: &Message,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        // An existing OPT holds upstream options the full path would strip
        // and rebuild, and a client cookie needs an answer computed here.
        if has_opt || edns::requested_cookie(request).is_some() {
            return None;
        }
        // Intake guarantees opcode Query, so a canonical wire with any other
        // opcode cannot answer this client without a rebuild.
        if wire.len() < 12 || wire[2] & 0x78 != 0 {
            return None;
        }

        let advertised = self.config.server.max_udp_size.max(512);
        let limit = match transport {
            Transport::Udp => usize::from(edns::payload_size(request).min(advertised)),
            Transport::Tcp | Transport::Tls | Transport::Https => usize::MAX,
        };
        let needs_opt = request.edns.is_some();
        let length = if needs_opt {
            wire.len().checked_add(edns::EMPTY_OPT_LEN)?
        } else {
            wire.len()
        };
        if length > limit {
            // The full path truncates to the client's payload size.
            return None;
        }

        let mut reply = wire.to_vec();
        patch_wire(
            &mut reply,
            WireRequest {
                id: request.metadata.id,
                recursion_desired: request.metadata.recursion_desired,
                checking_disabled: request.metadata.checking_disabled,
            },
        );
        if !patch_question(&mut reply, request.queries.first()?) {
            return None;
        }
        if needs_opt && !edns::append_empty_opt(&mut reply, advertised, edns::dnssec_ok(request)) {
            return None;
        }
        Some(reply)
    }

    fn finalize_with_ede(
        &self,
        mut message: Message,
        request: &Message,
        client: SocketAddr,
        transport: Transport,
        ede: Option<BogusReason>,
    ) -> Option<Vec<u8>> {
        message.metadata.id = request.metadata.id;
        message.metadata.message_type = MessageType::Response;
        message.metadata.op_code = request.metadata.op_code;
        message.metadata.recursion_desired = request.metadata.recursion_desired;
        message.metadata.recursion_available = true;
        message.metadata.checking_disabled = request.metadata.checking_disabled;
        if request.metadata.checking_disabled {
            message.metadata.authentic_data = false;
        }
        message.queries = request.queries.clone();
        message.edns = None;
        // An EDE is only visible to the client when it sent EDNS(0).
        let has_ede = request.edns.is_some() && ede.is_some();

        if request.edns.is_some() {
            let mut response_edns = Edns::new();
            response_edns.set_version(0);
            response_edns.set_max_payload(self.config.server.max_udp_size.max(512));
            response_edns.set_dnssec_ok(edns::dnssec_ok(request));
            if let Some(cookie) = edns::requested_cookie(request)
                && let Some(answer) = self.cookies.answer_cookie(client.ip(), &cookie)
            {
                response_edns
                    .options_mut()
                    .insert(EdnsOption::Unknown(10, answer));
            }
            if let Some(reason) = ede {
                response_edns.options_mut().insert(EdnsOption::Unknown(
                    15,
                    ede_payload(6, &format!("DNSSEC validation failed: {reason:?}")),
                ));
            }
            if message.metadata.response_code == ResponseCode::BADVERS {
                response_edns.set_rcode_high(1);
            }
            message.edns = Some(response_edns);
        }

        let wire = encode(&message).ok()?;
        let reply = match transport {
            Transport::Tcp | Transport::Tls | Transport::Https => Some(wire),
            Transport::Udp => {
                let advertised = self.config.server.max_udp_size.max(512);
                let limit = usize::from(edns::payload_size(request).min(advertised));
                if wire.len() <= limit {
                    Some(wire)
                } else {
                    truncate(message, limit)
                }
            }
        };
        if let Some(reply) = &reply {
            self.counters.reply(reply, has_ede);
        }
        reply
    }

    fn error(
        &self,
        request: &Message,
        code: ResponseCode,
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.response_code = code;
        response.metadata.recursion_available = true;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.queries = request.queries.clone();
        self.finalize(response, request, client, transport)
    }

    fn truncated_reply(
        &self,
        request: &Message,
        client: SocketAddr,
        transport: Transport,
    ) -> Option<Vec<u8>> {
        let mut response = Message::new(
            request.metadata.id,
            MessageType::Response,
            request.metadata.op_code,
        );
        response.metadata.recursion_available = true;
        response.metadata.truncation = true;
        response.queries = request.queries.clone();
        self.finalize(response, request, client, transport)
    }
}

/// Resolve `forward-host`/`stub-host` entries into upstream servers.
///
/// Unbound resolves these names once at startup through the system resolver
/// instead of routing client queries through them. When TLS is enabled the
/// host name doubles as the certificate name, as it does for `forward-addr`
/// targets with an `#auth-name`.
fn append_resolved_hosts(
    kind: &str,
    zone: &str,
    hosts: &[String],
    tls_upstream: bool,
    servers: &mut Vec<ForwardServer>,
) {
    let port = if tls_upstream { 853 } else { 53 };
    for host in hosts {
        match resolve_forward_host(host, port) {
            Ok(addresses) => {
                for addr in addresses {
                    servers.push(ForwardServer {
                        addr,
                        transport: if tls_upstream {
                            ForwardTransport::Tls
                        } else {
                            ForwardTransport::Plain
                        },
                        tls_name: tls_upstream.then(|| host.trim_end_matches('.').to_owned()),
                        path: None,
                    });
                }
            }
            Err(error) => warn!(
                %zone,
                %host,
                %error,
                "failed to resolve {kind}; skipping"
            ),
        }
    }
}

/// Drop upstream servers that fall inside the do-not-query list.
///
/// Without this, a single `forward-addr` or referral pointing at loopback
/// would be queried even though `do-not-query-localhost` is on, which is both
/// surprising and a local-service probe vector.
fn retain_queryable(kind: &str, zone: &str, servers: &mut Vec<ForwardServer>, blocked: &[IpNet]) {
    if blocked.is_empty() {
        return;
    }
    servers.retain(|server| {
        let is_blocked = blocked
            .iter()
            .any(|network| network.contains(&server.addr.ip()));
        if is_blocked {
            warn!(
                %zone,
                addr = %server.addr,
                "ignoring {kind} address blocked by do-not-query-address/do-not-query-localhost"
            );
        }
        !is_blocked
    });
}

/// Convert configured targets into concrete upstream servers.
///
/// Addresses whose family is disabled by `do-ip4`/`do-ip6` are dropped: the
/// transport setting applies to outgoing queries, not only to listeners.
fn build_servers(
    zone: &str,
    targets: &[ForwardTarget],
    tls_upstream: bool,
    allow_ipv4: bool,
    allow_ipv6: bool,
) -> Vec<ForwardServer> {
    let mut servers = Vec::new();
    for target in targets {
        if let Some(path) = &target.https_path {
            let Some(host) = &target.host else {
                warn!(%zone, "HTTPS target is missing a hostname; skipping");
                continue;
            };
            match resolve_forward_host(host, target.port) {
                Ok(addresses) => {
                    for addr in addresses {
                        servers.push(ForwardServer {
                            addr,
                            transport: ForwardTransport::Https,
                            tls_name: Some(host.clone()),
                            path: Some(path.clone()),
                        });
                    }
                }
                Err(error) => warn!(
                    %zone,
                    %host,
                    %error,
                    "failed to resolve HTTPS target; skipping"
                ),
            }
            continue;
        }
        let Some(addr) = target.addr else {
            continue;
        };
        let transport = if tls_upstream {
            ForwardTransport::Tls
        } else {
            ForwardTransport::Plain
        };
        let tls_name = target.tls_name.clone();
        if transport == ForwardTransport::Tls && tls_name.is_none() {
            warn!(
                %zone,
                %addr,
                "TLS upstream without #auth-name; accepting any certificate that chains to a trusted CA"
            );
        }
        servers.push(ForwardServer {
            addr,
            transport,
            tls_name,
            path: None,
        });
    }

    retain_allowed_families(zone, &mut servers, allow_ipv4, allow_ipv6);
    servers
}

/// Drop upstream servers whose address family is disabled by `do-ip4`/`do-ip6`.
///
/// The transport setting applies to outgoing queries, not only to listeners, so
/// a disabled family must not be attempted.
fn retain_allowed_families(
    zone: &str,
    servers: &mut Vec<ForwardServer>,
    allow_ipv4: bool,
    allow_ipv6: bool,
) {
    let dropped_v4 = servers
        .iter()
        .filter(|server| server.addr.is_ipv4() && !allow_ipv4)
        .count();
    let dropped_v6 = servers
        .iter()
        .filter(|server| server.addr.is_ipv6() && !allow_ipv6)
        .count();
    if dropped_v4 > 0 {
        warn!(
            %zone,
            count = dropped_v4,
            "ignoring IPv4 upstream addresses because do-ip4 is off"
        );
    }
    if dropped_v6 > 0 {
        warn!(
            %zone,
            count = dropped_v6,
            "ignoring IPv6 upstream addresses because do-ip6 is off"
        );
    }
    servers.retain(|server| match server.addr {
        SocketAddr::V4(_) => allow_ipv4,
        SocketAddr::V6(_) => allow_ipv6,
    });
}

fn resolve_forward_host(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    let mut addresses: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    addresses.sort_by_key(SocketAddr::is_ipv6);
    addresses.dedup();
    Ok(addresses)
}

/// Load an RFC 5011 tracker, falling back to the built-in root anchor.
fn load_or_bootstrap_auto_anchor(path: &Path) -> AutoTrustAnchor {
    match AutoTrustAnchor::load(path) {
        // Keep pending keys even if no key is valid yet; the probe task will
        // finish their hold-down once the zone can be authenticated.
        Ok(tracker) if !tracker.keys.is_empty() => tracker,
        Ok(_) => bootstrap_auto_anchor(path),
        Err(AutoTrustError::Io { .. }) => bootstrap_auto_anchor(path),
        Err(error) => {
            warn!(
                %error,
                path = %path.display(),
                "failed to parse auto-trust-anchor-file; using the built-in root anchor"
            );
            bootstrap_auto_anchor(path)
        }
    }
}

/// Seed an auto-trust-anchor file with the built-in root keys.
fn bootstrap_auto_anchor(path: &Path) -> AutoTrustAnchor {
    let now = unix_now();
    let tracker = AutoTrustAnchor::from_trust_anchor(root_trust_anchor(), now);
    if let Err(error) = tracker.save(path) {
        warn!(
            %error,
            path = %path.display(),
            "failed to write auto-trust-anchor-file"
        );
    }
    tracker
}

/// Probe and update an RFC 5011 trust anchor in the background.
fn spawn_autotrust(
    resolver: Arc<IteratorResolver>,
    store: TrustStore,
    mut tracker: AutoTrustAnchor,
    path: PathBuf,
    cancel: CancellationToken,
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = ticker.tick() => {}
            }
            let now = unix_now();
            if !tracker.is_due(now) {
                continue;
            }
            let probed = tokio::select! {
                _ = cancel.cancelled() => break,
                result = resolver.probe_dnskey(&tracker.zone) => result,
            };
            match probed {
                Ok(probed) => {
                    tracker.update_with_revocations(&probed.keys, &probed.revoked, now);
                    tracker.record_success(now);
                    store.replace(tracker.trust_anchor());
                    if let Err(error) = tracker.save(&path) {
                        warn!(
                            %error,
                            path = %path.display(),
                            "failed to save auto-trust-anchor-file"
                        );
                    }
                    info!(
                        zone = %tracker.zone,
                        keys = tracker.trusted_keys().len(),
                        "RFC 5011 trust anchors updated"
                    );
                }
                Err(error) => {
                    tracker.record_failure(now);
                    warn!(zone = %tracker.zone, %error, "RFC 5011 DNSKEY probe failed");
                }
            }
        }
    });
}

/// Encode an Extended DNS Error option (RFC 8914).
fn ede_payload(info_code: u16, text: &str) -> Vec<u8> {
    let mut payload = info_code.to_be_bytes().to_vec();
    payload.extend_from_slice(text.as_bytes());
    payload
}

/// Shrink a response until it fits the client's UDP payload.
///
/// The TC bit is always set; records are dropped in order of increasing
/// importance (additional, authority, answer, OPT) so clients retry over TCP.
///
/// Returns `None` when even a question-only message cannot be encoded, so the
/// caller drops the query instead of sending a zero-length datagram.
fn truncate(mut message: Message, limit: usize) -> Option<Vec<u8>> {
    message.metadata.truncation = true;
    loop {
        if let Ok(wire) = encode(&message)
            && wire.len() <= limit
        {
            return Some(wire);
        }

        if !message.additionals.is_empty() {
            message.additionals.clear();
            continue;
        }
        if !message.authorities.is_empty() {
            message.authorities.clear();
            continue;
        }
        if !message.answers.is_empty() {
            message.answers.clear();
            continue;
        }
        if message.edns.is_some() {
            message.edns = None;
            continue;
        }
        if !message.queries.is_empty() {
            message.queries.clear();
            continue;
        }
        return encode(&message).ok();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use dns_config::{Config, ServerConfig};
    use dns_control::UpstreamStats;
    use dns_dnssec::{BogusReason, Security};
    use dns_proto::{
        CNAME, Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType,
        ResponseCode,
    };
    use dns_testutil::query_bytes;

    use super::{PipelineStats, QueryCounters, QueryPipeline, Resolution, Transport};

    fn pipeline() -> QueryPipeline {
        QueryPipeline::new(Arc::new(Config::default()))
    }

    fn client() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
    }

    #[test]
    fn per_query_clones_do_not_cancel_the_pipeline_lifetime() {
        let pipeline = pipeline();
        let lifetime = pipeline._lifetime.0.clone();

        // The query path clones the pipeline for every cache miss. Dropping
        // such a clone must not stop the installed pipeline's maintenance task.
        let per_query = pipeline.clone();
        drop(per_query);
        assert!(!lifetime.is_cancelled());

        // Dropping the last clone (a reload) releases the background work.
        drop(pipeline);
        assert!(lifetime.is_cancelled());
    }

    #[test]
    fn counters_record_transport_rcode_flags_and_validation() {
        let counters = QueryCounters::default();
        counters.query(Transport::Udp);
        counters.query(Transport::Udp);
        counters.query(Transport::Tls);

        let mut wire = [0_u8; 12];
        wire[2] = 0x02;
        wire[3] = 0x23;
        counters.reply(&wire, true);
        counters.dnssec(&Security::Secure);
        counters.dnssec(&Security::Insecure);
        counters.dnssec(&Security::Bogus(BogusReason::Signature));

        let stats = counters.snapshot();
        assert_eq!(stats.queries_total, 3);
        assert_eq!(stats.by_transport.udp, 2);
        assert_eq!(stats.by_transport.tls, 1);
        assert_eq!(stats.responses_total, 1);
        assert_eq!(stats.by_rcode[3], 1);
        assert_eq!(stats.truncated, 1);
        assert_eq!(stats.ad, 1);
        assert_eq!(stats.ede, 1);
        assert_eq!(stats.dnssec_secure, 1);
        assert_eq!(stats.dnssec_insecure, 1);
        assert_eq!(stats.dnssec_bogus, 1);
    }

    #[test]
    fn prometheus_exposes_queries_and_upstreams() {
        let mut stats = PipelineStats::default();
        stats.queries.queries_total = 3;
        stats.queries.by_transport.udp = 2;
        stats.queries.by_rcode[3] = 1;
        stats.upstreams.push(UpstreamStats {
            address: "192.0.2.1:53".to_owned(),
            rtt_ms: 12,
            timeouts: 1,
            failures: 2,
            lame: false,
            backed_off: true,
            caps_ok: true,
        });
        stats.upstreams_omitted = 4;

        let text = stats.render_prometheus();
        assert!(text.contains("dns_rs_queries_total 3"), "{text}");
        assert!(
            text.contains("dns_rs_queries_by_transport_total{transport=\"udp\"} 2"),
            "{text}"
        );
        assert!(
            text.contains("dns_rs_responses_by_rcode_total{rcode=\"nxdomain\"} 1"),
            "{text}"
        );
        assert!(
            text.contains("dns_rs_upstream_rtt_seconds{server=\"192.0.2.1:53\"} 0.012000"),
            "{text}"
        );
        assert!(text.contains("dns_rs_upstream_backed_off{server=\"192.0.2.1:53\"} 1"));
        assert!(text.contains("dns_rs_upstreams_omitted 4"));
    }

    #[tokio::test]
    async fn handling_a_query_updates_the_pipeline_counters() {
        let pipeline = pipeline();
        let bytes = query_bytes("localhost.", RecordType::A);
        let response = pipeline
            .handle(&bytes, client(), Transport::Udp)
            .await
            .expect("response");
        assert!(response.len() >= 4);

        let stats = pipeline.stats();
        assert_eq!(stats.queries.queries_total, 1);
        assert_eq!(stats.queries.by_transport.udp, 1);
        assert_eq!(stats.queries.responses_total, 1);
        assert_eq!(
            stats.queries.by_rcode[usize::from(ResponseCode::NoError.low())],
            1
        );
    }

    #[tokio::test]
    async fn refuses_unknown_client() {
        let bytes = query_bytes("example.com.", RecordType::A);
        let response = pipeline()
            .handle(
                &bytes,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234),
                Transport::Udp,
            )
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn answers_localhost() {
        let bytes = query_bytes("localhost.", RecordType::A);
        let response = pipeline()
            .handle(&bytes, client(), Transport::Udp)
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(!message.answers.is_empty());
    }

    #[tokio::test]
    async fn echoes_edns_and_cookie() {
        let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            dns_proto::Name::from_ascii("localhost.").expect("name"),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(1400);
        edns.options_mut()
            .insert(dns_proto::EdnsOption::Unknown(10, vec![9u8; 8]));
        query.edns = Some(edns);
        let wire = query.to_vec().expect("encode");

        let response = pipeline()
            .handle(&wire, client(), Transport::Udp)
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        let response_edns = message.edns.as_ref().expect("OPT in response");
        assert_eq!(response_edns.max_payload(), 1232);
        assert!(response_edns.option(dns_proto::EDNS_COOKIE).is_some());
    }

    #[tokio::test]
    async fn cached_edns_response_uses_the_fast_path() {
        let pipeline = pipeline();
        let name = Name::from_ascii("cached.example.").expect("name");
        let mut cached = Message::new(0, MessageType::Response, OpCode::Query);
        cached.add_query(Query::query(name.clone(), RecordType::A));
        cached.add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        pipeline.messages.insert(
            &name,
            RecordType::A,
            false,
            &cached,
            Duration::from_secs(60),
        );

        let mut request = Message::new(0x4242, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, RecordType::A));
        let mut edns = Edns::new();
        edns.set_max_payload(1400);
        request.edns = Some(edns);

        let response = pipeline
            .handle(&request.to_vec().expect("encode"), client(), Transport::Udp)
            .await
            .expect("response");
        assert_eq!(&response[0..2], &0x4242u16.to_be_bytes());

        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.metadata.id, 0x4242);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.metadata.recursion_desired);
        assert!(message.metadata.recursion_available);
        assert_eq!(message.answers.len(), 1);
        let edns = message.edns.as_ref().expect("OPT in response");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
        assert!(!edns.flags().dnssec_ok);
        assert!(edns.option(dns_proto::EDNS_COOKIE).is_none());
    }

    #[tokio::test]
    async fn cached_edns_response_with_do_sets_the_do_bit() {
        let pipeline = pipeline();
        let name = Name::from_ascii("signed.example.").expect("name");
        let mut cached = Message::new(0, MessageType::Response, OpCode::Query);
        cached.add_query(Query::query(name.clone(), RecordType::A));
        cached.metadata.authentic_data = true;
        pipeline
            .messages
            .insert(&name, RecordType::A, true, &cached, Duration::from_secs(60));

        let mut request = Message::new(0x5151, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, RecordType::A));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        request.edns = Some(edns);

        let response = pipeline
            .handle(&request.to_vec().expect("encode"), client(), Transport::Udp)
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert!(message.metadata.authentic_data);
        assert!(message.edns.as_ref().expect("OPT").flags().dnssec_ok);
    }

    #[tokio::test]
    async fn answers_formerr_without_question() {
        let query = Message::new(7, MessageType::Query, OpCode::Query);
        let wire = query.to_vec().expect("encode");
        let response = pipeline()
            .handle(&wire, client(), Transport::Udp)
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.metadata.response_code, ResponseCode::FormErr);
    }

    fn resolved(security: dns_iter::Security) -> dns_iter::Resolved {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            dns_proto::Name::from_ascii("www.example.com.").expect("name"),
            RecordType::A,
        ));
        dns_iter::Resolved { message, security }
    }

    #[test]
    fn bogus_without_cd_becomes_servfail() {
        let pipeline = pipeline();
        let (message, ede) = pipeline.apply_security(
            resolved(dns_iter::Security::Bogus(dns_iter::BogusReason::Signature)),
            false,
        );
        assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
        assert!(ede.is_some());
    }

    #[test]
    fn bogus_with_cd_is_returned_without_ad() {
        let pipeline = pipeline();
        let (message, ede) = pipeline.apply_security(
            resolved(dns_iter::Security::Bogus(dns_iter::BogusReason::Signature)),
            true,
        );
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(!message.metadata.authentic_data);
        assert!(ede.is_none());
    }

    #[test]
    fn secure_sets_ad_unless_cd() {
        let pipeline = pipeline();
        let (message, _) = pipeline.apply_security(resolved(dns_iter::Security::Secure), false);
        assert!(message.metadata.authentic_data);

        let (message, _) = pipeline.apply_security(resolved(dns_iter::Security::Secure), true);
        assert!(!message.metadata.authentic_data);
    }

    #[test]
    fn servfail_carries_ede_when_edns_was_used() {
        let pipeline = pipeline();
        let mut request = Message::new(7, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            dns_proto::Name::from_ascii("www.example.com.").expect("name"),
            RecordType::A,
        ));
        request.edns = Some(Edns::new());

        let (message, ede) = pipeline.apply_security(
            resolved(dns_iter::Security::Bogus(dns_iter::BogusReason::Signature)),
            false,
        );
        let wire = pipeline
            .finalize_with_ede(message, &request, client(), Transport::Udp, ede)
            .expect("response");
        let response = Message::from_vec(&wire).expect("decode");
        let edns = response.edns.as_ref().expect("OPT");
        let option = edns
            .option(dns_proto::EdnsCode::Unknown(15))
            .expect("EDE option");
        match option {
            dns_proto::EdnsOption::Unknown(code, data) => {
                assert_eq!(*code, 15);
                assert_eq!(&data[..2], &6u16.to_be_bytes());
            }
            other => panic!("unexpected EDE option: {other:?}"),
        }
    }

    #[test]
    fn truncation_sets_tc_and_fits_the_limit() {
        let owner = dns_proto::Name::from_ascii("www.example.com.").expect("name");
        let mut message = Message::new(1, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(owner.clone(), RecordType::A));
        for last_octet in 0..20 {
            message.add_answer(Record::from_rdata(
                owner.clone(),
                300,
                RData::A(Ipv4Addr::new(192, 0, 2, last_octet).into()),
            ));
        }

        let wire = super::truncate(message, 128).expect("truncated response");
        assert!(wire.len() <= 128);

        let truncated = Message::from_vec(&wire).expect("decode truncated response");
        assert!(truncated.metadata.truncation);
        assert!(truncated.answers.is_empty());
        assert_eq!(truncated.queries.len(), 1);
    }

    fn answer(owner: &str, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(owner).expect("name"), 60, data)
    }

    fn resolved_with(answers: Vec<Record>) -> dns_iter::Resolved {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.recursion_available = true;
        for record in answers {
            message.add_answer(record);
        }
        dns_iter::Resolved {
            message,
            security: dns_iter::Security::Secure,
        }
    }

    #[test]
    fn rebinding_filter_removes_private_addresses_from_public_names() {
        let pipeline = pipeline();
        let qname = Name::from_ascii("evil.example.").expect("name");
        let resolved = resolved_with(vec![
            answer(
                "evil.example.",
                RData::A(Ipv4Addr::new(192, 168, 1, 10).into()),
            ),
            answer(
                "evil.example.",
                RData::A(Ipv4Addr::new(203, 0, 113, 5).into()),
            ),
            answer(
                "evil.example.",
                RData::AAAA(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into()),
            ),
        ]);

        let (message, _) = pipeline.prepare_response(resolved, &qname, false);
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].data.to_string(), "203.0.113.5");
        assert!(!message.metadata.authentic_data);
    }

    #[test]
    fn rebinding_filter_keeps_private_addresses_for_private_domains() {
        let config = Config {
            server: ServerConfig {
                private_domain: vec!["home.example".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };
        let pipeline = QueryPipeline::new(Arc::new(config));
        let qname = Name::from_ascii("printer.home.example.").expect("name");
        let resolved = resolved_with(vec![answer(
            "printer.home.example.",
            RData::A(Ipv4Addr::new(192, 168, 1, 20).into()),
        )]);

        let (message, _) = pipeline.prepare_response(resolved, &qname, false);
        assert_eq!(message.answers.len(), 1);
        assert!(message.metadata.authentic_data);
    }

    #[test]
    fn rebinding_filter_checks_the_answer_owner_name() {
        let config = Config {
            server: ServerConfig {
                private_domain: vec!["home.example".to_owned()],
                ..ServerConfig::default()
            },
            ..Config::default()
        };
        let pipeline = QueryPipeline::new(Arc::new(config));
        let qname = Name::from_ascii("www.example.").expect("name");
        let resolved = resolved_with(vec![
            answer(
                "www.example.",
                RData::CNAME(CNAME(
                    Name::from_ascii("printer.home.example.").expect("target"),
                )),
            ),
            answer(
                "printer.home.example.",
                RData::A(Ipv4Addr::new(192, 168, 1, 20).into()),
            ),
        ]);

        let (message, _) = pipeline.prepare_response(resolved, &qname, false);
        assert!(
            message
                .answers
                .iter()
                .any(|record| matches!(&record.data, RData::A(_)))
        );
    }

    #[test]
    fn rebinding_filter_removes_private_https_hints() {
        let pipeline = pipeline();
        let qname = Name::from_ascii("evil.example.").expect("name");
        let records = dns_proto::parse_zone_records(
            "evil.example. 60 IN HTTPS 1 . ipv4hint=192.168.1.10",
            None,
        )
        .expect("parse HTTPS record");
        let (message, _) = pipeline.prepare_response(resolved_with(records), &qname, false);
        assert!(
            message.answers.is_empty(),
            "an HTTPS record with a private hint must be removed"
        );
    }

    #[test]
    fn rebinding_filter_exempts_stub_zone_data() {
        let config = Config {
            stub_zones: vec![dns_config::StubZoneConfig {
                name: "corp.example.".to_owned(),
                stub_addrs: vec!["192.0.2.1".parse().expect("stub address")],
                ..dns_config::StubZoneConfig::default()
            }],
            ..Config::default()
        };
        config.validate().expect("valid stub zone");
        let pipeline = QueryPipeline::new(Arc::new(config));
        let qname = Name::from_ascii("host.corp.example.").expect("name");
        let resolved = resolved_with(vec![answer(
            "host.corp.example.",
            RData::A(Ipv4Addr::new(10, 0, 0, 5).into()),
        )]);

        let (message, _) = pipeline.prepare_response(resolved, &qname, false);
        assert_eq!(message.answers.len(), 1);
    }

    #[tokio::test]
    async fn cached_answers_are_stored_without_private_addresses() {
        let pipeline = pipeline();
        let name = Name::from_ascii("evil.example.").expect("name");
        let resolved = resolved_with(vec![
            answer(
                "evil.example.",
                RData::A(Ipv4Addr::new(192, 168, 1, 10).into()),
            ),
            answer(
                "evil.example.",
                RData::A(Ipv4Addr::new(203, 0, 113, 5).into()),
            ),
        ]);
        let (message, _) = pipeline.prepare_response(resolved, &name, false);
        pipeline.messages.insert(
            &name,
            RecordType::A,
            false,
            &message,
            Duration::from_secs(60),
        );

        let bytes = query_bytes("evil.example.", RecordType::A);
        let response = pipeline
            .handle(&bytes, client(), Transport::Udp)
            .await
            .expect("response");
        let message = Message::from_vec(&response).expect("decode");
        assert_eq!(message.answers.len(), 1);
        assert_eq!(message.answers[0].data.to_string(), "203.0.113.5");
    }

    /// A prepared miss response with a mixed-case stored question, plus its
    /// canonical encoding as the leader broadcasts it.
    ///
    /// The answer owner is deliberately all-caps: hickory compresses label
    /// pointers by exact (case-sensitive) byte match, so an owner matching
    /// one question's case but not the other's would let the two reply paths
    /// make different compression decisions and break byte comparison.
    fn canonical() -> (Message, Arc<Vec<u8>>) {
        let owner = Name::from_ascii("WWW.EXAMPLE.COM.").expect("name");
        let mut message = Message::new(0x7777, MessageType::Response, OpCode::Query);
        message.metadata.recursion_available = true;
        message.metadata.authentic_data = true;
        message.add_query(Query::query(
            Name::from_ascii("WwW.Example.Com.").expect("name"),
            RecordType::A,
        ));
        message.add_answer(Record::from_rdata(
            owner,
            60,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
        let wire = Arc::new(message.to_vec().expect("encode"));
        (message, wire)
    }

    fn miss_request() -> Message {
        let mut request = Message::new(0x4242, MessageType::Query, OpCode::Query);
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(
            Name::from_ascii("www.example.com.").expect("name"),
            RecordType::A,
        ));
        request
    }

    /// Run one miss reply through both reply paths and assert they produce
    /// identical bytes.
    ///
    /// The first `Resolution` carries the canonical wire, so a patchable
    /// reply takes the fast path; the second carries only the message, which
    /// forces the full decode/re-encode. When `expect_fast_path` is set the
    /// wire-patch path is invoked directly first, so equality cannot pass
    /// vacuously with both paths falling back.
    fn assert_reply_paths_match(
        pipeline: &QueryPipeline,
        message: &Message,
        request: &Message,
        transport: Transport,
        expect_fast_path: bool,
    ) -> Vec<u8> {
        let wire = Arc::new(message.to_vec().expect("encode"));
        if expect_fast_path {
            assert!(
                pipeline
                    .finalize_canonical(&wire, message.edns.is_some(), request, transport)
                    .is_some(),
                "expected the reply to be patched from the canonical wire",
            );
        }
        let fast = pipeline
            .client_reply(
                Resolution {
                    message: Some(message.clone()),
                    wire: Some(Arc::clone(&wire)),
                    has_opt: message.edns.is_some(),
                    ede: None,
                },
                request,
                client(),
                transport,
            )
            .expect("fast-path reply");
        let full = pipeline
            .client_reply(
                Resolution {
                    message: Some(message.clone()),
                    wire: None,
                    has_opt: false,
                    ede: None,
                },
                request,
                client(),
                transport,
            )
            .expect("full-path reply");
        assert_eq!(fast, full, "both reply paths must produce identical bytes");
        fast
    }

    #[test]
    fn miss_reply_without_edns_matches_full_reencode() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let request = miss_request();

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, true);
        let response = Message::from_vec(&reply).expect("decode");
        assert_eq!(response.metadata.id, 0x4242);
        assert!(response.metadata.recursion_desired);
        assert!(response.metadata.recursion_available);
        assert!(response.metadata.authentic_data);
        assert!(response.edns.is_none());
    }

    #[test]
    fn miss_reply_with_edns_matches_full_reencode() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let mut request = miss_request();
        let mut edns = Edns::new();
        edns.set_max_payload(1400);
        edns.set_dnssec_ok(true);
        request.edns = Some(edns);

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, true);
        let response = Message::from_vec(&reply).expect("decode");
        let response_edns = response.edns.as_ref().expect("OPT in response");
        assert_eq!(response_edns.max_payload(), 1232);
        assert_eq!(response_edns.version(), 0);
        assert!(response_edns.flags().dnssec_ok);
    }

    #[test]
    fn miss_reply_echoes_the_client_question_case() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let mut request = miss_request();
        request.queries[0] = Query::query(
            Name::from_ascii("WwW.eXaMpLe.CoM.").expect("name"),
            RecordType::A,
        );

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, true);
        let response = Message::from_vec(&reply).expect("decode");
        assert_eq!(response.queries[0].name.to_ascii(), "WwW.eXaMpLe.CoM.");
    }

    #[test]
    fn miss_reply_with_cd_matches_full_reencode_and_clears_ad() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let mut request = miss_request();
        request.metadata.checking_disabled = true;

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, true);
        let response = Message::from_vec(&reply).expect("decode");
        assert!(response.metadata.checking_disabled);
        assert!(!response.metadata.authentic_data);
    }

    #[test]
    fn miss_reply_falls_back_for_client_cookies() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let mut request = miss_request();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(dns_proto::EdnsOption::Unknown(10, vec![9u8; 8]));
        request.edns = Some(edns);
        let wire = message.to_vec().expect("encode");

        assert!(
            pipeline
                .finalize_canonical(&wire, false, &request, Transport::Udp)
                .is_none(),
            "a client cookie must be answered by the full path",
        );

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, false);
        let response = Message::from_vec(&reply).expect("decode");
        assert!(
            response
                .edns
                .expect("OPT")
                .option(dns_proto::EDNS_COOKIE)
                .is_some(),
            "the cookie answer proves the fallback ran",
        );
    }

    #[test]
    fn miss_reply_falls_back_when_the_wire_has_an_opt() {
        let pipeline = pipeline();
        let (mut message, _) = canonical();
        message.edns = Some(Edns::new());
        let wire = message.to_vec().expect("encode");
        let request = miss_request();

        assert!(
            pipeline
                .finalize_canonical(&wire, true, &request, Transport::Udp)
                .is_none(),
            "an upstream OPT record must be stripped by the full path",
        );

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, false);
        let response = Message::from_vec(&reply).expect("decode");
        assert!(
            response.edns.is_none(),
            "the client sent no EDNS, so the rebuilt reply carries no OPT",
        );
    }

    #[test]
    fn miss_reply_falls_back_for_extended_rcodes() {
        let pipeline = pipeline();
        let (mut message, _) = canonical();
        message.metadata.response_code = ResponseCode::BADVERS;
        let mut request = miss_request();
        request.edns = Some(Edns::new());

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, false);
        let response = Message::from_vec(&reply).expect("decode");
        // rcode 16 decodes as BADSIG, hickory's name for the shared value;
        // what matters is that the OPT-extended high bits survived.
        assert_eq!(
            response.metadata.response_code.high(),
            1,
            "the extended rcode only survives when the full path rebuilds the OPT",
        );
    }

    #[test]
    fn miss_reply_falls_back_when_an_ede_is_attached() {
        let pipeline = pipeline();
        let (message, _) = canonical();
        let mut request = miss_request();
        request.edns = Some(Edns::new());
        let wire = Arc::new(message.to_vec().expect("encode"));

        let reply = pipeline
            .client_reply(
                Resolution {
                    message: Some(message),
                    wire: Some(wire),
                    has_opt: false,
                    ede: Some(dns_iter::BogusReason::Signature),
                },
                &request,
                client(),
                Transport::Udp,
            )
            .expect("reply");
        let response = Message::from_vec(&reply).expect("decode");
        let edns = response.edns.as_ref().expect("OPT");
        let option = edns
            .option(dns_proto::EdnsCode::Unknown(15))
            .expect("EDE option");
        match option {
            dns_proto::EdnsOption::Unknown(code, data) => {
                assert_eq!(*code, 15);
                assert_eq!(&data[..2], &6u16.to_be_bytes());
            }
            other => panic!("unexpected EDE option: {other:?}"),
        }
    }

    #[test]
    fn miss_reply_falls_back_when_truncation_is_needed() {
        let pipeline = pipeline();
        let owner = Name::from_ascii("www.example.com.").expect("name");
        let mut message = Message::new(0x7777, MessageType::Response, OpCode::Query);
        message.metadata.recursion_available = true;
        message.add_query(Query::query(owner.clone(), RecordType::A));
        for octet in 0..40 {
            message.add_answer(Record::from_rdata(
                owner.clone(),
                60,
                RData::A(Ipv4Addr::new(192, 0, 2, octet).into()),
            ));
        }
        let request = miss_request();
        let wire = message.to_vec().expect("encode");
        assert!(
            pipeline
                .finalize_canonical(&wire, false, &request, Transport::Udp)
                .is_none(),
            "an oversized reply must be truncated by the full path",
        );

        let reply = assert_reply_paths_match(&pipeline, &message, &request, Transport::Udp, false);
        assert!(reply.len() <= 512, "the reply must fit the 512-byte limit");
        let response = Message::from_vec(&reply).expect("decode");
        assert!(response.metadata.truncation);
    }

    #[test]
    fn miss_reply_falls_back_for_mismatched_questions() {
        let pipeline = pipeline();
        let (_, wire) = canonical();
        let mut request = miss_request();
        request.queries[0] = Query::query(
            Name::from_ascii("other.example.").expect("name"),
            RecordType::A,
        );

        assert!(
            pipeline
                .finalize_canonical(&wire, false, &request, Transport::Udp)
                .is_none(),
            "the canonical wire cannot answer a different question",
        );
    }

    #[test]
    fn miss_reply_falls_back_for_a_non_query_opcode() {
        let pipeline = pipeline();
        let (mut message, _) = canonical();
        message.metadata.op_code = OpCode::Notify;
        let wire = message.to_vec().expect("encode");

        assert!(
            pipeline
                .finalize_canonical(&wire, false, &miss_request(), Transport::Udp)
                .is_none(),
            "only opcode Query replies may be patched in place",
        );
    }

    #[test]
    fn followers_answer_from_the_shared_wire() {
        let pipeline = pipeline();
        let (message, wire) = canonical();
        let request = miss_request();

        let follower = pipeline
            .client_reply(
                Resolution {
                    message: None,
                    wire: Some(Arc::clone(&wire)),
                    has_opt: false,
                    ede: None,
                },
                &request,
                client(),
                Transport::Udp,
            )
            .expect("follower reply");
        let leader = pipeline
            .client_reply(
                Resolution {
                    message: Some(message),
                    wire: Some(Arc::clone(&wire)),
                    has_opt: false,
                    ede: None,
                },
                &request,
                client(),
                Transport::Udp,
            )
            .expect("leader reply");
        assert_eq!(follower, leader, "both must come from the same bytes");

        // A cookie forces a fallback, which must decode the shared wire.
        let mut cookie_request = miss_request();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(dns_proto::EdnsOption::Unknown(10, vec![9u8; 8]));
        cookie_request.edns = Some(edns);
        let reply = pipeline
            .client_reply(
                Resolution {
                    message: None,
                    wire: Some(wire),
                    has_opt: false,
                    ede: None,
                },
                &cookie_request,
                client(),
                Transport::Udp,
            )
            .expect("follower reply with cookie");
        let response = Message::from_vec(&reply).expect("decode");
        assert!(
            response
                .edns
                .expect("OPT")
                .option(dns_proto::EDNS_COOKIE)
                .is_some()
        );
    }

    #[test]
    fn retain_queryable_drops_blocked_upstreams() {
        let mut servers = vec![
            super::ForwardServer {
                addr: "127.0.0.1:53".parse().expect("address"),
                transport: super::ForwardTransport::Plain,
                tls_name: None,
                path: None,
            },
            super::ForwardServer {
                addr: "192.0.2.1:53".parse().expect("address"),
                transport: super::ForwardTransport::Plain,
                tls_name: None,
                path: None,
            },
        ];
        super::retain_queryable(
            "forward-zone",
            ".",
            &mut servers,
            &["127.0.0.0/8".parse().expect("netblock")],
        );
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].addr, "192.0.2.1:53".parse().expect("address"));
    }

    #[test]
    fn forward_hosts_resolve_into_plain_upstreams() {
        let mut servers = Vec::new();
        super::append_resolved_hosts(
            "forward-host",
            ".",
            &["localhost".to_owned()],
            false,
            &mut servers,
        );

        assert!(!servers.is_empty(), "localhost must resolve");
        assert!(
            servers
                .iter()
                .all(|server| server.transport == super::ForwardTransport::Plain)
        );
        assert!(servers.iter().all(|server| server.addr.port() == 53));
        assert!(servers.iter().all(|server| server.tls_name.is_none()));
        assert!(servers.iter().any(|server| server.addr.ip().is_loopback()));
    }

    #[test]
    fn forward_hosts_use_the_tls_port_and_certificate_name() {
        let mut servers = Vec::new();
        super::append_resolved_hosts(
            "forward-host",
            "example.",
            &["localhost".to_owned()],
            true,
            &mut servers,
        );

        assert!(!servers.is_empty(), "localhost must resolve");
        assert!(
            servers
                .iter()
                .all(|server| server.transport == super::ForwardTransport::Tls)
        );
        assert!(servers.iter().all(|server| server.addr.port() == 853));
        assert!(
            servers
                .iter()
                .all(|server| server.tls_name.as_deref() == Some("localhost"))
        );
    }
}
