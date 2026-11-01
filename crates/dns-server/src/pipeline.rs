use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dns_cache::{
    CacheHit, CacheStats, DEFAULT_STALE_TTL, InfraCache, MessageCache, QueryKey, QueryRegistry,
    RegistryEntry, RrsetCache, WireRequest, response_ttl,
};
use dns_config::{Config, ForwardTarget};
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
use crate::ratelimit::{ClientConcurrency, RateDecision, RateLimiter};

const MESSAGE_CACHE_ENTRIES: u64 = 8_192;
const RRSET_CACHE_ENTRIES: u64 = 16_384;
const INFRA_CACHE_ENTRIES: u64 = 1_024;
const MAX_GLOBAL_INFLIGHT: usize = 8_192;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const FOLLOWER_TIMEOUT: Duration = Duration::from_secs(11);

/// Client transport, which controls truncation behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Tls,
    Https,
}

/// A resolved response plus an optional Extended DNS Error.
struct Resolution {
    message: Message,
    ede: Option<BogusReason>,
}

/// A point-in-time snapshot of pipeline counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Message-cache hit, miss, and stale-hit counters.
    pub cache: CacheStats,
    /// Number of entries currently held in the message cache.
    pub cache_entries: u64,
    /// Background refreshes started by prefetch or serve-expired.
    pub prefetches: u64,
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
        output
    }
}

/// Removes the in-flight marker when a background refresh ends.
struct RefreshGuard {
    inflight: Arc<Mutex<HashSet<String>>>,
    key: String,
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
    prefetch: bool,
    serve_expired: bool,
    stale_reply_ttl: u32,
    prefetch_inflight: Arc<Mutex<HashSet<String>>>,
    prefetches: Arc<AtomicU64>,
    local: local::LocalPolicy,
    auth_downstream: local::LocalZones,
    auth_upstream: local::LocalZones,
    private: PrivateAddressFilter,
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
        let infra = Arc::new(InfraCache::new(INFRA_CACHE_ENTRIES));

        let forward_zones = config
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
                if !zone.forward_hosts.is_empty() {
                    warn!(
                        zone = %zone.name,
                        "forward-host is not implemented yet; use forward-addr"
                    );
                }
                let servers = build_servers(
                    &zone.name,
                    &zone.forward_addrs,
                    zone.tls_upstream,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                if servers.is_empty() {
                    warn!(
                        zone = %zone.name,
                        "forward-zone has no usable forward-addr; ignoring"
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
                for host in &zone.stub_hosts {
                    let port = if zone.tls_upstream { 853 } else { 53 };
                    match resolve_forward_host(host, port) {
                        Ok(addresses) => {
                            for addr in addresses {
                                servers.push(ForwardServer {
                                    addr,
                                    transport: if zone.tls_upstream {
                                        ForwardTransport::Tls
                                    } else {
                                        ForwardTransport::Plain
                                    },
                                    tls_name: zone
                                        .tls_upstream
                                        .then(|| host.trim_end_matches('.').to_owned()),
                                    path: None,
                                });
                            }
                        }
                        Err(error) => warn!(
                            zone = %zone.name,
                            %host,
                            %error,
                            "failed to resolve stub-host; skipping"
                        ),
                    }
                }
                retain_allowed_families(
                    &zone.name,
                    &mut servers,
                    config.server.do_ip4,
                    config.server.do_ip6,
                );
                if servers.is_empty() {
                    warn!(
                        zone = %zone.name,
                        "stub-zone has no usable stub-addr; ignoring"
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
            dnssec_validation: config.server.dnssec_validation,
            trust_store: trust_store.clone(),
            domain_insecure: config.server.insecure_domains(),
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

        if let (Some((tracker, path)), Some(resolver)) = (auto_anchor, resolver.clone())
            && config.server.dnssec_validation
        {
            spawn_autotrust(resolver, trust_store.clone(), tracker, path);
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
        }
    }

    /// Return a snapshot of cache and refresh counters.
    pub fn stats(&self) -> PipelineStats {
        PipelineStats {
            cache: self.messages.stats(),
            cache_entries: self.messages.entry_count(),
            prefetches: self.prefetches.load(Ordering::Relaxed),
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
        let started = Instant::now();
        let mut request = match decode(bytes) {
            Ok(message) => message,
            Err(error) => {
                debug!(%client, %error, "dropping malformed query");
                return None;
            }
        };

        if request.metadata.message_type != MessageType::Query {
            return None;
        }

        if request.metadata.op_code != OpCode::Query {
            return self.error(&request, ResponseCode::NotImp, client, transport);
        }

        match acl::check(&self.config, &client) {
            Decision::Deny => return None,
            Decision::Refuse | Decision::DenyNonLocal | Decision::RefuseNonLocal => {
                return self.error(&request, ResponseCode::Refused, client, transport);
            }
            Decision::Allow => {}
            Decision::AllowSnoop => {
                // Snoop mode: cache-only access, no recursion sent upstream
                // (Unbound-like: RD=0, serve from message cache if available,
                //  otherwise NXDOMAIN/SERVFAIL without recursive resolution).
                request.metadata.recursion_desired = false;
            }
        }

        if request.queries.len() != 1 {
            return self.error(&request, ResponseCode::FormErr, client, transport);
        }
        let query = &request.queries[0];
        if query.query_class != DNSClass::IN {
            return self.error(&request, ResponseCode::NotImp, client, transport);
        }
        if matches!(query.query_type, RecordType::AXFR | RecordType::IXFR) {
            return self.error(&request, ResponseCode::NotImp, client, transport);
        }
        if edns::version(&request).is_some_and(|version| version != 0) {
            return self.error(&request, ResponseCode::BADVERS, client, transport);
        }

        match self.rate_limiter.check(client.ip()) {
            RateDecision::Allow => {}
            RateDecision::Drop => {
                debug!(%client, qname = %query.name, "rate limited; dropping query");
                return None;
            }
            RateDecision::Slip => {
                debug!(
                    %client,
                    qname = %query.name,
                    limited = self.rate_limiter.limited_count(),
                    "rate limited; slipping truncated response"
                );
                return self.truncated_reply(&request, client, transport);
            }
        }

        let _permit = match self.concurrency.try_acquire(client.ip()) {
            Some(permit) => permit,
            None => {
                debug!(%client, "per-client concurrency limit reached; dropping query");
                return None;
            }
        };

        let do_bit = edns::dnssec_ok(&request);
        let checking_disabled = request.metadata.checking_disabled;
        let wire_request = WireRequest {
            id: request.metadata.id,
            recursion_desired: request.metadata.recursion_desired,
            checking_disabled,
            question_name: &query.name,
        };
        // Local zones are answered before the cache, like Unbound. They are
        // never stored in the message cache because they are policy, not data.
        match self.local.answer(client.ip(), query) {
            local::LocalAction::Answer(message) => {
                return self.finalize(*message, &request, client, transport);
            }
            local::LocalAction::Drop => return None,
            local::LocalAction::NotHandled => {}
        }
        match self.auth_downstream.answer(query) {
            local::LocalAction::Answer(message) => {
                return self.finalize(*message, &request, client, transport);
            }
            local::LocalAction::Drop => return None,
            local::LocalAction::NotHandled => {}
        }

        // A CD client must see the underlying data even if a non-CD query
        // already cached a SERVFAIL for the same name. Cache entries are
        // written after `prepare_response` runs, so every hit is already
        // scrubbed by the rebinding filter.
        if !checking_disabled {
            if let Some(hit) =
                self.messages
                    .get(&query.name, query.query_type, do_bit, wire_request)
            {
                if self.prefetch && MessageCache::should_prefetch(&hit) {
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
                return self.serve_hit(hit, &request, client, transport);
            }

            if self.serve_expired
                && let Some(hit) = self.messages.get_stale(
                    &query.name,
                    query.query_type,
                    do_bit,
                    wire_request,
                    self.stale_reply_ttl,
                )
            {
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
                return self.serve_hit(hit, &request, client, transport);
            }
        }

        // Authority zones configured for upstream use answer recursive
        // lookups from local data after the cache.
        match self.auth_upstream.answer(query) {
            local::LocalAction::Answer(message) => {
                return self.finalize(*message, &request, client, transport);
            }
            local::LocalAction::Drop => return None,
            local::LocalAction::NotHandled => {}
        }

        if !self.local.covers(client.ip(), &query.name)
            && !self.auth_downstream.covers(&query.name)
            && let Some(local) = local::maybe_respond(query)
        {
            return self.finalize(local, &request, client, transport);
        }

        if !request.metadata.recursion_desired {
            return self.error(&request, ResponseCode::Refused, client, transport);
        }

        let resolution = match self
            .resolve_coalesced(query, do_bit, checking_disabled, &cancel)
            .await
        {
            Some(resolution) => resolution,
            None => {
                if cancel.is_cancelled() {
                    debug!(%client, qname = %query.name, "client went away; resolution cancelled");
                    return None;
                }
                return self.error(&request, ResponseCode::ServFail, client, transport);
            }
        };

        let response = self.finalize_with_ede(
            resolution.message,
            &request,
            client,
            transport,
            resolution.ede,
        );
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

    /// Return a cached wire response, adding EDNS/cookies or truncating only
    /// when the client requires it.
    fn serve_hit(
        &self,
        hit: CacheHit,
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

        if request.edns.is_none() && hit.wire.len() <= limit {
            return Some(hit.wire);
        }

        // Common EDNS(0) case: the cached wire has no OPT record, the client
        // sent no cookie, and the response fits. Append our OPT record instead
        // of decoding and re-encoding the whole message.
        if request.edns.is_some()
            && !hit.has_edns
            && edns::requested_cookie(request).is_none()
            && hit
                .wire
                .len()
                .checked_add(edns::EMPTY_OPT_LEN)
                .is_some_and(|length| length <= limit)
        {
            let mut wire = hit.wire;
            if edns::append_empty_opt(
                &mut wire,
                self.config.server.max_udp_size.max(512),
                edns::dnssec_ok(request),
            ) {
                return Some(wire);
            }
            let message = Message::from_vec(&wire).ok()?;
            return self.finalize_with_ede(message, request, client, transport, None);
        }

        let message = Message::from_vec(&hit.wire).ok()?;
        self.finalize_with_ede(message, request, client, transport, None)
    }

    /// Refresh a cache entry in the background, at most once per key.
    ///
    /// The refresh goes through the coalescing registry, so it joins a client
    /// query that is already resolving the same name instead of issuing a
    /// duplicate upstream request.
    fn spawn_refresh(&self, query: &Query, do_bit: bool) {
        let key = format!(
            "{}|{}|{}",
            query.name.to_ascii().to_lowercase(),
            u16::from(query.query_type),
            u8::from(do_bit)
        );
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

    async fn resolve_coalesced(
        &self,
        query: &Query,
        do_bit: bool,
        checking_disabled: bool,
        cancel: &CancellationToken,
    ) -> Option<Resolution> {
        let key = QueryKey {
            name: query.name.to_ascii().to_lowercase(),
            qtype: u16::from(query.query_type),
            qclass: u16::from(DNSClass::IN),
            do_bit,
            checking_disabled,
        };

        match self.registry.wait_or_register(key).await {
            RegistryEntry::Leader(leader) => {
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
                match resolution {
                    Ok(resolved) => {
                        let cacheable =
                            !checking_disabled && !matches!(resolved.security, Security::Bogus(_));
                        let security = resolved.security.clone();
                        let (message, ede) =
                            self.prepare_response(resolved, &query.name, checking_disabled);
                        if cacheable {
                            let ttl = response_ttl(
                                &message,
                                self.config.server.cache_min_ttl,
                                self.config.server.cache_max_ttl,
                            );
                            if ttl > Duration::ZERO {
                                self.messages.insert(
                                    &query.name,
                                    query.query_type,
                                    do_bit,
                                    &message,
                                    ttl,
                                );
                            }
                        }
                        if let Ok(wire) = encode(&message) {
                            leader.complete(Arc::new(wire));
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
                        Some(Resolution { message, ede })
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

                match result {
                    Ok(Ok(value)) => {
                        let wire = value.as_ref()?.clone();
                        let message = Message::from_vec(&wire).ok()?;
                        Some(Resolution { message, ede: None })
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
        let qname = query.name.to_ascii();
        let options = ResolveOptions {
            dnssec_ok: do_bit,
            checking_disabled,
        };
        tokio::time::timeout(
            RESOLVE_TIMEOUT,
            resolver.resolve_with_options(&qname, query.query_type, options),
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
        self.finalize_with_ede(message, request, client, transport, None)
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
        match transport {
            Transport::Tcp | Transport::Tls | Transport::Https => Some(wire),
            Transport::Udp => {
                let advertised = self.config.server.max_udp_size.max(512);
                let limit = usize::from(edns::payload_size(request).min(advertised));
                if wire.len() <= limit {
                    Some(wire)
                } else {
                    Some(truncate(message, limit))
                }
            }
        }
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

/// Resolve a DoH forwarder hostname at startup, preferring IPv4.
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
) {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return;
    };
    handle.spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = unix_now();
            if !tracker.is_due(now) {
                continue;
            }
            match resolver.probe_dnskey(&tracker.zone).await {
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
fn truncate(mut message: Message, limit: usize) -> Vec<u8> {
    message.metadata.truncation = true;
    loop {
        if let Ok(wire) = encode(&message)
            && wire.len() <= limit
        {
            return wire;
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
        return encode(&message).unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use dns_config::{Config, ServerConfig};
    use dns_proto::{
        CNAME, Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType,
        ResponseCode,
    };
    use dns_testutil::query_bytes;

    use super::{QueryPipeline, Transport};

    fn pipeline() -> QueryPipeline {
        QueryPipeline::new(Arc::new(Config::default()))
    }

    fn client() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1234)
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

        let wire = super::truncate(message, 128);
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
}
