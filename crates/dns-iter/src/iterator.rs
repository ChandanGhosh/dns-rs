//! Iterative resolver with 0x20, QNAME minimisation and response scrubbing.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use dns_cache::{InfraCache, RrsetCache};
use dns_client::{HttpsClient, TcpClient, TlsClient, UdpClient};
use dns_dnssec::{MAX_NSEC3_ITERATIONS, Security, TrustStore, rrsig_of};
use dns_proto::{
    Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, ResponseCode,
    decode, encode,
};
use rand::Rng;
use tracing::{debug, info, trace, warn};

use crate::ResolveError;
use crate::cookies::CookieJar;
use crate::root_hints;
use crate::scrub::{self, Referral};
use crate::validate::{ResolveOptions, Resolved, ZoneCache};

const MAX_DEPTH: u32 = 16;
const MAX_CNAME_CHAIN: usize = 8;
const MAX_REFERRAL_ROUNDS: usize = 12;
const MAX_SERVERS_PER_QUERY: usize = 8;
const MAX_QUERIES_PER_RESOLUTION: u32 = 64;
const MAX_NS_ADDRESS_PROBES: usize = 3;
const UDP_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_TIMEOUT: Duration = Duration::from_secs(3);
const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const ROOT_PRIME_TIMEOUT: Duration = Duration::from_secs(5);
const ROOT_PRIME_INTERVAL: Duration = Duration::from_secs(3600);
const ROOT_PRIME_RETRY: Duration = Duration::from_secs(60);

/// A zone whose queries are sent to recursive forwarders instead of being
/// resolved iteratively.
#[derive(Clone, Debug)]
pub struct ForwardZone {
    /// Zone apex. Use the root name for a global forwarder.
    pub zone: Name,
    /// Recursive resolvers to ask.
    pub servers: Vec<ForwardServer>,
    /// Fall back to iterative resolution when every forwarder fails.
    pub forward_first: bool,
    /// Resolve iteratively first and use the forwarders only when iteration
    /// fails with a reachability error.
    pub forward_fallback: bool,
}

/// Whether a resolution error means the network could not reach authoritative
/// servers.
///
/// Negative answers (`NXDOMAIN`, NODATA) and DNSSEC verdicts are returned as
/// data, never as these errors, so a `forward_fallback` zone cannot override an
/// authoritative answer or a validation failure.
fn is_reachability_error(error: &ResolveError) -> bool {
    matches!(
        error,
        ResolveError::NoNameservers | ResolveError::Timeout | ResolveError::Io(_)
    )
}

/// A zone whose queries are resolved iteratively starting from the listed
/// authoritative servers instead of from the root.
#[derive(Clone, Debug)]
pub struct StubZone {
    /// Zone apex.
    pub zone: Name,
    /// Authoritative servers for the zone.
    pub servers: Vec<ForwardServer>,
    /// Fall back to normal resolution when the stub servers fail.
    pub stub_first: bool,
    /// Refresh the delegation from the zone's published NS set.
    pub prime: bool,
    /// Do not cache data learned through this stub.
    pub no_cache: bool,
}

/// Transport used to reach one forwarder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardTransport {
    /// Classic UDP with TCP fallback.
    Plain,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
}

/// One recursive resolver used by a forward zone.
#[derive(Clone, Debug)]
pub struct ForwardServer {
    /// Socket address to connect to.
    pub addr: SocketAddr,
    /// Transport to use.
    pub transport: ForwardTransport,
    /// TLS authentication name for DoT, or HTTP authority for DoH.
    ///
    /// For DoT, `None` verifies the certificate chain but accepts any name in
    /// the certificate, matching Unbound's behaviour when `#auth-name` is
    /// omitted.
    pub tls_name: Option<String>,
    /// HTTP path for DoH.
    pub path: Option<String>,
}

impl From<SocketAddr> for ForwardServer {
    fn from(addr: SocketAddr) -> Self {
        Self {
            addr,
            transport: ForwardTransport::Plain,
            tls_name: None,
            path: None,
        }
    }
}

/// Tunables that affect how outgoing queries are built and validated.
#[derive(Clone, Debug)]
pub struct IteratorConfig {
    /// Randomise QNAME case and verify it is echoed (DNS 0x20).
    pub case_randomization: bool,
    /// Minimise QNAMEs sent to authoritative servers (RFC 9156).
    pub qname_minimization: bool,
    /// Do not relax minimisation on NODATA or CNAME responses.
    pub qname_minimization_strict: bool,
    /// Reject out-of-bailiwick glue.
    pub harden_glue: bool,
    /// Send DNS COOKIEs upstream.
    pub cookies: bool,
    /// EDNS payload size advertised upstream.
    pub edns_payload: u16,
    /// Lower bound applied to upstream TTLs.
    pub min_ttl: u32,
    /// Upper bound applied to upstream TTLs.
    pub max_ttl: u32,
    /// Allow outgoing queries to IPv4 servers.
    pub allow_ipv4: bool,
    /// Allow outgoing queries to IPv6 servers.
    ///
    /// When disabled, IPv6 root hints, priming glue, and delegation addresses
    /// are skipped so an IPv4-only host does not burn its budget on
    /// connections that cannot work.
    pub allow_ipv6: bool,
    /// Secret used for DNS cookies.
    pub cookie_secret: [u8; 32],
    /// Override the root server set (useful for tests and private roots).
    /// When set, root priming is disabled and these servers are used as-is.
    pub root_servers: Option<Vec<SocketAddr>>,
    /// Servers used to prime the root delegation when `root_servers` is unset.
    /// Defaults to the built-in root hints.
    pub bootstrap_servers: Option<Vec<SocketAddr>>,
    /// Port used for authoritative servers learned from referrals.
    pub nameserver_port: u16,
    /// Forward zones, most specific first or in any order.
    pub forward_zones: Vec<ForwardZone>,
    /// Stub zones, most specific first or in any order.
    pub stub_zones: Vec<StubZone>,
    /// Validate DNSSEC signatures and denial proofs.
    pub dnssec_validation: bool,
    /// Trust anchors used to start validation chains.
    pub trust_store: TrustStore,
    /// Domains whose DNSSEC chain of trust is ignored.
    ///
    /// Each entry is a static negative trust anchor (RFC 7646): the domain and
    /// all names below it are treated as insecure. An explicit trust anchor at
    /// or below an entry overrides the exclusion.
    pub domain_insecure: Vec<Name>,
    /// Treat unsigned data in a signed zone as bogus.
    pub harden_dnssec_stripped: bool,
    /// Maximum NSEC3 iteration count accepted during validation.
    ///
    /// Proofs with more iterations are treated as bogus before any hashing, so
    /// a signed zone cannot force unbounded CPU work (RFC 9276 section 3.2).
    pub nsec3_max_iterations: u16,
    /// Return bogus data instead of failing (validation still runs).
    pub val_permissive_mode: bool,
    /// Strip additional-section data after validation.
    pub val_clean_additional: bool,
    /// PEM bundle used to verify upstream DoT and DoH servers.
    pub tls_cert_bundle: Option<PathBuf>,
    /// Trust the system (webpki) roots for upstream encrypted transports.
    pub tls_use_system_ca: bool,
}

impl Default for IteratorConfig {
    fn default() -> Self {
        let mut cookie_secret = [0u8; 32];
        rand::rng().fill(&mut cookie_secret);
        Self {
            case_randomization: true,
            qname_minimization: true,
            qname_minimization_strict: false,
            harden_glue: true,
            cookies: true,
            edns_payload: 1232,
            min_ttl: 0,
            max_ttl: 86_400,
            allow_ipv4: true,
            allow_ipv6: true,
            cookie_secret,
            root_servers: None,
            bootstrap_servers: None,
            nameserver_port: 53,
            forward_zones: Vec::new(),
            stub_zones: Vec::new(),
            dnssec_validation: false,
            trust_store: TrustStore::builtin(),
            domain_insecure: Vec::new(),
            harden_dnssec_stripped: true,
            nsec3_max_iterations: MAX_NSEC3_ITERATIONS,
            val_permissive_mode: false,
            val_clean_additional: true,
            tls_cert_bundle: None,
            tls_use_system_ca: true,
        }
    }
}

#[derive(Clone)]
pub struct IteratorResolver {
    pub(crate) udp: UdpClient,
    pub(crate) tcp: TcpClient,
    pub(crate) tls: Option<TlsClient>,
    pub(crate) https: Option<HttpsClient>,
    pub(crate) config: IteratorConfig,
    pub(crate) cookies: CookieJar,
    pub(crate) rrsets: Option<Arc<RrsetCache>>,
    pub(crate) infra: Option<Arc<InfraCache>>,
    pub(crate) zones: Arc<std::sync::Mutex<ZoneCache>>,
    pub(crate) prime_state: Arc<std::sync::RwLock<RootPrimeState>>,
    prime_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone, Copy, Debug, Default)]
struct ResponseChecks {
    require_case: bool,
    require_cookie: bool,
}

/// Root delegation learned by the last successful priming query.
#[derive(Debug, Default)]
pub(crate) struct RootPrimeState {
    servers: Vec<SocketAddr>,
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
}

enum Minimized {
    /// Authoritative negative answer obtained during the minimised walk.
    Answer(Message),
    /// Continue with the full query.
    Continue,
}

/// Caps the total number of upstream exchanges for one client query, which
/// bounds the work an adversarial delegation graph can cause.
#[derive(Debug)]
pub(crate) struct Budget {
    remaining: AtomicU32,
}

impl Budget {
    pub(crate) fn new(limit: u32) -> Self {
        Self {
            remaining: AtomicU32::new(limit),
        }
    }

    fn spend(&self) -> bool {
        let mut remaining = self.remaining.load(Ordering::Relaxed);
        loop {
            if remaining == 0 {
                return false;
            }
            match self.remaining.compare_exchange_weak(
                remaining,
                remaining - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(actual) => remaining = actual,
            }
        }
    }
}

/// State shared by one client-facing resolution walk.
#[derive(Clone)]
pub(crate) struct WalkContext<'a> {
    pub(crate) depth: u32,
    pub(crate) ancestors: &'a HashSet<String>,
    pub(crate) deadline: Instant,
    pub(crate) budget: Arc<Budget>,
    /// Forwarded queries set RD; iterative queries must clear it.
    pub(crate) recursion_desired: bool,
    /// Request DNSSEC records from upstream servers.
    pub(crate) dnssec_ok: bool,
    /// This walk is an internal fetch for the validator; do not validate it.
    pub(crate) validating: bool,
    /// Ask upstream recursive servers not to validate (RFC 4035 section 3.2.2).
    ///
    /// Set when this resolver validates the answer itself, or when the client
    /// disabled checking and will validate on its own.
    pub(crate) checking_disabled: bool,
    /// Resolve only through forwarders.
    ///
    /// Set once a query is being answered by a forwarder, so a subquery for a
    /// CNAME target inside the same zone does not run the iteration-first
    /// fallback again.
    pub(crate) forward_only: bool,
}

/// A walk result plus the authoritative zone that supplied each answer owner.
///
/// Validation needs the zone that owns an unsigned RRset to start the chain of
/// trust at a real apex. Deriving it from the owner name is wrong for aliases:
/// a DS query for an alias is answered with a CNAME, not a delegation denial.
/// `origins` is empty for forwarded answers, where the authoritative zone is
/// not known and validation has to fall back to a DS probe.
pub(crate) struct WalkAnswer {
    pub(crate) message: Message,
    pub(crate) origins: HashMap<String, Name>,
}

impl WalkAnswer {
    fn new(message: Message) -> Self {
        Self {
            message,
            origins: HashMap::new(),
        }
    }

    /// Record the zone that answered every owner in `records`.
    fn note(&mut self, records: &[Record], zone: Option<&Name>) {
        note_origins(&mut self.origins, records, zone);
    }
}

fn note_origins(origins: &mut HashMap<String, Name>, records: &[Record], zone: Option<&Name>) {
    let Some(zone) = zone else {
        return;
    };
    for record in records {
        origins.insert(origin_key(&record.name), zone.clone());
    }
}

fn origin_key(name: &Name) -> String {
    name.to_ascii().to_ascii_lowercase()
}

impl IteratorResolver {
    pub fn new() -> std::io::Result<Self> {
        Self::with_config(IteratorConfig::default(), None)
    }

    pub fn with_config(
        config: IteratorConfig,
        bind_addr: Option<SocketAddr>,
    ) -> std::io::Result<Self> {
        let cookies = CookieJar::new(&config.cookie_secret);
        let needs_tls = config.forward_zones.iter().any(|zone| {
            zone.servers
                .iter()
                .any(|server| server.transport == ForwardTransport::Tls)
        });
        let needs_https = config.forward_zones.iter().any(|zone| {
            zone.servers
                .iter()
                .any(|server| server.transport == ForwardTransport::Https)
        });
        let tls = needs_tls
            .then(|| TlsClient::new(config.tls_cert_bundle.as_deref(), config.tls_use_system_ca))
            .transpose()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        let https = needs_https
            .then(|| HttpsClient::new(config.tls_cert_bundle.as_deref(), config.tls_use_system_ca))
            .transpose()
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?;
        Ok(Self {
            udp: UdpClient::new(bind_addr)?,
            tcp: TcpClient::new(),
            tls,
            https,
            config,
            cookies,
            rrsets: None,
            infra: None,
            zones: Arc::new(std::sync::Mutex::new(ZoneCache::default())),
            prime_state: Arc::new(std::sync::RwLock::new(RootPrimeState::default())),
            prime_lock: Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    /// Attach shared RRset and infrastructure caches.
    pub fn with_caches(mut self, rrsets: Arc<RrsetCache>, infra: Arc<InfraCache>) -> Self {
        self.rrsets = Some(rrsets);
        self.infra = Some(infra);
        self
    }

    pub fn cookies(&self) -> &CookieJar {
        &self.cookies
    }

    /// Resolve `qname`/`qtype` from the root.
    pub async fn resolve(&self, qname: &str, qtype: RecordType) -> Result<Message, ResolveError> {
        self.resolve_with_options(qname, qtype, ResolveOptions::default())
            .await
            .map(|resolved| resolved.message)
    }

    /// Resolve with explicit DNSSEC request flags and validation result.
    pub async fn resolve_with_options(
        &self,
        qname: &str,
        qtype: RecordType,
        options: ResolveOptions,
    ) -> Result<Resolved, ResolveError> {
        let name = Name::from_ascii(qname)
            .map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
        let deadline = Instant::now() + RESOLUTION_TIMEOUT;
        let ancestors = HashSet::new();
        let context = WalkContext {
            depth: 0,
            ancestors: &ancestors,
            deadline,
            budget: Arc::new(Budget::new(MAX_QUERIES_PER_RESOLUTION)),
            recursion_desired: false,
            // Validation needs signatures even when the client did not ask
            // for them; they are stripped before the response is returned.
            dnssec_ok: self.config.dnssec_validation || options.dnssec_ok,
            validating: false,
            checking_disabled: options.checking_disabled,
            forward_only: false,
        };
        let WalkAnswer {
            mut message,
            origins,
        } = self.resolve_inner(name, qtype, context.clone()).await?;
        message.metadata.recursion_available = true;

        let security = if self.config.dnssec_validation {
            self.validate_message(&message, qtype, &origins, &context)
                .await
        } else {
            Security::Insecure
        };

        if self.config.val_clean_additional && self.config.dnssec_validation {
            message.additionals.clear();
        }
        if !options.dnssec_ok {
            strip_dnssec_records(&mut message, qtype);
        }
        message.metadata.authentic_data =
            security == Security::Secure && !options.checking_disabled;

        Ok(Resolved { message, security })
    }

    pub(crate) fn resolve_inner<'a>(
        &'a self,
        name: Name,
        qtype: RecordType,
        context: WalkContext<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<WalkAnswer, ResolveError>> + Send + 'a>> {
        Box::pin(async move {
            if context.depth > MAX_DEPTH {
                return Err(ResolveError::DepthExceeded);
            }
            if Instant::now() >= context.deadline {
                return Err(ResolveError::Timeout);
            }

            let key = format!("{}|{}", name.to_ascii().to_lowercase(), u16::from(qtype));
            if context.ancestors.contains(&key) {
                return Err(ResolveError::Cycle);
            }
            let mut path = context.ancestors.clone();
            path.insert(key);

            let context = WalkContext {
                ancestors: &path,
                ..context
            };
            self.walk(name, qtype, context).await
        })
    }

    async fn walk(
        &self,
        name: Name,
        qtype: RecordType,
        context: WalkContext<'_>,
    ) -> Result<WalkAnswer, ResolveError> {
        // A matching forward zone normally short-circuits iteration. Subqueries
        // inherit this path, so a CNAME target inside the zone is forwarded
        // too. A `forward_fallback` zone is only used when iteration fails.
        let forward = self.forward_zone(&name).cloned();
        if let Some(zone) = &forward
            && !zone.forward_fallback
        {
            match self.walk_forward(&name, qtype, zone, &context).await {
                Ok(message) => return Ok(message),
                Err(error) if zone.forward_first => {
                    debug!(
                        qname = %name,
                        zone = %zone.zone,
                        %error,
                        "forwarding failed; falling back to iteration"
                    );
                }
                Err(error) => return Err(error),
            }
        }

        // Iterative queries must never set RD.
        let context = WalkContext {
            recursion_desired: false,
            ..context
        };
        let forward_only = context.forward_only;

        // A matching stub zone seeds the walk with its authoritative servers.
        // `stub-first` falls back to normal resolution when the stub fails.
        let iterated = if let Some(stub) = self.stub_zone(&name).cloned() {
            let start = Some((stub.zone.clone(), stub.servers.clone()));
            match self
                .iterate(name.clone(), qtype, context.clone(), start, stub.no_cache)
                .await
            {
                Ok(message) => Ok(message),
                Err(error) if stub.stub_first => {
                    debug!(
                        qname = %name,
                        zone = %stub.zone,
                        %error,
                        "stub resolution failed; falling back to normal resolution"
                    );
                    self.iterate(name.clone(), qtype, context.clone(), None, false)
                        .await
                }
                Err(error) => Err(error),
            }
        } else {
            self.iterate(name.clone(), qtype, context.clone(), None, false)
                .await
        };

        let error = match iterated {
            Ok(message) => return Ok(message),
            Err(error) => error,
        };

        // `forward_fallback` keeps iteration as the primary path and uses the
        // forwarders only when the network cannot reach authoritative servers.
        match forward {
            Some(zone)
                if zone.forward_fallback && !forward_only && is_reachability_error(&error) =>
            {
                // One warning per client query is actionable; validator and
                // NS-address subqueries would otherwise repeat it many times.
                if context.validating || context.depth > 0 {
                    debug!(
                        qname = %name,
                        zone = %zone.zone,
                        %error,
                        "iteration failed; falling back to forwarders"
                    );
                } else {
                    warn!(
                        qname = %name,
                        zone = %zone.zone,
                        %error,
                        "iteration failed; falling back to forwarders"
                    );
                }
                self.walk_forward(&name, qtype, &zone, &context).await
            }
            _ => Err(error),
        }
    }

    /// Return the most specific stub zone covering `name`.
    fn stub_zone(&self, name: &Name) -> Option<&StubZone> {
        self.config
            .stub_zones
            .iter()
            .filter(|zone| zone.zone.zone_of(name))
            .max_by_key(|zone| zone.zone.num_labels())
    }

    /// Walk delegations from either the cache, the root, or a stub zone.
    async fn iterate(
        &self,
        name: Name,
        qtype: RecordType,
        context: WalkContext<'_>,
        start: Option<(Name, Vec<ForwardServer>)>,
        no_cache: bool,
    ) -> Result<WalkAnswer, ResolveError> {
        // Reuse the closest cached delegation instead of walking from the
        // root again for every query. DS records live in the parent zone, so
        // a DS query must start from the delegation above the name rather than
        // from the child servers that may already be cached.
        let delegation_name = if qtype == RecordType::DS {
            name.base_name()
        } else {
            name.clone()
        };
        let mut stub_servers = None;
        let (mut servers, mut zone) = match start {
            Some((stub_zone, stub_start)) => match self.cached_delegation(&delegation_name) {
                Some((cached_zone, cached_servers))
                    if cached_zone.num_labels() >= stub_zone.num_labels()
                        && stub_zone.zone_of(&cached_zone) =>
                {
                    (self.ordered_servers(cached_servers), cached_zone)
                }
                _ => {
                    stub_servers = Some(stub_start);
                    (Vec::new(), stub_zone)
                }
            },
            None => match self.cached_delegation(&delegation_name) {
                Some((zone, servers)) => (self.ordered_servers(servers), zone),
                None => {
                    // The first iterative query primes the root delegation. This
                    // refreshes the built-in hints without delaying startup, and
                    // failures fall back to the current hint list.
                    if let Err(error) = self.prime_if_stale().await {
                        debug!(%error, "root priming failed; using current root hints");
                    }
                    (self.ordered_servers(self.root_servers()), Name::root())
                }
            },
        };

        // Minimise the client-facing walk only. Subqueries (NS addresses,
        // CNAME targets) and validator fetches use plain queries to avoid
        // amplification and to keep DS lookups at the parent. A stub server is
        // already authoritative for the whole zone, so there is nothing to
        // minimise.
        if stub_servers.is_none()
            && self.config.qname_minimization
            && context.depth == 0
            && !context.validating
        {
            match self
                .minimize(&name, qtype, &mut servers, &mut zone, &context)
                .await?
            {
                Minimized::Answer(message) => {
                    let records = message.answers.clone();
                    let mut answer = WalkAnswer::new(message);
                    answer.note(&records, Some(&zone));
                    return Ok(answer);
                }
                Minimized::Continue => {}
            }
        }

        for _ in 0..MAX_REFERRAL_ROUNDS {
            let mut response = if let Some(stub) = stub_servers.take() {
                self.query_stub_servers(&stub, &name, qtype, &context)
                    .await?
            } else {
                self.query_servers(&servers, &name, qtype, &context).await?
            };
            scrub::scrub_authorities(&mut response, &name);

            if response.metadata.response_code == ResponseCode::NXDomain {
                debug!(qname = %name, "authoritative NXDOMAIN");
                return Ok(WalkAnswer::new(
                    self.negative_message(name, qtype, response),
                ));
            }
            if scrub::is_negative(&response) {
                debug!(qname = %name, "authoritative NODATA");
                return Ok(WalkAnswer::new(
                    self.negative_message(name, qtype, response),
                ));
            }

            if let Some(answer) = self
                .answer_chain(&name, qtype, &response, context.clone(), Some(&zone))
                .await?
            {
                if !no_cache {
                    self.cache_answers(&answer.message, Some(&zone));
                }
                return Ok(answer);
            }

            let Some(referral) =
                scrub::extract_referral(&response, &name, &zone, self.config.harden_glue)
            else {
                return Err(ResolveError::NoNameservers);
            };

            if !referral.zone.zone_of(&name) {
                return Err(ResolveError::InvalidResponse(
                    "referral outside the query ancestry".to_owned(),
                ));
            }
            if referral.zone.num_labels() <= zone.num_labels() {
                return Err(ResolveError::InvalidResponse(
                    "referral did not advance the delegation".to_owned(),
                ));
            }

            debug!(
                qname = %name,
                zone = %referral.zone,
                nameservers = referral.nameservers.len(),
                glue = referral.glue.len(),
                "following delegation"
            );
            if !no_cache {
                self.cache_referral(&referral);
            }
            match self.referral_servers(&referral, &context).await {
                Ok(next) => servers = next,
                Err(error) => {
                    debug!(%error, zone = %referral.zone, "could not resolve delegated NS; staying put");
                }
            }
            zone = referral.zone;
        }

        Err(ResolveError::DepthExceeded)
    }

    /// Walk delegations one label at a time using NS queries (RFC 9156).
    async fn minimize(
        &self,
        qname: &Name,
        qtype: RecordType,
        servers: &mut Vec<SocketAddr>,
        zone: &mut Name,
        context: &WalkContext<'_>,
    ) -> Result<Minimized, ResolveError> {
        let mut suffixes = Vec::new();
        let mut current = qname.base_name();
        while current.num_labels() > 0 {
            suffixes.push(current.clone());
            current = current.base_name();
        }
        suffixes.reverse();

        for suffix in suffixes {
            if suffix.num_labels() <= zone.num_labels() {
                continue;
            }

            debug!(qname = %qname, step = %suffix, "QNAME minimisation step");

            let response = match self
                .query_servers(servers, &suffix, RecordType::NS, context)
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    // RFC 9156 permits falling back to the full query. This
                    // also covers unreachable servers and timeouts, which must
                    // not turn an otherwise answerable name into SERVFAIL.
                    debug!(step = %suffix, %error, "minimisation fell back to full query");
                    return Ok(Minimized::Continue);
                }
            };

            if response.metadata.response_code == ResponseCode::NXDomain {
                debug!(step = %suffix, "minimised query proved NXDOMAIN");
                return Ok(Minimized::Answer(self.negative_message(
                    qname.clone(),
                    qtype,
                    response,
                )));
            }

            let authoritative_ns = response
                .answers
                .iter()
                .any(|record| record.record_type() == RecordType::NS && record.name == suffix);
            if authoritative_ns {
                // The server returned the delegation in the answer section
                // (common in flat or proxied deployments). Use the NS set to
                // move to the child servers, resolving addresses if no glue
                // was provided.
                if let Some(referral) =
                    scrub::extract_referral(&response, qname, zone, self.config.harden_glue)
                {
                    debug!(
                        step = %suffix,
                        zone = %referral.zone,
                        nameservers = referral.nameservers.len(),
                        glue = referral.glue.len(),
                        "minimised answer delegation"
                    );
                    self.cache_referral(&referral);
                    match self.referral_servers(&referral, context).await {
                        Ok(next) => *servers = next,
                        Err(_) => {
                            debug!(step = %suffix, "could not resolve delegated NS; staying put");
                        }
                    }
                    *zone = referral.zone;
                } else {
                    *zone = suffix;
                }
                continue;
            }
            if !response.answers.is_empty() {
                // CNAME or DNAME at a delegation point: stop minimising.
                debug!(step = %suffix, "minimisation relaxed on alias answer");
                return Ok(Minimized::Continue);
            }

            if let Some(referral) =
                scrub::extract_referral(&response, &suffix, zone, self.config.harden_glue)
            {
                if !referral.zone.zone_of(qname) || referral.zone.num_labels() <= zone.num_labels()
                {
                    return Err(ResolveError::InvalidResponse(
                        "minimised referral did not advance".to_owned(),
                    ));
                }
                debug!(
                    step = %suffix,
                    zone = %referral.zone,
                    nameservers = referral.nameservers.len(),
                    glue = referral.glue.len(),
                    "minimised delegation"
                );
                self.cache_referral(&referral);
                *servers = self.referral_servers(&referral, context).await?;
                *zone = referral.zone;
                continue;
            }

            if self.config.qname_minimization_strict
                && suffix == *qname
                && scrub::is_negative(&response)
            {
                return Ok(Minimized::Answer(self.negative_message(
                    qname.clone(),
                    qtype,
                    response,
                )));
            }

            debug!(step = %suffix, "minimisation relaxed after NODATA");
            return Ok(Minimized::Continue);
        }

        Ok(Minimized::Continue)
    }

    /// Walk any CNAME chain, resolving the target when it is out of message.
    ///
    /// `zone` is the authoritative zone that answered `response`, when known.
    /// The owner-to-zone map it produces lets validation start at a real zone
    /// apex instead of probing DS at an alias.
    ///
    /// In-message targets are only trusted when `zone` owns them (RFC 2181
    /// §5.4.1). An authority for `evil.test` must not be able to append
    /// `victim.test A 6.6.6.6` (or an `NS` RRset) to a CNAME chain: those
    /// records would otherwise be cached and later used as a delegation. An
    /// out-of-bailiwick target is resolved through the normal walk instead.
    async fn answer_chain(
        &self,
        qname: &Name,
        qtype: RecordType,
        response: &Message,
        context: WalkContext<'_>,
        zone: Option<&Name>,
    ) -> Result<Option<WalkAnswer>, ResolveError> {
        if response.answers.is_empty() {
            return Ok(None);
        }

        let mut chain: Vec<Record> = Vec::new();
        let mut origins: HashMap<String, Name> = HashMap::new();
        let mut current = qname.clone();
        let mut seen = HashSet::new();

        for _ in 0..MAX_CNAME_CHAIN {
            if !seen.insert(current.to_ascii().to_lowercase()) {
                return Err(ResolveError::Cycle);
            }

            let direct = select_rrset(&response.answers, &current, qtype);
            if !direct.is_empty() {
                note_origins(&mut origins, &direct, zone);
                chain.extend(direct);
                return Ok(Some(WalkAnswer {
                    message: self.build_response(
                        qname,
                        qtype,
                        ResponseCode::NoError,
                        chain,
                        dnssec_authorities(response),
                        Vec::new(),
                    ),
                    origins,
                }));
            }

            let Some(target) = scrub::cname_target(response, &current) else {
                if chain.is_empty() {
                    // Answers exist but none belong to this query.
                    return Ok(None);
                }

                return self
                    .resolve_chain_target(qname, qtype, current, chain, origins, context)
                    .await
                    .map(Some);
            };

            // Bailiwick: only follow a target that the answering zone owns.
            // Otherwise the target must be resolved from the delegation tree;
            // records for it in this response are not authoritative.
            let in_bailiwick = zone.is_none_or(|zone| zone.zone_of(&target));

            if let Some(record) = response
                .answers
                .iter()
                .find(|record| record.record_type() == RecordType::CNAME && record.name == current)
            {
                note_origins(&mut origins, std::slice::from_ref(record), zone);
                chain.push(record.clone());
                let signatures = rrsigs_for(&response.answers, &current, RecordType::CNAME);
                note_origins(&mut origins, &signatures, zone);
                chain.extend(signatures);
            }

            if !in_bailiwick {
                debug!(
                    %current,
                    %target,
                    "CNAME target is outside the answering zone; resolving it separately"
                );
                return self
                    .resolve_chain_target(qname, qtype, target, chain, origins, context)
                    .await
                    .map(Some);
            }

            current = target;
        }

        Err(ResolveError::Cycle)
    }

    /// Finish a CNAME chain by resolving `target` through the normal walk.
    ///
    /// Used when the response has no record for the target, or when the target
    /// is outside the answering zone and its in-message records cannot be
    /// trusted.
    async fn resolve_chain_target(
        &self,
        qname: &Name,
        qtype: RecordType,
        target: Name,
        mut chain: Vec<Record>,
        mut origins: HashMap<String, Name>,
        context: WalkContext<'_>,
    ) -> Result<WalkAnswer, ResolveError> {
        let sub_context = WalkContext {
            depth: context.depth + 1,
            ..context.clone()
        };
        let WalkAnswer {
            message: sub,
            origins: sub_origins,
        } = self.resolve_inner(target, qtype, sub_context).await?;
        let authorities = dnssec_authorities(&sub);
        let rcode = sub.metadata.response_code;
        chain.extend(sub.answers);
        origins.extend(sub_origins);
        Ok(WalkAnswer {
            message: self.build_response(qname, qtype, rcode, chain, authorities, Vec::new()),
            origins,
        })
    }

    /// Return the most specific forward zone covering `name`.
    fn forward_zone(&self, name: &Name) -> Option<&ForwardZone> {
        self.config
            .forward_zones
            .iter()
            .filter(|zone| zone.zone.zone_of(name))
            .max_by_key(|zone| zone.zone.num_labels())
    }

    /// Resolve through a recursive forwarder.
    async fn walk_forward(
        &self,
        name: &Name,
        qtype: RecordType,
        forward: &ForwardZone,
        context: &WalkContext<'_>,
    ) -> Result<WalkAnswer, ResolveError> {
        let context = WalkContext {
            recursion_desired: true,
            // Subqueries for this answer already go to the forwarders; the
            // iteration-first fallback must not run again inside them.
            forward_only: true,
            // A validating resolver must receive the raw data so it can judge
            // it; a client that set CD is validating on its own.
            checking_disabled: context.checking_disabled || self.config.dnssec_validation,
            ..context.clone()
        };
        let mut last_error = None;

        for server in forward.servers.iter().take(MAX_SERVERS_PER_QUERY) {
            let mut response = match self.forward_exchange(server, name, qtype, &context).await {
                Ok(response) => response,
                Err(error) => {
                    trace!(addr = %server.addr, transport = ?server.transport, %error, "forwarder exchange failed");
                    last_error = Some(error);
                    continue;
                }
            };

            if matches!(
                response.metadata.response_code,
                ResponseCode::ServFail
                    | ResponseCode::Refused
                    | ResponseCode::NotImp
                    | ResponseCode::FormErr
            ) {
                debug!(
                    addr = %server.addr,
                    rcode = ?response.metadata.response_code,
                    "forwarder returned an error; trying the next one"
                );
                if let Some(infra) = &self.infra {
                    infra.record_failure(&server.addr);
                }
                last_error = Some(ResolveError::NoNameservers);
                continue;
            }

            scrub::scrub_authorities(&mut response, name);

            if response.metadata.response_code == ResponseCode::NXDomain
                || scrub::is_negative(&response)
            {
                return Ok(WalkAnswer::new(self.negative_message(
                    name.clone(),
                    qtype,
                    response,
                )));
            }

            if let Some(answer) = self
                .answer_chain(name, qtype, &response, context.clone(), None)
                .await?
            {
                // Forwarders are configured and trusted to have resolved and
                // scrubbed the response, so its answer RRsets may span zones.
                self.cache_answers(&answer.message, None);
                return Ok(answer);
            }

            debug!(addr = %server.addr, "forwarder returned no usable answer; trying the next one");
            last_error = Some(ResolveError::NoNameservers);
        }

        Err(last_error.unwrap_or(ResolveError::NoNameservers))
    }

    /// Send one query to a forwarder over the transport it selected.
    async fn forward_exchange(
        &self,
        server: &ForwardServer,
        name: &Name,
        qtype: RecordType,
        context: &WalkContext<'_>,
    ) -> Result<Message, ResolveError> {
        if server.transport == ForwardTransport::Plain {
            return self.exchange(server.addr, name, qtype, context).await;
        }
        if !context.budget.spend() {
            return Err(ResolveError::DepthExceeded);
        }

        // Encrypted transports already authenticate the server, so 0x20 case
        // randomisation and DNS cookies add nothing. RD follows the walk: set
        // for forward zones (recursive peers) and clear for stub zones
        // (authoritative peers).
        let mut query = self.build_query_with_cookies(
            name,
            qtype,
            server.addr,
            context.recursion_desired,
            context.dnssec_ok,
            false,
        );
        query.metadata.checking_disabled = context.checking_disabled;
        let wire =
            encode(&query).map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
        let timeout = remaining(context.deadline, TCP_TIMEOUT);
        if timeout.is_zero() {
            return Err(ResolveError::Timeout);
        }

        let response_wire =
            match server.transport {
                ForwardTransport::Tls => {
                    let client = self.tls.as_ref().ok_or_else(|| {
                        ResolveError::Io("TLS client is not configured".to_owned())
                    })?;
                    client
                        .send_recv(server.addr, server.tls_name.as_deref(), &wire, timeout)
                        .await
                        .map_err(|error| ResolveError::Io(error.to_string()))?
                }
                ForwardTransport::Https => {
                    let client = self.https.as_ref().ok_or_else(|| {
                        ResolveError::Io("HTTPS client is not configured".to_owned())
                    })?;
                    let host = server.tls_name.as_deref().ok_or_else(|| {
                        ResolveError::InvalidResponse("HTTPS forwarder has no hostname".to_owned())
                    })?;
                    let path = server.path.as_deref().unwrap_or("/dns-query");
                    client
                        .send_recv(server.addr, host, path, &wire, timeout)
                        .await
                        .map_err(|error| ResolveError::Io(error.to_string()))?
                }
                ForwardTransport::Plain => unreachable!("plain forwarders use exchange"),
            };

        let response = decode(&response_wire)
            .map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
        if !self.response_valid(
            &query,
            name,
            qtype,
            ResponseChecks {
                require_case: false,
                require_cookie: false,
            },
            &response,
            server.addr,
        ) {
            return Err(ResolveError::InvalidResponse(
                "forwarder response failed validation".to_owned(),
            ));
        }
        if response.metadata.truncation {
            return Err(ResolveError::InvalidResponse(
                "truncated encrypted forwarder response".to_owned(),
            ));
        }
        Ok(self.finish_response(response))
    }

    /// Query the configured servers of a stub zone. The transport may be
    /// plain DNS or encrypted, unlike referrals which are always plain.
    async fn query_stub_servers(
        &self,
        servers: &[ForwardServer],
        name: &Name,
        qtype: RecordType,
        context: &WalkContext<'_>,
    ) -> Result<Message, ResolveError> {
        if servers.is_empty() {
            return Err(ResolveError::NoNameservers);
        }
        let mut last_error = None;
        for server in servers.iter().take(MAX_SERVERS_PER_QUERY) {
            match self.forward_exchange(server, name, qtype, context).await {
                Ok(response) => {
                    if scrub::is_lame(&response) {
                        debug!(
                            addr = %server.addr,
                            rcode = ?response.metadata.response_code,
                            "stub server returned an unusable response"
                        );
                        last_error = Some(ResolveError::NoNameservers);
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    trace!(addr = %server.addr, %error, "stub exchange failed");
                    last_error = Some(error);
                }
            }
        }
        match last_error {
            Some(error @ ResolveError::InvalidResponse(_)) => Err(error),
            _ => Err(ResolveError::NoNameservers),
        }
    }

    async fn query_servers(
        &self,
        servers: &[SocketAddr],
        name: &Name,
        qtype: RecordType,
        context: &WalkContext<'_>,
    ) -> Result<Message, ResolveError> {
        if servers.is_empty() {
            return Err(ResolveError::NoNameservers);
        }

        let mut last_error = None;
        // Prefer servers that are not in a retry backoff window. If every
        // server is backed off, fail open and try them anyway rather than
        // turning a transient outage into a hard failure.
        let candidates: Vec<SocketAddr> = if let Some(infra) = &self.infra {
            let ready: Vec<SocketAddr> = servers
                .iter()
                .take(MAX_SERVERS_PER_QUERY)
                .copied()
                .filter(|server| !infra.is_backed_off(server))
                .collect();
            if ready.is_empty() {
                servers
                    .iter()
                    .take(MAX_SERVERS_PER_QUERY)
                    .copied()
                    .collect()
            } else {
                ready
            }
        } else {
            servers
                .iter()
                .take(MAX_SERVERS_PER_QUERY)
                .copied()
                .collect()
        };

        for server in &candidates {
            match self.exchange(*server, name, qtype, context).await {
                Ok(response) => {
                    if scrub::is_lame(&response) {
                        debug!(
                            %server,
                            rcode = ?response.metadata.response_code,
                            answers = response.answers.len(),
                            authorities = response.authorities.len(),
                            additionals = response.additionals.len(),
                            truncation = response.metadata.truncation,
                            "lame or unusable response"
                        );
                        if let Some(infra) = &self.infra {
                            if response.metadata.response_code == ResponseCode::NoError {
                                infra.mark_lame(server);
                            } else {
                                infra.record_failure(server);
                            }
                        }
                        last_error = Some(ResolveError::NoNameservers);
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    trace!(%server, %error, "upstream exchange failed");
                    last_error = Some(error);
                }
            }
        }

        // A total transport failure must not abort a minimised walk; callers
        // fall back to the full query. Keep protocol violations visible so
        // spoofed/garbled replies still surface as errors.
        match last_error {
            Some(error @ ResolveError::InvalidResponse(_)) => Err(error),
            _ => Err(ResolveError::NoNameservers),
        }
    }

    async fn exchange(
        &self,
        server: SocketAddr,
        name: &Name,
        qtype: RecordType,
        context: &WalkContext<'_>,
    ) -> Result<Message, ResolveError> {
        if !context.budget.spend() {
            return Err(ResolveError::DepthExceeded);
        }
        let caps = self.config.case_randomization
            && self
                .infra
                .as_ref()
                .is_none_or(|infra| infra.caps_supported(&server));
        let sent_name = if caps {
            randomize_case(name)
        } else {
            name.clone()
        };

        let mut query = self.build_query(
            &sent_name,
            qtype,
            server,
            context.recursion_desired,
            context.dnssec_ok,
        );
        query.metadata.checking_disabled = context.checking_disabled;
        let started = Instant::now();
        let response = self
            .udp_exchange_with_retry(server, &query, context.deadline)
            .await?;

        if !self.response_valid(
            &query,
            &sent_name,
            qtype,
            ResponseChecks {
                require_case: caps,
                require_cookie: self.config.cookies,
            },
            &response,
            server,
        ) {
            if !caps {
                return Err(ResolveError::InvalidResponse(
                    "response failed validation".to_owned(),
                ));
            }

            // The server does not echo QNAME case. Retry once in lowercase and
            // remember that this server cannot do DNS 0x20.
            debug!(%server, "0x20 case mismatch; retrying without case randomisation");
            if let Some(infra) = &self.infra {
                infra.mark_caps_unsupported(&server);
            }
            let plain = name.clone();
            let mut query = self.build_query(
                &plain,
                qtype,
                server,
                context.recursion_desired,
                context.dnssec_ok,
            );
            query.metadata.checking_disabled = context.checking_disabled;
            let response = self
                .udp_exchange_with_retry(server, &query, context.deadline)
                .await?;
            if !self.response_valid(
                &query,
                &plain,
                qtype,
                ResponseChecks {
                    require_case: false,
                    require_cookie: self.config.cookies,
                },
                &response,
                server,
            ) {
                return Err(ResolveError::InvalidResponse(
                    "response failed validation".to_owned(),
                ));
            }
            if let Some(infra) = &self.infra {
                infra.update_rtt(&server, started.elapsed());
            }
            return Ok(self.finish_response(response));
        }

        if response.metadata.truncation {
            debug!(%server, "truncated UDP response; retrying over TCP");
            let wire =
                encode(&query).map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
            let wire = self
                .tcp
                .send_recv(server, &wire, remaining(context.deadline, TCP_TIMEOUT))
                .await
                .map_err(|error| ResolveError::Io(error.to_string()))?;
            let response =
                decode(&wire).map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
            if !self.response_valid(
                &query,
                &sent_name,
                qtype,
                ResponseChecks {
                    require_case: caps,
                    require_cookie: self.config.cookies,
                },
                &response,
                server,
            ) {
                return Err(ResolveError::InvalidResponse(
                    "truncated response failed validation".to_owned(),
                ));
            }
            if let Some(infra) = &self.infra {
                infra.update_rtt(&server, started.elapsed());
            }
            return Ok(self.finish_response(response));
        }

        if let Some(infra) = &self.infra {
            infra.update_rtt(&server, started.elapsed());
        }
        Ok(self.finish_response(response))
    }

    async fn udp_exchange(
        &self,
        server: SocketAddr,
        query: &Message,
        deadline: Instant,
    ) -> Result<Message, ResolveError> {
        let timeout = remaining(deadline, UDP_TIMEOUT);
        if timeout.is_zero() {
            return Err(ResolveError::Timeout);
        }
        let wire =
            encode(query).map_err(|error| ResolveError::InvalidResponse(error.to_string()))?;
        let wire = self
            .udp
            .send_recv(server, &wire, timeout)
            .await
            .map_err(|error| ResolveError::Io(error.to_string()))?;
        decode(&wire).map_err(|error| ResolveError::InvalidResponse(error.to_string()))
    }

    /// UDP exchange with one retry after a timeout.
    ///
    /// The delay comes from the infrastructure cache's exponential backoff and
    /// is capped by both the resolution deadline and one second, so a slow or
    /// black-holed server cannot consume the whole query budget. Transport
    /// errors such as ECONNREFUSED are recorded but not retried.
    async fn udp_exchange_with_retry(
        &self,
        server: SocketAddr,
        query: &Message,
        deadline: Instant,
    ) -> Result<Message, ResolveError> {
        match self.udp_exchange(server, query, deadline).await {
            Ok(response) => Ok(response),
            Err(error @ ResolveError::Timeout) => {
                let Some(infra) = &self.infra else {
                    return Err(error);
                };
                infra.record_timeout(&server);
                let delay = infra
                    .backoff_remaining(&server)
                    .unwrap_or_default()
                    .min(remaining(deadline, Duration::from_secs(1)));
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                if Instant::now() >= deadline {
                    return Err(error);
                }
                let result = self.udp_exchange(server, query, deadline).await;
                if result.is_err() {
                    infra.record_timeout(&server);
                }
                result
            }
            Err(error) => {
                if let Some(infra) = &self.infra
                    && matches!(error, ResolveError::Io(_))
                {
                    infra.record_timeout(&server);
                }
                Err(error)
            }
        }
    }

    fn response_valid(
        &self,
        query: &Message,
        sent_name: &Name,
        qtype: RecordType,
        checks: ResponseChecks,
        response: &Message,
        server: SocketAddr,
    ) -> bool {
        if response.metadata.id != query.metadata.id
            || response.metadata.message_type != MessageType::Response
            || response.metadata.op_code != OpCode::Query
        {
            return false;
        }
        if !scrub::question_matches(sent_name, qtype, response, checks.require_case) {
            return false;
        }
        if checks.require_cookie
            && self.config.cookies
            && !self
                .cookies
                .validate_response(server, response.edns.as_ref())
        {
            debug!(%server, "DNS COOKIE mismatch; rejecting response");
            return false;
        }
        true
    }

    fn build_query(
        &self,
        name: &Name,
        qtype: RecordType,
        server: SocketAddr,
        recursion_desired: bool,
        dnssec_ok: bool,
    ) -> Message {
        self.build_query_with_cookies(name, qtype, server, recursion_desired, dnssec_ok, true)
    }

    fn build_query_with_cookies(
        &self,
        name: &Name,
        qtype: RecordType,
        server: SocketAddr,
        recursion_desired: bool,
        dnssec_ok: bool,
        cookies: bool,
    ) -> Message {
        let mut message = Message::new(rand::random(), MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = recursion_desired;
        message.queries.push(Query::query(name.clone(), qtype));

        let mut edns = Edns::new();
        edns.set_version(0);
        edns.set_max_payload(self.config.edns_payload);
        edns.set_dnssec_ok(dnssec_ok);
        if cookies && self.config.cookies {
            edns.options_mut().insert(self.cookies.option_for(server));
        }
        message.edns = Some(edns);
        message
    }

    fn finish_response(&self, mut response: Message) -> Message {
        // Never keep upstream EDNS state; the server adds its own OPT on the
        // way back to the client.
        response.edns = None;
        scrub::sanitize(&mut response, self.config.min_ttl, self.config.max_ttl);
        response
    }

    fn negative_message(&self, name: Name, qtype: RecordType, response: Message) -> Message {
        self.build_response(
            &name,
            qtype,
            response.metadata.response_code,
            Vec::new(),
            response.authorities,
            Vec::new(),
        )
    }

    fn build_response(
        &self,
        name: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
        additionals: Vec<Record>,
    ) -> Message {
        let mut message = Message::new(0, MessageType::Response, OpCode::Query);
        message.metadata.recursion_available = true;
        message.metadata.response_code = rcode;
        message.queries.push(Query::query(name.clone(), qtype));
        message.answers = answers;
        message.authorities = authorities;
        message.additionals = additionals;
        message
    }

    fn root_servers(&self) -> Vec<SocketAddr> {
        if let Some(pinned) = &self.config.root_servers {
            return pinned.clone();
        }
        {
            let state = self
                .prime_state
                .read()
                .unwrap_or_else(|error| error.into_inner());
            if !state.servers.is_empty() {
                return state.servers.clone();
            }
        }
        self.config
            .bootstrap_servers
            .clone()
            .unwrap_or_else(root_hints)
    }

    /// Refresh the root delegation if the last success is stale.
    ///
    /// Priming is skipped when `root_servers` pins a private root set. Failed
    /// attempts are retried at most once per minute so a broken network cannot
    /// turn every query into a burst of root probes.
    pub async fn prime_if_stale(&self) -> Result<(), ResolveError> {
        if self.config.root_servers.is_some() {
            return Ok(());
        }
        {
            let state = self
                .prime_state
                .read()
                .unwrap_or_else(|error| error.into_inner());
            if state
                .last_success
                .is_some_and(|at| at.elapsed() < ROOT_PRIME_INTERVAL)
            {
                return Ok(());
            }
            if state
                .last_attempt
                .is_some_and(|at| at.elapsed() < ROOT_PRIME_RETRY)
            {
                return Ok(());
            }
        }
        self.prime().await
    }

    /// Query the current root servers for the root NS set and its glue.
    ///
    /// The learned addresses replace the built-in hints. Priming never
    /// recurses through the iterator: it sends one NS query for the root and
    /// reads the NS targets plus A/AAAA glue from the reply.
    pub async fn prime(&self) -> Result<(), ResolveError> {
        if self.config.root_servers.is_some() {
            return Ok(());
        }

        let _guard = self.prime_lock.lock().await;

        // Another caller may have completed priming while we waited.
        {
            let state = self
                .prime_state
                .read()
                .unwrap_or_else(|error| error.into_inner());
            if state
                .last_success
                .is_some_and(|at| at.elapsed() < ROOT_PRIME_INTERVAL)
            {
                return Ok(());
            }
        }
        {
            let mut state = self
                .prime_state
                .write()
                .unwrap_or_else(|error| error.into_inner());
            state.last_attempt = Some(Instant::now());
        }

        let seeds = self
            .config
            .bootstrap_servers
            .clone()
            .unwrap_or_else(root_hints);
        let name = Name::root();
        let deadline = Instant::now() + ROOT_PRIME_TIMEOUT;
        let mut last_error = None;

        for server in self
            .ordered_servers(seeds)
            .into_iter()
            .take(MAX_SERVERS_PER_QUERY)
        {
            if Instant::now() >= deadline {
                break;
            }
            let query =
                self.build_query_with_cookies(&name, RecordType::NS, server, false, false, false);
            let response = match self.udp_exchange(server, &query, deadline).await {
                Ok(response) => response,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };
            if !self.response_valid(
                &query,
                &name,
                RecordType::NS,
                ResponseChecks {
                    require_case: false,
                    require_cookie: false,
                },
                &response,
                server,
            ) {
                last_error = Some(ResolveError::InvalidResponse(
                    "root priming response failed validation".to_owned(),
                ));
                continue;
            }

            let servers = self.root_addresses(&response);
            if servers.is_empty() {
                last_error = Some(ResolveError::InvalidResponse(
                    "root priming response had no NS addresses".to_owned(),
                ));
                continue;
            }

            {
                let mut state = self
                    .prime_state
                    .write()
                    .unwrap_or_else(|error| error.into_inner());
                state.servers = servers.clone();
                state.last_success = Some(Instant::now());
            }
            info!(servers = servers.len(), "primed root delegation");
            return Ok(());
        }

        Err(last_error.unwrap_or(ResolveError::NoNameservers))
    }

    /// Extract NS targets and matching A/AAAA glue from a root NS response.
    fn root_addresses(&self, response: &Message) -> Vec<SocketAddr> {
        let root = Name::root();
        let mut names = HashSet::new();
        for record in response.answers.iter().chain(response.authorities.iter()) {
            if record.record_type() != RecordType::NS || record.name != root {
                continue;
            }
            if let RData::NS(target) = &record.data {
                names.insert(target.0.to_ascii().to_lowercase());
            }
        }
        if names.is_empty() {
            return Vec::new();
        }

        let mut servers = Vec::new();
        for record in response.additionals.iter().chain(response.answers.iter()) {
            let owner = record.name.to_ascii().to_lowercase();
            if !names.contains(&owner) {
                continue;
            }
            match &record.data {
                RData::A(address) => servers.push(SocketAddr::new(
                    IpAddr::V4(address.0),
                    self.config.nameserver_port,
                )),
                RData::AAAA(address) => servers.push(SocketAddr::new(
                    IpAddr::V6(address.0),
                    self.config.nameserver_port,
                )),
                _ => {}
            }
        }
        servers.sort_unstable();
        servers.dedup();
        servers.retain(|server| self.address_allowed(server));
        servers
    }

    fn ordered_servers(&self, servers: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let mut servers: Vec<SocketAddr> = servers
            .into_iter()
            .filter(|server| self.address_allowed(server))
            .collect();
        servers.dedup();
        if let Some(infra) = &self.infra {
            servers.sort_by_key(|server| {
                let entry = infra.get(server);
                (
                    entry.as_ref().is_some_and(|entry| entry.lame),
                    infra.is_backed_off(server),
                    entry
                        .map(|entry| entry.rtt)
                        .unwrap_or(Duration::from_millis(100)),
                )
            });
        }
        servers
    }

    /// Whether outgoing queries may use this address family.
    ///
    /// `do_ip4`/`do_ip6` disable the transport, not just the listeners, so a
    /// host without working IPv6 does not spend its budget on unreachable
    /// upstreams.
    fn family_allowed(&self, addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(_) => self.config.allow_ipv4,
            IpAddr::V6(_) => self.config.allow_ipv6,
        }
    }

    fn address_allowed(&self, addr: &SocketAddr) -> bool {
        self.family_allowed(addr.ip())
    }

    /// Address record types that may be used to reach upstream servers.
    fn address_qtypes(&self) -> &'static [RecordType] {
        match (self.config.allow_ipv4, self.config.allow_ipv6) {
            (true, true) => &[RecordType::A, RecordType::AAAA],
            (true, false) => &[RecordType::A],
            (false, true) => &[RecordType::AAAA],
            (false, false) => &[],
        }
    }

    async fn referral_servers(
        &self,
        referral: &Referral,
        context: &WalkContext<'_>,
    ) -> Result<Vec<SocketAddr>, ResolveError> {
        let mut addresses: Vec<IpAddr> = scrub::addresses(&referral.glue);
        let glue_names: HashSet<String> = referral
            .glue
            .iter()
            .map(|record| record.name.to_ascii().to_lowercase())
            .collect();

        for nameserver in referral.nameservers.iter().take(MAX_NS_ADDRESS_PROBES) {
            if addresses.len() >= 4 {
                break;
            }
            let key = nameserver.to_ascii().to_lowercase();
            if glue_names.contains(&key) {
                continue;
            }

            let cached = self.cached_addresses(nameserver);
            if !cached.is_empty() {
                addresses.extend(cached);
                continue;
            }

            for qtype in self.address_qtypes().iter().copied() {
                let sub_context = WalkContext {
                    depth: context.depth + 1,
                    ancestors: context.ancestors,
                    deadline: context.deadline,
                    budget: Arc::clone(&context.budget),
                    recursion_desired: context.recursion_desired,
                    dnssec_ok: context.dnssec_ok,
                    validating: context.validating,
                    checking_disabled: context.checking_disabled,
                    forward_only: false,
                };
                let Ok(answer) = self
                    .resolve_inner(nameserver.clone(), qtype, sub_context)
                    .await
                else {
                    continue;
                };
                let found = scrub::addresses(&answer.message.answers);
                let had_found = !found.is_empty();
                addresses.extend(found);
                if had_found {
                    break;
                }
            }
        }

        addresses.sort_unstable();
        addresses.dedup();
        addresses.retain(|address| self.family_allowed(*address));
        let servers: Vec<SocketAddr> = addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, self.config.nameserver_port))
            .collect();
        if servers.is_empty() {
            return Err(ResolveError::NoNameservers);
        }
        Ok(self.ordered_servers(servers))
    }

    /// Find the deepest cached NS delegation covering `qname`.
    fn cached_delegation(&self, qname: &Name) -> Option<(Name, Vec<SocketAddr>)> {
        let cache = self.rrsets.as_ref()?;
        let mut candidate = qname.clone();
        loop {
            if let Some(entry) = cache.get(&candidate, RecordType::NS) {
                let mut addresses = Vec::new();
                for record in &entry.records {
                    let RData::NS(target) = &record.data else {
                        continue;
                    };
                    for qtype in self.address_qtypes().iter().copied() {
                        if let Some(addresses_entry) = cache.get(&target.0, qtype) {
                            addresses.extend(scrub::addresses(&addresses_entry.records));
                        }
                    }
                }
                addresses.sort_unstable();
                addresses.dedup();
                if !addresses.is_empty() {
                    let servers = addresses
                        .into_iter()
                        .map(|address| SocketAddr::new(address, self.config.nameserver_port))
                        .collect();
                    return Some((candidate, servers));
                }
            }
            if candidate.num_labels() == 0 {
                break;
            }
            candidate = candidate.base_name();
        }
        None
    }

    fn cached_addresses(&self, name: &Name) -> Vec<IpAddr> {
        let Some(cache) = &self.rrsets else {
            return Vec::new();
        };
        let mut addresses = Vec::new();
        for qtype in self.address_qtypes().iter().copied() {
            if let Some(entry) = cache.get(name, qtype) {
                addresses.extend(scrub::addresses(&entry.records));
            }
        }
        addresses
    }

    fn cache_referral(&self, referral: &Referral) {
        let Some(cache) = &self.rrsets else {
            return;
        };

        if !referral.nameserver_records.is_empty() {
            let ttl = min_ttl(&referral.nameserver_records);
            cache.insert(
                referral.zone.clone(),
                RecordType::NS,
                referral.nameserver_records.clone(),
                Duration::from_secs(u64::from(ttl)),
            );
        }

        for (name, qtype, records, ttl) in group_rrsets(&referral.glue) {
            cache.insert(name, qtype, records, Duration::from_secs(u64::from(ttl)));
        }
    }

    /// Cache answer RRsets, optionally restricted to the answering zone.
    ///
    /// RFC 2181 §5.4.1: only data at or below the zone that answered is
    /// authoritative. Restricting writes here keeps an authority for one zone
    /// from injecting NS or address RRsets for a foreign name into the shared
    /// RRset cache, where delegation selection would later trust them.
    ///
    /// `zone` is `None` for recursive forwarders, whose answers are already
    /// trusted to have been resolved and scrubbed on our behalf.
    fn cache_answers(&self, message: &Message, zone: Option<&Name>) {
        let Some(cache) = &self.rrsets else {
            return;
        };
        for (name, qtype, records, ttl) in group_rrsets(&message.answers) {
            if let Some(zone) = zone
                && !zone.zone_of(&name)
            {
                debug!(
                    name = %name,
                    zone = %zone,
                    "not caching an out-of-bailiwick answer RRset"
                );
                continue;
            }
            cache.insert(name, qtype, records, Duration::from_secs(u64::from(ttl)));
        }
    }
}

impl Default for IteratorResolver {
    fn default() -> Self {
        Self::new().expect("failed to create resolver")
    }
}

/// Select an RRset and the signatures that cover it.
fn select_rrset(answers: &[Record], name: &Name, qtype: RecordType) -> Vec<Record> {
    let mut selected = Vec::new();
    for record in answers {
        if &record.name != name {
            continue;
        }
        if qtype == RecordType::ANY {
            selected.push(record.clone());
            continue;
        }
        if record.record_type() == qtype {
            selected.push(record.clone());
            continue;
        }
        if record.record_type() == RecordType::RRSIG
            && rrsig_of(record).is_some_and(|sig| sig.input().type_covered == qtype)
        {
            selected.push(record.clone());
        }
    }
    selected
}

/// Signatures covering one RRset at `name`.
fn rrsigs_for(answers: &[Record], name: &Name, covered: RecordType) -> Vec<Record> {
    answers
        .iter()
        .filter(|record| {
            &record.name == name
                && record.record_type() == RecordType::RRSIG
                && rrsig_of(record).is_some_and(|sig| sig.input().type_covered == covered)
        })
        .cloned()
        .collect()
}

/// Authority records that carry DNSSEC proofs or negative-answer metadata.
fn dnssec_authorities(message: &Message) -> Vec<Record> {
    message
        .authorities
        .iter()
        .filter(|record| {
            matches!(
                record.record_type(),
                RecordType::SOA
                    | RecordType::NSEC
                    | RecordType::NSEC3
                    | RecordType::RRSIG
                    | RecordType::DS
                    | RecordType::DNSKEY
            )
        })
        .cloned()
        .collect()
}

/// Remove DNSSEC metadata from a response for a client that did not set DO.
fn strip_dnssec_records(message: &mut Message, qtype: RecordType) {
    let keep = |record: &Record| match record.record_type() {
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3 | RecordType::NSEC3PARAM => false,
        RecordType::DNSKEY | RecordType::DS => record.record_type() == qtype,
        _ => true,
    };
    message.answers.retain(keep);
    message.authorities.retain(keep);
    message.additionals.retain(keep);
}

fn remaining(deadline: Instant, default: Duration) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(default)
}

fn min_ttl(records: &[Record]) -> u32 {
    records.iter().map(|record| record.ttl).min().unwrap_or(0)
}

fn group_rrsets(records: &[Record]) -> Vec<(Name, RecordType, Vec<Record>, u32)> {
    let mut grouped: HashMap<(String, RecordType), (Name, Vec<Record>, u32)> = HashMap::new();
    for record in records {
        let key = (record.name.to_ascii().to_lowercase(), record.record_type());
        let entry = grouped
            .entry(key)
            .or_insert_with(|| (record.name.clone(), Vec::new(), record.ttl));
        entry.1.push(record.clone());
        entry.2 = entry.2.min(record.ttl);
    }
    grouped
        .into_values()
        .map(|(name, records, ttl)| {
            let qtype = records[0].record_type();
            (name, qtype, records, ttl)
        })
        .collect()
}

/// Randomise letter case in every label (DNS 0x20).
fn randomize_case(name: &Name) -> Name {
    let ascii = name.to_ascii();
    let mut rng = rand::rng();
    let mut mixed = String::with_capacity(ascii.len());
    let mut has_upper = false;
    for character in ascii.chars() {
        if character.is_ascii_alphabetic() && rng.random_bool(0.5) {
            has_upper = true;
            mixed.push(character.to_ascii_uppercase());
        } else {
            mixed.push(character);
        }
    }
    if !has_upper {
        // Guarantee at least one flipped bit so the response check is useful.
        if let Some(index) = mixed
            .char_indices()
            .find(|(_, character)| character.is_ascii_alphabetic())
            .map(|(index, _)| index)
        {
            mixed.replace_range(index..=index, &mixed[index..=index].to_ascii_uppercase());
        }
    }
    Name::from_ascii(&mixed).unwrap_or_else(|_| name.clone())
}

#[cfg(test)]
mod tests {
    use dns_cache::{InfraCache, RrsetCache};
    use dns_proto::{Name, RecordType};

    use super::{IteratorConfig, IteratorResolver, group_rrsets, randomize_case};
    use dns_proto::{RData, Record};

    #[test]
    fn randomisation_preserves_name() {
        let name = Name::from_ascii("www.example.com.").expect("name");
        for _ in 0..20 {
            let mixed = randomize_case(&name);
            assert!(mixed.to_ascii().eq_ignore_ascii_case("www.example.com."));
        }
    }

    #[test]
    fn groups_records_into_rrsets() {
        let name = Name::from_ascii("example.com.").expect("name");
        let records = vec![
            Record::from_rdata(
                name.clone(),
                60,
                RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1).into()),
            ),
            Record::from_rdata(
                name,
                30,
                RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2).into()),
            ),
        ];
        let grouped = group_rrsets(&records);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].1, RecordType::A);
        assert_eq!(grouped[0].2.len(), 2);
        assert_eq!(grouped[0].3, 30);
    }

    #[test]
    fn orders_backed_off_servers_last() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let resolver =
            IteratorResolver::with_config(IteratorConfig::default(), None).expect("resolver");
        let infra = std::sync::Arc::new(InfraCache::new(16));
        let resolver = resolver.with_caches(
            std::sync::Arc::new(RrsetCache::new(16)),
            std::sync::Arc::clone(&infra),
        );

        let failing = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let healthy = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 53);
        infra.record_timeout(&failing);

        let ordered = resolver.ordered_servers(vec![failing, healthy]);
        assert_eq!(ordered[0], healthy, "backed-off servers must be tried last");
        assert_eq!(ordered[1], failing);
    }

    #[test]
    fn skips_disabled_address_families() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);

        let config = IteratorConfig {
            allow_ipv6: false,
            ..IteratorConfig::default()
        };
        let resolver = IteratorResolver::with_config(config, None).expect("resolver");
        assert_eq!(
            resolver.ordered_servers(vec![v4, v6]),
            vec![v4],
            "do_ip6 = false must drop IPv6 upstreams"
        );

        let config = IteratorConfig {
            allow_ipv4: false,
            ..IteratorConfig::default()
        };
        let resolver = IteratorResolver::with_config(config, None).expect("resolver");
        assert_eq!(
            resolver.ordered_servers(vec![v4, v6]),
            vec![v6],
            "do_ip4 = false must drop IPv4 upstreams"
        );
    }
}
