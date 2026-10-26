use std::collections::BTreeSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use dns_proto::Name;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ConfigError;

/// Default DNS service port.
pub const DEFAULT_PORT: u16 = 53;
/// Default `unbound-control` compatible port.
pub const DEFAULT_CONTROL_PORT: u16 = 8953;

/// Root configuration object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Global resolver settings.
    pub server: ServerConfig,
    /// Forward zones, evaluated before iterative resolution.
    pub forward_zones: Vec<ForwardZoneConfig>,
    /// Stub zones, resolved iteratively starting from the listed authorities.
    pub stub_zones: Vec<StubZoneConfig>,
    /// Authority zones served from a local zone file.
    pub auth_zones: Vec<AuthZoneConfig>,
    /// Global local zones.
    pub local_zones: Vec<LocalZoneConfig>,
    /// Global `local-data` records in zone-file syntax.
    pub local_data: Vec<String>,
    /// Client-dependent overrides.
    pub views: Vec<ViewConfig>,
    /// Remote control settings.
    pub remote_control: RemoteControlConfig,
}

impl Config {
    /// Validate cross-field invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let server = &self.server;

        if server.interfaces.is_empty() {
            return Err(ConfigError::Validation(
                "at least one interface must be configured".to_owned(),
            ));
        }
        if server.port == 0 {
            return Err(ConfigError::Validation(
                "server port must be between 1 and 65535".to_owned(),
            ));
        }
        if server.num_threads == 0 || server.num_threads > 1024 {
            return Err(ConfigError::Validation(
                "num-threads must be between 1 and 1024".to_owned(),
            ));
        }
        if !server.do_ip4 && !server.do_ip6 {
            return Err(ConfigError::Validation(
                "at least one of do-ip4 or do-ip6 must be enabled".to_owned(),
            ));
        }
        if !server.do_udp && !server.do_tcp {
            return Err(ConfigError::Validation(
                "at least one of do-udp or do-tcp must be enabled".to_owned(),
            ));
        }
        if server.username.as_deref().is_some_and(str::is_empty) {
            return Err(ConfigError::Validation(
                "username must not be empty when set".to_owned(),
            ));
        }
        if server.edns_buffer_size < 512 || server.max_udp_size < 512 {
            return Err(ConfigError::Validation(
                "edns-buffer-size and max-udp-size must be at least 512".to_owned(),
            ));
        }
        if server.cache_min_ttl > server.cache_max_ttl {
            return Err(ConfigError::Validation(
                "cache-min-ttl must not exceed cache-max-ttl".to_owned(),
            ));
        }
        if server.min_ttl > server.max_ttl {
            return Err(ConfigError::Validation(
                "min-ttl must not exceed max-ttl".to_owned(),
            ));
        }
        if server.max_concurrent_queries_per_client == 0 {
            return Err(ConfigError::Validation(
                "max-concurrent-queries-per-client must be at least 1".to_owned(),
            ));
        }
        match (&server.tls_service_key, &server.tls_service_pem) {
            (Some(_), Some(_)) => {}
            (None, None) => {}
            _ => {
                return Err(ConfigError::Validation(
                    "tls-service-key and tls-service-pem must be set together".to_owned(),
                ));
            }
        }
        if server.tls_port == 0 || server.https_port == 0 {
            return Err(ConfigError::Validation(
                "tls-port and https-port must be between 1 and 65535".to_owned(),
            ));
        }
        if server.tls_port == server.https_port {
            return Err(ConfigError::Validation(
                "tls-port and https-port must differ".to_owned(),
            ));
        }
        if !server.http_endpoint.starts_with('/') {
            return Err(ConfigError::Validation(
                "http-endpoint must start with '/'".to_owned(),
            ));
        }

        let mut zone_names = BTreeSet::new();
        for zone in &self.forward_zones {
            zone.validate()?;
            let name = Name::from_ascii(&zone.name).map_err(|error| {
                ConfigError::Validation(format!(
                    "invalid forward-zone name {:?}: {error}",
                    zone.name
                ))
            })?;
            let canonical = name.to_ascii().to_ascii_lowercase();
            if !zone_names.insert(canonical.clone()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate forward-zone for {canonical}"
                )));
            }
        }

        let mut stub_names = BTreeSet::new();
        for zone in &self.stub_zones {
            zone.validate()?;
            if !stub_names.insert(zone.canonical_name()?) {
                return Err(ConfigError::Validation(format!(
                    "duplicate stub-zone for {:?}",
                    zone.name
                )));
            }
        }

        let mut auth_names = BTreeSet::new();
        for zone in &self.auth_zones {
            zone.validate()?;
            if !auth_names.insert(zone.canonical_name()?) {
                return Err(ConfigError::Validation(format!(
                    "duplicate auth-zone for {:?}",
                    zone.name
                )));
            }
        }

        let mut local_names = BTreeSet::new();
        for zone in &self.local_zones {
            zone.validate()?;
            if !local_names.insert(zone.canonical_name()?) {
                return Err(ConfigError::Validation(format!(
                    "duplicate local-zone for {:?}",
                    zone.name
                )));
            }
        }
        for data in &self.local_data {
            validate_local_data(data)?;
        }

        let mut view_names = BTreeSet::new();
        for view in &self.views {
            view.validate()?;
            if !view_names.insert(view.name.to_ascii_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "duplicate view {:?}",
                    view.name
                )));
            }
        }
        for mapping in &self.server.access_control_view {
            if !view_names.contains(&mapping.view.to_ascii_lowercase()) {
                return Err(ConfigError::Validation(format!(
                    "access-control-view refers to unknown view {:?}",
                    mapping.view
                )));
            }
        }

        if self.remote_control.enabled {
            if self.remote_control.interfaces.is_empty() {
                return Err(ConfigError::Validation(
                    "control-interface must be set when control-enable is enabled".to_owned(),
                ));
            }
            if self.remote_control.port == 0 {
                return Err(ConfigError::Validation(
                    "control-port must be between 1 and 65535".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

/// Global resolver settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    /// Addresses to listen on.
    pub interfaces: Vec<ListenAddress>,
    /// Default service port for interfaces without an explicit port.
    pub port: u16,
    /// Log verbosity, 0-5.
    pub verbosity: u8,
    /// Number of worker threads.
    pub num_threads: usize,
    /// Detach from the terminal.
    pub do_daemonize: bool,
    /// User to drop privileges to.
    pub username: Option<String>,
    /// Directory to chroot into.
    pub chroot: Option<PathBuf>,
    /// Working directory.
    pub directory: Option<PathBuf>,
    /// Log file path. Empty or unset means stderr/syslog.
    pub logfile: Option<PathBuf>,
    /// PID file path.
    pub pidfile: Option<PathBuf>,
    /// Send logs to syslog.
    pub use_syslog: bool,
    /// Enable IPv4 service.
    pub do_ip4: bool,
    /// Enable IPv6 service.
    pub do_ip6: bool,
    /// Enable UDP service.
    pub do_udp: bool,
    /// Enable TCP service.
    pub do_tcp: bool,
    /// Source addresses for outgoing queries.
    pub outgoing_interfaces: Vec<IpAddr>,
    /// Client access policy.
    pub access_control: Vec<AccessControl>,
    /// Map client networks to named views (`access-control-view`).
    pub access_control_view: Vec<AccessControlView>,
    /// Reject out-of-bailiwick glue records from referrals.
    pub harden_glue: bool,
    /// Validate DNSSEC signatures and denial proofs.
    pub dnssec_validation: bool,
    /// Reject unsigned data in signed zones (used by the DNSSEC validator).
    pub harden_dnssec_stripped: bool,
    /// Return bogus data instead of SERVFAIL (validation still runs).
    pub val_permissive_mode: bool,
    /// Strip unvalidated additional-section data from responses.
    pub val_clean_additional: bool,
    /// Inline trust anchors in zone-file syntax (`name DS ...` or `name DNSKEY ...`).
    pub trust_anchor: Vec<String>,
    /// File containing trust anchors in zone-file syntax.
    pub trust_anchor_file: Option<PathBuf>,
    /// File used for RFC 5011 automatic trust-anchor maintenance.
    pub auto_trust_anchor_file: Option<PathBuf>,
    /// Minimise QNAMEs sent to authoritative servers (RFC 9156).
    pub qname_minimisation: bool,
    /// Use strict minimisation (no relaxation on NODATA/CNAME).
    pub qname_minimisation_strict: bool,
    /// Randomise the case of outgoing QNAMEs (DNS 0x20).
    pub use_caps_for_id: bool,
    /// EDNS payload size advertised to upstream servers.
    pub edns_buffer_size: u16,
    /// Maximum UDP response size sent to clients.
    pub max_udp_size: u16,
    /// Maximum TTL for cached records.
    pub cache_max_ttl: u32,
    /// Minimum TTL for cached records.
    pub cache_min_ttl: u32,
    /// Refresh cache entries shortly before they expire.
    pub prefetch: bool,
    /// Serve expired cache entries while refreshing them.
    pub serve_expired: bool,
    /// Seconds an expired entry stays available for serve-expired.
    ///
    /// Zero selects the built-in 30 second window.
    pub serve_expired_ttl: u32,
    /// TTL attached to a serve-expired reply.
    pub serve_expired_reply_ttl: u32,
    /// Maximum TTL accepted from upstream servers.
    pub max_ttl: u32,
    /// Minimum TTL accepted from upstream servers.
    pub min_ttl: u32,
    /// Responses per second allowed per client IP. Zero disables rate limiting.
    pub ratelimit: u32,
    /// Send a truncated response for every Nth rate-limited query. Zero drops all.
    pub ratelimit_slip: u32,
    /// Maximum in-flight queries per client IP.
    pub max_concurrent_queries_per_client: usize,
    /// Maximum concurrent plain-TCP and DoT connections per worker thread.
    ///
    /// The server enforces `incoming_num_tcp * num_threads` connections across
    /// all TCP and DoT listeners. Zero disables both listeners. DoH keeps its
    /// own HTTP connection management.
    pub incoming_num_tcp: usize,
    /// PEM-encoded private key for downstream DNS-over-TLS and DNS-over-HTTPS.
    pub tls_service_key: Option<PathBuf>,
    /// PEM-encoded certificate chain for downstream DNS-over-TLS and DNS-over-HTTPS.
    pub tls_service_pem: Option<PathBuf>,
    /// Port on which configured interfaces serve DNS-over-TLS.
    pub tls_port: u16,
    /// Port on which configured interfaces serve DNS-over-HTTPS.
    pub https_port: u16,
    /// HTTP path used by the DNS-over-HTTPS listener.
    pub http_endpoint: String,
    /// PEM bundle used to verify upstream DNS-over-TLS and DNS-over-HTTPS servers.
    pub tls_cert_bundle: Option<PathBuf>,
    /// Trust the system (webpki) roots for upstream encrypted transports.
    pub tls_use_system_ca: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            interfaces: vec![
                ListenAddress::new(IpAddr::V4(Ipv4Addr::LOCALHOST), None),
                ListenAddress::new(IpAddr::V6(Ipv6Addr::LOCALHOST), None),
            ],
            port: DEFAULT_PORT,
            verbosity: 1,
            num_threads: 1,
            do_daemonize: false,
            username: None,
            chroot: None,
            directory: None,
            logfile: None,
            pidfile: None,
            use_syslog: false,
            do_ip4: true,
            do_ip6: true,
            do_udp: true,
            do_tcp: true,
            outgoing_interfaces: Vec::new(),
            access_control: default_access_control(),
            access_control_view: Vec::new(),
            harden_glue: true,
            dnssec_validation: true,
            harden_dnssec_stripped: true,
            val_permissive_mode: false,
            val_clean_additional: true,
            trust_anchor: Vec::new(),
            trust_anchor_file: None,
            auto_trust_anchor_file: None,
            qname_minimisation: true,
            qname_minimisation_strict: false,
            use_caps_for_id: true,
            edns_buffer_size: 1232,
            max_udp_size: 1232,
            cache_max_ttl: 86_400,
            cache_min_ttl: 0,
            prefetch: false,
            serve_expired: false,
            serve_expired_ttl: 0,
            serve_expired_reply_ttl: 30,
            max_ttl: 86_400,
            min_ttl: 0,
            ratelimit: 0,
            ratelimit_slip: 2,
            max_concurrent_queries_per_client: 64,
            incoming_num_tcp: 10,
            tls_service_key: None,
            tls_service_pem: None,
            tls_port: 853,
            https_port: 443,
            http_endpoint: "/dns-query".to_owned(),
            tls_cert_bundle: None,
            tls_use_system_ca: true,
        }
    }
}

fn default_access_control() -> Vec<AccessControl> {
    vec![
        AccessControl {
            network: IpNet::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8)
                .expect("static IPv4 CIDR is valid"),
            action: AccessAction::Allow,
        },
        AccessControl {
            network: IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)
                .expect("static IPv6 CIDR is valid"),
            action: AccessAction::Allow,
        },
        AccessControl {
            network: IpNet::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                .expect("static IPv4 CIDR is valid"),
            action: AccessAction::Refuse,
        },
        AccessControl {
            network: IpNet::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                .expect("static IPv6 CIDR is valid"),
            action: AccessAction::Refuse,
        },
    ]
}

/// A listening address, optionally with an explicit port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenAddress {
    /// IP address to bind.
    pub addr: IpAddr,
    /// Optional port override.
    pub port: Option<u16>,
}

impl ListenAddress {
    /// Create a listening address.
    pub const fn new(addr: IpAddr, port: Option<u16>) -> Self {
        Self { addr, port }
    }

    /// Resolve the effective socket address using the server's default port.
    pub fn socket_addr(self, default_port: u16) -> SocketAddr {
        SocketAddr::new(self.addr, self.port.unwrap_or(default_port))
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.port {
            Some(port) => write!(formatter, "{}@{port}", self.addr),
            None => write!(formatter, "{}", self.addr),
        }
    }
}

impl FromStr for ListenAddress {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty interface address".to_owned());
        }

        let (address, port) = match value.rsplit_once('@') {
            Some((address, port)) => (address, Some(parse_port(port)?)),
            None => (value, None),
        };
        let addr = IpAddr::from_str(address).map_err(|_| {
            format!("invalid interface address {address:?}; interface names are not supported yet")
        })?;
        Ok(Self { addr, port })
    }
}

impl Serialize for ListenAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ListenAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Access-control action for a client network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessAction {
    /// Allow recursive service.
    Allow,
    /// Drop the query without a response.
    Deny,
    /// Respond with REFUSED.
    Refuse,
    /// Allow access and permit cache snooping.
    AllowSnoop,
    /// Allow only queries for locally served data.
    DenyNonLocal,
    /// Respond REFUSED outside locally served data.
    RefuseNonLocal,
}

impl fmt::Display for AccessAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Refuse => "refuse",
            Self::AllowSnoop => "allow_snoop",
            Self::DenyNonLocal => "deny_non_local",
            Self::RefuseNonLocal => "refuse_non_local",
        };
        formatter.write_str(value)
    }
}

impl FromStr for AccessAction {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            "refuse" => Ok(Self::Refuse),
            "allow_snoop" => Ok(Self::AllowSnoop),
            "deny_non_local" => Ok(Self::DenyNonLocal),
            "refuse_non_local" => Ok(Self::RefuseNonLocal),
            _ => Err(format!("unknown access-control action {value:?}")),
        }
    }
}

/// A client network and its access policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessControl {
    /// Client network.
    pub network: IpNet,
    /// Action applied to matching clients.
    pub action: AccessAction,
}

impl fmt::Display for AccessControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.network, self.action)
    }
}

impl FromStr for AccessControl {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split_whitespace();
        let network = parts
            .next()
            .ok_or_else(|| "missing network in access-control entry".to_owned())?;
        let action = parts
            .next()
            .ok_or_else(|| "missing action in access-control entry".to_owned())?;
        if parts.next().is_some() {
            return Err(format!(
                "unexpected trailing data in access-control entry {value:?}"
            ));
        }

        Ok(Self {
            network: IpNet::from_str(network)
                .map_err(|error| format!("invalid access-control network {network:?}: {error}"))?,
            action: AccessAction::from_str(action)?,
        })
    }
}

impl Serialize for AccessControl {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccessControl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// A forward zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardZoneConfig {
    /// Zone name. Use `"."` for the default forwarder.
    pub name: String,
    /// Forwarder addresses.
    pub forward_addrs: Vec<ForwardTarget>,
    /// Forwarder hostnames, resolved at startup.
    pub forward_hosts: Vec<String>,
    /// Fall back to iterative resolution if forwarding fails.
    pub forward_first: bool,
    /// Resolve iteratively first and use the forwarders only when iteration
    /// fails with a reachability error.
    pub forward_fallback: bool,
    /// Require TLS for forwarding.
    pub tls_upstream: bool,
}

impl ForwardZoneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation(
                "forward-zone is missing a name".to_owned(),
            ));
        }
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!(
                "invalid forward-zone name {:?}: {error}",
                self.name
            ))
        })?;
        if !name.is_fqdn() {
            return Err(ConfigError::Validation(format!(
                "forward-zone name {:?} must be fully qualified",
                self.name
            )));
        }
        if self.forward_first && self.forward_fallback {
            return Err(ConfigError::Validation(format!(
                "forward-zone {:?} sets both forward-first and forward-fallback; choose one",
                self.name
            )));
        }
        if self.forward_addrs.is_empty() && self.forward_hosts.is_empty() {
            return Err(ConfigError::Validation(format!(
                "forward-zone {:?} has no forward-addr or forward-host",
                self.name
            )));
        }
        for target in &self.forward_addrs {
            if target.port() == 0 {
                return Err(ConfigError::Validation(format!(
                    "forward-zone {:?} has a target with port 0",
                    self.name
                )));
            }
            if target.is_https() && target.host.is_none() {
                return Err(ConfigError::Validation(format!(
                    "forward-zone {:?} has an HTTPS target without a hostname",
                    self.name
                )));
            }
            if !target.is_https() && target.addr.is_none() {
                return Err(ConfigError::Validation(format!(
                    "forward-zone {:?} has a target without an address",
                    self.name
                )));
            }
        }
        Ok(())
    }
}

/// A stub zone: iterative resolution starts at the listed authority servers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StubZoneConfig {
    /// Zone apex. Queries at or below this name start from `stub_addrs`.
    pub name: String,
    /// Authoritative server addresses.
    pub stub_addrs: Vec<ForwardTarget>,
    /// Authoritative server hostnames, resolved at startup.
    pub stub_hosts: Vec<String>,
    /// Refresh the delegation from the zone's published NS set.
    pub stub_prime: bool,
    /// Fall back to normal resolution when the stub servers fail.
    pub stub_first: bool,
    /// Do not cache data learned through this stub.
    pub stub_no_cache: bool,
    /// Require DNS-over-TLS for the stub servers.
    pub tls_upstream: bool,
}

impl StubZoneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation(
                "stub-zone is missing a name".to_owned(),
            ));
        }
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid stub-zone name {:?}: {error}", self.name))
        })?;
        if !name.is_fqdn() {
            return Err(ConfigError::Validation(format!(
                "stub-zone name {:?} must be fully qualified",
                self.name
            )));
        }
        if self.stub_addrs.is_empty() && self.stub_hosts.is_empty() {
            return Err(ConfigError::Validation(format!(
                "stub-zone {:?} has no stub-addr or stub-host",
                self.name
            )));
        }
        for target in &self.stub_addrs {
            validate_target("stub-zone", &self.name, target)?;
        }
        Ok(())
    }

    fn canonical_name(&self) -> Result<String, ConfigError> {
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid stub-zone name {:?}: {error}", self.name))
        })?;
        Ok(name.to_ascii().to_ascii_lowercase())
    }
}

/// An authority zone loaded from a zone file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthZoneConfig {
    /// Zone apex.
    pub name: String,
    /// Zone file to load.
    pub zonefile: Option<PathBuf>,
    /// AXFR/IXFR primaries. Not fetched yet; accepted for compatibility.
    pub primaries: Vec<String>,
    /// Zone-file download URLs. Not fetched yet; accepted for compatibility.
    pub urls: Vec<String>,
    /// Fall back to recursive resolution when local data cannot answer.
    pub fallback_enabled: bool,
    /// Answer downstream clients authoritatively from the zone contents.
    pub for_downstream: bool,
    /// Answer internal recursive lookups from the zone contents.
    pub for_upstream: bool,
}

impl Default for AuthZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            zonefile: None,
            primaries: Vec::new(),
            urls: Vec::new(),
            fallback_enabled: false,
            for_downstream: true,
            for_upstream: true,
        }
    }
}

impl AuthZoneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation(
                "auth-zone is missing a name".to_owned(),
            ));
        }
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid auth-zone name {:?}: {error}", self.name))
        })?;
        if !name.is_fqdn() {
            return Err(ConfigError::Validation(format!(
                "auth-zone name {:?} must be fully qualified",
                self.name
            )));
        }
        if self.zonefile.is_none() && self.primaries.is_empty() && self.urls.is_empty() {
            return Err(ConfigError::Validation(format!(
                "auth-zone {:?} has no zonefile, primary, or url",
                self.name
            )));
        }
        Ok(())
    }

    fn canonical_name(&self) -> Result<String, ConfigError> {
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid auth-zone name {:?}: {error}", self.name))
        })?;
        Ok(name.to_ascii().to_ascii_lowercase())
    }
}

/// Policy applied to a local zone when local data does not match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalZoneType {
    /// Drop the query.
    Deny,
    /// Answer REFUSED.
    Refuse,
    /// Answer from local data, otherwise NODATA or NXDOMAIN.
    #[default]
    Static,
    /// Answer from local data, otherwise resolve normally.
    Transparent,
    /// Answer every name under the zone from the zone apex data.
    Redirect,
    /// Answer matching types locally, resolve other types normally.
    Typetransparent,
    /// Resolve normally and log the client.
    Inform,
    /// Drop the query and log the client.
    InformDeny,
    /// Redirect and log the client.
    InformRedirect,
    /// Ignore local data and resolve normally.
    AlwaysTransparent,
    /// Ignore local data and answer REFUSED.
    AlwaysRefuse,
    /// Ignore local data and answer NXDOMAIN.
    AlwaysNxdomain,
    /// Ignore local data and answer NODATA.
    AlwaysNodata,
    /// Ignore local data and drop the query.
    AlwaysDeny,
    /// Answer 0.0.0.0 / :: for every name in the zone.
    AlwaysNull,
    /// Resolve normally except A queries, which get NODATA.
    BlockA,
    /// Resolve normally except AAAA queries, which get NODATA.
    BlockAaaa,
    /// Like `block-a`, but use local data when present.
    BlockAWdata,
    /// Like `block-aaaa`, but use local data when present.
    BlockAaaaWdata,
    /// Disable built-in content for this zone.
    Nodefault,
}

impl LocalZoneType {
    /// Whether the zone should be answered from local data before applying
    /// the fallback policy.
    pub const fn uses_local_data(self) -> bool {
        !matches!(
            self,
            Self::AlwaysTransparent
                | Self::AlwaysRefuse
                | Self::AlwaysNxdomain
                | Self::AlwaysNodata
                | Self::AlwaysDeny
                | Self::AlwaysNull
                | Self::BlockA
                | Self::BlockAaaa
                | Self::Nodefault
        )
    }
}

impl fmt::Display for LocalZoneType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Deny => "deny",
            Self::Refuse => "refuse",
            Self::Static => "static",
            Self::Transparent => "transparent",
            Self::Redirect => "redirect",
            Self::Typetransparent => "typetransparent",
            Self::Inform => "inform",
            Self::InformDeny => "inform_deny",
            Self::InformRedirect => "inform_redirect",
            Self::AlwaysTransparent => "always_transparent",
            Self::AlwaysRefuse => "always_refuse",
            Self::AlwaysNxdomain => "always_nxdomain",
            Self::AlwaysNodata => "always_nodata",
            Self::AlwaysDeny => "always_deny",
            Self::AlwaysNull => "always_null",
            Self::BlockA => "block_a",
            Self::BlockAaaa => "block_aaaa",
            Self::BlockAWdata => "block_a_wdata",
            Self::BlockAaaaWdata => "block_aaaa_wdata",
            Self::Nodefault => "nodefault",
        };
        formatter.write_str(text)
    }
}

impl FromStr for LocalZoneType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
        let zone_type = match normalized.as_str() {
            "deny" => Self::Deny,
            "refuse" => Self::Refuse,
            "static" => Self::Static,
            "transparent" => Self::Transparent,
            "redirect" => Self::Redirect,
            "typetransparent" | "type_transparent" => Self::Typetransparent,
            "inform" => Self::Inform,
            "inform_deny" => Self::InformDeny,
            "inform_redirect" => Self::InformRedirect,
            "always_transparent" => Self::AlwaysTransparent,
            "always_refuse" => Self::AlwaysRefuse,
            "always_nxdomain" => Self::AlwaysNxdomain,
            "always_nodata" => Self::AlwaysNodata,
            "always_deny" => Self::AlwaysDeny,
            "always_null" => Self::AlwaysNull,
            "block_a" => Self::BlockA,
            "block_aaaa" => Self::BlockAaaa,
            "block_a_wdata" => Self::BlockAWdata,
            "block_aaaa_wdata" => Self::BlockAaaaWdata,
            "nodefault" => Self::Nodefault,
            _ => return Err(format!("unknown local-zone type {value:?}")),
        };
        Ok(zone_type)
    }
}

/// A local zone served from static data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LocalZoneConfig {
    /// Zone apex.
    pub name: String,
    /// Fallback policy when local data does not match.
    #[serde(rename = "type")]
    pub zone_type: LocalZoneType,
    /// Records in zone-file syntax. Owners must fall inside the zone.
    pub data: Vec<String>,
}

impl Default for LocalZoneConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            zone_type: LocalZoneType::Static,
            data: Vec::new(),
        }
    }
}

impl LocalZoneConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation(
                "local-zone is missing a name".to_owned(),
            ));
        }
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid local-zone name {:?}: {error}", self.name))
        })?;
        if !name.is_fqdn() {
            return Err(ConfigError::Validation(format!(
                "local-zone name {:?} must be fully qualified",
                self.name
            )));
        }
        for data in &self.data {
            validate_local_data(data)?;
        }
        Ok(())
    }

    fn canonical_name(&self) -> Result<String, ConfigError> {
        let name = Name::from_ascii(&self.name).map_err(|error| {
            ConfigError::Validation(format!("invalid local-zone name {:?}: {error}", self.name))
        })?;
        Ok(name.to_ascii().to_ascii_lowercase())
    }
}

/// A named collection of local-zone overrides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ViewConfig {
    /// Unique view name, referenced by `access-control-view`.
    pub name: String,
    /// Fall back to global local zones when the view does not match.
    pub view_first: bool,
    /// View-specific local zones.
    pub local_zones: Vec<LocalZoneConfig>,
    /// View-specific `local-data` records in zone-file syntax.
    pub local_data: Vec<String>,
}

impl ViewConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.name.is_empty() {
            return Err(ConfigError::Validation("view is missing a name".to_owned()));
        }
        for zone in &self.local_zones {
            zone.validate()?;
        }
        for data in &self.local_data {
            validate_local_data(data)?;
        }
        Ok(())
    }
}

/// Map a client network to a named view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessControlView {
    /// Client network.
    pub network: IpNet,
    /// View name.
    pub view: String,
}

impl fmt::Display for AccessControlView {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.network, self.view)
    }
}

impl FromStr for AccessControlView {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut parts = value.split_whitespace();
        let network = parts
            .next()
            .ok_or_else(|| "missing network in access-control-view entry".to_owned())?;
        let view = parts
            .next()
            .ok_or_else(|| "missing view name in access-control-view entry".to_owned())?;
        if parts.next().is_some() {
            return Err(format!(
                "unexpected trailing data in access-control-view entry {value:?}"
            ));
        }
        Ok(Self {
            network: network
                .parse()
                .map_err(|error| format!("invalid network {network:?}: {error}"))?,
            view: view.to_owned(),
        })
    }
}

impl Serialize for AccessControlView {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AccessControlView {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

fn validate_target(kind: &str, zone: &str, target: &ForwardTarget) -> Result<(), ConfigError> {
    if target.port() == 0 {
        return Err(ConfigError::Validation(format!(
            "{kind} {zone:?} has a target with port 0"
        )));
    }
    if target.is_https() && target.host.is_none() {
        return Err(ConfigError::Validation(format!(
            "{kind} {zone:?} has an HTTPS target without a hostname"
        )));
    }
    if !target.is_https() && target.addr.is_none() {
        return Err(ConfigError::Validation(format!(
            "{kind} {zone:?} has a target without an address"
        )));
    }
    Ok(())
}

fn validate_local_data(text: &str) -> Result<(), ConfigError> {
    let records = dns_proto::parse_zone_records(text, None).map_err(|error| {
        ConfigError::Validation(format!("invalid local-data {text:?}: {error}"))
    })?;
    if records.is_empty() {
        return Err(ConfigError::Validation(format!(
            "local-data {text:?} contains no records"
        )));
    }
    Ok(())
}

/// One upstream forwarder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardTarget {
    /// Socket address of the forwarder. `None` for HTTPS targets, whose
    /// hostname is resolved at startup.
    pub addr: Option<SocketAddr>,
    /// Hostname used by DNS-over-HTTPS targets.
    pub host: Option<String>,
    /// TLS authentication name, when using DNS over TLS.
    pub tls_name: Option<String>,
    /// HTTP path for DNS-over-HTTPS targets.
    pub https_path: Option<String>,
    /// Destination port.
    pub port: u16,
}

impl ForwardTarget {
    /// Create a plain DNS or DNS-over-TLS target.
    pub const fn new(addr: SocketAddr, tls_name: Option<String>) -> Self {
        Self {
            addr: Some(addr),
            host: None,
            tls_name,
            https_path: None,
            port: addr.port(),
        }
    }

    /// Create a DNS-over-HTTPS target.
    pub fn https(host: String, port: u16, path: String) -> Self {
        Self {
            addr: None,
            tls_name: Some(host.clone()),
            host: Some(host),
            https_path: Some(path),
            port,
        }
    }

    /// Whether this target uses DNS-over-HTTPS.
    pub const fn is_https(&self) -> bool {
        self.https_path.is_some()
    }

    /// Destination port.
    pub const fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for ForwardTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_https() {
            let host = self.host.as_deref().unwrap_or_default();
            write!(formatter, "https://{host}")?;
            if self.port != 443 {
                write!(formatter, ":{}", self.port)?;
            }
            return write!(
                formatter,
                "{}",
                self.https_path.as_deref().unwrap_or("/dns-query")
            );
        }
        if let Some(addr) = self.addr {
            write!(formatter, "{}@{}", addr.ip(), addr.port())?;
        }
        if let Some(tls_name) = &self.tls_name {
            write!(formatter, "#{tls_name}")?;
        }
        Ok(())
    }
}

impl FromStr for ForwardTarget {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err("empty forwarder address".to_owned());
        }
        if let Some(rest) = value.strip_prefix("https://") {
            return parse_https_target(rest);
        }
        if value.starts_with("http://") {
            return Err("DNS-over-HTTPS forwarders must use https://".to_owned());
        }

        let (address, tls_name) = match value.rsplit_once('#') {
            Some((address, tls_name)) => {
                if tls_name.is_empty() {
                    return Err("empty TLS name after '#'".to_owned());
                }
                (address, Some(tls_name.to_owned()))
            }
            None => (value, None),
        };

        let (host, port) = match address.rsplit_once('@') {
            Some((host, port)) => (host, parse_port(port)?),
            None => (address, DEFAULT_PORT),
        };
        let ip = IpAddr::from_str(host)
            .map_err(|_| format!("forwarder {host:?} is not an IP address; use forward-host"))?;

        Ok(Self::new(SocketAddr::new(ip, port), tls_name))
    }
}

fn parse_https_target(rest: &str) -> Result<ForwardTarget, String> {
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/dns-query"),
    };
    if authority.is_empty() {
        return Err("HTTPS forwarder is missing a hostname".to_owned());
    }
    if !path.starts_with('/') {
        return Err(format!("invalid HTTPS forwarder path {path:?}"));
    }

    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let (host, tail) = stripped
            .split_once(']')
            .ok_or_else(|| format!("invalid IPv6 HTTPS authority {authority:?}"))?;
        let port = match tail.strip_prefix(':') {
            Some(port) => parse_port(port)?,
            None if tail.is_empty() => 443,
            None => return Err(format!("invalid HTTPS authority {authority:?}")),
        };
        (host.to_owned(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host.to_owned(), parse_port(port)?),
            _ => (authority.to_owned(), 443),
        }
    };
    if host.is_empty() {
        return Err("HTTPS forwarder is missing a hostname".to_owned());
    }
    Ok(ForwardTarget::https(host, port, path.to_owned()))
}

impl Serialize for ForwardTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ForwardTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// Remote-control settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RemoteControlConfig {
    /// Enable the control socket.
    pub enabled: bool,
    /// Interfaces (IP addresses or Unix socket paths).
    pub interfaces: Vec<String>,
    /// TCP control port.
    pub port: u16,
}

impl Default for RemoteControlConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: vec!["127.0.0.1".to_owned()],
            port: DEFAULT_CONTROL_PORT,
        }
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .trim()
        .parse::<u16>()
        .map_err(|_| format!("invalid port {value:?}"))?;
    if port == 0 {
        return Err("port must be between 1 and 65535".to_owned());
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{AccessAction, AccessControl, Config, ForwardTarget, ListenAddress};

    #[test]
    fn parses_listen_address_with_port() {
        let address = "127.0.0.1@5353"
            .parse::<ListenAddress>()
            .expect("valid address");
        assert_eq!(address.addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(address.port, Some(5353));
        assert_eq!(address.socket_addr(53).port(), 5353);
    }

    #[test]
    fn parses_forward_target_with_tls_name() {
        let target = "192.0.2.1@853#cloudflare-dns.com"
            .parse::<ForwardTarget>()
            .expect("valid target");
        assert_eq!(target.addr.expect("address").port(), 853);
        assert_eq!(target.tls_name.as_deref(), Some("cloudflare-dns.com"));
    }

    #[test]
    fn parses_https_forward_target() {
        let target = "https://cloudflare-dns.com/dns-query"
            .parse::<ForwardTarget>()
            .expect("valid HTTPS target");
        assert!(target.is_https());
        assert_eq!(target.host.as_deref(), Some("cloudflare-dns.com"));
        assert_eq!(target.port(), 443);
        assert_eq!(target.https_path.as_deref(), Some("/dns-query"));
        assert_eq!(target.to_string(), "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn parses_https_forward_target_with_port_and_path() {
        let target = "https://dns.example:8443/custom"
            .parse::<ForwardTarget>()
            .expect("valid HTTPS target");
        assert_eq!(target.host.as_deref(), Some("dns.example"));
        assert_eq!(target.port(), 8443);
        assert_eq!(target.https_path.as_deref(), Some("/custom"));
        assert_eq!(target.to_string(), "https://dns.example:8443/custom");
    }

    #[test]
    fn rejects_plain_http_forward_target() {
        assert!(
            "http://dns.example/dns-query"
                .parse::<ForwardTarget>()
                .is_err()
        );
    }

    #[test]
    fn parses_access_control() {
        let control = "127.0.0.0/8 allow"
            .parse::<AccessControl>()
            .expect("valid access control");
        assert_eq!(control.action, AccessAction::Allow);
        assert_eq!(control.network.prefix_len(), 8);
    }

    #[test]
    fn rejects_relative_forward_zone_name() {
        let config = Config {
            forward_zones: vec![super::ForwardZoneConfig {
                name: "example.com".to_owned(),
                forward_addrs: vec!["192.0.2.1".parse().expect("valid target")],
                ..super::ForwardZoneConfig::default()
            }],
            ..Config::default()
        };
        let error = config.validate().expect_err("relative name must fail");
        assert!(error.to_string().contains("fully qualified"));
    }

    #[test]
    fn rejects_forward_first_with_forward_fallback() {
        let config = Config {
            forward_zones: vec![super::ForwardZoneConfig {
                name: ".".to_owned(),
                forward_addrs: vec!["192.0.2.1".parse().expect("valid target")],
                forward_first: true,
                forward_fallback: true,
                ..super::ForwardZoneConfig::default()
            }],
            ..Config::default()
        };
        let error = config
            .validate()
            .expect_err("the two fallback directions are mutually exclusive");
        assert!(error.to_string().contains("forward-fallback"));
    }
}
