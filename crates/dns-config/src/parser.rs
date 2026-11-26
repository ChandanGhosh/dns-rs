use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::{ConfigError, ConfigWarning, LoadedConfig};
use crate::model::{
    AccessAction, AccessControl, AccessControlView, Config, ForwardTarget, ListenAddress,
    LocalZoneConfig, LocalZoneType, ThreadCount,
};
use crate::warnings::{CHROOT, DIRECTORY, DO_DAEMONIZE, LOGFILE, PIDFILE, USE_SYSLOG};

/// Parse an `unbound.conf`-style file.
pub(crate) fn parse_unbound_file(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let mut parser = Parser::default();
    let mut block = Block::None;
    parser.load_file(path, &mut block)?;
    parser.config.validate()?;
    Ok(LoadedConfig {
        config: parser.config,
        warnings: parser.warnings,
    })
}

/// Parse an `unbound.conf`-style configuration from an in-memory string.
///
/// `include` directives are reported as warnings and ignored, so this never
/// touches the filesystem. Use [`crate::load`] to resolve includes from a
/// file.
///
/// # Errors
///
/// Returns [`ConfigError::Parse`] when a line is malformed and
/// [`ConfigError::Validation`] when the parsed configuration is not usable.
pub fn parse_unbound_str(text: &str) -> Result<LoadedConfig, ConfigError> {
    let mut parser = Parser {
        resolve_includes: false,
        ..Parser::default()
    };
    let mut block = Block::None;
    parser.parse_text(Path::new("<memory>"), text, &mut block)?;
    parser.config.validate()?;
    Ok(LoadedConfig {
        config: parser.config,
        warnings: parser.warnings,
    })
}

#[derive(Debug, Clone)]
enum Block {
    None,
    Server,
    Forward(usize),
    Stub(usize),
    Auth(usize),
    View(usize),
    RemoteControl,
    Ignored,
}

struct Parser {
    config: Config,
    warnings: Vec<ConfigWarning>,
    include_stack: Vec<PathBuf>,
    private_address_explicit: bool,
    private_domain_explicit: bool,
    /// When false, `include` directives warn instead of reading the filesystem.
    resolve_includes: bool,
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            config: Config {
                server: crate::model::ServerConfig {
                    interfaces: Vec::new(),
                    access_control: Vec::new(),
                    ..Default::default()
                },
                forward_zones: Vec::new(),
                stub_zones: Vec::new(),
                auth_zones: Vec::new(),
                local_zones: Vec::new(),
                local_data: Vec::new(),
                views: Vec::new(),
                remote_control: crate::model::RemoteControlConfig::default(),
            },
            warnings: Vec::new(),
            include_stack: Vec::new(),
            private_address_explicit: false,
            private_domain_explicit: false,
            resolve_includes: true,
        }
    }
}

impl Parser {
    fn load_file(&mut self, path: &Path, block: &mut Block) -> Result<(), ConfigError> {
        let canonical = std::fs::canonicalize(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if self.include_stack.iter().any(|entry| entry == &canonical) {
            return Err(ConfigError::IncludeCycle(canonical));
        }
        let file = std::fs::File::open(&canonical).map_err(|source| ConfigError::Io {
            path: canonical.clone(),
            source,
        })?;

        self.include_stack.push(canonical.clone());
        // A guard would be nicer, but the error path must also pop, and the
        // borrow checker cannot see through the early returns above.
        let result = self.parse_reader(&canonical, std::io::BufReader::new(file), block);
        self.include_stack.pop();
        result
    }

    /// Expand an `include` pattern and parse every matched file.
    ///
    /// Relative patterns are resolved against the directory of the including
    /// file, then against the working directory (which is how Unbound resolves
    /// them). Wildcards follow `glob(7)` and are processed in sorted order so
    /// the resulting configuration is deterministic.
    fn include(
        &mut self,
        path: &Path,
        line: usize,
        pattern: &str,
        block: &mut Block,
    ) -> Result<(), ConfigError> {
        let candidates = include_candidates(path, pattern);
        let mut matched = 0usize;
        for candidate in &candidates {
            let mut paths = match glob::glob(&candidate.to_string_lossy()) {
                Ok(paths) => paths.collect::<Result<Vec<_>, _>>().map_err(|error| {
                    ConfigError::parse(
                        path,
                        line,
                        format!("failed to expand include {pattern:?}: {error}"),
                    )
                })?,
                Err(error) => {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        format!("invalid include pattern {pattern:?}: {error}"),
                    ));
                }
            };
            // `glob` does not guarantee an order across platforms.
            paths.sort();
            for include_path in paths {
                // Directories match wildcards such as `unbound.conf.d/*`, but
                // they are not configuration files.
                if include_path.is_dir() {
                    continue;
                }
                self.load_file(&include_path, block)?;
                matched += 1;
            }
            // Only fall back to the working directory when the including
            // file's directory produced no match at all.
            if matched > 0 {
                break;
            }
        }
        if matched == 0 {
            self.warn(path, line, format!("include {pattern:?} matched no files"));
        }
        Ok(())
    }

    /// Parse an include incrementally.
    ///
    /// Reading one line at a time keeps a large blocklist from being held as a
    /// single string while it is parsed. Line numbers stay continuous because
    /// each call is told which line of the file it received.
    fn parse_reader<R: std::io::BufRead>(
        &mut self,
        path: &Path,
        mut reader: R,
        block: &mut Block,
    ) -> Result<(), ConfigError> {
        // Reuse one buffer: a large blocklist can have hundreds of thousands of
        // lines, and `BufRead::lines` would allocate once per line.
        let mut line = String::new();
        let mut line_number = 0usize;
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .map_err(|source| ConfigError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            if read == 0 {
                return Ok(());
            }
            line_number += 1;
            let line = line.trim_end_matches(['\n', '\r']);
            self.parse_text_at(path, line, line_number, block)?;
        }
    }

    fn parse_text(
        &mut self,
        path: &Path,
        text: &str,
        block: &mut Block,
    ) -> Result<(), ConfigError> {
        self.parse_text_at(path, text, 1, block)
    }

    fn parse_text_at(
        &mut self,
        path: &Path,
        text: &str,
        first_line: usize,
        block: &mut Block,
    ) -> Result<(), ConfigError> {
        for (index, raw_line) in text.lines().enumerate() {
            let line_number = first_line + index;
            let line = strip_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            let Some((raw_key, raw_value)) = line.split_once(':') else {
                return Err(ConfigError::parse(
                    path,
                    line_number,
                    "expected 'key: value' syntax",
                ));
            };
            let key = raw_key.trim();
            let value = raw_value.trim();

            match key {
                "include" | "include-toplevel" => {
                    let include = parse_scalar(value);
                    if include.is_empty() {
                        return Err(ConfigError::parse(
                            path,
                            line_number,
                            "include path is empty",
                        ));
                    }
                    let toplevel = key == "include-toplevel";
                    if toplevel {
                        // `include-toplevel` closes the active clause before
                        // and after the include, so the outer file has to name
                        // a block again (Unbound documents this explicitly).
                        *block = Block::None;
                    }
                    if !self.resolve_includes {
                        self.warn(
                            path,
                            line_number,
                            "include is not resolved when parsing from a string; entry ignored",
                        );
                        continue;
                    }
                    self.include(path, line_number, &include, block)?;
                    if toplevel {
                        *block = Block::None;
                    }
                    continue;
                }
                _ => {}
            }

            if value.is_empty() {
                match key {
                    "server" => {
                        *block = Block::Server;
                        continue;
                    }
                    "forward-zone" => {
                        self.config.forward_zones.push(Default::default());
                        let zone_index = self.config.forward_zones.len() - 1;
                        *block = Block::Forward(zone_index);
                        continue;
                    }
                    "stub-zone" => {
                        self.config.stub_zones.push(Default::default());
                        let zone_index = self.config.stub_zones.len() - 1;
                        *block = Block::Stub(zone_index);
                        continue;
                    }
                    "auth-zone" => {
                        self.config.auth_zones.push(Default::default());
                        let zone_index = self.config.auth_zones.len() - 1;
                        *block = Block::Auth(zone_index);
                        continue;
                    }
                    "view" => {
                        self.config.views.push(Default::default());
                        let view_index = self.config.views.len() - 1;
                        *block = Block::View(view_index);
                        continue;
                    }
                    "remote-control" => {
                        *block = Block::RemoteControl;
                        continue;
                    }
                    "python" | "dynlib" | "rpz" => {
                        self.warn(
                            path,
                            line_number,
                            format!("'{key}' blocks are not supported yet; block ignored"),
                        );
                        *block = Block::Ignored;
                        continue;
                    }
                    _ if matches!(*block, Block::None) => {
                        self.warn(
                            path,
                            line_number,
                            format!("unsupported top-level block '{key}'; block ignored"),
                        );
                        *block = Block::Ignored;
                        continue;
                    }
                    _ => {}
                }
            }

            match *block {
                Block::None => {
                    return Err(ConfigError::parse(
                        path,
                        line_number,
                        format!("option '{key}' is outside of a block"),
                    ));
                }
                Block::Server => self.parse_server_option(path, line_number, key, value)?,
                Block::Forward(zone_index) => {
                    self.parse_forward_option(path, line_number, zone_index, key, value)?;
                }
                Block::Stub(zone_index) => {
                    self.parse_stub_option(path, line_number, zone_index, key, value)?;
                }
                Block::Auth(zone_index) => {
                    self.parse_auth_option(path, line_number, zone_index, key, value)?;
                }
                Block::View(view_index) => {
                    self.parse_view_option(path, line_number, view_index, key, value)?;
                }
                Block::RemoteControl => {
                    self.parse_remote_control_option(path, line_number, key, value)?;
                }
                Block::Ignored => {}
            }
        }

        Ok(())
    }

    fn parse_server_option(
        &mut self,
        path: &Path,
        line: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "interface" => {
                let address = ListenAddress::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
                self.config.server.interfaces.push(address);
            }
            "port" => self.config.server.port = parse_u16(path, line, key, value, true)?,
            "verbosity" => {
                let verbosity = parse_u8(path, line, key, value)?;
                if verbosity > 5 {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "verbosity must be between 0 and 5",
                    ));
                }
                self.config.server.verbosity = verbosity;
            }
            "num-threads" => {
                self.config.server.num_threads = parse_thread_count(path, line, key, value)?;
            }
            "do-daemonize" => {
                let enabled = parse_bool(path, line, key, value)?;
                self.config.server.do_daemonize = enabled;
                if enabled {
                    self.warn(path, line, DO_DAEMONIZE);
                }
            }
            "username" => self.config.server.username = optional_string(value),
            "chroot" => {
                self.config.server.chroot = optional_path(value);
                if self.config.server.chroot.is_some() {
                    self.warn(path, line, CHROOT);
                }
            }
            "directory" => {
                self.config.server.directory = optional_path(value);
                if self.config.server.directory.is_some() {
                    self.warn(path, line, DIRECTORY);
                }
            }
            "logfile" => {
                self.config.server.logfile = optional_path(value);
                if self.config.server.logfile.is_some() {
                    self.warn(path, line, LOGFILE);
                }
            }
            "pidfile" => {
                self.config.server.pidfile = optional_path(value);
                if self.config.server.pidfile.is_some() {
                    self.warn(path, line, PIDFILE);
                }
            }
            "use-syslog" => {
                let enabled = parse_bool(path, line, key, value)?;
                self.config.server.use_syslog = enabled;
                if enabled {
                    self.warn(path, line, USE_SYSLOG);
                }
            }
            "do-ip4" => self.config.server.do_ip4 = parse_bool(path, line, key, value)?,
            "do-ip6" => self.config.server.do_ip6 = parse_bool(path, line, key, value)?,
            "do-udp" => self.config.server.do_udp = parse_bool(path, line, key, value)?,
            "do-tcp" => self.config.server.do_tcp = parse_bool(path, line, key, value)?,
            "access-control" => {
                let control = AccessControl::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
                if control.action == AccessAction::AllowCookie {
                    self.warn(
                        path,
                        line,
                        "access-control action allow_cookie is not enforced yet; treating the network as allow",
                    );
                }
                self.config.server.access_control.push(control);
            }
            "access-control-view" => {
                let mapping = AccessControlView::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
                self.config.server.access_control_view.push(mapping);
            }
            "interface-view" => {
                self.warn(
                    path,
                    line,
                    "interface-view is not supported yet; use access-control-view",
                );
            }
            "local-zone" => {
                let zone = parse_local_zone(path, line, value)?;
                self.config.local_zones.push(zone);
            }
            "local-data" => {
                self.config
                    .local_data
                    .push(parse_local_data(path, line, value)?);
            }
            "local-data-ptr" => {
                let record = parse_local_data_ptr(path, line, value)?;
                self.config.local_data.push(record);
            }
            "outgoing-interface" => {
                let address = value.trim().parse::<std::net::IpAddr>().map_err(|_| {
                    ConfigError::parse(path, line, format!("invalid outgoing-interface {value:?}"))
                })?;
                self.config.server.outgoing_interfaces.push(address);
            }
            "do-not-query-address" => {
                let address = parse_scalar(value);
                if address.is_empty() {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "do-not-query-address is empty",
                    ));
                }
                self.config.server.do_not_query_address.push(address);
            }
            "do-not-query-localhost" => {
                self.config.server.do_not_query_localhost = parse_bool(path, line, key, value)?;
            }
            "root-hints" => {
                let path_value = parse_scalar(value);
                if path_value.is_empty() {
                    return Err(ConfigError::parse(path, line, "root-hints is empty"));
                }
                self.config
                    .server
                    .root_hints
                    .push(PathBuf::from(path_value));
            }
            "unblock-lan-zones" => {
                let enabled = parse_bool(path, line, key, value)?;
                self.config.server.unblock_lan_zones = Some(enabled);
                if !enabled {
                    self.warn(
                        path,
                        line,
                        "unblock-lan-zones: no is not implemented; private reverse zones are always resolved upstream",
                    );
                }
            }
            "insecure-lan-zones" => {
                self.config.server.insecure_lan_zones = parse_bool(path, line, key, value)?;
            }
            "harden-glue" => self.config.server.harden_glue = parse_bool(path, line, key, value)?,
            "harden-dnssec-stripped" => {
                self.config.server.harden_dnssec_stripped = parse_bool(path, line, key, value)?;
            }
            "nsec3-max-iterations" => {
                // Zero is allowed: RFC 9276 recommends no extra iterations.
                self.config.server.nsec3_max_iterations = parse_u16(path, line, key, value, false)?;
            }
            "module-config" => {
                let modules = parse_scalar(value);
                let lower = modules.to_ascii_lowercase();
                // These are the only modules the pipeline can honour. The
                // others are recognised so a stock config parses, but they
                // have no effect and must be reported.
                let mut unsupported = Vec::new();
                let mut unknown = false;
                for module in lower.split_whitespace() {
                    match module {
                        "validator" | "iterator" => {}
                        "subnetcache" | "respip" | "dynlib" => unsupported.push(module),
                        _ => unknown = true,
                    }
                }
                self.config.server.dnssec_validation =
                    lower.split_whitespace().any(|module| module == "validator");
                if unknown {
                    self.warn(
                        path,
                        line,
                        format!("unsupported module-config {modules:?}; using validator iterator"),
                    );
                } else if !unsupported.is_empty() {
                    self.warn(
                        path,
                        line,
                        format!(
                            "module-config module(s) {} are not implemented yet; ignored",
                            unsupported.join(", ")
                        ),
                    );
                }
            }
            "val-permissive-mode" => {
                self.config.server.val_permissive_mode = parse_bool(path, line, key, value)?;
            }
            "domain-insecure" => {
                let domain = parse_scalar(value);
                if domain.is_empty() {
                    return Err(ConfigError::parse(path, line, "domain-insecure is empty"));
                }
                self.config.server.domain_insecure.push(domain);
            }
            "private-address" => {
                let address = parse_scalar(value);
                if address.is_empty() {
                    return Err(ConfigError::parse(path, line, "private-address is empty"));
                }
                // An explicit list replaces the built-in defaults, matching
                // the TOML configuration where the field is a single list.
                if !self.private_address_explicit {
                    self.config.server.private_address.clear();
                    self.private_address_explicit = true;
                }
                self.config.server.private_address.push(address);
            }
            "private-domain" => {
                let domain = parse_scalar(value);
                if domain.is_empty() {
                    return Err(ConfigError::parse(path, line, "private-domain is empty"));
                }
                if !self.private_domain_explicit {
                    self.config.server.private_domain.clear();
                    self.private_domain_explicit = true;
                }
                self.config.server.private_domain.push(domain);
            }
            "val-clean-additional" => {
                self.config.server.val_clean_additional = parse_bool(path, line, key, value)?;
            }
            "trust-anchor" => {
                let anchor = parse_scalar(value);
                if anchor.is_empty() {
                    return Err(ConfigError::parse(path, line, "trust-anchor is empty"));
                }
                self.config.server.trust_anchor.push(anchor);
            }
            "trust-anchor-file" => {
                self.config.server.trust_anchor_file = optional_path(value);
            }
            "auto-trust-anchor-file" => {
                self.config.server.auto_trust_anchor_file = optional_path(value);
            }
            "qname-minimisation" | "qname-minimization" => {
                self.config.server.qname_minimisation = parse_bool(path, line, key, value)?;
            }
            "qname-minimisation-strict" | "qname-minimization-strict" => {
                self.config.server.qname_minimisation_strict = parse_bool(path, line, key, value)?;
            }
            "use-caps-for-id" => {
                self.config.server.use_caps_for_id = parse_bool(path, line, key, value)?;
            }
            "edns-buffer-size" => {
                let size = parse_u16(path, line, key, value, false)?;
                if size < 512 {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "edns-buffer-size must be at least 512",
                    ));
                }
                self.config.server.edns_buffer_size = size;
            }
            "max-udp-size" => {
                let size = parse_u16(path, line, key, value, false)?;
                if size < 512 {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "max-udp-size must be at least 512",
                    ));
                }
                self.config.server.max_udp_size = size;
            }
            "cache-max-ttl" => {
                self.config.server.cache_max_ttl = parse_u32(path, line, key, value)?;
            }
            "cache-min-ttl" => {
                self.config.server.cache_min_ttl = parse_u32(path, line, key, value)?;
            }
            "cache-max-negative-ttl" => {
                self.config.server.cache_max_negative_ttl = parse_u32(path, line, key, value)?;
            }
            "infra-host-ttl" => {
                self.config.server.infra_host_ttl = parse_u32(path, line, key, value)?;
            }
            "infra-cache-min-rtt" => {
                self.config.server.infra_cache_min_rtt = parse_u32(path, line, key, value)?;
            }
            "infra-cache-numhosts" => {
                let hosts = parse_usize(path, line, key, value)?;
                if hosts == 0 {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "infra-cache-numhosts must be at least 1",
                    ));
                }
                self.config.server.infra_cache_numhosts = hosts;
            }
            "so-reuseport" => {
                if !parse_bool(path, line, key, value)? {
                    self.warn(
                        path,
                        line,
                        "so-reuseport: no is not implemented; UDP listeners always set SO_REUSEPORT",
                    );
                }
            }
            "delay-close" => {
                let millis = parse_u32(path, line, key, value)?;
                if millis != 0 {
                    self.warn(
                        path,
                        line,
                        format!(
                            "delay-close: {millis} is not implemented; TCP connections close immediately"
                        ),
                    );
                }
            }
            "prefetch" => {
                self.config.server.prefetch = parse_bool(path, line, key, value)?;
            }
            "serve-expired" => {
                self.config.server.serve_expired = parse_bool(path, line, key, value)?;
            }
            "serve-expired-ttl" => {
                self.config.server.serve_expired_ttl = parse_u32(path, line, key, value)?;
            }
            "serve-expired-reply-ttl" => {
                self.config.server.serve_expired_reply_ttl = parse_u32(path, line, key, value)?;
            }
            "max-ttl" => self.config.server.max_ttl = parse_u32(path, line, key, value)?,
            "min-ttl" => self.config.server.min_ttl = parse_u32(path, line, key, value)?,
            "ratelimit" => self.config.server.ratelimit = parse_u32(path, line, key, value)?,
            "ratelimit-slip" => {
                self.config.server.ratelimit_slip = parse_u32(path, line, key, value)?;
            }
            "max-concurrent-queries-per-client" => {
                self.config.server.max_concurrent_queries_per_client =
                    parse_usize(path, line, key, value)?;
            }
            "incoming-num-tcp" => {
                self.config.server.incoming_num_tcp = parse_usize(path, line, key, value)?;
            }
            "tls-service-key" => {
                self.config.server.tls_service_key = optional_path(value);
            }
            "tls-service-pem" => {
                self.config.server.tls_service_pem = optional_path(value);
            }
            "tls-port" => self.config.server.tls_port = parse_u16(path, line, key, value, true)?,
            "https-port" => {
                self.config.server.https_port = parse_u16(path, line, key, value, true)?;
            }
            "http-endpoint" => {
                let endpoint = parse_scalar(value);
                if !endpoint.starts_with('/') {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "http-endpoint must start with '/'",
                    ));
                }
                self.config.server.http_endpoint = endpoint;
            }
            "tls-cert-bundle" => {
                self.config.server.tls_cert_bundle = optional_path(value);
            }
            "tls-use-system-ca" => {
                self.config.server.tls_use_system_ca = parse_bool(path, line, key, value)?;
            }
            "tls-enforce-name-check" => {
                // Not an Unbound option, and the resolver does not use it.
                // Keep parsing it so existing configs do not fail, but say so.
                self.config.server.tls_enforce_name_check = parse_bool(path, line, key, value)?;
                self.warn(
                    path,
                    line,
                    "tls-enforce-name-check is not an Unbound option and is not enforced; remove it",
                );
            }
            "udp-recv-buffer-size" => {
                self.config.server.udp_recv_buffer_size = parse_usize(path, line, key, value)?;
            }
            "udp-send-buffer-size" => {
                self.config.server.udp_send_buffer_size = parse_usize(path, line, key, value)?;
            }
            "tcp-recv-buffer-size" => {
                self.config.server.tcp_recv_buffer_size = parse_usize(path, line, key, value)?;
            }
            "tcp-send-buffer-size" => {
                self.config.server.tcp_send_buffer_size = parse_usize(path, line, key, value)?;
            }
            "tcp-user-timeout" => {
                self.config.server.tcp_user_timeout_ms = parse_u32(path, line, key, value)?;
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in server block; ignored"),
            ),
        }
        Ok(())
    }

    fn parse_forward_option(
        &mut self,
        path: &Path,
        line: usize,
        zone_index: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "name" => {
                self.config.forward_zones[zone_index].name = parse_scalar(value);
            }
            "forward-addr" => {
                let target = ForwardTarget::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
                self.config.forward_zones[zone_index]
                    .forward_addrs
                    .push(target);
            }
            "forward-host" => {
                self.config.forward_zones[zone_index]
                    .forward_hosts
                    .push(parse_scalar(value));
            }
            "forward-first" => {
                self.config.forward_zones[zone_index].forward_first =
                    parse_bool(path, line, key, value)?;
            }
            "forward-fallback" => {
                self.config.forward_zones[zone_index].forward_fallback =
                    parse_bool(path, line, key, value)?;
            }
            "forward-tls-upstream" | "forward-ssl-upstream" => {
                self.config.forward_zones[zone_index].tls_upstream =
                    parse_bool(path, line, key, value)?;
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in forward-zone block; ignored"),
            ),
        }
        Ok(())
    }

    fn parse_stub_option(
        &mut self,
        path: &Path,
        line: usize,
        zone_index: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "name" => self.config.stub_zones[zone_index].name = parse_scalar(value),
            "stub-addr" => {
                let target = ForwardTarget::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
                self.config.stub_zones[zone_index].stub_addrs.push(target);
            }
            "stub-host" => self.config.stub_zones[zone_index]
                .stub_hosts
                .push(parse_scalar(value)),
            "stub-prime" => {
                self.config.stub_zones[zone_index].stub_prime = parse_bool(path, line, key, value)?;
            }
            "stub-first" => {
                self.config.stub_zones[zone_index].stub_first = parse_bool(path, line, key, value)?;
            }
            "stub-no-cache" => {
                self.config.stub_zones[zone_index].stub_no_cache =
                    parse_bool(path, line, key, value)?;
            }
            "stub-tls-upstream" | "stub-ssl-upstream" => {
                self.config.stub_zones[zone_index].tls_upstream =
                    parse_bool(path, line, key, value)?;
            }
            "stub-tcp-upstream" => {
                self.warn(
                    path,
                    line,
                    "stub-tcp-upstream is not supported yet; using the default transport",
                );
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in stub-zone block; ignored"),
            ),
        }
        Ok(())
    }

    fn parse_auth_option(
        &mut self,
        path: &Path,
        line: usize,
        zone_index: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "name" => self.config.auth_zones[zone_index].name = parse_scalar(value),
            "zonefile" => self.config.auth_zones[zone_index].zonefile = optional_path(value),
            "primary" | "master" => {
                self.config.auth_zones[zone_index]
                    .primaries
                    .push(parse_scalar(value));
                self.warn(
                    path,
                    line,
                    format!("'{key}' is not supported yet (AXFR/IXFR is not implemented); zone transfers are ignored"),
                );
            }
            "url" => {
                self.config.auth_zones[zone_index]
                    .urls
                    .push(parse_scalar(value));
                self.warn(
                    path,
                    line,
                    "'url' is not supported yet (zone download is not implemented); ignored",
                );
            }
            "fallback-enabled" => {
                self.config.auth_zones[zone_index].fallback_enabled =
                    parse_bool(path, line, key, value)?;
                self.warn(
                    path,
                    line,
                    "'fallback-enabled' has no effect because auth zones are never transferred; ignored",
                );
            }
            "for-downstream" => {
                self.config.auth_zones[zone_index].for_downstream =
                    parse_bool(path, line, key, value)?;
            }
            "for-upstream" => {
                self.config.auth_zones[zone_index].for_upstream =
                    parse_bool(path, line, key, value)?;
            }
            "allow-notify"
            | "zonemd-check"
            | "zonemd-reject-absence"
            | "max-transfer-size"
            | "max-transfer-time" => {
                self.warn(
                    path,
                    line,
                    format!("'{key}' is not supported yet in auth-zone; ignored"),
                );
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in auth-zone block; ignored"),
            ),
        }
        Ok(())
    }

    fn parse_view_option(
        &mut self,
        path: &Path,
        line: usize,
        view_index: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "name" => self.config.views[view_index].name = parse_scalar(value),
            "view-first" => {
                self.config.views[view_index].view_first = parse_bool(path, line, key, value)?;
            }
            "local-zone" => {
                let zone = parse_local_zone(path, line, value)?;
                self.config.views[view_index].local_zones.push(zone);
            }
            "local-data" => {
                let record = parse_local_data(path, line, value)?;
                self.config.views[view_index].local_data.push(record);
            }
            "local-data-ptr" => {
                let record = parse_local_data_ptr(path, line, value)?;
                self.config.views[view_index].local_data.push(record);
            }
            "response-ip" | "response-ip-data" => {
                self.warn(
                    path,
                    line,
                    format!("'{key}' is not supported yet in view; ignored"),
                );
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in view block; ignored"),
            ),
        }
        Ok(())
    }

    fn parse_remote_control_option(
        &mut self,
        path: &Path,
        line: usize,
        key: &str,
        value: &str,
    ) -> Result<(), ConfigError> {
        match key {
            "control-enable" => {
                self.config.remote_control.enabled = parse_bool(path, line, key, value)?;
            }
            "control-interface" => {
                let value = parse_scalar(value);
                let value = value.trim_prefix("unix:");
                if value.is_empty() {
                    return Err(ConfigError::parse(
                        path,
                        line,
                        "control-interface must not be empty",
                    ));
                }
                self.config
                    .remote_control
                    .interfaces
                    .push(PathBuf::from(value));
            }
            "control-port" => {
                self.config.remote_control.port = parse_u16(path, line, key, value, true)?;
            }
            _ => self.warn(
                path,
                line,
                format!("unsupported option '{key}' in remote-control block; ignored"),
            ),
        }
        Ok(())
    }

    fn warn(&mut self, path: &Path, line: usize, message: impl Into<String>) {
        self.warnings.push(ConfigWarning {
            path: path.to_path_buf(),
            line,
            message: message.into(),
        });
    }
}

/// Candidate absolute paths for an `include` pattern.
///
/// Unbound resolves relative includes against its working directory, which is
/// either the launch directory or the `directory:` option. dns-rs resolves
/// against the including file first (so a config directory can be copied as a
/// unit) and only falls back to the process working directory when nothing
/// matches.
fn include_candidates(base: &Path, pattern: &str) -> Vec<PathBuf> {
    let include = Path::new(pattern);
    if include.is_absolute() {
        return vec![include.to_path_buf()];
    }
    let mut candidates = Vec::with_capacity(2);
    if let Some(directory) = base.parent() {
        candidates.push(directory.join(include));
    }
    if let Ok(directory) = std::env::current_dir() {
        let fallback = directory.join(include);
        if !candidates.contains(&fallback) {
            candidates.push(fallback);
        }
    }
    candidates
}

fn split_quoted(value: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            current.push(character);
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            character if character.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_local_zone(path: &Path, line: usize, value: &str) -> Result<LocalZoneConfig, ConfigError> {
    let tokens = split_quoted(value);
    let Some(name) = tokens.first() else {
        return Err(ConfigError::parse(
            path,
            line,
            "local-zone is missing a name",
        ));
    };
    let zone_type = match tokens.get(1) {
        Some(kind) => LocalZoneType::from_str(kind)
            .map_err(|message| ConfigError::parse(path, line, message))?,
        None => LocalZoneType::Static,
    };
    // Unbound resolves relative local-zone names against the root, so
    // `local-zone: "example.com" redirect` and `example.com.` are equivalent.
    if name.is_empty() {
        return Err(ConfigError::parse(
            path,
            line,
            "local-zone is missing a name",
        ));
    }
    let name = if name.ends_with('.') {
        name.clone()
    } else {
        format!("{name}.")
    };
    Ok(LocalZoneConfig {
        name,
        zone_type,
        data: Vec::new(),
    })
}

fn parse_local_data(path: &Path, line: usize, value: &str) -> Result<String, ConfigError> {
    let record = parse_scalar(value);
    if record.is_empty() {
        return Err(ConfigError::parse(path, line, "local-data is empty"));
    }
    Ok(record)
}

fn parse_local_data_ptr(path: &Path, line: usize, value: &str) -> Result<String, ConfigError> {
    let text = parse_scalar(value);
    let mut parts = text.split_whitespace();
    let address = parts
        .next()
        .ok_or_else(|| ConfigError::parse(path, line, "local-data-ptr is missing an address"))?;
    let name = parts
        .next()
        .ok_or_else(|| ConfigError::parse(path, line, "local-data-ptr is missing a name"))?;
    if parts.next().is_some() {
        return Err(ConfigError::parse(
            path,
            line,
            format!("unexpected trailing data in local-data-ptr {text:?}"),
        ));
    }
    let address = address.parse::<IpAddr>().map_err(|error| {
        ConfigError::parse(
            path,
            line,
            format!("invalid local-data-ptr address: {error}"),
        )
    })?;
    let name = if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    };
    let reverse = match address {
        IpAddr::V4(address) => {
            let mut labels: Vec<String> =
                address.octets().iter().rev().map(u8::to_string).collect();
            labels.push("in-addr".to_owned());
            labels.push("arpa".to_owned());
            labels.join(".")
        }
        IpAddr::V6(address) => {
            let mut labels = Vec::with_capacity(34);
            for byte in address.octets().iter().rev() {
                labels.push(format!("{:x}", byte & 0x0f));
                labels.push(format!("{:x}", byte >> 4));
            }
            labels.push("ip6".to_owned());
            labels.push("arpa".to_owned());
            labels.join(".")
        }
    };
    Ok(format!("{reverse}. 3600 IN PTR {name}"))
}

fn strip_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;

    for (index, character) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => {
                // Only treat # as comment if preceded by whitespace or start of relevant content
                // to avoid breaking values like forward-addr: ...#tls-name
                let before = &line[..index];
                if before.trim().is_empty() {
                    return &line[..index];
                }
                // Check if # appears to be attached to a value (no space before)
                if let Some(last) = before.chars().last()
                    && last.is_whitespace()
                {
                    return before;
                }
                // Otherwise it's likely part of the value, don't strip
                continue;
            }
            _ => {}
        }
    }
    line
}

fn parse_scalar(value: &str) -> String {
    let value = value.trim();
    if value.len() >= 2 && value.starts_with('"') && value.ends_with('"') {
        let inner = &value[1..value.len() - 1];
        let mut result = String::with_capacity(inner.len());
        let mut characters = inner.chars();
        while let Some(character) = characters.next() {
            if character != '\\' {
                result.push(character);
                continue;
            }
            match characters.next() {
                Some('n') => result.push('\n'),
                Some('t') => result.push('\t'),
                Some('\\') => result.push('\\'),
                Some('"') => result.push('"'),
                Some(other) => {
                    result.push('\\');
                    result.push(other);
                }
                None => result.push('\\'),
            }
        }
        result
    } else {
        value.to_owned()
    }
}

fn optional_string(value: &str) -> Option<String> {
    let value = parse_scalar(value);
    (!value.is_empty()).then_some(value)
}

fn optional_path(value: &str) -> Option<PathBuf> {
    optional_string(value).map(PathBuf::from)
}

fn parse_bool(path: &Path, line: usize, key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => Err(ConfigError::parse(
            path,
            line,
            format!("invalid boolean for '{key}': {value:?}"),
        )),
    }
}

fn parse_u8(path: &Path, line: usize, key: &str, value: &str) -> Result<u8, ConfigError> {
    value.trim().parse::<u8>().map_err(|_| {
        ConfigError::parse(path, line, format!("invalid number for '{key}': {value:?}"))
    })
}

fn parse_u16(
    path: &Path,
    line: usize,
    key: &str,
    value: &str,
    reject_zero: bool,
) -> Result<u16, ConfigError> {
    let number = value.trim().parse::<u16>().map_err(|_| {
        ConfigError::parse(path, line, format!("invalid number for '{key}': {value:?}"))
    })?;
    if reject_zero && number == 0 {
        return Err(ConfigError::parse(
            path,
            line,
            format!("'{key}' must be between 1 and 65535"),
        ));
    }
    Ok(number)
}

fn parse_thread_count(
    path: &Path,
    line: usize,
    key: &str,
    value: &str,
) -> Result<ThreadCount, ConfigError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("auto") {
        return Ok(ThreadCount::Auto);
    }
    let count = value.parse::<usize>().map_err(|_| {
        ConfigError::parse(path, line, format!("invalid number for '{key}': {value:?}"))
    })?;
    Ok(ThreadCount::from_count(count))
}

fn parse_usize(path: &Path, line: usize, key: &str, value: &str) -> Result<usize, ConfigError> {
    value.trim().parse::<usize>().map_err(|_| {
        ConfigError::parse(path, line, format!("invalid number for '{key}': {value:?}"))
    })
}

fn parse_u32(path: &Path, line: usize, key: &str, value: &str) -> Result<u32, ConfigError> {
    value.trim().parse::<u32>().map_err(|_| {
        ConfigError::parse(path, line, format!("invalid number for '{key}': {value:?}"))
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use crate::error::ConfigError;
    use crate::model::{LocalZoneType, ThreadCount};

    use super::parse_unbound_file;

    #[test]
    fn parses_core_unbound_subset() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
    interface: ::1@5353
    port: 5353
    verbosity: 2
    num-threads: 2
    do-daemonize: no
    incoming-num-tcp: 32
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 refuse
    domain-insecure: docker.com
    domain-insecure: "internal.example."
    private-address: 10.0.0.0/8
    private-address: 192.168.1.10
    private-domain: "home.example."
    private-domain: corp.example
    tls-service-key: "/tmp/key.pem"
    tls-service-pem: "/tmp/cert.pem"
    tls-port: 8853
    https-port: 8443
    http-endpoint: "/custom-dns"
    tls-cert-bundle: "/tmp/ca.pem"
    tls-use-system-ca: no

forward-zone:
    name: "example.com."
    forward-addr: 192.0.2.1@53
    forward-addr: 192.0.2.2@853#resolver.example
    forward-addr: https://cloudflare-dns.com/dns-query
    forward-first: yes
    forward-fallback: no
    forward-tls-upstream: yes

"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        let config = loaded.config;

        assert_eq!(config.server.interfaces.len(), 2);
        assert_eq!(config.server.port, 5353);
        assert_eq!(config.server.verbosity, 2);
        assert_eq!(config.server.num_threads, ThreadCount::Fixed(2));
        assert_eq!(config.server.incoming_num_tcp, 32);
        assert!(!config.server.do_daemonize);
        assert_eq!(config.server.access_control.len(), 2);
        assert_eq!(
            config.server.domain_insecure,
            vec!["docker.com".to_owned(), "internal.example.".to_owned()]
        );
        // Explicit lists replace the built-in defaults rather than appending.
        assert_eq!(
            config.server.private_address,
            vec!["10.0.0.0/8".to_owned(), "192.168.1.10".to_owned()]
        );
        assert_eq!(
            config.server.private_domain,
            vec!["home.example.".to_owned(), "corp.example".to_owned()]
        );
        assert_eq!(config.server.tls_port, 8853);
        assert_eq!(config.server.https_port, 8443);
        assert_eq!(config.server.http_endpoint, "/custom-dns");
        assert!(!config.server.tls_use_system_ca);
        assert!(config.server.tls_service_key.is_some());
        assert!(config.server.tls_service_pem.is_some());
        assert!(config.server.tls_cert_bundle.is_some());

        assert_eq!(config.forward_zones.len(), 1);
        let zone = &config.forward_zones[0];
        assert_eq!(zone.name, "example.com.");
        assert_eq!(zone.forward_addrs.len(), 3);
        assert!(zone.forward_first);
        assert!(!zone.forward_fallback);
        assert!(zone.tls_upstream);
        assert_eq!(
            zone.forward_addrs[1].tls_name.as_deref(),
            Some("resolver.example")
        );
        assert!(zone.forward_addrs[2].is_https());
        assert_eq!(
            zone.forward_addrs[2].host.as_deref(),
            Some("cloudflare-dns.com")
        );
        assert_eq!(
            zone.forward_addrs[2].https_path.as_deref(),
            Some("/dns-query")
        );

        // The control socket is opt-in and has no default interface.
        assert!(!config.remote_control.enabled);
        assert!(config.remote_control.interfaces.is_empty());
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn parses_nsec3_max_iterations() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("nsec3.conf");
        fs::write(
            &path,
            "server:\n    interface: 127.0.0.1@5353\n    nsec3-max-iterations: 42\n",
        )
        .expect("write config");

        let config = parse_unbound_file(&path).expect("parse config").config;
        assert_eq!(config.server.nsec3_max_iterations, 42);

        // Zero stays legal: RFC 9276 recommends running without extra
        // iterations.
        fs::write(
            &path,
            "server:\n    interface: 127.0.0.1@5353\n    nsec3-max-iterations: 0\n",
        )
        .expect("write config");
        let config = parse_unbound_file(&path).expect("parse config").config;
        assert_eq!(config.server.nsec3_max_iterations, 0);
    }

    #[test]
    fn parses_forward_ssl_upstream_alias_and_auth_name_port_default() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("forward.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353

forward-zone:
    name: "."
    forward-ssl-upstream: yes
    forward-addr: 192.0.2.1#resolver.example
"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
        let zone = &loaded.config.forward_zones[0];
        assert!(zone.tls_upstream);
        assert_eq!(zone.forward_addrs[0].port(), 853);
        assert_eq!(
            zone.forward_addrs[0].tls_name.as_deref(),
            Some("resolver.example")
        );
    }

    #[test]
    fn parses_policy_blocks() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("policy.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
    local-zone: "example.test." static
    local-data: "example.test. 300 IN A 192.0.2.10"
    local-data: "alias.example.test. 300 IN CNAME example.test."
    local-data-ptr: "192.0.2.10 host.example.test."
    access-control-view: 127.0.0.0/8 trusted

stub-zone:
    name: "corp.test."
    stub-addr: 192.0.2.53
    stub-first: yes
    stub-prime: yes
    stub-no-cache: yes

auth-zone:
    name: "auth.test."
    zonefile: "/tmp/auth.test.zone"
    for-downstream: no

view:
    name: trusted
    view-first: yes
    local-zone: "intranet.test." transparent
    local-data: "intranet.test. 300 IN A 10.0.0.1"
"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        let config = loaded.config;
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);

        assert_eq!(config.local_zones.len(), 1);
        assert_eq!(config.local_zones[0].name, "example.test.");
        assert_eq!(config.local_zones[0].zone_type, LocalZoneType::Static);
        assert_eq!(config.local_data.len(), 3);
        assert!(
            config.local_data[2].contains("10.2.0.192.in-addr.arpa."),
            "{}",
            config.local_data[2]
        );

        assert_eq!(config.stub_zones.len(), 1);
        let stub = &config.stub_zones[0];
        assert_eq!(stub.name, "corp.test.");
        assert_eq!(stub.stub_addrs.len(), 1);
        assert!(stub.stub_first && stub.stub_prime && stub.stub_no_cache);

        assert_eq!(config.auth_zones.len(), 1);
        let auth = &config.auth_zones[0];
        assert_eq!(auth.name, "auth.test.");
        assert!(auth.zonefile.is_some());
        assert!(!auth.for_downstream);
        assert!(auth.for_upstream);

        assert_eq!(config.views.len(), 1);
        assert_eq!(config.views[0].name, "trusted");
        assert!(config.views[0].view_first);
        assert_eq!(config.views[0].local_zones.len(), 1);
        assert_eq!(config.views[0].local_data.len(), 1);
        assert_eq!(config.server.access_control_view.len(), 1);
        assert_eq!(config.server.access_control_view[0].view, "trusted");
    }

    #[test]
    fn rejects_unknown_view_reference() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("bad-view.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
    access-control-view: 127.0.0.0/8 missing
"#,
        )
        .expect("write config");

        let error = parse_unbound_file(&path).expect_err("unknown view must fail");
        assert!(error.to_string().contains("unknown view"));
    }

    #[test]
    fn reports_unsupported_options_as_warnings() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
    msg-cache-size: 4m
    module-config: "validator iterator"
"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded
                .warnings
                .iter()
                .any(|warning| warning.message.contains("msg-cache-size"))
        );
        assert!(loaded.config.server.dnssec_validation);
    }

    #[test]
    fn warns_about_security_options_that_are_not_enforced() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
    chroot: "/var/lib/dns-rs"
    directory: "/var/lib/dns-rs"
    username: "dns"
    do-daemonize: yes
    logfile: "/var/log/dns-rs.log"
    pidfile: "/run/dns-rs.pid"
    use-syslog: yes
"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        for key in [
            "chroot",
            "directory",
            "do-daemonize",
            "logfile",
            "pidfile",
            "use-syslog",
        ] {
            assert!(
                loaded
                    .warnings
                    .iter()
                    .any(|warning| warning.message.contains(key)),
                "missing warning for {key}: {:?}",
                loaded.warnings
            );
        }
        assert_eq!(
            loaded.config.server.chroot.as_deref(),
            Some(std::path::Path::new("/var/lib/dns-rs"))
        );
    }

    #[test]
    fn string_parsing_ignores_includes() {
        let loaded = super::parse_unbound_str(
            "server:\n  interface: 127.0.0.1@5353\ninclude: \"/nonexistent.conf\"\n",
        )
        .expect("parse config");
        assert_eq!(loaded.config.server.interfaces.len(), 1);
        assert!(
            loaded
                .warnings
                .iter()
                .any(|warning| warning.message.contains("include")),
            "{:?}",
            loaded.warnings
        );
    }

    #[test]
    fn follows_relative_includes() {
        let directory = tempdir().expect("tempdir");
        let included = directory.path().join("server.conf");
        fs::write(&included, "server:\n  interface: 192.0.2.10@5353\n").expect("write include");
        let root = directory.path().join("root.conf");
        fs::write(&root, "include: \"server.conf\"\n").expect("write root");

        let loaded = parse_unbound_file(&root).expect("parse config");
        assert_eq!(loaded.config.server.interfaces.len(), 1);
        assert_eq!(
            loaded.config.server.interfaces[0]
                .socket_addr(53)
                .to_string(),
            "192.0.2.10:5353"
        );
    }

    #[test]
    fn rejects_include_cycles() {
        let directory = tempdir().expect("tempdir");
        let first = directory.path().join("first.conf");
        let second = directory.path().join("second.conf");
        fs::write(&first, "include: \"second.conf\"\n").expect("write first");
        fs::write(&second, "include: \"first.conf\"\n").expect("write second");

        let error = parse_unbound_file(&first).expect_err("cycle must fail");
        assert!(error.to_string().contains("include cycle"));
    }

    #[test]
    fn rejects_invalid_boolean_with_location() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(&path, "server:\n  do-daemonize: maybe\n").expect("write config");

        let error = parse_unbound_file(&path).expect_err("invalid boolean must fail");
        let message = error.to_string();
        assert!(message.contains("dns-rs.conf"));
        assert!(message.contains(":2:"));
        assert!(message.contains("invalid boolean"));
    }

    #[test]
    fn strips_comments_outside_quotes() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.conf");
        fs::write(&path, "server:\n  interface: 127.0.0.1@5353 # loopback\n")
            .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        assert_eq!(loaded.config.server.interfaces[0].port, Some(5353));
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn parses_unix_control_interfaces() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("control.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: unix:/run/dns-rs/dns-rs.sock
    control-interface: "/run/dns-rs/dns-rs-2.sock"
"#,
        )
        .expect("write config");

        let config = parse_unbound_file(&path).expect("parse config").config;
        assert!(config.remote_control.enabled);
        assert_eq!(
            config.remote_control.interfaces,
            vec![
                PathBuf::from("/run/dns-rs/dns-rs.sock"),
                PathBuf::from("/run/dns-rs/dns-rs-2.sock"),
            ]
        );
    }

    #[test]
    fn rejects_tcp_control_interfaces() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("control.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
"#,
        )
        .expect("write config");

        let error = parse_unbound_file(&path).expect_err("TCP control must fail");
        assert!(error.to_string().contains("Unix socket path"));
    }

    #[test]
    fn rejects_non_default_control_port() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("control.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs/dns-rs.sock
    control-port: 8954
"#,
        )
        .expect("write config");

        let error = parse_unbound_file(&path).expect_err("TCP port must fail");
        assert!(error.to_string().contains("control-port is not supported"));
    }

    #[test]
    fn rejects_duplicate_control_interfaces() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("control.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs/dns-rs.sock
    control-interface: /run/dns-rs/dns-rs.sock
"#,
        )
        .expect("write config");

        let error = parse_unbound_file(&path).expect_err("duplicate must fail");
        assert!(error.to_string().contains("duplicate control-interface"));
    }

    #[test]
    fn rejects_empty_control_interface() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("control.conf");
        fs::write(
            &path,
            r#"
server:
    interface: 127.0.0.1@5353
remote-control:
    control-enable: yes
    control-interface: ""
"#,
        )
        .expect("write config");

        let error = parse_unbound_file(&path).expect_err("empty path must fail");
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn parses_automatic_thread_count() {
        let directory = tempdir().expect("tempdir");
        let cases = [
            ("auto", ThreadCount::Auto),
            ("0", ThreadCount::Auto),
            ("6", ThreadCount::Fixed(6)),
        ];
        for (value, expected) in cases {
            let path = directory.path().join("threads.conf");
            fs::write(
                &path,
                format!("server:\n    interface: 127.0.0.1@5353\n    num-threads: {value}\n"),
            )
            .expect("write config");
            let loaded = parse_unbound_file(&path).expect("parse config");
            assert_eq!(loaded.config.server.num_threads, expected);
        }
    }

    #[test]
    fn included_file_reports_its_own_line_numbers() {
        let directory = tempdir().expect("tempdir");
        let fragment = directory.path().join("blocklist.conf");
        fs::write(
            &fragment,
            "local-zone: \"a.test\" always_nxdomain\n\nlocal-zone: \"b.test\" nonsense\n",
        )
        .expect("write fragment");
        let path = directory.path().join("unbound.conf");
        fs::write(&path, "server:\n    include: \"blocklist.conf\"\n").expect("write config");

        let error = parse_unbound_file(&path).expect_err("invalid zone type");
        match error {
            ConfigError::Parse { line, .. } => assert_eq!(line, 3),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn streams_a_large_include_without_losing_the_block() {
        let directory = tempdir().expect("tempdir");
        let mut fragment = String::with_capacity(120_000);
        for index in 0..2_000 {
            fragment.push_str(&format!(
                "local-zone: \"n{index}.ads.test\" always_nxdomain\n"
            ));
        }
        fs::write(directory.path().join("blocklist.conf"), fragment).expect("write fragment");
        let path = directory.path().join("unbound.conf");
        fs::write(
            &path,
            "server:\n    interface: 127.0.0.1@5353\n    include: \"blocklist.conf\"\n",
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        assert_eq!(loaded.config.local_zones.len(), 2_000);
        assert!(loaded.config.local_zones.iter().all(|zone| {
            zone.zone_type == LocalZoneType::AlwaysNxdomain && zone.name.ends_with(".ads.test.")
        }));
    }
}
