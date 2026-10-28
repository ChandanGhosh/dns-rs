use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use crate::error::{ConfigError, ConfigWarning, LoadedConfig};
use crate::model::{
    AccessControl, AccessControlView, Config, ForwardTarget, ListenAddress, LocalZoneConfig,
    LocalZoneType,
};

/// Parse an `unbound.conf`-style file.
pub(crate) fn parse_unbound_file(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let mut parser = Parser::default();
    parser.load_file(path)?;
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
        }
    }
}

impl Parser {
    fn load_file(&mut self, path: &Path) -> Result<(), ConfigError> {
        let canonical = std::fs::canonicalize(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if self.include_stack.iter().any(|entry| entry == &canonical) {
            return Err(ConfigError::IncludeCycle(canonical));
        }
        let text = std::fs::read_to_string(&canonical).map_err(|source| ConfigError::Io {
            path: canonical.clone(),
            source,
        })?;

        self.include_stack.push(canonical.clone());
        let result = self.parse_text(&canonical, &text);
        self.include_stack.pop();
        result
    }

    fn parse_text(&mut self, path: &Path, text: &str) -> Result<(), ConfigError> {
        let mut block = Block::None;

        for (index, raw_line) in text.lines().enumerate() {
            let line_number = index + 1;
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
                "include" => {
                    let include = parse_scalar(value);
                    if include.is_empty() {
                        return Err(ConfigError::parse(
                            path,
                            line_number,
                            "include path is empty",
                        ));
                    }
                    if include.contains(['*', '?', '[']) {
                        self.warn(
                            path,
                            line_number,
                            "include globs are not supported yet; entry ignored",
                        );
                        continue;
                    }
                    let include_path = resolve_include(path, &include);
                    self.load_file(&include_path)?;
                    continue;
                }
                "include-toplevel" => {
                    self.warn(
                        path,
                        line_number,
                        "include-toplevel is not supported yet; entry ignored",
                    );
                    continue;
                }
                _ => {}
            }

            if value.is_empty() {
                match key {
                    "server" => {
                        block = Block::Server;
                        continue;
                    }
                    "forward-zone" => {
                        self.config.forward_zones.push(Default::default());
                        let zone_index = self.config.forward_zones.len() - 1;
                        block = Block::Forward(zone_index);
                        continue;
                    }
                    "stub-zone" => {
                        self.config.stub_zones.push(Default::default());
                        let zone_index = self.config.stub_zones.len() - 1;
                        block = Block::Stub(zone_index);
                        continue;
                    }
                    "auth-zone" => {
                        self.config.auth_zones.push(Default::default());
                        let zone_index = self.config.auth_zones.len() - 1;
                        block = Block::Auth(zone_index);
                        continue;
                    }
                    "view" => {
                        self.config.views.push(Default::default());
                        let view_index = self.config.views.len() - 1;
                        block = Block::View(view_index);
                        continue;
                    }
                    "remote-control" => {
                        block = Block::RemoteControl;
                        continue;
                    }
                    "python" | "dynlib" | "rpz" => {
                        self.warn(
                            path,
                            line_number,
                            format!("'{key}' blocks are not supported yet; block ignored"),
                        );
                        block = Block::Ignored;
                        continue;
                    }
                    _ if matches!(block, Block::None) => {
                        self.warn(
                            path,
                            line_number,
                            format!("unsupported top-level block '{key}'; block ignored"),
                        );
                        block = Block::Ignored;
                        continue;
                    }
                    _ => {}
                }
            }

            match block {
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
                self.config.server.num_threads = parse_usize(path, line, key, value)?;
            }
            "do-daemonize" => self.config.server.do_daemonize = parse_bool(path, line, key, value)?,
            "username" => self.config.server.username = optional_string(value),
            "chroot" => self.config.server.chroot = optional_path(value),
            "directory" => self.config.server.directory = optional_path(value),
            "logfile" => self.config.server.logfile = optional_path(value),
            "pidfile" => self.config.server.pidfile = optional_path(value),
            "use-syslog" => self.config.server.use_syslog = parse_bool(path, line, key, value)?,
            "do-ip4" => self.config.server.do_ip4 = parse_bool(path, line, key, value)?,
            "do-ip6" => self.config.server.do_ip6 = parse_bool(path, line, key, value)?,
            "do-udp" => self.config.server.do_udp = parse_bool(path, line, key, value)?,
            "do-tcp" => self.config.server.do_tcp = parse_bool(path, line, key, value)?,
            "access-control" => {
                let control = AccessControl::from_str(value)
                    .map_err(|message| ConfigError::parse(path, line, message))?;
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
            "harden-glue" => self.config.server.harden_glue = parse_bool(path, line, key, value)?,
            "harden-dnssec-stripped" => {
                self.config.server.harden_dnssec_stripped = parse_bool(path, line, key, value)?;
            }
            "module-config" => {
                let modules = parse_scalar(value);
                let lower = modules.to_ascii_lowercase();
                self.config.server.dnssec_validation =
                    lower.split_whitespace().any(|module| module == "validator");
                if !lower.split_whitespace().all(|module| {
                    matches!(
                        module,
                        "validator" | "iterator" | "subnetcache" | "respip" | "dynlib"
                    )
                }) {
                    self.warn(
                        path,
                        line,
                        format!("unsupported module-config {modules:?}; using validator iterator"),
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
            "forward-tls-upstream" => {
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
            "primary" | "master" => self.config.auth_zones[zone_index]
                .primaries
                .push(parse_scalar(value)),
            "url" => self.config.auth_zones[zone_index]
                .urls
                .push(parse_scalar(value)),
            "fallback-enabled" => {
                self.config.auth_zones[zone_index].fallback_enabled =
                    parse_bool(path, line, key, value)?;
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
                self.config
                    .remote_control
                    .interfaces
                    .push(parse_scalar(value));
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

fn resolve_include(base: &Path, include: &str) -> PathBuf {
    let include = Path::new(include);
    if include.is_absolute() {
        include.to_path_buf()
    } else {
        base.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(include)
    }
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
    Ok(LocalZoneConfig {
        name: name.clone(),
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
                if let Some(last) = before.chars().last() {
                    if last.is_whitespace() {
                        return before;
                    }
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

    use tempfile::tempdir;

    use crate::model::LocalZoneType;

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

remote-control:
    control-enable: yes
    control-interface: 127.0.0.1
    control-port: 8953
"#,
        )
        .expect("write config");

        let loaded = parse_unbound_file(&path).expect("parse config");
        let config = loaded.config;

        assert_eq!(config.server.interfaces.len(), 2);
        assert_eq!(config.server.port, 5353);
        assert_eq!(config.server.verbosity, 2);
        assert_eq!(config.server.num_threads, 2);
        assert_eq!(config.server.incoming_num_tcp, 32);
        assert!(!config.server.do_daemonize);
        assert_eq!(config.server.access_control.len(), 2);
        assert_eq!(
            config.server.domain_insecure,
            vec!["docker.com".to_owned(), "internal.example.".to_owned()]
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

        assert!(config.remote_control.enabled);
        assert_eq!(config.remote_control.port, 8953);
        assert!(loaded.warnings.is_empty());
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
}
