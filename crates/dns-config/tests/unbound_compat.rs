//! End-to-end tests for the `unbound.conf` front-end.
//!
//! The fixtures mirror the layouts shipped by Linux distributions: a main file
//! plus a `conf.d` directory pulled in with a glob, options written by
//! `debconf`, and blocks that dns-rs does not implement. The assertions pin
//! both the enforced values and the warning set so compatibility cannot
//! regress silently.

use std::fs;
use std::path::{Path, PathBuf};

use dns_config::{ConfigError, LocalZoneType, load};
use tempfile::TempDir;

const ROOT_HINTS: &str = "\
.                        3600000      NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
";

fn write(directory: &Path, name: &str, contents: &str) -> PathBuf {
    let path = directory.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create directory");
    }
    fs::write(&path, contents).expect("write fixture");
    path
}

fn fixture() -> TempDir {
    tempfile::tempdir().expect("tempdir")
}

fn messages(loaded: &dns_config::LoadedConfig) -> Vec<&str> {
    loaded
        .warnings
        .iter()
        .map(|warning| warning.message.as_str())
        .collect()
}

#[test]
fn loads_a_stock_style_config_tree() {
    let directory = fixture();
    let root = directory.path();
    write(root, "root.hints", ROOT_HINTS);
    write(
        root,
        "unbound.conf.d/10-local.conf",
        r#"
server:
    local-zone: "lan." static
    local-data: "router.lan. IN A 192.168.1.1"
"#,
    );
    write(
        root,
        "unbound.conf.d/20-forward.conf",
        r#"
forward-zone:
    name: "."
    forward-host: localhost
    forward-first: no
"#,
    );
    write(
        root,
        "unbound.conf.d/30-acl.conf",
        r#"
server:
    access-control: 192.168.0.0/16 allow
"#,
    );
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 53
    verbosity: 1
    do-daemonize: no
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
    root-hints: "root.hints"
    private-domain: "lan."

include: "unbound.conf.d/*.conf"
"#,
    );

    let loaded = load(&main).expect("stock-style config");
    let config = &loaded.config;

    assert_eq!(config.server.port, 53);
    assert_eq!(config.local_zones.len(), 1);
    assert_eq!(config.local_zones[0].name, "lan.");
    assert_eq!(config.local_zones[0].zone_type, LocalZoneType::Static);
    assert_eq!(config.local_data, vec!["router.lan. IN A 192.168.1.1"]);

    // The glob pulled in the forward zone and the second ACL statement.
    assert_eq!(config.forward_zones.len(), 1);
    assert_eq!(config.forward_zones[0].forward_hosts, vec!["localhost"]);
    assert!(
        config
            .server
            .access_control
            .iter()
            .any(|rule| rule.to_string() == "192.168.0.0/16 allow"),
        "{:?}",
        config.server.access_control
    );

    // Relative includes resolve against the including file.
    assert_eq!(
        config.server.root_hints,
        vec![PathBuf::from("root.hints")],
        "root-hints is stored verbatim for later resolution"
    );
    let hints = dns_config::load_root_hints(&[root.join(&config.server.root_hints[0])])
        .expect("root hints");
    assert_eq!(hints, vec!["198.41.0.4:53".parse().expect("address")]);

    let warnings = messages(&loaded);
    assert!(
        !warnings.iter().any(|message| message.contains("include")),
        "includes must be resolved: {warnings:?}"
    );
}

#[test]
fn include_keeps_the_active_block() {
    let directory = fixture();
    let root = directory.path();
    write(
        root,
        "server-options.inc",
        "    verbosity: 3\n    do-ip6: no\n",
    );
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
include: "server-options.inc"
"#,
    );

    let loaded = load(&main).expect("included bare options stay in server:");
    assert_eq!(loaded.config.server.verbosity, 3);
    assert!(!loaded.config.server.do_ip6);
}

#[test]
fn include_toplevel_closes_the_current_block() {
    let directory = fixture();
    let root = directory.path();
    write(
        root,
        "whole-zone.conf",
        r#"
stub-zone:
    name: "corp.example."
    stub-addr: 192.0.2.53
"#,
    );
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
    verbosity: 2
    include-toplevel: "whole-zone.conf"
"#,
    );

    let loaded = load(&main).expect("include-toplevel");
    assert_eq!(loaded.config.stub_zones.len(), 1);

    // After `include-toplevel` the outer file is back at the top level, so a
    // bare option is an error rather than belonging to the server block.
    let bad = write(
        root,
        "bad.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
    include-toplevel: "whole-zone.conf"
    verbosity: 4
"#,
    );
    let error = load(&bad).expect_err("bare option after include-toplevel");
    assert!(
        matches!(error, ConfigError::Parse { .. }),
        "expected a parse error, got {error}"
    );
}

#[test]
fn missing_glob_is_reported() {
    let directory = fixture();
    let root = directory.path();
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353

include: "conf.d/*.conf"
"#,
    );

    let loaded = load(&main).expect("config with an empty include directory");
    assert!(
        messages(&loaded)
            .iter()
            .any(|message| message.contains("matched no files")),
        "{:?}",
        loaded.warnings
    );
}

#[test]
fn include_cycles_are_still_detected() {
    let directory = fixture();
    let root = directory.path();
    write(root, "b.conf", "include: \"a.conf\"\n");
    let main = write(
        root,
        "a.conf",
        "server:\n    interface: 127.0.0.1\n    port: 5353\ninclude: \"b.conf\"\n",
    );

    let error = load(&main).expect_err("cycle");
    assert!(matches!(error, ConfigError::IncludeCycle(_)), "{error}");
}

#[test]
fn unsupported_options_warn_instead_of_failing() {
    let directory = fixture();
    let root = directory.path();
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
    hide-identity: yes
    so-reuseport: no
    delay-close: 100
    module-config: "respip validator iterator"
    tls-enforce-name-check: yes
    unblock-lan-zones: no
    access-control: 192.0.2.0/24 allow_cookie
    do-not-query-address: 203.0.113.0/24
    do-not-query-localhost: no

auth-zone:
    name: "example."
    primary: 192.0.2.1
"#,
    );

    let loaded = load(&main).expect("unsupported options must not be fatal");
    let warnings = messages(&loaded);

    for expected in [
        "unsupported option 'hide-identity'",
        "so-reuseport: no",
        "delay-close: 100",
        "respip",
        "tls-enforce-name-check",
        "unblock-lan-zones: no",
        "allow_cookie",
        "primary",
    ] {
        assert!(
            warnings.iter().any(|message| message.contains(expected)),
            "missing warning containing {expected:?}: {warnings:?}"
        );
    }

    // The supported parts of those statements still take effect.
    assert!(!loaded.config.server.do_not_query_localhost);
    assert_eq!(
        loaded.config.server.do_not_query_address,
        vec!["203.0.113.0/24"]
    );
    assert_eq!(loaded.config.auth_zones[0].primaries, vec!["192.0.2.1"]);
    assert_eq!(
        loaded.config.server.do_not_query_networks().len(),
        1,
        "localhost is no longer blocked, so only the explicit netblock remains"
    );
}

#[test]
fn do_not_query_localhost_is_on_by_default() {
    let directory = fixture();
    let root = directory.path();
    let main = write(
        root,
        "unbound.conf",
        "server:\n    interface: 127.0.0.1\n    port: 5353\n",
    );

    let loaded = load(&main).expect("defaults");
    let networks = loaded.config.server.do_not_query_networks();
    assert_eq!(networks.len(), 2, "{networks:?}");
    assert!(networks.contains(&"127.0.0.0/8".parse().expect("net")));
    assert!(networks.contains(&"::1/128".parse().expect("net")));
}

#[test]
fn relative_local_zone_names_and_docker_style_options_load() {
    let directory = fixture();
    let root = directory.path();
    write(
        root,
        "blocklist.conf",
        r#"
server:
    local-zone: "ads.example" redirect
    local-data: "ads.example A 127.0.0.1"
"#,
    );
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
    cache-max-negative-ttl: 120
    infra-host-ttl: 600
    infra-cache-min-rtt: 25
    infra-cache-numhosts: 2048
    so-reuseport: yes
    delay-close: 0

include: "blocklist.conf"
"#,
    );

    let loaded = load(&main).expect("docker-style config");
    let server = &loaded.config.server;

    assert_eq!(server.cache_max_negative_ttl, 120);
    assert_eq!(server.infra_host_ttl, 600);
    assert_eq!(server.infra_cache_min_rtt, 25);
    assert_eq!(server.infra_cache_numhosts, 2048);
    assert_eq!(loaded.config.local_zones.len(), 1);
    assert_eq!(loaded.config.local_zones[0].name, "ads.example.");
    assert_eq!(
        loaded.config.local_zones[0].zone_type,
        LocalZoneType::Redirect
    );
    assert_eq!(loaded.config.local_data, vec!["ads.example A 127.0.0.1"]);

    let warnings = messages(&loaded);
    for key in [
        "cache-max-negative-ttl",
        "infra-host-ttl",
        "infra-cache-min-rtt",
        "infra-cache-numhosts",
        "so-reuseport",
        "delay-close",
    ] {
        assert!(
            !warnings.iter().any(|message| message.contains(key)),
            "enforced option {key} must not warn: {warnings:?}"
        );
    }
}

#[test]
fn insecure_lan_zones_adds_private_reverse_zones() {
    let directory = fixture();
    let root = directory.path();
    let main = write(
        root,
        "unbound.conf",
        r#"
server:
    interface: 127.0.0.1
    port: 5353
    insecure-lan-zones: yes
"#,
    );

    let loaded = load(&main).expect("insecure-lan-zones");
    let domains = loaded
        .config
        .server
        .insecure_domains()
        .iter()
        .map(|name| name.to_ascii())
        .collect::<Vec<_>>();
    assert!(
        domains.contains(&"10.in-addr.arpa.".to_owned()),
        "{domains:?}"
    );
    assert!(
        domains.contains(&"168.192.in-addr.arpa.".to_owned()),
        "{domains:?}"
    );
    assert!(
        domains.contains(&"8.b.d.0.1.0.0.2.ip6.arpa.".to_owned()),
        "{domains:?}"
    );
}
