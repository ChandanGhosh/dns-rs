# Configuration

Audience: anyone writing or changing a dns-rs configuration file. Start with
the [Quick start](quickstart.md); use
[`examples/minimal.toml`](../examples/minimal.toml) as a starter and
[`examples/full.toml`](../examples/full.toml) /
[`examples/full.conf`](../examples/full.conf) as annotated references.

## File selection and precedence

The daemon loads one file, chosen with `-c/--config`. The default is
`dns-rs.conf` in the process working directory.

| File name | Parser | `include:` / `include-toplevel:` |
|---|---|---|
| Extension is `.toml`, case-insensitively | Native TOML | Not supported |
| Any other name, including no extension | Supported `unbound.conf` subset | Supported |

Files pulled in by `include:` are always parsed as Unbound syntax, whatever
their extension. Never mix the two syntaxes in one file: renaming a TOML file to
`.conf` makes the daemon parse it as Unbound syntax and it will fail.

There is no configuration-file search path and no environment-variable
substitution. The only environment variable read by the binary is `RUST_LOG`,
which controls logging at startup. Precedence for the log filter is:

1. `RUST_LOG`, if set;
2. `-v` / `-vv` (`debug` / `trace`), if passed;
3. `verbosity` in the configuration (0 = warnings, 1 = info, 2-3 = debug,
   4-5 = trace).

`RUST_LOG` and `-v` are read when the process starts. Changing `verbosity` in
the file and reloading applies the new level without a restart; a running
`RUST_LOG` filter continues to take precedence.

Command syntax:

```bash
dns-rs -c <file> checkconf
dns-rs -c <file> run
dns-rs -c <file> control <status|stats|stats-prometheus|reload|stop> [--socket PATH]
dns-rs -c <file> healthcheck [--address IP] [--port PORT] [--name NAME] [--timeout MS] [--tcp]
```

`checkconf` prints the configuration path, resolved interfaces, thread count,
forward-zone count, the control socket paths when remote control is enabled, and
the warning count when there are warnings. It does not read TLS certificates,
root-hint files, or trust-anchor files; those are opened when the resolver
starts.

Unsupported options are accepted with a warning and ignored. Invalid values,
duplicate zones, a missing interface, and a configuration file that cannot be
read are fatal. A glob include that matches no files warns rather than fails,
but treat that warning as a migration problem: the missing file may have
supplied local data or trust anchors.

## TOML layout

TOML has two kinds of settings:

- Root-level keys before the first table header: `local_data`, `local_zones`,
  `auth_zones`, `stub_zones`, `forward_zones`, and `views`.
- `[server]` for resolver behavior, including `root_hints` and
  `access_control_view`, and `[remote_control]` for the control socket.

Placing a root-level key after `[server]` makes TOML treat it as a server field
and loading fails. Zone names in TOML must be fully qualified with a trailing
dot, and local-zone policies use kebab-case (`always-nxdomain`, not
`always_nxdomain`). The Unbound parser appends the root label and accepts
underscores.

The tables below describe the main groups. For every field, its type and
default, see [`examples/full.toml`](../examples/full.toml) or the source of
truth in [`crates/dns-config/src/model.rs`](../crates/dns-config/src/model.rs).

| Group | Keys | Notes |
|---|---|---|
| Listeners | `interfaces`, `port`, `tls_port`, `https_port`, `http_endpoint`, `tls_service_key`, `tls_service_pem` | At least one interface is required. The listener protocol is selected by port. DoT/DoH are enabled only when both TLS files are set. |
| Runtime | `num_threads`, `verbosity` | `0` or `"auto"` for `num_threads` uses all CPUs visible to the process. Default: `1`. `verbosity` is reloadable; `num_threads` is not. |
| Transports | `do_ip4`, `do_ip6`, `do_udp`, `do_tcp`, `outgoing_interfaces` | At least one IP family and one transport must stay enabled. |
| Access control | `access_control`, `access_control_view` | Strings like `"10.0.0.0/8 allow"`. The most specific matching prefix wins; later equal-prefix entries win ties; no match is `REFUSED`. |
| DNSSEC | `dnssec_validation`, `domain_insecure`, `trust_anchor`, `trust_anchor_file`, `auto_trust_anchor_file`, `nsec3_max_iterations`, `val_permissive_mode` | Validation is on by default with built-in root anchors. `val_permissive_mode` still validates but returns bogus data with `AD=0` instead of `SERVFAIL`. |
| Privacy | `qname_minimisation`, `qname_minimisation_strict`, `use_caps_for_id` | `use_caps_for_id` defaults to `true`, unlike Unbound. |
| Rebinding | `private_address`, `private_domain` | See [Rebinding protection](#rebinding-protection). |
| Caching | `cache_min_ttl`, `cache_max_ttl`, `cache_max_negative_ttl`, `prefetch`, `serve_expired`, `serve_expired_ttl`, `serve_expired_reply_ttl` | Caches are bounded by entry count, not bytes. |
| Upstreams | `forward_zones`, `stub_zones`, `root_hints`, `do_not_query_address`, `do_not_query_localhost` | See [Choosing an upstream model](#choosing-an-upstream-model). |
| Local data | `local_data`, `local_zones`, `auth_zones`, `views` | Zonefile loading only; no AXFR or URL fetch. |
| Upstream TLS | `tls_cert_bundle`, `tls_use_system_ca` | With `tls_use_system_ca = true` (default), dns-rs uses the compiled-in `webpki-roots` set; it does not read the OS CA store. Use `tls_cert_bundle` for private CAs. |
| Limits | `ratelimit`, `ratelimit_slip`, `incoming_num_tcp`, socket buffer sizes | Enforced. Unbound byte-sized cache options are not. |

### Rebinding protection

dns-rs removes A and AAAA records, and SVCB/HTTPS address hints, whose address
is in `private_address` unless the record owner is covered by `private_domain`.
Local, auth, and stub zones are exempt because their data is configured
locally.

The default `private_address` list is exactly:

```text
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
fd00::/8
fe80::/10
::ffff:0:0/96
```

The default `private_domain` list is `local`, `localdomain`, `lan`, `home`,
`home.arpa`, `internal`, `intranet`, `corp`, `private`, `test`, and `localhost`.
Setting either list replaces the built-in defaults rather than appending to
them. An empty `private_address = []` disables address filtering. In Unbound
syntax, empty lists are rejected; use TOML if you need that behavior.

### Local namespaces

The local suffixes above, except `test`, and the private reverse zones are
built into the resolver. They are always routed to the default gateway over
plain DNS and are never sent to a public, DoT, or DoH resolver, regardless of
`forward-zone` settings for `.`. If no default gateway is available, those
names are REFUSED. A more specific `forward-zone` for a local name is honored
only when it also uses a plain on-LAN server. `test` is excluded so examples
and test fixtures keep working; add an explicit plain on-LAN forward zone for
it if the LAN resolves `.test` names. `examples/full.conf` and
`examples/full.toml` show one explicit local-zone override.

### Zones and blocklists

TOML uses arrays of tables:

```toml
local_data = ["router.home. 3600 IN A 192.168.1.1"]

[[local_zones]]
name = "ads.example."
type = "always-nxdomain"
```

The equivalent Unbound syntax is:

```conf
server:
    local-data: "router.home. 3600 IN A 192.168.1.1"
    local-zone: "ads.example." always_nxdomain
```

TOML has no includes, so generate the whole file when you maintain a large
blocklist. The `.conf` front-end can split zones and blocklists across files
with `include:`; see
[Container image](container.md#configuration-files-zones-and-blocklists).
Redundant `always_nxdomain` entries under the same policy are suppressed at
load time, which keeps large generated blocklists small. A descendant with a
different policy is preserved.

## The `unbound.conf` subset

Any filename whose extension is not `.toml` uses this parser. It supports the
main `server:` options, `forward-zone:`, `stub-zone:`, `auth-zone:`, `view:`,
`remote-control:`, and includes. Relative includes are tried against the
including file's directory first, then the process working directory. Includes
are processed in sorted glob order; cycles are fatal.

Differences that need an operator decision are collected in
[Unbound compatibility](unbound-compatibility.md), and a migration walkthrough
is in [Unbound migration](unbound-migration.md). The compatibility guide also
lists the process-management options that are parsed but not applied:
`chroot`, `directory`, `logfile`, `pidfile`, `use-syslog`, and
`do-daemonize`.

### Privilege drop

`username` is enforced on Unix. The daemon resolves the account before binding,
creates the listeners and control socket with its original privileges, hands the
control socket and an existing RFC 5011 state file to the target account, then
drops supplementary groups, the primary group, and finally the user ID. The
effective IDs are verified before startup continues, so a failed switch is
fatal rather than a silent downgrade.

This lets a root-started daemon bind port 53 and read root-owned TLS keys and
trust anchors while serving queries unprivileged. The target account must still
be able to read the configuration, TLS material, trust anchors, zonefiles, and
any CA bundle for a later reload, and must be able to write the directory that
holds `auto_trust_anchor_file`. The `scratch` container has no user database, so
`username` cannot be resolved there; run the container as a non-root user
through the container runtime instead. `chroot`, `directory`, `logfile`,
`pidfile`, `use-syslog`, and `do-daemonize` remain parsed but unapplied.

## Choosing an upstream model

Pick one model deliberately:

- **Iterative by default.** dns-rs primes from built-in root hints, or from
  `root_hints` / `root-hints:` files if configured. No forward zone is needed.
  This exercises full DNSSEC validation and needs outbound UDP/TCP port 53.
- **Forwarding.** A `forward-zone: name: "."` or `[[forward_zones]]` with
  `name = "."` sends every query upstream. Use DoT or DoH on untrusted
  networks. `forward-first` tries the forwarder before iteration;
  `forward-fallback` keeps iteration as the primary path and only asks
  forwarders when iteration fails.
- **Stub zones** point at authoritative servers for specific names, typically
  local or split-horizon zones.

Do not leave a `.` forward zone and a root-hints file active together by
accident. `forward-host` and `stub-host` names are resolved once at startup, so
a reload is needed when their addresses change. `do_not_query_localhost`
defaults to `true`; set it to `false` if you intentionally forward to a
resolver on loopback.

## Remote control

The control channel is opt-in and uses a Unix socket only:

```toml
[remote_control]
enabled = true
interfaces = ["/run/dns-rs.sock"]
port = 8953
```

```conf
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs.sock
    control-port: 8953
```

`control-port` must remain `8953`; there is no TCP control transport. The socket
must be an absolute path, is created with mode `0600`, and accepts only
processes with the daemon's effective UID. Enabling, moving, or disabling it
requires a restart. See [Operations](operations.md) for commands and limits.

## Reload and restart

`SIGHUP` and `control reload` re-read the file the daemon started with, rebuild
the query pipeline, and flush caches. The swap is atomic: in-flight queries
finish on the old pipeline. A failed reload leaves the running configuration
unchanged. The client waits up to 30 seconds for a reload because it may need
to resolve hostnames and read anchor or CA files.

The following changes are fixed when listeners are bound and are reported as
requiring a restart:

- `interfaces`, `port`
- `do-ip4`, `do-ip6`, `do-udp`, `do-tcp`
- `num-threads`, `incoming-num-tcp`
- `tls-service-key`, `tls-service-pem`
- `tls-port`, `https-port`, `http-endpoint`
- `udp-recv-buffer-size`, `udp-send-buffer-size`
- `tcp-recv-buffer-size`, `tcp-send-buffer-size`, `tcp-user-timeout`
- `remote-control`

Everything else, including zones, ACLs, DNSSEC settings, forwarders, cache
limits, and `verbosity`, is applied by a reload.
