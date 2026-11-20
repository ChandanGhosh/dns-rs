# Unbound configuration compatibility

dns-rs reads a practical subset of Unbound's `unbound.conf` directly. The goal
is that a typical distribution configuration can be loaded after a short audit,
and that recognized options either take effect or produce an explicit warning.
Invalid values and duplicate zones are fatal; recognized compatibility options
are not silently ignored.

For a practical migration path, a recommended baseline, and container
deployment guidance, see [Migrating from Unbound](unbound-migration.md). This
page is the option-by-option reference.

The implementation lives in `crates/dns-config`; the end-to-end fixtures in
`crates/dns-config/tests/unbound_compat.rs` pin the behavior described here.

## Loading rules

- Any file whose extension is not `.toml` (case-insensitively) is parsed as
  `unbound.conf` syntax.
- Unknown options are accepted with a warning naming the option. Options with
  a dedicated compatibility arm explain what is missing and how to get the
  behaviour another way. The lists below group the options that stock
  configurations commonly set; they are not an exhaustive field list. See
  [Configuration](configuration.md) for the complete model.
- `include:` and `include-toplevel:` accept files, absolute paths, and `glob(7)`
  wildcards. Matches are processed in sorted order so includes are
  deterministic; directories matched by a wildcard are skipped.
- A relative include is tried against the including file's directory first, then
  the process working directory.
- `include:` keeps the active clause, so a file containing only `key: value`
  lines continues the `server:` block that included it. `include-toplevel:`
  closes the active clause before and after the include, exactly as Unbound
  documents.
- Include cycles are detected and reported as a fatal error.
- A wildcard that matches nothing produces a warning instead of failing, so an
  empty `unbound.conf.d/` is not fatal.

## Enforced options

### Access control

| Option | Notes |
| --- | --- |
| `access-control` | `deny`, `refuse`, `allow`, `allow_setrd`, `allow_snoop`, `deny_non_local`, `refuse_non_local`. The most specific netblock wins regardless of statement order; later statements win ties. No match means `refuse`. |
| `access-control-view` | Maps a client netblock to a `view:`. |
| `interface-view` | Parsed and reported as a warning; per-interface views are not implemented. |

`allow_cookie` is accepted and mapped to `allow` with a warning because DNS
cookie enforcement for clients is not implemented.

### Upstream selection

| Option | Notes |
| --- | --- |
| `forward-addr` | Plain DNS, DoT (`#auth-name`, port 853 default), and DoH (`https://`). |
| `forward-host` | Resolved once at startup through the system resolver. Reload the configuration to pick up address changes. |
| `forward-first`, `forward-fallback`, `forward-tls-upstream` | Enforced. `forward-ssl-upstream` is accepted as an alias. |
| `stub-addr`, `stub-host`, `stub-prime`, `stub-first`, `stub-no-cache`, `stub-tls-upstream` | Enforced. `stub-host` is also resolved at startup. |
| `do-not-query-address` | Netblocks are never queried. Applied to configured upstreams at startup and to addresses learned from referrals. |
| `do-not-query-localhost` | Default `yes`. Adds `127.0.0.0/8` and `::1/128`, matching Unbound. Set `no` to allow loopback forwarders. |
| `root-hints` | Loads NS/glue addresses from the named file and seeds root priming. If the file cannot be read the built-in hints are used with a warning. |
| `tls-cert-bundle` | PEM bundle of CA certificates for upstream DoT/DoH. Combine with `tls-use-system-ca: no` for a private CA; both sources can also be enabled together. |
| `tls-use-system-ca` | Default `yes`. Adds the compiled-in `webpki-roots` set; it does not read the host's CA store. Set `no` and configure `tls-cert-bundle` when using only a private CA. |

### Local data

| Option | Notes |
| --- | --- |
| `local-zone`, `local-data`, `local-data-ptr` | Enforced. |
| `view`, `view-first` | Enforced for local zones and data. |
| `auth-zone` with `zonefile` | Zonefile loading only. |

`local-data` records without a TTL use 3600 seconds, matching Unbound. An
explicit TTL in the record is preserved. Relative names in `local-zone` and
`local-data` are resolved against the root, so `local-zone: "example.com"` and
`local-zone: "example.com."` are the same zone.

### DNSSEC and hardening

`validator`, `domain-insecure`, `trust-anchor`, `trust-anchor-file`,
`auto-trust-anchor-file`, `harden-glue`, `harden-dnssec-stripped`,
`nsec3-max-iterations`, `val-permissive-mode`, `val-clean-additional`,
`qname-minimisation`, `qname-minimisation-strict`, and `use-caps-for-id` are
enforced.

### Serving and limits

Interfaces, ports, IPv4/IPv6 transport switches, UDP/TCP limits, TLS/HTTPS
listener material, socket buffer sizes (`udp-recv-buffer-size`,
`udp-send-buffer-size`, `tcp-recv-buffer-size`, `tcp-send-buffer-size`), TTL
bounds, negative-TTL bounds (`cache-max-negative-ttl`), prefetch, serve-expired,
rate limiting, and per-client concurrency limits are enforced. The
infrastructure cache honours
`infra-host-ttl`, `infra-cache-min-rtt`, and `infra-cache-numhosts`.
`so-reuseport: yes` and `delay-close: 0` describe the resolver's existing
behaviour. Options that describe process management (`username`, `chroot`,
`directory`, `logfile`, `pidfile`, `use-syslog`, `do-daemonize`) are parsed for
compatibility but are not applied; the container and service manager own those
concerns.

`insecure-lan-zones: yes` marks the private reverse zones (`10.in-addr.arpa`,
`168.192.in-addr.arpa`, the RFC 1918 and IPv6 equivalents) as insecure so local
resolution does not require DNSSEC proofs for them.

## Accepted with a warning

These options are recognized so that a stock configuration loads, but the
feature is not implemented. The warning names the option and, where useful, the
alternative.

- `module-config` with `subnetcache`, `respip`, or `dynlib`.
- `tls-enforce-name-check`. Certificate name checking is controlled by the
  forwarder's `forward-addr` auth name (`#auth-name`); add a specific auth name
  when verification is required.
- `unblock-lan-zones: no` (see the divergences below).
- `allow_cookie`.
- `response-ip` and `response-ip-data`.
- Auth-zone transfers: `primary`, `master`, `url`, `fallback-enabled`, and
  `allow-notify`. Only `zonefile` data is served.
- Logging switches: `log-queries`, `log-replies`, `log-servfail`,
  `log-local-actions`, and `log-time-ascii`. Per-query lines follow `verbosity`
  and `RUST_LOG`; the process supervisor owns log formatting.
- Cache sizing in bytes and slabs: `msg-cache-size`, `msg-cache-slabs`,
  `rrset-cache-size`, `rrset-cache-slabs`, `key-cache-size`, `key-cache-slabs`,
  `neg-cache-size`, and `infra-cache-slabs`. The caches are bounded by entry
  count instead.
- Connection and scheduling tuning: `msg-buffer-size`, `outgoing-range`,
  `num-queries-per-thread`, and `jostle-timeout`. `so-reuseport: no` and a
  non-zero `delay-close` also warn; the UDP listeners always set
  `SO_REUSEPORT`, and TCP connections close immediately.
- Unbound socket buffer options `so-rcvbuf` and `so-sndbuf`. Use
  `udp-recv-buffer-size`, `udp-send-buffer-size`, `tcp-recv-buffer-size`, and
  `tcp-send-buffer-size` instead.
- DNSSEC tuning beyond the enforced options: `prefetch-key`, `val-bogus-ttl`,
  `val-log-level`, `val-sig-skew-min`, and `val-sig-skew-max`.
- Hardening switches: `harden-short-bufsize`, `harden-large-queries`,
  `harden-below-nxdomain`, and `unwanted-reply-threshold`.
- `minimal-responses`.
- `hide-identity`, `hide-version`, `identity`, and `version`. CHAOS-class
  identity queries are not answered, so these options have no effect to apply.
- Unrecognized `server:` options and unknown blocks.

## Divergences from Unbound

These are intentional. Each one either favors a secure default or reflects a
feature that is out of scope.

1. **Rebinding protection is on by default.** Unbound ships with empty
   `private-address` and `private-domain` lists. dns-rs blocks RFC 1918,
   link-local, IPv6 unique-local, and IPv4-mapped answers by default and allows
   common local namespaces (`.lan`, `.home.arpa`, `.internal`, and similar). The
   exact defaults are listed in
   [Configuration](configuration.md#rebinding-protection). An explicit
   `private-address:` or `private-domain:` list replaces the built-in defaults;
   empty values are rejected in `unbound.conf` syntax. Use the TOML front-end
   with `private_address = []` and `private_domain = []` if you need Unbound's
   empty-list behavior exactly.
2. **`use-caps-for-id` defaults to `yes`.** Unbound defaults to `no`. The option
   only affects upstream traffic; set `use-caps-for-id: no` for byte-for-byte
   matching behavior.
3. **Private reverse zones are always resolved upstream.** dns-rs behaves as if
   `unblock-lan-zones: yes` were set. `unblock-lan-zones: no` is accepted with a
   warning because implementing the blocked form would require an additional
   local-zone layer.
4. **Relative includes prefer the including file's directory.** Unbound resolves
   them against its working directory (or chroot). The fallback keeps
   `include: "/etc/unbound/unbound.conf.d/*.conf"`-style configurations working
   from an arbitrary current directory.
5. **The control channel is not `unbound-control`.** `remote-control:` opens a
   Unix socket that speaks one JSON command per line. The wire protocol is not
   compatible with the Unbound client.

## Not implemented

RPZ, DNS64, response-IP filtering, per-interface views, auth-zone AXFR/URL
fetching, and DNS-over-QUIC. Configurations that use these options load with
warnings.
