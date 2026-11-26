# Operations

Audience: operators running dns-rs as a host service or container. This page
covers control, observability, logging, reload behavior, and upgrades. Deployment
steps are in [Installation](installation.md) and
[Container image](container.md).

## Control socket

The control channel is opt-in and local only. Configure an absolute Unix socket
path:

```toml
[remote_control]
enabled = true
interfaces = ["/run/dns-rs/dns-rs.sock"]
port = 8953
```

Or, in Unbound syntax:

```conf
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs/dns-rs.sock
    control-port: 8953
```

There is no TCP or TLS control transport, and `control-port` must stay `8953`.
Enabling, moving, or disabling the socket requires a restart.

Security properties:

- the socket is created with mode `0600`;
- every connection is checked with peer credentials and must match the daemon's
  effective UID;
- a stale socket is removed only if it is owned by that same UID; live sockets,
  symlinks, regular files, and other users' sockets are never replaced;
- the parent directory must exist, must not be group- or world-writable unless
  it has the sticky bit, and the path must be absolute;
- at most four connections are accepted at once.

Protocol limits: one JSON request per connection, at most 4096 bytes excluding
the trailing newline; responses are capped at 64 KiB including the newline;
idle connections time out after two seconds. Unknown fields in a request are
rejected.

Commands and the binary client:

```bash
dns-rs -c /etc/dns-rs/dns-rs.conf control status
dns-rs -c /etc/dns-rs/dns-rs.conf control stats
dns-rs -c /etc/dns-rs/dns-rs.conf control stats-prometheus
dns-rs -c /etc/dns-rs/dns-rs.conf control reload
dns-rs -c /etc/dns-rs/dns-rs.conf control stop
```

`status` returns the version, PID, control uptime in seconds, and protocol
version (`1`). `stats` returns pipeline counters as JSON;
`stats-prometheus` renders the same counters as Prometheus text. `reload`
re-reads the daemon's own configuration file; the request cannot name a path.
`stop` asks the daemon to shut down. The CLI uses the first enabled control
interface; pass `--socket PATH` to override it without loading the
configuration.

The client must have the daemon's effective UID. On a host install the packaged
service runs as `dns-rs`, so prefix these commands with `sudo -u dns-rs` or
`runuser -u dns-rs --`. Running them as root is rejected; use
`systemctl reload dns-rs.service` when only a reload is needed.

Any client able to write one JSON line to the socket works. For example:

```bash
printf '{"command":"stats"}\n' | socat - UNIX-CONNECT:/run/dns-rs/dns-rs.sock
```

The `control reload` client waits up to 30 seconds because a reload can resolve
configured hostnames and read trust-anchor or CA files. Other commands use the
two-second protocol timeout.

## Statistics

| JSON field | Prometheus metric | Meaning |
|---|---|---|
| `cache_hits` | `dns_rs_cache_hits_total` | Message-cache hits |
| `cache_misses` | `dns_rs_cache_misses_total` | Message-cache misses |
| `cache_stale_hits` | `dns_rs_cache_stale_hits_total` | Expired answers served by `serve-expired` |
| `cache_entries` | `dns_rs_cache_entries` | Current message-cache entries (gauge) |
| `prefetches` | `dns_rs_prefetches_total` | Background refreshes from prefetch or serve-expired |
| `coalesce_leaders` | `dns_rs_coalesce_leaders_total` | Queries that started an upstream resolution |
| `coalesce_followers` | `dns_rs_coalesce_followers_total` | Queries that joined an in-flight resolution |
| `coalesce_abandoned` | `dns_rs_coalesce_abandoned_total` | Leaders dropped before publishing a result |
| `queries_total` | `dns_rs_queries_total` | Queries presented to the pipeline |
| `queries_by_transport` | `dns_rs_queries_by_transport_total{transport=...}` | Queries by UDP, TCP, TLS, or HTTPS |
| `responses_total` | `dns_rs_responses_total` | Encoded client replies |
| `responses_by_rcode` | `dns_rs_responses_by_rcode_total{rcode=...}` | Replies by 4-bit response code |
| `responses_truncated` | `dns_rs_responses_truncated_total` | Replies with the TC bit set |
| `responses_ede` | `dns_rs_responses_ede_total` | Replies carrying an Extended DNS Error |
| `responses_ad` | `dns_rs_responses_ad_total` | Replies with the AD bit set |
| `dnssec_secure` / `dnssec_insecure` / `dnssec_bogus` | `dns_rs_dnssec_validations_total{result=...}` | DNSSEC validation outcomes |
| `upstreams` | `dns_rs_upstream_rtt_seconds{server=...}` and related gauges | Per-upstream RTT, timeouts, failures, lameness, backoff, and DNS 0x20 state |
| `upstreams_omitted` | `dns_rs_upstreams_omitted` | Upstreams left out of the bounded report |

`queries_total` counts every query handed to the pipeline, including malformed
or denied ones; `responses_total` counts only replies that were encoded.
Response codes use the 4-bit wire value, so extended rcodes are reported by
their low nibble. DNSSEC outcomes count completed validations by the current
pipeline, including cache misses that were coalesced into an in-flight lookup.

The upstream section reports the 64 most recently used servers from the
infrastructure cache. Its RTT is the same smoothed value used for server
selection; `timeouts` and `failures` are consecutive counters reset by a
successful query. `upstreams_omitted` is nonzero when more servers are tracked
than the report can hold.

These are pipeline counters only. There is no HTTP metrics listener and no
metrics on the DNS port. Counters are attached to the current query pipeline, so
they reset on reload as well as on a process restart; in-flight queries finish
on the old pipeline. A flat or reset `uptime_secs` from `status` is the quickest
way to confirm a restart loop.

Prometheus cannot scrape the control socket directly. Use an exec-based
exporter, or bind-mount the socket's parent directory and run a host-side
collector that calls `control stats-prometheus`. See
[Container image](container.md#prometheus).

## Logging

`verbosity` sets the startup log filter: 0 warnings, 1 info, 2-3 debug with one
line per query, 4-5 trace. `-v`/`-vv` raise it to debug/trace, and `RUST_LOG`
overrides both. `RUST_LOG` and `-v` are applied only at startup; changing
`verbosity` in the file takes effect on `SIGHUP` or `control reload`.

Logs go to standard output. The daemon does not write a log file, use syslog, or
daemonize. Under systemd, use `journalctl -u dns-rs`; in Docker, use
`docker logs`. Never put credentials or private keys in configuration values
that are logged.

## Signals, reload, and restart

| Action | Effect |
|---|---|
| `SIGINT`, `SIGTERM` | Graceful shutdown; in-flight work is allowed to finish. |
| `SIGHUP` or `control reload` | Re-read configuration, rebuild the pipeline, flush caches, atomically swap. Failed reload leaves the old pipeline running. |
| Restart | Required for listener, TLS, thread, socket-buffer, and control-socket changes. |

Settings fixed when listeners are bound: `interfaces`, `port`, `do-ip4`,
`do-ip6`, `do-udp`, `do-tcp`, `num-threads`, `incoming-num-tcp`,
`tls-service-key`, `tls-service-pem`, `tls-port`, `https-port`, `http-endpoint`,
socket buffer sizes, `tcp-user-timeout`, and `remote-control`. Everything else,
including zones, ACLs, forwarders, DNSSEC settings, cache limits, and
`verbosity`, is reloadable.

When reloading a container or service that uses a bind-mounted configuration,
mount the directory rather than a single file. Editors that save by renaming
replace the host inode, and a single-file mount keeps pointing at the old
inode. See [Configuration](configuration.md#reload-and-restart).

## Healthchecks

`dns-rs -c <file> healthcheck` loads the configuration, chooses the first
plain-DNS listener, maps wildcard addresses to loopback, and asks for the
built-in `localhost.` record. Options: `--address`, `--port`, `--name`,
`--timeout` (milliseconds), and `--tcp`. It is a listener liveness probe, not an
upstream connectivity test. A container can be healthy while recursive
resolution is broken.

The image has a built-in exec-form healthcheck, so plain `docker run` with the
default config path needs no extra flags. `docker run --health-cmd` does not work
with the `scratch` image because Docker wraps that string in `/bin/sh -c`, which
does not exist there. Leave the built-in probe enabled unless you change the
config path; in that case use `--no-healthcheck` on the CLI or define an
exec-form probe in Compose or Kubernetes. A DoT/DoH-only deployment needs a
matching TCP or HTTPS probe because the built-in healthcheck requires a
plain-DNS listener.

## Upgrade and rollback checklist

1. Read the release notes and [Limitations](limitations.md); note any
   configuration change.
2. Validate the new configuration with `dns-rs -c <file> checkconf`. Treat
   warnings as migration TODOs.
3. Confirm the host clock is correct. DNSSEC validation fails with large clock
   skew.
4. Check that UDP and TCP port 53 are reachable from intended clients and that
   the resolver is not open to the internet.
5. Deploy the new binary or image, keeping the old one available.
6. Roll forward with `reload` when only reloadable settings changed; otherwise
   restart.
7. Verify with `control status`, `control stats`, `healthcheck`, and a real
   query for a signed and an unsigned name.
8. Roll back by restarting with the previous binary/image and configuration.
   Caches are not persisted, so rollback needs no state migration.

Capacity checks before production use: file-descriptor limits, CPU budget for
`num_threads`, memory for the cache entry counts, writable state directory if
RFC 5011 is enabled, and access to the control socket for monitoring.

The upstream connection pools size themselves from the process's soft
`RLIMIT_NOFILE`, so a low limit reduces idle sockets instead of failing with
`EMFILE`. A startup warning reports the effective limit and the reduced pool
capacity with the suggested override. The packaged systemd unit raises the soft
limit to 65536 because older systemd releases (including EL9) default to 1024.
When running the binary directly or in a container without that unit, raise the
limit to at least 4096 under sustained recursive load.
