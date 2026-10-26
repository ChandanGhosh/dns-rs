# dns-rs

A validating, recursive, caching DNS resolver written in Rust, designed around the
behavior and operational model of [Unbound](https://github.com/NLnetLabs/unbound).

> **Status: working resolver, pre-1.0.** The daemon serves plain DNS over UDP and
> TCP, DNS-over-TLS and DNS-over-HTTPS; resolves iteratively from the root or
> through forward/stub zones; validates DNSSEC; and caches with prefetch and
> RFC 8767 serve-expired. See [Implemented](#implemented) and
> [Not yet implemented](#not-yet-implemented) for the exact boundary.

## Quick start

The example configurations listen on loopback port 5353, so they can run without
root privileges.

```bash
# Validate a configuration (TOML or unbound.conf syntax)
cargo run -p dns-daemon -- checkconf -c examples/minimal.toml

# Run the resolver
cargo run -p dns-daemon -- run -c examples/minimal.toml

# Query it from another terminal
dig @127.0.0.1 -p 5353 example.com A
```

Use `-v` for debug logging and `-vv` for trace logging. `RUST_LOG` overrides the
CLI verbosity. `examples/full.toml` and `examples/full.conf` are annotated
references covering every supported option, including DoT/DoH listeners and
encrypted forwarders.

## Container

The repository includes a multi-stage `Dockerfile` that cross-compiles a static
musl binary and ships it on a `scratch`, non-root runtime with a built-in DNS
healthcheck. Build and verify it locally with:

```bash
docker build -t dns-rs:dev .
PORT=15353 scripts/container-smoke.sh
```

Published images are available for `linux/amd64` and `linux/arm64`:

```bash
docker pull chandanghosh/dns-rs:26102026
```

The smoke test runs with a read-only root filesystem, all capabilities dropped
except `NET_BIND_SERVICE`, and Docker's default seccomp profile. For Compose and
Kubernetes examples, Raspberry Pi deployment notes, and the Docker Hub
publishing workflow, see [`docs/container.md`](docs/container.md).

## Implemented

**Resolution**

- Iterative resolution from the root, using built-in root hints.
- QNAME minimisation, with an optional strict mode.
- DNS 0x20 case randomisation and response scrubbing.
- DNS cookies (RFC 7873) on upstream queries.
- TCP fallback on truncation and pooled upstream connections.
- Forward zones over plain UDP, DNS-over-TLS, or DNS-over-HTTPS (`https://`
  targets), with `forward-first` fallback.
- Stub zones, including `stub-host`, `stub-prime`, `stub-first`, and
  `stub-no-cache`.
- Coalescing of identical in-flight questions.

**DNSSEC**

- RRSIG verification over canonical RRsets and DNSKEY/DS chain-of-trust checks.
- NSEC and NSEC3 denial-of-existence proofs.
- Extended DNS Errors in responses for bogus and insecure validation outcomes.
- Built-in root trust anchors, extra anchors from configuration or files, and
  RFC 5011 automatic trust-anchor updates.

**Caching**

- Message, RRset, and infrastructure caches with TTL clamping (`cache-min-ttl`,
  `cache-max-ttl`).
- Prefetch of entries nearing expiry.
- Serve-expired answers while refreshing (RFC 8767), with configurable reply TTL
  and stale window.

**Serving**

- Plain DNS over UDP and TCP.
- DNS-over-TLS (RFC 7858) and DNS-over-HTTPS (RFC 8484), selected by interface
  port when TLS material is configured.
- EDNS(0) buffer-size negotiation and cookie handling.
- Access control with `allow`, `deny`, `refuse`, `allow-snoop`,
  `deny-non-local`, and `refuse-non-local` actions.
- Views keyed by client network (`access-control-view`), with `view-first`
  fallback to global local data.
- Local zones and `local-data` records, plus authoritative zones loaded from
  zonefiles.
- Per-client rate limiting (`ratelimit`, `ratelimit-slip`) and concurrent-query
  limits.
- Prometheus text rendering for pipeline counters (`PipelineStats`), not yet
  exposed over the network.

**Operations**

- `checkconf`, `run`, and `healthcheck` commands, configuration warnings, and structured logging.
- Graceful shutdown on `SIGINT`/`SIGTERM`.
- TOML configuration and an `unbound.conf`-compatible front-end.
- Container image on a `scratch` runtime with a statically linked musl binary,
  published for `linux/amd64` and `linux/arm64`, with a `healthcheck`
  subcommand for container liveness probes and a read-only/hardened example
  deployment.

## Not yet implemented

- Control socket and statistics endpoint. `dns-control` currently defines the
  command type only.
- RPZ, DNS64, and response-IP filtering. Local zones are served by `dns-server`;
  the `dns-filter` crate is a placeholder.
- DNS-over-QUIC (the transport is named in `dns-client` but has no implementation).
- Privilege drop, `chroot`, daemonization, PID files, and syslog. These options
  are parsed for compatibility but not applied.
- `forward-host`, `interface-view`, `response-ip`, and AXFR/URL fetching for
  auth zones. These are parsed and reported as warnings.
- Configuration reload without restart.
- The Unbound `.rpl` replay harness (`docs/replay-harness.md` is still a design),
  live interop tests, and benchmarks.

## Workspace

| Crate | Responsibility |
|---|---|
| `dns-proto` | DNS wire types and codecs, isolated behind one dependency facade (`hickory-proto` today) |
| `dns-config` | Typed configuration, TOML front-end, and `unbound.conf` subset parser |
| `dns-cache` | TTL-aware cache primitives, message/RRset/infra caches, and the in-flight query registry |
| `dns-client` | Upstream UDP/TCP/DoT/DoH transports with connection pooling; DoQ is not implemented |
| `dns-iter` | Iterative resolution: 0x20, QNAME minimisation, scrubbing, cookies, forward and stub zones |
| `dns-dnssec` | RRSIG/DNSKEY/DS validation, NSEC/NSEC3 proofs, trust anchors, RFC 5011 autotrust |
| `dns-filter` | Placeholder for RPZ, DNS64, and response-IP filtering |
| `dns-server` | UDP/TCP/DoT/DoH listeners, ACLs, views, EDNS, rate limiting, local/auth zones, query pipeline, statistics |
| `dns-control` | Control command types; socket server not wired up yet |
| `dns-daemon` | `dns-rs` binary: `checkconf`, `run`, logging, signal handling |
| `dns-testutil` | DNS message builders for tests; mock servers and replay support still planned |

## Configuration

Two front-ends are supported:

- **TOML** for native configuration and tooling.
- A practical **`unbound.conf` subset** for incremental migration. Unsupported
  options are reported as warnings, not fatal errors.

Supported `unbound.conf` blocks:

- `server:` — interfaces, ports, TLS/HTTPS listeners, verbosity, threads,
  daemonize, user/chroot/directory, log file, PID file, syslog, IPv4/IPv6,
  UDP/TCP, outgoing interfaces, access control, access-control-view, local
  zones and data, hardening, DNSSEC validation, trust anchors, QNAME
  minimisation, 0x20, EDNS sizes, TTL bounds, prefetch, serve-expired, rate
  limiting, and TCP connection limits.
- `forward-zone:` — name, `forward-addr` (plain, DoT, or DoH targets),
  `forward-first`, and `forward-tls-upstream`. `forward-host` is parsed but not
  implemented.
- `stub-zone:` — name, `stub-addr`, `stub-host`, `stub-prime`, `stub-first`,
  `stub-no-cache`, and `stub-tls-upstream`.
- `auth-zone:` — name, zonefile, primaries, URL, fallback, and
  downstream/upstream selection. Only zonefile loading is implemented.
- `view:` — name, `view-first`, local zones/data, and local-data-ptr.
  `response-ip` is parsed but not implemented.
- `remote-control:` — enable, interface, port. Parsed for compatibility; the
  control socket is not served yet.
- `include:` and `include-toplevel:` — relative or absolute files, with cycle
  detection.

Options outside this set are accepted with a warning and ignored.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --doc
scripts/container-smoke.sh
```

CI additionally runs `cargo nextest`, `cargo deny`, `cargo audit`, and a
short `cargo fuzz` smoke test for the message decoder. The container job builds
the image, runs the smoke test, enforces a size budget, and scans for
vulnerabilities. The `delv` corpus-parity test in
`crates/dns-server/tests/delv_corpus.rs` is skipped when `delv` is not installed.

Architecture decisions live in [`docs/adr/`](docs/adr/). The Unbound replay
harness design is in [`docs/replay-harness.md`](docs/replay-harness.md), and
container deployment is covered in [`docs/container.md`](docs/container.md).

## License

BSD-3-Clause. Unbound is also BSD-3-Clause; this project is a clean-room
implementation and only reuses test vectors with attribution.
