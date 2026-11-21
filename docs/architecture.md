# Architecture

Audience: contributors and reviewers who need to find the right crate for a
change. The workspace default member is `dns-daemon`, so plain `cargo build`
builds the resolver binary.

## Crates

| Crate | Responsibility |
|---|---|
| `dns-proto` | DNS wire types and codecs, isolated behind one dependency facade (`hickory-proto` today) |
| `dns-config` | Typed configuration model, TOML front-end, Unbound-subset parser, includes, warnings, and built-in hints |
| `dns-cache` | TTL-aware cache primitives, message/RRset/infra caches, and the in-flight query registry |
| `dns-client` | Upstream UDP/TCP/DoT/DoH transports with connection and socket pooling; DoQ is not implemented |
| `dns-iter` | Iterative resolution: 0x20, QNAME minimisation, scrubbing, cookies, forward and stub zones |
| `dns-dnssec` | RRSIG/DNSKEY/DS validation, NSEC/NSEC3 proofs, trust anchors, and RFC 5011 autotrust |
| `dns-filter` | Placeholder for RPZ, DNS64, and response-IP filtering |
| `dns-server` | UDP/TCP/DoT/DoH listeners, ACLs, views, EDNS, rate limiting, local/auth zones, query pipeline, and statistics |
| `dns-control` | Unix-socket control channel and JSON protocol for status, statistics, Prometheus text, reload, and shutdown |
| `dns-daemon` | The `dns-rs` binary: `checkconf`, `run`, `control`, `healthcheck`, logging, and signal handling |
| `dns-testutil` | DNS message builders for tests plus the signed authoritative mock used by the DNSSEC benchmark |

## Query path

1. A listener in `dns-server` decodes a query and applies ACL, rate-limit, and
   concurrency checks.
2. The query pipeline probes the message cache. A hit is encoded and returned;
   a near-expiry hit may start a background prefetch.
3. Identical in-flight questions coalesce through the registry in `dns-cache`:
   one leader resolves, followers wait for the result.
4. `dns-iter` performs iterative resolution or applies forward/stub zones, using
   `dns-client` for upstream transport.
5. `dns-dnssec` validates chains and denial proofs. Validated status and keys
   are cached.
6. Rebinding policy and local/auth zone data are applied, the response is
   encoded, and the listener writes it back.

Reload builds a fresh pipeline with empty caches and swaps it atomically.
In-flight queries finish on the old pipeline. Listeners, TLS acceptors, thread
pools, control sockets, and log filters are created at startup and cannot change
through a reload.

## Control and configuration

`dns-config` loads one file; the extension selects TOML or the Unbound subset.
Includes are expanded at load time as Unbound syntax only. Warnings are
collected and returned with the config so `checkconf` and startup can report
them without failing on compatibility options.

`dns-control` owns the Unix socket, peer-credential check, JSON framing, and
closed command set. `dns-daemon` assembles the configuration, logging, runtime,
and control server. The daemon never daemonizes; when started as root it can
drop to the configured `username` after binding its sockets. Otherwise the
supervisor owns process identity.

## Where to make a change

- New configuration field: `crates/dns-config/src/model.rs`, both parsers in
  `crates/dns-config/src/`, warnings if it is compatibility-only, then
  [`examples/full.toml`](../examples/full.toml),
  [`examples/full.conf`](../examples/full.conf), and
  [Configuration](configuration.md).
- Resolver behavior: `dns-iter` for resolution policy, `dns-dnssec` for
  validation, `dns-cache` for cache and coalescing.
- Downstream protocol or access policy: `dns-server`.
- New control command: `dns-control` for the protocol, `dns-daemon` for the CLI,
  and [Operations](operations.md) for the reference.
- Benchmark workload or switch: `scripts/bench-loopback.sh`,
  `scripts/bench-compare.sh`, and [Benchmarking](benchmarking.md).

The test suites live beside each crate plus `crates/dns-config/tests/unbound_compat.rs`
and `crates/dns-server/tests/`. `crates/dns-server/tests/delv_corpus.rs` needs
`delv` and is skipped when it is not installed. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the validation commands.
