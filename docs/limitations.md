# Limitations

This page describes the current boundary of dns-rs 0.6.0. It is intentionally
blunt: pre-1.0 software should be adopted with a clear view of what is missing.
Last reviewed: 2026-11-20.

## Feature scope

| Area | Limitation | Impact | Workaround |
|---|---|---|---|
| Filtering | RPZ, DNS64, and response-IP filtering are not implemented. `dns-filter` is a placeholder. | No policy based on response addresses or RPZ feeds. | Use local zones and `always_nxdomain` blocklists, or keep Unbound for these deployments. |
| Views | `view:` and `access-control-view` work; `interface-view` is parsed with a warning. | Cannot vary answers by interface. | Use separate processes or client-network views. |
| Authoritative data | Auth zones load zonefiles only. AXFR, URL fetch, and notify are parsed with warnings. | No automatic zone transfers. | Generate and reload a zonefile. |
| Transport | DNS-over-QUIC is named in `dns-client` but has no implementation. | DoQ clients cannot connect. | Use UDP, TCP, DoT, or DoH. |
| Control | The Unix control socket speaks a small JSON protocol, not `unbound-control`. | Unbound control clients will not work. | Use the `dns-rs control` subcommand. |
| Process model | No daemonization, privilege drop, `chroot`, PID file, or syslog. Options are parsed for compatibility but not applied. | The supervisor owns process and privilege concerns. | Use systemd, Docker, or Kubernetes. |
| Configuration | TOML has no `include:`. The Unbound parser supports a practical subset, not every option. | Large blocklists need either one generated TOML file or `.conf` with includes. | Prefer `.conf` for split generated files. |
| Metrics | No HTTP metrics listener and no `/metrics` on the DNS port. Counters are available only through the control socket. | Prometheus needs an exec exporter or socket-side collector. | See [Operations](operations.md#statistics). |
| Metrics detail | Counters are pipeline-wide. No per-client, per-upstream, or RTT breakdown, and caches are bounded by entry count rather than bytes. | Capacity planning relies on observation and reload testing. | Use `control stats`, logs, and host memory counters. |
| Replay | [`docs/replay-harness.md`](replay-harness.md) is a design document only. | No Unbound `.rpl` interop harness. | Use `dig`/`drill` and the local test suites. |

## DNSSEC details

- Verification covers Ed25519, ECDSA P-256 SHA-256, ECDSA P-384 SHA-384,
  RSA/SHA-256, RSA/SHA-512, and legacy RSA/SHA-1 and RSA/SHA1-NSEC3-SHA1.
  SHA-1 algorithms are retained for interoperability, not for new deployments.
- NSEC3 hashing implements SHA-1 only. The accepted iteration cap is 150;
  responses above it are bogus per RFC 9276.
- Built-in root anchors are KSK-2017 (tag 20326) and KSK-2024 (tag 38696).
- A valid RFC 5011 auto-trust-anchor file replaces the built-in root anchor for
  its zone; it does not extend the anchor set. Autotrust runs only when an
  auto-anchor file, a resolver, and validation are all configured.
- `val_permissive_mode` returns bogus data with `AD=0` instead of `SERVFAIL`. It
  still runs validation; it is a global escape hatch, not a per-domain fix.

## Platform and packaging

- CI runs on Linux x86_64 only. macOS and Windows builds are best effort and
  are not automatically tested.
- The `linux/arm64` image is built and smoke-tested under QEMU, but sustained
  Raspberry Pi hardware validation is still pending.
- No native OS packages are published. Install from source or use the container
  image; see [Installation](installation.md).
- Host-mode benchmark CPU pinning uses `taskset` and container tooling targets
  Linux. The resolver itself builds and runs on the Tier 3 platforms above.

## Benchmark coverage

The full methodology is in [Benchmarking](benchmarking.md). The published
numbers do not cover:

- DoT or mixed UDP/TCP workloads;
- TCP connection churn or pipelined queries;
- DNSSEC negative (NSEC/NSEC3) proofs or first-time chain building;
- RSA signing cost in the signed mock, which uses Ed25519, the cheapest common
  algorithm;
- cold iteration for the headline table, which is a warm cache-hit workload.

Treat published numbers as workload- and host-specific. The
[result page](benchmark-results/0.6.0-loopback.md) records the exact host,
toolchain, commands, and repeated runs behind the 0.6.0 figures.

## Compatibility caveats worth repeating

- An `unbound.conf` with no `interface:` fails loading; it does not start with
  no listeners.
- Unbound syntax starts with no ACL rules, so an unmodified file may refuse
  every client.
- Unbound-style empty private-address/private-domain lists are rejected; use
  TOML with empty arrays if that behavior is required.
- dns-rs defaults differ from Unbound for `use-caps-for-id` (enabled) and
  rebinding protection (enabled). See
  [Unbound compatibility](unbound-compatibility.md).
