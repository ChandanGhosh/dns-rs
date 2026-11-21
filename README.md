# dns-rs

A validating, recursive, caching DNS resolver written in Rust. dns-rs follows the
operational model of [Unbound](https://github.com/NLnetLabs/unbound): it can
iterate from the root, forward through encrypted upstreams, validate DNSSEC,
serve local zones, and expose operational controls through a local socket.

> **Status: working resolver, version 0.6.0, pre-1.0.** The core resolver,
> DNSSEC validation, cache, listeners, configuration front-ends, and container
> image are implemented. Several features commonly found in production Unbound
> deployments are not. Read [Limitations](docs/limitations.md) before adopting
> it; that page is the authoritative feature boundary.

## Get started

The sample configuration listens on loopback port 5353 and forwards over
DNS-over-TLS, so no root privileges are needed.

```bash
git clone https://github.com/ChandanGhosh/dns-rs.git
cd dns-rs

cargo run -p dns-daemon -- checkconf -c examples/minimal.toml
cargo run -p dns-daemon -- run -c examples/minimal.toml
```

From another terminal:

```bash
dig @127.0.0.1 -p 5353 localhost. A
dig @127.0.0.1 -p 5353 example.com A
```

`localhost.` comes from built-in local data and verifies the listener.
`example.com` exercises the encrypted upstream path and DNSSEC validation; it
needs outbound TCP/853 and a correct host clock. Stop the daemon with `Ctrl-C`.

To try the published container image instead:

```bash
docker run -d --rm --name dns-rs-test \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  -p 127.0.0.1:15353:53/udp \
  -p 127.0.0.1:15353:53/tcp \
  chandanghosh/dns-rs:0.6.0

dig @127.0.0.1 -p 15353 example.com A
docker logs dns-rs-test
docker stop dns-rs-test
```

See the [Quick start](docs/quickstart.md) for prerequisites, interpretation of
results, and the next experiments.

## Documentation

The full documentation index is [docs/README.md](docs/README.md). The most
useful starting points are:

| Page | Use it for |
|---|---|
| [Quick start](docs/quickstart.md) | First run from source or container, with verification steps |
| [Installation](docs/installation.md) | Support tiers, source installs, image pulls, and a systemd unit |
| [Configuration](docs/configuration.md) | File formats, settings, upstream models, reload rules |
| [Container image](docs/container.md) | `docker run`, Compose, Kubernetes, volumes, monitoring, troubleshooting |
| [Operations](docs/operations.md) | Control socket, statistics, logs, signals, healthchecks, upgrades |
| [Troubleshooting](docs/troubleshooting.md) | Symptom-first checks for startup, resolution, DNSSEC, and containers |
| [Limitations](docs/limitations.md) | Missing features, platform gaps, and benchmark coverage |
| [Architecture](docs/architecture.md) | Crates, query path, and where to make a change |
| [Unbound migration](docs/unbound-migration.md) | Moving an existing `unbound.conf` deployment |
| [Unbound compatibility](docs/unbound-compatibility.md) | Compatibility matrix and differences |
| [Benchmarking](docs/benchmarking.md) | Runners, switches, methodology, and known gaps |
| [Contributing](CONTRIBUTING.md) | Development workflow and pull-request checklist |

## What is implemented

- **Resolution:** iterative queries from built-in root hints, QNAME
  minimisation, DNS 0x20 randomisation, DNS cookies, TCP fallback, pooled
  upstream connections, forward zones over UDP/TCP/DoT/DoH, and stub zones.
- **DNSSEC:** RRSIG/DNSKEY/DS chain validation, NSEC and NSEC3 proofs, built-in
  root anchors, extra anchors, RFC 5011 autotrust, and per-domain exclusions.
- **Caching:** message, RRset, and infrastructure caches with TTL clamping,
  prefetch, and RFC 8767 serve-expired.
- **Serving:** UDP and TCP listeners, DoT and DoH, ACLs keyed by client netblock,
  client-network views, local and authoritative zones from zonefiles, rate
  limiting, and rebinding protection.
- **Operations:** `checkconf`, `run`, `control`, and `healthcheck` commands;
  structured logging to standard output; graceful shutdown; live reload; an
  opt-in Unix control socket with JSON commands and Prometheus text output.
- **Configuration and packaging:** native TOML plus an `unbound.conf` subset, a
  small multi-arch `scratch`-based container image, and an example systemd unit.

## Current limitations

The most important gaps are:

- No RPZ, DNS64, response-IP filtering, or DoQ.
- No `unbound-control` protocol; the control socket uses a small JSON protocol.
- Auth zones load zonefiles only; there is no AXFR or URL fetch.
- No `chroot`, daemonization, PID file, log file, or syslog. `username`
  privilege drop is supported on Unix; a supervisor owns the rest.
- No HTTP metrics endpoint. Counters are available through the control socket.
- The Unbound-style `.rpl` replay harness is first-pass only: `cargo test` runs
  four bundled iterator scenarios. The upstream corpus, virtual time, cache
  manipulation, and DNSSEC replay are not implemented.
- Configuration reload cannot change listeners, TLS files, thread count,
  socket buffers, control socket, or verbosity. Those require a restart.

See [Limitations](docs/limitations.md) for the complete list and workarounds.

## Performance

Loopback UDP cache-hit baseline from two `make bench` runs on 2026-11-20. The
host was an Intel Core i7-9750H (6 cores / 12 threads) running Linux 7.3.4 with
`rustc 1.100.0`, shared with desktop workloads. The generator used 4,000
distinct names, 8 queries in flight, a 5-second warm-up, and a 10-second
measured window. All runs reported `errors=0 rcode=0`.

| Resolver workers | QPS, two runs | p50, two runs | p99, two runs |
|---:|---|---|---|
| 1 | 75,359 - 85,209 | 54.1 - 54.6 us | 107 - 282 us |
| 2 | 101,158 - 120,200 | 33.0 - 35.8 us | 76 - 217 us |
| 4 | 114,615 - 120,785 | 26.4 - 33.8 us | 173 - 184 us |

These are host-specific ranges, not portable guarantees. The spread between
runs is larger than the difference between two and four workers in one run, so
throughput differences at that scale are indicative only. Tail latency is
especially sensitive to the shared host. The exact commands, environment, and
raw results are in the [0.6.0 result page](docs/benchmark-results/0.6.0-loopback.md);
methodology and A/B testing are in [Benchmarking](docs/benchmarking.md).

The workload does not measure cold iteration, cache misses with a real upstream,
DNSSEC validation, TCP framing, DoT, mixed workloads, or connection churn.

## Container images

Published images support `linux/amd64` and `linux/arm64` under
`chandanghosh/dns-rs`:

| Tag | Stable? | Meaning |
|---|---|---|
| `X.Y.Z` | Immutable | Release image, for example `0.6.0` |
| `latest` | Mutable | Repointed to the newest release |
| `DDMMYYYY` (UTC) | Mutable | Edge build from `main` |
| Digest | Immutable | `chandanghosh/dns-rs@sha256:...` |

Pin a release tag or digest for production. Maintainer release automation and
verification commands are in [Container publishing](docs/container-publishing.md).

## Development

Rust 1.100 or newer is required. Common tasks are wrapped by the
[`Makefile`](Makefile); run `make help` for the full list.

```bash
make build           # format, then debug-build the workspace
make check           # formatting, Clippy, tests, dependency policy, config examples
make ci              # check plus audit and fuzz smoke test
make test            # cargo nextest when available, otherwise cargo test
make bench           # loopback benchmark for 1, 2, and 4 workers
make image-smoke     # build the image and run the hardened smoke test
```

The workspace is split into focused crates; see [Architecture](docs/architecture.md)
for the query path and ownership. Before opening a pull request, follow
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security and license

Report vulnerabilities privately through [SECURITY.md](SECURITY.md); the
supported releases are listed there. dns-rs is distributed under the
[BSD-3-Clause license](LICENSE). Unbound is also BSD-3-Clause; this project is a
clean-room implementation and only reuses test vectors with attribution.
