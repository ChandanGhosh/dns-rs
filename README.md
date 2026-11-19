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

`verbosity` in the server block now controls the log level directly, mirroring
Unbound: 0 = warnings, 1 = info, 2–3 = debug (one line per query with cache
hit/miss), 4–5 = trace. `-v`/`-vv` or `RUST_LOG` override it. `examples/full.toml`
and `examples/full.conf` are annotated references covering every supported
option, including DoT/DoH listeners and encrypted forwarders.

## Container

The repository includes a multi-stage `Dockerfile` that cross-compiles a static
musl binary and ships it on a `scratch`, non-root runtime with a built-in DNS
healthcheck. Build and verify it locally with:

```bash
docker build -t dns-rs:dev .
PORT=15353 scripts/container-smoke.sh
```

The same steps are available as `make image-smoke`.

Published images are available for `linux/amd64` and `linux/arm64`:

```bash
docker pull chandanghosh/dns-rs:0.6.0
```

Each release also publishes immutable `X.Y.Z` and `latest` image tags and a
GitHub Release. The `DDMMYYYY` tag keeps tracking the newest `main` build.

Run it manually on loopback port 15353:

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
docker stop dns-rs-test
```

Or start the Compose example, which pulls the published image:

```bash
docker compose up -d
docker compose logs -f resolver
```

The smoke test runs with a read-only root filesystem, all capabilities dropped
except `NET_BIND_SERVICE`, and Docker's default seccomp profile. For full
`docker run` and `docker compose` command references, Kubernetes examples,
Raspberry Pi deployment notes, and the Docker Hub publishing workflow, see
[`docs/container.md`](docs/container.md).

## Implemented

**Resolution**

- Iterative resolution from the root, using built-in root hints, with IPv4 and
  IPv6 upstream transports gated by `do-ip4`/`do-ip6`.
- QNAME minimisation, with an optional strict mode.
- DNS 0x20 case randomisation and response scrubbing. Answers keep the
  randomised spelling, which shows whether a name was learned by iteration or
  through an encrypted forwarder (see `docs/container.md`).
- DNS cookies (RFC 7873) on upstream queries.
- TCP fallback on truncation and pooled upstream connections.
- Forward zones over plain UDP, DNS-over-TLS, or DNS-over-HTTPS (`https://`
  targets), with `forward-first` fallback and iteration-first
  `forward-fallback`.
- Stub zones, including `stub-host`, `stub-prime`, `stub-first`, and
  `stub-no-cache`.
- Coalescing of identical in-flight questions.

**DNSSEC**

- RRSIG verification over canonical RRsets and DNSKEY/DS chain-of-trust checks.
- ED25519, ECDSA P-256/P-384, and RSA/SHA-1/256/512 signatures, with a
  configurable NSEC3 iteration cap.
- NSEC and NSEC3 denial-of-existence proofs.
- Extended DNS Errors in responses for bogus and insecure validation outcomes.
- Built-in root trust anchors, extra anchors from configuration or files, and
  RFC 5011 automatic trust-anchor updates.
- Per-domain exclusions for subtrees whose upstream DNSSEC cannot be
  validated, without disabling validation for other names.

A domain that fails validation because of an upstream problem can be excluded
instead of enabling permissive mode globally:

```toml
[server]
domain_insecure = ["broken.example"]
```

The domain and every name below it are treated as insecure. Validation
continues for all other names, and an explicit trust anchor at or below the
excluded domain overrides the exclusion. In `unbound.conf`, the equivalent is
`domain-insecure: "broken.example"`.

The entry is a static negative trust anchor in the sense of RFC 7646. dns-rs
never creates one automatically and does not expire it; an exclusion stays in
effect until it is removed from the configuration. Use it only for a domain
whose own DNSSEC is broken or deliberately unsigned, not to silence a
validator bug. For example, an alias in an unsigned zone that points into a
signed CDN zone is insecure by design and resolves without any exclusion.

`val_permissive_mode` is a different, global escape hatch: it still runs
validation but returns bogus data with `AD=0` instead of `SERVFAIL`.

Validated zone status is cached for the DNSKEY TTL when one is available, and
for at most five minutes for key-less or probed statuses. Insecure status is
inherited by descendants, so that five-minute bound is also the longest a newly
signed delegation can remain treated as unsigned. Secure and bogus results stop
the inheritance walk, and an explicit trust anchor below an insecure zone
bypasses it entirely.

**DNS rebinding protection**

Public names must not be able to return addresses on the local network. dns-rs
removes A and AAAA records (and SVCB/HTTPS address hints) whose address falls in
`private_address` unless the record's owner name is covered by `private_domain`.
Local zones, auth zones, and stub zones are exempt because their data is
configured locally.

```toml
[server]
# Names (and their subdomains) allowed to return private addresses. Setting
# this replaces the defaults; add your own names alongside the local ones.
private_domain = [
    "local", "localdomain", "lan", "home", "home.arpa", "internal",
    "intranet", "corp", "private", "test", "localhost",
    "home.example", "corp.internal",
]

# Optional: replace the default ranges. An empty list disables filtering.
private_address = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"]
```

The defaults block RFC 1918, link-local, and IPv6 unique-local ranges, and
allow the common local-only namespaces `.local`, `.localdomain`, `.lan`,
`.home`, `.home.arpa`, `.internal`, `.intranet`, `.corp`, `.private`, `.test`,
and `.localhost`. These names are not delegated in the public DNS, so allowing
them to return private addresses keeps mDNS-style and home-network names
working without weakening protection for public names. Explicitly setting
`private_domain` or `private_address` replaces the defaults rather than
appending to them. The `unbound.conf` equivalents are `private-address:` and
`private-domain:`.

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
- Access control with `allow`, `deny`, `refuse`, `allow-setrd`, `allow-snoop`,
  `deny-non-local`, and `refuse-non-local` actions. The most specific netblock
  wins regardless of statement order, as in Unbound; `allow-cookie` is accepted
  with a warning because cookie enforcement is not implemented.
- Views keyed by client network (`access-control-view`), with `view-first`
  fallback to global local data.
- Local zones and `local-data` records, plus authoritative zones loaded from
  zonefiles.
- DNS rebinding protection: A/AAAA answers in the configured private ranges are
  removed unless the answer name is covered by `private_domain` (stub-zone data
  is exempt).
- Per-client rate limiting (`ratelimit`, `ratelimit-slip`) and concurrent-query
  limits.
- Prometheus text rendering for pipeline counters (`PipelineStats`), served
  through the optional control socket.

**Operations**

- `checkconf`, `run`, and `healthcheck` commands, configuration warnings, and structured logging.
- Graceful shutdown on `SIGINT`/`SIGTERM`, and live configuration reload on
  `SIGHUP` or the control socket's `reload` command.
- Opt-in control socket (`remote-control:`): one JSON command per connection
  over a Unix domain socket. The socket is mode `0600`, only processes with the
  daemon's effective UID may connect, and there is no TCP or TLS control
  transport. The binary includes a small client:

  ```bash
  dns-rs -c /etc/dns-rs/dns-rs.conf control status
  dns-rs -c /etc/dns-rs/dns-rs.conf control stats
  dns-rs -c /etc/dns-rs/dns-rs.conf control stats-prometheus
  dns-rs -c /etc/dns-rs/dns-rs.conf control reload
  dns-rs -c /etc/dns-rs/dns-rs.conf control stop
  ```

  `reload` re-reads the file the daemon was started with, rebuilds the query
  pipeline, and flushes the caches. The swap is atomic: in-flight resolutions
  finish on the old pipeline. A failed reload leaves the running configuration
  in place. Settings fixed when the listeners were bound (interfaces, ports,
  TLS files, thread count, socket buffers, control sockets, and verbosity) need
  a restart; a change to one of them is logged and the running listener is
  kept.

  `control` uses the first enabled `control-interface`; pass `--socket PATH` to
  override it. Any client that can write one JSON line to the socket works too,
  for example `printf '{"command":"stats"}\n' | socat - UNIX-CONNECT:/run/dns-rs.sock`.
  `make control-smoke` exercises the socket against a local binary and
  `make control-container` does the same inside the container image.
- TOML configuration and an `unbound.conf`-compatible front-end.
- Container image on a `scratch` runtime with a statically linked musl binary,
  published for `linux/amd64` and `linux/arm64`, with a `healthcheck`
  subcommand for container liveness probes and a read-only/hardened example
  deployment.

## Not yet implemented

- RPZ, DNS64, and response-IP filtering. Local zones are served by `dns-server`;
  the `dns-filter` crate is a placeholder.
- DNS-over-QUIC (the transport is named in `dns-client` but has no implementation).
- Privilege drop, `chroot`, daemonization, PID files, and syslog. These options
  are parsed for compatibility but not applied.
- `interface-view` (per-interface views) and `response-ip` filtering. These are
  parsed and reported as warnings.
- AXFR/URL fetching for auth zones. Only zonefile loading is implemented, and
  the transfer-related options are parsed and reported as warnings.
- Applying listener, TLS, thread-count, socket-buffer, control-socket, or
  verbosity changes through a reload; those require a restart.
- The Unbound `.rpl` replay harness (`docs/replay-harness.md` is still a design)
  and live interop tests.

## Performance

Loopback UDP benchmark of the release binary on an Intel Core i7-9750H
(6 cores / 12 threads, Linux 7.3, rustc 1.99.1). The resolver was pinned to
four CPUs and the load generator to the remaining eight. Each run sent 4,000
distinct names against a warm message cache, with 8 queries in flight and
EDNS(0); `bench.test.` was answered by a local stub authority with
3,600-second TTLs, so these are steady-state cache hits rather than cold
iteration. Four thousand names stays below the 8,192-entry message cache;
8,000 names start evicting entries and depress the result.

| `num_threads` | p50 | p75 | p90 | p95 | p99 | Throughput | Idle RSS | Peak RSS |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 0.042 ms | 0.053 ms | 0.056 ms | 0.060 ms | 0.075 ms | 107,095 qps | 16.0 MiB | 24.1 MiB |
| 2 | 0.031 ms | 0.033 ms | 0.037 ms | 0.039 ms | 0.045 ms | 157,755 qps | 18.1 MiB | 26.2 MiB |
| 4 | 0.019 ms | 0.026 ms | 0.031 ms | 0.039 ms | 0.115 ms | 171,849 qps | 18.0 MiB | 28.2 MiB |

Values are from a 10-second run after a 5-second warm-up. Latency is the
client-side send-to-response RTT at 8 queries in flight. The host was shared
with desktop workloads, so tail latency is indicative rather than a strict
upper bound and repeated runs varied by up to 15% as background load rose.
These numbers were measured before `recvmmsg` batching landed; that change is
reported as a receive-syscall and RSS improvement rather than a further qps
claim, because the host's run-to-run variance is larger than the expected
throughput delta.
RSS is `VmRSS` at idle and `VmHWM` after the 4,000-name cache was
filled; `num_threads` sets the Tokio worker count (on unix it also binds one
`SO_REUSEPORT` UDP socket per worker, so the kernel fans datagrams out across
workers lock-free, and on Linux each worker harvests up to 8 queued datagrams
per receive syscall with `recvmmsg`). The daemon uses mimalloc, which raises
idle RSS compared with the system allocator but keeps the per-query allocation
path fast. `num_threads` defaults to 1; set it to `0` or `"auto"` to use the
CPUs visible to the process, including CPU-affinity and cgroup limits.

### Running it

The runner is [`scripts/bench-loopback.sh`](scripts/bench-loopback.sh); the
load generator is [`scripts/dns-bench.rs`](scripts/dns-bench.rs). The DNSSEC
scenario uses a signed mock authority,
[`crates/dns-testutil/src/bin/dnssec-mock.rs`](crates/dns-testutil/src/bin/dnssec-mock.rs),
because it needs `dns-proto` and `ring` to generate a key and sign answers.
The runner builds the release binary, starts the appropriate mock, and loops
over the thread counts. Every environment switch, the A/B compare workflow,
and the methodology rules are catalogued in
[`docs/benchmarking.md`](docs/benchmarking.md).

The script needs a Rust toolchain; host mode uses `cargo` to build the
resolver, and every mode uses `rustc` to build the load generator. Container
mode also needs Docker. For each worker count it writes a stub-zone config and
starts the resolver on loopback.

```bash
# All three worker counts (1, 2, 4).
scripts/bench-loopback.sh

# One worker count with a longer sample.
BENCH_WARMUP=5 BENCH_DURATION=30 scripts/bench-loopback.sh 2
```

The Makefile wraps the common cases:

```bash
make bench
make bench THREADS="1 2" BENCH_DURATION=30
make bench-container
make bench-ci
make bench-miss
make bench-dnssec
make bench-compare-miss THREADS="1 2 4" AB_REPEATS=3
make bench-compare-dnssec THREADS="1 2 4" AB_REPEATS=3
```

`make bench-ci` reproduces the CI settings: 4,000 names, 8 queries in flight,
a 5-second warm-up, a 15-second sample, and one and two workers against the
container image.

`make bench-dnssec` runs the signed TTL-0 workload: every measured query reaches
the mock and verifies one ED25519 RRSIG, while the zone key stays cached. Compare
it with `make bench-miss` to isolate validation cost. ED25519 is the cheapest
common algorithm, so the scenario understates the cost of RSA/SHA-256
validation and does not measure negative (NSEC/NSEC3) proofs or first-time
chain building.

To compare a change against a baseline commit,
[`scripts/bench-compare.sh`](scripts/bench-compare.sh) interleaves the two
binaries back to back — alternating run order and waiting for the machine to
settle between runs — and reports the median throughput and latency
difference, which absorbs run-to-run drift that single runs cannot:

```bash
# Working tree vs. origin/main, three pairs at each thread count.
scripts/bench-compare.sh origin/main

# An honest cache-miss comparison (TTL-0 upstream).
AB_REPEATS=3 BENCH_SCENARIO=miss scripts/bench-compare.sh origin/main 1 2 4

# A DNSSEC validation comparison (signed TTL-0 upstream).
AB_REPEATS=3 BENCH_SCENARIO=dnssec scripts/bench-compare.sh origin/main 1 2 4

# An allocation comparison: both variants build with the counting allocator.
BENCH_ALLOCS=1 scripts/bench-compare.sh origin/main 1 2 4

# A phase-attribution comparison: both variants build with per-phase timers.
BENCH_PHASES=1 scripts/bench-compare.sh origin/main 1 2 4
```

The baseline is built once into a worktree under `target/ab/` and reused by
later invocations; every `BENCH_*` variable passes through to the main runner.
`AB_REPEATS` sets the number of pairs per thread count (default 3) and
`AB_LOAD_LIMIT` the 1-minute load average each run waits for (default a
quarter of the CPU count). `BENCH_ALLOCS=1` instruments the allocator on
both sides and adds `allocs_per_query` per run and to the summary, and
`BENCH_PHASES=1` times each stage of the query pipeline and adds a per-phase
table (the baseline ref must contain the feature).

On Linux hosts with at least eight CPUs it pins the resolver to CPUs 0-3 and
the generator to the rest. Override this with `BENCH_SERVER_CPUS` and
`BENCH_CLIENT_CPUS`.

The generator can also be run directly. The resolver must have a `bench.test.`
stub zone pointing at the mock (the script writes this config for you):

```bash
rustc --edition 2024 -O -o /tmp/dns-bench scripts/dns-bench.rs
/tmp/dns-bench serve 127.0.0.1:15354 &
/tmp/dns-bench load 127.0.0.1:15353 4000 bench.test 8 5 10
```

The `load` arguments are address, distinct names, zone, concurrency, warm-up
seconds, and measured seconds.

### In a container

Build the image from this checkout and point the same script at it:

```bash
docker build -t dns-rs:bench .
BENCH_SERVER_IMAGE=dns-rs:bench scripts/bench-loopback.sh
```

The script starts the resolver with `--network host` (so it shares the loopback
mock and resolver port with the host), applies CPU pinning with `--cpuset-cpus`,
and reads the container process's RSS from the host. Host networking is
Linux-only; on Docker Desktop, run it from a Linux VM or place the mock in the
same network namespace.

Use an image built from this checkout. Images built before the `num_threads`
runtime fix ignore the setting, so 1, 2, and 4 workers would look identical.
The image uses the `dist` profile (opt-level 2, fat LTO, static musl), which is
slightly slower than the host `release` profile. The CI container job runs the
same loopback benchmark against the built image for one and two workers and
publishes the numbers to the workflow summary.

## Workspace

| Crate | Responsibility |
|---|---|
| `dns-proto` | DNS wire types and codecs, isolated behind one dependency facade (`hickory-proto` today) |
| `dns-config` | Typed configuration, TOML front-end, and `unbound.conf` subset parser |
| `dns-cache` | TTL-aware cache primitives, message/RRset/infra caches, and the in-flight query registry |
| `dns-client` | Upstream UDP/TCP/DoT/DoH transports with connection and socket pooling; DoQ is not implemented |
| `dns-iter` | Iterative resolution: 0x20, QNAME minimisation, scrubbing, cookies, forward and stub zones |
| `dns-dnssec` | RRSIG/DNSKEY/DS validation, NSEC/NSEC3 proofs, trust anchors, RFC 5011 autotrust |
| `dns-filter` | Placeholder for RPZ, DNS64, and response-IP filtering |
| `dns-server` | UDP/TCP/DoT/DoH listeners, ACLs, views, EDNS, rate limiting, local/auth zones, query pipeline, statistics |
| `dns-control` | Unix-socket control channel and JSON protocol for status, statistics, Prometheus text, reload, and shutdown |
| `dns-daemon` | `dns-rs` binary: `checkconf`, `run`, logging, signal handling (`SIGTERM`/`SIGINT`/`SIGHUP`) |
| `dns-testutil` | DNS message builders for tests plus the signed authoritative mock used by the DNSSEC benchmark; replay support still planned |

## Configuration

Two front-ends are supported:

- **TOML** for native configuration and tooling.
- A practical **`unbound.conf` subset** for incremental migration. Unsupported
  options are reported as warnings, not fatal errors.

Supported `unbound.conf` blocks:

- `server:` — interfaces, ports, TLS/HTTPS listeners, verbosity, threads,
  daemonize, user/chroot/directory, log file, PID file, syslog, IPv4/IPv6,
  UDP/TCP, outgoing interfaces, access control, access-control-view, local
  zones and data, hardening, DNSSEC validation and per-domain exclusions, trust
  anchors, QNAME minimisation, 0x20, EDNS sizes, TTL bounds (including
  `cache-max-negative-ttl`), infrastructure-cache limits, prefetch,
  serve-expired, rate limiting, private-address/private-domain rebinding
  protection, TCP connection limits, `root-hints`, `do-not-query-address`,
  `do-not-query-localhost`, and the `unblock-lan-zones`/`insecure-lan-zones`
  pair.
- `forward-zone:` — name, `forward-addr` (plain, DoT, or DoH targets),
  `forward-host` (resolved at startup through the system resolver),
  `forward-first`, `forward-fallback`, and `forward-tls-upstream` (Unbound
  alias `forward-ssl-upstream`). A DoT `#auth-name` without `@port` implies
  port 853; without an auth name the certificate chain is verified but any
  name is accepted, matching Unbound.
- `stub-zone:` — name, `stub-addr`, `stub-host`, `stub-prime`, `stub-first`,
  `stub-no-cache`, and `stub-tls-upstream`.
- `auth-zone:` — name, zonefile, primaries, URL, fallback, and
  downstream/upstream selection. Only zonefile loading is implemented.
- `view:` — name, `view-first`, local zones/data, and local-data-ptr.
  `response-ip` is parsed but not implemented.
- `remote-control:` — `control-enable` plus one or more absolute
  `control-interface` Unix socket paths (an optional `unix:` prefix is
  accepted). TCP control is not supported, so `control-port` must remain the
  Unbound default `8953`. Commands are sent as one JSON line per connection:
  `status`, `stats`, `stats-prometheus`, `reload`, and `stop`. The socket is
  mode `0600`, peers are authorized by effective UID, and `reload` re-reads the
  daemon's own configuration file (the request cannot name a path).
- `include:` and `include-toplevel:` — relative or absolute files, with glob
  patterns, cycle detection, and Unbound's block semantics: `include:` keeps the
  active clause, while `include-toplevel:` closes it before and after the
  file. Relative paths are tried against the including file's directory first
  and then the process working directory.

Options outside this set are accepted with a warning and ignored. For a
step-by-step migration, a recommended baseline, and a Compose layout, see
[`docs/unbound-migration.md`](docs/unbound-migration.md). The per-option matrix
and the documented differences from Unbound are in
[`docs/unbound-compatibility.md`](docs/unbound-compatibility.md).

## Development

Rust 1.100 or newer is required (`rust-version` in `Cargo.toml`). Host-mode
benchmarking selects the recursive resolver's CPU list with `taskset`, and the
container tooling targets Linux; macOS and Windows can build and run the
resolver itself.

Common tasks are wrapped by the [`Makefile`](Makefile); run `make help` for the
full list.

```bash
make build          # debug build of the workspace
make check          # fmt-check, Clippy, tests, cargo-deny, example configs
make ci             # check plus cargo-audit and the fuzz smoke test
make bench          # loopback benchmark for 1, 2, and 4 workers
make image-smoke    # build the image and run the hardened smoke test
make ci-container   # smoke test, load stats, 10 MiB size gate, Trivy scan
```

`make tools` installs the optional tools used by the full checks
(`cargo-nextest`, `cargo-deny`, `cargo-audit`, `cargo-fuzz`, and
`cargo-llvm-cov`), and `make doctor` reports what is installed. The underlying
commands are:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --doc
scripts/container-smoke.sh
```

Cargo 1.100 manifest lints are denied (`[workspace.lints.cargo]`), so an
unused dependency or workspace field fails the build. `.cargo/config.toml`
enforces a 7-day dependency cooldown: dependency resolution ignores versions
published less than a week ago unless they are already in `Cargo.lock`.

CI runs on every branch push and on every pull request, so a feature branch is
validated before a PR is opened and again against the merge result. It runs
`cargo nextest`, `cargo deny`, `cargo audit`, and a short `cargo fuzz` smoke
test for the message decoder. The container job builds the image, runs the
smoke test, enforces a size budget, scans for vulnerabilities, and records
informational one- and two-worker load stats. On pushes to `main`, a publish
job runs after all gates and pushes the date-tagged multi-arch image to Docker
Hub. The `delv` corpus-parity test in
`crates/dns-server/tests/delv_corpus.rs` is skipped when `delv` is not installed.

### Branch naming

Pull requests must come from a branch named `<type>/<description>`, for example
`feature/control-socket`, `bugfix/cache-expiry`, or `chore/bump-deps`. The
`Branch name` CI job accepts these types:

`feature`, `bugfix`, `chore`, `docs`, `test`, `refactor`, `perf`, `ci`,
`build`, `hotfix`, `release`, `dependabot`, `renovate`.

The description may contain letters, digits, dots, underscores, and hyphens,
and dependabot branches may add nested path components; no component may be
empty or start with a dot. The check only applies to pull requests; pushes to
`main` are unaffected. Make it mandatory by adding the `Branch name` job to the
required status checks once branch protection is available.

### Releases and versioning

The workspace version in `Cargo.toml` is the release version. Every push to
`main` runs the publish job, but it only creates a `vX.Y.Z` tag and GitHub
release when that version is newer than every existing `v*` tag. Otherwise the
push just refreshes the date-tagged Docker image.

A code-only push that should not release leaves the version untouched, and an
intended release bumps `version.workspace` in the same commit. The `Release
version` CI job fails a change that:

- moves the version to one that is not strictly newer than the latest `v*` tag;
- reuses an already released version;
- gives an individual crate its own `version` instead of
  `version.workspace = true`.

Keep one release bump in flight at a time. Two PRs that bump to the same
version can both pass before the first tag exists; only the first merge
releases, and the second change needs another bump to get its own release. A
merge queue or a release PR tool such as `release-plz` serializes this fully.

The release notes are generated from the commits since the previous tag.

### CI and workflow changes

Only repository writers can push branches, and only merged changes affect
`main`. `.github/CODEOWNERS` assigns `.github/workflows/` and
`.github/actions/` to the repository owner; enable branch protection or a
ruleset with **Require review from Code Owners** to make that mandatory.
Classic branch protection and rulesets are not available on private free-plan
repositories, so keep the collaborator list limited to trusted writers and
accept external contributions from forks. Fork pull requests do not receive
repository secrets.

The Unbound replay harness design is in
[`docs/replay-harness.md`](docs/replay-harness.md), migration from Unbound is
covered in [`docs/unbound-migration.md`](docs/unbound-migration.md), container
deployment is covered in [`docs/container.md`](docs/container.md), and
benchmarking switches and methodology are in
[`docs/benchmarking.md`](docs/benchmarking.md). Report security issues through
the private process in [`SECURITY.md`](SECURITY.md).

## License

BSD-3-Clause. Unbound is also BSD-3-Clause; this project is a clean-room
implementation and only reuses test vectors with attribution.
