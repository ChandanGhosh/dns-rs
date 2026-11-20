# Benchmarking dns-rs

Single reference for every benchmarking switch, runner, and methodology rule.
The headline numbers live in the [README](../README.md#performance); the exact
host, toolchain, commands, and repeated runs behind the 0.6.0 figures are in
[`docs/benchmark-results/0.6.0-loopback.md`](benchmark-results/0.6.0-loopback.md).
This document explains how to produce and compare numbers yourself.

Methodology last reviewed for dns-rs 0.6.0 on 2026-11-20 with Rust 1.100.0.
Hardware-specific figures below are examples from the development host, not
portable expectations.

## Quick start

```bash
# Cache-hit benchmark, worker counts 1 2 4 (builds the release binary).
make bench

# Interleaved A/B: working tree vs. a baseline ref (recommended for any
# performance claim; builds the baseline once, caches it under target/ab/).
make bench-compare
make bench-compare BASE_REF=origin/main THREADS="1 2 4"

# Cache-miss and DNSSEC-validation runs (see the sections below).
make bench-miss THREADS="1 2 4"
make bench-dnssec THREADS="1 2 4"

# Interleaved A/B for those workloads.
make bench-compare-miss THREADS="1 2 4" AB_REPEATS=3
make bench-compare-dnssec THREADS="1 2 4" AB_REPEATS=3

# Allocation A/B: both variants build with the counting allocator.
make bench-compare BENCH_ALLOCS=1

# Phase attribution A/B: both variants build with per-phase timers.
make bench-compare BENCH_PHASES=1

# TCP framing, with 100-record answers to size the response write path.
BENCH_TRANSPORT=tcp BENCH_RECORDS=100 scripts/bench-loopback.sh 1 2 4

# Interleaved A/B of the TCP write path.
BENCH_TRANSPORT=tcp BENCH_RECORDS=100 scripts/bench-compare.sh origin/main 1 2 4

# Longer sample for one worker count.
make bench THREADS="2" BENCH_DURATION=30
```

Equivalent script forms, if you prefer not to use `make`:

```bash
scripts/bench-loopback.sh [THREADS...]
scripts/bench-compare.sh [BASE_REF] [THREADS...]
```

## The runners

### `scripts/bench-loopback.sh` - one or more runs of the working binary

Builds the release resolver, starts a local mock authority, and for each
worker count writes a stub-zone config, starts the resolver on loopback,
warms it up, and measures with `scripts/dns-bench.rs`. `BENCH_SCENARIO`
selects the workload: `hit` (default) fixes the name set and 3600 s TTLs so
every measured query is a message-cache hit as long as `BENCH_NAMES` fits in
the 8,192-entry cache; `miss` answers with TTL 0 so nothing is cached and
every query is a genuine miss, reporting how many reached the mock upstream
and how many were coalesced away; `dnssec` runs the same TTL-0 miss path
against a signed mock, adding one Ed25519 RRSIG verification per query.

The signed mock is `crates/dns-testutil/src/bin/dnssec-mock.rs`, a cargo
binary because it needs `dns-proto` and `ring` to generate a key and sign
answers. It writes its own DNSKEY trust anchor to a temporary file, which the
runner embeds in the resolver config.

`BENCH_TRANSPORT=tcp` switches the load generator to one persistent TCP
connection per client thread and length-prefixes each query, so the measured
RTT includes the resolver's TCP framing path. The upstream leg to the mock
stays UDP, and the resolver still serves the cached answer over TCP.
`BENCH_RECORDS=N` makes the unsigned mock answer with N A records (capped at
1000), which sizes the response the resolver writes back; pair it with
`BENCH_TRANSPORT=tcp` and `BENCH_SCENARIO=hit` to isolate the TCP write path.
The signed DNSSEC mock always answers one record.

### `scripts/bench-compare.sh` - interleaved A/B against a git ref

Builds a baseline ref once in a worktree under `target/ab/<sha>/` (with its
own `CARGO_TARGET_DIR`, reused by later invocations), builds the working
tree, then runs the two binaries back to back in alternating order
(A,B then B,A) as repeated pairs. Before every run it waits for the
1-minute load average to fall below a limit - including a settle step after
its own builds, which would otherwise hand the first variant a machine still
spiking from compilation - and prints the load before and after each run.
Results summarize as the median of each variant with percentage deltas.

### Load generator directly

The runner scripts build the generator for you; to run it by hand:

```bash
rustc --edition 2024 -O -o /tmp/dns-bench scripts/dns-bench.rs
/tmp/dns-bench serve 127.0.0.1:15354 &        # optional TTL seconds, default 3600
/tmp/dns-bench load 127.0.0.1:15353 4000 bench.test 8 5 10
```

`serve` arguments are address, the answer TTL in seconds (pass `0` for the
miss scenario), and the A-record count per answer (default 1). `load`
arguments are address, distinct names, zone, concurrency, warm-up seconds,
measured seconds, and the transport (`udp`, the default, or `tcp`). The mock
prints `stats upstream_queries=N` every 250 ms, which the runner uses to
bracket the load window in miss and dnssec mode. The resolver needs a
`bench.test.` stub zone pointing at the mock (both runners write this config
for you). For the TCP write path:

```bash
/tmp/dns-bench serve 127.0.0.1:15354 3600 100 &
/tmp/dns-bench load 127.0.0.1:15353 4000 bench.test 8 5 10 tcp
```

To run the signed DNSSEC mock by hand, build it once and pass it the same
address, zone, TTL, distinct-name count, and a path for the generated trust
anchor:

```bash
cargo build --release -p dns-testutil --bin dnssec-mock
target/release/dnssec-mock serve 127.0.0.1:15354 bench.test. 0 4000 /tmp/bench-anchor.txt &
cat /tmp/bench-anchor.txt   # DNSKEY record to use as trust_anchor
```

## Environment reference

### `bench-loopback.sh` (all pass through `bench-compare.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_SCENARIO` | `hit` | `hit` fixes TTLs at 3600 s so every query is a cache hit; `miss` uses a TTL-0 unsigned mock so every query is a genuine miss; `dnssec` uses a signed TTL-0 mock so every query also verifies an Ed25519 RRSIG. Both miss-style scenarios add `upstream=`/`saved=` to RESULT |
| `BENCH_NAMES` | 4000 | Distinct query names. For `hit`, keep at or below 8192 so the working set fits the message cache (above it the run thrashes the cache); for `miss` it controls coalescing - 1 maximizes it, a large value with low concurrency nearly eliminates it |
| `BENCH_CONCURRENCY` | 8 | Queries in flight |
| `BENCH_TRANSPORT` | `udp` | Client transport: `udp` or `tcp`. `tcp` keeps one persistent connection per load-generator thread and measures the resolver's TCP framing path; the upstream leg stays UDP |
| `BENCH_RECORDS` | 1 | A records per unsigned-mock answer, capped at 1000. Raise it with `BENCH_TRANSPORT=tcp` to size the response written back; the signed DNSSEC mock always answers one record |
| `BENCH_WARMUP` | 5 | Warm-up seconds before measuring |
| `BENCH_DURATION` | 10 | Measured seconds |
| `BENCH_PORT` | 15353 | Resolver port (UDP listener, and the TCP listener when `BENCH_TRANSPORT=tcp`) |
| `BENCH_MOCK_PORT` | 15354 | Mock authority UDP port |
| `BENCH_SERVER_CPUS` | 0-3 (hosts with >= 8 CPUs) | CPU list for the resolver (`taskset`) |
| `BENCH_CLIENT_CPUS` | remaining CPUs | CPU list for the load generator |
| `BENCH_SERVER_IMAGE` | unset | Run the resolver from a container image instead of the host binary (host networking; needs Docker) |
| `BENCH_BINARY` | `target/release/dns-rs` | Host-mode resolver binary to run; skips the build. Set automatically by `bench-compare.sh`. Cannot be combined with `BENCH_SERVER_IMAGE` |
| `BENCH_ALLOCS` | unset | `1` builds the resolver with `--features alloc-stats` and appends `allocs=`/`allocs_per_query=` to RESULT (host mode only; the counter adds an atomic to every allocation, so read the allocs fields from these runs, not their QPS) |
| `BENCH_PHASES` | unset | `1` builds the resolver with `--features phase-stats` and appends `phase_<name>_us=` per pipeline phase to RESULT (host mode only; every phase costs a clock read and an atomic, so read the phase fields from these runs, not their QPS) |
| `SKIP_BUILD` | unset | `1` reuses an existing host binary instead of building |

### `bench-compare.sh`

| Variable | Default | Meaning |
|---|---|---|
| `AB_REPEATS` | 3 | Baseline/candidate pairs per thread count (more pairs = tighter median) |
| `AB_LOAD_LIMIT` | `nproc / 4` | Wait for the 1-minute load average below this before each run; waits up to 180 s, then proceeds with a warning |

### Make variables

| Variable | Default | Meaning |
|---|---|---|
| `THREADS` | `1 2 4` | Benchmark worker counts, for `bench`, `bench-container`, `bench-compare` |
| `BASE_REF` | `origin/main` | Baseline git ref for `bench-compare` |

Command-line Make variables are exported to the recipes, so
`make bench BENCH_DURATION=30` and `make bench-compare AB_REPEATS=5` work as
expected.

## Scenario recipes

### Cache hits (the default)

```bash
make bench
```

Fits 4,000 names in the 8,192-entry message cache; every query is a hit.

### Cache misses

```bash
# Honest misses: every query goes upstream through a TTL-0 mock.
make bench-compare-miss THREADS="1 2 4" AB_REPEATS=3

# Per-run form.
make bench-miss THREADS="1 2 4"

# Maximal single-flight coalescing: all in-flight queries share one name.
BENCH_SCENARIO=miss BENCH_NAMES=1 scripts/bench-loopback.sh

# Almost no coalescing: 4000 distinct names, 8 in flight.
BENCH_SCENARIO=miss BENCH_NAMES=4000 scripts/bench-loopback.sh
```

`BENCH_SCENARIO=miss` makes the mock answer with TTL 0. The default
`cache_min_ttl` of 0 keeps the stored TTL at 0, so the resolver never caches
the answer and every query is a genuine miss - no cache thrashing involved.
The RESULT line then reports `upstream=` (mock queries during the load
window) and `saved=` (queries sent that did not reach the mock, i.e.
coalesced away). As an illustration from the development host, `BENCH_NAMES=1`
at concurrency 8 coalesced ~87% of queries, while `BENCH_NAMES=4000` saved ~0.
Those percentages are workload-specific and will change with host and client
timing; re-run them before quoting them elsewhere.

The older `BENCH_NAMES=20000` cache-thrash proxy still works in hit mode
(the runner warns that it exceeds the 8192-entry cache), but prefer the miss
scenario: it measures the upstream path with a controlled upstream instead
of evicting the cache.

### DNSSEC validation

```bash
# Per-query signed validation, 4000 names, 8 in flight.
make bench-dnssec THREADS="1 2 4"

# Interleaved A/B of the validation path itself.
make bench-compare-dnssec THREADS="1 2 4" AB_REPEATS=3
```

`BENCH_SCENARIO=dnssec` starts a signed authoritative mock instead of the
unsigned one. On startup the mock generates an Ed25519 key, writes its
DNSKEY record to a temporary file, and the runner configures that record as
the `bench.test.` trust anchor. A answers are signed and carry TTL 0, so no
answer is cached: every measured query walks to the mock, validates the A
RRSIG, and returns. The benchmark therefore combines the miss path with
signature verification, while the zone's DNSKEY (and its validated status)
is cached for the DNSKEY TTL, as in steady-state resolution. Every measured
answer must come back with the AD bit set, and at least one answer must be
measured; the runner aborts otherwise, so neither a broken or missing trust
anchor nor a run that answered nothing can silently turn the benchmark into a
plain miss run.

The mock signs with a fixed inception/expiry window (`SIGNATURE_LIFETIME`,
one hour). A benchmark run keeps the same mock process alive across all worker
counts, so a single invocation longer than about an hour starts receiving
SERVFAIL once the signatures expire. Restart the runner for longer soaks.

Compare `dnssec` against `miss` to isolate validation overhead, not against
`hit`: the hit path never reaches the mock or the validator. Use the same
`BENCH_NAMES` and concurrency for both sides; expect the signed run to be
substantially slower because every query pays for an RRSIG verification.

### TCP framing and large responses

```bash
# Cached 100-record answers served over TCP, one persistent connection per
# client thread.
BENCH_SCENARIO=hit BENCH_TRANSPORT=tcp BENCH_RECORDS=100 \
    scripts/bench-loopback.sh 1 2 4

# A/B the server's TCP write path against a ref.
BENCH_SCENARIO=hit BENCH_TRANSPORT=tcp BENCH_RECORDS=100 \
    scripts/bench-compare.sh <ref> 1 2 4
```

`BENCH_TRANSPORT=tcp` enables the resolver's TCP listener (`incoming_num_tcp =
128`) and makes the load generator reuse one length-prefixed connection per
thread. `BENCH_RECORDS=100` makes the mock return 100 A records, so each
cached answer is roughly 1.6 KB and the framing write is a meaningful share of
the RTT. The upstream leg stays UDP, which keeps the mock simple and isolates
the downstream TCP path. Use `hit` mode: the answer is cached after warm-up,
so the measured loop is decode, cache probe, encode, and frame.

### Allocation counts

```bash
# Per-query allocation counts for the working binary.
BENCH_ALLOCS=1 scripts/bench-loopback.sh 1

# A/B the metric itself; both variants build with the counting allocator.
BENCH_ALLOCS=1 scripts/bench-compare.sh origin/main 1 2 4
```

`BENCH_ALLOCS=1` builds the resolver with its `alloc-stats` feature: a
counting wrapper that keeps mimalloc underneath and prints `stats allocs=N`
every 250 ms, which the runner brackets around the load window exactly like
the mock's upstream counter. The RESULT line gains `allocs=` (allocation
requests - `alloc`, `alloc_zeroed`, `realloc` - during the window; no
deallocations are counted) and `allocs_per_query=` (`allocs / sent`).
Counting adds one atomic per allocation, so use these runs for allocation
comparisons, not throughput claims; container mode is unsupported (the
image does not carry the feature). `bench-compare.sh` builds both variants
with the feature and adds an allocs/query column to its summary, and the
baseline ref must already contain the feature - an older ref cannot A/B
what it cannot build.

### Phase attribution

```bash
# Per-phase timings for the working binary.
BENCH_PHASES=1 scripts/bench-loopback.sh 1

# A/B the timings themselves; both variants build with the timers.
BENCH_PHASES=1 scripts/bench-compare.sh origin/main 1 2 4
```

`BENCH_PHASES=1` builds the resolver with its `phase-stats` feature: every
stage of a query is timed and summed into process-wide counters that a
reporter thread prints as `stats phases ...` every 250 ms, which the runner
brackets around the load window exactly like the mock's upstream counter.
The RESULT line gains one `phase_<name>_us=` field per phase - microseconds
per query sent, so phases that do not apply to the scenario report `0.00`:

| Field | Phase |
|---|---|
| `phase_queue_us` | Receive harvest to handling: each query's wait since the receive syscall returned (its position inside a `recvmmsg` batch counts here), plus the spawn-to-task-start wait for cache misses |
| `phase_decode_us` | Decode plus ACL/rate-limit/concurrency checks, up to the cache probe |
| `phase_lookup_us` | Message-cache probe |
| `phase_coalesce_us` | Single-flight registry wait (followers) / register (leaders) |
| `phase_upstream_us` | Recursive resolution against upstreams (leaders only) |
| `phase_finalize_us` | Reply construction and encoding |
| `phase_send_us` | `sendto` syscall (UDP only) |

The fields need not sum to the client RTT, which also includes network and
client time, and the runner divides by all queries sent (not per-phase
visits), so a phase can look small when only some queries reach it. Timing
adds a clock read and an atomic per phase, so use these runs for
attribution, not throughput claims; container mode is unsupported (the
image does not carry the feature). `bench-compare.sh` builds both variants
with the feature and adds a per-phase table to its summary, and the baseline
ref must already contain the feature.

### Container mode

```bash
docker build -t dns-rs:bench .
make bench-container IMAGE=dns-rs:bench
```

### Reproducing CI

```bash
make bench-ci
```

4,000 names, 8 in flight, 5 s warm-up, 15 s sample, one and two workers,
container image.

## Methodology

- **Interleave, don't batch.** Run A/B pairs alternating order
  (A,B / B,A / ...) so steady machine drift cannot favor one side.
  `bench-compare.sh` does this for you; when measuring by hand, alternate
  runs yourself.
- **Check the load.** Note `uptime` (or the printed per-run load) before and
  after each run. `bench-compare.sh` gates on the 1-minute average; its
  default limit is a quarter of the CPU count.
- **Mind your own builds.** Compilation spikes the load average for about a
  minute; `bench-compare.sh` settles after building. If you build between
  hand runs, wait for the load to decay first.
- **Expect noise.** Consecutive single runs on the shared development host
  varied by up to about 15% in QPS and much more in p99. An earlier
  interleaved median-of-pairs experiment on identical binaries measured a
  ~2% noise floor (18 runs, deltas -1.6% / +1.0% / -1.2% at 1/2/4 workers).
  Treat deltas below ~2% as noise and re-run before believing anything under
  ~5%. Deltas at 4 workers are the least stable.
- **Never run benchmarks in parallel.** Concurrent runs compete for the same
  cores and invalidate each other.
- **Never set `RUSTFLAGS` or `target-cpu=native`** for benchmarks; compare
  stock builds only.
- **Apples to apples.** Same host, same script, same environment variables,
  same worker counts on both sides; change one thing at a time. Keep benchmark
  runs independent - if a run depends on a feature (for example caching),
  disable the feature on both sides.
- **Kill stale processes between manual runs** with `pkill -9 dns-rs`,
  `pkill -9 dns-bench`, and `pkill -9 dnssec-mock` (exact names only; never
  `pkill -f`).

## Reading the output

Per-run line printed by the runner:

```
threads=2 idle_rss_kib=18332 peak_rss_kib=26580 RESULT concurrency=8 \
    samples=1460502 qps=97367 errors=0 rcode=0 ad=0 p50_us=40.4 ... max_us=1486.6
```

| Field | Meaning |
|---|---|
| `concurrency` | Queries in flight from the load generator (from `BENCH_CONCURRENCY`) |
| `samples` | Responses received during the measured window; the denominator for the reported RTT percentiles |
| `qps` | Queries per second over the measured window |
| `sent` | Total queries sent by the load generator (warm-up plus measured) |
| `p50_us` .. `p99_us`, `max_us` | Client-side send-to-response RTT percentiles, microseconds |
| `errors` / `rcode` | Timed-out or malformed responses / non-zero response codes - any non-zero value makes the run suspect |
| `ad` | Measured answers with the AD (authenticated data) bit set; the dnssec scenario fails the run unless at least one answer was measured and this equals `samples` |
| `upstream` / `saved` | Miss and dnssec scenarios: mock queries observed during the load window, and `sent - upstream` - queries answered without reaching the mock (coalesced away) |
| `allocs` / `allocs_per_query` | `BENCH_ALLOCS=1` only: allocation requests during the load window, and that count divided by `sent` |
| `phase_queue_us` .. `phase_send_us` | `BENCH_PHASES=1` only: per-phase time during the load window, microseconds divided by `sent` (see "Phase attribution") |
| `idle_rss_kib` / `peak_rss_kib` | Resolver `VmRSS` at idle and `VmHWM` after the run |

`bench-compare.sh` adds per-run `== A/B ... load=` headers, `waiting...` gate
lines, and a final summary table of median qps/p50 per variant with `%`
deltas (plus median allocs/query when `BENCH_ALLOCS=1` and a per-phase table
when `BENCH_PHASES=1`). Warnings are printed if a variant reported query
errors.

## Publishing a result

Any number quoted outside this file should have a result page under
[`benchmark-results/`](benchmark-results/) using this template. Copy it, fill in
every field, and link it from the claim that uses the number.

| Field | Required content |
|---|---|
| Title | Workload and version, for example `0.6.0 loopback cache-hit baseline` |
| Build | Version, commit, date, Rust compiler, build profile, and any feature flags |
| Host | OS/kernel, CPU model and core count, memory, and whether the host was shared |
| Command | Exact `make`/script invocation and all environment variables |
| Scenario | Workload, name count, concurrency, warm-up, measured duration, CPU pinning |
| Runs | Raw `RESULT` lines for every run, with no edits |
| Summary | Throughput and latency ranges across runs, not only the best run |
| Limitations | Which paths were not exercised and what could make the number unrepresentative |

The 0.6.0 baseline page is the reference example. Note that a single run is not
a result; record repeated runs or an interleaved A/B comparison.

## Known limitations

- DoT and mixed UDP/TCP workloads are not measured. `BENCH_TRANSPORT=tcp`
  exercises the TCP listener only, and the upstream leg to the mock stays UDP.
- The TCP scenario uses one persistent connection per client thread; it does
  not measure connection churn or pipelined queries.
- The DNSSEC scenario validates positive answers only; negative (NSEC/NSEC3
  denial) validation and first-time chain building are not measured.
- The signed mock uses Ed25519, the cheapest common algorithm. RSA/SHA-256
  validation is materially more expensive, so the scenario understates the
  cost of zones that sign with RSA.
- Only the hit-path scenario feeds the README performance table.

## Cleanup

Baseline worktrees and their build caches live under `target/ab/` (git
ignored; the 0.6.0 development host used roughly 426 MB per ref, but this
varies with target and dependency set). To reclaim the space:

```bash
git worktree prune
rm -rf target/ab
```
