# Benchmarking dns-rs

Single reference for every benchmarking switch, runner, and methodology rule.
The performance numbers live in the [README](../README.md#performance); this
document explains how to produce and compare numbers yourself.

## Quick start

```bash
# Cache-hit benchmark, worker counts 1 2 4 (builds the release binary).
make bench

# Interleaved A/B: working tree vs. a baseline ref (recommended for any
# performance claim; builds the baseline once, caches it under target/ab/).
make bench-compare
make bench-compare BASE_REF=e4176ff THREADS="1 2 4"

# Cache-miss A/B at high concurrency (see "Cache misses" below).
make bench-compare THREADS="1 2 4" AB_REPEATS=3 BENCH_SCENARIO=miss

# Allocation A/B: both variants build with the counting allocator.
make bench-compare BENCH_ALLOCS=1

# Phase attribution A/B: both variants build with per-phase timers.
make bench-compare BENCH_PHASES=1

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
and how many were coalesced away.

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

`serve` arguments are address and the answer TTL in seconds (pass `0` for
the miss scenario). `load` arguments are address, distinct names, zone,
concurrency, warm-up seconds, and measured seconds. The mock prints
`stats upstream_queries=N` every 250 ms, which the runner uses to bracket
the load window in miss mode. The resolver needs a `bench.test.` stub zone
pointing at the mock (both runners write this config for you).

## Environment reference

### `bench-loopback.sh` (all pass through `bench-compare.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_SCENARIO` | `hit` | `hit` fixes TTLs at 3600 s so every query is a cache hit; `miss` uses a TTL-0 mock so every query is a genuine miss and the RESULT line gains `upstream=`/`saved=` |
| `BENCH_NAMES` | 4000 | Distinct query names. For `hit`, keep at or below 8192 so the working set fits the message cache (above it the run thrashes the cache); for `miss` it controls coalescing - 1 maximizes it, a large value with low concurrency nearly eliminates it |
| `BENCH_CONCURRENCY` | 8 | Queries in flight |
| `BENCH_WARMUP` | 5 | Warm-up seconds before measuring |
| `BENCH_DURATION` | 10 | Measured seconds |
| `BENCH_PORT` | 15353 | Resolver UDP port |
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
make bench-compare THREADS="1 2 4" AB_REPEATS=3 BENCH_SCENARIO=miss

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
coalesced away). Measured on this host: `BENCH_NAMES=1` at concurrency 8
coalesces ~87% of queries, while `BENCH_NAMES=4000` saves ~0.

The older `BENCH_NAMES=20000` cache-thrash proxy still works in hit mode
(the runner warns that it exceeds the 8192-entry cache), but prefer the miss
scenario: it measures the upstream path with a controlled upstream instead
of evicting the cache.

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
| `phase_queue_us` | Receive syscall to handling: inline dispatch on hits, plus the spawn-to-task-start wait for cache misses |
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
- **Expect noise.** Repeated runs on a shared host have varied by up to 15%
  (README). The interleaved median-of-pairs method measured a ~2% noise floor
  on identical binaries (18 runs, deltas -1.6% / +1.0% / -1.2% at 1/2/4
  workers), so treat deltas below ~2% as noise and re-run before believing
  anything under ~5%. Deltas at 4 workers are the least stable.
- **Never run benchmarks in parallel.** Concurrent runs compete for the same
  cores and invalidate each other.
- **Never set `RUSTFLAGS` or `target-cpu=native`** for benchmarks; compare
  stock builds only.
- **Apples to apples.** Same host, same script, same environment variables,
  same worker counts on both sides; change one thing at a time. Keep benchmark
  runs independent - if a run depends on a feature (for example caching),
  disable the feature on both sides.
- **Kill stale processes between manual runs** with `pkill -9 dns-rs` and
  `pkill -9 dns-bench` (exact names only; never `pkill -f`).

## Reading the output

Per-run line printed by the runner:

```
threads=2 idle_rss_kib=18332 peak_rss_kib=26580 RESULT concurrency=8 \
    samples=1460502 qps=97367 errors=0 rcode=0 p50_us=40.4 ... max_us=1486.6
```

| Field | Meaning |
|---|---|
| `qps` | Queries per second over the measured window |
| `sent` | Total queries sent by the load generator (warm-up plus measured) |
| `p50_us` .. `p99_us`, `max_us` | Client-side send-to-response RTT percentiles, microseconds |
| `errors` / `rcode` | Timed-out or malformed responses / non-zero response codes - any non-zero value makes the run suspect |
| `upstream` / `saved` | Miss scenario only: mock queries observed during the load window, and `sent - upstream` - queries answered without reaching the mock (coalesced away) |
| `allocs` / `allocs_per_query` | `BENCH_ALLOCS=1` only: allocation requests during the load window, and that count divided by `sent` |
| `phase_queue_us` .. `phase_send_us` | `BENCH_PHASES=1` only: per-phase time during the load window, microseconds divided by `sent` (see "Phase attribution") |
| `idle_rss_kib` / `peak_rss_kib` | Resolver `VmRSS` at idle and `VmHWM` after the run |

`bench-compare.sh` adds per-run `== A/B ... load=` headers, `waiting...` gate
lines, and a final summary table of median qps/p50 per variant with `%`
deltas (plus median allocs/query when `BENCH_ALLOCS=1` and a per-phase table
when `BENCH_PHASES=1`). Warnings are printed if a variant reported query
errors.

## Known limitations

- There is no TCP/DoT, DNSSEC-validation, large-response, or mixed-workload
  scenario yet.
- Only the hit-path scenario feeds the README performance table.

## Cleanup

Baseline worktrees and their build caches live under `target/ab/` (git
ignored, ~426 MB per ref). To reclaim the space:

```bash
git worktree prune
rm -rf target/ab
```
