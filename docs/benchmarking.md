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
make bench-compare THREADS="1 2 4" AB_REPEATS=3 \
    BENCH_CONCURRENCY=32 BENCH_NAMES=20000

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
warms it up, and measures with `scripts/dns-bench.rs`. Both the name set and
TTLs are fixed, so every measured query is a message-cache hit as long as
`BENCH_NAMES` fits in the 8,192-entry cache.

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
/tmp/dns-bench serve 127.0.0.1:15354 &
/tmp/dns-bench load 127.0.0.1:15353 4000 bench.test 8 5 10
```

`load` arguments are address, distinct names, zone, concurrency, warm-up
seconds, and measured seconds. The resolver needs a `bench.test.` stub zone
pointing at the mock (both runners write this config for you).

## Environment reference

### `bench-loopback.sh` (all pass through `bench-compare.sh`)

| Variable | Default | Meaning |
|---|---|---|
| `BENCH_NAMES` | 4000 | Unique cache entries. Keep at or below 8192 for cache hits; above it the run thrashes the message cache and measures upstream misses |
| `BENCH_CONCURRENCY` | 8 | Queries in flight |
| `BENCH_WARMUP` | 5 | Warm-up seconds before measuring |
| `BENCH_DURATION` | 10 | Measured seconds |
| `BENCH_PORT` | 15353 | Resolver UDP port |
| `BENCH_MOCK_PORT` | 15354 | Mock authority UDP port |
| `BENCH_SERVER_CPUS` | 0-3 (hosts with >= 8 CPUs) | CPU list for the resolver (`taskset`) |
| `BENCH_CLIENT_CPUS` | remaining CPUs | CPU list for the load generator |
| `BENCH_SERVER_IMAGE` | unset | Run the resolver from a container image instead of the host binary (host networking; needs Docker) |
| `BENCH_BINARY` | `target/release/dns-rs` | Host-mode resolver binary to run; skips the build. Set automatically by `bench-compare.sh`. Cannot be combined with `BENCH_SERVER_IMAGE` |
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
make bench-compare THREADS="1 2 4" BENCH_CONCURRENCY=32 BENCH_NAMES=20000
```

`BENCH_NAMES=20000` exceeds the cache so most queries go upstream. This is a
proxy: it thrashes the cache rather than issuing clean misses with a
controlled upstream. The runner warns when `BENCH_NAMES` exceeds 8192. Use
it consistently for A/B comparisons and it remains useful; an honest
TTL-0-upstream miss scenario is planned (see "Known limitations").

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
| `p50_us` .. `p99_us`, `max_us` | Client-side send-to-response RTT percentiles, microseconds |
| `errors` / `rcode` | Timed-out or malformed responses / non-zero response codes - any non-zero value makes the run suspect |
| `idle_rss_kib` / `peak_rss_kib` | Resolver `VmRSS` at idle and `VmHWM` after the run |

`bench-compare.sh` adds per-run `== A/B ... load=` headers, `waiting...` gate
lines, and a final summary table of median qps/p50 per variant with `%`
deltas. Warnings are printed if a variant reported query errors.

## Known limitations

- The miss scenario is cache-thrash based (see above); an honest
  TTL-0-upstream scenario with coalescing counters is planned.
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
