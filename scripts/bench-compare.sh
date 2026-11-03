#!/bin/bash
# Interleaved A/B benchmark: run a baseline git ref and the working tree back
# to back and report the difference in throughput and latency. Runs alternate
# order (A,B then B,A) and repeat as pairs, which cancels machine drift that
# single back-to-back runs cannot — the README documents up to 15% run-to-run
# variance on a shared host.
#
# Usage: scripts/bench-compare.sh [BASE_REF] [THREADS...]
#   BASE_REF  git ref for variant A (default: origin/main)
#   THREADS   worker counts, one benchmark run each (default: 1 2 4)
#
# Environment overrides:
#   AB_REPEATS     baseline/candidate pairs per thread count (default 3)
#   AB_LOAD_LIMIT  wait for the 1-minute load average to fall below this
#                  before each run (default: a quarter of the CPU count, so
#                  the script's own builds settle before measuring)
#   All BENCH_* variables pass through to scripts/bench-loopback.sh
#   (BENCH_NAMES, BENCH_CONCURRENCY, BENCH_WARMUP, BENCH_DURATION, ...)
#
# The baseline is built once in a worktree under target/ab/<sha>/ and reused
# by later invocations as long as the ref points at the same commit. Builds
# and benchmark runs are strictly sequential; benchmarks never overlap.
#
# Results are printed per run and summarized as the median of each variant
# with the percentage delta. Repeated pairs beat single runs: judge small
# deltas against the README's variance note.
#
# Example (honest cache-miss A/B, TTL-0 upstream):
#   AB_REPEATS=3 BENCH_SCENARIO=miss scripts/bench-compare.sh origin/main 1 2 4

set -euo pipefail

cd "$(dirname "$0")/.."

base_ref="${1:-origin/main}"
if [ $# -gt 0 ]; then
    shift
fi
threads=("$@")
if [ ${#threads[@]} -eq 0 ]; then
    threads=(1 2 4)
fi

repeats="${AB_REPEATS:-3}"
cpus="$(nproc 2>/dev/null || echo 1)"
load_limit="${AB_LOAD_LIMIT:-$((cpus / 4))}"

if ! base_sha="$(git rev-parse --verify "$base_ref^{commit}" 2>/dev/null)"; then
    echo "cannot resolve BASE_REF '$base_ref'" >&2
    exit 1
fi
if [ -n "${BENCH_SERVER_IMAGE:-}" ]; then
    echo "bench-compare runs host binaries only; unset BENCH_SERVER_IMAGE" >&2
    exit 1
fi

echo "A = $base_ref ($(git rev-parse --short "$base_sha"))"
echo "B = working tree (HEAD $(git rev-parse --short HEAD), $(git status --porcelain | wc -l) local changes)"

# Stale bench processes would hold the ports or steal CPU from the run.
pkill -9 dns-rs 2>/dev/null || true
pkill -9 dns-bench 2>/dev/null || true

tmp="$(mktemp -d "${TMPDIR:-/tmp}/dns-rs-ab.XXXXXX")"
cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

# --- build both variants up front so no build runs between measurements ---
echo "building candidate (working tree)..."
cargo build --release -p dns-daemon
bin_b="$PWD/target/release/dns-rs"

ab_root="$PWD/target/ab/$base_sha"
bin_a="$ab_root/cargo/release/dns-rs"
if [ ! -x "$bin_a" ]; then
    echo "building baseline $base_sha (first run for this ref; cached afterwards)..."
    mkdir -p "$ab_root"
    if [ ! -d "$ab_root/src/.git" ]; then
        git worktree add --detach "$ab_root/src" "$base_sha" >/dev/null 2>&1
    fi
    CARGO_TARGET_DIR="$ab_root/cargo" \
        cargo build --release -p dns-daemon --manifest-path "$ab_root/src/Cargo.toml"
fi

# --- measurement helpers -------------------------------------------------

# Block while the 1-minute load average is above the limit so every run in
# the comparison sees a similar machine state.
wait_for_capacity() {
    local load1 waited=0
    while :; do
        load1="$(awk '{print $1}' /proc/loadavg)"
        if ! awk -v l="$load1" -v lim="$load_limit" 'BEGIN { exit !(l > lim) }'; then
            return 0
        fi
        if [ "$waited" -ge 180 ]; then
            echo "warning: load $load1 still above limit $load_limit after 180s;" \
                "running anyway" >&2
            return 0
        fi
        echo "load $load1 above limit $load_limit; waiting..."
        sleep 15
        waited=$((waited + 15))
    done
}

median() {
    sort -n | awk '
        { v[NR] = $1 }
        END {
            if (NR == 0) { print "nan" }
            else if (NR % 2) { print v[(NR + 1) / 2] }
            else { printf "%.1f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2 }
        }'
}

delta_pct() {
    awk -v a="$1" -v b="$2" 'BEGIN {
        if (a == 0 || a == "nan" || b == "nan") { print "n/a" }
        else { printf "%+.1f%%", (b - a) / a * 100 }
    }'
}

# One full bench-loopback.sh pass for a single worker count, on one variant.
# Usage: run_one LABEL BINARY WORKERS
run_one() {
    local label="$1" bin="$2" workers="$3"
    local out line load_before load_after qps p50
    wait_for_capacity
    load_before="$(awk '{print $1}' /proc/loadavg)"
    echo "== $label workers=$workers load=$load_before"
    if ! out="$(BENCH_BINARY="$bin" scripts/bench-loopback.sh "$workers")"; then
        echo "error: $label run failed for $workers worker(s)" >&2
        exit 1
    fi
    echo "$out"
    load_after="$(awk '{print $1}' /proc/loadavg)"
    if ! line="$(printf '%s\n' "$out" | grep -o 'RESULT.*' | tail -1)"; then
        echo "error: $label produced no RESULT line" >&2
        exit 1
    fi
    qps="$(printf '%s' "$line" | sed -n 's/.* qps=\([0-9.]*\).*/\1/p')"
    p50="$(printf '%s' "$line" | sed -n 's/.* p50_us=\([0-9.]*\).*/\1/p')"
    if [ -z "$qps" ] || [ -z "$p50" ]; then
        echo "error: could not parse RESULT line: $line" >&2
        exit 1
    fi
    printf '%s\n' "$qps" >>"$tmp/qps-$label-$workers"
    printf '%s\n' "$p50" >>"$tmp/p50-$label-$workers"
    if printf '%s' "$line" | grep -qE 'errors=[1-9]|rcode=[1-9]'; then
        echo "warning: $label reported query errors; its numbers are suspect" >&2
        echo 1 >>"$tmp/err-$label-$workers"
    fi
    echo "-- $label workers=$workers load $load_before -> $load_after"
}

# --- run interleaved pairs ----------------------------------------------

# The builds above leave a decaying 1-minute load average; settle before the
# first measurement so variant A does not systematically run on a busier box.
echo "settling after builds until load < $load_limit..."
wait_for_capacity

for workers in "${threads[@]}"; do
    for rep in $(seq 1 "$repeats"); do
        # Alternate which variant runs first so steady machine drift over the
        # session does not favor one side.
        if [ $((rep % 2)) -eq 1 ]; then
            order=(A B)
        else
            order=(B A)
        fi
        for variant in "${order[@]}"; do
            if [ "$variant" = "A" ]; then
                run_one A "$bin_a" "$workers"
            else
                run_one B "$bin_b" "$workers"
            fi
        done
    done
done

# --- summary -------------------------------------------------------------

echo
echo "=== A/B summary: median of $repeats pair(s), A = $base_ref, B = working tree ==="
printf '%-8s %11s %11s %9s %10s %10s %9s\n' \
    "threads" "A qps" "B qps" "delta" "A p50_us" "B p50_us" "delta"
for workers in "${threads[@]}"; do
    a="$(median <"$tmp/qps-A-$workers")"
    b="$(median <"$tmp/qps-B-$workers")"
    pa="$(median <"$tmp/p50-A-$workers")"
    pb="$(median <"$tmp/p50-B-$workers")"
    printf '%-8s %11s %11s %9s %10s %10s %9s\n' \
        "$workers" "$a" "$b" "$(delta_pct "$a" "$b")" "$pa" "$pb" "$(delta_pct "$pa" "$pb")"
done
for workers in "${threads[@]}"; do
    for label in A B; do
        if [ -f "$tmp/err-$label-$workers" ]; then
            echo "warning: variant $label at $workers worker(s) reported query errors" >&2
        fi
    done
done
echo "Note: repeated runs on a shared host vary by up to 15% (README); treat"
echo "small deltas, especially at 4 threads, as within noise unless repeated."
