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
#   BENCH_ALLOCS   1 builds both variants with --features alloc-stats and
#                  adds an allocs/query column to the summary (the baseline
#                  ref must contain that feature)
#   BENCH_PHASES   1 builds both variants with --features phase-stats and
#                  adds a per-phase table to the summary (the baseline ref
#                  must contain that feature)
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

# Instrumentation requested for both variants: the A/B must compare like with
# like, so each feature is compiled into the candidate and the baseline.
feature_list=""
if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
    feature_list="alloc-stats"
fi
if [ "${BENCH_PHASES:-0}" = "1" ]; then
    feature_list="${feature_list:+$feature_list,}phase-stats"
fi
feature_args=()
if [ -n "$feature_list" ]; then
    feature_args=(--features "$feature_list")
fi

# Phases reported by bench-loopback.sh, in report order.
phases="queue decode lookup coalesce upstream finalize send"

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
cargo build --release -p dns-daemon "${feature_args[@]}"
bin_b="$PWD/target/release/dns-rs"

# Instrumented baselines cache separately so toggling a feature does not
# rebuild a baseline built without it (and vice versa).
ab_suffix=""
if [ -n "$feature_list" ]; then
    ab_suffix="-$(printf '%s' "$feature_list" | tr ',' '-')"
fi
ab_root="$PWD/target/ab/${base_sha}${ab_suffix}"
bin_a="$ab_root/cargo/release/dns-rs"
if [ ! -x "$bin_a" ]; then
    echo "building baseline $base_sha (first run for this ref; cached afterwards)..."
    mkdir -p "$ab_root"
    if [ ! -d "$ab_root/src/.git" ]; then
        git worktree add --detach "$ab_root/src" "$base_sha" >/dev/null 2>&1
    fi
    if [ -n "$feature_list" ]; then
        IFS=',' read -r -a wanted_features <<<"$feature_list"
        for feature in "${wanted_features[@]}"; do
            if ! grep -q "$feature" "$ab_root/src/crates/dns-daemon/Cargo.toml"; then
                echo "baseline $base_ref predates the '$feature' feature;" \
                    "pick a BASE_REF that contains it" >&2
                exit 1
            fi
        done
    fi
    CARGO_TARGET_DIR="$ab_root/cargo" \
        cargo build --release -p dns-daemon --manifest-path "$ab_root/src/Cargo.toml" \
        "${feature_args[@]}"
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
    local out line load_before load_after qps p50 apq phase_value
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
    if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
        apq="$(printf '%s' "$line" | sed -n 's/.* allocs_per_query=\([0-9.]*\).*/\1/p')"
        if [ -z "$apq" ]; then
            echo "error: $label produced no allocs_per_query; both variants need" \
                "--features alloc-stats" >&2
            exit 1
        fi
        printf '%s\n' "$apq" >>"$tmp/apq-$label-$workers"
    fi
    if [ "${BENCH_PHASES:-0}" = "1" ]; then
        for phase in $phases; do
            phase_value="$(printf '%s' "$line" \
                | sed -n "s/.* phase_${phase}_us=\([0-9.]*\).*/\1/p")"
            if [ -z "$phase_value" ]; then
                echo "error: $label produced no phase_${phase}_us; both variants need" \
                    "--features phase-stats" >&2
                exit 1
            fi
            printf '%s\n' "$phase_value" >>"$tmp/phase-$phase-$label-$workers"
        done
    fi
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
if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
    echo
    printf '%-8s %14s %14s %9s\n' "threads" "A allocs/query" "B allocs/query" "delta"
    for workers in "${threads[@]}"; do
        a="$(median <"$tmp/apq-A-$workers")"
        b="$(median <"$tmp/apq-B-$workers")"
        printf '%-8s %14s %14s %9s\n' "$workers" "$a" "$b" "$(delta_pct "$a" "$b")"
    done
fi
if [ "${BENCH_PHASES:-0}" = "1" ]; then
    echo
    printf '%-8s %-11s %10s %10s %9s\n' "threads" "phase_us" "A" "B" "delta"
    for workers in "${threads[@]}"; do
        for phase in $phases; do
            a="$(median <"$tmp/phase-$phase-A-$workers")"
            b="$(median <"$tmp/phase-$phase-B-$workers")"
            printf '%-8s %-11s %10s %10s %9s\n' \
                "$workers" "$phase" "$a" "$b" "$(delta_pct "$a" "$b")"
        done
    done
fi
for workers in "${threads[@]}"; do
    for label in A B; do
        if [ -f "$tmp/err-$label-$workers" ]; then
            echo "warning: variant $label at $workers worker(s) reported query errors" >&2
        fi
    done
done
echo "Note: repeated runs on a shared host vary by up to 15% (README); treat"
echo "small deltas, especially at 4 threads, as within noise unless repeated."
