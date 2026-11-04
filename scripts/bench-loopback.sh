#!/bin/bash
# Loopback benchmark for the cache-hit and cache-miss paths. Builds the
# release binary and a standalone load generator, then reports latency
# percentiles, throughput, and RSS for 1, 2, and 4 worker threads.
#
# Usage: scripts/bench-loopback.sh [THREADS...]
#   THREADS defaults to "1 2 4".
#
# Environment overrides:
#   BENCH_SCENARIO      hit (default) or miss. hit uses a 3600 s mock TTL so
#                      every measured query is a cache hit; miss uses a TTL-0
#                      mock so nothing is cached and every query is a genuine
#                      miss, with upstream/saved reported (see below)
#   BENCH_NAMES        unique cache entries (default 4000; the message cache
#                      holds 8192 entries, so keep this below that limit —
#                      above it the run thrashes the cache and measures
#                      upstream misses instead of cache hits)
#   BENCH_CONCURRENCY  queries in flight (default 8; enough to pipeline
#                      loopback queries without queueing behind one worker)
#   BENCH_WARMUP       warm-up seconds (default 5)
#   BENCH_DURATION     measured seconds (default 10)
#   BENCH_PORT         resolver UDP port (default 15353)
#   BENCH_MOCK_PORT    mock authority UDP port (default 15354)
#   BENCH_SERVER_CPUS  CPU list for the resolver (default 0-3 when >= 8 CPUs)
#   BENCH_CLIENT_CPUS  CPU list for the load generator (default the rest)
#   BENCH_SERVER_IMAGE run the resolver from this image instead of the host
#                      binary (Linux host networking; see README)
#   BENCH_BINARY       host-mode resolver binary to run (skips the build;
#                      defaults to target/release/dns-rs; ignored when
#                      BENCH_SERVER_IMAGE is set)
#   BENCH_ALLOCS       1 reports allocation counts: builds with --features
#                      alloc-stats and appends allocs=/allocs_per_query= to
#                      RESULT (host mode only; the counter adds an atomic to
#                      every allocation, so read the allocs fields from these
#                      runs, not their QPS)
#   BENCH_PHASES       1 reports per-phase timings: builds with --features
#                      phase-stats and appends phase_<name>_us= to RESULT
#                      (host mode only; every phase costs a clock read and
#                      an atomic, so read the phase fields from these runs,
#                      not their QPS)
#   SKIP_BUILD=1       use an existing host binary (host mode only)
#
# The resolver serves a stub zone backed by a local mock authority. In hit
# mode both the name set and the TTLs are fixed, so every measured query is a
# message-cache hit as long as BENCH_NAMES fits in the cache. Results depend
# on the host; run on an otherwise idle machine for comparable numbers.
#
# In miss mode the mock answers with TTL 0 (the default cache_min_ttl keeps
# the entry at 0, so nothing is stored) and the RESULT line gains
#   upstream=N  mock queries observed during the load window
#   saved=M     queries sent that did not reach the mock (coalesced away)
# Names repeat across the name set, so BENCH_NAMES=1 maximizes coalescing
# (saved close to sent) while a large BENCH_NAMES with a small concurrency
# coalesces almost nothing (saved near 0).
#
# With BENCH_ALLOCS=1 the resolver runs a counting allocator (mimalloc
# underneath) that prints `stats allocs=N` every 250 ms; the runner brackets
# the load window the same way and the RESULT line gains
#   allocs=N        allocation requests (alloc, alloc_zeroed, realloc) in the window
#   allocs_per_query=X.Y  allocs divided by queries sent
#
# With BENCH_PHASES=1 the resolver times each stage of a query and prints
# `stats phases ...` every 250 ms; the runner brackets the load window the
# same way and the RESULT line gains one field per phase, in microseconds
# divided by the queries sent:
#   phase_queue_us      receive syscall to handler task start (task-spawn cost)
#   phase_decode_us     decode plus ACL/rate-limit/concurrency checks
#   phase_lookup_us     message-cache probe
#   phase_coalesce_us   single-flight registry wait
#   phase_upstream_us   recursive resolution (leaders only)
#   phase_finalize_us   reply construction and encoding
#   phase_send_us       sendto syscall (UDP only)
# A phase the scenario never reaches reports 0.00; the fields need not sum to
# the client RTT, which also includes network and client time.
#
# A cache-thrash run (not recommended; prefer BENCH_SCENARIO=miss):
#   BENCH_NAMES=20000 scripts/bench-loopback.sh
#
# Container mode example:
#   docker build -t dns-rs:bench .
#   BENCH_SERVER_IMAGE=dns-rs:bench scripts/bench-loopback.sh

set -euo pipefail

cd "$(dirname "$0")/.."

threads=("$@")
if [ ${#threads[@]} -eq 0 ]; then
    threads=(1 2 4)
fi

names="${BENCH_NAMES:-4000}"
scenario="${BENCH_SCENARIO:-hit}"
concurrency="${BENCH_CONCURRENCY:-8}"
warmup="${BENCH_WARMUP:-5}"
duration="${BENCH_DURATION:-10}"
port="${BENCH_PORT:-15353}"
mock_port="${BENCH_MOCK_PORT:-15354}"
zone="bench.test"
server_image="${BENCH_SERVER_IMAGE:-}"
binary="${BENCH_BINARY:-target/release/dns-rs}"

if [ -n "$server_image" ] && [ -n "${BENCH_BINARY:-}" ]; then
    echo "BENCH_BINARY and BENCH_SERVER_IMAGE both select the resolver; set only one" >&2
    exit 1
fi
if [ -n "$server_image" ] && [ "${BENCH_ALLOCS:-0}" = "1" ]; then
    echo "BENCH_ALLOCS=1 needs a host binary; unset BENCH_SERVER_IMAGE" >&2
    exit 1
fi
if [ -n "$server_image" ] && [ "${BENCH_PHASES:-0}" = "1" ]; then
    echo "BENCH_PHASES=1 needs a host binary; unset BENCH_SERVER_IMAGE" >&2
    exit 1
fi

# Instrumentation features requested for this run, joined for --features.
features=""
if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
    features="alloc-stats"
fi
if [ "${BENCH_PHASES:-0}" = "1" ]; then
    features="${features:+$features,}phase-stats"
fi

# Latest cumulative `stats` line in a log, polling up to 2 s for a reporter
# that prints every 250 ms. Prints nothing when the binary never reports, so
# the caller can fail fast on a build that lacks the feature.
poll_stats() {
    local log="$1" pattern="$2" value=""
    for _ in $(seq 1 20); do
        value="$(sed -n "$pattern" "$log" | tail -1)"
        if [ -n "$value" ]; then
            printf '%s' "$value"
            return
        fi
        sleep 0.1
    done
}

# Per-phase microseconds per query from two `stats phases ...` snapshots.
# Usage: phases_summary BEFORE AFTER SENT
phases_summary() {
    awk -v before="$1" -v after="$2" -v sent="$3" 'BEGIN {
        split(before, b, " ")
        split(after, a, " ")
        for (i in b) { split(b[i], kv, "="); prev[kv[1]] = kv[2] }
        for (i in a) { split(a[i], kv, "="); curr[kv[1]] = kv[2] }
        split("queue decode lookup coalesce upstream finalize send", names, " ")
        for (i = 1; i <= 7; i++) {
            key = names[i] "_ns"
            printf " phase_%s_us=%.2f", names[i], \
                (sent > 0) ? (curr[key] - prev[key]) / sent / 1000 : 0
        }
    }'
}

# Capacity of the message cache (dns-server MESSAGE_CACHE_ENTRIES). Above it
# the working set no longer fits and most queries go upstream.
cache_entries=8192
case "$scenario" in
    hit)
        mock_ttl=3600
        if [ "$names" -gt "$cache_entries" ]; then
            cache_mode="thrash"
            echo "warning: BENCH_NAMES=$names exceeds the $cache_entries-entry message cache;" \
                "this run measures upstream misses, not cache hits" >&2
        else
            cache_mode="fit"
        fi
        ;;
    miss)
        # TTL 0 is clamped to 0 by the default cache_min_ttl, so the resolver
        # never stores the answer and every query is a genuine miss.
        mock_ttl=0
        cache_mode="miss"
        ;;
    *)
        echo "BENCH_SCENARIO must be 'hit' or 'miss' (got: $scenario)" >&2
        exit 1
        ;;
esac

if [ -n "$server_image" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "BENCH_SERVER_IMAGE is set but docker is not available" >&2
        exit 1
    fi
elif [ -z "${BENCH_BINARY:-}" ] && [ "${SKIP_BUILD:-0}" != "1" ]; then
    if [ -n "$features" ]; then
        cargo build --release -p dns-daemon --features "$features"
    else
        cargo build --release -p dns-daemon
    fi
fi

if [ -z "$server_image" ] && [ ! -x "$binary" ]; then
    echo "resolver binary not found or not executable: $binary" >&2
    exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/dns-rs-bench.XXXXXX")"
# The runtime image runs as UID 65532, so the bind-mounted config must be
# reachable by a user that does not own the temporary directory.
chmod 755 "$tmp"
mock_pid=""
server_pid=""
container_name=""
cleanup() {
    if [ -n "$container_name" ]; then
        docker rm -f "$container_name" >/dev/null 2>&1 || true
    fi
    if [ -n "$server_pid" ]; then
        kill -TERM "$server_pid" 2>/dev/null || true
    fi
    if [ -n "$mock_pid" ]; then
        kill -TERM "$mock_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

rustc --edition 2024 -O -o "$tmp/dns-bench" scripts/dns-bench.rs

server_cpus="${BENCH_SERVER_CPUS:-}"
client_cpus="${BENCH_CLIENT_CPUS:-}"
cpus="$(nproc 2>/dev/null || echo 1)"
if [ -z "$server_cpus" ] && [ -z "$client_cpus" ] && [ "$cpus" -ge 8 ] \
    && command -v taskset >/dev/null 2>&1; then
    server_cpus="0-3"
    client_cpus="4-$((cpus - 1))"
fi
pin_server=()
pin_client=()
if [ -n "$server_cpus" ]; then
    pin_server=(taskset -c "$server_cpus")
fi
if [ -n "$client_cpus" ]; then
    pin_client=(taskset -c "$client_cpus")
fi

"$tmp/dns-bench" serve "127.0.0.1:$mock_port" "$mock_ttl" >"$tmp/mock.log" 2>&1 &
mock_pid=$!
sleep 0.3
if ! kill -0 "$mock_pid" 2>/dev/null; then
    echo "mock authority failed to bind 127.0.0.1:$mock_port" >&2
    cat "$tmp/mock.log" >&2
    exit 1
fi

printf 'scenario=%s names=%s cache=%s concurrency=%s warmup=%ss duration=%ss server_cpus=%s client_cpus=%s server=%s\n' \
    "$scenario" "$names" "$cache_mode" "$concurrency" "$warmup" "$duration" \
    "${server_cpus:-any}" "${client_cpus:-any}" "${server_image:-host}"

for workers in "${threads[@]}"; do
    config="$tmp/bench-$workers.toml"
    cat >"$config" <<EOF
[server]
interfaces = ["127.0.0.1"]
port = $port
verbosity = 0
num_threads = $workers
do_ip4 = true
do_ip6 = false
do_udp = true
do_tcp = false
incoming_num_tcp = 0

[[stub_zones]]
name = "$zone."
stub_addrs = ["127.0.0.1@$mock_port"]
stub_first = false
stub_no_cache = false
EOF

    if [ -n "$server_image" ]; then
        container_name="dns-rs-bench-$$-$workers"
        docker rm -f "$container_name" >/dev/null 2>&1 || true
        docker_args=(run -d --rm --name "$container_name" --network host --no-healthcheck)
        if [ -n "$server_cpus" ]; then
            docker_args+=(--cpuset-cpus "$server_cpus")
        fi
        docker "${docker_args[@]}" \
            -v "$config:/etc/dns-rs/dns-rs.toml:ro" \
            "$server_image" -c /etc/dns-rs/dns-rs.toml run >"$tmp/server-$workers.log" 2>&1 \
            || {
                cat "$tmp/server-$workers.log" >&2
                exit 1
            }
        server_pid="$(docker inspect -f '{{.State.Pid}}' "$container_name" 2>/dev/null || echo 0)"
    else
        "${pin_server[@]}" "$binary" -c "$config" run >"$tmp/server-$workers.log" 2>&1 &
        server_pid=$!
    fi

    ready=0
    for _ in $(seq 1 100); do
        if [ -n "$server_image" ]; then
            if docker exec "$container_name" /usr/local/bin/dns-rs \
                -c /etc/dns-rs/dns-rs.toml healthcheck \
                --name "n00000.$zone" --port "$port" >/dev/null 2>&1; then
                ready=1
                break
            fi
        elif "$binary" -c "$config" healthcheck \
            --name "n00000.$zone" --port "$port" >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 0.1
    done
    if [ "$ready" != "1" ]; then
        echo "server with $workers thread(s) did not start" >&2
        if [ -n "$container_name" ]; then
            docker logs "$container_name" >&2 2>&1 || true
        else
            cat "$tmp/server-$workers.log" >&2
        fi
        exit 1
    fi

    idle_kib="$(awk '/^VmRSS:/ {print $2}' "/proc/$server_pid/status")"
    # In miss mode the mock's cumulative query counter brackets the load
    # window: the snapshot after the healthcheck excludes readiness queries,
    # and the delta over the run measures how many queries actually went
    # upstream versus being coalesced or answered from cache.
    if [ "$scenario" = "miss" ]; then
        up0="$(poll_stats "$tmp/mock.log" 's/^stats upstream_queries=//p')"
        up0="${up0:-0}"
    fi
    # In alloc mode the resolver's reporter prints its cumulative counter
    # every 250 ms; snapshot the latest reading before the load so the delta
    # covers only the measured window. A binary built without
    # --features alloc-stats never prints one, so poll briefly and fail fast.
    if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
        allocs0="$(poll_stats "$tmp/server-$workers.log" 's/^stats allocs=//p')"
        if [ -z "$allocs0" ]; then
            echo "BENCH_ALLOCS=1 but the resolver reported no alloc stats; build with" \
                "--features alloc-stats (or unset BENCH_ALLOCS/SKIP_BUILD)" >&2
            exit 1
        fi
    fi
    # Phase mode brackets the window the same way, on the resolver's own
    # `stats phases ...` line.
    if [ "${BENCH_PHASES:-0}" = "1" ]; then
        phases0="$(poll_stats "$tmp/server-$workers.log" 's/^stats phases //p')"
        if [ -z "$phases0" ]; then
            echo "BENCH_PHASES=1 but the resolver reported no phase stats; build with" \
                "--features phase-stats (or unset BENCH_PHASES/SKIP_BUILD)" >&2
            exit 1
        fi
    fi
    result="$("${pin_client[@]}" "$tmp/dns-bench" load "127.0.0.1:$port" "$names" \
        "$zone" "$concurrency" "$warmup" "$duration")"
    if [ "$scenario" = "miss" ] || [ "${BENCH_ALLOCS:-0}" = "1" ] \
        || [ "${BENCH_PHASES:-0}" = "1" ]; then
        # The mock and the resolver's reporters all print every 250 ms; wait
        # for the post-load reading before snapshotting.
        sleep 1
        sent="$(printf '%s\n' "$result" | sed -n 's/.* sent=\([0-9]*\).*/\1/p')"
    fi
    if [ "$scenario" = "miss" ]; then
        up1="$(sed -n 's/^stats upstream_queries=//p' "$tmp/mock.log" | tail -1)"
        upstream=$((up1 - up0))
        saved=$((sent - upstream))
        result="$result upstream=$upstream saved=$saved"
    fi
    if [ "${BENCH_ALLOCS:-0}" = "1" ]; then
        allocs1="$(sed -n 's/^stats allocs=//p' "$tmp/server-$workers.log" | tail -1)"
        allocs=$((allocs1 - allocs0))
        allocs_per_query="$(awk -v a="$allocs" -v s="$sent" \
            'BEGIN { printf "%.1f", (s > 0) ? a / s : 0 }')"
        result="$result allocs=$allocs allocs_per_query=$allocs_per_query"
    fi
    if [ "${BENCH_PHASES:-0}" = "1" ]; then
        phases1="$(sed -n 's/^stats phases //p' "$tmp/server-$workers.log" | tail -1)"
        result="$result$(phases_summary "$phases0" "$phases1" "$sent")"
    fi
    peak_kib="$(awk '/^VmHWM:/ {print $2}' "/proc/$server_pid/status")"

    echo "threads=$workers idle_rss_kib=$idle_kib peak_rss_kib=$peak_kib $result"

    if [ -n "$container_name" ]; then
        docker stop --time 5 "$container_name" >/dev/null 2>&1 || true
        docker rm -f "$container_name" >/dev/null 2>&1 || true
        container_name=""
        server_pid=""
    else
        kill -TERM "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
        server_pid=""
    fi
    sleep 0.3
done
