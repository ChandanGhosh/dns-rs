#!/bin/bash
# Loopback benchmark for the cache-hit path. Builds the release binary and a
# standalone load generator, then reports latency percentiles, throughput, and
# RSS for 1, 2, and 4 worker threads.
#
# Usage: scripts/bench-loopback.sh [THREADS...]
#   THREADS defaults to "1 2 4".
#
# Environment overrides:
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
#   SKIP_BUILD=1       use an existing host binary (host mode only)
#
# The resolver serves a stub zone backed by a local mock authority. Both the
# name set and the TTLs are fixed, so every measured query is a message-cache
# hit as long as BENCH_NAMES fits in the cache. Results depend on the host;
# run on an otherwise idle machine for comparable numbers.
#
# A miss-heavy run that exercises the upstream path instead:
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

# Capacity of the message cache (dns-server MESSAGE_CACHE_ENTRIES). Above it
# the working set no longer fits and most queries go upstream.
cache_entries=8192
if [ "$names" -gt "$cache_entries" ]; then
    cache_mode="thrash"
    echo "warning: BENCH_NAMES=$names exceeds the $cache_entries-entry message cache;" \
        "this run measures upstream misses, not cache hits" >&2
else
    cache_mode="fit"
fi

if [ -n "$server_image" ]; then
    if ! command -v docker >/dev/null 2>&1; then
        echo "BENCH_SERVER_IMAGE is set but docker is not available" >&2
        exit 1
    fi
elif [ -z "${BENCH_BINARY:-}" ] && [ "${SKIP_BUILD:-0}" != "1" ]; then
    cargo build --release -p dns-daemon
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

"$tmp/dns-bench" serve "127.0.0.1:$mock_port" >"$tmp/mock.log" 2>&1 &
mock_pid=$!
sleep 0.3
if ! kill -0 "$mock_pid" 2>/dev/null; then
    echo "mock authority failed to bind 127.0.0.1:$mock_port" >&2
    cat "$tmp/mock.log" >&2
    exit 1
fi

printf 'names=%s cache=%s concurrency=%s warmup=%ss duration=%ss server_cpus=%s client_cpus=%s server=%s\n' \
    "$names" "$cache_mode" "$concurrency" "$warmup" "$duration" "${server_cpus:-any}" \
    "${client_cpus:-any}" "${server_image:-host}"

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
    result="$("${pin_client[@]}" "$tmp/dns-bench" load "127.0.0.1:$port" "$names" \
        "$zone" "$concurrency" "$warmup" "$duration")"
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
