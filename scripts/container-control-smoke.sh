#!/usr/bin/env bash
# End-to-end test for the control socket inside the published image.
#
# The runtime image is `scratch`, so this uses the built-in `dns-rs control`
# client through `docker exec` and a tmpfs for the writable socket path.
#
#   IMAGE=dns-rs:dev scripts/container-control-smoke.sh
set -euo pipefail

IMAGE="${IMAGE:-dns-rs:smoke}"
CONTAINER="${CONTAINER:-dns-rs-control-smoke}"
PLATFORM="${PLATFORM:-}"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "image $IMAGE not found; run 'make image' first" >&2
    exit 1
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/dns-rs-control-container.XXXXXX")"
chmod 700 "$work"

cleanup() {
    docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

cat > "$work/dns-rs.toml" <<'EOF'
[server]
interfaces = ["0.0.0.0"]
port = 53
verbosity = 1
num_threads = 1
do_daemonize = false
do_ip4 = true
do_ip6 = false
do_udp = true
do_tcp = true
access_control = ["127.0.0.0/8 allow", "0.0.0.0/0 refuse"]

[remote_control]
enabled = true
interfaces = ["/run/dns-rs.sock"]
EOF

platform_args=()
if [ -n "$PLATFORM" ]; then
    platform_args=(--platform "$PLATFORM")
fi

docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
docker run --detach \
    --name "$CONTAINER" \
    "${platform_args[@]}" \
    --read-only \
    --tmpfs /run:rw,noexec,nosuid,size=16m \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges=true \
    --volume "$work/dns-rs.toml:/etc/dns-rs/dns-rs.toml:ro" \
    "$IMAGE" >/dev/null

for _ in $(seq 1 60); do
    status="$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo starting)"
    case "$status" in
        healthy)
            break
            ;;
        unhealthy)
            echo "container became unhealthy" >&2
            docker logs "$CONTAINER" >&2 || true
            exit 1
            ;;
    esac
    if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
        echo "container exited before becoming healthy" >&2
        docker logs "$CONTAINER" >&2 || true
        exit 1
    fi
    sleep 1
done

if [ "$(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER")" != "healthy" ]; then
    echo "container did not become healthy in time" >&2
    docker logs "$CONTAINER" >&2 || true
    exit 1
fi

control() {
    docker exec "$CONTAINER" \
        /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml control "$@"
}

status="$(control status)"
echo "status: $status"
grep -q 'version=' <<<"$status"
grep -q 'protocol=1' <<<"$status"

stats="$(control stats)"
echo "stats: $stats"
grep -q '"cache_hits"' <<<"$stats"

prometheus="$(control stats-prometheus)"
grep -q 'dns_rs_cache_hits_total' <<<"$prometheus"
echo "prometheus: ok"

if reload="$(control reload 2>&1)"; then
    echo "reload unexpectedly succeeded: $reload" >&2
    exit 1
fi
grep -q 'not implemented' <<<"$reload"
echo "reload: rejected"

stop="$(control stop)"
if [ "$stop" != "stopping" ]; then
    echo "unexpected stop reply: $stop" >&2
    exit 1
fi
echo "stop: acknowledged"

exit_code="$(docker wait "$CONTAINER")"
if [ "$exit_code" != "0" ]; then
    echo "container exited with status $exit_code after stop" >&2
    docker logs "$CONTAINER" >&2 || true
    exit 1
fi
echo "container exited cleanly after stop"
