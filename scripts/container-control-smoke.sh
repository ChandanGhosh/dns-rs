#!/usr/bin/env bash
# End-to-end test for the control socket inside the published image.
#
# The runtime image is `scratch`, so this uses the built-in `dns-rs control`
# client through `docker exec` and a tmpfs for the writable socket path.
#
# The generated configuration is TOML on purpose: the image default is
# `dns-rs.conf` in Unbound syntax, so this keeps end-to-end coverage of the
# non-default `.toml` path (explicit `-c` plus a matching healthcheck).
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
mkdir -p "$work/config"

cleanup() {
    docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

cat > "$work/config/dns-rs.toml" <<'EOF'
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
    --no-healthcheck \
    --volume "$work/config:/etc/dns-rs:ro" \
    "$IMAGE" -c /etc/dns-rs/dns-rs.toml run >/dev/null

# The image is `scratch`, so `docker run --health-cmd` cannot work: Docker
# always runs it through `/bin/sh`, which does not exist. Disable the built-in
# probe and run the same command through `docker exec` instead.
for _ in $(seq 1 60); do
    if [ "$(docker inspect --format '{{.State.Running}}' "$CONTAINER")" != "true" ]; then
        echo "container exited before becoming ready" >&2
        docker logs "$CONTAINER" >&2 || true
        exit 1
    fi
    if docker exec "$CONTAINER" \
        /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck \
        >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! docker exec "$CONTAINER" \
    /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck \
    >/dev/null 2>&1; then
    echo "container did not become ready in time" >&2
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

# The configuration directory is a bind mount, so a host-side edit that renames
# a new file over the old one replaces the inode and the container still sees
# the new content. An invalid edit must be rejected without disturbing the
# running configuration.
config="$work/config/dns-rs.toml"
cp "$config" "$work/original.toml"
cp "$work/original.toml" "$work/invalid.toml"
printf '\nthis is not valid TOML\n' >> "$work/invalid.toml"
mv "$work/invalid.toml" "$config"
# Pass --socket explicitly: the client also parses the configuration to find
# the socket, and the point here is to exercise the server's reload validation.
if reload="$(docker exec "$CONTAINER" /usr/local/bin/dns-rs \
    control --socket /run/dns-rs.sock reload 2>&1)"; then
    echo "reload unexpectedly accepted an invalid configuration: $reload" >&2
    exit 1
fi
echo "reload: invalid configuration rejected"
mv "$work/original.toml" "$config"

reload="$(control reload)"
if [ "$reload" != "reloaded" ]; then
    echo "unexpected reload reply: $reload" >&2
    exit 1
fi
echo "reload: ok"

# SIGHUP takes the same reload path. A process that did not install the handler
# would terminate here; one that ignored it would not log another reload.
reloads_before="$(docker logs "$CONTAINER" 2>&1 | grep -c 'configuration reloaded' || true)"
docker kill --signal HUP "$CONTAINER" >/dev/null
reloads_after="$reloads_before"
for _ in $(seq 1 20); do
    reloads_after="$(docker logs "$CONTAINER" 2>&1 | grep -c 'configuration reloaded' || true)"
    if [ "$reloads_after" -gt "$reloads_before" ]; then
        break
    fi
    sleep 0.5
done
if [ "$reloads_after" -le "$reloads_before" ]; then
    echo "SIGHUP did not reload the configuration" >&2
    docker logs "$CONTAINER" >&2 || true
    exit 1
fi
echo "SIGHUP: ok"

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
