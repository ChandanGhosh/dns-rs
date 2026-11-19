#!/usr/bin/env bash
# Build the container image and verify it locally with the same hardening that
# the compose and Kubernetes examples use.
#
#   scripts/container-smoke.sh
#   IMAGE=dns-rs:test PORT=5353 scripts/container-smoke.sh
#   KEEP=1 scripts/container-smoke.sh        # leave the container running
#   PLATFORM=linux/arm64 IMAGE=dns-rs:pi scripts/container-smoke.sh
#
# The script requires Docker and, for the DNS query step, dig.
set -euo pipefail

IMAGE="${IMAGE:-dns-rs:smoke}"
CONTAINER="${CONTAINER:-dns-rs-smoke}"
PORT="${PORT:-5353}"
KEEP="${KEEP:-0}"
# Optional runtime platform, for example linux/arm64 when testing a foreign
# image through QEMU.
PLATFORM="${PLATFORM:-}"

cleanup() {
    if [ "$KEEP" != "1" ]; then
        docker rm --force "$CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [ "${SKIP_BUILD:-0}" != "1" ]; then
    docker build --tag "$IMAGE" .
fi

docker rm --force "$CONTAINER" >/dev/null 2>&1 || true

platform_args=()
if [ -n "$PLATFORM" ]; then
    platform_args=(--platform "$PLATFORM")
fi

docker run --detach \
    --name "$CONTAINER" \
    "${platform_args[@]}" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,size=16m \
    --cap-drop ALL \
    --cap-add NET_BIND_SERVICE \
    --security-opt no-new-privileges=true \
    --publish "127.0.0.1:${PORT}:53/udp" \
    --publish "127.0.0.1:${PORT}:53/tcp" \
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

# Exercise the healthcheck command directly, then query the published socket.
docker exec "$CONTAINER" \
    /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf healthcheck

if command -v dig >/dev/null 2>&1; then
    answer="$(dig +time=2 +tries=1 @127.0.0.1 -p "$PORT" localhost. A +short)"
    if [ "$answer" != "127.0.0.1" ]; then
        echo "unexpected dig answer: ${answer:-<empty>}" >&2
        exit 1
    fi
    echo "dig answer: $answer"
fi

size="$(docker image inspect --format '{{.Size}}' "$IMAGE")"
echo "image: $IMAGE"
echo "size: $((size / 1024 / 1024)) MiB"
echo "health: $(docker inspect --format '{{.State.Health.Status}}' "$CONTAINER")"
echo "container: $CONTAINER"
