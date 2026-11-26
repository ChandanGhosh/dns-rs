#!/usr/bin/env bash
# End-to-end test for the local Unix control socket.
#
# Starts a real daemon with `control-enable: yes`, then drives it through the
# built-in `dns-rs control` client. Verifies the socket mode, every command, the
# unsupported `reload` reply, graceful `stop`, and socket removal.
#
#   scripts/control-smoke.sh
#   BINARY=target/release/dns-rs SKIP_BUILD=1 scripts/control-smoke.sh
#   PORT=25353 scripts/control-smoke.sh
set -euo pipefail

BINARY="${BINARY:-target/debug/dns-rs}"
SKIP_BUILD="${SKIP_BUILD:-0}"
PORT="${PORT:-15353}"

if [ "$SKIP_BUILD" != "1" ]; then
    cargo build --package dns-daemon --bin dns-rs
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/dns-rs-control.XXXXXX")"
chmod 700 "$work"
pid=""

cleanup() {
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$work"
}
trap cleanup EXIT

cat > "$work/dns-rs.conf" <<EOF
server:
    interface: 127.0.0.1@${PORT}
    port: ${PORT}
    num-threads: 1
    do-ip6: no
    do-daemonize: no
    verbosity: 0
    access-control: 127.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse
remote-control:
    control-enable: yes
    control-interface: $work/control.sock
EOF

"$BINARY" -c "$work/dns-rs.conf" run &
pid=$!

for _ in $(seq 1 100); do
    [ -S "$work/control.sock" ] && break
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "daemon exited before creating the control socket" >&2
        wait "$pid" 2>/dev/null || true
        exit 1
    fi
    sleep 0.05
done
if [ ! -S "$work/control.sock" ]; then
    echo "control socket was not created" >&2
    exit 1
fi

mode="$(stat -c '%a' "$work/control.sock")"
if [ "$mode" != "600" ]; then
    echo "control socket mode is $mode, expected 600" >&2
    exit 1
fi
echo "socket mode: $mode"

control() {
    "$BINARY" -c "$work/dns-rs.conf" control "$@"
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

reload="$(control reload)"
if [ "$reload" != "reloaded" ]; then
    echo "unexpected reload reply: $reload" >&2
    exit 1
fi
echo "reload: ok"

# An invalid edit must be rejected without disturbing the running config. Pass
# the socket explicitly because the client can no longer parse the edited file.
cp "$work/dns-rs.conf" "$work/valid.conf"
printf '\nthis is not valid unbound.conf\n' >>"$work/dns-rs.conf"
if reload="$("$BINARY" -c "$work/dns-rs.conf" control \
    --socket "$work/control.sock" reload 2>&1)"; then
    echo "reload unexpectedly accepted an invalid configuration: $reload" >&2
    exit 1
fi
echo "reload: invalid configuration rejected"
cp "$work/valid.conf" "$work/dns-rs.conf"

reload="$(control reload)"
if [ "$reload" != "reloaded" ]; then
    echo "unexpected reload reply after restore: $reload" >&2
    exit 1
fi
echo "reload: restored configuration accepted"

stop="$(control stop)"
if [ "$stop" != "stopping" ]; then
    echo "unexpected stop reply: $stop" >&2
    exit 1
fi
echo "stop: acknowledged"

wait "$pid"
pid=""
if [ -e "$work/control.sock" ]; then
    echo "control socket was not removed on shutdown" >&2
    exit 1
fi
echo "socket removed on shutdown"
