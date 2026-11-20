# Quick start

This page gets a working resolver running in a few minutes and verifies it with
`dig`. It covers the source build and the published container image. Read
[Installation](installation.md) for support tiers and production deployment.

## Prerequisites

- Rust 1.100 or newer (`rustc --version`) for a source build, or Docker for the
  container path.
- `dig` or `drill` for verification.
- Outbound TCP/853 for the bundled minimal example, which forwards to public
  DoT resolvers. It does not demonstrate iteration from the root; see
  [Configuration](configuration.md#choosing-an-upstream-model) to switch.

Nothing needs root privileges: the examples bind loopback port 5353.

## Source build

```bash
git clone https://github.com/ChandanGhosh/dns-rs.git
cd dns-rs

# 1. Validate the example configuration.
cargo run -p dns-daemon -- checkconf -c examples/minimal.toml

# 2. Run in the foreground. Logs go to standard output.
cargo run -p dns-daemon -- run -c examples/minimal.toml
```

From a second terminal:

```bash
# Built-in local record: works even without upstream connectivity.
dig @127.0.0.1 -p 5353 localhost. A

# Recursive query through the configured DoT forwarder.
dig @127.0.0.1 -p 5353 example.com A
```

A working query returns `status: NOERROR` with an answer section. `localhost.`
is served from built-in local data, so it is the quickest check that the
listener, decoder, and local zone path are alive. `example.com` exercises the
upstream path and DNSSEC validation; a `SERVFAIL` there usually means outbound
TCP/853 is blocked, the host clock is wrong, or an upstream is broken.

Stop the resolver with `Ctrl-C` in the terminal running it.

## Published container image

The image defaults to `/etc/dns-rs/dns-rs.conf`, which listens on `0.0.0.0:53`
inside the container and allows loopback and private LAN clients. The example
below publishes it on loopback port 15353 on the host:

```bash
docker run -d --rm --name dns-rs-test \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  -p 127.0.0.1:15353:53/udp \
  -p 127.0.0.1:15353:53/tcp \
  chandanghosh/dns-rs:0.6.0

dig @127.0.0.1 -p 15353 example.com A
docker logs dns-rs-test
docker stop dns-rs-test
```

The image has a built-in exec-form healthcheck, so no shell or `dig` is needed
inside the container. Do not add `docker run --health-cmd`: Docker runs that
string through `/bin/sh`, which does not exist in the `scratch` image. See
[Container image](container.md) for Compose, Kubernetes, custom configurations,
and zone/blocklist layout.

## What to try next

- Change `verbosity` in `examples/minimal.toml` to `2` and watch one line per
  query, including cache hits and misses.
- Replace the DoT forward zone with an iterative resolver by deleting its
  `[[forward_zones]]` block, then re-run `checkconf` and `run`. Iteration needs
  outbound UDP/TCP port 53 to authoritative servers.
- Read [Configuration](configuration.md) for the full set of settings and
  [Limitations](limitations.md) for the feature boundary before deploying.
- For a persistent service, follow [Installation](installation.md#host-service-systemd).
