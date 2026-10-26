# Container image

The repository ships a multi-stage container image for local testing and for
long-running deployment (including a Raspberry Pi test node). The builder
cross-compiles a statically linked musl binary, and the runtime image is
`scratch`: it contains only the `dns-rs` binary, its default configuration, and
two empty state directories. There is no shell, libc, package manager, or
system CA bundle in the runtime image.

The image has been smoke-tested on `linux/amd64` natively and on `linux/arm/v7`
under QEMU. Raspberry Pi hardware validation is still pending.

Published images live on Docker Hub at
[`chandanghosh/dns-rs`](https://hub.docker.com/r/chandanghosh/dns-rs):

```bash
docker pull chandanghosh/dns-rs:26102026
docker run --rm chandanghosh/dns-rs:26102026 --version
```

## Image layout

| Item | Value |
|---|---|
| Builder | `rust:1.99-bookworm` |
| Runtime | `scratch` |
| Binary | `/usr/local/bin/dns-rs`, statically linked against musl |
| User | numeric UID/GID `65532:65532` (no `/etc/passwd`) |
| Default config | `/etc/dns-rs/dns-rs.toml` |
| State directory | `/var/lib/dns-rs` |
| Plain DNS | port 53 UDP/TCP |
| DoT / DoH | ports 853 / 443 when TLS material is configured |
| Healthcheck | `dns-rs healthcheck` (no shell or `dig` needed) |
| Size | about 6.3 MiB uncompressed on `amd64`, 1.7 MiB on `arm/v7` |

The image runs with no writable filesystem paths by default. If you enable
features that write state (for example the RFC 5011
`auto-trust-anchor-file`), mount a volume at `/var/lib/dns-rs`. If a feature
needs a scratch directory, mount a small tmpfs at `/tmp`.

TLS verification uses roots compiled into the binary (`webpki-roots`), so the
missing system CA store is not a problem. Name resolution for configuration
values such as `forward-host` uses the C library resolver, so Docker's
bind-mounted `/etc/resolv.conf` and `/etc/hosts` are still consulted.

The default configuration in `packaging/container.toml` listens on `0.0.0.0:53`
and allows loopback, RFC 1918, and Docker bridge clients. Replace it before
exposing the resolver to a wider network.

## Build and verify locally

```bash
docker build -t dns-rs:dev .

# Builds, starts with the hardened settings, waits for healthy, and queries
# the published socket. Uses host port 15353 so it does not collide with a
# local DNS service.
IMAGE=dns-rs:dev PORT=15353 scripts/container-smoke.sh
```

The build uses the size-optimised `dist` Cargo profile (fat LTO,
`opt-level = "z"`, `panic = "abort"`, stripped symbols). To build both
published architectures without pushing:

```bash
docker buildx build --platform linux/amd64,linux/arm/v7 \
  --output type=cacheonly .
```

A `linux/arm64` build is also supported by the `Dockerfile` for local use,
although it is not one of the published tags.

The smoke script runs the image with:

- a read-only root filesystem,
- all capabilities dropped except `NET_BIND_SERVICE`,
- `no-new-privileges`,
- no writable paths except a small `/tmp` tmpfs,
- a Docker healthcheck.

If `docker build` is slow while iterating, set `SKIP_BUILD=1` after building.
Set `KEEP=1` to leave the container running for manual queries. To smoke-test a
foreign architecture through QEMU, set `PLATFORM`, for example
`PLATFORM=linux/arm/v7 IMAGE=chandanghosh/dns-rs:26102026 scripts/container-smoke.sh`.

## Run with Docker Compose

```bash
# Listen on host port 53 for LAN clients.
docker compose up --build

# Or use a high port for a loopback-only test.
DNS_RS_BIND_ADDR=127.0.0.1 DNS_RS_HOST_PORT=5353 docker compose up --build

dig @127.0.0.1 -p 5353 example.com A
```

The compose file mounts `packaging/container.toml` read-only over the image's
default configuration. Edit that file or mount your own. The named
`dns-rs-data` volume is available for `/var/lib/dns-rs`, which is where the RFC
5011 `auto-trust-anchor-file` lives when enabled.

### Configuration and TLS material

Mount the configuration directory rather than individual files when possible:

```yaml
volumes:
    - ./config:/etc/dns-rs:ro
    - ./tls:/etc/dns-rs/tls:ro
    - dns-rs-data:/var/lib/dns-rs
```

Files must be readable by UID 65532. For DoT/DoH, enable the matching
interfaces in the configuration (for example `0.0.0.0@853` and `0.0.0.0@443`)
and set `tls_service_key` and `tls_service_pem`. The daemon selects the
listener protocol from the port, as in Unbound.

### Binding port 53 as a non-root user

The image runs as UID 65532. Binding port 53 therefore requires the
`NET_BIND_SERVICE` capability (compose adds it) or a high port published with
`-p 5353:53`. If you see `permission denied` on startup, check that the
capability was not dropped by the runtime.

## Healthcheck

The image's `HEALTHCHECK` runs:

```bash
/usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck
```

`dns-rs healthcheck` loads the configuration, picks the first plain-DNS
listener (skipping the DoT/DoH ports), maps wildcard addresses to loopback, and
asks for the built-in `localhost.` record. Options:

```bash
dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck \
  --address 127.0.0.1 --port 53 \
  --name localhost. --timeout 2000 --tcp
```

If you override the container command with a different configuration path,
override the healthcheck as well. It is a liveness/readiness probe for the
listener, not an upstream connectivity test. It requires a plain DNS listener;
for a DoT/DoH-only deployment, use a TCP or HTTPS probe that matches the
enabled service instead.

## Kubernetes

`deploy/k8s/dns-rs.yaml` contains a ConfigMap, a single-replica Deployment, and
a ClusterIP Service. It uses:

- `runAsNonRoot` and UID/GID 65532,
- `readOnlyRootFilesystem: true`,
- `allowPrivilegeEscalation: false`,
- all capabilities dropped except `NET_BIND_SERVICE`,
- `seccompProfile: RuntimeDefault`,
- exec liveness and readiness probes that run `dns-rs healthcheck`.

Set the image to your Docker Hub repository and apply:

```bash
kubectl apply -f deploy/k8s/dns-rs.yaml
```

The example Service is cluster-local. To serve LAN clients from a Pi running
k3s, either add a `hostPort: 53` to the container ports, run the pod with
`hostNetwork: true`, or use your cluster's LoadBalancer implementation. Only
run one replica when binding host port 53.

## Raspberry Pi test node

The published `linux/arm/v7` image covers 32-bit Raspberry Pi OS on Pi 2 v1.2
and later, Pi 3, Pi 4, Pi 5, and Zero 2 W. Pi 1 and Pi Zero (ARMv6) are not
supported. On 64-bit Raspberry Pi OS, either enable 32-bit emulation for the
`arm/v7` image or build an `arm64` image locally:

```bash
git clone <repository> dns-rs
cd dns-rs
docker buildx build --platform linux/arm64 -t dns-rs:pi --load .
docker compose up -d
```

To use the published image:

```bash
docker pull chandanghosh/dns-rs:26102026
DNS_RS_IMAGE=chandanghosh/dns-rs:26102026 DNS_RS_HOST_PORT=53 docker compose up -d
```

For a long-lived test node:

1. Use a wired network connection and a 32-bit or 64-bit OS with enough RAM
   (at least 512 MB for the 32-bit image).
2. Keep the root filesystem read-only in compose (the default) and mount a
   named volume at `/var/lib/dns-rs`.
3. Point the Pi's own resolver at `127.0.0.1` only after the container is
   healthy, and keep an out-of-band SSH path for recovery.
4. Enable `auto_trust_anchor_file = "/var/lib/dns-rs/root.key"` if you want
   RFC 5011 updates to persist.
5. Record baseline and load behavior with:

   ```bash
   docker stats --no-stream dns-rs
   vcgencmd measure_temp
   vcgencmd get_throttled
   ```

6. Drive real query load from another host, for example:

   ```bash
   dnsperf -s <pi-address> -d queries.txt -l 300 -c 8 -T 4
   ```

Record CPU, RSS, temperature, throttling, cache hit ratio, and any resolution
failures in the test notes. The M7 roadmap item remains open until the Pi has
run for a sustained period under real traffic.

The image does not daemonize; keep it in the foreground under Docker or
Kubernetes. If you prefer systemd without a container, run the same binary
under a systemd unit and apply the equivalent `NoNewPrivileges`,
`ProtectSystem=strict`, `PrivateTmp`, and `AmbientCapabilities=CAP_NET_BIND_SERVICE`
settings.

## Publishing to Docker Hub

Images are published manually under `chandanghosh/dns-rs`; the current tag is
`26102026` (26 October 2026). The tag contains `linux/amd64` and `linux/arm/v7`
manifests plus BuildKit SBOM and provenance attestations.

To publish from a workstation:

```bash
docker login
docker buildx build \
  --platform linux/amd64,linux/arm/v7 \
  --tag chandanghosh/dns-rs:<tag> \
  --build-arg VERSION=<tag> \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --provenance=mode=max --sbom=true \
  --push .
```

To publish through GitHub Actions instead:

1. Add repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The token
   should be a Docker Hub access token with write scope, not your password.
2. Run the `Container` workflow manually, set `tag` (for example `26102026` or
   `dev`), and enable `push`.
3. The publish job builds `linux/amd64` and `linux/arm/v7`, pushes
   `docker.io/<username>/dns-rs:<tag>`, and attaches an SBOM and provenance
   attestation via BuildKit.
4. Verify the result:

   ```bash
   docker buildx imagetools inspect docker.io/<username>/dns-rs:<tag>
   docker run --rm --platform linux/arm/v7 \
     docker.io/<username>/dns-rs:<tag> --version
   ```

The workflow does not run on tag pushes, so creating a release tag will not
publish an image by accident. Cross-compilation happens on the native build
platform; QEMU is only needed to run the foreign `arm/v7` image for smoke
testing.

## CI gates

`.github/workflows/ci.yml` builds the image on every push and pull request,
runs the smoke test, enforces a 10 MiB image-size budget, and scans the image
with Trivy for `CRITICAL` and `HIGH` vulnerabilities (ignoring unfixed
findings). The manual `Container` workflow does not publish unless `push` is
enabled.
