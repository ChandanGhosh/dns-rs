# Container image

The repository ships a multi-stage container image for local testing and for
long-running deployment (including a Raspberry Pi test node). The runtime image
contains only the `dns-rs` binary, its default configuration, and the glibc
runtime from `gcr.io/distroless/cc-debian12:nonroot`.

The build has been smoke-tested on `linux/amd64` natively and on `linux/arm64`
under QEMU. Raspberry Pi hardware validation is still pending.

The project does **not** publish images yet. The manual `Container` GitHub
Actions workflow targets Docker Hub and stays disabled unless you explicitly
enable pushing (see [Publishing](#publishing-to-docker-hub)).

## Image layout

| Item | Value |
|---|---|
| Builder | `rust:1.99-bookworm` |
| Runtime | `gcr.io/distroless/cc-debian12:nonroot` |
| User | `nonroot:nonroot` (UID/GID 65532) |
| Binary | `/usr/local/bin/dns-rs` |
| Default config | `/etc/dns-rs/dns-rs.toml` |
| State directory | `/var/lib/dns-rs` |
| Plain DNS | port 53 UDP/TCP |
| DoT / DoH | ports 853 / 443 when TLS material is configured |
| Healthcheck | `dns-rs healthcheck` (no shell or `dig` needed) |

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

The smoke script runs the image with:

- a read-only root filesystem,
- all capabilities dropped except `NET_BIND_SERVICE`,
- `no-new-privileges`,
- no writable paths except a small `/tmp` tmpfs,
- a Docker healthcheck.

If `docker build` is slow while iterating, set `SKIP_BUILD=1` after building.
Set `KEEP=1` to leave the container running for manual queries.

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

The image is built for `linux/arm64` in the publishing workflow. You can also
build it directly on a 64-bit Pi (Docker Engine and at least 2 GB of RAM
recommended):

```bash
git clone <repository> dns-rs
cd dns-rs
docker build -t dns-rs:pi .
DNS_RS_HOST_PORT=53 docker compose up -d
```

For a long-lived test node:

1. Use a 64-bit OS and a wired network connection.
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

Publishing is intentionally deferred until the local image has been verified.
When ready:

1. Create the Docker Hub repository (for example `your-user/dns-rs`).
2. Add repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The token
   should be a Docker Hub access token with write scope, not your password.
3. Run the `Container` workflow manually, set `tag` (for example `0.1.0` or
   `dev`), and enable `push`.
4. The publish job builds `linux/amd64` and `linux/arm64`, pushes
   `docker.io/<username>/dns-rs:<tag>`, and attaches an SBOM and provenance
   attestation via BuildKit.
5. Verify the result:

   ```bash
   docker buildx imagetools inspect docker.io/<username>/dns-rs:<tag>
   docker run --rm docker.io/<username>/dns-rs:<tag> --version
   ```

The workflow does not run on tag pushes, so creating a release tag will not
publish an image by accident. To build both architectures without pushing:

```bash
docker buildx build --platform linux/amd64,linux/arm64 \
  --output type=cacheonly .
```

This requires QEMU/binfmt support for the non-native architecture.

## CI gates

`.github/workflows/ci.yml` builds the image on every push and pull request,
runs the smoke test, enforces a 100 MiB image-size budget, and scans the image
with Trivy for `CRITICAL` and `HIGH` vulnerabilities (ignoring unfixed
findings). The manual `Container` workflow does not publish unless `push` is
enabled.
