# Container image

The repository ships a multi-stage container image for local testing and for
long-running deployment (including a Raspberry Pi test node). The builder
cross-compiles a statically linked musl binary, and the runtime image is
`scratch`: it contains only the `dns-rs` binary, its default configuration, and
two empty state directories. There is no shell, libc, package manager, or
system CA bundle in the runtime image.

The image has been smoke-tested on `linux/amd64` natively and on `linux/arm64`
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
| Size | about 2.0 MiB compressed (4.3 MiB on disk) on `amd64`; about 2.0 MiB compressed (3.4 MiB on disk) on `arm64` |

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

## Access control

`access_control` decides which client addresses may query the resolver. Rules
are evaluated in order and the first match wins; a client that matches no rule
is refused. A refused client receives `REFUSED`, not a resolution failure.

The default configuration allows loopback, RFC 1918, and Docker bridge clients
only:

```toml
access_control = [
    "127.0.0.0/8 allow",
    "10.0.0.0/8 allow",
    "172.16.0.0/12 allow",
    "192.168.0.0/16 allow",
    "0.0.0.0/0 refuse",
]
```

Use canonical CIDRs:

| Purpose | IPv4 | IPv6 |
|---|---|---|
| Loopback | `127.0.0.0/8` | `::1/128` |
| Private LAN | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | `fc00::/7` (unique-local; `fd00::/8` in home networks), `fe80::/10` (link-local) |
| Default deny | `0.0.0.0/0 refuse` | `::/0 refuse` |

Common mistakes:

- `fc80::/7` is equivalent to `fc00::/7` but non-canonical; write
  `fc00::/7`.
- `172::/7` is not the IPv4 `172.16.0.0/12` private range. It is an IPv6
  prefix that normalizes to `::/7`; use `172.16.0.0/12` for IPv4.

IPv6 entries have no effect while `do_ip6 = false`, which is the container
default. `do_ip4`/`do_ip6` apply to outgoing queries as well: with `do_ip6 =
false` the resolver also skips IPv6 root hints, glue, and forwarder addresses
instead of timing out on them. To serve IPv6 clients, set `do_ip6 = true`, add
an IPv6 listener (for example `interfaces = ["0.0.0.0", "::"]`), and include the
IPv6 allow rules before `::/0 refuse`. With an Unbound-style `.conf` file, use
one `access-control: <cidr> allow` line per entry instead of the TOML array.

### Troubleshooting

- A client gets `REFUSED`: its source address does not match an `allow` rule.
  Check whether the client is using IPv4 or IPv6 and whether an earlier rule
  matches it first.
- `localhost.` resolves and cached names work, but fresh external names return
  `SERVFAIL`: access control is not the cause. The upstream/iterative path is
  failing, for example because the network intercepts port 53. Fix the network
  or add an encrypted forward zone (DoT/DoH); `examples/full.toml` contains
  working syntax.

If you want to keep local iteration but survive a network that blocks or
rewrites port 53, do not make the forwarder the primary path. Use
`forward_fallback = true` instead, which only asks the forwarders after
iteration fails to reach authoritative servers:

```toml
[[forward_zones]]
name = "."
forward_fallback = true
tls_upstream = true
forward_addrs = [
    "1.1.1.1@853#cloudflare-dns.com",
    "1.0.0.1@853#cloudflare-dns.com",
]
```

`forward_first = true` is the opposite direction: forward first, then iterate.
The two are mutually exclusive, and a fallback is never taken for an
authoritative `NXDOMAIN`/NODATA answer or a DNSSEC validation failure, so a
forwarder cannot override signed data. A client-facing fallback logs
`iteration failed; falling back to forwarders` with the query name and the
original error; internal validator and nameserver-address lookups log the same
message at debug level.

### Which path answered the query?

dns-rs randomises the case of the query name on iterative queries (DNS 0x20,
the equivalent of Unbound's `use-caps-for-id`) so a spoofed reply that guessed
the name cannot match. Authoritative servers echo the case of the question, so
answers learned by iteration keep that spelling:

```console
$ dig @127.0.0.1 kernel.org A
;; ANSWER SECTION:
keRnel.orG.		300	IN	A	172.105.4.254
```

This is correct on the wire: DNS names are compared case-insensitively
(RFC 4343), and the resolver does not rewrite the spelling. The cached RRset
keeps the case it was first learned with until its TTL expires, so repeated
queries return the same mixed-case name — and different names will show
different capitalisation.

Casing does not multiply cache entries: the message cache, the RRset cache and
the in-flight registry all key on the lowercased name (`name|type`), so the
randomised spelling changes bytes in place, not the number of keys or their
size. A mixed-case entry and a lowercase lookup of the same name share one
cache slot.

Encrypted forwarders (DoT and DoH) skip 0x20 and DNS cookies, because the TLS
connection already authenticates the server. Their answers therefore arrive
all-lowercase. Plain-UDP forwarders still use the iterator's transport and can
show mixed case, and a server that is learned not to preserve case is not
randomised against again.

| Answer owner name | How the cached data was learned |
|---|---|
| Mixed case (`keRnel.orG.`) | local iteration |
| All lowercase (`kernel.org.`) | DoT/DoH forwarding, or an upstream that does not preserve case |

The casing describes how the cached entry was learned, not necessarily how the
current query was routed. To be certain, check the startup log line
`using configured forward zones ...` and the per-query
`iteration failed; falling back to forwarders` warning.

### Verifying that the network allows iteration

A gateway that filters DNS redirects every query sent to port 53, whatever its
destination, so a rewritten path can look like a resolver bug. Two probes
distinguish them:

```bash
# A root server answers authoritatively and never recurses.
# Expect "qr aa", 13 NS records and NO "ra" flag.
dig +norecurse @198.41.0.4 . NS

# 203.0.113.0/24 (TEST-NET-3) is reserved and unroutable.
# Expect a timeout. An answer means port 53 is being intercepted.
dig +norecurse @203.0.113.53 . NS
dig +tcp +norecurse @203.0.113.53 . NS
```

A router or gateway that filters content or blocks ads redirects DNS to itself
so it can inspect the answers, and some deployments add an explicit port-53
DNAT rule. Disable DNS/content filtering for this host, or move it to a segment
that is not redirected, and remove any such rule. While the redirect is active,
dns-rs receives recursive, unsigned answers from a root server, rejects them,
and returns `SERVFAIL` for fresh names while cached names and `localhost.` keep
working.

The container healthcheck is a listener probe only: it asks for `localhost.`,
so a container can be `healthy` while upstream resolution is broken.

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
docker buildx build --platform linux/amd64,linux/arm64 \
  --output type=cacheonly .
```

The smoke script runs the image with:

- a read-only root filesystem,
- all capabilities dropped except `NET_BIND_SERVICE`,
- `no-new-privileges`,
- no writable paths except a small `/tmp` tmpfs,
- a Docker healthcheck.

If `docker build` is slow while iterating, set `SKIP_BUILD=1` after building.
Set `KEEP=1` to leave the container running for manual queries. To smoke-test a
foreign architecture through QEMU, set `PLATFORM`, for example
`PLATFORM=linux/arm64 IMAGE=chandanghosh/dns-rs:26102026 scripts/container-smoke.sh`.

## Run manually with `docker run`

Because the image is `scratch`, it has no shell. Use `docker logs`,
`docker inspect`, and `docker exec ... /usr/local/bin/dns-rs` for diagnostics;
`docker exec ... sh` will not work. The optional `packaging/container.toml`
mount below assumes the repository root; omit it to use the image's built-in
configuration.

### Quick loopback test

Start the resolver in the foreground on a high port, then query it from another
terminal:

```bash
docker run --rm --name dns-rs-test \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  -p 127.0.0.1:15353:53/udp \
  -p 127.0.0.1:15353:53/tcp \
  chandanghosh/dns-rs:26102026
```

```bash
dig @127.0.0.1 -p 15353 example.com A
dig @127.0.0.1 -p 15353 localhost. A
```

Press `Ctrl+C` (or run `docker stop dns-rs-test` from another terminal) to stop
the container.

### Run in the background on port 53

This is the hardened, production-style invocation used by the Compose example:

```bash
docker run -d --name dns-rs \
  --restart unless-stopped \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  -p 53:53/udp \
  -p 53:53/tcp \
  -v "$PWD/packaging/container.toml:/etc/dns-rs/dns-rs.toml:ro" \
  -v dns-rs-data:/var/lib/dns-rs \
  chandanghosh/dns-rs:26102026
```

Operate it with:

```bash
# Status, logs, and health
docker ps --filter name=dns-rs
docker logs -f dns-rs
docker inspect --format '{{.State.Health.Status}}' dns-rs

# Run the liveness probe by hand
docker exec dns-rs \
  /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck

# Query it
dig @127.0.0.1 example.com A

# Stop and remove it
docker stop dns-rs
docker rm dns-rs
```

To use a different configuration or provide DoT/DoH certificates, add these
flags to the `docker run` command and mount a directory containing
`dns-rs.toml` and the TLS files instead of the single default file:

```bash
-v "$PWD/config:/etc/dns-rs:ro" \
-v "$PWD/tls:/etc/dns-rs/tls:ro" \
```

Files must be readable by UID 65532.

### Binding a privileged port

The image runs as UID 65532. Keep `--cap-add NET_BIND_SERVICE` so it can bind
port 53 inside the container, or publish a high port with `-p 15353:53`. The host
side of the mapping may bind port 53 without extra container capabilities
because Docker performs the publish as root.

If the host already uses port 53 (for example `systemd-resolved` on
`127.0.0.53:53`), use the loopback high-port command instead or stop the local
stub resolver first. Check with `ss -lntup '( sport = :53 )'`.

## Run with Docker Compose

The compose file (`docker-compose.yml`) pulls the published image from Docker
Hub, mounts `packaging/container.toml`, persists `/var/lib/dns-rs` in the
`dns-rs-data` volume, and applies the same hardening as the manual `docker run`
examples. It does not build the image locally.

### Start with the published image

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs -f resolver
```

To pin a different tag or use a locally built image, set `DNS_RS_IMAGE`:

```bash
DNS_RS_IMAGE=chandanghosh/dns-rs@sha256:<digest> docker compose up -d
DNS_RS_IMAGE=dns-rs:local docker compose up -d
```

### Loopback-only test on a high port

```bash
DNS_RS_BIND_ADDR=127.0.0.1 DNS_RS_HOST_PORT=15353 \
  docker compose up -d

dig @127.0.0.1 -p 15353 example.com A
```

### Common operations

```bash
# Follow logs
docker compose logs -f resolver

# Health status and an explicit probe
docker compose ps
docker compose exec resolver \
  /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml healthcheck

# Restart after editing packaging/container.toml
docker compose restart resolver

# Stop, then remove the container and network
docker compose down

# Also delete the persisted RFC 5011 state volume
docker compose down -v
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

The published `linux/arm64` image targets Raspberry Pi 4, Pi 400, CM4, Pi 5,
and CM5 running 64-bit Raspberry Pi OS (or another 64-bit ARM Linux). Pi 1,
Pi 2, Pi 3, and Pi Zero are not supported by the published tags.

```bash
docker pull chandanghosh/dns-rs:26102026
DNS_RS_HOST_PORT=53 docker compose up -d
```

For a long-lived test node:

1. Use a 64-bit OS on a Pi 4 or later, with a wired network connection.
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

If the Pi sits behind a gateway that intercepts port 53, pure iteration fails
for uncached names while cached ones still resolve, and the container
healthcheck keeps reporting `healthy`. Add a DoT forward zone with
`forward_fallback = true` (see [Troubleshooting](#troubleshooting)) rather than
replacing iteration with forwarding. Each client-facing fallback appears in
`docker logs` as `iteration failed; falling back to forwarders`.

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
`26102026` (26 October 2026). The tag contains `linux/amd64` and `linux/arm64`
manifests plus BuildKit SBOM and provenance attestations.

Tags are date-based (`DDMMYYYY`) and mutable: the current day's tag is rebuilt
and pushed in place when the source changes, so `docker pull` picks up the
latest build for that date. There are no semantic-version tags and no
per-commit tags, so record the manifest digest from `imagetools inspect` when
you need an immutable reference:

```bash
TAG=26102026
docker buildx imagetools inspect "chandanghosh/dns-rs:$TAG" --format '{{json .Manifest}}'
docker pull "chandanghosh/dns-rs@sha256:<digest>"
```

To publish from a workstation:

```bash
TAG=26102026
docker login
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag "chandanghosh/dns-rs:$TAG" \
  --build-arg VERSION="$TAG" \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg SOURCE_URL="$(git remote get-url origin)" \
  --provenance=mode=max --sbom=true \
  --push .
```

To publish through GitHub Actions instead:

1. Add repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The token
   should be a Docker Hub access token with write scope, not your password.
2. Run the `Container` workflow manually, set `tag` (for example `26102026` or
   `dev`), and enable `push`.
3. The publish job builds `linux/amd64` and `linux/arm64`, pushes
   `docker.io/<username>/dns-rs:<tag>`, and attaches an SBOM and provenance
   attestation via BuildKit.
4. Verify the result:

   ```bash
   docker buildx imagetools inspect docker.io/<username>/dns-rs:<tag>
   docker run --rm --platform linux/arm64 \
     docker.io/<username>/dns-rs:<tag> --version
   ```

The workflow does not run on tag pushes, so creating a release tag will not
publish an image by accident. Cross-compilation happens on the native build
platform; QEMU is only needed to run the foreign `arm64` image for smoke
testing.

## CI gates

`.github/workflows/ci.yml` builds the image on every push and pull request,
runs the smoke test, enforces a 10 MiB image-size budget, and scans the image
with Trivy for `CRITICAL` and `HIGH` vulnerabilities (ignoring unfixed
findings). The manual `Container` workflow does not publish unless `push` is
enabled.
