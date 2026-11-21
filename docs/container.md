# Container image

The repository ships a multi-stage container image for local testing and for
long-running deployment (including a Raspberry Pi test node). The builder
cross-compiles a statically linked musl binary, and the runtime image is
`scratch`: it contains only the `dns-rs` binary, its default configuration, and
empty `/var/lib/dns-rs` and `/var/cache/dns-rs` directories. There is no shell,
libc, package manager, or system CA bundle in the runtime image.

The image has been smoke-tested on `linux/amd64` natively and on `linux/arm64`
under QEMU. Raspberry Pi hardware validation is still pending.

## Published images

Published images live on Docker Hub at
[`chandanghosh/dns-rs`](https://hub.docker.com/r/chandanghosh/dns-rs):

```bash
docker pull chandanghosh/dns-rs:0.6.0
docker run --rm chandanghosh/dns-rs:0.6.0 --version
```

| Tag | Stable? | Meaning |
|---|---|---|
| `X.Y.Z` | Immutable | Release image, for example `0.6.0` |
| `latest` | Mutable | Repointed to the newest release |
| `DDMMYYYY` (UTC) | Mutable | Edge build from `main`; rebuilt when `main` changes |
| Digest | Immutable | `chandanghosh/dns-rs@sha256:...`, the strongest pin |

Production deployments should pin a release tag or digest. The maintainer build
and publish workflow is documented in
[Container publishing](container-publishing.md).

## Image layout

| Item | Value |
|---|---|
| Builder | `rust:1.100-bookworm` |
| Runtime | `scratch` |
| Binary | `/usr/local/bin/dns-rs`, statically linked against musl |
| User | numeric UID/GID `65532:65532` (no `/etc/passwd`) |
| Default config | `/etc/dns-rs/dns-rs.conf` |
| State directory | `/var/lib/dns-rs` (RFC 5011 anchor file when enabled) |
| Reserved directory | `/var/cache/dns-rs` (currently unused by the daemon) |
| Plain DNS | port 53 UDP/TCP |
| DoT / DoH | ports 853 / 443 when TLS material is configured |

The image has no `/etc/passwd` or `/etc/group`, so the `username` privilege-drop
option cannot resolve an account inside the container. Run the image as its
numeric `USER` (`65532`) instead; `username` is intended for host installs that
start the daemon as root.
| Healthcheck | `dns-rs healthcheck` (no shell or `dig` needed) |
| Size | measured 2026-11-20 with `docker image inspect`: about 9.4 MB (9.0 MiB) on disk for `amd64` and 8.0 MB (7.6 MiB) for `arm64`; compressed transfer was about 3.0 MB and 2.8 MB. CI enforces a 10 MiB uncompressed limit; measure your own image rather than treating these figures as fixed. |

The `-c` file name selects the configuration parser: names ending in `.toml`
use native TOML, and every other name uses the Unbound-compatible syntax. Both
formats can express zones and blocklists; see
[Configuration files, zones, and blocklists](#configuration-files-zones-and-blocklists)
before deploying a custom file.

The compose and smoke-test examples below use a read-only root filesystem. The
image itself contains writable `/var/lib/dns-rs` and `/var/cache/dns-rs`
directories, but only mount persistent storage for state you need. For RFC 5011
`auto-trust-anchor-file`, mount a volume at `/var/lib/dns-rs`; for a scratch
directory, mount a small tmpfs at `/tmp`.

The optional control socket needs both configuration and a writable directory:
enable `remote-control` and mount a tmpfs that contains its path. Neither change
alone is enough. For example, mount a tmpfs and point `control-interface` at it:
`--tmpfs /run:rw,noexec,nosuid,size=16m` with
`control-interface: /run/dns-rs.sock`. The socket is mode `0600` and is owned
by the container user (`65532`), so use `docker exec` (which runs as that same
UID by default) for control requests:

```bash
docker exec dns-rs /usr/local/bin/dns-rs \
    -c /etc/dns-rs/dns-rs.conf control status

# Re-read the configuration and flush the caches without a restart.
docker exec dns-rs /usr/local/bin/dns-rs \
    -c /etc/dns-rs/dns-rs.conf control reload

# Equivalent: SIGHUP to the daemon, which is the container's PID 1.
docker kill -s HUP dns-rs
```

Counter commands, the metric names, and Prometheus scraping are covered in
[Statistics and monitoring](#statistics-and-monitoring).

A reload replaces the query pipeline atomically: in-flight queries finish on
the old pipeline, and a file that fails to parse or validate leaves the running
configuration untouched. Interfaces, ports, TLS certificate/key paths, the
thread count, socket buffer sizes, control socket paths, and `verbosity` are
fixed when the listeners are bound. A change to one of them is logged as
requiring a restart; `docker compose restart resolver` (or `docker restart
dns-rs`) applies it.

When reloading, mount the configuration directory rather than a single file.
Editors that save by renaming replace the host inode, and a single-file bind
mount keeps pointing at the old inode, so the daemon would re-read the old
content. The compose example mounts `packaging/config`, which contains
`dns-rs.conf`, as a directory; do the same for your own configuration.

`make control-container` builds the image and runs this end-to-end, including
`reload` and `stop`. The socket path must be on a writable mount; a read-only
root filesystem with only `/tmp` writable cannot create `/run/dns-rs.sock`.

TLS verification uses roots compiled into the binary (`webpki-roots`), so the
missing system CA store is not a problem. Name resolution for configuration
values such as `forward-host` uses the C library resolver, so Docker's
bind-mounted `/etc/resolv.conf` and `/etc/hosts` are still consulted.

The default configuration in `packaging/config/dns-rs.conf` listens on
`0.0.0.0:53` and allows loopback, RFC 1918, and Docker bridge clients. Replace
it before exposing the resolver to a wider network.

## Access control

`access-control` (`access_control` in TOML) decides which client addresses may
query the resolver. The most specific matching netblock wins regardless of
statement order; later rules win equal-prefix ties. A client that matches no
rule is refused. A refused client receives `REFUSED`, not a resolution failure.

The default configuration allows loopback, RFC 1918, and Docker bridge clients
only:

```conf
access-control: 127.0.0.0/8 allow
access-control: 10.0.0.0/8 allow
access-control: 172.16.0.0/12 allow
access-control: 192.168.0.0/16 allow
access-control: 0.0.0.0/0 refuse
```

In TOML, put the same `"<cidr> <action>"` strings in the `access_control`
array under `[server]`.

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

IPv6 entries have no effect while `do-ip6: no`, which is the container
default. `do-ip4`/`do-ip6` apply to outgoing queries as well: with IPv6
disabled the resolver also skips IPv6 root hints, glue, and forwarder addresses
instead of timing out on them. To serve IPv6 clients, set `do-ip6: yes`, add an
IPv6 listener (for example `interface: ::`), and include the IPv6 allow rules.
A broad `::/0 refuse` does not override a more specific allow. In TOML the
equivalents are `do_ip6 = true` and `interfaces = ["0.0.0.0", "::"]`.

### Troubleshooting

- A client gets `REFUSED`: its source address does not match an `allow` rule.
  Check whether the client is using IPv4 or IPv6 and whether a more specific
  rule matches it. Statement order only breaks equal-prefix ties.
- `localhost.` resolves and cached names work, but fresh external names return
  `SERVFAIL`: access control is not the cause. The upstream/iterative path is
  failing, for example because the network intercepts port 53. Fix the network
  or add an encrypted forward zone (DoT/DoH); `examples/full.toml` contains
  working syntax.

- One domain returns `SERVFAIL` with an EDE such as `DNSSEC Bogus` while other
  names resolve: that domain's upstream data is failing validation. If the
  domain is legitimately unsigned or its operator's DNSSEC is broken, exclude
  just that subtree instead of disabling validation globally:

  ```toml
  [server]
  domain_insecure = ["broken.example"]
  ```

  The domain and every name below it are then treated as insecure. In
  `unbound.conf`, use `domain-insecure: "broken.example"`. This is a static
  negative trust anchor (RFC 7646) and is never created automatically. Prefer
  it over `val-permissive-mode` (TOML: `val_permissive_mode`), which applies to
  every domain.

If you want to keep local iteration but survive a network that blocks or
rewrites port 53, do not make the forwarder the primary path. Use
`forward-fallback: yes` instead, which only asks the forwarders after
iteration fails to reach authoritative servers:

```conf
forward-zone:
    name: "."
    forward-fallback: yes
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
```

In TOML, the equivalent keys are `forward_fallback = true`,
`tls_upstream = true`, and a `forward_addrs` array.

`forward-first: yes` is the opposite direction: forward first, then iterate.
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

## Configuration files, zones, and blocklists

The daemon loads one configuration file, chosen with `-c`. The file name
selects the parser:

| File name | Parser | Includes |
|---|---|---|
| Ends in `.toml` (case-insensitive) | Native TOML | Not supported |
| Anything else (`unbound.conf`, `dns-rs.conf`, no extension) | Unbound-compatible syntax | `include:` and `include-toplevel:` |

The image default is `/etc/dns-rs/dns-rs.conf`, an Unbound-syntax file, and
the image command, healthcheck, and Compose example all point at it. That
default exists because `include:` lets zones and blocklists live in separate
files. A TOML file must keep the `.toml` suffix; renaming it to `.conf` makes
the daemon parse it as Unbound syntax, which fails on TOML constructs. Never
mix the two syntaxes in one file. Files pulled in by `include:` are always
parsed as Unbound syntax, whatever their extension, so give generated
fragments a `.conf` name.

Choose one format per deployment:

| Use case | Recommended format |
|---|---|
| Default container configuration and split zones/blocklists | Unbound `.conf` |
| Hand-maintained configuration, typed values, tooling | TOML |
| Reusing an existing `unbound.conf` or its supported subset | Unbound `.conf` |
| Generated blocklists updated as independent files | Unbound `.conf` with `include:` |
| A generated blocklist emitted as one complete file | Either; TOML works without includes |

The same objects in each format:

| Object | TOML | `unbound.conf` |
|---|---|---|
| Local zone | `[[local_zones]]` with `name`, `type`, `data` | `local-zone:` plus repeated `local-data:` |
| Blocklist entry | `[[local_zones]]` with `type = "always-nxdomain"` | `local-zone: "name" always_nxdomain` |
| Authority zone | `[[auth_zones]]` with `zonefile` | `auth-zone:` block with `zonefile:` |
| Split generated files | Not supported | `include:` / `include-toplevel:` |

### Zones and blocklists in TOML

TOML lists zones as arrays of tables. Zone names must be fully qualified (end
with `.`), and `type` uses kebab-case; the underscore spelling from
`unbound.conf` is rejected. `data` holds inline zone-file records, not file
paths.

```toml
# Root-level keys go before the first [table] header.
local_data = [
    "router.home. 3600 IN A 192.168.1.1",
]

[server]
interfaces = ["0.0.0.0@53"]
access_control = [
    "127.0.0.0/8 allow",
    "10.0.0.0/8 allow",
    "0.0.0.0/0 refuse",
]

# Static local zone: records below, NXDOMAIN for other names in the zone.
[[local_zones]]
name = "internal.example."
type = "static"
data = [
    "internal.example. 300 IN A 192.0.2.10",
    "host.internal.example. 300 IN A 192.0.2.20",
]

# Redirect every name in the zone to the apex address.
[[local_zones]]
name = "tracker.example."
type = "redirect"
data = ["tracker.example. 300 IN A 0.0.0.0"]

# One blocklist entry. `data` is optional and defaults to [].
[[local_zones]]
name = "ads.example."
type = "always-nxdomain"
```

Common `type` values: `static`, `redirect`, `transparent`, `typetransparent`,
`refuse`, `deny`, `always-nxdomain`, `always-nodata`, `always-null`,
`always-refuse`, `always-deny`, `block-a`, `block-aaaa`, `block-a-wdata`,
`block-aaaa-wdata`, `inform-deny`, `inform-redirect`, `nodefault`.

Key differences from `unbound.conf`:

- Zone names need the trailing dot. TOML values are used as written; only the
  Unbound parser appends the root label.
- Policies use hyphens (`always-nxdomain`), not underscores
  (`always_nxdomain`).
- `local_data` is a root-level array and must appear before the first table
  header. After `[server]`, TOML treats it as a server field and startup fails.
- There is no `include`. Every zone and blocklist entry must be in the same
  file. Generate the TOML file as a whole, or use `.conf` when the blocklist is
  updated by dropping in separate files.

Authority zones use `[[auth_zones]]` and load a real zone file. Only zone-file
loading is implemented (no AXFR or URL fetch). The path is resolved inside the
container, so make it absolute and mount the directory:

```toml
[[auth_zones]]
name = "auth.example."
zonefile = "/etc/dns-rs/zones/auth.example.zone"
for_downstream = true
for_upstream = false
```

### Zones and blocklists in `unbound.conf`

Use `local-zone:` and repeated `local-data:` lines. Relative zone names get a
trailing dot automatically, but writing one explicitly works in both formats.

```conf
server:
    interface: 0.0.0.0@53
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 0.0.0.0/0 refuse

    local-zone: "internal.example." static
    local-data: "internal.example. 300 IN A 192.0.2.10"
    local-data: "host.internal.example. 300 IN A 192.0.2.20"

    local-zone: "tracker.example." redirect
    local-data: "tracker.example. 300 IN A 0.0.0.0"

    # Generated blocklist kept in a separate file.
    include: "blocklist.conf"

auth-zone:
    name: "auth.example."
    zonefile: "/etc/dns-rs/zones/auth.example.zone"
    for-downstream: yes
    for-upstream: no
```

`blocklist.conf` contains only policy lines:

```conf
local-zone: "ads.example" always_nxdomain
local-zone: "metrics.example" always_nxdomain
```

- `include:` keeps the active `server:` block, so a fragment with bare
  `local-zone:` lines belongs inside `server:`. Use `include-toplevel:` for
  complete clauses such as `auth-zone:`, `forward-zone:`, or `view:`.
- Relative include patterns are resolved against the including file's directory
  first, then the working directory (`/etc/dns-rs` in the image). Glob matches
  are sorted for deterministic order.
- Duplicate `local-zone` names are rejected, including duplicates introduced by
  an included blocklist. Deduplicate generated lists.
- Repeating `always_nxdomain` for a parent and its children is harmless; the
  loader keeps only the ancestor when the policy is identical.

See [Migrating from Unbound](unbound-migration.md) for the full include layout
and option matrix.

### Selecting a format in the container

The image entrypoint and healthcheck default to
`/etc/dns-rs/dns-rs.conf`, so an Unbound-style file at that path needs no extra
flags:

```bash
docker run -d --name dns-rs \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  -p 53:53/udp -p 53:53/tcp \
  -v "$PWD/config:/etc/dns-rs:ro" \
  -v dns-rs-data:/var/lib/dns-rs \
  chandanghosh/dns-rs:0.6.0
```

If your Unbound-style file has another name, either mount it as
`dns-rs.conf` or override both the command and the healthcheck as shown below.

For TOML, mount a `.toml` file and pass its path after the image name (it is
appended to the entrypoint). The image's built-in exec-form healthcheck keeps
probing `/etc/dns-rs/dns-rs.conf`, so it is wrong for this command. Disable it
with `--no-healthcheck` (Docker cannot replace it with an exec-form probe from
the CLI), or use Compose/Kubernetes, whose exec-form probes work:

```bash
docker run -d --name dns-rs \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges=true \
  --no-healthcheck \
  -p 53:53/udp -p 53:53/tcp \
  -v "$PWD/config:/etc/dns-rs:ro" \
  -v dns-rs-data:/var/lib/dns-rs \
  chandanghosh/dns-rs:0.6.0 -c /etc/dns-rs/dns-rs.toml run
```

For Compose, override `command` and the healthcheck in an override file. The
list form uses `exec` and works without a shell:

```yaml
services:
    resolver:
        command: ["-c", "/etc/dns-rs/dns-rs.toml", "run"]
        healthcheck:
            test:
                - CMD
                - /usr/local/bin/dns-rs
                - -c
                - /etc/dns-rs/dns-rs.toml
                - healthcheck
```

Use the same `-c` path for validation and reload:

```bash
docker exec dns-rs /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml checkconf
docker exec dns-rs /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.toml control reload
```

`checkconf` validates before a reload; a failed reload keeps the old pipeline.
Zone and blocklist changes are reloadable. Listener, TLS, and thread changes
need a restart. See
[Healthcheck](#healthcheck) for the default path and probe options.

## Build and verify locally

The `Makefile` wraps the common image tasks:

```bash
make image             # docker build -t dns-rs:dev .
make image-smoke       # build, run hardened, wait for healthy, and query
make image-size        # enforce the 10 MiB size budget
make image-scan        # Trivy scan for CRITICAL and HIGH findings
make image-multiarch   # build amd64 and arm64 without loading or pushing
```

The equivalent commands are:

```bash
docker build -t dns-rs:dev .

# Builds, starts with the hardened settings, waits for healthy, and queries
# the published socket. Uses host port 15353 so it does not collide with a
# local DNS service.
IMAGE=dns-rs:dev PORT=15353 scripts/container-smoke.sh
```

The build uses the container-oriented `dist` Cargo profile (fat LTO,
`opt-level = 2`, `panic = "abort"`, stripped symbols, static musl). The daemon
uses mimalloc, which raises idle RSS slightly but keeps the per-query
allocation path fast. To build both published architectures without pushing:

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

If `docker build` is slow while iterating, build once for the target platform
and set `SKIP_BUILD=1` so the smoke script reuses that image. Set `KEEP=1` to
leave the container running for manual queries:

```bash
docker build --platform linux/arm64 -t dns-rs:arm64 .
PLATFORM=linux/arm64 SKIP_BUILD=1 IMAGE=dns-rs:arm64 scripts/container-smoke.sh
```

`PLATFORM` selects the runtime platform; QEMU is needed only to run a foreign
image for the smoke test. Cross-compilation itself uses the native build
platform.

## Run manually with `docker run`

Because the image is `scratch`, it has no shell. Use `docker logs`,
`docker inspect`, and `docker exec ... /usr/local/bin/dns-rs` for diagnostics;
`docker exec ... sh` will not work. The optional `packaging/config` directory
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
  chandanghosh/dns-rs:0.6.0
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
  -v "$PWD/packaging/config:/etc/dns-rs:ro" \
  -v dns-rs-data:/var/lib/dns-rs \
  chandanghosh/dns-rs:0.6.0
```

Operate it with:

```bash
# Status, logs, and health
docker ps --filter name=dns-rs
docker logs -f dns-rs
docker inspect --format '{{.State.Health.Status}}' dns-rs

# Run the liveness probe by hand
docker exec dns-rs \
  /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf healthcheck

# Query it
dig @127.0.0.1 example.com A

# Stop and remove it
docker stop dns-rs
docker rm dns-rs
```

To use a different configuration or provide DoT/DoH certificates, add these
flags to the `docker run` command instead of the single default file:

```bash
-v "$PWD/config:/etc/dns-rs:ro" \
-v "$PWD/tls:/etc/dns-rs/tls:ro" \
```

The mounted directory can contain `dns-rs.conf` (the default name) or any
other Unbound-style file such as `unbound.conf`. A TOML file must use a
`.toml` name. Select a non-default name with `-c` after the image name and
override the healthcheck to match; see
[Selecting a format in the container](#selecting-a-format-in-the-container).

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
Hub, mounts `packaging/config` (the directory containing `dns-rs.conf`),
persists `/var/lib/dns-rs` in the `dns-rs-data` volume, and applies the same
hardening as the manual `docker run` examples. It does not build the image
locally.

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
  /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf healthcheck

# Apply a configuration edit without dropping in-flight queries. This covers
# resolver policy, zones, ACLs, DNSSEC, and cache settings. Listener, TLS,
# thread-count, and socket-buffer changes still need a restart.
docker compose exec resolver \
  /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf control reload

# Restart to apply listener/TLS/thread changes or to re-read a single-file mount
docker compose restart resolver

# Stop, then remove the container and network
docker compose down

# Also delete the persisted RFC 5011 state volume
docker compose down -v
```

The compose file mounts `packaging/config` read-only over the image's default
configuration directory. Edit `packaging/config/dns-rs.conf` or mount your own
directory. The named `dns-rs-data` volume is available for `/var/lib/dns-rs`,
which is where the RFC 5011 `auto-trust-anchor-file` lives when enabled.

The default is an Unbound-style file. For TOML, mount a `.toml` file and
override `command` and the healthcheck as shown in
[Selecting a format in the container](#selecting-a-format-in-the-container).

### Configuration and TLS material

For migrating an existing `unbound.conf`, including a recommended directory
layout and a Compose example, see
[Migrating from Unbound](unbound-migration.md).

Mount the configuration directory rather than individual files when possible:

```yaml
volumes:
    - ./config:/etc/dns-rs:ro
    - ./tls:/etc/dns-rs/tls:ro
    - dns-rs-data:/var/lib/dns-rs
```

Files must be readable by UID 65532. For DoT/DoH, enable the matching
interfaces in the configuration (for example `0.0.0.0@853` and `0.0.0.0@443`)
and set `tls-service-key` and `tls-service-pem` (TOML: `tls_service_key` and
`tls_service_pem`). The daemon selects the listener protocol from the port, as
in Unbound.

A reload re-reads the configuration but does not replace certificates or bind
new ports. Rotating TLS material, adding an interface, or changing the thread
count requires a restart. Rotating a certificate at the same path still needs a
restart because the acceptor is built once at startup.

## Healthcheck

The image's `HEALTHCHECK` runs:

```bash
/usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf healthcheck
```

If the resolver loads a different file, such as `/etc/dns-rs/dns-rs.toml`,
change the healthcheck path too. Otherwise the listener may be healthy while
Docker reports the container unhealthy because the probe cannot find
`dns-rs.conf`. In Compose, override `healthcheck.test` with the exec-form list
and the same `-c` path. In Kubernetes, change the exec probe arguments.

`docker run --health-cmd` is not a workaround: Docker wraps that string in
`/bin/sh -c`, and the `scratch` runtime has no shell. Leave the built-in probe
enabled when the default config path is correct. For a custom config path,
disable it with `--no-healthcheck` on the CLI, or define an exec-form probe in
Compose/Kubernetes. See
[Selecting a format in the container](#selecting-a-format-in-the-container).

`dns-rs healthcheck` loads the configuration, picks the first plain-DNS
listener (skipping the DoT/DoH ports), maps wildcard addresses to loopback, and
asks for the built-in `localhost.` record. Options:

```bash
dns-rs -c /etc/dns-rs/dns-rs.conf healthcheck \
  --address 127.0.0.1 --port 53 \
  --name localhost. --timeout 2000 --tcp
```

If you override the container command with a different configuration path,
override the healthcheck as well. It is a liveness/readiness probe for the
listener, not an upstream connectivity test. It requires a plain DNS listener;
for a DoT/DoH-only deployment, use a TCP or HTTPS probe that matches the
enabled service instead.

## Statistics and monitoring

Resolver counters are exposed on the opt-in control socket. There is no HTTP
metrics listener and no stats endpoint on the DNS port. The socket is disabled
by default, so enable it in the configuration the container loads:

```conf
remote-control:
    control-enable: yes
    control-interface: /run/dns-rs.sock
```

The TOML front-end is equivalent:

```toml
[remote_control]
enabled = true
interfaces = ["/run/dns-rs.sock"]
port = 8953
```

Enabling, moving, or disabling the socket requires a restart: a reload reports
`remote-control` as a restart-only change, just like a listener or port change.

The socket needs a writable directory, which a read-only root filesystem does
not provide. Mount a tmpfs at `/run`:

```yaml
read_only: true
tmpfs:
    - /run:rw,noexec,nosuid,size=16m
```

The daemon refuses a parent directory that is group- or other-writable unless it
has the sticky bit, so a default `755` tmpfs or a host directory owned by UID
`65532` with mode `0755` both work. A `0777` bind mount fails at startup.

### Counter commands

`docker exec` runs as the image's `USER` (UID `65532`) by default, which matches
the socket owner. The socket is mode `0600` and the server rejects every other
UID, so `docker exec -u 0` does not work.

```bash
# Version, PID, control uptime, and control protocol.
docker exec dns-rs /usr/local/bin/dns-rs \
    -c /etc/dns-rs/dns-rs.conf control status

# Counters as one JSON object.
docker exec dns-rs /usr/local/bin/dns-rs \
    -c /etc/dns-rs/dns-rs.conf control stats

# The same counters in Prometheus text format.
docker exec dns-rs /usr/local/bin/dns-rs \
    -c /etc/dns-rs/dns-rs.conf control stats-prometheus
```

The client reads the socket path from the file passed with `-c`, so use the same
path as the container command. `--socket /run/dns-rs.sock` skips loading the
configuration entirely.

| JSON field | Prometheus metric | Meaning |
| --- | --- | --- |
| `cache_hits` | `dns_rs_cache_hits_total` | Message-cache hits |
| `cache_misses` | `dns_rs_cache_misses_total` | Message-cache misses |
| `cache_stale_hits` | `dns_rs_cache_stale_hits_total` | Expired entries served by `serve-expired` |
| `cache_entries` | `dns_rs_cache_entries` | Entries currently in the message cache (gauge) |
| `prefetches` | `dns_rs_prefetches_total` | Background refreshes started by prefetch or serve-expired |
| `coalesce_leaders` | `dns_rs_coalesce_leaders_total` | Queries that started an upstream resolution |
| `coalesce_followers` | `dns_rs_coalesce_followers_total` | Queries that joined an in-flight resolution |
| `coalesce_abandoned` | `dns_rs_coalesce_abandoned_total` | Leaders dropped before publishing a result |
| `queries_total` | `dns_rs_queries_total` | Queries presented to the pipeline |
| `queries_by_transport` | `dns_rs_queries_by_transport_total{transport=...}` | Queries by UDP, TCP, TLS, or HTTPS |
| `responses_total` | `dns_rs_responses_total` | Encoded client replies |
| `responses_by_rcode` | `dns_rs_responses_by_rcode_total{rcode=...}` | Replies by 4-bit response code |
| `responses_truncated` | `dns_rs_responses_truncated_total` | Replies with the TC bit set |
| `responses_ede` | `dns_rs_responses_ede_total` | Replies carrying an Extended DNS Error |
| `responses_ad` | `dns_rs_responses_ad_total` | Replies with the AD bit set |
| `dnssec_secure` / `dnssec_insecure` / `dnssec_bogus` | `dns_rs_dnssec_validations_total{result=...}` | DNSSEC validation outcomes |
| `upstreams` | `dns_rs_upstream_rtt_seconds{server=...}` and related gauges | Per-upstream RTT, timeouts, failures, lameness, backoff, and DNS 0x20 state |
| `upstreams_omitted` | `dns_rs_upstreams_omitted` | Upstreams left out of the bounded report |

Every counter field resets when the process restarts or the pipeline is
replaced on reload. `status` reports control uptime, so a value that stays flat
or resets is the quickest confirmation of a restart loop. The upstream section
covers the 64 most recently used servers; `upstreams_omitted` reports any that
did not fit. Cache capacity is measured in entries rather than bytes, and there
is no per-client breakdown.

### Prometheus

Nothing listens on HTTP, so Prometheus cannot scrape the container directly.
Two patterns work:

- Run an exec-based exporter that calls `control stats-prometheus` and serves
  the text over HTTP. This needs access to `docker exec` or the Docker socket.
- Bind-mount a host directory at `/run`, then point a host-side collector at the
  same socket path with `dns-rs control stats-prometheus --socket <path>` or
  `socat`. Keep the directory owned by UID `65532` with mode `0755`; a
  world-writable directory without the sticky bit is rejected.

Counters are cheap: a request allocates a 4 KiB request buffer and one of four
connection slots, and the response is rendered on demand. Prometheus output is
bounded by the 64 KiB control response limit.

### Container resource usage

`docker stats` reports the cgroup total, which includes page cache and tmpfs
(shmem) pages, not only the resolver's heap:

```bash
docker stats --no-stream dns-rs
docker top dns-rs -o pid,rss,vsz,comm
docker inspect dns-rs --format \
  'OOMKilled={{.State.OOMKilled}} ExitCode={{.State.ExitCode}} Restarts={{.RestartCount}} MemLimit={{.HostConfig.Memory}}'
docker events --filter container=dns-rs --since 1h
```

`docker top` shows the daemon's resident set without page cache. A rise in
`docker stats` that does not appear in `docker top` is cache or tmpfs
accounting: `docker stats` subtracts only inactive page cache, so freshly
exec'd pages (including the roughly 9 MB static client binary) and tmpfs writes
remain in the reported figure until they age out or are reclaimed. The control
socket itself adds one listener and one task, and allocates buffers only while a
request is in flight.

To separate process memory from cache, read the cgroup counters on the host:

```bash
id=$(docker inspect -f '{{.Id}}' dns-rs)
cat /sys/fs/cgroup/system.slice/docker-$id.scope/memory.stat
```

With cgroup v1 the path is `/sys/fs/cgroup/memory/docker/$id/memory.stat`.
`anon` is process memory; `file` and `shmem` are page cache and tmpfs. The
`kernel` and `sock` fields cover socket and kernel structures.

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
docker pull chandanghosh/dns-rs:0.6.0
DNS_RS_HOST_PORT=53 docker compose up -d
```

For a long-lived test node:

1. Use a 64-bit OS on a Pi 4 or later, with a wired network connection.
2. Keep the root filesystem read-only in compose (the default) and mount a
   named volume at `/var/lib/dns-rs`.
3. Point the Pi's own resolver at `127.0.0.1` only after the container is
   healthy, and keep an out-of-band SSH path for recovery.
4. Enable `auto-trust-anchor-file: "/var/lib/dns-rs/root.key"` (TOML:
   `auto_trust_anchor_file`) if you want RFC 5011 updates to persist.
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
`forward-fallback: yes` (see [Troubleshooting](#troubleshooting)) rather than
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

## Publishing and CI

Maintainer publishing steps, tag rules, release automation, secrets, and CI gates
are documented in [Container publishing](container-publishing.md).
