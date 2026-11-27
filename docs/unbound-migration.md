# Migrating from Unbound to dns-rs

dns-rs reads a practical subset of `unbound.conf` directly. A stock
configuration often becomes a working starting point after a validation pass,
but it is not a drop-in replacement: expect operator decisions about listeners,
ACLs, rebinding defaults, DNSSEC anchors, the upstream model, and the control
channel. This guide covers that path, a recommended baseline, host and container
deployment, and the settings that need a decision.

The option-by-option reference is
[Unbound configuration compatibility](unbound-compatibility.md). Annotated
examples covering the main options are in
[`examples/full.conf`](../examples/full.conf) and
[`examples/full.toml`](../examples/full.toml); the complete field list is in
[Configuration](configuration.md).

## Scope

This guide targets dns-rs 0.6.0 and later. It is not a byte-for-byte drop-in for
every Unbound feature: RPZ, DNS64, response-IP filtering, per-interface views,
auth-zone transfers and URL fetching, and the `unbound-control` protocol are not
implemented. Such configurations load with warnings, but the feature does not
take effect.

## Quick migration

```bash
# 1. Copy the main file and the include tree.
sudo install -d -m 0755 /etc/dns-rs
sudo cp /etc/unbound/unbound.conf /etc/dns-rs/unbound.conf

# 2. Validate. Warnings are migration TODOs; errors are fatal.
dns-rs -c /etc/dns-rs/unbound.conf checkconf

# 3. Run in the foreground. The service manager or container owns daemonization.
dns-rs -c /etc/dns-rs/unbound.conf run

# 4. Verify from another terminal (adjust the port if needed).
dig @127.0.0.1 example.com A
```

Any filename whose extension is not `.toml` (case-insensitively) is parsed as
`unbound.conf` syntax. Calling the file `dns-rs.conf`, `unbound.conf`, or
`resolver.conf` makes no difference. Only a `.toml` extension selects the native
TOML front-end.

`checkconf` prints the interfaces, thread count, and forward-zone count it
parsed. A missing include, an unsupported option, or a cache sizing option
produces a warning and does not fail the check. A parse error, invalid value, or
duplicate zone does fail.

## Migration checklist

### 1. Inventory the files Unbound reads

Collect the main configuration and every file referenced by `include`,
`include-toplevel`, `root-hints`, `trust-anchor-file`,
`auto-trust-anchor-file`, and `auth-zone` zonefiles. Record which paths are
absolute and which are relative.

Relative includes are tried against the directory of the including file first,
then against the process working directory. This means a configuration that
uses `include: "unbound.conf.d/*.conf"` keeps working when the whole tree is
copied together. Absolute paths such as `/etc/unbound/unbound.conf.d/*.conf`
must either be rewritten to the new location or mounted at the same path in the
container.

A glob that matches no files only warns. Treat that warning as a real migration
issue: the missing file may have supplied local records, forwarders, or trust
anchors.

### 2. Decide how the process is supervised

Unbound normally daemonizes, writes a PID file, changes user and chroot, and
owns its own log file. dns-rs stays in the foreground and logs to standard
output, but it does implement `username` privilege drop on Unix: listeners and
the control socket are created first, then the process permanently switches to
the configured account. Make sure that account can read the configuration, TLS,
trust-anchor, zone, and CA files for reload, and can write the directory that
holds `auto-trust-anchor-file`.

These options are parsed for compatibility but have no effect:

- `do-daemonize`
- `chroot`
- `directory`
- `logfile`
- `pidfile`
- `use-syslog`

Remove them if they make the resulting configuration misleading, or leave them
and accept the compatibility warning. Do not use `directory:` to relocate file
paths; use absolute paths instead. The container or service manager owns reload
and restart behavior.

### 3. Make listeners explicit

An `unbound.conf` with no `interface:` fails validation with `at least one
interface must be configured`. It does not start with zero listeners. Specify at
least one listener:

```conf
server:
    interface: 0.0.0.0
    port: 53
```

Inside a container, `interface: 127.0.0.1` is usually wrong: published ports
arrive on the container's bridge interface, not its loopback. Use
`interface: 0.0.0.0` (and `interface: ::` if IPv6 is enabled) and restrict
reachability with the host firewall and `access-control`.

### 4. Define access control

An `unbound.conf` parse starts with no access-control rules. If no
`access-control` rule matches a client, the query is refused. Include every
network that must query the resolver:

```conf
server:
    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 0.0.0.0/0 refuse
```

The most specific netblock wins regardless of statement order; later statements
win ties. `allow`, `deny`, `refuse`, `allow_setrd`, `allow_snoop`,
`deny_non_local`, and `refuse_non_local` are implemented. `allow_cookie` is
mapped to `allow` with a warning because client cookie enforcement is not
implemented.

A refused client receives `REFUSED`. It is not a resolution failure.

### 5. Triage the warnings

Every accepted-with-a-warning option is a deliberate compatibility decision,
not a silent no-op. Common groups:

- Logging switches such as `log-queries`, `log-replies`, `log-servfail`,
  `log-local-actions`, and `log-time-ascii`. Use `verbosity` or `RUST_LOG`
  instead.
- Cache slabs and unused byte budgets: `key-cache-size`, `neg-cache-size`, and
  their `*-slabs` companions. `msg-cache-size` and `rrset-cache-size` are
  enforced as byte budgets.
- Connection tuning: `outgoing-range`, `num-queries-per-thread`,
  `msg-buffer-size`, and `jostle-timeout`. Remove these rather than expecting
  them to change capacity.
- DNSSEC tuning beyond the implemented set: `prefetch-key`, `val-bogus-ttl`,
  `val-log-level`, `val-sig-skew-min`, and `val-sig-skew-max`.
- Hardening switches: `harden-short-bufsize`, `harden-large-queries`,
  `harden-below-nxdomain`, and `unwanted-reply-threshold`.
- `minimal-responses`, `hide-identity`, `hide-version`, `identity`, and
  `version`. CHAOS identity queries are not answered.
- `so-rcvbuf` and `so-sndbuf`. Use `udp-recv-buffer-size`,
  `udp-send-buffer-size`, `tcp-recv-buffer-size`, and `tcp-send-buffer-size` if
  socket buffer tuning is required.
- `module-config` with `subnetcache`, `respip`, or `dynlib`, plus RPZ, DNS64,
  and response-IP features. These are out of scope; remove the directives or
  keep Unbound for that deployment.

Warnings do not cause a restart. If a container exits with code 137, the cause
is a signal kill, not a configuration warning. See
[Troubleshooting](#troubleshooting).

### 6. Decide on DNSSEC and trust anchors

dns-rs validates DNSSEC by default and ships with built-in root trust anchors.
You do not need to copy Unbound's root key file for basic operation.

If you keep `auto-trust-anchor-file`, point it at a writable location:

```conf
server:
    auto-trust-anchor-file: "/var/lib/dns-rs/root.key"
```

Do not point it into the read-only configuration directory. `trust-anchor` and
`trust-anchor-file` are read-only inputs and can live with the configuration.

`val-permissive-mode: yes` does not turn validation off: dns-rs still validates,
but returns bogus data with `AD=0` instead of `SERVFAIL`. Keep it off unless you
are debugging a specific domain. Prefer `domain-insecure` for a known-broken
subtree.

### 7. Choose iteration or forwarding

Pick one upstream model deliberately:

- Iterative resolution uses built-in root hints, or `root-hints:` if you copy
  the file. It is the default and gives the resolver full DNSSEC validation.
- A `forward-zone: name: "."` sends every query to the listed upstreams. Use
  DoT or DoH when the network is untrusted. A plain-DNS forwarder is only
  appropriate for a trusted local upstream.

Do not leave both a `.` forward zone and a root-hints configuration active by
accident. If you forward to a local stub resolver, make sure that resolver does
not forward back to dns-rs; that creates a query loop.

`forward-host` and `stub-host` are resolved once at startup through the system
resolver. A configuration reload is needed when those hostnames change.

`do-not-query-localhost` defaults to `yes`, which blocks `127.0.0.0/8` and
`::1/128` as upstreams. Set `do-not-query-localhost: no` if you intentionally
forward to a resolver on loopback.

### 8. Validate behavior, then cut over

A configuration that loads is not necessarily a configuration that resolves.
Before switching clients, check:

```bash
# Ordinary resolution and caching
dig @127.0.0.1 -p 53 example.com A
dig @127.0.0.1 -p 53 example.com A

# DNSSEC validation
dig @127.0.0.1 -p 53 cloudflare.com A +dnssec

# Local data and a blocklist entry
dig @127.0.0.1 -p 53 router.home A
dig @127.0.0.1 -p 53 ads.example A

# Access control from a client that should be refused
dig @<resolver-ip> -p 53 example.com A
```

`SERVFAIL` with an Extended DNS Error about bogus DNSSEC is an upstream or
zone problem, not an access-control problem. Use `domain-insecure` for a
specific broken subtree, not `val-permissive-mode` for the whole resolver.

## Recommended baseline

This is a conservative starting point. Change the listener and ACLs for your
network. The private-address and private-domain defaults are intentionally left
in place; see [Divergences](#divergences-that-need-a-decision).

```conf
server:
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes

    num-threads: 2
    verbosity: 1
    do-daemonize: no

    access-control: 127.0.0.0/8 allow
    access-control: 10.0.0.0/8 allow
    access-control: 172.16.0.0/12 allow
    access-control: 192.168.0.0/16 allow
    access-control: 0.0.0.0/0 refuse

    qname-minimisation: yes
    qname-minimisation-strict: no
    use-caps-for-id: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    edns-buffer-size: 1232

    cache-min-ttl: 0
    cache-max-ttl: 86400
    cache-max-negative-ttl: 3600
    prefetch: no
    serve-expired: yes
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30

    # Optional: persist RFC 5011 state on a writable filesystem.
    # auto-trust-anchor-file: "/var/lib/dns-rs/root.key"

    # Optional: use a copied hints file instead of the built-in hints.
    # root-hints: "/etc/dns-rs/root.hints"
```

For encrypted forwarding, add a complete top-level clause after the server
block:

```conf
forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 8.8.8.8@853#dns.google
    forward-first: no
```

This baseline validates with `dns-rs -c <file> checkconf`. The values are
starting points, not universal tuning: `num-threads` should not exceed the CPU
budget of the host, and `do-ip6: no` should be changed only when the host
actually has working IPv6.

## Divergences that need a decision

These differences are intentional. Decide whether to keep dns-rs's safer
behavior or reproduce your old Unbound behavior.

### Rebinding protection

Unbound ships with empty `private-address` and `private-domain` lists. dns-rs
blocks RFC 1918, link-local, IPv6 unique-local, and IPv4-mapped answers by
default and allows common local namespaces (`.lan`, `.home.arpa`, `.internal`,
and similar). The exact default ranges and namespaces are listed in
[Configuration](configuration.md#rebinding-protection).

An explicit `private-address:` or `private-domain:` line replaces the entire
built-in list. If you set either option, include every network or namespace you
rely on. Empty values are rejected in `unbound.conf` syntax. If you need
Unbound's empty-list behavior exactly, use the TOML front-end with
`private_address = []` and `private_domain = []`. Otherwise keep the defaults.

### DNS 0x20 case randomisation

`use-caps-for-id` defaults to `yes` in dns-rs and `no` in Unbound. It affects
upstream queries only. Set `use-caps-for-id: no` if you need byte-for-byte
matching behavior or if an upstream is known to mishandle mixed-case names.

### Private reverse zones

dns-rs routes private reverse zones and common local suffixes through the
default gateway over plain DNS. They are never sent to a public, DoT, or DoH
resolver. With no discoverable gateway, these names are REFUSED.
`unblock-lan-zones: no` is accepted with a warning because dns-rs resolves the
names locally instead of blocking them outright.

### Relative includes

dns-rs tries a relative include against the including file's directory first,
then the process working directory. Unbound resolves it against its working
directory or chroot. This makes copied configuration trees more portable, but
absolute paths remain the most predictable option.

### Control channel

`remote-control:` opens a Unix socket that accepts one JSON command per line.
It is not compatible with `unbound-control`. `control-port` must remain `8953`,
and only Unix control interfaces are supported. Use the dns-rs binary for
control requests.

## Container deployment

Pin an image version in production. Build locally with
`docker build -t dns-rs:dev .`, or use a published tag.

```yaml
name: dns-rs

services:
    resolver:
        image: ${DNS_RS_IMAGE:-chandanghosh/dns-rs:0.6.0}
        container_name: dns-rs
        restart: unless-stopped
        command: ["-c", "/etc/dns-rs/unbound.conf", "run"]

        ports:
            - "${DNS_RS_BIND_ADDR:-0.0.0.0}:${DNS_RS_HOST_PORT:-53}:53/udp"
            - "${DNS_RS_BIND_ADDR:-0.0.0.0}:${DNS_RS_HOST_PORT:-53}:53/tcp"

        volumes:
            - ./unbound:/etc/dns-rs:ro
            - dns-rs-data:/var/lib/dns-rs

        read_only: true
        tmpfs:
            - /tmp:rw,noexec,nosuid,size=16m
            # Enable when remote-control uses the unified Unix socket path.
            # - /run/dns-rs:rw,noexec,nosuid,size=16m,uid=65532,gid=65532,mode=0700
        cap_drop:
            - ALL
        cap_add:
            - NET_BIND_SERVICE
        security_opt:
            - no-new-privileges:true
        pids_limit: 256
        mem_limit: 512m

        healthcheck:
            test:
                - CMD
                - /usr/local/bin/dns-rs
                - -c
                - /etc/dns-rs/unbound.conf
                - healthcheck
            interval: 30s
            timeout: 5s
            start_period: 5s
            retries: 3

volumes:
    dns-rs-data:
```

The `command` and `healthcheck` must use the same configuration path. Mounting
over `/etc/dns-rs` hides the image's built-in `dns-rs.conf`, so the default
healthcheck would fail. Keeping the migrated file named `dns-rs.conf` avoids
both overrides; the name `unbound.conf` above is only an example.

### Directory layout

```text
dns-rs-deploy/
├── docker-compose.yml
├── .env
├── .gitignore
├── unbound/                       # mounted at /etc/dns-rs:ro
│   ├── unbound.conf
│   ├── server.d/                  # include: fragments
│   │   ├── 10-acl.conf
│   │   └── 30-blocklist.conf
│   ├── zones.d/                   # include-toplevel: clauses
│   │   ├── 10-forward-zones.conf
│   │   └── 20-remote-control.conf
│   ├── root.hints
│   ├── zones/
│   │   └── example.com.zone
│   └── tls/
│       ├── server.pem
│       └── server.key
└── state/                         # only for a bind-mounted state directory
    └── root.key
```

`unbound.conf` connects the pieces:

```conf
server:
    interface: 0.0.0.0
    port: 53
    do-ip6: no
    verbosity: 1

    include: "server.d/*.conf"

    root-hints: "/etc/dns-rs/root.hints"
    # auto-trust-anchor-file: "/var/lib/dns-rs/root.key"

include-toplevel: "zones.d/*.conf"
```

Use `include:` for files that contain only server options. It keeps the active
`server:` clause. Use `include-toplevel:` for complete clauses such as
`forward-zone:`, `stub-zone:`, `auth-zone:`, `view:`, or `remote-control:`; it
closes the active clause before and after the include. Mixing them up can make
the parser interpret a later option inside the wrong block.

Mount the configuration directory, not a single file. Editors that save by
renaming replace the inode, and a single-file bind mount would keep reading the
old content after a reload.

### State and permissions

The image runs as UID/GID `65532`. Configuration files must be readable by that
user:

```bash
chmod 755 unbound unbound/server.d unbound/zones.d unbound/zones unbound/tls
chmod 644 unbound/unbound.conf unbound/server.d/*.conf unbound/zones.d/*.conf
chmod 644 unbound/root.hints unbound/zones/*.zone unbound/tls/server.pem
chmod 600 unbound/tls/server.key
chown 65532:65532 unbound/tls/server.key
```

`/var/lib/dns-rs` must be writable when `auto-trust-anchor-file` is enabled.
Use the named volume from the compose file, or a host directory owned by
`65532:65532`. The control socket needs a writable tmpfs at `/run/dns-rs`. If the
socket must be reachable from the host, bind-mount a host directory at that path
instead and give UID `65532` write access.

### Reload and restart

```bash
# Reload policy, zones, ACLs, DNSSEC settings, and caches.
docker compose exec resolver \
  /usr/local/bin/dns-rs -c /etc/dns-rs/unbound.conf control reload

# Equivalent when remote-control is disabled.
docker kill -s HUP dns-rs

# Restart for listener, port, TLS certificate, or thread-count changes.
docker compose restart resolver
```

A reload replaces the query pipeline atomically. In-flight queries finish on
the old pipeline, and a configuration that fails to parse leaves the running
configuration untouched.

## Blocklists

Blocklists work through Unbound local-zone policies. Supported patterns include:

```conf
# NXDOMAIN for the name and every subdomain.
local-zone: "ads.example" always_nxdomain

# Answer every name in the zone with the apex A record.
local-zone: "tracker.example" redirect
local-data: "tracker.example A 0.0.0.0"

# A static zone: apex data, NXDOMAIN for unknown subdomains.
local-zone: "static.example" static
local-data: "static.example A 0.0.0.0"
```

Also supported are `always_null`, `refuse`, `always_refuse`, `deny`,
`always_deny`, `block_a`, `block_aaaa`, and the `_wdata` variants. A generated
blocklist file can contain bare `local-zone:` lines and be included from inside
the `server:` block:

```conf
server:
    include: "server.d/*.conf"
```

Convert adblock syntax (`||example.com^`) and hosts-file lines to Unbound
`local-zone` or `local-data` entries before loading them. Duplicate
`local-zone` names are rejected by validation, so deduplicate generated lists.

Local-zone lookup walks the labels of the query name and finds each suffix with
a binary search, so per-query cost depends on the number of labels in the name,
not on the size of the list. Startup parses includes as a stream and builds the
index in linear time; lists with tens of thousands of entries load in well under
a second on ordinary hardware.

A zone that repeats the policy of its closest ancestor is redundant and is
dropped at load time. This is the usual shape of a generated blocklist, where
`always_nxdomain` appears for both a parent and many of its children: only the
parent is kept. Because the ancestor answers the query, a generated negative
reply may carry the ancestor's SOA in the authority section rather than the
child's. The response code is unchanged.

## Logging, control, and monitoring

`verbosity` maps directly to the log level:

| Value | Level | Typical use |
| --- | --- | --- |
| 0 | warnings | Quiet production |
| 1 | info | Default production |
| 2-3 | debug | Per-query lines while investigating |
| 4-5 | trace | Protocol-level debugging |

`-v`/`-vv` and `RUST_LOG` override the configuration. The Unbound `log-*`
switches are accepted with warnings but do not change the output. In a
container, logs go to standard output; do not configure `logfile`.

The control socket supports `status`, `stats`, `stats-prometheus`, `reload`, and
`stop`:

```bash
dns-rs -c /etc/dns-rs/unbound.conf control status
dns-rs -c /etc/dns-rs/unbound.conf control stats-prometheus
```

The socket is mode `0600` and authorizes peers by effective UID. A reload
re-reads the daemon's own configuration path; the request cannot name a
different file.

## Host service example

For a non-container deployment, run dns-rs as an unprivileged user and grant
only the capability needed to bind port 53. Create the user and state directory
first.

```ini
[Unit]
Description=dns-rs DNS resolver
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/dns-rs -c /etc/dns-rs/unbound.conf run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2

User=dns-rs
Group=dns-rs
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RuntimeDirectory=dns-rs
ReadWritePaths=/var/lib/dns-rs /run/dns-rs

[Install]
WantedBy=multi-user.target
```

The control socket path is `/run/dns-rs/dns-rs.sock` everywhere. Adjust the
`RuntimeDirectory` and socket path together only for a custom unit.
`ProtectSystem=strict` keeps `/etc/dns-rs` readable but read-only, which is the
intended configuration model.

## Recommendations

- Keep dns-rs's secure defaults unless you have a specific compatibility need.
  In particular, do not disable rebinding protection just because the old
  Unbound configuration had empty private lists.
- Prefer iterative resolution with DNSSEC validation. If the network blocks
  outbound port 53 or intercepts plain DNS, use DoT or DoH forwarders instead of
  unencrypted forwarding.
- Never forward to a resolver that forwards back to dns-rs. Check for loops
  before cutting clients over.
- Do not expose port 53 to the public internet. Restrict access with
  `access-control` and a host firewall, and rate-limit if the deployment is
  shared.
- Run at `verbosity: 1` in production. Debug logging emits a line per query and
  can dominate CPU and disk write volume at high query rates.
- Size `num-threads` to the available CPU budget. More threads do not help on a
  single-core host and increase per-thread buffers.
- Give the container 256-512 MB of memory and monitor it. A `137` exit is a
  signal kill, most often the OOM killer or an external watchdog; it is not a
  configuration error.
- Pin the image tag and mount the configuration directory read-only. Keep
  writable state in `/var/lib/dns-rs`, not in the configuration tree.
- Make the healthcheck use the same `-c` path as the service, and use
  `start_period` long enough for startup and DNSSEC priming.
- Validate every configuration change with `checkconf` before reloading. A
  failed reload keeps the old configuration, but catching errors earlier is
  cheaper.
- Deduplicate generated blocklists. Repeating `always_nxdomain` for a child of
  an already-blocked parent is harmless because the loader drops it, but exact
  duplicate lines are rejected and every source line still costs memory while
  the configuration is held.
- Keep the old Unbound configuration and a rollback plan until the new resolver
  has served production traffic through at least one full cache cycle.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Container exits with code 137 | `SIGKILL`: OOM killer, host memory pressure, or an external watchdog | Check `docker inspect dns-rs --format '{{.State.OOMKilled}} {{.State.ExitCode}} {{.HostConfig.Memory}}'` and raise the memory limit or remove it. |
| Container restarts but logs look normal | Healthcheck points at a different or hidden config path | Set the healthcheck `-c` to the same path as `command`. |
| `REFUSED` for clients | No matching `access-control` rule | Add a matching `allow` rule for the client network. A more specific allow wins over a broad `refuse`; statement order only breaks equal-prefix ties. |
| `SERVFAIL` for one domain with an EDE about DNSSEC | Upstream or zone is bogus | Use `domain-insecure` for that subtree, not global permissive mode. |
| Service exits before startup | No `interface:` in the config | Add at least one `interface:`; this is a fatal validation error. |
| No externally reachable listener | Only loopback configured in a container | Add `interface: 0.0.0.0` and publish the port. |
| `address already in use` at startup | Another resolver owns port 53 | Stop or move `systemd-resolved`, `dnsmasq`, or the old Unbound instance. |
| `include ... matched no files` | Path not mounted or rewritten for the container | Mount the include tree or change the path. |
| `Permission denied` reading config or TLS key | File not readable by UID `65532` | Fix mode and ownership. |
| `Permission denied` writing root key | `auto-trust-anchor-file` is in a read-only path | Move it to `/var/lib/dns-rs` or another writable mount. |
| Logs show per-query lines in production | `verbosity` is 2 or higher | Set `verbosity: 1`. |
| Startup takes a long time with a blocklist | The list is parsed and indexed at startup, so time grows with the number of lines | Deduplicate the generated list, remove entries already covered by an `always_nxdomain` ancestor, and keep the file on a local disk rather than a slow network mount. |

## See also

- [Unbound configuration compatibility](unbound-compatibility.md): the
  compatibility matrix and warning groups.
- [Container deployment](container.md): image details, hardening, Kubernetes,
  and operational commands.
- [`examples/full.conf`](../examples/full.conf) and
  [`examples/full.toml`](../examples/full.toml): annotated reference
  configurations.
- [`docs/benchmarking.md`](benchmarking.md): benchmarking methodology and
  switches.
