# Installation

Audience: operators and developers installing dns-rs on a host or pulling the
container image. For a first run, start with the [Quick start](quickstart.md).

## Support tiers

| Platform | Architecture | Methods | Tier | Notes |
|---|---|---|---|---|
| Linux | x86_64 | source, container image | 1 | Unit, integration, and container smoke tests run in CI on `ubuntu-latest`. |
| Linux | aarch64/arm64 | container image | 2 | Multi-arch image is built and smoke-tested under QEMU. Sustained Raspberry Pi hardware testing is still pending. |
| macOS | x86_64, arm64 | source | 3 | Expected to build and run; not covered by CI. Host benchmarking CPU pinning and container tooling are Linux-only. |
| Windows | x86_64 | source | 3 | Expected to build and run; not covered by CI. |
| Other / 32-bit | — | source | unsupported | Not tested and not maintained. |

Tier 1 means regressions block a release. Tier 2 means best-effort validation.
Tier 3 means the code is expected to compile but no automated check protects it.

There are no prebuilt host binaries in GitHub Releases today. Install from
source or use the container image.

## Install from source

Requirements: Rust 1.100 or newer and a C toolchain for dependencies such as
`ring`.

```bash
git clone https://github.com/ChandanGhosh/dns-rs.git
cd dns-rs

# Installs the dns-rs binary into ~/.cargo/bin (or Cargo's configured bin dir).
make install
# Equivalent: cargo install --locked --path crates/dns-daemon --bin dns-rs

dns-rs --version
dns-rs -c examples/minimal.toml checkconf
```

For a system-wide install, build the release binary and copy it yourself:

```bash
make release
sudo install -m 0755 target/release/dns-rs /usr/local/bin/dns-rs
```

`make build` formats the workspace before a debug build; use `make release` or
`cargo build --release -p dns-daemon --bin dns-rs` when you do not want an
automatic `cargo fmt`.

## Container image

```bash
docker pull chandanghosh/dns-rs:0.6.0
docker run --rm chandanghosh/dns-rs:0.6.0 --version
```

Images are published for `linux/amd64` and `linux/arm64`. `X.Y.Z` tags are
immutable; `latest` is repointed to the newest release; `DDMMYYYY` tracks the
newest successful `main` build that is still HEAD when the publish job runs.
See [Container publishing](container-publishing.md) for the full tag policy.

## Host service (systemd)

The daemon stays in the foreground, logs to standard output, and never
daemonizes or changes user by itself. A service manager should own those
concerns. An example
unit is provided at
[`packaging/systemd/dns-rs.service`](../packaging/systemd/dns-rs.service).

```bash
# 1. Create an unprivileged service user and state directories.
sudo useradd --system --home-dir /var/lib/dns-rs \
  --shell /usr/sbin/nologin dns-rs
sudo install -d -o dns-rs -g dns-rs -m 0750 /etc/dns-rs /var/lib/dns-rs /run/dns-rs

# 2. Install the binary and the default configuration.
sudo install -m 0755 target/release/dns-rs /usr/local/bin/dns-rs
sudo install -o dns-rs -g dns-rs -m 0640 \
  packaging/config/dns-rs.conf /etc/dns-rs/dns-rs.conf

# 3. Validate before starting the service.
sudo -u dns-rs /usr/local/bin/dns-rs -c /etc/dns-rs/dns-rs.conf checkconf

# 4. Install and enable the unit.
sudo install -m 0644 packaging/systemd/dns-rs.service /etc/systemd/system/dns-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now dns-rs.service

# 5. Verify.
systemctl status dns-rs.service
journalctl -u dns-rs.service -f
dig @127.0.0.1 example.com A
```

The example unit grants `CAP_NET_BIND_SERVICE` so the service can bind port 53.
If you prefer to avoid that capability, change `port: 53` in the configuration
to a high port and remove the two `Capability*` lines from the unit. Keep a
plain-DNS listener if you want to use `dns-rs healthcheck` and systemd's
reload path.

Reload is `systemctl reload dns-rs.service` (it sends `SIGHUP`). It rebuilds
the query pipeline and flushes caches, but listener, TLS, thread, socket-buffer,
control-socket, and verbosity changes need `systemctl restart dns-rs.service`.
See [Configuration](configuration.md#reload-and-restart) for the exact list.

## Verify an installation

Whichever method you used:

```bash
dns-rs --version
dns-rs -c <your-config> checkconf
dns-rs -c <your-config> healthcheck
dig @<listener-address> -p <listener-port> example.com A
```

`checkconf` prints the configuration path, interfaces, thread count, forward
zone count, and the number of warnings. It does not read TLS files, root hint
files, or trust anchors; those are loaded when the resolver starts.

## Uninstall

For a source install, remove `/usr/local/bin/dns-rs` (or
`~/.cargo/bin/dns-rs`), the systemd unit, the service user, and the state
directories. For a container, run `docker rm`/`docker compose down` and delete
any named volumes separately with `docker compose down -v`.
