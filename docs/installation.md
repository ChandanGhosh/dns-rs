# Installation

Audience: operators and developers installing dns-rs on a host or pulling the
container image. For a first run, start with the [Quick start](quickstart.md).

## Support tiers

| Platform | Architecture | Methods | Tier | Notes |
|---|---|---|---|---|
| Linux | x86_64 | release tarball, source, container image | 1 | Unit, integration, and container smoke tests run in CI on `ubuntu-latest`. |
| Linux | aarch64/arm64 | release tarball, container image | 2 | Multi-arch image is built and smoke-tested under QEMU. Sustained Raspberry Pi hardware testing is still pending. |
| macOS | x86_64, arm64 | source | 3 | Expected to build and run; not covered by CI. Host benchmarking CPU pinning and container tooling are Linux-only. |
| Windows | x86_64 | source | 3 | Expected to build and run; not covered by CI. |
| Other / 32-bit | — | source | unsupported | Not tested and not maintained. |

Tier 1 means regressions block a release. Tier 2 means best-effort validation.
Tier 3 means the code is expected to compile but no automated check protects it.

Prebuilt static musl binaries are attached to every versioned GitHub release.
Install from a release tarball, from source, from a distro package, or use the
container image.

## Install from a release tarball

Each release publishes `dns-rs-<version>-linux-amd64.tar.gz` and
`dns-rs-<version>-linux-arm64.tar.gz`, with a `SHA256SUMS` covering both. Each
bundle contains the binary, `dns-rs.conf`, `dns-rs.service`, `LICENSE`, and a
README.

```bash
version=0.6.1
arch=amd64  # or arm64
base="https://github.com/ChandanGhosh/dns-rs/releases/download/v$version"
curl -fsSLO "$base/dns-rs-$version-linux-$arch.tar.gz"
curl -fsSLO "$base/SHA256SUMS"
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf "dns-rs-$version-linux-$arch.tar.gz"
cd "dns-rs-$version-linux-$arch"

# The bundle README repeats these steps; see Host service below for the
# service user, state directories, and verification.
sudo install -m 0755 dns-rs /usr/bin/dns-rs
sudo install -o dns-rs -g dns-rs -m 0640 dns-rs.conf /etc/dns-rs/dns-rs.conf
sudo install -m 0644 dns-rs.service /etc/systemd/system/dns-rs.service
```

Create the `dns-rs` user and state directories first as shown in
[Host service](#host-service-systemd). The binary is statically linked, so it
works across glibc versions without additional runtime packages.

## Distro packages

The recipes in [`packaging/`](../packaging/) produce installable `.deb` and
`.rpm` packages from the release tarballs. They install the static binary, the
default configuration as a conffile, the systemd unit, and a `dns-rs` system
user. No Rust toolchain is needed on the build host. Both recipes verify the
downloaded tarball against the release's `SHA256SUMS` before installing it.

Official Debian and Fedora repositories are not targeted. Publish through a
community build service or a signed repository you control.

### Fedora and RHEL with COPR

1. Create a COPR project and submit [`packaging/rpm/dns-rs.spec`](../packaging/rpm/dns-rs.spec).
2. The spec fetches `Source0` from the versioned GitHub release and builds
   natively for `x86_64` and `aarch64`.
3. For each new release, set `Version` to the new workspace version and reset
   `Release` to `1`.

### Debian and Ubuntu with openSUSE Build Service

1. Create an OBS package and copy [`packaging/debian/`](../packaging/debian/)
   into it alongside the RPM spec. OBS uses the spec for RPM targets and the
   `debian/` directory for DEB targets.
2. Enable the Debian and Ubuntu distributions you need for `amd64` and `arm64`.
3. `debian/rules` downloads the matching release tarball during the build; add
   a new `debian/changelog` entry with the new version for each release.

Upgrades keep local edits to `/etc/dns-rs/dns-rs.conf` through the package
manager's conffile handling.

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
docker pull chandanghosh/dns-rs:0.6.1
docker run --rm chandanghosh/dns-rs:0.6.1 --version
```

Images are published for `linux/amd64` and `linux/arm64`. `X.Y.Z` tags are
immutable; `latest` is repointed to the newest release; `DDMMYYYY` tracks the
newest successful `main` build that is still HEAD when the publish job runs.
See [Container publishing](container-publishing.md) for the full tag policy.

## Host service (systemd)

The daemon stays in the foreground and logs to standard output. It does not
daemonize; if started as root it can drop to the configured `username` after
binding its sockets, but the recommended unit runs it as an unprivileged user
from the start. A service manager should own the remaining process concerns. An
example unit is provided at
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
the query pipeline, flushes caches, and applies a new `verbosity`, but listener,
TLS, thread, socket-buffer, and control-socket changes need
`systemctl restart dns-rs.service`.
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
