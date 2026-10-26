# dns-rs

A validating, recursive, caching DNS resolver written in Rust, designed around the
behavior and operational model of [Unbound](https://github.com/NLnetLabs/unbound).

> **Status: M0 foundations.** The workspace, configuration loader, CLI, codecs
> facade, cache primitive, and CI are in place. The resolver itself starts in M1.

## Quick start

```bash
# Validate a configuration
cargo run -p dns-daemon -- checkconf -c examples/minimal.conf

# Run the daemon (M0 lifecycle skeleton; listeners arrive in M1)
cargo run -p dns-daemon -- run -c examples/minimal.conf
```

Use `-v` for debug logging and `-vv` for trace logging. `RUST_LOG` overrides the
CLI verbosity.

## Workspace

| Crate | Responsibility |
|---|---|
| `dns-proto` | DNS wire types and codecs, isolated behind one dependency facade |
| `dns-config` | Typed configuration plus an `unbound.conf` subset parser |
| `dns-cache` | TTL-aware cache primitives; RRset/message/infra caches in M3 |
| `dns-client` | Upstream UDP/TCP/TLS/HTTPS/QUIC transports |
| `dns-iter` | Iterative resolution |
| `dns-dnssec` | DNSSEC validation and crypto primitives |
| `dns-filter` | Local zones, views, RPZ, response IP filtering, DNS64 |
| `dns-server` | Downstream listeners, ACLs, EDNS, query pipeline |
| `dns-control` | Control socket and statistics |
| `dns-daemon` | `dns-rs` binary, lifecycle, reload, privilege drop |
| `dns-testutil` | Mock authoritative server, packet builders, replay harness support |

## Configuration

Two front-ends are supported:

- **TOML** for native configuration and tooling.
- A practical **`unbound.conf` subset** for incremental migration. Unsupported
  options are reported as warnings, not fatal errors.

Supported `unbound.conf` blocks in M0:

- `server:` — interfaces, port, verbosity, threads, daemonize, user/chroot/directory,
  log file, PID file, syslog, IPv4/IPv6, UDP/TCP, outgoing interfaces, access control
- `forward-zone:` — name, forward addresses, forward-first. `forward-host` and
  `forward-tls-upstream` are parsed but not yet implemented; they log a warning
  and plain-DNS forwarding is used.
- `remote-control:` — enable, interface, port
- `include:` — relative or absolute files, with cycle detection

Everything else is accepted with a warning and ignored.

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --doc
```

CI additionally runs `cargo nextest`, `cargo deny`, and `cargo audit`.

Architecture decisions live in [`docs/adr/`](docs/adr/). The Unbound replay
harness design is in [`docs/replay-harness.md`](docs/replay-harness.md).

## License

BSD-3-Clause. Unbound is also BSD-3-Clause; this project is a clean-room
implementation and only reuses test vectors with attribution.
