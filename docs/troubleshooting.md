# Troubleshooting

Start with the observed symptom. Each entry lists safe checks and the data to
collect if the problem persists. Do not paste private keys, tokens, or client
data into an issue.

## First checks

```bash
dns-rs -c <file> checkconf
dns-rs -c <file> healthcheck
dig @<listener> -p <port> localhost. A
dig @<listener> -p <port> example.com A
```

`localhost.` is served from built-in local data, so it isolates the listener
from upstream connectivity. `checkconf` warnings are compatibility notes;
invalid values, duplicate zones, and a missing `interface:` are fatal.

## The service exits immediately or will not start

| Likely cause | Check | Fix |
|---|---|---|
| Configuration error | `dns-rs -c <file> checkconf` | Correct the reported line or value. |
| No interface configured | `checkconf` reports `at least one interface must be configured` | Add `interface:` / `interfaces`. An `unbound.conf` with no interface fails to load; it does not start with zero listeners. |
| Port 53 already in use | `ss -lunp`, `ss -ltnp` | Stop the other resolver, use a high port, or grant `CAP_NET_BIND_SERVICE`. |
| TLS files unreadable | Startup log names the file | Mount readable PEM files. `checkconf` does not read them. |
| Control socket parent invalid | Startup log names the path | Use an absolute path whose parent is not group/world-writable without the sticky bit. |
| Container exits with code 137 | `docker inspect dns-rs --format '{{.State.OOMKilled}} {{.State.ExitCode}}'`, `docker events --filter container=dns-rs` | A 137 is a signal kill, commonly OOM or an external stop. Inspect host memory and events; a configuration warning alone cannot cause it. |

## Queries time out

- Confirm the listener: `healthcheck`, then `dig` from the same host.
- In Docker, check published ports for **both** UDP and TCP, and bind to
  `0.0.0.0` inside the container. `127.0.0.1` inside a container is not the
  Docker bridge address.
- Check host and cloud firewalls for UDP/TCP 53.
- Check the ACL. With no matching `access-control` rule a client receives
  `REFUSED`, not a timeout. The most specific matching netblock wins regardless
  of statement order; a broad `0.0.0.0/0 refuse` placed before a more specific
  `allow` does not override it.

## Responses are `REFUSED`

The client address matched no rule, or matched a `refuse` / `refuse_non_local`
rule. Add a rule for the client network. In TOML, entries are strings such as
`"10.0.0.0/8 allow"` in `access_control`. Remember that explicit rules replace
the built-in list rather than appending to it.

## Responses are `SERVFAIL` with a bogus-DNSSEC extended error

- Check the clock first. DNSSEC validation fails with significant skew.
- Try another upstream or a plain-DNS forwarder on a trusted network.
- For one known-broken subtree, add `domain-insecure = ["broken.example"]` (TOML)
  or `domain-insecure: "broken.example"` (Unbound syntax). This is a static
  negative trust anchor: it never expires and is never created automatically.
- Avoid `val_permissive_mode`. It still validates but returns bogus data with
  `AD=0` globally, which hides real failures.
- If port 53 is intercepted by a gateway, cached names keep working while fresh
  names fail. Use a DoT forward zone with `forward-fallback: yes` rather than
  replacing iteration entirely.

## Fresh names fail but cached names work

This is the signature of broken upstream iteration: port 53 filtering, no
outbound IPv6 with `do-ip6: yes`, an empty or incorrect root-hints file, or a
looping forwarder. Check `docker logs` for `iteration failed; falling back to
forwarders`, verify outbound UDP/TCP 53, and make sure a local stub does not
forward back to dns-rs.

## `checkconf` reports warnings

Warnings mean an option was recognized but is not enforced, or a file such as an
include or root-hints file was not found. They do not stop startup and they do
not cause a container exit. Treat them as migration TODOs: a missing include
may have supplied local data, forwarders, or trust anchors. Invalid values and
duplicate zones are errors, not warnings.

## TOML configuration fails after adding a key

Root-level arrays such as `local_data`, `local_zones`, and `forward_zones` must
appear before the first table header. After `[server]`, TOML treats them as
server fields and loading fails. Zone names need a trailing dot and policies use
kebab-case (`always-nxdomain`). See [Configuration](configuration.md#toml-layout).

## DoT or DoH listener is not reachable

Both `tls_service_key` and `tls_service_pem` must be set, and a listener must use
the matching port (`853` or `443`). The protocol is selected by port. Certificate
rotation at the same path needs a restart because the acceptor is built at
startup. Upstream TLS uses the compiled-in `webpki-roots` set by default; use
`tls_cert_bundle` for private CAs.

## The container is `healthy` but resolution is broken

The built-in healthcheck asks for `localhost.` on the first plain-DNS listener.
It proves the listener is alive, not that upstreams, DNSSEC, or ACLs work. Run a
real query and inspect `docker logs`. If you mounted a custom configuration
with a different `-c` path, override the healthcheck too; otherwise Docker may
report unhealthy for the wrong reason.

## No control commands or metrics

The control socket is disabled in the shipped configuration. Enable
`remote-control` with an absolute socket path, mount a writable directory, and
restart. Use the same UID as the daemon (`docker exec` without `-u`), because
peer credentials are checked and the socket is mode `0600`. There is no HTTP
metrics endpoint.

## Memory or CPU is higher than expected

- mimalloc raises idle RSS compared with the system allocator; compare `VmRSS`
  and `VmHWM` inside the process rather than only `docker stats`, which includes
  page cache and tmpfs.
- Caches are bounded by entry count, not bytes. Raise or lower cache TTL bounds
  and entry counts deliberately.
- `num_threads` defaults to 1; `0` or `"auto"` uses every CPU visible to the
  process. On Linux each worker uses its own `SO_REUSEPORT` socket.
- Benchmark numbers are workload-specific and noisy. Read
  [Benchmarking](benchmarking.md) before comparing a local run with the
  published results.

## Escalating a bug

Include the dns-rs version (`dns-rs --version`), the exact configuration with
secrets removed, the command line, the OS and container runtime, a short log
excerpt, the `dig` output, and whether a reload or restart changes the behavior.
Report security issues privately through [SECURITY.md](../SECURITY.md).
