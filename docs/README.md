# dns-rs documentation

Start here if you want to run dns-rs, configure it, deploy it, or contribute.
The [project README](../README.md) is a short orientation page; this index is
the map of the full documentation set.

## Start here

- [Quick start](quickstart.md) — build or pull, run, and verify a resolver in a
  few minutes.
- [Installation](installation.md) — support tiers, source builds, container
  images, and a host systemd service.
- [Configuration](configuration.md) — file formats, CLI precedence, the TOML
  reference, and what reload can and cannot change.

## Use it

- [Container image](container.md) — image layout, `docker run`, Compose,
  Kubernetes, configuration formats, zones, blocklists, monitoring, and
  troubleshooting.
- [Operations](operations.md) — control socket, commands, stats, logs, signals,
  healthchecks, and an upgrade checklist.
- [Troubleshooting](troubleshooting.md) — symptom-first checks for startup,
  resolution, DNSSEC, containers, and performance.
- [Limitations](limitations.md) — what MVP1 does not do, platform caveats, and
  benchmark gaps.

## Reference

- [Architecture](architecture.md) — crates and the query path.
- [Benchmarking](benchmarking.md) — runners, switches, methodology, and known
  gaps. Published results are under [benchmark-results/](benchmark-results/).
- [Unbound migration](unbound-migration.md) — moving an existing
  `unbound.conf` deployment.
- [Unbound compatibility](unbound-compatibility.md) — compatibility matrix and
  differences.
- [Replay harness design](replay-harness.md) — design only; not implemented.
- [Container publishing](container-publishing.md) — tags, releases, and CI
  gates for maintainers.

## Project

- [Contributing guide](../CONTRIBUTING.md) — how to prepare and submit a change.
- [Security policy](../SECURITY.md) — reporting vulnerabilities and supported
  versions.
- [License](../LICENSE) — BSD-3-Clause.

## Documentation conventions

Guides state their audience and prerequisites where useful, include verification
steps for practical workflows, and link to the canonical reference for details.
Numbers that depend on a particular host are labelled with the version, date, and
hardware they were measured on. Statements about unsupported features point to
[Limitations](limitations.md) rather than being repeated in several places.
