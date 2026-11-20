# Contributing to dns-rs

Thanks for helping improve dns-rs. This page covers the practical workflow. Read
the [Architecture](docs/architecture.md) guide to find the right crate, and the
[Limitations](docs/limitations.md) page before adding a feature that may already
be explicitly out of scope. The agent-specific rules used by automated
contributors are in [AGENTS.md](AGENTS.md).

## Development environment

- Rust 1.100 or newer, matching `rust-version` in `Cargo.toml`.
- `make`, Git, and a C toolchain for dependencies such as `ring`.
- Docker for container smoke tests. Not required for host-only changes.
- `dig` or `drill` for manual query checks. The `delv` corpus test is skipped
  when `delv` is absent.

Install optional CI tools with `make tools`, and check what is present with
`make doctor`.

## Build and validate

```bash
make help            # list every target and variable
make build           # format the workspace, then debug-build all crates
make release         # build the release dns-rs binary
make fmt-check       # cargo fmt --all --check
make clippy          # cargo clippy --workspace --all-targets --all-features -- -D warnings
make test            # nextest when installed, otherwise cargo test
make test-doc        # doctests
make check           # fmt-check + clippy + tests + deny + checkconf-examples
make ci              # check + audit + fuzz smoke
make ci-container    # container smoke, load stats, size gate, Trivy scan
```

CI runs on every branch push and pull request on `ubuntu-latest`. It uses stable
Rust for formatting, Clippy, and tests, nightly Rust for fuzzing, and a Rust
1.100 Docker builder for images. Fuzzing covers all three targets
(`decode_message`, `parse_unbound_config`, `parse_toml_config`) in CI; the local
`make fuzz` wrapper runs only `decode_message`.

Never set `RUSTFLAGS` or `target-cpu=native` for benchmarks, and never run
benchmarks in parallel. See [Benchmarking](docs/benchmarking.md).

## Branches and pull requests

Pull requests must come from a branch named `<type>/<description>`, for example
`feature/control-socket`, `bugfix/cache-expiry`, `docs/benchmark-refresh`, or
`chore/bump-deps`. Accepted types:

`feature`, `bugfix`, `chore`, `docs`, `test`, `refactor`, `perf`, `ci`, `build`,
`hotfix`, `release`, `dependabot`, `renovate`.

Each slash-separated component must be non-empty and must not start with a dot;
nested components are allowed for every prefix. The `Branch name` job checks
this on pull requests only.

Use a clear, imperative commit subject, conventionally
`type(scope): summary`, for example `fix(dnssec): reject excessive NSEC3 iterations`.
Keep commits focused. Do not commit commented-out code, debug prints, or
credentials. Never add `Co-authored-by` lines without the contributor's explicit
request.

Before opening a pull request:

- all tests, Clippy, formatting, and `checkconf` examples pass;
- user-facing behavior has a matching documentation update;
- new public items have doc comments;
- new or changed code has unit tests;
- public APIs and configuration changes are described in the PR body;
- the security impact is considered, and vulnerabilities are reported privately
  through [SECURITY.md](SECURITY.md).

Pull requests from forks do not receive repository secrets, so container
publishing is limited to the canonical repository. Only repository writers can
push branches; enable branch protection with code-owner review for
`.github/workflows/` when available.

## Documentation is part of the change

Update the right canonical page rather than duplicating a long explanation:

| Change | Update |
|---|---|
| Configuration field | [Configuration](docs/configuration.md), both annotated examples, and [Unbound compatibility](docs/unbound-compatibility.md) if applicable |
| New CLI command or flag | [Operations](docs/operations.md) and [Quick start](docs/quickstart.md) if it affects onboarding |
| Deployment behavior | [Installation](docs/installation.md) or [Container image](docs/container.md) |
| Supported/unsupported feature | [Limitations](docs/limitations.md) and the README status summary |
| Benchmark change | [Benchmarking](docs/benchmarking.md) and a new result page if numbers are published |
| New crate or pipeline stage | [Architecture](docs/architecture.md) |

The documentation index is [docs/README.md](docs/README.md).

## Releases

The workspace version in `Cargo.toml` is the release version. Do not bump it in
an ordinary change. Discuss whether a release is needed and which semver level
is appropriate with the maintainers first. The `Release version` CI job rejects
a version that is not strictly newer than the latest `v*` tag or that is set on
an individual crate instead of `version.workspace = true`. Release notes are
generated from commits since the previous tag; see
[Container publishing](docs/container-publishing.md) for tag rules.
