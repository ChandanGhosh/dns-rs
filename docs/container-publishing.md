# Container publishing

Audience: maintainers and release managers. Users only need the tag policy in
[Container image](container.md#published-images); this page explains how tags,
GitHub releases, and CI gates are produced. Last reviewed for dns-rs 0.6.0 on
2026-11-20.

## Tag policy

Published images live under `chandanghosh/dns-rs`. Every push carries
`linux/amd64` and `linux/arm64` manifests plus BuildKit SBOM and provenance
attestations.

| Tag | Mutable? | Published when |
|---|---|---|
| `DDMMYYYY` (UTC) | Yes | Every successful `main` build; a later commit the same day repoints it |
| `X.Y.Z` | No | The workspace version is newer than every existing `v*` tag |
| `latest` | Yes | Alongside each `X.Y.Z` release; repointed at the newest release |
| `sha256:...` digest | No | Available for every pushed manifest |

`X.Y.Z` tags and digests are the production pins. `latest` and date tags are
convenience aliases. The current release at the time of writing is `0.6.0`.

The version compiled into the binary comes from `[workspace.package] version`
in `Cargo.toml` through the `VERSION` Docker build argument, which the
Dockerfile exports as `DNS_RS_VERSION` at compile time. A release image and its
`--version` output therefore agree. Date tags are build metadata only; they are
not part of the semver.

## Automatic release flow

The `publish` job in `.github/workflows/ci.yml` runs only for pushes to `main`
in the canonical repository, after all other jobs pass. A `publish-main`
concurrency group prevents overlapping releases, and the job skips publishing
if a newer `main` commit landed while the run was in progress.

The job then:

1. Reads the workspace version and computes the UTC date tag.
2. Compares the version with existing `v*` tags.
3. Always pushes the date-tagged multi-arch image.
4. Pushes `X.Y.Z` and `latest`, creates the annotated `vX.Y.Z` tag, and opens a
   GitHub Release when the version is newer or its tag already points at this
   commit.
5. Leaves an existing GitHub Release unchanged when re-running the same commit.

Release notes list commits since the previous release tag, followed by a full
changelog compare link, the image tags, digest, platforms, revision, build
time, and workflow run. Date-tag pushes that happen before the next semver bump
appear in those notes when the release is cut.

Versioned tags are immutable. The `vX.Y.Z` Git tag is never moved; if it exists
at another commit, the job fails instead of reusing it. Keep one release bump
in flight at a time: two pull requests that bump to the same version can both
pass before the first tag exists, and only the first merge releases.

## Version rules

`[workspace.package] version` is the single source of truth. Each crate must use
`version.workspace = true`. The `Release version` CI job rejects a version that
is not strictly newer than the latest `v*` tag, reuses a tag at another commit,
or leaves `Cargo.lock` out of date.

Use conventional semver:

- **major** for incompatible configuration or behavior changes;
- **minor** for backward-compatible features;
- **patch** for fixes and internal changes.

While the project is `0.x`, a minor bump may still change configuration
behavior. An ordinary change should not bump the version; discuss the release
level with the maintainers first.

## CI gates

Publishing depends on `fmt`, `clippy`, `test`, `container`, `deny`, `audit`,
`fuzz`, and `version`. The container job builds the image, runs the hardened
smoke test, enforces a 10 MiB uncompressed image-size limit, and scans with
Trivy for `CRITICAL` and `HIGH` findings while ignoring unfixed issues.

The container job also writes loopback load stats to the workflow summary. The
summary states a target of one worker at or above 50,000 QPS with p99 at or
below 1 ms, but explicitly marks it informational: the step fails only on a
benchmark, server, or process error. See [Benchmarking](benchmarking.md) for
methodology.

CI fuzzes all three targets (`decode_message`, `parse_unbound_config`, and
`parse_toml_config`) with nightly Rust. The local `make fuzz` wrapper runs only
`decode_message`.

Cross-compilation happens on the native build platform through
`FROM --platform=$BUILDPLATFORM`. QEMU is needed only when a workflow must run
a foreign-architecture image for smoke testing; the manual workflow configures
it, while the main publish job relies on native cross-compilation.

## Publishing by hand

Repository secrets `DOCKER_USERNAME` and `DOCKER_TOKEN` are required, with the
legacy `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` names accepted as fallback.
The token should be a Docker Hub access token with write scope, not a password.

The guarded Make target requires both `TAG` and `CONFIRM=1`:

```bash
docker login
make image-publish TAG=dev CONFIRM=1
```

The equivalent raw command is:

```bash
TAG=dev
VERSION="$(make -s version)"
docker login
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --tag "chandanghosh/dns-rs:$TAG" \
  --build-arg VERSION="$VERSION" \
  --build-arg VCS_REF="$(git rev-parse HEAD)" \
  --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --build-arg SOURCE_URL="$(git remote get-url origin)" \
  --provenance=mode=max --sbom=true \
  --push .
```

For an explicit dev or hotfix tag, run the manual `Container` workflow with a
`tag` input and `push` enabled. It pushes
`docker.io/chandanghosh/dns-rs:<tag>` with an SBOM and provenance attestation.
Neither the automatic nor the manual workflow runs on Git tag pushes, so
pushing a tag by hand does not publish an image.

## Verify a published image

```bash
docker buildx imagetools inspect docker.io/chandanghosh/dns-rs:0.6.0
docker run --rm --platform linux/amd64 \
  docker.io/chandanghosh/dns-rs:0.6.0 --version
docker run --rm --platform linux/arm64 \
  docker.io/chandanghosh/dns-rs:0.6.0 --version
```

For a security-sensitive deployment, pin the digest printed by `imagetools
inspect` and verify it before rollout.
