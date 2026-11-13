# syntax=docker/dockerfile:1.7

# Multi-stage build. The builder cross-compiles a static musl binary on the
# native build platform, and the runtime image is `scratch`: it contains only
# the resolver, its default configuration, and two empty state directories.
#
# Build locally:
#   docker build -t chandanghosh/dns-rs:dev .
#
# Build and verify:
#   scripts/container-smoke.sh
#
# Multi-arch (requires buildx and QEMU only for running the foreign image):
#   docker buildx build --platform linux/amd64,linux/arm64 -t dns-rs:dev .
ARG RUST_VERSION=1.100

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-bookworm AS builder

ARG TARGETARCH
ARG TARGETVARIANT

# Baked into the binary so `dns-rs --version` matches the image label. The
# image tag is the build date (`DDMMYYYY`); `VERSION` is the workspace semver.
ARG VERSION=dev
ARG BUILD_DATE=unknown

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        musl-tools \
        perl \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Select the static musl target for the requested runtime platform.
RUN arch="${TARGETARCH:-amd64}"; variant="${TARGETVARIANT:-}"; \
    case "${arch}${variant}" in \
        amd64) target=x86_64-unknown-linux-musl ;; \
        arm64|arm64v8) target=aarch64-unknown-linux-musl ;; \
        *) echo "unsupported platform: ${arch}${variant}" >&2; exit 1 ;; \
    esac \
    && echo "$target" > /tmp/rust-target \
    && rustup target add "$target"

# Debian provides musl-gcc for amd64. The ARM64 target uses the pinned
# cross-tools musl-cross toolchain, which includes its own linker and libc.
# GitHub releases are used instead of musl.cc because musl.cc is not reliably
# reachable from GitHub-hosted runners. The checksum pins the exact tarball.
ARG AARCH64_MUSL_VERSION=20261001
ARG AARCH64_MUSL_SHA256=7bf54ef24ecbca3f418e6b74ddc055e3a23b2cbf31ffc0b9a25775189df344ad
RUN arch="${TARGETARCH:-amd64}"; \
    if [ "$arch" = "arm64" ]; then \
        url="https://github.com/cross-tools/musl-cross/releases/download/${AARCH64_MUSL_VERSION}/aarch64-unknown-linux-musl.tar.xz"; \
        curl -fsSL --retry 5 --retry-all-errors --retry-delay 5 \
            -o /tmp/aarch64-musl.tar.xz "$url"; \
        echo "${AARCH64_MUSL_SHA256}  /tmp/aarch64-musl.tar.xz" | sha256sum -c -; \
        tar -xJf /tmp/aarch64-musl.tar.xz -C /opt; \
        rm /tmp/aarch64-musl.tar.xz; \
    fi

ENV RUSTFLAGS="-C target-feature=+crt-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C link-arg=-static" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=/opt/aarch64-unknown-linux-musl/bin/aarch64-unknown-linux-musl-gcc \
    CC_aarch64_unknown_linux_musl=/opt/aarch64-unknown-linux-musl/bin/aarch64-unknown-linux-musl-gcc \
    AR_aarch64_unknown_linux_musl=/opt/aarch64-unknown-linux-musl/bin/aarch64-unknown-linux-musl-ar

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# The `dist` profile uses fat LTO, opt-level=2, strip, and panic=abort. It is
# fast enough for the load benchmark while keeping the image under 10 MiB.
# `DNS_RS_VERSION` and `DNS_RS_BUILD_DATE` are read by `main.rs` at compile
# time, so a rebuilt image reports the version it was built from.
RUN target="$(cat /tmp/rust-target)" \
    && DNS_RS_VERSION="${VERSION}" \
       DNS_RS_BUILD_DATE="${BUILD_DATE}" \
       cargo build --locked --profile dist --target "$target" \
        --package dns-daemon --bin dns-rs \
    && mkdir -p /out/var/lib/dns-rs /out/var/cache/dns-rs \
    && cp "target/$target/dist/dns-rs" /out/dns-rs \
    && chown -R 65532:65532 /out/var

FROM scratch AS runtime

# `VERSION` is the workspace semver. The mutable `DDMMYYYY` build date lives in
# `org.opencontainers.image.created`, not in the version label.
ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG SOURCE_URL=""

LABEL org.opencontainers.image.title="dns-rs" \
      org.opencontainers.image.description="Validating, recursive, caching DNS resolver" \
      org.opencontainers.image.licenses="BSD-3-Clause" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="${SOURCE_URL}"

COPY --from=builder /out/dns-rs /usr/local/bin/dns-rs
COPY --chown=65532:65532 packaging/container.toml /etc/dns-rs/dns-rs.toml
COPY --from=builder --chown=65532:65532 /out/var/lib/dns-rs /var/lib/dns-rs
COPY --from=builder --chown=65532:65532 /out/var/cache/dns-rs /var/cache/dns-rs

WORKDIR /etc/dns-rs
USER 65532:65532

EXPOSE 53/udp 53/tcp 853/tcp 443/tcp

# The binary handles SIGTERM and drains in-flight queries.
STOPSIGNAL SIGTERM

# The probe loads the image's default configuration, finds the plain-DNS
# listener, and asks for the built-in localhost. record. Override the config
# path here if you change the container command.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/dns-rs", "-c", "/etc/dns-rs/dns-rs.toml", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/dns-rs"]
CMD ["-c", "/etc/dns-rs/dns-rs.toml", "run"]
