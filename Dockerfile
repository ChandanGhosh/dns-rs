# syntax=docker/dockerfile:1.7

# Multi-stage build. The builder compiles the workspace, and the runtime image
# contains only the resolver binary, its default configuration, and glibc.
#
# Build locally:
#   docker build -t dns-rs:dev .
#
# Build and verify:
#   scripts/container-smoke.sh
#
# Multi-arch (requires buildx and QEMU):
#   docker buildx build --platform linux/amd64,linux/arm64 -t dns-rs:dev .
ARG RUST_VERSION=1.99

FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

# Compile the pinned dependency graph. The release profile already strips
# debug info, so the copied binary stays small.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --locked --release --package dns-daemon --bin dns-rs

# Prepare writable state directories with the distroless non-root UID.
RUN mkdir -p /out/var/lib/dns-rs /out/var/cache/dns-rs \
    && chown -R 65532:65532 /out

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

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

WORKDIR /etc/dns-rs

COPY --from=builder /build/target/release/dns-rs /usr/local/bin/dns-rs
COPY --chown=65532:65532 packaging/container.toml /etc/dns-rs/dns-rs.toml
COPY --from=builder --chown=65532:65532 /out/var/lib/dns-rs /var/lib/dns-rs
COPY --from=builder --chown=65532:65532 /out/var/cache/dns-rs /var/cache/dns-rs

USER nonroot:nonroot

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
