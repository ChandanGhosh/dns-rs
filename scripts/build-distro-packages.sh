#!/usr/bin/env bash
# Build .deb and .rpm packages from local release tarballs using Docker.
# No Rust toolchain or native packaging tools are needed on the build host.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build-distro-packages.sh --tarball-dir DIR --output-dir DIR

Build Debian and RPM packages for amd64/arm64 from release tarballs already
present on disk. Each build runs in a container and verifies the tarball
against the release SHA256SUMS before installing it.

Arguments:
  --tarball-dir DIR       Directory holding the release tarballs and SHA256SUMS
  --output-dir DIR        Directory to receive the built packages and checksums
  -h, --help              Show this help text
EOF
}

tarball_dir=""
output_dir=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --tarball-dir)
            tarball_dir="${2:-}"
            shift 2
            ;;
        --output-dir)
            output_dir="${2:-}"
            shift 2
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            printf 'error: unknown argument: %s\n' "$1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [ -z "$tarball_dir" ] || [ -z "$output_dir" ]; then
    printf 'error: --tarball-dir and --output-dir are both required\n' >&2
    usage >&2
    exit 1
fi

if [ ! -d "$tarball_dir" ]; then
    printf 'error: tarball directory does not exist: %s\n' "$tarball_dir" >&2
    exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
tarball_dir="$(cd "$tarball_dir" && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

build_deb() {
    local arch="$1"
    local image
    if [ "$arch" = "amd64" ]; then
        image="debian:bookworm"
    else
        image="arm64v8/debian:bookworm"
    fi

    local build_dir
    build_dir="$(mktemp -d)"
    # The Debian recipe downloads from a URL by default; point it at the local
    # tarballs so CI does not refetch assets it already built.
    cp -a "$repo_root/packaging/debian" "$build_dir/debian"
    sed -i "s#^base := .*#base := file:///src#" "$build_dir/debian/rules"

    docker run --rm --platform "linux/$arch" \
        -v "$tarball_dir:/src:ro" \
        -v "$build_dir:/work" \
        -v "$output_dir:/out" \
        -w /work \
        "$image" bash -lc '
            set -euo pipefail
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends \
                build-essential debhelper dpkg-dev curl ca-certificates >/dev/null
            dpkg-buildpackage -us -uc -b
            cp ../*.deb /out/
            find /work -mindepth 1 -delete
        '
    rm -rf "$build_dir"
}

build_rpm() {
    local arch="$1"
    local image
    if [ "$arch" = "amd64" ]; then
        image="fedora:41"
    else
        image="arm64v8/fedora:41"
    fi

    docker run --rm --platform "linux/$arch" \
        -v "$tarball_dir:/src:ro" \
        -v "$repo_root/packaging/rpm:/recipe:ro" \
        -v "$output_dir:/out" \
        "$image" bash -lc '
            set -euo pipefail
            dnf install -y -q rpm-build systemd-rpm-macros >/dev/null
            mkdir -p /root/rpmbuild/SOURCES /root/rpmbuild/SPECS
            cp /src/*.tar.gz /src/SHA256SUMS /root/rpmbuild/SOURCES/
            cp /recipe/dns-rs.spec /root/rpmbuild/SPECS/
            rpmbuild -ba /root/rpmbuild/SPECS/dns-rs.spec >/dev/null
            find /root/rpmbuild/RPMS -name "*.rpm" -exec cp {} /out/ \;
        '
}

for arch in amd64 arm64; do
    printf 'building Debian package for %s\n' "$arch"
    build_deb "$arch"
    printf 'building RPM package for %s\n' "$arch"
    build_rpm "$arch"
done

printf 'generating PACKAGES_SHA256SUMS\n'
(
    cd "$output_dir"
    sha256sum *.deb *.rpm > PACKAGES_SHA256SUMS
)

printf 'packages written to %s:\n' "$output_dir"
find "$output_dir" -maxdepth 1 -type f -printf '%f %s bytes\n' | sort
