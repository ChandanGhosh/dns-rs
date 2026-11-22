#!/usr/bin/env bash
# Assemble per-architecture release bundles from the static musl binaries.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: scripts/build-release-tarballs.sh --version VERSION --input-dir DIR --output-dir DIR

Input binaries must be named dns-rs-amd64 and dns-rs-arm64. Each output
tarball contains the binary, default configuration, systemd unit, LICENSE,
and a short README; SHA256SUMS covers every tarball in the output directory.
EOF
}

version=""
input_dir=""
output_dir=""

while (($#)); do
    case "$1" in
        --version) version="${2:?--version needs a value}"; shift 2 ;;
        --input-dir) input_dir="${2:?--input-dir needs a value}"; shift 2 ;;
        --output-dir) output_dir="${2:?--output-dir needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
done

if [[ -z "$version" || -z "$input_dir" || -z "$output_dir" ]]; then
    usage >&2
    exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$output_dir"
: >"$output_dir/SHA256SUMS"

for arch in amd64 arm64; do
    (
        binary="$input_dir/dns-rs-$arch"
        if [[ ! -f "$binary" ]]; then
            printf 'missing input binary: %s\n' "$binary" >&2
            exit 1
        fi

        name="dns-rs-$version-linux-$arch"
        staging="$(mktemp -d)"
        trap 'rm -rf "$staging"' EXIT

        install -D -m 0755 "$binary" "$staging/$name/dns-rs"
        install -D -m 0644 "$repo_root/LICENSE" "$staging/$name/LICENSE"
        install -D -m 0644 "$repo_root/packaging/config/dns-rs.conf" \
            "$staging/$name/dns-rs.conf"
        install -D -m 0644 "$repo_root/packaging/systemd/dns-rs.service" \
            "$staging/$name/dns-rs.service"

        cat >"$staging/$name/README.md" <<EOF
# dns-rs $version (linux-$arch)

This bundle contains a statically linked musl binary with no runtime
dependencies beyond a C library-free Linux kernel.

## Contents

- \`dns-rs\` -- resolver binary
- \`dns-rs.conf\` -- default configuration (port 53, RFC 1918 clients only)
- \`dns-rs.service\` -- systemd unit
- \`LICENSE\` -- BSD-3-Clause

## Install

\`\`\`bash
# Verify the bundle against SHA256SUMS from the same release.
sha256sum --check SHA256SUMS --ignore-missing

sudo useradd --system --home-dir /var/lib/dns-rs \\
  --shell /usr/sbin/nologin dns-rs
sudo install -d -o dns-rs -g dns-rs -m 0750 /etc/dns-rs /var/lib/dns-rs /run/dns-rs
sudo install -m 0755 dns-rs /usr/bin/dns-rs
sudo install -o dns-rs -g dns-rs -m 0640 dns-rs.conf /etc/dns-rs/dns-rs.conf
sudo -u dns-rs /usr/bin/dns-rs -c /etc/dns-rs/dns-rs.conf checkconf
sudo install -m 0644 dns-rs.service /etc/systemd/system/dns-rs.service
sudo systemctl daemon-reload
sudo systemctl enable --now dns-rs.service
\`\`\`

The unit grants \`CAP_NET_BIND_SERVICE\` so the unprivileged service can bind
port 53. Check \`systemctl status dns-rs.service\` and resolve a name with
\`dig @127.0.0.1 example.com A\` to confirm the install.

See https://github.com/ChandanGhosh/dns-rs/tree/main/docs/installation.md
for upgrades, reload semantics, and uninstall steps.
EOF

        tar -C "$staging" -czf "$output_dir/$name.tar.gz" "$name"
        (cd "$output_dir" && sha256sum "$name.tar.gz" >>SHA256SUMS)
    )
done

(cd "$output_dir" && sha256sum --check SHA256SUMS)
