# Fedora/RHEL-family recipe. The binary comes from the static musl release
# bundle, so no Rust toolchain is needed on the build host. Bump Version and
# Release together with Cargo.toml for each new release.
%global debug_package %{nil}

%ifarch x86_64
%global tarball_arch amd64
%else
%ifarch aarch64
%global tarball_arch arm64
%else
%{error:unsupported architecture %{_arch}}
%endif
%endif

Name:           dns-rs
Version:        0.6.9
Release:        1%{?dist}
Summary:        Validating, recursive, caching DNS resolver

License:        BSD-3-Clause
URL:            https://github.com/ChandanGhosh/dns-rs
Source0:        https://github.com/ChandanGhosh/dns-rs/releases/download/v%{version}/dns-rs-%{version}-linux-%{tarball_arch}.tar.gz
Source1:        https://github.com/ChandanGhosh/dns-rs/releases/download/v%{version}/SHA256SUMS

BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires(pre):  shadow-utils

%description
dns-rs is a validating, recursive, caching DNS resolver with an
Unbound-compatible configuration format, DNSSEC validation, and a local
control socket. The systemd service binds port 53 as an unprivileged user.

%prep
# Verify the downloaded bundle against the checksums published with it.
expected="$(awk -v f='dns-rs-%{version}-linux-%{tarball_arch}.tar.gz' '$2 == f { print $1 }' '%{SOURCE1}')"
actual="$(sha256sum '%{SOURCE0}' | awk '{ print $1 }')"
if [ -z "$expected" ] || [ "$expected" != "$actual" ]; then
    echo "SHA256 mismatch for %{SOURCE0}" >&2
    exit 1
fi
%setup -q -n dns-rs-%{version}-linux-%{tarball_arch}

%install
install -D -m 0755 dns-rs %{buildroot}%{_bindir}/dns-rs
install -D -m 0640 dns-rs.conf %{buildroot}%{_sysconfdir}/dns-rs/dns-rs.conf
install -D -m 0640 zones.d/local-zones.conf \
    %{buildroot}%{_sysconfdir}/dns-rs/zones.d/local-zones.conf
install -D -m 0644 dns-rs.service %{buildroot}%{_unitdir}/dns-rs.service
install -d -m 0750 %{buildroot}%{_sharedstatedir}/dns-rs

%files
%license LICENSE
%{_bindir}/dns-rs
%dir %attr(0750,root,dns-rs) %{_sysconfdir}/dns-rs
%attr(0640,root,dns-rs) %config(noreplace) %{_sysconfdir}/dns-rs/dns-rs.conf
%dir %attr(0750,root,dns-rs) %{_sysconfdir}/dns-rs/zones.d
%attr(0640,root,dns-rs) %config(noreplace) %{_sysconfdir}/dns-rs/zones.d/local-zones.conf
%{_unitdir}/dns-rs.service
%dir %attr(0750,dns-rs,dns-rs) %{_sharedstatedir}/dns-rs

%pre
getent passwd dns-rs >/dev/null || \
    useradd --system --user-group --home-dir %{_sharedstatedir}/dns-rs \
        --shell /usr/sbin/nologin dns-rs
exit 0

%post
%systemd_post dns-rs.service

%preun
%systemd_preun dns-rs.service

%postun
%systemd_postun_with_restart dns-rs.service

%changelog
* Sun Nov 22 2026 Chandan Ghosh <ckghosh1983@gmail.com> - 0.6.3-1
- Publish prebuilt deb and rpm packages with each release.

* Sun Nov 22 2026 Chandan Ghosh <ckghosh1983@gmail.com> - 0.6.2-1
- Point the systemd unit at the packaged binary path.

* Sun Nov 22 2026 Chandan Ghosh <ckghosh1983@gmail.com> - 0.6.1-1
- Package the static release bundle with a systemd service.
