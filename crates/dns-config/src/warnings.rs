//! Messages for options that are parsed but not enforced.

use std::path::Path;

use crate::error::ConfigWarning;
use crate::model::Config;

pub(crate) const DO_DAEMONIZE: &str =
    "do-daemonize is parsed but not enforced; run the resolver under a process supervisor";
pub(crate) const CHROOT: &str =
    "chroot is parsed but not enforced; the resolver does not change its root directory";
pub(crate) const DIRECTORY: &str =
    "directory is parsed but not enforced; the resolver does not change its working directory";
pub(crate) const LOGFILE: &str =
    "logfile is parsed but not enforced; collect logs from stderr or the process supervisor";
pub(crate) const PIDFILE: &str =
    "pidfile is parsed but not enforced; track the process through its supervisor";
pub(crate) const USE_SYSLOG: &str = "use-syslog is parsed but not enforced; logs go to stderr";
pub(crate) const TLS_ENFORCE_NAME_CHECK: &str =
    "tls-enforce-name-check is not an Unbound option and is not enforced; remove it";
pub(crate) const UNBLOCK_LAN_ZONES: &str =
    "unblock-lan-zones: no is not implemented; private reverse zones are always resolved upstream";
pub(crate) const AUTH_TRANSFER: &str = "auth-zone primary/url/fallback-enabled are parsed but not enforced; zone transfers and downloads are not implemented";
pub(crate) const ALLOW_COOKIE: &str =
    "access-control action allow_cookie is not enforced yet; treating the network as allow";

/// Warnings for every unenforced option that is set in `config`.
///
/// TOML has no line numbers, so these warnings use line 0. The
/// `unbound.conf` parser emits the same messages at the option's own line.
pub(crate) fn unenforced(config: &Config, path: &Path) -> Vec<ConfigWarning> {
    let mut warnings = Vec::new();
    let mut push = |message: &str| {
        warnings.push(ConfigWarning {
            path: path.to_path_buf(),
            line: 0,
            message: message.to_owned(),
        });
    };
    if config.server.do_daemonize {
        push(DO_DAEMONIZE);
    }
    if config.server.chroot.is_some() {
        push(CHROOT);
    }
    if config.server.directory.is_some() {
        push(DIRECTORY);
    }
    if config.server.logfile.is_some() {
        push(LOGFILE);
    }
    if config.server.pidfile.is_some() {
        push(PIDFILE);
    }
    if config.server.use_syslog {
        push(USE_SYSLOG);
    }
    if config.server.tls_enforce_name_check {
        push(TLS_ENFORCE_NAME_CHECK);
    }
    if config.server.unblock_lan_zones == Some(false) {
        push(UNBLOCK_LAN_ZONES);
    }
    let mut reported_transfer = false;
    for zone in &config.auth_zones {
        if !reported_transfer
            && (!zone.primaries.is_empty() || !zone.urls.is_empty() || zone.fallback_enabled)
        {
            push(AUTH_TRANSFER);
            reported_transfer = true;
        }
    }
    if config
        .server
        .access_control
        .iter()
        .any(|control| control.action == crate::model::AccessAction::AllowCookie)
    {
        push(ALLOW_COOKIE);
    }
    warnings
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::model::Config;

    #[test]
    fn reports_every_set_option() {
        let config: Config = toml::from_str(
            r#"
[server]
chroot = "/var/lib/dns-rs"
directory = "/var/lib/dns-rs"
logfile = "/var/log/dns-rs.log"
pidfile = "/run/dns-rs.pid"
use_syslog = true
do_daemonize = true
"#,
        )
        .expect("config");

        let warnings = super::unenforced(&config, Path::new("dns-rs.toml"));
        assert_eq!(warnings.len(), 6);
        for key in [
            "chroot",
            "directory",
            "do-daemonize",
            "logfile",
            "pidfile",
            "use-syslog",
        ] {
            assert!(
                warnings.iter().any(|warning| warning.message.contains(key)),
                "missing warning for {key}: {warnings:?}"
            );
        }
        assert!(warnings.iter().all(|warning| warning.line == 0));
    }

    #[test]
    fn reports_nothing_for_defaults() {
        let warnings = super::unenforced(&Config::default(), Path::new("dns-rs.toml"));
        assert!(warnings.is_empty());
    }

    #[test]
    fn reports_unenforced_compatibility_options() {
        let config: Config = toml::from_str(
            r#"
[server]
tls_enforce_name_check = true
unblock_lan_zones = false
access_control = ["192.0.2.0/24 allow_cookie"]

[[auth_zones]]
name = "example."
primaries = ["192.0.2.1"]
"#,
        )
        .expect("config");

        let warnings = super::unenforced(&config, Path::new("dns-rs.toml"));
        for key in [
            "tls-enforce-name-check",
            "unblock-lan-zones",
            "auth-zone",
            "allow_cookie",
        ] {
            assert!(
                warnings.iter().any(|warning| warning.message.contains(key)),
                "missing warning for {key}: {warnings:?}"
            );
        }
    }
}
