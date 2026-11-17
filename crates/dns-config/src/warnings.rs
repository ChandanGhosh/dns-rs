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
}
