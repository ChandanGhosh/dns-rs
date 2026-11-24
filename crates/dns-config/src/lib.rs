//! Typed configuration for dns-rs.
//!
//! The internal representation is deliberately independent of the on-disk format.
//! Two front-ends are supported:
//!
//! - TOML (`.toml`) for native configuration and tooling.
//! - A practical subset of Unbound's `unbound.conf` syntax for drop-in adoption.
//!
//! Unsupported Unbound options are reported as warnings instead of hard failures so
//! that an existing configuration can be brought over incrementally.

mod error;
mod gateway;
mod hints;
mod model;
mod parser;
mod warnings;

pub use error::{ConfigError, ConfigWarning, LoadedConfig};
pub use gateway::default_gateways;
pub use hints::{RootHintsError, load_root_hints, parse_root_hints};
pub use model::{
    AccessAction, AccessControl, AccessControlView, AuthZoneConfig, Config, ForwardTarget,
    ForwardZoneConfig, LOCAL_DATA_DEFAULT_TTL, ListenAddress, LocalZoneConfig, LocalZoneType,
    RemoteControlConfig, ServerConfig, StubZoneConfig, ThreadCount, ViewConfig, local_domains,
    parse_local_data,
};
pub use parser::parse_unbound_str;

use std::path::Path;

/// Load and validate a configuration file.
///
/// Files ending in `.toml` are parsed as native configuration; everything else is
/// parsed as an `unbound.conf`-style file.
pub fn load(path: impl AsRef<Path>) -> Result<LoadedConfig, ConfigError> {
    let path = path.as_ref();
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
    {
        load_toml(path)
    } else {
        parser::parse_unbound_file(path)
    }
}

fn load_toml(path: &Path) -> Result<LoadedConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let config: Config = toml::from_str(&text).map_err(|source| ConfigError::Toml {
        path: path.to_path_buf(),
        source,
    })?;
    config.validate()?;
    let warnings = warnings::unenforced(&config, path);
    Ok(LoadedConfig { config, warnings })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::load;

    #[test]
    fn toml_reports_unenforced_options() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.toml");
        fs::write(
            &path,
            r#"
[server]
interfaces = ["127.0.0.1"]
port = 5353
chroot = "/var/lib/dns-rs"
directory = "/var/lib/dns-rs"
logfile = "/var/log/dns-rs.log"
pidfile = "/run/dns-rs.pid"
use_syslog = true
do_daemonize = true
"#,
        )
        .expect("write config");

        let loaded = load(&path).expect("load config");
        for key in [
            "chroot",
            "directory",
            "do-daemonize",
            "logfile",
            "pidfile",
            "use-syslog",
        ] {
            assert!(
                loaded
                    .warnings
                    .iter()
                    .any(|warning| warning.message.contains(key)),
                "missing warning for {key}: {:?}",
                loaded.warnings
            );
        }
    }

    #[test]
    fn toml_defaults_report_no_warnings() {
        let directory = tempdir().expect("tempdir");
        let path = directory.path().join("dns-rs.toml");
        fs::write(
            &path,
            "[server]\ninterfaces = [\"127.0.0.1\"]\nport = 5353\n",
        )
        .expect("write config");

        let loaded = load(&path).expect("load config");
        assert!(loaded.warnings.is_empty(), "{:?}", loaded.warnings);
    }
}
