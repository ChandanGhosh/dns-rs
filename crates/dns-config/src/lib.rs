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
mod model;
mod parser;

pub use error::{ConfigError, ConfigWarning, LoadedConfig};
pub use model::{
    AccessAction, AccessControl, AccessControlView, AuthZoneConfig, Config, ForwardTarget,
    ForwardZoneConfig, ListenAddress, LocalZoneConfig, LocalZoneType, RemoteControlConfig,
    ServerConfig, StubZoneConfig, ViewConfig,
};

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
    Ok(LoadedConfig {
        config,
        warnings: Vec::new(),
    })
}
