use std::path::PathBuf;

use crate::Config;

/// A fatal configuration error.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A configuration file could not be read.
    #[error("failed to read {path}: {source}")]
    Io {
        /// File that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// A line in an `unbound.conf`-style file could not be parsed.
    #[error("{path}:{line}: {message}")]
    Parse {
        /// File containing the error.
        path: PathBuf,
        /// One-based line number.
        line: usize,
        /// Human-readable description.
        message: String,
    },

    /// A TOML file could not be parsed.
    #[error("failed to parse {path}: {source}")]
    Toml {
        /// File containing the error.
        path: PathBuf,
        /// Underlying TOML error.
        #[source]
        source: toml::de::Error,
    },

    /// The configuration parsed but is not usable.
    #[error("invalid configuration: {0}")]
    Validation(String),

    /// An include loop was detected.
    #[error("include cycle detected at {0}")]
    IncludeCycle(PathBuf),
}

impl ConfigError {
    pub(crate) fn parse(path: &std::path::Path, line: usize, message: impl Into<String>) -> Self {
        Self::Parse {
            path: path.to_path_buf(),
            line,
            message: message.into(),
        }
    }
}

/// A non-fatal problem found while loading a configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWarning {
    /// File containing the warning.
    pub path: PathBuf,
    /// One-based line number, or 0 when the source has no line information.
    pub line: usize,
    /// Human-readable description.
    pub message: String,
}

impl std::fmt::Display for ConfigWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // TOML sources have no line numbers; omit the `:0` rather than print a
        // misleading line that does not exist.
        if self.line == 0 {
            write!(formatter, "{}: {}", self.path.display(), self.message)
        } else {
            write!(
                formatter,
                "{}:{}: {}",
                self.path.display(),
                self.line,
                self.message
            )
        }
    }
}

/// A validated configuration plus any non-fatal warnings.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// Parsed and validated configuration.
    pub config: Config,
    /// Unsupported options and other non-fatal issues.
    pub warnings: Vec<ConfigWarning>,
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::ConfigWarning;

    fn warning(line: usize) -> ConfigWarning {
        ConfigWarning {
            path: PathBuf::from("dns-rs.toml"),
            line,
            message: "example".to_owned(),
        }
    }

    #[test]
    fn display_includes_a_known_line() {
        assert_eq!(warning(12).to_string(), "dns-rs.toml:12: example");
    }

    #[test]
    fn display_omits_a_missing_line() {
        assert_eq!(warning(0).to_string(), "dns-rs.toml: example");
    }
}
