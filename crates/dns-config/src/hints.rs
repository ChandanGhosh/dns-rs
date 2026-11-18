//! Root hints loading for the `root-hints` option.
//!
//! Unbound reads root server addresses from a zone-file formatted hints file
//! (the classic `named.root` layout) instead of its compiled-in list. Only the
//! root NS records and their A/AAAA glue are relevant, so unrelated records
//! in the file are ignored.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use dns_proto::{Name, RData, RecordType};

/// Port used for root servers read from a hints file.
const ROOT_SERVER_PORT: u16 = 53;

/// Error returned when a `root-hints` file cannot be used.
#[derive(Debug, thiserror::Error)]
pub enum RootHintsError {
    /// The hints file could not be read.
    #[error("failed to read root hints file {path}: {source}")]
    Io {
        /// File that could not be read.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The hints file is not valid zone-file syntax.
    #[error("failed to parse root hints file {path}: {message}")]
    Parse {
        /// File that failed to parse.
        path: PathBuf,
        /// Parser diagnostic.
        message: String,
    },
    /// The hints file contains NS records but no usable addresses.
    #[error("root hints file {path} contains no root server addresses")]
    NoAddresses {
        /// File without root server addresses.
        path: PathBuf,
    },
}

/// Load root server addresses from one or more hints files.
///
/// Files are read in order and the resulting addresses are de-duplicated, so a
/// later file can extend the set without repeating earlier entries. Every
/// address is used with the standard DNS port.
///
/// # Errors
///
/// Returns [`RootHintsError::Io`] when a file cannot be read,
/// [`RootHintsError::Parse`] when it is not valid zone-file syntax, and
/// [`RootHintsError::NoAddresses`] when a file contains NS records for the
/// root but no matching A/AAAA records.
///
/// # Examples
///
/// ```
/// use std::path::Path;
///
/// let hints = "\
/// . 3600000 IN NS a.root-servers.net.
/// a.root-servers.net. 3600000 IN A 198.41.0.4
/// ";
/// let servers =
///     dns_config::parse_root_hints(hints, Path::new("root.hints")).expect("hints");
/// assert_eq!(servers.len(), 1);
/// ```
pub fn load_root_hints(paths: &[PathBuf]) -> Result<Vec<SocketAddr>, RootHintsError> {
    let mut servers = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(path).map_err(|source| RootHintsError::Io {
            path: path.clone(),
            source,
        })?;
        servers.extend(parse_root_hints(&text, path)?);
    }
    servers.sort();
    servers.dedup();
    Ok(servers)
}

/// Parse root server addresses from hints text.
///
/// Relative names are resolved against the root, matching Unbound's hints
/// files, which always use absolute names.
///
/// # Errors
///
/// Returns [`RootHintsError::Parse`] for invalid zone-file syntax and
/// [`RootHintsError::NoAddresses`] when the file names root servers but
/// supplies no address records for them.
pub fn parse_root_hints(text: &str, path: &Path) -> Result<Vec<SocketAddr>, RootHintsError> {
    let records = dns_proto::parse_zone_records(text, Some(&Name::root())).map_err(|message| {
        RootHintsError::Parse {
            path: path.to_path_buf(),
            message,
        }
    })?;

    // Only glue for servers named by a root NS record is used. A file with no
    // NS records at all is treated as a plain address list, which keeps
    // minimal hand-written hints working.
    let root_names: HashSet<Name> = records
        .iter()
        .filter(|record| record.record_type() == RecordType::NS && record.name.is_root())
        .filter_map(|record| match &record.data {
            RData::NS(target) => Some(target.0.clone()),
            _ => None,
        })
        .collect();

    let mut servers = Vec::new();
    for record in &records {
        if !matches!(record.record_type(), RecordType::A | RecordType::AAAA) {
            continue;
        }
        if !root_names.is_empty() && !root_names.contains(&record.name) {
            continue;
        }
        let address = match &record.data {
            RData::A(address) => IpAddr::V4(address.0),
            RData::AAAA(address) => IpAddr::V6(address.0),
            _ => continue,
        };
        servers.push(SocketAddr::new(address, ROOT_SERVER_PORT));
    }

    if servers.is_empty() {
        return Err(RootHintsError::NoAddresses {
            path: path.to_path_buf(),
        });
    }
    servers.sort();
    servers.dedup();
    Ok(servers)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::parse_root_hints;

    const HINTS: &str = "\
.                        3600000      NS    A.ROOT-SERVERS.NET.
.                        3600000      NS    B.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
B.ROOT-SERVERS.NET.      3600000      A     170.247.170.2
";

    #[test]
    fn reads_ns_glue_only() {
        let servers = parse_root_hints(HINTS, Path::new("root.hints")).expect("hints");
        assert_eq!(servers.len(), 3);
        assert!(servers.contains(&"198.41.0.4:53".parse().expect("address")));
        assert!(servers.contains(&"[2001:503:ba3e::2:30]:53".parse().expect("address")));
        assert!(servers.contains(&"170.247.170.2:53".parse().expect("address")));
    }

    #[test]
    fn ignores_unrelated_address_records() {
        let text = format!("{HINTS}\nwww.example. 60 IN A 192.0.2.1\n");
        let servers = parse_root_hints(&text, Path::new("root.hints")).expect("hints");
        assert_eq!(servers.len(), 3);
        assert!(
            !servers.contains(&"192.0.2.1:53".parse().expect("address")),
            "non-root address must not be used"
        );
    }

    #[test]
    fn accepts_root_addresses_without_ns_records() {
        let servers = parse_root_hints(". 3600 IN A 198.41.0.4\n", Path::new("root.hints"))
            .expect("address-only hints");
        assert_eq!(servers, vec!["198.41.0.4:53".parse().expect("address")]);
    }

    #[test]
    fn rejects_empty_file() {
        let error = parse_root_hints("", Path::new("root.hints")).expect_err("empty file");
        assert!(
            error.to_string().contains("no root server addresses"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_syntax() {
        let error = parse_root_hints(". IN NS\n", Path::new("root.hints")).expect_err("syntax");
        assert!(error.to_string().contains("failed to parse"), "{error}");
    }
}
