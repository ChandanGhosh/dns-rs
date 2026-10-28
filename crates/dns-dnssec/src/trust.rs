//! Built-in trust anchors and trust-anchor file parsing.

use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, RwLock};

use data_encoding::{BASE64, HEXLOWER};
use dns_proto::{
    Algorithm, DNSKEY, DNSSECRData, DS, DigestType, Name, PublicKeyBuf, RData, Record,
};

/// Root KSK-2017 (key tag 20326), algorithm 8 (RSA/SHA-256).
pub const ROOT_KSK_2017: &str = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=";

/// Root KSK-2024 (key tag 38696), algorithm 8 (RSA/SHA-256).
pub const ROOT_KSK_2024: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";

/// A configured trust anchor.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    /// Zone apex the anchor applies to.
    pub name: Name,
    /// Trusted DNSKEY records.
    pub keys: Vec<Record>,
    /// Trusted DS records.
    pub ds: Vec<Record>,
}

impl TrustAnchor {
    /// Create an anchor from DNSKEY records.
    pub fn from_keys(name: Name, keys: Vec<Record>) -> Self {
        Self {
            name,
            keys,
            ds: Vec::new(),
        }
    }

    /// Create an anchor from DS records.
    pub fn from_ds(name: Name, ds: Vec<Record>) -> Self {
        Self {
            name,
            keys: Vec::new(),
            ds,
        }
    }
}

/// A set of configured trust anchors.
///
/// Clones share the same underlying anchor list, so an RFC 5011 update task
/// can replace the root anchor while resolutions are reading it.
#[derive(Clone, Debug, Default)]
pub struct TrustStore {
    anchors: Arc<RwLock<Vec<TrustAnchor>>>,
}

impl TrustStore {
    /// A store containing only the built-in root anchor.
    pub fn builtin() -> Self {
        Self {
            anchors: Arc::new(RwLock::new(vec![root_trust_anchor().clone()])),
        }
    }

    /// Build a store from inline anchors and anchor files.
    ///
    /// The built-in root anchor is included unless the configuration supplies
    /// its own root anchor. Other configured anchors are added alongside it.
    pub fn from_config(inline: &[String], files: &[PathBuf]) -> Result<Self, TrustAnchorError> {
        let mut parsed = Vec::new();
        for text in inline {
            parsed.extend(parse_trust_anchors(text)?);
        }
        for path in files {
            parsed.extend(load_trust_anchors(path)?);
        }

        let has_root = parsed.iter().any(|anchor| anchor.name.is_root());
        let mut anchors = if has_root {
            Vec::new()
        } else {
            vec![root_trust_anchor().clone()]
        };
        for anchor in parsed {
            if let Some(existing) = anchors
                .iter_mut()
                .find(|existing| existing.name == anchor.name)
            {
                existing.keys.extend(anchor.keys);
                existing.ds.extend(anchor.ds);
            } else {
                anchors.push(anchor);
            }
        }
        Ok(Self {
            anchors: Arc::new(RwLock::new(anchors)),
        })
    }

    /// Add or extend the anchor for a zone.
    pub fn insert(&self, anchor: TrustAnchor) {
        let mut anchors = self
            .anchors
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = anchors
            .iter_mut()
            .find(|existing| existing.name == anchor.name)
        {
            existing.keys.extend(anchor.keys);
            existing.ds.extend(anchor.ds);
        } else {
            anchors.push(anchor);
        }
    }

    /// Replace every key and DS record for a zone.
    ///
    /// This is used by RFC 5011 maintenance, where the set of trusted keys is
    /// authoritative rather than additive.
    pub fn replace(&self, anchor: TrustAnchor) {
        let mut anchors = self
            .anchors
            .write()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = anchors
            .iter_mut()
            .find(|existing| existing.name == anchor.name)
        {
            *existing = anchor;
        } else {
            anchors.push(anchor);
        }
    }

    /// The anchor configured for exactly this zone.
    pub fn anchor_for(&self, zone: &Name) -> Option<TrustAnchor> {
        self.anchors
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .find(|anchor| anchor.name == *zone)
            .cloned()
    }

    /// All configured anchors.
    pub fn anchors(&self) -> Vec<TrustAnchor> {
        self.anchors
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    /// Whether an anchor at or below `domain` covers `name`.
    ///
    /// `domain-insecure` ignores anchors above the excluded domain, but an
    /// explicit anchor inside the excluded subtree re-enables validation for
    /// the names it covers.
    pub fn anchor_within(&self, domain: &Name, name: &Name) -> bool {
        self.anchors
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .iter()
            .any(|anchor| domain.zone_of(&anchor.name) && anchor.name.zone_of(name))
    }

    /// Whether the store contains no anchors.
    pub fn is_empty(&self) -> bool {
        self.anchors
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .is_empty()
    }
}

/// Errors while parsing trust anchors.
#[derive(Debug, thiserror::Error)]
pub enum TrustAnchorError {
    /// The anchor file could not be read.
    #[error("failed to read trust anchor file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// A line was not valid zone-file syntax for DS or DNSKEY.
    #[error("invalid trust anchor: {0}")]
    Parse(String),
}

/// Parse one or more trust anchors from zone-file syntax.
///
/// Each non-empty line has the form `name [ttl] [IN] DS ...` or
/// `name [ttl] [IN] DNSKEY ...`.
pub fn parse_trust_anchors(text: &str) -> Result<Vec<TrustAnchor>, TrustAnchorError> {
    let mut anchors: Vec<TrustAnchor> = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        let record = parse_anchor_record(line)
            .map_err(|message| TrustAnchorError::Parse(format!("line {}: {message}", index + 1)))?;
        let name = record.name.clone();
        let mut anchor = match &record.data {
            RData::DNSSEC(DNSSECRData::DS(_)) => TrustAnchor::from_ds(name.clone(), vec![record]),
            RData::DNSSEC(DNSSECRData::DNSKEY(_)) => {
                TrustAnchor::from_keys(name.clone(), vec![record])
            }
            _ => unreachable!("parser only returns DS and DNSKEY records"),
        };
        if let Some(existing) = anchors.iter_mut().find(|existing| existing.name == name) {
            existing.keys.append(&mut anchor.keys);
            existing.ds.append(&mut anchor.ds);
        } else {
            anchors.push(anchor);
        }
    }
    if anchors.is_empty() {
        return Err(TrustAnchorError::Parse(
            "no DS or DNSKEY records found".to_owned(),
        ));
    }
    Ok(anchors)
}

/// Load trust anchors from a file.
pub fn load_trust_anchors(path: &Path) -> Result<Vec<TrustAnchor>, TrustAnchorError> {
    let text = std::fs::read_to_string(path).map_err(|source| TrustAnchorError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_trust_anchors(&text)
}

pub(crate) fn parse_anchor_record(line: &str) -> Result<Record, String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let Some(name_text) = tokens.first() else {
        return Err("empty record".to_owned());
    };
    let name = Name::from_ascii(name_text)
        .map_err(|error| format!("invalid owner name {name_text:?}: {error}"))?;

    let mut index = 1;
    let mut ttl = 0u32;
    if let Some(token) = tokens.get(index)
        && let Ok(parsed) = token.parse::<u32>()
    {
        ttl = parsed;
        index += 1;
    }
    if tokens
        .get(index)
        .is_some_and(|token| token.eq_ignore_ascii_case("IN"))
    {
        index += 1;
    }

    let Some(record_type) = tokens.get(index) else {
        return Err("missing record type".to_owned());
    };
    index += 1;
    let rdata = &tokens[index..];

    match record_type.to_ascii_uppercase().as_str() {
        "DS" => {
            if rdata.len() != 4 {
                return Err("DS record needs key tag, algorithm, digest type and digest".to_owned());
            }
            let key_tag = rdata[0]
                .parse::<u16>()
                .map_err(|_| format!("invalid DS key tag {:?}", rdata[0]))?;
            let algorithm = rdata[1]
                .parse::<u8>()
                .map_err(|_| format!("invalid DS algorithm {:?}", rdata[1]))?;
            let digest_type = rdata[2]
                .parse::<u8>()
                .map_err(|_| format!("invalid DS digest type {:?}", rdata[2]))?;
            let digest = HEXLOWER
                .decode(rdata[3].as_bytes())
                .map_err(|_| "invalid DS digest hex".to_owned())?;
            Ok(Record::from_rdata(
                name,
                ttl,
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    key_tag,
                    Algorithm::from_u8(algorithm),
                    DigestType::from(digest_type),
                    digest,
                ))),
            ))
        }
        "DNSKEY" => {
            if rdata.len() != 4 {
                return Err("DNSKEY record needs flags, protocol, algorithm and key".to_owned());
            }
            let flags = rdata[0]
                .parse::<u16>()
                .map_err(|_| format!("invalid DNSKEY flags {:?}", rdata[0]))?;
            let protocol = rdata[1]
                .parse::<u8>()
                .map_err(|_| format!("invalid DNSKEY protocol {:?}", rdata[1]))?;
            if protocol != 3 {
                return Err("DNSKEY protocol must be 3".to_owned());
            }
            let algorithm = rdata[2]
                .parse::<u8>()
                .map_err(|_| format!("invalid DNSKEY algorithm {:?}", rdata[2]))?;
            let key = BASE64
                .decode(rdata[3].as_bytes())
                .map_err(|_| "invalid DNSKEY base64".to_owned())?;
            Ok(Record::from_rdata(
                name,
                ttl,
                RData::DNSSEC(DNSSECRData::DNSKEY(DNSKEY::with_flags(
                    flags,
                    PublicKeyBuf::new(key, Algorithm::from_u8(algorithm)),
                ))),
            ))
        }
        other => Err(format!("unsupported trust anchor type {other:?}")),
    }
}

fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (index, character) in line.char_indices() {
        match character {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => return &line[..index],
            _ => {}
        }
    }
    line
}

/// The built-in root trust anchor.
pub fn root_trust_anchor() -> &'static TrustAnchor {
    static ANCHOR: LazyLock<TrustAnchor> =
        LazyLock::new(|| TrustAnchor::from_keys(Name::root(), root_trust_anchor_keys().to_vec()));
    &ANCHOR
}

/// Root KSK records, parsed from the built-in public keys.
pub fn root_trust_anchor_keys() -> &'static [Record] {
    static KEYS: LazyLock<Vec<Record>> = LazyLock::new(|| {
        [ROOT_KSK_2017, ROOT_KSK_2024]
            .into_iter()
            .map(|encoded| {
                let bytes = BASE64
                    .decode(encoded.as_bytes())
                    .expect("built-in root key is valid base64");
                let key = DNSKEY::with_flags(257, PublicKeyBuf::new(bytes, Algorithm::RSASHA256));
                Record::from_rdata(
                    Name::root(),
                    172_800,
                    RData::DNSSEC(DNSSECRData::DNSKEY(key)),
                )
            })
            .collect()
    });
    &KEYS
}

#[cfg(test)]
mod tests {
    use dns_proto::PublicKey;

    use super::{TrustStore, parse_trust_anchors, root_trust_anchor_keys};
    use crate::crypto::dnskey_of;

    #[test]
    fn parses_ds_and_dnskey_anchors() {
        let text = r#"
; comment
example.com. 3600 IN DS 12345 8 2 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
example.org. DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
"#;
        let anchors = parse_trust_anchors(text).expect("parse anchors");
        assert_eq!(anchors.len(), 2);
        assert_eq!(anchors[0].name.to_ascii(), "example.com.");
        assert_eq!(anchors[0].ds.len(), 1);
        assert_eq!(anchors[1].keys.len(), 1);
    }

    #[test]
    fn builtin_store_has_root_anchor() {
        let store = TrustStore::builtin();
        assert!(store.anchor_for(&dns_proto::Name::root()).is_some());
    }

    #[test]
    fn configured_root_replaces_builtin() {
        let store =
            TrustStore::from_config(&["example.com. DS 1 8 2 00".to_owned()], &[]).expect("store");
        assert!(store.anchor_for(&dns_proto::Name::root()).is_some());
        assert!(
            store
                .anchor_for(&dns_proto::Name::from_ascii("example.com.").expect("name"))
                .is_some()
        );
    }

    #[test]
    fn built_in_root_keys_have_expected_tags() {
        let keys = root_trust_anchor_keys();
        assert_eq!(keys.len(), 2);
        let tags: Vec<u16> = keys
            .iter()
            .map(|record| {
                dnskey_of(record)
                    .expect("DNSKEY rdata")
                    .calculate_key_tag()
                    .expect("key tag")
            })
            .collect();
        assert!(tags.contains(&20326));
        assert!(tags.contains(&38696));
    }

    #[test]
    fn built_in_root_keys_are_zone_keys() {
        for record in root_trust_anchor_keys() {
            let key = dnskey_of(record).expect("DNSKEY rdata");
            assert!(key.zone_key());
            assert_eq!(
                key.public_key().algorithm(),
                dns_proto::Algorithm::RSASHA256
            );
        }
    }
}
