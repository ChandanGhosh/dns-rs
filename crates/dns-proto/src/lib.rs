//! DNS wire-format types and codecs.
//!
//! This crate is the only place in the workspace that should depend directly on
//! `hickory-proto`. Keeping that dependency behind this facade preserves the option
//! of replacing it with a packed, zero-copy implementation once benchmarks justify it.

pub use hickory_proto::ProtoError;
pub use hickory_proto::dnssec::rdata::{
    DNSKEY, DNSSECRData, DS, NSEC, NSEC3, NSEC3PARAM, RRSIG, SIG, SigInput,
};
pub use hickory_proto::dnssec::{
    Algorithm, DigestType, Nsec3HashAlgorithm, PublicKey, PublicKeyBuf, TBS,
};
pub use hickory_proto::op::{Edns, EdnsFlags, Message, MessageType, OpCode, Query, ResponseCode};
pub use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
pub use hickory_proto::rr::rdata::{CNAME, NS, SOA};
pub use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
pub use hickory_proto::serialize::binary::DecodeError;

/// DNS COOKIE option code (RFC 7873).
pub const EDNS_COOKIE: EdnsCode = EdnsCode::Cookie;

/// Length of a client cookie in bytes (RFC 7873).
pub const CLIENT_COOKIE_LEN: usize = 8;

/// Errors produced while decoding or encoding DNS messages.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The bytes are not a complete, well-formed DNS message.
    #[error("failed to decode DNS message: {0}")]
    Decode(#[source] DecodeError),

    /// The message could not be serialized.
    #[error("failed to encode DNS message: {0}")]
    Encode(#[source] ProtoError),
}

/// Parse one or more records from zone-file syntax.
///
/// This backs `local-data`, `auth-zone` files, and other text-based record
/// sources. Relative names are resolved against `origin`.
pub fn parse_zone_records(input: &str, origin: Option<&Name>) -> Result<Vec<Record>, String> {
    // The zone parser needs an origin to resolve relative names. Records in
    // local-data are normally absolute; treating a missing origin as the root
    // also accepts `example.com A 192.0.2.1` without a trailing dot.
    let origin = origin.cloned().unwrap_or_else(Name::root);
    let parser = hickory_proto::serialize::txt::Parser::new(input, None, Some(origin));
    let (_, sets) = parser.parse().map_err(|error| error.to_string())?;
    let mut records = Vec::new();
    for set in sets.values() {
        records.extend(set.records(false).cloned());
    }
    Ok(records)
}

/// Decode a complete DNS message from wire format.
pub fn decode(bytes: &[u8]) -> Result<Message, WireError> {
    Message::from_vec(bytes).map_err(WireError::Decode)
}

/// Encode a DNS message to wire format.
pub fn encode(message: &Message) -> Result<Vec<u8>, WireError> {
    message.to_vec().map_err(WireError::Encode)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::{Message, MessageType, Name, OpCode, Query, RecordType};

    #[test]
    fn query_round_trips() {
        let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(Query::query(
            Name::from_ascii("example.com.").expect("valid name"),
            RecordType::A,
        ));

        let wire = encode(&message).expect("message encodes");
        let parsed = decode(&wire).expect("message decodes");

        assert_eq!(parsed.metadata.id, 0x1234);
        assert_eq!(parsed.metadata.message_type, MessageType::Query);
        assert_eq!(parsed.queries[0].name.to_string(), "example.com.");
    }

    #[test]
    fn truncated_input_is_rejected() {
        let error = decode(&[0x00, 0x01, 0x02]).expect_err("input is too short");
        assert!(matches!(error, super::WireError::Decode(_)));
    }
}
