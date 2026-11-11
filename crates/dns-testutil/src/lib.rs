//! Test helpers shared by workspace crates.
//!
//! Provides DNS message builders. The `dnssec-mock` binary is a signed
//! authoritative server used by the DNSSEC benchmark scenario; a virtual clock
//! and the Unbound replay harness are not implemented yet.

use dns_proto::{Message, MessageType, Name, OpCode, Query, RecordType, encode};

/// Build a recursive query message with the given ID.
pub fn query_with_id(id: u16, name: &str, record_type: RecordType) -> Message {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_ascii(name).expect("test name is valid"),
        record_type,
    ));
    message
}

/// Build a recursive query message with ID 0.
pub fn query(name: &str, record_type: RecordType) -> Message {
    query_with_id(0, name, record_type)
}

/// Build and encode a recursive query.
pub fn query_bytes(name: &str, record_type: RecordType) -> Vec<u8> {
    encode(&query(name, record_type)).expect("test query encodes")
}

#[cfg(test)]
mod tests {
    use dns_proto::{Message, RecordType};

    use super::{query, query_bytes};

    #[test]
    fn builds_queries() {
        let message = query("example.com.", RecordType::AAAA);
        assert_eq!(message.queries[0].name.to_string(), "example.com.");
    }

    #[test]
    fn encodes_queries() {
        let bytes = query_bytes("example.com.", RecordType::A);
        let message = Message::from_vec(&bytes).expect("query decodes");
        assert_eq!(message.queries[0].query_type, RecordType::A);
    }
}
