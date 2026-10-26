//! Malformed wire-format inputs must be rejected without panicking.
//!
//! These cases are deterministic regression seeds for the `decode_message`
//! fuzz target in `fuzz/`.

use dns_proto::{Message, MessageType, Name, OpCode, Query, RecordType, decode, encode};

#[test]
fn every_truncation_of_a_valid_query_is_rejected_or_decoded_safely() {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.queries.push(Query::query(
        Name::from_ascii("www.example.com.").expect("name"),
        RecordType::AAAA,
    ));
    let wire = encode(&message).expect("encode query");

    for length in 0..wire.len() {
        let _ = decode(&wire[..length]);
    }
}

#[test]
fn compression_pointer_loop_is_rejected() {
    // Header with one question, then a name that points at itself (offset 12).
    let bytes = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c, 0x00,
        0x01, 0x00, 0x01,
    ];
    assert!(decode(&bytes).is_err());
}

#[test]
fn oversized_label_is_rejected() {
    // A label length of 64 is larger than the 63-byte DNS limit.
    let mut bytes = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    ];
    bytes.extend(std::iter::repeat_n(b'a', 64));
    bytes.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    assert!(decode(&bytes).is_err());
}

#[test]
fn random_bytes_never_panic() {
    // xorshift64 keeps the corpus deterministic and dependency-free.
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for _ in 0..20_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let length = (state % 512) as usize;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push((state >> 33) as u8);
        }
        let _ = decode(&bytes);
    }
}
