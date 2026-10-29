//! EDNS(0) helpers for the client-facing side.

use dns_proto::{EDNS_COOKIE, EdnsOption, Message};

/// Minimum UDP payload size mandated by RFC 1035/6891.
pub const MIN_UDP_PAYLOAD: u16 = 512;

/// Size of an OPT record with no options: root name (1), type (2), class (2),
/// TTL (4), and RDLENGTH (2).
pub const EMPTY_OPT_LEN: usize = 11;

/// UDP payload size advertised by a client, clamped to at least 512.
pub fn payload_size(message: &Message) -> u16 {
    message
        .edns
        .as_ref()
        .map(|edns| edns.max_payload().max(MIN_UDP_PAYLOAD))
        .unwrap_or(MIN_UDP_PAYLOAD)
}

/// Whether the client set the DNSSEC OK bit.
pub fn dnssec_ok(message: &Message) -> bool {
    message
        .edns
        .as_ref()
        .map(|edns| edns.flags().dnssec_ok)
        .unwrap_or(false)
}

/// The raw COOKIE option payload sent by a client, if any.
pub fn requested_cookie(message: &Message) -> Option<Vec<u8>> {
    match message.edns.as_ref()?.option(EDNS_COOKIE) {
        Some(EdnsOption::Unknown(_, data)) => Some(data.clone()),
        _ => None,
    }
}

/// EDNS version advertised by the client (0 for EDNS(0)).
pub fn version(message: &Message) -> Option<u8> {
    message.edns.as_ref().map(|edns| edns.version())
}

/// Append an empty OPT record to an encoded response.
///
/// Normal cached responses do not contain an OPT record: the resolver strips
/// upstream EDNS state and the server adds its own record for each client.
/// Appending the record directly avoids decoding and re-encoding the whole
/// message on a cache hit. The caller must check the cache entry first, because
/// a caller that inserted a message with EDNS state already has an OPT record.
///
/// Returns `false` when the wire is malformed or its additional count is
/// already at the maximum.
pub fn append_empty_opt(wire: &mut Vec<u8>, max_payload: u16, dnssec_ok: bool) -> bool {
    if wire.len() < 12 {
        return false;
    }
    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    let Some(next) = arcount.checked_add(1) else {
        return false;
    };
    let payload = max_payload.max(MIN_UDP_PAYLOAD);
    let flags = if dnssec_ok { 0x8000u16 } else { 0 };
    wire.reserve(EMPTY_OPT_LEN);
    wire.extend_from_slice(&[
        0, // root name
        0,
        41, // OPT
        (payload >> 8) as u8,
        payload as u8,
        0, // extended RCODE
        0, // EDNS version
        (flags >> 8) as u8,
        flags as u8,
        0,
        0, // RDLENGTH
    ]);
    wire[10..12].copy_from_slice(&next.to_be_bytes());
    true
}

#[cfg(test)]
mod tests {
    use dns_proto::{Edns, EdnsOption, Message, MessageType, Name, OpCode, Query, RecordType};

    use super::{append_empty_opt, payload_size, requested_cookie};

    #[test]
    fn defaults_to_512_without_edns() {
        let message = Message::new(1, MessageType::Query, OpCode::Query);
        assert_eq!(payload_size(&message), 512);
        assert!(requested_cookie(&message).is_none());
    }

    #[test]
    fn reads_payload_and_cookie() {
        let mut message = Message::new(1, MessageType::Query, OpCode::Query);
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![1, 2, 3, 4, 5, 6, 7, 8]));
        message.edns = Some(edns);

        assert_eq!(payload_size(&message), 4096);
        assert_eq!(
            requested_cookie(&message).as_deref(),
            Some(&[1, 2, 3, 4, 5, 6, 7, 8][..])
        );
    }

    fn response_wire() -> Vec<u8> {
        let mut message = Message::new(0x1234, MessageType::Response, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("www.example.").expect("name"),
            RecordType::A,
        ));
        message.to_vec().expect("encode")
    }

    #[test]
    fn appends_an_empty_opt_record() {
        let mut wire = response_wire();
        let original_arcount = u16::from_be_bytes([wire[10], wire[11]]);
        assert!(append_empty_opt(&mut wire, 1232, true));

        assert_eq!(wire.len(), response_wire().len() + 11);
        let message = Message::from_vec(&wire).expect("decode");
        let edns = message.edns.as_ref().expect("OPT");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
        assert!(edns.flags().dnssec_ok);
        assert_eq!(
            u16::from_be_bytes([wire[10], wire[11]]),
            original_arcount + 1
        );
    }

    #[test]
    fn append_opt_clamps_the_payload_and_clears_do_when_unset() {
        let mut wire = response_wire();
        assert!(append_empty_opt(&mut wire, 1, false));
        let message = Message::from_vec(&wire).expect("decode");
        let edns = message.edns.as_ref().expect("OPT");
        assert_eq!(edns.max_payload(), 512);
        assert!(!edns.flags().dnssec_ok);
    }

    #[test]
    fn append_opt_rejects_a_short_wire() {
        let mut wire = vec![0; 11];
        assert!(!append_empty_opt(&mut wire, 1232, false));
        assert_eq!(wire.len(), 11);
    }
}
