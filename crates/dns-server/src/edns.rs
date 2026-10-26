//! EDNS(0) helpers for the client-facing side.

use dns_proto::{EDNS_COOKIE, EdnsOption, Message};

/// Minimum UDP payload size mandated by RFC 1035/6891.
pub const MIN_UDP_PAYLOAD: u16 = 512;

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

#[cfg(test)]
mod tests {
    use dns_proto::{Edns, EdnsOption, Message, MessageType, OpCode};

    use super::{payload_size, requested_cookie};

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
}
