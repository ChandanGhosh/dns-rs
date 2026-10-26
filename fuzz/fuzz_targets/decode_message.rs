#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Decoding must never panic on arbitrary bytes. If the input happens to be
    // a valid message, encoding the parsed form must not panic either.
    if let Ok(message) = dns_proto::decode(data) {
        let _ = dns_proto::encode(&message);
    }
});
