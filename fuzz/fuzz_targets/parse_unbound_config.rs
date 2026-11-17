#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Invalid UTF-8 and invalid syntax are ordinary parse errors; neither may
    // panic. Includes are ignored by the string entry point, so this never
    // touches the filesystem.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = dns_config::parse_unbound_str(text);
    }
});
