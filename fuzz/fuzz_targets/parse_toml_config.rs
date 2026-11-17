#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parsing and validation of arbitrary TOML must never panic.
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(config) = toml::from_str::<dns_config::Config>(text)
    {
        let _ = config.validate();
    }
});
