//! Fuzz target for parsing a typed pairing code: anything but exactly six
//! ASCII digits is refused, and what parses round-trips.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keys_pairing::PairingCode;

fuzz_target!(|data: &[u8]| {
    let Ok(typed) = std::str::from_utf8(data) else {
        return;
    };
    let well_formed = typed.len() == 6 && typed.bytes().all(|b| b.is_ascii_digit());
    match PairingCode::parse(typed) {
        Ok(code) => {
            assert!(well_formed, "accepted a malformed code");
            assert_eq!(code.digits().as_str(), typed);
        }
        Err(_) => assert!(!well_formed, "refused a well-formed code"),
    }
});
