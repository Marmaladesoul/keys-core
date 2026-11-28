//! Fuzz target for a local-network advertisement's TXT record: entries
//! chosen by any device on the network.
//!
//! The input is cut into entries at 0x00 bytes and each entry into key and
//! value at its first `=`, as a TXT record is. A panic is a bug. So is an
//! accepted record that names one of its keys twice (in any case), one
//! whose address doesn't survive being written back out, or a relay that
//! isn't a plain `https://` URL.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keys_pairing::advert::{address_from_txt, txt_entries};

fuzz_target!(|data: &[u8]| {
    let entries: Vec<(String, String)> = data
        .split(|byte| *byte == 0)
        .filter_map(|entry| {
            let entry = std::str::from_utf8(entry).ok()?;
            let (key, value) = entry.split_once('=')?;
            Some((key.to_owned(), value.to_owned()))
        })
        .collect();
    let Ok(address) = address_from_txt(&entries) else {
        return;
    };
    for key in ["v", "id", "relay"] {
        let named = entries
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case(key))
            .count();
        assert!(named <= 1, "accepted a record that names `{key}` twice");
    }
    if let Some(relay) = address.relay_url() {
        assert!(relay.starts_with("https://"), "a relay that isn't https");
    }
    assert_eq!(
        address_from_txt(&txt_entries(&address)).as_ref(),
        Ok(&address),
        "an advertised address didn't round-trip"
    );
});
