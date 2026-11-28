//! Fuzz target for the `keys://pair/…` link parser: text a person pastes or
//! a camera scans, from anyone.
//!
//! Each input is tried twice: as the link's text, and as a link's body
//! given a checksum that matches (through a fuzzing-only hook), since
//! random text all but never gets past the checksum.
//!
//! A panic is a bug. So is a parsed link that doesn't survive being written
//! out and read back, text that parses without being the one spelling of
//! its link (case aside, and an invite's unsanitised name aside), a name that isn't what the sanitiser leaves, a relay
//! that isn't a plain `https://` URL, or accepted text longer than a link
//! can be.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keys_pairing::link::MAX_LINK_BYTES;
use keys_pairing::{PairingAddress, PairingLink, sanitize_display_name};

/// Bytes of an invite's written form from its name's length prefix to the
/// end: the prefix (one byte for a name under 128 bytes, two from there
/// up), the name, and the four-byte checksum.
fn bytes_from_the_name_on(name: &str) -> usize {
    let length_prefix = if name.len() < 128 { 1 } else { 2 };
    length_prefix + name.len() + 4
}

fn check_address(address: &PairingAddress) {
    if let Some(relay) = address.relay_url() {
        assert!(relay.starts_with("https://"), "a relay that isn't https");
        assert!(
            relay.bytes().all(|byte| byte.is_ascii_graphic()),
            "a relay with something other than printable ASCII in it"
        );
    }
}

/// Checks whatever `text` parses as, if it parses.
fn check(text: &str) {
    let Ok(link) = PairingLink::parse(text) else {
        return;
    };
    assert!(
        text.trim().len() <= MAX_LINK_BYTES,
        "accepted an overlong link"
    );
    match &link {
        PairingLink::Device(address) => check_address(address),
        PairingLink::Person(invite) => {
            check_address(&invite.address);
            assert_eq!(
                invite.inviter_name,
                sanitize_display_name(&invite.inviter_name),
                "a parsed name that the sanitiser would change"
            );
        }
    }
    let written = link.to_text();
    assert!(written.len() <= MAX_LINK_BYTES, "wrote an overlong link");
    // Strictness: text that parses is the text this link is written as, in
    // some mix of case. The one exception is an invite whose name the
    // sanitiser changed, which only ever shortens it; and then everything
    // before the name must still be the one spelling.
    let trimmed = text.trim_matches(|character: char| character.is_ascii_whitespace());
    match &link {
        PairingLink::Person(invite) if written.len() < trimmed.len() => {
            let before_name = written.len() - 2 * bytes_from_the_name_on(&invite.inviter_name);
            assert!(
                trimmed.is_char_boundary(before_name)
                    && written[..before_name].eq_ignore_ascii_case(&trimmed[..before_name]),
                "accepted a second spelling of an invite's fields"
            );
        }
        _ => assert!(
            written.eq_ignore_ascii_case(trimmed),
            "accepted a second spelling of a link"
        ),
    }
    assert_eq!(
        PairingLink::parse(&written).as_ref(),
        Ok(&link),
        "a parsed link didn't round-trip"
    );
}

fuzz_target!(|data: &[u8]| {
    // The input as the text itself: the prefix, the hex and the checksum
    // are all the fuzzer's to get wrong.
    if let Ok(text) = std::str::from_utf8(data) {
        check(text);
    }
    // And as a link's body under a checksum that matches, which random
    // text almost never has: the first byte picks the kind of link.
    if let Some((kind, fields)) = data.split_first() {
        let person = kind & 1 == 1;
        check(&keys_pairing::link::link_with_matching_checksum_for_fuzzing(person, fields));
    }
});
