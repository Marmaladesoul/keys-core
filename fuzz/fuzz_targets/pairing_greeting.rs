//! Fuzz target for the first message on a pairing connection and its
//! answers: what any endpoint that can reach a device may send it before
//! anything is verified, and what a dialler is sent back.
//!
//! A panic is a bug. So is a second encoding: whatever decodes must be,
//! byte for byte, what encoding it produces, and no longer than the bound a
//! transport reads to.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keys_pairing::greeting::MAX_GREETING_BYTES;
use keys_pairing::{Greeting, KnockAnswer, MeetingAnswer};

fuzz_target!(|data: &[u8]| {
    if let Some(greeting) = Greeting::decode(data) {
        assert_eq!(greeting.encode(), data, "a greeting with two encodings");
        assert!(
            data.len() <= MAX_GREETING_BYTES,
            "a greeting over the bound"
        );
    }
    if let Some(answer) = KnockAnswer::decode(data) {
        assert_eq!(answer.encode(), data, "a knock answer with two encodings");
    }
    if let Some(answer) = MeetingAnswer::decode(data) {
        assert_eq!(answer.encode(), data, "a meeting answer with two encodings");
    }
    // One message is never two things at once.
    let readings = usize::from(Greeting::decode(data).is_some())
        + usize::from(KnockAnswer::decode(data).is_some())
        + usize::from(MeetingAnswer::decode(data).is_some());
    assert!(readings <= 1, "a message that reads as more than one thing");
});
