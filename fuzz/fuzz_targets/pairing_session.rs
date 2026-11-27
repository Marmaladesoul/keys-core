//! Fuzz target for the verified session's frame parser. An honest pairing
//! runs to completion, the typing side sends one honest frame, then each
//! side is handed the fuzzed bytes: first from a stranger, which must leave
//! the session untouched, then from its peer. No fuzzed frame may open; a
//! frame-typed message from the peer spoils the session for good, and
//! anything else from the peer leaves it usable.

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

use keys_pairing::{EndpointId, Outcome, SessionError, VerifiedSession};

use common::{DISPLAY_ENDPOINT, STRANGER_ENDPOINT, TYPE_ENDPOINT, open_pair};

/// The wire type byte of a session frame.
const FRAME_TYPE: u8 = 6;

fn verified(outcome: Outcome) -> Box<VerifiedSession> {
    match outcome {
        Outcome::Verified(session) => session,
        other => panic!("an honest run verifies, got {other:?}"),
    }
}

fn hand_fuzzed_bytes(session: &mut VerifiedSession, peer: EndpointId, bytes: &[u8]) {
    assert_eq!(
        session.open(STRANGER_ENDPOINT, bytes).map(|_| ()),
        Err(SessionError::WrongSender)
    );
    let from_peer = session.open(peer, bytes).map(|_| ());
    let still_usable = session.seal(b"after").is_ok();
    if bytes.first() == Some(&FRAME_TYPE) {
        assert_eq!(
            from_peer,
            Err(SessionError::FrameRejected),
            "a fuzzed frame opened"
        );
        assert!(!still_usable, "a rejected frame left the session usable");
    } else {
        assert_eq!(from_peer, Err(SessionError::NotAFrame));
        assert!(
            still_usable,
            "a message that isn't a frame spoilt the session"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, bytes)) = data.split_first() else {
        return;
    };
    let mut pair = open_pair(selector);
    let reply = pair.reply();
    let confirm = pair.display.handle(TYPE_ENDPOINT, &reply).expect("handle");
    let mut display = verified(confirm.outcome);
    let finish = pair.typing.handle(
        DISPLAY_ENDPOINT,
        &confirm.reply.expect("a Reply is answered with a Confirm"),
    );
    let mut typing = verified(finish.outcome);

    let honest = typing.seal(b"hello").expect("the typing side speaks first");
    display
        .open(TYPE_ENDPOINT, &honest)
        .expect("an honest frame opens");

    hand_fuzzed_bytes(&mut display, TYPE_ENDPOINT, bytes);
    hand_fuzzed_bytes(&mut typing, DISPLAY_ENDPOINT, bytes);
});
