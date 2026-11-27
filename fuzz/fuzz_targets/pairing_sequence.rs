//! Fuzz target for the two sheets as state machines. The input is a script
//! of operations: type a code (right or wrong), carry the pending message
//! one way or the other (once, or again as a duplicate), hand either side
//! arbitrary bytes from its peer or from a stranger, move either side's
//! clock, press New Code, abandon a run, poll a side's status.
//!
//! Polling is an operation of its own, not something done after every step:
//! a poll settles an expired code or a timed-out run, and the paths where a
//! message is what finds them expired must stay reachable.
//!
//! Whatever the script does:
//! - neither side starts more runs than its budget (a Share or a Reply is a
//!   run started, and a Reply is a guess spent);
//! - a side's remaining runs never go up;
//! - a stranger's message never draws a reply from the typing side, and a
//!   stranger's message that isn't a Hello never draws one from the
//!   displaying side or starts anything there, unless the stranger's own
//!   Hello started the run in flight (a Hello is all it takes to be a run's
//!   peer, and a run's peer is answered);
//! - a session handed out for a Person pairing has the other account
//!   recorded on it, and one for a device pairing has none;
//! - the typing side verifies only if the displaying side did, and a run
//!   verifies a side only if the code typed is the very code the displaying
//!   side's run consumed;
//! - nothing panics.
//!
//! And once per process, before any script: an honest, undisturbed run of
//! each kind does verify (a Person pairing by way of both key sets), the
//! displaying side moves from "awaiting peer" to "verified" on the typing
//! side's first frame, and a frame travels each way. A sheet that refused
//! everything would pass every check above.
//!
//! The random stream is scripted, so the honest messages of a given script
//! are fixed byte strings. Don't seed the corpus with real transcripts: an
//! input that carries the honest next message as its "arbitrary bytes" is
//! indistinguishable from the honest message.

#![no_main]

#[path = "common.rs"]
mod common;

use std::sync::Once;
use std::time::Duration;

use libfuzzer_sys::fuzz_target;

use keys_pairing::sheet::MAX_RUNS_PER_SHEET as MAX_RUNS;
use keys_pairing::{DisplayStatus, Outcome, PairingCode, TypeStatus, VerifiedSession};

use common::{DISPLAY_ENDPOINT, Pair, STRANGER_ENDPOINT, TYPE_ENDPOINT, is_person, open_pair};

/// What the typing side types when told to type a wrong code, or when the
/// displaying side shows none.
const WRONG_CODE: &str = "000000";
/// The script's operations, in the order of their codes.
const OPERATIONS: u8 = 17;
/// The wire type bytes of a Hello, a Share and a Reply.
const HELLO_TYPE: u8 = 1;
const SHARE_TYPE: u8 = 2;
const REPLY_TYPE: u8 = 3;
/// Clock steps are this many seconds per unit of the script's operand, so
/// one byte reaches past the code lifetime (five minutes).
const SECONDS_PER_CLOCK_UNIT: u64 = 2;

/// Reads the script: one byte at a time, and length-prefixed blobs.
struct Script<'a>(&'a [u8]);

impl<'a> Script<'a> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn blob(&mut self) -> &'a [u8] {
        let len = usize::from(self.byte().unwrap_or(0)).min(self.0.len());
        let (blob, rest) = self.0.split_at(len);
        self.0 = rest;
        blob
    }
}

/// The two sheets, the one message in flight each way, and the tallies the
/// invariants are checked against.
struct World {
    pair: Pair,
    /// Whether the sheets were opened for a Person pairing.
    person: bool,
    to_display: Option<Vec<u8>>,
    to_typing: Option<Vec<u8>>,
    shares_sent: u8,
    replies_sent: u8,
    display_runs_left: u8,
    typing_runs_left: u8,
    display_verified: bool,
    typing_verified: bool,
    /// The code the typing side's current run was typed with.
    typed_code: Option<PairingCode>,
    /// The code the displaying side's current run consumed.
    display_run_code: Option<PairingCode>,
    /// Whose Hello started the displaying side's run in flight, as far as
    /// the script has seen. It can outlive a run that timed out unnoticed,
    /// which only makes the stranger check below skip a case.
    display_run_peer: Option<[u8; 32]>,
}

fn first_byte(message: Option<&Vec<u8>>) -> Option<u8> {
    message.and_then(|message| message.first().copied())
}

fn same_code(a: Option<&PairingCode>, b: Option<&PairingCode>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.digits().as_str() == b.digits().as_str(),
        _ => false,
    }
}

impl World {
    /// Types the code the person last read off the displaying side's
    /// screen, or a wrong one. Doesn't poll.
    fn type_code(&mut self, known_code: Option<&PairingCode>) {
        let code = known_code
            .cloned()
            .unwrap_or_else(|| PairingCode::parse(WRONG_CODE).expect("six digits"));
        if let Ok(hello) = self.pair.typing.submit_code(code.clone()) {
            self.to_display = Some(hello);
            self.typed_code = Some(code);
        }
    }

    /// A run verifies only when the typing side typed the very code the
    /// displaying side's run consumed.
    fn assert_the_codes_matched(&self, side: &str) {
        assert!(
            same_code(self.typed_code.as_ref(), self.display_run_code.as_ref()),
            "the {side} side verified a run whose two codes differ"
        );
    }

    /// A Person pairing hands out a session only with the other account's
    /// checked key set recorded on it; a device pairing records none.
    fn assert_the_account_is_recorded(&self, session: &VerifiedSession, side: &str) {
        assert_eq!(
            session.peer_account().is_some(),
            self.person,
            "the {side} side's session has the wrong idea of its peer's account"
        );
    }

    fn to_display_sheet(&mut self, sender: [u8; 32], message: &[u8]) {
        let showing = self.pair.display.shown_code_without_refresh_for_fuzzing();
        let response = self
            .pair
            .display
            .handle(sender, message)
            .expect("the scripted random source doesn't fail");
        let from_an_outsider =
            sender == STRANGER_ENDPOINT && self.display_run_peer != Some(STRANGER_ENDPOINT);
        if from_an_outsider && message.first() != Some(&HELLO_TYPE) {
            // Nothing goes back to it, and all it can coincide with is a
            // timeout of the run in flight.
            assert!(
                response.reply.is_none(),
                "the displaying side answered a stranger"
            );
            assert!(
                matches!(
                    response.outcome,
                    Outcome::Ignored | Outcome::RunFailed { .. } | Outcome::DeadEnd { .. }
                ),
                "a stranger's message did something: {:?}",
                response.outcome
            );
        }
        // A Share going out is a run started. (In a Person pairing the
        // displaying side also carries on after the Reply, with its
        // Confirm: that is the same run.)
        let started_a_run = first_byte(response.reply.as_ref()) == Some(SHARE_TYPE);
        match response.outcome {
            Outcome::Continue if started_a_run => {
                self.shares_sent += 1;
                // The run that just started consumed the code that was
                // showing.
                self.display_run_code = showing;
                self.display_run_peer = Some(sender);
            }
            Outcome::Verified(session) => {
                self.assert_the_account_is_recorded(&session, "displaying");
                self.assert_the_codes_matched("displaying");
                self.display_verified = true;
                self.display_run_peer = None;
            }
            Outcome::RunFailed { .. } | Outcome::DeadEnd { .. } => self.display_run_peer = None,
            _ => {}
        }
        // A reply goes back only to the sender of what it answers.
        if sender == TYPE_ENDPOINT
            && let Some(reply) = response.reply
        {
            self.to_typing = Some(reply);
        }
    }

    fn to_typing_sheet(&mut self, sender: [u8; 32], message: &[u8]) {
        let response = self.pair.typing.handle(sender, message);
        if sender != DISPLAY_ENDPOINT {
            assert!(matches!(response.outcome, Outcome::Ignored));
            assert!(response.reply.is_none());
            return;
        }
        // A Reply going out is a guess spent. (In a Person pairing the
        // typing side also carries on after the Confirm, with its key set.)
        let spent_a_guess = first_byte(response.reply.as_ref()) == Some(REPLY_TYPE);
        match response.outcome {
            Outcome::Continue if spent_a_guess => self.replies_sent += 1,
            Outcome::Verified(session) => {
                self.assert_the_account_is_recorded(&session, "typing");
                self.assert_the_codes_matched("typing");
                self.typing_verified = true;
            }
            _ => {}
        }
        if let Some(reply) = response.reply {
            self.to_display = Some(reply);
        }
    }

    /// The tallies, checked after every operation. No polling here.
    fn check_tallies(&self) {
        assert!(
            self.shares_sent <= MAX_RUNS,
            "the displaying side started a fourth run"
        );
        assert!(
            self.replies_sent <= MAX_RUNS,
            "the typing side spent a fourth guess"
        );
        assert!(
            !self.typing_verified || self.display_verified,
            "the typing side verified a displaying side that didn't"
        );
    }

    /// Polls the displaying side: its budget never grows. Returns the code
    /// it shows, if any, as the person now reading the screen would see it.
    fn poll_display(&mut self) -> Option<PairingCode> {
        let status = self.pair.display.status().expect("status");
        if !matches!(status, DisplayStatus::Running) {
            self.display_run_peer = None;
        }
        match status {
            DisplayStatus::ShowingCode {
                code, runs_left, ..
            } => {
                assert!(
                    runs_left <= self.display_runs_left,
                    "the displaying side's budget grew"
                );
                self.display_runs_left = runs_left;
                Some(code)
            }
            _ => None,
        }
    }

    /// Polls the typing side: its budget never grows.
    fn poll_typing(&mut self) {
        if let TypeStatus::AwaitingCode { runs_left } = self.pair.typing.status() {
            assert!(
                runs_left <= self.typing_runs_left,
                "the typing side's budget grew"
            );
            self.typing_runs_left = runs_left;
        }
    }
}

/// An honest run, start to finish, on sheets of its own: a device pairing
/// or a Person pairing, as `selector` says.
fn an_honest_run_verifies(selector: u8) {
    let mut pair = open_pair(selector);
    let reply = pair.reply();
    let mut from_display = pair.display.handle(TYPE_ENDPOINT, &reply).expect("handle");
    let mut from_typing = pair.typing.handle(
        DISPLAY_ENDPOINT,
        &from_display.reply.take().expect("a Confirm"),
    );
    // A Person pairing goes one more round: the two key sets.
    assert_eq!(from_typing.reply.is_some(), is_person(selector));
    if let Some(typing_keys) = from_typing.reply.take() {
        from_display = pair
            .display
            .handle(TYPE_ENDPOINT, &typing_keys)
            .expect("handle");
        from_typing = pair.typing.handle(
            DISPLAY_ENDPOINT,
            &from_display.reply.take().expect("a key set"),
        );
    }
    let Outcome::Verified(mut display_session) = from_display.outcome else {
        panic!("an honest run verifies the displaying side");
    };
    let Outcome::Verified(mut typing_session) = from_typing.outcome else {
        panic!("an honest run verifies the typing side");
    };
    assert_eq!(
        display_session.peer_account().is_some(),
        is_person(selector)
    );
    assert_eq!(typing_session.peer_account().is_some(), is_person(selector));
    assert!(matches!(
        pair.display.status().expect("status"),
        DisplayStatus::VerifiedAwaitingPeer
    ));
    assert!(display_session.seal(b"too early").is_err());
    let frame = typing_session.seal(b"device keys").expect("seal");
    assert_eq!(
        display_session
            .open(TYPE_ENDPOINT, &frame)
            .expect("open")
            .as_slice(),
        b"device keys"
    );
    assert!(matches!(
        pair.display.status().expect("status"),
        DisplayStatus::Verified
    ));
    let frame = display_session.seal(b"bundle").expect("seal");
    assert_eq!(
        typing_session
            .open(DISPLAY_ENDPOINT, &frame)
            .expect("open")
            .as_slice(),
        b"bundle"
    );
}

/// One selector of each kind (see `common::credentials`).
const HONEST_DEVICE_RUN: u8 = 0;
const HONEST_PERSON_RUN: u8 = 1;

static HONEST_RUN_CHECKED: Once = Once::new();

fn clock_step(units: u8) -> Duration {
    Duration::from_secs(u64::from(units) * SECONDS_PER_CLOCK_UNIT)
}

fuzz_target!(|data: &[u8]| {
    HONEST_RUN_CHECKED.call_once(|| {
        an_honest_run_verifies(HONEST_DEVICE_RUN);
        an_honest_run_verifies(HONEST_PERSON_RUN);
    });
    let mut script = Script(data);
    let Some(selector) = script.byte() else {
        return;
    };
    let mut world = World {
        pair: open_pair(selector),
        person: is_person(selector),
        to_display: None,
        to_typing: None,
        shares_sent: 0,
        replies_sent: 0,
        display_runs_left: MAX_RUNS,
        typing_runs_left: MAX_RUNS,
        display_verified: false,
        typing_verified: false,
        typed_code: None,
        display_run_code: None,
        display_run_peer: None,
    };
    // What the person last read off the displaying side's screen.
    let mut known_code = world.poll_display();
    while let Some(operation) = script.byte() {
        match operation % OPERATIONS {
            0 => world.type_code(known_code.as_ref()),
            1 => world.type_code(None),
            // Carry the pending message across, once...
            2 => {
                if let Some(message) = world.to_display.take() {
                    world.to_display_sheet(TYPE_ENDPOINT, &message);
                }
            }
            3 => {
                if let Some(message) = world.to_typing.take() {
                    world.to_typing_sheet(DISPLAY_ENDPOINT, &message);
                }
            }
            // ...or deliver it and leave a duplicate in flight.
            4 => {
                if let Some(message) = world.to_display.clone() {
                    world.to_display_sheet(TYPE_ENDPOINT, &message);
                }
            }
            5 => {
                if let Some(message) = world.to_typing.clone() {
                    world.to_typing_sheet(DISPLAY_ENDPOINT, &message);
                }
            }
            // Arbitrary bytes, from the peer or from a stranger.
            6 => world.to_display_sheet(TYPE_ENDPOINT, script.blob()),
            7 => world.to_display_sheet(STRANGER_ENDPOINT, script.blob()),
            8 => world.to_typing_sheet(DISPLAY_ENDPOINT, script.blob()),
            9 => world.to_typing_sheet(STRANGER_ENDPOINT, script.blob()),
            10 => world
                .pair
                .display_clock
                .advance(clock_step(script.byte().unwrap_or(0))),
            11 => world
                .pair
                .typing_clock
                .advance(clock_step(script.byte().unwrap_or(0))),
            12 => {
                let _ = world.pair.display.new_code();
            }
            13 => {
                if world.pair.display.abandon_run().is_ok() {
                    world.display_run_peer = None;
                }
            }
            14 => {
                let _ = world.pair.typing.abandon_run();
            }
            // The person looks at the displaying side's screen...
            15 => known_code = world.poll_display(),
            // ...or at the typing side's.
            _ => world.poll_typing(),
        }
        world.check_tallies();
    }
});
