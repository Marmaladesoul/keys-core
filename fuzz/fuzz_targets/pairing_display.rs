//! Fuzz target for every message the displaying side parses: a Hello in
//! place of the honest one, a Reply after an honest Hello and Share, or (in
//! a Person pairing) a key-set frame after an honest Confirm.
//!
//! The first byte picks the credentials and the stage; the rest is the
//! message, sent from the typing endpoint. A panic is a bug. So is a fuzzed
//! message verifying a run, and so is a sheet whose state doesn't match the
//! outcome it reported: in particular, whatever arrives in place of the
//! Reply or the key set must cost the run.

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

use keys_pairing::sheet::MAX_RUNS_PER_SHEET as ALL_RUNS;
use keys_pairing::{DisplayStatus, Outcome};

use common::{
    AWAITING_KEY_SET, PAST_FIRST_MESSAGE, TYPE_ENDPOINT, assert_not_verified, is_person, open_pair,
};

/// The wire type byte of a Hello.
const HELLO_TYPE: u8 = 1;
/// What a fresh sheet's budget is after one failure.
const ONE_RUN_SPENT: u8 = ALL_RUNS - 1;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, message)) = data.split_first() else {
        return;
    };
    let mut pair = open_pair(selector);
    let run_in_flight = selector & PAST_FIRST_MESSAGE != 0;
    if run_in_flight && is_person(selector) && selector & AWAITING_KEY_SET != 0 {
        // Stage 3 (Person pairings): the fuzzed message arrives where the
        // typing side's key-set frame belongs.
        let _typing_keys = pair.typing_key_set();
    } else if run_in_flight {
        // Stage 2: the fuzzed message arrives where the Reply belongs.
        let _share = pair.share();
    }
    // Stage 1 (top bit clear): the fuzzed message arrives at a shown code.
    let response = pair
        .display
        .handle(TYPE_ENDPOINT, message)
        .expect("handling a message never errors in these states");
    assert_not_verified(&response.outcome);

    let status = pair.display.status().expect("status");
    let is_hello = message.first() == Some(&HELLO_TYPE);
    if run_in_flight && !is_hello {
        // Anything from the run's peer but the message the run is waiting
        // for (a valid Reply, a valid key set) fails the run.
        assert!(matches!(response.outcome, Outcome::RunFailed { .. }));
        assert!(
            matches!(status, DisplayStatus::ShowingCode { runs_left, .. } if runs_left == ONE_RUN_SPENT)
        );
    } else if run_in_flight {
        // A second Hello is turned away and the run goes on.
        assert!(matches!(response.outcome, Outcome::NoRun(_)));
        assert!(matches!(status, DisplayStatus::Running));
    } else {
        match response.outcome {
            Outcome::Continue => assert!(matches!(status, DisplayStatus::Running)),
            Outcome::NoRun(_) | Outcome::Ignored => assert!(
                matches!(status, DisplayStatus::ShowingCode { runs_left, .. } if runs_left == ALL_RUNS)
            ),
            other => panic!("a message at a shown code gave {other:?}"),
        }
    }
});
