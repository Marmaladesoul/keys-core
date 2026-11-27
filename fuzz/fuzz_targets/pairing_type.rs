//! Fuzz target for every message the typing side parses: a Share in place
//! of the honest one, a Confirm / Refuse after an honest Share and Reply, or
//! (in a Person pairing) a key-set frame after its own key set went out.
//!
//! The first byte picks the credentials and the stage; the rest is the
//! message, sent from the displaying endpoint. A panic is a bug. So is a
//! fuzzed message verifying a run, and so is the policy slipping: once the
//! Reply is out, whatever arrives must cost the typing side its run.

#![no_main]

#[path = "common.rs"]
mod common;

use libfuzzer_sys::fuzz_target;

use keys_pairing::sheet::MAX_RUNS_PER_SHEET as ALL_RUNS;
use keys_pairing::{Outcome, TypeStatus};

use common::{
    AWAITING_KEY_SET, DISPLAY_ENDPOINT, PAST_FIRST_MESSAGE, STRANGER_ENDPOINT, assert_not_verified,
    is_person, open_pair,
};

/// What a fresh sheet's budget is after one failure.
const ONE_RUN_SPENT: u8 = ALL_RUNS - 1;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, message)) = data.split_first() else {
        return;
    };
    let mut pair = open_pair(selector);
    let reply_is_out = selector & PAST_FIRST_MESSAGE != 0;
    if reply_is_out && is_person(selector) && selector & AWAITING_KEY_SET != 0 {
        // Stage 3 (Person pairings): the fuzzed message arrives where the
        // displaying side's key-set frame belongs.
        let _typing_keys = pair.typing_key_set();
    } else if reply_is_out {
        // Stage 2: the fuzzed message answers the Reply.
        let _reply = pair.reply();
    } else {
        // Stage 1: the fuzzed message answers the Hello.
        let _hello = pair.hello();
    }

    // From a stranger first: nothing may come of it.
    let ignored = pair.typing.handle(STRANGER_ENDPOINT, message);
    assert!(matches!(ignored.outcome, Outcome::Ignored));
    assert!(ignored.reply.is_none());
    assert_eq!(pair.typing.status(), TypeStatus::Running);

    let response = pair.typing.handle(DISPLAY_ENDPOINT, message);
    assert_not_verified(&response.outcome);
    let status = pair.typing.status();
    if reply_is_out {
        // A guess is spent: no message hands the run back uncounted.
        assert!(response.reply.is_none());
        match response.outcome {
            Outcome::RunFailed { .. } => {
                assert_eq!(
                    status,
                    TypeStatus::AwaitingCode {
                        runs_left: ONE_RUN_SPENT
                    }
                );
            }
            Outcome::DeadEnd { .. } => assert_eq!(status, TypeStatus::DeadEnd),
            other => panic!("after the Reply, a message gave {other:?}"),
        }
    } else {
        match response.outcome {
            Outcome::Continue => assert_eq!(status, TypeStatus::Running),
            Outcome::NoRun(_) => {
                assert_eq!(
                    status,
                    TypeStatus::AwaitingCode {
                        runs_left: ALL_RUNS
                    }
                );
            }
            Outcome::RunFailed { .. } => {
                assert_eq!(
                    status,
                    TypeStatus::AwaitingCode {
                        runs_left: ONE_RUN_SPENT
                    }
                );
            }
            Outcome::DeadEnd { .. } => assert_eq!(status, TypeStatus::DeadEnd),
            other => panic!("before the Reply, a message gave {other:?}"),
        }
    }
});
