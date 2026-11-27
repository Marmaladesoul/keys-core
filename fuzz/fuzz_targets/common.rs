//! Setup shared by the pairing fuzz targets: two honest sheets, one on each
//! side, driven up to the message the fuzzer replaces.

// Each target uses a different subset of these helpers.
#![allow(dead_code)]

use std::sync::{Arc, OnceLock};

use keys_pairing::{
    AccountKeys, Credentials, DisplaySheet, DisplayStatus, EndpointId, ManualClock, Outcome,
    PairingCode, TypeSheet,
};

pub const DISPLAY_ENDPOINT: EndpointId = [0xd1; 32];
pub const TYPE_ENDPOINT: EndpointId = [0x7e; 32];
pub const STRANGER_ENDPOINT: EndpointId = [0x57; 32];

// The random stream is scripted (below), so for a given input the honest
// messages are fixed byte strings. Never seed a corpus with real
// transcripts: "a fuzzed message verified a run" would then fire on an
// input that simply is the honest message.

/// Seeds for the scripted random stream (`keys_pairing`'s fuzzing-only
/// hook): every nonce, scalar, key and code in a fuzz run is a function of
/// the input alone, so a crash replays from its artefact.
const ACCOUNTS_SEED: &[u8] = b"keys-pairing fuzz: accounts";
const RUN_SEED: &[u8] = b"keys-pairing fuzz: run";

static ACCOUNTS: OnceLock<(Arc<AccountKeys>, Arc<AccountKeys>)> = OnceLock::new();

/// The (displaying, typing) accounts: made once per process, from their own
/// seed, so they are the same in every process.
fn accounts() -> (Arc<AccountKeys>, Arc<AccountKeys>) {
    ACCOUNTS
        .get_or_init(|| {
            keys_pairing::script_random_for_fuzzing(ACCOUNTS_SEED);
            let account = || Arc::new(AccountKeys::generate().expect("random source").0);
            (account(), account())
        })
        .clone()
}

/// Both sides' credentials: a device pairing, or a Person pairing (with or
/// without the typing side pinning the displaying side's identity).
pub fn credentials(selector: u8) -> (Credentials, Credentials) {
    match selector % 3 {
        0 => (Credentials::Device, Credentials::Device),
        pin => {
            let (display, typing) = accounts();
            let expected = (pin == 2).then(|| display.public_keys().identity);
            (
                Credentials::Person {
                    account: display,
                    expected_peer_identity: None,
                },
                Credentials::Person {
                    account: typing,
                    expected_peer_identity: expected,
                },
            )
        }
    }
}

pub struct Pair {
    pub display: DisplaySheet,
    pub typing: TypeSheet,
    pub display_clock: Arc<ManualClock>,
    pub typing_clock: Arc<ManualClock>,
}

/// Opens both sheets, each on a clock of its own, with the run's random
/// stream scripted.
pub fn open_pair(selector: u8) -> Pair {
    let (display_credentials, type_credentials) = credentials(selector);
    keys_pairing::script_random_for_fuzzing(RUN_SEED);
    let display_clock = Arc::new(ManualClock::default());
    let typing_clock = Arc::new(ManualClock::default());
    let display = DisplaySheet::open(display_credentials, DISPLAY_ENDPOINT, display_clock.clone())
        .expect("random source");
    let typing = TypeSheet::open(
        type_credentials,
        TYPE_ENDPOINT,
        DISPLAY_ENDPOINT,
        typing_clock.clone(),
    );
    Pair {
        display,
        typing,
        display_clock,
        typing_clock,
    }
}

impl Pair {
    /// The code the displaying side shows, if it shows one.
    pub fn shown_code(&mut self) -> Option<PairingCode> {
        match self.display.status().expect("status") {
            DisplayStatus::ShowingCode { code, .. } => Some(code),
            _ => None,
        }
    }

    /// Types the displayed code and returns the honest Hello.
    pub fn hello(&mut self) -> Vec<u8> {
        let code = self.shown_code().expect("a fresh sheet shows a code");
        self.typing.submit_code(code).expect("submit")
    }

    /// Delivers the honest Hello and returns the honest Share.
    pub fn share(&mut self) -> Vec<u8> {
        let hello = self.hello();
        self.display
            .handle(TYPE_ENDPOINT, &hello)
            .expect("handle")
            .reply
            .expect("a Hello is answered with a Share")
    }

    /// Delivers the honest Share and returns the honest Reply.
    pub fn reply(&mut self) -> Vec<u8> {
        let share = self.share();
        self.typing
            .handle(DISPLAY_ENDPOINT, &share)
            .reply
            .expect("a Share is answered with a Reply")
    }
}

/// No fuzzed message may ever complete a run: that would mean a forged
/// message got past key confirmation.
pub fn assert_not_verified(outcome: &Outcome) {
    assert!(
        !matches!(outcome, Outcome::Verified(_)),
        "a fuzzed message verified a run"
    );
}
