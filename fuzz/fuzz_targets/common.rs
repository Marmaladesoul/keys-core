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
    match selector % CREDENTIAL_CHOICES {
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

/// How many kinds of credentials a selector byte picks between: a device
/// pairing, a Person pairing, and a Person pairing whose typing side
/// expects the displaying side's identity.
const CREDENTIAL_CHOICES: u8 = 3;

/// Whether `selector` picks a Person pairing.
pub fn is_person(selector: u8) -> bool {
    selector % CREDENTIAL_CHOICES != 0
}

/// Selector bits the two sheet targets share, above the credential choice:
/// the honest run has got past its first message when the fuzzed message
/// arrives, and (Person pairings) as far as the wait for a key set.
pub const PAST_FIRST_MESSAGE: u8 = 0x80;
pub const AWAITING_KEY_SET: u8 = 0x40;

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

    /// Person pairings: delivers the honest Reply and then the honest
    /// Confirm, and returns the typing side's honest key-set frame. Both
    /// sides are then waiting for the other's key set.
    pub fn typing_key_set(&mut self) -> Vec<u8> {
        let reply = self.reply();
        let confirm = self
            .display
            .handle(TYPE_ENDPOINT, &reply)
            .expect("handle")
            .reply
            .expect("a Reply is answered with a Confirm");
        self.typing
            .handle(DISPLAY_ENDPOINT, &confirm)
            .reply
            .expect("in a Person pairing a Confirm is answered with a key set")
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
