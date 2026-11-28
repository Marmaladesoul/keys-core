//! Fuzz target for reading a device enrolment: a roster entry's signed
//! core, which anyone who can write the account's documents can write.
//!
//! A panic is a bug. So is acceptance of anything but the one enrolment the
//! account signed, byte for byte: the fuzzer either writes bytes of its own
//! or alters a genuine enrolment, and only the unaltered one may open.

#![no_main]

use std::sync::OnceLock;

use keys_account::DeviceEnrolment;
use keys_pairing::{AccountKeys, DeviceKeys};
use libfuzzer_sys::fuzz_target;

/// Seed for the scripted random stream, so the account, the device and so
/// the genuine enrolment are the same on every run.
const SEED: &[u8] = b"keys-account fuzz: enrolment";

struct Fixture {
    identity: [u8; 32],
    genuine: Vec<u8>,
}

static FIXTURE: OnceLock<Fixture> = OnceLock::new();

fn fixture() -> &'static Fixture {
    FIXTURE.get_or_init(|| {
        keys_pairing::script_random_for_fuzzing(SEED);
        let (account, _) = AccountKeys::generate().expect("scripted random");
        let device = DeviceKeys::generate()
            .expect("scripted random")
            .public_keys();
        // The transport's endpoint and author ids are Ed25519 keys; other
        // devices' signing keys stand in for them.
        let endpoint = DeviceKeys::generate()
            .expect("scripted random")
            .public_keys()
            .signing;
        let author = DeviceKeys::generate()
            .expect("scripted random")
            .public_keys()
            .signing;
        let genuine = DeviceEnrolment::sign(&account, device, endpoint, author)
            .expect("usable keys")
            .to_bytes()
            .to_vec();
        Fixture {
            identity: account.public_keys().identity,
            genuine,
        }
    })
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let candidate = if mode % 2 == 0 {
        rest.to_vec()
    } else {
        // XOR the input over the genuine enrolment, then cut or pad it to the
        // input's length if that differs.
        let mut altered = fixture.genuine.clone();
        for (byte, mask) in altered.iter_mut().zip(rest) {
            *byte ^= mask;
        }
        altered.resize(rest.len().max(1).min(2 * fixture.genuine.len()), 0);
        altered
    };
    if let Ok(enrolment) = DeviceEnrolment::open(&candidate, &fixture.identity) {
        assert_eq!(
            candidate, fixture.genuine,
            "an enrolment the account didn't sign was accepted"
        );
        assert_eq!(enrolment.to_bytes().as_slice(), candidate.as_slice());
    }
});
