//! Fuzz target for a Person pairing's key set: the plaintext of a key-set
//! frame, which a peer that knows the code chooses freely. The sheet
//! targets can't reach its parser, because nothing a fuzzer makes opens as
//! a session frame.
//!
//! A panic is a bug. So is acceptance: a key set is accepted only with a
//! strict Ed25519 signature, by the identity key it names, over a
//! transcript the fuzzer doesn't control.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    assert!(
        !keys_pairing::key_set_is_accepted_for_fuzzing(data),
        "a fuzzed key set was accepted"
    );
});
