//! What the tests of several modules share: the fixed keys their known
//! answers are computed from, and small helpers.

use keys_pairing::keys::PUBLIC_KEY_BYTES;
use keys_pairing::{AccountKeys, DeviceKeys, DeviceSyncKeys, RecoverySecret};

/// A stored form of `kind` over `fields`, built by hand from the format.
pub(crate) fn stored(kind: u8, fields: &[[u8; PUBLIC_KEY_BYTES]]) -> Vec<u8> {
    let mut form = vec![0x01, kind];
    for field in fields {
        form.extend_from_slice(field);
    }
    form
}

/// The known-answer account: identity seed `0x11`s, encryption `0x22`s,
/// recovery secret `0x33`s.
pub(crate) fn kat_account() -> AccountKeys {
    let recovery_public = RecoverySecret::from_bytes(&[0x33; 16]).public_key();
    AccountKeys::from_stored(&stored(b'A', &[[0x11; 32], [0x22; 32], recovery_public]))
        .expect("account form")
}

/// The known-answer device's sync keys: signing seed `0x44`s, relay `0x55`s.
pub(crate) fn kat_device_sync() -> DeviceSyncKeys {
    DeviceSyncKeys::from_stored(&stored(b'S', &[[0x44; 32], [0x55; 32]])).expect("sync form")
}

/// A fresh usable Ed25519 public key that is no device's: a stand-in for a
/// transport id.
pub(crate) fn usable_ed25519() -> [u8; PUBLIC_KEY_BYTES] {
    DeviceKeys::generate().expect("rng").public_keys().signing
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}
