//! Fuzz target for reading stored key sets back: whatever is in the secure
//! storage item, damaged or put there by someone else.
//!
//! A panic is a bug. So is reading anything but a canonical stored form: a
//! form that reads must write back byte for byte, and reads as one kind
//! only.

#![no_main]

use keys_pairing::{AccountKeys, DeviceSyncKeys, DeviceVaultKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let account = AccountKeys::from_stored(data).ok();
    let sync = DeviceSyncKeys::from_stored(data).ok();
    let vault = DeviceVaultKey::from_stored(data).ok();
    let read = [account.is_some(), sync.is_some(), vault.is_some()];
    assert!(
        read.iter().filter(|&&ok| ok).count() <= 1,
        "one stored form read as two kinds"
    );
    if let Some(keys) = account {
        assert_eq!(
            keys.to_stored().as_slice(),
            data,
            "account form not canonical"
        );
    }
    if let Some(keys) = sync {
        assert_eq!(keys.to_stored().as_slice(), data, "sync form not canonical");
    }
    if let Some(key) = vault {
        assert_eq!(key.to_stored().as_slice(), data, "vault form not canonical");
    }
});
